//! Fail-closed boundaries for the runtime slot generation.

use super::super::*;
use super::fixtures::*;
use std::sync::Arc;
use tokio::task::JoinHandle;

const MAX_GENERATION: u64 = u64::MAX;

struct NetworkConfigEnvironment {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl NetworkConfigEnvironment {
    fn set(path: &std::path::Path) -> Self {
        let lock = crate::NETWORK_CONFIG_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous = std::env::var_os("HELIOS_NETWORK_CONFIG");
        std::env::set_var("HELIOS_NETWORK_CONFIG", path);
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for NetworkConfigEnvironment {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var("HELIOS_NETWORK_CONFIG", previous);
        } else {
            std::env::remove_var("HELIOS_NETWORK_CONFIG");
        }
    }
}

async fn finish_without_panic<T: Send + 'static>(task: JoinHandle<T>, label: &'static str) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap_or_else(|_| panic!("{label} timed out"))
        .unwrap_or_else(|_| panic!("{label} panicked"))
}

#[tokio::test]
async fn prepare_at_max_minus_one_refuses_before_reserving_or_writing() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert!(matches!(&slot.state, SlotState::Empty));
        slot.generation = MAX_GENERATION - 1;
    }

    let prepare_handler = Arc::new(handler);
    let prepare = {
        let handler = Arc::clone(&prepare_handler);
        tokio::spawn(async move {
            handler
                .prepare(
                    CERTIFICATE_FINGERPRINT.into(),
                    PUBLIC_SOURCE,
                    request([41; 16], &fixture),
                )
                .await
        })
    };
    let result = finish_without_panic(prepare, "prepare at generation MAX-1").await;
    assert!(matches!(result, Err(PublicError::Internal)));
    assert!(
        plane.writes().await.is_empty(),
        "generation exhaustion must be detected before a data-plane write"
    );

    let mut state = prepare_handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION - 1);
    assert!(matches!(&slot.state, SlotState::Empty));
    assert!(state.active.is_empty());
    assert!(!state.peers.contains(CLIENT_KEY));
    assert!(state.replay_set.is_empty());
    assert!(state.replay_order.is_empty());
}

#[tokio::test]
async fn clear_and_signed_release_at_max_refuse_without_clearing() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let handler = Arc::new(handler);
    let transaction_id = [42; 16];
    commit(&handler, &plane, &fixture, transaction_id, PUBLIC_SOURCE).await;
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION;
    }
    let writes_before = plane.writes().await.len();

    let clear_handler = Arc::clone(&handler);
    let clear =
        tokio::spawn(async move { clear_handler.clear_slot(CLIENT_KEY, MAX_GENERATION).await });
    assert!(matches!(
        finish_without_panic(clear, "clear at generation MAX").await,
        Err(PublicError::Internal)
    ));
    assert_eq!(
        plane.writes().await.len(),
        writes_before,
        "failed clear must not touch the backend"
    );

    let release_handler = Arc::clone(&handler);
    let release =
        tokio::spawn(
            async move { release_in_tunnel(&release_handler, &fixture, transaction_id).await },
        );
    assert!(matches!(
        finish_without_panic(release, "signed release at generation MAX").await,
        Err(PskReleaseRefusal::Internal)
    ));
    assert_eq!(
        plane.writes().await.len(),
        writes_before,
        "failed signed release must not touch the backend"
    );

    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(
        &slot.state,
        SlotState::Committed(installed) if installed.transaction_id == transaction_id
    ));
}

#[tokio::test]
async fn rollback_at_max_remains_owned_without_restoring_the_backend() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let handler = Arc::new(handler);
    let transaction_id = [43; 16];
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .expect("prepare candidate");
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION;
        state
            .active
            .get_mut(&transaction_id)
            .expect("active transaction")
            .generation = MAX_GENERATION;
    }
    let writes_before = plane.writes().await.len();

    let rollback_handler = Arc::clone(&handler);
    let rollback = tokio::spawn(async move {
        rollback_handler.rollback(transaction_id, CLIENT_KEY).await;
    });
    finish_without_panic(rollback, "rollback at generation MAX").await;

    assert_eq!(
        plane.writes().await.len(),
        writes_before,
        "rollback exhaustion must not restore the backend and leave state inconsistent"
    );
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(
        &slot.state,
        SlotState::Preparing {
            transaction_id: owner,
            ..
        } if *owner == transaction_id
    ));
    assert!(state.active.contains_key(&transaction_id));
    assert!(state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn confirm_at_max_refuses_before_raising_the_floor_or_committing() {
    let directory = tempfile::tempdir().expect("temporary network-config directory");
    let _network_config = NetworkConfigEnvironment::set(&directory.path().join("network.toml"));
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::StaticPsk);
    let handler = Arc::new(handler);
    let transaction_id = [46; 16];
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .expect("prepare candidate above the existing static-PSK floor");
    plane.handshake_happens().await;
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION;
        state
            .active
            .get_mut(&transaction_id)
            .expect("active transaction")
            .generation = MAX_GENERATION;
    }
    let writes_before = plane.writes().await.len();
    let confirmation =
        authenticate_confirmation(TEST_CHALLENGE, transaction_id, &fixture.client_private_key)
            .expect("signed confirmation");

    let confirm_handler = Arc::clone(&handler);
    let confirm = tokio::spawn(async move { confirm_handler.confirm(confirmation).await });
    assert!(matches!(
        finish_without_panic(confirm, "confirm at generation MAX").await,
        Err(PublicError::Internal)
    ));
    assert_eq!(
        plane.writes().await.len(),
        writes_before,
        "generation exhaustion must not issue another backend write"
    );
    assert_eq!(
        handler.network.read().await.peers[0].minimum_key_negotiation_mode,
        Some(ProtectionMode::StaticPsk),
        "generation exhaustion must not raise the persistent security floor"
    );

    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(
        &slot.state,
        SlotState::Preparing {
            transaction_id: owner,
            ..
        } if *owner == transaction_id
    ));
    assert!(state.active.contains_key(&transaction_id));
    assert!(state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn max_minus_two_allows_the_terminal_commit_or_rollback_transition() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION - 2;
    }
    let commit_id = [44; 16];
    commit(&handler, &plane, &fixture, commit_id, PUBLIC_SOURCE).await;
    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert_eq!(slot.generation, MAX_GENERATION);
        assert!(matches!(
            &slot.state,
            SlotState::Committed(installed) if installed.transaction_id == commit_id
        ));
    }

    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION - 2;
    }
    let rollback_id = [45; 16];
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(rollback_id, &fixture),
        )
        .await
        .expect("prepare with one terminal generation available");
    handler.rollback(rollback_id, CLIENT_KEY).await;
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(&slot.state, SlotState::Empty));
    assert!(!state.active.contains_key(&rollback_id));
    assert!(!state.peers.contains(CLIENT_KEY));
    assert_eq!(plane.writes().await.len(), 2);
}
