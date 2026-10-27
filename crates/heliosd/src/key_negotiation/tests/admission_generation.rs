//! Admission changes are slot mutations too: their generation must never wrap.

use super::super::*;
use super::fixtures::{gateway_with, pq_fixture, CLIENT_KEY};

const MAX_GENERATION: u64 = u64::MAX;

#[test]
fn revocation_at_max_keeps_a_terminal_slot_and_clears_reservation() {
    let mut state = TransactionState::default();
    let slot = state.slot(CLIENT_KEY);
    slot.generation = MAX_GENERATION;
    slot.state = SlotState::Preparing {
        transaction_id: [7; 16],
        previous: Box::new(SlotState::Empty),
        address: "100.64.1.2".into(),
        previous_psk: Some(aether::SecretString::new("discard-on-revocation")),
        install_attempted: true,
    };
    state.active.insert(
        [7; 16],
        Transaction {
            public_key: CLIENT_KEY.into(),
            address: "100.64.1.2".into(),
            client_pq_public_key: String::new(),
            mode: ProtectionMode::MlKem,
            server_challenge: [0; SERVER_CHALLENGE_LEN],
            generation: MAX_GENERATION,
            handshake_before_install: None,
        },
    );
    state.peers.insert(CLIENT_KEY.into());

    assert!(matches!(
        state.settle_admission(CLIENT_KEY, false),
        Err(PublicError::Internal)
    ));

    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(&slot.state, SlotState::Revoked));
    assert!(!state.peers.contains(CLIENT_KEY));
    assert!(state.active.is_empty());
}

#[test]
fn readmission_after_last_generation_does_not_revive_a_revoked_slot() {
    let mut state = TransactionState::default();
    let slot = state.slot(CLIENT_KEY);
    slot.generation = MAX_GENERATION - 1;

    assert!(matches!(
        state.settle_admission(CLIENT_KEY, false),
        Ok(true)
    ));
    assert_eq!(state.slot(CLIENT_KEY).generation, MAX_GENERATION);
    assert!(matches!(&state.slot(CLIENT_KEY).state, SlotState::Revoked));

    assert!(matches!(
        state.settle_admission(CLIENT_KEY, true),
        Err(PublicError::Internal)
    ));

    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, MAX_GENERATION);
    assert!(matches!(&slot.state, SlotState::Revoked));
}

#[tokio::test]
async fn exhausted_handler_revocation_clears_static_psk_without_backend_write() {
    let fixture = pq_fixture();
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    handler.network.write().await.peers.clear();
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION;
        state.peers.insert(CLIENT_KEY.into());
    }

    let settlement = {
        let mut state = handler.transactions.lock().await;
        handler.settle_admission(&mut state, CLIENT_KEY).await
    };
    assert!(matches!(settlement, Err(PublicError::Internal)));

    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert_eq!(slot.generation, MAX_GENERATION);
        assert!(matches!(&slot.state, SlotState::Revoked));
        assert!(state.peers.is_empty());
    }
    {
        let static_psks = handler.static_psks.read().await;
        assert!(!static_psks.contains_key(CLIENT_KEY));
    }
    assert!(plane.writes().await.is_empty());
}

#[tokio::test]
async fn exhausted_revocation_sweep_cleans_every_peer_and_continues_without_backend_writes() {
    const OTHER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    let fixture = pq_fixture();
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    handler.network.write().await.peers.clear();
    handler.static_psks.write().await.insert(
        OTHER_KEY.into(),
        aether::SecretString::new("second-static-psk"),
    );
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = MAX_GENERATION;
        state.slot(OTHER_KEY).generation = MAX_GENERATION;
        state.peers.extend([CLIENT_KEY.into(), OTHER_KEY.into()]);
    }

    handler.revoke_unadmitted().await;

    {
        let mut state = handler.transactions.lock().await;
        for key in [CLIENT_KEY, OTHER_KEY] {
            let slot = state.slot(key);
            assert_eq!(slot.generation, MAX_GENERATION);
            assert!(matches!(&slot.state, SlotState::Revoked));
        }
        assert!(state.peers.is_empty());
    }
    {
        let static_psks = handler.static_psks.read().await;
        assert!(!static_psks.contains_key(CLIENT_KEY));
        assert!(!static_psks.contains_key(OTHER_KEY));
    }
    assert!(plane.writes().await.is_empty());
}
