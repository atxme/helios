//! Admission changes are slot mutations too: their generation must never wrap.

use super::super::*;
use super::fixtures::{
    gateway_with, pq_fixture, request_in_mode, CERTIFICATE_FINGERPRINT, CLIENT_KEY, PUBLIC_SOURCE,
};

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

#[tokio::test]
async fn cancelled_admission_revocation_leaves_slot_unchanged_until_cache_cleanup_can_commit() {
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    let fixture = pq_fixture();
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    handler.network.write().await.peers.clear();
    let cache_guard = handler.static_psks.write().await;
    let mut state = handler.transactions.lock().await;
    state.slot(CLIENT_KEY).generation = 17;

    let mut settlement = Box::pin(handler.settle_admission(&mut state, CLIENT_KEY));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        settlement.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(settlement);

    let unchanged_while_cache_is_locked = {
        let slot = state.slot(CLIENT_KEY);
        slot.generation == 17 && matches!(&slot.state, SlotState::Empty)
    };
    drop(state);
    drop(cache_guard);

    {
        let mut state = handler.transactions.lock().await;
        handler
            .settle_admission(&mut state, CLIENT_KEY)
            .await
            .expect("retrying revocation after cache lock is available");
    }
    let final_state_is_terminal = {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        slot.generation == 18 && matches!(&slot.state, SlotState::Revoked)
    };
    let cache_is_empty = !handler.static_psks.read().await.contains_key(CLIENT_KEY);

    assert!(
        unchanged_while_cache_is_locked,
        "settlement must not revoke before it can synchronously clear the cached PSK"
    );
    assert!(final_state_is_terminal);
    assert!(cache_is_empty);
    assert!(plane.writes().await.is_empty());
}

#[tokio::test]
async fn readmission_does_not_use_stale_static_psk_when_config_has_none() {
    let old_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &old_psk, ProtectionMode::StaticPsk);
    handler.network.write().await.peers[0].preshared_key = None;
    handler
        .static_psks
        .write()
        .await
        .insert(CLIENT_KEY.into(), aether::SecretString::new(&old_psk));
    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        slot.generation = 9;
        slot.state = SlotState::Revoked;
    }

    let result = handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                [91; 16],
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&old_psk),
            ),
        )
        .await;

    assert!(matches!(result, Err(PublicError::Rejected)));
    let writes = plane.writes().await;
    assert!(writes
        .iter()
        .all(|write| write.as_deref() != Some(old_psk.as_str())));
    {
        let mut state = handler.transactions.lock().await;
        assert!(matches!(&state.slot(CLIENT_KEY).state, SlotState::Empty));
        assert!(!state.peers.contains(CLIENT_KEY));
    }
    assert!(!handler.static_psks.read().await.contains_key(CLIENT_KEY));
}

#[tokio::test]
async fn readmission_uses_newly_configured_static_psk_not_stale_cache() {
    let old_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let new_psk = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &old_psk, ProtectionMode::StaticPsk);
    handler.network.write().await.peers[0].preshared_key = Some(new_psk.clone().into());
    handler
        .static_psks
        .write()
        .await
        .insert(CLIENT_KEY.into(), aether::SecretString::new(&old_psk));
    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        slot.generation = 9;
        slot.state = SlotState::Revoked;
    }

    let old_result = handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                [92; 16],
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&old_psk),
            ),
        )
        .await;
    let new_result = handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                [93; 16],
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&new_psk),
            ),
        )
        .await;

    assert!(matches!(old_result, Err(PublicError::Rejected)));
    assert!(new_result.is_ok());
    let writes = plane.writes().await;
    assert!(writes
        .iter()
        .all(|write| write.as_deref() != Some(old_psk.as_str())));
    assert!(writes
        .last()
        .is_some_and(|write| write.as_deref() == Some(new_psk.as_str())));
    {
        let mut state = handler.transactions.lock().await;
        assert!(matches!(
            &state.slot(CLIENT_KEY).state,
            SlotState::Preparing { transaction_id, .. } if *transaction_id == [93; 16]
        ));
        assert!(state.peers.contains(CLIENT_KEY));
    }
    {
        let static_psks = handler.static_psks.read().await;
        assert!(static_psks
            .get(CLIENT_KEY)
            .is_some_and(|cached| cached.expose() == new_psk));
    }
}

#[tokio::test(start_paused = true)]
async fn static_psk_cache_learns_under_the_slot_transaction_lock() {
    use std::sync::Arc;

    let static_psk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &static_psk, ProtectionMode::StaticPsk);
    let handler = Arc::new(handler);
    let transaction_id = [94; 16];
    let gate = plane.pause_after_write(1).await;

    let prepare_handler = Arc::clone(&handler);
    let request_psk = static_psk.clone();
    let mut prepare = tokio::spawn(async move {
        prepare_handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                PUBLIC_SOURCE,
                request_in_mode(
                    transaction_id,
                    &fixture,
                    ProtectionMode::StaticPsk,
                    Some(&request_psk),
                ),
            )
            .await
    });
    let backend_write_entered =
        tokio::time::timeout(std::time::Duration::from_secs(5), gate.wait_until_entered())
            .await
            .is_ok();

    let cache_guard = handler.static_psks.write().await;
    gate.open();
    let transaction_lock_blocked = tokio::time::timeout(
        std::time::Duration::from_millis(5),
        handler.transactions.lock(),
    )
    .await
    .is_err();
    drop(cache_guard);

    let prepare_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut prepare).await;
    let prepare_succeeded = matches!(&prepare_result, Ok(Ok(Ok(_))));
    if prepare_result.is_err() {
        prepare.abort();
        let _ = prepare.await;
    }
    drop(prepare_result);
    let slot_and_cache_are_coherent = if prepare_succeeded {
        let mut state = handler.transactions.lock().await;
        let owns_transaction = matches!(
            &state.slot(CLIENT_KEY).state,
            SlotState::Preparing { transaction_id: owner, .. } if *owner == transaction_id
        ) && state.active.contains_key(&transaction_id);
        let cache_matches = handler
            .static_psks
            .read()
            .await
            .get(CLIENT_KEY)
            .is_some_and(|cached| cached.expose() == static_psk);
        owns_transaction && cache_matches
    } else {
        false
    };

    if prepare_succeeded {
        handler.rollback(transaction_id, CLIENT_KEY).await;
    }
    let slot_released = {
        let mut state = handler.transactions.lock().await;
        matches!(&state.slot(CLIENT_KEY).state, SlotState::Empty)
            && !state.peers.contains(CLIENT_KEY)
    };

    assert!(
        backend_write_entered,
        "static PSK backend write reached the gate"
    );
    assert!(prepare_succeeded, "static PSK preparation completed");
    assert!(
        transaction_lock_blocked,
        "transaction ownership must cover learning the static PSK cache entry"
    );
    assert!(slot_and_cache_are_coherent);
    assert!(slot_released, "test rollback released the prepared slot");
}

#[tokio::test]
async fn queued_preparation_obeys_the_latest_security_floor_before_reserving() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    for wait_for_slot in [true, false] {
        let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &static_psk, ProtectionMode::StaticPsk);
        let transaction = [94; 16];
        let state_guard = if wait_for_slot {
            Some(handler.transactions.lock().await)
        } else {
            None
        };
        let cache_guard = if wait_for_slot {
            None
        } else {
            Some(handler.static_psks.write().await)
        };
        let mut prepare = Box::pin(handler.prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                transaction,
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&static_psk),
            ),
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(prepare.as_mut().poll(&mut context), Poll::Pending));

        // The authenticated request waits either for its slot or its cache
        // snapshot. Neither wait may keep the previous policy authoritative.
        let mut network =
            tokio::time::timeout(std::time::Duration::from_secs(5), handler.network.write())
                .await
                .expect("no configuration read guard may span the blocked cache wait");
        network.peers[0].minimum_key_negotiation_mode = Some(ProtectionMode::MlKem);
        drop(network);
        drop(state_guard);
        drop(cache_guard);

        assert!(matches!(prepare.await, Err(PublicError::Rejected)));
        assert!(plane.writes().await.is_empty());
        let mut state = handler.transactions.lock().await;
        assert_eq!(state.slot(CLIENT_KEY).generation, 0);
        assert!(state.active.is_empty());
        assert!(!state.peers.contains(CLIENT_KEY));
        assert!(!state.replay_set.contains(&transaction));
    }
}
