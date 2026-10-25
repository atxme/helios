//! Cancellation boundaries around gateway PSK ownership and backend writes.

use super::super::*;
use super::fixtures::*;
use std::sync::Arc;

#[tokio::test]
async fn cancelled_prepare_after_backend_write_can_be_rolled_back() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let handler = Arc::new(handler);
    let transaction_id = [31; 16];
    let gate = plane.pause_after_write(1).await;

    let prepare_handler = Arc::clone(&handler);
    let prepare = tokio::spawn(async move {
        prepare_handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                PUBLIC_SOURCE,
                request(transaction_id, &fixture),
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        gate.wait_until_entered(),
    )
    .await
    .expect("candidate write took effect before acknowledgement pause");
    let candidate_was_not_static = plane
        .writes()
        .await
        .first()
        .and_then(Option::as_ref)
        .is_some_and(|candidate| candidate != &previous_psk);
    assert!(candidate_was_not_static);

    prepare.abort();
    let cancelled = match prepare.await {
        Err(error) => error,
        Ok(_) => panic!("prepare task was not cancelled"),
    };
    assert!(cancelled.is_cancelled());
    gate.open();

    handler.rollback(transaction_id, CLIENT_KEY).await;
    let writes = plane.writes().await;
    assert_eq!(writes.len(), 2, "candidate install and rollback restore");
    assert!(writes
        .last()
        .is_some_and(|restored| restored.as_deref() == Some(previous_psk.as_str())));

    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(&slot.state, SlotState::Empty));
    assert!(slot.generation >= 2, "rollback advances slot ownership");
    assert!(
        slot.resting_until.is_some(),
        "post-install rollback rests the peer"
    );
    assert!(!state.peers.contains(CLIENT_KEY));
    drop(state);

    let static_configuration_preserved = handler
        .network
        .read()
        .await
        .peers
        .iter()
        .find(|peer| peer.public_key == CLIENT_KEY)
        .and_then(|peer| peer.preshared_key.as_ref().map(SecretString::expose))
        == Some(previous_psk.as_str());
    let static_cache_preserved = handler
        .static_psks
        .read()
        .await
        .get(CLIENT_KEY)
        .is_some_and(|psk| psk.expose() == previous_psk.as_str());
    assert!(static_configuration_preserved);
    assert!(static_cache_preserved);
}

#[tokio::test]
async fn cancelled_rollback_keeps_ownership_until_backend_restore_acknowledges() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let handler = Arc::new(handler);
    let transaction_id = [32; 16];

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .expect("candidate prepared");
    let before_rollback = plane.writes().await;
    assert_eq!(before_rollback.len(), 1);

    let gate = plane.pause_after_write(2).await;
    let rollback_handler = Arc::clone(&handler);
    let rollback = tokio::spawn(async move {
        rollback_handler.rollback(transaction_id, CLIENT_KEY).await;
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        gate.wait_until_entered(),
    )
    .await
    .expect("restore write took effect before acknowledgement pause");
    let restore_was_static = plane
        .writes()
        .await
        .get(1)
        .is_some_and(|restored| restored.as_deref() == Some(previous_psk.as_str()));
    assert!(restore_was_static);

    rollback.abort();
    let cancelled = match rollback.await {
        Err(error) => error,
        Ok(()) => panic!("rollback task was not cancelled"),
    };
    assert!(cancelled.is_cancelled());
    gate.open();

    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert!(matches!(
            &slot.state,
            SlotState::Preparing {
                transaction_id: owner,
                install_attempted: true,
                ..
            } if *owner == transaction_id
        ));
        assert!(state.active.contains_key(&transaction_id));
        assert!(state.peers.contains(CLIENT_KEY));
    }

    handler.rollback(transaction_id, CLIENT_KEY).await;
    let writes = plane.writes().await;
    assert_eq!(writes.len(), 3, "cancelled restore is safely retried");
    assert!(writes
        .last()
        .is_some_and(|restored| restored.as_deref() == Some(previous_psk.as_str())));
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(&slot.state, SlotState::Empty));
    assert!(slot.resting_until.is_some());
    assert!(!state.active.contains_key(&transaction_id));
    assert!(!state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn stale_rollback_cannot_undo_a_newer_preparation() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let old_transaction = [33; 16];
    let new_transaction = [34; 16];

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(old_transaction, &fixture),
        )
        .await
        .expect("old transaction prepared");
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, old_transaction, &fixture.client_private_key)
                .expect("old transaction confirmation"),
        )
        .await
        .expect("old transaction committed");
    let committed_generation = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;
    handler
        .clear_slot(CLIENT_KEY, committed_generation)
        .await
        .expect("clear old committed slot");

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(new_transaction, &fixture),
        )
        .await
        .expect("new transaction prepared");
    let writes_before_stale_cleanup = plane.writes().await.len();
    let generation_before_stale_cleanup = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;

    handler.rollback(old_transaction, CLIENT_KEY).await;

    assert_eq!(plane.writes().await.len(), writes_before_stale_cleanup);
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(slot.generation, generation_before_stale_cleanup);
    assert!(matches!(
        &slot.state,
        SlotState::Preparing {
            transaction_id: owner,
            ..
        } if *owner == new_transaction
    ));
    assert!(state.active.contains_key(&new_transaction));
    assert!(state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn failed_restore_keeps_preparing_ownership_and_can_be_retried() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let transaction_id = [35; 16];
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .expect("candidate prepared");

    plane.start_failing().await;
    handler.rollback(transaction_id, CLIENT_KEY).await;
    let writes_after_refused_restore = plane.writes().await;
    assert_eq!(writes_after_refused_restore.len(), 2);
    assert!(writes_after_refused_restore
        .last()
        .is_some_and(|restore| restore.as_deref() == Some(previous_psk.as_str())));
    {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert!(matches!(
            &slot.state,
            SlotState::Preparing {
                transaction_id: owner,
                install_attempted: true,
                ..
            } if *owner == transaction_id
        ));
        assert!(state.active.contains_key(&transaction_id));
        assert!(state.peers.contains(CLIENT_KEY));
    }

    plane.stop_failing().await;
    handler.rollback(transaction_id, CLIENT_KEY).await;
    let writes_after_retry = plane.writes().await;
    assert_eq!(writes_after_retry.len(), 3);
    assert!(writes_after_retry
        .last()
        .is_some_and(|restore| restore.as_deref() == Some(previous_psk.as_str())));
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(&slot.state, SlotState::Empty));
    assert!(slot.resting_until.is_some());
    assert!(!state.active.contains_key(&transaction_id));
    assert!(!state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn rolling_back_renewal_restores_the_committed_ml_kem_psk_and_owner() {
    let configured_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &configured_psk, ProtectionMode::MlKem);
    let first = [36; 16];
    let renewal = [37; 16];

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(first, &fixture),
        )
        .await
        .expect("first candidate prepared");
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, first, &fixture.client_private_key)
                .expect("first confirmation"),
        )
        .await
        .expect("first PSK committed");
    let first_psk = plane
        .writes()
        .await
        .first()
        .and_then(|write| write.clone())
        .expect("first candidate PSK");
    let (first_metadata, first_generation) = {
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        let SlotState::Committed(installed) = &slot.state else {
            panic!("first ml_kem transaction must own a committed slot");
        };
        (
            (
                installed.transaction_id,
                installed.public_key.clone(),
                installed.address.clone(),
                installed.installed_at,
                installed.bytes_baseline,
            ),
            slot.generation,
        )
    };

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(renewal, &fixture),
        )
        .await
        .expect("renewal candidate prepared");
    handler.rollback(renewal, CLIENT_KEY).await;

    let writes = plane.writes().await;
    assert_eq!(writes.len(), 3);
    let restored_first_psk = writes
        .last()
        .is_some_and(|restored| restored.as_deref() == Some(first_psk.as_str()));
    assert!(
        restored_first_psk,
        "rollback must restore the prior committed candidate, not only the configured PSK"
    );
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    let restored_metadata = match &slot.state {
        SlotState::Committed(installed) => Some((
            installed.transaction_id,
            installed.public_key.clone(),
            installed.address.clone(),
            installed.installed_at,
            installed.bytes_baseline,
        )),
        _ => None,
    };
    assert_eq!(restored_metadata, Some(first_metadata));
    assert!(slot.generation > first_generation);
    assert!(!state.active.contains_key(&renewal));
    assert!(!state.peers.contains(CLIENT_KEY));
}

#[tokio::test]
async fn same_or_older_handshake_cannot_confirm_but_a_newer_one_can() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let transaction_id = [38; 16];
    let before = std::time::UNIX_EPOCH + std::time::Duration::from_secs(50);
    *plane.handshake.lock().await = Some(before);
    *plane.tick.lock().await = 50;

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .expect("candidate prepared with a known handshake baseline");
    let confirmation = || {
        authenticate_confirmation(TEST_CHALLENGE, transaction_id, &fixture.client_private_key)
            .expect("valid confirmation")
    };

    assert!(matches!(
        handler.confirm(confirmation()).await,
        Err(PublicError::Rejected)
    ));
    *plane.handshake.lock().await = Some(before - std::time::Duration::from_secs(1));
    assert!(matches!(
        handler.confirm(confirmation()).await,
        Err(PublicError::Rejected)
    ));
    *plane.handshake.lock().await = Some(before + std::time::Duration::from_secs(1));
    handler
        .confirm(confirmation())
        .await
        .expect("strictly newer handshake proves the candidate");
    let mut state = handler.transactions.lock().await;
    assert!(matches!(
        &state.slot(CLIENT_KEY).state,
        SlotState::Committed(_)
    ));
}

#[tokio::test]
async fn configured_static_release_and_clear_are_noops_even_at_generation_limit() {
    let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &static_psk, ProtectionMode::StaticPsk);
    let transaction_id = [39; 16];

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                transaction_id,
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&static_psk),
            ),
        )
        .await
        .expect("static PSK possession verified");
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, transaction_id, &fixture.client_private_key)
                .expect("confirmation"),
        )
        .await
        .expect("static PSK transaction committed");
    let writes_before_release = plane.writes().await.len();
    assert_eq!(writes_before_release, 1);
    {
        let mut state = handler.transactions.lock().await;
        state.slot(CLIENT_KEY).generation = u64::MAX;
    }

    release_in_tunnel(&handler, &fixture, transaction_id)
        .await
        .expect("release of a configured static slot is an idempotent no-op");
    handler
        .clear_slot(CLIENT_KEY, u64::MAX)
        .await
        .expect("clearing a configured static slot is an idempotent no-op");

    assert_eq!(plane.writes().await.len(), writes_before_release);
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(&slot.state, SlotState::ConfiguredStatic));
    assert_eq!(slot.generation, u64::MAX);
    assert!(state.active.is_empty());
}
