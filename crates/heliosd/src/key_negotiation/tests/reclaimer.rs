//! Integration tests of the periodic PSK reclaimer over the mock data plane.

use super::super::*;
use super::fixtures::*;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

const GIB: u64 = 1024 * 1024 * 1024;

fn status(total_bytes: u64) -> helios_wireguard::PeerStatus {
    helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(CLIENT_KEY)
            .expect("fixture WireGuard key"),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(SystemTime::now()),
        endpoint: None,
        rx_bytes: total_bytes / 2,
        tx_bytes: total_bytes - total_bytes / 2,
    }
}

async fn wait_for_write_count(plane: &TestDataPlane, expected: usize) {
    for _ in 0..1_000 {
        if plane.writes().await.len() >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the reclaimer should attempt the expected data-plane write");
}

async fn wait_for_empty_slot(handler: &GatewayHandler, generation: u64) {
    for _ in 0..1_000 {
        let mut transactions = handler.transactions.lock().await;
        let slot = transactions.slot(CLIENT_KEY);
        if matches!(slot.state, SlotState::Empty) && slot.generation == generation {
            return;
        }
        drop(transactions);
        tokio::task::yield_now().await;
    }
    panic!("the reclaimer should finish the expected slot transition");
}

#[tokio::test(start_paused = true)]
async fn periodic_reclaimer_clears_a_committed_psk_at_the_volume_ceiling() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(
        &fixture,
        &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        ProtectionMode::MlKem,
    );
    commit(&handler, &plane, &fixture, [60; 16], PUBLIC_SOURCE).await;

    // The first observation establishes the per-slot byte baseline. The next
    // snapshot is exactly 100 GiB above it, the wire policy's hard ceiling.
    assert!(handler.reclaimable(&[status(10 * GIB)]).await.is_empty());
    let peer_runtime = Arc::new(RwLock::new(vec![status(110 * GIB)]));
    let handler = Arc::new(handler);
    let task = server::spawn_psk_reclaimer(Arc::clone(&handler), peer_runtime);

    wait_for_write_count(&plane, 2).await;
    wait_for_empty_slot(&handler, 3).await;
    task.abort();
    assert!(
        task.await.is_err(),
        "the test stops its background reclaimer"
    );

    let writes = plane.writes().await;
    assert_eq!(writes.len(), 2);
    assert!(writes[0].is_some(), "commit installed a candidate PSK");
    assert_eq!(writes[1], None, "reclamation clears the negotiated PSK");
    let mut transactions = handler.transactions.lock().await;
    let slot = transactions.slot(CLIENT_KEY);
    assert!(matches!(slot.state, SlotState::Empty));
    assert_eq!(slot.generation, 3);
}

#[tokio::test(start_paused = true)]
async fn periodic_reclaimer_revokes_a_peer_removed_from_admission() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(
        &fixture,
        &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        ProtectionMode::MlKem,
    );
    commit(&handler, &plane, &fixture, [61; 16], PUBLIC_SOURCE).await;
    handler
        .network
        .write()
        .await
        .peers
        .retain(|peer| peer.public_key != CLIENT_KEY);

    let handler = Arc::new(handler);
    let task = server::spawn_psk_reclaimer(Arc::clone(&handler), Arc::new(RwLock::new(Vec::new())));
    for _ in 0..1_000 {
        if matches!(
            handler.transactions.lock().await.slot(CLIENT_KEY).state,
            SlotState::Revoked
        ) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        matches!(
            handler.transactions.lock().await.slot(CLIENT_KEY).state,
            SlotState::Revoked
        ),
        "the sweep should revoke an unadmitted slot"
    );
    task.abort();
    assert!(
        task.await.is_err(),
        "the test stops its background reclaimer"
    );

    assert!(
        !handler.static_psks.read().await.contains_key(CLIENT_KEY),
        "revocation discards the cached static baseline"
    );
    assert_eq!(
        plane.writes().await.len(),
        1,
        "the orchestrator already removed the peer"
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_after_backend_clear_leaves_a_retryable_slot() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(
        &fixture,
        &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        ProtectionMode::MlKem,
    );
    commit(&handler, &plane, &fixture, [63; 16], PUBLIC_SOURCE).await;
    assert!(handler.reclaimable(&[status(10 * GIB)]).await.is_empty());
    let gate = plane.pause_after_write(2).await;
    let peer_runtime = Arc::new(RwLock::new(vec![status(110 * GIB)]));
    let handler = Arc::new(handler);

    let interrupted = server::spawn_psk_reclaimer(Arc::clone(&handler), Arc::clone(&peer_runtime));
    gate.wait_until_entered().await;
    assert_eq!(
        plane.writes().await.len(),
        2,
        "backend has applied the clear"
    );
    interrupted.abort();
    assert!(interrupted.await.is_err());
    gate.open();

    assert!(matches!(
        handler.transactions.lock().await.slot(CLIENT_KEY).state,
        SlotState::Committed(_)
    ));
    let retry = server::spawn_psk_reclaimer(Arc::clone(&handler), peer_runtime);
    wait_for_write_count(&plane, 3).await;
    wait_for_empty_slot(&handler, 3).await;
    retry.abort();
    assert!(retry.await.is_err());
    assert_eq!(plane.writes().await.len(), 3);
}

#[tokio::test]
async fn a_reclaimer_decision_cannot_clear_a_newer_committed_generation() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(
        &fixture,
        &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        ProtectionMode::MlKem,
    );
    commit(&handler, &plane, &fixture, [64; 16], PUBLIC_SOURCE).await;
    assert!(handler.reclaimable(&[status(10 * GIB)]).await.is_empty());
    let stale_decision = handler.reclaimable(&[status(110 * GIB)]).await;
    assert_eq!(stale_decision.len(), 1);

    commit(&handler, &plane, &fixture, [65; 16], TUNNEL_SOURCE).await;
    handler
        .clear_slot(CLIENT_KEY, stale_decision[0].1)
        .await
        .expect("a stale reclamation generation is a no-op");

    assert_eq!(
        plane.writes().await.len(),
        2,
        "the newer PSK remains installed"
    );
    let mut transactions = handler.transactions.lock().await;
    let SlotState::Committed(installed) = &transactions.slot(CLIENT_KEY).state else {
        panic!("the newer transaction must still own the slot");
    };
    assert_eq!(installed.transaction_id, [65; 16]);
}

#[tokio::test(start_paused = true)]
async fn failed_reclamation_write_keeps_the_slot_and_retries_on_the_next_poll() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(
        &fixture,
        &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        ProtectionMode::MlKem,
    );
    commit(&handler, &plane, &fixture, [62; 16], PUBLIC_SOURCE).await;
    assert!(handler.reclaimable(&[status(10 * GIB)]).await.is_empty());
    plane.start_failing().await;

    let peer_runtime = Arc::new(RwLock::new(vec![status(110 * GIB)]));
    let handler = Arc::new(handler);
    let task = server::spawn_psk_reclaimer(Arc::clone(&handler), peer_runtime);
    wait_for_write_count(&plane, 2).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    {
        let mut transactions = handler.transactions.lock().await;
        assert!(matches!(
            transactions.slot(CLIENT_KEY).state,
            SlotState::Committed(_)
        ));
    }

    plane.stop_failing().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_write_count(&plane, 3).await;
    wait_for_empty_slot(&handler, 3).await;
    task.abort();
    assert!(
        task.await.is_err(),
        "the test stops its background reclaimer"
    );

    let mut transactions = handler.transactions.lock().await;
    assert!(matches!(
        transactions.slot(CLIENT_KEY).state,
        SlotState::Empty
    ));
    assert_eq!(transactions.slot(CLIENT_KEY).generation, 3);
    assert_eq!(plane.writes().await.last(), Some(&None));
}
