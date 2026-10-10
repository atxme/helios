//! In-tunnel PSK renewal: the tunnel path only ever renews.

use super::super::*;
use super::fixtures::*;

fn psk() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

#[tokio::test]
async fn an_in_tunnel_negotiation_renews_a_committed_slot() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [30; 16], PUBLIC_SOURCE).await;
    commit(&handler, &plane, &fixture, [31; 16], TUNNEL_SOURCE).await;

    assert_eq!(
        plane.writes().await.len(),
        2,
        "one PSK per committed negotiation"
    );
    let mut state = handler.transactions.lock().await;
    let SlotState::Committed(installed) = &state.slot(CLIENT_KEY).state else {
        panic!("the renewal must leave an owned slot");
    };
    assert_eq!(
        installed.transaction_id, [31; 16],
        "the renewal owns the slot now"
    );
}

#[tokio::test]
async fn an_in_tunnel_negotiation_cannot_post_a_first_psk() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    let refused = handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            TUNNEL_SOURCE,
            request([32; 16], &fixture),
        )
        .await;
    assert!(matches!(refused, Err(PublicError::Rejected)));
    assert!(
        plane.writes().await.is_empty(),
        "nothing may reach the data plane"
    );
    assert!(
        handler.transactions.lock().await.peers.is_empty(),
        "a refused renewal must not keep the peer reserved"
    );
}

#[tokio::test]
async fn a_vip_belonging_to_another_peer_is_not_admitted() {
    let fixture = pq_fixture();
    let (handler, _plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    let other = aether::WgPeer {
        name: "other".into(),
        public_key: base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
        address: "100.64.1.3/32".into(),
        address_v6: None,
        admin: false,
        preshared_key: None,
        key_negotiation_certificate_sha256: Some("ff".repeat(32)),
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: ProtectionMode::Classic,
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    };
    handler.network.write().await.peers.push(other);

    assert_eq!(
        handler
            .resolve_admitted_peer(CERTIFICATE_FINGERPRINT, TUNNEL_SOURCE)
            .await
            .as_deref(),
        Some(CLIENT_KEY)
    );
    assert_eq!(
        handler
            .resolve_admitted_peer(CERTIFICATE_FINGERPRINT, PUBLIC_SOURCE)
            .await
            .as_deref(),
        Some(CLIENT_KEY)
    );
    assert_eq!(
        handler
            .resolve_admitted_peer(CERTIFICATE_FINGERPRINT, "100.64.1.3".parse().unwrap())
            .await,
        None,
        "a certificate cannot negotiate from another peer's VIP"
    );
}

fn installed() -> InstalledPsk {
    InstalledPsk {
        transaction_id: [1; 16],
        public_key: CLIENT_KEY.into(),
        address: "100.64.1.2/32".into(),
        installed_at: std::time::Instant::now(),
        bytes_baseline: None,
    }
}

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn the_first_observation_only_sets_the_baseline() {
    let mut psk = installed();
    assert_eq!(psk.charge_transfer(500 * GIB), None);
    assert_eq!(psk.bytes_baseline, Some(500 * GIB));
    assert_eq!(psk.charge_transfer(599 * GIB), None, "99 GiB carried");
    assert!(psk.charge_transfer(600 * GIB).is_some(), "100 GiB carried");
}

#[test]
fn a_counter_that_went_backwards_rebases_instead_of_reclaiming() {
    let mut psk = installed();
    psk.charge_transfer(90 * GIB);
    assert_eq!(
        psk.charge_transfer(GIB),
        None,
        "peer re-created: counting restarts"
    );
    assert_eq!(psk.bytes_baseline, Some(GIB));
}

fn status(total: u64) -> helios_wireguard::PeerStatus {
    helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(CLIENT_KEY)
            .unwrap(),
        allowed_ips: Vec::new(),
        last_handshake: Some(std::time::SystemTime::now()),
        endpoint: None,
        rx_bytes: total / 2,
        tx_bytes: total - total / 2,
    }
}

#[tokio::test]
async fn a_committed_psk_is_reclaimed_at_its_byte_ceiling() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [40; 16], PUBLIC_SOURCE).await;

    assert!(
        handler.reclaimable(&[status(10 * GIB)]).await.is_empty(),
        "baseline"
    );
    assert!(
        handler.reclaimable(&[status(109 * GIB)]).await.is_empty(),
        "99 GiB"
    );
    let reclaimed = handler.reclaimable(&[status(110 * GIB)]).await;
    assert_eq!(reclaimed.len(), 1);
    assert!(
        reclaimed[0].2.contains("ceiling"),
        "the journal names the cause: {reclaimed:?}"
    );
}
