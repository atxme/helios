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
