use super::*;
use aether::certificates::transport::{TrustUpdateObject, TrustUpdateRequest};
use astra_channel::RelayedTrustUpdatePreparation;

async fn request(fixture: &Fixture, issuer_epoch: u64) -> RelayedTrustUpdatePreparation {
    let peer = fixture.gateway.view.lock().await.clone();
    let active = &peer.state.active;
    let request = TrustUpdateRequest {
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([0x98; 16]).expect("request ID"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        ca_epoch: 1,
        ca_tls_epoch: active.ca_tls_epoch,
        astra_service_key_epoch: 1,
        issuer_epoch,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        client_identity_generation: active.generation,
        active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway TLS"),
        active_gateway_certificate_fingerprint: pq_certificate_fingerprint(
            &fixture.gateway.gateway_leaf,
        )
        .expect("gateway fingerprint"),
        active_client_tls_certificate_fingerprint: active.tls_certificate_fingerprint,
        active_client_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
        client_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
        base_state_fingerprint: Fingerprint::of(b"client's opaque local trust state"),
    }
    .authenticate(peer.active_pq_certificate.clone(), &fixture.active_private)
    .expect("signed trust update request");
    RelayedTrustUpdatePreparation {
        caller_wg_public_key: client_key(),
        request: Box::new(request),
        peer: Box::new(peer),
    }
}

#[tokio::test]
async fn a_lagging_peer_gets_a_service_signed_transaction_bound_to_its_state() {
    let fixture = fixture().await;
    record_delegation(&fixture, 2).await;
    let relayed = request(&fixture, 1).await;

    let (manifest, chunks) = crate::distribution::prepare(&fixture.service, &relayed, NOW)
        .await
        .expect("authenticated request")
        .expect("a newer delegation is available");
    let base_state = relayed.request.request.base_state_fingerprint;
    manifest
        .verify(
            &fixture.service.service_public_key,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            &base_state,
            NOW,
        )
        .expect("service signature covers this peer and its local trust state");

    assert_eq!(
        manifest.expires_at,
        NOW + crate::distribution::TRANSACTION_LIFETIME_SECS
    );
    assert_eq!(manifest.objects.len(), 1);
    assert_eq!(chunks.len(), 1);
    assert!(matches!(
        chunks[0].objects.as_slice(),
        [TrustUpdateObject::AstraIssuerAuthorization(authorization)] if authorization.issuer_epoch == 2
    ));
}

#[tokio::test]
async fn a_peer_already_on_the_current_delegation_gets_no_transaction() {
    let fixture = fixture().await;
    record_delegation(&fixture, 2).await;
    let relayed = request(&fixture, 2).await;

    assert!(
        crate::distribution::prepare(&fixture.service, &relayed, NOW)
            .await
            .expect("authenticated request")
            .is_none()
    );
}

#[tokio::test]
async fn a_relay_cannot_substitute_the_active_snapshot_fingerprint() {
    use crate::distribution::PrepareError;

    let fixture = fixture().await;
    let mut relayed = request(&fixture, 1).await;
    let before = std::fs::read(fixture.registry_path()).expect("initial registry");
    relayed.peer.state.active.pq_certificate_fingerprint =
        Fingerprint::of(b"different active leaf");

    assert!(matches!(
        crate::distribution::prepare(&fixture.service, &relayed, NOW).await,
        Err(PrepareError::PeerMismatch)
    ));
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry"),
        before
    );
}

#[tokio::test]
async fn changing_the_local_state_token_after_signature_refuses_the_request() {
    use crate::distribution::PrepareError;

    let fixture = fixture().await;
    record_delegation(&fixture, 2).await;
    let mut relayed = request(&fixture, 1).await;
    relayed.request.request.base_state_fingerprint = Fingerprint::of(b"modified trust state");

    assert!(matches!(
        crate::distribution::prepare(&fixture.service, &relayed, NOW).await,
        Err(PrepareError::Request(_))
    ));
}
