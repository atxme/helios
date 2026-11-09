//! A client revocation during a `CA-PQ` overlap (F14 lot 5c, spec §5.4).
//!
//! The overlap keeps the outgoing anchor in two places: Astra verifies under
//! `state.ca_public_key` until the rotation retires it, and the gateway holds
//! the same key as `state.gateway.current_ca_public_key`, installed by the
//! signed `CaTransition` the rotation describes. A revocation signed with the
//! outgoing key, under its `ca_epoch`, must pass both, and stop passing once
//! the gateway promotes at `ca_retire_active_at`.
//!
//! Signing mirrors `astra-operator`'s `sign_revocation` under
//! `RevocationAnchor::Outgoing`. This file does not depend on `astra-operator`
//! or `heliosd`: the gateway state is aether's own type, built as a literal
//! (every field is public) and driven through its public transition methods.

use aether::certificates::approval::CredentialRegistry;
use aether::certificates::authority::CaTransition;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, MlDsa87Signature,
};
use aether::certificates::revocation::{
    EmergencyCertificateRevocation, RevocationReason, RevocationScope,
};
use aether::certificates::state::{GatewayCertificateState, TrustLedger};
use aether::certificates::status::{AstraSignerResult, CampaignApproval};
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

use super::tunnel::{approving_credential, assertion_for, submit_token};
use super::*;
use crate::registry::CaPqRotation;
use crate::service::ApprovalCredentials;

/// The outgoing `CA-PQ` epoch, which Astra serves until the rotation retires it.
const OUTGOING_EPOCH: u64 = 1;

#[tokio::test]
async fn a_revocation_during_a_ca_pq_overlap_is_accepted_by_astra_and_the_gateway() {
    let dir = tempfile::tempdir().expect("tempdir");
    let domain = TrustDomainId::new([1; 16]).expect("domain");

    // The outgoing key, kept by the vault and served by Astra; the incoming
    // key, accepted by the rotation and not yet active.
    let (outgoing_private, outgoing_public) = generate_ml_dsa_87_keypair().expect("outgoing");
    let (incoming_private, incoming_public) = generate_ml_dsa_87_keypair().expect("incoming");

    let channel = gateway_channel(
        dir.path(),
        FakeGateway {
            accepts_revocations: true,
            ..Default::default()
        },
    )
    .await;
    let mut built = build_service_with_ca(dir.path(), None, Some(channel)).0;
    // The served document: the outgoing key's, at the outgoing epoch.
    let (credential_key, binding) = approving_credential(&outgoing_private, 1);
    built.approval_credentials = RwLock::new(Arc::new(ApprovalCredentials {
        ids: vec![binding.credential_id.clone()],
        epoch: 1,
        registry: Some(Box::new(CredentialRegistry {
            trust_domain_id: domain,
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            ca_epoch: OUTGOING_EPOCH,
            credential_registry_epoch: 1,
            bindings: vec![binding.clone()],
        })),
    }));
    let service = Arc::new(built);
    // Domain state: the rotation is accepted, Astra still on the outgoing
    // anchor, and `not_after` is in the future.
    rewrite_registry(&service, |state| {
        state.ca_public_key = outgoing_public.clone();
        state.ca_epoch = OUTGOING_EPOCH;
        state.ca_rotation = Some(CaPqRotation {
            next_ca_epoch: OUTGOING_EPOCH + 1,
            next_ca_public_key: incoming_public.clone(),
            activation_at: NOW - 100,
            retire_active_at: NOW + 10_000,
        });
    })
    .await;

    // The operator opens the client revocation through the door, and approves
    // it under the document Astra serves.
    let opened = opened(service.door(console(), revocation(2), NOW).await);
    let campaign = campaign_of(&service, &opened).await;
    let (tls, pq, not_after, epoch) = {
        let registry = service.registry.lock().await;
        let record = &registry.state().peers[&peer_key(2).to_base64()];
        (
            record.active.tls_certificate_fingerprint,
            record.active.pq_certificate_fingerprint,
            record.active.not_after,
            record.revocation_epoch,
        )
    };

    // Signed under the outgoing key and epoch, as `sign_revocation` does for
    // `RevocationAnchor::Outgoing`.
    let signed = EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain,
        ca_epoch: OUTGOING_EPOCH,
        scope: RevocationScope::Client,
        identity_key: peer_key(2),
        server_name: None,
        revocation_epoch: epoch + 1,
        revoked_tls_fingerprint: Some(tls),
        revoked_tls_not_after: Some(not_after),
        revoked_pq_fingerprint: Some(pq),
        revoked_pq_not_after: Some(not_after),
        effective_at: NOW,
        reason: RevocationReason::Cessation,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&outgoing_private)
    .expect("signed under the outgoing CA-PQ");

    // Astra accepts the deposit: the relay to the gateway succeeds, and the
    // peer is withdrawn.
    let result = Box::new(AstraSignerResult {
        format_version: CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(CampaignApproval {
            campaign_id: campaign.campaign_id,
            campaign_fingerprint: campaign.fingerprint(),
            required_credentials: campaign.required_credentials,
            approved_at: NOW,
            approvals: vec![assertion_for(&credential_key, &binding, &campaign)],
        }),
        objects: vec![TrustUpdateObject::CertificateRevocation(Box::new(
            signed.clone(),
        ))],
        credential_registry: None,
        issuer_authorization: None,
    });
    let token = submit_token(&service, &opened.operation_id).await;
    crate::service::operator_signer_result(&service, &opened.operation_id, &token, result, NOW)
        .await
        .expect("the deposit is accepted during the overlap");
    assert!(
        service.registry.lock().await.state().peers[&peer_key(2).to_base64()].revoked,
        "Astra holds the peer as revoked"
    );

    // The gateway's own state. The CA-PQ transition the rotation describes is
    // signed by both anchors and applied before its activation, as heliosd
    // installs it; the gateway then holds the outgoing anchor until
    // `ca_retire_active_at`.
    let window = TransitionWindow::new(NOW - 1_000, NOW - 100, NOW + 10_000).expect("window");
    let transition = CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain,
        current_ca_epoch: OUTGOING_EPOCH,
        next_ca_epoch: OUTGOING_EPOCH + 1,
        current_ca_fingerprint: outgoing_public.authority_fingerprint(),
        next_ca_public_key: incoming_public.clone(),
        next_ca_fingerprint: incoming_public.authority_fingerprint(),
        window,
        current_ca_signature: MlDsa87Signature::placeholder(),
        next_ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&outgoing_private, &incoming_private)
    .expect("signed by both anchors");
    let mut gateway = GatewayCertificateState {
        trust_domain_id: domain,
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        ca_epoch: OUTGOING_EPOCH,
        current_ca_public_key: outgoing_public.clone(),
        next_ca_public_key: None,
        next_ca_transition_fingerprint: None,
        ca_activation_at: None,
        ca_retire_active_at: None,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        next_gateway_identity_epoch: None,
        next_transition_fingerprint: None,
        last_aborted_transition: None,
        active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate: PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [3; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([1; 32]).to_base64(),
            ml_dsa_87_public_key: String::new(),
            not_before_unix: 0,
            not_after_unix: NOW * 2,
            ml_dsa_87_signature: String::new(),
        },
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: false,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    };
    gateway
        .apply_ca_transition(&transition, &TrustLedger::default(), NOW - 200)
        .expect("the overlap installs");
    assert!(
        !gateway.promote_ca_if_due(NOW),
        "the outgoing anchor still serves inside the overlap"
    );

    // The gateway side: the check heliosd's `revoke` runs
    // (`heliosd/src/certificates/astra.rs`), under the gateway's current
    // anchor, its `ca_epoch`, and the peer's current revocation epoch.
    let verify_as_gateway = |gateway: &GatewayCertificateState| {
        signed.verify(
            &gateway.current_ca_public_key,
            &gateway.trust_domain_id,
            gateway.ca_epoch,
            epoch,
        )
    };
    verify_as_gateway(&gateway).expect("the gateway verifies it under its current anchor");
    // The anchor is what makes it pass: the incoming key does not verify it.
    assert!(signed
        .verify(&incoming_public, &domain, OUTGOING_EPOCH, epoch)
        .is_err());

    // The window is pinned: still valid one second before `ca_retire_active_at`,
    // and refused once the gateway promotes.
    assert!(!gateway.promote_ca_if_due(NOW + 9_999));
    verify_as_gateway(&gateway).expect("still verifies one second before retirement");
    assert!(gateway.promote_ca_if_due(NOW + 10_000));
    assert_eq!(gateway.ca_epoch, OUTGOING_EPOCH + 1);
    assert!(
        verify_as_gateway(&gateway).is_err(),
        "the outgoing revocation does not verify under the promoted anchor"
    );
}
