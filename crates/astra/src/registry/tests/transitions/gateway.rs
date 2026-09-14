//! Gateway identity transition and gateway revocation tests.

use super::*;
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

pub(super) fn gateway_campaign(
    epoch: u64,
    tls: Fingerprint,
    pq: Fingerprint,
) -> aether::certificates::status::AstraRotationCampaign {
    campaign(
        aether::certificates::status::CampaignScope::GatewayIdentity,
        vec![aether::certificates::status::CampaignTarget {
            certificate_kind: aether::certificates::status::CertificateKind::GatewayPq,
            identity_key: WireGuardKey::from_bytes([1; 32]),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: tls,
            active_pq_certificate_fingerprint: pq,
        }],
    )
}

/// The leaf a transition installs. A decision that installs neither
/// half is refused as empty, and rightly: it would consume an epoch
/// and move nothing.
fn gateway_leaf(anchored: &Anchored, epoch: u64) -> PqCertificate {
    use base64::Engine as _;

    let (_, subject) = generate_ml_dsa_87_keypair().expect("keygen");
    aether::key_negotiation::issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [epoch as u8; 16],
            subject: "gateway.example".into(),
            issuer: "helios-ca-pq".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([1; 32]).to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                .encode(subject.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        },
        &anchored.ca_private,
    )
    .expect("issue")
}

pub(super) fn gateway_transition(
    anchored: &Anchored,
    epoch: u64,
    tls: Fingerprint,
    pq: Fingerprint,
) -> TrustUpdateObject {
    use aether::certificates::authority::RotationReason;
    use aether::certificates::gateway::GatewayIdentityTransition;

    let object = GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: anchored.registry.state().trust_domain_id,
        ca_epoch: 1,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        active_gateway_tls_certificate_fingerprint: tls,
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: pq,
        next_gateway_certificate: Some(gateway_leaf(anchored, epoch)),
        window: TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
        reason: RotationReason::Scheduled,
        ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("signing");
    TrustUpdateObject::GatewayIdentityTransition(Box::new(object))
}

fn gateway_abort(
    anchored: &Anchored,
    transition: &TrustUpdateObject,
    aborted_at: u64,
) -> TrustUpdateObject {
    use aether::certificates::gateway::{AbortReason, GatewayTransitionAbort};

    let TrustUpdateObject::GatewayIdentityTransition(cancelled) = transition else {
        panic!("not a gateway transition");
    };
    let object = GatewayTransitionAbort {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: anchored.registry.state().trust_domain_id,
        ca_epoch: 1,
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        gateway_identity_epoch: cancelled.gateway_identity_epoch,
        gateway_transition_fingerprint: cancelled.fingerprint().expect("fingerprint"),
        aborted_at,
        reason: AbortReason::OperatorCancelled,
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("signing");
    TrustUpdateObject::GatewayTransitionAbort(Box::new(object))
}

/// A gateway revocation belongs to the **revocation** family, not to
/// the gateway-identity one: it withdraws a leaf, it does not move an
/// identity forward, and the two refuse each other's objects.
fn gateway_revocation_campaign(
    epoch: u64,
    tls: Fingerprint,
    pq: Fingerprint,
) -> aether::certificates::status::AstraRotationCampaign {
    campaign(
        aether::certificates::status::CampaignScope::EmergencyRevocation,
        vec![aether::certificates::status::CampaignTarget {
            certificate_kind: aether::certificates::status::CertificateKind::GatewayPq,
            identity_key: WireGuardKey::from_bytes([1; 32]),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: tls,
            active_pq_certificate_fingerprint: pq,
        }],
    )
}

fn gateway_revocation(
    anchored: &Anchored,
    revocation_epoch: u64,
    tls: Fingerprint,
    pq: Fingerprint,
    effective_at: u64,
) -> TrustUpdateObject {
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let object = EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: anchored.registry.state().trust_domain_id,
        ca_epoch: 1,
        scope: RevocationScope::Gateway,
        identity_key: WireGuardKey::from_bytes([1; 32]),
        server_name: Some("gateway.example".into()),
        revocation_epoch,
        revoked_tls_fingerprint: Some(tls),
        revoked_tls_not_after: Some(200_000),
        revoked_pq_fingerprint: Some(pq),
        revoked_pq_not_after: Some(300_000),
        effective_at,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("signing");
    TrustUpdateObject::CertificateRevocation(Box::new(object))
}

/// The gateway's leaves were never recorded here, so the campaign is
/// the only place their state is pinned — as for a transition.
#[test]
fn a_gateway_revocation_is_stored_against_the_campaign_that_froze_it() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let object = gateway_revocation(&anchored, 5, tls, pq, 2_000);

    assert_eq!(
        anchored
            .registry
            .accept_transitions(
                &gateway_revocation_campaign(4, tls, pq),
                &[object],
                None,
                2_000,
            )
            .expect("accepted"),
        1
    );
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

/// A leaf the operator never read, under a signature that verifies.
#[test]
fn a_gateway_revocation_over_another_leaf_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let elsewhere = gateway_revocation(&anchored, 5, tls, Fingerprint::of(b"another leaf"), 2_000);

    assert!(anchored
        .registry
        .accept_transitions(
            &gateway_revocation_campaign(4, tls, pq),
            &[elsewhere],
            None,
            2_000,
        )
        .is_err());
    assert!(anchored.registry.state().transitions.is_empty());
}

/// The two gateway families refuse each other: withdrawing a leaf and
/// moving an identity forward are not the same decision, and one
/// approved text must not authorise the other.
#[test]
fn a_gateway_revocation_under_an_identity_campaign_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let object = gateway_revocation(&anchored, 5, tls, pq, 2_000);

    assert!(anchored
        .registry
        .accept_transitions(&gateway_campaign(4, tls, pq), &[object], None, 2_000)
        .is_err());
}

/// §10.2: a consumed counter never comes back down.
#[test]
fn a_gateway_revocation_replaying_a_counter_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let replayed = gateway_revocation(&anchored, 4, tls, pq, 2_000);

    assert!(anchored
        .registry
        .accept_transitions(
            &gateway_revocation_campaign(4, tls, pq),
            &[replayed],
            None,
            2_000,
        )
        .is_err());
}

/// A decision dated in the future is not this authority's to hold.
#[test]
fn a_gateway_revocation_that_is_not_yet_effective_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let later = gateway_revocation(&anchored, 5, tls, pq, 9_000);

    assert!(anchored
        .registry
        .accept_transitions(
            &gateway_revocation_campaign(4, tls, pq),
            &[later],
            None,
            2_000,
        )
        .is_err());
}

/// This authority holds no gateway leaf, so the approved text is the
/// only place the state a decision was taken against is pinned.
#[test]
fn a_gateway_transition_is_stored_against_the_campaign_that_froze_it() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let object = gateway_transition(&anchored, 5, tls, pq);

    assert_eq!(
        anchored
            .registry
            .accept_transitions(&gateway_campaign(4, tls, pq), &[object], None, 2_000)
            .expect("accepted"),
        1
    );
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

/// A leaf the operator never read, under a signature that verifies.
#[test]
fn a_gateway_transition_over_another_leaf_in_service_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let elsewhere = gateway_transition(&anchored, 5, tls, Fingerprint::of(b"another leaf"));

    assert!(anchored
        .registry
        .accept_transitions(&gateway_campaign(4, tls, pq), &[elsewhere], None, 2_000)
        .is_err());
    assert!(anchored.registry.state().transitions.is_empty());
}

/// An abort is verified against the exact document it cancels, so that
/// document has to be here — not promised for later.
#[test]
fn an_abort_without_its_transition_is_refused() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let transition = gateway_transition(&anchored, 5, tls, pq);
    let abort = gateway_abort(&anchored, &transition, 2_100);

    assert!(anchored
        .registry
        .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
        .is_err());
}

/// §6.3, at the authority: past the publication no abort is
/// legitimate, because a client may already hold the decision.
#[test]
fn an_abort_is_refused_once_the_transition_has_been_published() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let transition = gateway_transition(&anchored, 5, tls, pq);
    anchored
        .registry
        .accept_transitions(
            &gateway_campaign(4, tls, pq),
            std::slice::from_ref(&transition),
            None,
            2_000,
        )
        .expect("staged");
    anchored
        .registry
        .publish_gateway_transition(5, 2_050)
        .expect("published");
    let abort = gateway_abort(&anchored, &transition, 2_100);

    assert!(anchored
        .registry
        .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
        .is_err());
}

/// A cancelled decision never becomes publishable again.
#[test]
fn an_aborted_transition_is_not_published_afterwards() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let transition = gateway_transition(&anchored, 5, tls, pq);
    anchored
        .registry
        .accept_transitions(
            &gateway_campaign(4, tls, pq),
            std::slice::from_ref(&transition),
            None,
            2_000,
        )
        .expect("staged");
    let abort = gateway_abort(&anchored, &transition, 2_100);
    anchored
        .registry
        .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
        .expect("cancelled");

    assert!(anchored
        .registry
        .publish_gateway_transition(5, 2_300)
        .is_err());
}

#[test]
fn an_abort_cancels_the_transition_already_stored() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    let transition = gateway_transition(&anchored, 5, tls, pq);
    anchored
        .registry
        .accept_transitions(
            &gateway_campaign(4, tls, pq),
            std::slice::from_ref(&transition),
            None,
            2_000,
        )
        .expect("staged");
    let abort = gateway_abort(&anchored, &transition, 2_100);

    assert_eq!(
        anchored
            .registry
            .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
            .expect("cancelled"),
        1
    );
    assert_eq!(anchored.registry.state().transitions.len(), 2);
}

/// The ceiling refuses rather than evicting: dropping the oldest would
/// drop the one a lagging peer is still missing.
#[test]
fn the_store_refuses_rather_than_dropping_what_a_peer_still_needs() {
    let mut anchored = anchored();
    let tls = Fingerprint::of(b"gateway tls in service");
    let pq = Fingerprint::of(b"gateway pq in service");
    for index in 0..MAX_STORED_TRANSITIONS {
        let active_epoch = index as u64 + 1;
        let object = gateway_transition(&anchored, active_epoch + 1, tls, pq);
        anchored
            .registry
            .accept_transitions(
                &gateway_campaign(active_epoch, tls, pq),
                &[object],
                None,
                2_000 + index as u64,
            )
            .expect("accepted");
    }
    let active_epoch = MAX_STORED_TRANSITIONS as u64 + 1;
    let overflow = gateway_transition(&anchored, active_epoch + 1, tls, pq);
    assert!(matches!(
        anchored.registry.accept_transitions(
            &gateway_campaign(active_epoch, tls, pq),
            &[overflow],
            None,
            3_000,
        ),
        Err(RegistryError::TransitionStoreFull { .. })
    ));
    assert_eq!(
        anchored.registry.state().transitions.len(),
        MAX_STORED_TRANSITIONS
    );
}
