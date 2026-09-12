//! Registry trust-transition, peer revocation, and retention tests.

use super::*;
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

fn admitted(anchored: &mut Anchored) -> WireGuardKey {
    let client = WireGuardKey::from_bytes([5; 32]);
    anchored.registry.state.peers.insert(
        client.to_base64(),
        PeerRecord {
            name: "compromised workstation".into(),
            client_wg_public_key: client,
            active: generation(3),
            active_pq_certificate: certificate(),
            pending: Some(PendingRotation {
                stage_id: Id16::new([4; 16]).expect("stage"),
                request_fingerprint: Fingerprint::of(b"request"),
                candidate: generation(4),
                window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                stage_expires_at: 3_000,
                granted: false,
            }),
            revoked: false,
            revocation_epoch: 0,
            admission_pq_ca: None,
        },
    );
    client
}

fn revocation(
    anchored: &Anchored,
    client: WireGuardKey,
    effective_at: u64,
    not_after: u64,
) -> TrustUpdateObject {
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let active = generation(3);
    let object = EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: anchored.registry.state().trust_domain_id,
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: client,
        server_name: None,
        revocation_epoch: 1,
        revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
        revoked_tls_not_after: Some(not_after),
        revoked_pq_fingerprint: Some(active.pq_certificate_fingerprint),
        revoked_pq_not_after: Some(not_after),
        effective_at,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("signing");
    TrustUpdateObject::CertificateRevocation(Box::new(object))
}

/// The one property that lets an online authority hold `CA-PQ` output
/// at all: it re-derives the proof under the anchor it already pins.
#[test]
fn a_transition_is_verified_under_the_anchor_this_registry_pins() {
    let mut anchored = anchored();
    let object = transition(&anchored, 1);
    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
            .expect("accepted"),
        1
    );
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

/// A transition leaving another epoch, or signed by another anchor, is
/// refused — the check is the object's own `verify`, run here.
#[test]
fn a_transition_this_domain_did_not_authorize_is_refused() {
    let mut anchored = anchored();
    let wrong_epoch = transition(&anchored, 2);
    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[wrong_epoch], None, 2_000)
        .is_err());

    let other_domain = self::anchored();
    let foreign = transition(&other_domain, 1);
    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[foreign], None, 2_000)
        .is_err());
    assert!(anchored.registry.state().transitions.is_empty());
}

/// A companion that retries after a lost response must not make a peer
/// collect the same transition under two fingerprints.
#[test]
fn depositing_the_same_transition_twice_stores_it_once() {
    let mut anchored = anchored();
    let object = transition(&anchored, 1);
    assert_eq!(
        anchored
            .registry
            .accept_transitions(
                &anchor_campaign(),
                std::slice::from_ref(&object),
                None,
                2_000
            )
            .expect("accepted"),
        1
    );
    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, 2_100)
            .expect("replayed"),
        0
    );
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

#[test]
fn an_accepted_revocation_is_terminal_and_cancels_staging() {
    let mut anchored = anchored();
    let client = admitted(&mut anchored);
    let object = revocation(&anchored, client, 2_000, generation(3).not_after);
    assert_eq!(
        anchored
            .registry
            .accept_transitions(
                &anchor_campaign(),
                std::slice::from_ref(&object),
                None,
                2_000,
            )
            .expect("accepted"),
        1
    );
    let peer = &anchored.registry.state().peers[&client.to_base64()];
    assert!(peer.revoked);
    assert_eq!(peer.revocation_epoch, 1);
    assert!(peer.pending.is_none());

    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, 2_100)
            .expect("identical retry"),
        0
    );
}

#[test]
fn a_revocation_with_a_retyped_expiry_or_future_effect_is_refused_atomically() {
    let mut anchored = anchored();
    let client = admitted(&mut anchored);
    let wrong_expiry = revocation(&anchored, client, 2_000, 99_999);
    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[wrong_expiry], None, 2_000)
        .is_err());
    let future = revocation(&anchored, client, 2_001, generation(3).not_after);
    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[future], None, 2_000)
        .is_err());
    let peer = &anchored.registry.state().peers[&client.to_base64()];
    assert!(!peer.revoked);
    assert!(anchored.registry.state().transitions.is_empty());
}

#[test]
fn a_revocation_is_retained_until_its_signed_expiry() {
    let mut anchored = anchored();
    let client = admitted(&mut anchored);
    let expiry = generation(3).not_after;
    let object = revocation(&anchored, client, 2_000, expiry);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect("accepted");
    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(expiry - 1)
            .expect("sweep"),
        0
    );
    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(expiry)
            .expect("sweep"),
        1
    );
}
