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

fn client_tls_transition(
    anchored: &Anchored,
    window: TransitionWindow,
) -> (TrustUpdateObject, Fingerprint) {
    use aether::certificates::authority::ClientTlsCaTransition;

    let next = aether::certificates::test_x509::client_material("retained-successor").authority;
    let next_fingerprint = next.fingerprint();
    let state = anchored.registry.state();
    let object = ClientTlsCaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: state.trust_domain_id,
        ca_epoch: state.ca_epoch,
        current_ca_tls_epoch: state.ca_tls_epoch,
        next_ca_tls_epoch: state.ca_tls_epoch + 1,
        active_client_tls_ca_fingerprint: state
            .ca_tls_fingerprint
            .expect("the fixture pins client CA-TLS"),
        next_client_tls_ca_certificate: next,
        window,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("sign client CA-TLS transition");
    (
        TrustUpdateObject::ClientTlsCaTransition(Box::new(object)),
        next_fingerprint,
    )
}

/// A later deposit prunes the expired CA-TLS object but leaves its slot live
/// until the sweep. A restart must preserve that slot and promote it at expiry.
#[test]
fn an_expired_tls_transition_pruned_by_another_deposit_does_not_drop_its_slot() {
    let mut anchored = anchored();
    let (tls, expected_tls_fingerprint) = client_tls_transition(
        &anchored,
        TransitionWindow::new(1_000, 2_000, 3_000).expect("short TLS window"),
    );
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[tls], None, 2_000)
        .expect("accept CA-TLS transition");
    let accepted_tls_slot = anchored
        .registry
        .state()
        .ca_tls_rotation
        .clone()
        .expect("CA-TLS slot opened");

    // Deposit CA-PQ at the TLS object's retirement instant, before the
    // periodic expiry sweep has run. The PQ decision is still within its own
    // long window, while this deposit's normal retention pass prunes TLS.
    let pq = transition(&anchored, 1);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[pq], None, 3_000)
        .expect("accept CA-PQ transition");

    assert_eq!(
        anchored.registry.state().ca_tls_rotation,
        Some(accepted_tls_slot.clone())
    );
    assert_eq!(anchored.registry.state().transitions.len(), 1);
    assert!(matches!(
        &anchored.registry.state().transitions[0].object,
        TrustUpdateObject::CaTransition(_)
    ));

    let path = anchored._directory.path().join("astra.json");
    let restored = AstraRegistry::load(&path, None)
        .expect("a slot remains valid after its delivery object was pruned");
    assert_eq!(restored.state().ca_epoch, 1);
    assert_eq!(restored.state().ca_tls_epoch, 1);
    assert_eq!(
        restored.state().ca_tls_rotation,
        Some(accepted_tls_slot.clone())
    );
    assert_eq!(restored.state().transitions.len(), 1);

    let mut restored = restored;
    restored
        .forget_expired_transitions(3_000)
        .expect("promote the retained CA-TLS slot");
    assert_eq!(restored.state().ca_epoch, 1);
    assert_eq!(restored.state().ca_tls_epoch, 2);
    assert_eq!(
        restored.state().ca_tls_fingerprint,
        Some(expected_tls_fingerprint)
    );
    assert!(restored.state().ca_tls_rotation.is_none());
    assert_eq!(restored.state().transitions.len(), 1);
}

/// CA-TLS can remain in overlap after the CA-PQ signer retires. Its explicit
/// slot survives restart even though its retained object names the old PQ epoch.
#[test]
fn ca_tls_rotation_survives_restart_after_its_signing_ca_is_promoted() {
    let mut anchored = anchored();
    let pq = transition(&anchored, 1); // retires at 200_000
    let (tls, next_tls_fingerprint) = client_tls_transition(
        &anchored,
        TransitionWindow::new(1_000, 250_000, 300_000).expect("TLS window"),
    );
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[pq, tls], None, 2_000)
        .expect("accept overlapping CA-PQ and CA-TLS rotations");

    assert!(anchored.registry.state().ca_rotation.is_some());
    assert_eq!(
        anchored
            .registry
            .state()
            .ca_tls_rotation
            .as_ref()
            .expect("TLS slot opened")
            .next_ca_tls_fingerprint,
        next_tls_fingerprint
    );
    assert_eq!(anchored.registry.state().transitions.len(), 2);

    // CA-PQ retires first. This prunes its own signed object but keeps the
    // longer-lived TLS object and slot; the latter was signed at ca_epoch 1.
    anchored
        .registry
        .forget_expired_transitions(200_000)
        .expect("promote CA-PQ first");
    assert_eq!(anchored.registry.state().ca_epoch, 2);
    assert!(anchored.registry.state().ca_rotation.is_none());
    assert!(anchored.registry.state().ca_tls_rotation.is_some());
    assert_eq!(anchored.registry.state().transitions.len(), 1);

    let path = anchored._directory.path().join("astra.json");
    let mut restored = AstraRegistry::load(&path, None)
        .expect("retain the already-accepted TLS decision under its old signer");
    assert_eq!(restored.state().ca_epoch, 2);
    assert_eq!(restored.state().ca_tls_epoch, 1);
    assert!(restored.state().ca_tls_rotation.is_some());
    assert_eq!(restored.state().transitions.len(), 1);

    restored
        .forget_expired_transitions(300_000)
        .expect("promote CA-TLS after its own overlap");
    assert_eq!(restored.state().ca_epoch, 2);
    assert_eq!(restored.state().ca_tls_epoch, 2);
    assert_eq!(
        restored.state().ca_tls_fingerprint,
        Some(next_tls_fingerprint)
    );
    assert!(restored.state().ca_tls_rotation.is_none());
    assert!(restored.state().transitions.is_empty());
}
