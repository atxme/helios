//! Client TLS CA rotation tests.

use super::*;
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

fn client_tls_ca_transition(
    anchored: &Anchored,
    current_epoch: u64,
    active: Fingerprint,
) -> (
    TrustUpdateObject,
    aether::certificates::encoding::DerCertificate,
) {
    client_tls_ca_transition_with_window(
        anchored,
        current_epoch,
        active,
        "successor",
        TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
    )
}

fn client_tls_ca_transition_with_window(
    anchored: &Anchored,
    current_epoch: u64,
    active: Fingerprint,
    successor_name: &str,
    window: TransitionWindow,
) -> (
    TrustUpdateObject,
    aether::certificates::encoding::DerCertificate,
) {
    use aether::certificates::authority::ClientTlsCaTransition;

    let next = aether::certificates::test_x509::client_material(successor_name).authority;
    let object = ClientTlsCaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: anchored.registry.state().trust_domain_id,
        ca_epoch: 1,
        current_ca_tls_epoch: current_epoch,
        next_ca_tls_epoch: current_epoch + 1,
        active_client_tls_ca_fingerprint: active,
        next_client_tls_ca_certificate: next.clone(),
        window,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&anchored.ca_private)
    .expect("signing");
    (
        TrustUpdateObject::ClientTlsCaTransition(Box::new(object)),
        next,
    )
}

/// §9.4 was unverifiable while this registry pinned the epoch of that
/// anchor without pinning the anchor: the only value to compare
/// against came from the object itself.
#[test]
fn a_client_tls_ca_rotation_is_verified_against_the_pinned_anchor() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned by the fixture");
    let (object, next) = client_tls_ca_transition(&anchored, 1, active);

    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
            .expect("accepted"),
        1
    );
    assert_eq!(
        anchored.registry.state().ca_tls_rotation,
        Some(ClientTlsCaRotation {
            next_ca_tls_epoch: 2,
            next_ca_tls_fingerprint: next.fingerprint(),
            activation_at: 3_000,
            retire_active_at: 5_000,
        })
    );
}

#[test]
fn a_client_tls_ca_rotation_does_not_promote_before_not_after() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");
    let (object, next) = client_tls_ca_transition(&anchored, 1, active);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect("accepted");

    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(4_999)
            .expect("sweep before retirement"),
        0
    );
    assert_eq!(anchored.registry.state().ca_tls_epoch, 1);
    assert_eq!(anchored.registry.state().ca_tls_fingerprint, Some(active));
    assert!(anchored.registry.state().ca_tls_rotation.is_some());
    assert_eq!(anchored.registry.state().transitions.len(), 1);
    assert!(!active.matches(&next.fingerprint()));
}

#[test]
fn a_due_client_tls_ca_rotation_is_promoted_once_and_allows_the_next_rotation() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");
    let (first, first_successor) = client_tls_ca_transition(&anchored, 1, active);
    let first_successor_fingerprint = first_successor.fingerprint();
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
        .expect("first rotation accepted");

    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(5_000)
            .expect("promoted at retirement"),
        1
    );
    assert_eq!(anchored.registry.state().ca_tls_epoch, 2);
    assert_eq!(
        anchored.registry.state().ca_tls_fingerprint,
        Some(first_successor_fingerprint)
    );
    assert!(anchored.registry.state().ca_tls_rotation.is_none());
    assert!(anchored.registry.state().transitions.is_empty());

    anchored.registry = AstraRegistry::load(&anchored._directory.path().join("astra.json"), None)
        .expect("the promotion and removal were persisted together");
    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(5_000)
            .expect("second promotion is a no-op"),
        0
    );
    assert_eq!(anchored.registry.state().ca_tls_epoch, 2);
    assert_eq!(
        anchored.registry.state().ca_tls_fingerprint,
        Some(first_successor_fingerprint)
    );

    let (second, second_successor) = client_tls_ca_transition_with_window(
        &anchored,
        2,
        first_successor_fingerprint,
        "second-successor",
        TransitionWindow::new(6_000, 7_000, 8_000).expect("second window"),
    );
    let second_campaign = campaign(
        aether::certificates::status::CampaignScope::TrustAuthorities,
        vec![aether::certificates::status::CampaignTarget {
            certificate_kind: aether::certificates::status::CertificateKind::CaTls,
            identity_key: anchored.registry.state().gateway_wg_public_key,
            epoch: 2,
            generation: 2,
            active_tls_certificate_fingerprint: first_successor_fingerprint,
            active_pq_certificate_fingerprint: first_successor_fingerprint,
        }],
    );
    second_campaign
        .covers_authority_object(&second)
        .expect("the next campaign describes the promoted anchor");
    assert_eq!(
        anchored
            .registry
            .accept_transitions(&second_campaign, &[second], None, 6_500)
            .expect("second rotation accepted"),
        1
    );
    assert_eq!(
        anchored.registry.state().ca_tls_rotation,
        Some(ClientTlsCaRotation {
            next_ca_tls_epoch: 3,
            next_ca_tls_fingerprint: second_successor.fingerprint(),
            activation_at: 7_000,
            retire_active_at: 8_000,
        })
    );
}

#[test]
fn a_registry_recovers_a_stored_client_tls_ca_window_from_the_legacy_format() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");
    let (object, _) = client_tls_ca_transition(&anchored, 1, active);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect("accepted");
    let expected = anchored.registry.state().ca_tls_rotation.clone();
    let mut encoded = serde_json::to_value(anchored.registry.state()).expect("encoding");
    encoded
        .as_object_mut()
        .expect("registry object")
        .remove("ca_tls_rotation");
    let path = anchored._directory.path().join("astra.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&encoded).expect("legacy encoding"),
    )
    .expect("legacy registry written");

    let restored = AstraRegistry::load(&path, None).expect("legacy registry loaded");
    assert_eq!(restored.state().ca_tls_rotation, expected);
}

#[test]
fn a_second_client_tls_ca_rotation_is_refused_while_one_is_in_flight() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");
    let (first, _) = client_tls_ca_transition(&anchored, 1, active);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
        .expect("first accepted");
    let held = anchored.registry.state().ca_tls_rotation.clone();
    let (competing, _) = client_tls_ca_transition_with_window(
        &anchored,
        1,
        active,
        "competing-successor",
        TransitionWindow::new(1_000, 3_500, 5_500).expect("competing window"),
    );

    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[competing], None, 2_100)
        .is_err());
    assert_eq!(anchored.registry.state().ca_tls_rotation, held);
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

#[test]
fn a_client_tls_ca_rotation_over_another_anchor_is_refused() {
    let mut anchored = anchored();
    let (object, _) = client_tls_ca_transition(&anchored, 1, Fingerprint::of(b"another anchor"));

    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .is_err());
    assert!(anchored.registry.state().transitions.is_empty());
}

/// A domain bootstrapped before the pin existed is refused by name,
/// not checked against a placeholder that would always match.
#[test]
fn a_client_tls_ca_rotation_without_a_pinned_anchor_is_refused() {
    let anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");
    let (object, _) = client_tls_ca_transition(&anchored, 1, active);
    let mut unpinned = anchored.registry.state().clone();
    unpinned.ca_tls_fingerprint = None;
    let mut registry =
        AstraRegistry::new(anchored._directory.path().join("unpinned.json"), unpinned);

    let refusal = registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect_err("no anchor to verify against");
    assert!(format!("{refusal}").contains("pin-ca-tls"));
}

/// An anchor a command can overwrite is an anchor an operator error
/// can move; §9.4 makes that move a signed transition.
#[test]
fn a_pinned_client_tls_ca_is_not_replaced_by_a_command() {
    let mut anchored = anchored();
    let held = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("pinned");

    anchored
        .registry
        .pin_client_tls_ca(held, 2_000)
        .expect("idempotent");
    assert!(anchored
        .registry
        .pin_client_tls_ca(Fingerprint::of(b"elsewhere"), 2_000)
        .is_err());
    assert_eq!(anchored.registry.state().ca_tls_fingerprint, Some(held));
}

#[test]
fn a_legacy_registry_with_ambiguous_client_tls_ca_successors_is_refused() {
    let mut anchored = anchored();
    let active = anchored
        .registry
        .state()
        .ca_tls_fingerprint
        .expect("active CA-TLS fingerprint");
    let (first, _) = client_tls_ca_transition(&anchored, 1, active);
    let (competing, _) = client_tls_ca_transition_with_window(
        &anchored,
        1,
        active,
        "competing-successor",
        TransitionWindow::new(1_000, 3_500, 5_500).expect("competing window"),
    );
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
        .expect("first transition accepted");
    let mut competing_record = anchored.registry.state.transitions[0].clone();
    competing_record.object = competing;
    anchored.registry.state.transitions.push(competing_record);
    let mut encoded = serde_json::to_value(anchored.registry.state()).expect("encoding");
    encoded
        .as_object_mut()
        .expect("registry object")
        .remove("ca_tls_rotation");
    let path = anchored._directory.path().join("astra.json");
    let bytes = serde_json::to_vec_pretty(&encoded).expect("legacy encoding");
    std::fs::write(&path, &bytes).expect("legacy registry written");
    for result in [
        AstraRegistry::load(&path, None).map(|_| ()),
        AstraRegistry::read_state(&path, None).map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(RegistryError::Corrupt(message)) if message.contains("multiple client CA-TLS rotations target the active epoch"))
        );
    }
    assert_eq!(std::fs::read(&path).expect("read unchanged file"), bytes);
}
