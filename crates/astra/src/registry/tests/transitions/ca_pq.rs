//! CA-PQ rotation tests.

use super::*;
use aether::certificates::authority::CaTransition;
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

fn transition_from(
    registry: &AstraRegistry,
    current_private: &[u8],
    current_public: &MlDsa87PublicKey,
    current_epoch: u64,
    window: TransitionWindow,
) -> (
    TrustUpdateObject,
    zeroize::Zeroizing<Vec<u8>>,
    MlDsa87PublicKey,
) {
    let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let transition = CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: registry.state().trust_domain_id,
        current_ca_epoch: current_epoch,
        next_ca_epoch: current_epoch + 1,
        current_ca_fingerprint: current_public.authority_fingerprint(),
        next_ca_fingerprint: next_public.authority_fingerprint(),
        next_ca_public_key: next_public.clone(),
        window,
        current_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        next_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(current_private, &next_private)
    .expect("signing");
    (
        TrustUpdateObject::CaTransition(Box::new(transition)),
        next_private,
        next_public,
    )
}

pub(super) fn transition(anchored: &Anchored, current_epoch: u64) -> TrustUpdateObject {
    transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        current_epoch,
        TransitionWindow::new(1_000, 90_000, 200_000).expect("window"),
    )
    .0
}

#[test]
fn a_ca_pq_rotation_opens_an_active_next_window() {
    let mut anchored = anchored();
    let (object, _, next) = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
    );

    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
            .expect("accepted"),
        1
    );
    assert_eq!(anchored.registry.state().ca_epoch, 1);
    assert_eq!(anchored.registry.state().ca_public_key, anchored.ca_public);
    assert_eq!(
        anchored.registry.state().ca_rotation,
        Some(CaPqRotation {
            next_ca_epoch: 2,
            next_ca_public_key: next,
            activation_at: 3_000,
            retire_active_at: 5_000,
        })
    );
}

#[test]
fn a_ca_pq_rotation_does_not_promote_before_not_after() {
    let mut anchored = anchored();
    let object = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
    )
    .0;
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
    assert_eq!(anchored.registry.state().ca_epoch, 1);
    assert_eq!(anchored.registry.state().ca_public_key, anchored.ca_public);
    assert!(anchored.registry.state().ca_rotation.is_some());
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

#[test]
fn a_due_ca_pq_rotation_is_promoted_once_and_allows_the_next_rotation() {
    let mut anchored = anchored();
    let (first, first_successor_private, first_successor_public) = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_000, 5_000).expect("first window"),
    );
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
    assert_eq!(anchored.registry.state().ca_epoch, 2);
    assert_eq!(
        anchored.registry.state().ca_public_key,
        first_successor_public
    );
    assert!(anchored.registry.state().ca_rotation.is_none());
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
    assert_eq!(anchored.registry.state().ca_epoch, 2);

    let (second, _, second_successor_public) = transition_from(
        &anchored.registry,
        &first_successor_private,
        &first_successor_public,
        2,
        TransitionWindow::new(6_000, 7_000, 8_000).expect("second window"),
    );
    assert_eq!(
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[second], None, 6_500)
            .expect("second rotation accepted"),
        1
    );
    assert_eq!(
        anchored.registry.state().ca_rotation,
        Some(CaPqRotation {
            next_ca_epoch: 3,
            next_ca_public_key: second_successor_public,
            activation_at: 7_000,
            retire_active_at: 8_000,
        })
    );
}

/// Three offline CA transitions in a row, and never three anchors
/// (spec §14.1).
///
/// The bound is what makes an offline rotation safe to repeat: between
/// two of them the registry holds one anchor, and during one it holds
/// the outgoing key and its single successor. A third would mean a
/// document signed by a key nobody can still place.
#[test]
fn three_successive_ca_pq_transitions_never_hold_three_anchors() {
    let mut anchored = anchored();
    let mut private = anchored.ca_private.clone();
    let mut public = anchored.ca_public.clone();
    let mut retired = vec![public.clone()];

    for round in 0..3u64 {
        let epoch = round + 1;
        let base = 10_000 * (round + 1);
        let window = TransitionWindow::new(base, base + 1_000, base + 2_000).expect("window");
        let (object, next_private, next_public) =
            transition_from(&anchored.registry, &private, &public, epoch, window);
        anchored
            .registry
            .accept_transitions(&anchor_campaign(), &[object], None, base + 500)
            .expect("successive rotation accepted");

        // Staged: the outgoing anchor and exactly one successor.
        let state = anchored.registry.state();
        assert_eq!(state.ca_epoch, epoch);
        assert_eq!(state.ca_public_key, public);
        let rotation = state.ca_rotation.clone().expect("a rotation is in flight");
        assert_eq!(rotation.next_ca_epoch, epoch + 1);
        assert_eq!(rotation.next_ca_public_key, next_public);
        assert_eq!(
            state.transitions.len(),
            1,
            "one decision in flight, never two"
        );
        assert!(
            !retired.contains(&rotation.next_ca_public_key),
            "a rotation must not reinstate an anchor already retired"
        );

        // Promoted at retirement: the predecessor goes in the same
        // write that installs the successor.
        assert_eq!(
            anchored
                .registry
                .forget_expired_transitions(base + 2_000)
                .expect("promotion at retirement"),
            1
        );
        let state = anchored.registry.state();
        assert_eq!(state.ca_epoch, epoch + 1);
        assert_eq!(state.ca_public_key, next_public);
        assert!(state.ca_rotation.is_none(), "no successor is kept around");
        assert!(state.transitions.is_empty());

        retired.push(public);
        private = next_private;
        public = next_public;
    }

    assert_eq!(anchored.registry.state().ca_epoch, 4);
    assert_eq!(
        retired.len(),
        4,
        "three predecessors and the anchor of \
                                  the fixture, none of them still held"
    );
}

#[test]
fn a_registry_recovers_a_stored_ca_pq_window_from_the_legacy_format() {
    let mut anchored = anchored();
    let object = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
    )
    .0;
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect("accepted");
    let expected = anchored.registry.state().ca_rotation.clone();
    let mut encoded = serde_json::to_value(anchored.registry.state()).expect("encoding");
    encoded
        .as_object_mut()
        .expect("registry object")
        .remove("ca_rotation");
    let path = anchored._directory.path().join("astra.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&encoded).expect("legacy encoding"),
    )
    .expect("legacy registry written");

    let restored = AstraRegistry::load(&path, None).expect("legacy registry loaded");
    assert_eq!(restored.state().ca_rotation, expected);
}

#[test]
fn a_second_ca_pq_rotation_is_refused_while_one_is_in_flight() {
    let mut anchored = anchored();
    let first = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_000, 5_000).expect("first window"),
    )
    .0;
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
        .expect("first accepted");
    let held = anchored.registry.state().ca_rotation.clone();
    let competing = transition_from(
        &anchored.registry,
        &anchored.ca_private,
        &anchored.ca_public,
        1,
        TransitionWindow::new(1_000, 3_500, 5_500).expect("competing window"),
    )
    .0;

    assert!(anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[competing], None, 2_100)
        .is_err());
    assert_eq!(anchored.registry.state().ca_rotation, held);
    assert_eq!(anchored.registry.state().transitions.len(), 1);
}

/// Past its `not_after` a transition authorizes nothing, and keeping
/// it would fill a bounded store with objects that can no longer act.
#[test]
fn an_expired_transition_is_forgotten() {
    let mut anchored = anchored();
    let object = transition(&anchored, 1);
    anchored
        .registry
        .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
        .expect("accepted");
    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(199_999)
            .expect("swept"),
        0
    );
    assert_eq!(
        anchored
            .registry
            .forget_expired_transitions(200_000)
            .expect("swept"),
        1
    );
    assert!(anchored.registry.state().transitions.is_empty());
}
