use super::*;

pub(super) fn window() -> TransitionWindow {
    TransitionWindow {
        not_before: 1_000,
        activation_at: 2_000,
        not_after: 3_000,
    }
}

pub(super) fn gateway_transition(
    fixture: &Fixture,
    next: &Keys,
    epoch: u64,
    window: TransitionWindow,
) -> GatewayIdentityTransition {
    let gateway = &fixture.registry.state().gateway;
    GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        active_gateway_tls_certificate_fingerprint: gateway.active_tls_fingerprint(),
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: gateway
            .active_pq_fingerprint()
            .expect("active fingerprint"),
        next_gateway_certificate: Some(leaf(
            &fixture.ca,
            next,
            PqCertificateRole::Gateway,
            &gateway_key(),
            9,
        )),
        window,
        reason: RotationReason::Scheduled,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca.private)
    .expect("sign the transition")
}

pub(super) fn gateway_abort(
    fixture: &Fixture,
    transition: &GatewayIdentityTransition,
    aborted_at: u64,
) -> GatewayTransitionAbort {
    GatewayTransitionAbort {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        gateway_identity_epoch: transition.gateway_identity_epoch,
        gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        aborted_at,
        reason: AbortReason::OperatorCancelled,
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca.private)
    .expect("sign the abort")
}

#[test]
fn a_staged_transition_leaves_the_identity_in_service_untouched() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());

    let outcome = fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");

    assert_eq!(outcome, InstallOutcome::Installed);
    let gateway = &fixture.registry.state().gateway;
    assert_eq!(gateway.next_gateway_identity_epoch, Some(2));
    assert_eq!(gateway.activation_at, Some(2_000));
    assert_eq!(gateway.retire_active_at, Some(3_000));
    // The switch belongs to `activation_at`, not to the installation: a
    // staging that changed the served leaf would take the identity out of
    // service the moment the operator came back from the ceremony.
    assert_eq!(gateway.active_gateway_identity_epoch, 1);
    assert!(!gateway.published);

    // And it survives the process: the ceremony is measured in days.
    let reloaded = CertificateRegistry::load(
        fixture
            ._directory
            .path()
            .join("certificates.json")
            .as_path(),
    )
    .expect("reload")
    .expect("registry");
    assert_eq!(
        reloaded.state().gateway.next_gateway_identity_epoch,
        Some(2)
    );
}

#[test]
fn the_same_transition_carried_in_twice_consumes_one_epoch() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");

    let outcome = fixture
        .registry
        .install_gateway_transition(&transition, 1_600)
        .expect("replay");

    assert_eq!(outcome, InstallOutcome::AlreadyPresent);
    assert_eq!(fixture.registry.state().gateway.gateway_decision_epoch, 2);
}

#[test]
fn a_published_gateway_transition_is_promoted_durably_at_not_after() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    fixture
        .registry
        .state
        .gateway
        .mark_published()
        .expect("publish");

    assert!(!fixture
        .registry
        .promote_gateway_if_due(2_999)
        .expect("not due"));
    assert!(fixture
        .registry
        .promote_gateway_if_due(3_000)
        .expect("promote"));
    assert_eq!(
        fixture
            .registry
            .state()
            .gateway
            .active_gateway_identity_epoch,
        2
    );
    assert!(fixture
        .registry
        .state()
        .gateway
        .next_gateway_certificate
        .is_none());

    let reloaded = CertificateRegistry::load(
        fixture
            ._directory
            .path()
            .join("certificates.json")
            .as_path(),
    )
    .expect("reload")
    .expect("registry");
    assert_eq!(reloaded.state().gateway.active_gateway_identity_epoch, 2);
    assert!(!fixture
        .registry
        .promote_gateway_if_due(u64::MAX)
        .expect("idempotent"));
}

/// A `CA-PQ` rotation signed by the fixture's anchor and by its successor.
fn ca_transition(
    fixture: &Fixture,
    next: &Keys,
    window: TransitionWindow,
) -> aether::certificates::authority::CaTransition {
    let transition = aether::certificates::authority::CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        current_ca_epoch: 1,
        next_ca_epoch: 2,
        current_ca_fingerprint: fixture.ca.public.authority_fingerprint(),
        next_ca_public_key: next.public.clone(),
        next_ca_fingerprint: next.public.authority_fingerprint(),
        window,
        current_ca_signature: MlDsa87Signature::placeholder(),
        next_ca_signature: MlDsa87Signature::placeholder(),
    };
    transition
        .sign(&fixture.ca.private, &next.private)
        .expect("sign")
}

/// §9.1 on the gateway: the anchor is staged, both verify during the
/// overlap, and the epoch moves only at `not_after`.
#[test]
fn a_ca_rotation_keeps_both_anchors_until_the_end_of_its_overlap() {
    let mut fixture = fixture();
    let next = keys();
    let transition = ca_transition(&fixture, &next, window());

    assert!(matches!(
        fixture
            .registry
            .install_ca_transition(&transition, 1_500)
            .expect("install"),
        InstallOutcome::Installed
    ));
    assert_eq!(fixture.registry.state().gateway.ca_epoch, 1);
    assert_eq!(
        fixture.registry.state().client_leaf_issuers(1_999).len(),
        1,
        "prepared, not yet acceptable"
    );
    assert_eq!(
        fixture.registry.state().client_leaf_issuers(2_000).len(),
        2,
        "both anchors verify from activation_at"
    );

    // A repeat of the same signed document consumes nothing.
    assert!(matches!(
        fixture
            .registry
            .install_ca_transition(&transition, 1_600)
            .expect("replay"),
        InstallOutcome::AlreadyPresent
    ));

    fixture.registry.promote_due(2_999).expect("not due");
    assert_eq!(fixture.registry.state().gateway.ca_epoch, 1);

    fixture.registry.promote_due(3_000).expect("promotion");
    assert_eq!(fixture.registry.state().gateway.ca_epoch, 2);
    assert_eq!(
        fixture
            .registry
            .state()
            .gateway
            .current_ca_public_key
            .authority_fingerprint()
            .to_hex(),
        next.public.authority_fingerprint().to_hex()
    );
    assert_eq!(
        fixture.registry.state().client_leaf_issuers(3_000).len(),
        1,
        "the outgoing anchor is gone, not merely unpreferred"
    );
}

/// The promotion is persisted, not merely computed: a restart must find
/// the same anchor the pass moved to.
#[test]
fn the_promoted_anchor_survives_a_reopen() {
    let mut fixture = fixture();
    let next = keys();
    let transition = ca_transition(&fixture, &next, window());
    fixture
        .registry
        .install_ca_transition(&transition, 1_500)
        .expect("install");
    fixture.registry.promote_due(3_000).expect("promotion");

    let reopened = CertificateRegistry::load(&fixture.registry.path)
        .expect("load")
        .expect("registry on disk");
    assert_eq!(reopened.state().gateway.ca_epoch, 2);
    assert!(reopened.state().gateway.next_ca_public_key.is_none());
}

/// Two anchors at most: a second, different rotation while one is in
/// flight would leave three, of which the domain names two.
#[test]
fn a_second_ca_rotation_is_refused_while_one_is_in_flight() {
    let mut fixture = fixture();
    let first = keys();
    let second = keys();
    fixture
        .registry
        .install_ca_transition(&ca_transition(&fixture, &first, window()), 1_500)
        .expect("install");

    let refusal = fixture
        .registry
        .install_ca_transition(&ca_transition(&fixture, &second, window()), 1_500)
        .expect_err("second rotation");
    assert!(matches!(
        refusal,
        RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
    ));
}

/// A rotation whose activation has already passed installs nothing: it
/// would take effect the instant it landed, on a fleet that never saw it.
#[test]
fn a_ca_rotation_activating_in_the_past_is_refused() {
    let mut fixture = fixture();
    let next = keys();
    let refusal = fixture
        .registry
        .install_ca_transition(&ca_transition(&fixture, &next, window()), 2_500)
        .expect_err("late");
    assert!(matches!(
        refusal,
        RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
    ));
    assert!(fixture
        .registry
        .state()
        .gateway
        .next_ca_public_key
        .is_none());
}

/// A rollback authorization signed by the fixture's `CA-PQ` for its own
/// staged overlap.
pub(super) fn rollback(
    fixture: &Fixture,
    transition: &GatewayIdentityTransition,
    expires_at: u64,
) -> aether::certificates::status::CertificateServiceRollbackAuthorization {
    let gateway = &fixture.registry.state().gateway;
    let authorization = aether::certificates::status::CertificateServiceRollbackAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        selected_certificate_fingerprint: gateway.active_tls_fingerprint(),
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        expires_at,
        ca_signature: MlDsa87Signature::placeholder(),
    };
    authorization.sign(&fixture.ca.private).expect("sign")
}

/// §11.1 step 8: the selection is persisted, and it moves nothing else —
/// the promotion still fires at `not_after`, and it takes the selection
/// with it.
#[test]
fn a_gateway_rollback_is_persisted_and_dies_with_the_overlap_it_lives_in() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    fixture
        .registry
        .publish_gateway_transition(2, &transition.fingerprint().expect("fingerprint"))
        .expect("publish");

    let authorization = rollback(&fixture, &transition, 2_800);
    assert!(matches!(
        fixture
            .registry
            .install_gateway_rollback(&authorization, 2_100)
            .expect("rollback"),
        InstallOutcome::Installed
    ));
    assert!(fixture.registry.active_gateway_rollback(2_100).is_some());
    assert_eq!(
        fixture
            .registry
            .state()
            .gateway
            .active_gateway_identity_epoch,
        1,
        "a service rollback moves no counter"
    );
    assert_eq!(
        fixture.registry.state().gateway.next_gateway_identity_epoch,
        Some(2),
        "and removes no slot"
    );

    assert!(fixture
        .registry
        .promote_gateway_if_due(3_000)
        .expect("promotion"));
    assert!(fixture.registry.active_gateway_rollback(3_000).is_none());
}

/// Before publication there is nothing to roll back from: the outgoing
/// leaf is still the one served, and an abort is the gesture that applies.
#[test]
fn a_gateway_rollback_is_refused_outside_the_overlap() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");

    let authorization = rollback(&fixture, &transition, 2_800);
    let refusal = fixture
        .registry
        .install_gateway_rollback(&authorization, 2_100)
        .expect_err("unpublished");
    assert!(matches!(
        refusal,
        RegistryError::Certificate(CertificateError::RollbackUnavailable)
    ));
    assert!(fixture.registry.active_gateway_rollback(2_100).is_none());
}

#[test]
fn an_unpublished_gateway_transition_never_reaches_the_active_slot() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");

    let refusal = fixture
        .registry
        .promote_gateway_if_due(3_000)
        .expect_err("unpublished transition");

    assert!(matches!(
        refusal,
        RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
    ));
    assert_eq!(
        fixture
            .registry
            .state()
            .gateway
            .active_gateway_identity_epoch,
        1
    );
    assert_eq!(
        fixture.registry.state().gateway.next_gateway_identity_epoch,
        Some(2)
    );
}

#[test]
fn a_second_transition_is_refused_while_one_is_staged() {
    let mut fixture = fixture();
    let first = keys();
    let second = keys();
    let transition = gateway_transition(&fixture, &first, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");

    let refusal = fixture
        .registry
        .install_gateway_transition(&gateway_transition(&fixture, &second, 3, window()), 1_500)
        .expect_err("a second candidate at once");

    assert!(matches!(
        refusal,
        RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
    ));
}

#[test]
fn an_abort_clears_the_slot_and_leaves_the_epoch_consumed() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    let abort = gateway_abort(&fixture, &transition, 1_600);

    let outcome = fixture
        .registry
        .abort_gateway_transition(&abort, &transition, 1_700)
        .expect("abort");

    assert_eq!(outcome, InstallOutcome::Installed);
    let gateway = &fixture.registry.state().gateway;
    assert_eq!(gateway.next_gateway_identity_epoch, None);
    assert!(gateway.next_gateway_certificate.is_none());
    // The number stays spent. A client holding the tombstone refuses a
    // second decision at the same epoch, and it is right to.
    assert_eq!(gateway.gateway_decision_epoch, 2);
    assert!(gateway.last_aborted_transition.is_some());
}

/// §6.3: `revoked` dominates every phase and every date, and nothing
/// local repairs it.
#[test]
fn revoking_the_served_leaf_is_terminal_for_the_gateway() {
    let mut fixture = fixture();
    let active_pq = fixture
        .registry
        .state()
        .gateway
        .active_pq_fingerprint()
        .expect("active fingerprint");

    let hit = fixture
        .registry
        .revoke_gateway(None, Some(&active_pq), 1, None)
        .expect("revoked");

    assert!(hit);
    let gateway = &fixture.registry.state().gateway;
    assert!(gateway.revoked);
    assert_eq!(gateway.revocation_epoch, 1);
}

/// §10.1 followed by §6.1, on the registry: a withdrawal that names its
/// replacement is recoverable, and the replacement is served at once —
/// there is no outgoing identity left to overlap with.
#[test]
fn a_revocation_naming_a_replacement_lets_the_gateway_come_back() {
    let mut fixture = fixture();
    let next = keys();
    let mut replacement = gateway_transition(&fixture, &next, 2, window());
    replacement.reason = RotationReason::EmergencyReplacement;
    let replacement = replacement.sign(&fixture.ca.private).expect("sign");
    let named = replacement.fingerprint().expect("fingerprint");
    let active_pq = fixture
        .registry
        .state()
        .gateway
        .active_pq_fingerprint()
        .expect("active fingerprint");

    assert!(fixture
        .registry
        .revoke_gateway(None, Some(&active_pq), 1, Some(&named))
        .expect("revoked"));
    assert!(fixture.registry.state().gateway.revoked);

    assert!(matches!(
        fixture
            .registry
            .install_gateway_transition(&replacement, 1_500)
            .expect("replacement"),
        InstallOutcome::Installed
    ));
    let gateway = &fixture.registry.state().gateway;
    assert!(!gateway.revoked);
    assert_eq!(gateway.active_gateway_identity_epoch, 2);
    assert!(gateway.next_gateway_identity_epoch.is_none());
    assert_eq!(
        gateway.revocation_epoch, 1,
        "the revocation counter never comes back down"
    );

    // And it survives a reopen: the decision is on disk, not in a clone.
    let reopened = CertificateRegistry::load(&fixture.registry.path)
        .expect("load")
        .expect("registry on disk");
    assert!(!reopened.state().gateway.revoked);
    assert_eq!(reopened.state().gateway.active_gateway_identity_epoch, 2);
}

/// A decision about a leaf this gateway never held is not an error — an
/// offline document carries the fleet's decisions — but its counter is
/// consumed, which is what stops that leaf arriving later by transition.
#[test]
fn revoking_a_leaf_this_gateway_never_held_consumes_the_counter() {
    let mut fixture = fixture();
    let stranger = Fingerprint::of(b"a leaf from elsewhere");

    let hit = fixture
        .registry
        .revoke_gateway(Some(&stranger), None, 4, None)
        .expect("recorded");

    assert!(!hit);
    let gateway = &fixture.registry.state().gateway;
    assert!(!gateway.revoked, "the identity in service is untouched");
    assert_eq!(gateway.revocation_epoch, 4);
}

/// A revocation reaching only the staged generation withdraws it and
/// leaves the identity in service `active` (§6.3).
#[test]
fn revoking_the_staged_candidate_leaves_the_served_identity_active() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    let staged = aether::certificates::gateway::pq_certificate_fingerprint(
        transition
            .next_gateway_certificate
            .as_ref()
            .expect("staged leaf"),
    )
    .expect("fingerprint");

    let hit = fixture
        .registry
        .revoke_gateway(None, Some(&staged), 2, None)
        .expect("revoked");

    assert!(hit);
    let gateway = &fixture.registry.state().gateway;
    assert!(!gateway.revoked);
    assert_eq!(gateway.next_gateway_identity_epoch, None);
    assert_eq!(gateway.revocation_epoch, 2);
}
