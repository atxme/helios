use super::*;
use crate::certificates::window::TransitionWindow;

fn generation(index: u64, seed: u8) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: index,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(&[seed, 1]),
        pq_certificate_fingerprint: Fingerprint::of(&[seed, 2]),
        not_before: 0,
        not_after: 100_000,
    }
}

/// A distinct signed-commit identity per seed.
fn commit_fingerprint(seed: u8) -> Fingerprint {
    Fingerprint::of(&[seed, 0xC0])
}

fn staged_state() -> ClientCertificateState {
    let mut state = ClientCertificateState::new(generation(4, 1));
    state.pending = Some(ClientCertificatePendingStage {
        stage_id: Id16::new([3; 16]).expect("stage"),
        authorization_fingerprint: Fingerprint::of(b"authorization"),
        request_fingerprint: Fingerprint::of(b"request"),
        candidate: generation(5, 2),
        state: PendingStageState::PendingGrant,
        stage_expires_at: 5_000,
        window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
    });
    state
}

/// The negotiation resolves a caller by the TLS half mTLS proved, and
/// must then know which PQ leaf that caller may present.
///
/// The answer is the partner of that exact half, never the union of both
/// generations: the union accepts the mixed pair of §3.3 — the TLS of the
/// outgoing identity beside the PQ of the incoming one — which is an
/// identity the domain never issued.
#[test]
fn the_pq_half_returned_belongs_to_the_generation_the_tls_half_named() {
    let active = generation(4, 1);
    let next = generation(5, 2);
    let mut state = ClientCertificateState::new(active.clone());
    state.next = Some(next.clone());
    state.activation_at = Some(1_000);

    assert_eq!(
        state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
        Some(active.pq_certificate_fingerprint)
    );
    assert_eq!(
        state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 2_000),
        Some(next.pq_certificate_fingerprint)
    );
    // Never the other one's, from either side.
    assert_ne!(
        state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
        Some(next.pq_certificate_fingerprint)
    );
}

/// Before its activation instant the successor is not an identity yet.
#[test]
fn a_successor_resolves_nothing_until_its_activation() {
    let active = generation(4, 1);
    let next = generation(5, 2);
    let mut state = ClientCertificateState::new(active.clone());
    state.next = Some(next.clone());
    state.activation_at = Some(1_000);

    assert_eq!(
        state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 999),
        None
    );
    assert_eq!(
        state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 1_000),
        Some(next.pq_certificate_fingerprint)
    );
}

/// Revocation dominates: neither half of either generation resolves.
#[test]
fn a_revoked_peer_resolves_no_pq_half_at_all() {
    let active = generation(4, 1);
    let next = generation(5, 2);
    let mut state = ClientCertificateState::new(active.clone());
    state.next = Some(next.clone());
    state.activation_at = Some(1_000);
    state.revoke(7);

    assert_eq!(
        state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
        None
    );
    assert_eq!(
        state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 2_000),
        None
    );
}

/// A candidate under lease is not presentable, so it resolves nothing —
/// the same rule `accepts_pair` applies, stated for the half the
/// negotiation actually looks up.
#[test]
fn a_candidate_under_lease_resolves_no_pq_half() {
    let state = staged_state();
    let candidate = generation(5, 2);
    assert_eq!(
        state.pq_paired_with_tls(&candidate.tls_certificate_fingerprint, 2_000),
        None
    );
}

/// The commit is the moment a candidate becomes usable, and not before.
#[test]
fn a_candidate_is_not_presentable_until_it_is_committed() {
    let mut state = staged_state();
    let candidate = generation(5, 2);
    assert!(!state.accepts_pair(
        &candidate.tls_certificate_fingerprint,
        &candidate.pq_certificate_fingerprint,
        15_000
    ));

    state
        .commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000,
        )
        .expect("commit");
    assert!(state.pending.is_none());
    assert!(state.next.is_some());
    // Committed, but only presentable from `activation_at`.
    assert!(!state.accepts_pair(
        &candidate.tls_certificate_fingerprint,
        &candidate.pq_certificate_fingerprint,
        9_999
    ));
    assert!(state.accepts_pair(
        &candidate.tls_certificate_fingerprint,
        &candidate.pq_certificate_fingerprint,
        10_000
    ));
}

/// The two mixed pairs of spec §3.3, at the state level this time.
#[test]
fn a_state_in_overlap_refuses_a_pair_split_across_generations() {
    let mut state = staged_state();
    state
        .commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000,
        )
        .unwrap();
    let active = generation(4, 1);
    let next = generation(5, 2);

    assert!(state.accepts_pair(
        &active.tls_certificate_fingerprint,
        &active.pq_certificate_fingerprint,
        15_000
    ));
    assert!(!state.accepts_pair(
        &active.tls_certificate_fingerprint,
        &next.pq_certificate_fingerprint,
        15_000
    ));
    assert!(!state.accepts_pair(
        &next.tls_certificate_fingerprint,
        &active.pq_certificate_fingerprint,
        15_000
    ));
}

#[test]
fn an_uncommitted_candidate_is_purged_at_its_lease() {
    let mut state = staged_state();
    assert!(!state.purge_expired(4_999));
    assert!(state.purge_expired(5_000));
    assert!(state.pending.is_none());

    // And a commit arriving afterwards has nothing to commit.
    assert!(matches!(
        state.commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            5_001
        ),
        Err(CertificateError::UnknownStage)
    ));
}

#[test]
fn a_commit_at_the_deadline_loses_the_race_against_the_purge() {
    let mut state = staged_state();
    assert!(matches!(
        state.commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            5_000
        ),
        Err(CertificateError::StageExpired)
    ));
}

/// The two ends commit from different states, and neither may adopt the
/// other's rule: Orion must hold the grant first.
#[test]
fn each_end_commits_only_from_the_state_it_owns() {
    let mut orion = staged_state();
    assert!(matches!(
        orion.commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingCommit,
            2_000
        ),
        Err(CertificateError::IllegalStateTransition(_))
    ));

    orion
        .mark_pending_commit(&Id16::new([3; 16]).unwrap())
        .expect("grant persisted");
    orion
        .commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingCommit,
            2_000,
        )
        .expect("commit");
    assert!(orion.next.is_some());
}

/// A retry over a lossy link is a no-op, and it is recognised by the exact
/// signed commit — not by "there is a `next` roughly here", and not by the
/// stage identifier alone.
#[test]
fn a_replayed_commit_is_idempotent_only_for_its_own_signed_document() {
    let mut state = staged_state();
    let stage = Id16::new([3; 16]).unwrap();
    state
        .commit(
            &stage,
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000,
        )
        .expect("commit");

    assert_eq!(
        state
            .commit(
                &stage,
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_100
            )
            .expect("replay"),
        InstallOutcome::AlreadyPresent
    );
    // A *different* document closing the same stage is a conflict: telling
    // its sender the commit landed would report someone else's decision as
    // theirs.
    assert!(matches!(
        state.commit(
            &stage,
            &commit_fingerprint(2),
            PendingStageState::PendingGrant,
            2_100
        ),
        Err(CertificateError::GenerationConflict { .. })
    ));
    // And another stage landing on the same generation is refused.
    assert!(matches!(
        state.commit(
            &Id16::new([4; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_100
        ),
        Err(CertificateError::UnknownStage)
    ));
}

#[test]
fn a_commit_naming_another_stage_is_refused() {
    let mut state = staged_state();
    assert!(matches!(
        state.commit(
            &Id16::new([9; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000
        ),
        Err(CertificateError::UnknownStage)
    ));
    assert!(state.pending.is_some());
}

/// Revocation wins every race, and no later object undoes it.
#[test]
fn revocation_dominates_staging_commit_and_promotion() {
    let mut state = staged_state();
    state.revoke(1);
    assert!(state.pending.is_none());
    assert!(state.next.is_none());
    assert!(matches!(
        state.commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000
        ),
        Err(CertificateError::Revoked)
    ));
    assert!(!state.promote_if_due(u64::MAX));
    let active = generation(4, 1);
    assert!(!state.accepts_pair(
        &active.tls_certificate_fingerprint,
        &active.pq_certificate_fingerprint,
        1_000
    ));
    assert!(state.acceptable_pq_fingerprints(1_000).is_empty());
}

/// Promotion deletes the outgoing generation, so a clock moved backwards
/// finds nothing to reactivate.
#[test]
fn a_promoted_generation_never_comes_back_when_the_clock_moves_backwards() {
    let mut state = staged_state();
    state
        .commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000,
        )
        .unwrap();
    assert!(state.promote_if_due(20_000));
    assert_eq!(state.active.generation, 5);
    assert!(state.next.is_none());

    let old = generation(4, 1);
    assert!(!state.accepts_pair(
        &old.tls_certificate_fingerprint,
        &old.pq_certificate_fingerprint,
        1_000
    ));
    assert!(!state.promote_if_due(u64::MAX));
}

#[test]
fn a_peer_never_holds_three_generations_at_once() {
    let mut state = staged_state();
    assert_eq!(state.occupied_fingerprints().len(), 4);
    state
        .commit(
            &Id16::new([3; 16]).unwrap(),
            &commit_fingerprint(1),
            PendingStageState::PendingGrant,
            2_000,
        )
        .unwrap();
    assert_eq!(state.occupied_fingerprints().len(), 4);
    assert!(state.pending.is_none() || state.next.is_none());
}

/// The `staged -> published -> overlap -> promoted` machine of spec §6.3,
/// and the one door that closes: an abort after publication.
#[cfg(feature = "key-negotiation-signing")]
mod gateway_machine {
    use super::*;
    use crate::certificates::authority::RotationReason;
    use crate::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use crate::certificates::gateway::AbortReason;
    use crate::certificates::status::CertificateServiceRollbackAuthorization;
    use crate::certificates::{CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION};
    use crate::key_negotiation::{issue_pq_certificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use zeroize::Zeroizing;

    const SERVER_NAME: &str = "gateway.example";

    struct Keys {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn keys() -> Keys {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Keys { private, public }
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([5; 32])
    }

    fn leaf(ca: &Keys, subject: &Keys, serial: u8) -> PqCertificate {
        let certificate = PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: SERVER_NAME.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        };
        issue_pq_certificate(certificate, &ca.private).expect("issue")
    }

    fn state(ca: &Keys, active: PqCertificate) -> GatewayCertificateState {
        GatewayCertificateState {
            trust_domain_id: TrustDomainId::new([4; 16]).expect("domain"),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            ca_epoch: 1,
            current_ca_public_key: ca.public.clone(),
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
            active_gateway_certificate: active,
            next_gateway_certificate: None,
            activation_at: None,
            retire_active_at: None,
            published: false,
            revoked: false,
            revocation_epoch: 0,
            service_rollback: None,
            awaited_replacement: None,
        }
    }

    fn transition(
        ca: &Keys,
        state: &GatewayCertificateState,
        epoch: u64,
        next: PqCertificate,
    ) -> GatewayIdentityTransition {
        let transition = GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: state.ca_epoch,
            gateway_identity_epoch: epoch,
            gateway_wg_public_key: state.gateway_wg_public_key,
            server_name: state.server_name.clone(),
            active_gateway_tls_certificate_fingerprint: state.active_tls_fingerprint(),
            next_gateway_tls_certificate: None,
            active_gateway_certificate_fingerprint: state
                .active_pq_fingerprint()
                .expect("fingerprint"),
            next_gateway_certificate: Some(next),
            window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
            reason: RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        transition.sign(&ca.private).expect("sign")
    }

    fn abort(
        ca: &Keys,
        transition: &GatewayIdentityTransition,
        aborted_at: u64,
    ) -> GatewayTransitionAbort {
        let abort = GatewayTransitionAbort {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: transition.trust_domain_id,
            ca_epoch: transition.ca_epoch,
            gateway_wg_public_key: transition.gateway_wg_public_key,
            server_name: transition.server_name.clone(),
            gateway_identity_epoch: transition.gateway_identity_epoch,
            gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
            aborted_at,
            reason: AbortReason::OperatorCancelled,
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        abort.sign(&ca.private).expect("sign")
    }

    /// Builds a state sitting inside a published overlap: the window is
    /// [2_000, 3_000), so 2_000 is the first second the daemon would serve
    /// the incoming leaf and 2_999 the last.
    fn in_overlap(ca: &Keys, active: &Keys, candidate: &Keys) -> GatewayCertificateState {
        let mut state = state(ca, leaf(ca, active, 1));
        let transition = transition(ca, &state, 2, leaf(ca, candidate, 2));
        state
            .install_transition(&transition, &TrustLedger::default(), 500)
            .expect("install");
        state.mark_published().expect("publish");
        state
    }

    /// A rollback authorization signed by `ca` for the state's own overlap.
    fn rollback(
        ca: &Keys,
        state: &GatewayCertificateState,
        selected: Fingerprint,
        expires_at: u64,
    ) -> CertificateServiceRollbackAuthorization {
        let authorization = CertificateServiceRollbackAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: state.ca_epoch,
            gateway_wg_public_key: state.gateway_wg_public_key,
            server_name: state.server_name.clone(),
            transition_fingerprint: state
                .next_transition_fingerprint
                .unwrap_or_else(|| Fingerprint::of(b"no staged transition")),
            selected_certificate_fingerprint: selected,
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            expires_at,
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        authorization.sign(&ca.private).expect("sign")
    }

    /// A transition with the emergency reason, for a state that has been
    /// revoked and told what replaces it.
    fn replacement(
        ca: &Keys,
        state: &GatewayCertificateState,
        epoch: u64,
        next: PqCertificate,
    ) -> GatewayIdentityTransition {
        let mut transition = transition(ca, state, epoch, next);
        transition.reason = RotationReason::EmergencyReplacement;
        transition.sign(&ca.private).expect("sign")
    }

    /// §10.2 followed by §6.1: the revocation names what replaces the
    /// identity it withdraws, and that one document still installs.
    #[test]
    fn a_revoked_identity_accepts_the_replacement_its_revocation_named() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let revoked_pq = state.active_pq_fingerprint().expect("fingerprint");
        let replacement = replacement(&ca, &state, 2, leaf(&ca, &candidate, 2));
        let named = replacement.fingerprint().expect("fingerprint");

        assert!(state
            .apply_revocation(None, Some(&revoked_pq), 3, Some(&named))
            .expect("revocation"));
        assert!(state.revoked);
        assert!(
            state.acceptable_pq_fingerprints(1_500).unwrap().is_empty(),
            "a revoked gateway offers nothing while it waits"
        );

        assert_eq!(
            state
                .install_transition(&replacement, &TrustLedger::default(), 1_500)
                .expect("replacement"),
            InstallOutcome::Installed
        );
        // Served immediately: there is no outgoing identity to overlap
        // with, and staging would leave the service down until
        // activation_at.
        assert!(!state.revoked);
        assert_eq!(state.active_gateway_identity_epoch, 2);
        assert_eq!(state.gateway_decision_epoch, 2);
        assert!(state.next_gateway_identity_epoch.is_none());
        assert!(state.activation_at.is_none());
        assert_eq!(state.acceptable_pq_fingerprints(1_500).unwrap().len(), 1);
        assert_eq!(
            state.revocation_epoch, 3,
            "the revocation counter is a separate axis and never comes back down"
        );
        assert!(state.awaited_replacement.is_none());
    }

    /// Any other document, however well signed, stays refused.
    #[test]
    fn a_revoked_identity_refuses_every_transition_but_the_one_named() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let revoked_pq = state.active_pq_fingerprint().expect("fingerprint");
        let named = replacement(&ca, &state, 2, leaf(&ca, &candidate, 2))
            .fingerprint()
            .expect("fingerprint");
        state
            .apply_revocation(None, Some(&revoked_pq), 3, Some(&named))
            .expect("revocation");

        let other = keys();
        let elsewhere = replacement(&ca, &state, 2, leaf(&ca, &other, 3));
        assert!(matches!(
            state.install_transition(&elsewhere, &TrustLedger::default(), 1_500),
            Err(CertificateError::Revoked)
        ));
        assert!(state.revoked);
    }

    /// A revocation that names nothing leaves the identity terminal, which
    /// is what it was before this path existed.
    #[test]
    fn a_revocation_naming_no_replacement_stays_terminal() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let revoked_pq = state.active_pq_fingerprint().expect("fingerprint");
        state
            .apply_revocation(None, Some(&revoked_pq), 3, None)
            .expect("revocation");
        assert!(state.awaited_replacement.is_none());

        let refused = replacement(&ca, &state, 2, leaf(&ca, &candidate, 2));
        assert!(matches!(
            state.install_transition(&refused, &TrustLedger::default(), 1_500),
            Err(CertificateError::Revoked)
        ));
    }

    /// The revoked leaves never come back, whatever names them: the ledger
    /// refuses them before the awaited fingerprint is even consulted.
    #[test]
    fn the_replacement_may_not_reinstall_the_leaf_that_was_revoked() {
        let (ca, active) = (keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let revoked = leaf(&ca, &active, 7);
        let revoked_fingerprint = pq_certificate_fingerprint(&revoked).expect("fingerprint");
        let reinstalls = replacement(&ca, &state, 2, revoked);
        let named = reinstalls.fingerprint().expect("fingerprint");
        state
            .apply_revocation(
                None,
                Some(&state.active_pq_fingerprint().expect("fingerprint")),
                3,
                Some(&named),
            )
            .expect("revocation");

        let ledger = TrustLedger {
            revoked: vec![RevocationTombstone {
                scope: RevocationScope::Gateway,
                family: RevokedFamily::Pq,
                fingerprint: revoked_fingerprint,
                revocation_epoch: 3,
                expires_at: 100_000,
                revocation_fingerprint: None,
            }],
            ..TrustLedger::default()
        };

        assert!(state
            .install_transition(&reinstalls, &ledger, 1_500)
            .is_err());
        assert!(state.revoked, "and the identity stays withdrawn");
    }

    /// The reason and the situation must agree in both directions: an
    /// emergency replacement offered to a healthy identity would be an
    /// immediate swap nobody scheduled.
    #[test]
    fn the_emergency_reason_belongs_only_to_a_revoked_identity() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let emergency = replacement(&ca, &state, 2, leaf(&ca, &candidate, 2));
        assert!(matches!(
            state.install_transition(&emergency, &TrustLedger::default(), 1_500),
            Err(CertificateError::IllegalStateTransition(_))
        ));

        // And the converse: the awaited document must carry the reason.
        let ordinary = transition(&ca, &state, 2, leaf(&ca, &candidate, 3));
        let named = ordinary.fingerprint().expect("fingerprint");
        state
            .apply_revocation(
                None,
                Some(&state.active_pq_fingerprint().expect("fingerprint")),
                3,
                Some(&named),
            )
            .expect("revocation");
        assert!(matches!(
            state.install_transition(&ordinary, &TrustLedger::default(), 1_500),
            Err(CertificateError::IllegalStateTransition(_))
        ));
    }

    /// The window a rollback lives in is exactly the window in which the
    /// daemon would otherwise serve the incoming leaf.
    #[test]
    fn the_overlap_opens_at_activation_and_closes_at_not_after() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        assert!(!state.in_overlap(2_500), "nothing staged");

        let transition = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
        state
            .install_transition(&transition, &TrustLedger::default(), 500)
            .expect("install");
        assert!(!state.in_overlap(2_500), "staged but not published");

        state.mark_published().expect("publish");
        assert!(!state.in_overlap(1_999), "before activation_at");
        assert!(state.in_overlap(2_000));
        assert!(state.in_overlap(2_999));
        assert!(!state.in_overlap(3_000), "at not_after the overlap is over");
    }

    /// The nominal gesture of §11.1 step 8: during the overlap, the
    /// outgoing leaf is selected again, and nothing else moves.
    #[test]
    fn a_rollback_selects_the_outgoing_leaf_without_moving_a_counter() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let authorization = rollback(&ca, &state, outgoing, 2_800);

        assert_eq!(
            state
                .apply_service_rollback(&authorization, 2_100)
                .expect("rollback"),
            InstallOutcome::Installed
        );
        assert_eq!(state.active_gateway_identity_epoch, 1);
        assert_eq!(state.gateway_decision_epoch, 2);
        assert_eq!(state.next_gateway_identity_epoch, Some(2));
        assert!(state.published);
        assert_eq!(
            state.acceptable_pq_fingerprints(2_100).unwrap().len(),
            2,
            "a service rollback changes what is served, not what is accepted"
        );
        assert!(state.active_service_rollback(2_100).is_some());
    }

    /// The same signed document twice is a replay; the state says so
    /// rather than writing a second time.
    #[test]
    fn the_same_authorization_carried_twice_is_a_replay() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let authorization = rollback(&ca, &state, outgoing, 2_800);
        state
            .apply_service_rollback(&authorization, 2_100)
            .expect("rollback");
        assert_eq!(
            state
                .apply_service_rollback(&authorization, 2_200)
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        );
    }

    /// Expiry is answered by the clock, not by a purge.
    #[test]
    fn a_rollback_stops_being_served_the_second_it_expires() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let authorization = rollback(&ca, &state, outgoing, 2_800);
        state
            .apply_service_rollback(&authorization, 2_100)
            .expect("rollback");
        assert!(state.active_service_rollback(2_799).is_some());
        assert!(state.active_service_rollback(2_800).is_none());
        assert!(
            state.service_rollback.is_some(),
            "the document is kept; only its effect ends"
        );
    }

    /// Outside the overlap there is nothing to roll back to: before
    /// publication the outgoing leaf is already served, and after
    /// `not_after` reviving it would be a state rollback.
    #[test]
    fn a_rollback_is_refused_outside_an_overlap() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let outgoing = state.active_tls_fingerprint();
        let unstaged = rollback(&ca, &state, outgoing, 2_800);
        assert!(matches!(
            state.apply_service_rollback(&unstaged, 2_100),
            Err(CertificateError::RollbackUnavailable)
        ));

        let transition = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
        state
            .install_transition(&transition, &TrustLedger::default(), 500)
            .expect("install");
        let authorization = rollback(&ca, &state, outgoing, 2_800);
        assert!(
            matches!(
                state.apply_service_rollback(&authorization, 2_100),
                Err(CertificateError::RollbackUnavailable)
            ),
            "staged but unpublished: the outgoing leaf is already the one served"
        );

        state.mark_published().expect("publish");
        let early = rollback(&ca, &state, outgoing, 1_900);
        assert!(
            matches!(
                state.apply_service_rollback(&early, 1_800),
                Err(CertificateError::RollbackUnavailable)
            ),
            "before activation_at"
        );
    }

    /// Naming any leaf but the outgoing one would make this a downgrade
    /// primitive rather than a selection.
    #[test]
    fn a_rollback_may_name_only_the_outgoing_leaf() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let elsewhere = rollback(&ca, &state, Fingerprint::of(b"another leaf"), 2_800);
        assert!(matches!(
            state.apply_service_rollback(&elsewhere, 2_100),
            Err(CertificateError::RollbackUnavailable)
        ));
    }

    /// A rollback cannot outlive the overlap it rolls back within, and
    /// cannot be installed already expired.
    #[test]
    fn a_rollback_is_bounded_by_the_overlap_it_lives_in() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let beyond = rollback(&ca, &state, outgoing, 3_001);
        assert!(
            matches!(
                state.apply_service_rollback(&beyond, 2_100),
                Err(CertificateError::RollbackUnavailable)
            ),
            "past not_after"
        );
        let spent = rollback(&ca, &state, outgoing, 2_100);
        assert!(
            matches!(
                state.apply_service_rollback(&spent, 2_100),
                Err(CertificateError::RollbackUnavailable)
            ),
            "already expired"
        );
        let exact = rollback(&ca, &state, outgoing, 3_000);
        state
            .apply_service_rollback(&exact, 2_100)
            .expect("exactly not_after is allowed");
    }

    /// Promotion ends the overlap, so it ends the selection: keeping it
    /// would leave a document naming a leaf the state no longer holds.
    #[test]
    fn promotion_clears_the_selection_it_ends() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let authorization = rollback(&ca, &state, outgoing, 3_000);
        state
            .apply_service_rollback(&authorization, 2_100)
            .expect("rollback");
        assert!(state.promote_if_due(3_000).expect("promotion"));
        assert!(state.service_rollback.is_none());
    }

    /// A revoked identity offers nothing to serve, rolled back or not.
    #[test]
    fn revocation_clears_the_selection_and_forbids_a_new_one() {
        let (ca, active, candidate) = (keys(), keys(), keys());
        let mut state = in_overlap(&ca, &active, &candidate);
        let outgoing = state.active_tls_fingerprint();
        let authorization = rollback(&ca, &state, outgoing, 3_000);
        let second = rollback(&ca, &state, outgoing, 2_900);
        state
            .apply_service_rollback(&authorization, 2_100)
            .expect("rollback");
        assert!(state
            .apply_revocation(Some(&outgoing), None, 1, None)
            .expect("revocation"));
        assert!(state.service_rollback.is_none());
        assert!(!state.in_overlap(2_200));
        assert!(matches!(
            state.apply_service_rollback(&second, 2_200),
            Err(CertificateError::RollbackUnavailable)
        ));
    }

    #[test]
    fn a_staged_transition_is_promoted_at_the_end_of_its_overlap() {
        let ca = keys();
        let active = keys();
        let candidate = keys();
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let next = leaf(&ca, &candidate, 2);
        let transition = transition(&ca, &state, 2, next.clone());

        assert_eq!(
            state
                .install_transition(&transition, &TrustLedger::default(), 500)
                .expect("install"),
            InstallOutcome::Installed
        );
        assert_eq!(state.gateway_decision_epoch, 2);
        assert_eq!(state.active_gateway_identity_epoch, 1);

        // Prepared, not served: the client accepts only the active leaf.
        assert_eq!(state.acceptable_pq_fingerprints(1_999).unwrap().len(), 1);
        // Overlap: both.
        assert_eq!(state.acceptable_pq_fingerprints(2_000).unwrap().len(), 2);

        assert!(!state.promote_if_due(2_999).expect("promotion"), "not due");
        assert!(state.promote_if_due(3_000).expect("promotion"));
        assert_eq!(state.active_gateway_identity_epoch, 2);
        assert!(state.next_gateway_certificate.is_none());
        assert_eq!(
            state.acceptable_pq_fingerprints(3_000).unwrap().len(),
            1,
            "the outgoing leaf is gone, not merely unpreferred"
        );
        assert!(!state.promote_if_due(u64::MAX).expect("idempotent"));
    }

    /// Publication is the point of no return: after it, only a forward
    /// transition or the bounded service rollback remain.
    #[test]
    fn an_abort_is_refused_once_the_transition_has_been_published() {
        let ca = keys();
        let active = keys();
        let candidate = keys();
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let transition = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
        state
            .install_transition(&transition, &TrustLedger::default(), 500)
            .expect("install");
        state.mark_published().expect("publish");

        let abort = abort(&ca, &transition, 1_500);
        assert!(matches!(
            state.apply_abort(&abort, &transition, 1_600),
            Err(CertificateError::AlreadyPublished)
        ));
        assert!(state.next_gateway_certificate.is_some());
    }

    /// An aborted epoch stays consumed: the next attempt is `current + 1`,
    /// never a second document under the same number.
    #[test]
    fn an_aborted_epoch_is_never_reused() {
        let ca = keys();
        let active = keys();
        let candidate = keys();
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let staged = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
        state
            .install_transition(&staged, &TrustLedger::default(), 500)
            .expect("install");

        let abort = abort(&ca, &staged, 1_500);
        assert_eq!(
            state.apply_abort(&abort, &staged, 1_600).expect("abort"),
            InstallOutcome::Installed
        );
        assert!(state.next_gateway_certificate.is_none());
        assert_eq!(state.gateway_decision_epoch, 2, "the epoch is consumed");
        assert_eq!(state.active_gateway_identity_epoch, 1);
        assert!(state.last_aborted_transition.is_some());

        // Replaying the same abort changes nothing.
        assert_eq!(
            state.apply_abort(&abort, &staged, 1_700).expect("replay"),
            InstallOutcome::AlreadyPresent
        );

        // A second attempt at the consumed epoch is refused; epoch 3 works.
        let retry = transition(&ca, &state, 2, leaf(&ca, &candidate, 3));
        assert!(state
            .install_transition(&retry, &TrustLedger::default(), 500)
            .is_err());
        let forward = transition(&ca, &state, 3, leaf(&ca, &candidate, 4));
        assert_eq!(
            state
                .install_transition(&forward, &TrustLedger::default(), 500)
                .expect("install"),
            InstallOutcome::Installed
        );
    }

    /// Two staged transitions at once would give the state two futures.
    #[test]
    fn a_second_transition_cannot_be_staged_over_the_first() {
        let ca = keys();
        let active = keys();
        let candidate = keys();
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let first = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
        state
            .install_transition(&first, &TrustLedger::default(), 500)
            .expect("install");

        let second = transition(&ca, &state, 3, leaf(&ca, &candidate, 3));
        assert!(matches!(
            state.install_transition(&second, &TrustLedger::default(), 500),
            Err(CertificateError::IllegalStateTransition(_))
        ));

        // The identical one is an idempotent replay, not a refusal.
        assert_eq!(
            state
                .install_transition(&first, &TrustLedger::default(), 500)
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        );
    }

    /// A revoked leaf never comes back through a later transition.
    ///
    /// This is the case a revocation applied and then forgotten misses
    /// entirely: the decision named a leaf the holder did not have yet, so
    /// nothing was removed and nothing was remembered — and the very next
    /// transition installs it as though the revocation had never existed.
    #[test]
    fn a_revoked_leaf_is_refused_by_a_later_transition() {
        let ca = keys();
        let active = keys();
        let candidate = keys();
        let mut state = state(&ca, leaf(&ca, &active, 1));
        let next = leaf(&ca, &candidate, 2);
        let transition = transition(&ca, &state, 2, next.clone());

        let mut ledger = TrustLedger::default();
        ledger
            .remember(
                RevocationTombstone {
                    scope: RevocationScope::Gateway,
                    family: RevokedFamily::Pq,
                    fingerprint: pq_certificate_fingerprint(&next).expect("fingerprint"),
                    revocation_epoch: 1,
                    // Never held, but the signed revocation still carries the
                    // cryptographic expiry.
                    expires_at: next.not_after_unix,
                    revocation_fingerprint: Some(Fingerprint::of(b"the signed revocation")),
                },
                500,
            )
            .expect("tombstone");

        assert!(matches!(
            state.install_transition(&transition, &ledger, 500),
            Err(CertificateError::Revoked)
        ));
        assert!(state.next_gateway_certificate.is_none());

        // And without the tombstone the very same document installs — so
        // the refusal above is the tombstone's doing, not the window's.
        assert_eq!(
            state
                .install_transition(&transition, &TrustLedger::default(), 500)
                .expect("install"),
            InstallOutcome::Installed
        );
    }
}

/// A live tombstone is never traded away to make room for another.
#[test]
fn a_full_tombstone_list_refuses_rather_than_forgetting_a_revocation() {
    let tombstone = |seed: u8, expires_at| RevocationTombstone {
        scope: RevocationScope::Client,
        family: RevokedFamily::Pq,
        fingerprint: Fingerprint::of(&[seed]),
        revocation_epoch: u64::from(seed),
        expires_at,
        revocation_fingerprint: None,
    };

    let mut ledger = TrustLedger::default();
    for seed in 0..MAX_REVOCATION_TOMBSTONES as u8 {
        ledger
            .remember(tombstone(seed, 10_000), 1_000)
            .expect("room");
    }
    assert!(matches!(
        ledger.remember(tombstone(200, 10_000), 1_000),
        Err(CertificateError::InvalidTransaction(_))
    ));
    assert!(
        ledger.is_revoked(&Fingerprint::of(&[0u8])),
        "the first tombstone was not evicted to make room"
    );

    // Recording the same fingerprint twice is one decision, not two slots.
    assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
    ledger.remember(tombstone(0, 9_000), 1_000).expect("merge");
    assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
}

/// Expired entries are reclaimed before the ceiling can refuse a new one.
#[test]
fn an_expired_tombstone_makes_room_for_a_new_revocation() {
    let mut ledger = TrustLedger::default();
    for seed in 0..MAX_REVOCATION_TOMBSTONES as u8 {
        ledger
            .remember(
                RevocationTombstone {
                    scope: RevocationScope::Client,
                    family: RevokedFamily::Tls,
                    fingerprint: Fingerprint::of(&[seed]),
                    revocation_epoch: u64::from(seed),
                    expires_at: if seed == 0 { 5_000 } else { 10_000 },
                    revocation_fingerprint: None,
                },
                1_000,
            )
            .expect("tombstone");
    }

    ledger
        .remember(
            RevocationTombstone {
                scope: RevocationScope::Client,
                family: RevokedFamily::Pq,
                fingerprint: Fingerprint::of(b"new decision"),
                revocation_epoch: 33,
                expires_at: 12_000,
                revocation_fingerprint: None,
            },
            5_000,
        )
        .expect("tombstone");

    assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
    assert!(!ledger.is_revoked(&Fingerprint::of(&[0])));
    assert!(ledger.is_revoked(&Fingerprint::of(b"new decision")));
}

/// Updating a decision updates its counter and signed provenance together.
#[test]
fn a_newer_revocation_of_the_same_leaf_replaces_the_whole_tombstone() {
    let mut ledger = TrustLedger::default();
    let first_document = Fingerprint::of(b"first revocation");
    let second_document = Fingerprint::of(b"second revocation");
    ledger
        .remember(
            RevocationTombstone {
                scope: RevocationScope::Client,
                family: RevokedFamily::Pq,
                fingerprint: Fingerprint::of(b"same leaf"),
                revocation_epoch: 1,
                expires_at: 9_000,
                revocation_fingerprint: Some(first_document),
            },
            1_000,
        )
        .expect("tombstone");
    ledger
        .remember(
            RevocationTombstone {
                scope: RevocationScope::Client,
                family: RevokedFamily::Pq,
                fingerprint: Fingerprint::of(b"same leaf"),
                revocation_epoch: 2,
                expires_at: 9_000,
                revocation_fingerprint: Some(second_document),
            },
            1_000,
        )
        .expect("replace");

    assert_eq!(ledger.revoked.len(), 1);
    assert_eq!(ledger.revoked[0].revocation_epoch, 2);
    assert_eq!(
        ledger.revoked[0].revocation_fingerprint,
        Some(second_document)
    );
}

/// A malformed later item cannot consume itself or leave an earlier due
/// revocation applied. The first item would revoke this client; the second
/// writes one tombstone and then conflicts on the held PQ expiry. The whole
/// batch stays at its pre-call snapshot so it can be diagnosed or retried.
fn ledger_test_gateway() -> GatewayCertificateState {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    GatewayCertificateState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        server_name: "gateway.example".into(),
        ca_epoch: 1,
        current_ca_public_key: MlDsa87PublicKey::new(vec![4; 2_592]).expect("key"),
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
            version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [3; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: crate::key_negotiation::PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
            ml_dsa_87_public_key: STANDARD
                .encode([8; crate::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN]),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: STANDARD
                .encode([9; crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN]),
        },
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: true,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    }
}

#[test]
fn apply_due_is_atomic_when_a_later_leaf_expiry_conflicts() {
    let client_generation = generation(4, 1);
    let mut client = ClientCertificateState::new(client_generation.clone());
    let mut gateway = ledger_test_gateway();
    let mut ledger = TrustLedger::default();
    ledger.scheduled_revocations.push(ScheduledRevocation {
        scope: RevocationScope::Client,
        revocation_epoch: 1,
        effective_at: 10,
        revoked_tls_fingerprint: None,
        revoked_tls_not_after: None,
        revoked_pq_fingerprint: Some(client_generation.pq_certificate_fingerprint),
        revoked_pq_not_after: Some(client_generation.not_after),
        revocation_fingerprint: Some(Fingerprint::of(b"first revocation")),
        replacement_transition_fingerprint: None,
    });
    ledger.scheduled_revocations.push(ScheduledRevocation {
        scope: RevocationScope::Client,
        revocation_epoch: 2,
        effective_at: 10,
        revoked_tls_fingerprint: Some(Fingerprint::of(b"unheld first leaf")),
        revoked_tls_not_after: Some(9_000),
        revoked_pq_fingerprint: Some(client_generation.pq_certificate_fingerprint),
        revoked_pq_not_after: Some(client_generation.not_after + 1),
        revocation_fingerprint: Some(Fingerprint::of(b"conflicting revocation")),
        replacement_transition_fingerprint: None,
    });

    let before_ledger = ledger.clone();
    let before_gateway = gateway.clone();
    let before_client = client.clone();
    assert!(matches!(
        ledger.apply_due(&mut gateway, &mut client, 10),
        Err(CertificateError::InvalidTransaction(
            "revocation expiry does not match the held certificate"
        ))
    ));
    assert_eq!(ledger, before_ledger);
    assert_eq!(gateway, before_gateway);
    assert_eq!(client, before_client);
    assert!(!client.revoked);
    assert_eq!(client.revocation_epoch, 0);
    assert!(!ledger.is_revoked(&client_generation.pq_certificate_fingerprint));
}

#[test]
fn apply_due_capacity_failure_rolls_back_then_expired_tombstone_allows_retry() {
    let client_generation = generation(4, 1);
    let mut client = ClientCertificateState::new(client_generation.clone());
    let mut gateway = ledger_test_gateway();
    let first_revoked = client_generation.pq_certificate_fingerprint;
    let second_revoked = Fingerprint::of(b"unheld revoked TLS leaf");
    let mut ledger = TrustLedger::default();
    for seed in 0..MAX_REVOCATION_TOMBSTONES - 1 {
        ledger.revoked.push(RevocationTombstone {
            scope: RevocationScope::Client,
            family: RevokedFamily::Tls,
            fingerprint: Fingerprint::of(&u64::try_from(seed).expect("small index").to_be_bytes()),
            revocation_epoch: u64::try_from(seed).expect("small index"),
            expires_at: if seed == 0 { 50 } else { 10_000 },
            revocation_fingerprint: None,
        });
    }
    ledger.scheduled_revocations = vec![
        ScheduledRevocation {
            scope: RevocationScope::Client,
            revocation_epoch: 1,
            effective_at: 10,
            revoked_tls_fingerprint: None,
            revoked_tls_not_after: None,
            revoked_pq_fingerprint: Some(first_revoked),
            revoked_pq_not_after: Some(client_generation.not_after),
            revocation_fingerprint: Some(Fingerprint::of(b"first signed revocation")),
            replacement_transition_fingerprint: None,
        },
        ScheduledRevocation {
            scope: RevocationScope::Client,
            revocation_epoch: 2,
            effective_at: 10,
            revoked_tls_fingerprint: Some(second_revoked),
            revoked_tls_not_after: Some(9_000),
            revoked_pq_fingerprint: None,
            revoked_pq_not_after: None,
            revocation_fingerprint: Some(Fingerprint::of(b"second signed revocation")),
            replacement_transition_fingerprint: None,
        },
    ];

    let before_ledger = ledger.clone();
    let before_gateway = gateway.clone();
    let before_client = client.clone();
    assert!(matches!(
        ledger.apply_due(&mut gateway, &mut client, 10),
        Err(CertificateError::InvalidTransaction(
            "no room left for a revocation tombstone"
        ))
    ));
    assert_eq!(ledger, before_ledger);
    assert_eq!(gateway, before_gateway);
    assert_eq!(client, before_client);

    // Once the oldest tombstone's signed validity ends, the same whole
    // transaction can be retried and both decisions are recorded.
    assert!(ledger
        .apply_due(&mut gateway, &mut client, 100)
        .expect("retry"));
    assert!(ledger.scheduled_revocations.is_empty());
    assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
    assert!(ledger.is_revoked(&first_revoked));
    assert!(ledger.is_revoked(&second_revoked));
    assert!(client.revoked);
    assert_eq!(client.revocation_epoch, 1);
}

#[test]
fn status_target_capacity_allows_updates_but_refuses_new_targets() {
    let mut ledger = TrustLedger::default();
    let status_for = |fingerprint: Fingerprint, status_epoch| AstraCertificateStatus {
        format_version: crate::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        certificate_fingerprint: fingerprint,
        certificate_kind: crate::certificates::status::CertificateKind::ClientPq,
        generation: 1,
        status: crate::certificates::status::CertificateStatus::Active,
        suggested_window_start: 0,
        suggested_window_end: 0,
        produced_at: 1,
        next_update: 2,
        status_epoch,
        astra_service_key_epoch: 1,
        astra_signature: super::super::encoding::MlDsa87Signature::placeholder(),
    };

    let fingerprints: Vec<_> = (0..MAX_TRACKED_STATUS_TARGETS)
        .map(|index| {
            Fingerprint::of(
                &u64::try_from(index)
                    .expect("small target index")
                    .to_be_bytes(),
            )
        })
        .collect();
    for fingerprint in &fingerprints {
        ledger
            .record_status(fingerprint, &status_for(*fingerprint, 1))
            .expect("room for status target");
    }
    let first = fingerprints[0];
    ledger
        .record_status(&first, &status_for(first, 2))
        .expect("an existing target can advance at capacity");
    assert_eq!(ledger.last_status_for(&first), Some((1, 2)));

    let new_target = Fingerprint::of(b"target beyond capacity");
    assert!(matches!(
        ledger.record_status(&new_target, &status_for(new_target, 1)),
        Err(CertificateError::InvalidTransaction(
            "too many status targets"
        ))
    ));
    assert_eq!(ledger.last_statuses.len(), MAX_TRACKED_STATUS_TARGETS);
    assert_eq!(ledger.last_status_for(&new_target), None);
}

/// After the outgoing key is retired, no `status_epoch` revives it.
#[test]
fn a_retired_astra_service_key_is_refused_whatever_it_signs() {
    let key = |seed: u8| {
        // A syntactically valid ML-DSA-87 key is 2 592 bytes; the profile
        // only ever compares and selects them here.
        MlDsa87PublicKey::new(vec![seed; 2_592])
    };
    // A byte string of the right length is not necessarily a decodable
    // key, so this test only runs when one can be built.
    let (Ok(active), Ok(next)) = (key(0), key(1)) else {
        return;
    };
    let profile = AstraProfile {
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("policy"),
        credential_registry_epoch: 1,
        credential_bindings: BTreeMap::new(),
        active_astra_service_public_key: active,
        next_astra_service_public_key: Some(next),
        next_service_key_transition_fingerprint: None,
        astra_service_key_epoch: 3,
        service_key_activation_at: Some(1_000),
        service_key_retire_active_at: Some(2_000),
        service_key_revocation_epoch: 0,
        last_emergency_replacement_fingerprint: None,
    };
    assert!(profile.service_key_for(3, 999).is_some());
    assert!(profile.service_key_for(4, 999).is_none());
    assert!(profile.service_key_for(4, 1_000).is_some());
    assert!(profile.service_key_for(3, 2_000).is_none());
}

#[test]
fn the_astra_profile_refuses_a_binding_older_than_its_global_registry() {
    let Ok(service_key) = MlDsa87PublicKey::new(vec![1; 2_592]) else {
        return;
    };
    let mut profile = AstraProfile {
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("policy"),
        credential_registry_epoch: 7,
        credential_bindings: BTreeMap::new(),
        active_astra_service_public_key: service_key,
        next_astra_service_public_key: None,
        next_service_key_transition_fingerprint: None,
        astra_service_key_epoch: 1,
        service_key_activation_at: None,
        service_key_retire_active_at: None,
        service_key_revocation_epoch: 0,
        last_emergency_replacement_fingerprint: None,
    };
    let stale = AstraCredentialBinding {
        format_version: crate::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id: vec![1],
        credential_public_key: vec![1],
        aaguid: [0; 16],
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        state: crate::certificates::approval::CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 6,
        ca_epoch: 1,
        created_at: 1,
        ca_pq_signature: super::super::encoding::MlDsa87Signature::placeholder(),
    };
    assert!(matches!(
        profile.accept_credential_binding(&stale),
        Err(CertificateError::GenerationRollback {
            current: 7,
            proposed: 6
        })
    ));
}

/// A fixed trust state, built from constant bytes only, and the fingerprint it
/// must keep.
///
/// `base_state_fingerprint` is what a manifest binds (spec §8.1): the gateway
/// and every client compute it independently and must agree byte for byte.
/// Refactoring the states around it — moving them, reordering fields,
/// splitting this module — must not move a single byte of the canonical
/// encoding, and no other test would notice if it did: they all compare two
/// fingerprints computed by the same code. If this value changes, the change
/// is a wire-format change, and it needs a new `BASE_STATE_DOMAIN`, not a new
/// constant here.
#[test]
fn the_base_state_fingerprint_is_pinned() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let gateway = GatewayCertificateState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        server_name: "gateway.example".into(),
        ca_epoch: 1,
        current_ca_public_key: MlDsa87PublicKey::new(vec![4; 2592]).expect("key"),
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
            version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [3; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: crate::key_negotiation::PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
            // Constant bytes of the exact ML-DSA-87 lengths: the fingerprint
            // decodes both halves but verifies nothing, and a real signature
            // is randomized, which a pinned value cannot be.
            ml_dsa_87_public_key: STANDARD
                .encode([8; crate::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN]),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: STANDARD
                .encode([9; crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN]),
        },
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: true,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    };
    let client_tls_ca = ClientTlsCaState {
        ca_tls_epoch: 1,
        active_client_tls_ca_certificate: DerCertificate::new(vec![5; 64]).expect("der"),
        next_client_tls_ca_certificate: None,
        next_transition_fingerprint: None,
        activation_at: None,
        retire_active_at: None,
    };
    let astra = AstraProfile {
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("pin"),
        credential_registry_epoch: 1,
        credential_bindings: BTreeMap::new(),
        active_astra_service_public_key: MlDsa87PublicKey::new(vec![6; 2592]).expect("key"),
        next_astra_service_public_key: None,
        next_service_key_transition_fingerprint: None,
        astra_service_key_epoch: 1,
        service_key_activation_at: None,
        service_key_retire_active_at: None,
        service_key_revocation_epoch: 0,
        last_emergency_replacement_fingerprint: None,
    };
    let client = ClientCertificateState::new(generation(1, 7));
    let ledger = TrustLedger::default();

    let fingerprint = base_state_fingerprint(&TrustSnapshot {
        gateway: &gateway,
        client_tls_ca: &client_tls_ca,
        astra: &astra,
        issuer_epoch: 3,
        issuer: None,
        client: &client,
        ledger: &ledger,
    })
    .expect("a well-formed state has a fingerprint");

    assert_eq!(
        fingerprint.to_hex(),
        "73d2a0af6597a32bbb10fe65cca280e874c621f43542e3f115b2c6e9497dc627"
    );
}
