//! The gateway identity gestures, against the operator's finished domain and its scripted
//! gateway and Astra (the renewal's and the revocation's own remotes).
//!
//! The vault, the campaigns, the signatures and the record are production code. Simulated
//! here: the CTAP2 boundary (the keys) and the tunnel, through the operator's remotes.

use std::cell::Cell;
use std::sync::mpsc::channel;

use aether::certificates::encoding::{Fingerprint, Id16, WireGuardKey};
use aether::certificates::operator_session::{
    AstraManifest, GestureState, OperatorAction, OperatorStatus, Refusal,
};
use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};
use aether::certificates::transport::SigningOperationState;
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::fixtures::{gateway_key, Domain, TestKey, EXPIRES, NOW};
use astra_operator::operations::gateway_identity::tests::{
    gateway_read, Remote as RenewalRemote, Scenario, ACTIVE_TLS,
};
use astra_operator::operations::gateway_identity::{self, GatewayIdentityRemote};
use astra_operator::operations::gateway_revocation::tests::Remote as RevocationRemote;
use astra_operator::operations::revocation::RevocationReasonChoice;
use astra_operator::tunnel::GatewayIdentityRead;

use super::super::Press;
use super::probe;
use super::{discard_waiting, run_with, Reach};
use crate::operator::rotations::{gateway_pending_of, Local, RotationsOverview};
use crate::operator::{GatewayGesture, GatewayTarget, Words};

const DAY: u64 = 86_400;

/// Nothing answers at this address: a tunnel to it reaches no Astra.
const NO_ONE_ANSWERS: &str = "http://127.0.0.1:1";

/// The sentence a waiting revocation with its replacement deposited answers with.
const REVOCATION_TO_SIGN: &str =
    "La révocation reste à signer : choisir « Révoquer la gateway ». Rien n'a été révoqué.";

/// What the operator does at each key the ceremony asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Touches the key, which is the domain's first.
    Keys,
    /// Abandons at the first key asked.
    CancelAtKey,
    /// Touches the first round's keys, and abandons at the second round's first key.
    CancelSecondRound,
}

/// Everything one run left behind.
struct Ran {
    outcome: Result<(), String>,
    statuses: Vec<OperatorStatus>,
    keys_connected: u32,
    /// The sentence the run stored for the page, if it stored one.
    words: Option<String>,
    /// Openings made, and openings dropped, by the run.
    openings: (usize, usize),
}

impl Ran {
    fn last(&self) -> &OperatorStatus {
        self.statuses.last().expect("a status")
    }

    /// The statuses that asked for a key, in order.
    fn awaiting_keys(&self) -> Vec<&OperatorStatus> {
        self.statuses
            .iter()
            .filter(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
            .collect()
    }
}

/// The domain's first key, registered for the fixture's credential.
fn key(serial: u8) -> Box<dyn Authenticator> {
    let key = TestKey::new(serial);
    key.registered.set(true);
    Box::new(key)
}

fn target(peer: WireGuardKey) -> GatewayTarget {
    GatewayTarget {
        address: NO_ONE_ANSWERS.into(),
        peer_key: peer.to_base64(),
        own_key: None,
    }
}

fn renewal(rotate_tls: bool, key_recovery: bool) -> GatewayGesture {
    GatewayGesture::Renew {
        rotate_tls,
        key_recovery,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 365,
    }
}

/// Drives one gesture through the ceremony, answering each key as `answer` says, at `now`.
fn drive(
    domain: &Domain,
    remote: &dyn GatewayIdentityRemote,
    peer: WireGuardKey,
    gesture: GatewayGesture,
    requested_by: &str,
    answer: Answer,
    now: u64,
) -> Ran {
    let (sender, received) = channel::<Press>();
    let connected = Cell::new(0_u32);
    let connect = |_owner: isize| -> Result<Box<dyn Authenticator>, (Refusal, String)> {
        connected.set(connected.get() + 1);
        Ok(key(1))
    };
    let clock = Cell::new(now);
    let now_of = || clock.get();
    let reach = Reach {
        remote,
        connect: &connect,
        now: &now_of,
    };
    let words: Words = Default::default();
    let mut statuses = Vec::new();
    probe::reset();
    let outcome = {
        let mut publish = |status: OperatorStatus| {
            if matches!(status.gesture, GestureState::AwaitingKey { .. }) {
                let revocation_round =
                    matches!(status.manifest, Some(AstraManifest::Revocation(_)));
                let action = match answer {
                    Answer::Keys => OperatorAction::Continue,
                    Answer::CancelAtKey => OperatorAction::Cancel,
                    Answer::CancelSecondRound if revocation_round => OperatorAction::Cancel,
                    Answer::CancelSecondRound => OperatorAction::Continue,
                };
                let _ = sender.send(Press {
                    action,
                    revision: status.revision,
                    owner: 0,
                    terms: None,
                });
            }
            statuses.push(status);
        };
        run_with(
            Id16::new([5; 16]).expect("id"),
            gesture,
            &target(peer),
            received,
            &mut publish,
            &domain.path,
            requested_by,
            &words,
            &reach,
        )
    };
    let (made, dropped) = probe::counts();
    let words = words
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ran {
        outcome,
        statuses,
        keys_connected: connected.get(),
        words,
        openings: (made, dropped),
    }
}

/// A gateway the domain's relay does not name.
fn other_gateway() -> WireGuardKey {
    WireGuardKey::from_bytes([9; 32])
}

/// A renewal whose installation the gateway refuses after the deposit: the record stays
/// waiting, and the refusal's sentence is kept for the page.
fn refused_install(scenario: &Scenario, remote: &RenewalRemote<'_>) -> Ran {
    remote.install_replies.borrow_mut().push_back(409);
    drive(
        &scenario.domain,
        remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    )
}

#[test]
fn renew_runs_to_published() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(ran.last().gesture, GestureState::Done);
    assert_eq!(ran.keys_connected, 1, "one key approves the renewal");
    assert!(remote.called("publish"), "the transition is published");
    assert_eq!(
        ran.openings,
        (1, 1),
        "the opening made is the opening dropped"
    );
    let asked = ran.awaiting_keys();
    assert!(
        matches!(asked[0].manifest, Some(AstraManifest::Campaign(_))),
        "the campaign is shown before the key is asked for"
    );
    assert!(
        gateway_identity::pending(&scenario.domain.path, NOW)
            .expect("read")
            .is_none(),
        "a published renewal clears its record"
    );
}

#[test]
fn abort_runs_to_its_end() {
    let scenario = Scenario::new(false);
    let mut remote = RenewalRemote::new(&scenario);
    let renewed = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );
    renewed.outcome.expect("renewed");
    // The transition is staged on the gateway and not yet published: its cancellation is open.
    let transition = remote.installed.borrow()[0].clone();
    let epoch = transition.gateway_identity_epoch;
    remote.campaign = scenario.domain.campaign(
        CampaignScope::GatewayIdentity,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayPq,
            identity_key: gateway_key(),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: Fingerprint::of(ACTIVE_TLS),
            active_pq_certificate_fingerprint: scenario.leaf(),
        }],
        EXPIRES,
    );
    remote.staged = Some(transition.clone());
    remote.gateway = GatewayIdentityRead {
        now_unix: Some(NOW),
        gateway_identity_epoch: epoch,
        gateway_transition_pending: true,
        gateway_transition_published: false,
        gateway_activation_at: Some(transition.window.activation_at),
        ..gateway_read()
    };

    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Abort,
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(ran.last().gesture, GestureState::Done);
    assert_eq!(
        remote.aborted.borrow().len(),
        1,
        "the cancellation is installed"
    );
    assert!(remote.called("abort"));
    assert_eq!(ran.openings, (1, 1));
    assert!(
        gateway_identity::pending(&scenario.domain.path, NOW)
            .expect("read")
            .is_none(),
        "a finished cancellation clears its record"
    );
}

#[test]
fn rollback_names_this_workstation_as_requester() {
    let scenario = Scenario::new(false);
    let mut remote = RenewalRemote::new(&scenario);
    let renewed = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );
    renewed.outcome.expect("renewed");
    // The gateway holds the transition published, inside its overlap.
    let transition = remote.installed.borrow()[0].clone();
    let clock = NOW + 8 * DAY;
    remote.staged = Some(transition.clone());
    remote.gateway = GatewayIdentityRead {
        now_unix: Some(clock),
        gateway_identity_epoch: transition.gateway_identity_epoch,
        gateway_transition_pending: true,
        gateway_transition_published: true,
        gateway_activation_at: Some(transition.window.activation_at),
        ..gateway_read()
    };

    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Rollback {
            hours: 24,
            reason: "Retour arrière".into(),
        },
        "poste-1",
        Answer::Keys,
        clock,
    );

    assert_eq!(ran.outcome, Ok(()));
    let asked = ran.awaiting_keys();
    let Some(AstraManifest::Campaign(manifest)) = &asked[0].manifest else {
        panic!("the rollback's campaign is shown before its key");
    };
    assert_eq!(
        manifest.campaign.requested_by, "poste-1",
        "the campaign names this workstation as the requester"
    );
    assert_eq!(remote.rolled.borrow().len(), 1);
}

#[test]
fn revoke_with_replacement_publishes_two_key_rounds() {
    let scenario = Scenario::new(true);
    let remote = RevocationRemote::new(&scenario);
    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Revoke {
            reason: RevocationReasonChoice::StolenOrLost,
            with_replacement: true,
        },
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(
        ran.keys_connected, 2,
        "two key rounds: replacement, then revocation"
    );
    assert_eq!(ran.last().gesture, GestureState::Done);
    assert_eq!(ran.openings, (2, 2));
    let asked = ran.awaiting_keys();
    assert_eq!(asked.len(), 2);
    assert!(matches!(
        asked[0].manifest,
        Some(AstraManifest::Campaign(_))
    ));
    // The second round shows the replacement's fingerprint: the document the gateway accepts.
    let Some(AstraManifest::Revocation(revocation)) = &asked[1].manifest else {
        panic!("the second round shows the revocation");
    };
    let installed = remote.installed.borrow();
    assert_eq!(installed.len(), 1, "the replacement is installed");
    assert_eq!(
        revocation.replacement_transition_fingerprint,
        Some(installed[0].fingerprint().expect("fingerprint")),
        "the second press shows the replacement transition's fingerprint"
    );
}

#[test]
fn resume_without_a_record_does_nothing() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Resume,
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(ran.last().gesture, GestureState::Done);
    assert!(
        remote.calls().is_empty(),
        "nothing is asked of the gateway or Astra"
    );
    assert_eq!(ran.keys_connected, 0);
}

#[test]
fn resume_applies_a_waiting_renewal() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let first = refused_install(&scenario, &remote);
    assert!(first.outcome.is_err());

    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Resume,
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(
        ran.keys_connected, 0,
        "a waiting renewal is carried with no key"
    );
    // The fake records the refused attempt too: the resume's install is the second.
    assert_eq!(remote.installed.borrow().len(), 2);
    assert!(remote.called("publish"));
    assert!(gateway_identity::pending(&scenario.domain.path, NOW)
        .expect("read")
        .is_none());
}

#[test]
fn resume_applies_a_signed_revocation_whose_apply_was_lost() {
    let scenario = Scenario::new(true);
    let remote = RevocationRemote::new(&scenario);
    // The replacement is accepted; the revocation's deposit answer is lost.
    remote
        .submit_replies
        .borrow_mut()
        .push_back(Ok(SigningOperationState::Approved));
    remote.submit_replies.borrow_mut().push_back(Err(500));
    let first = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Revoke {
            reason: RevocationReasonChoice::StolenOrLost,
            with_replacement: true,
        },
        "",
        Answer::Keys,
        NOW,
    );
    assert!(first.outcome.is_err(), "the lost answer ends the gesture");
    assert!(
        remote.installed.borrow().is_empty(),
        "nothing is installed yet"
    );

    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Resume,
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Ok(()));
    assert_eq!(
        ran.keys_connected, 0,
        "the signed revocation is deposited with no key"
    );
    assert_eq!(
        remote.installed.borrow().len(),
        1,
        "the replacement follows the revocation"
    );
    assert!(gateway_identity::pending(&scenario.domain.path, NOW)
        .expect("read")
        .is_none());
}

#[test]
fn resume_of_a_revocation_to_sign_says_so_before_any_call() {
    let scenario = Scenario::new(true);
    let remote = RevocationRemote::new(&scenario);
    // The replacement is deposited; the operator cancels before signing the revocation.
    let stopped = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Revoke {
            reason: RevocationReasonChoice::StolenOrLost,
            with_replacement: true,
        },
        "",
        Answer::CancelSecondRound,
        NOW,
    );
    assert_eq!(stopped.outcome, Ok(()));
    let calls_before = remote.calls().len();

    let ran = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        GatewayGesture::Resume,
        "",
        Answer::Keys,
        NOW,
    );

    assert_eq!(ran.outcome, Err(REVOCATION_TO_SIGN.to_string()));
    assert_eq!(ran.last().refusal, Some(Refusal::RevocationToSign));
    assert_eq!(ran.words.as_deref(), Some(REVOCATION_TO_SIGN));
    assert_eq!(
        remote.calls().len(),
        calls_before,
        "nothing is called before the refusal"
    );
    assert_eq!(ran.keys_connected, 0);
    assert!(remote.installed.borrow().is_empty(), "nothing is revoked");
}

#[test]
fn another_domains_gateway_is_never_touched() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = drive(
        &scenario.domain,
        &remote,
        other_gateway(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );

    assert!(ran.outcome.is_err());
    assert_eq!(ran.last().refusal, Some(Refusal::HandoffMismatch));
    assert!(
        remote.calls().is_empty(),
        "no call reaches the other domain's gateway"
    );
    assert_eq!(ran.keys_connected, 0);
    assert_eq!(ran.openings, (0, 0), "the guard refuses before any opening");
}

#[test]
fn opened_is_erased_on_every_exit() {
    // Through the approval and the publication.
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let approved = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );
    assert_eq!(approved.outcome, Ok(()));
    assert_eq!(approved.openings.0, 1, "the approval made an opening");
    assert_eq!(approved.openings.0, approved.openings.1);

    // Out at the first key, which the operator cancels after the opening is held.
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let cancelled = drive(
        &scenario.domain,
        &remote,
        gateway_key(),
        renewal(false, false),
        "",
        Answer::CancelAtKey,
        NOW,
    );
    assert!(cancelled.outcome.is_ok());
    assert!(
        !remote.called("install"),
        "a cancelled approval installs nothing"
    );
    assert_eq!(cancelled.openings.0, cancelled.openings.1);

    // Out after the opening is signed and deposited, when the gateway refuses the install.
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let refused = refused_install(&scenario, &remote);
    assert!(refused.outcome.is_err());
    assert_eq!(
        refused.openings.0, 1,
        "the refused install follows an opening"
    );
    assert_eq!(refused.openings.0, refused.openings.1);

    // Out of the guard, before any opening: nothing made, nothing to drop.
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let guarded = drive(
        &scenario.domain,
        &remote,
        other_gateway(),
        renewal(false, false),
        "",
        Answer::Keys,
        NOW,
    );
    assert_eq!(guarded.openings, (0, 0));
}

#[test]
fn overview_reads_the_gateway_fields() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = refused_install(&scenario, &remote);
    assert!(ran.outcome.is_err());

    let view = gateway_pending_of(&scenario.domain.path, NOW).expect("a decision waits");
    assert_eq!(view.kind, "decision");
    assert_eq!(view.decision_kind.as_deref(), Some("renewal"));
    assert!(!view.installed && !view.published);
    assert!(!view.revocation_to_sign);

    let local = Local {
        gateway_pending: Some(view),
        ..Local::default()
    };
    let overview = RotationsOverview::assemble(
        true,
        orion_core::operator_rotations::Reach::Unreachable,
        orion_core::operator_rotations::Reach::Unreachable,
        orion_core::operator_rotations::Reach::Unreachable,
        orion_core::operator_rotations::Reach::Unreachable,
        local,
    );
    let shown = serde_json::to_value(overview).expect("json");
    assert_eq!(shown["gatewayPending"]["kind"], "decision");
    assert_eq!(shown["gatewayPending"]["decision_kind"], "renewal");
}

#[test]
fn discard_drops_the_waiting_record() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = refused_install(&scenario, &remote);
    assert!(ran.outcome.is_err());
    assert!(gateway_identity::pending(&scenario.domain.path, NOW)
        .expect("read")
        .is_some());

    discard_waiting(&scenario.domain.path).expect("discarded");

    assert!(gateway_identity::pending(&scenario.domain.path, NOW)
        .expect("read")
        .is_none());
}

#[test]
fn a_refusal_after_the_deposit_keeps_its_sentence_for_the_page() {
    let scenario = Scenario::new(false);
    let remote = RenewalRemote::new(&scenario);
    let ran = refused_install(&scenario, &remote);
    let message = ran.outcome.expect_err("refused");
    assert_eq!(ran.words.as_deref(), Some(message.as_str()));
    assert!(!message.is_empty());
}
