//! The revocation, against a gateway and an Astra that answer as the test says.
//!
//! The domain is astra-operator's finished fixture: its vault, its document, its
//! campaigns and every signature are production code. Simulated here: the CTAP2
//! boundary (the keys), the tunnel to Astra and the gateway's admission.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::mpsc::{channel, Sender};

use aether::certificates::encoding::{Fingerprint, Id16, WireGuardKey};
use aether::certificates::operator_session::{
    AstraManifest, GestureState, OperationLocator, OperatorAction, OperatorStatus, Refusal,
    RemoteState,
};
use aether::certificates::status::{
    AstraSignerResult, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorOpenRequest, OperatorOpened, RevocationExpiries,
    SigningOperationState,
};
use aether_fido::authenticator::Authenticator;
use anyhow::{anyhow, Result};
use astra_operator::handoff;
use astra_operator::operations::fixtures::{
    domain, gateway_key, nothing_in_flight, operation, Domain, TestKey, EXPIRES, NOW,
};
use astra_operator::operations::revocation::{RevocationReasonChoice, RevocationRemote};
use astra_operator::origin::CampaignRequest;
use astra_operator::tunnel::Tunnel;
use orion_core::gateway_admin::{AdmittedPeer, GatewayAdminError};

use super::super::Press;
use super::{run_with, Ceremony, Reach, RevocationRun};
use crate::operator::{GatewayTarget, RevocationGesture};

/// Nothing answers at this address: a tunnel to it reaches no Astra.
const NO_ONE_ANSWERS: &str = "http://127.0.0.1:1";

const TLS_NOT_AFTER: u64 = EXPIRES + 86_400;
const PQ_NOT_AFTER: u64 = EXPIRES + 2 * 86_400;

/// The workstation the gesture cuts. Its key is never a key of the domain.
fn peer() -> WireGuardKey {
    WireGuardKey::from_bytes([7; 32])
}

fn other_key() -> WireGuardKey {
    WireGuardKey::from_bytes([8; 32])
}

/// The one row an emergency revocation of `key` carries, as the door resolves it.
fn revocation_campaign(
    domain: &Domain,
    key: WireGuardKey,
) -> aether::certificates::status::AstraRotationCampaign {
    domain.campaign(
        CampaignScope::EmergencyRevocation,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientTls,
            identity_key: key,
            epoch: 0,
            generation: 0,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls leaf"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq leaf"),
        }],
        EXPIRES,
    )
}

/// The tunnel to Astra, scripted: its status, its campaigns, and each call by name.
struct Remote {
    authority: RefCell<OperatorAuthorityStatus>,
    overlap: Cell<Option<u64>>,
    requests: RefCell<VecDeque<CampaignRequest>>,
    calls: RefCell<Vec<&'static str>>,
    submitted: Cell<u32>,
    /// Whether the deposit fails in transport: the decision stays on disk.
    deposit_fails: Cell<bool>,
}

impl Remote {
    /// Astra as the fixture domain leaves it, with a campaign for `peer` ready for each
    /// of `fetches` reads: one per opening, one per deposit.
    fn armed(domain: &Domain, fetches: usize) -> Self {
        Self {
            authority: RefCell::new(nothing_in_flight(&domain.path)),
            overlap: Cell::new(None),
            requests: RefCell::new(
                (0..fetches)
                    .map(|_| domain.request(revocation_campaign(domain, peer())))
                    .collect(),
            ),
            calls: RefCell::default(),
            submitted: Cell::new(0),
            deposit_fails: Cell::new(false),
        }
    }

    fn called(&self, name: &'static str) -> bool {
        self.calls.borrow().contains(&name)
    }

    fn note(&self, name: &'static str) {
        self.calls.borrow_mut().push(name);
    }
}

impl RevocationRemote for Remote {
    fn open_campaign(&self, _request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        self.note("open_campaign");
        Ok(OperatorOpened {
            operation_id: operation(),
            campaign_id: Id16::new([9; 16]).expect("id"),
            campaign_fingerprint: Fingerprint::of(b"campagne"),
            scope: CampaignScope::EmergencyRevocation,
            target_count: 1,
            required_credentials: 1,
            expires_at: EXPIRES,
            revocation_expiries: Some(RevocationExpiries {
                tls_not_after: Some(TLS_NOT_AFTER),
                pq_not_after: Some(PQ_NOT_AFTER),
            }),
            delegation_request: None,
        })
    }

    fn fetch_campaign(&self, _operation_id: &Id16) -> Result<CampaignRequest> {
        self.note("fetch_campaign");
        self.requests
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| anyhow!("no campaign armed"))
    }

    fn submit_campaign(
        &self,
        _operation_id: &Id16,
        _result_token: &str,
        _result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        self.note("submit_campaign");
        self.submitted.set(self.submitted.get() + 1);
        if self.deposit_fails.get() {
            return Err(anyhow!("le dépôt a été perdu en route"));
        }
        Ok(SigningOperationState::Approved)
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        self.note("authority_status");
        Ok(self.authority.borrow().clone())
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        self.note("overlap_not_after");
        Ok(self.overlap.get())
    }
}

/// The gateway's admission, as the test states it, and the calls the cut made.
struct Gateway {
    admitted: Vec<AdmittedPeer>,
    reads: Cell<usize>,
    cuts: Cell<usize>,
}

impl Gateway {
    fn admitting(name: &str, key: &WireGuardKey) -> Self {
        Self {
            admitted: vec![AdmittedPeer {
                name: name.to_string(),
                wg_public_key: key.to_base64(),
            }],
            reads: Cell::new(0),
            cuts: Cell::new(0),
        }
    }

    fn read(&self, _base: &str) -> Result<Vec<AdmittedPeer>, GatewayAdminError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.admitted.clone())
    }

    fn withdraw(&self, _base: &str, _name: &str) -> Result<(), GatewayAdminError> {
        self.cuts.set(self.cuts.get() + 1);
        Ok(())
    }
}

/// What the operator does at each key the ceremony asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Touches the key, which is the domain's first.
    Keys,
    /// Abandons at the first key asked.
    CancelAtKey,
}

/// A key of the domain, connected as the window would connect it.
fn key(serial: u8) -> Box<dyn Authenticator> {
    let key = TestKey::new(serial);
    key.registered.set(true);
    Box::new(key)
}

/// Everything one run left behind.
struct Ran {
    outcome: Result<(), String>,
    published: Vec<OperatorStatus>,
    keys_connected: u32,
}

impl Ran {
    fn last(&self) -> &OperatorStatus {
        self.published.last().expect("a status")
    }

    fn refused(&self, refusal: Refusal) {
        assert!(self.outcome.is_err(), "the run stops");
        assert_eq!(self.last().gesture, GestureState::Failed);
        assert_eq!(self.last().refusal, Some(refusal));
    }
}

/// Runs a gesture through [`run_with`], answering each key the way `answer` says.
fn drive(
    domain: &Domain,
    gesture: RevocationGesture,
    target: &GatewayTarget,
    gateway: &Gateway,
    remote: &dyn RevocationRemote,
    answer: Answer,
) -> Ran {
    let connected = Cell::new(0u32);
    let (presses, received) = channel::<Press>();
    let mut sender: Option<Sender<Press>> = Some(presses);
    let mut published = Vec::new();
    let connect = |_owner: isize| {
        connected.set(connected.get() + 1);
        Ok(key(1))
    };
    let now = || NOW;
    let reach = Reach {
        remote,
        admitted: &|base: &str| gateway.read(base),
        withdraw: &|base: &str, name: &str| gateway.withdraw(base, name),
        connect: &connect,
        now: &now,
    };
    let outcome = {
        let mut publish = |status: OperatorStatus| {
            if let (GestureState::AwaitingKey { .. }, Some(sender)) = (status.gesture, &sender) {
                let action = match answer {
                    Answer::Keys => OperatorAction::Continue,
                    Answer::CancelAtKey => OperatorAction::Cancel,
                };
                let _ = sender.send(Press {
                    action,
                    revision: status.revision,
                    owner: 0,
                    terms: None,
                });
            }
            published.push(status);
        };
        run_with(
            Id16::new([6; 16]).expect("session"),
            gesture,
            target,
            received,
            &mut publish,
            &domain.path,
            &reach,
        )
    };
    sender.take();
    Ran {
        outcome,
        published,
        keys_connected: connected.get(),
    }
}

fn target(own_key: Option<WireGuardKey>) -> GatewayTarget {
    GatewayTarget {
        address: NO_ONE_ANSWERS.into(),
        peer_key: gateway_key().to_base64(),
        own_key: own_key.map(|key| key.to_base64()),
    }
}

fn revoke(peer: &WireGuardKey, name: &str) -> RevocationGesture {
    RevocationGesture::Revoke {
        peer: peer.to_base64(),
        name: name.to_string(),
        reason: RevocationReasonChoice::StolenOrLost,
    }
}

fn pending_on_disk(domain: &Domain) -> bool {
    domain
        .path
        .parent()
        .expect("parent")
        .join("pending-revocation.json")
        .exists()
}

/// A name the gateway binds to another key is never cut, whatever the operator chose.
#[test]
fn cut_refuses_a_name_bound_to_another_key() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &other_key());
    let remote = Remote::armed(&domain, 0);
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &remote,
        Answer::Keys,
    );

    ran.refused(Refusal::PeerNameMismatch);
    assert_eq!(gateway.cuts.get(), 0, "nothing is cut");
    assert!(!ran.last().peer_cut);
    assert!(remote.calls.borrow().is_empty(), "Astra is not asked");
}

/// This workstation is never cut: its own console would go with it.
#[test]
fn this_workstation_is_never_cut() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 0);
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(Some(peer())),
        &gateway,
        &remote,
        Answer::Keys,
    );

    ran.refused(Refusal::SelfRevocation);
    assert_eq!(gateway.reads.get(), 0, "the admission is not even read");
    assert_eq!(gateway.cuts.get(), 0, "nothing is cut");
}

/// A tunnel to a gateway the domain's relay does not name cuts nothing.
#[test]
fn another_domains_gateway_is_never_cut() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 0);
    let mut elsewhere = target(None);
    elsewhere.peer_key = other_key().to_base64();
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &elsewhere,
        &gateway,
        &remote,
        Answer::Keys,
    );

    ran.refused(Refusal::HandoffMismatch);
    assert_eq!(gateway.reads.get(), 0);
    assert_eq!(gateway.cuts.get(), 0);
}

/// Astra unreachable after the cut: the workstation stays cut, and the refusal says so.
#[test]
fn cut_happens_without_astra() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let unanswering = Tunnel::new(NO_ONE_ANSWERS).expect("tunnel");
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &unanswering,
        Answer::Keys,
    );

    ran.refused(Refusal::AuthorityUnreachable);
    assert_eq!(gateway.cuts.get(), 1, "the admission is withdrawn");
    assert!(ran.last().peer_cut, "the refusal is said after the cut");
    assert_eq!(
        ran.keys_connected, 0,
        "no key is asked before Astra answers"
    );
}

/// The outgoing `CA-PQ` may sign only until the margin: inside it, the cut stands and the
/// refusal names the date, and no campaign is opened.
///
/// The fixture vault keeps no outgoing key, so the window is the one a vault from before
/// the keeping had: Astra on the previous epoch, and the gateway's word on when it ends.
#[test]
fn cut_happens_inside_the_margin() {
    let domain = domain();
    let epoch = handoff::identity_of(&domain.relay())
        .expect("identity")
        .ca_epoch;
    let window_ends = NOW + 3_600;
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 0);
    remote.overlap.set(Some(window_ends));
    {
        let mut authority = remote.authority.borrow_mut();
        authority.ca_fingerprint = Fingerprint::of(b"the previous anchor");
        authority.ca_epoch = epoch - 1;
    }
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &remote,
        Answer::Keys,
    );

    ran.refused(Refusal::RevocationNotBefore { until: window_ends });
    assert_eq!(
        gateway.cuts.get(),
        1,
        "the cut is not held back by the margin"
    );
    assert!(ran.last().peer_cut);
    assert!(!remote.called("open_campaign"), "no campaign is opened");
}

/// The operator sees what the campaign names before any key is touched.
#[test]
fn the_manifest_names_the_peer_before_any_press() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 2);
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &remote,
        Answer::Keys,
    );

    let shown = ran
        .published
        .iter()
        .position(|status| status.manifest.is_some())
        .expect("a status names the campaign");
    let asking = ran
        .published
        .iter()
        .position(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked");
    // The manifest is published before the first key is asked for, and it stays on.
    assert!(
        shown < asking,
        "the campaign is shown before any key is asked"
    );
    assert!(ran.published[shown..]
        .iter()
        .all(|status| status.manifest.is_some()));
    let Some(AstraManifest::Revocation(manifest)) = &ran.published[shown].manifest else {
        panic!("the status names the revocation");
    };
    assert_eq!(manifest.target, peer().to_base64());
    assert_eq!(manifest.scope, "emergency_revocation");
    assert_eq!(manifest.reason, "Volé ou perdu");
    assert_eq!(manifest.revocation_epoch, 1);
    ran.outcome.as_ref().expect("the run completes");
}

/// The whole gesture: cut, open, one key, signature, deposit.
#[test]
fn revoke_runs_to_revoked() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 2);
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &remote,
        Answer::Keys,
    );

    ran.outcome.as_ref().expect("the revocation completes");
    assert_eq!(ran.last().gesture, GestureState::Done);
    assert_eq!(ran.last().refusal, None);
    assert_eq!(ran.last().remote, RemoteState::Deposited);
    assert!(ran.last().peer_cut);
    assert_eq!(gateway.cuts.get(), 1);
    assert_eq!(remote.submitted.get(), 1, "the decision is deposited once");
    assert_eq!(ran.last().approved.len(), 1);
    assert!(
        !pending_on_disk(&domain),
        "the record leaves with the deposit"
    );
}

/// A decision lost in transport stays on disk, and « Reprendre » deposits it again with
/// no key touched.
#[test]
fn resume_redeposits_without_a_key() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let lost = Remote::armed(&domain, 2);
    lost.deposit_fails.set(true);
    let first = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &lost,
        Answer::Keys,
    );
    assert!(first.outcome.is_err());
    assert!(first.last().peer_cut, "the cut stands");
    assert!(
        pending_on_disk(&domain),
        "the decision is kept for the next try"
    );

    let back = Remote::armed(&domain, 1);
    let resumed = drive(
        &domain,
        RevocationGesture::Resume {
            peer: peer().to_base64(),
            reason: RevocationReasonChoice::StolenOrLost,
        },
        &target(None),
        &gateway,
        &back,
        Answer::Keys,
    );

    resumed.outcome.as_ref().expect("the deposit goes through");
    assert_eq!(
        resumed.keys_connected, 0,
        "no key is asked to deposit again"
    );
    assert_eq!(resumed.last().gesture, GestureState::Done);
    assert_eq!(back.submitted.get(), 1);
    assert!(!pending_on_disk(&domain));
}

/// Whatever ends a revocation, the opening held for its approval is erased: the way out
/// of the step, not the operator's choice, decides nothing about it.
#[test]
fn opened_is_erased_on_every_exit() {
    fn held_after(
        domain: &Domain,
        gesture: RevocationGesture,
        answer: Answer,
        remote: &Remote,
        clock_at_key: Option<u64>,
    ) -> (Result<(), String>, bool) {
        let gateway = Gateway::admitting("poste-1", &peer());
        let clock = Cell::new(NOW);
        let (presses, received) = channel::<Press>();
        let mut sender: Option<Sender<Press>> = Some(presses);
        let connect = |_owner: isize| {
            if let Some(at) = clock_at_key {
                clock.set(at);
            }
            Ok(key(1))
        };
        let now = || clock.get();
        let reach = Reach {
            remote,
            admitted: &|base: &str| gateway.read(base),
            withdraw: &|base: &str, name: &str| gateway.withdraw(base, name),
            connect: &connect,
            now: &now,
        };
        let target = target(None);
        let mut ceremony = Ceremony::new(
            Id16::new([4; 16]).expect("id"),
            OperationLocator {
                kind: gesture.operation(),
                operation_id: None,
            },
        );
        let mut publish = |status: OperatorStatus| {
            if let (GestureState::AwaitingKey { .. }, Some(sender)) = (status.gesture, &sender) {
                let action = match answer {
                    Answer::Keys => OperatorAction::Continue,
                    Answer::CancelAtKey => OperatorAction::Cancel,
                };
                let _ = sender.send(Press {
                    action,
                    revision: status.revision,
                    owner: 0,
                    terms: None,
                });
            }
        };
        let mut run = RevocationRun::new(
            &mut ceremony,
            &received,
            &mut publish,
            &domain.path,
            &target.address,
            peer(),
            &reach,
        );
        let outcome = run.run(&gesture);
        let held = run.held.is_some();
        drop(run);
        sender.take();
        (outcome, held)
    }

    let domain = domain();
    let revoke_gesture = revoke(&peer(), "poste-1");

    // Completed: the signature took the opening.
    let (outcome, held) = held_after(
        &domain,
        revoke_gesture.clone(),
        Answer::Keys,
        &Remote::armed(&domain, 2),
        None,
    );
    outcome.expect("completed");
    assert!(!held, "completed");

    // Abandoned at the key: the opening was held when the key was asked.
    let (outcome, held) = held_after(
        &domain,
        revoke_gesture.clone(),
        Answer::CancelAtKey,
        &Remote::armed(&domain, 2),
        None,
    );
    outcome.expect("abandoning ends cleanly");
    assert!(!held, "abandoned");

    // The window closes between the touch and the approval: refused, and erased.
    let (outcome, held) = held_after(
        &domain,
        revoke_gesture.clone(),
        Answer::Keys,
        &Remote::armed(&domain, 2),
        Some(EXPIRES),
    );
    assert!(outcome.is_err(), "the window is closed");
    assert!(!held, "refused at the approval");

    // Astra refuses the opening itself: nothing was ever held.
    let refused_at_open = Remote::armed(&domain, 2);
    refused_at_open
        .authority
        .borrow_mut()
        .revoked_peers
        .push(peer());
    let (outcome, held) = held_after(
        &domain,
        revoke_gesture,
        Answer::Keys,
        &refused_at_open,
        None,
    );
    assert!(outcome.is_err(), "already revoked");
    assert!(!held, "refused at the opening");
}

/// A resumption runs for a workstation already cut, and a refusal it says tells so.
#[test]
fn a_failing_resume_says_the_workstation_is_cut() {
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let unanswering = Tunnel::new(NO_ONE_ANSWERS).expect("tunnel");
    let ran = drive(
        &domain,
        RevocationGesture::Resume {
            peer: peer().to_base64(),
            reason: RevocationReasonChoice::StolenOrLost,
        },
        &target(None),
        &gateway,
        &unanswering,
        Answer::Keys,
    );

    ran.refused(Refusal::AuthorityUnreachable);
    assert!(
        ran.last().peer_cut,
        "the refusal says the workstation is cut"
    );
    assert_eq!(gateway.cuts.get(), 0, "a resumption cuts nothing");
}

/// Every JSON key, at any depth, of what the window receives.
fn json_keys(value: &serde_json::Value, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                keys.push(key.clone());
                json_keys(inner, keys);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| json_keys(item, keys)),
        _ => {}
    }
}

/// The revocation's statuses carry labels only: no key name that names a secret, no
/// deposit token, and no credential's bytes in any form the window could receive.
#[test]
fn the_webview_status_carries_labels_only() {
    use base64::Engine as _;
    let domain = domain();
    let gateway = Gateway::admitting("poste-1", &peer());
    let remote = Remote::armed(&domain, 2);
    let ran = drive(
        &domain,
        revoke(&peer(), "poste-1"),
        &target(None),
        &gateway,
        &remote,
        Answer::Keys,
    );
    ran.outcome.as_ref().expect("the revocation completes");
    let credential = TestKey::new(1).credential_id();

    for status in &ran.published {
        let value = serde_json::to_value(status).expect("status");
        let mut keys = Vec::new();
        json_keys(&value, &mut keys);
        for key in &keys {
            let lowered = key.to_lowercase();
            for forbidden in ["secret", "pin", "token", "wrapped", "sealed", "opening"] {
                assert!(!lowered.contains(forbidden), "{key}");
            }
        }
        let text = value.to_string();
        assert!(!text.contains("jeton-de-depot"), "the deposit's token");
        let hex: String = credential
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let standard = base64::engine::general_purpose::STANDARD.encode(&credential);
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential);
        let raw = serde_json::to_string(&credential).expect("array");
        for form in [hex, standard, url, raw] {
            assert!(!text.contains(&form), "a credential's bytes as {form}");
        }
    }
}
