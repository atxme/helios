//! The gateway's identity gestures (F14 lot 6b), run as an operator ceremony.
//!
//! The sequences are [`astra_operator::operations::gateway_identity`]'s and
//! [`astra_operator::operations::gateway_revocation`]'s; this module puts the touches and
//! the publications between them, and words what they refuse as a [`Refusal`]. The sentence
//! of a refusal goes to the page as it is, through [`Words`], and never through a status.
//!
//! # What stays here
//!
//! The openings a campaign released are held for the length of the approval, and nothing
//! else. Each one is an [`Opening`]: it is dropped when it is signed or when the ceremony
//! ends, whatever the step ended with, and under test each drop is counted.
//!
//! # Whose gateway
//!
//! Before any call, the tunnel must lead to the gateway the domain's relay names. Another
//! domain's gateway is never touched, and a refusal there says so.

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationKind, OperationLocator,
    OperatorStatus, Refusal, RemoteState,
};
use aether::certificates::status::CampaignScope;
use aether::certificates::transport::OperatorOpened;
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::gateway_identity::{
    self, GatewayDecisionKind, GatewayIdentityRemote, GatewayRefusal, OpenedGatewayAbort,
    OpenedGatewayRenewal, OpenedGatewayRollback, RenewalOptions,
};
use astra_operator::operations::gateway_revocation::{self, OpenedGatewayRevocation};
use astra_operator::operations::revocation::RevocationReasonChoice;
use astra_operator::operations::rotation::KeyStep;
use astra_operator::tunnel::Tunnel;

use super::wait::{Ended, Step, Waiting};
use super::{connect_key, now_unix, Ceremony, Press};
use crate::operator::{relay_names_peer, GatewayGesture, GatewayTarget, Words};

/// Said when the tunnel leads to a gateway the domain's relay does not name.
const WRONG_GATEWAY: &str = "la gateway jointe n'est pas celle que le relais du domaine désigne";

/// Said when no tunnel is up to the gateway.
pub(crate) const NO_TUNNEL: &str = "aucun tunnel n'est monté vers la gateway";

/// Said when a discard, forced or not, is asked of a ceremony: it takes no key and runs no
/// ceremony.
const DISCARD_IS_NO_CEREMONY: &str = "jeter une décision en attente ne se fait pas en cérémonie";

/// Said when the record waiting for the gateway cannot be read. The detail names paths: it goes
/// to the log, never to the page.
pub(crate) const RECORD_UNREADABLE: &str =
    "le registre de l'identité de la gateway ne se lit pas : rien n'a été changé";

/// Said for an internal failure of Orion's own. Its detail can name the vault and the record's
/// paths: it goes to the log, never to the page. The failure can happen after the signature,
/// so the sentence does not say that nothing was signed.
pub(crate) const INTERNAL_FAILURE: &str = "Erreur interne d'Orion ; le détail est dans le journal.";

/// Said when the waiting record could not be dropped. The detail names paths: it goes to the
/// log, never to the page.
const DISCARD_FAILED: &str = "la décision en attente n'a pas pu être jetée : rien n'a été changé";

/// Said when a renewal runs under the chain but no campaign of the gateway's identity is held for
/// it: the step was never opened in this session, or it was of another family.
const CHAIN_CAMPAIGN_UNKNOWN: &str =
    "La campagne de l'étape n'est plus connue d'Orion : rouvrir l'étape après son échéance.";

/// Said when the revocation's replacement is deposited and the revocation is still to sign.
const REVOCATION_TO_SIGN: &str =
    "La révocation reste à signer : choisir « Révoquer la gateway ». Rien n'a été révoqué.";

/// Runs one gateway gesture to its end against the vault at `vault_path`, publishing every
/// state it reaches. `requested_by` is the workstation's name, which a rollback's campaign
/// names.
///
/// Called from the ceremony's own thread, which is what lets the tunnel be used with a
/// blocking wait: that thread is not a runtime worker.
#[allow(clippy::too_many_arguments)]
pub fn run_gateway(
    session_id: Id16,
    gesture: GatewayGesture,
    gateway: Option<GatewayTarget>,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
    requested_by: &str,
    words: &Words,
    chain: Option<OperatorOpened>,
) -> Result<(), String> {
    // Before the first status, which is the ceremony's own: a tunnel that cannot be made is
    // the only failure answered here, before anything the gesture runs.
    let failed = |publish: &mut dyn FnMut(OperatorStatus), refusal: Refusal, message: String| {
        let mut ceremony = Ceremony::new(
            session_id,
            OperationLocator {
                kind: gesture.operation(),
                operation_id: None,
            },
        );
        stop(&mut ceremony, publish, words, refusal, message)
    };
    let Some(target) = gateway else {
        return failed(publish, Refusal::GatewayUnavailable, NO_TUNNEL.to_string());
    };
    let tunnel = match Tunnel::new(&target.address) {
        Ok(tunnel) => tunnel,
        Err(error) => return failed(publish, Refusal::GatewayUnavailable, format!("{error:#}")),
    };
    let reach = Reach {
        remote: &tunnel,
        connect: &connect_key,
        now: &now_unix,
    };
    run_with(
        session_id,
        gesture,
        &target,
        presses,
        publish,
        vault_path,
        requested_by,
        words,
        chain,
        &reach,
    )
}

/// What a gateway gesture reaches outside this process, and the time it reads.
struct Reach<'a> {
    remote: &'a dyn GatewayIdentityRemote,
    connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
    now: &'a dyn Fn() -> u64,
}

/// [`run_gateway`] with what it reaches named, so a test can stand in for the gateway and for
/// Astra.
#[allow(clippy::too_many_arguments)]
fn run_with(
    session_id: Id16,
    gesture: GatewayGesture,
    target: &GatewayTarget,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
    requested_by: &str,
    words: &Words,
    chain: Option<OperatorOpened>,
    reach: &Reach<'_>,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(
        session_id,
        OperationLocator {
            kind: gesture.operation(),
            operation_id: None,
        },
    );
    publish(ceremony.status());
    if !relay_names_peer(vault_path, &target.peer_key).unwrap_or(false) {
        return stop(
            &mut ceremony,
            publish,
            words,
            Refusal::HandoffMismatch,
            WRONG_GATEWAY.to_string(),
        );
    }
    let mut run = GatewayRun::new(
        &mut ceremony,
        &presses,
        publish,
        vault_path,
        requested_by,
        words,
        reach,
    );
    run.run(gesture, chain)
}

/// Stops before any call: the refusal is published, its sentence stored for the page.
fn stop(
    ceremony: &mut Ceremony,
    publish: &mut dyn FnMut(OperatorStatus),
    words: &Words,
    refusal: Refusal,
    message: String,
) -> Result<(), String> {
    store_words(words, &message);
    ceremony.refuse(refusal);
    publish(ceremony.status());
    Err(message)
}

/// Stores the sentence a gateway ceremony ends on. Written before its failure is published,
/// so that the page reads it as soon as it sees the failure.
fn store_words(words: &Words, message: &str) {
    *words
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(message.to_string());
}

/// The refusal a gateway step answers with. A call that gave no answer is Astra or the
/// gateway unreachable; everything else is said in its sentence.
fn refusal_of(error: &GatewayRefusal) -> Refusal {
    match error {
        GatewayRefusal::Unreachable
        | GatewayRefusal::UnreachableBeforeSigning
        | GatewayRefusal::RollbackUnreachable => Refusal::AuthorityUnreachable,
        _ => Refusal::Internal,
    }
}

/// The sentence a refusal puts on the page. An internal failure is logged with its detail,
/// which can name paths, and said as a fixed sentence; every other refusal is its own sentence.
pub(crate) fn page_sentence(error: &GatewayRefusal) -> String {
    match error {
        GatewayRefusal::Internal(detail) => {
            tracing::warn!(error = %detail, "échec interne d'une cérémonie gateway");
            INTERNAL_FAILURE.to_string()
        }
        other => other.to_string(),
    }
}

/// The record waiting for the gateway could not be read: the detail goes to the log only.
pub(crate) fn unreadable_record(error: &anyhow::Error) -> String {
    tracing::warn!(error = %format!("{error:#}"), "registre de la gateway illisible");
    RECORD_UNREADABLE.to_string()
}

/// An opening the ceremony holds until it is signed or the ceremony ends. Its drop is where
/// the ceremony erases what the campaign released; under test, each drop is counted against
/// each opening made.
struct Opening<T> {
    inner: Option<T>,
}

#[cfg(test)]
mod probe {
    use std::cell::Cell;

    thread_local! {
        /// Openings made, and openings dropped, on this thread.
        static OPENINGS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    pub(super) fn reset() {
        OPENINGS.with(|counts| counts.set((0, 0)));
    }

    pub(super) fn made() {
        OPENINGS.with(|counts| {
            let (made, dropped) = counts.get();
            counts.set((made + 1, dropped));
        });
    }

    pub(super) fn dropped() {
        OPENINGS.with(|counts| {
            let (made, dropped) = counts.get();
            counts.set((made, dropped + 1));
        });
    }

    pub(super) fn counts() -> (usize, usize) {
        OPENINGS.with(Cell::get)
    }
}

impl<T> Opening<T> {
    fn new(inner: T) -> Self {
        #[cfg(test)]
        probe::made();
        Self { inner: Some(inner) }
    }

    fn get(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    fn get_mut(&mut self) -> Option<&mut T> {
        self.inner.as_mut()
    }

    /// Takes the opening out to sign it. What remains is dropped at once.
    fn take(mut self) -> Option<T> {
        self.inner.take()
    }
}

impl<T> Drop for Opening<T> {
    fn drop(&mut self) {
        #[cfg(test)]
        probe::dropped();
    }
}

/// The openings a gesture holds between its approval and its signature. Neither `Send` nor
/// `Sync`: they stay on the ceremony's thread.
enum Held {
    Nothing,
    Renewal(Opening<OpenedGatewayRenewal>),
    Abort(Opening<OpenedGatewayAbort>),
    Rollback(Opening<OpenedGatewayRollback>),
    Revocation(Opening<OpenedGatewayRevocation>),
}

impl Held {
    /// How many credentials approve what is held, or `None` when nothing is.
    fn required(&self) -> Option<u8> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => held.get().map(OpenedGatewayRenewal::required_credentials),
            Self::Abort(held) => held.get().map(OpenedGatewayAbort::required_credentials),
            Self::Rollback(held) => held.get().map(OpenedGatewayRollback::required_credentials),
            Self::Revocation(held) => held
                .get()
                .map(OpenedGatewayRevocation::required_credentials),
        }
    }

    fn expires_at(&self) -> Option<u64> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => held.get().map(OpenedGatewayRenewal::campaign_expires_at),
            Self::Abort(held) => held.get().map(OpenedGatewayAbort::campaign_expires_at),
            Self::Rollback(held) => held.get().map(OpenedGatewayRollback::campaign_expires_at),
            Self::Revocation(held) => held.get().map(OpenedGatewayRevocation::campaign_expires_at),
        }
    }

    fn manifest(&self, now: u64) -> Option<AstraManifest> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => held.get().map(OpenedGatewayRenewal::manifest),
            Self::Abort(held) => held.get().map(OpenedGatewayAbort::manifest),
            Self::Rollback(held) => held.get().map(OpenedGatewayRollback::manifest),
            Self::Revocation(held) => held.get().map(|opened| opened.manifest(now)),
        }
    }

    /// Whether the gateway resumed the request it had prepared. Only a renewal and a
    /// revocation's replacement can have been reused; the others never are.
    fn request_reused(&self) -> bool {
        match self {
            Self::Nothing | Self::Abort(_) | Self::Rollback(_) => false,
            Self::Renewal(held) => held.get().is_some_and(OpenedGatewayRenewal::request_reused),
            Self::Revocation(held) => held
                .get()
                .is_some_and(OpenedGatewayRevocation::request_reused),
        }
    }

    /// One key: its approval. `None` when nothing is held.
    fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Option<Result<String, KeyStep>> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => held.get_mut().map(|opened| opened.approve(key, now)),
            Self::Abort(held) => held.get_mut().map(|opened| opened.approve(key, now)),
            Self::Rollback(held) => held.get_mut().map(|opened| opened.approve(key, now)),
            Self::Revocation(held) => held.get_mut().map(|opened| opened.approve(key, now)),
        }
    }
}

struct GatewayRun<'a> {
    wait: Waiting<'a>,
    vault_path: &'a Path,
    requested_by: &'a str,
    words: &'a Words,
    reach: &'a Reach<'a>,
    held: Held,
}

impl<'a> Deref for GatewayRun<'a> {
    type Target = Waiting<'a>;

    fn deref(&self) -> &Waiting<'a> {
        &self.wait
    }
}

impl DerefMut for GatewayRun<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wait
    }
}

impl<'a> GatewayRun<'a> {
    fn new(
        ceremony: &'a mut Ceremony,
        presses: &'a Receiver<Press>,
        publish: &'a mut dyn FnMut(OperatorStatus),
        vault_path: &'a Path,
        requested_by: &'a str,
        words: &'a Words,
        reach: &'a Reach<'a>,
    ) -> Self {
        Self {
            wait: Waiting::new(ceremony, presses, publish, reach.connect, reach.now),
            vault_path,
            requested_by,
            words,
            reach,
            held: Held::Nothing,
        }
    }

    /// Runs the gesture. `chain` is the step the certificate chain holds, read by a renewal
    /// that runs under it. Whatever the gesture ended with, the openings it held are dropped here.
    fn run(
        &mut self,
        gesture: GatewayGesture,
        chain: Option<OperatorOpened>,
    ) -> Result<(), String> {
        let stepped = match gesture {
            GatewayGesture::Renew {
                rotate_tls,
                key_recovery,
                prepare_days,
                overlap_days,
                validity_days,
                in_chain,
            } => self.renew(
                RenewalOptions {
                    rotate_tls,
                    key_recovery,
                    prepare_days,
                    overlap_days,
                    validity_days,
                },
                in_chain,
                chain,
            ),
            GatewayGesture::Abort => self.abort(),
            GatewayGesture::Rollback { hours, reason } => self.rollback(hours, reason.trim()),
            GatewayGesture::Revoke {
                reason,
                with_replacement,
            } => self.revoke(reason, with_replacement),
            GatewayGesture::Resume => self.resume(),
            GatewayGesture::Discard | GatewayGesture::ForceDiscard => {
                Err(self.fail(Refusal::Internal, DISCARD_IS_NO_CEREMONY.to_string()))
            }
        };
        self.held = Held::Nothing;
        match stepped {
            Ok(()) => Ok(()),
            Err(Ended(end)) => end,
        }
    }

    /// Stops with a refusal, storing its sentence for the page first.
    fn fail(&mut self, refusal: Refusal, message: String) -> Ended {
        store_words(self.words, &message);
        self.refuse(refusal, message)
    }

    fn fail_with(&mut self, error: &GatewayRefusal) -> Ended {
        self.fail(refusal_of(error), page_sentence(error))
    }

    /// A record that cannot be read: its detail to the log, a fixed sentence to the page.
    fn unreadable(&mut self, error: &anyhow::Error) -> Ended {
        let message = unreadable_record(error);
        self.fail(Refusal::Internal, message)
    }

    /// Holds what a campaign opened, and shows the operator what it names before the first key.
    fn hold(&mut self, held: Held, now: u64) -> Step<()> {
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.manifest = held.manifest(now);
        self.ceremony.request_reused = held.request_reused();
        self.until = held.expires_at();
        self.held = held;
        self.show();
        Ok(())
    }

    /// One approval per credential the campaign requires, each asked for on its own press.
    fn approve(&mut self) -> Step<()> {
        let Some(required) = self.held.required() else {
            return Err(self.nothing_held());
        };
        for index in 1..=required {
            loop {
                let key = self.ask_key(index, required, KeyPurpose::ApproveCampaign)?;
                // Read after the key is reached: the campaign may have died meanwhile.
                let now = self.now();
                let Some(result) = self.held.approve(key.as_ref(), now) else {
                    return Err(self.nothing_held());
                };
                match result {
                    Ok(label) => {
                        self.ceremony.approved.push(KeySlotLabel {
                            slot: index.to_string(),
                            label,
                        });
                        self.ceremony.key_retry = None;
                        self.operator_seen();
                        break;
                    }
                    Err(step) => self.turned_down(step)?,
                }
            }
        }
        Ok(())
    }

    /// The last moment: signing offers no way back. Takes what was held.
    fn sign_gate(&mut self) -> Step<Held> {
        self.honour_cancel()?;
        self.ceremony.gesture = GestureState::Signing;
        self.ceremony.idle_until = None;
        self.show();
        Ok(std::mem::replace(&mut self.held, Held::Nothing))
    }

    /// Renews the gateway's identity. Under the chain, the campaign is the step's own, held
    /// since the chain opened it; a step that is not a gateway identity's is refused before any
    /// key is asked for.
    fn renew(
        &mut self,
        options: RenewalOptions,
        in_chain: bool,
        chain: Option<OperatorOpened>,
    ) -> Step<()> {
        let now = self.now();
        let opened = match (in_chain, chain) {
            (false, _) => {
                gateway_identity::open_renewal(self.reach.remote, self.vault_path, options, now)
                    .map_err(|error| self.fail_with(&error))?
            }
            (true, Some(held)) if held.scope == CampaignScope::GatewayIdentity => {
                gateway_identity::open_renewal_in(
                    self.reach.remote,
                    self.vault_path,
                    held,
                    options,
                    now,
                )
                .map_err(|error| self.fail_with(&error))?
            }
            (true, _) => {
                return Err(self.fail(
                    Refusal::ManifestMismatch,
                    CHAIN_CAMPAIGN_UNKNOWN.to_string(),
                ))
            }
        };
        self.hold(Held::Renewal(Opening::new(opened)), now)?;
        self.approve()?;
        let Held::Renewal(opening) = self.sign_gate()? else {
            return Err(self.nothing_held());
        };
        let Some(opened) = opening.take() else {
            return Err(self.nothing_held());
        };
        let now = self.now();
        let decision = opened
            .sign_and_record(self.vault_path, now)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Prepared;
        self.show();
        self.carry_renewal(decision)
    }

    /// Carries a recorded renewal to its end, with no key.
    fn carry_renewal(&mut self, decision: gateway_identity::SignedGatewayDecision) -> Step<()> {
        let now = self.now();
        gateway_identity::carry(self.reach.remote, self.vault_path, decision, now)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Committed;
        self.done();
        Ok(())
    }

    fn abort(&mut self) -> Step<()> {
        let now = self.now();
        let opened = gateway_identity::open_abort(self.reach.remote, self.vault_path, now)
            .map_err(|error| self.fail_with(&error))?;
        self.hold(Held::Abort(Opening::new(opened)), now)?;
        self.approve()?;
        let Held::Abort(opening) = self.sign_gate()? else {
            return Err(self.nothing_held());
        };
        let Some(opened) = opening.take() else {
            return Err(self.nothing_held());
        };
        let now = self.now();
        let decision = opened
            .sign_and_record(self.vault_path, now)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Prepared;
        self.show();
        self.carry_cancellation(decision)
    }

    /// Carries a recorded cancellation to its end, with no key.
    fn carry_cancellation(
        &mut self,
        decision: gateway_identity::SignedGatewayDecision,
    ) -> Step<()> {
        let now = self.now();
        gateway_identity::carry_abort(self.reach.remote, self.vault_path, decision, now)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Committed;
        self.done();
        Ok(())
    }

    /// Returns to the outgoing identity for `hours`, with the workstation as the requester.
    fn rollback(&mut self, hours: u64, reason: &str) -> Step<()> {
        let now = self.now();
        let opened = gateway_identity::open_rollback(
            self.reach.remote,
            self.vault_path,
            hours,
            reason,
            self.requested_by,
            now,
        )
        .map_err(|error| self.fail_with(&error))?;
        self.hold(Held::Rollback(Opening::new(opened)), now)?;
        self.approve()?;
        let Held::Rollback(opening) = self.sign_gate()? else {
            return Err(self.nothing_held());
        };
        let Some(opened) = opening.take() else {
            return Err(self.nothing_held());
        };
        let now = self.now();
        let authorization = opened
            .sign(self.vault_path, now)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Prepared;
        self.show();
        gateway_identity::carry_rollback(self.reach.remote, authorization)
            .map_err(|error| self.fail_with(&error))?;
        self.ceremony.remote = RemoteState::Committed;
        self.done();
        Ok(())
    }

    /// Revokes the gateway. With a replacement there are two rounds, each with its own
    /// approval: the replacement's, then the revocation's, which names the replacement's
    /// fingerprint on its manifest.
    fn revoke(&mut self, reason: RevocationReasonChoice, with_replacement: bool) -> Step<()> {
        let mut round = 1;
        loop {
            let now = self.now();
            let opened = gateway_revocation::open_gateway_revocation(
                self.reach.remote,
                self.vault_path,
                reason,
                with_replacement,
                now,
            )
            .map_err(|error| self.fail_with(&error))?;
            self.hold(Held::Revocation(Opening::new(opened)), now)?;
            self.approve()?;
            let Held::Revocation(opening) = self.sign_gate()? else {
                return Err(self.nothing_held());
            };
            let Some(opened) = opening.take() else {
                return Err(self.nothing_held());
            };
            let now = self.now();
            let signed = opened
                .sign_and_record(self.vault_path, now)
                .map_err(|error| self.fail_with(&error))?;
            self.ceremony.remote = RemoteState::Prepared;
            self.show();
            let now = self.now();
            match gateway_revocation::carry_revocation(
                self.reach.remote,
                self.vault_path,
                signed,
                now,
            ) {
                Ok(()) => {
                    self.ceremony.remote = RemoteState::Committed;
                    self.done();
                    return Ok(());
                }
                // The replacement is deposited and the revocation still waits for its own approval:
                // the second round opens it.
                Err(GatewayRefusal::RevocationToSign) if with_replacement && round == 1 => {
                    round += 1;
                    self.ceremony.remote = RemoteState::Deposited;
                    self.ceremony.gesture = GestureState::Idle;
                    self.show();
                }
                Err(error) => return Err(self.fail_with(&error)),
            }
        }
    }

    /// Carries what a gateway gesture left waiting, with no key: a revocation first, then
    /// a renewal or a cancellation. Nothing waiting is nothing to do.
    fn resume(&mut self) -> Step<()> {
        let now = self.now();
        let revocation = gateway_revocation::pending_revocation(self.vault_path, now)
            .map_err(|error| self.unreadable(&error))?;
        if let Some(signed) = revocation {
            // The carry decides: it reads the gateway's view once when only the revocation is left
            // to sign, and refuses with RevocationToSign unless the view shows it applied.
            self.ceremony.operation = OperationKind::RevokeCertificate;
            self.ceremony.gesture = GestureState::Signing;
            self.show();
            let now = self.now();
            return match gateway_revocation::carry_revocation(
                self.reach.remote,
                self.vault_path,
                signed,
                now,
            ) {
                Ok(()) => {
                    self.ceremony.remote = RemoteState::Committed;
                    self.done();
                    Ok(())
                }
                // The approval that signs the revocation is a new gesture, which takes the reason.
                Err(GatewayRefusal::RevocationToSign) => {
                    Err(self.fail(Refusal::RevocationToSign, REVOCATION_TO_SIGN.to_string()))
                }
                Err(error) => Err(self.fail_with(&error)),
            };
        }
        let decision = gateway_identity::pending(self.vault_path, now)
            .map_err(|error| self.unreadable(&error))?;
        match decision {
            Some(decision) => {
                self.ceremony.gesture = GestureState::Signing;
                self.show();
                match decision.kind {
                    GatewayDecisionKind::Renewal => self.carry_renewal(decision),
                    GatewayDecisionKind::Abort => self.carry_cancellation(decision),
                }
            }
            None => {
                self.done();
                Ok(())
            }
        }
    }
}

/// Drops the waiting record: the revocation's when one waits, the decision's otherwise. Takes
/// no key. The operations decide whether a discard is allowed: a refusal's sentence reaches the
/// page as it is, and a failed read or write is said as a fixed sentence.
pub(crate) fn discard_waiting(vault_path: &Path) -> Result<(), String> {
    let revocation = gateway_revocation::pending_revocation(vault_path, now_unix())
        .map_err(|error| unreadable_record(&error))?;
    if revocation.is_some() {
        gateway_revocation::discard_pending_revocation(vault_path).map_err(discard_sentence)
    } else {
        gateway_identity::discard_pending(vault_path).map_err(discard_sentence)
    }
}

/// Drops the waiting record when the gateway's own view proves it has no way out: the
/// revocation's when one waits, the decision's otherwise. Takes no key, and reads the view
/// through `remote`, the tunnel. A refusal's sentence reaches the page as it is; any other
/// failure is said as a fixed sentence.
pub(crate) fn force_discard_waiting(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
) -> Result<(), String> {
    let now = now_unix();
    let revocation = gateway_revocation::pending_revocation(vault_path, now)
        .map_err(|error| unreadable_record(&error))?;
    if revocation.is_some() {
        gateway_revocation::force_discard_pending_revocation(remote, vault_path)
            .map_err(force_discard_sentence)
    } else {
        gateway_identity::force_discard_pending(remote, vault_path, now)
            .map_err(force_discard_sentence)
    }
}

/// [`force_discard_waiting`] for the connected gateway. As for every gateway gesture, the tunnel
/// must lead to the gateway the domain's relay names before any call: another domain's gateway
/// is never asked, and its view never clears the record.
pub(crate) fn force_discard_at(
    target: &GatewayTarget,
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
) -> Result<(), String> {
    if !relay_names_peer(vault_path, &target.peer_key).unwrap_or(false) {
        return Err(WRONG_GATEWAY.to_string());
    }
    force_discard_waiting(remote, vault_path)
}

/// The sentence a forced discard puts on the page: a refusal's own sentence, or the failure's
/// fixed sentence.
fn force_discard_sentence(refusal: GatewayRefusal) -> String {
    match refusal {
        GatewayRefusal::NotForceDiscardable(sentence) => sentence,
        other => page_sentence(&other),
    }
}

/// The sentence a discard puts on the page. A record that still has work to finish names what
/// is left; any other failure is logged and said as a fixed sentence.
fn discard_sentence(refusal: GatewayRefusal) -> String {
    match refusal {
        GatewayRefusal::NotDiscardable(sentence) => sentence,
        other => {
            tracing::warn!(error = %other, "décision gateway non jetée");
            DISCARD_FAILED.to_string()
        }
    }
}

#[cfg(test)]
mod tests;
