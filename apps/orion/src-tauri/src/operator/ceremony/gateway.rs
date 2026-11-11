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
//! else. Every exit of the ceremony erases them, whatever the step ended with: see
//! [`GatewayRun::run`].
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
const NO_TUNNEL: &str = "aucun tunnel n'est monté vers la gateway";

/// Said when a discard is asked of a ceremony: it takes no key and runs no ceremony.
const DISCARD_IS_NO_CEREMONY: &str = "jeter une décision en attente ne se fait pas en cérémonie";

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
        &reach,
    )
    .0
}

/// What a gateway gesture reaches outside this process, and the time it reads.
struct Reach<'a> {
    remote: &'a dyn GatewayIdentityRemote,
    connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
    now: &'a dyn Fn() -> u64,
}

/// [`run_gateway`] with what it reaches named, so a test can stand in for the gateway and for
/// Astra. Returns the outcome, and whether the openings were erased at the exit.
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
    reach: &Reach<'_>,
) -> (Result<(), String>, bool) {
    let mut ceremony = Ceremony::new(
        session_id,
        OperationLocator {
            kind: gesture.operation(),
            operation_id: None,
        },
    );
    publish(ceremony.status());
    if !relay_names_peer(vault_path, &target.peer_key).unwrap_or(false) {
        let result = stop(
            &mut ceremony,
            publish,
            words,
            Refusal::HandoffMismatch,
            WRONG_GATEWAY.to_string(),
        );
        return (result, true);
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
    run.run(gesture)
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

/// The openings a gesture holds between its approval and its signature. Neither `Send` nor
/// `Sync`: they stay on the ceremony's thread, and dropping them wipes them.
enum Held {
    Nothing,
    Renewal(Box<OpenedGatewayRenewal>),
    Abort(Box<OpenedGatewayAbort>),
    Rollback(Box<OpenedGatewayRollback>),
    Revocation(Box<OpenedGatewayRevocation>),
}

impl Held {
    fn is_nothing(&self) -> bool {
        matches!(self, Self::Nothing)
    }

    /// How many credentials approve what is held, or `None` when nothing is.
    fn required(&self) -> Option<u8> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => Some(held.required_credentials()),
            Self::Abort(held) => Some(held.required_credentials()),
            Self::Rollback(held) => Some(held.required_credentials()),
            Self::Revocation(held) => Some(held.required_credentials()),
        }
    }

    fn expires_at(&self) -> Option<u64> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => Some(held.campaign_expires_at()),
            Self::Abort(held) => Some(held.campaign_expires_at()),
            Self::Rollback(held) => Some(held.campaign_expires_at()),
            Self::Revocation(held) => Some(held.campaign_expires_at()),
        }
    }

    fn manifest(&self, now: u64) -> Option<AstraManifest> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => Some(held.manifest()),
            Self::Abort(held) => Some(held.manifest()),
            Self::Rollback(held) => Some(held.manifest()),
            Self::Revocation(held) => Some(held.manifest(now)),
        }
    }

    /// One key: its approval. `None` when nothing is held.
    fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Option<Result<String, KeyStep>> {
        match self {
            Self::Nothing => None,
            Self::Renewal(held) => Some(held.approve(key, now)),
            Self::Abort(held) => Some(held.approve(key, now)),
            Self::Rollback(held) => Some(held.approve(key, now)),
            Self::Revocation(held) => Some(held.approve(key, now)),
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

    /// Runs the gesture. Returns the outcome and whether nothing is held once it has ended:
    /// every exit erases what the ceremony held, whatever the step ended with.
    fn run(&mut self, gesture: GatewayGesture) -> (Result<(), String>, bool) {
        let stepped = match gesture {
            GatewayGesture::Renew {
                rotate_tls,
                key_recovery,
                prepare_days,
                overlap_days,
                validity_days,
            } => self.renew(RenewalOptions {
                rotate_tls,
                key_recovery,
                prepare_days,
                overlap_days,
                validity_days,
            }),
            GatewayGesture::Abort => self.abort(),
            GatewayGesture::Rollback { hours, reason } => self.rollback(hours, reason.trim()),
            GatewayGesture::Revoke {
                reason,
                with_replacement,
            } => self.revoke(reason, with_replacement),
            GatewayGesture::Resume => self.resume(),
            GatewayGesture::Discard => {
                Err(self.fail(Refusal::Internal, DISCARD_IS_NO_CEREMONY.to_string()))
            }
        };
        self.held = Held::Nothing;
        let erased = self.held.is_nothing();
        match stepped {
            Ok(()) => (Ok(()), erased),
            Err(Ended(end)) => (end, erased),
        }
    }

    /// Stops with a refusal, storing its sentence for the page first.
    fn fail(&mut self, refusal: Refusal, message: String) -> Ended {
        store_words(self.words, &message);
        self.refuse(refusal, message)
    }

    fn fail_with(&mut self, error: &GatewayRefusal) -> Ended {
        self.fail(refusal_of(error), error.to_string())
    }

    /// Holds what a campaign opened, and shows the operator what it names before the first key.
    fn hold(&mut self, held: Held, now: u64) -> Step<()> {
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.manifest = held.manifest(now);
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

    fn renew(&mut self, options: RenewalOptions) -> Step<()> {
        let now = self.now();
        let opened =
            gateway_identity::open_renewal(self.reach.remote, self.vault_path, options, now)
                .map_err(|error| self.fail_with(&error))?;
        self.hold(Held::Renewal(Box::new(opened)), now)?;
        self.approve()?;
        let Held::Renewal(opened) = self.sign_gate()? else {
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
        self.hold(Held::Abort(Box::new(opened)), now)?;
        self.approve()?;
        let Held::Abort(opened) = self.sign_gate()? else {
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
        self.hold(Held::Rollback(Box::new(opened)), now)?;
        self.approve()?;
        let Held::Rollback(opened) = self.sign_gate()? else {
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
            self.hold(Held::Revocation(Box::new(opened)), now)?;
            self.approve()?;
            let Held::Revocation(opened) = self.sign_gate()? else {
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
            .map_err(|error| self.fail(Refusal::Internal, format!("{error:#}")))?;
        if let Some(signed) = revocation {
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
                Err(error) => Err(self.fail_with(&error)),
            };
        }
        let decision = gateway_identity::pending(self.vault_path, now)
            .map_err(|error| self.fail(Refusal::Internal, format!("{error:#}")))?;
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
/// no key. The operations decide whether a discard is allowed, and their error is surfaced.
pub(crate) fn discard_waiting(vault_path: &Path) -> Result<(), String> {
    let revocation = gateway_revocation::pending_revocation(vault_path, now_unix())
        .map_err(|error| format!("{error:#}"))?;
    if revocation.is_some() {
        gateway_revocation::discard_pending_revocation(vault_path)
    } else {
        gateway_identity::discard_pending(vault_path)
    }
    .map_err(|error| format!("{error:#}"))
}

#[cfg(test)]
mod tests;
