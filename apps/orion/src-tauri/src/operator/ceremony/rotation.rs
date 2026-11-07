//! The CA rotations (F14 lot 5b), run as an operator ceremony.
//!
//! The sequences are [`astra_operator::operations::rotation`]'s; this module only
//! puts the touches and the publications between them, and words what they refuse
//! as a [`Refusal`].
//!
//! # What stays here
//!
//! The openings two validated keys released are held for the length of a screen the
//! operator may walk away from, and neither [`ValidatedKeys`] nor [`OpenedRotation`]
//! has a clock. [`Openings`] is what bounds them: it cannot cross a thread, and
//! every way out of a ceremony erases it, abandoned, failed, finished, or idle for
//! [`VALIDATION_IDLE_SECS`]. No status carries more than a label.

use std::marker::PhantomData;
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationKind, OperationLocator,
    OperatorAction, OperatorStatus, Refusal, RemoteState,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::rotation::{
    self, CaTlsFinish, FinishRefusal, KeyStep, OpenedRotation, RotationRemote, RotationTerms,
    ValidatedKeys,
};
use astra_operator::rotation_journal::{
    self, JournalStage, ResumeStep, RotationJournal, RotationKind,
};
use astra_operator::tunnel::{self, Tunnel, TunnelRefusal};

use super::{connect_key, now_unix, Ceremony, Press};
use crate::operator::RotationGesture;

/// How long an opening is kept for an operator who answers nothing.
pub const VALIDATION_IDLE_SECS: u64 = 300;

/// How often a wait looks at the clock: nothing else would end it, with no press.
const WAIT_TICK: Duration = Duration::from_secs(1);

/// A rotation takes two distinct keys, each touched once to validate and once to
/// approve.
const ROTATION_KEYS: u8 = 2;

/// Runs one rotation gesture to its end against the vault at `vault_path`, publishing
/// every state it reaches.
///
/// Called from the ceremony's own thread, which is what lets the tunnel be used with
/// a blocking wait: that thread is not a runtime worker.
pub fn run_rotation(
    session_id: Id16,
    gesture: RotationGesture,
    gateway: Option<String>,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(
        session_id,
        OperationLocator {
            kind: gesture.operation(),
            operation_id: None,
        },
    );
    publish(ceremony.status());

    let tunnel = gateway
        .ok_or_else(|| "aucun tunnel n'est monté vers la gateway".to_string())
        .and_then(|address| Tunnel::new(&address).map_err(|error| format!("{error:#}")));
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(message) => {
            ceremony.refuse(Refusal::GatewayUnavailable);
            publish(ceremony.status());
            return Err(message);
        }
    };

    let reach = Reach {
        remote: &tunnel,
        connect: &connect_key,
        now: &now_unix,
    };
    RotationRun::new(&mut ceremony, &presses, publish, vault_path, &reach).run(gesture)
}

/// What a ceremony reaches outside this process, and the time it reads.
struct Reach<'a> {
    remote: &'a dyn RotationRemote,
    connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
    now: &'a dyn Fn() -> u64,
}

/// How long one wait for the operator may last.
///
/// Both clocks count: the wall clock goes on through a machine asleep, and the
/// monotonic one is not fooled by a wall clock set back.
struct Patience {
    since: u64,
    started: Instant,
    /// The end of the campaign being approved, when one is open.
    until: Option<u64>,
}

impl Patience {
    fn is_over(&self, now: u64) -> bool {
        now.saturating_sub(self.since) >= VALIDATION_IDLE_SECS
            || self.started.elapsed() >= Duration::from_secs(VALIDATION_IDLE_SECS)
            || self.until.is_some_and(|until| now >= until)
    }
}

enum Held {
    Nothing,
    Keys(ValidatedKeys),
    Campaign(Box<OpenedRotation>),
}

/// The vault openings of the ceremony in progress.
///
/// The marker removes `Send` and `Sync`: what unwraps the vault cannot leave the
/// ceremony's thread, whatever a later change would like to do with it. Neither
/// `Debug` nor `Serialize` is implemented, for the same reason.
struct Openings {
    held: Held,
    _thread: PhantomData<*const ()>,
}

impl Openings {
    fn none() -> Self {
        Self {
            held: Held::Nothing,
            _thread: PhantomData,
        }
    }

    fn take(&mut self) -> Held {
        std::mem::replace(&mut self.held, Held::Nothing)
    }

    /// The secrets wipe themselves as they are dropped.
    fn erase(&mut self) {
        drop(self.take());
    }
}

/// A ceremony over before the end of its steps, already published as such.
struct Ended(Result<(), String>);

type Step<T> = Result<T, Ended>;

struct RotationRun<'a> {
    ceremony: &'a mut Ceremony,
    presses: &'a Receiver<Press>,
    publish: &'a mut dyn FnMut(OperatorStatus),
    vault_path: &'a Path,
    reach: &'a Reach<'a>,
    openings: Openings,
    until: Option<u64>,
}

impl RotationRun<'_> {
    fn new<'a>(
        ceremony: &'a mut Ceremony,
        presses: &'a Receiver<Press>,
        publish: &'a mut dyn FnMut(OperatorStatus),
        vault_path: &'a Path,
        reach: &'a Reach<'a>,
    ) -> RotationRun<'a> {
        RotationRun {
            ceremony,
            presses,
            publish,
            vault_path,
            reach,
            openings: Openings::none(),
            until: None,
        }
    }

    fn run(&mut self, gesture: RotationGesture) -> Result<(), String> {
        let stepped = match gesture {
            RotationGesture::ReplaceCaPq => self.replace(RotationKind::CaPq),
            RotationGesture::ReplaceCaTls => self.replace(RotationKind::CaTls),
            RotationGesture::FinishCaTls => self.finish_ca_tls(),
            RotationGesture::Resume => self.resume(),
        };
        match stepped {
            Ok(()) => Ok(()),
            Err(Ended(end)) => end,
        }
    }

    fn replace(&mut self, kind: RotationKind) -> Step<()> {
        let vault_path = self.vault_path;
        rotation::ensure_nothing_outstanding(vault_path)
            .map_err(|error| self.refuse(Refusal::RotationInFlight, format!("{error:#}")))?;
        let keys = ValidatedKeys::new(vault_path)
            .map_err(|error| self.refuse(Refusal::VaultUnavailable, format!("{error:#}")))?;
        keys.ensure_domain_readable(vault_path, kind)
            .map_err(|error| self.refuse(Refusal::HandoffMismatch, format!("{error:#}")))?;
        self.openings.held = Held::Keys(keys);

        self.validate_keys()?;
        let terms = self.await_terms()?;
        self.open_campaign(kind, &terms)?;
        self.approve_campaign()?;
        let journal = self.sign()?;
        self.carry(journal)
    }

    fn validate_keys(&mut self) -> Step<()> {
        for index in 1..=ROTATION_KEYS {
            loop {
                let key = self.ask_key(index, ROTATION_KEYS, KeyPurpose::ValidateKey)?;
                let Held::Keys(keys) = &mut self.openings.held else {
                    return Err(self.nothing_held());
                };
                match keys.validate(key.as_ref()) {
                    Ok(label) => {
                        self.ceremony.keys.push(KeySlotLabel {
                            slot: index.to_string(),
                            label,
                        });
                        self.ceremony.key_retry = None;
                        break;
                    }
                    Err(step) => self.turned_down(step)?,
                }
            }
        }
        Ok(())
    }

    /// The approval screen. Nothing exists at the authority yet.
    fn await_terms(&mut self) -> Step<RotationTerms> {
        self.ceremony.gesture = GestureState::Idle;
        self.ceremony.remote = RemoteState::Local;
        let patience = self.patience();
        let offered = self.show();
        loop {
            let press = self.await_press(&offered, &patience)?;
            if let Some(terms) = press.terms {
                return Ok(terms);
            }
        }
    }

    fn open_campaign(&mut self, kind: RotationKind, terms: &RotationTerms) -> Step<()> {
        self.ceremony.gesture = GestureState::Verifying;
        self.show();
        let now = self.now();
        rotation::check_terms(kind, terms, now)
            .map_err(|error| self.refuse(Refusal::ManifestMismatch, format!("{error:#}")))?;
        let Held::Keys(keys) = self.openings.take() else {
            return Err(self.nothing_held());
        };
        let opened = rotation::open(self.reach.remote, self.vault_path, kind, keys, terms, now)
            .map_err(|error| self.refuse(refusal_of_open(&error), format!("{error:#}")))?;
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.operation_id = Some(opened.operation_id());
        self.ceremony.manifest = Some(opened.manifest().clone());
        self.until = Some(opened.campaign_expires_at());
        self.openings.held = Held::Campaign(Box::new(opened));
        Ok(())
    }

    fn approve_campaign(&mut self) -> Step<()> {
        for index in 1..=ROTATION_KEYS {
            loop {
                let key = self.ask_key(index, ROTATION_KEYS, KeyPurpose::ApproveCampaign)?;
                // Read after the key is reached: the campaign may have died meanwhile.
                let now = self.now();
                let Held::Campaign(opened) = &mut self.openings.held else {
                    return Err(self.nothing_held());
                };
                match opened.approve(key.as_ref(), now) {
                    Ok(_) => {
                        self.ceremony.key_retry = None;
                        break;
                    }
                    Err(step) => self.turned_down(step)?,
                }
            }
        }
        Ok(())
    }

    fn sign(&mut self) -> Step<RotationJournal> {
        self.ceremony.gesture = GestureState::Signing;
        self.show();
        let Held::Campaign(opened) = self.openings.take() else {
            return Err(self.nothing_held());
        };
        let now = self.now();
        let journal = opened
            .sign_and_journal(self.vault_path, now)
            .map_err(|error| {
                let refusal = match error.downcast_ref::<KeyStep>() {
                    Some(KeyStep::Expired) => Refusal::WindowExpired,
                    _ => Refusal::Internal,
                };
                self.refuse(refusal, format!("{error:#}"))
            })?;
        self.ceremony.remote = RemoteState::Prepared;
        // The incoming anchor did not exist at the touch, and the journal carrying it
        // disappears at the end: this is where the operator can read it.
        if let Some(AstraManifest::CaRotation(manifest)) = &mut self.ceremony.manifest {
            manifest.next_anchor_fingerprint = Some(journal.next_anchor_fingerprint);
        }
        self.show();
        Ok(journal)
    }

    /// Carries a signed rotation as far as it goes. Asks no key: everything from here
    /// is already decided, which is what lets a resumption do the same.
    fn carry(&mut self, mut journal: RotationJournal) -> Step<()> {
        let now = self.now();
        let advanced = rotation::advance(self.reach.remote, self.vault_path, &mut journal, now);
        if journal.stage != JournalStage::Signed && self.ceremony.remote != RemoteState::Deposited {
            self.ceremony.remote = RemoteState::Deposited;
            self.show();
        }
        match advanced {
            // A copy held back is on its way: the rotation is on the gateway, the
            // journal stays, and the next look sends it again.
            Ok(ResumeStep::Finished | ResumeStep::SendVaultCopy) => {
                self.done();
                Ok(())
            }
            Ok(step) => Err(self.refuse(
                refusal_of_stop(step),
                format!("rotation arrêtée : {step:?}"),
            )),
            Err(error) => Err(self.refuse(
                refusal_of_carry(&error, journal.stage),
                format!("{error:#}"),
            )),
        }
    }

    /// Takes up whatever is in flight, with no key. No journal is nothing to do.
    fn resume(&mut self) -> Step<()> {
        let adopted = rotation_journal::adopt_legacy(self.vault_path)
            .map_err(|error| self.refuse(Refusal::VaultUnavailable, format!("{error:#}")))?;
        let Some(journal) = adopted else {
            self.done();
            return Ok(());
        };
        self.ceremony.operation = match journal.kind {
            RotationKind::CaPq => OperationKind::RotateAnchor,
            RotationKind::CaTls => OperationKind::RotateClientTlsCa,
        };
        self.ceremony.operation_id = journal.deposit.as_ref().map(|deposit| deposit.operation_id);
        // Never `Prepared` and `Idle`, which would offer a press this run does not read.
        (self.ceremony.remote, self.ceremony.gesture) = match journal.stage {
            JournalStage::Signed => (RemoteState::Prepared, GestureState::Signing),
            _ => (RemoteState::Deposited, GestureState::Idle),
        };
        self.show();
        self.carry(journal)
    }

    /// « Terminer » a client TLS rotation: one key, and the record leaves.
    fn finish_ca_tls(&mut self) -> Step<()> {
        let now = self.now();
        let finish = CaTlsFinish::begin(self.vault_path, now).map_err(|error| {
            let refusal = refusal_of_finish(&error).unwrap_or(Refusal::VaultUnavailable);
            self.refuse(refusal, format!("{error:#}"))
        })?;
        self.ceremony.manifest = Some(finish.manifest().clone());
        let opening = loop {
            let key = self.ask_key(1, 1, KeyPurpose::Promotion)?;
            match finish.open(key.as_ref()) {
                Ok(opening) => break opening,
                Err(step) => self.turned_down(step)?,
            }
        };
        self.ceremony.key_retry = None;
        self.ceremony.gesture = GestureState::Signing;
        self.show();

        let now = self.now();
        let finished = finish.finish(self.reach.remote, self.vault_path, &opening, now);
        drop(opening);
        match finished {
            Ok(()) => {
                self.done();
                Ok(())
            }
            Err(error) => {
                let refusal = refusal_of_finish(&error).unwrap_or(Refusal::Internal);
                Err(self.refuse(refusal, format!("{error:#}")))
            }
        }
    }

    /// Offers a key and connects it once the operator presses. A key out of reach
    /// costs nothing that was already validated, so it asks again rather than ending.
    fn ask_key(&mut self, index: u8, of: u8, purpose: KeyPurpose) -> Step<Box<dyn Authenticator>> {
        loop {
            self.ceremony.gesture = GestureState::AwaitingKey { index, of, purpose };
            let patience = self.patience();
            let offered = self.show();
            let press = self.await_press(&offered, &patience)?;

            self.ceremony.key_retry = None;
            self.ceremony.gesture = GestureState::ProcessingKey { index, of };
            self.show();
            match (self.reach.connect)(press.owner) {
                Ok(key) => return Ok(key),
                Err((
                    refusal @ (Refusal::KeyDeclined | Refusal::ForegroundUnavailable),
                    message,
                )) => {
                    tracing::warn!(error = %message, "clé de sécurité injoignable");
                    self.ceremony.key_retry = Some(refusal);
                }
                Err((refusal, message)) => return Err(self.refuse(refusal, message)),
            }
        }
    }

    /// A key that answered and cannot be used is asked for again, except once the
    /// campaign is dead, which no key changes.
    fn turned_down(&mut self, step: KeyStep) -> Step<()> {
        let retry = match step {
            KeyStep::NotEnrolled => Refusal::KeyNotEnrolled,
            KeyStep::Repeated => Refusal::KeyRepeated,
            KeyStep::NotValidated => Refusal::KeyNotValidated,
            KeyStep::Declined => Refusal::KeyDeclined,
            KeyStep::Expired => {
                return Err(self.refuse(Refusal::WindowExpired, step.to_string()));
            }
        };
        self.ceremony.key_retry = Some(retry);
        Ok(())
    }

    /// Waits for the operator's answer to one status, for as long as `patience` allows.
    ///
    /// A press naming another revision answers a screen already left, and is ignored.
    /// Every sender gone means the window holding the ceremony was closed.
    fn await_press(&mut self, offered: &OperatorStatus, patience: &Patience) -> Step<Press> {
        loop {
            if patience.is_over(self.now()) {
                return Err(self.expired());
            }
            match self.presses.recv_timeout(WAIT_TICK) {
                Ok(press) if offered.accepts(press.action, press.revision) => {
                    if press.action == OperatorAction::Cancel {
                        return Err(self.cancel());
                    }
                    // Past the bound, a press in the queue opens nothing.
                    if patience.is_over(self.now()) {
                        return Err(self.expired());
                    }
                    return Ok(press);
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(self.cancel()),
            }
        }
    }

    /// Taken before the status it bounds is published: a wait begins as it is offered.
    fn patience(&self) -> Patience {
        Patience {
            since: self.now(),
            started: Instant::now(),
            until: self.until,
        }
    }

    fn now(&self) -> u64 {
        (self.reach.now)()
    }

    fn show(&mut self) -> OperatorStatus {
        let status = self.ceremony.status();
        (self.publish)(status.clone());
        status
    }

    fn expired(&mut self) -> Ended {
        self.refuse(
            Refusal::WindowExpired,
            "aucune réponse dans le délai : les ouvertures sont effacées".to_string(),
        )
    }

    /// An opening a step needed was gone: this code's own contradiction.
    fn nothing_held(&mut self) -> Ended {
        self.refuse(
            Refusal::Internal,
            "aucune ouverture n'est détenue à cette étape de la cérémonie".to_string(),
        )
    }

    fn refuse(&mut self, refusal: Refusal, message: String) -> Ended {
        self.openings.erase();
        self.ceremony.keys.clear();
        self.ceremony.refuse(refusal);
        self.show();
        Ended(Err(message))
    }

    fn cancel(&mut self) -> Ended {
        self.openings.erase();
        self.ceremony.keys.clear();
        self.ceremony.cancel();
        self.show();
        Ended(Ok(()))
    }

    fn done(&mut self) {
        self.openings.erase();
        self.ceremony.gesture = GestureState::Done;
        self.show();
    }
}

fn refusal_of_open(error: &anyhow::Error) -> Refusal {
    if tunnel::is_unreachable(error) {
        return Refusal::GatewayUnavailable;
    }
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refused) => Refusal::AuthorityRefused {
            status: refused.status,
        },
        // What came back does not verify against this domain's files.
        None => Refusal::HandoffMismatch,
    }
}

fn refusal_of_stop(step: ResumeStep) -> Refusal {
    match step {
        ResumeStep::Discard => Refusal::RotationExpired,
        ResumeStep::DomainConflict => Refusal::DomainConflict,
        ResumeStep::InstallDeadlinePassed => Refusal::InstallDeadlinePassed,
        ResumeStep::GatewayOutdated => Refusal::GatewayNamesNoAnchor,
        _ => Refusal::Internal,
    }
}

/// Whose word a refusal is follows from the stage: once applied, only the gateway is
/// spoken to.
fn refusal_of_carry(error: &anyhow::Error, stage: JournalStage) -> Refusal {
    if tunnel::is_unreachable(error) {
        return Refusal::GatewayUnavailable;
    }
    match (error.downcast_ref::<TunnelRefusal>(), stage) {
        (Some(refused), JournalStage::Applied) => Refusal::GatewayRefused {
            status: refused.status,
        },
        (Some(refused), _) => Refusal::AuthorityRefused {
            status: refused.status,
        },
        (None, _) => Refusal::Internal,
    }
}

/// `None` is a failure that is not « Terminer »'s own word, for the caller to name.
fn refusal_of_finish(error: &anyhow::Error) -> Option<Refusal> {
    error
        .downcast_ref::<FinishRefusal>()
        .map(|refusal| match refusal {
            FinishRefusal::InFlight | FinishRefusal::NotYet { .. } => Refusal::RotationInFlight,
            FinishRefusal::Nothing | FinishRefusal::Moved => Refusal::DomainChanged,
            FinishRefusal::Mismatch => Refusal::HandoffMismatch,
        })
}

#[cfg(test)]
mod tests;
