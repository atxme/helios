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
//! has a clock. Neither can cross a thread, and [`Openings`] is what bounds them:
//! every way out of a ceremony erases it, abandoned, failed, finished, or idle for
//! [`VALIDATION_IDLE_SECS`]. No status carries more than a label.

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationKind, OperationLocator,
    OperatorStatus, Refusal, RemoteState,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::rotation::{
    self, CaTlsFinish, FinishRefusal, KeyStep, OpenRefusal, OpenedRotation, RotationRemote,
    RotationTerms, ValidatedKeys,
};
use astra_operator::rotation_journal::{
    self, JournalStage, ResumeStep, RotationJournal, RotationKind,
};
use astra_operator::tunnel::{self, Tunnel, TunnelRefusal};
use astra_operator::vault::VaultError;

use super::wait::{answers_the_terms, Ended, Step, Waiting};
use super::{connect_key, now_unix, Ceremony, Press};
use crate::operator::{relay_names_peer, GatewayTarget, RotationGesture};

/// Said when the tunnel leads to a gateway the domain's relay does not name.
const WRONG_GATEWAY: &str = "la gateway jointe n'est pas celle que le relais du domaine désigne";

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
    gateway: Option<GatewayTarget>,
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
        .and_then(|target| {
            // Before any call: a resumption reads the status of whatever authority
            // answers, and sends the sealed vault to whatever gateway it reaches.
            // « Terminer », of either kind: each sends the vault copy at its end.
            if matches!(
                gesture,
                RotationGesture::Resume
                    | RotationGesture::FinishCaTls
                    | RotationGesture::FinishCaPq
            ) && !relay_names_peer(vault_path, &target.peer_key).unwrap_or(false)
            {
                return Err(WRONG_GATEWAY.to_string());
            }
            Tunnel::new(&target.address).map_err(|error| format!("{error:#}"))
        });
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(message) => {
            ceremony.refuse(if message == WRONG_GATEWAY {
                Refusal::HandoffMismatch
            } else {
                Refusal::GatewayUnavailable
            });
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

enum Held {
    Nothing,
    /// Boxed: the validated keys are the largest variant by far, and every held opening
    /// lives in this enum.
    Keys(Box<ValidatedKeys>),
    Campaign(Box<OpenedRotation>),
}

/// The vault openings of the ceremony in progress.
///
/// Neither `Send` nor `Sync`, through [`ValidatedKeys`]: what unwraps the vault cannot
/// leave the ceremony's thread, whatever a later change would like to do with it.
/// Neither `Debug` nor `Serialize` is implemented, for the same reason. The one opening
/// of « Terminer » is not held here: it lives in that function, and `finish` consumes it.
struct Openings {
    held: Held,
}

impl Openings {
    fn none() -> Self {
        Self {
            held: Held::Nothing,
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

struct RotationRun<'a> {
    wait: Waiting<'a>,
    vault_path: &'a Path,
    reach: &'a Reach<'a>,
    openings: Openings,
}

impl<'a> Deref for RotationRun<'a> {
    type Target = Waiting<'a>;

    fn deref(&self) -> &Waiting<'a> {
        &self.wait
    }
}

impl DerefMut for RotationRun<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wait
    }
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
            wait: Waiting::new(ceremony, presses, publish, reach.connect, reach.now),
            vault_path,
            reach,
            openings: Openings::none(),
        }
    }

    fn run(&mut self, gesture: RotationGesture) -> Result<(), String> {
        let stepped = match gesture {
            RotationGesture::ReplaceCaPq => self.replace(RotationKind::CaPq),
            RotationGesture::ReplaceCaTls => self.replace(RotationKind::CaTls),
            RotationGesture::FinishCaTls => self.finish_ca_tls(),
            RotationGesture::FinishCaPq => self.finish_ca_pq(),
            RotationGesture::Resume => self.resume(),
        };
        // Every exit of the ceremony erases what it held, whatever the step ended with.
        self.openings.erase();
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
        self.openings.held = Held::Keys(Box::new(keys));

        self.validate_keys()?;
        let terms = self.await_terms(kind)?;
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
                        self.operator_seen();
                        break;
                    }
                    Err(step) => self.turned_down(step)?,
                }
            }
        }
        Ok(())
    }

    /// The approval screen. Nothing exists at the authority yet, so terms it would
    /// refuse cost nothing: the screen stays, and so do both keys.
    fn await_terms(&mut self, kind: RotationKind) -> Step<RotationTerms> {
        self.honour_cancel()?;
        self.ceremony.gesture = GestureState::Idle;
        self.ceremony.remote = RemoteState::Local;
        loop {
            let patience = self.patience();
            self.ceremony.idle_until = Some(patience.ends_at());
            let offered = self.show();
            let press = self.await_press(&offered, &patience, answers_the_terms)?;
            let Some(terms) = press.terms else {
                continue;
            };
            match rotation::check_terms(kind, &terms, self.now()) {
                Ok(()) => {
                    self.ceremony.key_retry = None;
                    return Ok(terms);
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "durées de rotation refusées");
                    self.ceremony.key_retry = Some(Refusal::TermsRefused);
                }
            }
        }
    }

    fn open_campaign(&mut self, kind: RotationKind, terms: &RotationTerms) -> Step<()> {
        self.ceremony.gesture = GestureState::Verifying;
        self.ceremony.idle_until = None;
        self.show();
        let now = self.now();
        let Held::Keys(keys) = self.openings.take() else {
            return Err(self.nothing_held());
        };
        let opened = rotation::open(self.reach.remote, self.vault_path, kind, *keys, terms, now)
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

    fn sign(&mut self) -> Step<RotationJournal> {
        // The last moment: `Signing` offers no way back.
        self.honour_cancel()?;
        self.ceremony.gesture = GestureState::Signing;
        self.ceremony.idle_until = None;
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

    /// « Terminer » a CA-PQ rotation: one key destroys the outgoing `CA-PQ` in one sealed
    /// write, and the copy of the vault goes to Astra as after any key gesture.
    fn finish_ca_pq(&mut self) -> Step<()> {
        let vault_path = self.vault_path;
        rotation_journal::ensure_none_in_flight(vault_path)
            .map_err(|error| self.refuse(Refusal::RotationInFlight, format!("{error:#}")))?;
        let mut vault = astra_operator::store::load(vault_path)
            .map_err(|error| self.refuse(Refusal::VaultUnavailable, format!("{error:#}")))?;
        // Read before any key: what it would refuse costs no touch.
        let Some((_, _, not_after)) = vault.retained_outgoing_ca_pq_public() else {
            return Err(self.refuse(
                Refusal::NothingToFinish,
                "aucune CA-PQ sortante n'est gardée".to_string(),
            ));
        };
        let now = self.now();
        if now < not_after {
            return Err(self.refuse(
                Refusal::OutgoingCaPqKept { until: not_after },
                "la CA-PQ sortante est gardée jusqu'à son échéance".to_string(),
            ));
        }
        let opening = loop {
            let key = self.ask_key(1, 1, KeyPurpose::Promotion)?;
            match astra_operator::gestures::open_with_authorized_key(key.as_ref(), &vault, "") {
                Ok(opening) => break opening,
                Err(_) => self.turned_down(KeyStep::Declined)?,
            }
        };
        self.honour_cancel()?;
        self.ceremony.key_retry = None;
        self.ceremony.gesture = GestureState::Signing;
        self.ceremony.idle_until = None;
        self.show();

        let now = self.now();
        vault
            .retire_outgoing_ca_pq(&opening, now)
            .map_err(|error| {
                let refusal = match error {
                    VaultError::OutgoingCaPqKept { at } => Refusal::OutgoingCaPqKept { until: at },
                    _ => Refusal::Internal,
                };
                self.refuse(refusal, error.to_string())
            })?;
        astra_operator::store::save(vault_path, &vault)
            .map_err(|error| self.refuse(Refusal::VaultUnavailable, format!("{error:#}")))?;
        // Wiped before the copy, a network call nothing in it is needed for. A copy that
        // fails undoes nothing: the screen offers to send it again (spec §5.9).
        drop(opening);
        let _ = rotation::vault_copy(vault_path)
            .and_then(|copy| self.reach.remote.send_vault_copy(&copy));
        self.done();
        Ok(())
    }

    /// Carries a signed rotation as far as it goes. Asks no key: everything from here
    /// is already decided, which is what lets a resumption do the same.
    fn carry(&mut self, mut journal: RotationJournal) -> Step<()> {
        let now = self.now();
        let advanced = rotation::advance(self.reach.remote, self.vault_path, &mut journal, now);
        if is_deposited(&journal) && self.ceremony.remote != RemoteState::Deposited {
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
                refusal_of_stop(step, &journal),
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
        (self.ceremony.remote, self.ceremony.gesture) = if is_deposited(&journal) {
            (RemoteState::Deposited, GestureState::Idle)
        } else {
            (RemoteState::Prepared, GestureState::Signing)
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
        self.honour_cancel()?;
        self.ceremony.key_retry = None;
        self.ceremony.gesture = GestureState::Signing;
        self.ceremony.idle_until = None;
        self.show();

        let now = self.now();
        match finish.finish(self.reach.remote, self.vault_path, opening, now) {
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
}

/// Whether the authority is known to hold the deposit: past `Signed`, except for an
/// adoption that nothing has confirmed, and that may yet prove a conflict.
fn is_deposited(journal: &RotationJournal) -> bool {
    journal.stage != JournalStage::Signed && !journal.awaits_confirmation()
}

fn refusal_of_open(error: &anyhow::Error) -> Refusal {
    if tunnel::is_unreachable(error) {
        return Refusal::GatewayUnavailable;
    }
    if let Some(refused) = error.downcast_ref::<OpenRefusal>() {
        return match refused {
            OpenRefusal::KeyNotApprovable => Refusal::SignerRevoked,
            OpenRefusal::RotationInFlight | OpenRefusal::CaTlsToFinish => Refusal::RotationInFlight,
            OpenRefusal::AnchorsDisagree => Refusal::DomainConflict,
        };
    }
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refused) => Refusal::AuthorityRefused {
            status: refused.status,
        },
        // What came back does not verify against this domain's files.
        None => Refusal::HandoffMismatch,
    }
}

fn refusal_of_stop(step: ResumeStep, journal: &RotationJournal) -> Refusal {
    match step {
        ResumeStep::Discard => Refusal::RotationExpired,
        ResumeStep::CampaignClosing => Refusal::CampaignClosing {
            until: journal
                .campaign_expires_at
                .saturating_add(rotation_journal::DISCARD_MARGIN_SECS),
        },
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
            FinishRefusal::InFlight => Refusal::RotationInFlight,
            FinishRefusal::NotYet { at } => Refusal::OverlapRunning { until: *at },
            FinishRefusal::Nothing => Refusal::NothingToFinish,
            FinishRefusal::Moved => Refusal::DomainChanged,
            FinishRefusal::Mismatch => Refusal::HandoffMismatch,
        })
}

#[cfg(test)]
mod tests;
