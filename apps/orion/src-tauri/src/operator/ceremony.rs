//! The operator ceremony, run in a thread of this process.
//!
//! # Why it runs here
//!
//! The WebAuthn API answers only inside the interactive user's session, and
//! the platform dialog belongs to a window of the process that asks for it.
//! Orion is that process: its window is the one the operator is looking at,
//! and the press that opens a key dialog comes from it. The ceremony therefore
//! needs no second process, no socket and no foreground grant.
//!
//! # What crosses
//!
//! Presses come in over a channel, one [`Press`] per button. Statuses go out
//! through `publish`. Neither carries a PIN, an assertion or a vault byte: the
//! vault is opened and the key is asked for in this function, and nothing it
//! holds is handed to the caller.

use std::sync::mpsc::Receiver;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationKind, OperationLocator,
    OperatorAction, OperatorStatus, Refusal, RemoteState,
};
use aether_fido::authenticator::DialogOwner;

/// One button pressed in the window: what it asks, the status it answers, and
/// the window the press came from.
///
/// `owner` is the platform handle of that window, or `0` where there is none.
/// It is read on the press that opens a key dialog and is the window the
/// dialog belongs to, so it is carried per press rather than fixed at launch.
#[derive(Debug, Clone, Copy)]
pub struct Press {
    pub action: OperatorAction,
    pub revision: u64,
    pub owner: isize,
}

/// Runs one ceremony to its end, publishing every state it reaches.
///
/// Returns when the ceremony is over, whatever the reason. A `Err` has
/// already been published as a refusal before it is returned, except when the
/// ceremony could not start at all.
pub fn run(
    session_id: Id16,
    locator: OperationLocator,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(session_id, locator);
    publish(ceremony.status());

    match ceremony.operation {
        OperationKind::RecoverIdentity => recover(&mut ceremony, &presses, publish),
        OperationKind::ApproveCampaign => approve_campaign(&mut ceremony, &presses, publish),
        // Named rather than swallowed: an operator whose tab offered a
        // ceremony this build cannot run must be told that, and not left
        // watching a status that never moves.
        other => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            Err(format!(
                "la cérémonie « {other:?} » n'est pas encore portée dans ce processus"
            ))
        }
    }
}

/// §7.5, driven from a screen instead of a terminal.
///
/// The shape is the protocol's: verify, show, wait for the operator, act. The
/// waiting is a press naming the revision it answers, not a blocking read on a
/// console this process does not have.
fn recover(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
) -> Result<(), String> {
    let operation = ceremony.operation_id.ok_or_else(|| {
        "une récupération est désignée par l'identifiant qu'Orion détient".to_string()
    })?;
    let vault_path = astra_operator::store::default_path().map_err(|error| format!("{error:#}"))?;

    let verified = match astra_operator::operations::recovery::begin(
        &vault_path,
        operation,
        None,
        None,
        now_unix(),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            ceremony.refuse(Refusal::HandoffMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };

    // Shown before a key is asked for anything, and it is this object that is
    // signed — §12.2 is the reason the two are the same value rather than two
    // descriptions of one intention.
    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    ceremony.manifest = Some(AstraManifest::Recovery(verified.manifest().clone()));
    let offered = ceremony.status();
    publish(offered.clone());

    let press = match awaited_action(presses, &offered) {
        Some(press) if press.action == OperatorAction::Continue => press,
        _ => {
            ceremony.cancel();
            publish(ceremony.status());
            return Ok(());
        }
    };

    ceremony.gesture = GestureState::ProcessingKey { index: 1, of: 1 };
    publish(ceremony.status());

    let owner = match dialog_owner(press.owner) {
        Ok(owner) => owner,
        Err(error) => {
            ceremony.refuse(Refusal::ForegroundUnavailable);
            publish(ceremony.status());
            return Err(error);
        }
    };
    let key = match aether_fido::authenticator::connect_owned(
        aether_fido::authenticator::Transport::default(),
        owner,
    ) {
        Ok(key) => key,
        Err(error) => {
            ceremony.refuse(Refusal::KeyDeclined);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    // The platform collects the PIN in its own dialog, so it never enters this
    // process. A transport that needs one has no way to ask from here — there
    // is no console — and saying so is better than an empty string that fails
    // three steps later as «clé refusée».
    if key.needs_pin() {
        ceremony.refuse(Refusal::ProtocolViolation);
        publish(ceremony.status());
        return Err(
            "ce transport demande que le PIN soit saisi par le programme, et ce processus n'a \
             aucune interface pour le demander"
                .to_string(),
        );
    }

    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());

    let mut reached = Vec::new();
    let outcome = verified.approve(key.as_ref(), "", &mut |state| reached.push(state));
    // Emitted after the fact rather than from inside the callback: the
    // publisher is borrowed by this frame, and a status lost to a closure's
    // borrow would be a step the operator never saw.
    for state in reached {
        ceremony.remote = state;
        publish(ceremony.status());
    }
    match outcome {
        Ok(()) => {
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::AuthorityRefused { status: 0 });
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

/// §8.5, with its keys asked for one at a time.
///
/// The campaign says how many distinct credentials must approve it, and each
/// one is a separate wait: an operator about to touch the same token twice
/// finds that out at the *second* prompt rather than after both, which is the
/// only moment where the answer is still theirs to change.
fn approve_campaign(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
) -> Result<(), String> {
    let operation = ceremony.operation_id.ok_or_else(|| {
        "une campagne est désignée par l'opération que l'autorité a ouverte".to_string()
    })?;
    let vault_path = astra_operator::store::default_path().map_err(|error| format!("{error:#}"))?;

    let verified = match astra_operator::operations::campaign::begin(
        &vault_path,
        operation,
        None,
        None,
        now_unix(),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            ceremony.refuse(Refusal::HandoffMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };

    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.manifest = Some(AstraManifest::Campaign(verified.manifest().clone()));
    let mut approval = match verified.start_approval(now_unix()) {
        Ok(approval) => approval,
        Err(error) => {
            ceremony.refuse(Refusal::ManifestMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    let required = approval.required_credentials();

    for index in 1..=required {
        ceremony.gesture = GestureState::AwaitingKey {
            index,
            of: required,
            purpose: KeyPurpose::ApproveCampaign,
        };
        let offered = ceremony.status();
        publish(offered.clone());

        let press = match awaited_action(presses, &offered) {
            Some(press) if press.action == OperatorAction::Continue => press,
            _ => {
                ceremony.cancel();
                publish(ceremony.status());
                return Ok(());
            }
        };

        ceremony.gesture = GestureState::ProcessingKey {
            index,
            of: required,
        };
        publish(ceremony.status());
        let owner = match dialog_owner(press.owner) {
            Ok(owner) => owner,
            Err(error) => {
                ceremony.refuse(Refusal::ForegroundUnavailable);
                publish(ceremony.status());
                return Err(error);
            }
        };
        let key = match aether_fido::authenticator::connect_owned(
            aether_fido::authenticator::Transport::default(),
            owner,
        ) {
            Ok(key) => key,
            Err(error) => {
                ceremony.refuse(Refusal::KeyDeclined);
                publish(ceremony.status());
                return Err(format!("{error:#}"));
            }
        };
        if key.needs_pin() {
            ceremony.refuse(Refusal::ProtocolViolation);
            publish(ceremony.status());
            return Err(
                "ce transport demande que le PIN soit saisi par le programme, et ce processus \
                 n'a aucune interface pour le demander"
                    .to_string(),
            );
        }
        match approval.approve_key(key.as_ref(), "", now_unix()) {
            Ok(label) => ceremony.keys.push(KeySlotLabel {
                slot: index.to_string(),
                label,
            }),
            Err(error) => {
                ceremony.refuse(Refusal::KeyDeclined);
                publish(ceremony.status());
                return Err(format!("{error:#}"));
            }
        }
    }

    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());

    let mut reached = Vec::new();
    let outcome = approval.finish(now_unix(), &mut |state| reached.push(state));
    for state in reached {
        ceremony.remote = state;
        publish(ceremony.status());
    }
    match outcome {
        Ok(_) => {
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::AuthorityRefused { status: 0 });
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

/// Waits for the operator's answer to one rendered status.
///
/// A press naming another revision is ignored rather than obeyed: it answers a
/// screen this session has already left, and acting on it would apply a press
/// to whatever replaced it. `None` means every sender is gone — the window that
/// held the ceremony was closed, which is an abandonment and not a failure.
fn awaited_action(presses: &Receiver<Press>, offered: &OperatorStatus) -> Option<Press> {
    loop {
        let press = presses.recv().ok()?;
        if offered.accepts(press.action, press.revision) {
            return Some(press);
        }
    }
}

/// The window the platform dialog belongs to, from the press that opened it.
///
/// Orion's own window: the press came from it, and it is the window the
/// operator is looking at. A press that carries no handle is refused rather
/// than opened unowned — an unowned dialog may appear behind the window the
/// operator is reading, with nothing to say why the key never answers.
#[cfg(windows)]
fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    if owner == 0 {
        return Err(
            "la fenêtre d'Orion est introuvable : la boîte de la clé n'aurait pas de propriétaire"
                .to_string(),
        );
    }
    Ok(DialogOwner::Window(owner))
}

/// Off Windows the only transport is raw CTAP, whose gesture is on the token
/// and shows no dialog: the console is the honest owner, and nothing is
/// claimed.
#[cfg(not(windows))]
fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    let _ = owner;
    Ok(DialogOwner::Console)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One ceremony, and the revision counter that orders what it says.
struct Ceremony {
    session_id: Id16,
    operation: OperationKind,
    operation_id: Option<Id16>,
    revision: u64,
    remote: RemoteState,
    gesture: GestureState,
    manifest: Option<AstraManifest>,
    refusal: Option<Refusal>,
    keys: Vec<KeySlotLabel>,
}

impl Ceremony {
    fn new(session_id: Id16, locator: OperationLocator) -> Self {
        Self {
            session_id,
            operation: locator.kind,
            operation_id: locator.operation_id,
            revision: 0,
            remote: RemoteState::Local,
            gesture: GestureState::Verifying,
            manifest: None,
            refusal: None,
            keys: Vec::new(),
        }
    }

    /// Renders the current state, advancing the revision.
    ///
    /// Every status a ceremony emits goes through here, so the counter can only
    /// move forward and two statuses can never share a revision — which is what
    /// makes a press naming one of them unambiguous.
    fn status(&mut self) -> OperatorStatus {
        self.revision += 1;
        let mut status = OperatorStatus::new(
            self.session_id,
            self.revision,
            self.operation,
            self.remote,
            self.gesture,
        );
        status.operation_id = self.operation_id;
        status.manifest = self.manifest.clone();
        status.refusal = self.refusal;
        status.keys = self.keys.clone();
        status
    }

    fn refuse(&mut self, refusal: Refusal) {
        self.gesture = GestureState::Failed;
        self.refusal = Some(refusal);
    }

    /// Abandoned by the operator, before anything left this machine.
    ///
    /// A distinct state from a refusal: nothing failed, and an interface that
    /// showed «échec» for a decision would be telling the operator their own
    /// choice went wrong.
    fn cancel(&mut self) {
        self.gesture = GestureState::Cancelled;
        self.refusal = Some(Refusal::Cancelled);
    }
}

#[cfg(test)]
mod tests;
