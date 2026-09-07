//! The operator process Orion starts, and that nobody starts by hand.
//!
//! # Why it exists as a process
//!
//! Orion runs elevated, always and by design: WireGuard-NT cannot be loaded
//! otherwise. The Windows WebAuthn API answers only inside the interactive
//! user's session, at medium integrity. The two requirements are not
//! reconcilable in one process, so the ceremony runs here, in a child launched
//! **below** Orion's token.
//!
//! # Why it has no command line
//!
//! Because a command line is what this whole change exists to remove. Every
//! value a ceremony needs is already held by one of the three programs: Orion
//! opened the operation and holds its identifier, this helper pins the domain
//! hand-off beside the vault, Astra holds the policy. An operator retyping
//! them was a transcription channel with a human as the wire, and it failed the
//! way transcription always does — a flag renamed, a window expired mid-copy,
//! an argument missing from the help.
//!
//! So there is exactly one argument, and it is not a secret: where to connect
//! back. The session token comes through the environment block, which Orion
//! gives this child alone. On both platforms a command line is readable by any
//! process of the same user; an environment block is not, and protocol 1 put
//! the token on the command line as a known limitation. This closes it.
//!
//! # What it may be asked to do
//!
//! One [`OperationLocator`] per session — a kind, and at most an identifier.
//! Not a URL, not a path, not a request. The authority origin, the RP ID, the
//! service key and the domain all come from the hand-off this process pins
//! itself: taking them from the socket would mean the program holding the
//! vault learned where to send its signatures from a program that does not
//! hold it.

mod owner;
mod session;

use std::io::BufReader;
use std::net::TcpStream;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    AstraManifest, BeginCommand, GestureState, KeyPurpose, OperationKind, OperationLocator,
    OperatorAction, OperatorCommand, OperatorHello, OperatorStatus, Refusal, RemoteState,
    PROTOCOL_VERSION,
};
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// Where the session token is read from.
///
/// Orion builds this child an environment block of its own. Unlike a command
/// line it is not readable by other processes of the same user, which is the
/// limitation protocol 1 documented and did not close.
const TOKEN_VARIABLE: &str = "HELIOS_ASTRA_SESSION_TOKEN";

/// Where the session identifier is read from.
///
/// Beside the token rather than on the command line, for one reason: the two
/// are checked together, and splitting them across two channels would let a
/// stale launch present a fresh token with an old session.
const SESSION_VARIABLE: &str = "HELIOS_ASTRA_SESSION_ID";

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("helios-astra-helper".into())
        .stack_size(astra_operator::WORK_STACK_BYTES)
        .spawn(run)
        .context("démarrage du fil de travail")?
        .join()
        .map_err(|_| anyhow::anyhow!("le fil de travail s'est interrompu"))?
}

/// The one argument: where to connect back.
struct Invocation {
    address: String,
    session_id: Id16,
    token: Zeroizing<String>,
}

fn invocation() -> Result<Invocation> {
    let mut arguments = std::env::args().skip(1);
    let address = match arguments.next().as_deref() {
        Some("--ipc-address") => arguments
            .next()
            .context("« --ipc-address » attend une adresse")?,
        // Named rather than inferred: a helper someone ran by hand should be
        // told what it is, not silently do nothing.
        _ => bail!(
            "ce programme est lancé par Orion et par rien d'autre : il n'a pas d'interface en \
             ligne de commande. Les cérémonies opérateur se font dans l'onglet Astra d'Orion."
        ),
    };
    if arguments.next().is_some() {
        bail!("un seul argument est accepté : « --ipc-address »");
    }
    let session_id = std::env::var(SESSION_VARIABLE)
        .ok()
        .and_then(|raw| Id16::parse_hex(raw.trim()).ok())
        .with_context(|| format!("{SESSION_VARIABLE} manquant ou illisible"))?;
    let token = Zeroizing::new(
        std::env::var(TOKEN_VARIABLE).with_context(|| format!("{TOKEN_VARIABLE} manquant"))?,
    );
    if token.trim().is_empty() {
        bail!("{TOKEN_VARIABLE} est vide");
    }
    // Removed from this process's own environment once read: the ceremony
    // below spawns nothing, but a token that stays in the block is a token any
    // future child would inherit.
    std::env::remove_var(TOKEN_VARIABLE);
    Ok(Invocation {
        address,
        session_id,
        token,
    })
}

fn run() -> Result<()> {
    let invocation = invocation()?;
    let stream = TcpStream::connect(&invocation.address)
        .with_context(|| format!("connexion au canal opérateur {}", invocation.address))?;
    let mut writer = stream.try_clone().context("duplication du canal")?;
    let mut reader = BufReader::new(stream);

    session::write_hello(
        &mut writer,
        &OperatorHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: invocation.session_id,
            token: invocation.token.to_string(),
        },
    )?;
    drop(invocation.token);

    let Some(command) = session::read_command(&mut reader)? else {
        // Orion closed before asking for anything. Not a failure: a window was
        // shut, and there is nothing to report to anyone.
        return Ok(());
    };
    let OperatorCommand::Begin(BeginCommand { locator }) = command else {
        bail!("la première commande d'une session doit être « begin »");
    };

    let mut ceremony = Ceremony::new(invocation.session_id, locator);
    session::write_status(&mut writer, &ceremony.status())?;

    // The window the platform prompts will belong to, held for the whole
    // ceremony and destroyed with it. Acquired **before** any key is asked
    // for: a helper that discovered it had nowhere to show a dialog after
    // opening the vault would be holding `CA-PQ` with no way to finish.
    let window = owner::create()?;

    match ceremony.operation {
        OperationKind::RecoverIdentity => recover(&mut ceremony, &mut reader, &mut writer, &window),
        // Named rather than swallowed: an operator whose tab offered a
        // ceremony this build cannot run must be told that, and not left
        // watching a status that never moves.
        other => {
            ceremony.refuse(Refusal::Internal);
            session::write_status(&mut writer, &ceremony.status())?;
            bail!("la cérémonie « {other:?} » n'est pas encore portée dans ce processus")
        }
    }
}

/// §7.5, driven from a screen instead of a terminal.
///
/// The shape is the protocol's: verify, show, wait for the operator, act. The
/// waiting is a `Continue` naming the revision it answers, not a blocking read
/// on a console this process does not have.
fn recover<R: std::io::BufRead, W: std::io::Write>(
    ceremony: &mut Ceremony,
    reader: &mut R,
    writer: &mut W,
    window: &owner::OwnerWindow,
) -> Result<()> {
    let operation = ceremony
        .operation_id
        .context("une récupération est désignée par l'identifiant qu'Orion détient")?;
    let vault_path = astra_operator::store::default_path()?;

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
            session::write_status(writer, &ceremony.status())?;
            return Err(error);
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
    session::write_status(writer, &offered)?;

    match awaited_action(reader, &offered)? {
        Some(OperatorAction::Continue) => {}
        Some(OperatorAction::Cancel) | None => {
            ceremony.cancel();
            session::write_status(writer, &ceremony.status())?;
            return Ok(());
        }
    }

    ceremony.gesture = GestureState::ProcessingKey { index: 1, of: 1 };
    session::write_status(writer, &ceremony.status())?;

    let key = helios_fido::authenticator::connect_owned(
        helios_fido::authenticator::Transport::default(),
        window.owner(),
    )?;
    // The platform collects the PIN in its own dialog, so it never enters this
    // process. A transport that needs one has no way to ask from here — there
    // is no console — and saying so is better than an empty string that fails
    // three steps later as «clé refusée».
    if key.needs_pin() {
        ceremony.refuse(Refusal::ProtocolViolation);
        session::write_status(writer, &ceremony.status())?;
        bail!(
            "ce transport demande que le PIN soit saisi par le programme, et ce processus n'a \
             aucune interface pour le demander"
        );
    }

    ceremony.gesture = GestureState::Signing;
    session::write_status(writer, &ceremony.status())?;

    let mut reached = Vec::new();
    let outcome = verified.approve(key.as_ref(), "", &mut |state| reached.push(state));
    // Emitted after the fact rather than from inside the callback: the writer
    // is borrowed by this frame, and a status lost to a closure's borrow would
    // be a step the operator never saw.
    for state in reached {
        ceremony.remote = state;
        session::write_status(writer, &ceremony.status())?;
    }
    match outcome {
        Ok(()) => {
            ceremony.gesture = GestureState::Done;
            session::write_status(writer, &ceremony.status())?;
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::AuthorityRefused { status: 0 });
            session::write_status(writer, &ceremony.status())?;
            Err(error)
        }
    }
}

/// Waits for the operator's answer to one rendered status.
///
/// A command naming another revision is ignored rather than obeyed: it answers
/// a screen this session has already left, and acting on it would apply a press
/// to whatever replaced it.
fn awaited_action<R: std::io::BufRead>(
    reader: &mut R,
    offered: &OperatorStatus,
) -> Result<Option<OperatorAction>> {
    loop {
        let Some(command) = session::read_command(reader)? else {
            return Ok(None);
        };
        let (action, revision) = match command {
            OperatorCommand::Continue(step) => (OperatorAction::Continue, step.revision),
            OperatorCommand::Cancel(step) => (OperatorAction::Cancel, step.revision),
            OperatorCommand::Begin(_) => {
                bail!("une session ne commence qu'une fois")
            }
        };
        if offered.accepts(action, revision) {
            return Ok(Some(action));
        }
    }
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
        }
    }

    /// Renders the current state, advancing the revision.
    ///
    /// Every status a session emits goes through here, so the counter can only
    /// move forward and two statuses can never share a revision — which is
    /// what makes a command naming one of them unambiguous.
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
mod tests {
    use super::*;
    use aether::certificates::operator_session::OperatorAction;

    fn locator() -> OperationLocator {
        OperationLocator {
            kind: OperationKind::RecoverIdentity,
            operation_id: Id16::parse_hex("fdcc7341b0cf98f1672eab37508db464").ok(),
        }
    }

    /// The property a command depends on: no two statuses of one session ever
    /// share a revision, and the counter never goes back.
    #[test]
    fn revisions_only_move_forward() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        let first = ceremony.status();
        let second = ceremony.status();
        assert_eq!(first.revision, 1);
        assert_eq!(second.revision, 2);
    }

    /// A refusal is terminal, and a terminal status offers nothing: an
    /// interface that still rendered «Continuer» would be offering a button
    /// the listener refuses.
    #[test]
    fn a_refused_ceremony_offers_no_action() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        ceremony.refuse(Refusal::KeyDeclined);
        let status = ceremony.status();
        assert_eq!(status.refusal, Some(Refusal::KeyDeclined));
        assert!(status.allowed.is_empty());
        assert!(!status.accepts(OperatorAction::Continue, status.revision));
    }

    /// A press answering a screen this session has already left must not be
    /// applied to whatever replaced it.
    #[test]
    fn a_command_on_a_stale_revision_is_ignored_and_the_right_one_is_taken() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        ceremony.remote = RemoteState::AwaitingOperator;
        ceremony.gesture = GestureState::AwaitingKey {
            index: 1,
            of: 1,
            purpose: KeyPurpose::OpenVault,
        };
        let offered = ceremony.status();

        let mut wire = Vec::new();
        for command in [
            OperatorCommand::Continue(aether::certificates::operator_session::StepCommand {
                revision: offered.revision + 5,
            }),
            OperatorCommand::Continue(aether::certificates::operator_session::StepCommand {
                revision: offered.revision,
            }),
        ] {
            session::write_frame(
                &mut wire,
                &command,
                aether::certificates::operator_session::limits::COMMAND_BYTES,
            )
            .expect("written");
        }
        let mut reader = std::io::BufReader::new(wire.as_slice());
        assert_eq!(
            awaited_action(&mut reader, &offered).expect("read"),
            Some(OperatorAction::Continue)
        );
    }

    /// A socket that closes while the operator is being waited on is an
    /// abandonment, not a refusal: Orion's window was shut.
    #[test]
    fn a_closed_channel_while_waiting_is_an_abandonment() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        ceremony.gesture = GestureState::AwaitingKey {
            index: 1,
            of: 1,
            purpose: KeyPurpose::OpenVault,
        };
        let offered = ceremony.status();
        let mut reader = std::io::BufReader::new(&b""[..]);
        assert_eq!(awaited_action(&mut reader, &offered).expect("closed"), None);
    }

    /// An abandonment is not a failure, and the interface must be able to tell
    /// the operator's own choice from something that went wrong.
    #[test]
    fn a_cancellation_is_not_a_failure() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        ceremony.cancel();
        let status = ceremony.status();
        assert_eq!(status.gesture, GestureState::Cancelled);
        assert_eq!(status.refusal, Some(Refusal::Cancelled));
        assert!(status.allowed.is_empty());
    }

    /// The locator travels whole: an operation the authority opened is reached
    /// by the identifier Orion holds, and a status that dropped it would leave
    /// an operator unable to say which recovery they were looking at.
    #[test]
    fn a_status_names_the_operation_it_is_about() {
        let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
        let status = ceremony.status();
        assert_eq!(status.operation, OperationKind::RecoverIdentity);
        assert_eq!(status.operation_id, locator().operation_id);
    }
}
