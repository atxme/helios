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
    BeginCommand, GestureState, OperationKind, OperationLocator, OperatorCommand, OperatorHello,
    OperatorStatus, Refusal, RemoteState, PROTOCOL_VERSION,
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
    let _owner = window.owner();

    ceremony.refuse(Refusal::Internal);
    session::write_status(&mut writer, &ceremony.status())?;
    bail!(
        "cette cérémonie n'est pas encore portée dans le helper ; elle reste dans l'adaptateur \
         en ligne de commande"
    )
}

/// One ceremony, and the revision counter that orders what it says.
struct Ceremony {
    session_id: Id16,
    operation: OperationKind,
    operation_id: Option<Id16>,
    revision: u64,
    remote: RemoteState,
    gesture: GestureState,
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
        status.refusal = self.refusal;
        status
    }

    fn refuse(&mut self, refusal: Refusal) {
        self.gesture = GestureState::Failed;
        self.refusal = Some(refusal);
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
