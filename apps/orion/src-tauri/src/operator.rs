//! Orion's half of an operator ceremony (protocol 2).
//!
//! # What is here, and what deliberately is not
//!
//! A loopback listener, a one-use session, and the states the helper
//! publishes. The authority vault, the FIDO gesture and every signature are in
//! the helper and reachable from nowhere else — this process does not even
//! depend on the crate that knows how to open a vault, which is a dependency
//! edge rather than a promise.
//!
//! Orion is the **server** of the socket, not the client: it binds before the
//! child exists, so there is no window in which something else could hold the
//! address the helper is told to reach.
//!
//! # What crosses
//!
//! Only [`OperatorStatus`] one way and [`OperatorCommand`] the other, both
//! defined in `aether` and both public by construction: two states, a typed
//! manifest, the labels of the key-slots that answered. No PIN, no assertion,
//! no vault byte. The WebView therefore renders progress it cannot influence,
//! and the refusals stay where the secrets are.
//!
//! # Why the WebView names so little
//!
//! An [`OperationLocator`] — a kind, and at most an operation identifier Orion
//! itself opened. The authority origin, the RP ID, the domain and the service
//! key come from the hand-off the helper pins beside its own vault. A stolen
//! session token therefore buys the ability to watch a ceremony the operator
//! started; it does not buy the ability to choose one.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    limits, BeginCommand, GestureState, OperationLocator, OperatorAction, OperatorCommand,
    OperatorHello, OperatorStatus, Refusal, RemoteState, StepCommand, PROTOCOL_VERSION,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use zeroize::Zeroizing;

/// How long the helper has to connect and authenticate.
///
/// It covers a process launch and nothing else. A minute would mean an
/// operator staring at «Démarrage» long after the launch has already failed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a step may take before Orion stops waiting for the next state.
///
/// The steps that hold on a human — finding a key, touching it — are not
/// bounded here: the helper answers those with a state change of its own the
/// moment it starts working. This bounds the fetching and the signing between
/// two such states.
const STEP_TIMEOUT: Duration = Duration::from_secs(90);

/// Where the helper reads the session token from.
const TOKEN_VARIABLE: &str = "HELIOS_ASTRA_SESSION_TOKEN";
/// Where the helper reads the session identifier from.
const SESSION_VARIABLE: &str = "HELIOS_ASTRA_SESSION_ID";

/// The live helper, for as long as one is connected.
struct Session {
    commands: OwnedWriteHalf,
    status: watch::Receiver<OperatorStatus>,
}

/// The one ceremony Orion hosts at a time.
///
/// A second concurrent ceremony is refused rather than queued. Two of them
/// would open the vault twice against one domain, and — for the two that
/// consume an operation — each would spend an approval the other is still
/// counting on.
#[derive(Default)]
pub struct OperatorCeremony(Mutex<Option<Session>>);

impl OperatorCeremony {
    /// The last state the helper published, or `None` when none ran.
    ///
    /// `None` rather than a synthetic «idle» status: there is no session, so
    /// there is no revision, and inventing one would give the WebView a number
    /// it could send back.
    pub async fn status(&self) -> Option<OperatorStatus> {
        self.0
            .lock()
            .await
            .as_mut()
            .map(|session| session.status.borrow_and_update().clone())
    }

    /// Launches the helper and returns the first state it publishes.
    pub async fn begin(&self, locator: OperationLocator) -> Result<OperatorStatus, String> {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !current.gesture.is_terminal() {
                return Err(
                    "une cérémonie opérateur est déjà ouverte : la mener à son terme ou \
                     l'annuler avant d'en ouvrir une autre"
                        .to_string(),
                );
            }
        }
        *held = None;

        // Bound to the loopback address explicitly rather than to `0.0.0.0`: a
        // listener reachable off-machine would be a way to drive an operator's
        // ceremony from the network.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(|error| format!("ouverture du canal local : {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("adresse du canal local : {error}"))?;
        let session_id = Id16::new(
            *aether::random::secret_bytes::<16>()
                .map_err(|error| format!("tirage de l'identifiant de session : {error}"))?,
        )
        .map_err(|error| format!("identifiant de session : {error}"))?;
        let token = session_token()?;

        crate::companion::launch_helper(
            &["--ipc-address".to_string(), address.to_string()],
            &[
                (SESSION_VARIABLE.to_string(), session_id.to_hex()),
                (TOKEN_VARIABLE.to_string(), token.to_string()),
            ],
        )?;

        let (reader, mut commands) = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            authenticated_helper(&listener, session_id, &token),
        )
        .await
        .map_err(|_| {
            "le processus opérateur ne s'est pas présenté. Vérifier que « helios-astra-helper » \
             est installé à côté d'Orion."
                .to_string()
        })??;

        let kind = locator.kind;
        send(
            &mut commands,
            &OperatorCommand::Begin(BeginCommand { locator }),
        )
        .await?;

        let (publisher, status) = watch::channel(OperatorStatus::new(
            session_id,
            0,
            kind,
            RemoteState::Local,
            GestureState::Verifying,
        ));
        tauri::async_runtime::spawn(pump(reader, publisher, session_id));
        let mut session = Session { commands, status };
        let first = awaited(&mut session.status).await?;
        *held = Some(session);
        Ok(first)
    }

    /// Takes the next step of the open ceremony.
    ///
    /// `revision` names the status the operator was looking at. Both ends
    /// check it: this one because it is the surface that offered the button,
    /// the helper because it is the one that would act on it.
    pub async fn advance(
        &self,
        action: OperatorAction,
        revision: u64,
    ) -> Result<OperatorStatus, String> {
        let mut held = self.0.lock().await;
        let session = held
            .as_mut()
            .ok_or_else(|| "aucune cérémonie opérateur n'est ouverte".to_string())?;

        let current = session.status.borrow_and_update().clone();
        if !current.accepts(action, revision) {
            return Err(
                "cette étape n'accepte pas cette action : l'écran a changé depuis la pression"
                    .to_string(),
            );
        }

        let command = match action {
            OperatorAction::Continue => OperatorCommand::Continue(StepCommand { revision }),
            OperatorAction::Cancel => OperatorCommand::Cancel(StepCommand { revision }),
        };
        send(&mut session.commands, &command).await?;
        awaited(&mut session.status).await
    }

    /// Forgets a completed session after its final state has been shown.
    /// A live session cannot be dismissed: dropping its command channel would
    /// look like cancellation even after the helper crossed the point where
    /// cancellation is honest.
    pub async fn dismiss(&self) -> Result<(), String> {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !current.gesture.is_terminal() {
                return Err("la cérémonie opérateur est encore en cours".to_string());
            }
        }
        *held = None;
        Ok(())
    }
}

/// 256 bits from the one entry point this repository draws randomness through.
fn session_token() -> Result<Zeroizing<String>, String> {
    let bytes = aether::random::secret_bytes::<32>()
        .map_err(|error| format!("tirage du jeton de session : {error}"))?;
    Ok(Zeroizing::new(
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    ))
}

/// Accepts local connections until one presents the session.
///
/// A loop rather than a single accept: anything on the machine may reach a
/// loopback port, and letting the first connection consume the listener would
/// let any local process keep the real helper from ever being heard.
///
/// The identifier is checked beside the token. A token alone authenticates
/// *something*; the pair says it is the child of the session this Orion opened,
/// and refuses a stale launch presenting a fresh token.
async fn authenticated_helper(
    listener: &TcpListener,
    session_id: Id16,
    token: &Zeroizing<String>,
) -> Result<(BufReader<OwnedReadHalf>, OwnedWriteHalf), String> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("acceptation du canal local : {error}"))?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let hello: Option<OperatorHello> = match receive(&mut reader, limits::HELLO_BYTES).await {
            Ok(hello) => hello,
            Err(_) => continue,
        };
        let Some(hello) = hello else { continue };
        if hello.protocol_version == PROTOCOL_VERSION
            && hello.session_id == session_id
            && same_secret(&hello.token, token)
        {
            return Ok((reader, writer));
        }
    }
}

/// Compares two secrets without letting the timing say where they differ.
fn same_secret(candidate: &str, expected: &str) -> bool {
    let (candidate, expected) = (candidate.as_bytes(), expected.as_bytes());
    candidate.len() == expected.len()
        && candidate
            .iter()
            .zip(expected)
            .fold(0u8, |accumulator, (left, right)| {
                accumulator | (left ^ right)
            })
            == 0
}

/// Republishes every state the helper sends, until it stops sending.
///
/// Two things are refused rather than forwarded, and both are the same defect
/// seen from different sides: a status about another session, and a status
/// whose revision does not advance. Either would let a second connection — or
/// a replayed frame — move the screen the operator is deciding from.
///
/// A helper that dies mid-ceremony is reported as a failure rather than left
/// on its last hopeful state: the operator would otherwise wait on a
/// «signature en cours» that nothing is performing.
async fn pump(
    mut reader: BufReader<OwnedReadHalf>,
    publisher: watch::Sender<OperatorStatus>,
    session_id: Id16,
) {
    let mut last_revision = 0;
    loop {
        match receive::<OperatorStatus>(&mut reader, limits::STATUS_BYTES).await {
            Ok(Some(status)) => {
                if status.session_id != session_id || status.revision <= last_revision {
                    continue;
                }
                last_revision = status.revision;
                let terminal = status.gesture.is_terminal();
                if publisher.send(status).is_err() || terminal {
                    return;
                }
            }
            Ok(None) => {
                let last = publisher.borrow().clone();
                if !last.gesture.is_terminal() {
                    let mut failed = OperatorStatus::new(
                        session_id,
                        last.revision + 1,
                        last.operation,
                        last.remote,
                        GestureState::Failed,
                    );
                    failed.operation_id = last.operation_id;
                    failed.refusal = Some(Refusal::Internal);
                    let _ = publisher.send(failed);
                }
                return;
            }
            Err(_) => {
                let last = publisher.borrow().clone();
                let mut failed = OperatorStatus::new(
                    session_id,
                    last.revision + 1,
                    last.operation,
                    last.remote,
                    GestureState::Failed,
                );
                failed.operation_id = last.operation_id;
                failed.refusal = Some(Refusal::ProtocolViolation);
                let _ = publisher.send(failed);
                return;
            }
        }
    }
}

/// Waits for the next state the helper publishes.
async fn awaited(status: &mut watch::Receiver<OperatorStatus>) -> Result<OperatorStatus, String> {
    tokio::time::timeout(STEP_TIMEOUT, status.changed())
        .await
        .map_err(|_| "le processus opérateur ne répond plus".to_string())?
        .map_err(|_| "le processus opérateur s'est arrêté".to_string())?;
    Ok(status.borrow_and_update().clone())
}

/// Writes one newline-delimited JSON frame, bounded by what it carries.
async fn send(writer: &mut OwnedWriteHalf, command: &OperatorCommand) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(command).map_err(|error| format!("encodage du message : {error}"))?;
    if bytes.len() > limits::COMMAND_BYTES {
        return Err("message trop volumineux pour le canal local".into());
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| format!("écriture du canal local : {error}"))
}

/// Reads one newline-delimited JSON frame, refusing an unbounded one.
///
/// `Ok(None)` is a closed channel, which is how a finished helper looks.
async fn receive<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>,
    ceiling: usize,
) -> Result<Option<T>, String> {
    let mut frame = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| format!("lecture du canal local : {error}"))?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err("message tronqué sur le canal local".into())
            };
        }
        let (taken, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index, true),
            None => (available.len(), false),
        };
        if frame.len() + taken > ceiling {
            return Err("message trop volumineux sur le canal local".into());
        }
        frame.extend_from_slice(&available[..taken]);
        reader.consume(taken + usize::from(complete));
        if complete {
            break;
        }
    }
    serde_json::from_slice(&frame)
        .map(Some)
        .map_err(|error| format!("message illisible sur le canal local : {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::operator_session::{KeyPurpose, OperationKind};

    fn session() -> Id16 {
        Id16::new([4; 16]).expect("id")
    }

    #[test]
    fn a_wrong_secret_is_refused_whatever_its_shape() {
        assert!(same_secret("abcd", "abcd"));
        assert!(!same_secret("abcd", "abce"));
        assert!(!same_secret("abcd", "abcde"));
        assert!(!same_secret("", "a"));
    }

    /// The button is offered and refused from the same value, so a WebView
    /// that invented one gains nothing.
    #[tokio::test]
    async fn a_ceremony_that_never_started_accepts_nothing() {
        let ceremony = OperatorCeremony::default();
        assert!(ceremony.status().await.is_none());
        assert!(ceremony.advance(OperatorAction::Continue, 1).await.is_err());
    }

    /// A press on a screen the helper has already left must not be applied to
    /// whatever replaced it, and Orion refuses it before it reaches the wire.
    #[test]
    fn a_stale_revision_is_not_accepted() {
        let status = OperatorStatus::new(
            session(),
            9,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        );
        assert!(status.accepts(OperatorAction::Continue, 9));
        assert!(!status.accepts(OperatorAction::Continue, 8));
    }

    /// Once the signed objects have left, «Annuler» would promise something
    /// this side cannot deliver — and the surface must not offer it either.
    #[test]
    fn nothing_is_cancellable_past_the_deposit() {
        let status = OperatorStatus::new(
            session(),
            2,
            OperationKind::RecoverIdentity,
            RemoteState::Staged,
            GestureState::Idle,
        );
        assert!(!status.accepts(OperatorAction::Cancel, 2));
    }
}
