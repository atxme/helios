//! Orion's half of the CA-TLS ceremony the Astra companion performs.
//!
//! # What runs where, and why it has to be split
//!
//! `astra-signer` owns the authority vault, the FIDO2 gesture and every
//! signature: none of that moves here, and none of it is reachable from the
//! WebView. Orion owns the window the operator is already looking at. The two
//! cannot share a process — Orion runs elevated so WireGuard-NT will load,
//! while the WebAuthn platform API answers only inside the interactive user's
//! session — so the companion is spawned **below** Orion's token and talks
//! back over a loopback socket.
//!
//! Orion is the server of that socket, not the client: it binds before the
//! child exists, so there is no window in which something else could be
//! holding the address the companion is told to reach.
//!
//! # What crosses the channel
//!
//! Only [`AstraCaTlsStatus`](aether::certificates::operator_ipc::AstraCaTlsStatus) one way and [`AstraIpcCommand`](aether::certificates::operator_ipc::AstraIpcCommand) the other, both
//! defined in `aether` and both public by construction: a phase, a sentence,
//! the campaign manifest the authority signed, and the labels of the key-slots
//! that answered. No PIN, no assertion, no vault byte. The WebView therefore
//! renders progress it cannot influence, and the ceremony's refusals stay
//! where the secrets are.
//!
//! # Known limitation: the session token is on the child's command line
//!
//! The 32-byte token authenticates the companion to this listener. It is
//! handed over as an argument, which on both platforms is readable by other
//! processes of the same user, so a local process could in principle
//! impersonate the companion and publish a false *progress display*. It gains
//! nothing else: it holds no vault, signs nothing, and Astra accepts no
//! deposit from it. Closing it means giving the launcher an environment block
//! of its own — `CreateProcessWithTokenW` is passed none today — which is
//! Windows-only code this repository cannot compile or exercise (see
//! `docs/testing/TESTING.md`). The `--ipc-token` flag already reads
//! `ASTRA_ORION_IPC_TOKEN`, so that change needs no protocol change.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use aether::certificates::operator_ipc::{
    AstraCaTlsPhase, AstraCaTlsStatus, AstraIpcCommand, AstraIpcHello, MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
};
use orion_core::certificate_renewal::CompanionInvocation;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use zeroize::Zeroizing;

/// How long the companion has to connect and authenticate.
///
/// It covers a process launch and nothing else. A minute would mean an
/// operator staring at «Démarrage» long after the launch has already failed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a step may take before Orion stops waiting for its next state.
///
/// The steps that hold on an operator — plugging a key, touching it — are not
/// bounded here: the companion answers those with a phase change of its own
/// the moment it starts working. This bounds the fetching and the signing
/// between two such phases.
const STEP_TIMEOUT: Duration = Duration::from_secs(90);

/// An operation identifier is 16 bytes, written as hex (`Id16`).
const OPERATION_ID_HEX: usize = 32;

/// What the operator chose for one rotation.
///
/// The campaign itself is **not** here: it is fetched by the companion and
/// verified under the Astra service key the vault's hand-off pins. This
/// structure names an existing operation; it cannot describe one.
#[derive(Debug, Clone, Deserialize)]
pub struct RotationInput {
    pub vault_path: String,
    pub heliosd_url: String,
    pub operation_id: String,
    pub output_path: String,
}

/// The live companion, for as long as one is connected.
struct Session {
    commands: OwnedWriteHalf,
    status: watch::Receiver<AstraCaTlsStatus>,
}

/// The one ceremony Orion will host at a time.
///
/// A second concurrent rotation is refused rather than queued: both would
/// spend a campaign approval against the same outgoing anchor, and each would
/// then name the other's transition as the one it replaces.
#[derive(Default)]
pub struct Ceremony(Mutex<Option<Session>>);

impl Ceremony {
    /// Last state published by the companion, or `idle` when none ran.
    pub async fn status(&self) -> AstraCaTlsStatus {
        match self.0.lock().await.as_mut() {
            Some(session) => session.status.borrow_and_update().clone(),
            None => AstraCaTlsStatus::new(AstraCaTlsPhase::Idle, "Aucune rotation en cours."),
        }
    }

    /// Launches the companion and returns the first state it publishes.
    pub async fn start(&self, input: RotationInput) -> Result<AstraCaTlsStatus, String> {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !matches!(
                current.phase,
                AstraCaTlsPhase::Failed | AstraCaTlsPhase::Cancelled | AstraCaTlsPhase::Promoted
            ) {
                return Err(format!(
                    "une rotation CA-TLS est déjà en cours ({}). La mener à son terme ou \
                     l'annuler avant d'en ouvrir une autre.",
                    current.message
                ));
            }
        }
        *held = None;

        let input = validated(input)?;
        // Bound to the loopback address explicitly rather than to `0.0.0.0`:
        // the companion refuses anything but a loopback endpoint, and a
        // listener reachable off-machine would be a way to drive an operator's
        // ceremony from the network.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(|error| format!("ouverture du canal local : {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("adresse du canal local : {error}"))?;
        let token = session_token()?;

        launch(&input, address, &token)?;
        let (reader, commands) = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            authenticated_companion(&listener, &token),
        )
        .await
        .map_err(|_| {
            "le compagnon Astra ne s'est pas présenté. Vérifier qu'« astra-signer » est \
             installé et joignable depuis le PATH."
                .to_string()
        })??;

        let (publisher, status) = watch::channel(AstraCaTlsStatus::new(
            AstraCaTlsPhase::Starting,
            "Compagnon Astra démarré ; vérification de la campagne.",
        ));
        tauri::async_runtime::spawn(pump(reader, publisher));
        let mut session = Session { commands, status };
        let first = awaited(&mut session.status).await?;
        *held = Some(session);
        Ok(first)
    }

    /// Takes the next step of the open ceremony.
    pub async fn advance(&self, command: AstraIpcCommand) -> Result<AstraCaTlsStatus, String> {
        let mut held = self.0.lock().await;
        let session = held
            .as_mut()
            .ok_or_else(|| "aucune rotation CA-TLS n'est ouverte".to_string())?;

        let current = session.status.borrow_and_update().clone();
        // Refused here as well as in the companion. Orion is the surface that
        // offers the button, and a button offered for a decision that has
        // already been written durably is the defect worth preventing twice.
        let allowed = match command {
            AstraIpcCommand::Continue => current.can_continue,
            AstraIpcCommand::Cancel => current.can_cancel,
        };
        if !allowed {
            return Err(format!(
                "cette étape n'accepte pas cette action ({}).",
                current.message
            ));
        }

        send(&mut session.commands, &command).await?;
        awaited(&mut session.status).await
    }
}

/// Rejects what the companion would only reject later, and less legibly.
fn validated(input: RotationInput) -> Result<RotationInput, String> {
    let input = RotationInput {
        vault_path: input.vault_path.trim().to_string(),
        heliosd_url: input.heliosd_url.trim().to_string(),
        operation_id: input.operation_id.trim().to_string(),
        output_path: input.output_path.trim().to_string(),
    };
    if input.vault_path.is_empty() {
        return Err("indiquer le coffre d'autorité".into());
    }
    if input.output_path.is_empty() {
        return Err("indiquer où écrire la transition signée".into());
    }
    if !input.heliosd_url.starts_with("http://") && !input.heliosd_url.starts_with("https://") {
        return Err("l'URL de la gateway doit commencer par http:// ou https://".into());
    }
    if input.operation_id.len() != OPERATION_ID_HEX
        || !input
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "l'identifiant d'opération doit compter {OPERATION_ID_HEX} caractères hexadécimaux"
        ));
    }
    Ok(input)
}

/// 256 bits from the one entry point this repository draws randomness through.
fn session_token() -> Result<Zeroizing<String>, String> {
    let bytes = aether::random::secret_bytes::<32>()
        .map_err(|error| format!("tirage du jeton de session : {error}"))?;
    Ok(Zeroizing::new(
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    ))
}

/// Starts the companion on the fixed invocation this ceremony needs.
fn launch(
    input: &RotationInput,
    address: SocketAddr,
    token: &Zeroizing<String>,
) -> Result<(), String> {
    crate::companion::launch(&CompanionInvocation {
        program: "astra-signer",
        arguments: vec![
            "--vault".into(),
            input.vault_path.clone(),
            "orion".into(),
            "--heliosd-url".into(),
            input.heliosd_url.clone(),
            "--operation-id".into(),
            input.operation_id.clone(),
            "--out".into(),
            input.output_path.clone(),
            "--ipc-address".into(),
            address.to_string(),
            "--ipc-token".into(),
            token.to_string(),
        ],
    })
}

/// Accepts local connections until one presents the session token.
///
/// A loop rather than a single accept: anything on the machine may reach a
/// loopback port, and letting the first connection consume the listener would
/// let any local process keep the real companion from ever being heard.
async fn authenticated_companion(
    listener: &TcpListener,
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
        let hello: Option<AstraIpcHello> = match receive(&mut reader).await {
            Ok(hello) => hello,
            Err(_) => continue,
        };
        let Some(hello) = hello else { continue };
        if hello.protocol_version == PROTOCOL_VERSION && same_secret(&hello.token, token) {
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

/// Republishes every state the companion sends, until it stops sending.
///
/// A companion that dies mid-ceremony is reported as a failure rather than
/// left on its last hopeful phase: the operator would otherwise wait on a
/// «signature en cours» that nothing is performing.
async fn pump(mut reader: BufReader<OwnedReadHalf>, publisher: watch::Sender<AstraCaTlsStatus>) {
    loop {
        match receive::<AstraCaTlsStatus>(&mut reader).await {
            Ok(Some(status)) => {
                let terminal = matches!(
                    status.phase,
                    AstraCaTlsPhase::Failed
                        | AstraCaTlsPhase::Cancelled
                        | AstraCaTlsPhase::Promoted
                        | AstraCaTlsPhase::Deposited
                );
                if publisher.send(status).is_err() || terminal {
                    return;
                }
            }
            Ok(None) => {
                let last = publisher.borrow().phase;
                if !last.is_actionable_or_terminal() {
                    let _ = publisher.send(AstraCaTlsStatus::new(
                        AstraCaTlsPhase::Failed,
                        "Le compagnon Astra s'est arrêté avant la fin de la cérémonie.",
                    ));
                }
                return;
            }
            Err(error) => {
                let _ = publisher.send(AstraCaTlsStatus::new(AstraCaTlsPhase::Failed, error));
                return;
            }
        }
    }
}

/// Waits for the next state the companion publishes.
async fn awaited(
    status: &mut watch::Receiver<AstraCaTlsStatus>,
) -> Result<AstraCaTlsStatus, String> {
    tokio::time::timeout(STEP_TIMEOUT, status.changed())
        .await
        .map_err(|_| "le compagnon Astra ne répond plus".to_string())?
        .map_err(|_| "le compagnon Astra s'est arrêté".to_string())?;
    Ok(status.borrow_and_update().clone())
}

/// Writes one newline-delimited JSON frame.
async fn send<T: serde::Serialize>(writer: &mut OwnedWriteHalf, value: &T) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("encodage du message : {error}"))?;
    if bytes.len() > MAX_FRAME_BYTES {
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
/// `Ok(None)` is a closed channel, which is how a finished companion looks.
async fn receive<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>,
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
        if frame.len() + taken > MAX_FRAME_BYTES {
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

    fn input() -> RotationInput {
        RotationInput {
            vault_path: "/tmp/authority-vault.json".into(),
            heliosd_url: "http://100.64.0.1:8080".into(),
            operation_id: "0f".repeat(16),
            output_path: "/tmp/ca-tls-transition.json".into(),
        }
    }

    #[test]
    fn an_operation_identifier_that_is_not_sixteen_bytes_is_refused() {
        let mut short = input();
        short.operation_id = "0f".into();
        assert!(validated(short).is_err());

        let mut wrong = input();
        wrong.operation_id = "z".repeat(32);
        assert!(validated(wrong).is_err());

        assert!(validated(input()).is_ok());
    }

    /// The companion composes its own URL from this value; a bare host would
    /// make it compose one against a scheme nobody chose.
    #[test]
    fn the_gateway_url_must_carry_its_scheme() {
        let mut bare = input();
        bare.heliosd_url = "100.64.0.1:8080".into();
        assert!(validated(bare).is_err());
    }

    #[test]
    fn a_session_token_answers_only_to_itself() {
        let token = session_token().expect("token");
        assert_eq!(token.len(), 64);
        assert!(same_secret(&token, &token));
        assert!(!same_secret(&token[..63], &token));
        assert!(!same_secret(&"0".repeat(64), &token));
    }

    /// The launcher is handed one fixed program and the arguments the
    /// ceremony needs — never a value the WebView could turn into another
    /// command.
    #[test]
    fn the_companion_is_invoked_under_its_own_subcommand() {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 57_121));
        let token = Zeroizing::new("ab".repeat(32));
        let invocation = CompanionInvocation {
            program: "astra-signer",
            arguments: vec![
                "--vault".into(),
                input().vault_path,
                "orion".into(),
                "--heliosd-url".into(),
                input().heliosd_url,
                "--operation-id".into(),
                input().operation_id,
                "--out".into(),
                input().output_path,
                "--ipc-address".into(),
                address.to_string(),
                "--ipc-token".into(),
                token.to_string(),
            ],
        };
        assert!(invocation.command_line().contains("orion --heliosd-url"));
        assert!(invocation.command_line().contains("127.0.0.1:57121"));
    }

    /// A frame longer than the shared cap is refused rather than buffered.
    #[tokio::test]
    async fn an_unbounded_frame_is_refused() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("listen");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            let flood = vec![b'x'; MAX_FRAME_BYTES + 64];
            let _ = stream.write_all(&flood).await;
        });
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, _writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let refusal = receive::<AstraIpcHello>(&mut reader)
            .await
            .expect_err("an unbounded frame must be refused");
        assert!(refusal.contains("trop volumineux"));
    }

    /// One frame in, one frame out, and a closed channel is not an error.
    #[tokio::test]
    async fn frames_round_trip_and_a_closed_channel_ends_the_read() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("listen");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            let (_reader, mut writer) = stream.into_split();
            send(&mut writer, &AstraIpcCommand::Continue)
                .await
                .expect("send");
        });
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, _writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(
            receive::<AstraIpcCommand>(&mut reader).await.expect("read"),
            Some(AstraIpcCommand::Continue)
        );
        assert_eq!(
            receive::<AstraIpcCommand>(&mut reader)
                .await
                .expect("close"),
            None
        );
    }

    /// A connection that does not know the token never becomes the session.
    #[tokio::test]
    async fn an_impostor_does_not_take_the_channel_from_the_companion() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("listen");
        let address = listener.local_addr().expect("address");
        let token = Zeroizing::new("cd".repeat(32));
        let announced = token.clone();
        tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("impostor");
            let (_reader, mut writer) = stream.into_split();
            send(
                &mut writer,
                &AstraIpcHello {
                    protocol_version: PROTOCOL_VERSION,
                    token: "00".repeat(32),
                },
            )
            .await
            .expect("impostor hello");

            let stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("companion");
            let (_reader, mut writer) = stream.into_split();
            send(
                &mut writer,
                &AstraIpcHello {
                    protocol_version: PROTOCOL_VERSION,
                    token: announced.to_string(),
                },
            )
            .await
            .expect("companion hello");
            // Held open: dropping the companion's write half here would let
            // the accepted session close before the assertion below reads it.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let accepted = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            authenticated_companion(&listener, &token),
        )
        .await
        .expect("the companion must still be heard after the impostor")
        .expect("authenticated");
        drop(accepted);
    }
}
