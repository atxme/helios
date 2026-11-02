//! The console connector: every opening and every write of this binary goes
//! to the door (spec §5.5, §5.9).
//!
//! # An opening needs the service
//!
//! A campaign lives in the running service's memory, signed by a key only
//! the service reads. Without the service there is nothing to open, so an
//! opening is sent over the door socket or refused, and nothing is left on
//! disk for a later start to pick up.
//!
//! # A write follows the volume lock, never the socket
//!
//! `pin-ca-tls`, `issuer install` and `gateway-identity publish` change the
//! registry. Whoever holds [`VolumeLock`] is its only writer: a running
//! service holds it for its whole life. So a write first tries the lock.
//! Obtained, no service runs, and the write happens here, on the registry
//! read from disk, through the same [`astra::door::write`] functions the
//! door calls, with the lock held until it is done — the path
//! `scripts/deploy.sh` takes with the service stopped. Held, the service
//! runs, and the write goes through its door. Whether a connection happens
//! to succeed decides nothing: a stale socket beside a free lock is a service
//! that died, and the write is local.

use std::path::Path;

use anyhow::{Context, Result};
use astra::door::local::{DoorRefused, DOOR_ROUTE, MAX_DOOR_BODY_BYTES};
use astra::door::{DoorOutcome, DoorRequest, Opening, OpeningText, VolumeLock, DOOR_SOCKET_FILE};
use astra::registry::AstraRegistry;
use axum::body::Body;
use axum::http::{header, Request};
use hyper_util::rt::TokioIo;

use crate::REGISTRY_FILE;

/// The refusal of an opening while no service answers.
const SERVICE_STOPPED: &str = "le service Astra ne tourne pas : rien n'a été ouvert";

/// The refusal of a write whose volume is held by a process that does not
/// answer at the door.
const VOLUME_HELD: &str =
    "un autre processus tient le volume, et le service Astra n'y répond pas : rien n'a été écrit";

/// Why a call to the door produced no outcome.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CallError {
    /// No socket, or a socket nobody listens on.
    #[error("la porte du service Astra ne répond pas : {0}")]
    Unreachable(std::io::Error),
    /// The door's own sentence, whole.
    #[error("{0}")]
    Refused(String),
    /// The exchange broke after it began: what was done, if anything, is in
    /// the service's log.
    #[error("{0:#}")]
    Broken(anyhow::Error),
}

/// Sends one request to the running service's door and waits for its answer.
pub(crate) fn call(state_dir: &Path, request: &DoorRequest) -> Result<DoorOutcome, CallError> {
    let body = serde_json::to_vec(request)
        .context("encoding the request")
        .map_err(CallError::Broken)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for the door")
        .map_err(CallError::Broken)?;
    runtime.block_on(exchange(&state_dir.join(DOOR_SOCKET_FILE), body))
}

async fn exchange(socket: &Path, body: Vec<u8>) -> Result<DoorOutcome, CallError> {
    let stream = match tokio::net::UnixStream::connect(socket).await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(CallError::Unreachable(error));
        }
        Err(error) => {
            return Err(CallError::Broken(
                anyhow::Error::new(error).context(format!("joindre {}", socket.display())),
            ))
        }
    };
    let broken = |error: anyhow::Error| {
        CallError::Broken(error.context(
            "l'échange avec la porte du service Astra s'est interrompu : ce qui a été fait, s'il \
             y a lieu, est dans le journal du service",
        ))
    };
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| broken(error.into()))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "door connection ended");
        }
    });
    let request = Request::post(DOOR_ROUTE)
        .header(header::HOST, "astra")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|error| broken(error.into()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| broken(error.into()))?;
    let status = response.status();
    let answer = axum::body::to_bytes(Body::new(response.into_body()), MAX_DOOR_BODY_BYTES)
        .await
        .map_err(|error| broken(error.into()))?;
    if status.is_success() {
        serde_json::from_slice(&answer).map_err(|error| broken(error.into()))
    } else {
        let refused: DoorRefused =
            serde_json::from_slice(&answer).map_err(|error| broken(error.into()))?;
        Err(CallError::Refused(refused.refusal))
    }
}

/// An opening: through the running service, or refused.
pub(crate) fn open(state_dir: &Path, request: DoorRequest) -> Result<DoorOutcome> {
    match call(state_dir, &request) {
        Ok(outcome) => Ok(outcome),
        Err(CallError::Unreachable(_)) => anyhow::bail!(SERVICE_STOPPED),
        Err(error) => Err(error.into()),
    }
}

/// A write: here under the volume lock when no service holds it, through the
/// service's door otherwise.
///
/// `local` is the same write on the registry read from disk; it runs only
/// when the lock was obtained, and the lock is held until it returns.
pub(crate) fn write(
    state_dir: &Path,
    request: DoorRequest,
    local: impl FnOnce(&mut AstraRegistry) -> Result<DoorOutcome>,
) -> Result<DoorOutcome> {
    let lock = VolumeLock::try_acquire(state_dir).with_context(|| {
        format!(
            "locking {}",
            state_dir.join(astra::door::VOLUME_LOCK_FILE).display()
        )
    })?;
    match lock {
        Some(volume) => write_locally(state_dir, volume, local),
        None => match call(state_dir, &request) {
            Ok(outcome) => Ok(outcome),
            Err(CallError::Unreachable(_)) => anyhow::bail!(VOLUME_HELD),
            Err(error) => Err(error.into()),
        },
    }
}

/// The write with the service stopped: this process is the volume's writer
/// for as long as `_volume` lives.
fn write_locally(
    state_dir: &Path,
    _volume: VolumeLock,
    local: impl FnOnce(&mut AstraRegistry) -> Result<DoorOutcome>,
) -> Result<DoorOutcome> {
    let mut registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    local(&mut registry)
}

/// What the operator reads before the touch, as the door takes it.
pub(crate) fn opening_text(reason: &str, requested_by: &str, window_secs: u64) -> OpeningText {
    OpeningText {
        reason: reason.to_string(),
        requested_by: requested_by.to_string(),
        window_secs,
    }
}

/// The campaign an opening produced.
pub(crate) fn opened(outcome: DoorOutcome) -> Result<Opening> {
    match outcome {
        DoorOutcome::Opened(opening) => Ok(opening),
        other => Err(unexpected(&other)),
    }
}

/// An answer the door gives, but not to this request.
pub(crate) fn unexpected(outcome: &DoorOutcome) -> anyhow::Error {
    anyhow::anyhow!(
        "la porte du service Astra a répondu autre chose que ce qui était demandé : {outcome:?}"
    )
}
