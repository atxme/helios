//! The console connector: the door, served on a Unix socket of the volume.
//!
//! `astra run` binds [`super::DOOR_SOCKET_FILE`] in its state directory and
//! serves one route there, `POST` [`DOOR_ROUTE`], whose body is a
//! [`DoorRequest`] and whose answer is a [`DoorOutcome`] or a
//! [`DoorRefused`]. Nothing else is mounted: the socket is the door, and
//! only the door.
//!
//! # Who may connect
//!
//! The socket is `0600`, owned by the service's user: whoever can connect can
//! already write the volume the service owns, so the socket grants nothing
//! the filesystem had not. The kernel's peer credential gives the local user
//! the door logs ([`DoorConnector::Console`]); the body never names it.
//!
//! # A socket left behind
//!
//! A service killed hard leaves its socket on disk. The next one replaces it,
//! but only a socket: a regular file at that path is something an operator
//! put there, and it is refused rather than deleted — the same rule as the
//! gateway's local administration socket.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;

use super::{DoorConnector, DoorOutcome, DoorRequest};
use crate::service::AstraService;

/// The one route of the socket.
pub const DOOR_ROUTE: &str = "/door";

/// Largest body the socket reads, and largest answer the console reads.
///
/// A request is a few fields; the largest is an `issuer install`, whose
/// delegation weighs a few kilobytes. Anything above this is not a request.
pub const MAX_DOOR_BODY_BYTES: usize = 64 * 1024;

/// What the socket answers when the door, or the socket itself, refuses.
///
/// The sentence is the whole of it: the console is local, and prints it as
/// is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoorRefused {
    pub refusal: String,
}

/// Serves the door on `path` until the listener fails.
///
/// The socket is removed when this future is dropped, which is how
/// `astra run` stops: a clean stop leaves no socket behind it.
pub async fn serve(path: &Path, service: Arc<AstraService>) -> anyhow::Result<()> {
    let listener = bind(path)?;
    let _socket = RemoveOnDrop(path.to_path_buf());
    tracing::info!(socket = %path.display(), "Astra's door listening for the local console");
    let router = router(service);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                // Transient (descriptor exhaustion): keep serving.
                tracing::warn!(%error, "the door socket could not accept a connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let uid = match stream.peer_cred() {
            Ok(credentials) => credentials.uid(),
            Err(error) => {
                tracing::warn!(%error, "door connection refused: unreadable peer credentials");
                continue;
            }
        };
        let connection = TowerToHyperService::new(
            router
                .clone()
                .layer(Extension(DoorConnector::Console { uid })),
        );
        tokio::spawn(async move {
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), connection)
                .await
            {
                tracing::debug!(%error, "door connection ended");
            }
        });
    }
}

fn router(service: Arc<AstraService>) -> Router {
    Router::new()
        .route(DOOR_ROUTE, post(door))
        .layer(DefaultBodyLimit::max(MAX_DOOR_BODY_BYTES))
        .with_state(service)
}

async fn door(
    State(service): State<Arc<AstraService>>,
    Extension(connector): Extension<DoorConnector>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return refused(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "cette requête dépasse {MAX_DOOR_BODY_BYTES} octets : ce n'est pas une \
                     action de la porte, et rien n'a été fait"
                ),
            );
        }
        Err(rejection) => {
            return refused(
                StatusCode::BAD_REQUEST,
                format!("cette requête n'a pas pu être lue ({rejection}) : rien n'a été fait"),
            );
        }
    };
    let request: DoorRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(connector = %connector, %error, "unreadable request at the door");
            return refused(
                StatusCode::BAD_REQUEST,
                format!(
                    "cette requête n'est pas une action de la porte ({error}) : rien n'a été fait"
                ),
            );
        }
    };
    match service.door(connector, request, now_unix()).await {
        Ok(outcome) => (StatusCode::OK, Json::<DoorOutcome>(outcome)).into_response(),
        Err(refusal) => refused(StatusCode::UNPROCESSABLE_ENTITY, refusal.to_string()),
    }
}

fn refused(status: StatusCode, refusal: String) -> Response {
    (status, Json(DoorRefused { refusal })).into_response()
}

/// Replaces only a stale socket, never another kind of file, and makes the
/// new one the service user's alone.
fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket {}", path.display()))?,
        Ok(_) => anyhow::bail!(
            "{} existe et n'est pas un socket : il n'est pas remplacé, et la porte n'est pas \
             ouverte",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {} to its owner", path.display()))?;
    Ok(listener)
}

/// The socket this process bound, removed when serving stops.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => tracing::info!(socket = %self.0.display(), "Astra's door closed"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                socket = %self.0.display(),
                %error,
                "the door socket could not be removed; the next start replaces it"
            ),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use super::*;

    #[tokio::test]
    async fn a_stale_socket_is_replaced_but_a_regular_file_is_not() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(super::super::DOOR_SOCKET_FILE);
        drop(std::os::unix::net::UnixListener::bind(&path).expect("stale socket"));
        assert!(path.exists(), "a dropped listener leaves its socket");
        let listener = bind(&path).expect("a stale socket is replaced");
        drop(listener);

        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, b"operator notes").expect("regular file");
        let refusal = bind(&file).expect_err("a regular file is refused");
        assert!(
            refusal.to_string().contains("n'est pas un socket"),
            "{refusal}"
        );
        assert_eq!(
            std::fs::read(&file).expect("still there"),
            b"operator notes",
            "the file is left as it was"
        );
    }

    #[tokio::test]
    async fn the_socket_is_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(super::super::DOOR_SOCKET_FILE);
        let _listener = bind(&path).expect("bound");
        let mode = std::fs::metadata(&path)
            .expect("socket")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// One request over the socket, raw, the way any client would send it.
    fn exchange(path: &Path, body: &[u8]) -> (u16, DoorRefused) {
        let mut stream = std::os::unix::net::UnixStream::connect(path).expect("connect");
        write!(
            stream,
            "POST {DOOR_ROUTE} HTTP/1.1\r\nHost: astra\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("head");
        // The service may answer before the body is all sent, and close.
        let _ = stream.write_all(body);
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).expect("answer");
        let answer = String::from_utf8(answer).expect("utf-8");
        let status = answer
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status");
        let (_, body) = answer.split_once("\r\n\r\n").expect("body");
        (status, serde_json::from_str(body).expect("a refusal"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oversized_or_unreadable_body_is_refused_with_a_sentence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service = super::super::tests::fixture(dir.path());
        let path = dir.path().join(super::super::DOOR_SOCKET_FILE);
        let server = tokio::spawn({
            let path = path.clone();
            async move { serve(&path, service).await }
        });
        while std::os::unix::net::UnixStream::connect(&path).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let oversized = vec![b' '; MAX_DOOR_BODY_BYTES + 1];
        let socket = path.clone();
        let (status, refused) = tokio::task::spawn_blocking(move || exchange(&socket, &oversized))
            .await
            .expect("exchange");
        assert_eq!(status, 413);
        assert!(refused.refusal.contains("rien n'a été fait"), "{refused:?}");

        let socket = path.clone();
        let (status, refused) = tokio::task::spawn_blocking(move || {
            exchange(&socket, br#"{"action":"open_everything"}"#)
        })
        .await
        .expect("exchange");
        assert_eq!(status, 400);
        assert!(
            refused
                .refusal
                .starts_with("cette requête n'est pas une action de la porte"),
            "{refused:?}"
        );

        // A refusal of the door itself is its sentence, whole.
        let socket = path.clone();
        let (status, refused) = tokio::task::spawn_blocking(move || {
            exchange(&socket, br#"{"action":"chain_abandon"}"#)
        })
        .await
        .expect("exchange");
        assert_eq!(status, 422);
        assert_eq!(
            refused.refusal,
            super::super::DoorRefusal::NoChain.to_string()
        );

        server.abort();
        let _ = server.await;
        assert!(!path.exists(), "a stopped door removes its socket");
    }
}
