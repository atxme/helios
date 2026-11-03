//! The tunnel's connector, through Astra's real private router.
//!
//! The production listener is the pinned Astra–gateway mTLS channel; these
//! loopback tests exercise the router, its extractor and the handler behind
//! it, not that TLS boundary (`private_channel.rs` covers it).

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use astra_channel::{OperatorOpenAction, OperatorOpenRequest, RelayedOperatorOpen};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

struct PrivateListener {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PrivateListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Astra's private router, the one `astra run` serves the gateway.
async fn listen(service: Arc<AstraService>) -> PrivateListener {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let router = crate::renewal::router::router(service);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    PrivateListener { address, task }
}

/// One `POST` to the opening route, raw, as the gateway's client sends it.
async fn post_open(listener: &PrivateListener, body: &[u8]) -> (u16, Vec<u8>) {
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(listener.address).await.expect("connect");
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            astra_channel::OPERATOR_OPEN_ROUTE,
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("head");
        stream.write_all(body).await.expect("body");
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.expect("answer");
        answer
    })
    .await
    .expect("the private route answers");
    let split = answer
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("headers");
    let status = String::from_utf8_lossy(&answer[..split])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    (status, answer[split + 4..].to_vec())
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn administrator() -> OperatorIdentity {
    OperatorIdentity::WireGuard {
        public_key: tunnel_key(),
    }
}

fn relayed_fleet_opening() -> Vec<u8> {
    serde_json::to_vec(&RelayedOperatorOpen {
        operator: administrator(),
        request: OperatorOpenRequest {
            action: OperatorOpenAction::FleetLeafs,
            reason: "quarterly rotation".into(),
            requested_by: "alice".into(),
            window_secs: 300,
        },
    })
    .expect("relayed opening")
}

/// A coarse refusal: the class, and not a word about why.
fn coarse(body: &[u8], class: ServiceError) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).ok()
        == Some(serde_json::json!({ "error": class.to_string() }))
}

#[tokio::test]
async fn a_tunnel_open_lands_in_pending() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    // `OperatorOpened` refuses unknown fields: the console-only facts of an
    // opening (its URL, its subject) are not in this answer.
    let opened: OperatorOpened = serde_json::from_slice(&body).expect("the tunnel's answer");
    assert_eq!(opened.scope, CampaignScope::FleetLeafs);
    assert_eq!(opened.target_count, PEERS.len());

    let pending = service.signing.lock().await.pending(wall_clock());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, opened.operation_id);
    assert_eq!(
        pending[0].requested_by,
        format!("alice — pair wireguard:{}", tunnel_key())
    );
}

/// The tunnel's enum has no console action, so the body is refused before
/// the door is reached — and the refusal names neither the action nor the
/// ones that exist.
#[tokio::test]
async fn a_tunnel_open_of_a_console_action_is_refused_coarsely() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let body = serde_json::json!({
        "operator": administrator(),
        "request": {
            "action": "chain_open",
            "reason": "quarterly rotation",
            "requested_by": "alice",
        },
    });
    let (status, answer) = post_open(&listener, body.to_string().as_bytes()).await;
    assert_eq!(status, 400);
    assert!(
        coarse(&answer, ServiceError::Protocol),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(service
        .signing
        .lock()
        .await
        .pending(wall_clock())
        .is_empty());
    assert!(!plan_path(dir.path()).exists());
}

/// A refusal at the door crosses back as its class; the sentence that says
/// which campaign is already open stays in the service log.
#[tokio::test]
async fn a_refused_tunnel_open_answers_its_class_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (first, _) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(first, 200);
    let (status, answer) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(status, 403);
    assert!(
        coarse(&answer, ServiceError::Refused),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(service.signing.lock().await.pending(wall_clock()).len(), 1);
}
