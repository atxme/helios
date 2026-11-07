use super::*;
use aether::certificates::encoding::Fingerprint;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Serves one canned answer per connection and records each request line.
async fn serve(
    answers: Vec<(u16, Vec<u8>)>,
    lines: Arc<Mutex<Vec<String>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for (status, body) in answers {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = vec![0u8; 4096];
            let read = stream.read(&mut request).await.expect("read request");
            let line = String::from_utf8_lossy(&request[..read])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string();
            lines.lock().unwrap().push(line);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.expect("head");
            stream.write_all(&body).await.expect("body");
        }
    });
    (format!("http://{address}"), task)
}

async fn answered<T>(status: u16, body: &str, ask: impl AsyncFnOnce(&str) -> Reach<T>) -> Reach<T> {
    let (url, server) = serve(vec![(status, body.as_bytes().to_vec())], Arc::default()).await;
    let reach = ask(&url).await;
    server.await.unwrap();
    reach
}

#[tokio::test]
async fn http_403_is_not_admin() {
    let reach = answered(403, "{}", async |url| authority_status(url).await).await;
    assert_eq!(reach, Reach::NotAdmin);
}

#[tokio::test]
async fn http_503_is_astra_unavailable() {
    let reach = answered(503, "", async |url| pending(url).await).await;
    assert!(matches!(reach, Reach::AstraUnavailable));
}

#[tokio::test]
async fn http_429_is_throttled() {
    let reach = answered(429, "", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Throttled);
}

#[tokio::test]
async fn other_statuses_and_no_answer_are_unreachable() {
    let reach = answered(500, "", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Unreachable);
    // A redirect is not followed: the answer is the 302 itself.
    let reach = answered(302, "", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Unreachable);
    assert_eq!(
        domain("http://127.0.0.1:9").await,
        Reach::<GatewayDomainRead>::Unreachable
    );
}

#[tokio::test]
async fn an_unreadable_or_oversized_answer_is_unreachable() {
    let reach = answered(200, "not json", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Unreachable);
    let big = format!(
        "{{\"operations\":[],\"pad\":\"{}\"}}",
        "x".repeat(MAX_ANSWER_BYTES)
    );
    let reach = answered(200, &big, async |url| pending(url).await).await;
    assert!(matches!(reach, Reach::Unreachable));
}

#[tokio::test]
async fn unknown_fields_of_the_domain_view_are_ignored() {
    let body = serde_json::json!({
        "ca_epoch": 3,
        "ca_pq_fingerprint": "ab".repeat(32),
        "client_tls_ca_epoch": 2,
        "ca_retire_active_at": 99,
        "next_ca_fingerprint": "cd".repeat(32),
        "client_tls_ca_transition_pending": true,
        "a_field_a_later_gateway_adds": {"x": 1},
        "peers": [{"name": "laptop", "wg_public_key": "k", "not_after": 1234, "revoked": false}],
    });
    let reach = answered(200, &body.to_string(), async |url| domain(url).await).await;
    let Reach::Ok(domain) = reach else {
        panic!("the read must go through: {reach:?}");
    };
    assert_eq!(domain.ca_epoch, 3);
    assert_eq!(domain.ca_tls_epoch, 2);
    assert_eq!(domain.ca_fingerprint, "ab".repeat(32));
    assert_eq!(domain.ca_retire_active_at, Some(99));
    assert!(domain.client_tls_ca_transition_pending);
    assert!(!domain.ca_transition_pending, "defaulted when absent");
    assert_eq!(domain.peers, vec![PeerExpiry { not_after: 1234 }]);
}

#[tokio::test]
async fn the_domain_read_shows_neither_a_peer_name_nor_a_peer_key() {
    let body = serde_json::json!({
        "ca_epoch": 1, "ca_pq_fingerprint": "ab".repeat(32), "client_tls_ca_epoch": 1,
        "peers": [{"name": "laptop-of-alice", "wg_public_key": "SECRETISH", "not_after": 5}],
    });
    let Reach::Ok(domain) = answered(200, &body.to_string(), async |url| domain(url).await).await
    else {
        panic!("read");
    };
    let shown = serde_json::to_string(&domain).unwrap();
    assert!(!shown.contains("laptop-of-alice") && !shown.contains("SECRETISH"));
}

#[tokio::test]
async fn the_authority_status_keeps_none_distinct_from_zero() {
    let status = OperatorAuthorityStatus {
        ca_epoch: 1,
        ca_fingerprint: Fingerprint::of(b"a"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: None,
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
    };
    let body = serde_json::to_string(&status).unwrap();
    let Reach::Ok(read) = answered(200, &body, async |url| authority_status(url).await).await
    else {
        panic!("read");
    };
    assert_eq!(read.credential_registry_epoch, None);
}

#[tokio::test]
async fn the_routes_are_the_gateways_own_and_a_slash_does_not_double() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let (url, server) = serve(
        vec![(503, vec![]), (503, vec![]), (503, vec![])],
        Arc::clone(&lines),
    )
    .await;
    let url = format!("{url}/");
    let _ = pending(&url).await;
    let _ = authority_status(&url).await;
    let _ = domain(&url).await;
    server.await.unwrap();
    let lines = lines.lock().unwrap().clone();
    assert_eq!(
        lines,
        vec![
            "GET /api/certificates/operator/pending HTTP/1.1",
            "GET /api/certificates/operator/status HTTP/1.1",
            "GET /api/certificates HTTP/1.1",
        ]
    );
}
