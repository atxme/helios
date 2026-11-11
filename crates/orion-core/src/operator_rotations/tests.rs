use super::*;
use aether::certificates::encoding::{Fingerprint, WireGuardKey};
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
async fn no_answer_is_unreachable() {
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
    assert_eq!(domain.peers.len(), 1);
    assert_eq!(domain.peers[0].not_after, 1234);
}

/// A gateway older than the identity fields answers without them: the read
/// goes through with defaults, and a newer one's leaf expiries are kept.
#[tokio::test]
async fn domain_read_tolerates_the_gateway_fields() {
    let older = serde_json::json!({
        "ca_epoch": 1, "ca_pq_fingerprint": "ab".repeat(32), "client_tls_ca_epoch": 1,
        "peers": [],
    });
    let Reach::Ok(read) = answered(200, &older.to_string(), async |url| domain(url).await).await
    else {
        panic!("an older gateway's domain must still read");
    };
    assert_eq!(read.gateway_identity_epoch, 0);
    assert_eq!(read.gateway_tls_fingerprint, "");
    assert_eq!(read.gateway_pq_fingerprint, "");
    assert_eq!(read.gateway_tls_not_after, None);
    assert_eq!(read.gateway_pq_not_after, None);
    assert!(!read.gateway_transition_pending);
    assert!(!read.gateway_transition_published);
    assert_eq!(read.gateway_activation_at, None);
    assert_eq!(read.gateway_retire_active_at, None);
    assert_eq!(read.gateway_rollback_expires_at, None);
    assert_eq!(read.gateway_restart_due, None);

    let newer = serde_json::json!({
        "ca_epoch": 1, "ca_pq_fingerprint": "ab".repeat(32), "client_tls_ca_epoch": 1,
        "gateway_identity_epoch": 3,
        "gateway_tls_fingerprint": "cd".repeat(32),
        "gateway_pq_fingerprint": "ef".repeat(32),
        "gateway_tls_not_after": 900,
        "gateway_pq_not_after": 1000,
        "gateway_transition_pending": true,
        "gateway_transition_published": true,
        "gateway_activation_at": 950,
        "gateway_retire_active_at": 1100,
        "gateway_rollback_expires_at": 960,
        "gateway_restart_due": "retour arrière",
        "peers": [],
    });
    let Reach::Ok(read) = answered(200, &newer.to_string(), async |url| domain(url).await).await
    else {
        panic!("a newer gateway's domain must read");
    };
    assert_eq!(read.gateway_identity_epoch, 3);
    assert_eq!(read.gateway_tls_not_after, Some(900));
    assert_eq!(read.gateway_pq_not_after, Some(1000));
    assert!(read.gateway_transition_pending && read.gateway_transition_published);
    assert_eq!(read.gateway_activation_at, Some(950));
    assert_eq!(read.gateway_retire_active_at, Some(1100));
    assert_eq!(read.gateway_rollback_expires_at, Some(960));
    assert_eq!(read.gateway_restart_due.as_deref(), Some("retour arrière"));
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
        chain: None,
        ca_epoch: 1,
        ca_fingerprint: Fingerprint::of(b"a"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: None,
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
        revoked_peers: Vec::new(),
        served_credentials: None,
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

#[tokio::test]
async fn a_refusal_is_told_apart_from_a_gateway_that_does_not_answer() {
    // An older gateway without the route answers 404: it is up, and says no.
    let reach = answered(404, "", async |url| authority_status(url).await).await;
    assert_eq!(reach, Reach::Refused(404));
    let reach = answered(500, "", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Refused(500));
    // A redirect is not followed: the answer is the 302 itself.
    let reach = answered(302, "", async |url| domain(url).await).await;
    assert_eq!(reach, Reach::Refused(302));
    let value = serde_json::to_value(Reach::<u8>::Refused(404)).unwrap();
    assert_eq!(value, serde_json::json!({"state": "refused", "value": 404}));
}

#[tokio::test]
async fn an_authority_status_that_gains_a_field_still_reads() {
    let mut status = serde_json::to_value(OperatorAuthorityStatus {
        chain: None,
        ca_epoch: 4,
        ca_fingerprint: Fingerprint::of(b"a"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 2,
        ca_tls_fingerprint: None,
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: Some(Fingerprint::of(b"v")),
        credential_registry_epoch: Some(7),
        revoked_peers: Vec::new(),
        served_credentials: None,
    })
    .unwrap();
    status["a_field_a_later_astra_adds"] = serde_json::json!(true);
    let Reach::Ok(read) = answered(200, &status.to_string(), async |url| {
        authority_status(url).await
    })
    .await
    else {
        panic!("a field added later must not blind the screen");
    };
    assert_eq!(read.ca_epoch, 4);
    assert_eq!(read.credential_registry_epoch, Some(7));
    assert_eq!(
        read.vault_copy_fingerprint,
        Some(Fingerprint::of(b"v").to_hex())
    );
}

#[tokio::test]
async fn a_pending_list_that_gains_a_field_still_reads() {
    let body = serde_json::json!({
        "operations": [{
            "operation_id": "00".repeat(16), "scope": "fleet_leafs", "reason": "r",
            "requested_by": "u", "target_count": 3, "required_credentials": 2,
            "campaign_fingerprint": "ab".repeat(32), "created_at": 1, "expires_at": 2,
            "a_field_a_later_gateway_adds": 1
        }],
        "and_another": true
    });
    let Reach::Ok(list) = answered(200, &body.to_string(), async |url| pending(url).await).await
    else {
        panic!("read");
    };
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].target_count, 3);
    assert_eq!(list[0].scope, "fleet_leafs");
}

#[tokio::test]
async fn revoked_peers_are_left_out_and_the_gateways_clock_is_kept() {
    let body = serde_json::json!({
        "now_unix": 1_000,
        "ca_epoch": 1, "ca_pq_fingerprint": "ab".repeat(32), "client_tls_ca_epoch": 1,
        "peers": [
            {"not_after": 10, "revoked": false},
            {"not_after": 5, "revoked": true},
            {"not_after": 20},
        ],
    });
    let Reach::Ok(read) = answered(200, &body.to_string(), async |url| domain(url).await).await
    else {
        panic!("read");
    };
    assert_eq!(read.now_unix, Some(1_000));
    let ends: Vec<u64> = read.peers.iter().map(|peer| peer.not_after).collect();
    assert_eq!(
        ends,
        vec![10, 20],
        "a revoked leaf is not a workstation to renew"
    );
}

#[tokio::test]
async fn status_read_tolerates_the_new_fields() {
    let base = serde_json::to_value(OperatorAuthorityStatus {
        chain: None,
        ca_epoch: 4,
        ca_fingerprint: Fingerprint::of(b"a"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 2,
        ca_tls_fingerprint: None,
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: Some(7),
        revoked_peers: Vec::new(),
        served_credentials: None,
    })
    .unwrap();

    // An Astra that names a revoked peer and serves its document.
    let key = WireGuardKey::from_bytes([3; 32]).to_base64();
    let mut named = base.clone();
    named["revoked_peers"] = serde_json::json!([key]);
    named["served_credentials"] = serde_json::json!({
        "credential_registry_epoch": 7,
        "bindings": [{"credential_id": [1, 2, 3]}],
    });
    let Reach::Ok(read) = answered(200, &named.to_string(), async |url| {
        authority_status(url).await
    })
    .await
    else {
        panic!("the new fields must not blind the screen");
    };
    assert_eq!(read.revoked_peers, vec![key]);
    let document = read.served_credentials.expect("the served document");
    assert_eq!(document["credential_registry_epoch"], 7);

    // An older Astra, without the fields, reads as no revoked peer and no document.
    let Reach::Ok(older) = answered(200, &base.to_string(), async |url| {
        authority_status(url).await
    })
    .await
    else {
        panic!("an older Astra must still read");
    };
    assert!(older.revoked_peers.is_empty());
    assert_eq!(older.served_credentials, None);
}

#[tokio::test]
async fn the_peer_certificates_keep_the_revoked_peers_and_the_gateways_clock() {
    let body = serde_json::json!({
        "now_unix": 5_000,
        "ca_epoch": 1,
        "peers": [
            {"name": "PC_FIXE", "wg_public_key": "AAA", "generation": 2,
             "not_before": 100, "not_after": 900, "revoked": false,
             "pending": null, "next_generation": null},
            {"name": "PORTABLE", "wg_public_key": "BBB", "generation": 1,
             "not_before": 100, "not_after": 800, "revoked": false,
             "pending": {"generation": 3, "state": "leased", "stage_expires_at": 9},
             "next_generation": null},
            {"name": "PC_BUREAU", "wg_public_key": "CCC", "generation": 4,
             "not_before": 10, "not_after": 700, "revoked": true,
             "pending": null, "next_generation": 5}
        ]
    });
    let Reach::Ok(read) = answered(200, &body.to_string(), async |url| {
        peer_certificates(url).await
    })
    .await
    else {
        panic!("the domain view must read");
    };
    assert_eq!(read.now_unix, Some(5_000));
    let names: Vec<_> = read.peers.iter().map(|peer| peer.name.as_str()).collect();
    assert_eq!(names, ["PC_FIXE", "PORTABLE", "PC_BUREAU"]);
    assert!(read.peers[2].revoked, "a revoked peer stays listed");
    assert_eq!(read.peers[2].wg_public_key, "CCC");
    assert_eq!(read.peers[2].not_after, 700);
    let renewing: Vec<_> = read.peers.iter().map(|peer| peer.renewing).collect();
    assert_eq!(renewing, [false, true, true]);
}
