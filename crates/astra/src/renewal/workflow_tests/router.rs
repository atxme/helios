//! Real HTTP coverage for the private renewal router after TLS termination.
//!
//! The production listener is the pinned Astra–gateway mTLS channel. These
//! loopback tests exercise Axum's routing, extractors, limits and handlers;
//! they do not claim to test that TLS boundary.

use super::*;
use aether::certificates::{
    capability::{CapabilityRequirement, CapabilityScope},
    encoding::WireGuardKey,
    transport::{AuthenticatedTrustUpdateRequest, TrustUpdateRequest},
    CERTIFICATE_PROTOCOL_VERSION,
};
use astra_channel::{
    RelayedOperationQuery, RelayedRotationRequest, RelayedTrustUpdatePreparation,
    ROTATION_REQUEST_PATH, TRUST_UPDATE_PREPARE_PATH,
};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct HttpServer {
    address: SocketAddr,
    _task: ServerTask,
}

struct ServerTask(tokio::task::JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(fixture: &Fixture) -> HttpServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let app = super::super::router::router(fixture.service.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    HttpServer {
        address,
        _task: ServerTask(task),
    }
}

async fn http(server: &HttpServer, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("write request");
        stream.write_all(body).await.expect("write body");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.expect("read response");
        bytes
    })
    .await
    .expect("HTTP request timed out");
    let split = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("HTTP response headers");
    let status = String::from_utf8_lossy(&response[..split])
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("HTTP status")
        .parse()
        .expect("numeric status");
    (status, response[split + 4..].to_vec())
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs()
}

async fn persist_readable_operation(fixture: &Fixture) -> Id16 {
    let now = wall_clock();
    let id = Id16::new([0x91; 16]).expect("operation ID");
    // This persisted read fixture deliberately makes no claim that its
    // placeholder request signatures are valid. The operation route only
    // reads a previously persisted operation and mints peer-bound read data.
    let mut request = fixture.request.clone();
    request.created_at = now.saturating_sub(1);
    request.expires_at = now + 3_600;
    let rp_id = fixture
        .service
        .registry
        .lock()
        .await
        .state()
        .webauthn_rp_id
        .clone();
    let approval_request = super::super::approval::build_approval_request(
        &fixture.service,
        id,
        &request,
        &request.active_generation,
        domain(),
        gateway_key(),
        &rp_id,
        1,
        1,
        now,
    )
    .expect("signed approval request for persisted read fixture");
    let operation = crate::operations::Operation::awaiting_operator(
        id,
        client_key(),
        Box::new(request),
        Box::new(approval_request),
        now.saturating_sub(1),
    );
    {
        let mut operations = fixture.service.operations.lock().await;
        operations.open(operation, now).expect("open read fixture");
        operations.persist().expect("persist read fixture");
    }
    *fixture.service.operations.lock().await =
        crate::operations::OperationStore::load(&fixture.operations_path(), now)
            .expect("reload persisted read fixture");
    id
}

#[tokio::test]
async fn private_router_refuses_bad_typed_bodies_methods_ids_and_unknown_paths_without_mutation() {
    let fixture = fixture().await;
    let server = serve(&fixture).await;
    let before_operations = std::fs::read(fixture.operations_path()).expect("operations");
    let before_registry = std::fs::read(fixture.registry_path()).expect("registry");

    let (status, _) = http(&server, "POST", ROTATION_REQUEST_PATH, b"{").await;
    assert_eq!(status, 400, "malformed JSON is rejected by Json");

    let (status, _) = http(
        &server,
        "POST",
        ROTATION_REQUEST_PATH,
        br#"{"caller_wg_public_key":"not-a-wireguard-key","request":{}}"#,
    )
    .await;
    assert_eq!(status, 422, "invalid typed identity fails deserialization");

    let oversized = vec![b'x'; super::super::router::MAX_PRIVATE_BODY_BYTES + 1];
    let (status, _) = http(&server, "POST", ROTATION_REQUEST_PATH, &oversized).await;
    assert_eq!(status, 413, "body limit runs before deserialization");

    let (status, _) = http(&server, "GET", ROTATION_REQUEST_PATH, b"").await;
    assert_eq!(status, 405, "request route is POST only");

    let valid_query = serde_json::to_vec(&RelayedOperationQuery {
        caller_wg_public_key: client_key(),
    })
    .expect("operation query");
    let (status, _) = http(
        &server,
        "POST",
        "/internal/v1/client-rotation/operations/not-hex",
        &valid_query,
    )
    .await;
    assert_eq!(status, 400, "malformed operation ID is a protocol refusal");

    let (status, _) = http(&server, "POST", "/unserved", b"{}").await;
    assert_eq!(status, 404, "unknown private paths reach the fallback");

    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("operations"),
        before_operations
    );
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry"),
        before_registry
    );
    assert!(fixture.service.operations.lock().await.is_empty());
}

#[tokio::test]
async fn operation_route_returns_persisted_operation_and_refreshes_bound_capabilities() {
    let fixture = fixture().await;
    let id = persist_readable_operation(&fixture).await;
    let server = serve(&fixture).await;
    let query = serde_json::to_vec(&RelayedOperationQuery {
        caller_wg_public_key: client_key(),
    })
    .expect("query JSON");
    let (status, body) = http(
        &server,
        "POST",
        &format!("/internal/v1/client-rotation/operations/{}", id.to_hex()),
        &query,
    )
    .await;
    assert_eq!(status, 200);
    let view: ClientRenewalOperationView = serde_json::from_slice(&body).expect("operation view");
    assert_eq!(view.operation_id, id);
    assert_eq!(view.state, ClientRenewalOperationState::AwaitingOperator);
    assert!(
        view.signer_request_token.is_some(),
        "read capability is returned"
    );
    assert!(
        view.signer_result_token.is_some(),
        "submit capability is returned"
    );

    let (manifest, operation_expires_at) = {
        let operations = fixture.service.operations.lock().await;
        let operation = operations
            .get(&id, &client_key(), wall_clock())
            .expect("reloaded operation");
        (operation.manifest_fingerprint(), operation.expires_at)
    };
    for (scope, token) in [
        (
            CapabilityScope::SignerRequestRead,
            view.signer_request_token
                .as_deref()
                .expect("read capability"),
        ),
        (
            CapabilityScope::SignerResultSubmit,
            view.signer_result_token
                .as_deref()
                .expect("submit capability"),
        ),
    ] {
        let requirement = CapabilityRequirement {
            scope,
            operation_id: &id,
            operation_manifest_fingerprint: &manifest,
            encrypted_vault_fingerprint: None,
            operation_expires_at,
        };
        fixture
            .service
            .capabilities
            .lock()
            .await
            .authenticate(token, &requirement, wall_clock())
            .expect("capability is bound to its route, operation and manifest");
    }

    let before_journal = std::fs::read(fixture.operations_path()).expect("journal before refusal");
    let before_registry = std::fs::read(fixture.registry_path()).expect("registry before refusal");
    let before_operation = {
        let operations = fixture.service.operations.lock().await;
        serde_json::to_vec(
            operations
                .get(&id, &client_key(), wall_clock())
                .expect("operation before refusal"),
        )
        .expect("serialized operation")
    };

    let wrong_caller = serde_json::to_vec(&RelayedOperationQuery {
        caller_wg_public_key: gateway_key(),
    })
    .expect("wrong caller JSON");
    let (wrong_status, _) = http(
        &server,
        "POST",
        &format!("/internal/v1/client-rotation/operations/{}", id.to_hex()),
        &wrong_caller,
    )
    .await;
    assert_eq!(
        wrong_status, 403,
        "another caller receives a coarse refusal"
    );
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("journal after refusal"),
        before_journal
    );
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry after refusal"),
        before_registry
    );
    let after_operation = {
        let operations = fixture.service.operations.lock().await;
        serde_json::to_vec(
            operations
                .get(&id, &client_key(), wall_clock())
                .expect("operation after refusal"),
        )
        .expect("serialized operation")
    };
    assert_eq!(after_operation, before_operation);
}

#[tokio::test]
async fn unknown_and_expired_operations_have_the_same_coarse_refusal_without_mutation() {
    let fixture = fixture().await;
    let now = wall_clock().saturating_sub(120);
    let id = Id16::new([0x92; 16]).expect("expired operation ID");
    let expired_peer = WireGuardKey::from_bytes([0x94; 32]);
    let mut request = fixture.request.clone();
    request.client_wg_public_key = expired_peer;
    request.created_at = now.saturating_sub(1);
    request.expires_at = now + 30;
    let rp_id = fixture
        .service
        .registry
        .lock()
        .await
        .state()
        .webauthn_rp_id
        .clone();
    let approval = super::super::approval::build_approval_request(
        &fixture.service,
        id,
        &request,
        &request.active_generation,
        domain(),
        gateway_key(),
        &rp_id,
        1,
        1,
        now,
    )
    .expect("approval request");
    let operation = crate::operations::Operation::awaiting_operator(
        id,
        expired_peer,
        Box::new(request),
        Box::new(approval),
        now.saturating_sub(1),
    );
    {
        let mut operations = fixture.service.operations.lock().await;
        operations
            .open(operation, now)
            .expect("open expiring operation");
        operations.persist().expect("persist expiring operation");
    }
    let server = serve(&fixture).await;
    let before_operations = std::fs::read(fixture.operations_path()).expect("operation journal");
    let before_registry = std::fs::read(fixture.registry_path()).expect("registry");
    let query = serde_json::to_vec(&RelayedOperationQuery {
        caller_wg_public_key: expired_peer,
    })
    .expect("query");
    let path = format!("/internal/v1/client-rotation/operations/{}", id.to_hex());
    let (expired_status, expired_body) = http(&server, "POST", &path, &query).await;
    assert_eq!(expired_status, 403, "expired record is refused");

    let unknown_path = format!(
        "/internal/v1/client-rotation/operations/{}",
        Id16::new([0x93; 16]).expect("unknown ID").to_hex()
    );
    let (unknown_status, unknown_body) = http(&server, "POST", &unknown_path, &query).await;
    assert_eq!(
        unknown_status, expired_status,
        "unknown and expired are indistinguishable"
    );
    assert_eq!(
        unknown_body, expired_body,
        "refusal response bodies are identical"
    );
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("operation journal"),
        before_operations
    );
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry"),
        before_registry
    );
}

#[tokio::test]
async fn renewal_request_route_rejects_a_typed_caller_mismatch_without_persisting() {
    let fixture = fixture().await;
    let server = serve(&fixture).await;
    let before_operations = std::fs::read(fixture.operations_path()).expect("operation journal");
    let before_registry = std::fs::read(fixture.registry_path()).expect("registry");
    let before_registry_state = serde_json::to_vec(fixture.service.registry.lock().await.state())
        .expect("serialized registry state");
    let mut request = fixture.request.clone();
    request.created_at = wall_clock().saturating_sub(1);
    request.expires_at = wall_clock() + 3_600;
    let relayed = RelayedRotationRequest {
        caller_wg_public_key: gateway_key(),
        request: Box::new(request),
    };
    let body = serde_json::to_vec(&relayed).expect("typed relayed request");
    let (status, _) = http(&server, "POST", ROTATION_REQUEST_PATH, &body).await;
    assert_eq!(
        status, 403,
        "caller mismatch is refused before request verification"
    );
    assert!(fixture.service.operations.lock().await.is_empty());
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("operation journal"),
        before_operations
    );
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry"),
        before_registry
    );
    assert_eq!(
        serde_json::to_vec(fixture.service.registry.lock().await.state())
            .expect("serialized registry state"),
        before_registry_state
    );
}

#[tokio::test]
async fn trust_update_prepare_route_handles_a_typed_caller_mismatch_without_mutation() {
    let fixture = fixture().await;
    let server = serve(&fixture).await;
    let peer = fixture.gateway.view.lock().await.clone();
    let relayed = RelayedTrustUpdatePreparation {
        // The request names the admitted client, while this resolved caller
        // deliberately names another identity. `prepare` refuses this cheap
        // ownership mismatch before transcribing peers or reading objects.
        caller_wg_public_key: gateway_key(),
        request: Box::new(AuthenticatedTrustUpdateRequest {
            request: TrustUpdateRequest {
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                request_id: Id16::new([0x96; 16]).expect("trust update request ID"),
                trust_domain_id: domain(),
                gateway_wg_public_key: gateway_key(),
                client_wg_public_key: client_key(),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                astra_service_key_epoch: 1,
                issuer_epoch: 1,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                client_identity_generation: 4,
                active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway TLS"),
                active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway PQ"),
                active_client_tls_certificate_fingerprint: Fingerprint::of(b"client TLS"),
                active_client_pq_certificate_fingerprint: Fingerprint::of(b"client PQ"),
                client_pq_certificate_fingerprint: Fingerprint::of(b"client PQ request"),
                base_state_fingerprint: Fingerprint::of(b"local trust state"),
            },
            certificate: peer.active_pq_certificate.clone(),
            ml_dsa_87_signature: MlDsa87Signature::placeholder(),
        }),
        peer: Box::new(peer),
    };
    let body = serde_json::to_vec(&relayed).expect("typed preparation request");
    let before_operations = std::fs::read(fixture.operations_path()).expect("operation journal");
    let before_registry = std::fs::read(fixture.registry_path()).expect("registry");
    let (status, _) = http(&server, "POST", TRUST_UPDATE_PREPARE_PATH, &body).await;
    assert_eq!(
        status, 403,
        "caller mismatch is a coarse trust-update refusal"
    );
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("operation journal"),
        before_operations
    );
    assert_eq!(
        std::fs::read(fixture.registry_path()).expect("registry"),
        before_registry
    );
    assert!(fixture.service.operations.lock().await.is_empty());
}
