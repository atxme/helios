use super::*;
use crate::transport::PinnedHttpClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

struct ResponseServer {
    address: SocketAddr,
    client_tls: rustls::ClientConfig,
    request: JoinHandle<Vec<u8>>,
}

async fn response_server(response: Vec<u8>) -> ResponseServer {
    let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
    let astra = disposable("astra.internal", PinnedRole::Client);
    let server_tls = server_config(&gateway.identity, &astra.certificate).expect("server TLS");
    let client_tls = client_config(&astra.identity, &gateway.certificate).expect("client TLS");
    response_server_with_tls(response, server_tls, client_tls).await
}

async fn response_server_with_tls(
    response: Vec<u8>,
    server_tls: rustls::ServerConfig,
    client_tls: rustls::ClientConfig,
) -> ResponseServer {
    let listener = within_deadline(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let request = tokio::spawn(within_deadline(async move {
        let (socket, _) = listener.accept().await.expect("client connection");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let Ok(mut stream) = acceptor.accept(socket).await else {
            return Vec::new();
        };
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            let length = match stream.read(&mut buffer).await {
                Ok(length) => length,
                Err(_) if request.is_empty() => return request,
                Err(error) => panic!("request read after HTTP bytes: {error}"),
            };
            if length == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..length]);
            assert!(request.len() <= MAX_OPERATOR_RELAY_BODY_BYTES + 4096);
            if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).expect("HTTP headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + content_length {
                    break;
                }
            }
        }
        // A bound refusal can close the connection while the response is still
        // being sent; the request remains available to inspect in either case.
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
        request
    }));
    ResponseServer {
        address,
        client_tls,
        request,
    }
}

fn fixed_response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

async fn within_deadline<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .expect("loopback operation completes within the independent test deadline")
}

async fn finish(mut request: JoinHandle<Vec<u8>>) -> Vec<u8> {
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut request).await;
    request.abort();
    result.expect("server terminates").expect("server task")
}

#[tokio::test]
async fn the_http_client_bounds_content_length_answers() {
    for length in [
        MAX_INTERNAL_BODY_BYTES - 1,
        MAX_INTERNAL_BODY_BYTES,
        MAX_INTERNAL_BODY_BYTES + 1,
    ] {
        let body = vec![b'x'; length];
        let server = response_server(fixed_response(200, &body)).await;
        let client = PinnedHttpClient::new(server.address, server.client_tls, INTERNAL_SERVER_NAME);
        let result = within_deadline(client.request("GET", "/bounded", None, None)).await;
        if length <= MAX_INTERNAL_BODY_BYTES {
            assert_eq!(result.expect("bounded answer"), body);
        } else {
            assert!(matches!(result, Err(ChannelError::Body(_))));
        }
        finish(server.request).await;
    }
}

#[tokio::test]
async fn chunked_answers_cannot_bypass_the_http_client_ceiling() {
    for length in [MAX_INTERNAL_BODY_BYTES, MAX_INTERNAL_BODY_BYTES + 1] {
        let body = vec![b'x'; length];
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for chunk in body.chunks(4096) {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        let server = response_server(response).await;
        let client = PinnedHttpClient::new(server.address, server.client_tls, INTERNAL_SERVER_NAME);
        let result = within_deadline(client.request("GET", "/chunked", None, None)).await;
        if length == MAX_INTERNAL_BODY_BYTES {
            assert_eq!(result.expect("boundary answer"), body);
        } else {
            assert!(matches!(result, Err(ChannelError::Body(_))));
        }
        finish(server.request).await;
    }
}

#[tokio::test]
async fn an_incomplete_http_body_is_never_returned_as_success() {
    let server = response_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let client = PinnedHttpClient::new(server.address, server.client_tls, INTERNAL_SERVER_NAME);
    assert!(matches!(
        within_deadline(client.request("GET", "/truncated", None, None)).await,
        Err(ChannelError::Body(_))
    ));
    finish(server.request).await;
}

#[tokio::test]
async fn non_success_answers_are_status_errors_and_redirects_are_not_followed() {
    for status in [307, 400, 403, 503] {
        let response = format!(
            "HTTP/1.1 {status} Refused\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ).into_bytes();
        let server = response_server(response).await;
        let client = PinnedHttpClient::new(server.address, server.client_tls, INTERNAL_SERVER_NAME);
        assert!(matches!(
            within_deadline(client.request("GET", "/original", None, None)).await,
            Err(ChannelError::Status(actual)) if actual.as_u16() == status
        ));
        let request = finish(server.request).await;
        assert!(request.starts_with(b"GET /original HTTP/1.1\r\n"));
    }
}

#[tokio::test]
async fn the_typed_peer_query_encodes_its_identity_and_rejects_invalid_json() {
    let server = response_server(fixed_response(200, b"{}")).await;
    let client = GatewayLifecycleClient::new(server.address, server.client_tls);
    let identity = WireGuardKey::from_bytes([255; 32]);
    assert_eq!(client.address(), server.address);
    assert!(matches!(
        within_deadline(client.peer_state(&identity)).await,
        Err(ChannelError::Body(_))
    ));
    let request = String::from_utf8(finish(server.request).await).expect("request text");
    let expected = format!(
        "GET {INTERNAL_PREFIX}state/{} HTTP/1.1\r\n",
        percent_encode_segment(&identity.to_base64())
    );
    assert!(request.starts_with(&expected));
    let (headers, _) = request.split_once("\r\n\r\n").expect("request parts");
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case(&format!("host: {INTERNAL_SERVER_NAME}"))));
}

#[tokio::test]
async fn publication_serializes_the_exact_document_on_its_typed_route() {
    let server = response_server(fixed_response(204, b"")).await;
    let client = GatewayLifecycleClient::new(server.address, server.client_tls);
    let document = GatewayTransitionPublished {
        gateway_identity_epoch: 29,
        transition_fingerprint: Fingerprint::of(b"typed publication"),
    };
    within_deadline(client.gateway_transition_published(&document))
        .await
        .expect("publication acknowledged");
    let request = finish(server.request).await;
    let split = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("headers");
    assert!(request.starts_with(format!("POST {GATEWAY_PUBLISHED_PATH} HTTP/1.1\r\n").as_bytes()));
    assert_eq!(
        serde_json::from_slice::<GatewayTransitionPublished>(&request[split + 4..])
            .expect("typed body"),
        document
    );
}

#[tokio::test]
async fn encrypted_vault_answers_use_the_operator_ceiling_and_header_capability() {
    let fingerprint = Fingerprint::of(b"encrypted vault");
    let relayed = RelayedOperatorCampaign {
        operator: OperatorIdentity::DevLoopback,
    };
    for length in [MAX_OPERATOR_ANSWER_BYTES, MAX_OPERATOR_ANSWER_BYTES + 1] {
        let vault = vec![0xa5; length];
        let server = response_server(fixed_response(200, &vault)).await;
        let client = AstraLifecycleClient::new(server.address, server.client_tls);
        assert_eq!(client.address(), server.address);
        let result = within_deadline(client.operator_encrypted_vault(
            &fingerprint,
            "test-capability",
            &relayed,
        ))
        .await;
        if length == MAX_OPERATOR_ANSWER_BYTES {
            assert_eq!(result.expect("vault at the operator ceiling"), vault);
        } else {
            assert!(matches!(result, Err(ChannelError::Body(_))));
        }
        let request = String::from_utf8(finish(server.request).await).expect("request text");
        let (headers, body) = request.split_once("\r\n\r\n").expect("request parts");
        assert!(headers.starts_with(&format!(
            "POST {} HTTP/1.1\r\n",
            operator_path("vaults", &fingerprint.to_string())
        )));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: bearer test-capability")));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("host: {ASTRA_INTERNAL_SERVER_NAME}"))));
        assert!(!headers
            .lines()
            .next()
            .expect("request line")
            .contains("test-capability"));
        assert!(!body.contains("test-capability"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).expect("relay JSON"),
            serde_json::to_value(&relayed).expect("relay value")
        );
    }
}

#[tokio::test]
async fn a_client_refuses_a_wrong_pin_and_an_unrelated_alpn() {
    for wrong_pin in [true, false] {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let impostor = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);
        let server_tls = server_config(&gateway.identity, &astra.certificate).expect("server TLS");
        let mut client_tls = client_config(
            &astra.identity,
            if wrong_pin {
                &impostor.certificate
            } else {
                &gateway.certificate
            },
        )
        .expect("client TLS");
        if !wrong_pin {
            client_tls.alpn_protocols = vec![b"unrelated-service/1".to_vec()];
        }
        let server =
            response_server_with_tls(fixed_response(200, b"{}"), server_tls, client_tls).await;
        let client = PinnedHttpClient::new(server.address, server.client_tls, INTERNAL_SERVER_NAME);
        assert!(matches!(
            within_deadline(client.request("GET", "/never-sent", None, None)).await,
            Err(ChannelError::Tls(_))
        ));
        assert!(
            finish(server.request).await.is_empty(),
            "TLS refusal precedes every HTTP byte"
        );
    }
}

#[tokio::test]
async fn an_oversized_operator_open_is_refused_before_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
    let astra = disposable("astra.internal", PinnedRole::Client);
    let tls = client_config(&astra.identity, &gateway.certificate).expect("client TLS");
    let client = AstraLifecycleClient::new(listener.local_addr().expect("address"), tls);
    let request = RelayedOperatorOpen {
        operator: OperatorIdentity::DevLoopback,
        request: OperatorOpenRequest {
            action: OperatorOpenAction::TrustAuthorities,
            reason: "x".repeat(MAX_OPERATOR_RELAY_BODY_BYTES + 1),
            requested_by: "operator".to_owned(),
            window_secs: 300,
        },
    };
    assert!(matches!(
        within_deadline(client.operator_open(&request)).await,
        Err(ChannelError::Body(_))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "an invalid relay must not reach Astra"
    );
}

fn client_renewal_view() -> ClientRenewalOperationView {
    ClientRenewalOperationView {
        operation_id: Id16::new([7; 16]).expect("operation id"),
        state: ClientRenewalOperationState::AwaitingOperator,
        client_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        operation_manifest_fingerprint: Fingerprint::of(b"approval manifest"),
        created_at: 10,
        expires_at: 20,
        signer_request_token: Some("read-token".into()),
        signer_result_token: Some("write-token".into()),
        grant: None,
    }
}

fn rotation_request() -> aether::certificates::client::ClientCertificateRotationRequest {
    use aether::certificates::{
        client::ClientCertificateRotationRequest,
        encoding::{DerCertificate, MlDsa87PublicKey, MlDsa87Signature},
        CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
    };
    ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([1; 16]).expect("request id"),
        trust_domain_id: Id16::new([2; 16]).expect("trust domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([3; 32]),
        server_name: "gateway.example".into(),
        client_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        active_generation: 4,
        requested_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        // The authority owns CSR/proof validation. These values exercise only
        // the gateway client's typed serialization and response decoding.
        tls_csr: DerCertificate::new(vec![1]).expect("bounded CSR wrapper"),
        new_ml_dsa_87_public_key: MlDsa87PublicKey::new(vec![22; 2592])
            .expect("test public key encoding"),
        created_at: 10,
        expires_at: 20,
        active_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
}

fn captured_parts(request: &[u8]) -> (&str, &str) {
    let text = std::str::from_utf8(request).expect("HTTP request text");
    let (headers, body) = text.split_once("\r\n\r\n").expect("HTTP body separator");
    (headers, body)
}

#[tokio::test]
async fn authority_rotation_request_uses_the_private_route_and_decodes_the_typed_answer() {
    let expected_view = client_renewal_view();
    let response = serde_json::to_vec(&expected_view).expect("operation view");
    let server = response_server(fixed_response(200, &response)).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let relayed = RelayedRotationRequest {
        caller_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        request: Box::new(rotation_request()),
    };

    let actual = within_deadline(client.request_rotation(&relayed))
        .await
        .expect("typed operation answer");
    assert_eq!(actual.operation_id, expected_view.operation_id);
    assert_eq!(actual.state, ClientRenewalOperationState::AwaitingOperator);
    let request = finish(server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(format!("POST {ROTATION_REQUEST_PATH} HTTP/1.1\r\n").as_str()));
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case(&format!("host: {ASTRA_INTERNAL_SERVER_NAME}"))));
    assert!(!headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
    let decoded: RelayedRotationRequest = serde_json::from_str(body).expect("relayed request");
    assert_eq!(decoded.caller_wg_public_key, relayed.caller_wg_public_key);
    assert_eq!(*decoded.request, *relayed.request);
}

#[tokio::test]
async fn authority_operation_query_uses_its_collection_and_caller_body() {
    let response = serde_json::to_vec(&client_renewal_view()).expect("operation view");
    let server = response_server(fixed_response(200, &response)).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).expect("operation id");
    let caller = WireGuardKey::from_bytes([9; 32]);
    let actual = within_deadline(client.operation(
        &operation,
        &RelayedOperationQuery {
            caller_wg_public_key: caller,
        },
    ))
    .await
    .expect("typed operation answer");
    assert_eq!(actual.operation_id, operation);
    let request = finish(server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(
        format!(
            "POST {} HTTP/1.1\r\n",
            operation_path("operations", &operation)
        )
        .as_str()
    ));
    let decoded: RelayedOperationQuery = serde_json::from_str(body).expect("caller query");
    assert_eq!(decoded.caller_wg_public_key, caller);
    assert!(!headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
}

#[tokio::test]
async fn renewal_signer_request_keeps_its_capability_in_the_header_only() {
    let server = response_server(fixed_response(200, b"{}")).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).expect("operation id");
    let result = within_deadline(client.signer_request(
        &operation,
        "renewal-capability-secret",
        &RelayedOperationQuery {
            caller_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        },
    ))
    .await;
    assert!(matches!(result, Err(ChannelError::Body(_))));
    let request = finish(server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(
        format!(
            "POST {} HTTP/1.1\r\n",
            operation_path("signer-requests", &operation)
        )
        .as_str()
    ));
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer renewal-capability-secret")));
    assert!(!headers
        .lines()
        .next()
        .unwrap()
        .contains("renewal-capability-secret"));
    assert!(!body.contains("renewal-capability-secret"));
    assert_eq!(
        serde_json::from_str::<RelayedOperationQuery>(body)
            .expect("caller query")
            .caller_wg_public_key,
        WireGuardKey::from_bytes([9; 32])
    );
}

#[tokio::test]
async fn operator_pending_and_open_use_operator_paths_without_capabilities() {
    let pending_server = response_server(fixed_response(200, br#"{"operations":[]}"#)).await;
    let client = AstraLifecycleClient::new(pending_server.address, pending_server.client_tls);
    let relayed = RelayedOperatorCampaign {
        operator: OperatorIdentity::DevLoopback,
    };
    let pending = within_deadline(client.operator_pending(&relayed))
        .await
        .expect("empty pending list");
    assert!(pending.operations.is_empty());
    let request = finish(pending_server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(format!("POST {OPERATOR_PENDING_ROUTE} HTTP/1.1\r\n").as_str()));
    assert_eq!(
        serde_json::from_str::<RelayedOperatorCampaign>(body)
            .unwrap()
            .operator,
        relayed.operator
    );
    assert!(!headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));

    let opened = OperatorOpened {
        operation_id: Id16::new([7; 16]).expect("operation id"),
        campaign_id: Id16::new([8; 16]).expect("campaign id"),
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        scope: aether::certificates::status::CampaignScope::TrustAuthorities,
        target_count: 1,
        required_credentials: 1,
        expires_at: 30,
        revocation_expiries: None,
    };
    let open_server = response_server(fixed_response(
        200,
        &serde_json::to_vec(&opened).expect("opened campaign"),
    ))
    .await;
    let client = AstraLifecycleClient::new(open_server.address, open_server.client_tls);
    let request_value = RelayedOperatorOpen {
        operator: OperatorIdentity::DevLoopback,
        request: OperatorOpenRequest {
            action: OperatorOpenAction::TrustAuthorities,
            reason: "rotation".into(),
            requested_by: "operator".into(),
            window_secs: 300,
        },
    };
    let actual = within_deadline(client.operator_open(&request_value))
        .await
        .expect("opened campaign");
    assert_eq!(actual, opened);
    let request = finish(open_server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(format!("POST {OPERATOR_OPEN_ROUTE} HTTP/1.1\r\n").as_str()));
    assert_eq!(
        serde_json::from_str::<RelayedOperatorOpen>(body)
            .unwrap()
            .request,
        request_value.request
    );
    assert!(!headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
}

fn operator_view() -> SigningOperationView {
    SigningOperationView {
        operation_id: Id16::new([7; 16]).expect("operation id"),
        state: SigningOperationState::AwaitingOperator,
        scope: aether::certificates::status::CampaignScope::TrustAuthorities,
        target_count: 1,
        required_credentials: 1,
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        created_at: 10,
        expires_at: 30,
        signer_request_token: Some("read-token".into()),
        vault_token: None,
        signer_result_token: Some("write-token".into()),
    }
}

#[tokio::test]
async fn operator_operation_uses_campaign_prefix_and_decodes_typed_view() {
    let expected = operator_view();
    let server = response_server(fixed_response(
        200,
        &serde_json::to_vec(&expected).expect("campaign view"),
    ))
    .await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).expect("operation id");
    let relayed = RelayedOperatorCampaign {
        operator: OperatorIdentity::DevLoopback,
    };
    let actual = within_deadline(client.operator_operation(&operation, &relayed))
        .await
        .expect("campaign view");
    assert_eq!(actual.operation_id, operation);
    let request = finish(server.request).await;
    let (headers, body) = captured_parts(&request);
    let expected_path = operator_path("operations", &operation.to_string());
    assert!(headers.starts_with(format!("POST {expected_path} HTTP/1.1\r\n").as_str()));
    assert!(expected_path.starts_with(ASTRA_OPERATOR_PREFIX));
    assert!(!expected_path.starts_with(ASTRA_INTERNAL_PREFIX));
    assert_eq!(
        serde_json::from_str::<RelayedOperatorCampaign>(body)
            .unwrap()
            .operator,
        relayed.operator
    );
    assert!(!headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
}

#[tokio::test]
async fn operator_signer_request_keeps_capability_out_of_url_and_reports_bad_answer_json() {
    let server = response_server(fixed_response(200, b"not-json")).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).expect("operation id");
    let relayed = RelayedOperatorCampaign {
        operator: OperatorIdentity::DevLoopback,
    };
    assert!(matches!(
        within_deadline(client.operator_signer_request(
            &operation,
            "campaign-capability-secret",
            &relayed,
        ))
        .await,
        Err(ChannelError::Body(_))
    ));
    let request = finish(server.request).await;
    let (headers, body) = captured_parts(&request);
    assert!(headers.starts_with(
        format!(
            "POST {} HTTP/1.1\r\n",
            operator_path("signer-requests", &operation.to_string())
        )
        .as_str()
    ));
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer campaign-capability-secret")));
    assert!(!headers
        .lines()
        .next()
        .unwrap()
        .contains("campaign-capability-secret"));
    assert!(!body.contains("campaign-capability-secret"));
}

#[tokio::test]
async fn operator_signer_result_sends_the_entire_typed_deposit_with_header_capability() {
    use aether::certificates::status::{AstraSignerResult, CampaignApproval};
    let view = operator_view();
    let server = response_server(fixed_response(200, &serde_json::to_vec(&view).unwrap())).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).unwrap();
    let result = RelayedOperatorSignerResult {
        operator: OperatorIdentity::DevLoopback,
        result: Box::new(AstraSignerResult {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: Id16::new([8; 16]).unwrap(),
                campaign_fingerprint: Fingerprint::of(b"campaign"),
                required_credentials: 1,
                approved_at: 10,
                approvals: vec![],
            }),
            objects: vec![],
            credential_registry: None,
            issuer_authorization: None,
        }),
    };
    let answer =
        within_deadline(client.operator_signer_result(&operation, "deposit-secret", &result))
            .await
            .expect("typed response");
    assert_eq!(answer.operation_id, operation);
    let captured = finish(server.request).await;
    let (headers, body) = captured_parts(&captured);
    assert!(headers.starts_with(&format!(
        "POST {} HTTP/1.1\r\n",
        operator_path("signer-results", &operation.to_string())
    )));
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer deposit-secret")));
    assert!(!headers.lines().next().unwrap().contains("deposit-secret"));
    assert!(!body.contains("deposit-secret"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::to_value(&result).unwrap()
    );
}

#[tokio::test]
async fn renewal_signer_result_sends_the_approval_for_the_resolved_peer() {
    use aether::certificates::{
        approval::{AstraCredentialBinding, AstraRenewalApproval, CredentialState},
        encoding::MlDsa87Signature,
        webauthn::WebAuthnAssertion,
        CERTIFICATE_FORMAT_VERSION,
    };
    let view = client_renewal_view();
    let server = response_server(fixed_response(200, &serde_json::to_vec(&view).unwrap())).await;
    let client = AstraLifecycleClient::new(server.address, server.client_tls);
    let operation = Id16::new([7; 16]).unwrap();
    let peer = WireGuardKey::from_bytes([9; 32]);
    let fingerprint = Fingerprint::of(b"fixture");
    let result = ClientRenewalSignerResult {
        caller_wg_public_key: peer,
        approval: Box::new(AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: operation,
            request_fingerprint: fingerprint,
            approval_request_fingerprint: fingerprint,
            credential_binding: AstraCredentialBinding {
                format_version: CERTIFICATE_FORMAT_VERSION,
                credential_id: vec![1],
                credential_public_key: vec![2],
                aaguid: [0; 16],
                trust_domain_id: Id16::new([3; 16]).unwrap(),
                gateway_wg_public_key: WireGuardKey::from_bytes([4; 32]),
                state: CredentialState::Active,
                credential_epoch: 1,
                credential_registry_epoch: 1,
                ca_epoch: 1,
                created_at: 10,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            },
            credential_fingerprint: fingerprint,
            assertion_fingerprint: fingerprint,
            webauthn_assertion: WebAuthnAssertion {
                authenticator_data: vec![1],
                client_data_json: vec![2],
                signature: vec![3],
            },
            approved_at: 10,
            expires_at: 20,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        }),
    };
    let answer = within_deadline(client.signer_result(&operation, "renewal-secret", &result))
        .await
        .expect("typed response");
    assert_eq!(answer.operation_id, operation);
    let captured = finish(server.request).await;
    let (headers, body) = captured_parts(&captured);
    assert!(headers.starts_with(&format!(
        "POST {} HTTP/1.1\r\n",
        operation_path("signer-results", &operation)
    )));
    assert!(headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer renewal-secret")));
    assert!(!headers.lines().next().unwrap().contains("renewal-secret"));
    assert!(!body.contains("renewal-secret"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::to_value(&result).unwrap()
    );
}
