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
async fn the_typed_peer_listing_reads_every_key_and_refuses_a_malformed_one() {
    let listed = WireGuardKey::from_bytes([7; 32]);
    let body = format!(r#"{{"peers":["{}"]}}"#, listed.to_base64());
    let server = response_server(fixed_response(200, body.as_bytes())).await;
    let client = GatewayLifecycleClient::new(server.address, server.client_tls);
    assert_eq!(
        within_deadline(client.peer_keys()).await.expect("listing"),
        vec![listed]
    );
    let request = String::from_utf8(finish(server.request).await).expect("request text");
    assert!(request.starts_with(&format!("GET {PEERS_PATH} HTTP/1.1\r\n")));

    let server = response_server(fixed_response(200, br#"{"peers":["AAAA"]}"#)).await;
    let client = GatewayLifecycleClient::new(server.address, server.client_tls);
    assert!(matches!(
        within_deadline(client.peer_keys()).await,
        Err(ChannelError::Body(_))
    ));
    finish(server.request).await;
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
