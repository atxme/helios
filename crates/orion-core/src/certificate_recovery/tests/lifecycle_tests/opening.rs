use super::*;

const CHALLENGE: [u8; 32] = [0x37; 32];
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn finish_peer<T>(peer: tokio::task::JoinHandle<T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, peer)
        .await
        .expect("mock peer finishes within the test timeout")
        .expect("mock HTTP peer")
}

fn recovery_material(domain: &Domain) -> (ClientIdentityBundle, crate::certificates::TrustState) {
    let directory = tempfile::tempdir().expect("fixture directory");
    let (expired_leaf, expired_key) = expired_leaf(domain);
    let state = state_with(
        directory.path(),
        domain,
        vec![binding(CredentialState::Active)],
        &expired_leaf,
    );

    let encode = base64::engine::general_purpose::STANDARD;
    let bundle = ClientIdentityBundle {
        pq_certificate: encode.encode(serde_json::to_vec(&expired_leaf).expect("expired leaf")),
        pq_private_key: encode.encode(expired_key.as_slice()).into(),
        ..crate::test_domain::bundle(domain)
    };
    (bundle, state)
}

#[tokio::test]
async fn begin_refuses_a_profile_without_an_identity_name() {
    let mut settings = crate::test_domain::settings(&domain());
    settings.identity = " \t ".into();
    assert!(matches!(
        begin(&settings, LATER).await,
        Err(RecoveryError::Identity(message))
            if message == "ce profil ne nomme aucune identité protégée"
    ));
}

#[tokio::test]
async fn begin_requires_an_authority_and_readable_historical_material() {
    let (mut bundle, mut state) = recovery_material(&domain());
    state.astra.authority_url = "///".into();
    assert!(matches!(
        begin_with_material(&bundle, &state, LATER).await,
        Err(RecoveryError::TrustMaterialMissing)
    ));

    bundle.pq_private_key = "!invalid base64!".into();
    assert!(matches!(
        begin_with_material(&bundle, &state, LATER).await,
        Err(RecoveryError::Identity(message))
            if message == "clé privée PQ expirée : base64 illisible"
    ));

    bundle.certificate_chain[0] = "!invalid base64!".into();
    assert!(matches!(
        begin_with_material(&bundle, &state, LATER).await,
        Err(RecoveryError::NoHistoricalProof)
    ));

    bundle.pq_certificate = "!invalid base64!".into();
    assert!(matches!(
        begin_with_material(&bundle, &state, LATER).await,
        Err(RecoveryError::Identity(message))
            if message == "protected identity store: certificat PQ client : base64 illisible"
    ));
}

#[tokio::test]
async fn begin_stops_at_a_refused_or_malformed_challenge() {
    let (bundle, mut state) = recovery_material(&domain());

    for (status, body) in [(503, b"{}".as_slice()), (200, b"{}".as_slice())] {
        let (base, peer) = mock_json_server(vec![(status, body.to_vec())]).await;
        state.astra.authority_url = base;
        let result =
            tokio::time::timeout(TEST_TIMEOUT, begin_with_material(&bundle, &state, LATER))
                .await
                .expect("challenge request has a bounded duration");
        match status {
            503 => assert!(matches!(result, Err(RecoveryError::Status { status: 503 }))),
            _ => assert!(matches!(result, Err(RecoveryError::Malformed(_)))),
        }
        assert_eq!(
            finish_peer(peer).await,
            ["POST /v1/client-rotation/challenge HTTP/1.1"]
        );
    }
}

async fn mock_opening(
    wrong_fingerprint: bool,
) -> (
    String,
    tokio::task::JoinHandle<(Id16, ExpiredCertificateRecoveryRequest)>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock HTTP listener");
    let address = listener.local_addr().expect("mock HTTP address");
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("challenge connection");
        let challenge_body = read_post(&mut stream, "/v1/client-rotation/challenge").await;
        assert_eq!(challenge_body, b"null");
        write_json(
            &mut stream,
            &serde_json::json!({ "astra_challenge": CHALLENGE }),
        )
        .await;
        drop(stream);

        let (mut stream, _) = listener.accept().await.expect("recovery connection");
        let body = read_post(&mut stream, "/v1/client-rotation/recovery").await;
        let request: ExpiredCertificateRecoveryRequest =
            serde_json::from_slice(&body).expect("valid public recovery request JSON");
        let operation_id = Id16::new([0x27; 16]).expect("nonzero operation ID");
        let response = ExpiredRecoveryOperationView {
            operation_id,
            state: ExpiredRecoveryState::AwaitingOperator,
            client_wg_public_key: request.client_wg_public_key,
            request_fingerprint: if wrong_fingerprint {
                Fingerprint::from_bytes([0x55; 32])
            } else {
                request.fingerprint()
            },
            created_at: LATER,
            expires_at: LATER + 300,
            request: None,
            receipt: None,
            gateway_pq_certificate: None,
            grant: None,
        };
        write_json(&mut stream, &response).await;
        (operation_id, request)
    });
    (format!("http://{address}"), peer)
}

async fn read_post(stream: &mut tokio::net::TcpStream, path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let count = stream.read(&mut chunk).await.expect("read POST");
        assert_ne!(count, 0, "complete POST headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("HTTP headers");
    assert_eq!(
        headers.lines().next(),
        Some(format!("POST {path} HTTP/1.1").as_str())
    );
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .expect("content length")
        .1
        .trim()
        .parse::<usize>()
        .expect("numeric content length");
    let mut body = bytes.split_off(header_end);
    assert!(body.len() <= content_length);
    let already_read = body.len();
    body.resize(content_length, 0);
    stream
        .read_exact(&mut body[already_read..])
        .await
        .expect("complete POST body");
    body
}

async fn write_json(stream: &mut tokio::net::TcpStream, response: &impl serde::Serialize) {
    let (status, body) = (200, serde_json::to_vec(response).expect("response JSON"));
    let header = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .expect("response header");
    stream.write_all(&body).await.expect("response body");
}

#[tokio::test]
async fn begin_opens_an_operation_bound_to_the_double_signed_request() {
    let domain = domain();
    let (bundle, mut state) = recovery_material(&domain);
    let (origin, peer) = mock_opening(false).await;
    state.astra.authority_url = format!("{origin}/");

    let (session, step) =
        tokio::time::timeout(TEST_TIMEOUT, begin_with_material(&bundle, &state, LATER))
            .await
            .expect("opening finishes within the test timeout")
            .expect("operation opened");
    let (operation_id, request) = finish_peer(peer).await;
    assert_eq!(step, RecoveryStep::AwaitingOperator { operation_id });
    assert_eq!(session.operation_id(), operation_id);
    assert_eq!(session.authority_url(), origin);
    assert_eq!(request_fingerprint(&session), request.fingerprint());

    request
        .verify_historical(
            &[&domain.ca_pq_public],
            &state.trust_domain_id,
            &state.gateway.gateway_wg_public_key,
            SERVER_NAME,
            &state.client_wg_public_key,
            &state.certificates.active,
            &CHALLENGE,
            LATER,
        )
        .expect("authority verifies both proof signatures and the challenge");
    let debug = format!("{session:?}");
    assert_eq!(
        debug,
        format!(
            "RecoverySession {{ operation_id: {:?}, candidate_keys: \"***\" }}",
            operation_id.to_hex()
        )
    );
}

#[tokio::test]
async fn begin_refuses_an_operation_for_a_different_request_fingerprint() {
    let (bundle, mut state) = recovery_material(&domain());
    let (origin, peer) = mock_opening(true).await;
    state.astra.authority_url = origin;
    let result = tokio::time::timeout(TEST_TIMEOUT, begin_with_material(&bundle, &state, LATER))
        .await
        .expect("opening finishes within the test timeout");
    assert!(matches!(result, Err(RecoveryError::Refused)));
    finish_peer(peer).await;
}
