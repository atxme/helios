use super::*;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request},
};
use std::net::SocketAddr;
use tower::ServiceExt;

const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PEER_PSK: &str = "ultra-secret-psk-must-never-leak";

fn state() -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
    state_with_mode(true)
}

/// Same state, but in real mode: secret persistence there does not follow
/// the same rules as in dry-run, where the TPM is absent.
fn state_real() -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
    state_with_mode(false)
}

fn state_with_mode(dry_run: bool) -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
    let network = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        admin_iface: Some("helios0".into()),
        wg_private_key: PRIVATE_KEY.into(),
        peers: vec![aether::WgPeer {
            name: "workstation".into(),
            public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: true,
            preshared_key: Some(PEER_PSK.into()),
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    };
    let policy = network.firewall_policy();
    let (event_tx, _) = broadcast::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    (
        AppState::new(
            Arc::new(RwLock::new(network)),
            dry_run,
            Arc::new(RwLock::new(TunnelState::Down)),
            event_tx,
            cmd_tx,
            auto_ack_psk_channel(),
            Arc::new(RwLock::new(policy)),
        ),
        cmd_rx,
    )
}

/// Serializes tests that persist `network.toml` and redirects the system
/// path to a disposable file.
///
/// `HELIOS_NETWORK_CONFIG` is process-wide state: without this lock, two
/// parallel tests would read each other's file and fail intermittently,
/// which is worse than a missing test.
async fn isolated_config() -> (tokio::sync::MutexGuard<'static, ()>, std::path::PathBuf) {
    // Async lock: the tests that take it cross `await` points, which a
    // `std::sync::Mutex` cannot hold safely.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;
    let path = std::env::temp_dir().join(format!("helios-api-network-{}.toml", std::process::id()));
    std::env::set_var("HELIOS_NETWORK_CONFIG", &path);
    let _ = std::fs::remove_file(&path);
    (guard, path)
}

/// Admin request authenticated by the VIP of peer `workstation`, who is `admin`.
fn admin_request(uri: &str, body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    request
}

/// Simulated orchestrator that acknowledges every PSK installation.
///
/// These tests exercise the router and the redaction of secrets, not the
/// data plane: without this sink, the channel would be closed and
/// provisioning would fail for a reason unrelated to what they verify.
fn auto_ack_psk_channel() -> mpsc::Sender<InstallPskRequest> {
    let (tx, mut rx) = mpsc::channel::<InstallPskRequest>(8);
    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            let _ = request.reply.send(Ok(()));
        }
    });
    tx
}

/// The operator campaign sits on the admin surface, not the peer one.
///
/// Three probes of the same route, in the real router: a source tied to no
/// admitted peer, a browser origin that is not this host, and — in the
/// third — an admitted administrator whose gateway simply has no authority
/// to relay to. The first two must not be told the route exists; the third
/// is told the authority is missing, which is the one answer §8.5 allows
/// to be specific.
#[tokio::test]
async fn the_operator_campaign_routes_live_behind_the_admin_barrier() {
    const URI: &str = "/api/certificates/operator/operations/07070707070707070707070707070707";

    let (unknown_state, _cmd_rx) = state();
    let mut unknown = Request::builder().uri(URI).body(Body::empty()).unwrap();
    unknown.extensions_mut().insert(ConnectInfo(
        "100.64.9.9:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(unknown_state).oneshot(unknown).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a source tied to no admitted peer must not reach a campaign"
    );

    let (cross_state, _cmd_rx) = state();
    let mut cross_origin = Request::builder()
        .uri(URI)
        .header(header::HOST, "100.64.0.1:8080")
        .header(header::ORIGIN, "https://hostile.example")
        .body(Body::empty())
        .unwrap();
    cross_origin.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(cross_state).oneshot(cross_origin).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an inconsistent browser origin is refused before the caller is resolved"
    );

    let (admin_state, _cmd_rx) = state();
    let mut administrator = Request::builder().uri(URI).body(Body::empty()).unwrap();
    administrator.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(admin_state).oneshot(administrator).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the administrator is admitted; what is missing is the private channel"
    );
}

/// The status read sits on the admin surface like the rest of the campaign.
#[tokio::test]
async fn the_operator_status_is_an_admin_read() {
    const URI: &str = "/api/certificates/operator/status";

    let (unknown_state, _cmd_rx) = state();
    let mut unknown = Request::builder().uri(URI).body(Body::empty()).unwrap();
    unknown.extensions_mut().insert(ConnectInfo(
        "100.64.9.9:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(unknown_state).oneshot(unknown).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (admin_state, _cmd_rx) = state();
    let mut administrator = Request::builder().uri(URI).body(Body::empty()).unwrap();
    administrator.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(admin_state).oneshot(administrator).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Operator results have their own 64 KiB contract.
///
/// The trust-update protocol is chunked and uses a smaller 32 KiB request
/// bound. Reusing that constant here would make the tunnel reject a result
/// which Astra's public operator origin accepts. Invalid JSON below lets us
/// distinguish "the route read it" (`400`) from "the body limit stopped it"
/// (`413`) without constructing a signed authority result.
#[tokio::test]
async fn operator_results_use_the_operator_body_bound() {
    const URI: &str = "/api/certificates/operator/signer-results/07070707070707070707070707070707";

    let (within_state, _cmd_rx) = state();
    let within = " ".repeat(40 * 1024);
    let mut request = admin_request(URI, &within);
    request.headers_mut().insert(
        header::AUTHORIZATION,
        "Bearer invalid".parse().expect("header"),
    );
    let response = router(within_state).oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a body above the trust-update bound but within the operator bound must reach the parser"
    );

    let (oversized_state, _cmd_rx) = state();
    let oversized = " ".repeat(astra_channel::MAX_OPERATOR_REQUEST_BYTES + 1);
    let mut request = admin_request(URI, &oversized);
    request.headers_mut().insert(
        header::AUTHORIZATION,
        "Bearer invalid".parse().expect("header"),
    );
    let response = router(oversized_state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// The vault copy has a bound of its own: a vault is larger than an operator
/// result, and the 64 KiB bound would refuse every real one.
#[tokio::test]
async fn vault_copy_route_refuses_a_non_admin_and_an_oversized_body() {
    const URI: &str = "/api/certificates/operator/vault-copy";
    const BODY: &str = r#"{"vault_base64":"e30="}"#;

    let (non_admin_state, _cmd_rx) = state();
    non_admin_state.network.write().await.peers[0].admin = false;
    let response = router(non_admin_state)
        .oneshot(admin_request(URI, BODY))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (within_state, _cmd_rx) = state();
    let within = " ".repeat(astra_channel::MAX_OPERATOR_REQUEST_BYTES + 1024);
    let response = router(within_state)
        .oneshot(admin_request(URI, &within))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "above the operator result bound, within the vault copy bound: the parser is reached"
    );

    let (oversized_state, _cmd_rx) = state();
    let oversized = " ".repeat(astra_channel::MAX_OPERATOR_VAULT_COPY_BODY_BYTES + 1);
    let response = router(oversized_state)
        .oneshot(admin_request(URI, &oversized))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let (admin_state, _cmd_rx) = state();
    let response = router(admin_state)
        .oneshot(admin_request(URI, BODY))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the administrator is admitted; what is missing is the private channel"
    );
}

/// The gateway publication is an administrative mutation: refused to a peer
/// that is not an administrator, and admitted to one, whatever the authority
/// behind it says.
#[tokio::test]
async fn publish_is_refused_to_a_non_admin() {
    const URI: &str = "/api/certificates/operator/gateway-identity/publish";
    const BODY: &str = r#"{"epoch":5,"transition_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}"#;

    let (non_admin_state, _cmd_rx) = state();
    non_admin_state.network.write().await.peers[0].admin = false;
    let response = router(non_admin_state)
        .oneshot(admin_request(URI, BODY))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (admin_state, _cmd_rx) = state();
    let response = router(admin_state)
        .oneshot(admin_request(URI, BODY))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the administrator is admitted; what is missing is the private channel"
    );
}

/// Opening a campaign is an administrative mutation like any other.
///
/// Mounted beside the signer results, it inherits the same barriers in the
/// real router: an inconsistent browser origin is refused, a form post is
/// refused, the operator body bound holds, and an administrator whose gateway
/// has no authority is told only that.
#[tokio::test]
async fn an_operator_opening_is_an_administrative_mutation() {
    const URI: &str = "/api/certificates/operator/campaigns";
    const BODY: &str = r#"{"action":"fleet_leafs","reason":"r","requested_by":"alice"}"#;

    let (cross_state, _cmd_rx) = state();
    let mut cross_origin = admin_request(URI, BODY);
    cross_origin
        .headers_mut()
        .insert(header::HOST, "100.64.0.1:8080".parse().expect("header"));
    cross_origin.headers_mut().insert(
        header::ORIGIN,
        "https://hostile.example".parse().expect("header"),
    );
    let response = router(cross_state).oneshot(cross_origin).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (form_state, _cmd_rx) = state();
    let mut form = admin_request(URI, BODY);
    form.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().expect("header"),
    );
    let response = router(form_state).oneshot(form).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (oversized_state, _cmd_rx) = state();
    let oversized = " ".repeat(astra_channel::MAX_OPERATOR_REQUEST_BYTES + 1);
    let response = router(oversized_state)
        .oneshot(admin_request(URI, &oversized))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let (admin_state, _cmd_rx) = state();
    let response = router(admin_state)
        .oneshot(admin_request(URI, BODY))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the administrator is admitted; what is missing is the private channel"
    );
}

#[tokio::test]
async fn orion_cannot_relay_astra_stage_authorizations() {
    let (state, _cmd_rx) = state();
    let response = router(state)
        .oneshot(admin_request("/api/key-negotiation/stage", "{}"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_network_is_redacted_in_the_real_router() {
    let (state, _cmd_rx) = state();
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/api/network")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(json["wg_private_key_configured"], true);
    assert_eq!(json["peers"][0]["preshared_key_configured"], true);
    assert!(!text.contains(PRIVATE_KEY));
    assert!(!text.contains(PEER_PSK));
    // The public half, on the other hand, must come out: it is the
    // `peer_public_key` the operator puts into client profiles.
    assert_eq!(
        json["wg_public_key"],
        aether::wg::public_from_private(PRIVATE_KEY).unwrap()
    );
}

#[tokio::test]
async fn mutations_refuse_form_posts_and_posts_without_json_type() {
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let (state, mut cmd_rx) = state();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/tunnel/start");
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = router(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(cmd_rx.try_recv().is_err());
    }
}

#[tokio::test]
async fn speedtest_upload_accepts_a_bounded_binary_body_only_for_a_peer() {
    let (app_state, _cmd_rx) = state();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/speedtest/upload?bytes=4")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, "4")
        .body(Body::from("test"))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(app_state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (app_state, _cmd_rx) = state_real();
    let response = router(app_state)
        .oneshot(
            Request::builder()
                .uri("/api/speedtest/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn speedtest_download_is_bounded_and_returns_the_requested_size() {
    let (app_state, _cmd_rx) = state();
    let mut request = Request::builder()
        .uri("/api/speedtest/download?bytes=32")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(app_state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64).await.unwrap();
    assert_eq!(body.len(), 32);

    let (app_state, _cmd_rx) = state();
    let uri = format!(
        "/api/speedtest/download?bytes={}",
        speedtest::MAX_TRANSFER_BYTES + 1
    );
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(app_state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn spoofed_proxy_headers_cannot_authorize_an_admin_mutation() {
    let (app_state, mut commands) = state_real();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/tunnel/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "100.64.1.2")
        .header("x-real-ip", "100.64.1.2")
        .header("forwarded", "for=100.64.1.2")
        .body(Body::from("{}"))
        .expect("request");
    let response = router(app_state).oneshot(request).await.expect("router");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        commands.try_recv().is_err(),
        "a spoofed source must not reach the orchestrator"
    );
}

#[tokio::test]
async fn mutation_requires_the_admin_peer_identified_by_its_vip() {
    let (non_admin_state, mut cmd_rx) = state();
    non_admin_state.network.write().await.peers[0].admin = false;
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/tunnel/start")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(non_admin_state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(cmd_rx.try_recv().is_err());

    let (state, mut cmd_rx) = state();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/tunnel/start")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "100.64.1.2:4242".parse::<SocketAddr>().unwrap(),
    ));
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(matches!(
        cmd_rx.recv().await,
        Some(OrchestratorCmd::Connect)
    ));
}

/// Test public key, distinct from the already-admitted peer's.
const NEW_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
/// Ce que la v5 exige de toute admission : les deux empreintes.
///
/// Un pair sans identité PQ est refusé, et le plancher `ml_kem` est
/// imposé — le défaut v4, qui retombait sur `classic` en l'absence de
/// certificat, produisait des pairs au premier handshake nu.
const ADMIT_IDENTITY: &str = concat!(
    r#""key_negotiation_certificate_sha256":"#,
    r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
    r#""key_negotiation_pq_certificate_sha256":"#,
    r#""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#
);

/// A gateway holding a trust domain, for the two admission refusals below.
struct RecordingTrustHandler {
    admitted: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl certificates::TrustUpdateHandler for RecordingTrustHandler {
    async fn trust_enrolment(
        &self,
        _peer_wg_public_key: &str,
    ) -> Result<certificates::TrustEnrolmentView, certificates::TrustUpdateRefusal> {
        Err(certificates::TrustUpdateRefusal::Rejected)
    }

    async fn domain(
        &self,
    ) -> Result<certificates::CertificateDomainView, certificates::TrustUpdateRefusal> {
        Err(certificates::TrustUpdateRefusal::Rejected)
    }

    async fn admit_peer(
        &self,
        _name: &str,
        peer_wg_public_key: &str,
        _tls_certificate: aether::certificates::encoding::DerCertificate,
        _pq_certificate: Box<aether::key_negotiation::PqCertificate>,
    ) -> Result<(), certificates::TrustUpdateRefusal> {
        self.admitted
            .lock()
            .unwrap()
            .push(peer_wg_public_key.to_string());
        Ok(())
    }

    async fn trust_update(
        &self,
        _caller_wg_public_key: &str,
        _request: aether::certificates::transport::AuthenticatedTrustUpdateRequest,
    ) -> Result<certificates::TrustUpdateResponse, certificates::TrustUpdateRefusal> {
        Err(certificates::TrustUpdateRefusal::Rejected)
    }

    async fn stage_commit(
        &self,
        _caller_wg_public_key: &str,
        _request: Box<certificates::StageCommitRequest>,
    ) -> Result<(), certificates::TrustUpdateRefusal> {
        Err(certificates::TrustUpdateRefusal::Rejected)
    }
}

/// A gateway that holds a trust domain records the **leaves**, not their
/// digests. An admission that carries only the fingerprints would produce
/// a peer with no registry row: a client that connects and can never renew,
/// and nothing would say so until 80 % of its leaf's life.
#[tokio::test]
async fn admission_into_a_trust_domain_refuses_fingerprints_alone() {
    let (_lock, _path) = isolated_config().await;
    let (mut state, _cmd_rx) = state();
    state.trust_update = Some(Arc::new(RecordingTrustHandler {
        admitted: Default::default(),
    }));

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let message = String::from_utf8_lossy(&body);
    assert!(
        message.contains("certificates"),
        "the refusal names what is missing: {message}"
    );
}

/// The peer table pins digests and the registry records objects. If the
/// two disagree, the gateway would hold two answers about which
/// certificate belongs to this peer — so the admission is refused rather
/// than resolved in favour of either.
#[tokio::test]
async fn admission_refuses_a_certificate_that_contradicts_its_pin() {
    use base64::Engine as _;
    let (_lock, _path) = isolated_config().await;
    let (mut state, _cmd_rx) = state();
    let handler = Arc::new(RecordingTrustHandler {
        admitted: Default::default(),
    });
    state.trust_update = Some(handler.clone());

    let encoder = base64::engine::general_purpose::STANDARD;
    let certificate = encoder.encode(vec![9u8; 64]);
    let pq = encoder.encode(
        serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "serial": vec![0u8; 16],
            "subject": "laptop",
            "issuer": "CA-PQ",
            "role": "client",
            "wireguard_public_key": NEW_KEY,
            "ml_dsa_87_public_key": "cHVibGlj",
            "not_before_unix": 0,
            "not_after_unix": 1_000_000,
            "ml_dsa_87_signature": "c2ln",
        }))
        .unwrap(),
    );

    let body = format!(
        r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY},"key_negotiation_certificate":"{certificate}","key_negotiation_pq_certificate":"{pq}"}}"#
    );
    let response = router(state)
        .oneshot(admin_request("/api/peers", &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        handler.admitted.lock().unwrap().is_empty(),
        "nothing reaches the registry when the two halves disagree"
    );
}

#[tokio::test]
async fn admission_allocates_a_vip_and_notifies_the_orchestrator() {
    let (_lock, _path) = isolated_config().await;
    let (state, mut cmd_rx) = state();

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "laptop");
    assert_eq!(json["admin"], false);
    assert_eq!(
        json["post_quantum"], false,
        "admission does not install a PSK"
    );
    let address = json["address"].as_str().expect("address");
    assert!(address.ends_with("/32"), "address: {address}");
    assert!(address.starts_with("100."), "outside CGNAT: {address}");

    match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => {
            assert_eq!(config.peers.len(), 2);
            assert_eq!(
                config.wg_private_key.expose(),
                PRIVATE_KEY,
                "the orchestrator must keep the resolved identity"
            );
            assert_eq!(
                config.peers[0]
                    .preshared_key
                    .as_ref()
                    .map(aether::SecretString::expose),
                Some(PEER_PSK),
                "the existing peer's PSK must survive admission"
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

/// In real mode, the key comes from the sealed vault: rewriting it into
/// `network.toml` would undo the sealing. PSKs, meanwhile, are never
/// persisted, regardless of the mode.
#[tokio::test]
async fn real_persistence_contains_neither_private_key_nor_psk() {
    let (_lock, path) = isolated_config().await;
    let (state, mut cmd_rx) = state_real();

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = cmd_rx.recv().await;

    let persisted = std::fs::read_to_string(&path).expect("network.toml written");
    assert!(
        persisted.contains("laptop"),
        "the admitted peer must be persisted: {persisted}"
    );
    assert!(
        !persisted.contains(PRIVATE_KEY),
        "private key written in clear: {persisted}"
    );
    assert!(
        !persisted.contains(PEER_PSK),
        "PSK persisted to disk: {persisted}"
    );
}

/// In dry-run there is no TPM vault: `network.toml` is the only place
/// where the identity can live. Erasing it would make a `--dev` daemon
/// lose its identity on the first `peer add`, breaking the dev bench
/// without any message tying the failure to its cause.
#[tokio::test]
async fn dry_run_persistence_keeps_the_identity_but_not_the_psks() {
    let (_lock, path) = isolated_config().await;
    let (state, mut cmd_rx) = state();

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = cmd_rx.recv().await;

    let persisted = std::fs::read_to_string(&path).expect("network.toml written");
    assert!(
        persisted.contains(PRIVATE_KEY),
        "the --dev daemon lost its identity while admitting a peer: {persisted}"
    );
    assert!(
        !persisted.contains(PEER_PSK),
        "a PSK must never reach disk, even in dry-run: {persisted}"
    );
}

#[tokio::test]
async fn duplicate_admission_is_a_conflict() {
    let (_lock, _path) = isolated_config().await;

    for (body, expected) in [
        (
            format!(r#"{{"name":"workstation","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
            StatusCode::CONFLICT,
        ),
        (
            format!(
                r#"{{"name":"other","public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",{ADMIT_IDENTITY}}}"#
            ),
            StatusCode::CONFLICT,
        ),
        (
            format!(r#"{{"name":"other","public_key":"not-a-key",{ADMIT_IDENTITY}}}"#),
            StatusCode::BAD_REQUEST,
        ),
        // Nouveau en v5 : une admission sans identité PQ est refusée, et
        // c'est une erreur d'entrée, pas un conflit d'état.
        (
            format!(r#"{{"name":"nu","public_key":"{NEW_KEY}"}}"#),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (state, mut cmd_rx) = state();
        let response = router(state)
            .oneshot(admin_request("/api/peers", &body))
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "body: {body}");
        assert!(
            cmd_rx.try_recv().is_err(),
            "a refusal must send nothing to the orchestrator"
        );
    }
}

/// The remote admission path hands the live WireGuard table to the
/// collision view: a peer the data plane carries holds its address even
/// when `network.toml` does not declare it (`ADRESSAGE-IPV6.md` §3 bis.2).
#[tokio::test]
async fn admission_avoids_an_address_held_in_the_live_table() {
    let (_lock, _path) = isolated_config().await;
    let (state, mut cmd_rx) = state();
    let natural = helios_provisioning::derive_cgnat_ip(&[2u8; 32], 0);
    state.peer_runtime.write().await.push(PeerStatus {
        public_key: vec![9u8; 32],
        allowed_ips: vec![format!("{natural}/32")],
        last_handshake: None,
        endpoint: None,
        rx_bytes: 0,
        tx_bytes: 0,
    });

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let probed = helios_provisioning::derive_cgnat_ip(&[2u8; 32], 1);
    assert_eq!(json["address"], format!("{probed}/32"));
    let _ = cmd_rx.recv().await;
}

/// §9 criterion 12 through the API: readmitting the same identity answers
/// with the same address and writes nothing; once the gateway has a tunnel
/// prefix, readmission declares the IPv6 VIP alone.
#[tokio::test]
async fn readmission_keeps_the_vip_and_only_adds_the_ipv6_one() {
    let (_lock, _path) = isolated_config().await;
    let (state, mut cmd_rx) = state();
    let body = format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#);
    let admit = |state: AppState| {
        let request = admin_request("/api/peers", &body);
        async move { router(state).oneshot(request).await.unwrap() }
    };

    assert_eq!(admit(state.clone()).await.status(), StatusCode::OK);
    let admitted = match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => config,
        other => panic!("unexpected command: {other:?}"),
    };
    let address = admitted.peers[1].address.clone();
    // What the orchestrator would do with it.
    *state.network.write().await = *admitted;

    let again = admit(state.clone()).await;
    assert_eq!(again.status(), StatusCode::OK);
    let body_again = to_bytes(again.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_again).unwrap();
    assert_eq!(json["address"], address.as_str());
    assert!(
        cmd_rx.try_recv().is_err(),
        "an unchanged readmission has nothing to apply"
    );

    let prefix: aether::net::TunnelPrefixV6 = "fd3c:91a2:7e04::1/64".parse().unwrap();
    state.network.write().await.wg_address_v6 = Some(prefix);
    assert_eq!(admit(state.clone()).await.status(), StatusCode::OK);
    match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => {
            let laptop = &config.peers[1];
            assert_eq!(laptop.address, address, "the IPv4 VIP is untouched");
            let iid = helios_provisioning::derive_ula_iid(&[2u8; 32], 0);
            assert_eq!(
                laptop.address_v6,
                Some(std::net::Ipv6Addr::from(
                    u128::from(prefix.network()) | u128::from(iid)
                ))
            );
            assert_eq!(
                config.peers[0]
                    .preshared_key
                    .as_ref()
                    .map(aether::SecretString::expose),
                Some(PEER_PSK),
                "the other peer's PSK survives the readmission"
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn revocation_removes_the_peer_and_refuses_an_unknown_one() {
    let (_lock, _path) = isolated_config().await;

    let (first_state, mut cmd_rx) = state();
    let response = router(first_state)
        .oneshot(admin_request(
            "/api/peers/revoke",
            r#"{"name":"workstation"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => assert!(config.peers.is_empty()),
        other => panic!("unexpected command: {other:?}"),
    }

    let (fresh_state, mut cmd_rx) = state();
    let response = router(fresh_state)
        .oneshot(admin_request("/api/peers/revoke", r#"{"name":"ghost"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(cmd_rx.try_recv().is_err());
}

/// Admission mutates the control plane: it must require the admin role,
/// like other mutations (ADR-003 §3).
#[tokio::test]
async fn admission_requires_the_admin_role() {
    let (_lock, _path) = isolated_config().await;
    let (state, mut cmd_rx) = state();
    state.network.write().await.peers[0].admin = false;

    let response = router(state)
        .oneshot(admin_request(
            "/api/peers",
            &format!(r#"{{"name":"laptop","public_key":"{NEW_KEY}",{ADMIT_IDENTITY}}}"#),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(cmd_rx.try_recv().is_err());
}

/// The ADR-004 §4 trap, on the full-reload side: a configuration read
/// back and reposted comes back without secrets, and must not erase them.
#[tokio::test]
async fn a_config_reload_loses_neither_identity_nor_psk() {
    let (_lock, _path) = isolated_config().await;
    let (state, mut cmd_rx) = state();

    let response = router(state)
        .oneshot(admin_request(
            "/api/network",
            r#"{"wan_iface":"eth1","peers":[{"name":"workstation",
                    "public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                    "address":"100.64.1.2/32","admin":true}]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => {
            assert_eq!(
                config.wan_ifaces,
                vec!["eth1".to_string()],
                "the requested setting applies"
            );
            assert_eq!(
                config.wg_private_key.expose(),
                PRIVATE_KEY,
                "the gateway's identity was erased by a plain setting change"
            );
            assert_eq!(
                config.peers[0]
                    .preshared_key
                    .as_ref()
                    .map(aether::SecretString::expose),
                Some(PEER_PSK),
                "the negotiated PSK was erased by a plain setting change"
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

/// The tunnel prefix applies at startup only (`ADRESSAGE-IPV6.md` §5.4): a
/// full reload that changes it — here, one that simply lacks the key — is
/// refused before anything is written, so the next start does not quietly
/// lose the prefix either.
#[tokio::test]
async fn a_config_reload_cannot_change_the_tunnel_prefix() {
    const PEER: &str = r#"{"name":"workstation",
        "public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "address":"100.64.1.2/32","address_v6":"fd3c:91a2:7e04::2/128","admin":true}"#;
    let (_lock, path) = isolated_config().await;

    let (state, mut cmd_rx) = state();
    {
        let mut network = state.network.write().await;
        network.wg_address_v6 = Some("fd3c:91a2:7e04::1/64".parse().unwrap());
        network.peers[0].address_v6 = Some("fd3c:91a2:7e04::2".parse().unwrap());
    }
    let response = router(state.clone())
        .oneshot(admin_request(
            "/api/network",
            &format!(r#"{{"wan_iface":"eth1","peers":[{PEER}]}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let message = String::from_utf8(body.to_vec()).unwrap();
    assert!(message.contains("wg_address_v6"), "{message}");
    assert!(
        cmd_rx.try_recv().is_err(),
        "nothing reaches the orchestrator"
    );
    assert!(!path.exists(), "nothing is written");

    // The same body with the running prefix is an ordinary reload, and the
    // peer's IPv6 VIP goes through it.
    let response = router(state)
        .oneshot(admin_request(
            "/api/network",
            &format!(
                r#"{{"wan_iface":"eth1","wg_address_v6":"fd3c:91a2:7e04::1/64",
                    "peers":[{PEER}]}}"#
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    match cmd_rx.recv().await {
        Some(OrchestratorCmd::LoadNetworkConfig(config)) => assert_eq!(
            config.peers[0].address_v6,
            Some("fd3c:91a2:7e04::2".parse().unwrap())
        ),
        other => panic!("unexpected command: {other:?}"),
    }
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("address_v6 = \"fd3c:91a2:7e04::2/128\""),
        "{written}"
    );
    assert!(!written.contains(PEER_PSK));
    let _ = std::fs::remove_file(&path);
}

/// A full reload carrying an address the firewall would refuse is answered
/// `400`, naming it, before anything is written or sent: the orchestrator
/// would keep the running configuration anyway.
#[tokio::test]
async fn a_config_reload_with_an_invalid_firewall_address_is_refused() {
    let (_lock, path) = isolated_config().await;
    let (state, mut cmd_rx) = state();

    for field in [
        r#""split_tunnel_cidrs":["192.168.1.0/24","fd00::/129"]"#,
        r#""allow_ssh_from":["fd00::/129"]"#,
    ] {
        let response = router(state.clone())
            .oneshot(admin_request(
                "/api/network",
                &format!(r#"{{"wan_iface":"eth1",{field}}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert!(message.contains("`fd00::/129`"), "{message}");
    }
    assert!(
        cmd_rx.try_recv().is_err(),
        "nothing reaches the orchestrator"
    );
    assert!(!path.exists(), "nothing is written");
}

#[tokio::test]
async fn cross_origin_json_mutation_is_refused_without_cors() {
    let (state, mut cmd_rx) = state();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tunnel/start")
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .header(header::ORIGIN, "https://malicious-site.invalid")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
    assert!(cmd_rx.try_recv().is_err());
}

/// ADR-003, amendment of 3 October 2026: the local socket serves only the
/// callers its policy admits, as administrators, and closes on the others
/// before reading a request.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_local_socket_admits_by_kernel_credentials_only() {
    use crate::local::{serve_local, AdminPolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn exchange(path: &std::path::Path, request: &str) -> String {
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        // A refused connection may already be closed: the write can fail.
        let _ = stream.write_all(request.as_bytes()).await;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        String::from_utf8_lossy(&response).into_owned()
    }

    let dir = std::env::temp_dir().join(format!("helios-local-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: plain getters of the calling process's credentials.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    let admitted = dir.join("admitted.sock");
    let (state, _commands) = state_real();
    let policy = AdminPolicy {
        admin_gid: Some(gid),
    };
    let path = admitted.clone();
    tokio::spawn(async move { serve_local(state, &path, policy).await });
    let status = exchange(
        &admitted,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let admin = exchange(
        &admitted,
        "POST /api/tunnel/stop HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    assert!(!admin.starts_with("HTTP/1.1 401"), "{admin}");
    assert!(!admin.starts_with("HTTP/1.1 403"), "{admin}");
    let mode = std::fs::metadata(&admitted).unwrap().permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o666
    );

    if uid != 0 {
        let refused = dir.join("refused.sock");
        let (state, _commands) = state_real();
        let path = refused.clone();
        let policy = AdminPolicy { admin_gid: None };
        tokio::spawn(async move { serve_local(state, &path, policy).await });
        let response = exchange(
            &refused,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.is_empty(), "a refused caller got: {response}");
    }

    let occupied = dir.join("occupied.sock");
    std::fs::write(&occupied, b"not a socket").unwrap();
    let (state, _commands) = state_real();
    let error = serve_local(state, &occupied, AdminPolicy { admin_gid: None })
        .await
        .expect_err("a non-socket file must never be replaced");
    assert!(format!("{error:#}").contains("not a socket"), "{error:#}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `/api/status` reports the daemon's release, not this crate's version:
/// the console and the operator terminal both label it `heliosd`.
#[tokio::test]
async fn status_reports_the_daemon_version() {
    let (state, _commands) = state_real();
    let response = router(state.with_daemon_version("9.9.9"))
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["version"], "9.9.9");
}

/// The CA-TLS rotation moves the anchor every client chain is judged against:
/// an admitted peer that is not an administrator must not even reach the
/// handler.
#[tokio::test]
async fn client_tls_ca_route_refuses_a_non_admin() {
    let (non_admin_state, _cmd_rx) = state();
    non_admin_state.network.write().await.peers[0].admin = false;

    let response = router(non_admin_state)
        .oneshot(admin_request(
            "/api/certificates/client-tls-ca-transition",
            "{}",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A body that is not a transition stops at the extractor: the gateway never
/// guesses what an unreadable document meant.
#[tokio::test]
async fn client_tls_ca_route_refuses_an_unreadable_body() {
    let (admin_state, _cmd_rx) = state();

    let response = router(admin_state)
        .oneshot(admin_request(
            "/api/certificates/client-tls-ca-transition",
            r#"{"not":"a transition"}"#,
        ))
        .await
        .unwrap();

    assert!(
        matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "got {}",
        response.status()
    );
}
