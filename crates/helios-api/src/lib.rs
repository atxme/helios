//! Control-plane HTTP server: REST + WebSocket + static web interface.
//!
//! ## Architecture
//!
//! ```text
//! browser ──GET /──────────────────► static React files (embedded or 503)
//! browser ──GET /api/status────────► JSON current state
//! browser ──GET /api/trust─────────► publisher trust anchor (ADR-002)
//! browser ──GET /api/network───────► JSON current network config
//! browser ──POST /api/network──────► hot-reloads the network config (JSON)
//! browser ──POST /api/peers────────► admits a peer, derived VIP (ADR-004)
//! browser ──POST /api/tunnel/start► command to the orchestrator (mpsc)
//! browser ──WS /ws─────────────────► real-time event stream (broadcast)
//! ```
//!
//! [`AppState`] is the shared pivot: it carries the event channel
//! (broadcast), the command channel (mpsc), and the current tunnel state
//! (RwLock shared with the orchestrator).

pub mod auth;
pub mod embed;
pub mod health;
pub mod provision;
mod routes;
pub mod update;
pub mod ws;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use aether::{
    FirewallPolicy, HeliosEvent, InstallPskRequest, NetworkConfig, OrchestratorCmd, TunnelState,
};
use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use helios_wireguard::PeerStatus;
use tokio::sync::{broadcast, mpsc, RwLock};

/// State shared across all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Current tunnel state, updated by the orchestrator.
    pub tunnel_state: Arc<RwLock<TunnelState>>,
    /// Event emitter towards WebSocket clients.
    pub event_tx: broadcast::Sender<HeliosEvent>,
    /// Command channel towards the orchestrator (Start/Stop from the UI).
    pub cmd_tx: mpsc::Sender<OrchestratorCmd>,
    /// Provisioning channel: installs the post-quantum PSK on the data
    /// plane. Kept separate from `cmd_tx` because it carries a secret and
    /// waits for an acknowledgement (see [`aether::InstallPskRequest`]).
    pub psk_tx: mpsc::Sender<InstallPskRequest>,
    /// Current network configuration (hot-reloadable).
    pub network: Arc<RwLock<NetworkConfig>>,
    /// `true` = daemon running in simulation mode (WSL2 or --dev).
    pub dry_run: bool,
    /// Current firewall policy (updated by the orchestrator).
    pub policy: Arc<RwLock<FirewallPolicy>>,
    /// Signed application update staging. Privileged installation stays
    /// outside the API process.
    pub updates: helios_update::UpdateStore,
    /// True as soon as the API socket is actually bound. The update health
    /// check must not confirm a daemon whose UI would still be absent.
    pub api_ready: Arc<AtomicBool>,
    /// Public material of the key-negotiation service, `None` when the
    /// gateway does not run it. Published so the operator tooling can build
    /// a complete Orion profile from the gateway itself, instead of copying
    /// certificate files off `/var/lib/helios` by hand.
    pub key_negotiation: Option<Arc<KeyNegotiationMaterial>>,
    /// Non-secret summary of the boot-time sealing decision, `None` when the
    /// daemon runs without TPM validation. A projection: `BootDecision` itself
    /// carries the unlock secret and must not reach this crate.
    pub tpm: Option<health::TpmSummary>,
    /// Last observation of the data plane, written by the orchestrator's
    /// handshake poller.
    ///
    /// The API holds no WireGuard backend — it must not, it would then be able
    /// to change the data plane from an HTTP handler. So the runtime arrives
    /// the same way the tunnel state and the firewall policy do: a snapshot
    /// the orchestrator publishes. It is emptied when the interface goes down,
    /// because a stale list of "connected" peers is worse than no list.
    pub peer_runtime: Arc<RwLock<Vec<PeerStatus>>>,
}

/// Public key-negotiation material, exactly as an Orion profile pins it.
///
/// Everything here is a **certificate**: public by construction. The TLS and
/// ML-DSA private keys stay sealed to the TPM and never reach this process's
/// serialization path — which is why this type holds bytes it read from the
/// public files, not the identity the service runs on.
pub struct KeyNegotiationMaterial {
    /// DER gateway certificate, used by Orion as its trust anchor.
    pub certificate_der: Vec<u8>,
    /// JSON ML-DSA-65 gateway certificate, as written on disk.
    pub pq_certificate_json: Vec<u8>,
}

impl AppState {
    pub fn new(
        network: Arc<RwLock<NetworkConfig>>,
        dry_run: bool,
        tunnel_state: Arc<RwLock<TunnelState>>,
        event_tx: broadcast::Sender<HeliosEvent>,
        cmd_tx: mpsc::Sender<OrchestratorCmd>,
        psk_tx: mpsc::Sender<InstallPskRequest>,
        policy: Arc<RwLock<FirewallPolicy>>,
    ) -> Self {
        Self {
            tunnel_state,
            event_tx,
            cmd_tx,
            psk_tx,
            network,
            dry_run,
            policy,
            updates: helios_update::UpdateStore::new(helios_update::UpdateLayout::for_daemon(
                dry_run,
            )),
            api_ready: Arc::new(AtomicBool::new(false)),
            key_negotiation: None,
            tpm: None,
            peer_runtime: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Publishes the gateway's sealing posture, without its secret.
    ///
    /// A builder rather than a `new` parameter: a daemon built without the
    /// `tpm` feature, or started with validation disabled, is the ordinary
    /// case in development and must not have to name an absent value.
    pub fn with_tpm(mut self, kind: &'static str, preserved_vaults: bool) -> Self {
        self.tpm = Some(health::TpmSummary {
            kind,
            preserved_vaults,
        });
        self
    }

    /// Publishes the key-negotiation certificates read from disk at startup.
    ///
    /// A builder rather than a `new` parameter: a gateway built without the
    /// feature, or not yet initialized, is the ordinary case and must not
    /// have to name an absent value.
    pub fn with_key_negotiation(mut self, material: KeyNegotiationMaterial) -> Self {
        self.key_negotiation = Some(Arc::new(material));
        self
    }
}

/// Builds the complete HTTP router.
///
/// Exposed separately from [`serve`] so that integration tests exercise the
/// same routes and middlewares as the real binary.
pub fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/network", post(routes::network_set))
        .route("/api/peers", post(routes::peer_admit))
        .route("/api/peers/revoke", post(routes::peer_revoke))
        .route("/api/gateway/wireguard-key", post(routes::gateway_key_set))
        .route("/api/tunnel/start", post(routes::tunnel_start))
        .route("/api/tunnel/stop", post(routes::tunnel_stop))
        .route("/api/firewall/rules", post(routes::firewall_rules_apply))
        .route(
            "/api/captive-portal/release",
            post(routes::captive_portal_release),
        )
        .route("/api/split-tunnel", post(routes::split_tunnel_set))
        .route("/api/update", get(update::status))
        .route("/api/update/stage", post(update::stage))
        .route("/api/update/chunk", post(update::chunk))
        .route("/api/update/finalize", post(update::finalize))
        .route("/api/update/activate", post(update::activate))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    let authenticated_peer = Router::new()
        .route("/api/provision", post(provision::provision))
        .route("/ws", get(ws::handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_peer,
        ));

    Router::new()
        .route("/api/status", get(routes::status))
        // Publisher trust anchor compiled into the binary (ADR-002).
        .route("/api/trust", get(routes::trust))
        .route("/api/health", get(health::health))
        .route("/api/network", get(routes::network_get))
        .route("/api/key-negotiation", get(routes::key_negotiation_get))
        .route("/api/firewall/rules", get(routes::firewall_rules_get))
        .merge(admin)
        .merge(authenticated_peer)
        .fallback(embed::static_handler)
        .layer(middleware::from_fn(require_json_for_mutations))
        .with_state(state)
}

/// CSRF barrier: a third-party HTML form can issue a simple POST, but not a
/// `application/json` POST without a CORS preflight. Since the server
/// publishes no CORS header, this combination blocks cross-origin web
/// commands while still allowing native clients and the same-origin frontend.
async fn require_json_for_mutations(request: Request<Body>, next: Next) -> Response {
    if matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH
    ) && !request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    next.run(request).await
}

/// Launches the HTTP server and blocks until it stops.
pub async fn serve(state: AppState, bind: &str) -> anyhow::Result<()> {
    let app = router(state.clone());

    let listener = tokio::net::TcpListener::bind(bind).await?;
    state.api_ready.store(true, Ordering::Release);
    tracing::info!("web interface available at http://{}", bind);
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await;
    state.api_ready.store(false, Ordering::Release);
    result.map_err(Into::into)
}

#[cfg(test)]
mod security_tests {
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
            wan_iface: "eth0".into(),
            admin_iface: Some("helios0".into()),
            wg_private_key: PRIVATE_KEY.into(),
            peers: vec![aether::WgPeer {
                name: "workstation".into(),
                public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                address: "100.64.1.2/32".into(),
                admin: true,
                preshared_key: Some(PEER_PSK.into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
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
        let path =
            std::env::temp_dir().join(format!("helios-api-network-{}.toml", std::process::id()));
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
                    config.wg_private_key, PRIVATE_KEY,
                    "the orchestrator must keep the resolved identity"
                );
                assert_eq!(
                    config.peers[0].preshared_key.as_deref(),
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
                assert_eq!(config.wan_iface, "eth1", "the requested setting applies");
                assert_eq!(
                    config.wg_private_key, PRIVATE_KEY,
                    "the gateway's identity was erased by a plain setting change"
                );
                assert_eq!(
                    config.peers[0].preshared_key.as_deref(),
                    Some(PEER_PSK),
                    "the negotiated PSK was erased by a plain setting change"
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
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
}
