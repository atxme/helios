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
pub mod certificates;
pub mod embed;
pub mod health;
pub mod internal;
pub mod key_negotiation;
pub mod provision;
mod routes;
pub mod speedtest;
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
    extract::DefaultBodyLimit,
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
    /// Gateway side of the in-tunnel PSK release, `None` when the gateway
    /// runs no key-negotiation service.
    ///
    /// A trait object, and deliberately so: the API must not own a WireGuard
    /// backend — it would then be able to change the data plane from an HTTP
    /// handler. It hands an authenticated command to the state machine that
    /// owns the per-peer serializer, and learns nothing back beyond a refusal
    /// class.
    pub psk_release: Option<Arc<dyn key_negotiation::PskReleaseHandler>>,
    /// The gateway's own certificate identity, driven from the console
    /// (spec §12.2). `None` on a daemon that holds no TPM unlock material:
    /// the screen then reads the domain and offers no gesture, rather than
    /// offering one that fails at its last step.
    pub gateway_identity: Option<Arc<dyn certificates::GatewayIdentityHandler>>,
    /// Gateway side of the certificate lifecycle, `None` when the trust
    /// domain is not bootstrapped. Absent, the in-tunnel trust-update route
    /// answers `404` — the same answer an older gateway gives, so Orion has a
    /// single behaviour to implement.
    pub trust_update: Option<Arc<dyn certificates::TrustUpdateHandler>>,
    /// Gateway side of the relayed client renewal (spec §8.1.2), `None` when
    /// this gateway has no private channel to the authority. Absent, the four
    /// renewal routes answer `503` — the route exists and the client is right
    /// to use it; what is missing is the authority behind it.
    pub client_renewal: Option<Arc<dyn certificates::ClientRenewalRelay>>,
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
            psk_release: None,
            gateway_identity: None,
            trust_update: None,
            client_renewal: None,
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

    /// Wires the in-tunnel PSK release to the running key-negotiation service.
    ///
    /// A builder, like the two above: a gateway with no `key_negotiation_port`
    /// runs no such service, and must not have to name an absent value.
    pub fn with_psk_release(
        mut self,
        handler: Arc<dyn key_negotiation::PskReleaseHandler>,
    ) -> Self {
        self.psk_release = Some(handler);
        self
    }

    /// Wires the certificate lifecycle, once the trust domain exists.
    pub fn with_trust_update(mut self, handler: Arc<dyn certificates::TrustUpdateHandler>) -> Self {
        self.trust_update = Some(handler);
        self
    }

    /// Wires the gateway's own identity, once the daemon can open its vault.
    pub fn with_gateway_identity(
        mut self,
        handler: Arc<dyn certificates::GatewayIdentityHandler>,
    ) -> Self {
        self.gateway_identity = Some(handler);
        self
    }

    /// Wires the relayed client renewal, once the gateway can reach Astra.
    ///
    /// Separate from [`Self::with_trust_update`] on purpose: a gateway may hold
    /// a registry and yet have no private channel, and in that state the
    /// trust-update route must keep working while the renewal routes report
    /// that the authority is unreachable.
    pub fn with_client_renewal(mut self, relay: Arc<dyn certificates::ClientRenewalRelay>) -> Self {
        self.client_renewal = Some(relay);
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
        .route(
            "/api/certificates/gateway-renewal",
            post(certificates::gateway_renewal),
        )
        .route(
            "/api/certificates/gateway-transition",
            post(certificates::gateway_transition_install),
        )
        .route(
            "/api/certificates/gateway-transition/abort",
            post(certificates::gateway_transition_abort),
        )
        .route(
            "/api/certificates/gateway-transition/rollback",
            post(certificates::gateway_transition_rollback),
        )
        .route(
            "/api/certificates/ca-transition",
            post(certificates::ca_transition_install),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    let authenticated_peer = Router::new()
        .route("/api/provision", post(provision::provision))
        .route("/api/speedtest/ping", get(speedtest::ping))
        .route("/api/speedtest/download", get(speedtest::download))
        .route(
            "/api/speedtest/upload",
            post(speedtest::upload).layer(DefaultBodyLimit::max(speedtest::MAX_TRANSFER_BYTES)),
        )
        // Explicit teardown of a negotiated PSK, sent through the tunnel
        // before the client unmounts its adapter (spec §7.5). Behind
        // `require_peer` like provisioning: the source VIP is what ties the
        // command to a peer, and the body's key is only ever compared to it.
        .route(
            "/api/key-negotiation/release",
            // The 32 KiB bound is applied by the transport, so an oversized
            // body is refused before it is buffered — the handler's own check
            // is what keeps that guarantee true when it is called directly.
            post(key_negotiation::release).layer(DefaultBodyLimit::max(
                key_negotiation::MAX_RELEASE_BODY_BYTES,
            )),
        )
        // Certificate lifecycle inside the tunnel (spec §7 and §8.1). Same
        // `require_peer` resolution as the release: the source VIP names the
        // peer, the body only ever confirms it.
        .route(
            "/api/key-negotiation/trust-update",
            post(certificates::trust_update).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
        // Tombstone of the pre-15-August flow. Astra, not Orion, stages the
        // candidate through the private veth API; an explicit 404 also keeps
        // the SPA fallback from returning HTML with status 200.
        .route(
            "/api/key-negotiation/stage",
            post(certificates::retired_in_tunnel_stage),
        )
        .route(
            "/api/key-negotiation/stage-commit",
            post(certificates::stage_commit).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
        // The relayed ordinary renewal (spec §8.1.2). Four routes, all behind
        // the same source-VIP resolution: a peer opens an operation, polls it,
        // and passes its companion through the two `signer-*` exchanges. None
        // of them reaches Astra's public origin, and none of them is a proxy —
        // each accepts one type, one size, and relays an object the gateway
        // built itself.
        .route(
            "/api/key-negotiation/certificate-renewal/request",
            post(certificates::renewal_request).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
        .route(
            "/api/key-negotiation/certificate-renewal/operations/:operation",
            get(certificates::renewal_operation),
        )
        .route(
            "/api/key-negotiation/certificate-renewal/signer-requests/:operation",
            get(certificates::renewal_signer_request),
        )
        .route(
            "/api/key-negotiation/certificate-renewal/signer-results/:operation",
            post(certificates::renewal_signer_result).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
        // The commit of §8.1.2 is the route above under its historical path.
        // Both are mounted on the same handler: the spec's list names the
        // renewal prefix, and a client already built against the shorter path
        // must not stop committing because a path moved.
        .route(
            "/api/key-negotiation/certificate-renewal/stage-commit",
            post(certificates::stage_commit).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
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
        // What a profile must carry for its holder to renew (spec §19). An
        // operator read, on the admin surface: it is consulted while the
        // client is being enrolled, hence before it has any tunnel.
        .route(
            "/api/key-negotiation/trust-enrolment/:public_key",
            get(certificates::trust_enrolment),
        )
        // The domain as the operator console reads it. On the admin surface
        // rather than in the tunnel: it reports every admitted peer, which is
        // exactly what no client may learn about its neighbours.
        .route("/api/certificates", get(certificates::domain))
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
    ) && request.uri().path() != "/api/speedtest/upload"
        && !request
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
            wan_ifaces: vec!["eth0".into()],
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
                assert_eq!(
                    config.wan_ifaces,
                    vec!["eth1".to_string()],
                    "the requested setting applies"
                );
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
