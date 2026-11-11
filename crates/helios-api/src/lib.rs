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
pub mod key_negotiation;
#[cfg(target_os = "linux")]
pub mod local;
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
    net::Ipv6TunnelStatus, FirewallPolicy, HeliosEvent, InstallPskRequest, NetworkConfig,
    OrchestratorCmd, TunnelState,
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
    /// The relay for operator campaigns inside the tunnel (spec §8.5).
    ///
    /// Separate from `client_renewal` because the two surfaces are separate:
    /// one is a peer's own renewal, the other an authority ceremony an
    /// administrator makes circulate. `None` is a gateway with no private
    /// channel, and its routes answer `503`.
    pub operator_campaign: Option<Arc<dyn certificates::OperatorCampaignRelay>>,
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
    /// Release of the daemon serving this API, reported by `/api/status`.
    pub daemon_version: &'static str,
    /// What the orchestrator's last bring-up did with the IPv6 tunnel prefix,
    /// published the same way as [`Self::peer_runtime`]: the API reports it
    /// and cannot change it (`ADRESSAGE-IPV6.md` §6.2).
    pub ipv6: Arc<RwLock<Ipv6TunnelStatus>>,
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
            operator_campaign: None,
            tpm: None,
            peer_runtime: Arc::new(RwLock::new(Vec::new())),
            // Visible rather than wrong when a binary forgets to name itself:
            // this crate's own version is not the gateway's release.
            daemon_version: "unknown",
            ipv6: Arc::new(RwLock::new(Ipv6TunnelStatus::default())),
        }
    }

    /// Names the daemon release that `/api/status` reports.
    pub fn with_daemon_version(mut self, version: &'static str) -> Self {
        self.daemon_version = version;
        self
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
    pub fn with_operator_campaign(
        mut self,
        relay: Arc<dyn certificates::OperatorCampaignRelay>,
    ) -> Self {
        self.operator_campaign = Some(relay);
        self
    }

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
            get(certificates::gateway_renewal_request).post(certificates::gateway_renewal),
        )
        .route(
            "/api/certificates/gateway-renewal/tls",
            get(certificates::gateway_candidate_tls),
        )
        .route(
            "/api/certificates/gateway-transition",
            get(certificates::gateway_transition_staged)
                .post(certificates::gateway_transition_install),
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
        .route(
            "/api/certificates/client-tls-ca-transition",
            post(certificates::client_tls_ca_transition_install),
        )
        // The operator campaign, relayed from inside the tunnel (spec §8.5).
        // The surfaces Astra's public origin exposes, plus the opening, which
        // that origin refuses and Astra's door serves privately (lot 5a). On
        // the **admin** surface rather than the peer one: a campaign belongs
        // to no peer, and letting any admitted peer make one circulate is the
        // distinction this placement exists to draw. None of them is a proxy —
        // each accepts one type, one size, and relays an object this gateway
        // built itself.
        .route(
            "/api/certificates/operator/pending",
            get(certificates::operator_pending),
        )
        .route(
            "/api/certificates/operator/status",
            get(certificates::operator_status),
        )
        .route(
            "/api/certificates/operator/operations/{operation}",
            get(certificates::operator_operation),
        )
        .route(
            "/api/certificates/operator/signer-requests/{operation}",
            get(certificates::operator_signer_request),
        )
        .route(
            "/api/certificates/operator/vaults/{fingerprint}",
            get(certificates::operator_vault),
        )
        .route(
            "/api/certificates/operator/signer-results/{operation}",
            post(certificates::operator_signer_result).layer(DefaultBodyLimit::max(
                astra_channel::MAX_OPERATOR_REQUEST_BYTES,
            )),
        )
        // Its own body bound: the vault travels in base64 beside the
        // credential document, and 64 KiB would refuse every real one.
        .route(
            "/api/certificates/operator/vault-copy",
            post(certificates::operator_vault_copy).layer(DefaultBodyLimit::max(
                astra_channel::MAX_OPERATOR_VAULT_COPY_BODY_BYTES,
            )),
        )
        .route(
            "/api/certificates/operator/gateway-identity/publish",
            post(certificates::operator_gateway_publish).layer(DefaultBodyLimit::max(
                astra_channel::MAX_OPERATOR_REQUEST_BYTES,
            )),
        )
        .route(
            "/api/certificates/operator/campaigns",
            post(certificates::operator_open).layer(DefaultBodyLimit::max(
                astra_channel::MAX_OPERATOR_REQUEST_BYTES,
            )),
        )
        .route(
            "/api/certificates/operator/chain/next",
            post(certificates::operator_chain_next),
        )
        .route(
            "/api/certificates/operator/chain/abandon",
            post(certificates::operator_chain_abandon),
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
                aether::certificates::transport::MAX_STAGE_COMMIT_REQUEST_BYTES,
            )),
        )
        // The relayed ordinary renewal (spec §8.1.2). A peer opens an
        // operation, polls it, then commits the resulting grant. The 80 %
        // path has no operator-companion exchange.
        .route(
            "/api/key-negotiation/certificate-renewal/request",
            post(certificates::renewal_request).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES,
            )),
        )
        .route(
            "/api/key-negotiation/certificate-renewal/operations/{operation}",
            get(certificates::renewal_operation),
        )
        // The commit of §8.1.2 is the route above under its historical path.
        // Both are mounted on the same handler: the spec's list names the
        // renewal prefix, and a client already built against the shorter path
        // must not stop committing because a path moved.
        .route(
            "/api/key-negotiation/certificate-renewal/stage-commit",
            post(certificates::stage_commit).layer(DefaultBodyLimit::max(
                aether::certificates::transport::MAX_STAGE_COMMIT_REQUEST_BYTES,
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
            "/api/key-negotiation/trust-enrolment/{public_key}",
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
pub async fn serve(state: AppState, bind: std::net::SocketAddr) -> anyhow::Result<()> {
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
mod security_tests;
