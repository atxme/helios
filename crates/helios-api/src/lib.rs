//! Serveur HTTP du plan de contrôle : REST + WebSocket + interface web statique.
//!
//! ## Architecture
//!
//! ```text
//! navigateur ──GET /──────────────────► fichiers statiques React (embed ou 503)
//! navigateur ──GET /api/status────────► JSON état courant
//! navigateur ──GET /api/trust─────────► ancre de confiance éditeur (ADR-002)
//! navigateur ──GET /api/network───────► JSON config réseau courante
//! navigateur ──POST /api/network──────► recharge la config réseau (JSON)
//! navigateur ──POST /api/tunnel/start► commande vers l'orchestrateur (mpsc)
//! navigateur ──WS /ws─────────────────► flux d'événements temps réel (broadcast)
//! ```
//!
//! [`AppState`] est le pivot partagé : il porte le canal d'événements
//! (broadcast), le canal de commandes (mpsc) et l'état courant du tunnel
//! (RwLock partagé avec l'orchestrateur).

pub mod embed;
pub mod provision;
pub mod routes;
pub mod ws;

use std::sync::Arc;

use aether::{FirewallPolicy, HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelState};
use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use tokio::sync::{broadcast, mpsc, RwLock};

/// État partagé entre tous les handlers Axum.
#[derive(Clone)]
pub struct AppState {
    /// État courant du tunnel, mis à jour par l'orchestrateur.
    pub tunnel_state: Arc<RwLock<TunnelState>>,
    /// Émetteur d'événements vers les clients WebSocket.
    pub event_tx: broadcast::Sender<HeliosEvent>,
    /// Canal de commandes vers l'orchestrateur (Start/Stop depuis l'UI).
    pub cmd_tx: mpsc::Sender<OrchestratorCmd>,
    /// Configuration réseau courante (rechargeable à chaud).
    pub network: Arc<RwLock<NetworkConfig>>,
    /// `true` = daemon en mode simulation (WSL2 ou --dev).
    pub dry_run: bool,
    /// Politique de pare-feu courante (mise à jour par l'orchestrateur).
    pub policy: Arc<RwLock<FirewallPolicy>>,
}

impl AppState {
    pub fn new(
        network: Arc<RwLock<NetworkConfig>>,
        dry_run: bool,
        tunnel_state: Arc<RwLock<TunnelState>>,
        event_tx: broadcast::Sender<HeliosEvent>,
        cmd_tx: mpsc::Sender<OrchestratorCmd>,
        policy: Arc<RwLock<FirewallPolicy>>,
    ) -> Self {
        Self {
            tunnel_state,
            event_tx,
            cmd_tx,
            network,
            dry_run,
            policy,
        }
    }
}

/// Construit le routeur HTTP complet.
///
/// Exposé séparément de [`serve`] afin que les tests d'intégration traversent
/// les mêmes routes et middlewares que le binaire réel.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/status", get(routes::status))
        // Ancre de confiance éditeur compilée dans le binaire (ADR-002).
        .route("/api/trust", get(routes::trust))
        .route("/api/network", get(routes::network_get))
        .route("/api/network", post(routes::network_set))
        // Provisioning : joignable uniquement dans le tunnel, comme le reste.
        .route("/api/provision", post(provision::provision))
        // Rotation de l'identité WireGuard de la gateway — tunnel uniquement.
        .route("/api/gateway/wireguard-key", post(routes::gateway_key_set))
        .route("/api/tunnel/start", post(routes::tunnel_start))
        .route("/api/tunnel/stop", post(routes::tunnel_stop))
        .route("/api/firewall/rules", get(routes::firewall_rules_get))
        .route("/api/firewall/rules", post(routes::firewall_rules_apply))
        .route(
            "/api/captive-portal/release",
            post(routes::captive_portal_release),
        )
        .route("/api/split-tunnel", post(routes::split_tunnel_set))
        .route("/ws", get(ws::handler))
        .fallback(embed::static_handler)
        .layer(middleware::from_fn(require_json_for_mutations))
        .with_state(state)
}

/// Barrière CSRF : un formulaire HTML tiers peut émettre un POST simple, mais
/// pas un POST `application/json` sans pré-vérification CORS. Comme le serveur
/// ne publie aucun en-tête CORS, cette combinaison interdit les commandes web
/// cross-origin tout en conservant les clients natifs et le frontend same-origin.
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

/// Lance le serveur HTTP et bloque jusqu'à son arrêt.
pub async fn serve(state: AppState, bind: &str) -> anyhow::Result<()> {
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("interface web disponible sur http://{}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request},
    };
    use tower::ServiceExt;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PEER_PSK: &str = "psk-ultra-secret-ne-doit-jamais-sortir";

    fn state() -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
        let network = NetworkConfig {
            wan_iface: "eth0".into(),
            admin_iface: Some("helios0".into()),
            wg_private_key: PRIVATE_KEY.into(),
            peers: vec![aether::WgPeer {
                name: "poste".into(),
                public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                address: "100.64.1.2/32".into(),
                preshared_key: Some(PEER_PSK.into()),
            }],
            ..NetworkConfig::default()
        };
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        (
            AppState::new(
                Arc::new(RwLock::new(network)),
                true,
                Arc::new(RwLock::new(TunnelState::Down)),
                event_tx,
                cmd_tx,
                Arc::new(RwLock::new(policy)),
            ),
            cmd_rx,
        )
    }

    #[tokio::test]
    async fn get_network_est_redige_dans_le_routeur_reel() {
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
    }

    #[tokio::test]
    async fn mutations_refusent_formulaire_et_post_sans_type_json() {
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
    async fn mutation_json_est_transmise_sans_cors_permissif() {
        let (state, mut cmd_rx) = state();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/tunnel/start")
                    .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                    .header(header::ORIGIN, "https://site-malveillant.invalid")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
        assert!(matches!(
            cmd_rx.recv().await,
            Some(OrchestratorCmd::Connect)
        ));
    }
}
