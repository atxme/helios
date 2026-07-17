//! Serveur HTTP du plan de contrôle : REST + WebSocket + interface web statique.
//!
//! ## Architecture
//!
//! ```text
//! navigateur ──GET /──────────────────► fichiers statiques React (embed ou 503)
//! navigateur ──GET /api/status────────► JSON état courant
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
pub mod routes;
pub mod ws;

use std::sync::Arc;

use aether::{FirewallPolicy, HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelState};
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
        Self { tunnel_state, event_tx, cmd_tx, network, dry_run, policy }
    }
}

/// Lance le serveur HTTP et bloque jusqu'à son arrêt.
pub async fn serve(state: AppState, bind: &str) -> anyhow::Result<()> {
    use axum::{
        routing::{get, post},
        Router,
    };
    use tower_http::cors::CorsLayer;

    let app = Router::new()
        .route("/api/status", get(routes::status))
        .route("/api/network", get(routes::network_get))
        .route("/api/network", post(routes::network_set))
        .route("/api/tunnel/start", post(routes::tunnel_start))
        .route("/api/tunnel/stop", post(routes::tunnel_stop))
        .route("/api/firewall/rules", get(routes::firewall_rules_get))
        .route("/api/firewall/rules", post(routes::firewall_rules_apply))
        .route("/api/captive-portal/release", post(routes::captive_portal_release))
        .route("/api/split-tunnel", post(routes::split_tunnel_set))
        .route("/ws", get(ws::handler))
        .fallback(embed::static_handler)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("interface web disponible sur http://{}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
