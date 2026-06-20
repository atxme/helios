//! Serveur HTTP du plan de contrôle : REST + WebSocket + interface web statique.
//!
//! ## Architecture
//!
//! ```text
//! navigateur ──GET /──────────────────► fichiers statiques React (embed ou 404)
//! navigateur ──GET /api/status────────► JSON état courant
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

use helios_core::{Config, HeliosEvent, OrchestratorCmd, TunnelState};
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
    pub config: Arc<Config>,
    /// Propositions IKE/ESP effectives si surchargées par l'UI (ike, esp).
    /// `None` = utiliser les valeurs de la config.
    pub effective_proposals: Arc<RwLock<Option<(String, String)>>>,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        tunnel_state: Arc<RwLock<TunnelState>>,
        event_tx: broadcast::Sender<HeliosEvent>,
        cmd_tx: mpsc::Sender<OrchestratorCmd>,
        effective_proposals: Arc<RwLock<Option<(String, String)>>>,
    ) -> Self {
        Self { tunnel_state, event_tx, cmd_tx, config, effective_proposals }
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
        .route("/api/tunnel/start", post(routes::tunnel_start))
        .route("/api/tunnel/stop", post(routes::tunnel_stop))
        .route("/api/connections/apply", post(routes::connection_apply))
        .route("/api/firewall/rules", get(routes::firewall_rules_get))
        .route("/api/firewall/rules", post(routes::firewall_rules_apply))
        .route("/ws", get(ws::handler))
        .fallback(embed::static_handler)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("interface web disponible sur http://{}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
