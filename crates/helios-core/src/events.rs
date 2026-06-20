use serde::Serialize;

use crate::state::TunnelState;

/// Événements diffusés aux abonnés (WebSocket, future télémétrie).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeliosEvent {
    StateChanged { state: TunnelState },
    /// Réservé à la télémétrie : entrées de journal structurées.
    Log { level: String, message: String },
}

/// Commandes envoyées par l'interface web vers l'orchestrateur.
#[derive(Debug, Clone)]
pub enum OrchestratorCmd {
    Connect,
    Disconnect,
}
