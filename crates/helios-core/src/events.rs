use serde::Serialize;

use crate::state::TunnelState;

/// Événements diffusés aux abonnés (WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeliosEvent {
    StateChanged { state: TunnelState },
    Log { level: String, message: String },
    /// Compteurs réseau lus depuis /proc/net/dev, émis toutes les secondes.
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
}

/// Commandes envoyées par l'interface web vers l'orchestrateur.
#[derive(Debug, Clone)]
pub enum OrchestratorCmd {
    Connect,
    Disconnect,
}
