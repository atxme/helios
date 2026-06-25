//! Événements émis par le cœur client vers l'IHM (via le shell Tauri).
//!
//! Forme alignée sur [`helios_core::HeliosEvent`] pour que le frontend partage
//! les mêmes types TypeScript que l'app web de heliosd.

use helios_core::TunnelState;
use serde::Serialize;

/// Événement temps réel poussé vers le frontend (`emit("helios://event", …)`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    /// Transition de l'état du tunnel.
    StateChanged { state: TunnelState },
    /// Ligne de journal à afficher dans l'IHM.
    Log { level: String, message: String },
    /// Compteurs réseau relayés depuis la télémétrie heliosd (post-tunnel).
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
    /// Erreur non fatale remontée à l'utilisateur.
    Error { message: String },
}

impl ClientEvent {
    /// Raccourci pour un événement de journal.
    pub fn log(level: &str, message: impl Into<String>) -> Self {
        ClientEvent::Log {
            level: level.to_string(),
            message: message.into(),
        }
    }

    /// Raccourci pour une transition d'état.
    pub fn state(state: TunnelState) -> Self {
        ClientEvent::StateChanged { state }
    }
}
