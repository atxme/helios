//! Events emitted by the client core toward the UI (via the Tauri shell).
//!
//! Shape aligned with [`aether::HeliosEvent`] so the frontend shares the same
//! TypeScript types as heliosd's web app.

use aether::TunnelState;
use serde::Serialize;

/// What occupies the `PresharedKey` slot of the current tunnel.
///
/// **A PSK is not a PQC PSK.** Both live in the same WireGuard slot and look
/// alike on disk — 32 bytes in base64 — but don't mean the same thing: one
/// was copied by hand into the profile, the other comes from an ML-KEM-768
/// exchange conducted on every connection. The profile alone can't
/// distinguish them, since the negotiated PSK is never persisted; only the
/// client core knows which one it set, hence this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PskKind {
    /// Empty slot: confidentiality relies on Curve25519 alone.
    None,
    /// Static PSK entered in the profile, shared out of band. It holds up
    /// against "harvest now, decrypt later", but it doesn't rotate and its
    /// presence disables ML-KEM negotiation.
    Static,
    /// PSK derived from an ML-KEM-768 exchange on this connection, and
    /// renewed on the next one.
    MlKem,
}

/// Real-time event pushed to the frontend (`emit("helios://event", …)`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    /// Tunnel state transition.
    StateChanged { state: TunnelState },
    /// The actual kind of PSK set, once the question is settled for the
    /// current connection. The UI can't guess it from the profile.
    Protection { psk: PskKind },
    /// Log line to display in the UI.
    Log { level: String, message: String },
    /// Network counters relayed from heliosd telemetry (post-tunnel).
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
    /// Non-fatal error surfaced to the user.
    Error { message: String },
}

impl ClientEvent {
    /// Shortcut for a log event.
    pub fn log(level: &str, message: impl Into<String>) -> Self {
        ClientEvent::Log {
            level: level.to_string(),
            message: message.into(),
        }
    }

    /// Shortcut for a state transition.
    pub fn state(state: TunnelState) -> Self {
        ClientEvent::StateChanged { state }
    }

    /// Shortcut for a protection announcement.
    pub fn protection(psk: PskKind) -> Self {
        ClientEvent::Protection { psk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_psk_kind_serializes_in_snake_case() {
        let json = serde_json::to_value(ClientEvent::protection(PskKind::MlKem)).unwrap();
        assert_eq!(json["type"], "protection");
        assert_eq!(json["psk"], "ml_kem");

        let json = serde_json::to_value(ClientEvent::protection(PskKind::Static)).unwrap();
        assert_eq!(json["psk"], "static");

        let json = serde_json::to_value(ClientEvent::protection(PskKind::None)).unwrap();
        assert_eq!(json["psk"], "none");
    }
}
