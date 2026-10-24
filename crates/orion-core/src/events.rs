//! Events emitted by the client core toward the UI (via the Tauri shell).
//!
//! Shape aligned with [`aether::HeliosEvent`] so the frontend shares the same
//! TypeScript types as heliosd's web app.

use aether::TunnelState;
use serde::{Deserialize, Serialize};

/// What occupies the `PresharedKey` slot of the current tunnel.
///
/// **A PSK is not a PQC PSK.** Both live in the same WireGuard slot and look
/// alike on disk — 32 bytes in base64 — but don't mean the same thing: one
/// was copied by hand into the profile, the other comes from an ML-KEM-1024
/// exchange conducted on every connection. The profile alone can't
/// distinguish them, since the negotiated PSK is never persisted; only the
/// client core knows which one it set, hence this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PskKind {
    /// Empty slot: confidentiality relies on Curve25519 alone.
    None,
    /// Static PSK entered in the profile, shared out of band. It holds up
    /// against "harvest now, decrypt later", but it doesn't rotate and its
    /// presence disables ML-KEM negotiation.
    Static,
    /// PSK derived from an ML-KEM-1024 exchange on this connection, and
    /// renewed on the next one.
    MlKem,
}

/// Whether the mounted adapter really captures what the profile asked for.
///
/// `AllowedIPs` is the whole of Orion's protection (ADR-001 §3 bis): what the
/// adapter does not capture leaves through the physical interface, tunnel up
/// or not. And the driver may apply less than it was given —
/// `defguard_wireguard_rs` on Windows drops the prefixes of an address family
/// the adapter does not carry, without an error. Only a read-back of what was
/// applied tells the two situations apart, hence this event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CaptureCheck {
    /// Every requested prefix and address was read back from the adapter.
    Complete,
    /// What the adapter does not carry. At least one of the two lists is
    /// non-empty.
    Incomplete {
        /// Requested prefixes the adapter does not capture, in the profile's
        /// order and canonical form (`::/0`, `10.0.0.0/8`).
        missing: Vec<String>,
        /// Addresses of the profile the driver did not put on the adapter
        /// (`fd3c:91a2:7e04::2/128`), in the profile's order. `defguard`
        /// skips the addresses of a family the adapter lacks exactly as it
        /// skips its prefixes, and as silently (`ADRESSAGE-IPV6.md` §7.3).
        missing_addresses: Vec<String>,
    },
    /// The applied configuration could not be read back. Not "fine": the
    /// capture is unknown, and the reason says which read failed.
    Unverified { reason: String },
}

/// Real-time event pushed to the frontend (`emit("helios://event", …)`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    /// Tunnel state transition.
    StateChanged { state: TunnelState },
    /// The actual kind of PSK set, once the question is settled for the
    /// current connection. The UI can't guess it from the profile.
    Protection { psk: PskKind },
    /// What the adapter really captures, read back after each configuration.
    /// Only a backend able to read it back emits it: the simulation verifies
    /// nothing, so it claims nothing.
    Capture { capture: CaptureCheck },
    /// A PSK renewal started (`true`) or ended, whatever its outcome
    /// (`false`). The UI withholds its renewal action in between.
    Renewal { in_flight: bool },
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

    /// Shortcut for a capture verdict.
    pub fn capture(capture: CaptureCheck) -> Self {
        ClientEvent::Capture { capture }
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

    #[test]
    fn a_renewal_announcement_serializes_its_flag() {
        let json = serde_json::to_value(ClientEvent::Renewal { in_flight: true }).unwrap();
        assert_eq!(json["type"], "renewal");
        assert_eq!(json["in_flight"], true);
    }

    #[test]
    fn the_capture_verdict_serializes_with_its_status() {
        let json = serde_json::to_value(ClientEvent::capture(CaptureCheck::Incomplete {
            missing: vec!["::/0".into()],
            missing_addresses: vec!["fd3c:91a2:7e04::2/128".into()],
        }))
        .unwrap();
        assert_eq!(json["type"], "capture");
        assert_eq!(json["capture"]["status"], "incomplete");
        assert_eq!(json["capture"]["missing"][0], "::/0");
        assert_eq!(
            json["capture"]["missing_addresses"][0],
            "fd3c:91a2:7e04::2/128"
        );

        let json = serde_json::to_value(ClientEvent::capture(CaptureCheck::Complete)).unwrap();
        assert_eq!(json["capture"]["status"], "complete");

        let json = serde_json::to_value(ClientEvent::capture(CaptureCheck::Unverified {
            reason: "lecture impossible".into(),
        }))
        .unwrap();
        assert_eq!(json["capture"]["status"], "unverified");
        assert_eq!(json["capture"]["reason"], "lecture impossible");
    }
}
