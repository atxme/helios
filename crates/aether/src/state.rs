use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};

/// Operational state of the WireGuard tunnel.
///
/// Security invariant (gateway): LAN traffic is allowed out ONLY when the
/// tunnel is [`TunnelState::Up`]. In any other state, the kill-switch is
/// engaged ("fail-closed").
///
/// WireGuard is connectionless: there is no observable "rekeying in
/// progress" state (rekeying is transparent, roughly every 2 min). The `Up`
/// state is *inferred* from a recent handshake (`last_handshake_time`,
/// threshold ~150 s), not received as a control-plane event — see ADR-001 §3.
///
/// Controlled exception: [`TunnelState::CaptivePortal`] partially lifts the
/// kill-switch (HTTP/HTTPS to the local gateway only) while the user accepts
/// the captive portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    #[default]
    /// No tunnel. Kill-switch ACTIVE.
    Down,
    /// Tunnel being established. Kill-switch ACTIVE.
    ///
    /// Also covers WireGuard's two-step ramp-up window: classic tunnel up
    /// (Curve25519 keys) but post-quantum PSK not yet installed. Traffic
    /// stays blocked until the transition to `Up` (ADR-001, sequence).
    Connecting,
    /// Recent WireGuard handshake: traffic allowed through the tunnel.
    Up,
    /// Failure. Kill-switch ACTIVE.
    Failed,
    /// Captive portal intercepting traffic: partial kill-switch
    /// (HTTP/HTTPS to the local gateway allowed, everything else blocked).
    CaptivePortal,
}

/// Events driving the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// Ramp-up requested (UI or startup).
    StartRequested,
    /// Fresh WireGuard handshake observed (polling) *and* PSK in place →
    /// tunnel fully operational.
    HandshakeEstablished,
    /// No more recent handshake (polling): the tunnel is no longer
    /// considered `Up`, falling back to a re-establishment attempt. Not a
    /// hard failure.
    HandshakeExpired,
    /// Explicit teardown.
    Disconnected,
    /// Error: back to fail-closed.
    Error,
    /// Captive portal detected — HTTP intercepted on the current network.
    CaptivePortalDetected,
    /// The user validated the captive portal — attempt a reconnection.
    CaptivePortalResolved,
}

impl TunnelState {
    /// Is user traffic (LAN -> WAN) allowed in this state?
    pub fn traffic_allowed(self) -> bool {
        matches!(self, TunnelState::Up)
    }

    /// Is the kill-switch engaged (everything blocked except the WireGuard port)?
    pub fn kill_switch_engaged(self) -> bool {
        !self.traffic_allowed()
    }

    /// Active captive portal: HTTP/HTTPS to the local gateway allowed.
    pub fn captive_portal_active(self) -> bool {
        matches!(self, TunnelState::CaptivePortal)
    }

    /// Stable string representation (used by the REST API).
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelState::Down => "down",
            TunnelState::Connecting => "connecting",
            TunnelState::Up => "up",
            TunnelState::Failed => "failed",
            TunnelState::CaptivePortal => "captive_portal",
        }
    }

    /// Applies an event and returns the next state, or an error if the
    /// transition makes no sense.
    pub fn on(self, event: TunnelEvent) -> Result<TunnelState> {
        use TunnelEvent::*;
        use TunnelState::*;

        let next = match (self, event) {
            (Down | Failed, StartRequested) => Connecting,
            // Captive portal: resolved by the user → retry the connection
            (CaptivePortal, CaptivePortalResolved) => Connecting,
            // Fresh handshake + PSK in place → tunnel fully operational
            (Connecting, HandshakeEstablished) => Up,
            // The handshake has aged past the threshold → back to attempting
            (Up, HandshakeExpired) => Connecting,
            // Captive portal detected from any non-Up state
            (Down | Failed | Connecting, CaptivePortalDetected) => CaptivePortal,
            (_, Disconnected) => Down,
            (_, Error) => Failed,
            (s, e) => {
                return Err(HeliosError::State(format!(
                    "state {s:?} cannot handle event {e:?}"
                )))
            }
        };
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_is_fail_closed() {
        assert!(TunnelState::Down.kill_switch_engaged());
        assert!(TunnelState::Failed.kill_switch_engaged());
        assert!(TunnelState::Connecting.kill_switch_engaged());
        assert!(TunnelState::CaptivePortal.kill_switch_engaged());
    }

    #[test]
    fn only_up_allows_traffic() {
        assert!(TunnelState::Up.traffic_allowed());
        assert!(!TunnelState::Connecting.traffic_allowed());
        assert!(!TunnelState::Down.traffic_allowed());
        assert!(!TunnelState::CaptivePortal.traffic_allowed());
    }

    #[test]
    fn captive_portal_lifecycle() {
        // Connecting → portal detected → CaptivePortal
        let s = TunnelState::Connecting
            .on(TunnelEvent::CaptivePortalDetected)
            .unwrap();
        assert_eq!(s, TunnelState::CaptivePortal);
        assert!(s.captive_portal_active());
        // Resolved → Connecting
        let s = s.on(TunnelEvent::CaptivePortalResolved).unwrap();
        assert_eq!(s, TunnelState::Connecting);
    }

    #[test]
    fn nominal_lifecycle() {
        let s = TunnelState::Down;
        let s = s.on(TunnelEvent::StartRequested).unwrap();
        assert_eq!(s, TunnelState::Connecting);
        // Classic ramp-up + PSK upgrade → fully established handshake
        let s = s.on(TunnelEvent::HandshakeEstablished).unwrap();
        assert_eq!(s, TunnelState::Up);
    }

    #[test]
    fn handshake_expiry_returns_to_connecting() {
        let s = TunnelState::Up.on(TunnelEvent::HandshakeExpired).unwrap();
        assert_eq!(s, TunnelState::Connecting);
        // A new handshake restores Up.
        let s = s.on(TunnelEvent::HandshakeEstablished).unwrap();
        assert_eq!(s, TunnelState::Up);
    }

    #[test]
    fn error_always_fails_closed() {
        for start in [TunnelState::Up, TunnelState::Connecting] {
            assert_eq!(start.on(TunnelEvent::Error).unwrap(), TunnelState::Failed);
        }
    }

    #[test]
    fn invalid_transition_is_rejected() {
        // An "established" handshake makes no sense outside ramp-up.
        assert!(TunnelState::Down
            .on(TunnelEvent::HandshakeEstablished)
            .is_err());
        // An expiry only makes sense from Up.
        assert!(TunnelState::Down.on(TunnelEvent::HandshakeExpired).is_err());
    }
}
