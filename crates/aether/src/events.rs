use serde::Serialize;
use tokio::sync::oneshot;

use crate::config::NetworkConfig;
use crate::secret::SecretString;
use crate::state::TunnelState;

/// Events broadcast to subscribers (WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeliosEvent {
    StateChanged {
        state: TunnelState,
    },
    Log {
        level: String,
        message: String,
    },
    /// Network counters read from /proc/net/dev, emitted every second.
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
    /// Captive portal intercepting HTTP traffic detected on the current network.
    CaptivePortalDetected {
        gateway: String,
    },
    /// Optimal MTU determined by PMTUD — MSS clamping rule applied.
    MtuDiscovered {
        mtu: u16,
        mss: u16,
    },
    /// List of split-tunneling CIDRs updated.
    SplitTunnelChanged {
        cidrs: Vec<String>,
    },
}

/// Commands sent by the web interface to the orchestrator.
#[derive(Debug, Clone)]
pub enum OrchestratorCmd {
    Connect,
    /// Replaces the gateway's WireGuard private key and seals it in the TPM.
    ///
    /// The sealing secret never leaves `heliosd`: the API only transmits the
    /// new key, only the orchestrator knows how to seal it.
    ///
    /// **Identity rotation**: after applying, all clients must update their
    /// `peer_public_key`.
    UpdateGatewayKey(String),
    /// Applies a raw nftables ruleset (dry-run = log only).
    ApplyFirewallRules(String),
    Disconnect,
    /// The user accepted the captive portal in their browser — restart the connection.
    AcknowledgeCaptivePortal,
    /// Updates the list of CIDRs bypassing the tunnel (dynamic split-tunneling).
    SetSplitTunnel(Vec<String>),
    /// Applies an MSS clamping value from the PMTUD probe (internal use).
    SetMssClamp(u16),
    /// State inferred from polling WireGuard handshakes (**internal use**).
    ///
    /// Emitted by the prober, never by the API — no route builds it.
    /// It exists because the prober holds neither the firewall backend nor
    /// the policy: writing the state itself would leave the ruleset frozen
    /// on the previous state. Going through the main loop guarantees that a
    /// promotion to `Up` or a fallback to `Connecting` always re-renders the
    /// firewall.
    TunnelStateInferred(TunnelState),
    /// Reloads the network configuration hot (without restarting the daemon).
    /// Boxed: `NetworkConfig` is far larger than the other variants.
    LoadNetworkConfig(Box<NetworkConfig>),
}

/// Request to install a post-quantum PSK on a data plane peer, emitted by
/// the provisioning endpoint towards the orchestrator.
///
/// # Why a dedicated channel rather than a variant of [`OrchestratorCmd`]
///
/// Two reasons, both structural:
///
/// * this request carries a **secret** and expects a **response**, whereas
///   `OrchestratorCmd` is a stream of UI orders with no return — giving it a
///   `oneshot` would make it lose `Clone`;
/// * keeping the PSK out of an enum that derives `Debug` removes any
///   possibility of leaking it through logging. The field is moreover a
///   [`SecretString`], hence silent on display.
///
/// # Why a response is essential
///
/// WireGuard has only one PSK slot per peer: a value set on only one side
/// makes **all** subsequent handshakes fail. The endpoint must therefore
/// only announce the PSK to the client once the gateway is certain it has
/// been set. Without this acknowledgment, a failure on the data plane side
/// would leave the client installing an orphan PSK and falling — with no
/// control channel to recover, since that channel lives in the tunnel that
/// just died.
#[derive(Debug)]
pub struct InstallPskRequest {
    /// Curve25519 public key of the peer concerned (base64) — its identity.
    pub public_key: String,
    /// VIP assigned to the peer, in CIDR notation (e.g. `100.64.1.2/32`).
    pub address: String,
    /// PSK to install, in base64, or `None` to clear the slot. **Secret.**
    pub psk: Option<SecretString>,
    /// Acknowledgment: `Ok` only if the PSK is actually set on the peer.
    pub reply: oneshot::Sender<Result<(), String>>,
}
