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
///
/// `Debug` is derived and stays safe because the two variants that carry
/// secret material declare it with a secret type: the enum used to hold the
/// gateway's private key as a bare `String` and a whole [`NetworkConfig`]
/// with every peer PSK, so one `{cmd:?}` put the gateway's identity in a log
/// line (ADR-006 §5).
///
/// `Clone` is gone with them. A command is sent once down an mpsc channel and
/// consumed once; copying one was never needed, and for these two variants it
/// was a second buffer nobody wiped.
#[derive(Debug)]
pub enum OrchestratorCmd {
    Connect,
    /// Replaces the gateway's WireGuard private key and seals it in the TPM.
    ///
    /// The sealing secret never leaves `heliosd`: the API only transmits the
    /// new key, only the orchestrator knows how to seal it.
    ///
    /// **Identity rotation**: after applying, all clients must update their
    /// `peer_public_key`.
    UpdateGatewayKey(SecretString),
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

/// A **fresh** read of one peer's last handshake, straight from the backend.
///
/// # Why not the published snapshot
///
/// The orchestrator already republishes the whole peer table every ten
/// seconds, and the API reads that. The key-negotiation commit cannot: it
/// must decide whether a handshake happened *since* the candidate PSK was
/// posed, and the client confirms within a second or two of that handshake.
/// A snapshot up to ten seconds old would routinely still show the previous
/// value, and the gateway would refuse confirmations that are entirely
/// legitimate — turning a security check into an outage.
///
/// Hence a second channel rather than a second reader: the backend lives in
/// the orchestrator and nowhere else, so a caller that needs the current
/// value asks the task that owns it. The channel carries no secret, but it
/// does carry a `oneshot` for the same reason [`InstallPskRequest`] does —
/// the answer is what the caller is about to make a decision on.
#[derive(Debug)]
pub struct ObserveHandshakeRequest {
    /// Curve25519 public key of the peer concerned (base64).
    pub public_key: String,
    /// Last successful handshake, or `None` if the peer never handshook.
    ///
    /// `Err` is a backend failure, which is **not** the same answer as
    /// `Ok(None)`: one means the gateway cannot tell, the other means it can
    /// and the answer is "never".
    pub reply: oneshot::Sender<Result<Option<std::time::SystemTime>, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command's `Debug` must not print the material it carries.
    ///
    /// Both variants used to hold it as plain data — `UpdateGatewayKey` a
    /// bare `String`, `LoadNetworkConfig` a whole configuration with every
    /// peer PSK — inside an enum that derives `Debug`. One `{cmd:?}` in a
    /// `tracing` call was all it took (ADR-006 §5).
    #[test]
    fn a_command_debug_reveals_neither_the_gateway_key_nor_a_psk() {
        const KEY: &str = "nouvelle-cle-privee-de-la-gateway";
        const PSK: &str = "psk-du-pair-en-clair";

        let rotation = OrchestratorCmd::UpdateGatewayKey(KEY.into());
        let rendered = format!("{rotation:?}");
        assert!(
            !rendered.contains(KEY),
            "the rotation leaked the key: {rendered}"
        );

        let mut config = NetworkConfig {
            wg_private_key: KEY.into(),
            ..NetworkConfig::default()
        };
        config.peers.push(crate::config::WgPeer {
            name: "alice".into(),
            public_key: "CLE-PUBLIQUE-ALICE".into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: false,
            preshared_key: Some(PSK.into()),
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
            persistent_keepalive_secs: crate::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });

        let reload = OrchestratorCmd::LoadNetworkConfig(Box::new(config));
        let rendered = format!("{reload:?}");
        assert!(
            !rendered.contains(KEY),
            "the hot reload leaked the identity: {rendered}"
        );
        assert!(
            !rendered.contains(PSK),
            "the hot reload leaked a PSK: {rendered}"
        );
        assert!(
            rendered.contains("alice"),
            "the rest must stay diagnosable: {rendered}"
        );
    }
}
