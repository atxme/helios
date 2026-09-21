//! WireGuard data plane of the Helios gateway.
//!
//! The gateway is a **server**: it listens on UDP 51820 and Orion clients
//! connect to it. It never dials out to an endpoint — road-warriors roam,
//! their source address is unknown in advance. This is the structuring
//! difference with Orion's backend (`orion-core::backend::wireguard`), which
//! dials a fixed endpoint.
//!
//! Two backends, following the pattern already in place in
//! `helios-firewall`:
//! * [`DryRunBackend`] — in memory, testable everywhere (including WSL2);
//! * [`KernelBackend`] — real, behind the `wireguard` feature.
//!
//! The crate owns no admission and no IPAM: it reports [`PeerStatus`], and
//! whoever composes the gateway turns that snapshot into the VIP collision
//! view the IPAM consumes (ADR-001 §4). That keeps this crate a leaf — the
//! data plane depends on nothing else in the workspace.

use std::time::SystemTime;

use async_trait::async_trait;

pub mod dryrun;
#[cfg(feature = "wireguard")]
pub mod kernel;

pub use dryrun::DryRunBackend;
#[cfg(feature = "wireguard")]
pub use kernel::KernelBackend;
/// Re-exported because it is part of this crate's public shape: the secret
/// fields below are declared with it, so a caller must be able to name it
/// without taking its own `zeroize` dependency.
pub use zeroize::Zeroizing;

/// Gateway's WireGuard listening port (architectural invariant).
pub const WG_LISTEN_PORT: u16 = 51820;

/// Errors of the WireGuard data plane.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("invalid WireGuard key: {0}")]
    BadKey(String),
    #[error("invalid address: {0}")]
    BadAddress(String),
    #[error("interface {iface}: {source_msg}")]
    Interface { iface: String, source_msg: String },
    #[error("WireGuard backend unavailable: {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, WgError>;

/// Configuration of the gateway's WireGuard interface.
///
/// Deliberately derives **neither `Debug` nor `Clone`**: it carries the
/// gateway's private key, and both derives are exactly how such a value ends
/// up in a log line or in a buffer nobody wipes (ADR-006 §5). A duplication
/// that is genuinely needed is written out at the call site.
///
/// The key is held in [`Zeroizing`] rather than in a bare `String` so the
/// copy this structure owns is wiped when the bring-up is over. `zeroize`
/// rather than `aether::SecretString`: this crate is a leaf, as the module
/// documentation states, and the data plane is where a workspace dependency
/// has the least business being.
pub struct InterfaceConfig {
    /// Interface name (e.g. `helios0`).
    pub name: String,
    /// Gateway's Curve25519 private key, in base64. **Secret.**
    pub private_key: Zeroizing<String>,
    /// UDP listening port. The gateway listens; it does not dial.
    pub listen_port: u16,
    /// Gateway's address within the tunnel network (e.g. `100.64.0.1/10`).
    pub address: String,
    /// Interface MTU, or `None` to leave WireGuard's default.
    ///
    /// Derived from the WAN link's MTU by `aether::mtu::tunnel_mtu`: the
    /// default of 1420 assumes a 1500 transport and makes large packets
    /// vanish as soon as the WAN is narrower.
    ///
    /// Since the WireGuard MTU is **per interface, not per peer**, this value
    /// applies to all clients. Those whose path is narrower fall under MSS
    /// clamping (TCP) or PMTUD (UDP), not this setting.
    pub mtu: Option<u32>,
}

/// A peer (Orion client) admitted on the gateway.
///
/// Same reasoning as [`InterfaceConfig`], for the same reason: the optional
/// PSK is a secret. `PartialEq` goes with them — comparing a structure that
/// holds a PSK byte by byte is a timing oracle nobody asked for, and nothing
/// compares two peers.
pub struct PeerConfig {
    /// Client's Curve25519 public key, in base64 — its identity.
    pub public_key: String,
    /// VIP assigned to the client, in CIDR notation (e.g. `100.64.1.2/32`).
    ///
    /// In WireGuard, `AllowedIPs` **is** the cryptographic routing table: two
    /// peers cannot claim the same address.
    pub allowed_ips: String,
    /// Post-quantum PSK derived from the ML-KEM exchange, in base64. **Secret.**
    ///
    /// Wiped with the structure: a negotiated PSK has a lifetime bounded by
    /// its installation on the data plane, and this copy must not outlive it.
    pub preshared_key: Option<Zeroizing<String>>,
    /// Seconds between keep-alives the **gateway** sends this peer. `0` is off.
    ///
    /// Set by the gateway rather than inherited from the client, so that the
    /// handshake ages both ends read stay meaningful on an idle tunnel. See
    /// `aether::config::WgPeer::persistent_keepalive_secs`.
    pub persistent_keepalive_secs: u16,
}

/// Beyond this age, a handshake no longer proves anything.
///
/// WireGuard is connectionless: nothing announces a disconnection, and the
/// only evidence a peer is still there is a recent handshake. The value lives
/// here, next to [`PeerStatus`], because two very different consumers must
/// agree on it — the orchestrator, which infers the tunnel state from it and
/// therefore decides whether the kill-switch lifts, and the API, which reports
/// to the console who is connected. A console applying its own threshold would
/// eventually show a client as online while the firewall had already cut it.
pub const HANDSHAKE_STALE_AFTER_SECS: u64 = 150;

/// Beyond this age, a negotiated PSK is reclaimed.
///
/// A **third** threshold, deliberately longer than
/// [`HANDSHAKE_STALE_AFTER_SECS`], because it answers a different question.
/// At 150 seconds the gateway stops counting a peer as connected; at 300 it
/// destroys that peer's secret. Freeing a resource is not the same moment as
/// ceasing to believe in a presence, and collapsing the two would delete a PSK
/// the instant a peer looked briefly absent.
///
/// It also sits above the 180 seconds after which WireGuard abandons a session
/// on its own: at 300 the gateway never destroys something still working, it
/// records what the data plane already settled.
///
/// Only meaningful for peers the gateway sends keep-alives to — which
/// `NetworkConfig::validate` makes mandatory for every negotiated peer.
pub const PSK_RECLAIM_AFTER_STALE_SECS: u64 = 300;

/// Observed state of a peer, read from the data plane.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// Raw public key (32 bytes) — also the IPAM's entry key.
    pub public_key: Vec<u8>,
    /// VIPs claimed by this peer.
    pub allowed_ips: Vec<String>,
    /// Last successful handshake. `None` = never.
    pub last_handshake: Option<SystemTime>,
    /// Peer's current endpoint (it roams: this value changes).
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl PeerStatus {
    /// Public key in base64, for display and the REST API.
    pub fn public_key_b64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.public_key)
    }
}

/// The gateway's WireGuard data plane.
#[async_trait]
pub trait WireguardBackend: Send + Sync {
    /// Brings up the interface and applies the configuration + initial peers.
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()>;

    /// Brings down the interface.
    async fn down(&self) -> Result<()>;

    /// Aligns the list of admitted peers to `peers` (additions and removals).
    /// Called after every admission or revocation.
    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()>;

    /// Reads the current peer state from the data plane.
    async fn peers(&self) -> Result<Vec<PeerStatus>>;

    /// Is the interface up?
    fn is_up(&self) -> bool;

    /// Human-readable backend identifier (diagnostics / UI).
    fn kind(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pubkey: &[u8], vip: &str) -> PeerStatus {
        PeerStatus {
            public_key: pubkey.to_vec(),
            allowed_ips: vec![vip.to_string()],
            last_handshake: None,
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    #[test]
    fn public_key_in_base64() {
        let p = peer(&[0u8; 32], "100.64.0.2/32");
        assert_eq!(
            p.public_key_b64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }
}
