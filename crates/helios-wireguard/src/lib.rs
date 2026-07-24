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
//! The crate also provides [`PeerAddressTable`], which wires the **live**
//! peer table onto `helios-provisioning`'s IPAM: it is the source of truth
//! used for VIP collision resolution, with no state persisted to disk
//! (ADR-001 §4).

use std::net::Ipv4Addr;
use std::time::SystemTime;

use async_trait::async_trait;

pub mod dryrun;
#[cfg(feature = "wireguard")]
pub mod kernel;

pub use dryrun::DryRunBackend;
#[cfg(feature = "wireguard")]
pub use kernel::KernelBackend;

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
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Interface name (e.g. `helios0`).
    pub name: String,
    /// Gateway's Curve25519 private key, in base64. **Secret.**
    pub private_key: String,
    /// UDP listening port. The gateway listens; it does not dial.
    pub listen_port: u16,
    /// Gateway's address within the tunnel network (e.g. `100.64.0.1/10`).
    pub address: String,
    /// Interface MTU, or `None` to leave WireGuard's default.
    ///
    /// Derived from the WAN link's MTU by [`aether::mtu::tunnel_mtu`]: the
    /// default of 1420 assumes a 1500 transport and makes large packets
    /// vanish as soon as the WAN is narrower.
    ///
    /// Since the WireGuard MTU is **per interface, not per peer**, this value
    /// applies to all clients. Those whose path is narrower fall under MSS
    /// clamping (TCP) or PMTUD (UDP), not this setting.
    pub mtu: Option<u32>,
}

/// A peer (Orion client) admitted on the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Client's Curve25519 public key, in base64 — its identity.
    pub public_key: String,
    /// VIP assigned to the client, in CIDR notation (e.g. `100.64.1.2/32`).
    ///
    /// In WireGuard, `AllowedIPs` **is** the cryptographic routing table: two
    /// peers cannot claim the same address.
    pub allowed_ips: String,
    /// Post-quantum PSK derived from the ML-KEM exchange, in base64. **Secret.**
    pub preshared_key: Option<String>,
}

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

/// View of the live peer table, wired onto the IPAM.
///
/// This is the link that makes "no disk state" VIP assignment real: the
/// source of truth is the data plane itself, rebuilt as clients reconnect
/// (ADR-001 §4).
pub struct PeerAddressTable {
    /// `(VIP, raw public key)` for each known peer.
    entries: Vec<(Ipv4Addr, Vec<u8>)>,
}

impl PeerAddressTable {
    /// Builds the table from a data plane snapshot.
    ///
    /// Non-IPv4 or malformed `allowed_ips` are ignored: they cannot collide
    /// with a derived CGNAT VIP.
    pub fn from_peers(peers: &[PeerStatus]) -> Self {
        let mut entries = Vec::new();
        for peer in peers {
            for cidr in &peer.allowed_ips {
                let host = cidr.split('/').next().unwrap_or(cidr);
                if let Ok(addr) = host.parse::<Ipv4Addr>() {
                    entries.push((addr, peer.public_key.clone()));
                }
            }
        }
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl helios_provisioning::PeerTable for PeerAddressTable {
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|(a, owner)| *a == addr && owner.as_slice() != pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_provisioning::PeerTable;

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
    fn table_detects_collision_with_another_peer() {
        let table = PeerAddressTable::from_peers(&[peer(&[1u8; 32], "100.64.1.2/32")]);
        let vip: Ipv4Addr = "100.64.1.2".parse().unwrap();

        // Another key claiming the same VIP = collision.
        assert!(table.is_taken_by_other(vip, &[2u8; 32]));
        // The same peer never collides with itself (reconnection).
        assert!(!table.is_taken_by_other(vip, &[1u8; 32]));
    }

    #[test]
    fn free_address_not_flagged() {
        let table = PeerAddressTable::from_peers(&[peer(&[1u8; 32], "100.64.1.2/32")]);
        let other: Ipv4Addr = "100.64.9.9".parse().unwrap();
        assert!(!table.is_taken_by_other(other, &[2u8; 32]));
    }

    #[test]
    fn non_ipv4_allowed_ips_ignored() {
        let mut p = peer(&[1u8; 32], "100.64.1.2/32");
        p.allowed_ips.push("fd00::1/128".into());
        p.allowed_ips.push("not-an-address".into());
        let table = PeerAddressTable::from_peers(&[p]);
        // Only the valid IPv4 entry is retained.
        assert!(!table.is_empty());
        assert!(table.is_taken_by_other("100.64.1.2".parse().unwrap(), &[2u8; 32]));
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
