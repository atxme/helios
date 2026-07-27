use std::{collections::HashSet, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};
use crate::policy::{FirewallPolicy, PolicyMode};

const NETWORK_CONFIG_PATH: &str = "/var/lib/helios/network.toml";

/// TCP port of the REST/WS API (hardcoded, architectural invariant).
pub const API_PORT: u16 = 8080;
/// Listen address of the HTTP server in degraded mode (no tunnel interface).
///
/// Loopback only: without a tunnel, the API has no reason to be reachable
/// from the outside.
pub const API_BIND_LOOPBACK: &str = "127.0.0.1:8080";

/// Network configuration loadable by the operator via CLI or graphical interface.
///
/// Persisted in `/var/lib/helios/network.toml`. It is the only configuration
/// file provided by the operator — all other parameters (TPM, API and
/// firewall mode) are architectural constants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub wan_iface: String,
    #[serde(default)]
    pub lan_ifaces: Vec<String>,
    /// CIDRs or IPs allowed for administrative SSH, even with the kill-switch engaged.
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
    /// Allows DHCP (UDP 67/68) on the WAN interface, kill-switch engaged.
    ///
    /// Enable when the WAN address comes from a lease. See
    /// [`crate::FirewallPolicy::allow_dhcp_on_wan`] for the cost of forgetting it.
    #[serde(default)]
    pub allow_dhcp_on_wan: bool,
    /// Routes tunnel clients' traffic to the Internet (forward + NAT).
    ///
    /// Closed by default: a gateway giving access to internal resources has
    /// no reason to route Internet traffic, and opening it would widen its
    /// attack surface for nothing. See [`crate::FirewallPolicy::allow_client_internet`]
    /// for what this covers — and what it does not cover, namely DNS.
    #[serde(default)]
    pub allow_client_internet: bool,
    /// Exclusive network interface for administration access.
    /// Must be the WireGuard interface (`wg_iface`): the API lives behind the tunnel.
    #[serde(default)]
    pub admin_iface: Option<String>,
    /// Local CIDRs bypassing the tunnel by default (static split-tunneling).
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<String>,

    // ── WireGuard data plane (server role) ──────────────────────────────
    /// Name of the WireGuard interface created by the gateway.
    #[serde(default = "default_wg_iface")]
    pub wg_iface: String,
    /// Gateway's Curve25519 private key, in base64. **Secret.**
    /// Empty = the gateway cannot bring up its interface.
    #[serde(default)]
    pub wg_private_key: String,
    /// Gateway's address in the tunnel network (CGNAT, ADR-001 §4).
    #[serde(default = "default_wg_address")]
    pub wg_address: String,
    /// UDP listen port.
    #[serde(default = "default_wg_port")]
    pub wg_listen_port: u16,
    /// Public UDP port of the authenticated key-negotiation service.
    ///
    /// `None` keeps the WAN port closed. A binary built with the
    /// `key-negotiation` feature requires this value before it starts the
    /// service, so the firewall never exposes an unserved socket.
    #[serde(default)]
    pub key_negotiation_port: Option<u16>,
    /// Authorized peers. Eventually populated by `helios-provisioning` at
    /// enrollment; declarable by hand in the meantime.
    #[serde(default)]
    pub peers: Vec<WgPeer>,

    /// Static peers reachable outbound (site-to-site). Empty in road-warrior mode.
    #[serde(default)]
    pub static_peer_addrs: Vec<String>,

    /// Operator's **public** X25519 escrow key, in base64.
    ///
    /// When set, the gateway encrypts a copy of its WireGuard private key to
    /// this key on every sealing. Only the operator — who holds the private
    /// half, kept **outside** the gateway — can open it.
    ///
    /// This is what allows recovering the gateway's identity after a PCR
    /// change (new kernel, bootloader, firmware) without going through SSH
    /// access. Absent = no escrow, the key is then permanently lost in that
    /// case.
    #[serde(default)]
    pub escrow_public_key: Option<String>,
}

fn default_wg_iface() -> String {
    "helios0".to_string()
}

/// `100.64.0.1/10`: first address of the shared CGNAT range (RFC 6598).
fn default_wg_address() -> String {
    "100.64.0.1/10".to_string()
}

fn default_wg_port() -> u16 {
    51820
}

/// An authorized WireGuard client on the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    /// Friendly name (logging, UI).
    pub name: String,
    /// Client's Curve25519 public key, in base64 — its identity.
    pub public_key: String,
    /// Assigned VIP, in CIDR notation (e.g. `100.64.1.2/32`).
    /// In WireGuard, `AllowedIPs` **is** the cryptographic routing table.
    pub address: String,
    /// Authorizes this peer to mutate the control plane and drive updates.
    /// The peer remains an ordinary WireGuard client.
    #[serde(default)]
    pub admin: bool,
    /// Post-quantum PSK derived from the ML-KEM exchange, in base64. **Secret.**
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// SHA-256 fingerprint of the client leaf certificate authorized for
    /// public key negotiation. Public metadata; the certificate private key
    /// remains on Orion.
    #[serde(default)]
    pub key_negotiation_certificate_sha256: Option<String>,
    /// Fingerprint of the ML-DSA-65 application certificate admitted for
    /// this WireGuard identity.
    #[serde(default)]
    pub key_negotiation_pq_certificate_sha256: Option<String>,
    /// Lowest protection mode accepted for this peer. A network negotiation
    /// can raise the mode but can never lower it below this policy.
    #[serde(default)]
    pub minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode,
}

impl NetworkConfig {
    /// Configuration path. `HELIOS_NETWORK_CONFIG` allows isolating manual
    /// tests without writing to `/var/lib/helios`; the production service
    /// keeps the system path when it is absent.
    pub fn path() -> PathBuf {
        std::env::var_os("HELIOS_NETWORK_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(NETWORK_CONFIG_PATH))
    }

    /// Loads the network config from `/var/lib/helios/network.toml`.
    /// Returns an empty config if the file does not exist yet.
    pub fn load() -> Result<Self> {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let config: Self =
                    toml::from_str(&raw).map_err(|e| HeliosError::Config(e.to_string()))?;
                config.validate()?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(HeliosError::Config(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }

    /// Persists the network config atomically (rename).
    pub fn save(&self) -> Result<()> {
        self.validate()?;
        let path = Self::path();
        let raw = toml::to_string_pretty(self).map_err(|e| HeliosError::Config(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HeliosError::Config(format!("creating directory: {e}")))?;
        }
        std::fs::write(&tmp, raw.as_bytes())
            .map_err(|e| HeliosError::Config(format!("writing: {e}")))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| HeliosError::Config(format!("atomic rename: {e}")))?;
        Ok(())
    }

    /// Restores what a configuration coming from outside the daemon cannot
    /// carry.
    ///
    /// Two sources feed the running configuration, and **neither** holds the
    /// runtime secrets: `GET /api/network` redacts them by design, and
    /// `network.toml` is written without them for the same reason — the
    /// WireGuard private key lives sealed in the TPM vault and the
    /// post-quantum PSKs are renegotiated on each enrollment. Applying either
    /// as-is would erase both: the gateway would lose the identity it brings
    /// its interface up with, and every peer would keep a PSK slot filled on
    /// one side only — which fails every handshake, with no recovery channel.
    ///
    /// The anti-downgrade floor is treated the same way, for the same reason:
    /// it only ever goes up. Reloading a file must not become the way to
    /// lower it.
    ///
    /// Everything else — the peer list itself, addresses, flags, ports —
    /// comes from the incoming configuration. That is the point: this is how
    /// a peer admitted on the console reaches the running gateway.
    pub fn adopt_runtime_secrets_from(&mut self, current: &Self) {
        if self.wg_private_key.trim().is_empty() {
            self.wg_private_key.clone_from(&current.wg_private_key);
        }
        if self.key_negotiation_port.is_none() {
            self.key_negotiation_port = current.key_negotiation_port;
        }
        for peer in &mut self.peers {
            let Some(known) = current
                .peers
                .iter()
                .find(|known| known.public_key == peer.public_key)
            else {
                continue;
            };
            if peer.preshared_key.is_none() {
                peer.preshared_key.clone_from(&known.preshared_key);
            }
            if peer.key_negotiation_certificate_sha256.is_none() {
                peer.key_negotiation_certificate_sha256
                    .clone_from(&known.key_negotiation_certificate_sha256);
            }
            if peer.key_negotiation_pq_certificate_sha256.is_none() {
                peer.key_negotiation_pq_certificate_sha256
                    .clone_from(&known.key_negotiation_pq_certificate_sha256);
            }
            if peer.minimum_key_negotiation_mode.security_level()
                < known.minimum_key_negotiation_mode.security_level()
            {
                peer.minimum_key_negotiation_mode = known.minimum_key_negotiation_mode;
            }
        }
    }

    /// Validates the identity table used by the API to attach a request's
    /// source address to the WireGuard peer that sent it.
    ///
    /// A broad or duplicated VIP would make administrator authorization
    /// ambiguous. Helios clients therefore exclusively use a `/32` host IPv4,
    /// consistent with their WireGuard `AllowedIPs`.
    pub fn validate_peer_identities(&self) -> Result<()> {
        let mut addresses = HashSet::new();
        let mut public_keys = HashSet::new();
        for peer in &self.peers {
            let (host, prefix) = peer.address.split_once('/').ok_or_else(|| {
                HeliosError::Config(format!(
                    "peer {} VIP without /32 prefix: {}",
                    peer.name, peer.address
                ))
            })?;
            if prefix != "32" || host.parse::<Ipv4Addr>().is_err() {
                return Err(HeliosError::Config(format!(
                    "invalid VIP for peer {}, a /32 IPv4 is required: {}",
                    peer.name, peer.address
                )));
            }
            if !addresses.insert(host.to_string()) {
                return Err(HeliosError::Config(format!(
                    "duplicate VIP in the peer table: {host}/32"
                )));
            }
            if !public_keys.insert(peer.public_key.as_str()) {
                return Err(HeliosError::Config(format!(
                    "duplicate WireGuard public key for peer {}",
                    peer.name
                )));
            }
            let tls_identity = peer.key_negotiation_certificate_sha256.as_deref();
            let pq_identity = peer.key_negotiation_pq_certificate_sha256.as_deref();
            if tls_identity.is_some() != pq_identity.is_some() {
                return Err(HeliosError::Config(format!(
                    "peer {} has an incomplete TLS/PQ key-negotiation identity",
                    peer.name
                )));
            }
            for fingerprint in [tls_identity, pq_identity].into_iter().flatten() {
                crate::key_negotiation::validate_certificate_fingerprint(fingerprint).map_err(
                    |_| {
                        HeliosError::Config(format!(
                            "peer {} has an invalid key-negotiation certificate fingerprint",
                            peer.name
                        ))
                    },
                )?;
            }
            if peer.minimum_key_negotiation_mode != crate::key_negotiation::ProtectionMode::Classic
                && pq_identity.is_none()
            {
                return Err(HeliosError::Config(format!(
                    "peer {} requires a PQ key-negotiation identity for its security floor",
                    peer.name
                )));
            }
        }
        Ok(())
    }

    /// Validates relationships that cannot be expressed by serde defaults.
    pub fn validate(&self) -> Result<()> {
        self.validate_peer_identities()?;
        if let Some(port) = self.key_negotiation_port {
            if port == 0 {
                return Err(HeliosError::Config(
                    "key_negotiation_port must not be zero".into(),
                ));
            }
            if port == self.wg_listen_port {
                return Err(HeliosError::Config(
                    "key_negotiation_port and wg_listen_port must be distinct".into(),
                ));
            }
        }
        Ok(())
    }

    /// Static peers reachable outbound (site-to-site). Empty in road-warrior
    /// mode: clients arrive inbound, on `wg_listen_port`.
    pub fn wg_peers(&self) -> Vec<String> {
        self.static_peer_addrs.clone()
    }

    /// Is the gateway configured to bring up its WireGuard interface?
    pub fn wireguard_ready(&self) -> bool {
        !self.wg_private_key.trim().is_empty() && !self.wg_address.trim().is_empty()
    }

    /// Listen address of the HTTP server.
    ///
    /// **The API must listen on the tunnel address**, not on loopback: that
    /// is how Orion clients reach provisioning and telemetry. Listening on
    /// `127.0.0.1` would make the firewall rule filtering on `admin_iface`
    /// inoperative — it could never apply, for lack of a socket to reach.
    ///
    /// Filtering is still enforced by the firewall (`admin_iface`), not by
    /// the bind address: it is nftables that refuses connections coming
    /// from anywhere other than the tunnel.
    ///
    /// Without a configured gateway, we fall back to loopback.
    pub fn api_bind(&self) -> String {
        if !self.wireguard_ready() {
            return API_BIND_LOOPBACK.to_string();
        }
        // `wg_address` is in CIDR notation (`100.64.0.1/10`): keep only the host.
        match self.wg_address.split('/').next() {
            Some(host) if !host.trim().is_empty() => format!("{}:{}", host.trim(), API_PORT),
            _ => API_BIND_LOOPBACK.to_string(),
        }
    }

    /// Projects the network config onto the declarative firewall policy.
    /// Mode always `fail-closed` — non-configurable security invariant.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        let admin_port = self.admin_iface.as_ref().map(|_| API_PORT);
        FirewallPolicy {
            wan_iface: self.wan_iface.clone(),
            lan_ifaces: self.lan_ifaces.clone(),
            wg_peers: self.wg_peers(),
            // Server role: we only open the inbound port if the gateway is
            // actually able to bring up its interface. Otherwise we'd leave
            // a port open with nothing behind it.
            wg_listen_port: self.wireguard_ready().then_some(self.wg_listen_port),
            key_negotiation_port: self
                .wireguard_ready()
                .then_some(self.key_negotiation_port)
                .flatten(),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: self.allow_ssh_from.clone(),
            allow_dhcp_on_wan: self.allow_dhcp_on_wan,
            allow_client_internet: self.allow_client_internet,
            wg_iface: self.wg_iface.clone(),
            admin_port,
            admin_iface: self.admin_iface.clone(),
            split_tunnel_cidrs: self.split_tunnel_cidrs.clone(),
            mss_clamp: None,
            captive_portal_gateway: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration reloaded from disk carries no secret — by design.
    ///
    /// This is the accident the merge exists to prevent: `network.toml` is
    /// written without the sealed private key and without the negotiated
    /// PSKs, so applying it as-is would take the gateway's identity away and
    /// leave every peer with a PSK slot filled on one side only. Every
    /// handshake would then fail, with no recovery channel.
    #[test]
    fn a_reloaded_config_keeps_the_secrets_the_file_never_held() {
        let running = NetworkConfig {
            wg_private_key: "SECRET-DE-LA-GATEWAY".into(),
            key_negotiation_port: Some(51821),
            peers: vec![WgPeer {
                name: "poste".into(),
                public_key: "CLE-PUBLIQUE-DU-POSTE".into(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("PSK-NEGOCIE".into()),
                key_negotiation_certificate_sha256: Some("empreinte-tls".into()),
                key_negotiation_pq_certificate_sha256: Some("empreinte-pq".into()),
                minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
            }],
            ..NetworkConfig::default()
        };

        // What `heliosd peer add` leaves on disk: the same peer, a new one,
        // and nothing secret.
        let mut from_disk = NetworkConfig {
            peers: vec![
                WgPeer {
                    preshared_key: None,
                    key_negotiation_certificate_sha256: None,
                    key_negotiation_pq_certificate_sha256: None,
                    // A file that asks for less than what was reached: the
                    // floor must not follow it down.
                    minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
                    ..running.peers[0].clone()
                },
                WgPeer {
                    name: "nouveau".into(),
                    public_key: "CLE-DU-NOUVEAU".into(),
                    address: "100.64.1.3/32".into(),
                    admin: false,
                    preshared_key: None,
                    key_negotiation_certificate_sha256: None,
                    key_negotiation_pq_certificate_sha256: None,
                    minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
                },
            ],
            ..NetworkConfig::default()
        };

        from_disk.adopt_runtime_secrets_from(&running);

        assert_eq!(from_disk.wg_private_key, "SECRET-DE-LA-GATEWAY");
        assert_eq!(from_disk.key_negotiation_port, Some(51821));
        assert_eq!(
            from_disk.peers[0].preshared_key.as_deref(),
            Some("PSK-NEGOCIE"),
            "the negotiated PSK must survive a reload"
        );
        assert_eq!(
            from_disk.peers[0]
                .key_negotiation_certificate_sha256
                .as_deref(),
            Some("empreinte-tls")
        );
        assert_eq!(
            from_disk.peers[0].minimum_key_negotiation_mode,
            crate::key_negotiation::ProtectionMode::MlKem,
            "the anti-downgrade floor only ever goes up"
        );

        // And the point of the whole exercise: the new peer is there.
        assert_eq!(from_disk.peers.len(), 2);
        assert_eq!(from_disk.peers[1].name, "nouveau");
        assert_eq!(from_disk.peers[1].preshared_key, None);
    }

    #[test]
    fn config_empty_by_default() {
        let cfg = NetworkConfig::default();
        assert!(cfg.peers.is_empty());
        assert!(cfg.wan_iface.is_empty());
        assert!(
            !cfg.wireguard_ready(),
            "without a private key, nothing should come up"
        );
    }

    #[test]
    fn deserializes_gateway_config() {
        let toml = r#"
            wan_iface = "eth0"
            lan_ifaces = ["eth1"]
            admin_iface = "helios0"
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [[peers]]
            name = "poste-christophe"
            public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            address = "100.64.1.2/32"
            admin = true
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.wan_iface, "eth0");
        // WireGuard defaults apply without being written.
        assert_eq!(cfg.wg_iface, "helios0");
        assert_eq!(cfg.wg_listen_port, 51820);
        assert_eq!(cfg.wg_address, "100.64.0.1/10");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].address, "100.64.1.2/32");
        assert!(cfg.peers[0].admin);
        assert!(cfg.wireguard_ready());

        let policy = cfg.firewall_policy();
        assert!(policy.is_fail_closed());
        // Server role: the listen port must be open inbound, otherwise no
        // client can handshake.
        assert_eq!(policy.wg_listen_port, Some(51820));
        assert!(policy.wg_peers.is_empty(), "road-warrior: no outbound peer");
    }

    #[test]
    fn identities_require_unique_host_vips() {
        let peer = |name: &str, key: &str, address: &str| WgPeer {
            name: name.into(),
            public_key: key.into(),
            address: address.into(),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
        };
        let mut cfg = NetworkConfig {
            peers: vec![
                peer("a", "cle-a", "100.64.1.2/32"),
                peer("b", "cle-b", "100.64.1.2/32"),
            ],
            ..NetworkConfig::default()
        };
        assert!(cfg.validate_peer_identities().is_err());

        cfg.peers[1].address = "100.64.1.3/24".into();
        assert!(cfg.validate_peer_identities().is_err());

        cfg.peers[1].address = "100.64.1.3/32".into();
        assert!(cfg.validate_peer_identities().is_ok());
    }

    #[test]
    fn key_negotiation_requires_a_distinct_nonzero_udp_port() {
        let mut config = NetworkConfig {
            key_negotiation_port: Some(0),
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
        config.key_negotiation_port = Some(config.wg_listen_port);
        assert!(config.validate().is_err());
        config.key_negotiation_port = Some(51821);
        assert!(config.validate().is_ok());
    }

    /// The API must listen on the tunnel address. On `127.0.0.1`, no Orion
    /// client could reach provisioning, and the firewall rule filtering on
    /// `admin_iface` could never apply.
    #[test]
    fn the_api_listens_on_the_tunnel_address() {
        let cfg = NetworkConfig {
            wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.api_bind(), "100.64.0.1:8080");
        assert_ne!(
            cfg.api_bind(),
            API_BIND_LOOPBACK,
            "on loopback, provisioning would be unreachable"
        );
    }

    /// Without a configured gateway, no reason to expose the API: loopback.
    #[test]
    fn falls_back_to_loopback_without_a_gateway() {
        assert_eq!(NetworkConfig::default().api_bind(), API_BIND_LOOPBACK);

        // Malformed address: we fall back rather than exposing anything.
        let cfg = NetworkConfig {
            wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_address: "/10".into(),
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.api_bind(), API_BIND_LOOPBACK);
    }

    #[test]
    fn port_not_opened_if_the_gateway_is_not_ready() {
        // No private key -> we don't open a port with nothing behind it.
        let cfg = NetworkConfig {
            wan_iface: "eth0".into(),
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.firewall_policy().wg_listen_port, None);
    }
}
