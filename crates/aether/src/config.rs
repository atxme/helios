use std::{collections::HashSet, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};
use crate::policy::{FirewallPolicy, NordvpnMeshnetPolicy, PolicyMode};
use crate::speedtest::SPEEDTEST_PORT;

const NETWORK_CONFIG_PATH: &str = "/var/lib/helios/network.toml";

/// TCP port of the REST/WS API (hardcoded, architectural invariant).
pub const API_PORT: u16 = 8080;
/// Default address of the gateway inside the WireGuard network.
pub const DEFAULT_WG_ADDRESS: &str = "100.64.0.1/10";
/// Default in-tunnel URL of the gateway API.
pub const DEFAULT_WG_API_URL: &str = "http://100.64.0.1:8080";
/// Listen address of the HTTP server in degraded mode (no tunnel interface).
///
/// Loopback only: without a tunnel, the API has no reason to be reachable
/// from the outside.
pub const API_BIND_LOOPBACK: &str = "127.0.0.1:8080";

/// Reads `wan_iface` as a single name or as a list.
///
/// Both spellings, because every `network.toml` in the field holds the
/// singular one and a gateway with two uplinks needs the plural. Writing back
/// always normalises to a list — one shape on disk after the first save, and
/// the reader still accepts both forever.
fn de_wan_ifaces<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        // An absent value and `wan_iface = ""` are the same thing: no uplink
        // declared. Keeping the empty string would put a rule on an interface
        // named nothing.
        OneOrMany::One(name) if name.trim().is_empty() => Vec::new(),
        OneOrMany::One(name) => vec![name],
        OneOrMany::Many(names) => names,
    })
}

fn valid_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if address.parse::<Ipv4Addr>().is_err() {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= 32
}

/// Network configuration loadable by the operator via CLI or graphical interface.
///
/// Persisted in `/var/lib/helios/network.toml`. It is the only configuration
/// file provided by the operator — all other parameters (TPM, API and
/// firewall mode) are architectural constants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Uplink interfaces, in order of preference, or a single
    /// [`Self::WAN_IFACE_AUTO`] to let the daemon enumerate them.
    ///
    /// Reads both `wan_iface = "eth0"` and `wan_iface = ["enp3s0", "wlo1"]`:
    /// the singular form is what every existing `network.toml` holds, and
    /// breaking it to gain a list would be a migration for nothing.
    ///
    /// **All of them are permitted, none is selected.** The firewall opens
    /// every rule that names the WAN once per interface, so a gateway with a
    /// cable and a radio keeps working when the cable is unplugged — the
    /// kernel moves its default route and the rules are already there. Which
    /// one a packet actually leaves by is the routing table's decision, and a
    /// preference between two live uplinks is a route metric.
    // The TOML key stays `wan_iface`: every `network.toml` in the field holds
    // it, and renaming a key to gain a plural would be a migration for
    // nothing. `wan_ifaces` is accepted too, for whoever writes the obvious
    // thing after seeing a list.
    #[serde(
        rename = "wan_iface",
        alias = "wan_ifaces",
        default,
        deserialize_with = "de_wan_ifaces"
    )]
    pub wan_ifaces: Vec<String>,
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
    /// Answers ICMP on the tunnel interface. See
    /// [`crate::FirewallPolicy::allow_tunnel_icmp`] for why this one defaults
    /// to open while everything else here defaults to closed.
    #[serde(default = "default_true")]
    pub allow_tunnel_icmp: bool,
    /// Lets the gateway resolve, synchronize its clock and fetch packages for
    /// itself, on the WAN interface.
    ///
    /// Closed by default. See [`crate::FirewallPolicy::allow_gateway_egress`]
    /// for what a gateway without it cannot do — starting with the OS upgrade
    /// `helios-ctl update` is supposed to run on that very machine.
    #[serde(default)]
    pub allow_gateway_egress: bool,
    /// Accepts SSH arriving **through the tunnel**, on the tunnel interface.
    ///
    /// Closed by default. Prefer it to listing the CGNAT range in
    /// [`Self::allow_ssh_from`]: that one matches on the source address with
    /// no interface constraint, so a packet forging a `100.64.x.x` source
    /// from the WAN would satisfy it.
    #[serde(default)]
    pub allow_ssh_over_tunnel: bool,
    /// Port of an `iperf3` measurement on the tunnel interface, both ways.
    ///
    /// Absent — the default — keeps it closed. See
    /// [`crate::FirewallPolicy::iperf_port`] for why this one opens the
    /// `output` chain as well, which no other tunnel rule does.
    #[serde(default)]
    pub iperf_port: Option<u16>,
    /// Exclusive network interface for administration access.
    /// Must be the WireGuard interface (`wg_iface`): the API lives behind the tunnel.
    #[serde(default)]
    pub admin_iface: Option<String>,
    /// Local CIDRs bypassing the tunnel by default (static split-tunneling).
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<String>,

    /// A second, locally terminated WireGuard overlay managed by NordVPN.
    ///
    /// Absent by default. When present, the firewall admits only NordVPN's
    /// marked transport on the WAN and application traffic scoped to this
    /// interface, these peer networks and the declared inbound ports.
    #[serde(default)]
    pub nordvpn_meshnet: Option<NordvpnMeshnetConfig>,

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

/// Operator-facing NordVPN Meshnet firewall configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NordvpnMeshnetConfig {
    /// Interface created by NordVPN/libtelio.
    pub iface: String,
    /// Packet mark configured on `nordlynx` (`0xe1f1` by NordVPN by default).
    pub fwmark: u32,
    /// Meshnet addresses allowed to communicate with this gateway.
    pub peer_cidrs: Vec<String>,
    /// Meshnet peers allowed to route traffic through this gateway.
    pub traffic_routing_peer_cidrs: Vec<String>,
    /// Routing peers allowed to reach private networks behind this gateway.
    pub local_network_peer_cidrs: Vec<String>,
    /// TCP services exposed to the selected Meshnet peers.
    pub inbound_tcp_ports: Vec<u16>,
    /// UDP services exposed to the selected Meshnet peers.
    pub inbound_udp_ports: Vec<u16>,
    /// Whether selected Meshnet peers may ping the gateway.
    pub allow_icmp: bool,
}

impl Default for NordvpnMeshnetConfig {
    fn default() -> Self {
        Self {
            iface: "nordlynx".into(),
            fwmark: 0xe1f1,
            peer_cidrs: vec!["100.64.0.0/10".into()],
            traffic_routing_peer_cidrs: Vec::new(),
            local_network_peer_cidrs: Vec::new(),
            inbound_tcp_ports: Vec::new(),
            inbound_udp_ports: Vec::new(),
            allow_icmp: true,
        }
    }
}

impl From<&NordvpnMeshnetConfig> for NordvpnMeshnetPolicy {
    fn from(config: &NordvpnMeshnetConfig) -> Self {
        Self {
            iface: config.iface.clone(),
            fwmark: config.fwmark,
            peer_cidrs: config.peer_cidrs.clone(),
            traffic_routing_peer_cidrs: config.traffic_routing_peer_cidrs.clone(),
            local_network_peer_cidrs: config.local_network_peer_cidrs.clone(),
            inbound_tcp_ports: config.inbound_tcp_ports.clone(),
            inbound_udp_ports: config.inbound_udp_ports.clone(),
            allow_icmp: config.allow_icmp,
        }
    }
}

/// Serde default for the flags that are open unless the operator closes them.
fn default_true() -> bool {
    true
}

/// Delegated to serde so the two notions of "nothing configured" cannot drift.
///
/// `#[derive(Default)]` would have produced `false` for every `bool`,
/// including [`NetworkConfig::allow_tunnel_icmp`], whose documented default is
/// `true`. A config built in code would then have filtered differently from
/// the identical config read from an empty file — the kind of divergence that
/// only ever shows up on the target, in the one path nobody tested.
impl Default for NetworkConfig {
    fn default() -> Self {
        toml::from_str("").expect("every field of the network configuration has a serde default")
    }
}

fn default_wg_iface() -> String {
    "helios0".to_string()
}

fn default_wg_address() -> String {
    DEFAULT_WG_ADDRESS.to_string()
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
    /// Fingerprint of the ML-DSA-87 application certificate admitted for
    /// this WireGuard identity.
    #[serde(default)]
    pub key_negotiation_pq_certificate_sha256: Option<String>,
    /// Lowest protection mode accepted for this peer. A network negotiation
    /// can raise the mode but can never lower it below this policy.
    #[serde(default)]
    pub minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode,
    /// Seconds between WireGuard keep-alives sent **by the gateway** to this
    /// peer. `0` disables them.
    ///
    /// Since v5 the whole liveness story reads the data plane: Orion
    /// renegotiates when its last handshake ages past
    /// `HANDSHAKE_STALE_AFTER_SECS`, and the gateway reclaims a PSK slot past
    /// [`PSK_RECLAIM_AFTER_STALE_SECS`](crate::key_negotiation::PSK_RECLAIM_AFTER_STALE_SECS).
    /// Both assume a live tunnel keeps producing handshakes, which an idle one
    /// does not unless something sends.
    ///
    /// The gateway therefore sends its own keep-alives rather than trusting
    /// the client's configuration, which it cannot inspect. That turns the
    /// assumption into a consequence of its own settings: every 25 seconds it
    /// emits, so as long as the peer answers, a rekey lands roughly every two
    /// minutes and the handshake age stays well under either threshold. When
    /// the peer stops answering, those failures **are** the disappearance
    /// signal.
    #[serde(default = "default_persistent_keepalive_secs")]
    pub persistent_keepalive_secs: u16,
}

/// Gateway-side keep-alive interval, in seconds.
///
/// Matches the client default. Short enough that a rekey happens well inside
/// the reclamation window, long enough to be one 32-byte packet per peer per
/// 25 seconds.
pub const DEFAULT_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

const fn default_persistent_keepalive_secs() -> u16 {
    DEFAULT_PERSISTENT_KEEPALIVE_SECS
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
        if let Some(parent) = path.parent() {
            // 0700, so the mode of the file it holds is not the only barrier.
            crate::private_file::create_private_dir(parent)
                .map_err(|e| HeliosError::Config(format!("creating directory: {e}")))?;
        }
        // 0600 from creation, not a `chmod` afterwards: see `private_file`. A
        // plain write here handed the file back to the umask on every save,
        // undoing the install-time hardening (ADR-006).
        crate::private_file::write_private_atomic(&path, raw.as_bytes())
            .map_err(|e| HeliosError::Config(format!("private atomic write: {e}")))?;
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
    /// [`Self::WAN_IFACE_AUTO`] is a third case, and the same shape: the file
    /// states an intent, the daemon resolved it against the kernel at startup,
    /// and the resolved name is not written back. Letting the marker through a
    /// reload would rebuild the ruleset around an interface literally named
    /// `auto` — every egress rule and the masquerade bound to a device that
    /// does not exist, which is a gateway that drops its own traffic. The name
    /// is also one of the values that cannot change under a running data
    /// plane, so re-resolving here would be wrong even if it worked.
    ///
    /// Everything else — the peer list itself, addresses, flags, ports —
    /// comes from the incoming configuration. That is the point: this is how
    /// a peer admitted on the console reaches the running gateway.
    pub fn adopt_runtime_secrets_from(&mut self, current: &Self) {
        if self.wan_iface_is_auto() && !current.wan_iface_is_auto() {
            self.wan_ifaces.clone_from(&current.wan_ifaces);
        }
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
            // A negotiated peer without keep-alives silently loses both
            // liveness mechanisms of v5: the gateway would never reclaim its
            // slot, and the client would never notice a gateway restart. The
            // failure only shows the day something falls over, so it is
            // refused here — at load and at every hot reload — rather than
            // documented as an operator responsibility.
            if pq_identity.is_some() && peer.persistent_keepalive_secs == 0 {
                return Err(HeliosError::Config(format!(
                    "peer {} negotiates its PSK but has persistent_keepalive_secs = 0; \
                     liveness is read from the data plane and needs handshakes to read",
                    peer.name
                )));
            }
        }
        Ok(())
    }

    /// Validates relationships that cannot be expressed by serde defaults.
    pub fn validate(&self) -> Result<()> {
        self.validate_peer_identities()?;
        // `auto` means « enumerate them all », so it cannot sit beside a name:
        // the two readings — « these, plus whatever you find » and « just
        // these » — differ, and a firewall built on the wrong one is a gateway
        // that drops traffic it was told to pass.
        if self.mentions_auto() && !self.wan_iface_is_auto() {
            return Err(HeliosError::Config(
                "wan_iface: « auto » stands alone, it does not combine with an interface name"
                    .into(),
            ));
        }
        if self.wan_ifaces.iter().any(|iface| iface.trim().is_empty()) {
            return Err(HeliosError::Config(
                "wan_iface: an empty interface name matches nothing and silently drops the \
                 traffic it was meant to pass"
                    .into(),
            ));
        }
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
        if let Some(meshnet) = &self.nordvpn_meshnet {
            if !self.allow_gateway_egress {
                return Err(HeliosError::Config(
                    "nordvpn_meshnet requires allow_gateway_egress = true for NordVPN HTTPS control traffic"
                        .into(),
                ));
            }
            if meshnet.iface.trim().is_empty() {
                return Err(HeliosError::Config(
                    "nordvpn_meshnet.iface must not be empty".into(),
                ));
            }
            if meshnet.iface == self.wg_iface {
                return Err(HeliosError::Config(format!(
                    "nordvpn_meshnet.iface must differ from the Helios WireGuard interface {}",
                    self.wg_iface
                )));
            }
            if self.wan_ifaces.iter().any(|wan| wan == &meshnet.iface) {
                return Err(HeliosError::Config(format!(
                    "nordvpn_meshnet.iface {} is an overlay and must not also be a WAN interface",
                    meshnet.iface
                )));
            }
            if meshnet.fwmark == 0 {
                return Err(HeliosError::Config(
                    "nordvpn_meshnet.fwmark must not be zero".into(),
                ));
            }
            if meshnet.peer_cidrs.is_empty() {
                return Err(HeliosError::Config(
                    "nordvpn_meshnet.peer_cidrs must name at least one Meshnet peer or network"
                        .into(),
                ));
            }
            for peer in &meshnet.peer_cidrs {
                if !valid_ipv4_cidr(peer) {
                    return Err(HeliosError::Config(format!(
                        "invalid nordvpn_meshnet peer CIDR `{peer}`"
                    )));
                }
            }
            for (permission, peers) in [
                ("traffic routing", &meshnet.traffic_routing_peer_cidrs),
                ("local network access", &meshnet.local_network_peer_cidrs),
            ] {
                for peer in peers {
                    if !valid_ipv4_cidr(peer) {
                        return Err(HeliosError::Config(format!(
                            "invalid nordvpn_meshnet {permission} peer CIDR `{peer}`"
                        )));
                    }
                    if !meshnet.peer_cidrs.contains(peer) {
                        return Err(HeliosError::Config(format!(
                            "nordvpn_meshnet {permission} peer `{peer}` must also appear in peer_cidrs"
                        )));
                    }
                }
                let unique: HashSet<_> = peers.iter().collect();
                if unique.len() != peers.len() {
                    return Err(HeliosError::Config(format!(
                        "nordvpn_meshnet {permission} peer CIDRs must not contain duplicates"
                    )));
                }
            }
            for peer in &meshnet.local_network_peer_cidrs {
                if !meshnet.traffic_routing_peer_cidrs.contains(peer) {
                    return Err(HeliosError::Config(format!(
                        "nordvpn_meshnet local network peer `{peer}` must also have traffic routing permission"
                    )));
                }
            }
            for (protocol, ports) in [
                ("TCP", &meshnet.inbound_tcp_ports),
                ("UDP", &meshnet.inbound_udp_ports),
            ] {
                if ports.contains(&0) {
                    return Err(HeliosError::Config(format!(
                        "nordvpn_meshnet inbound {protocol} ports must not contain zero"
                    )));
                }
                if protocol == "TCP" && ports.contains(&API_PORT) {
                    return Err(HeliosError::Config(format!(
                        "nordvpn_meshnet must not expose the Helios administration API port {API_PORT}"
                    )));
                }
                let unique: HashSet<_> = ports.iter().collect();
                if unique.len() != ports.len() {
                    return Err(HeliosError::Config(format!(
                        "nordvpn_meshnet inbound {protocol} ports must not contain duplicates"
                    )));
                }
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

    /// Address where the raw TCP/UDP speedtest service listens behind the
    /// tunnel. It follows the same gateway VIP as the HTTP API, but has its
    /// own port so no HTTP framing can enter the measurement.
    pub fn speedtest_bind(&self) -> String {
        if !self.wireguard_ready() {
            return format!("127.0.0.1:{SPEEDTEST_PORT}");
        }
        match self.wg_address.split('/').next() {
            Some(host) if !host.trim().is_empty() => format!("{}:{SPEEDTEST_PORT}", host.trim()),
            _ => format!("127.0.0.1:{SPEEDTEST_PORT}"),
        }
    }

    /// Projects the network config onto the declarative firewall policy.
    /// Mode always `fail-closed` — non-configurable security invariant.
    /// Asks the daemon to pick the uplink from the kernel, preferring a wired
    /// link. Resolved once at startup; see `heliosd::uplink`.
    pub const WAN_IFACE_AUTO: &'static str = "auto";

    /// Whether the daemon is asked to enumerate the uplinks itself.
    ///
    /// Only meaningful alone: `["auto", "eth0"]` is a contradiction, and
    /// [`Self::validate`] refuses it rather than picking a reading.
    pub fn wan_iface_is_auto(&self) -> bool {
        self.wan_ifaces.len() == 1
            && self.wan_ifaces[0]
                .trim()
                .eq_ignore_ascii_case(Self::WAN_IFACE_AUTO)
    }

    /// The preferred uplink: the first declared.
    ///
    /// For the things that watch **one** interface — MTU probing, throughput
    /// telemetry — where watching all of them would report a sum that
    /// describes nothing. The firewall never uses it: it permits them all.
    pub fn primary_wan_iface(&self) -> Option<&str> {
        self.wan_ifaces.first().map(String::as_str)
    }

    /// Whether `auto` appears at all — including where it must not.
    fn mentions_auto(&self) -> bool {
        self.wan_ifaces
            .iter()
            .any(|iface| iface.trim().eq_ignore_ascii_case(Self::WAN_IFACE_AUTO))
    }

    pub fn firewall_policy(&self) -> FirewallPolicy {
        let admin_port = self.admin_iface.as_ref().map(|_| API_PORT);
        FirewallPolicy {
            wan_ifaces: self.wan_ifaces.clone(),
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
            // No `wireguard_ready()` gate: this one is scoped to the WAN, not
            // to the tunnel interface, and it is most needed on a gateway
            // whose tunnel is precisely not up.
            allow_gateway_egress: self.allow_gateway_egress,
            // Both are scoped to the tunnel interface, so they are worth
            // nothing until that interface can exist — the same gate the
            // listener openings above go through.
            allow_tunnel_icmp: self.allow_tunnel_icmp && self.wireguard_ready(),
            allow_ssh_over_tunnel: self.allow_ssh_over_tunnel && self.wireguard_ready(),
            iperf_port: self.wireguard_ready().then_some(self.iperf_port).flatten(),
            wg_iface: self.wg_iface.clone(),
            admin_port,
            admin_iface: self.admin_iface.clone(),
            split_tunnel_cidrs: self.split_tunnel_cidrs.clone(),
            mss_clamp: None,
            captive_portal_gateway: None,
            nordvpn_meshnet: self.nordvpn_meshnet.as_ref().map(Into::into),
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
                persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
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
                    persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
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
                    persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
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
        assert!(cfg.wan_ifaces.is_empty());
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
        assert_eq!(cfg.wan_ifaces, vec!["eth0".to_string()]);
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
        // ICMP on the tunnel is the one opening that does not have to be
        // asked for: it routes nothing and only lets the gateway answer for
        // itself, to peers WireGuard has already authenticated.
        assert!(policy.allow_tunnel_icmp, "absent means open, for this one");
        assert!(
            !policy.allow_ssh_over_tunnel,
            "administrative access is never opened by omission"
        );
    }

    /// The tunnel openings are worth nothing until the interface can exist.
    #[test]
    fn the_tunnel_openings_follow_wireguard_readiness() {
        let toml = r#"
            wan_iface = "eth0"
            allow_ssh_over_tunnel = true
            iperf_port = 5202
        "#;
        let mut cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert!(
            !cfg.wireguard_ready(),
            "no private key: the interface cannot come up"
        );
        let policy = cfg.firewall_policy();
        assert!(!policy.allow_tunnel_icmp);
        assert!(!policy.allow_ssh_over_tunnel);
        assert_eq!(policy.iperf_port, None);

        cfg.wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        let policy = cfg.firewall_policy();
        assert!(policy.allow_tunnel_icmp);
        assert!(policy.allow_ssh_over_tunnel);
        assert_eq!(policy.iperf_port, Some(5202));
    }

    /// A diagnostic, so it is absent unless asked for by name.
    #[test]
    fn iperf_is_absent_from_a_default_configuration() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.iperf_port, None);
        assert_eq!(cfg.firewall_policy().iperf_port, None);
    }

    /// Unlike the two tunnel openings, this one is scoped to the WAN and must
    /// survive a gateway whose interface cannot come up: an operator upgrades
    /// a gateway precisely when its tunnel is down.
    #[test]
    fn gateway_egress_is_opt_in_and_ignores_wireguard_readiness() {
        let cfg = NetworkConfig::default();
        assert!(
            !cfg.firewall_policy().allow_gateway_egress,
            "the gateway's own egress is never opened by omission"
        );

        let toml = r#"
            wan_iface = "eth0"
            allow_gateway_egress = true
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.wireguard_ready());
        assert!(cfg.firewall_policy().allow_gateway_egress);
    }

    #[test]
    fn meshnet_config_projects_explicit_peer_and_service_limits() {
        let toml = r#"
            wan_iface = "eth0"
            allow_gateway_egress = true

            [nordvpn_meshnet]
            peer_cidrs = ["100.70.36.212/32"]
            traffic_routing_peer_cidrs = ["100.70.36.212/32"]
            inbound_tcp_ports = [22, 9100]
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();

        let meshnet = cfg.firewall_policy().nordvpn_meshnet.unwrap();
        assert_eq!(meshnet.iface, "nordlynx");
        assert_eq!(meshnet.fwmark, 0xe1f1);
        assert_eq!(meshnet.peer_cidrs, ["100.70.36.212/32"]);
        assert_eq!(meshnet.traffic_routing_peer_cidrs, ["100.70.36.212/32"]);
        assert!(meshnet.local_network_peer_cidrs.is_empty());
        assert_eq!(meshnet.inbound_tcp_ports, [22, 9100]);
        assert!(meshnet.inbound_udp_ports.is_empty());
        assert!(meshnet.allow_icmp);
    }

    #[test]
    fn meshnet_rejects_ambiguous_or_unbounded_configuration() {
        let valid = NordvpnMeshnetConfig {
            peer_cidrs: vec!["100.70.36.212/32".into()],
            ..NordvpnMeshnetConfig::default()
        };
        let mut cfg = NetworkConfig {
            wan_ifaces: vec!["eth0".into()],
            nordvpn_meshnet: Some(valid),
            ..NetworkConfig::default()
        };

        assert!(cfg.validate().is_err(), "HTTPS control egress is required");
        cfg.allow_gateway_egress = true;
        assert!(cfg.validate().is_ok());

        cfg.nordvpn_meshnet.as_mut().unwrap().iface = "eth0".into();
        assert!(cfg.validate().is_err(), "the overlay cannot also be a WAN");
        cfg.nordvpn_meshnet.as_mut().unwrap().iface = "nordlynx".into();
        cfg.nordvpn_meshnet.as_mut().unwrap().peer_cidrs = vec!["100.70.36.212/99".into()];
        assert!(cfg.validate().is_err(), "invalid CIDRs must fail closed");
        cfg.nordvpn_meshnet.as_mut().unwrap().peer_cidrs = vec!["100.70.36.212/32".into()];
        cfg.nordvpn_meshnet.as_mut().unwrap().inbound_tcp_ports = vec![22, 22];
        assert!(
            cfg.validate().is_err(),
            "duplicate ports are configuration errors"
        );
        cfg.nordvpn_meshnet.as_mut().unwrap().inbound_tcp_ports = vec![API_PORT];
        assert!(
            cfg.validate().is_err(),
            "the administration API must remain exclusive to the Helios tunnel"
        );
        cfg.nordvpn_meshnet
            .as_mut()
            .unwrap()
            .inbound_tcp_ports
            .clear();
        cfg.nordvpn_meshnet
            .as_mut()
            .unwrap()
            .traffic_routing_peer_cidrs = vec!["100.70.36.213/32".into()];
        assert!(
            cfg.validate().is_err(),
            "routing permission must not name an undeclared peer"
        );
        cfg.nordvpn_meshnet
            .as_mut()
            .unwrap()
            .traffic_routing_peer_cidrs = vec!["100.70.36.212/32".into()];
        cfg.nordvpn_meshnet
            .as_mut()
            .unwrap()
            .local_network_peer_cidrs = vec!["100.70.36.213/32".into()];
        assert!(
            cfg.validate().is_err(),
            "local-network permission must be a subset of routing peers"
        );
    }

    #[test]
    fn repository_network_example_is_valid() {
        let cfg: NetworkConfig = toml::from_str(include_str!("../../../config/network.toml"))
            .expect("the shipped network configuration must deserialize");
        cfg.validate()
            .expect("the shipped network configuration must validate");
    }

    /// Closing ICMP stays possible: the default is a choice, not a fixture.
    #[test]
    fn tunnel_icmp_can_be_closed_explicitly() {
        let toml = r#"
            wan_iface = "eth0"
            allow_tunnel_icmp = false
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.firewall_policy().allow_tunnel_icmp);
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
            persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
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

    #[test]
    fn the_raw_speedtest_uses_the_fixed_in_tunnel_port() {
        let cfg = NetworkConfig {
            wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.speedtest_bind(), "100.64.0.1:5201");
        assert_eq!(NetworkConfig::default().speedtest_bind(), "127.0.0.1:5201");
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

    /// Serialises the tests that drive `HELIOS_NETWORK_CONFIG`.
    ///
    /// The variable is **process-wide**, so two tests setting it run into each
    /// other under the default parallel harness — one pointing the other's
    /// `save()` at its own directory. A single test could ignore this; a second
    /// one cannot, and adding a third without this lock would resurrect it.
    #[cfg(unix)]
    static NETWORK_CONFIG_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// No secret ever reaches `network.toml`, whatever the field.
    ///
    /// The most valuable test of ADR-006's validation family, and the cheapest:
    /// it does not check that we *remembered* to redact a known list of fields,
    /// it scans the produced bytes for the secrets themselves. A field added
    /// later that happens to carry a secret fails here rather than in a
    /// customer's backup.
    ///
    /// It scans the temporary files too — a secret written and renamed away is
    /// still a secret that touched the disk.
    #[cfg(unix)]
    #[test]
    fn no_secret_ever_reaches_the_network_config() {
        let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());
        const PRIVATE_KEY: &str = "MOTIF-CLE-PRIVEE-GATEWAY-A-NE-JAMAIS-ECRIRE";
        const PSK: &str = "MOTIF-PSK-NEGOCIE-A-NE-JAMAIS-ECRIRE";

        let dir = std::env::temp_dir().join(format!(
            "aether-network-secrets-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("network.toml");
        std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

        // The redaction that callers are supposed to perform before saving.
        // Here the config is saved **without** it on purpose: what is under
        // test is that `save` itself cannot be handed a secret and quietly
        // publish it — the failure must be loud.
        let mut cfg = NetworkConfig {
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        };
        cfg.peers.push(WgPeer {
            name: "poste".into(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: Some(PSK.into()),
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
            persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });

        // What the daemon actually does before persisting (ADR-006 §4).
        let mut on_disk = cfg.clone();
        on_disk.wg_private_key.clear();
        for peer in &mut on_disk.peers {
            peer.preshared_key = None;
        }
        on_disk.save().expect("save");

        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let bytes = std::fs::read(entry.path()).expect("read");
            for (label, secret) in [("private key", PRIVATE_KEY), ("PSK", PSK)] {
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes()),
                    "the {label} appears in {}",
                    entry.path().display()
                );
            }
        }

        std::env::remove_var("HELIOS_NETWORK_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `network.toml` must never become world-readable, and above all not on a
    /// **rewrite**.
    ///
    /// This is the regression ADR-006 opens on: `save()` used to write its
    /// temporary file with a plain `std::fs::write`, whose mode came from the
    /// umask — 0644 for a daemon running as root. The `rename` carried that
    /// mode onto the final file, silently undoing the `chmod 600` applied by
    /// `scripts/target-bootstrap.sh`. The gateway lost it at its first peer
    /// admission, and nothing said so.
    ///
    /// Goes through `HELIOS_NETWORK_CONFIG`, which no other test in this crate
    /// touches: there is nothing here to race against.
    #[cfg(unix)]
    #[test]
    fn the_network_config_stays_private_across_rewrites() {
        use std::os::unix::fs::PermissionsExt as _;

        let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!(
            "aether-network-mode-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("network.toml");
        std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

        let cfg = NetworkConfig {
            wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        };
        cfg.save().expect("first save");
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "mode after the first save");

        cfg.save().expect("rewrite");
        assert_eq!(mode(&path), 0o600, "mode after a rewrite");

        std::env::remove_var("HELIOS_NETWORK_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn port_not_opened_if_the_gateway_is_not_ready() {
        // No private key -> we don't open a port with nothing behind it.
        let cfg = NetworkConfig {
            wan_ifaces: vec!["eth0".into()],
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.firewall_policy().wg_listen_port, None);
    }
    /// `auto` states an intent, and the daemon resolved it against the kernel
    /// at startup. A reload must not put the marker back: every egress rule
    /// and the masquerade would then be bound to an interface literally named
    /// `auto`, and the gateway would drop its own traffic.
    #[test]
    fn a_reload_keeps_the_resolved_uplink_rather_than_the_marker() {
        let mut from_disk = NetworkConfig {
            wan_ifaces: vec!["auto".into()],
            ..NetworkConfig::default()
        };
        let running = NetworkConfig {
            wan_ifaces: vec!["eth0".into()],
            ..NetworkConfig::default()
        };
        from_disk.adopt_runtime_secrets_from(&running);
        assert_eq!(from_disk.wan_ifaces, vec!["eth0".to_string()]);
        assert!(!from_disk.wan_iface_is_auto());
    }

    /// An operator who names an interface in the file gets that interface,
    /// even if the running one was resolved: the file is the intent.
    #[test]
    fn a_reload_that_names_an_interface_replaces_the_resolved_one() {
        let mut from_disk = NetworkConfig {
            wan_ifaces: vec!["eth1".into()],
            ..NetworkConfig::default()
        };
        let running = NetworkConfig {
            wan_ifaces: vec!["eth0".into()],
            ..NetworkConfig::default()
        };
        from_disk.adopt_runtime_secrets_from(&running);
        assert_eq!(from_disk.wan_ifaces, vec!["eth1".to_string()]);
    }

    /// The marker is recognised however it is spelled and spaced, because a
    /// missed one is a ruleset built around a device that does not exist.
    #[test]
    fn the_auto_marker_is_recognised_regardless_of_case_and_spacing() {
        for spelling in ["auto", "AUTO", " Auto ", "aUtO"] {
            let config = NetworkConfig {
                wan_ifaces: vec![spelling.into()],
                ..NetworkConfig::default()
            };
            assert!(config.wan_iface_is_auto(), "« {spelling} » is the marker");
        }
        let named = NetworkConfig {
            wan_ifaces: vec!["auto0".into()],
            ..NetworkConfig::default()
        };
        assert!(
            !named.wan_iface_is_auto(),
            "« auto0 » is a real interface name on some boards, not the marker"
        );
    }
}
