use std::{collections::HashSet, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

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
/// Deliberately derives neither `Clone` nor `Serialize`.
///
/// **`Serialize`**: the only shape that reaches `network.toml` is
/// [`PersistedNetworkConfig`], an allow-list. The derive was dead code that
/// would have made any `toml::to_string(&config)` write the gateway identity
/// to disk — the one thing ADR-006 §4 exists to prevent.
///
/// **`Clone`**: this structure carries the gateway's private key and every
/// peer PSK. Duplicating it is a decision, not a convenience, so it goes
/// through [`NetworkConfig::duplicate`] — the same reasoning, and the same
/// name, as [`SecretString::duplicate`].
///
/// `Debug` **is** derived, and that is safe by construction rather than by
/// vigilance: the two secret fields are [`SecretString`], whose `Debug`
/// prints nothing. A field added later leaks only if someone declares it with
/// a non-secret type — which is the point of putting the rule on the type
/// (ADR-006 §5).
#[derive(Debug, PartialEq, Eq, Deserialize)]
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
    ///
    /// Matches the source address only. For an address the gateway reaches
    /// through one of its own overlays, use [`Self::admin_ifaces`] instead:
    /// see [`crate::FirewallPolicy::admin_ifaces`] for why an address list is
    /// the wrong shape for a recovery path.
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
    /// Out-of-band administration interfaces (`tailscale0`, `nordlynx`, …).
    ///
    /// SSH is accepted on them whatever the tunnel state, so they stay usable
    /// when Helios itself is down. One entry covers every address the
    /// interface carries, v4 and v6 — see
    /// [`crate::FirewallPolicy::admin_ifaces`].
    #[serde(default, alias = "admin_iface_extra")]
    pub admin_ifaces: Vec<String>,
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
    ///
    /// Nominally it comes from the TPM vault and this field is filled at
    /// startup; a legacy `network.toml` may still carry it in the clear,
    /// which is why it still deserializes (ADR-006 §4).
    #[serde(default)]
    pub wg_private_key: SecretString,
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
///
/// Same derives, and the same reasons, as [`NetworkConfig`]: it may hold a
/// PSK. Duplication goes through [`WgPeer::duplicate`].
#[derive(Debug, PartialEq, Eq, Deserialize)]
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
    ///
    /// Runtime-only for a negotiated PSK; a static one lives in the sealed
    /// table and is refilled here at startup. Never written back to the file.
    #[serde(default)]
    pub preshared_key: Option<SecretString>,
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

/// Allow-listed projection of [`NetworkConfig`] for `network.toml`.
///
/// Runtime configuration deliberately contains material that must not reach
/// disk. Keeping persistence as a separate shape makes new fields fail closed:
/// adding one to [`NetworkConfig`] does not serialize it until this projection
/// explicitly classifies it as public configuration.
#[derive(Serialize)]
struct PersistedNetworkConfig<'a> {
    #[serde(rename = "wan_iface")]
    wan_ifaces: &'a [String],
    lan_ifaces: &'a [String],
    allow_ssh_from: &'a [String],
    admin_ifaces: &'a [String],
    allow_dhcp_on_wan: bool,
    allow_client_internet: bool,
    allow_tunnel_icmp: bool,
    allow_gateway_egress: bool,
    allow_ssh_over_tunnel: bool,
    iperf_port: Option<u16>,
    admin_iface: &'a Option<String>,
    split_tunnel_cidrs: &'a [String],
    nordvpn_meshnet: Option<PersistedNordvpnMeshnetConfig<'a>>,
    wg_iface: &'a str,
    wg_private_key: &'a str,
    wg_address: &'a str,
    wg_listen_port: u16,
    key_negotiation_port: Option<u16>,
    peers: Vec<PersistedWgPeer<'a>>,
    static_peer_addrs: &'a [String],
    escrow_public_key: &'a Option<String>,
}

#[derive(Serialize)]
struct PersistedNordvpnMeshnetConfig<'a> {
    iface: &'a str,
    fwmark: u32,
    peer_cidrs: &'a [String],
    traffic_routing_peer_cidrs: &'a [String],
    local_network_peer_cidrs: &'a [String],
    inbound_tcp_ports: &'a [u16],
    inbound_udp_ports: &'a [u16],
    allow_icmp: bool,
}

#[derive(Serialize)]
struct PersistedWgPeer<'a> {
    name: &'a str,
    public_key: &'a str,
    address: &'a str,
    admin: bool,
    key_negotiation_certificate_sha256: &'a Option<String>,
    key_negotiation_pq_certificate_sha256: &'a Option<String>,
    minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode,
    persistent_keepalive_secs: u16,
}

impl<'a> PersistedNetworkConfig<'a> {
    fn new(config: &'a NetworkConfig, include_development_identity: bool) -> Self {
        Self {
            wan_ifaces: &config.wan_ifaces,
            lan_ifaces: &config.lan_ifaces,
            allow_ssh_from: &config.allow_ssh_from,
            admin_ifaces: &config.admin_ifaces,
            allow_dhcp_on_wan: config.allow_dhcp_on_wan,
            allow_client_internet: config.allow_client_internet,
            allow_tunnel_icmp: config.allow_tunnel_icmp,
            allow_gateway_egress: config.allow_gateway_egress,
            allow_ssh_over_tunnel: config.allow_ssh_over_tunnel,
            iperf_port: config.iperf_port,
            admin_iface: &config.admin_iface,
            split_tunnel_cidrs: &config.split_tunnel_cidrs,
            nordvpn_meshnet: config.nordvpn_meshnet.as_ref().map(|meshnet| {
                PersistedNordvpnMeshnetConfig {
                    iface: &meshnet.iface,
                    fwmark: meshnet.fwmark,
                    peer_cidrs: &meshnet.peer_cidrs,
                    traffic_routing_peer_cidrs: &meshnet.traffic_routing_peer_cidrs,
                    local_network_peer_cidrs: &meshnet.local_network_peer_cidrs,
                    inbound_tcp_ports: &meshnet.inbound_tcp_ports,
                    inbound_udp_ports: &meshnet.inbound_udp_ports,
                    allow_icmp: meshnet.allow_icmp,
                }
            }),
            wg_iface: &config.wg_iface,
            // The one place the identity may legitimately reach a
            // serializer, and only under the two named exceptions. Every
            // other field of this projection is public configuration.
            wg_private_key: if include_development_identity {
                config.wg_private_key.expose()
            } else {
                ""
            },
            wg_address: &config.wg_address,
            wg_listen_port: config.wg_listen_port,
            key_negotiation_port: config.key_negotiation_port,
            peers: config
                .peers
                .iter()
                .map(|peer| PersistedWgPeer {
                    name: &peer.name,
                    public_key: &peer.public_key,
                    address: &peer.address,
                    admin: peer.admin,
                    key_negotiation_certificate_sha256: &peer.key_negotiation_certificate_sha256,
                    key_negotiation_pq_certificate_sha256: &peer
                        .key_negotiation_pq_certificate_sha256,
                    minimum_key_negotiation_mode: peer.minimum_key_negotiation_mode,
                    persistent_keepalive_secs: peer.persistent_keepalive_secs,
                })
                .collect(),
            static_peer_addrs: &config.static_peer_addrs,
            escrow_public_key: &config.escrow_public_key,
        }
    }
}

/// Gateway-side keep-alive interval, in seconds.
///
/// Matches the client default. Short enough that a rekey happens well inside
/// the reclamation window, long enough to be one 32-byte packet per peer per
/// 25 seconds.
pub const DEFAULT_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

impl WgPeer {
    /// Makes a second, independent copy of the peer, PSK included.
    ///
    /// Replaces the `Clone` derive, for the reason [`NetworkConfig::duplicate`]
    /// gives.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            address: self.address.clone(),
            admin: self.admin,
            preshared_key: self.preshared_key.as_ref().map(SecretString::duplicate),
            key_negotiation_certificate_sha256: self.key_negotiation_certificate_sha256.clone(),
            key_negotiation_pq_certificate_sha256: self
                .key_negotiation_pq_certificate_sha256
                .clone(),
            minimum_key_negotiation_mode: self.minimum_key_negotiation_mode,
            persistent_keepalive_secs: self.persistent_keepalive_secs,
        }
    }
}

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
        match std::fs::read_to_string(&path).map(zeroize::Zeroizing::new) {
            // The file's text is `Zeroizing` because a legacy `network.toml`
            // still carries the gateway identity in the clear, and a
            // hand-edited one a static PSK: the parse buffer holds both
            // (ADR-006 §5).
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

    /// Persists an already public network config atomically (rename).
    ///
    /// Secret-bearing runtime state is refused rather than silently redacted:
    /// an offline caller cannot know whether a plaintext gateway identity is a
    /// disposable development key or the only copy of a legacy identity.
    pub fn save(&self) -> Result<()> {
        if !self.wg_private_key.is_empty()
            || self.peers.iter().any(|peer| peer.preshared_key.is_some())
        {
            return Err(HeliosError::Config(
                "refusing to persist runtime secrets through NetworkConfig::save".into(),
            ));
        }
        self.save_projected(false)
    }

    /// Persists the allow-listed public projection of runtime configuration.
    ///
    /// This is the daemon path: its gateway identity already lives in the TPM
    /// vault and peer PSKs are runtime-only material.
    pub fn save_redacted(&self) -> Result<()> {
        self.save_projected(false)
    }

    /// Persists a development configuration, including its simulated gateway
    /// identity but still excluding every peer PSK.
    ///
    /// A dry-run has no TPM vault, so its disposable identity has no other
    /// durable home. The separate name keeps that exception explicit at each
    /// call site; production code must use [`Self::save`].
    pub fn save_for_development(&self) -> Result<()> {
        self.save_projected(true)
    }

    /// Rewrites a legacy configuration while preserving the plaintext gateway
    /// identity it already contained and excluding every peer PSK.
    ///
    /// This narrow compatibility path prevents an in-place migration from
    /// deleting the gateway's only identity before it has been sealed. New
    /// production writes must use [`Self::save`] or [`Self::save_redacted`].
    pub fn save_preserving_legacy_identity(&self) -> Result<()> {
        self.save_projected(true)
    }

    fn save_projected(&self, include_development_identity: bool) -> Result<()> {
        self.validate()?;
        let path = Self::path();
        let persisted = PersistedNetworkConfig::new(self, include_development_identity);
        let raw =
            toml::to_string_pretty(&persisted).map_err(|e| HeliosError::Config(e.to_string()))?;
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
    /// Makes a second, independent copy of the whole configuration.
    ///
    /// Replaces the `Clone` derive. The name is the point: this copy carries
    /// the gateway identity and every peer PSK, so each call site is a place
    /// to justify in review — exactly like [`SecretString::duplicate`], whose
    /// reasoning this follows (ADR-006 §5).
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            wan_ifaces: self.wan_ifaces.clone(),
            lan_ifaces: self.lan_ifaces.clone(),
            allow_ssh_from: self.allow_ssh_from.clone(),
            admin_ifaces: self.admin_ifaces.clone(),
            allow_dhcp_on_wan: self.allow_dhcp_on_wan,
            allow_client_internet: self.allow_client_internet,
            allow_tunnel_icmp: self.allow_tunnel_icmp,
            allow_gateway_egress: self.allow_gateway_egress,
            allow_ssh_over_tunnel: self.allow_ssh_over_tunnel,
            iperf_port: self.iperf_port,
            admin_iface: self.admin_iface.clone(),
            split_tunnel_cidrs: self.split_tunnel_cidrs.clone(),
            nordvpn_meshnet: self.nordvpn_meshnet.clone(),
            wg_iface: self.wg_iface.clone(),
            wg_private_key: self.wg_private_key.duplicate(),
            wg_address: self.wg_address.clone(),
            wg_listen_port: self.wg_listen_port,
            key_negotiation_port: self.key_negotiation_port,
            peers: self.peers.iter().map(WgPeer::duplicate).collect(),
            static_peer_addrs: self.static_peer_addrs.clone(),
            escrow_public_key: self.escrow_public_key.clone(),
        }
    }

    pub fn adopt_runtime_secrets_from(&mut self, current: &Self) {
        if self.wan_iface_is_auto() && !current.wan_iface_is_auto() {
            self.wan_ifaces.clone_from(&current.wan_ifaces);
        }
        if self.wg_private_key.is_empty() {
            self.wg_private_key = current.wg_private_key.duplicate();
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
                peer.preshared_key = known.preshared_key.as_ref().map(SecretString::duplicate);
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
        for iface in &self.admin_ifaces {
            let iface = iface.trim();
            if iface.is_empty() {
                return Err(HeliosError::Config(
                    "admin_ifaces: an empty interface name matches nothing, and an administration \
                     opening that matches nothing is a lockout waiting for the next restart"
                        .into(),
                ));
            }
            if iface == self.wg_iface.trim() {
                return Err(HeliosError::Config(format!(
                    "admin_ifaces: {iface} is the Helios tunnel interface — SSH through the \
                     tunnel is allow_ssh_over_tunnel, which is opted into deliberately"
                )));
            }
            if self.wan_ifaces.iter().any(|wan| wan.trim() == iface) {
                return Err(HeliosError::Config(format!(
                    "admin_ifaces: {iface} is a WAN interface — that would expose SSH to the \
                     Internet, not to an out-of-band overlay"
                )));
            }
        }
        // The lockout this catches: a deployment run *through* the Helios
        // tunnel reads its own source address — a peer VIP — and pins SSH to
        // it. The rule then survives only as long as the tunnel does, so the
        // next restart of `heliosd` takes remote access down with it, and the
        // one interface that could let the operator back in is the one that
        // just went away. `admin_ifaces` is the shape that survives.
        if self.wireguard_ready() {
            for source in &self.allow_ssh_from {
                if Self::cidr_contains(&self.wg_address, source) {
                    return Err(HeliosError::Config(format!(
                        "allow_ssh_from: {source} is inside the Helios tunnel network {} — it \
                         only matches while the tunnel is up, so it cannot be the way back in \
                         when it is down. Use allow_ssh_over_tunnel for access through the \
                         tunnel, or admin_ifaces for an out-of-band overlay.",
                        self.wg_address
                    )));
                }
            }
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
            if port == SPEEDTEST_PORT {
                return Err(HeliosError::Config(format!(
                    "key_negotiation_port and the built-in speedtest port ({SPEEDTEST_PORT}) must be distinct"
                )));
            }
        }
        if self.wg_listen_port == SPEEDTEST_PORT {
            return Err(HeliosError::Config(format!(
                "wg_listen_port and the built-in speedtest port ({SPEEDTEST_PORT}) must be distinct"
            )));
        }
        if self.iperf_port == Some(SPEEDTEST_PORT) {
            return Err(HeliosError::Config(format!(
                "iperf_port and the built-in speedtest port ({SPEEDTEST_PORT}) must be distinct"
            )));
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
        !self.wg_private_key.is_empty() && !self.wg_address.trim().is_empty()
    }

    /// Out-of-band administration interfaces, trimmed and deduplicated.
    ///
    /// An entry naming the Helios interface is dropped rather than rendered:
    /// that opening is `allow_ssh_over_tunnel`, and letting it in here would
    /// turn an opt-in flag into something a typo can switch on.
    /// [`Self::validate`] refuses the overlap outright, so this only guards
    /// the paths that build a policy without validating first.
    pub fn admin_ifaces(&self) -> Vec<String> {
        let mut resolved: Vec<String> = Vec::new();
        for iface in &self.admin_ifaces {
            let iface = iface.trim();
            if iface.is_empty() || iface == self.wg_iface.trim() {
                continue;
            }
            if !resolved.iter().any(|kept| kept == iface) {
                resolved.push(iface.to_string());
            }
        }
        resolved
    }

    /// Is `candidate` an address or CIDR contained in `network`?
    ///
    /// Both sides are `addr/len`, a bare address counting as a full-length
    /// prefix. Anything unparseable answers `false`: this backs a refusal,
    /// and refusing a configuration nobody can interpret is not this
    /// function's call to make.
    fn cidr_contains(network: &str, candidate: &str) -> bool {
        fn parse(text: &str) -> Option<(std::net::IpAddr, u8)> {
            let text = text.trim();
            let (addr, len) = match text.split_once('/') {
                Some((addr, len)) => (addr, Some(len)),
                None => (text, None),
            };
            let addr: std::net::IpAddr = addr.trim().parse().ok()?;
            let full = if addr.is_ipv4() { 32 } else { 128 };
            let len = match len {
                Some(len) => len.trim().parse::<u8>().ok()?,
                None => full,
            };
            (len <= full).then_some((addr, len))
        }
        fn octets(addr: std::net::IpAddr) -> Vec<u8> {
            match addr {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            }
        }

        let (Some((net_addr, net_len)), Some((cand_addr, cand_len))) =
            (parse(network), parse(candidate))
        else {
            return false;
        };
        if net_addr.is_ipv4() != cand_addr.is_ipv4() {
            return false;
        }
        // A candidate wider than the network cannot be inside it, and a
        // *wider* candidate is the dangerous direction: `0.0.0.0/0` must not
        // pass as « not in the tunnel range » on a technicality.
        if cand_len < net_len {
            return false;
        }
        let (net, cand) = (octets(net_addr), octets(cand_addr));
        let (whole, spare) = (net_len as usize / 8, net_len as usize % 8);
        if net[..whole] != cand[..whole] {
            return false;
        }
        if spare == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - spare);
        net[whole] & mask == cand[whole] & mask
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
            // Deliberately ungated by `wireguard_ready()`, unlike the tunnel
            // openings below: this is the way back in when the tunnel cannot
            // come up, so gating it on the tunnel would close it exactly when
            // the operator needs it. `admin_ifaces()` drops any entry naming
            // the tunnel interface, which is `allow_ssh_over_tunnel`'s job.
            admin_ifaces: self.admin_ifaces(),
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
mod tests;
