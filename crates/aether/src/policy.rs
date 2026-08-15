use serde::{Deserialize, Serialize};

/// NordVPN Meshnet traffic explicitly admitted alongside the Helios tunnel.
///
/// Meshnet is a second authenticated WireGuard overlay, not an uplink. Its
/// transport leaves through a WAN interface with NordVPN's packet mark, while
/// application traffic enters and leaves through `iface`. Keeping both
/// identities in the policy prevents `nordlynx` from being mistaken for a WAN
/// and preserves the fail-closed treatment of forwarded traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NordvpnMeshnetPolicy {
    /// Interface owned by NordVPN/libtelio.
    pub iface: String,
    /// Packet mark applied by libtelio to relay, STUN and direct-path traffic.
    pub fwmark: u32,
    /// Meshnet peers allowed to exchange application traffic with the gateway.
    pub peer_cidrs: Vec<String>,
    /// Meshnet peers allowed by NordVPN to route traffic through the gateway.
    pub traffic_routing_peer_cidrs: Vec<String>,
    /// Routing peers additionally allowed by NordVPN to reach private LANs.
    pub local_network_peer_cidrs: Vec<String>,
    /// TCP services exposed to those peers on the gateway.
    pub inbound_tcp_ports: Vec<u16>,
    /// UDP services exposed to those peers on the gateway.
    pub inbound_udp_ports: Vec<u16>,
    /// Answers ICMP arriving from those peers through the Meshnet interface.
    pub allow_icmp: bool,
}

/// Firewall behavior when the tunnel is not operational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    /// Kill-switch: block everything (except IKE) as long as the tunnel is not Up.
    #[default]
    FailClosed,
    /// Degraded mode: let traffic through in the clear if the tunnel drops (not recommended).
    FailOpen,
}

/// High-level description of what the firewall must enforce.
///
/// This is the input to the rule-rendering engine ([`crate`] consumed by
/// `helios-firewall`). It is deliberately declarative: it describes the
/// intent, not nftables syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// Interfaces towards the Internet, in order of preference.
    ///
    /// A **set**, not a choice: a gateway with a cable and a radio must keep
    /// working when the cable is unplugged, and the firewall is the one thing
    /// that must not stand in the way. Every rule below that names the WAN is
    /// emitted once per interface, so whichever one the kernel routes through
    /// at the moment is permitted — failover costs no restart and no reload.
    ///
    /// The order carries the operator's preference and nothing else. What
    /// decides where a packet actually leaves is the routing table, and route
    /// metrics are where a preference between two live uplinks is expressed —
    /// see `heliosd::uplink`.
    pub wan_ifaces: Vec<String>,
    /// LAN-side interfaces whose traffic must go through the tunnel.
    pub lan_ifaces: Vec<String>,
    /// Peers (IP addresses) reachable in the clear for WireGuard transport
    /// (UDP 51820). The only traffic allowed to leave the WAN outside the
    /// tunnel. Useful for static peers (site-to-site); empty in pure
    /// road-warrior mode.
    pub wg_peers: Vec<String>,
    /// UDP port on which the gateway **listens** for WireGuard clients.
    ///
    /// `Some(port)` opens this port **inbound** from any source: road
    /// warriors roam, their IP is unknown in advance. This is the only
    /// inbound opening of the fail-closed model, and it is essential —
    /// without it no client can handshake. `None` = no server role.
    pub wg_listen_port: Option<u16>,
    /// Public UDP port of the pre-WireGuard key-negotiation service.
    ///
    /// It is deliberately separate from the kernel-owned WireGuard socket.
    /// `None` means that no key-negotiation listener is ready and the firewall
    /// must keep the port closed.
    pub key_negotiation_port: Option<u16>,
    /// Behavior outside the tunnel.
    pub mode: PolicyMode,
    /// CIDR or IPs allowed on port 22 (administrative SSH), even when the
    /// kill-switch is engaged.
    pub allow_ssh_from: Vec<String>,
    /// Allows DHCP (UDP 67/68) on the WAN interface, kill-switch engaged.
    ///
    /// A gateway normally has a fixed address, hence the default of `false`.
    /// But a gateway placed behind a box often gets its address from a
    /// lease: without this opening, it loses its address at the first
    /// renewal — hence its tunnel and its administration at the same time,
    /// and several hours after a startup that seemed to succeed.
    pub allow_dhcp_on_wan: bool,
    /// Routes tunnel clients' traffic to the Internet: forward
    /// `wg_iface -> wan_iface` and masquerade, **only** in a state where
    /// traffic is allowed.
    ///
    /// Closed by default. What this does not cover: DNS. The client keeps
    /// its resolver, so its requests leave outside the tunnel — an Orion
    /// profile does not yet know how to push a resolver.
    pub allow_client_internet: bool,
    /// WireGuard interface, source of client traffic to route.
    pub wg_iface: String,
    /// TCP port of the REST/WS administration interface.
    pub admin_port: Option<u16>,
    /// Exclusive network interface for administration access (e.g. `helios0`).
    pub admin_iface: Option<String>,
    /// Local CIDRs bypassing the tunnel (dynamic split-tunneling).
    /// Empty = all WAN traffic goes through the tunnel (default behavior).
    pub split_tunnel_cidrs: Vec<String>,
    /// Post-PMTUD MSS clamping (bytes). `None` = no clamping.
    /// Computed automatically when the tunnel starts.
    pub mss_clamp: Option<u16>,
    /// IP of the captive portal gateway.
    /// Set upon detection; HTTP/HTTPS towards this IP are allowed.
    pub captive_portal_gateway: Option<String>,
    /// Answers ICMP on the tunnel interface.
    ///
    /// Open by default, unlike everything else this policy opens, and the
    /// asymmetry is deliberate: this routes nothing and exposes nothing
    /// outward. It lets the gateway answer for **itself**, on an interface
    /// only peers already admitted by WireGuard can reach.
    ///
    /// What closing it costs is a diagnostic dead end. `ping 100.64.0.1` is
    /// the first thing anyone tries on a fresh tunnel, and under a `drop`
    /// policy it times out exactly like a tunnel that never mounted — so the
    /// one test people reach for first is the one that cannot distinguish
    /// success from failure.
    pub allow_tunnel_icmp: bool,
    /// Lets the gateway open outbound connections **for itself**: name
    /// resolution, time synchronization and package fetching, on the WAN
    /// interface only.
    ///
    /// Closed by default, like everything else here. But what closing it
    /// costs is not obvious, because the `output` chain is the one nobody
    /// looks at: under the fail-closed policy it accepts loopback,
    /// `established` traffic, DHCP renewal and the site-to-site WireGuard
    /// transport — and nothing else. A gateway in that state cannot resolve a
    /// name, cannot reach an NTP server and cannot fetch a package. It is not
    /// a DNS failure, though that is exactly what it looks like: `apt` prints
    /// `Ign` for every source and hangs at 0 %, because the resolver's query
    /// to the LAN leaves as a **new** flow and the policy drops it.
    ///
    /// Two consequences that are worth naming, since neither announces
    /// itself. `helios-ctl update` runs `apt-get update` **on the gateway**,
    /// so the product's own OS-upgrade path cannot work while its own
    /// kill-switch is applied. And without NTP the clock drifts, on the
    /// machine whose job is to check certificate validity dates.
    ///
    /// Note what this does **not** do: it opens nothing inbound, forwards
    /// nothing, and gives no client anything. It is the gateway's own
    /// traffic, which was never meant to go through a tunnel — the
    /// kill-switch protects what the gateway *relays*, and that stays in the
    /// `forward` chain, untouched by this flag.
    ///
    /// Deliberately **not** gated on the tunnel state, unlike
    /// [`Self::allow_client_internet`]: an operator upgrades a gateway
    /// precisely when its tunnel is down, and a flag that closed itself in
    /// that moment would be closed exactly when it is needed.
    pub allow_gateway_egress: bool,
    /// Accepts SSH **arriving through the tunnel**.
    ///
    /// Closed by default: administrative access is what an attacker wants
    /// most, and the fail-closed model opens it only on request.
    ///
    /// Note what this is not. [`Self::allow_ssh_from`] filters on the source
    /// address alone, with no interface constraint — putting the CGNAT range
    /// there would accept a packet forging that source **from the WAN**. This
    /// rule is scoped to the tunnel interface instead, so it cannot be
    /// reached by anything WireGuard has not already authenticated.
    pub allow_ssh_over_tunnel: bool,
    /// Port of an `iperf3` measurement, on the tunnel interface, **both ways**.
    ///
    /// `None` — the default — keeps it closed. This is a diagnostic, not a
    /// service: it exists to check the built-in speedtest against a reference
    /// implementation, and an always-open `iperf3` is an always-open surface.
    ///
    /// # Why both chains, unlike every other opening here
    ///
    /// The other tunnel rules answer for the gateway: something arrives, the
    /// reply leaves under `ct state established`. `iperf3` is used in both
    /// roles. Server on the gateway, the `input` rule is enough. Server on the
    /// **client** — the usual case, since that is the machine one already sits
    /// at — the gateway opens the connection, and a new outbound flow on
    /// `wg_iface` matches nothing in the `output` chain: under the fail-closed
    /// policy it is dropped. The symptom is `iperf3 -c` hanging at
    /// "Connecting to host", which reads as a client that is not listening.
    ///
    /// Scoped by **interface**, never by address, for the reason spelled out
    /// on [`Self::allow_ssh_over_tunnel`]: only WireGuard puts packets on
    /// `wg_iface`, and only for an already-authenticated peer.
    pub iperf_port: Option<u16>,
    /// Optional NordVPN Meshnet overlay. Absent means no Meshnet opening.
    pub nordvpn_meshnet: Option<NordvpnMeshnetPolicy>,
}

impl FirewallPolicy {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.mode, PolicyMode::FailClosed)
    }
}
