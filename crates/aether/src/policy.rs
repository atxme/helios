use serde::{Deserialize, Serialize};

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
    /// Interface towards the Internet (e.g. `eth0`, the Realtek RTL8111HS controller).
    pub wan_iface: String,
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
}

impl FirewallPolicy {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.mode, PolicyMode::FailClosed)
    }
}
