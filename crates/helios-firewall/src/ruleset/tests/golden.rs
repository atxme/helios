//! Golden snapshots of the **complete, ordered** ruleset produced by
//! [`render`].
//!
//! The other test files in this directory assert on one behavior at a time:
//! they ask whether a rule exists, in which chain, with which matches. None of
//! them can see a rule that moved. In an nftables chain the order is semantic —
//! first match wins — so a rule that keeps its content but changes position
//! changes the firewall. A refactor of `render` that reorders two `push` calls
//! is exactly that, and it passes every behavioral test in this directory.
//!
//! These snapshots close that gap. They capture the whole `Ruleset`: the
//! default verdict, the MSS clamp, the masquerade uplinks, and every rule in
//! `rules` order with its chain — so a change of content *or* of position
//! fails. The expected text is literal and readable in review on purpose: a
//! snapshot nobody can read in a diff protects nothing.
//!
//! The cases are chosen to cover the branches of `render`, not to enumerate
//! the product of its flags; each one is justified where it is defined.

use super::super::*;
use super::support::policy;
use aether::{NordvpnMeshnetPolicy, PolicyMode};

/// Renders the whole ruleset as ordered, comparable text.
///
/// Rules are emitted in `rules` order — not grouped by chain — because that
/// vector order is what a chain-by-chain view cannot show: two rules of the
/// same chain keep their relative order, and a rule moved across a section
/// boundary shows up here even when its own chain is untouched.
fn snapshot(rs: &Ruleset) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "default {}\n",
        match rs.default_verdict {
            Verdict::Accept => "accept",
            Verdict::Drop => "drop",
        }
    ));
    out.push_str(&format!(
        "mss clamp {}\n",
        match rs.mss_clamp {
            Some(value) => value.to_string(),
            None => "none".to_string(),
        }
    ));
    out.push_str(&format!("masquerade [{}]\n", rs.masquerade_out.join(", ")));
    for rule in &rs.rules {
        out.push_str(&format!("{} {rule}\n", rule.chain.as_str()));
    }
    out
}

fn assert_golden(name: &str, rs: &Ruleset, expected: &str) {
    let rendered = snapshot(rs);
    assert_eq!(
        rendered, expected,
        "{name}: the rendered ruleset no longer matches its golden. A rule \
         changed content, chain, verdict — or position. Position is not \
         cosmetic: in an nftables chain the first match wins.\n\
         --- rendered ---\n{rendered}--- expected ---\n{expected}"
    );
}

/// Baseline fail-closed gateway, kill-switch engaged.
///
/// Everything optional is off, which is what makes this case the reference for
/// what is emitted *unconditionally*: the head-of-chain openings, the
/// always-allowed loopback/established pairs, the Astra channel, both public
/// listeners, the site-to-site transport and the tunnel speedtest. Nothing
/// gated on the tunnel state appears.
const DOWN_FAIL_CLOSED: &str = "\
default drop
mss clamp none
masquerade []
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
input iifname \"eth0\" udp dport 51820 accept
output oifname \"eth0\" udp sport 51820 accept
input iifname \"eth0\" udp dport 51821 accept
output oifname \"eth0\" udp sport 51821 accept
output oifname \"eth0\" ip daddr 203.0.113.10 udp dport 51820 accept
input iifname \"helios0\" tcp dport 55182 accept
input iifname \"helios0\" udp dport 55182 accept
";

#[test]
fn golden_tunnel_down_fail_closed() {
    assert_golden(
        "tunnel down, fail-closed",
        &render(&policy(), TunnelState::Down),
        DOWN_FAIL_CLOSED,
    );
}

/// The same policy with the tunnel `Up`.
///
/// The single added line is the whole point: `allow_client_internet` is off,
/// so `Up` opens the site-to-site LAN forward and nothing else — no
/// road-warrior egress, no masquerade. The diff against
/// [`DOWN_FAIL_CLOSED`] is exactly what the tunnel state is allowed to change
/// for this policy.
const UP_WITHOUT_CLIENT_INTERNET: &str = "\
default drop
mss clamp none
masquerade []
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
input iifname \"eth0\" udp dport 51820 accept
output oifname \"eth0\" udp sport 51820 accept
input iifname \"eth0\" udp dport 51821 accept
output oifname \"eth0\" udp sport 51821 accept
output oifname \"eth0\" ip daddr 203.0.113.10 udp dport 51820 accept
input iifname \"helios0\" tcp dport 55182 accept
input iifname \"helios0\" udp dport 55182 accept
forward iifname \"eth1\" oifname \"eth0\" accept
";

#[test]
fn golden_tunnel_up_without_client_internet() {
    assert_golden(
        "tunnel up, client internet closed",
        &render(&policy(), TunnelState::Up),
        UP_WITHOUT_CLIENT_INTERNET,
    );
}

/// Every operator-facing opening on at once, on two uplinks, tunnel `Up`.
///
/// This is the case that pins the *interleaving* of the capabilities, which is
/// where a refactor of `render` can go wrong without changing any single rule:
/// the administration API before loopback, DHCP before the gateway's own
/// egress, the tunnel openings before the SSH sources, the out-of-band admin
/// interfaces before the state-gated forwarding, and split-tunnel bypasses
/// before the LAN forward. Two uplinks also pin the per-uplink expansion
/// order of every WAN rule and of the masquerade.
fn everything_open_policy() -> FirewallPolicy {
    let mut p = policy();
    p.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
    p.admin_port = Some(8080);
    p.admin_iface = Some("helios0".into());
    p.admin_ifaces = vec!["tailscale0".into()];
    p.allow_ssh_from = vec!["198.51.100.7/32".into()];
    p.allow_dhcp_on_wan = true;
    p.allow_gateway_egress = true;
    p.allow_client_internet = true;
    p.allow_tunnel_icmp = true;
    p.allow_ssh_over_tunnel = true;
    p.iperf_port = Some(5201);
    p.split_tunnel_cidrs = vec!["192.168.50.0/24".into()];
    p.mss_clamp = Some(1280);
    p
}

const UP_EVERY_CAPABILITY_OPEN: &str = "\
default drop
mss clamp 1280
masquerade [enp3s0, wlo1]
input tcp dport 8080 iifname \"helios0\" accept
input tcp dport 8080 drop
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
input iifname \"enp3s0\" udp dport 51820 accept
output oifname \"enp3s0\" udp sport 51820 accept
input iifname \"wlo1\" udp dport 51820 accept
output oifname \"wlo1\" udp sport 51820 accept
input iifname \"enp3s0\" udp dport 51821 accept
output oifname \"enp3s0\" udp sport 51821 accept
input iifname \"wlo1\" udp dport 51821 accept
output oifname \"wlo1\" udp sport 51821 accept
output oifname \"enp3s0\" ip daddr 203.0.113.10 udp dport 51820 accept
output oifname \"wlo1\" ip daddr 203.0.113.10 udp dport 51820 accept
output oifname \"enp3s0\" udp dport 67 accept
input iifname \"enp3s0\" udp dport 68 accept
output oifname \"wlo1\" udp dport 67 accept
input iifname \"wlo1\" udp dport 68 accept
output oifname \"enp3s0\" udp dport 53 accept
output oifname \"enp3s0\" tcp dport { 53, 80, 443 } accept
output oifname \"enp3s0\" udp dport 123 accept
output oifname \"wlo1\" udp dport 53 accept
output oifname \"wlo1\" tcp dport { 53, 80, 443 } accept
output oifname \"wlo1\" udp dport 123 accept
input iifname \"helios0\" meta l4proto icmp accept
input iifname \"helios0\" tcp dport 22 accept
input iifname \"helios0\" tcp dport 55182 accept
input iifname \"helios0\" udp dport 55182 accept
input iifname \"helios0\" tcp dport 5201 accept
output oifname \"helios0\" tcp dport 5201 accept
input iifname \"helios0\" udp dport 5201 accept
output oifname \"helios0\" udp dport 5201 accept
input ip saddr 198.51.100.7/32 tcp dport 22 accept
input iifname \"tailscale0\" tcp dport 22 accept
forward ip daddr 192.168.50.0/24 accept
forward iifname \"eth1\" oifname \"enp3s0\" accept
forward iifname \"eth1\" oifname \"wlo1\" accept
forward iifname \"helios0\" oifname \"enp3s0\" accept
forward iifname \"helios0\" oifname \"wlo1\" accept
";

#[test]
fn golden_tunnel_up_with_every_capability_open() {
    assert_golden(
        "tunnel up, every capability open, two uplinks",
        &render(&everything_open_policy(), TunnelState::Up),
        UP_EVERY_CAPABILITY_OPEN,
    );
}

/// NordVPN Meshnet, with neither listener and without a tunnel interface.
///
/// Two branches meet here that no other case reaches. Meshnet is the longest
/// and most order-sensitive section — a routing peer without local-network
/// permission gets its four private-network `drop` rules *before* its accept,
/// which is the whole permission model; inverting them would open the LAN.
/// And dropping `wg_listen_port`, `key_negotiation_port`, `wg_peers` and
/// `wg_iface` renders the absent-listener side of those four conditions,
/// including the speedtest openings disappearing with the tunnel interface.
fn meshnet_without_listeners_policy() -> FirewallPolicy {
    let mut p = policy();
    p.wg_listen_port = None;
    p.key_negotiation_port = None;
    p.wg_peers = vec![];
    p.wg_iface = String::new();
    p.nordvpn_meshnet = Some(NordvpnMeshnetPolicy {
        iface: "nordlynx".into(),
        fwmark: 0xe1f1,
        peer_cidrs: vec!["100.72.0.5/32".into()],
        // The first routing peer has no local-network permission, the second
        // has one: both halves of the permission branch in a single case.
        traffic_routing_peer_cidrs: vec!["100.72.0.5/32".into(), "100.72.0.6/32".into()],
        local_network_peer_cidrs: vec!["100.72.0.6/32".into()],
        inbound_tcp_ports: vec![22, 443],
        inbound_udp_ports: vec![51820],
        allow_icmp: true,
    });
    p
}

const DOWN_MESHNET_WITHOUT_LISTENERS: &str = "\
default drop
mss clamp none
masquerade []
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
output oifname \"eth0\" meta mark 0xe1f1 accept
output oifname \"nordlynx\" ip daddr 100.72.0.5/32 accept
input iifname \"nordlynx\" ip saddr 100.72.0.5/32 meta l4proto icmp accept
input iifname \"nordlynx\" ip saddr 100.72.0.5/32 tcp dport { 22, 443 } accept
input iifname \"nordlynx\" ip saddr 100.72.0.5/32 udp dport { 51820 } accept
forward iifname \"nordlynx\" ip saddr 100.72.0.5/32 ip daddr 10.0.0.0/8 drop
forward iifname \"nordlynx\" ip saddr 100.72.0.5/32 ip daddr 169.254.0.0/16 drop
forward iifname \"nordlynx\" ip saddr 100.72.0.5/32 ip daddr 172.16.0.0/12 drop
forward iifname \"nordlynx\" ip saddr 100.72.0.5/32 ip daddr 192.168.0.0/16 drop
forward iifname \"nordlynx\" ip saddr 100.72.0.5/32 oifname \"eth0\" accept
forward iifname \"nordlynx\" ip saddr 100.72.0.6/32 oifname \"eth0\" accept
forward iifname \"nordlynx\" ip saddr 100.72.0.6/32 oifname \"eth1\" accept
";

#[test]
fn golden_meshnet_without_listeners() {
    assert_golden(
        "meshnet, no listener, no tunnel interface",
        &render(&meshnet_without_listeners_policy(), TunnelState::Down),
        DOWN_MESHNET_WITHOUT_LISTENERS,
    );
}

/// Captive portal with a known gateway.
///
/// `CaptivePortal` is the branch that *replaces* the state-gated forwarding
/// rather than adding to it: no LAN forward, no split tunnel, no masquerade,
/// only HTTP/HTTPS towards the portal, in `output` then `forward`.
const CAPTIVE_PORTAL_KNOWN_GATEWAY: &str = "\
default drop
mss clamp none
masquerade []
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
input iifname \"eth0\" udp dport 51820 accept
output oifname \"eth0\" udp sport 51820 accept
input iifname \"eth0\" udp dport 51821 accept
output oifname \"eth0\" udp sport 51821 accept
output oifname \"eth0\" ip daddr 203.0.113.10 udp dport 51820 accept
input iifname \"helios0\" tcp dport 55182 accept
input iifname \"helios0\" udp dport 55182 accept
output oifname \"eth0\" ip daddr 192.0.2.1 tcp dport { 80, 443 } accept
forward oifname \"eth0\" ip daddr 192.0.2.1 tcp dport { 80, 443 } accept
";

#[test]
fn golden_captive_portal_with_known_gateway() {
    let mut p = policy();
    p.captive_portal_gateway = Some("192.0.2.1".into());
    assert_golden(
        "captive portal, known gateway",
        &render(&p, TunnelState::CaptivePortal),
        CAPTIVE_PORTAL_KNOWN_GATEWAY,
    );
}

/// Captive portal without a known gateway, under a fail-open policy.
///
/// Two branches nothing else reaches, and they belong together: the unknown
/// portal drops the destination match from the two rules above, and
/// `PolicyMode::FailOpen` is the only way `default_verdict` becomes `accept`.
/// Pinning the pair here keeps the degraded mode visible — a fail-open
/// default silently appearing anywhere else would break this golden.
const CAPTIVE_PORTAL_UNKNOWN_GATEWAY_FAIL_OPEN: &str = "\
default accept
mss clamp none
masquerade []
input iifname \"lo\" accept
input ct state established,related accept
forward iifname \"lo\" accept
forward ct state established,related accept
output oifname \"lo\" accept
output ct state established,related accept
input iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept
output oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept
output oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept
input iifname \"eth0\" udp dport 51820 accept
output oifname \"eth0\" udp sport 51820 accept
input iifname \"eth0\" udp dport 51821 accept
output oifname \"eth0\" udp sport 51821 accept
output oifname \"eth0\" ip daddr 203.0.113.10 udp dport 51820 accept
input iifname \"helios0\" tcp dport 55182 accept
input iifname \"helios0\" udp dport 55182 accept
output oifname \"eth0\" tcp dport { 80, 443 } accept
forward oifname \"eth0\" tcp dport { 80, 443 } accept
";

#[test]
fn golden_captive_portal_without_gateway_fail_open() {
    let mut p = policy();
    p.mode = PolicyMode::FailOpen;
    assert_golden(
        "captive portal, unknown gateway, fail-open",
        &render(&p, TunnelState::CaptivePortal),
        CAPTIVE_PORTAL_UNKNOWN_GATEWAY_FAIL_OPEN,
    );
}
