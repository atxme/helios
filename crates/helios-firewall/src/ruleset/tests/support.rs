//! Shared fixtures for ruleset renderer tests.

use super::super::*;
use aether::PolicyMode;

pub(super) fn policy() -> FirewallPolicy {
    FirewallPolicy {
        wan_ifaces: vec!["eth0".into()],
        lan_ifaces: vec!["eth1".into()],
        wg_peers: vec!["203.0.113.10".into()],
        wg_listen_port: Some(51820),
        key_negotiation_port: Some(51821),
        mode: PolicyMode::FailClosed,
        allow_ssh_from: vec![],
        admin_ifaces: vec![],
        allow_dhcp_on_wan: false,
        allow_client_internet: false,
        allow_tunnel_icmp: false,
        allow_gateway_egress: false,
        allow_ssh_over_tunnel: false,
        iperf_port: None,
        wg_iface: "helios0".into(),
        admin_port: None,
        admin_iface: None,
        split_tunnel_cidrs: vec![],
        mss_clamp: None,
        captive_portal_gateway: None,
        nordvpn_meshnet: None,
    }
}

/// Textual rendering of a chain, for readable assertions.
pub(super) fn text(rs: &Ruleset, kind: ChainKind) -> Vec<String> {
    rs.chain(kind).map(|r| r.to_string()).collect()
}
