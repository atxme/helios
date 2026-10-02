//! Meshnet peer rules follow the peer's address family.
//!
//! The configuration refuses IPv6 Meshnet peers (`aether`'s Meshnet
//! validation accepts IPv4 CIDRs only), so every policy here is built in code:
//! it is the only way an IPv6 peer reaches the renderer today. That is also
//! why these renderings stay out of `ipv6_relay.rs`, whose sweep covers the
//! policies a validated configuration can produce.
//!
//! What is locked: an IPv6 routing peer without the local-network permission
//! is denied the local IPv6 networks before any of its accepts, its ICMP
//! opening is ICMPv6, and no rule pairs a source of one family with a
//! destination of the other — such a rule never matches, and a denial written
//! that way is an opening.

use super::super::*;
use super::support::{every_state, policy, render};
use aether::NordvpnMeshnetPolicy;

const IPV4_PEER: &str = "100.70.36.212/32";
const IPV6_PEER: &str = "2001:db8::5/128";

fn net(value: &str) -> ipnetwork::IpNetwork {
    value.parse().expect("valid test network")
}

/// Meshnet with the given peers, all of them routing peers; `local_network`
/// lists those that also hold the local-network permission.
fn meshnet_policy(peers: &[&str], local_network: &[&str]) -> FirewallPolicy {
    let owned = |list: &[&str]| list.iter().map(|peer| peer.to_string()).collect();
    let mut p = policy();
    p.allow_gateway_egress = true;
    p.lan_ifaces = vec!["lan0".into()];
    p.nordvpn_meshnet = Some(NordvpnMeshnetPolicy {
        iface: "nordlynx".into(),
        fwmark: 0xe1f1,
        peer_cidrs: owned(peers),
        traffic_routing_peer_cidrs: owned(peers),
        local_network_peer_cidrs: owned(local_network),
        inbound_tcp_ports: vec![22],
        inbound_udp_ports: Vec::new(),
        allow_icmp: true,
    });
    p
}

/// The `forward` rules whose source is `peer`, in rendering order.
fn forward_from<'a>(rs: &'a Ruleset, peer: &str) -> Vec<&'a Rule> {
    let source = Match::SourceNet(net(peer));
    rs.chain(ChainKind::Forward)
        .filter(|rule| rule.matches.contains(&source))
        .collect()
}

fn destination(rule: &Rule) -> Option<ipnetwork::IpNetwork> {
    rule.matches.iter().find_map(|m| match m {
        Match::DestNet(network) => Some(*network),
        _ => None,
    })
}

#[test]
fn an_ipv6_routing_peer_is_denied_local_ipv6_networks_before_any_accept() {
    let p = meshnet_policy(&[IPV6_PEER], &[]);
    for state in every_state() {
        let rs = render(&p, state);
        let rules = forward_from(&rs, IPV6_PEER);

        let drops: Vec<String> = rules
            .iter()
            .filter(|rule| rule.verdict == Verdict::Drop)
            .map(|rule| rule.to_string())
            .collect();
        assert_eq!(
            drops,
            [
                "iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 ip6 daddr fc00::/7 drop",
                "iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 ip6 daddr fe80::/10 drop",
            ],
            "state {state:?}: an IPv4 destination would make the drop dead"
        );

        // The order is the permission: every drop precedes the first accept.
        let first_accept = rules
            .iter()
            .position(|rule| rule.verdict == Verdict::Accept)
            .expect("the routing peer keeps its WAN opening");
        assert!(
            rules[..first_accept]
                .iter()
                .all(|rule| rule.verdict == Verdict::Drop)
                && rules[first_accept..]
                    .iter()
                    .all(|rule| rule.verdict == Verdict::Accept),
            "state {state:?}: an accept precedes a local-network drop"
        );
        assert_eq!(
            rules[first_accept..]
                .iter()
                .map(|rule| rule.to_string())
                .collect::<Vec<_>>(),
            ["iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 oifname \"eth0\" accept"],
            "state {state:?}: without the permission, the WAN is the only way out"
        );
    }
}

#[test]
fn an_ipv6_routing_peer_with_the_local_network_permission_gets_no_drop() {
    let rs = render(&meshnet_policy(&[IPV6_PEER], &[IPV6_PEER]), TunnelState::Up);
    let rules = forward_from(&rs, IPV6_PEER);

    assert!(rules.iter().all(|rule| rule.verdict == Verdict::Accept));
    assert_eq!(
        rules
            .iter()
            .map(|rule| rule.to_string())
            .collect::<Vec<_>>(),
        [
            "iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 oifname \"eth0\" accept",
            "iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 oifname \"lan0\" accept",
        ]
    );
}

#[test]
fn the_meshnet_icmp_opening_follows_the_peer_family() {
    let rs = render(
        &meshnet_policy(&[IPV4_PEER, IPV6_PEER], &[]),
        TunnelState::Up,
    );
    let icmp_from = |peer: &str| -> Vec<&Match> {
        rs.chain(ChainKind::Input)
            .filter(|rule| rule.matches.contains(&Match::SourceNet(net(peer))))
            .flat_map(|rule| rule.matches.iter())
            .filter(|m| matches!(m, Match::Icmp(_)))
            .collect()
    };

    assert_eq!(icmp_from(IPV4_PEER), [&Match::Icmp(AddressFamily::Ipv4)]);
    assert_eq!(icmp_from(IPV6_PEER), [&Match::Icmp(AddressFamily::Ipv6)]);
    assert!(rs.chain(ChainKind::Input).any(|rule| rule.to_string()
        == "iifname \"nordlynx\" ip6 saddr 2001:db8::5/128 meta l4proto ipv6-icmp accept"));
}

#[test]
fn mixed_peers_each_get_their_own_family_local_networks() {
    let rs = render(
        &meshnet_policy(&[IPV4_PEER, IPV6_PEER], &[]),
        TunnelState::Up,
    );

    let denied = |peer: &str| -> Vec<ipnetwork::IpNetwork> {
        forward_from(&rs, peer)
            .into_iter()
            .filter(|rule| rule.verdict == Verdict::Drop)
            .filter_map(destination)
            .collect()
    };
    assert_eq!(
        denied(IPV4_PEER),
        PRIVATE_IPV4_CIDRS.map(net),
        "the IPv4 peer keeps exactly the IPv4 list"
    );
    assert_eq!(denied(IPV6_PEER), PRIVATE_IPV6_CIDRS.map(net));

    // No rule anywhere pairs a source with a destination of the other family.
    for rule in &rs.rules {
        let source = rule.matches.iter().find_map(|m| match m {
            Match::SourceNet(network) => Some(*network),
            _ => None,
        });
        if let (Some(source), Some(destination)) = (source, destination(rule)) {
            assert_eq!(
                source.is_ipv4(),
                destination.is_ipv4(),
                "`{rule}` can never match"
            );
        }
    }
}
