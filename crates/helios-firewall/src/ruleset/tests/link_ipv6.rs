//! IPv6 control traffic of the gateway's own links.
//!
//! Neighbor discovery and MLD on every WAN and LAN interface, router
//! discovery on the WANs only, in every tunnel state and under both policy
//! modes: these are what keep an IPv6 WAN address and default route alive
//! under the `drop` policy of the `inet` table. And the other side of the
//! same rules: no router advertisement from anywhere but a WAN, no Redirect,
//! no echo on the WAN.

use super::super::*;
use super::support::{every_state, policy, render};
use aether::{NordvpnMeshnetPolicy, PolicyMode};

const WANS: [&str; 2] = ["enp3s0", "wlo1"];
const LAN: &str = "eth1";
/// Every interface that is neither a WAN nor a LAN, with a role of its own.
const NOT_A_LINK: [&str; 3] = ["helios0", "tailscale0", "nordlynx"];

const ND_TYPES: [Icmpv6Type; 2] = [Icmpv6Type::NeighborSolicit, Icmpv6Type::NeighborAdvert];
const MLD_TYPES: [Icmpv6Type; 4] = [
    Icmpv6Type::MldListenerQuery,
    Icmpv6Type::MldListenerReport,
    Icmpv6Type::MldListenerDone,
    Icmpv6Type::Mld2ListenerReport,
];

/// Two uplinks, a LAN, the tunnel, an out-of-band overlay and Meshnet: every
/// interface role the renderer knows.
fn every_role_policy(mode: PolicyMode) -> FirewallPolicy {
    let mut p = policy();
    p.mode = mode;
    p.wan_ifaces = WANS.iter().map(|wan| wan.to_string()).collect();
    p.lan_ifaces = vec![LAN.into()];
    p.admin_ifaces = vec!["tailscale0".into()];
    p.allow_gateway_egress = true;
    p.nordvpn_meshnet = Some(NordvpnMeshnetPolicy {
        iface: "nordlynx".into(),
        fwmark: 0xe1f1,
        peer_cidrs: vec!["100.72.0.5/32".into()],
        traffic_routing_peer_cidrs: vec![],
        local_network_peer_cidrs: vec![],
        inbound_tcp_ports: vec![],
        inbound_udp_ports: vec![],
        allow_icmp: true,
    });
    p
}

/// Every `(mode, state)` pair, rendered.
fn every_rendering() -> Vec<(PolicyMode, TunnelState, Ruleset)> {
    let mut renderings = Vec::new();
    for mode in [PolicyMode::FailClosed, PolicyMode::FailOpen] {
        for state in every_state() {
            renderings.push((mode, state, render(&every_role_policy(mode), state)));
        }
    }
    renderings
}

fn scope(chain: ChainKind, iface: &str) -> Match {
    match chain {
        ChainKind::Output => Match::OutIface(iface.into()),
        ChainKind::Input | ChainKind::Forward => Match::InIface(iface.into()),
    }
}

/// The exact matches of an ND or router-discovery rule.
fn nd_matches(chain: ChainKind, iface: &str, icmp_type: Icmpv6Type) -> Vec<Match> {
    vec![
        scope(chain, iface),
        Match::Icmpv6Type(icmp_type),
        Match::Ipv6HopLimit(255),
    ]
}

/// The exact matches of an MLD rule.
fn mld_matches(chain: ChainKind, iface: &str, icmp_type: Icmpv6Type) -> Vec<Match> {
    vec![
        scope(chain, iface),
        Match::Family(AddressFamily::Ipv6),
        Match::Icmpv6Type(icmp_type),
    ]
}

fn accepts(rs: &Ruleset, chain: ChainKind, matches: &[Match]) -> bool {
    rs.chain(chain)
        .any(|rule| rule.matches == matches && rule.verdict == Verdict::Accept)
}

fn icmpv6_type_of(rule: &Rule) -> Option<Icmpv6Type> {
    rule.matches.iter().find_map(|m| match m {
        Match::Icmpv6Type(icmp_type) => Some(*icmp_type),
        _ => None,
    })
}

#[test]
fn neighbor_discovery_and_mld_hold_on_every_wan_and_lan_in_every_state() {
    for (mode, state, rs) in every_rendering() {
        for iface in WANS.iter().copied().chain([LAN]) {
            for chain in [ChainKind::Input, ChainKind::Output] {
                for icmp_type in ND_TYPES {
                    assert!(
                        accepts(&rs, chain, &nd_matches(chain, iface, icmp_type)),
                        "{mode:?}/{state:?}: {icmp_type:?} missing in {chain:?} on {iface}"
                    );
                }
                for icmp_type in MLD_TYPES {
                    assert!(
                        accepts(&rs, chain, &mld_matches(chain, iface, icmp_type)),
                        "{mode:?}/{state:?}: {icmp_type:?} missing in {chain:?} on {iface}"
                    );
                }
            }
        }
    }
}

#[test]
fn router_discovery_holds_on_every_wan_in_every_state() {
    for (mode, state, rs) in every_rendering() {
        for wan in WANS {
            assert!(
                accepts(
                    &rs,
                    ChainKind::Output,
                    &nd_matches(ChainKind::Output, wan, Icmpv6Type::RouterSolicit)
                ),
                "{mode:?}/{state:?}: router solicitation cannot leave {wan}"
            );
            assert!(
                accepts(
                    &rs,
                    ChainKind::Input,
                    &nd_matches(ChainKind::Input, wan, Icmpv6Type::RouterAdvert)
                ),
                "{mode:?}/{state:?}: router advertisements cannot reach {wan}"
            );
        }
    }
}

/// The gateway is a host on its uplinks and a router everywhere else. A
/// router advertisement accepted from the tunnel, a LAN, an overlay or
/// Meshnet could hand it a default route: the only RA rules are `input` on a
/// WAN, and the only RS rules are `output` on a WAN.
#[test]
fn router_discovery_exists_on_wans_only() {
    for (mode, state, rs) in every_rendering() {
        let mut seen = 0;
        for rule in &rs.rules {
            let (expected_chain, icmp_type) = match icmpv6_type_of(rule) {
                Some(Icmpv6Type::RouterAdvert) => (ChainKind::Input, Icmpv6Type::RouterAdvert),
                Some(Icmpv6Type::RouterSolicit) => (ChainKind::Output, Icmpv6Type::RouterSolicit),
                _ => continue,
            };
            seen += 1;
            assert!(
                WANS.iter().any(
                    |wan| rule.matches == nd_matches(expected_chain, wan, icmp_type)
                        && rule.chain == expected_chain
                ),
                "{mode:?}/{state:?}: `{rule}` is not router discovery on a WAN"
            );
        }
        assert_eq!(seen, 2 * WANS.len(), "{mode:?}/{state:?}");
    }
}

#[test]
fn no_router_advertisement_is_accepted_on_the_tunnel_lan_or_overlays() {
    for (mode, state, rs) in every_rendering() {
        for iface in NOT_A_LINK.iter().copied().chain([LAN]) {
            for rule in rs.chain(ChainKind::Input) {
                let on_iface = rule.matches.contains(&Match::InIface(iface.into()));
                assert!(
                    !(on_iface && icmpv6_type_of(rule) == Some(Icmpv6Type::RouterAdvert)),
                    "{mode:?}/{state:?}: `{rule}` accepts a rogue RA on {iface}"
                );
            }
        }
    }
}

/// An uplink also declared in another role gets no router discovery: the
/// other role would let that side announce routes to the gateway. Its
/// neighbor discovery is unaffected, and rendered once.
#[test]
fn a_wan_shared_with_another_role_accepts_no_router_advertisement() {
    let shared_roles: [fn(&mut FirewallPolicy); 4] = [
        |p| p.lan_ifaces = vec!["enp3s0".into()],
        |p| p.wg_iface = "enp3s0".into(),
        |p| p.admin_ifaces = vec!["enp3s0".into()],
        |p| {
            if let Some(meshnet) = p.nordvpn_meshnet.as_mut() {
                meshnet.iface = "enp3s0".into();
            }
        },
    ];
    for share in shared_roles {
        let mut p = every_role_policy(PolicyMode::FailClosed);
        share(&mut p);
        let rs = render(&p, TunnelState::Up);
        assert!(
            !rs.rules.iter().any(|rule| {
                rule.matches.contains(&Match::InIface("enp3s0".into()))
                    && icmpv6_type_of(rule) == Some(Icmpv6Type::RouterAdvert)
            }),
            "a WAN shared with another role must not accept router advertisements"
        );
        assert!(accepts(
            &rs,
            ChainKind::Input,
            &nd_matches(ChainKind::Input, "wlo1", Icmpv6Type::RouterAdvert)
        ));
        let solicit_rules = rs
            .chain(ChainKind::Input)
            .filter(|rule| {
                rule.matches == nd_matches(ChainKind::Input, "enp3s0", Icmpv6Type::NeighborSolicit)
            })
            .count();
        assert_eq!(solicit_rules, 1, "neighbor discovery is rendered once");
    }
}

/// ND and router discovery must carry the RFC 4861 hop limit: 255 proves
/// the packet was sent on the link, which is what makes off-link spoofing
/// impossible. MLD is sent with a hop limit of 1 and carries the explicit
/// IPv6 guard instead.
#[test]
fn every_icmpv6_link_rule_is_guarded_at_the_network_layer() {
    for (mode, state, rs) in every_rendering() {
        for rule in &rs.rules {
            let Some(icmp_type) = icmpv6_type_of(rule) else {
                continue;
            };
            let hop_limit = rule.matches.contains(&Match::Ipv6HopLimit(255));
            let guard = rule.matches.contains(&Match::Family(AddressFamily::Ipv6));
            if MLD_TYPES.contains(&icmp_type) {
                assert!(guard && !hop_limit, "{mode:?}/{state:?}: `{rule}`");
            } else {
                assert!(hop_limit && !guard, "{mode:?}/{state:?}: `{rule}`");
            }
        }
    }
}

/// Redirect (137) is not representable in the IR, so nothing can accept
/// it: it falls to the policy drop. The display check catches a variant
/// added for it later.
#[test]
fn redirects_are_never_accepted() {
    for (mode, state, rs) in every_rendering() {
        for rule in &rs.rules {
            assert_ne!(
                icmpv6_type_of(rule).map(Icmpv6Type::number),
                Some(137),
                "{mode:?}/{state:?}: `{rule}`"
            );
            assert!(
                !rule.to_string().contains("redirect"),
                "{mode:?}/{state:?}: `{rule}`"
            );
        }
    }
}

/// The WAN keeps the IPv4 behavior: no echo, in either family. Only the
/// link-control types above are accepted there.
#[test]
fn no_echo_and_no_other_icmp_is_opened_on_the_wan() {
    for (mode, state, rs) in every_rendering() {
        for rule in &rs.rules {
            let on_a_wan = WANS.iter().any(|wan| {
                rule.matches.contains(&Match::InIface((*wan).into()))
                    || rule.matches.contains(&Match::OutIface((*wan).into()))
            });
            if !on_a_wan {
                continue;
            }
            assert!(
                !rule.matches.iter().any(|m| matches!(m, Match::Icmp(_))),
                "{mode:?}/{state:?}: `{rule}` opens ICMP by protocol on a WAN"
            );
            assert!(
                !rule.to_string().contains("echo"),
                "{mode:?}/{state:?}: `{rule}`"
            );
        }
    }
}

/// The link rules come after the `ct state invalid` drop of their chain:
/// an invalid packet is never rescued by them.
#[test]
fn link_rules_follow_the_invalid_drop() {
    for (mode, state, rs) in every_rendering() {
        for chain in [ChainKind::Input, ChainKind::Output] {
            let rules: Vec<&Rule> = rs.chain(chain).collect();
            assert_eq!(
                rules[0].matches,
                [Match::ConnectionState(ConnectionStates::INVALID)],
                "{mode:?}/{state:?}"
            );
            assert!(rules[1..].iter().any(|rule| icmpv6_type_of(rule).is_some()));
        }
    }
}
