//! The gateway relays no IPv6 from its tunnel clients.
//!
//! The table is `inet`, so a rule that names no address applies to both
//! families. Two of them concern the tunnel clients' Internet egress: the
//! `forward` from `wg_iface` to each WAN and the `postrouting` masquerade.
//! Unguarded, the first would relay IPv6 as soon as the gateway enables IPv6
//! forwarding, and the second would NAT66 it — a decision nobody took. Both
//! are IPv4-only (ADRESSAGE-IPV6 §6.4), and these tests lock it for every
//! tunnel state, with the road-warrior egress open and closed, on several
//! uplinks.
//!
//! IPv6 relaying opens only with the future specification B, which decides
//! IPv6 Internet egress (blackhole, routed prefix or NAT66, ETUDE-IPV6 §6.5).
//! Until then no rule selects IPv6 by family: the last test fails the moment
//! one does, so that change cannot slip in as a side effect.

use super::super::*;
use super::support::{policy, render};

/// Every tunnel state. The `match` has no wildcard: a new state fails to
/// compile here instead of silently escaping these invariants.
fn every_state() -> [TunnelState; 5] {
    let _exhaustive = |state: TunnelState| match state {
        TunnelState::Down
        | TunnelState::Connecting
        | TunnelState::Up
        | TunnelState::Failed
        | TunnelState::CaptivePortal => {}
    };
    [
        TunnelState::Down,
        TunnelState::Connecting,
        TunnelState::Up,
        TunnelState::Failed,
        TunnelState::CaptivePortal,
    ]
}

const UPLINKS: [&str; 2] = ["enp3s0", "wlo1"];

/// Two uplinks and every opening on, so that no rule is missing from the
/// sweep because its flag happened to be off.
fn relay_policy(allow_client_internet: bool) -> FirewallPolicy {
    let mut p = policy();
    p.wan_ifaces = UPLINKS.iter().map(|uplink| uplink.to_string()).collect();
    p.allow_client_internet = allow_client_internet;
    p.admin_port = Some(8080);
    p.admin_iface = Some("helios0".into());
    p.admin_ifaces = vec!["tailscale0".into()];
    p.allow_ssh_from = vec!["198.51.100.7/32".into()];
    p.allow_dhcp_on_wan = true;
    p.allow_gateway_egress = true;
    p.allow_tunnel_icmp = true;
    p.allow_ssh_over_tunnel = true;
    p.iperf_port = Some(5201);
    p.split_tunnel_cidrs = vec!["192.168.50.0/24".into()];
    p.captive_portal_gateway = Some("192.0.2.1".into());
    p
}

/// Every `(state, allow_client_internet)` pair, rendered.
fn every_rendering() -> Vec<(TunnelState, bool, Ruleset)> {
    let mut renderings = Vec::new();
    for state in every_state() {
        for allow_client_internet in [false, true] {
            renderings.push((
                state,
                allow_client_internet,
                render(&relay_policy(allow_client_internet), state),
            ));
        }
    }
    renderings
}

#[test]
fn tunnel_client_forwarding_to_a_wan_is_ipv4_only_in_every_state() {
    for (state, allow_client_internet, rs) in every_rendering() {
        let mut relays = 0;
        for rule in rs.chain(ChainKind::Forward) {
            let from_tunnel = rule.matches.contains(&Match::InIface("helios0".into()));
            let to_a_wan = UPLINKS
                .iter()
                .any(|uplink| rule.matches.contains(&Match::OutIface((*uplink).into())));
            if from_tunnel && to_a_wan {
                relays += 1;
                assert!(
                    rule.matches.contains(&Match::Family(AddressFamily::Ipv4)),
                    "state {state:?}, client internet {allow_client_internet}: `{rule}` \
                     would relay IPv6 from the tunnel to the WAN"
                );
            }
        }
        // The sweep must have seen the rules it guards where they exist,
        // otherwise it would pass on a renderer that stopped emitting them.
        let expected = if state == TunnelState::Up && allow_client_internet {
            UPLINKS.len()
        } else {
            0
        };
        assert_eq!(
            relays, expected,
            "state {state:?}, client internet {allow_client_internet}"
        );
    }
}

#[test]
fn the_masquerade_is_ipv4_only_whenever_present() {
    for (state, allow_client_internet, rs) in every_rendering() {
        let masquerades: Vec<MasqueradeRule> = rs.masquerade_rules().collect();
        for rule in &masquerades {
            assert_eq!(
                rule.matches().first(),
                Some(&Match::Family(AddressFamily::Ipv4)),
                "state {state:?}: `{rule}` would NAT66 in the `inet` table"
            );
            assert!(
                rule.to_string().starts_with("meta nfproto ipv4 oifname "),
                "state {state:?}: the display must show the guard the backend applies: `{rule}`"
            );
        }
        // Presence itself is unchanged: one per uplink, only in `Up` and on
        // request.
        let expected = if state == TunnelState::Up && allow_client_internet {
            UPLINKS.len()
        } else {
            0
        };
        assert_eq!(
            masquerades.len(),
            expected,
            "state {state:?}, client internet {allow_client_internet}"
        );
    }
}

/// No rule selects IPv6 by family today. Opening an IPv6 relay belongs to
/// the future specification B; this test is meant to fail when it lands, so
/// that the change is reviewed as the decision it is.
#[test]
fn no_rule_selects_ipv6_by_family_today() {
    let ipv6 = Match::Family(AddressFamily::Ipv6);
    for (state, allow_client_internet, rs) in every_rendering() {
        for rule in &rs.rules {
            assert!(
                !rule.matches.contains(&ipv6),
                "state {state:?}, client internet {allow_client_internet}: `{rule}`"
            );
        }
        for rule in rs.masquerade_rules() {
            assert!(
                !rule.matches().contains(&ipv6),
                "state {state:?}, client internet {allow_client_internet}: `{rule}`"
            );
        }
    }
}
