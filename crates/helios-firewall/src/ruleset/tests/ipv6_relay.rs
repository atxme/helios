//! The gateway relays no IPv6 from its tunnel clients, and says so.
//!
//! The table is `inet`, so a rule that names no address applies to both
//! families. Two of them concern the tunnel clients' Internet egress: the
//! `forward` from `wg_iface` to each WAN and the `postrouting` masquerade.
//! Unguarded, the first would relay IPv6 as soon as the gateway enables IPv6
//! forwarding, and the second would NAT66 it — a decision nobody took. Both
//! are IPv4-only (ADRESSAGE-IPV6 §6.4).
//!
//! SORTIE-IPV6 §3.1 adds the answer: a tunnel client's IPv6 bound for a WAN
//! is rejected with `icmpx admin-prohibited`, one rule per uplink, in every
//! state, last of `forward`, instead of vanishing under the `drop` policy.
//! These tests lock both halves for every tunnel state, under both policy
//! modes, with the road-warrior egress open and closed, on several uplinks:
//! no `forward` rule accepts IPv6 entering by the tunnel interface and no
//! masquerade selects IPv6 — they fail the moment one does, so that NAT66 or
//! any other IPv6 relay cannot slip in as a side effect — and the rejection is
//! present, exact and last. The only `forward` acceptance of IPv6 is an
//! operator's IPv6 split-tunnel CIDR, which never applies to traffic entering
//! by the tunnel interface. The other rules that select IPv6 are the gateway's
//! own link control (neighbor and router discovery, MLD, DHCPv6), in `input`
//! and `output` on its WAN and LAN interfaces; they relay nothing.

use super::super::*;
use super::support::{every_state, policy, render};
use aether::PolicyMode;

const UPLINKS: [&str; 2] = ["enp3s0", "wlo1"];
const TUNNEL: &str = "helios0";
/// An IPv6 split-tunnel CIDR, so that the sweep sees the one `forward` rule
/// allowed to accept IPv6.
const IPV6_SPLIT_TUNNEL: &str = "fd00:50::/64";

/// Two uplinks and every opening on, so that no rule is missing from the
/// sweep because its flag happened to be off.
fn relay_policy(allow_client_internet: bool, mode: PolicyMode) -> FirewallPolicy {
    let mut p = policy();
    p.mode = mode;
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
    p.split_tunnel_cidrs = vec!["192.168.50.0/24".into(), IPV6_SPLIT_TUNNEL.into()];
    p.captive_portal_gateway = Some("192.0.2.1".into());
    p
}

/// One rendering of the sweep, and what produced it.
struct Rendering {
    state: TunnelState,
    allow_client_internet: bool,
    mode: PolicyMode,
    ruleset: Ruleset,
}

impl std::fmt::Display for Rendering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "state {:?}, client internet {}, mode {:?}",
            self.state, self.allow_client_internet, self.mode
        )
    }
}

/// Every `(state, allow_client_internet, mode)` triple, rendered.
///
/// Fail-open matters here: outside the tunnel its default verdict is
/// `accept`, so the rejection is what keeps the tunnel clients' IPv6 from
/// being relayed at all.
fn every_rendering() -> Vec<Rendering> {
    let mut renderings = Vec::new();
    for state in every_state() {
        for allow_client_internet in [false, true] {
            for mode in [PolicyMode::FailClosed, PolicyMode::FailOpen] {
                renderings.push(Rendering {
                    state,
                    allow_client_internet,
                    mode,
                    ruleset: render(&relay_policy(allow_client_internet, mode), state),
                });
            }
        }
    }
    renderings
}

/// The rejection of one uplink, exactly as SORTIE-IPV6 §3.1 scopes it.
fn ipv6_rejection(uplink: &str) -> Rule {
    Rule {
        chain: ChainKind::Forward,
        matches: vec![
            Match::Family(AddressFamily::Ipv6),
            Match::InIface("helios0".into()),
            Match::OutIface(uplink.into()),
        ],
        actions: Vec::new(),
        verdict: Verdict::RejectAdminProhibited,
        note: Some(
            "tunnel clients' IPv6 Internet egress: refused, without waiting for a timeout".into(),
        ),
    }
}

#[test]
fn tunnel_client_forwarding_to_a_wan_accepts_ipv4_and_rejects_ipv6_in_every_state() {
    for r in every_rendering() {
        let mut accepted = 0;
        let mut rejected = Vec::new();
        for rule in r.ruleset.chain(ChainKind::Forward) {
            let from_tunnel = rule.matches.contains(&Match::InIface("helios0".into()));
            let to_a_wan = UPLINKS
                .iter()
                .any(|uplink| rule.matches.contains(&Match::OutIface((*uplink).into())));
            if !(from_tunnel && to_a_wan) {
                continue;
            }
            match rule.verdict {
                Verdict::Accept => {
                    accepted += 1;
                    assert!(
                        rule.matches.contains(&Match::Family(AddressFamily::Ipv4)),
                        "{r}: `{rule}` would relay IPv6 from the tunnel to the WAN"
                    );
                }
                Verdict::RejectAdminProhibited => rejected.push(rule.clone()),
                Verdict::Drop => panic!("{r}: unexpected `{rule}`"),
            }
        }
        // The sweep must have seen the rules it guards where they exist,
        // otherwise it would pass on a renderer that stopped emitting them.
        let expected_accepts = if r.state == TunnelState::Up && r.allow_client_internet {
            UPLINKS.len()
        } else {
            0
        };
        assert_eq!(accepted, expected_accepts, "{r}");
        // One rejection per uplink, in uplink order, in every state.
        assert_eq!(
            rejected,
            UPLINKS.map(ipv6_rejection).to_vec(),
            "{r}: the IPv6 egress must be rejected on every uplink"
        );
    }
}

#[test]
fn the_masquerade_is_ipv4_only_whenever_present() {
    for r in every_rendering() {
        let masquerades: Vec<MasqueradeRule> = r.ruleset.masquerade_rules().collect();
        for rule in &masquerades {
            assert_eq!(
                rule.matches().first(),
                Some(&Match::Family(AddressFamily::Ipv4)),
                "{r}: `{rule}` would NAT66 in the `inet` table"
            );
            assert!(
                rule.to_string().starts_with("meta nfproto ipv4 oifname "),
                "{r}: the display must show the guard the backend applies: `{rule}`"
            );
        }
        // Presence itself is unchanged: one per uplink, only in `Up` and on
        // request.
        let expected = if r.state == TunnelState::Up && r.allow_client_internet {
            UPLINKS.len()
        } else {
            0
        };
        assert_eq!(masquerades.len(), expected, "{r}");
    }
}

/// Whether a match can only be satisfied by an IPv6 packet.
fn selects_ipv6(m: &Match) -> bool {
    match m {
        Match::Family(AddressFamily::Ipv6) | Match::Icmpv6Type(_) | Match::Ipv6HopLimit(_) => true,
        Match::DestNet(network) | Match::SourceNet(network) => network.is_ipv6(),
        _ => false,
    }
}

/// The operator's IPv6 split-tunnel bypass, exactly as `kill_switch` scopes
/// it: off the traffic entering by the tunnel interface.
fn ipv6_split_tunnel_bypass() -> Rule {
    Rule::new(
        ChainKind::Forward,
        vec![
            Match::NotInIface(TUNNEL.into()),
            Match::DestNet(IPV6_SPLIT_TUNNEL.parse().expect("a valid IPv6 CIDR")),
        ],
        Verdict::Accept,
    )
}

/// No relay accepts IPv6: every `forward` rule that selects IPv6, ICMPv6
/// control included, is the rejection or the operator's IPv6 split-tunnel
/// bypass — present only in `Up` and never for traffic entering by the
/// tunnel interface — and no masquerade selects it. Opening an IPv6 relay —
/// NAT66 first among them, out of the scope of SORTIE-IPV6 — is meant to fail
/// here, so that the change is reviewed as the decision it is.
#[test]
fn no_relay_accepts_ipv6() {
    for r in every_rendering() {
        let mut bypasses = 0;
        for rule in r.ruleset.chain(ChainKind::Forward) {
            if *rule == ipv6_split_tunnel_bypass() {
                bypasses += 1;
            } else if rule.matches.iter().any(selects_ipv6) {
                assert_eq!(
                    rule.verdict,
                    Verdict::RejectAdminProhibited,
                    "{r}: `{rule}`"
                );
            }
            assert!(
                !(rule.verdict == Verdict::Accept
                    && rule.matches.contains(&Match::Family(AddressFamily::Ipv6))),
                "{r}: `{rule}`"
            );
        }
        let expected_bypasses = usize::from(r.state == TunnelState::Up);
        assert_eq!(bypasses, expected_bypasses, "{r}");
        for rule in r.ruleset.masquerade_rules() {
            assert!(!rule.matches().iter().any(selects_ipv6), "{r}: `{rule}`");
        }
    }
}

/// Whether a match can only be satisfied by an IPv4 packet.
fn selects_ipv4(m: &Match) -> bool {
    match m {
        Match::Family(AddressFamily::Ipv4) | Match::Icmp(AddressFamily::Ipv4) => true,
        Match::DestNet(network) | Match::SourceNet(network) => network.is_ipv4(),
        _ => false,
    }
}

/// Whether a packet entering by the tunnel interface can satisfy the rule's
/// interface matches: no exclusion of the tunnel, and no other input
/// interface required.
fn may_enter_by_the_tunnel(rule: &Rule) -> bool {
    rule.matches.iter().all(|m| match m {
        Match::NotInIface(iface) => iface != TUNNEL,
        Match::InIface(iface) => iface == TUNNEL,
        _ => true,
    })
}

/// No `forward` acceptance can take IPv6 entering by the tunnel interface,
/// whatever its destination — an IPv6 split-tunnel CIDR included
/// (ADRESSAGE-IPV6 §6.4, SORTIE-IPV6). Every acceptance a tunnel packet can
/// reach is IPv4-only, except the return path of an already accepted flow,
/// `ct state established,related`. The IPv6 split-tunnel bypass is in the
/// sweep, so a renderer that dropped its `iifname != wg_iface` fails here.
#[test]
fn no_forward_rule_accepts_ipv6_entering_by_the_tunnel() {
    let return_path = [Match::ConnectionState(
        ConnectionStates::ESTABLISHED_RELATED,
    )];
    for r in every_rendering() {
        for rule in r.ruleset.chain(ChainKind::Forward) {
            if rule.verdict != Verdict::Accept || rule.matches == return_path {
                continue;
            }
            assert!(
                !may_enter_by_the_tunnel(rule) || rule.matches.iter().any(selects_ipv4),
                "{r}: `{rule}` would accept IPv6 entering by `{TUNNEL}`"
            );
        }
        // The bypass the sweep guards is rendered where it exists, otherwise
        // the sweep would pass on a renderer that stopped emitting it.
        assert_eq!(
            r.ruleset
                .chain(ChainKind::Forward)
                .filter(|rule| **rule == ipv6_split_tunnel_bypass())
                .count(),
            usize::from(r.state == TunnelState::Up),
            "{r}"
        );
    }
}

/// The rejections close the `forward` chain: behind `ct state invalid drop`
/// and `ct state established,related accept` at its head, behind every
/// opening, right before the chain policy. Before the established
/// acceptance, they would cut the return path of a flow; before an opening,
/// they would shadow it.
#[test]
fn the_ipv6_rejections_are_the_last_rules_of_forward() {
    for r in every_rendering() {
        let forward: Vec<&Rule> = r.ruleset.chain(ChainKind::Forward).collect();
        let tail = &forward[forward.len() - UPLINKS.len()..];
        assert_eq!(
            tail.iter().map(|rule| (*rule).clone()).collect::<Vec<_>>(),
            UPLINKS.map(ipv6_rejection).to_vec(),
            "{r}"
        );
        assert_eq!(
            forward[0].matches,
            [Match::ConnectionState(ConnectionStates::INVALID)],
            "{r}"
        );
        assert!(
            forward[..forward.len() - UPLINKS.len()].iter().any(|rule| {
                rule.matches
                    == [Match::ConnectionState(
                        ConnectionStates::ESTABLISHED_RELATED,
                    )]
                    && rule.verdict == Verdict::Accept
            }),
            "{r}: the established acceptance must precede the rejections"
        );
        assert!(
            forward[..forward.len() - UPLINKS.len()]
                .iter()
                .all(|rule| rule.verdict != Verdict::RejectAdminProhibited),
            "{r}"
        );
    }
}

/// The rejection lives in `forward` only. A client's IPv6 to the gateway
/// itself stays under the `input` rules, the tunnel ICMPv6 opening
/// included, and nothing the gateway emits is rejected.
#[test]
fn ipv6_to_the_gateway_itself_is_left_to_input() {
    for r in every_rendering() {
        for chain in [ChainKind::Input, ChainKind::Output] {
            assert!(
                r.ruleset
                    .chain(chain)
                    .all(|rule| rule.verdict != Verdict::RejectAdminProhibited),
                "{r}: rejection outside `forward`"
            );
        }
        assert!(
            r.ruleset.chain(ChainKind::Input).any(|rule| rule.matches
                == [
                    Match::InIface("helios0".into()),
                    Match::Icmp(AddressFamily::Ipv6)
                ]
                && rule.verdict == Verdict::Accept),
            "{r}: the tunnel ICMPv6 opening must be unchanged"
        );
    }
}

/// Without a tunnel interface there are no tunnel clients and nothing to
/// scope the rejection to: none is rendered, rather than an unscoped one
/// that would refuse the LAN's IPv6.
#[test]
fn no_rejection_without_a_tunnel_interface() {
    let mut p = relay_policy(true, PolicyMode::FailClosed);
    p.wg_iface = String::new();
    p.admin_iface = None;
    p.admin_port = None;
    for state in every_state() {
        assert!(
            render(&p, state)
                .rules
                .iter()
                .all(|rule| rule.verdict != Verdict::RejectAdminProhibited),
            "state {state:?}"
        );
    }
}

/// The rules that select IPv6 are the gateway's own link control, in
/// `input` or `output` and scoped to one of its WAN or LAN interfaces, the
/// tunnel clients' egress rejection in `forward`, and the operator's IPv6
/// split-tunnel bypass, off the tunnel interface. A rule selecting IPv6
/// anywhere else — on the tunnel, an overlay, or unscoped — fails here.
#[test]
fn rules_selecting_ipv6_are_link_control_or_the_egress_rejection() {
    let links: Vec<&str> = UPLINKS.iter().copied().chain(["eth1"]).collect();
    let rejections = UPLINKS.map(ipv6_rejection);
    let bypass = ipv6_split_tunnel_bypass();
    for r in every_rendering() {
        let mut link_control = 0;
        for rule in r
            .ruleset
            .rules
            .iter()
            .filter(|rule| rule.matches.iter().any(selects_ipv6))
        {
            if rejections.contains(rule) || *rule == bypass {
                continue;
            }
            link_control += 1;
            let on_a_link = links.iter().any(|iface| {
                let scope = match rule.chain {
                    ChainKind::Input => Match::InIface((*iface).into()),
                    ChainKind::Output => Match::OutIface((*iface).into()),
                    ChainKind::Forward => return false,
                };
                rule.matches.first() == Some(&scope)
            });
            assert!(
                on_a_link && rule.verdict == Verdict::Accept,
                "{r}: `{rule}`"
            );
        }
        // The sweep must have seen the link-control rules, otherwise it
        // would pass on a renderer that stopped emitting them.
        assert!(link_control > 0, "{r}: no IPv6 link-control rule rendered");
    }
}
