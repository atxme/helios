//! Tests for the ruleset renderer, grouped by the behavior they protect.

use super::super::*;
use super::support::{policy, render, text};
#[test]
fn down_blocks_lan_forward() {
    let rs = render(&policy(), TunnelState::Down);
    assert_eq!(rs.default_verdict, Verdict::Drop);
    assert!(!text(&rs, ChainKind::Forward)
        .iter()
        .any(|r| r.contains("iifname \"eth1\"")));
}

/// Without this rule, no road-warrior client can handshake: fail-closed
/// drops inbound packets. This is the condition for access.
#[test]
fn listen_port_is_open_inbound() {
    for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let rs = render(&policy(), st);
        assert!(
            text(&rs, ChainKind::Input)
                .iter()
                .any(|r| r == "iifname \"eth0\" udp dport 51820 accept"),
            "state {st:?}: the WireGuard listening port must stay reachable"
        );
    }
}

#[test]
fn astra_channel_is_open_only_on_its_fixed_bridge_tuple() {
    let rs = render(&policy(), TunnelState::Down);
    let input = text(&rs, ChainKind::Input);
    let output = text(&rs, ChainKind::Output);
    assert!(input.iter().any(|rule| {
        rule == "iifname \"astra0\" ip saddr 10.88.7.2/32 ip daddr 10.88.7.1/32 tcp dport 8444 accept"
    }));
    assert!(output.iter().any(|rule| {
        rule == "oifname \"astra0\" ip saddr 10.88.7.1/32 ip daddr 10.88.7.2/32 tcp dport 8445 accept"
    }));
    assert!(!text(&rs, ChainKind::Forward)
        .iter()
        .any(|rule| rule.contains("astra0") || rule.contains("10.88.7.")));
}

/// The origin published on loopback is DNATed onto the public Astra
/// bridge, so the packet leaves through `astra1` and is judged by the
/// output chain — not by the loopback rule its destination address
/// suggests. Without this opening the gateway cannot reach its own
/// authority, and the §7.5 recovery of an expired identity has nowhere to
/// go: it is the one exchange that must work when the tunnel does not.
#[test]
fn the_public_astra_origin_is_reachable_from_the_gateway_only_outbound() {
    let rs = render(&policy(), TunnelState::Down);
    let expected =
        "oifname \"astra1\" ip saddr 10.88.7.9/32 ip daddr 10.88.7.10/32 tcp dport 8443 accept";
    assert!(
        text(&rs, ChainKind::Output)
            .iter()
            .any(|rule| rule == expected),
        "the gateway must be able to dial the origin: {:?}",
        text(&rs, ChainKind::Output)
    );
    // The opening is the host's. Nothing here admits the container inbound
    // or grants it a route through the gateway.
    assert!(!text(&rs, ChainKind::Input)
        .iter()
        .any(|rule| rule.contains("astra1")));
    assert!(!text(&rs, ChainKind::Forward)
        .iter()
        .any(|rule| rule.contains("astra1")));
}

/// UDP conntrack is not a transport contract. A WireGuard rekey or the
/// final QUIC frame can be emitted after its entry expired; with several
/// uplinks, the reply may also leave through a different interface. The
/// listeners therefore need a source-port-scoped output opening of their
/// own in every state.
#[test]
fn public_udp_listeners_can_answer_on_every_uplink() {
    let mut p = policy();
    p.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];

    for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let output = text(&render(&p, state), ChainKind::Output);
        for wan in ["enp3s0", "wlo1"] {
            for port in [51820, 51821] {
                let expected = format!("oifname \"{wan}\" udp sport {port} accept");
                assert!(
                    output.iter().any(|rule| rule == &expected),
                    "state {state:?}: missing listener response rule `{expected}`"
                );
            }
        }
    }
}
