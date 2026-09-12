//! Tests for the ruleset renderer, grouped by the behavior they protect.

use super::super::*;
use super::support::policy;
/// A gateway with a cable and a radio: every rule that names the WAN is
/// emitted for both. This is what makes an uplink failover survive with no
/// restart — the kernel moves its default route and the rules are already
/// there.
#[test]
fn every_wan_rule_is_emitted_for_every_uplink() {
    let mut policy = policy();
    policy.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
    policy.allow_gateway_egress = true;
    policy.allow_client_internet = true;
    policy.allow_dhcp_on_wan = true;
    let rs = render(&policy, TunnelState::Up);

    for iface in ["enp3s0", "wlo1"] {
        let inbound: Vec<&Rule> = rs
            .chain(ChainKind::Input)
            .filter(|rule| rule.matches.contains(&Match::InIface(iface.into())))
            .collect();
        let opens = |port: u16| {
            inbound.iter().any(|rule| {
                rule.matches.contains(&Match::DestPort {
                    port,
                    proto: L4::Udp,
                })
            })
        };
        assert!(opens(51820), "the WireGuard listener is open on {iface}");
        assert!(
            opens(68),
            "DHCP replies are accepted on {iface}: a lease renewed on one link only \
             would strand the other"
        );
        assert!(
            rs.chain(ChainKind::Output)
                .any(|rule| rule.matches.contains(&Match::OutIface(iface.into()))),
            "the gateway's own egress leaves by {iface}"
        );
        assert!(
            rs.chain(ChainKind::Forward)
                .any(|rule| rule.matches.contains(&Match::OutIface(iface.into()))),
            "tunnel clients reach the Internet through {iface}"
        );
    }
    assert_eq!(
        rs.masquerade_out,
        vec!["enp3s0".to_string(), "wlo1".to_string()],
        "one masquerade per uplink: each only matches what leaves by its own interface"
    );
}

/// The kill-switch is unchanged by any of it: several uplinks is not a
/// reason for NAT to outlive the tunnel.
#[test]
fn several_uplinks_do_not_outlive_the_kill_switch() {
    let mut policy = policy();
    policy.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
    policy.allow_client_internet = true;
    for state in [TunnelState::Down, TunnelState::Connecting] {
        let rs = render(&policy, state);
        assert!(
            rs.masquerade_out.is_empty(),
            "a masquerade surviving the kill-switch would let out in the clear what it \
             has just cut, on either uplink"
        );
    }
}

/// No uplink declared emits no WAN rule at all — never a rule on an
/// interface named nothing, which would match everything or nothing
/// depending on the backend.
#[test]
fn no_uplink_emits_no_wan_rule() {
    let mut policy = policy();
    policy.wan_ifaces = Vec::new();
    policy.allow_gateway_egress = true;
    policy.allow_client_internet = true;
    let rs = render(&policy, TunnelState::Up);
    assert!(
        !rs.rules
            .iter()
            .any(|rule| rule.matches.iter().any(|m| matches!(
                m,
                Match::InIface(name) | Match::OutIface(name) if name.is_empty()
            ))),
        "no rule is emitted on an empty interface name"
    );
    assert!(rs.masquerade_out.is_empty());
}
