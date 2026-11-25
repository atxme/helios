//! Operator services on local bridges: the gateway reaches them, and nothing
//! else changes.

use super::super::*;
use super::support::{every_state, policy, render, text};
use aether::{LocalService, PolicyMode};
use std::net::Ipv4Addr;

const EXPECTED: &str =
    "oifname \"vault0\" ip saddr 10.88.7.17/32 ip daddr 10.88.7.18/32 tcp dport 9443 accept";

fn with_service(mode: PolicyMode) -> FirewallPolicy {
    let mut policy = policy();
    policy.mode = mode;
    policy.local_services = vec![LocalService {
        name: "vault".into(),
        iface: "vault0".into(),
        host: Ipv4Addr::new(10, 88, 7, 17),
        peer: Ipv4Addr::new(10, 88, 7, 18),
        port: 9443,
    }];
    policy
}

/// In every state, the ruleset is the one without the service plus a single
/// `output` rule. Nothing in `input`, `forward`, `prerouting` or the NAT.
#[test]
fn a_service_adds_one_outbound_rule_and_nothing_else() {
    for mode in [PolicyMode::FailClosed, PolicyMode::FailOpen] {
        let with = with_service(mode);
        let mut without = with.clone();
        without.local_services.clear();
        for state in every_state() {
            let mut rendered = render(&with, state);
            let position = rendered
                .rules
                .iter()
                .position(|rule| rule.to_string() == EXPECTED)
                .unwrap_or_else(|| panic!("{state:?}: the service must be reachable"));
            let added = rendered.rules.remove(position);
            assert_eq!(added.chain, ChainKind::Output, "{state:?}");
            assert_eq!(
                format!("{rendered:?}"),
                format!("{:?}", render(&without, state)),
                "{state:?}"
            );
        }
    }
}

#[test]
fn each_service_gets_its_own_rule() {
    let mut policy = with_service(PolicyMode::FailClosed);
    policy.local_services.push(LocalService {
        name: "other".into(),
        iface: "other0".into(),
        host: Ipv4Addr::new(10, 90, 0, 1),
        peer: Ipv4Addr::new(10, 90, 0, 2),
        port: 8000,
    });
    let output = text(&render(&policy, TunnelState::Down), ChainKind::Output);
    assert!(output.iter().any(|rule| rule == EXPECTED));
    assert!(output.iter().any(|rule| rule
        == "oifname \"other0\" ip saddr 10.90.0.1/32 ip daddr 10.90.0.2/32 tcp dport 8000 accept"));
}

#[test]
fn the_rule_names_its_service() {
    let rs = render(&with_service(PolicyMode::FailClosed), TunnelState::Down);
    let note = rs
        .rules
        .iter()
        .find(|rule| rule.to_string() == EXPECTED)
        .and_then(|rule| rule.note.as_deref());
    assert_eq!(note, Some("gateway to the local service vault"));
}
