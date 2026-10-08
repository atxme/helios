//! How an operator reaches the gateway.
//!
//! Three independent paths, rendered at three different positions of the
//! chain: the administration API at its head, then SSH from declared source
//! addresses, then SSH on the out-of-band overlay interfaces. ADR-001 §3
//! quater names them and explains why the last one is scoped by interface.

use aether::{FirewallPolicy, Result};

use super::ChainKind::Input;
use super::{parse_network, Match, Rule, Verdict, L4};

pub(super) fn admin_api(rules: &mut Vec<Rule>, policy: &FirewallPolicy) {
    // ── Administration: the API must only be reachable through the tunnel ──
    // At the head of the chain, even before loopback.
    if let (Some(port), Some(iface)) = (policy.admin_port, policy.admin_iface.as_deref()) {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::DestPort {
                        port,
                        proto: L4::Tcp,
                    },
                    Match::InIface(iface.to_string()),
                ],
                Verdict::Accept,
            )
            .with_note("administration API: only via the tunnel interface"),
        );
        rules.push(
            Rule::new(
                Input,
                vec![Match::DestPort {
                    port,
                    proto: L4::Tcp,
                }],
                Verdict::Drop,
            )
            .with_note(
                "any other origin is refused. No `ct state new`: the drop also covers \
                 connections already established from another interface — stricter, \
                 and expressible in Netlink",
            ),
        );
    }
}

pub(super) fn ssh_sources(rules: &mut Vec<Rule>, policy: &FirewallPolicy) -> Result<()> {
    // ── Administrative SSH, regardless of tunnel state ───────────────────────
    for src in &policy.allow_ssh_from {
        rules.push(Rule::new(
            Input,
            vec![
                Match::SourceNet(parse_network(src)?),
                Match::DestPort {
                    port: 22,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        ));
    }
    Ok(())
}

pub(super) fn out_of_band_admin_ifaces(rules: &mut Vec<Rule>, policy: &FirewallPolicy) {
    // ── Out-of-band administration overlays, regardless of tunnel state ──────
    //
    // The operator's way back in when Helios itself is down, so it is rendered
    // in every state — `Down` and `Connecting` included, which is the whole
    // point: those are the states a broken tunnel leaves the gateway in.
    //
    // Scoped by interface, never by address, for the reason on the tunnel
    // openings above — and for a second one specific to overlays. Tailscale
    // and NordVPN each carry several addresses (v4 and v6), reassigned
    // without notice. An address list stops matching the day the address
    // moves, which is the day the recovery path is needed; `iifname` covers
    // every address the interface will ever hold.
    for iface in &policy.admin_ifaces {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::InIface(iface.clone()),
                    Match::DestPort {
                        port: 22,
                        proto: L4::Tcp,
                    },
                ],
                Verdict::Accept,
            )
            .with_note("out-of-band administration SSH: survives a tunnel that cannot come up"),
        );
    }
}
