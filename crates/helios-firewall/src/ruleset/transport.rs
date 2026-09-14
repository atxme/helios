//! The WireGuard and key-negotiation transport on the uplinks.
//!
//! The two public UDP listeners the gateway answers on, and the outbound
//! transport towards statically configured peers. All three are rendered per
//! uplink: a gateway with a cable and a radio must keep answering when one of
//! them goes away.

use aether::FirewallPolicy;

use super::ChainKind::{Input, Output};
use super::{Match, Rule, Verdict, L4};

pub(super) fn wireguard_listener(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) {
    // ── WireGuard listener (server role) ─────────────────────────────────────
    // Road-warrior clients arrive from unknown, changing IPs: impossible to
    // scope by source. This is the sole inbound opening of the fail-closed
    // model, and it is indispensable for the handshake.
    if let Some(port) = policy.wg_listen_port {
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        Match::InIface(wan.clone()),
                        Match::DestPort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("WireGuard listener — without this rule, no client can handshake"),
            );
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::SourcePort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "WireGuard listener transport — replies, rekeys and keep-alives may be new \
                     conntrack flows, especially after an uplink change",
                ),
            );
        }
    }
}

pub(super) fn key_negotiation_listener(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) {
    // ── Key-negotiation listener ─────────────────────────────────────────────
    // This public QUIC endpoint authenticates peers before the first
    // WireGuard handshake. It is opened only when the configured service is
    // ready; the administration API remains restricted to the tunnel.
    if let Some(port) = policy.key_negotiation_port {
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        Match::InIface(wan.clone()),
                        Match::DestPort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("authenticated key-negotiation QUIC listener"),
            );
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::SourcePort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "key-negotiation QUIC replies — the final frame can outlive UDP conntrack",
                ),
            );
        }
    }
}

pub(super) fn site_to_site_peers(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) {
    // ── Outbound WireGuard transport to static peers (site-to-site) ─────────
    // Scoped by destination: opening 51820 outbound without restricting the
    // destination would be a leak.
    for peer in &policy.wg_peers {
        for wan in wan_ifaces {
            rules.push(Rule::new(
                Output,
                vec![
                    Match::OutIface(wan.clone()),
                    Match::DestNet(peer.clone()),
                    Match::DestPort {
                        port: 51820,
                        proto: L4::Udp,
                    },
                ],
                Verdict::Accept,
            ));
        }
    }
}
