//! The openings the kill-switch gates.
//!
//! Everything rendered here exists only in a state where traffic is allowed,
//! or under the captive-portal derogation — and the two are exclusive, which
//! is why they are a single `if`/`else if` and not two independent sections.
//! A captive portal opens HTTP/HTTPS and nothing else; an operational tunnel
//! opens the split-tunnel bypasses, the LAN forward and, on request, the
//! road-warrior egress.

use aether::{FirewallPolicy, Result, TunnelState};

use super::ChainKind::{Forward, Output};
use super::{network, Match, Rule, Verdict, L4};

pub(super) fn state_gated_openings(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    state: TunnelState,
    wan_ifaces: &[String],
) -> Result<()> {
    if state.captive_portal_active() {
        // Captive portal: the kill-switch is lifted for HTTP/HTTPS only.
        let ports = Match::DestPortSet {
            ports: vec![80, 443],
            proto: L4::Tcp,
        };
        match &policy.captive_portal_gateway {
            Some(gw) => {
                for chain in [Output, Forward] {
                    for wan in wan_ifaces {
                        rules.push(
                            Rule::new(
                                chain,
                                vec![
                                    Match::OutIface(wan.clone()),
                                    Match::DestNet(network(gw)?),
                                    ports.clone(),
                                ],
                                Verdict::Accept,
                            )
                            .with_note(format!("captive portal: HTTP/HTTPS to {gw}")),
                        );
                    }
                }
            }
            None => {
                // Unknown gateway: let the browser reach the portal's landing
                // page, whatever its destination.
                for chain in [Output, Forward] {
                    for wan in wan_ifaces {
                        rules.push(
                            Rule::new(
                                chain,
                                vec![Match::OutIface(wan.clone()), ports.clone()],
                                Verdict::Accept,
                            )
                            .with_note("captive portal: unknown gateway"),
                        );
                    }
                }
            }
        }
    } else if state.traffic_allowed() {
        // Split-tunneling: local CIDRs bypass the tunnel.
        for cidr in &policy.split_tunnel_cidrs {
            rules.push(Rule::new(
                Forward,
                vec![Match::DestNet(network(cidr)?)],
                Verdict::Accept,
            ));
        }

        // Tunnel operational: forward the LAN. WireGuard encrypts on egress;
        // a packet not captured by the tunnel interface will not go out.
        for lan in &policy.lan_ifaces {
            for wan in wan_ifaces {
                rules.push(Rule::new(
                    Forward,
                    vec![Match::InIface(lan.clone()), Match::OutIface(wan.clone())],
                    Verdict::Accept,
                ));
            }
        }

        // Internet egress for tunnel clients. The return path is covered by
        // the forward chain's `ct state established,related` rule: opening
        // the outbound direction is enough, and scoping to the client -> WAN
        // direction only avoids exposing the gateway's LAN to clients.
        if policy.allow_client_internet && !policy.wg_iface.is_empty() {
            for wan in wan_ifaces {
                rules.push(
                    Rule::new(
                        Forward,
                        vec![
                            Match::InIface(policy.wg_iface.clone()),
                            Match::OutIface(wan.clone()),
                        ],
                        Verdict::Accept,
                    )
                    .with_note("Internet egress for tunnel clients (masquerade in postrouting)"),
                );
            }
        }
    }
    Ok(())
}
