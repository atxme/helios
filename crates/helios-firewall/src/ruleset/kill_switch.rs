//! The openings the kill-switch gates.
//!
//! Everything rendered here exists only in a state where traffic is allowed,
//! or under the captive-portal derogation — and the two are exclusive, which
//! is why they are a single `if`/`else if` and not two independent sections.
//! A captive portal opens HTTP/HTTPS and nothing else, for the gateway itself
//! and, relayed, for its LAN only; an operational tunnel opens the
//! split-tunnel bypasses (from the LAN only), the LAN forward and, on request,
//! the road-warrior egress.

use aether::{FirewallPolicy, Result, TunnelState};

use super::ChainKind::{Forward, Output};
use super::{parse_network, MasqueradeRule, Match, Rule, Verdict, L4};

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
        // A known gateway narrows the opening to its address; an unknown one
        // lets the browser reach the portal's landing page, whatever its
        // destination. The address is parsed before any rule is emitted, LAN
        // interfaces or not, so that an invalid gateway fails the render
        // whatever the topology.
        let (destination, note) = match &policy.captive_portal_gateway {
            Some(gw) => (
                Some(parse_network(gw)?),
                format!("captive portal: HTTP/HTTPS to {gw}"),
            ),
            None => (None, "captive portal: unknown gateway".to_string()),
        };
        let opening = |mut matches: Vec<Match>| {
            matches.extend(destination.map(Match::DestNet));
            matches.push(ports.clone());
            matches
        };

        // The gateway itself.
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Output,
                    opening(vec![Match::OutIface(wan.clone())]),
                    Verdict::Accept,
                )
                .with_note(note.clone()),
            );
        }

        // The relayed opening is for the gateway's LAN, and only for it: a
        // packet enters by a LAN interface or the rule does not see it.
        // Scoped by the WAN alone, it would relay the tunnel clients'
        // HTTP/HTTPS to the WAN in the clear, outside any
        // `allow_client_internet` decision — and, without a known gateway,
        // their IPv6 with it, ahead of the `client_ipv6_egress` rejection
        // (ADRESSAGE-IPV6 §6.4, SORTIE-IPV6). Hence `iifname <lan>`, one rule
        // per LAN interface and WAN; without a LAN, no relayed opening is
        // rendered (fail closed).
        for lan in &policy.lan_ifaces {
            for wan in wan_ifaces {
                rules.push(
                    Rule::new(
                        Forward,
                        opening(vec![
                            Match::InIface(lan.clone()),
                            Match::OutIface(wan.clone()),
                        ]),
                        Verdict::Accept,
                    )
                    .with_note(note.clone()),
                );
            }
        }
    } else if state.traffic_allowed() {
        // Split-tunneling: local CIDRs bypass the tunnel.
        //
        // The bypass is for the gateway's LAN, and only for it: a packet
        // enters by a LAN interface or the rule does not see it. Scoped any
        // wider, an IPv4 CIDR would open those destinations to the tunnel
        // clients, an IPv6 one would relay their IPv6 ahead of the
        // `client_ipv6_egress` rejection (ADRESSAGE-IPV6 §6.4, SORTIE-IPV6),
        // and either would accept new connections entering by a WAN — for a
        // global IPv6 LAN prefix, an inbound opening from the Internet to the
        // LAN. Hence `iifname <lan>`, one rule per LAN interface and CIDR, in
        // both families.
        //
        // Every CIDR is parsed before any rule is emitted, LAN interfaces or
        // not: without a LAN no bypass is rendered (fail closed), but an
        // invalid CIDR is still refused, so that `check_policy` rejects it
        // whatever the topology.
        let destinations = policy
            .split_tunnel_cidrs
            .iter()
            .map(|cidr| parse_network(cidr))
            .collect::<Result<Vec<_>>>()?;
        for lan in &policy.lan_ifaces {
            for destination in &destinations {
                rules.push(Rule::new(
                    Forward,
                    vec![Match::InIface(lan.clone()), Match::DestNet(*destination)],
                    Verdict::Accept,
                ));
            }
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
        //
        // The opening relays the family the masquerade rewrites, and only
        // that one. The table is `inet`: without the guard, an IPv6 packet on
        // the tunnel interface would be forwarded to the WAN as soon as the
        // gateway enables IPv6 forwarding (ADRESSAGE-IPV6 §6.4). A peer's
        // IPv6 bound for a WAN is rejected instead, last of `forward`, by
        // module `client_ipv6_egress`.
        if policy.allow_client_internet && !policy.wg_iface.is_empty() {
            for wan in wan_ifaces {
                rules.push(
                    Rule::new(
                        Forward,
                        vec![
                            Match::Family(MasqueradeRule::FAMILY),
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
