//! NordVPN Meshnet: transport, local services and routing.
//!
//! The longest and the most order-sensitive of the capabilities. A routing
//! peer without the local-network permission gets its private-network `drop`
//! rules *before* its accept, and that order is the permission: inverted, the
//! same rules would open the LAN they exist to close.

use aether::{FirewallPolicy, Result};

use super::ChainKind::{Forward, Input, Output};
use super::{network, AddressFamily, Match, Rule, Verdict, L4, PRIVATE_IPV4_CIDRS};

pub(super) fn nordvpn_meshnet(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) -> Result<()> {
    // ── NordVPN Meshnet: transport, local services and routing ──────────────
    // Libtelio marks its relay, STUN and direct-path packets; accepting that
    // mark on a declared WAN lets paths and ports evolve without granting an
    // unmarked process arbitrary egress. Plaintext application packets are
    // separately scoped to nordlynx and the operator-selected peer networks.
    // Forwarding mirrors NordVPN's per-peer permissions. NordVPN owns the NAT
    // and applies a second independent filter; Helios still has to accept the
    // same flows because every base chain must accept a packet for it to
    // survive a drop policy.
    if let Some(meshnet) = &policy.nordvpn_meshnet {
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::PacketMark(meshnet.fwmark),
                    ],
                    Verdict::Accept,
                )
                .with_note("NordVPN Meshnet transport marked by libtelio"),
            );
        }

        for peer in &meshnet.peer_cidrs {
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(meshnet.iface.clone()),
                        Match::DestNet(network(peer)?),
                    ],
                    Verdict::Accept,
                )
                .with_note("gateway application traffic to an allowed Meshnet peer"),
            );

            if meshnet.allow_icmp {
                rules.push(
                    Rule::new(
                        Input,
                        vec![
                            Match::InIface(meshnet.iface.clone()),
                            Match::SourceNet(network(peer)?),
                            Match::Icmp(AddressFamily::Ipv4),
                        ],
                        Verdict::Accept,
                    )
                    .with_note("ICMP from an allowed Meshnet peer"),
                );
            }
            for (proto, ports) in [
                (L4::Tcp, &meshnet.inbound_tcp_ports),
                (L4::Udp, &meshnet.inbound_udp_ports),
            ] {
                if !ports.is_empty() {
                    rules.push(
                        Rule::new(
                            Input,
                            vec![
                                Match::InIface(meshnet.iface.clone()),
                                Match::SourceNet(network(peer)?),
                                Match::DestPortSet {
                                    ports: ports.clone(),
                                    proto,
                                },
                            ],
                            Verdict::Accept,
                        )
                        .with_note("service exposed to an allowed Meshnet peer"),
                    );
                }
            }
        }

        for peer in &meshnet.traffic_routing_peer_cidrs {
            let may_reach_local_network = meshnet.local_network_peer_cidrs.contains(peer);

            if !may_reach_local_network {
                for private_network in PRIVATE_IPV4_CIDRS {
                    rules.push(
                        Rule::new(
                            Forward,
                            vec![
                                Match::InIface(meshnet.iface.clone()),
                                Match::SourceNet(network(peer)?),
                                Match::DestNet(network(private_network)?),
                            ],
                            Verdict::Drop,
                        )
                        .with_note("Meshnet routing peer has no local-network permission"),
                    );
                }
            }

            let mut routed_out_ifaces = wan_ifaces.to_vec();
            if may_reach_local_network {
                for lan in &policy.lan_ifaces {
                    if !routed_out_ifaces.contains(lan) {
                        routed_out_ifaces.push(lan.clone());
                    }
                }
            }
            for out_iface in routed_out_ifaces {
                rules.push(
                    Rule::new(
                        Forward,
                        vec![
                            Match::InIface(meshnet.iface.clone()),
                            Match::SourceNet(network(peer)?),
                            Match::OutIface(out_iface),
                        ],
                        Verdict::Accept,
                    )
                    .with_note("traffic from a NordVPN-authorized Meshnet routing peer"),
                );
            }
        }
    }
    Ok(())
}
