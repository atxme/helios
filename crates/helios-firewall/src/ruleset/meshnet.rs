//! NordVPN Meshnet: transport, local services and routing.
//!
//! The longest and the most order-sensitive of the capabilities. A routing
//! peer without the local-network permission gets its private-network `drop`
//! rules *before* its accept, and that order is the permission: inverted, the
//! same rules would open the LAN they exist to close.
//!
//! Every peer-scoped rule follows the peer's address family: its ICMP opening
//! is ICMPv4 or ICMPv6, and its private-network drops name the local networks
//! of its own family. A drop pairing an IPv6 source with an IPv4 destination
//! never matches, and the accept after it would then open the local IPv6
//! networks.
//!
//! # Known limitation: IPv6 Meshnet peers are refused by the configuration
//!
//! `aether` validates Meshnet peer CIDRs as IPv4, because NordVPN hands out
//! IPv4 Meshnet addresses. An IPv6 peer reaches this module only through a
//! [`FirewallPolicy`] built in code. For such a peer, the local IPv6 networks
//! are the unique local and link-local scopes: a global unicast prefix on the
//! WAN's own link is not among them, whereas its IPv4 counterpart is usually
//! RFC 1918 and is dropped. Accepting IPv6 peers in the configuration needs
//! that decision and a target test of an IPv6 routing peer.

use aether::{FirewallPolicy, Result};
use ipnetwork::IpNetwork;

use super::ChainKind::{Forward, Input, Output};
use super::{local_networks, parse_network, AddressFamily, Match, Rule, Verdict, L4};

/// The family a peer-scoped rule must select to ever match that peer.
fn family_of(peer: &IpNetwork) -> AddressFamily {
    if peer.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    }
}

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
                        Match::DestNet(parse_network(peer)?),
                    ],
                    Verdict::Accept,
                )
                .with_note("gateway application traffic to an allowed Meshnet peer"),
            );

            if meshnet.allow_icmp {
                let source = parse_network(peer)?;
                rules.push(
                    Rule::new(
                        Input,
                        vec![
                            Match::InIface(meshnet.iface.clone()),
                            Match::SourceNet(source),
                            Match::Icmp(family_of(&source)),
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
                                Match::SourceNet(parse_network(peer)?),
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
                let source = parse_network(peer)?;
                for private_network in local_networks(family_of(&source)) {
                    rules.push(
                        Rule::new(
                            Forward,
                            vec![
                                Match::InIface(meshnet.iface.clone()),
                                Match::SourceNet(source),
                                Match::DestNet(parse_network(private_network)?),
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
                            Match::SourceNet(parse_network(peer)?),
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
