//! IPv6 control traffic of the gateway's own links.
//!
//! The table is `inet` and its hooked chains drop by default, so the policy
//! applies to IPv6 too. IPv4 never noticed: neighbor resolution is ARP, which
//! an `inet` table does not see. IPv6 resolves neighbors with ICMPv6 — Neighbor
//! Solicitation and Advertisement — and learns its routers the same way, so
//! those packets go through the very chains that drop. Conntrack does not
//! rescue them: it classifies ND, router discovery and MLD as `untracked`,
//! neither `invalid` nor `established,related` (kernel behavior, to verify on
//! target). Without the rules below, a WAN that gets IPv6 by SLAAC loses
//! neighbor resolution at once, then its IPv6 default route when the router
//! lifetime of the last accepted Router Advertisement expires.
//!
//! # What is opened, and where
//!
//! * Neighbor Solicitation and Advertisement, `input` and `output`, on every
//!   WAN and every LAN interface: without them nothing on the link is
//!   reachable over IPv6.
//! * Router Solicitation in `output` and Router Advertisement in `input`, on
//!   the WAN interfaces only: the gateway is a *host* on its uplink and learns
//!   its default route there. An advertisement accepted from the tunnel, a LAN
//!   or an overlay is a rogue RA that could hand the gateway a default route.
//!   A WAN that is also declared in another role is therefore left without
//!   them rather than given the benefit of the doubt.
//! * MLD query, report and done and the MLDv2 report, `input` and `output`, on
//!   every WAN and LAN interface: a switch that snoops MLD forwards the
//!   solicited-node multicast an NS is sent to only to ports that reported
//!   it.
//!
//! None of these relay anything, so all are rendered in **every** tunnel
//! state, like the DHCPv4 lease renewal: the kill-switch stops relayed traffic
//! from leaving in the clear, it must not cut the gateway off its own links.
//! None is behind a flag either — on an interface that never carries IPv6 they
//! never match. There is no `forward` rule: link-local and link-scope
//! multicast traffic is never routed, and the gateway relays no IPv6
//! (`ADRESSAGE-IPV6.md` §6.4).
//!
//! Every rule is scoped by **interface**, never by address: ND and MLD use
//! link-local sources and link-scope multicast destinations, which belong to
//! no configured network. The overlays — `wg_iface`, `admin_ifaces`, the
//! Meshnet interface — get nothing: they are layer-3 tunnels without
//! link-layer addresses, on which the kernel resolves no neighbors.
//!
//! # Hop limit 255
//!
//! RFC 4861 requires ND messages to arrive with a hop limit of 255 and a
//! receiver to discard any other. A router decrements the hop limit, so 255
//! proves the packet was sent on the link itself: it is what makes ND and
//! router discovery unspoofable from off-link. The rules require it as well,
//! so the firewall accepts nothing wider than what a conforming stack would
//! process. MLD is sent with a hop limit of 1 (RFC 2710, RFC 3810) and is not
//! checked against 255; its rules carry an explicit `meta nfproto ipv6`
//! instead, because nothing else in them pins the network family and the
//! ICMPv6 protocol number alone could be carried by an IPv4 header.
//!
//! # What stays closed
//!
//! * Redirect (137) is not even representable in [`super::Icmpv6Type`]: it
//!   falls to the policy drop. A gateway has no use for a redirect, and
//!   accepting one lets the link rewrite its routes.
//! * Echo request and reply on the WAN, as for IPv4.
//! * The ICMPv6 errors — Destination Unreachable (1), Packet Too Big (2), Time
//!   Exceeded (3), Parameter Problem (4) — get no unconditional opening. When
//!   they concern a flow conntrack tracks, they are `related` and already
//!   accepted by `ct state established,related`, Packet Too Big included,
//!   which keeps path-MTU discovery working.
//!
//! # Known limitation: Packet Too Big outside a tracked flow
//!
//! A Packet Too Big about an encapsulation flow conntrack does not track — or
//! no longer tracks, once a UDP entry of the WireGuard transport has expired —
//! is not `related` and falls to the policy drop. Path-MTU discovery for that
//! transport over IPv6 would then black-hole. Whether the case occurs is a
//! kernel question that WSL cannot answer. What unblocks it: observing it on a
//! target gateway with an IPv6 WAN, then deciding an interface-scoped
//! acceptance of type 2 (`ETUDE-IPV6.md` §9.1).

use aether::FirewallPolicy;

use super::ChainKind::{self, Input, Output};
use super::{AddressFamily, Icmpv6Type, Match, Rule, Verdict};

/// Hop limit RFC 4861 requires on every ND and router-discovery message.
const ND_HOP_LIMIT: u8 = 255;

/// MLD messages, accepted in both directions on every link interface.
const MLD_TYPES: [Icmpv6Type; 4] = [
    Icmpv6Type::MldListenerQuery,
    Icmpv6Type::MldListenerReport,
    Icmpv6Type::MldListenerDone,
    Icmpv6Type::Mld2ListenerReport,
];

pub(super) fn link_control(rules: &mut Vec<Rule>, policy: &FirewallPolicy, wan_ifaces: &[String]) {
    // WANs first, then the LANs not already listed: an interface named in
    // both roles gets its rules once.
    let mut links: Vec<(&str, bool)> = Vec::new();
    for (iface, is_wan) in wan_ifaces
        .iter()
        .map(|wan| (wan.as_str(), true))
        .chain(policy.lan_ifaces.iter().map(|lan| (lan.as_str(), false)))
    {
        if !links.iter().any(|(listed, _)| *listed == iface) {
            links.push((iface, is_wan));
        }
    }

    for (iface, is_wan) in links {
        for chain in [Input, Output] {
            for message in [Icmpv6Type::NeighborSolicit, Icmpv6Type::NeighborAdvert] {
                rules.push(
                    Rule::new(
                        chain,
                        vec![
                            on_link(chain, iface),
                            Match::Icmpv6Type(message),
                            Match::Ipv6HopLimit(ND_HOP_LIMIT),
                        ],
                        Verdict::Accept,
                    )
                    .with_note(
                        "IPv6 neighbor discovery: ARP is invisible to an `inet` table, ND is \
                         not, and it is `untracked`",
                    ),
                );
            }
        }
        if is_wan && is_only_an_uplink(policy, iface) {
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        on_link(Output, iface),
                        Match::Icmpv6Type(Icmpv6Type::RouterSolicit),
                        Match::Ipv6HopLimit(ND_HOP_LIMIT),
                    ],
                    Verdict::Accept,
                )
                .with_note("the gateway is a host on its uplink: it solicits its router"),
            );
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        on_link(Input, iface),
                        Match::Icmpv6Type(Icmpv6Type::RouterAdvert),
                        Match::Ipv6HopLimit(ND_HOP_LIMIT),
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "router advertisements on the uplink only: anywhere else they are rogue",
                ),
            );
        }
        for chain in [Input, Output] {
            for message in MLD_TYPES {
                rules.push(Rule::new(
                    chain,
                    vec![
                        on_link(chain, iface),
                        Match::Family(AddressFamily::Ipv6),
                        Match::Icmpv6Type(message),
                    ],
                    Verdict::Accept,
                ));
            }
        }
    }
}

/// The interface match of a link rule: ingress in `input`, egress in
/// `output`, where a locally generated packet has no ingress interface.
fn on_link(chain: ChainKind, iface: &str) -> Match {
    if chain == Output {
        Match::OutIface(iface.to_string())
    } else {
        Match::InIface(iface.to_string())
    }
}

/// Whether `iface` holds no role but uplink. Router advertisements are
/// accepted only on such an interface: a name shared with the tunnel, a LAN,
/// an overlay or Meshnet would let that side announce routes to the gateway.
fn is_only_an_uplink(policy: &FirewallPolicy, iface: &str) -> bool {
    let meshnet = policy
        .nordvpn_meshnet
        .as_ref()
        .is_some_and(|meshnet| meshnet.iface == iface);
    policy.wg_iface != iface
        && !policy.lan_ifaces.iter().any(|lan| lan == iface)
        && !policy.admin_ifaces.iter().any(|admin| admin == iface)
        && !meshnet
}
