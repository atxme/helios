//! The gateway's own traffic on its uplinks.
//!
//! Neither of these two openings relays anything: they are what the machine
//! itself emits on the WAN — its DHCP lease renewal and, when the operator
//! opens it, its name resolution, time and package fetching. Both are
//! deliberately independent of the tunnel state; the module doc of
//! [`super`] explains why for the second.

use aether::FirewallPolicy;

use super::ChainKind::{Input, Output};
use super::{AddressFamily, Match, Rule, Verdict, L4};

pub(super) fn dhcp_lease_renewal(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) {
    // ── DHCP lease renewal on the WAN ────────────────────────────────────────
    // Scoped to the WAN interface and to the protocol's two ports. Traffic is
    // local to the link: the client sends to 67, the server replies to 68.
    // The reply is not left to `ct state established` — a DHCPDISCOVER goes
    // out as a broadcast and the reply does not always attach to a tracked
    // flow.
    //
    // The same flag opens the DHCPv6 client: "the WAN address comes from a
    // lease" holds for both families. The client sends to 547 — a Solicit
    // goes to the `ff02::1:2` multicast group, so its answer, unicast from
    // the server's link-local address, attaches to no tracked flow either —
    // and the server replies to 546. Those two rules carry `meta nfproto
    // ipv6`: they name no address, and DHCPv6 ports mean nothing to IPv4.
    // The DHCPv4 pair above names no family; it predates the guard and is
    // left as it is.
    if policy.allow_dhcp_on_wan {
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::DestPort {
                            port: 67,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("DHCP: without renewal, the gateway loses its WAN address"),
            );
            rules.push(Rule::new(
                Input,
                vec![
                    Match::InIface(wan.clone()),
                    Match::DestPort {
                        port: 68,
                        proto: L4::Udp,
                    },
                ],
                Verdict::Accept,
            ));
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::Family(AddressFamily::Ipv6),
                        Match::DestPort {
                            port: 547,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("DHCPv6: the lease of an IPv6 WAN address renews the same way"),
            );
            rules.push(Rule::new(
                Input,
                vec![
                    Match::InIface(wan.clone()),
                    Match::Family(AddressFamily::Ipv6),
                    Match::DestPort {
                        port: 546,
                        proto: L4::Udp,
                    },
                ],
                Verdict::Accept,
            ));
        }
    }
}

pub(super) fn gateway_own_egress(
    rules: &mut Vec<Rule>,
    policy: &FirewallPolicy,
    wan_ifaces: &[String],
) {
    // ── The gateway's own egress ─────────────────────────────────────────────
    // Name resolution, time and package fetching, for the gateway itself.
    // Scoped to the WAN interface and to those ports, in `output` only: this
    // forwards nothing and opens nothing inbound.
    //
    // Not gated on the tunnel state. The kill-switch exists to stop relayed
    // traffic from leaving in the clear, and relaying lives in `forward`. The
    // moment an operator most needs this opening is an upgrade, which is
    // exactly a moment when the tunnel may be down.
    if policy.allow_gateway_egress {
        for wan in wan_ifaces {
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::DestPort {
                            port: 53,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "the gateway's own DNS: without it the resolver's query to the LAN is a \
                     new flow, dropped by the policy — which reads as a name-resolution \
                     failure and is not one",
                ),
            );
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::DestPortSet {
                            // 53 over TCP is not optional: a truncated answer
                            // falls back to it, and so does anything DNSSEC-sized.
                            ports: vec![53, 80, 443],
                            proto: L4::Tcp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("package fetching — `helios update` runs `apt-get` on the gateway"),
            );
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::DestPort {
                            port: 123,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "NTP: the machine that checks certificate validity dates is the one whose \
                     clock must not drift",
                ),
            );
        }
    }
}
