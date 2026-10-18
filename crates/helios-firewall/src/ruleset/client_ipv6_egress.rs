//! The tunnel clients' IPv6 Internet egress: refused, and said so.
//!
//! Orion captures `::/0`, so a client's IPv6 enters the tunnel instead of
//! leaving in the clear, and the gateway relays none of it
//! (ADRESSAGE-IPV6 §6.4): no `forward` rule accepts IPv6 from `wg_iface` to a
//! WAN, and there is no NAT66. Left to the `drop` policy, such a packet
//! vanishes silently, and an application that tries IPv6 first waits for its
//! own timeout — 250 ms under RFC 8305, several seconds on some stacks —
//! before falling back to IPv4.
//!
//! These rules turn that silence into an answer (SORTIE-IPV6 §3.1): one
//! `reject with icmpx admin-prohibited` per uplink, scoped by
//! `meta nfproto ipv6`, `iifname <wg_iface>` and the uplink. The verdict
//! refuses exactly what the policy would have dropped; it opens nothing.
//!
//! # Before routing first
//!
//! A gateway without IPv6 forwarding — the kernel default, which Helios does
//! not change (SORTIE-IPV6 §3.2) — drops such a packet in `ip6_forward`,
//! before the `forward` hook: a rejection there alone is never reached, and
//! the client waits for its timeout anyway. Observed on the netns bench, and
//! the reason for the amendment of SORTIE-IPV6 §3.1. The rejection is
//! therefore rendered in `prerouting`, where `oifname` does not exist yet:
//! `fib daddr oifname <wan>` names the uplink the route lookup would pick, so
//! the gateway's own traffic, another peer and the LAN stay out of scope.
//!
//! The same rejection stays last of `forward`, by `oifname`, for a gateway
//! that does forward IPv6 and whose actual routing (marks, policy routing)
//! differs from that lookup.
//!
//! # Every state
//!
//! The rules do not follow the tunnel state. Outside `Up` the `drop` policy
//! would refuse the packet anyway, but the answer keeps the fallback fast
//! during `Connecting`; under a fail-open policy, whose default becomes
//! `accept` outside the tunnel, it is what keeps the tunnel clients' IPv6 from
//! being relayed at all.
//!
//! # Order
//!
//! In `forward`, rendered after every other capability, so last: behind
//! `ct state invalid drop` and `ct state established,related accept` at the
//! head of the chain, behind every opening, before the chain policy. Only
//! IPv6 from the tunnel to an uplink matches; IPv6 a client sends to the
//! gateway itself goes through `input`, which these rules do not touch. In
//! `prerouting` the chain holds these rejections and nothing else.
//!
//! The ICMPv6 answers are not rate limited in the ruleset, because
//! `rustables 0.8.7` has no `limit`: the kernel bounds them with
//! `net.ipv6.icmp.ratelimit`, and their only recipient is the peer itself,
//! through its authenticated tunnel (SORTIE-IPV6 §4.2).

use aether::FirewallPolicy;

use super::ChainKind::{Forward, Prerouting};
use super::{AddressFamily, Match, Rule, Verdict};

pub(super) fn reject(rules: &mut Vec<Rule>, policy: &FirewallPolicy, wan_ifaces: &[String]) {
    // Without a tunnel interface there are no tunnel clients, and nothing to
    // scope the rule to: an unscoped variant would reject the IPv6 of every
    // interface, the LAN's included.
    if policy.wg_iface.is_empty() {
        return;
    }
    for wan in wan_ifaces {
        rules.push(
            Rule::new(
                Forward,
                vec![
                    Match::Family(AddressFamily::Ipv6),
                    Match::InIface(policy.wg_iface.clone()),
                    Match::OutIface(wan.clone()),
                ],
                Verdict::RejectAdminProhibited,
            )
            .with_note(
                "tunnel clients' IPv6 Internet egress: refused, without waiting for a timeout",
            ),
        );
    }
    for wan in wan_ifaces {
        rules.push(
            Rule::new(
                Prerouting,
                vec![
                    Match::Family(AddressFamily::Ipv6),
                    Match::InIface(policy.wg_iface.clone()),
                    Match::FibDestinationOutIface(wan.clone()),
                ],
                Verdict::RejectAdminProhibited,
            )
            .with_note(
                "tunnel clients' IPv6 Internet egress: refused before routing, so answered \
                 without IPv6 forwarding",
            ),
        );
    }
}
