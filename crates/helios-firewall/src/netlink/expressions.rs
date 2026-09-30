//! Translation of a [`Match`] into `rustables` expressions.
//!
//! The deterministic half of the backend: every function here maps a rendered
//! rule onto what nf_tables understands, and none of them talks to the kernel.
//! That is why the batch built from them can be validated without a machine
//! carrying `nf_tables`.

use aether::Result;
use ipnetwork::IpNetwork;
use rustables::{
    expr::{
        Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Counter as NfCounter,
        Log as NfLog, Meta, MetaType,
    },
    HookClass, Protocol, Rule as NfRule,
};

use super::NetlinkBackend;
use crate::ruleset::{
    Action, AddressFamily, ChainKind, ConnectionState, ConnectionStates, Counter, Match, L4,
};

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_ICMPV6: u8 = 58;
/// Netfilter family numbers (`NFPROTO_IPV4`, `NFPROTO_IPV6`), the value
/// `meta nfproto` loads into the register.
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

impl NetlinkBackend {
    pub(super) fn hook_class(kind: ChainKind) -> HookClass {
        match kind {
            ChainKind::Input => HookClass::In,
            ChainKind::Forward => HookClass::Forward,
            ChainKind::Output => HookClass::Out,
        }
    }

    /// Applies a match to a rule under construction.
    pub(super) fn apply_match(rule: NfRule, m: &Match) -> Result<NfRule> {
        let proto = |p: L4| match p {
            L4::Tcp => Protocol::TCP,
            L4::Udp => Protocol::UDP,
        };

        Ok(match m {
            Match::ConnectionState(states) => Self::connection_states(rule, *states)?,
            Match::InIface(i) => rule.iiface(i).map_err(Self::err)?,
            Match::OutIface(i) => rule.oiface(i).map_err(Self::err)?,
            Match::DestPort { port, proto: p } => rule.dport(*port, proto(*p)),
            Match::SourcePort { port, proto: p } => rule.sport(*port, proto(*p)),
            Match::DestPortSet { .. } => {
                return Err(Self::err(
                    "port set: must be expanded by expand_port_sets before translation",
                ))
            }
            Match::DestNet(addr) => Self::match_net(rule, addr, false)?,
            Match::SourceNet(addr) => Self::match_net(rule, addr, true)?,
            Match::Icmp(family) => Self::icmp_protocol(rule, *family),
            Match::PacketMark(mark) => rule
                .with_expr(Meta::new(MetaType::Mark))
                .with_expr(Cmp::new(CmpOp::Eq, Self::packet_mark_bytes(*mark))),
            Match::Family(family) => Self::network_family(rule, *family),
        })
    }

    /// Applies a non-verdict statement to a rule under construction.
    pub(super) fn apply_action(rule: NfRule, action: &Action) -> Result<NfRule> {
        Ok(match action {
            Action::Counter(Counter::Anonymous) => rule.with_expr(NfCounter::default()),
            Action::Counter(Counter::Named(name)) => {
                return Err(Self::err(format!(
                    "named counter `{name}` is not supported by rustables 0.8.7"
                )))
            }
            Action::Log(log) => {
                rule.with_expr(NfLog::new(log.group, Some(log.prefix.clone())).map_err(Self::err)?)
            }
            Action::Limit(limit) => {
                return Err(Self::err(format!(
                    "rate limit {}/{:?} burst {} {:?} is not supported by rustables 0.8.7",
                    limit.rate, limit.unit, limit.burst, limit.mode
                )))
            }
        })
    }

    /// Encodes a packet mark as the native `u32` stored in the nftables meta
    /// register. Unlike IP addresses and ports, `meta mark` is not a network
    /// protocol field and must therefore not use network byte order.
    fn packet_mark_bytes(mark: u32) -> [u8; 4] {
        mark.to_ne_bytes()
    }

    fn icmp_protocol(rule: NfRule, family: AddressFamily) -> NfRule {
        let protocol = match family {
            AddressFamily::Ipv4 => IP_PROTOCOL_ICMP,
            AddressFamily::Ipv6 => IP_PROTOCOL_ICMPV6,
        };
        rule.with_expr(Meta::new(MetaType::L4Proto))
            .with_expr(Cmp::new(CmpOp::Eq, [protocol]))
    }

    /// A standalone `meta nfproto` guard.
    ///
    /// The same two expressions `rustables` emits ahead of an address in
    /// [`NfRule::match_ip`], without the address: the rule stays
    /// single-family in the `inet` table while naming no address.
    fn network_family(rule: NfRule, family: AddressFamily) -> NfRule {
        let nfproto = match family {
            AddressFamily::Ipv4 => NFPROTO_IPV4,
            AddressFamily::Ipv6 => NFPROTO_IPV6,
        };
        rule.with_expr(Meta::new(MetaType::NfProto))
            .with_expr(Cmp::new(CmpOp::Eq, [nfproto]))
    }

    /// A structured `ct state` match, built from the exact IR state set.
    ///
    /// [`NfRule::established`] would be the obvious call, and it is wrong
    /// here: it masks `ESTABLISHED` alone, so what got applied was `ct state
    /// established` while [`Match`] displayed — and the API served, and the
    /// console showed — `ct state established,related`. Exactly the
    /// display/applied divergence the `ruleset` module doc rules out, and the
    /// kind that survives review because both sides read correct on their
    /// own.
    ///
    /// What `related` covers is not decorative. It is how conntrack labels an
    /// ICMP error attached to a tracked flow, `destination unreachable —
    /// fragmentation needed` first among them. Dropping those under a
    /// fail-closed policy black-holes path-MTU discovery: connections open,
    /// then hang on the first full-size packet, and the tunnel gets blamed.
    ///
    /// The three expressions reproduce what `rustables` emits while deriving
    /// the mask from the structured state set — same layout and same
    /// little-endian mask convention.
    fn connection_states(rule: NfRule, states: ConnectionStates) -> Result<NfRule> {
        let mut mask = 0u32;
        for state in states.iter() {
            mask |= match state {
                ConnectionState::Invalid => ConnTrackState::INVALID.bits(),
                ConnectionState::Established => ConnTrackState::ESTABLISHED.bits(),
                ConnectionState::Related => ConnTrackState::RELATED.bits(),
                ConnectionState::New => ConnTrackState::NEW.bits(),
                ConnectionState::Untracked => ConnTrackState::UNTRACKED.bits(),
            };
        }
        Ok(rule
            .with_expr(Conntrack::new(ConntrackKey::State))
            .with_expr(Bitwise::new(mask.to_le_bytes(), 0u32.to_be_bytes()).map_err(Self::err)?)
            // Non-zero after masking: the packet is in one of the requested states.
            .with_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes())))
    }

    /// Applies an already validated address match.
    fn match_net(rule: NfRule, network: &IpNetwork, source: bool) -> Result<NfRule> {
        let host_prefix = if network.is_ipv4() { 32 } else { 128 };
        if network.prefix() != host_prefix {
            let r = if source {
                rule.snetwork(*network)
            } else {
                rule.dnetwork(*network)
            };
            r.map_err(Self::err)
        } else {
            let ip = network.ip();
            Ok(if source {
                rule.saddr(ip)
            } else {
                rule.daddr(ip)
            })
        }
    }

    /// Expands a `DestPortSet` into a list of single-port match sets.
    /// The resulting filtering is identical.
    pub(super) fn expand_port_sets(matches: &[Match]) -> Vec<Vec<Match>> {
        let Some(idx) = matches
            .iter()
            .position(|m| matches!(m, Match::DestPortSet { .. }))
        else {
            return vec![matches.to_vec()];
        };
        let Match::DestPortSet { ports, proto } = &matches[idx] else {
            unreachable!()
        };

        ports
            .iter()
            .map(|port| {
                let mut copy = matches.to_vec();
                copy[idx] = Match::DestPort {
                    port: *port,
                    proto: *proto,
                };
                copy
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rustables::{expr::RawExpression, ProtocolFamily};

    use super::*;

    #[test]
    fn port_sets_are_expanded() {
        let matches = vec![
            Match::OutIface("eth0".into()),
            Match::DestPortSet {
                ports: vec![80, 443],
                proto: L4::Tcp,
            },
        ];
        let expanded = NetlinkBackend::expand_port_sets(&matches);
        assert_eq!(expanded.len(), 2);
        assert!(expanded[0].contains(&Match::DestPort {
            port: 80,
            proto: L4::Tcp
        }));
        assert!(expanded[1].contains(&Match::DestPort {
            port: 443,
            proto: L4::Tcp
        }));
        // The other matches are preserved in each produced rule.
        assert!(expanded[0].contains(&Match::OutIface("eth0".into())));
    }

    #[test]
    fn a_set_without_expansion_stays_intact() {
        let matches = vec![Match::InIface("lo".into())];
        assert_eq!(NetlinkBackend::expand_port_sets(&matches), vec![matches]);
    }

    /// `related` is how conntrack labels an ICMP error attached to a tracked
    /// flow — `fragmentation needed` above all. Matching `established` alone
    /// black-holes path-MTU discovery under a drop policy: connections open,
    /// then hang on the first full-size packet.
    ///
    /// Only the mask is checked here; that the kernel prints `ct state
    /// established,related` is target-only, see `docs/testing/TESTING.md`.
    #[test]
    fn the_conntrack_mask_carries_related_and_not_established_alone() {
        let established_or_related =
            ConnTrackState::ESTABLISHED.bits() | ConnTrackState::RELATED.bits();
        assert_eq!(
            established_or_related, 0b110,
            "the mask the kernel reads must carry both states"
        );
        assert_ne!(
            established_or_related,
            ConnTrackState::ESTABLISHED.bits(),
            "`NfRule::established` must not replace the structured state encoder"
        );
    }

    #[test]
    fn connection_state_masks_match_the_kernel_bits() {
        let mask = |states: ConnectionStates| {
            states.iter().fold(0u32, |mask, state| {
                mask | match state {
                    ConnectionState::Invalid => ConnTrackState::INVALID.bits(),
                    ConnectionState::Established => ConnTrackState::ESTABLISHED.bits(),
                    ConnectionState::Related => ConnTrackState::RELATED.bits(),
                    ConnectionState::New => ConnTrackState::NEW.bits(),
                    ConnectionState::Untracked => ConnTrackState::UNTRACKED.bits(),
                }
            })
        };

        assert_eq!(
            mask(ConnectionStates::INVALID),
            ConnTrackState::INVALID.bits()
        );
        assert_eq!(
            mask(ConnectionStates::ESTABLISHED_RELATED),
            ConnTrackState::ESTABLISHED.bits() | ConnTrackState::RELATED.bits()
        );
    }

    #[test]
    fn packet_mark_is_encoded_in_the_kernel_register_byte_order() {
        let mark = 0xe1f1;

        assert_eq!(
            u32::from_ne_bytes(NetlinkBackend::packet_mark_bytes(mark)),
            mark
        );
    }

    #[test]
    fn icmp_protocol_numbers_are_family_specific() {
        assert_eq!(IP_PROTOCOL_ICMP, 1);
        assert_eq!(IP_PROTOCOL_ICMPV6, 58);
        assert_ne!(IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMPV6);
    }

    /// `rustables` binds its protocol families to the kernel UAPI values:
    /// checking the constants against them pins what the kernel will read.
    #[test]
    fn nfproto_numbers_are_the_kernel_family_values() {
        assert_eq!(NFPROTO_IPV4, 2);
        assert_eq!(NFPROTO_IPV6, 10);
        assert_eq!(i32::from(NFPROTO_IPV4), ProtocolFamily::Ipv4 as i32);
        assert_eq!(i32::from(NFPROTO_IPV6), ProtocolFamily::Ipv6 as i32);
    }

    #[test]
    fn family_match_emits_the_nfproto_guard_rustables_uses() {
        let expressions = |family| {
            NetlinkBackend::apply_match(NfRule::default(), &Match::Family(family))
                .expect("a family match always translates")
                .get_expressions()
                .map(|list| list.iter().cloned().collect::<Vec<RawExpression>>())
                .unwrap_or_default()
        };

        assert_eq!(
            expressions(AddressFamily::Ipv4),
            [
                RawExpression::from(Meta::new(MetaType::NfProto)),
                RawExpression::from(Cmp::new(CmpOp::Eq, [2u8])),
            ]
        );
        assert_eq!(
            expressions(AddressFamily::Ipv6),
            [
                RawExpression::from(Meta::new(MetaType::NfProto)),
                RawExpression::from(Cmp::new(CmpOp::Eq, [10u8])),
            ]
        );
    }
}
