//! The nftables vocabulary and its textual rendering.
//!
//! The types a rendered policy is expressed in — chains, matches, verdicts,
//! rules — and the [`fmt::Display`] implementations that turn them into
//! nftables syntax for the dry-run backend and the API. Nothing here reads a
//! [`FirewallPolicy`]: compiling a policy into these types is the job of the
//! capability modules beside this one.
//!
//! [`FirewallPolicy`]: aether::FirewallPolicy

use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use ipnetwork::IpNetwork;

/// Network-layer family used by family-sensitive matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// ICMPv6 messages a typed match can select.
///
/// Only the messages Helios opens are listed: a type that is not here cannot
/// enter a [`Match`], so Redirect (137) — which no rule may accept — is not
/// representable at all, rather than merely absent from the renderer. Adding
/// a message is a deliberate change of this enum, reviewed as such.
///
/// ICMPv4 has no typed counterpart. Helios matches it by protocol only, see
/// [`Match::Icmp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    /// Multicast Listener Query (130, RFC 2710 / RFC 3810).
    MldListenerQuery,
    /// MLDv1 Multicast Listener Report (131, RFC 2710).
    MldListenerReport,
    /// Multicast Listener Done (132, RFC 2710).
    MldListenerDone,
    /// Router Solicitation (133, RFC 4861).
    RouterSolicit,
    /// Router Advertisement (134, RFC 4861).
    RouterAdvert,
    /// Neighbor Solicitation (135, RFC 4861).
    NeighborSolicit,
    /// Neighbor Advertisement (136, RFC 4861).
    NeighborAdvert,
    /// MLDv2 Multicast Listener Report (143, RFC 3810).
    Mld2ListenerReport,
}

impl Icmpv6Type {
    /// The value of the ICMPv6 `type` octet.
    pub const fn number(self) -> u8 {
        match self {
            Self::MldListenerQuery => 130,
            Self::MldListenerReport => 131,
            Self::MldListenerDone => 132,
            Self::RouterSolicit => 133,
            Self::RouterAdvert => 134,
            Self::NeighborSolicit => 135,
            Self::NeighborAdvert => 136,
            Self::Mld2ListenerReport => 143,
        }
    }

    /// The keyword `nft` uses for this type.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MldListenerQuery => "mld-listener-query",
            Self::MldListenerReport => "mld-listener-report",
            Self::MldListenerDone => "mld-listener-done",
            Self::RouterSolicit => "nd-router-solicit",
            Self::RouterAdvert => "nd-router-advert",
            Self::NeighborSolicit => "nd-neighbor-solicit",
            Self::NeighborAdvert => "nd-neighbor-advert",
            Self::Mld2ListenerReport => "mld2-listener-report",
        }
    }
}

/// Conntrack states understood by the Helios firewall IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Invalid,
    Established,
    Related,
    New,
    Untracked,
}

impl ConnectionState {
    const fn bit(self) -> u8 {
        match self {
            Self::Invalid => 1 << 0,
            Self::Established => 1 << 1,
            Self::Related => 1 << 2,
            Self::New => 1 << 3,
            Self::Untracked => 1 << 4,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Established => "established",
            Self::Related => "related",
            Self::New => "new",
            Self::Untracked => "untracked",
        }
    }
}

/// Non-empty set of conntrack states, with deterministic rendering order.
///
/// The bits are private so an unknown or empty state set cannot enter a
/// [`Match`]. Add a named constant when Helios needs another combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStates(u8);

impl ConnectionStates {
    pub const INVALID: Self = Self(ConnectionState::Invalid.bit());
    pub const ESTABLISHED_RELATED: Self =
        Self(ConnectionState::Established.bit() | ConnectionState::Related.bit());

    pub const fn contains(self, state: ConnectionState) -> bool {
        self.0 & state.bit() != 0
    }

    pub fn iter(self) -> impl Iterator<Item = ConnectionState> {
        [
            ConnectionState::Invalid,
            ConnectionState::Established,
            ConnectionState::Related,
            ConnectionState::New,
            ConnectionState::Untracked,
        ]
        .into_iter()
        .filter(move |state| self.contains(*state))
    }
}

/// Terminal verdict of a rule.
///
/// Closed on purpose: a rejection is a named variant, not a free-form
/// `reject` whose type and code a caller picks. Each variant is a decision
/// reviewed as such, like the messages of [`Icmpv6Type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    /// `reject with icmpx admin-prohibited`: the packet is dropped and its
    /// sender receives "administratively prohibited" — ICMPv6 type 1 code 1
    /// for an IPv6 packet, ICMP type 3 code 13 for an IPv4 one.
    ///
    /// It refuses exactly like [`Verdict::Drop`] and opens nothing; the only
    /// difference is that the sender learns it at once instead of waiting for
    /// its own timeout. Used for the tunnel clients' IPv6 Internet egress
    /// (SORTIE-IPV6 §3.1), so that a dual-stack application falls back to
    /// IPv4 immediately.
    RejectAdminProhibited,
}

impl Verdict {
    /// The nftables statement this verdict renders as.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
            Self::RejectAdminProhibited => "reject with icmpx admin-prohibited",
        }
    }
}

/// Default policy of the hooked chains.
///
/// Separate from [`Verdict`] because nftables only takes `accept` or `drop`
/// as a chain policy: a rejecting default is not representable, rather than
/// refused late by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultVerdict {
    Accept,
    Drop,
}

impl DefaultVerdict {
    /// The keyword `nft` uses for this chain policy.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
        }
    }
}

/// Packet/byte counter attached to a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counter {
    /// Counter state lives directly in the rule.
    Anonymous,
    /// Counter state lives in a separately named nftables object.
    ///
    /// The IR can preserve the operator-facing identity, but the current
    /// Netlink adapter rejects this variant because `rustables 0.8.8` cannot
    /// create or reference named counter objects.
    Named(String),
}

/// Kernel log statement, independent from the rule verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogAction {
    pub prefix: String,
    pub group: Option<u16>,
}

/// Time unit for a packet rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
}

impl RateUnit {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Second => "second",
            Self::Minute => "minute",
            Self::Hour => "hour",
        }
    }
}

/// Whether a rule matches packets inside or above the configured rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitMode {
    Until,
    Over,
}

/// Packet rate limit represented without zero-rate or zero-burst states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub rate: NonZeroU64,
    pub unit: RateUnit,
    pub burst: NonZeroU32,
    pub mode: RateLimitMode,
}

/// Non-verdict statements evaluated after the matches and before the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Counter(Counter),
    Log(LogAction),
    Limit(RateLimit),
}

/// Netfilter hooked chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// Traffic destined for the gateway itself.
    Input,
    /// Traffic passing through the gateway (LAN -> WAN).
    Forward,
    /// Traffic emitted by the gateway.
    Output,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainKind::Input => "input",
            ChainKind::Forward => "forward",
            ChainKind::Output => "output",
        }
    }
}

/// Transport protocol for a port match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
}

impl L4 {
    fn as_str(self) -> &'static str {
        match self {
            L4::Tcp => "tcp",
            L4::Udp => "udp",
        }
    }
}

/// A match criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// `ct state <states>`
    ConnectionState(ConnectionStates),
    /// `iifname "<iface>"`
    InIface(String),
    /// `oifname "<iface>"`
    OutIface(String),
    /// `<proto> dport <port>`
    DestPort { port: u16, proto: L4 },
    /// `<proto> sport <port>`
    SourcePort { port: u16, proto: L4 },
    /// `<proto> dport { a, b }` — set of ports.
    DestPortSet { ports: Vec<u16>, proto: L4 },
    /// `ip daddr <addr>` — IP or CIDR.
    DestNet(IpNetwork),
    /// `ip saddr <addr>` — IP or CIDR.
    SourceNet(IpNetwork),
    /// `meta l4proto icmp` or `meta l4proto ipv6-icmp`.
    ///
    /// # Known limitation: ICMPv4 type is not discriminated
    ///
    /// The match covers the protocol, not a narrower type such as
    /// `echo-request`. ICMPv6 has a typed match, [`Match::Icmpv6Type`],
    /// because the high-level `rustables` API exposes the ICMPv6 type octet;
    /// it has no ICMPv4 payload field for it. The ICMPv4 widening remains
    /// interface-scoped, so only peers already admitted by WireGuard can reach
    /// the tunnel rule. Typing ICMPv4 messages requires a checked
    /// payload-expression encoder for that family, which Helios does not have.
    Icmp(AddressFamily),
    /// `icmpv6 type <type>`.
    ///
    /// Selects ICMPv6 by `meta l4proto ipv6-icmp`, then compares the type
    /// octet. The network-layer family is not checked here: a rule that must
    /// be IPv6 at the network layer also carries [`Match::Ipv6HopLimit`] or
    /// [`Match::Family`].
    Icmpv6Type(Icmpv6Type),
    /// `ip6 hoplimit <value>`.
    ///
    /// A network-header field, so only meaningful on an IPv6 packet: the
    /// backend emits the `meta nfproto ipv6` guard ahead of the comparison,
    /// exactly as it does ahead of an `ip6 daddr`. Without it, the same offset
    /// of an IPv4 header is a fragment-offset octet. The guard belongs to the
    /// match, so an unguarded hop-limit comparison cannot be represented.
    Ipv6HopLimit(u8),
    /// Packet mark assigned by a privileged local networking service.
    PacketMark(u32),
    /// `meta nfproto ipv4` or `meta nfproto ipv6`.
    ///
    /// The table is `inet`: a rule that names no address applies to both
    /// families. Address matches already carry their own family guard, so
    /// this match is for rules that must stay single-family without naming an
    /// address — the tunnel clients' Internet egress first among them, which
    /// relays IPv4 only.
    Family(AddressFamily),
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Match::ConnectionState(states) => {
                let list = states
                    .iter()
                    .map(ConnectionState::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                write!(f, "ct state {list}")
            }
            Match::InIface(i) => write!(f, "iifname \"{i}\""),
            Match::OutIface(i) => write!(f, "oifname \"{i}\""),
            Match::DestPort { port, proto } => write!(f, "{} dport {port}", proto.as_str()),
            Match::SourcePort { port, proto } => {
                write!(f, "{} sport {port}", proto.as_str())
            }
            Match::DestPortSet { ports, proto } => {
                let list: Vec<String> = ports.iter().map(u16::to_string).collect();
                write!(f, "{} dport {{ {} }}", proto.as_str(), list.join(", "))
            }
            Match::DestNet(network) => write!(
                f,
                "{} daddr {network}",
                if network.is_ipv4() { "ip" } else { "ip6" }
            ),
            Match::SourceNet(network) => write!(
                f,
                "{} saddr {network}",
                if network.is_ipv4() { "ip" } else { "ip6" }
            ),
            Match::Icmp(AddressFamily::Ipv4) => write!(f, "meta l4proto icmp"),
            Match::Icmp(AddressFamily::Ipv6) => write!(f, "meta l4proto ipv6-icmp"),
            Match::Icmpv6Type(icmp_type) => write!(f, "icmpv6 type {}", icmp_type.as_str()),
            Match::Ipv6HopLimit(hop_limit) => write!(f, "ip6 hoplimit {hop_limit}"),
            Match::PacketMark(mark) => write!(f, "meta mark {mark:#x}"),
            Match::Family(AddressFamily::Ipv4) => write!(f, "meta nfproto ipv4"),
            Match::Family(AddressFamily::Ipv6) => write!(f, "meta nfproto ipv6"),
        }
    }
}

/// A rule: a chain, matches, a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: ChainKind,
    pub matches: Vec<Match>,
    pub actions: Vec<Action>,
    pub verdict: Verdict,
    /// Justification, for human reading. No effect on filtering.
    pub note: Option<String>,
}

impl Rule {
    pub(super) fn new(chain: ChainKind, matches: Vec<Match>, verdict: Verdict) -> Self {
        Self {
            chain,
            matches,
            actions: Vec::new(),
            verdict,
            note: None,
        }
    }

    pub(super) fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub(super) fn with_counter(mut self, counter: Counter) -> Self {
        self.actions.push(Action::Counter(counter));
        self
    }

    #[cfg(test)]
    pub(super) fn with_log(mut self, log: LogAction) -> Self {
        self.actions.push(Action::Log(log));
        self
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for m in &self.matches {
            write!(f, "{m} ")?;
        }
        for action in &self.actions {
            match action {
                Action::Counter(Counter::Anonymous) => write!(f, "counter ")?,
                Action::Counter(Counter::Named(name)) => write!(f, "counter name \"{name}\" ")?,
                Action::Log(LogAction { prefix, group }) => {
                    write!(f, "log prefix \"{prefix}\"")?;
                    if let Some(group) = group {
                        write!(f, " group {group}")?;
                    }
                    write!(f, " ")?;
                }
                Action::Limit(limit) => {
                    write!(f, "limit rate ")?;
                    if limit.mode == RateLimitMode::Over {
                        write!(f, "over ")?;
                    }
                    write!(
                        f,
                        "{}/{} burst {} packets ",
                        limit.rate,
                        limit.unit.as_str(),
                        limit.burst
                    )?;
                }
            }
        }
        write!(f, "{}", self.verdict.as_str())
    }
}

/// Complete ruleset of the `inet helios` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// Default policy of hooked chains (`Drop` = fail-closed).
    pub default_verdict: DefaultVerdict,
    pub rules: Vec<Rule>,
    /// Requested MSS clamping, if any.
    ///
    /// Deliberately **outside** of `rules`: it is a *mangle* action (TCP
    /// option rewrite), not a filtering verdict. See the dedicated Netlink
    /// chain, which runs before filtering and is scoped to `wg_iface`.
    ///
    /// The value is the IPv4 MSS of the tunnel (`aether::mtu::mss_ipv4`). In
    /// this `inet` table IPv4 and IPv6 SYNs use separate values; the latter is
    /// 20 bytes smaller and is omitted when the tunnel MTU is below 1280.
    pub mss_clamp: Option<u16>,
    /// Interface whose ingress and egress TCP SYN packets may be MSS-clamped.
    pub wg_iface: String,
    /// Egress interface on which to masquerade the source of client traffic.
    ///
    /// Outside of `rules` for the same reason as `mss_clamp`: it is not a
    /// filtering verdict but an address rewrite, which lives in a chain of a
    /// different type (`nat`) and a different hook (`postrouting`). The
    /// upstream `rustables` API already expresses masquerade directly; the
    /// small Helios extension handles TCP MSS writes.
    ///
    /// One entry per uplink: a gateway with a cable and a radio masquerades on
    /// whichever the kernel routes through, and neither entry matches a packet
    /// that leaves by the other.
    ///
    /// **Empty** outside of states where traffic is allowed — NAT must never
    /// survive the tunnel going down, otherwise the kill-switch would leak
    /// what it is supposed to hold back.
    ///
    /// Only the uplinks are stored here. The rules themselves, with their
    /// IPv4 guard, come from [`Ruleset::masquerade_rules`].
    pub masquerade_out: Vec<String>,
}

impl Ruleset {
    /// Rules of a given chain, in order.
    pub fn chain(&self, kind: ChainKind) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |r| r.chain == kind)
    }

    /// MSS values to apply on the WireGuard interface, by packet family.
    /// IPv6 requires an internal tunnel MTU of at least 1280 bytes, equivalent
    /// to an IPv4 MSS of at least 1240; its MSS is always 20 bytes smaller.
    pub fn mss_clamps(&self) -> impl Iterator<Item = (AddressFamily, u16)> {
        self.mss_clamp
            .filter(|_| !self.wg_iface.is_empty())
            .into_iter()
            .flat_map(|mss| {
                std::iter::once((AddressFamily::Ipv4, mss))
                    .chain((mss >= 1240).then(|| (AddressFamily::Ipv6, mss - 20)))
            })
    }

    /// The `postrouting` masquerade rules, one per entry of
    /// [`masquerade_out`](Self::masquerade_out), in the same order.
    ///
    /// The single place where a masquerade gets its matches: the Netlink
    /// backend translates exactly these, and the dry-run, the API and the
    /// golden snapshots display exactly these, so what is shown cannot drift
    /// from what is applied.
    pub fn masquerade_rules(&self) -> impl Iterator<Item = MasqueradeRule> + '_ {
        self.masquerade_out.iter().map(|out_iface| MasqueradeRule {
            matches: vec![
                Match::Family(MasqueradeRule::FAMILY),
                Match::OutIface(out_iface.clone()),
            ],
        })
    }
}

/// A source-NAT rule of the `postrouting` chain.
///
/// # Why the family is not a field of the ruleset
///
/// In an `inet` table a masquerade that names only an interface also
/// rewrites IPv6: the first IPv6 packet relayed to a WAN would be NAT66-ed,
/// a translation nobody decided. The masquerade therefore carries
/// `meta nfproto ipv4`. That guard is a fixed invariant — NAT44 exists
/// because tunnel addresses are non-routable CGNAT, and the tunnel clients'
/// IPv6 egress is rejected in `forward` (SORTIE-IPV6 §3.1), NAT66 being out
/// of scope — not a per-uplink choice, so
/// [`Ruleset::masquerade_out`] keeps listing uplinks only and this type adds
/// the guard. Its matches are private and only [`Ruleset::masquerade_rules`]
/// builds it: an unguarded or IPv6 masquerade cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeRule {
    matches: Vec<Match>,
}

impl MasqueradeRule {
    /// The only family the masquerade rewrites.
    pub const FAMILY: AddressFamily = AddressFamily::Ipv4;

    /// Matches evaluated before the `masquerade` statement, in order.
    pub fn matches(&self) -> &[Match] {
        &self.matches
    }
}

impl fmt::Display for MasqueradeRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for m in &self.matches {
            write!(f, "{m} ")?;
        }
        write!(f, "masquerade")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_render_in_evaluation_order_before_the_verdict() {
        let rule = Rule::new(
            ChainKind::Input,
            vec![Match::ConnectionState(ConnectionStates::INVALID)],
            Verdict::Drop,
        )
        .with_counter(Counter::Anonymous)
        .with_log(LogAction {
            prefix: "helios invalid: ".into(),
            group: Some(7),
        });

        assert_eq!(
            rule.to_string(),
            "ct state invalid counter log prefix \"helios invalid: \" group 7 drop"
        );
    }

    #[test]
    fn the_admin_prohibited_rejection_renders_the_icmpx_statement() {
        let rule = Rule::new(
            ChainKind::Forward,
            vec![
                Match::Family(AddressFamily::Ipv6),
                Match::InIface("helios0".into()),
                Match::OutIface("eth0".into()),
            ],
            Verdict::RejectAdminProhibited,
        );

        assert_eq!(
            rule.to_string(),
            "meta nfproto ipv6 iifname \"helios0\" oifname \"eth0\" \
             reject with icmpx admin-prohibited"
        );
    }

    #[test]
    fn named_counter_identity_is_preserved_by_the_ir_display() {
        let rule = Rule::new(ChainKind::Forward, Vec::new(), Verdict::Drop)
            .with_counter(Counter::Named("drop-kill-switch".into()));

        assert_eq!(rule.to_string(), "counter name \"drop-kill-switch\" drop");
    }

    #[test]
    fn rate_limits_render_all_security_relevant_parameters() {
        let rule = Rule {
            chain: ChainKind::Input,
            matches: Vec::new(),
            actions: vec![Action::Limit(RateLimit {
                rate: NonZeroU64::new(30).unwrap(),
                unit: RateUnit::Minute,
                burst: NonZeroU32::new(10).unwrap(),
                mode: RateLimitMode::Over,
            })],
            verdict: Verdict::Drop,
            note: None,
        };

        assert_eq!(
            rule.to_string(),
            "limit rate over 30/minute burst 10 packets drop"
        );
    }

    #[test]
    fn network_matches_render_their_typed_address_family() {
        let ipv4: IpNetwork = "192.0.2.1".parse().unwrap();
        let ipv6: IpNetwork = "2001:db8::/32".parse().unwrap();

        assert_eq!(Match::SourceNet(ipv4).to_string(), "ip saddr 192.0.2.1/32");
        assert_eq!(Match::DestNet(ipv6).to_string(), "ip6 daddr 2001:db8::/32");
    }

    #[test]
    fn family_matches_render_the_nfproto_guard() {
        assert_eq!(
            Match::Family(AddressFamily::Ipv4).to_string(),
            "meta nfproto ipv4"
        );
        assert_eq!(
            Match::Family(AddressFamily::Ipv6).to_string(),
            "meta nfproto ipv6"
        );
    }

    #[test]
    fn icmpv6_type_matches_render_the_nft_keyword_of_their_number() {
        let expected = [
            (Icmpv6Type::MldListenerQuery, 130, "mld-listener-query"),
            (Icmpv6Type::MldListenerReport, 131, "mld-listener-report"),
            (Icmpv6Type::MldListenerDone, 132, "mld-listener-done"),
            (Icmpv6Type::RouterSolicit, 133, "nd-router-solicit"),
            (Icmpv6Type::RouterAdvert, 134, "nd-router-advert"),
            (Icmpv6Type::NeighborSolicit, 135, "nd-neighbor-solicit"),
            (Icmpv6Type::NeighborAdvert, 136, "nd-neighbor-advert"),
            (Icmpv6Type::Mld2ListenerReport, 143, "mld2-listener-report"),
        ];
        for (icmp_type, number, keyword) in expected {
            assert_eq!(icmp_type.number(), number, "{keyword}");
            assert_eq!(
                Match::Icmpv6Type(icmp_type).to_string(),
                format!("icmpv6 type {keyword}")
            );
        }
    }

    #[test]
    fn hop_limit_matches_render_the_ip6_field() {
        assert_eq!(Match::Ipv6HopLimit(255).to_string(), "ip6 hoplimit 255");
    }

    #[test]
    fn masquerade_rules_carry_the_ipv4_guard_before_the_uplink() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
            rules: Vec::new(),
            mss_clamp: None,
            wg_iface: "helios0".into(),
            masquerade_out: vec!["enp3s0".into(), "wlo1".into()],
        };

        let rendered: Vec<String> = ruleset
            .masquerade_rules()
            .map(|rule| rule.to_string())
            .collect();
        assert_eq!(
            rendered,
            [
                "meta nfproto ipv4 oifname \"enp3s0\" masquerade",
                "meta nfproto ipv4 oifname \"wlo1\" masquerade",
            ]
        );
    }

    #[test]
    fn mss_clamp_values_follow_family_threshold_and_require_tunnel_interface() {
        for mss in [0, 19, 20, 1239] {
            let ruleset = Ruleset {
                default_verdict: DefaultVerdict::Drop,
                rules: Vec::new(),
                mss_clamp: Some(mss),
                wg_iface: "helios0".into(),
                masquerade_out: Vec::new(),
            };
            assert_eq!(
                ruleset.mss_clamps().collect::<Vec<_>>(),
                [(AddressFamily::Ipv4, mss)]
            );
        }
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
            rules: Vec::new(),
            mss_clamp: Some(1240),
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };
        assert_eq!(
            ruleset.mss_clamps().collect::<Vec<_>>(),
            [(AddressFamily::Ipv4, 1240), (AddressFamily::Ipv6, 1220),]
        );

        let mut unscoped = ruleset;
        unscoped.wg_iface.clear();
        assert!(unscoped.mss_clamps().next().is_none());
    }
}
