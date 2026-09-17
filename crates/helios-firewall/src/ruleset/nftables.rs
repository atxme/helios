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

/// Network-layer family used by family-sensitive matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
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

/// Verdict of a rule or default policy of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
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
    DestNet(String),
    /// `ip saddr <addr>` — IP or CIDR.
    SourceNet(String),
    /// `meta l4proto icmp` or `meta l4proto ipv6-icmp`.
    ///
    /// # Known limitation: ICMP type is not discriminated
    ///
    /// The match covers the protocol, not a narrower type such as
    /// `echo-request`. The high-level `rustables` API has no ICMPv4 payload
    /// field for the type octet. The widening remains interface-scoped, so
    /// only peers already admitted by WireGuard can reach the tunnel rule.
    /// Supporting typed ICMP messages requires a checked payload-expression
    /// encoder for both families.
    Icmp(AddressFamily),
    /// Packet mark assigned by a privileged local networking service.
    PacketMark(u32),
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
            Match::DestNet(a) => write!(f, "ip daddr {a}"),
            Match::SourceNet(a) => write!(f, "ip saddr {a}"),
            Match::Icmp(AddressFamily::Ipv4) => write!(f, "meta l4proto icmp"),
            Match::Icmp(AddressFamily::Ipv6) => write!(f, "meta l4proto ipv6-icmp"),
            Match::PacketMark(mark) => write!(f, "meta mark {mark:#x}"),
        }
    }
}

/// A rule: a chain, matches, a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: ChainKind,
    pub matches: Vec<Match>,
    pub verdict: Verdict,
    /// Justification, for human reading. No effect on filtering.
    pub note: Option<String>,
}

impl Rule {
    pub(super) fn new(chain: ChainKind, matches: Vec<Match>, verdict: Verdict) -> Self {
        Self {
            chain,
            matches,
            verdict,
            note: None,
        }
    }

    pub(super) fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for m in &self.matches {
            write!(f, "{m} ")?;
        }
        match self.verdict {
            Verdict::Accept => write!(f, "accept"),
            Verdict::Drop => write!(f, "drop"),
        }
    }
}

/// Complete ruleset of the `inet helios` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// Default policy of hooked chains (`Drop` = fail-closed).
    pub default_verdict: Verdict,
    pub rules: Vec<Rule>,
    /// Requested MSS clamping, if any.
    ///
    /// Deliberately **outside** of `rules`: it is a *mangle* action (TCP
    /// option rewrite), not a filtering verdict, and `rustables`' high-level
    /// API does not express it. See the Netlink backend.
    pub mss_clamp: Option<u16>,
    /// Egress interface on which to masquerade the source of client traffic.
    ///
    /// Outside of `rules` for the same reason as `mss_clamp`: it is not a
    /// filtering verdict but an address rewrite, which lives in a chain of a
    /// different type (`nat`) and a different hook (`postrouting`). Unlike
    /// MSS clamping, `rustables` can express it: the Netlink backend actually
    /// applies it.
    ///
    /// One entry per uplink: a gateway with a cable and a radio masquerades on
    /// whichever the kernel routes through, and neither entry matches a packet
    /// that leaves by the other.
    ///
    /// **Empty** outside of states where traffic is allowed — NAT must never
    /// survive the tunnel going down, otherwise the kill-switch would leak
    /// what it is supposed to hold back.
    pub masquerade_out: Vec<String>,
}

impl Ruleset {
    /// Rules of a given chain, in order.
    pub fn chain(&self, kind: ChainKind) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |r| r.chain == kind)
    }
}
