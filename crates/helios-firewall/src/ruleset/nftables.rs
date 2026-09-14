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
    /// `ct state established,related`
    Established,
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
    /// `meta l4proto icmp`
    ///
    /// # Limite connue : le type ICMP n'est pas discriminé
    ///
    /// La règle porte sur le protocole, pas sur `icmp type echo-request` :
    /// l'API haut niveau de `rustables` expose `Rule::icmp()` et aucun moyen
    /// de comparer l'octet de type sans écrire l'expression `payload` à la
    /// main — même nature de limite que le MSS clamping documenté en tête de
    /// `netlink`. Ce que ça élargit reste borné : la règle n'est posée que
    /// sur l'interface du tunnel, donc seuls des pairs déjà admis par
    /// WireGuard l'atteignent, et les erreurs ICMP utiles étaient déjà
    /// acceptées par `ct state established,related`. Ce qui la débloquerait :
    /// une expression `payload` brute, ou un `rustables` qui expose le type.
    Icmp,
    /// Packet mark assigned by a privileged local networking service.
    PacketMark(u32),
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Match::Established => write!(f, "ct state established,related"),
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
            Match::Icmp => write!(f, "meta l4proto icmp"),
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
