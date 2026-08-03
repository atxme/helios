//! Rendering of a policy + a state into a **structured** ruleset.
//!
//! The ruleset is a data structure, not text: it is what the Netlink backend
//! translates into expressions, and from which [`crate::DryRunBackend`] and the
//! API derive human-readable nftables syntax via [`Display`]. The reverse —
//! producing text then re-parsing it — would be fragile and would silently
//! let the display diverge from what is actually applied.
//!
//! Each rule carries the **hooked chain** it belongs to: traffic destined for
//! the gateway itself (WireGuard listener, API, SSH) goes into `input`, LAN
//! traffic passing through it into `forward`, and traffic it emits into
//! `output`. Confusing them would let through — or block — the wrong traffic.
//!
//! # Internet egress for tunnel clients
//!
//! Two forms coexist, and they do not open the same paths:
//!
//! * **site-to-site**, always active: `forward` from `lan_ifaces` to
//!   `wan_iface`, for hosts located *behind* the gateway;
//! * **road-warrior**, behind `allow_client_internet`: `forward` from
//!   `wg_iface` to `wan_iface`, plus a masquerade in `postrouting`, for a
//!   client arriving *through* the tunnel.
//!
//! The second is closed by default. A gateway granting access to internal
//! resources has no reason to route Internet traffic, and opening it would
//! widen its surface with no benefit. Both only hold in a state where traffic
//! is allowed: NAT is applied and removed together with the tunnel, otherwise
//! the kill-switch would let out in the clear what it just cut off.
//!
//! # Known limitation: DNS is not tunneled
//!
//! Even with `allow_client_internet` active, the client keeps its own
//! resolver: its DNS queries leave outside the tunnel and reveal the names it
//! looks up, while the rest of its traffic is protected. What would unblock
//! this: a resolver field in the `orion-profile` document — which
//! `orion-core` currently rejects, including the `DNS` key of a `wg-quick`
//! file — and the choice of a resolver reachable inside the tunnel. See
//! ADR-004 batch 5.

use std::fmt;

use aether::{FirewallPolicy, TunnelState};

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
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Match::Established => write!(f, "ct state established,related"),
            Match::InIface(i) => write!(f, "iifname \"{i}\""),
            Match::OutIface(i) => write!(f, "oifname \"{i}\""),
            Match::DestPort { port, proto } => write!(f, "{} dport {port}", proto.as_str()),
            Match::DestPortSet { ports, proto } => {
                let list: Vec<String> = ports.iter().map(u16::to_string).collect();
                write!(f, "{} dport {{ {} }}", proto.as_str(), list.join(", "))
            }
            Match::DestNet(a) => write!(f, "ip daddr {a}"),
            Match::SourceNet(a) => write!(f, "ip saddr {a}"),
            Match::Icmp => write!(f, "meta l4proto icmp"),
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
    fn new(chain: ChainKind, matches: Vec<Match>, verdict: Verdict) -> Self {
        Self {
            chain,
            matches,
            verdict,
            note: None,
        }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
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
    /// `None` outside of states where traffic is allowed — NAT must never
    /// survive the tunnel going down, otherwise the kill-switch would leak
    /// what it is supposed to hold back.
    pub masquerade_out: Option<String>,
}

impl Ruleset {
    /// Rules of a given chain, in order.
    pub fn chain(&self, kind: ChainKind) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |r| r.chain == kind)
    }
}

/// Builds the ruleset for `(policy, state)`.
///
/// Invariants, regardless of state:
/// * loopback and established/related traffic always accepted;
/// * the WireGuard listening port stays reachable, without which no client
///   could (re)establish the tunnel;
/// * LAN -> WAN forwarding is only open in the `Up` state.
pub fn render(policy: &FirewallPolicy, state: TunnelState) -> Ruleset {
    use ChainKind::{Forward, Input, Output};
    let mut rules = Vec::new();
    let wan = policy.wan_iface.clone();

    // ── Administration: the API must only be reachable through the tunnel ──
    // At the head of the chain, even before loopback.
    if let (Some(port), Some(iface)) = (policy.admin_port, policy.admin_iface.as_deref()) {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::DestPort {
                        port,
                        proto: L4::Tcp,
                    },
                    Match::InIface(iface.to_string()),
                ],
                Verdict::Accept,
            )
            .with_note("administration API: only via the tunnel interface"),
        );
        rules.push(
            Rule::new(
                Input,
                vec![Match::DestPort {
                    port,
                    proto: L4::Tcp,
                }],
                Verdict::Drop,
            )
            .with_note(
                "any other origin is refused. No `ct state new`: the drop also covers \
                 connections already established from another interface — stricter, \
                 and expressible in Netlink",
            ),
        );
    }

    // ── Always allowed ───────────────────────────────────────────────────────
    for chain in [Input, Forward, Output] {
        // Loopback is designated by the *ingress* interface in input and
        // forward, but by the *egress* interface in output: a locally
        // generated packet has no ingress interface. An `iifname "lo"` on the
        // output hook therefore never matches, and all local traffic falls
        // under the `drop` policy — including the gateway's API on
        // 127.0.0.1. Observed on target.
        let loopback = if chain == Output {
            Match::OutIface("lo".into())
        } else {
            Match::InIface("lo".into())
        };
        rules.push(Rule::new(chain, vec![loopback], Verdict::Accept));
        rules.push(Rule::new(chain, vec![Match::Established], Verdict::Accept));
    }

    // ── WireGuard listener (server role) ─────────────────────────────────────
    // Road-warrior clients arrive from unknown, changing IPs: impossible to
    // scope by source. This is the sole inbound opening of the fail-closed
    // model, and it is indispensable for the handshake.
    if let Some(port) = policy.wg_listen_port {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::InIface(wan.clone()),
                    Match::DestPort {
                        port,
                        proto: L4::Udp,
                    },
                ],
                Verdict::Accept,
            )
            .with_note("WireGuard listener — without this rule, no client can handshake"),
        );
    }

    // ── Key-negotiation listener ─────────────────────────────────────────────
    // This public QUIC endpoint authenticates peers before the first
    // WireGuard handshake. It is opened only when the configured service is
    // ready; the administration API remains restricted to the tunnel.
    if let Some(port) = policy.key_negotiation_port {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::InIface(wan.clone()),
                    Match::DestPort {
                        port,
                        proto: L4::Udp,
                    },
                ],
                Verdict::Accept,
            )
            .with_note("authenticated key-negotiation QUIC listener"),
        );
    }

    // ── Outbound WireGuard transport to static peers (site-to-site) ─────────
    // Scoped by destination: opening 51820 outbound without restricting the
    // destination would be a leak.
    for peer in &policy.wg_peers {
        rules.push(Rule::new(
            Output,
            vec![
                Match::OutIface(wan.clone()),
                Match::DestNet(peer.clone()),
                Match::DestPort {
                    port: 51820,
                    proto: L4::Udp,
                },
            ],
            Verdict::Accept,
        ));
    }

    // ── DHCP lease renewal on the WAN ────────────────────────────────────────
    // Scoped to the WAN interface and to the protocol's two ports. Traffic is
    // local to the link: the client sends to 67, the server replies to 68.
    // The reply is not left to `ct state established` — a DHCPDISCOVER goes
    // out as a broadcast and the reply does not always attach to a tracked
    // flow.
    if policy.allow_dhcp_on_wan {
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
    }

    // ── ICMP and SSH on the tunnel interface ─────────────────────────────────
    //
    // Both are scoped by **interface**, never by source address, and that is
    // the whole security argument: only WireGuard puts packets on `wg_iface`,
    // and it only does so for a peer whose key it has already authenticated.
    // A source-address match would be satisfiable from the WAN by forging the
    // address — which is exactly the trap of listing the CGNAT range in
    // `allow_ssh_from`.
    if !policy.wg_iface.is_empty() {
        if policy.allow_tunnel_icmp {
            rules.push(
                Rule::new(
                    Input,
                    vec![Match::InIface(policy.wg_iface.clone()), Match::Icmp],
                    Verdict::Accept,
                )
                .with_note(
                    "ICMP on the tunnel: `ping` is the first test anyone runs, and under a \
                     drop policy it fails identically whether the tunnel works or not",
                ),
            );
        }
        if policy.allow_ssh_over_tunnel {
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        Match::InIface(policy.wg_iface.clone()),
                        Match::DestPort {
                            port: 22,
                            proto: L4::Tcp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("administrative SSH arriving through the tunnel"),
            );
        }
    }

    // ── Administrative SSH, regardless of tunnel state ───────────────────────
    for src in &policy.allow_ssh_from {
        rules.push(Rule::new(
            Input,
            vec![
                Match::SourceNet(src.clone()),
                Match::DestPort {
                    port: 22,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        ));
    }

    if state.captive_portal_active() {
        // Captive portal: the kill-switch is lifted for HTTP/HTTPS only.
        let ports = Match::DestPortSet {
            ports: vec![80, 443],
            proto: L4::Tcp,
        };
        match &policy.captive_portal_gateway {
            Some(gw) => {
                for chain in [Output, Forward] {
                    rules.push(
                        Rule::new(
                            chain,
                            vec![
                                Match::OutIface(wan.clone()),
                                Match::DestNet(gw.clone()),
                                ports.clone(),
                            ],
                            Verdict::Accept,
                        )
                        .with_note(format!("captive portal: HTTP/HTTPS to {gw}")),
                    );
                }
            }
            None => {
                // Unknown gateway: let the browser reach the portal's landing
                // page, whatever its destination.
                for chain in [Output, Forward] {
                    rules.push(
                        Rule::new(
                            chain,
                            vec![Match::OutIface(wan.clone()), ports.clone()],
                            Verdict::Accept,
                        )
                        .with_note("captive portal: unknown gateway"),
                    );
                }
            }
        }
    } else if state.traffic_allowed() {
        // Split-tunneling: local CIDRs bypass the tunnel.
        for cidr in &policy.split_tunnel_cidrs {
            rules.push(Rule::new(
                Forward,
                vec![Match::DestNet(cidr.clone())],
                Verdict::Accept,
            ));
        }

        // Tunnel operational: forward the LAN. WireGuard encrypts on egress;
        // a packet not captured by the tunnel interface will not go out.
        for lan in &policy.lan_ifaces {
            rules.push(Rule::new(
                Forward,
                vec![Match::InIface(lan.clone()), Match::OutIface(wan.clone())],
                Verdict::Accept,
            ));
        }

        // Internet egress for tunnel clients. The return path is covered by
        // the forward chain's `ct state established,related` rule: opening
        // the outbound direction is enough, and scoping to the client -> WAN
        // direction only avoids exposing the gateway's LAN to clients.
        if policy.allow_client_internet && !policy.wg_iface.is_empty() {
            rules.push(
                Rule::new(
                    Forward,
                    vec![
                        Match::InIface(policy.wg_iface.clone()),
                        Match::OutIface(wan.clone()),
                    ],
                    Verdict::Accept,
                )
                .with_note("Internet egress for tunnel clients (masquerade in postrouting)"),
            );
        }
    }

    // In fail-open, the default policy becomes accept outside the tunnel (not recommended).
    let default_verdict = if policy.is_fail_closed() || state.traffic_allowed() {
        Verdict::Drop
    } else {
        Verdict::Accept
    };

    Ruleset {
        default_verdict,
        rules,
        mss_clamp: state
            .traffic_allowed()
            .then_some(policy.mss_clamp)
            .flatten(),
        // NAT follows the tunnel state exactly: applied with it, removed with
        // it. A masquerade that survived the tunnel going down would let out
        // in the clear what the kill-switch just cut off.
        masquerade_out: (state.traffic_allowed()
            && policy.allow_client_internet
            && !policy.wg_iface.is_empty()
            && !wan.is_empty())
        .then(|| wan.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::PolicyMode;

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_iface: "eth0".into(),
            lan_ifaces: vec!["eth1".into()],
            wg_peers: vec!["203.0.113.10".into()],
            wg_listen_port: Some(51820),
            key_negotiation_port: Some(51821),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            allow_dhcp_on_wan: false,
            allow_client_internet: false,
            allow_tunnel_icmp: false,
            allow_ssh_over_tunnel: false,
            wg_iface: "helios0".into(),
            admin_port: None,
            admin_iface: None,
            split_tunnel_cidrs: vec![],
            mss_clamp: None,
            captive_portal_gateway: None,
        }
    }

    /// Textual rendering of a chain, for readable assertions.
    fn text(rs: &Ruleset, kind: ChainKind) -> Vec<String> {
        rs.chain(kind).map(|r| r.to_string()).collect()
    }

    #[test]
    fn down_blocks_lan_forward() {
        let rs = render(&policy(), TunnelState::Down);
        assert_eq!(rs.default_verdict, Verdict::Drop);
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\"")));
    }

    /// Without this rule, no road-warrior client can handshake: fail-closed
    /// drops inbound packets. This is the condition for access.
    #[test]
    fn listen_port_is_open_inbound() {
        for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            let rs = render(&policy(), st);
            assert!(
                text(&rs, ChainKind::Input)
                    .iter()
                    .any(|r| r == "iifname \"eth0\" udp dport 51820 accept"),
                "state {st:?}: the WireGuard listening port must stay reachable"
            );
        }
    }

    /// The default stays closed: a gateway normally has a fixed address, and
    /// opening DHCP without reason would widen fail-closed for nothing.
    #[test]
    fn dhcp_is_closed_by_default() {
        let rs = render(&policy(), TunnelState::Down);
        for kind in [ChainKind::Input, ChainKind::Output] {
            assert!(
                !text(&rs, kind)
                    .iter()
                    .any(|r| r.contains("dport 67") || r.contains("dport 68")),
                "DHCP open without the configuration requesting it"
            );
        }
    }

    /// Without these two rules, a gateway addressed by lease loses its
    /// address on the first renewal — hence its tunnel and its
    /// administration — several hours after a startup that seemed
    /// successful.
    #[test]
    fn allowed_dhcp_stays_scoped_to_wan() {
        let mut p = policy();
        p.allow_dhcp_on_wan = true;

        for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            let rs = render(&p, st);
            assert!(
                text(&rs, ChainKind::Output)
                    .iter()
                    .any(|r| r.starts_with("oifname \"eth0\" udp dport 67 accept")),
                "state {st:?}: the renewal request must be able to go out"
            );
            assert!(
                text(&rs, ChainKind::Input)
                    .iter()
                    .any(|r| r.starts_with("iifname \"eth0\" udp dport 68 accept")),
                "state {st:?}: the server's reply must be able to come in"
            );
            // The opening must only exist on the WAN: on the LAN it would let
            // a client speak DHCP through the gateway.
            assert!(
                !text(&rs, ChainKind::Forward)
                    .iter()
                    .any(|r| r.contains("dport 67") || r.contains("dport 68")),
                "state {st:?}: DHCP must not traverse the gateway"
            );
        }
    }

    /// Closed by default: a gateway granting access to internal resources has
    /// no reason to route Internet traffic.
    #[test]
    fn client_internet_egress_is_closed_by_default() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(
            rs.masquerade_out.is_none(),
            "NAT applied without requesting it"
        );
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"helios0\"")));
    }

    /// NAT and forward must appear **and disappear** together with the
    /// tunnel. A masquerade that survived the tunnel going down would let out
    /// in the clear what the kill-switch just cut off.
    #[test]
    fn client_internet_egress_follows_tunnel_state_exactly() {
        let mut p = policy();
        p.allow_client_internet = true;

        let up = render(&p, TunnelState::Up);
        assert_eq!(up.masquerade_out.as_deref(), Some("eth0"));
        assert!(
            text(&up, ChainKind::Forward)
                .iter()
                .any(|r| r == "iifname \"helios0\" oifname \"eth0\" accept"),
            "client forward rule missing in the Up state: {:?}",
            text(&up, ChainKind::Forward)
        );

        for st in [
            TunnelState::Down,
            TunnelState::Connecting,
            TunnelState::Failed,
        ] {
            let rs = render(&p, st);
            assert!(
                rs.masquerade_out.is_none(),
                "state {st:?}: NAT must not exist outside the tunnel"
            );
            assert!(
                !text(&rs, ChainKind::Forward)
                    .iter()
                    .any(|r| r.contains("iifname \"helios0\"")),
                "state {st:?}: client traffic must not traverse"
            );
        }
    }

    /// The opening is unidirectional: the client goes out, but nothing comes
    /// in towards the gateway's LAN. The return path is covered by
    /// `established`.
    #[test]
    fn client_internet_egress_does_not_open_lan_to_clients() {
        let mut p = policy();
        p.allow_client_internet = true;
        let rs = render(&p, TunnelState::Up);

        assert!(
            !text(&rs, ChainKind::Forward)
                .iter()
                .any(|r| r.starts_with("iifname \"helios0\" oifname \"eth1\"")),
            "a client must not reach the gateway's LAN"
        );
    }

    #[test]
    fn no_inbound_opening_without_server_role() {
        let mut p = policy();
        p.wg_listen_port = None;
        let rs = render(&p, TunnelState::Down);
        assert!(!text(&rs, ChainKind::Input)
            .iter()
            .any(|r| r.contains("udp dport 51820")));
    }

    /// The WireGuard listener is in `input` (traffic towards the gateway),
    /// LAN forward in `forward`. Confusing them would block or open the
    /// wrong traffic.
    #[test]
    fn loopback_is_accepted_according_to_chain_direction() {
        // Regression test: `iif "lo"` used to be applied on all three
        // chains. On the output hook, a locally generated packet has no
        // ingress interface: the rule never matched and all outbound
        // loopback traffic fell under `policy drop`. Symptom observed on
        // target — any connection to 127.0.0.1 stayed hung, without being
        // refused.
        let rs = render(&policy(), TunnelState::Down);

        assert!(
            rs.chain(ChainKind::Output)
                .any(|r| r.matches == vec![Match::OutIface("lo".into())]
                    && r.verdict == Verdict::Accept),
            "the output chain must accept loopback via its egress interface"
        );

        for kind in [ChainKind::Input, ChainKind::Forward] {
            assert!(
                rs.chain(kind)
                    .any(|r| r.matches == vec![Match::InIface("lo".into())]
                        && r.verdict == Verdict::Accept),
                "{kind:?} must accept loopback via its ingress interface"
            );
        }
    }

    /// Both tunnel openings exist only when asked, and only on the tunnel.
    ///
    /// The interface scope is the whole security argument. A source-address
    /// match — listing `100.64.0.0/10` in `allow_ssh_from`, the obvious
    /// shortcut — would be satisfiable from the WAN by a packet forging that
    /// source, because those rules carry no interface constraint. Only
    /// WireGuard puts packets on `wg_iface`, and only for an authenticated
    /// peer.
    #[test]
    fn tunnel_icmp_and_ssh_are_opt_in_and_scoped_to_the_tunnel_interface() {
        let closed = render(&policy(), TunnelState::Up);
        for forbidden in ["meta l4proto icmp", "tcp dport 22"] {
            assert!(
                !text(&closed, ChainKind::Input)
                    .iter()
                    .any(|r| r.contains(forbidden)),
                "`{forbidden}` must not appear while the flag is off"
            );
        }

        let mut open = policy();
        open.allow_tunnel_icmp = true;
        open.allow_ssh_over_tunnel = true;
        let rs = render(&open, TunnelState::Up);
        let input = text(&rs, ChainKind::Input);
        assert!(input
            .iter()
            .any(|r| r == "iifname \"helios0\" meta l4proto icmp accept"));
        assert!(input
            .iter()
            .any(|r| r == "iifname \"helios0\" tcp dport 22 accept"));

        // Neither may ever be rendered without its interface match, whatever
        // the state: that rule alone is what keeps them off the WAN.
        for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            for rule in render(&open, state).chain(ChainKind::Input) {
                let touches_tunnel_opening = rule.matches.contains(&Match::Icmp)
                    || rule.matches.contains(&Match::DestPort {
                        port: 22,
                        proto: L4::Tcp,
                    });
                if touches_tunnel_opening && rule.verdict == Verdict::Accept {
                    assert!(
                        rule.matches.contains(&Match::InIface("helios0".into())),
                        "{state:?}: `{rule}` opens without being scoped to the tunnel"
                    );
                }
            }
        }
    }

    /// A gateway that cannot bring up its interface must open neither.
    ///
    /// Same gate as the listener ports: a rule naming an interface that does
    /// not exist is at best dead weight, and at worst a rule that starts
    /// matching the day something else claims that name.
    #[test]
    fn the_tunnel_openings_need_a_wireguard_interface() {
        let mut p = policy();
        p.allow_tunnel_icmp = true;
        p.allow_ssh_over_tunnel = true;
        p.wg_iface = String::new();
        let rs = render(&p, TunnelState::Up);
        for forbidden in ["meta l4proto icmp", "tcp dport 22"] {
            assert!(
                !text(&rs, ChainKind::Input)
                    .iter()
                    .any(|r| r.contains(forbidden)),
                "`{forbidden}` must not be rendered without a tunnel interface"
            );
        }
    }

    #[test]
    fn rules_are_in_the_right_chain() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(text(&rs, ChainKind::Input)
            .iter()
            .any(|r| r.contains("udp dport 51820")));
        assert!(text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\" oifname \"eth0\"")));
        // Outbound transport to a static peer is in `output`.
        assert!(text(&rs, ChainKind::Output)
            .iter()
            .any(|r| r.contains("ip daddr 203.0.113.10")));
    }

    #[test]
    fn up_allows_lan_forward() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r == "iifname \"eth1\" oifname \"eth0\" accept"));
    }

    #[test]
    fn fail_closed_default_is_always_drop() {
        for st in [
            TunnelState::Down,
            TunnelState::Failed,
            TunnelState::Connecting,
        ] {
            assert_eq!(render(&policy(), st).default_verdict, Verdict::Drop);
        }
    }

    #[test]
    fn admin_api_restricted_to_tunnel_interface() {
        let mut p = policy();
        p.admin_port = Some(8080);
        p.admin_iface = Some("helios0".into());
        let rs = render(&p, TunnelState::Up);
        let input = text(&rs, ChainKind::Input);

        // The scoped accept must precede the generic drop.
        let accept = input.iter().position(|r| r.contains("helios0")).unwrap();
        let drop = input
            .iter()
            .position(|r| r == "tcp dport 8080 drop")
            .unwrap();
        assert!(
            accept < drop,
            "the scoped accept must take precedence over the drop"
        );
    }

    #[test]
    fn captive_portal_allows_http_to_gateway() {
        let mut p = policy();
        p.captive_portal_gateway = Some("192.168.1.1".into());
        let rs = render(&p, TunnelState::CaptivePortal);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.to_string().contains("192.168.1.1") && r.to_string().contains("dport")));
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|r| r.contains("iifname \"eth1\" oifname")));
        assert_eq!(rs.default_verdict, Verdict::Drop);
    }

    #[test]
    fn captive_portal_without_gateway_allows_all_http() {
        let rs = render(&policy(), TunnelState::CaptivePortal);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.to_string().contains("tcp dport { 80, 443 } accept")));
    }

    #[test]
    fn split_tunnel_adds_bypass_rules() {
        let mut p = policy();
        p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
        let rs = render(&p, TunnelState::Up);
        let fwd = text(&rs, ChainKind::Forward);
        assert!(fwd.iter().any(|r| r == "ip daddr 192.168.1.0/24 accept"));
        assert!(fwd.iter().any(|r| r == "ip daddr 10.0.0.0/8 accept"));
        assert!(fwd.iter().any(|r| r.contains("iifname \"eth1\"")));
    }

    /// MSS clamping is a mangle action, not a verdict: it lives outside of
    /// `rules` and is only retained while the tunnel is operational.
    #[test]
    fn mss_clamping_outside_rules_and_only_when_up() {
        let mut p = policy();
        p.mss_clamp = Some(1380);
        assert_eq!(render(&p, TunnelState::Up).mss_clamp, Some(1380));
        assert_eq!(render(&p, TunnelState::Down).mss_clamp, None);
    }
}
