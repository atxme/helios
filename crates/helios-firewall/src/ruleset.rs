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
//! # The gateway's own egress
//!
//! Neither of the two forms above covers the gateway's *own* traffic, and the
//! `output` chain is the one nobody reads: under the fail-closed policy it
//! accepts loopback, `established` flows, DHCP renewal and the site-to-site
//! WireGuard transport, then drops the rest. So a gateway resolves no name,
//! reaches no NTP server and fetches no package — including through
//! `helios-ctl update`, which runs `apt-get` on that very machine.
//!
//! `allow_gateway_egress` opens it, on the WAN interface and on those ports
//! only. It is separate from `allow_client_internet` because it answers a
//! different question — what the gateway emits, not what it relays — and it
//! does not follow the tunnel state, because an upgrade happens when the
//! tunnel is down.
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

use aether::{FirewallPolicy, TunnelState, SPEEDTEST_PORT};

/// Networks NordVPN classifies as local for Meshnet's separate local-network
/// permission.
const PRIVATE_IPV4_CIDRS: [&str; 4] = [
    "10.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

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
    let wan_ifaces = policy.wan_ifaces.clone();

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
                vec![
                    Match::DestPort {
                        port: SPEEDTEST_PORT,
                        proto: L4::Tcp,
                    },
                    Match::InIface(iface.to_string()),
                ],
                Verdict::Accept,
            )
            .with_note("raw speedtest TCP: only via the tunnel interface"),
        );
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::DestPort {
                        port: SPEEDTEST_PORT,
                        proto: L4::Udp,
                    },
                    Match::InIface(iface.to_string()),
                ],
                Verdict::Accept,
            )
            .with_note("raw speedtest UDP: only via the tunnel interface"),
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
        for wan in &wan_ifaces {
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
    }

    // ── Key-negotiation listener ─────────────────────────────────────────────
    // This public QUIC endpoint authenticates peers before the first
    // WireGuard handshake. It is opened only when the configured service is
    // ready; the administration API remains restricted to the tunnel.
    if let Some(port) = policy.key_negotiation_port {
        for wan in &wan_ifaces {
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
    }

    // ── Outbound WireGuard transport to static peers (site-to-site) ─────────
    // Scoped by destination: opening 51820 outbound without restricting the
    // destination would be a leak.
    for peer in &policy.wg_peers {
        for wan in &wan_ifaces {
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
    }

    // ── DHCP lease renewal on the WAN ────────────────────────────────────────
    // Scoped to the WAN interface and to the protocol's two ports. Traffic is
    // local to the link: the client sends to 67, the server replies to 68.
    // The reply is not left to `ct state established` — a DHCPDISCOVER goes
    // out as a broadcast and the reply does not always attach to a tracked
    // flow.
    if policy.allow_dhcp_on_wan {
        for wan in &wan_ifaces {
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
    }

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
        for wan in &wan_ifaces {
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
                .with_note("package fetching — `helios-ctl update` runs `apt-get` on the gateway"),
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
        for wan in &wan_ifaces {
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
                        Match::DestNet(peer.clone()),
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
                            Match::SourceNet(peer.clone()),
                            Match::Icmp,
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
                                Match::SourceNet(peer.clone()),
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
                                Match::SourceNet(peer.clone()),
                                Match::DestNet(private_network.into()),
                            ],
                            Verdict::Drop,
                        )
                        .with_note("Meshnet routing peer has no local-network permission"),
                    );
                }
            }

            let mut routed_out_ifaces = wan_ifaces.clone();
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
                            Match::SourceNet(peer.clone()),
                            Match::OutIface(out_iface),
                        ],
                        Verdict::Accept,
                    )
                    .with_note("traffic from a NordVPN-authorized Meshnet routing peer"),
                );
            }
        }
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
                    for wan in &wan_ifaces {
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
            }
            None => {
                // Unknown gateway: let the browser reach the portal's landing
                // page, whatever its destination.
                for chain in [Output, Forward] {
                    for wan in &wan_ifaces {
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
            for wan in &wan_ifaces {
                rules.push(Rule::new(
                    Forward,
                    vec![Match::InIface(lan.clone()), Match::OutIface(wan.clone())],
                    Verdict::Accept,
                ));
            }
        }

        // Internet egress for tunnel clients. The return path is covered by
        // the forward chain's `ct state established,related` rule: opening
        // the outbound direction is enough, and scoping to the client -> WAN
        // direction only avoids exposing the gateway's LAN to clients.
        if policy.allow_client_internet && !policy.wg_iface.is_empty() {
            for wan in &wan_ifaces {
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
        // One masquerade per uplink, and they enter the **same** transaction as
        // the filtering: a masquerade that outlived the kill-switch would let
        // out in the clear what it had just cut. Several is not a widening —
        // each only ever matches packets that actually leave by its own
        // interface, which is what makes an uplink failover survive without a
        // reload.
        masquerade_out: if state.traffic_allowed()
            && policy.allow_client_internet
            && !policy.wg_iface.is_empty()
        {
            wan_ifaces.clone()
        } else {
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::PolicyMode;

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_ifaces: vec!["eth0".into()],
            lan_ifaces: vec!["eth1".into()],
            wg_peers: vec!["203.0.113.10".into()],
            wg_listen_port: Some(51820),
            key_negotiation_port: Some(51821),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            allow_dhcp_on_wan: false,
            allow_client_internet: false,
            allow_tunnel_icmp: false,
            allow_gateway_egress: false,
            allow_ssh_over_tunnel: false,
            wg_iface: "helios0".into(),
            admin_port: None,
            admin_iface: None,
            split_tunnel_cidrs: vec![],
            mss_clamp: None,
            captive_portal_gateway: None,
            nordvpn_meshnet: None,
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

    /// Closed by default like everything else — but the failure it produces
    /// is a name-resolution timeout, which points nowhere near the firewall.
    #[test]
    fn gateway_egress_is_closed_by_default() {
        let rs = render(&policy(), TunnelState::Up);
        for port in ["dport 53", "dport 123", "dport 443"] {
            assert!(
                !text(&rs, ChainKind::Output)
                    .iter()
                    .any(|r| r.contains(port)),
                "{port} open without the configuration requesting it"
            );
        }
    }

    /// The three openings the gateway needs for itself, and only in `output`:
    /// this is what it emits, never what it relays.
    #[test]
    fn gateway_egress_opens_resolution_time_and_packages_on_the_wan() {
        let mut p = policy();
        p.allow_gateway_egress = true;
        let rs = render(&p, TunnelState::Up);
        let out = text(&rs, ChainKind::Output);

        for expected in [
            "oifname \"eth0\" udp dport 53 accept",
            "oifname \"eth0\" tcp dport { 53, 80, 443 } accept",
            "oifname \"eth0\" udp dport 123 accept",
        ] {
            assert!(
                out.iter().any(|r| r == expected),
                "missing rule: {expected}"
            );
        }

        for kind in [ChainKind::Input, ChainKind::Forward] {
            assert!(
                !text(&rs, kind)
                    .iter()
                    .any(|r| r.contains("dport 53") || r.contains("dport 123")),
                "the gateway's own egress must open nothing in {}",
                kind.as_str()
            );
        }
    }

    /// The moment an operator needs this opening is an upgrade, and that is
    /// exactly a moment when the tunnel may be down. A flag that followed the
    /// tunnel state would be closed precisely when it is needed —
    /// `helios-ctl update` runs `apt-get` on the gateway itself.
    #[test]
    fn gateway_egress_does_not_follow_the_tunnel_state() {
        let mut p = policy();
        p.allow_gateway_egress = true;

        for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            assert!(
                text(&render(&p, st), ChainKind::Output)
                    .iter()
                    .any(|r| r == "oifname \"eth0\" udp dport 53 accept"),
                "state {st:?}: the gateway must still be able to resolve"
            );
        }
    }

    #[test]
    fn meshnet_is_scoped_to_its_mark_interface_peers_and_services() {
        let mut p = policy();
        p.allow_gateway_egress = true;
        p.nordvpn_meshnet = Some(aether::NordvpnMeshnetPolicy {
            iface: "nordlynx".into(),
            fwmark: 0xe1f1,
            peer_cidrs: vec!["100.70.36.212/32".into()],
            traffic_routing_peer_cidrs: Vec::new(),
            local_network_peer_cidrs: Vec::new(),
            inbound_tcp_ports: vec![22, 9100],
            inbound_udp_ports: vec![51830],
            allow_icmp: true,
        });

        for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            let rs = render(&p, state);
            let output = text(&rs, ChainKind::Output);
            let input = text(&rs, ChainKind::Input);

            assert!(output
                .iter()
                .any(|rule| rule == "oifname \"eth0\" meta mark 0xe1f1 accept"));
            assert!(output
                .iter()
                .any(|rule| { rule == "oifname \"nordlynx\" ip daddr 100.70.36.212/32 accept" }));
            assert!(input.iter().any(|rule| {
                rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 meta l4proto icmp accept"
            }));
            assert!(input.iter().any(|rule| {
                rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 tcp dport { 22, 9100 } accept"
            }));
            assert!(input.iter().any(|rule| {
                rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 udp dport { 51830 } accept"
            }));
            assert!(!text(&rs, ChainKind::Forward)
                .iter()
                .any(|rule| rule.contains("nordlynx") || rule.contains("0xe1f1")));
            assert!(!rs.rules.iter().any(|rule| {
                rule.matches
                    .contains(&Match::SourceNet("100.70.36.213/32".into()))
            }));
        }
    }

    #[test]
    fn meshnet_routing_mirrors_per_peer_routing_and_local_network_permissions() {
        let mut p = policy();
        p.wan_ifaces = vec!["eth0".into(), "wlan0".into()];
        p.lan_ifaces = vec!["lan0".into()];
        p.allow_gateway_egress = true;
        p.nordvpn_meshnet = Some(aether::NordvpnMeshnetPolicy {
            iface: "nordlynx".into(),
            fwmark: 0xe1f1,
            peer_cidrs: vec!["100.70.36.212/32".into(), "100.70.36.213/32".into()],
            traffic_routing_peer_cidrs: vec!["100.70.36.212/32".into(), "100.70.36.213/32".into()],
            local_network_peer_cidrs: vec!["100.70.36.213/32".into()],
            inbound_tcp_ports: vec![22, 49111],
            inbound_udp_ports: Vec::new(),
            allow_icmp: true,
        });

        for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
            let forward = text(&render(&p, state), ChainKind::Forward);

            for private_network in PRIVATE_IPV4_CIDRS {
                assert!(forward.iter().any(|rule| {
                    rule
                        == &format!(
                            "iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr {private_network} drop"
                        )
                }));
                assert!(!forward.iter().any(|rule| {
                    rule.contains("100.70.36.213/32") && rule.contains(private_network)
                }));
            }
            let private_drop = forward
                .iter()
                .position(|rule| {
                    rule
                        == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr 192.168.0.0/16 drop"
                })
                .unwrap();
            let wan_accept = forward
                .iter()
                .position(|rule| {
                    rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 oifname \"eth0\" accept"
                })
                .unwrap();
            assert!(
                private_drop < wan_accept,
                "the broad WAN acceptance must not precede the private-network denial"
            );
            for wan in ["eth0", "wlan0"] {
                for peer in ["100.70.36.212/32", "100.70.36.213/32"] {
                    assert!(forward.iter().any(|rule| {
                        rule == &format!(
                            "iifname \"nordlynx\" ip saddr {peer} oifname \"{wan}\" accept"
                        )
                    }));
                }
            }
            assert!(forward.iter().any(|rule| {
                rule == "iifname \"nordlynx\" ip saddr 100.70.36.213/32 oifname \"lan0\" accept"
            }));
            assert!(!forward.iter().any(|rule| {
                rule.contains("100.70.36.212/32") && rule.contains("oifname \"lan0\"")
            }));
        }
    }

    /// Closed by default: a gateway granting access to internal resources has
    /// no reason to route Internet traffic.
    #[test]
    fn client_internet_egress_is_closed_by_default() {
        let rs = render(&policy(), TunnelState::Up);
        assert!(
            rs.masquerade_out.is_empty(),
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
        assert_eq!(up.masquerade_out, vec!["eth0".to_string()]);
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
                rs.masquerade_out.is_empty(),
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
        assert!(input
            .iter()
            .any(|r| r.contains("tcp dport 5201") && r.contains("iifname \"helios0\"")));
        assert!(input
            .iter()
            .any(|r| r.contains("udp dport 5201") && r.contains("iifname \"helios0\"")));
        assert!(!input
            .iter()
            .any(|r| r == "tcp dport 5201 accept" || r == "udp dport 5201 accept"));
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
    /// A gateway with a cable and a radio: every rule that names the WAN is
    /// emitted for both. This is what makes an uplink failover survive with no
    /// restart — the kernel moves its default route and the rules are already
    /// there.
    #[test]
    fn every_wan_rule_is_emitted_for_every_uplink() {
        let mut policy = policy();
        policy.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
        policy.allow_gateway_egress = true;
        policy.allow_client_internet = true;
        policy.allow_dhcp_on_wan = true;
        let rs = render(&policy, TunnelState::Up);

        for iface in ["enp3s0", "wlo1"] {
            let inbound: Vec<&Rule> = rs
                .chain(ChainKind::Input)
                .filter(|rule| rule.matches.contains(&Match::InIface(iface.into())))
                .collect();
            let opens = |port: u16| {
                inbound.iter().any(|rule| {
                    rule.matches.contains(&Match::DestPort {
                        port,
                        proto: L4::Udp,
                    })
                })
            };
            assert!(opens(51820), "the WireGuard listener is open on {iface}");
            assert!(
                opens(68),
                "DHCP replies are accepted on {iface}: a lease renewed on one link only \
                 would strand the other"
            );
            assert!(
                rs.chain(ChainKind::Output)
                    .any(|rule| rule.matches.contains(&Match::OutIface(iface.into()))),
                "the gateway's own egress leaves by {iface}"
            );
            assert!(
                rs.chain(ChainKind::Forward)
                    .any(|rule| rule.matches.contains(&Match::OutIface(iface.into()))),
                "tunnel clients reach the Internet through {iface}"
            );
        }
        assert_eq!(
            rs.masquerade_out,
            vec!["enp3s0".to_string(), "wlo1".to_string()],
            "one masquerade per uplink: each only matches what leaves by its own interface"
        );
    }

    /// The kill-switch is unchanged by any of it: several uplinks is not a
    /// reason for NAT to outlive the tunnel.
    #[test]
    fn several_uplinks_do_not_outlive_the_kill_switch() {
        let mut policy = policy();
        policy.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
        policy.allow_client_internet = true;
        for state in [TunnelState::Down, TunnelState::Connecting] {
            let rs = render(&policy, state);
            assert!(
                rs.masquerade_out.is_empty(),
                "a masquerade surviving the kill-switch would let out in the clear what it \
                 has just cut, on either uplink"
            );
        }
    }

    /// No uplink declared emits no WAN rule at all — never a rule on an
    /// interface named nothing, which would match everything or nothing
    /// depending on the backend.
    #[test]
    fn no_uplink_emits_no_wan_rule() {
        let mut policy = policy();
        policy.wan_ifaces = Vec::new();
        policy.allow_gateway_egress = true;
        policy.allow_client_internet = true;
        let rs = render(&policy, TunnelState::Up);
        assert!(
            !rs.rules
                .iter()
                .any(|rule| rule.matches.iter().any(|m| matches!(
                    m,
                    Match::InIface(name) | Match::OutIface(name) if name.is_empty()
                ))),
            "no rule is emitted on an empty interface name"
        );
        assert!(rs.masquerade_out.is_empty());
    }
}
