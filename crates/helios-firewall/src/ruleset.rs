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

/// Fixed, host-visible bridge of the Astra private channel (spec §8.3).
///
/// Compose gives the bridge this exact name; keeping the tuple here avoids an
/// interface wildcard turning a source-spoofed packet into an authority call.
const ASTRA_PRIVATE_IFACE: &str = "astra0";
const ASTRA_PRIVATE_HOST: &str = "10.88.7.1/32";
const ASTRA_PRIVATE_PEER: &str = "10.88.7.2/32";
const HELIOS_LIFECYCLE_PORT: u16 = 8444;
const ASTRA_LIFECYCLE_PORT: u16 = 8445;

/// Fixed bridge of the Astra **public** origin, and its two coordinates.
///
/// Named for the same reason `astra0` is: compose pins the bridge and the
/// addresses, so the opening below can state all four coordinates instead of
/// wildcarding an interface Docker renames on every recreation.
///
/// The origin is published on `127.0.0.1:8443`, which Docker DNATs onto this
/// bridge. Without this rule the translated packet leaves through `astra1`,
/// matches nothing in a chain whose policy is `drop`, and dies — so the
/// authority's own machine cannot reach the authority. That is what blocks
/// the expired-identity recovery of ADR-008 §7.5, whose whole point is to be
/// reachable when the tunnel is not.
const ASTRA_PUBLIC_IFACE: &str = "astra1";
const ASTRA_PUBLIC_HOST: &str = "10.88.7.9/32";
const ASTRA_PUBLIC_PEER: &str = "10.88.7.10/32";
const ASTRA_ORIGIN_PORT: u16 = 8443;

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

    // ── Private Astra ↔ Helios lifecycle channel ───────────────────────────
    // These openings name all four coordinates: interface, source, target and
    // port. They are harmless when the optional bridge does not exist and do
    // not grant the container any forwarding or general host access.
    rules.push(
        Rule::new(
            Input,
            vec![
                Match::InIface(ASTRA_PRIVATE_IFACE.into()),
                Match::SourceNet(ASTRA_PRIVATE_PEER.into()),
                Match::DestNet(ASTRA_PRIVATE_HOST.into()),
                Match::DestPort {
                    port: HELIOS_LIFECYCLE_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Astra mTLS client to the private Helios lifecycle API"),
    );
    rules.push(
        Rule::new(
            Output,
            vec![
                Match::OutIface(ASTRA_PRIVATE_IFACE.into()),
                Match::SourceNet(ASTRA_PRIVATE_HOST.into()),
                Match::DestNet(ASTRA_PRIVATE_PEER.into()),
                Match::DestPort {
                    port: ASTRA_LIFECYCLE_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Helios mTLS client to the private Astra lifecycle API"),
    );
    // The gateway reaching the authority's public origin, on its own machine.
    //
    // Output only, and scoped to the container: nothing here lets the origin
    // out to the WAN, and nothing lets a third party in. `forward` stays
    // `drop`, so the container gains no route through the gateway either —
    // the opening is the host's, not Astra's.
    rules.push(
        Rule::new(
            Output,
            vec![
                Match::OutIface(ASTRA_PUBLIC_IFACE.into()),
                Match::SourceNet(ASTRA_PUBLIC_HOST.into()),
                Match::DestNet(ASTRA_PUBLIC_PEER.into()),
                Match::DestPort {
                    port: ASTRA_ORIGIN_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Helios client to the public Astra origin, published on loopback"),
    );

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
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::SourcePort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "WireGuard listener transport — replies, rekeys and keep-alives may be new \
                     conntrack flows, especially after an uplink change",
                ),
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
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(wan.clone()),
                        Match::SourcePort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note(
                    "key-negotiation QUIC replies — the final frame can outlive UDP conntrack",
                ),
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
        // The Helios speedtest, on the address the daemon binds inside the
        // tunnel.
        //
        // It lives here, with the tunnel's own openings, and no longer beside
        // the administration API. It sat in that block for as long as it took
        // one gateway to leave `admin_iface` unset: `admin_port` is derived
        // from that field, the whole block is skipped when it is absent, and
        // the two rules below went with it. Nothing else opens the speedtest
        // port, so every probe was dropped in `input` — and a drop is silent,
        // so the client reported a timeout (`os error 10060`) against a daemon
        // that was listening perfectly well. The opening belongs to the
        // interface the service listens on, not to another service's
        // configuration.
        //
        // Input only: the gateway never opens a speedtest flow of its own, and
        // its answers are `established`.
        for proto in [L4::Tcp, L4::Udp] {
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        Match::InIface(policy.wg_iface.clone()),
                        Match::DestPort {
                            port: SPEEDTEST_PORT,
                            proto,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("raw speedtest: only via the tunnel interface"),
            );
        }
        // `iperf3`, and the only opening here that touches `output`.
        //
        // Both roles have to work: server on the gateway (the `input` rule),
        // and server on the client with the gateway as `iperf3 -c` (the
        // `output` one). Without the second, a new outbound flow on the tunnel
        // interface matches nothing and the drop policy takes it — `iperf3`
        // then hangs on "Connecting to host", which looks like a client that
        // is not listening.
        //
        // TCP and UDP both: `iperf3 -u` is a different port role, not a
        // different port.
        if let Some(port) = policy.iperf_port {
            for proto in [L4::Tcp, L4::Udp] {
                rules.push(
                    Rule::new(
                        Input,
                        vec![
                            Match::InIface(policy.wg_iface.clone()),
                            Match::DestPort { port, proto },
                        ],
                        Verdict::Accept,
                    )
                    .with_note("iperf3 server on the gateway: only via the tunnel interface"),
                );
                rules.push(
                    Rule::new(
                        Output,
                        vec![
                            Match::OutIface(policy.wg_iface.clone()),
                            Match::DestPort { port, proto },
                        ],
                        Verdict::Accept,
                    )
                    .with_note("iperf3 client on the gateway, reaching a server on the peer"),
                );
            }
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

    // ── Out-of-band administration overlays, regardless of tunnel state ──────
    //
    // The operator's way back in when Helios itself is down, so it is rendered
    // in every state — `Down` and `Connecting` included, which is the whole
    // point: those are the states a broken tunnel leaves the gateway in.
    //
    // Scoped by interface, never by address, for the reason on the tunnel
    // openings above — and for a second one specific to overlays. Tailscale
    // and NordVPN each carry several addresses (v4 and v6), reassigned
    // without notice. An address list stops matching the day the address
    // moves, which is the day the recovery path is needed; `iifname` covers
    // every address the interface will ever hold.
    for iface in &policy.admin_ifaces {
        rules.push(
            Rule::new(
                Input,
                vec![
                    Match::InIface(iface.clone()),
                    Match::DestPort {
                        port: 22,
                        proto: L4::Tcp,
                    },
                ],
                Verdict::Accept,
            )
            .with_note("out-of-band administration SSH: survives a tunnel that cannot come up"),
        );
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
mod tests;
