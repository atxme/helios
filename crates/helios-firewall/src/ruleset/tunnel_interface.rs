//! What the gateway exposes on its own tunnel interface.
//!
//! ICMP, administrative SSH, the raw speedtest and `iperf3`. The single
//! `wg_iface` guard around all four is what ties them together: without a
//! tunnel interface none of them has an interface to be scoped to, and an
//! unscoped variant of any of them would be reachable from the WAN.

use aether::FirewallPolicy;

use super::ChainKind::{Input, Output};
use super::{Match, Rule, Verdict, L4, SPEEDTEST_PORT};

pub(super) fn openings(rules: &mut Vec<Rule>, policy: &FirewallPolicy) {
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
}
