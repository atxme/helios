//! Real Netlink backend, based on `rustables` (nf_tables).
//!
//! ⚠️ **Target-only.** This module compiles everywhere, but can only be
//! *exercised* on a kernel with `nf_tables` — not WSL2. To validate on the
//! dedicated machine:
//!
//! ```sh
//! cargo build -p heliosd --features netlink
//! sudo ./target/debug/heliosd run
//! sudo nft list table inet helios
//! ```
//!
//! # Atomicity and fail-closed
//!
//! The whole application goes through **a single Netlink transaction**
//! (`Batch`): the kernel applies it entirely or not at all. So there is no
//! instant where the table would be half-populated — i.e. no instant where
//! the kill-switch would be partially lifted.
//!
//! The table is **recreated on every application** (`Add`, `Del`, then `Add`
//! within the same transaction): this is the only way to get an atomic
//! replacement without leaving stale rules behind.
//!
//! The first `Add` guarantees the table exists before it is deleted. The
//! kernel does **not** tolerate a `Del` on an absent table: it responds
//! `ENOENT` and rejects the whole transaction. Without this `Add`, no
//! kill-switch was applied on a machine's very first startup and heliosd
//! would stop — a behavior only a real-target trial could reveal.
//!
//! # Known limitation: MSS clamping
//!
//! `Ruleset::mss_clamp` is **not** applied here: rewriting the TCP MSS option
//! is a *mangle* action that `rustables`' high-level API does not expose.
//! This is a performance optimization (avoiding fragmentation), not a
//! security rule: its absence leaves no gap. It is logged at `warn` level so
//! it does not silently disappear.

use std::net::IpAddr;
use std::str::FromStr;

use aether::{FirewallPolicy, HeliosError, Result, TunnelState};
use async_trait::async_trait;
use rustables::{
    expr::Masquerade, Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol,
    ProtocolFamily, Rule as NfRule, Table,
};
use tracing::{info, warn};

use crate::ruleset::{render, ChainKind, Match, Ruleset, Verdict, L4};
use crate::FirewallBackend;

const TABLE_NAME: &str = "helios";

pub struct NetlinkBackend {
    table_name: String,
}

impl NetlinkBackend {
    pub fn new() -> Self {
        Self {
            table_name: TABLE_NAME.to_string(),
        }
    }

    fn err(msg: impl std::fmt::Display) -> HeliosError {
        HeliosError::Firewall(msg.to_string())
    }

    fn hook_class(kind: ChainKind) -> HookClass {
        match kind {
            ChainKind::Input => HookClass::In,
            ChainKind::Forward => HookClass::Forward,
            ChainKind::Output => HookClass::Out,
        }
    }

    /// Applies a match to a rule under construction.
    fn apply_match(rule: NfRule, m: &Match) -> Result<NfRule> {
        let proto = |p: L4| match p {
            L4::Tcp => Protocol::TCP,
            L4::Udp => Protocol::UDP,
        };

        Ok(match m {
            Match::Established => rule.established().map_err(Self::err)?,
            Match::InIface(i) => rule.iiface(i).map_err(Self::err)?,
            Match::OutIface(i) => rule.oiface(i).map_err(Self::err)?,
            Match::DestPort { port, proto: p } => rule.dport(*port, proto(*p)),
            Match::DestPortSet { .. } => {
                return Err(Self::err(
                    "port set: must be expanded by expand_port_sets before translation",
                ))
            }
            Match::DestNet(addr) => Self::match_net(rule, addr, false)?,
            Match::SourceNet(addr) => Self::match_net(rule, addr, true)?,
            Match::Icmp => rule.icmp(),
        })
    }

    /// Applies an address match, accepting either a plain IP or a CIDR.
    fn match_net(rule: NfRule, addr: &str, source: bool) -> Result<NfRule> {
        if addr.contains('/') {
            let net = ipnetwork::IpNetwork::from_str(addr)
                .map_err(|e| Self::err(format!("invalid CIDR `{addr}`: {e}")))?;
            let r = if source {
                rule.snetwork(net)
            } else {
                rule.dnetwork(net)
            };
            r.map_err(Self::err)
        } else {
            let ip = IpAddr::from_str(addr)
                .map_err(|e| Self::err(format!("invalid IP `{addr}`: {e}")))?;
            Ok(if source {
                rule.saddr(ip)
            } else {
                rule.daddr(ip)
            })
        }
    }

    /// Expands a `DestPortSet` into a list of single-port match sets.
    /// The resulting filtering is identical.
    fn expand_port_sets(matches: &[Match]) -> Vec<Vec<Match>> {
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

    /// Sequence of messages applied to the table itself, in this order.
    ///
    /// The initial `Add` is not decorative: without it, the `Del` targets an
    /// absent table on the very first startup, the kernel responds `ENOENT`
    /// and rejects the whole transaction — so no kill-switch, and heliosd
    /// stops. Observed on a real target; dry-run could not see it.
    const SEQUENCE_TABLE: [MsgType; 3] = [MsgType::Add, MsgType::Del, MsgType::Add];

    /// Builds the complete transaction for this ruleset.
    ///
    /// Touches nothing: on translation error, `Err` is returned without
    /// having sent anything to the kernel — the previous policy stays in
    /// place, which is the expected fail-closed behavior.
    fn build_batch(&self, rs: &Ruleset) -> Result<Batch> {
        let mut batch = Batch::new();
        let table = Table::new(ProtocolFamily::Inet).with_name(self.table_name.clone());

        // Atomic replacement: removal of the old table and recreation within
        // the same transaction.
        //
        // The first `Add` is not redundant. Contrary to what one might
        // expect, the kernel does not tolerate a `Del` on an absent table: it
        // responds `ENOENT` and **rejects the whole transaction**. On a
        // machine where `inet helios` never existed — i.e. on a very first
        // startup — the firewall would not apply and heliosd would stop
        // during "firewall application".
        //
        // The nftables idiom is to guarantee the table exists before
        // deleting it: `Add` (no-op if present), `Del` (now safe), then
        // `Add` to start over from an empty table.
        for msg in Self::SEQUENCE_TABLE {
            batch.add(&table, msg);
        }

        let policy = match rs.default_verdict {
            Verdict::Drop => ChainPolicy::Drop,
            Verdict::Accept => ChainPolicy::Accept,
        };

        for kind in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
            let chain = Chain::new(&table)
                .with_name(kind.as_str())
                .with_hook(Hook::new(Self::hook_class(kind), 0))
                .with_policy(policy)
                .add_to_batch(&mut batch);

            for rule in rs.chain(kind) {
                for matches in Self::expand_port_sets(&rule.matches) {
                    let mut nf = NfRule::new(&chain).map_err(Self::err)?;
                    for m in &matches {
                        nf = Self::apply_match(nf, m)?;
                    }
                    nf = match rule.verdict {
                        Verdict::Accept => nf.accept(),
                        Verdict::Drop => nf.drop(),
                    };
                    nf.add_to_batch(&mut batch);
                }
            }
        }

        // ── Masquerade of tunnel clients ─────────────────────────────────────
        // A chain of a different type (`nat`) and a different hook
        // (`postrouting`), so outside the loop above. It lives in the
        // **same** transaction: NAT and filtering must appear and disappear
        // together, otherwise there is an instant where one protects without
        // the other.
        //
        // Priority 100 (`NF_IP_PRI_NAT_SRC`): this is the expected place for
        // a source-NAT, after filtering.
        if let Some(out_iface) = &rs.masquerade_out {
            let chain = Chain::new(&table)
                .with_name("postrouting")
                .with_hook(Hook::new(HookClass::PostRouting, 100))
                .with_type(ChainType::Nat)
                // No default policy on a NAT chain: it does not render a
                // filtering verdict, it rewrites or lets through.
                .add_to_batch(&mut batch);

            NfRule::new(&chain)
                .map_err(Self::err)?
                .oiface(out_iface)
                .map_err(Self::err)?
                .with_expr(Masquerade::default())
                .add_to_batch(&mut batch);
        }

        Ok(batch)
    }

    fn commit(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state);

        if let Some(mss) = rs.mss_clamp {
            warn!(
                "MSS clamping ({mss} bytes) not applied: mangle action not expressible \
                 via rustables. Performance optimization, no security gap."
            );
        }

        let batch = self.build_batch(&rs)?;
        batch.send().map_err(|e| {
            Self::err(format!(
                "Netlink transaction rejected (table {} unchanged): {e}",
                self.table_name
            ))
        })?;

        info!(
            "table inet {} applied — policy {:?}, {} rule(s), state {:?}",
            self.table_name,
            rs.default_verdict,
            rs.rules.len(),
            state
        );
        Ok(())
    }
}

impl Default for NetlinkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for NetlinkBackend {
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        self.commit(policy, state)
    }

    async fn teardown(&self) -> Result<()> {
        // The kill-switch is left **engaged** at shutdown: the table is
        // never removed (fail-closed invariant). This method exists only for
        // trait symmetry.
        warn!(
            "teardown ignored: table inet {} is left in place (fail-closed)",
            self.table_name
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    fn table_is_created_before_being_deleted() {
        // Regression test: `Del` first used to fail with `ENOENT` on a
        // machine where `inet helios` had never existed, and the kernel
        // rejected the whole transaction — no kill-switch applied, startup
        // impossible.
        let seq = NetlinkBackend::SEQUENCE_TABLE;
        assert_eq!(seq[0], MsgType::Add, "the table must exist before Del");
        let del = seq
            .iter()
            .position(|m| *m == MsgType::Del)
            .expect("a Del is expected");
        assert!(del > 0, "no Add precedes the Del");
        assert_eq!(
            seq[del + 1],
            MsgType::Add,
            "the table must be recreated after Del"
        );
    }

    #[test]
    fn a_set_without_expansion_stays_intact() {
        let matches = vec![Match::InIface("lo".into())];
        assert_eq!(NetlinkBackend::expand_port_sets(&matches), vec![matches]);
    }

    #[test]
    fn address_parsing() {
        assert!(ipnetwork::IpNetwork::from_str("10.0.0.0/8").is_ok());
        assert!(IpAddr::from_str("203.0.113.10").is_ok());
        assert!(ipnetwork::IpNetwork::from_str("not-a-cidr").is_err());
    }

    /// Translation is the largest deterministic part of the real backend.
    /// It is exercised without sending the resulting batch to the kernel.
    #[test]
    fn a_complete_ruleset_translates_before_any_netlink_side_effect() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![
                crate::ruleset::Rule {
                    chain: ChainKind::Input,
                    matches: vec![
                        Match::Established,
                        Match::InIface("helios0".into()),
                        Match::DestPort {
                            port: 8080,
                            proto: L4::Tcp,
                        },
                        Match::DestNet("100.64.0.1".into()),
                        Match::SourceNet("100.64.0.0/10".into()),
                    ],
                    verdict: Verdict::Accept,
                    note: None,
                },
                crate::ruleset::Rule {
                    chain: ChainKind::Forward,
                    matches: vec![
                        Match::OutIface("eth0".into()),
                        Match::DestPortSet {
                            ports: vec![53, 51820],
                            proto: L4::Udp,
                        },
                        Match::DestNet("2001:db8::/32".into()),
                        Match::SourceNet("2001:db8::1".into()),
                    ],
                    verdict: Verdict::Drop,
                    note: None,
                },
            ],
            mss_clamp: Some(1280),
            masquerade_out: Some("eth0".into()),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_ok());

        let mut accept_by_default = ruleset;
        accept_by_default.default_verdict = Verdict::Accept;
        accept_by_default.masquerade_out = None;
        assert!(NetlinkBackend::new()
            .build_batch(&accept_by_default)
            .is_ok());
    }

    #[test]
    fn malformed_addresses_abort_the_batch_before_it_can_be_sent() {
        for malformed in [
            Match::DestNet("not-an-address".into()),
            Match::DestNet("10.0.0.0/99".into()),
            Match::SourceNet("still-not-an-address".into()),
            Match::SourceNet("2001:db8::/999".into()),
        ] {
            let ruleset = Ruleset {
                default_verdict: Verdict::Drop,
                rules: vec![crate::ruleset::Rule {
                    chain: ChainKind::Output,
                    matches: vec![malformed],
                    verdict: Verdict::Accept,
                    note: None,
                }],
                mss_clamp: None,
                masquerade_out: None,
            };
            assert!(
                NetlinkBackend::new().build_batch(&ruleset).is_err(),
                "an invalid address must cancel translation"
            );
        }
    }

    #[test]
    fn two_port_sets_are_refused_instead_of_becoming_a_partial_rule() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: vec![
                    Match::DestPortSet {
                        ports: vec![80, 443],
                        proto: L4::Tcp,
                    },
                    Match::DestPortSet {
                        ports: vec![53],
                        proto: L4::Udp,
                    },
                ],
                verdict: Verdict::Accept,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: None,
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_err());
    }
}
