//! The Netlink transaction: one batch, applied whole or not at all.
//!
//! Owns the table name, the `Add`/`Del`/`Add` sequence that makes the
//! replacement atomic, and the single `send` that reaches the kernel. The
//! atomicity argument and the reason the first `Add` is not redundant are in
//! the module doc of [`super`] and on [`NetlinkBackend::SEQUENCE_TABLE`].

use aether::{FirewallPolicy, HeliosError, Result, TunnelState};
use async_trait::async_trait;
use rustables::{
    expr::Masquerade, Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType,
    ProtocolFamily, Rule as NfRule, Table,
};
use tracing::{info, warn};

use super::TABLE_NAME;
use crate::ruleset::{render, ChainKind, Ruleset, Verdict};
use crate::{FirewallBackend, FirewallCapabilities};

pub struct NetlinkBackend {
    table_name: String,
}

impl NetlinkBackend {
    pub fn new() -> Self {
        Self {
            table_name: TABLE_NAME.to_string(),
        }
    }

    pub(super) fn err(msg: impl std::fmt::Display) -> HeliosError {
        HeliosError::Firewall(msg.to_string())
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
        if let Some(mss) = rs.mss_clamp {
            return Err(Self::err(format!(
                "MSS clamp {mss} cannot be encoded by rustables 0.8.7; transaction not sent"
            )));
        }

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
                    for action in &rule.actions {
                        nf = Self::apply_action(nf, action)?;
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
        if !rs.masquerade_out.is_empty() {
            // One chain, one rule per uplink. Creating the chain inside the
            // loop would declare it several times in a single batch.
            let chain = Chain::new(&table)
                .with_name("postrouting")
                .with_hook(Hook::new(HookClass::PostRouting, 100))
                .with_type(ChainType::Nat)
                // No default policy on a NAT chain: it does not render a
                // filtering verdict, it rewrites or lets through.
                .add_to_batch(&mut batch);

            for out_iface in &rs.masquerade_out {
                NfRule::new(&chain)
                    .map_err(Self::err)?
                    .oiface(out_iface)
                    .map_err(Self::err)?
                    .with_expr(Masquerade::default())
                    .add_to_batch(&mut batch);
            }
        }

        Ok(batch)
    }

    fn commit(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state)?;
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
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities::default()
    }

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
    use std::num::{NonZeroU32, NonZeroU64};

    use super::*;
    use crate::ruleset::{
        Action, AddressFamily, Counter, LogAction, Match, RateLimit, RateLimitMode, RateUnit, L4,
    };

    fn network(value: &str) -> ipnetwork::IpNetwork {
        value.parse().expect("valid test network")
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
                        Match::ConnectionState(
                            crate::ruleset::ConnectionStates::ESTABLISHED_RELATED,
                        ),
                        Match::InIface("helios0".into()),
                        Match::DestPort {
                            port: 8080,
                            proto: L4::Tcp,
                        },
                        Match::DestNet(network("100.64.0.1")),
                        Match::SourceNet(network("100.64.0.0/10")),
                    ],
                    actions: Vec::new(),
                    verdict: Verdict::Accept,
                    note: None,
                },
                crate::ruleset::Rule {
                    chain: ChainKind::Forward,
                    matches: vec![
                        Match::OutIface("eth0".into()),
                        Match::PacketMark(0xe1f1),
                        Match::DestPortSet {
                            ports: vec![53, 51820],
                            proto: L4::Udp,
                        },
                        Match::DestNet(network("2001:db8::/32")),
                        Match::SourceNet(network("2001:db8::1")),
                    ],
                    actions: Vec::new(),
                    verdict: Verdict::Drop,
                    note: None,
                },
                crate::ruleset::Rule {
                    chain: ChainKind::Input,
                    matches: vec![
                        Match::InIface("helios0".into()),
                        Match::Icmp(AddressFamily::Ipv6),
                    ],
                    actions: Vec::new(),
                    verdict: Verdict::Accept,
                    note: None,
                },
            ],
            mss_clamp: None,
            masquerade_out: vec!["eth0".into()],
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_ok());

        let mut accept_by_default = ruleset;
        accept_by_default.default_verdict = Verdict::Accept;
        accept_by_default.masquerade_out = Vec::new();
        assert!(NetlinkBackend::new()
            .build_batch(&accept_by_default)
            .is_ok());
    }

    #[test]
    fn mss_clamping_fails_translation_instead_of_being_ignored() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: Vec::new(),
            mss_clamp: Some(1280),
            masquerade_out: Vec::new(),
        };

        let error = match NetlinkBackend::new().build_batch(&ruleset) {
            Ok(_) => panic!("an unapplied MSS clamp must not produce a transaction"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("MSS clamp 1280") && error.contains("transaction not sent"));
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
                actions: Vec::new(),
                verdict: Verdict::Accept,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_err());
    }

    #[test]
    fn anonymous_counters_and_logs_translate_before_any_side_effect() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: vec![Match::ConnectionState(
                    crate::ruleset::ConnectionStates::INVALID,
                )],
                actions: vec![
                    Action::Counter(Counter::Anonymous),
                    Action::Log(LogAction {
                        prefix: "helios invalid: ".into(),
                        group: None,
                    }),
                ],
                verdict: Verdict::Drop,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_ok());
    }

    #[test]
    fn named_counters_fail_translation_instead_of_becoming_anonymous() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: Vec::new(),
                actions: vec![Action::Counter(Counter::Named("drop-invalid".into()))],
                verdict: Verdict::Drop,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: Vec::new(),
        };

        let error = match NetlinkBackend::new().build_batch(&ruleset) {
            Ok(_) => panic!("a named counter must not be downgraded to an anonymous one"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("named counter `drop-invalid`"));
    }

    #[test]
    fn invalid_log_prefix_fails_translation() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: Vec::new(),
                actions: vec![Action::Log(LogAction {
                    prefix: "x".repeat(128),
                    group: None,
                })],
                verdict: Verdict::Drop,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_err());
    }

    #[test]
    fn rate_limits_fail_translation_instead_of_being_ignored() {
        let ruleset = Ruleset {
            default_verdict: Verdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: Vec::new(),
                actions: vec![Action::Limit(RateLimit {
                    rate: NonZeroU64::new(20).unwrap(),
                    unit: RateUnit::Second,
                    burst: NonZeroU32::new(5).unwrap(),
                    mode: RateLimitMode::Until,
                })],
                verdict: Verdict::Accept,
                note: None,
            }],
            mss_clamp: None,
            masquerade_out: Vec::new(),
        };

        let error = match NetlinkBackend::new().build_batch(&ruleset) {
            Ok(_) => panic!("a rate limit must not disappear during translation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("rate limit") && error.contains("rustables 0.8.7"));
    }
}
