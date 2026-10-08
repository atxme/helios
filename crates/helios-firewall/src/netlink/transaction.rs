//! The Netlink transaction: one batch, applied whole or not at all.
//!
//! Owns the table name, the `Add`/`Del`/`Add` sequence that makes the
//! replacement atomic, and the single `send` that reaches the kernel. The
//! atomicity argument and the reason the first `Add` is not redundant are in
//! the module doc of [`super`] and on [`NetlinkBackend::SEQUENCE_TABLE`].

use aether::{FirewallPolicy, HeliosError, Result, TunnelState};
use async_trait::async_trait;
use rustables::{
    expr::{
        Bitwise, Cmp, CmpOp, Exthdr, HighLevelPayload, Immediate, Masquerade, Meta, MetaType,
        Register, TransportHeaderField,
    },
    Batch, Chain, ChainPolicy as NfChainPolicy, ChainType, Hook, HookClass, MsgType,
    ProtocolFamily, Rule as NfRule, Table,
};
use tracing::{info, warn};

use super::TABLE_NAME;
use crate::ruleset::{render, ChainKind, DefaultVerdict, MasqueradeRule, Match, Rule, Ruleset};
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
            DefaultVerdict::Drop => NfChainPolicy::Drop,
            DefaultVerdict::Accept => NfChainPolicy::Accept,
        };

        for kind in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
            let chain = Chain::new(&table)
                .with_name(kind.as_str())
                .with_hook(Hook::new(Self::hook_class(kind), 0))
                .with_policy(policy)
                .add_to_batch(&mut batch);

            for rule in rs.chain(kind) {
                for matches in Self::expand_port_sets(&rule.matches) {
                    Self::filter_rule(&chain, &matches, rule)?.add_to_batch(&mut batch);
                }
            }
        }

        let mss_values: Vec<_> = rs.mss_clamps().collect();
        if !mss_values.is_empty() {
            // A separate mangle-priority chain performs only the TCP option
            // rewrite; it has no verdict and cannot bypass the filter chain's
            // invalid-conntrack drop or any other policy rule.
            let chain = Chain::new(&table)
                .with_name("mss")
                .with_hook(Hook::new(HookClass::Forward, -150))
                .with_type(ChainType::Filter)
                .add_to_batch(&mut batch);
            for (family, mss) in mss_values {
                let family = match family {
                    crate::ruleset::AddressFamily::Ipv4 => 2,
                    crate::ruleset::AddressFamily::Ipv6 => 10,
                };
                for incoming in [true, false] {
                    Self::mss_clamp_rule(&chain, family, mss, &rs.wg_iface, incoming)?
                        .add_to_batch(&mut batch);
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

            for rule in rs.masquerade_rules() {
                Self::masquerade_rule(&chain, &rule)?.add_to_batch(&mut batch);
            }
        }

        Ok(batch)
    }

    fn mss_clamp_rule(
        chain: &Chain,
        family: u8,
        mss: u16,
        wg_iface: &str,
        incoming: bool,
    ) -> Result<NfRule> {
        let mut rule = NfRule::new(chain).map_err(Self::err)?;
        rule = if incoming {
            rule.iiface(wg_iface)
        } else {
            rule.oiface(wg_iface)
        }
        .map_err(Self::err)?;
        rule = rule
            .with_expr(Meta::new(MetaType::NfProto))
            .with_expr(Cmp::new(CmpOp::Eq, [family]))
            .with_expr(Meta::new(MetaType::L4Proto))
            .with_expr(Cmp::new(CmpOp::Eq, [6]))
            .with_expr(
                HighLevelPayload::Transport(TransportHeaderField::Tcp(
                    rustables::expr::TCPHeaderField::Flags,
                ))
                .build(),
            )
            .with_expr(Bitwise::new([0x02], [0x00]).map_err(Self::err)?)
            .with_expr(Cmp::new(CmpOp::Eq, [0x02]))
            .with_expr(Immediate::new_data(
                mss.to_be_bytes().to_vec(),
                Register::Reg1,
            ))
            .with_expr(Exthdr::tcp_mss_store(Register::Reg1));
        Ok(rule)
    }

    /// Translates one port-expanded match set of `rule` into a filter rule.
    fn filter_rule(chain: &Chain, matches: &[Match], rule: &Rule) -> Result<NfRule> {
        let mut nf = NfRule::new(chain).map_err(Self::err)?;
        for m in matches {
            nf = Self::apply_match(nf, m)?;
        }
        for action in &rule.actions {
            nf = Self::apply_action(nf, action)?;
        }
        Ok(Self::apply_verdict(nf, rule.verdict))
    }

    /// Translates a masquerade rule: its matches — the IPv4 guard first —
    /// then the `masquerade` statement. The matches go through the same
    /// [`Self::apply_match`] as the filter rules, so the guard applied is the
    /// one [`MasqueradeRule`]'s display shows.
    fn masquerade_rule(chain: &Chain, rule: &MasqueradeRule) -> Result<NfRule> {
        let mut nf = NfRule::new(chain).map_err(Self::err)?;
        for m in rule.matches() {
            nf = Self::apply_match(nf, m)?;
        }
        Ok(nf.with_expr(Masquerade::default()))
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
        FirewallCapabilities { mss_clamp: true }
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

    use aether::PolicyMode;
    use rustables::expr::{Cmp, CmpOp, Meta, MetaType, RawExpression};

    use super::*;
    use crate::ruleset::{
        Action, AddressFamily, Counter, LogAction, RateLimit, RateLimitMode, RateUnit, Verdict, L4,
    };

    fn network(value: &str) -> ipnetwork::IpNetwork {
        value.parse().expect("valid test network")
    }

    /// Road-warrior egress open on two uplinks.
    fn client_internet_policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_ifaces: vec!["enp3s0".into(), "wlo1".into()],
            lan_ifaces: vec!["eth1".into()],
            wg_peers: vec![],
            wg_listen_port: Some(51820),
            key_negotiation_port: None,
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            admin_ifaces: vec![],
            allow_dhcp_on_wan: false,
            allow_client_internet: true,
            allow_tunnel_icmp: false,
            allow_gateway_egress: false,
            allow_ssh_over_tunnel: false,
            iperf_port: None,
            wg_iface: "helios0".into(),
            admin_port: None,
            admin_iface: None,
            split_tunnel_cidrs: vec![],
            mss_clamp: None,
            captive_portal_gateway: None,
            nordvpn_meshnet: None,
        }
    }

    /// A chain of the table `build_batch` creates, for per-rule translation.
    fn chain(name: &str) -> Chain {
        Chain::new(&Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME)).with_name(name)
    }

    fn expressions(rule: &NfRule) -> Vec<RawExpression> {
        rule.get_expressions()
            .map(|list| list.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `meta nfproto ipv4`, exactly as `rustables` emits it ahead of an IPv4
    /// address in `Rule::match_ip`.
    fn ipv4_guard() -> [RawExpression; 2] {
        [
            RawExpression::from(Meta::new(MetaType::NfProto)),
            RawExpression::from(Cmp::new(CmpOp::Eq, [2u8])),
        ]
    }

    /// In an `inet` NAT chain, a masquerade on `oifname` alone would NAT66
    /// the first IPv6 packet relayed to a WAN. Each uplink's rule must carry
    /// the IPv4 guard before the interface match and the rewrite.
    #[test]
    fn the_masquerade_rewrites_ipv4_only_on_every_uplink() {
        let rs = render(&client_internet_policy(), TunnelState::Up).expect("valid test policy");
        assert!(NetlinkBackend::new().build_batch(&rs).is_ok());

        let postrouting = chain("postrouting");
        let rules: Vec<MasqueradeRule> = rs.masquerade_rules().collect();
        assert_eq!(rules.len(), 2, "one masquerade per uplink");
        for (rule, uplink) in rules.iter().zip(["enp3s0", "wlo1"]) {
            let nf = NetlinkBackend::masquerade_rule(&postrouting, rule)
                .expect("a masquerade rule translates");
            let oifname = expressions(
                &NfRule::default()
                    .oiface(uplink)
                    .expect("valid interface name"),
            );

            let mut expected = ipv4_guard().to_vec();
            expected.extend(oifname);
            expected.push(RawExpression::from(Masquerade::default()));
            assert_eq!(expressions(&nf), expected, "masquerade on {uplink}");
        }
    }

    /// The forward opening that feeds the masquerade relays IPv4 only: the
    /// guard is translated ahead of the interface matches.
    #[test]
    fn the_client_internet_forward_rule_carries_the_ipv4_guard() {
        let rs = render(&client_internet_policy(), TunnelState::Up).expect("valid test policy");
        let forward = chain(ChainKind::Forward.as_str());

        let egress: Vec<&Rule> = rs
            .chain(ChainKind::Forward)
            .filter(|rule| {
                rule.verdict == Verdict::Accept
                    && rule.matches.contains(&Match::InIface("helios0".into()))
            })
            .collect();
        assert_eq!(egress.len(), 2, "one client egress rule per uplink");
        for rule in egress {
            let nf = NetlinkBackend::filter_rule(&forward, &rule.matches, rule)
                .expect("the egress rule translates");
            assert_eq!(expressions(&nf)[..2], ipv4_guard(), "{rule}");
        }
    }

    /// The rejection of the tunnel clients' IPv6 egress translates, on each
    /// uplink, to the IPv6 guard, the two interfaces and the `reject`
    /// expression — no verdict after it — and enters the same batch as the
    /// rest of the ruleset, in a state where traffic is not allowed too.
    #[test]
    fn the_ipv6_egress_rejection_translates_behind_the_ipv6_guard_on_every_uplink() {
        let ipv6_guard = [
            RawExpression::from(Meta::new(MetaType::NfProto)),
            RawExpression::from(Cmp::new(CmpOp::Eq, [10u8])),
        ];
        let reject = RawExpression::from(
            rustables::expr::Reject::default()
                .with_type(rustables::expr::RejectType::IcmpxUnreach)
                .with_icmp_code(rustables::expr::IcmpCode::AdminProhibited),
        );
        let forward = chain(ChainKind::Forward.as_str());
        for state in [TunnelState::Down, TunnelState::Up] {
            let rs = render(&client_internet_policy(), state).expect("valid test policy");
            assert!(NetlinkBackend::new().build_batch(&rs).is_ok(), "{state:?}");

            let rejects: Vec<&Rule> = rs
                .chain(ChainKind::Forward)
                .filter(|rule| rule.verdict == Verdict::RejectAdminProhibited)
                .collect();
            assert_eq!(rejects.len(), 2, "{state:?}: one rejection per uplink");
            for (rule, uplink) in rejects.into_iter().zip(["enp3s0", "wlo1"]) {
                let nf = NetlinkBackend::filter_rule(&forward, &rule.matches, rule)
                    .expect("the rejection translates");
                let interfaces = expressions(
                    &NfRule::default()
                        .iiface("helios0")
                        .expect("valid interface name")
                        .oiface(uplink)
                        .expect("valid interface name"),
                );

                let mut expected = ipv6_guard.to_vec();
                expected.extend(interfaces);
                expected.push(reject.clone());
                assert_eq!(expressions(&nf), expected, "{state:?}: {rule}");
            }
        }
    }

    /// An IPv6 Meshnet routing peer's local-network drops go through the
    /// IPv6 path of `match_net` for both addresses, each behind the
    /// `meta nfproto ipv6` guard, with no IPv4 guard. The policy is built in
    /// code: the configuration refuses IPv6 Meshnet peers.
    #[test]
    fn an_ipv6_meshnet_local_network_drop_translates_behind_ipv6_guards() {
        let mut policy = client_internet_policy();
        policy.allow_client_internet = false;
        policy.nordvpn_meshnet = Some(aether::NordvpnMeshnetPolicy {
            iface: "nordlynx".into(),
            fwmark: 0xe1f1,
            peer_cidrs: vec!["2001:db8::5/128".into()],
            traffic_routing_peer_cidrs: vec!["2001:db8::5/128".into()],
            local_network_peer_cidrs: Vec::new(),
            inbound_tcp_ports: Vec::new(),
            inbound_udp_ports: Vec::new(),
            allow_icmp: false,
        });
        let rs = render(&policy, TunnelState::Up).expect("valid test policy");
        assert!(NetlinkBackend::new().build_batch(&rs).is_ok());

        let forward = chain(ChainKind::Forward.as_str());
        let drops: Vec<&Rule> = rs
            .chain(ChainKind::Forward)
            .filter(|rule| {
                rule.verdict == Verdict::Drop
                    && rule.matches.contains(&Match::InIface("nordlynx".into()))
            })
            .collect();
        assert_eq!(drops.len(), 2, "one drop per local IPv6 network");
        let ipv6_guard = [
            RawExpression::from(Meta::new(MetaType::NfProto)),
            RawExpression::from(Cmp::new(CmpOp::Eq, [10u8])),
        ];
        for (rule, local) in drops.into_iter().zip(["fc00::/7", "fe80::/10"]) {
            let nf = NetlinkBackend::filter_rule(&forward, &rule.matches, rule)
                .expect("the drop rule translates");
            let expected = NfRule::default()
                .iiface("nordlynx")
                .expect("valid interface name")
                .saddr(network("2001:db8::5/128").ip())
                .dnetwork(network(local))
                .expect("valid IPv6 network")
                .drop();
            let translated = expressions(&nf);
            assert_eq!(translated, expressions(&expected), "{rule}");

            let guards = |guard: &[RawExpression]| {
                translated.windows(2).filter(|pair| *pair == guard).count()
            };
            assert_eq!(guards(&ipv6_guard), 2, "source and destination: {rule}");
            assert_eq!(guards(&ipv4_guard()), 0, "{rule}");
        }
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
            default_verdict: DefaultVerdict::Drop,
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
            wg_iface: "helios0".into(),
            masquerade_out: vec!["eth0".into()],
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_ok());

        let mut accept_by_default = ruleset;
        accept_by_default.default_verdict = DefaultVerdict::Accept;
        accept_by_default.masquerade_out = Vec::new();
        assert!(NetlinkBackend::new()
            .build_batch(&accept_by_default)
            .is_ok());
    }

    #[test]
    fn mss_clamping_is_encoded_for_ipv4_and_ipv6_in_the_whole_batch() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
            rules: Vec::new(),
            mss_clamp: Some(1280),
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };

        let bytes = NetlinkBackend::new()
            .build_batch(&ruleset)
            .unwrap()
            .finalize();
        assert!(bytes.windows(6).any(|w| w == b"exthdr"));
        assert!(bytes.windows(7).any(|w| w == b"payload"));
        assert!(bytes.windows(2).any(|w| w == 1280u16.to_be_bytes()));
        assert!(bytes.windows(2).any(|w| w == 1260u16.to_be_bytes()));
        assert_eq!(bytes.windows(7).filter(|w| *w == b"helios0").count(), 4);
        assert!(bytes.windows(4).any(|w| w == (-150i32).to_be_bytes()));

        let mut ipv4_only = ruleset.clone();
        ipv4_only.mss_clamp = Some(1239);
        let bytes = NetlinkBackend::new()
            .build_batch(&ipv4_only)
            .unwrap()
            .finalize();
        assert!(!bytes.windows(2).any(|w| w == 1219u16.to_be_bytes()));

        ipv4_only.wg_iface.clear();
        let bytes = NetlinkBackend::new()
            .build_batch(&ipv4_only)
            .unwrap()
            .finalize();
        assert!(!bytes.windows(6).any(|w| w == b"exthdr"));
    }

    #[test]
    fn mss_rules_are_scoped_family_specific_syn_only_and_have_no_verdict() {
        use rustables::expr::{
            Bitwise, Cmp, CmpOp, Exthdr, HighLevelPayload, Immediate, Meta, MetaType,
            RawExpression, Register, TCPHeaderField, TransportHeaderField,
        };

        let table = Table::new(ProtocolFamily::Inet).with_name("helios");
        let chain = Chain::new(&table).with_name("mss");
        let expressions = |rule: NfRule| {
            rule.get_expressions()
                .map(|list| list.iter().cloned().collect::<Vec<RawExpression>>())
                .unwrap_or_default()
        };
        for (family, mss, incoming) in [(2, 1280, true), (10, 1260, false)] {
            let rule =
                NetlinkBackend::mss_clamp_rule(&chain, family, mss, "helios0", incoming).unwrap();
            let scoped = if incoming {
                NfRule::new(&chain).unwrap().iiface("helios0").unwrap()
            } else {
                NfRule::new(&chain).unwrap().oiface("helios0").unwrap()
            };
            let expected = scoped
                .with_expr(Meta::new(MetaType::NfProto))
                .with_expr(Cmp::new(CmpOp::Eq, [family]))
                .with_expr(Meta::new(MetaType::L4Proto))
                .with_expr(Cmp::new(CmpOp::Eq, [6]))
                .with_expr(
                    HighLevelPayload::Transport(TransportHeaderField::Tcp(TCPHeaderField::Flags))
                        .build(),
                )
                .with_expr(Bitwise::new([0x02], [0]).unwrap())
                .with_expr(Cmp::new(CmpOp::Eq, [0x02]))
                .with_expr(Immediate::new_data(
                    mss.to_be_bytes().to_vec(),
                    Register::Reg1,
                ))
                .with_expr(Exthdr::tcp_mss_store(Register::Reg1));
            assert_eq!(expressions(rule), expressions(expected));
        }
    }

    #[test]
    fn two_port_sets_are_refused_instead_of_becoming_a_partial_rule() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
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
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_err());
    }

    #[test]
    fn anonymous_counters_and_logs_translate_before_any_side_effect() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
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
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_ok());
    }

    #[test]
    fn named_counters_fail_translation_instead_of_becoming_anonymous() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
            rules: vec![crate::ruleset::Rule {
                chain: ChainKind::Input,
                matches: Vec::new(),
                actions: vec![Action::Counter(Counter::Named("drop-invalid".into()))],
                verdict: Verdict::Drop,
                note: None,
            }],
            mss_clamp: None,
            wg_iface: "helios0".into(),
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
            default_verdict: DefaultVerdict::Drop,
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
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };

        assert!(NetlinkBackend::new().build_batch(&ruleset).is_err());
    }

    #[test]
    fn rate_limits_fail_translation_instead_of_being_ignored() {
        let ruleset = Ruleset {
            default_verdict: DefaultVerdict::Drop,
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
            wg_iface: "helios0".into(),
            masquerade_out: Vec::new(),
        };

        let error = match NetlinkBackend::new().build_batch(&ruleset) {
            Ok(_) => panic!("a rate limit must not disappear during translation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("rate limit") && error.contains("rustables 0.8.8"));
    }
}
