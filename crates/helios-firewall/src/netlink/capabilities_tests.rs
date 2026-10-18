use rustables::sys;

use super::NetlinkBackend;
use crate::ruleset::{
    Action, AddressFamily, ChainKind, Counter, DefaultVerdict, Icmpv4Type, Match, Rule, Ruleset,
    Verdict,
};

fn ruleset(matches: Vec<Match>, actions: Vec<Action>) -> Ruleset {
    Ruleset {
        default_verdict: DefaultVerdict::Drop,
        rules: vec![Rule {
            chain: ChainKind::Input,
            matches,
            actions,
            verdict: Verdict::Drop,
            note: None,
        }],
        mss_clamp: None,
        wg_iface: "helios0".into(),
        masquerade_out: Vec::new(),
    }
}

fn attributes(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap());
        assert!(length >= 4 && length <= bytes.len());
        result.push((kind, &bytes[4..length]));
        bytes = &bytes[(length + 3) & !3..];
    }
    result
}

fn attribute<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> &'a [u8] {
    attrs.iter().find(|(id, _)| *id & 0x3fff == kind).unwrap().1
}

fn messages(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        assert!(length >= 20 && length <= bytes.len());
        result.push((kind & 0xff, &bytes[20..length]));
        bytes = &bytes[(length + 3) & !3..];
    }
    result
}

type Attributes<'a> = Vec<(u16, &'a [u8])>;

fn expressions(payload: &[u8]) -> Vec<(&str, Attributes<'_>)> {
    let rule = attributes(payload);
    attributes(attribute(&rule, sys::NFTA_RULE_EXPRESSIONS))
        .into_iter()
        .map(|(_, payload)| {
            let expr = attributes(payload);
            let name = attribute(&expr, sys::NFTA_EXPR_NAME);
            // NLA_STRING allows an optional NUL; rustables omits it.
            // https://github.com/torvalds/linux/blob/master/lib/nlattr.c
            let name = name.strip_suffix(b"\0").unwrap_or(name);
            (
                std::str::from_utf8(name).unwrap(),
                attributes(attribute(&expr, sys::NFTA_EXPR_DATA)),
            )
        })
        .collect()
}

#[test]
fn named_counters_are_declared_once_before_their_references() {
    let mut rs = ruleset(
        Vec::new(),
        vec![Action::Counter(Counter::Named("drops".into()))],
    );
    rs.rules.push(rs.rules[0].clone());
    let bytes = NetlinkBackend::new().build_batch(&rs).unwrap().finalize();
    let messages = messages(&bytes);
    let objects: Vec<_> = messages
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| *kind == sys::NFT_MSG_NEWOBJ as u16)
        .collect();
    assert_eq!(objects.len(), 1);
    let (index, (_, payload)) = objects[0];
    let object = attributes(payload);
    assert_eq!(attribute(&object, sys::NFTA_OBJ_TABLE), b"helios");
    assert_eq!(attribute(&object, sys::NFTA_OBJ_NAME), b"drops");
    assert_eq!(attribute(&object, sys::NFTA_OBJ_TYPE), 1u32.to_be_bytes());
    assert!(object
        .iter()
        .any(|(kind, _)| *kind & 0x3fff == sys::NFTA_OBJ_DATA && *kind & 0x8000 != 0));
    let counters = attributes(attribute(&object, sys::NFTA_OBJ_DATA));
    assert_eq!(attribute(&counters, sys::NFTA_COUNTER_BYTES), [0; 8]);
    assert_eq!(attribute(&counters, sys::NFTA_COUNTER_PACKETS), [0; 8]);
    let rules: Vec<_> = messages
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| *kind == sys::NFT_MSG_NEWRULE as u16)
        .collect();
    assert_eq!(rules.len(), 2);
    for (rule_index, (_, payload)) in rules {
        assert!(rule_index > index);
        let exprs = expressions(payload);
        assert_eq!(exprs[0].0, "objref");
        assert_eq!(
            attribute(&exprs[0].1, sys::NFTA_OBJREF_IMM_TYPE),
            1u32.to_be_bytes()
        );
        assert_eq!(attribute(&exprs[0].1, sys::NFTA_OBJREF_IMM_NAME), b"drops");
    }
}

#[test]
fn invalid_named_counters_refuse_the_whole_batch() {
    for name in [String::new(), "bad\0name".into(), "a".repeat(256)] {
        assert!(NetlinkBackend::new()
            .build_batch(&ruleset(
                Vec::new(),
                vec![Action::Counter(Counter::Named(name))]
            ))
            .is_err());
    }
}

#[test]
fn icmpv4_types_encode_family_protocol_and_the_type_octet() {
    for (kind, number) in [
        (Icmpv4Type::EchoReply, 0),
        (Icmpv4Type::DestinationUnreachable, 3),
        (Icmpv4Type::EchoRequest, 8),
        (Icmpv4Type::TimeExceeded, 11),
        (Icmpv4Type::ParameterProblem, 12),
    ] {
        let bytes = NetlinkBackend::new()
            .build_batch(&ruleset(vec![Match::Icmpv4Type(kind)], Vec::new()))
            .unwrap()
            .finalize();
        let messages = messages(&bytes);
        let (_, payload) = messages
            .iter()
            .find(|(kind, _)| *kind == sys::NFT_MSG_NEWRULE as u16)
            .unwrap();
        let exprs = expressions(payload);
        assert_eq!(
            exprs.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            ["meta", "cmp", "meta", "cmp", "payload", "cmp", "immediate"]
        );
        let cmp = |index: usize| {
            let data = attributes(attribute(&exprs[index].1, sys::NFTA_CMP_DATA));
            attribute(&data, sys::NFTA_DATA_VALUE)
        };
        assert_eq!(cmp(1), [2]);
        assert_eq!(cmp(3), [1]);
        assert_eq!(cmp(5), [number]);
        assert_eq!(
            attribute(&exprs[4].1, sys::NFTA_PAYLOAD_BASE),
            2u32.to_be_bytes()
        );
        assert_eq!(
            attribute(&exprs[4].1, sys::NFTA_PAYLOAD_OFFSET),
            0u32.to_be_bytes()
        );
        assert_eq!(
            attribute(&exprs[4].1, sys::NFTA_PAYLOAD_LEN),
            1u32.to_be_bytes()
        );
    }
}

#[test]
fn fib_existence_uses_one_byte_and_an_explicit_mark_decision() {
    for use_mark in [false, true] {
        for present in [false, true] {
            let bytes = NetlinkBackend::new()
                .build_batch(&ruleset(
                    vec![
                        Match::InIface("eth0".into()),
                        Match::FibSourceRoute { use_mark, present },
                    ],
                    Vec::new(),
                ))
                .unwrap()
                .finalize();
            let messages = messages(&bytes);
            let (_, payload) = messages
                .iter()
                .find(|(kind, _)| *kind == sys::NFT_MSG_NEWRULE as u16)
                .unwrap();
            let exprs = expressions(payload);
            let index = exprs.iter().position(|(name, _)| *name == "fib").unwrap();
            assert_eq!(
                attribute(&exprs[index].1, sys::NFTA_FIB_DREG),
                1u32.to_be_bytes()
            );
            assert_eq!(
                attribute(&exprs[index].1, sys::NFTA_FIB_RESULT),
                1u32.to_be_bytes()
            );
            assert_eq!(
                attribute(&exprs[index].1, sys::NFTA_FIB_FLAGS),
                (41u32 | if use_mark { 4 } else { 0 }).to_be_bytes()
            );
            let cmp = attributes(attribute(&exprs[index + 1].1, sys::NFTA_CMP_DATA));
            assert_eq!(attribute(&cmp, sys::NFTA_DATA_VALUE), [u8::from(present)]);
        }
    }
}

#[test]
fn fib_refuses_unscoped_and_output_lookups_before_sending() {
    let mut rs = ruleset(
        vec![Match::FibSourceRoute {
            use_mark: true,
            present: false,
        }],
        Vec::new(),
    );
    assert!(NetlinkBackend::new().build_batch(&rs).is_err());
    rs.rules[0].chain = ChainKind::Output;
    rs.rules[0].matches.insert(0, Match::InIface("eth0".into()));
    assert!(NetlinkBackend::new().build_batch(&rs).is_err());
}

/// The rejection of the tunnel clients' IPv6 egress in `prerouting`.
fn prerouting_rejection(chain: ChainKind) -> Ruleset {
    let mut rs = ruleset(
        vec![
            Match::Family(AddressFamily::Ipv6),
            Match::InIface("helios0".into()),
            Match::FibDestinationOutIface("enp3s0".into()),
        ],
        Vec::new(),
    );
    rs.rules[0].chain = chain;
    rs.rules[0].verdict = Verdict::RejectAdminProhibited;
    rs
}

#[test]
fn fib_destination_lookup_compares_the_interface_its_route_names() {
    let bytes = NetlinkBackend::new()
        .build_batch(&prerouting_rejection(ChainKind::Prerouting))
        .unwrap()
        .finalize();
    let messages = messages(&bytes);
    let (_, payload) = messages
        .iter()
        .find(|(kind, _)| *kind == sys::NFT_MSG_NEWRULE as u16)
        .unwrap();
    let exprs = expressions(payload);
    let index = exprs.iter().position(|(name, _)| *name == "fib").unwrap();
    assert_eq!(
        attribute(&exprs[index].1, sys::NFTA_FIB_DREG),
        1u32.to_be_bytes()
    );
    assert_eq!(
        attribute(&exprs[index].1, sys::NFTA_FIB_RESULT),
        sys::NFT_FIB_RESULT_OIFNAME.to_be_bytes()
    );
    assert_eq!(
        attribute(&exprs[index].1, sys::NFTA_FIB_FLAGS),
        sys::NFTA_FIB_F_DADDR.to_be_bytes()
    );
    let cmp = attributes(attribute(&exprs[index + 1].1, sys::NFTA_CMP_DATA));
    assert_eq!(attribute(&cmp, sys::NFTA_DATA_VALUE), b"enp3s0\0");
    assert_eq!(exprs.last().unwrap().0, "reject");
}

// <linux/netfilter.h>: verdicts and the IPv4/IPv6 hook numbers.
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_INET_PRE_ROUTING: u32 = 0;

/// A `drop` policy on `prerouting` would cut every packet, the gateway's own
/// included: the chain keeps `accept` while the filtering chains take the
/// ruleset's default.
#[test]
fn the_prerouting_chain_keeps_the_accept_policy_under_a_drop_default() {
    let bytes = NetlinkBackend::new()
        .build_batch(&prerouting_rejection(ChainKind::Prerouting))
        .unwrap()
        .finalize();
    let chains: Vec<Attributes<'_>> = messages(&bytes)
        .into_iter()
        .filter(|(kind, _)| *kind == sys::NFT_MSG_NEWCHAIN as u16)
        .map(|(_, payload)| attributes(payload))
        .collect();
    let named = |name: &str| {
        chains
            .iter()
            .find(|chain| {
                let value = attribute(chain, sys::NFTA_CHAIN_NAME);
                value.strip_suffix(b"\0").unwrap_or(value) == name.as_bytes()
            })
            .unwrap_or_else(|| panic!("no `{name}` chain"))
    };
    let prerouting = named("prerouting");
    assert_eq!(
        attribute(prerouting, sys::NFTA_CHAIN_POLICY),
        NF_ACCEPT.to_be_bytes()
    );
    let hook = attributes(attribute(prerouting, sys::NFTA_CHAIN_HOOK));
    assert_eq!(
        attribute(&hook, sys::NFTA_HOOK_HOOKNUM),
        NF_INET_PRE_ROUTING.to_be_bytes()
    );
    assert_eq!(
        attribute(named("input"), sys::NFTA_CHAIN_POLICY),
        NF_DROP.to_be_bytes()
    );
}

/// The kernel only accepts an egress-interface lookup in `prerouting`,
/// `input` and `forward`: an `output` one is refused before sending, rather
/// than failing the whole transaction in the kernel.
#[test]
fn fib_destination_lookup_is_refused_in_output() {
    assert!(NetlinkBackend::new()
        .build_batch(&prerouting_rejection(ChainKind::Output))
        .is_err());
}
