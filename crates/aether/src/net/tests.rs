use super::*;

/// The prefix of the specification's own example (§5.1).
const PREFIX: &str = "fd3c:91a2:7e04::1/64";
/// The peer VIP of the same example.
const PEER_V6: &str = "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128";

fn prefix() -> TunnelPrefixV6 {
    PREFIX.parse().expect("the specification's example prefix")
}

fn v6(text: &str) -> Ipv6Addr {
    text.parse().expect("test address")
}

// --- TunnelPrefixV6: what §2.4 accepts ---------------------------------------

#[test]
fn the_specification_prefix_is_accepted_and_rendered_back_identically() {
    let prefix = prefix();
    assert_eq!(prefix.to_string(), PREFIX);
    assert_eq!(prefix.network(), v6("fd3c:91a2:7e04::"));
    assert_eq!(prefix.gateway(), v6("fd3c:91a2:7e04::1"));
}

#[test]
fn a_global_id_builds_the_prefix_with_a_zero_subnet_id() {
    let prefix = TunnelPrefixV6::from_global_id([0x3c, 0x91, 0xa2, 0x7e, 0x04]);
    assert_eq!(prefix, self::prefix());
    assert_eq!(prefix.to_string(), PREFIX);
}

#[test]
fn every_global_id_gives_a_prefix_the_parser_accepts() {
    for global_id in [[0; 5], [0xff; 5], [0x01, 0x23, 0x45, 0x67, 0x89]] {
        let prefix = TunnelPrefixV6::from_global_id(global_id);
        assert_eq!(prefix.to_string().parse::<TunnelPrefixV6>(), Ok(prefix));
    }
}

#[test]
fn a_non_canonical_spelling_is_accepted_and_rendered_in_rfc_5952_form() {
    let prefix: TunnelPrefixV6 = "FD3C:91A2:7E04:0000:0:0:0:1/64".parse().expect("prefix");
    assert_eq!(prefix.to_string(), PREFIX);
}

// --- TunnelPrefixV6: what §2.4 refuses ---------------------------------------

fn refusal(text: &str) -> AddressError {
    match text.parse::<TunnelPrefixV6>() {
        Ok(prefix) => panic!("{text} was accepted as {prefix}"),
        Err(error) => error,
    }
}

#[test]
fn an_undefined_ula_with_the_l_bit_clear_is_refused() {
    assert_eq!(
        refusal("fc3c:91a2:7e04::1/64"),
        AddressError::UndefinedUla(v6("fc3c:91a2:7e04::1"))
    );
}

#[test]
fn a_global_unicast_prefix_is_refused() {
    assert_eq!(
        refusal("2001:db8:1::1/64"),
        AddressError::NotUla(v6("2001:db8:1::1"))
    );
}

#[test]
fn link_local_and_loopback_are_not_ula() {
    assert_eq!(refusal("fe80::1/64"), AddressError::NotUla(v6("fe80::1")));
    assert_eq!(refusal("::1/64"), AddressError::NotUla(v6("::1")));
}

#[test]
fn a_length_other_than_64_is_refused() {
    for (text, found) in [
        ("fd3c:91a2:7e04::1/48", 48),
        ("fd3c:91a2:7e04::1/56", 56),
        ("fd3c:91a2:7e04::1/80", 80),
        ("fd3c:91a2:7e04::1/128", 128),
        ("fd3c:91a2:7e04::1/0", 0),
    ] {
        assert_eq!(
            refusal(text),
            AddressError::WrongPrefixLength {
                expected: 64,
                found
            },
            "{text}"
        );
    }
}

#[test]
fn a_gateway_other_than_host_one_is_refused() {
    for text in [
        "fd3c:91a2:7e04::/64",
        "fd3c:91a2:7e04::2/64",
        "fd3c:91a2:7e04::1:1/64",
        "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/64",
    ] {
        let host = v6(text.trim_end_matches("/64"));
        assert_eq!(
            refusal(text),
            AddressError::GatewayNotHostOne(host),
            "{text}"
        );
    }
}

#[test]
fn a_non_zero_subnet_id_is_refused() {
    assert_eq!(
        refusal("fd3c:91a2:7e04:1::1/64"),
        AddressError::NonZeroSubnetId(v6("fd3c:91a2:7e04:1::1"))
    );
}

#[test]
fn an_ipv4_address_is_refused_as_a_tunnel_prefix() {
    assert_eq!(
        refusal("100.64.0.1/10"),
        AddressError::NotIpv6(Ipv4Addr::new(100, 64, 0, 1))
    );
}

#[test]
fn a_zone_identifier_is_refused() {
    assert_eq!(
        refusal("fd3c:91a2:7e04::1%eth0/64"),
        AddressError::ZoneId("fd3c:91a2:7e04::1%eth0/64".into())
    );
}

#[test]
fn a_prefix_without_its_length_is_refused() {
    assert_eq!(
        refusal("fd3c:91a2:7e04::1"),
        AddressError::MissingPrefixLength("fd3c:91a2:7e04::1".into())
    );
}

#[test]
fn a_length_not_in_canonical_decimal_is_refused() {
    for len in ["", "064", "+64", " 64", "64 ", "0x40", "256", "-1"] {
        let text = format!("fd3c:91a2:7e04::1/{len}");
        assert_eq!(
            refusal(&text),
            AddressError::InvalidPrefixLength(len.into()),
            "{text:?}"
        );
    }
}

#[test]
fn text_that_is_not_an_address_is_refused() {
    for (text, address) in [
        ("fd3c:91a2:7e04:::1/64", "fd3c:91a2:7e04:::1"),
        (" fd3c:91a2:7e04::1/64", " fd3c:91a2:7e04::1"),
        ("[fd3c:91a2:7e04::1]/64", "[fd3c:91a2:7e04::1]"),
        ("/64", ""),
    ] {
        assert_eq!(
            refusal(text),
            AddressError::InvalidAddress(address.into()),
            "{text:?}"
        );
    }
}

// --- TunnelPrefixV6: serde ---------------------------------------------------

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Persisted {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wg_address_v6: Option<TunnelPrefixV6>,
}

#[test]
fn the_persisted_prefix_round_trips_byte_for_byte() {
    let file = format!("wg_address_v6 = \"{PREFIX}\"\n");
    let read: Persisted = toml::from_str(&file).expect("read");
    assert_eq!(read.wg_address_v6, Some(prefix()));
    assert_eq!(toml::to_string(&read).expect("write"), file);
}

#[test]
fn an_absent_prefix_writes_nothing() {
    let read: Persisted = toml::from_str("").expect("read");
    assert_eq!(read.wg_address_v6, None);
    assert_eq!(toml::to_string(&read).expect("write"), "");
}

#[test]
fn a_refused_prefix_fails_deserialization_naming_the_reason() {
    let error = toml::from_str::<Persisted>("wg_address_v6 = \"fc3c:91a2:7e04::1/64\"\n")
        .expect_err("fc00::/8 refused");
    let message = error.to_string();
    assert!(message.contains("wg_address_v6"), "{message}");
    assert!(message.contains("fc00::/8"), "{message}");
}

// --- Interface identifiers (§3.2) --------------------------------------------

#[test]
fn excluded_identifiers_stop_exactly_at_their_boundaries() {
    assert!(is_excluded_iid(0));
    assert!(is_excluded_iid(1));
    assert!(!is_excluded_iid(2));
    assert!(!is_excluded_iid(0xfdff_ffff_ffff_ff7f));
    assert!(is_excluded_iid(0xfdff_ffff_ffff_ff80));
    assert!(is_excluded_iid(u64::MAX));
}

#[test]
fn a_peer_vip_is_built_from_any_identifier_that_is_not_excluded() {
    let prefix = prefix();
    assert_eq!(prefix.peer_vip(2), Ok(v6("fd3c:91a2:7e04::2")));
    assert_eq!(
        prefix.peer_vip(0x8a1f_3b2c_9d40_e517),
        Ok(v6("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517"))
    );
    assert_eq!(
        prefix.peer_vip(0xfdff_ffff_ffff_ff7f),
        Ok(v6("fd3c:91a2:7e04:0:fdff:ffff:ffff:ff7f"))
    );
}

#[test]
fn no_peer_vip_is_built_from_an_excluded_identifier() {
    let prefix = prefix();
    for iid in [0, 1, 0xfdff_ffff_ffff_ff80, u64::MAX] {
        assert_eq!(
            prefix.peer_vip(iid),
            Err(AddressError::ExcludedIid(iid)),
            "{iid:#x}"
        );
    }
}

#[test]
fn the_prefix_contains_its_whole_64_and_nothing_else() {
    let prefix = prefix();
    assert!(prefix.contains(prefix.network()));
    assert!(prefix.contains(prefix.gateway()));
    assert!(prefix.contains(v6("fd3c:91a2:7e04:0:ffff:ffff:ffff:ffff")));
    assert!(!prefix.contains(v6("fd3c:91a2:7e04:1::2")));
    assert!(!prefix.contains(v6("fd3c:91a2:7e05::2")));
    assert!(!prefix.contains(v6("::ffff:100.64.0.1")));
}

// --- Peer IPv6 VIP against the prefix (§5.2) ---------------------------------

#[test]
fn a_peer_vip_inside_the_prefix_is_accepted() {
    assert_eq!(
        prefix().check_peer_vip(v6(PEER_V6.trim_end_matches("/128"))),
        Ok(())
    );
}

#[test]
fn a_peer_vip_outside_the_prefix_is_refused() {
    let vip = v6("fd3c:91a2:7e05::2");
    assert_eq!(
        prefix().check_peer_vip(vip),
        Err(AddressError::OutsideTunnelPrefix {
            vip,
            prefix: prefix()
        })
    );
}

#[test]
fn the_gateway_address_is_refused_as_a_peer_vip() {
    let gateway = prefix().gateway();
    assert_eq!(
        prefix().check_peer_vip(gateway),
        Err(AddressError::GatewayAddress(gateway))
    );
}

#[test]
fn an_excluded_identifier_is_refused_as_a_peer_vip() {
    for (text, iid) in [
        ("fd3c:91a2:7e04::", 0),
        (
            "fd3c:91a2:7e04:0:fdff:ffff:ffff:ff80",
            0xfdff_ffff_ffff_ff80,
        ),
        ("fd3c:91a2:7e04:0:ffff:ffff:ffff:ffff", u64::MAX),
    ] {
        assert_eq!(
            prefix().check_peer_vip(v6(text)),
            Err(AddressError::ExcludedIid(iid)),
            "{text}"
        );
    }
    assert_eq!(
        prefix().check_peer_vip(v6("fd3c:91a2:7e04:0:fdff:ffff:ffff:ff7f")),
        Ok(())
    );
}

#[test]
fn a_peer_without_ipv6_passes_with_or_without_a_prefix() {
    let vips = PeerVips {
        v4: Ipv4Addr::new(100, 64, 98, 223),
        v6: None,
    };
    assert_eq!(vips.check_against(None), Ok(()));
    assert_eq!(vips.check_against(Some(&prefix())), Ok(()));
}

#[test]
fn a_peer_ipv6_without_a_gateway_prefix_is_refused() {
    let vips = PeerVips::parse("100.64.98.223/32", Some(PEER_V6)).expect("vips");
    let vip = vips.v6.expect("v6");
    assert_eq!(
        vips.check_against(None),
        Err(AddressError::V6WithoutTunnelPrefix(vip))
    );
    assert_eq!(vips.check_against(Some(&prefix())), Ok(()));
}

#[test]
fn check_against_applies_the_prefix_rules() {
    let vips = PeerVips::parse("100.64.98.223/32", Some("fd3c:91a2:7e04::1/128")).expect("vips");
    assert_eq!(
        vips.check_against(Some(&prefix())),
        Err(AddressError::GatewayAddress(prefix().gateway()))
    );
}

// --- PeerVips text forms -----------------------------------------------------

#[test]
fn the_persisted_peer_addresses_round_trip_byte_for_byte() {
    let vips = PeerVips::parse("100.64.98.223/32", Some(PEER_V6)).expect("vips");
    assert_eq!(vips.v4, Ipv4Addr::new(100, 64, 98, 223));
    assert_eq!(vips.address(), "100.64.98.223/32");
    assert_eq!(vips.address_v6().as_deref(), Some(PEER_V6));
}

#[test]
fn a_peer_without_address_v6_renders_none() {
    let vips = PeerVips::parse("100.64.98.223/32", None).expect("vips");
    assert_eq!(vips.v6, None);
    assert_eq!(vips.address(), "100.64.98.223/32");
    assert_eq!(vips.address_v6(), None);
}

#[test]
fn an_ipv4_vip_must_be_a_single_host() {
    for (text, found) in [("100.64.98.223/10", 10), ("100.64.98.223/31", 31)] {
        assert_eq!(
            parse_vip_v4(text),
            Err(AddressError::WrongPrefixLength {
                expected: 32,
                found
            }),
            "{text}"
        );
    }
    assert_eq!(
        parse_vip_v4("100.64.98.223"),
        Err(AddressError::MissingPrefixLength("100.64.98.223".into()))
    );
    assert_eq!(
        parse_vip_v4("100.64.98.223/032"),
        Err(AddressError::InvalidPrefixLength("032".into()))
    );
}

#[test]
fn an_ipv4_vip_is_read_only_in_its_canonical_spelling() {
    for address in [
        "100.064.98.223",
        "100.64.98",
        "100.64.98.223.1",
        "0x64.64.98.223",
    ] {
        assert_eq!(
            parse_vip_v4(&format!("{address}/32")),
            Err(AddressError::InvalidAddress(address.into())),
            "{address}"
        );
    }
}

#[test]
fn each_family_is_refused_where_the_other_is_required() {
    assert_eq!(
        parse_vip_v4("fd3c:91a2:7e04::2/32"),
        Err(AddressError::NotIpv4(v6("fd3c:91a2:7e04::2")))
    );
    assert_eq!(
        parse_vip_v6("100.64.98.223/128"),
        Err(AddressError::NotIpv6(Ipv4Addr::new(100, 64, 98, 223)))
    );
    assert_eq!(
        PeerVips::parse("100.64.98.223/32", Some("100.64.98.224/32")),
        Err(AddressError::NotIpv6(Ipv4Addr::new(100, 64, 98, 224)))
    );
}

#[test]
fn an_ipv6_vip_must_be_a_single_host() {
    for (text, found) in [("fd3c:91a2:7e04::2/64", 64), ("fd3c:91a2:7e04::2/127", 127)] {
        assert_eq!(
            parse_vip_v6(text),
            Err(AddressError::WrongPrefixLength {
                expected: 128,
                found
            }),
            "{text}"
        );
    }
    assert_eq!(
        parse_vip_v6("fd3c:91a2:7e04::2"),
        Err(AddressError::MissingPrefixLength(
            "fd3c:91a2:7e04::2".into()
        ))
    );
}

#[test]
fn an_ipv6_vip_with_a_zone_identifier_is_refused() {
    assert_eq!(
        parse_vip_v6("fe80::2%wg0/128"),
        Err(AddressError::ZoneId("fe80::2%wg0/128".into()))
    );
}

#[test]
fn an_invalid_ipv4_address_fails_the_whole_peer() {
    assert_eq!(
        PeerVips::parse("100.64.98.223/31", Some(PEER_V6)),
        Err(AddressError::WrongPrefixLength {
            expected: 32,
            found: 31
        })
    );
}

// --- canonical_source --------------------------------------------------------

#[test]
fn an_ipv4_mapped_source_becomes_ipv4() {
    assert_eq!(
        canonical_source("::ffff:100.64.98.223".parse().expect("mapped")),
        IpAddr::V4(Ipv4Addr::new(100, 64, 98, 223))
    );
}

#[test]
fn a_native_ipv6_source_is_unchanged() {
    let source: IpAddr = "fd3c:91a2:7e04::2".parse().expect("v6");
    assert_eq!(canonical_source(source), source);
    let plain_v4 = IpAddr::V4(Ipv4Addr::new(100, 64, 98, 223));
    assert_eq!(canonical_source(plain_v4), plain_v4);
}

#[test]
fn an_ipv4_compatible_source_stays_ipv6() {
    let source: IpAddr = "::100.64.98.223".parse().expect("compatible");
    assert_eq!(canonical_source(source), source);
    assert!(canonical_source(source).is_ipv6());
}

#[test]
fn loopbacks_are_recognised_after_canonicalization() {
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().expect("mapped loopback");
    assert!(
        !mapped.is_loopback(),
        "the trap: mapped loopback is not IPv6 loopback"
    );
    assert_eq!(canonical_source(mapped), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(canonical_source(mapped).is_loopback());
    assert_eq!(
        canonical_source(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
}
