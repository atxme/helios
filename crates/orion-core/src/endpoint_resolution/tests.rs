use std::net::SocketAddr;

use super::*;

fn addr(value: &str) -> SocketAddr {
    value.parse().unwrap()
}

fn addrs(values: &[&str]) -> Vec<SocketAddr> {
    values.iter().map(|value| addr(value)).collect()
}

/// The dual-stack case: the resolver sorted IPv6 first, and the families
/// alternate from there, each keeping the resolver's own order.
#[test]
fn families_are_interleaved_starting_with_ipv6() {
    let ordered = rfc8305_order(addrs(&[
        "[2001:db8::1]:51821",
        "[2001:db8::2]:51821",
        "[2001:db8::3]:51821",
        "203.0.113.10:51821",
        "203.0.113.11:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&[
            "[2001:db8::1]:51821",
            "203.0.113.10:51821",
            "[2001:db8::2]:51821",
            "203.0.113.11:51821",
            "[2001:db8::3]:51821",
        ])
    );
}

/// RFC 8305 §4 keeps the family the resolver put first. A resolver that
/// sorted IPv4 first did so because IPv6 is unusable here (RFC 6724), and
/// overruling it would pin an un-raced tunnel endpoint to the dead family.
#[test]
fn the_family_the_resolver_put_first_leads() {
    let ordered = rfc8305_order(addrs(&[
        "203.0.113.10:51821",
        "203.0.113.11:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&[
            "203.0.113.10:51821",
            "[2001:db8::1]:51821",
            "203.0.113.11:51821",
        ])
    );
}

#[test]
fn an_ipv4_only_answer_keeps_its_order() {
    let ordered = rfc8305_order(addrs(&["203.0.113.10:51821", "203.0.113.11:51821"]));
    assert_eq!(
        ordered,
        addrs(&["203.0.113.10:51821", "203.0.113.11:51821"])
    );
}

#[test]
fn an_ipv6_only_answer_keeps_its_order() {
    let ordered = rfc8305_order(addrs(&["[2001:db8::2]:51821", "[2001:db8::1]:51821"]));
    assert_eq!(
        ordered,
        addrs(&["[2001:db8::2]:51821", "[2001:db8::1]:51821"])
    );
}

/// `getaddrinfo` returns one entry per socket type unless told otherwise:
/// the same address several times is one candidate, at its first position.
#[test]
fn duplicates_are_tried_once() {
    let ordered = rfc8305_order(addrs(&[
        "[2001:db8::1]:51821",
        "[2001:db8::1]:51821",
        "203.0.113.10:51821",
        "203.0.113.10:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&["[2001:db8::1]:51821", "203.0.113.10:51821"])
    );
}

/// A mapped address is the IPv4 address it carries — and the duplicate of
/// the `A` record when both come back.
#[test]
fn an_ipv4_mapped_address_is_read_as_ipv4() {
    let ordered = rfc8305_order(addrs(&[
        "[::ffff:203.0.113.10]:51821",
        "203.0.113.10:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&["203.0.113.10:51821", "[2001:db8::1]:51821"])
    );
}

#[test]
fn a_zero_port_is_never_a_candidate() {
    assert!(rfc8305_order(addrs(&["203.0.113.10:0"])).is_empty());
    assert!(rfc8305_order(Vec::new()).is_empty());
}

/// A literal is its own and only candidate, and no resolver is asked.
#[tokio::test]
async fn a_literal_endpoint_is_its_own_single_candidate() {
    assert_eq!(
        resolve_candidates("[2001:db8::1]:51821").await.unwrap(),
        addrs(&["[2001:db8::1]:51821"])
    );
    assert_eq!(
        resolve_candidates("203.0.113.10:51821").await.unwrap(),
        addrs(&["203.0.113.10:51821"])
    );
    assert_eq!(
        rfc8305_order(addrs(&["203.0.113.10:51821"])),
        addrs(&["203.0.113.10:51821"])
    );
}

#[tokio::test]
async fn a_literal_without_a_usable_port_is_refused_by_name() {
    let error = resolve_candidates("203.0.113.10:0").await.unwrap_err();
    assert!(format!("{error:#}").contains("203.0.113.10:0"), "{error:#}");
}

#[test]
fn the_data_plane_only_takes_literals() {
    assert_eq!(
        literal_endpoint("[2001:db8::1]:51820").unwrap(),
        addr("[2001:db8::1]:51820")
    );
    assert_eq!(
        literal_endpoint("203.0.113.10:51820").unwrap(),
        addr("203.0.113.10:51820")
    );
    assert!(literal_endpoint("gateway.example:51820").is_err());
    assert!(literal_endpoint("2001:db8::1:51820").is_err());
    assert!(literal_endpoint("203.0.113.10:0").is_err());
}

#[test]
fn same_host_ignores_ports_brackets_case_and_a_final_dot() {
    assert!(same_host("gateway.example:51820", "Gateway.Example.:51821"));
    assert!(same_host("[2001:db8::1]:51820", "[2001:db8::1]:51821"));
    assert!(same_host("203.0.113.10:51820", "203.0.113.10:51821"));
    assert!(!same_host("gateway.example:51820", "nego.example:51821"));
    // A name and the address it may resolve to are still two hosts: they
    // are resolved separately, never merged.
    assert!(!same_host("gateway.example:51820", "203.0.113.10:51821"));
    assert!(!same_host("gateway.example", "gateway.example:51821"));
}

#[test]
fn the_port_is_read_from_the_endpoint() {
    assert_eq!(port_of("gateway.example:51820"), Some(51820));
    assert_eq!(port_of("[2001:db8::1]:51820"), Some(51820));
    assert_eq!(port_of("gateway.example:0"), None);
    assert_eq!(port_of("gateway.example"), None);
}

#[test]
fn the_family_is_named() {
    assert_eq!(family(&addr("[2001:db8::1]:51820")), "IPv6");
    assert_eq!(family(&addr("203.0.113.10:51820")), "IPv4");
}
