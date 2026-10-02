//! The tunnel's IPv6 address (`ADRESSAGE-IPV6.md` §2.3, §7.2): one `/128`
//! host next to the IPv4 address, in the document, in a `wg-quick` file and on
//! the editing screen.

use super::fixtures::{CLIENT_PRIVATE, GATEWAY_PUBLIC};
use crate::profile_import::{inspect_profile, parse_profile_import, validate_address_v6};
use crate::ClientProfile;

fn document(address_v6: Option<&str>) -> String {
    let address_v6 = address_v6
        .map(|value| format!(r#", "address_v6": "{value}""#))
        .unwrap_or_default();
    format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": "{CLIENT_PRIVATE}",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "address": "100.64.1.2/32"{address_v6}
            }}
        }}"#
    )
}

fn wg_quick(address: &str) -> String {
    format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress={address}\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=203.0.113.10:51820"
    )
}

#[test]
fn a_document_without_the_key_imports_as_ipv4_only() {
    let profile = parse_profile_import(&document(None), "p.json")
        .unwrap()
        .profile;
    assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
    assert_eq!(profile.address_v6, None);
}

#[test]
fn a_document_with_the_key_imports_both_addresses() {
    let profile = parse_profile_import(&document(Some(" fd3c:91a2:7e04::2/128 ")), "p.json")
        .unwrap()
        .profile;
    assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
    // Trimmed, never rewritten into another spelling.
    assert_eq!(profile.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));
}

/// An empty value is an absent one: a document never makes an empty address
/// mean anything.
#[test]
fn an_empty_key_reads_as_absent() {
    let profile = parse_profile_import(&document(Some("  ")), "p.json")
        .unwrap()
        .profile;
    assert_eq!(profile.address_v6, None);
}

#[test]
fn a_document_with_a_malformed_ipv6_address_is_refused_by_name() {
    for (value, expected) in [
        ("fd3c:91a2:7e04::/64", "/64 au lieu de /128"),
        ("100.64.1.3/32", "est une adresse IPv4"),
        ("fe80::2%eth0/128", "identifiant de zone"),
        ("fd3c:91a2:7e04::2", "notation …/128 attendue"),
        ("fd3c::zz/128", "adresse IP illisible"),
        ("fd3c::2/0128", "longueur de préfixe illisible"),
    ] {
        let error = parse_profile_import(&document(Some(value)), "p.json")
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("adresse IPv6 invalide"),
            "{value}: {error}"
        );
        assert!(error.contains(expected), "{value}: {error}");
    }
}

/// The IPv6 address accompanies an IPv4 one (§2.6): a virtual address that is
/// itself IPv6 would put two IPv6 addresses on the adapter.
#[test]
fn an_ipv6_address_next_to_an_ipv6_virtual_address_is_refused() {
    let raw = document(Some("fd3c:91a2:7e04::2/128")).replace("100.64.1.2/32", "fd00::9/128");
    let error = parse_profile_import(&raw, "p.json")
        .unwrap_err()
        .to_string();
    assert!(error.contains("déjà une adresse IPv6"), "{error}");
}

#[test]
fn the_field_rule_is_the_gateway_rule() {
    assert!(validate_address_v6("fd3c:91a2:7e04::2/128").is_ok());
    assert!(validate_address_v6("FD3C:91A2:7E04:0::2/128").is_ok());
    assert!(validate_address_v6("fd3c:91a2:7e04::2/127").is_err());
    assert!(validate_address_v6("::ffff:100.64.1.2/96").is_err());
}

#[test]
fn a_wg_quick_address_list_lands_one_entry_per_family() {
    for line in [
        "100.64.1.2/32, fd3c:91a2:7e04::2/128",
        "fd3c:91a2:7e04::2/128,100.64.1.2/32",
    ] {
        let profile = parse_profile_import(&wg_quick(line), "p.conf")
            .unwrap()
            .profile;
        assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"), "{line}");
        assert_eq!(
            profile.address_v6.as_deref(),
            Some("fd3c:91a2:7e04::2/128"),
            "{line}"
        );
    }
}

/// A single entry is read as it always was, whatever its family: a file that
/// imported before the IPv6 field still imports the same.
#[test]
fn a_single_wg_quick_address_stays_the_virtual_address() {
    for line in ["100.64.1.2/32", "10.8.0.2/24", "fd00::2/128"] {
        let profile = parse_profile_import(&wg_quick(line), "p.conf")
            .unwrap()
            .profile;
        assert_eq!(profile.address.as_deref(), Some(line));
        assert_eq!(profile.address_v6, None);
    }
}

#[test]
fn an_ambiguous_wg_quick_address_list_is_refused_by_name() {
    for (line, expected) in [
        ("100.64.1.2/32, 100.64.1.3/32", "plusieurs adresses IPv4"),
        (
            "100.64.1.2/32, fd00::2/128, fd00::3/128",
            "plusieurs adresses IPv6",
        ),
        ("fd00::2/128, fd00::3/128", "plusieurs adresses IPv6"),
        ("100.64.1.2/32, fd00::/64", "/64 au lieu de /128"),
        (
            "100.64.1.2/32, fe80::2%eth0/128",
            "n'est pas une adresse IP",
        ),
        ("100.64.1.2/32, pas-une-adresse", "n'est pas une adresse IP"),
    ] {
        let error = parse_profile_import(&wg_quick(line), "p.conf")
            .err()
            .unwrap_or_else(|| panic!("{line} must be refused"))
            .to_string();
        assert!(error.contains(expected), "{line}: {error}");
    }
}

#[test]
fn the_editor_reports_the_ipv6_field_on_its_own() {
    let profile = |address: &str, address_v6: Option<&str>| ClientProfile {
        address: Some(address.into()),
        address_v6: address_v6.map(Into::into),
        ..ClientProfile::default()
    };
    assert_eq!(
        inspect_profile(&profile("100.64.1.2/32", None)).address_v6,
        None
    );
    assert_eq!(
        inspect_profile(&profile("100.64.1.2/32", Some(""))).address_v6,
        None,
        "not filled in yet is not wrong"
    );
    assert_eq!(
        inspect_profile(&profile("100.64.1.2/32", Some("fd3c:91a2:7e04::2/128"))).address_v6,
        None
    );
    let issues = inspect_profile(&profile("100.64.1.2/32", Some("fd3c:91a2:7e04::/64")));
    assert!(issues
        .address_v6
        .as_deref()
        .is_some_and(|message| message.contains("/128")));
    assert_eq!(issues.address, None, "the IPv4 field is not blamed");
    let issues = inspect_profile(&profile("fd00::9/128", Some("fd3c:91a2:7e04::2/128")));
    assert!(issues
        .address_v6
        .as_deref()
        .is_some_and(|message| message.contains("déjà une adresse IPv6")));
}
