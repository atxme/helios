//! The versioned Orion JSON envelope: defaults applied, and the documents it
//! refuses to read.

use super::fixtures::{CLIENT_PRIVATE, GATEWAY_PUBLIC};
use crate::profile_import::parse_profile_import;
use crate::{DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

#[test]
fn imports_versioned_json_with_defaults() {
    let raw = format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": " portable ",
                "endpoint": "vpn.example.net:51820",
                "private_key": "{CLIENT_PRIVATE}",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "address": "100.64.1.2/32",
                "heliosd_url": "http://100.64.0.1:8080"
            }}
        }}"#
    );

    let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
    assert_eq!(profile.name, "portable");
    assert_eq!(profile.allowed_ips, DEFAULT_ALLOWED_IPS);
    // A document that says nothing about routing gets the full tunnel in
    // both families: the one `helios` emits without `--allowed-ips`.
    assert!(!profile.ipv6_uncaptured_full_tunnel());
    assert_eq!(profile.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
    assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
}

/// Tolerating the absence of a private key must not tolerate a truncated
/// key: that's not an invitation, it's a corruption.
#[test]
fn a_private_key_present_but_malformed_stays_refused() {
    let raw = r#"{
        "format": "orion-profile",
        "version": 1,
        "profile": {
            "name": "portable",
            "endpoint": "vpn.example.net:51820",
            "private_key": "AAAA",
            "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "address": "100.64.1.2/32"
        }
    }"#;
    let error = parse_profile_import(raw, "portable.json").unwrap_err();
    assert!(error.to_string().contains("clé privée"), "message: {error}");
}

#[test]
fn refuses_unknown_json_or_unexpected_field() {
    let wrong_version = r#"{
        "format": "orion-profile",
        "version": 2,
        "profile": {}
    }"#;
    assert!(parse_profile_import(wrong_version, "profile.json")
        .unwrap_err()
        .to_string()
        .contains("version"));

    let unknown_field = format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": "site",
                "endpoint": "vpn.example.net:51820",
                "private_key": "{CLIENT_PRIVATE}",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "dns": "100.64.0.1"
            }}
        }}"#
    );
    assert!(parse_profile_import(&unknown_field, "profile.json").is_err());
}

/// The v1 Helios document carried the client's private keys, or admitted a key
/// with no proof of possession. Neither exists in v5, and the refusal names the
/// procedure that replaces it.
#[test]
fn a_v1_helios_document_is_refused_with_the_new_procedure_named() {
    use super::fixtures::{gateway_settings, identity_bundle, CLIENT_PRIVATE, GATEWAY_PUBLIC};
    use aether::key_negotiation::ProtectionMode;

    let settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    let mut with_identity = serde_json::json!({
        "format": "orion-profile",
        "version": 1,
        "profile": {
            "name": "portable",
            "type": "helios_key_negotiation",
            "endpoint": "vpn.example.net:51820",
            "private_key": CLIENT_PRIVATE,
            "peer_public_key": GATEWAY_PUBLIC,
            "key_negotiation": settings,
        }
    });
    let without_identity = with_identity.to_string();
    with_identity["profile"]["key_negotiation_identity"] = identity_bundle("orion-portable");

    for document in [without_identity, with_identity.to_string()] {
        let error = format!(
            "{:#}",
            parse_profile_import(&document, "portable.orion").expect_err("refused")
        );
        assert!(error.contains("invitation d'enrôlement"), "{error}");
    }
}

#[test]
fn a_v1_classic_document_still_imports() {
    let document = serde_json::json!({
        "format": "orion-profile",
        "version": 1,
        "profile": {
            "name": "portable",
            "type": "classic",
            "endpoint": "vpn.example.net:51820",
            "private_key": super::fixtures::CLIENT_PRIVATE,
            "peer_public_key": super::fixtures::GATEWAY_PUBLIC,
            "address": "100.64.1.2/32",
        }
    });
    let imported = parse_profile_import(&document.to_string(), "portable.orion").expect("classic");
    assert!(imported.enrollment.is_none());
    assert!(imported.profile.key_negotiation.is_none());
}
