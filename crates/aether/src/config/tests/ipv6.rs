//! The optional IPv6 tunnel addresses of `network.toml`
//! (`ADRESSAGE-IPV6.md` §5): persistence, validation and hot reload.

use super::*;

/// The prefix of the specification's own example (§5.1).
const PREFIX: &str = "fd3c:91a2:7e04::1/64";
/// The peer VIP of the same example.
const PEER_V6: &str = "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128";

fn prefix() -> TunnelPrefixV6 {
    PREFIX.parse().expect("the specification's example prefix")
}

fn host(text: &str) -> Ipv6Addr {
    text.parse().expect("test address")
}

fn peer(name: &str, public_key: &str, address: &str, address_v6: Option<&str>) -> WgPeer {
    WgPeer {
        name: name.into(),
        public_key: public_key.into(),
        address: address.into(),
        address_v6: address_v6.map(host),
        admin: false,
        preshared_key: None,
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
        persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    }
}

/// A gateway with the example prefix and two peers, one with an IPv6 VIP.
fn dual_stack() -> NetworkConfig {
    NetworkConfig {
        wg_address_v6: Some(prefix()),
        peers: vec![
            peer(
                "laptop",
                "cle-laptop",
                "100.64.98.223/32",
                Some("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517"),
            ),
            peer("phone", "cle-phone", "100.73.14.6/32", None),
        ],
        ..NetworkConfig::default()
    }
}

fn config_error(result: Result<NetworkConfig>) -> String {
    match result {
        Err(HeliosError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

fn validation_error(config: &NetworkConfig) -> String {
    match config.validate() {
        Err(HeliosError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

// --- Validation (§5.2, §9 criterion 2) ---------------------------------------

#[test]
fn a_dual_stack_configuration_validates() {
    dual_stack()
        .validate()
        .expect("the specification's example");
}

/// A prefix outside §2.4 is refused when the file is read, naming the key.
#[test]
fn a_refused_tunnel_prefix_fails_the_read_naming_the_key() {
    for (prefix, reason) in [
        ("fc3c:91a2:7e04::1/64", "fc00::/8"),
        ("2001:db8::1/64", "not an ULA"),
        ("fd3c:91a2:7e04::1/48", "/64"),
        ("fd3c:91a2:7e04::2/64", "::1"),
        ("fd3c:91a2:7e04:1::1/64", "Subnet ID"),
        ("100.64.0.1/10", "IPv4"),
    ] {
        let file = format!("wg_address_v6 = \"{prefix}\"\n");
        let message = config_error(NetworkConfig::from_toml(&file));
        assert!(message.contains("wg_address_v6"), "{prefix}: {message}");
        assert!(message.contains(reason), "{prefix}: {message}");
    }
}

/// The same refusal on the JSON path (`POST /api/network`), which reports a
/// position rather than the offending line: the message has to name the key
/// itself.
#[test]
fn a_refused_tunnel_prefix_names_the_key_in_json_too() {
    let error = serde_json::from_str::<NetworkConfig>(r#"{"wg_address_v6": "fc00::1/64"}"#)
        .expect_err("fc00::/8 refused");
    assert!(error.to_string().contains("wg_address_v6"), "{error}");
}

/// Anything but one host is refused when the file is read: the type holds
/// a host, so a `/64` has nowhere to go.
#[test]
fn a_peer_address_v6_that_is_not_a_host_fails_the_read() {
    for address_v6 in [
        "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/64",
        "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517",
        "100.64.98.223/32",
        "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517%helios0/128",
    ] {
        let file = format!(
            "wg_address_v6 = \"{PREFIX}\"\n\n[[peers]]\nname = \"laptop\"\n\
             public_key = \"cle-laptop\"\naddress = \"100.64.98.223/32\"\n\
             address_v6 = \"{address_v6}\"\n"
        );
        let message = config_error(NetworkConfig::from_toml(&file));
        assert!(message.contains("address_v6"), "{address_v6}: {message}");
    }
    let message = config_error(NetworkConfig::from_toml(&format!(
        "wg_address_v6 = \"{PREFIX}\"\n\n[[peers]]\nname = \"laptop\"\n\
         public_key = \"cle-laptop\"\naddress = \"100.64.98.223/32\"\n\
         address_v6 = \"fd3c:91a2:7e04::5/64\"\n"
    )));
    assert!(message.contains("/128"), "{message}");
}

#[test]
fn a_peer_address_v6_without_a_tunnel_prefix_is_refused() {
    let mut config = dual_stack();
    config.wg_address_v6 = None;
    let message = validation_error(&config);
    assert!(message.contains("address_v6"), "{message}");
    assert!(message.contains("wg_address_v6"), "{message}");
    assert!(message.contains("laptop"), "{message}");

    // A gateway without IPv6 and peers without IPv6 is today's gateway.
    config.peers[0].address_v6 = None;
    config.validate().expect("no IPv6 at all");
}

#[test]
fn a_peer_address_v6_must_fit_the_tunnel_prefix() {
    for (address_v6, reason) in [
        ("fd3c:91a2:7e05::5", "outside the tunnel prefix"),
        ("fd3c:91a2:7e04:1::5", "outside the tunnel prefix"),
        ("fd3c:91a2:7e04::1", "gateway's own address"),
        ("fd3c:91a2:7e04::", "excluded"),
        ("fd3c:91a2:7e04:0:fdff:ffff:ffff:ff80", "excluded"),
        ("fd3c:91a2:7e04:0:ffff:ffff:ffff:ffff", "excluded"),
    ] {
        let mut config = dual_stack();
        config.peers[0].address_v6 = Some(host(address_v6));
        let message = validation_error(&config);
        assert!(message.contains("address_v6"), "{address_v6}: {message}");
        assert!(message.contains("laptop"), "{address_v6}: {message}");
        assert!(message.contains(reason), "{address_v6}: {message}");
    }

    // The boundaries of §3.2, from the inside.
    for address_v6 in ["fd3c:91a2:7e04::2", "fd3c:91a2:7e04:0:fdff:ffff:ffff:ff7f"] {
        let mut config = dual_stack();
        config.peers[0].address_v6 = Some(host(address_v6));
        config.validate().expect(address_v6);
    }
}

/// Two peers on one IPv6 VIP are refused, never renumbered — including when
/// the two spellings differ: the comparison is on addresses, not on text.
#[test]
fn a_duplicate_peer_address_v6_is_refused_whatever_its_spelling() {
    let file = format!(
        "wg_address_v6 = \"{PREFIX}\"\n\n\
         [[peers]]\nname = \"laptop\"\npublic_key = \"cle-laptop\"\n\
         address = \"100.64.98.223/32\"\naddress_v6 = \"{PEER_V6}\"\n\n\
         [[peers]]\nname = \"phone\"\npublic_key = \"cle-phone\"\n\
         address = \"100.73.14.6/32\"\n\
         address_v6 = \"FD3C:91A2:7E04:0000:8A1F:3B2C:9D40:E517/128\"\n"
    );
    let message = config_error(NetworkConfig::from_toml(&file));
    assert!(message.contains("duplicate address_v6"), "{message}");
    assert!(message.contains("laptop"), "{message}");
    assert!(message.contains("phone"), "{message}");
}

/// The IPv4 identity rules are untouched: the IPv6 checks come on top.
#[test]
fn ipv4_identity_checks_still_apply_on_a_dual_stack_gateway() {
    let mut config = dual_stack();
    config.peers[1].address = config.peers[0].address.clone();
    assert!(validation_error(&config).contains("duplicate VIP"));
}
