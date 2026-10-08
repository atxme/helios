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

// --- Persistence (§5.1, §9 criterion 1) --------------------------------------

/// Runs `file` through the production persistence path: written to
/// `network.toml`, read by [`NetworkConfig::load`], written back by `save`,
/// read again as bytes.
///
/// `save` is one of the public writers; all of them end in
/// `save_projected`, the `PersistedNetworkConfig` allow-list.
#[cfg(unix)]
fn rewrite_through_the_save_path(
    tag: &str,
    file: &str,
    save: fn(&NetworkConfig) -> Result<()>,
) -> String {
    let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!(
        "aether-network-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test directory");
    let path = dir.join("network.toml");
    std::fs::write(&path, file).expect("seed network.toml");
    std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

    let loaded = NetworkConfig::load();
    let saved = loaded.and_then(|config| save(&config));
    let rewritten = std::fs::read_to_string(&path);

    std::env::remove_var("HELIOS_NETWORK_CONFIG");
    let _ = std::fs::remove_dir_all(&dir);
    saved.expect("load then save");
    rewritten.expect("read the rewritten file")
}

/// The test the specification asks for first: a file without IPv6, read
/// then written back, is the same file, byte for byte.
///
/// The fixture is a production-shaped `network.toml` — several uplinks,
/// Meshnet, escrow, three peers of different kinds — as **the writer
/// before IPv6 support** produced it. Both writers a gateway uses on it are
/// covered: `save` (`heliosd peer add`, on the console) and `save_redacted`
/// (the API and the key negotiation, in the daemon).
#[cfg(unix)]
#[test]
fn a_production_file_without_ipv6_is_rewritten_byte_for_byte() {
    const FILE: &str = include_str!("../fixtures/network-production-without-ipv6.toml");
    assert!(!FILE.contains("_v6"), "the fixture must not carry IPv6");

    assert_eq!(
        rewrite_through_the_save_path("production-save", FILE, NetworkConfig::save),
        FILE
    );
    assert_eq!(
        rewrite_through_the_save_path("production-redacted", FILE, |config| config.save_redacted()),
        FILE
    );
}

/// The shipped example is hand-written and commented, so its first rewrite
/// is the writer's normal form, not its bytes — comments are not
/// configuration, and `wan_iface = "auto"` becomes a list (see
/// `de_wan_ifaces`). From there on it must not move, it must say exactly
/// what the example says, and nothing about IPv6 may appear.
#[cfg(unix)]
#[test]
fn the_shipped_example_rewrites_to_a_fixed_point_without_ipv6() {
    const EXAMPLE: &str = include_str!("../../../../../config/network.toml");

    let first = rewrite_through_the_save_path("example-first", EXAMPLE, NetworkConfig::save);
    let second = rewrite_through_the_save_path("example-second", &first, NetworkConfig::save);
    assert_eq!(second, first, "a second rewrite must change nothing");
    assert!(!first.contains("_v6"), "{first}");

    let example = NetworkConfig::from_toml(EXAMPLE).expect("the example");
    let rewritten = NetworkConfig::from_toml(&first).expect("its rewrite");
    assert_eq!(rewritten, example, "the rewrite must mean the same thing");
}

/// With IPv6, both keys are written next to their IPv4 counterpart, only
/// where present, and in RFC 5952 form: a hand-written uppercase or
/// uncompressed address is rewritten canonically once, then stays put.
///
/// The canonical rewrite is accepted for files that carry IPv6 only — a file
/// without it is never touched (test above).
#[cfg(unix)]
#[test]
fn a_file_with_ipv6_is_written_canonically_then_stays_stable() {
    const HAND_WRITTEN: &str = r#"
wan_iface = "eth0"
wg_address = "100.64.0.1/10"
wg_address_v6 = "FD3C:91A2:7E04:0:0:0:0:1/64"

[[peers]]
name = "laptop"
public_key = "cle-laptop"
address = "100.64.98.223/32"
address_v6 = "FD3C:91A2:7E04:0000:8A1F:3B2C:9D40:E517/128"

[[peers]]
name = "phone"
public_key = "cle-phone"
address = "100.73.14.6/32"
"#;

    let first = rewrite_through_the_save_path("ipv6-first", HAND_WRITTEN, NetworkConfig::save);
    assert!(
        first.contains(&format!(
            "wg_address = \"100.64.0.1/10\"\nwg_address_v6 = \"{PREFIX}\"\n"
        )),
        "{first}"
    );
    assert!(
        first.contains(&format!(
            "address = \"100.64.98.223/32\"\naddress_v6 = \"{PEER_V6}\"\n"
        )),
        "{first}"
    );
    assert!(
        first.contains("address = \"100.73.14.6/32\"\nadmin = false\n"),
        "a peer without an IPv6 VIP gets no address_v6 line: {first}"
    );
    assert_eq!(first.matches("\naddress_v6").count(), 1, "{first}");

    let second = rewrite_through_the_save_path("ipv6-second", &first, NetworkConfig::save);
    assert_eq!(second, first, "the canonical form is a fixed point");

    let reread = NetworkConfig::from_toml(&second).expect("the rewrite");
    assert_eq!(reread.wg_address_v6, Some(prefix()));
    assert_eq!(
        reread.peers[0].address_v6,
        Some(host("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517"))
    );
    assert_eq!(reread.peers[1].address_v6, None);
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

// --- Hot reload (§5.4) -------------------------------------------------------

/// A peer's IPv6 VIP is public configuration: a reload takes it from the
/// file — added, changed or removed — while the runtime secrets are still
/// adopted from the running configuration.
#[test]
fn a_reload_takes_peer_ipv6_vips_from_the_file_and_keeps_the_secrets() {
    let mut running = dual_stack();
    running.wg_private_key = "SECRET-DE-LA-GATEWAY".into();
    running.peers[0].preshared_key = Some("PSK-NEGOCIE".into());

    let mut from_disk = dual_stack();
    from_disk.peers[0].address_v6 = Some(host("fd3c:91a2:7e04::42"));
    from_disk.peers[1].address_v6 = Some(host("fd3c:91a2:7e04::43"));
    from_disk.adopt_runtime_secrets_from(&running);

    from_disk
        .check_hot_reload(&running)
        .expect("peers reload live");
    from_disk.validate().expect("the merged configuration");
    assert_eq!(
        from_disk.peers[0].address_v6,
        Some(host("fd3c:91a2:7e04::42"))
    );
    assert_eq!(
        from_disk.peers[1].address_v6,
        Some(host("fd3c:91a2:7e04::43"))
    );
    assert_eq!(from_disk.wg_private_key.expose(), "SECRET-DE-LA-GATEWAY");
    assert_eq!(
        from_disk.peers[0]
            .preshared_key
            .as_ref()
            .map(SecretString::expose),
        Some("PSK-NEGOCIE")
    );
    assert_ne!(from_disk, running, "the watcher must see a change to apply");

    // Removed from the file, removed from the running gateway: this is not
    // runtime state to preserve.
    let mut from_disk = dual_stack();
    from_disk.peers[0].address_v6 = None;
    from_disk.adopt_runtime_secrets_from(&running);
    assert_eq!(from_disk.peers[0].address_v6, None);
}

/// The tunnel prefix applies at startup only: every change of it — added,
/// removed, replaced — is refused live, naming the key and the restart.
#[test]
fn a_reload_that_changes_the_tunnel_prefix_requires_a_restart() {
    let other: TunnelPrefixV6 = "fd00:1:2::1/64".parse().expect("prefix");
    for (running, incoming) in [
        (None, Some(prefix())),
        (Some(prefix()), None),
        (Some(prefix()), Some(other)),
    ] {
        let running = NetworkConfig {
            wg_address_v6: running,
            ..NetworkConfig::default()
        };
        let incoming = NetworkConfig {
            wg_address_v6: incoming,
            ..NetworkConfig::default()
        };
        match incoming.check_hot_reload(&running) {
            Err(HeliosError::Config(message)) => {
                assert!(message.contains("wg_address_v6"), "{message}");
                assert!(message.contains("restart"), "{message}");
            }
            other => panic!("expected a restart requirement, got {other:?}"),
        }
    }

    let running = dual_stack();
    let mut incoming = dual_stack();
    incoming.peers.pop();
    incoming
        .check_hot_reload(&running)
        .expect("an unchanged prefix is not a restart");
}

/// Duplicating a configuration carries the IPv6 addresses too: the hot
/// reload compares duplicates.
#[test]
fn duplicating_a_configuration_carries_the_ipv6_addresses() {
    let original = dual_stack();
    let copy = original.duplicate();
    assert_eq!(copy.wg_address_v6, Some(prefix()));
    assert_eq!(copy.peers[0].address_v6, original.peers[0].address_v6);
    assert_eq!(copy, original);
}

/// What provisioning returns is read here, from the declared pair: both
/// families as written, and an unreadable IPv4 refused rather than guessed
/// (`ADRESSAGE-IPV6.md` §3 bis.2, rule 4).
#[test]
fn a_peer_reads_back_the_vips_it_was_admitted_with() {
    let config = dual_stack();
    assert_eq!(
        config.peers[0].vips(),
        Ok(crate::net::PeerVips {
            v4: "100.64.98.223".parse().expect("IPv4"),
            v6: Some(host("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517")),
        })
    );
    assert_eq!(config.peers[1].vips().map(|vips| vips.v6), Ok(None));

    for unreadable in ["", "100.64.98.223", "100.64.98.0/24", "fd3c::5/128"] {
        let peer = peer("laptop", "cle-laptop", unreadable, None);
        assert!(peer.vips().is_err(), "{unreadable:?} accepted");
    }
}
