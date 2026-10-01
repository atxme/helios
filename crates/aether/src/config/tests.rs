use super::*;

/// A configuration reloaded from disk carries no secret — by design.
///
/// This is the accident the merge exists to prevent: `network.toml` is
/// written without the sealed private key and without the negotiated
/// PSKs, so applying it as-is would take the gateway's identity away and
/// leave every peer with a PSK slot filled on one side only. Every
/// handshake would then fail, with no recovery channel.
#[test]
fn a_reloaded_config_keeps_the_secrets_the_file_never_held() {
    let running = NetworkConfig {
        wg_private_key: "SECRET-DE-LA-GATEWAY".into(),
        key_negotiation_port: Some(51821),
        peers: vec![WgPeer {
            name: "poste".into(),
            public_key: "CLE-PUBLIQUE-DU-POSTE".into(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: Some("PSK-NEGOCIE".into()),
            key_negotiation_certificate_sha256: Some("empreinte-tls".into()),
            key_negotiation_pq_certificate_sha256: Some("empreinte-pq".into()),
            minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
            persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    };

    // What `heliosd peer add` leaves on disk: the same peer, a new one,
    // and nothing secret.
    let mut from_disk = NetworkConfig {
        peers: vec![
            WgPeer {
                preshared_key: None,
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                // A file that asks for less than what was reached: the
                // floor must not follow it down.
                minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
                persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
                ..running.peers[0].duplicate()
            },
            WgPeer {
                name: "nouveau".into(),
                public_key: "CLE-DU-NOUVEAU".into(),
                address: "100.64.1.3/32".into(),
                admin: false,
                preshared_key: None,
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
                persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            },
        ],
        ..NetworkConfig::default()
    };

    from_disk.adopt_runtime_secrets_from(&running);

    assert_eq!(from_disk.wg_private_key.expose(), "SECRET-DE-LA-GATEWAY");
    assert_eq!(from_disk.key_negotiation_port, Some(51821));
    assert_eq!(
        from_disk.peers[0]
            .preshared_key
            .as_ref()
            .map(SecretString::expose),
        Some("PSK-NEGOCIE"),
        "the negotiated PSK must survive a reload"
    );
    assert_eq!(
        from_disk.peers[0]
            .key_negotiation_certificate_sha256
            .as_deref(),
        Some("empreinte-tls")
    );
    assert_eq!(
        from_disk.peers[0].minimum_key_negotiation_mode,
        crate::key_negotiation::ProtectionMode::MlKem,
        "the anti-downgrade floor only ever goes up"
    );

    // And the point of the whole exercise: the new peer is there.
    assert_eq!(from_disk.peers.len(), 2);
    assert_eq!(from_disk.peers[1].name, "nouveau");
    assert_eq!(from_disk.peers[1].preshared_key, None);
}

/// The `Debug` of the running configuration must not print the gateway
/// identity nor a peer PSK.
///
/// This is the derive, not a hand-written impl: it stays safe because the
/// two fields are `SecretString`. The test is what fails if one of them
/// ever goes back to a bare `String` (ADR-006 §5).
#[test]
fn the_debug_of_a_running_configuration_reveals_no_secret() {
    const KEY: &str = "cle-privee-de-la-gateway";
    const PSK: &str = "psk-negocie-du-pair";

    let mut config = NetworkConfig {
        wg_private_key: KEY.into(),
        ..NetworkConfig::default()
    };
    config.peers.push(WgPeer {
        name: "alice".into(),
        public_key: "CLE-PUBLIQUE-ALICE".into(),
        address: "100.64.1.2/32".into(),
        admin: false,
        preshared_key: Some(PSK.into()),
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
        persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });

    let rendered = format!("{config:?}");
    assert!(!rendered.contains(KEY), "the identity leaked: {rendered}");
    assert!(!rendered.contains(PSK), "a PSK leaked: {rendered}");
    // The rest must stay readable, or the redaction would have cost the
    // diagnostic the `Debug` exists for.
    assert!(rendered.contains("alice"));
    assert!(rendered.contains("100.64.1.2/32"));
}

/// Duplication is named, and it really does copy the secrets.
///
/// Both halves matter: a `duplicate` that dropped them would silently
/// disarm the hot reload, which is what `adopt_runtime_secrets_from`
/// relies on.
#[test]
fn duplicating_a_configuration_carries_the_secrets_independently() {
    let mut original = NetworkConfig {
        wg_private_key: "identite".into(),
        ..NetworkConfig::default()
    };
    original.peers.push(WgPeer {
        name: "alice".into(),
        public_key: "CLE-PUBLIQUE-ALICE".into(),
        address: "100.64.1.2/32".into(),
        admin: false,
        preshared_key: Some("psk".into()),
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::MlKem,
        persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });

    let copy = original.duplicate();
    assert_eq!(copy.wg_private_key.expose(), "identite");
    assert_eq!(
        copy.peers[0]
            .preshared_key
            .as_ref()
            .map(SecretString::expose),
        Some("psk")
    );
    assert_eq!(copy, original);

    // Independent: mutating one must not reach the other.
    original.wg_private_key = "autre".into();
    assert_eq!(copy.wg_private_key.expose(), "identite");
}

#[test]
fn config_empty_by_default() {
    let cfg = NetworkConfig::default();
    assert!(cfg.peers.is_empty());
    assert!(cfg.wan_ifaces.is_empty());
    assert!(
        !cfg.wireguard_ready(),
        "without a private key, nothing should come up"
    );
}

#[test]
fn deserializes_gateway_config() {
    let toml = r#"
            wan_iface = "eth0"
            lan_ifaces = ["eth1"]
            admin_iface = "helios0"
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [[peers]]
            name = "poste-christophe"
            public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            address = "100.64.1.2/32"
            admin = true
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.wan_ifaces, vec!["eth0".to_string()]);
    // WireGuard defaults apply without being written.
    assert_eq!(cfg.wg_iface, "helios0");
    assert_eq!(cfg.wg_listen_port, 51820);
    assert_eq!(cfg.wg_address, "100.64.0.1/10");
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].address, "100.64.1.2/32");
    assert!(cfg.peers[0].admin);
    assert!(cfg.wireguard_ready());

    let policy = cfg.firewall_policy();
    assert!(policy.is_fail_closed());
    // Server role: the listen port must be open inbound, otherwise no
    // client can handshake.
    assert_eq!(policy.wg_listen_port, Some(51820));
    assert!(policy.wg_peers.is_empty(), "road-warrior: no outbound peer");
    // ICMP on the tunnel is the one opening that does not have to be
    // asked for: it routes nothing and only lets the gateway answer for
    // itself, to peers WireGuard has already authenticated.
    assert!(policy.allow_tunnel_icmp, "absent means open, for this one");
    assert!(
        !policy.allow_ssh_over_tunnel,
        "administrative access is never opened by omission"
    );
}

/// The tunnel openings are worth nothing until the interface can exist.
#[test]
fn the_tunnel_openings_follow_wireguard_readiness() {
    let toml = r#"
            wan_iface = "eth0"
            allow_ssh_over_tunnel = true
            iperf_port = 5202
        "#;
    let mut cfg: NetworkConfig = toml::from_str(toml).unwrap();
    assert!(
        !cfg.wireguard_ready(),
        "no private key: the interface cannot come up"
    );
    let policy = cfg.firewall_policy();
    assert!(!policy.allow_tunnel_icmp);
    assert!(!policy.allow_ssh_over_tunnel);
    assert_eq!(policy.iperf_port, None);

    cfg.wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
    let policy = cfg.firewall_policy();
    assert!(policy.allow_tunnel_icmp);
    assert!(policy.allow_ssh_over_tunnel);
    assert_eq!(policy.iperf_port, Some(5202));
}

/// An out-of-band overlay is not gated on the tunnel it exists to survive.
#[test]
fn admin_ifaces_do_not_follow_wireguard_readiness() {
    let toml = r#"
            wan_iface = "eth0"
            admin_ifaces = ["tailscale0", "nordlynx"]
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    assert!(!cfg.wireguard_ready());
    assert_eq!(
        cfg.firewall_policy().admin_ifaces,
        vec!["tailscale0".to_string(), "nordlynx".to_string()],
        "the recovery path must not need the tunnel to be up"
    );
}

/// The tunnel interface is `allow_ssh_over_tunnel`'s business, not this list's.
#[test]
fn admin_ifaces_refuse_the_tunnel_and_the_wan() {
    for (field, value) in [("admin_ifaces", "helios0"), ("admin_ifaces", "eth0")] {
        let toml = format!(
            r#"
                wan_iface = "eth0"
                {field} = ["{value}"]
            "#
        );
        let cfg: NetworkConfig = toml::from_str(&toml).unwrap();
        assert!(
            cfg.validate().is_err(),
            "{value} must not be usable as an out-of-band administration interface"
        );
    }
}

/// The exact configuration that locked the gateway out on 2026-09-01.
///
/// A deployment running through the tunnel read its own source address —
/// the peer VIP `100.89.226.187` — and pinned SSH to it. The rule held
/// until `heliosd` restarted, then the tunnel went away and took the only
/// permitted SSH source with it.
#[test]
fn allow_ssh_from_refuses_an_address_inside_the_tunnel() {
    let toml = r#"
            wan_iface = "eth0"
            wg_address = "100.64.0.1/10"
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            allow_ssh_from = ["100.89.226.187/32"]
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    let error = cfg.validate().unwrap_err().to_string();
    assert!(
        error.contains("100.89.226.187/32") && error.contains("admin_ifaces"),
        "the refusal must name the offending source and the way out: {error}"
    );

    // A LAN source is the shape that legitimately survives a tunnel
    // outage, and it must keep working.
    let toml = toml.replace("100.89.226.187/32", "192.168.1.41/32");
    let cfg: NetworkConfig = toml::from_str(&toml).unwrap();
    assert!(
        cfg.validate().is_ok(),
        "a LAN source is a valid way back in"
    );
}

/// Containment, both directions, so the refusal cannot be stepped around.
#[test]
fn cidr_containment_handles_widths_and_families() {
    assert!(NetworkConfig::cidr_contains(
        "100.64.0.1/10",
        "100.89.226.187"
    ));
    assert!(NetworkConfig::cidr_contains(
        "100.64.0.1/10",
        "100.64.0.0/10"
    ));
    assert!(!NetworkConfig::cidr_contains(
        "100.64.0.1/10",
        "192.168.1.41"
    ));
    // Wider than the network: must not pass as « outside » on a technicality.
    assert!(!NetworkConfig::cidr_contains("100.64.0.1/10", "0.0.0.0/0"));
    // Mixed families never contain one another.
    assert!(!NetworkConfig::cidr_contains("100.64.0.1/10", "fd7a::1"));
    // Unparseable input backs a refusal, so it answers false.
    assert!(!NetworkConfig::cidr_contains("100.64.0.1/10", "not-an-ip"));
}

/// A diagnostic, so it is absent unless asked for by name.
#[test]
fn iperf_is_absent_from_a_default_configuration() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.iperf_port, None);
    assert_eq!(cfg.firewall_policy().iperf_port, None);
}

/// Unlike the two tunnel openings, this one is scoped to the WAN and must
/// survive a gateway whose interface cannot come up: an operator upgrades
/// a gateway precisely when its tunnel is down.
#[test]
fn gateway_egress_is_opt_in_and_ignores_wireguard_readiness() {
    let cfg = NetworkConfig::default();
    assert!(
        !cfg.firewall_policy().allow_gateway_egress,
        "the gateway's own egress is never opened by omission"
    );

    let toml = r#"
            wan_iface = "eth0"
            allow_gateway_egress = true
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    assert!(!cfg.wireguard_ready());
    assert!(cfg.firewall_policy().allow_gateway_egress);
}

#[test]
fn meshnet_config_projects_explicit_peer_and_service_limits() {
    let toml = r#"
            wan_iface = "eth0"
            allow_gateway_egress = true

            [nordvpn_meshnet]
            peer_cidrs = ["100.70.36.212/32"]
            traffic_routing_peer_cidrs = ["100.70.36.212/32"]
            inbound_tcp_ports = [22, 9100]
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    cfg.validate().unwrap();

    let meshnet = cfg.firewall_policy().nordvpn_meshnet.unwrap();
    assert_eq!(meshnet.iface, "nordlynx");
    assert_eq!(meshnet.fwmark, 0xe1f1);
    assert_eq!(meshnet.peer_cidrs, ["100.70.36.212/32"]);
    assert_eq!(meshnet.traffic_routing_peer_cidrs, ["100.70.36.212/32"]);
    assert!(meshnet.local_network_peer_cidrs.is_empty());
    assert_eq!(meshnet.inbound_tcp_ports, [22, 9100]);
    assert!(meshnet.inbound_udp_ports.is_empty());
    assert!(meshnet.allow_icmp);
}

#[test]
fn meshnet_rejects_ambiguous_or_unbounded_configuration() {
    let valid = NordvpnMeshnetConfig {
        peer_cidrs: vec!["100.70.36.212/32".into()],
        ..NordvpnMeshnetConfig::default()
    };
    let mut cfg = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        nordvpn_meshnet: Some(valid),
        ..NetworkConfig::default()
    };

    assert!(cfg.validate().is_err(), "HTTPS control egress is required");
    cfg.allow_gateway_egress = true;
    assert!(cfg.validate().is_ok());

    cfg.nordvpn_meshnet.as_mut().unwrap().iface = "eth0".into();
    assert!(cfg.validate().is_err(), "the overlay cannot also be a WAN");
    cfg.nordvpn_meshnet.as_mut().unwrap().iface = "nordlynx".into();
    cfg.nordvpn_meshnet.as_mut().unwrap().peer_cidrs = vec!["100.70.36.212/99".into()];
    assert!(cfg.validate().is_err(), "invalid CIDRs must fail closed");
    cfg.nordvpn_meshnet.as_mut().unwrap().peer_cidrs = vec!["100.70.36.212/32".into()];
    cfg.nordvpn_meshnet.as_mut().unwrap().inbound_tcp_ports = vec![22, 22];
    assert!(
        cfg.validate().is_err(),
        "duplicate ports are configuration errors"
    );
    cfg.nordvpn_meshnet.as_mut().unwrap().inbound_tcp_ports = vec![API_PORT];
    assert!(
        cfg.validate().is_err(),
        "the administration API must remain exclusive to the Helios tunnel"
    );
    cfg.nordvpn_meshnet
        .as_mut()
        .unwrap()
        .inbound_tcp_ports
        .clear();
    cfg.nordvpn_meshnet
        .as_mut()
        .unwrap()
        .traffic_routing_peer_cidrs = vec!["100.70.36.213/32".into()];
    assert!(
        cfg.validate().is_err(),
        "routing permission must not name an undeclared peer"
    );
    cfg.nordvpn_meshnet
        .as_mut()
        .unwrap()
        .traffic_routing_peer_cidrs = vec!["100.70.36.212/32".into()];
    cfg.nordvpn_meshnet
        .as_mut()
        .unwrap()
        .local_network_peer_cidrs = vec!["100.70.36.213/32".into()];
    assert!(
        cfg.validate().is_err(),
        "local-network permission must be a subset of routing peers"
    );
}

/// IPv6 Meshnet peers stay refused: NordVPN hands out IPv4 Meshnet
/// addresses, and the firewall's IPv6 Meshnet rules are only reachable from a
/// policy built in code until accepting them is decided.
#[test]
fn meshnet_refuses_ipv6_peer_cidrs() {
    let mut cfg = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        allow_gateway_egress: true,
        nordvpn_meshnet: Some(NordvpnMeshnetConfig {
            peer_cidrs: vec!["100.70.36.212/32".into()],
            ..NordvpnMeshnetConfig::default()
        }),
        ..NetworkConfig::default()
    };
    assert!(cfg.validate().is_ok());

    let meshnet = cfg.nordvpn_meshnet.as_mut().unwrap();
    meshnet.peer_cidrs = vec!["100.70.36.212/32".into(), "2001:db8::5/128".into()];
    meshnet.traffic_routing_peer_cidrs = vec!["2001:db8::5/128".into()];
    assert!(cfg.validate().is_err(), "an IPv6 peer CIDR is refused");

    let meshnet = cfg.nordvpn_meshnet.as_mut().unwrap();
    meshnet.peer_cidrs = vec!["2001:db8::/64".into()];
    meshnet.traffic_routing_peer_cidrs.clear();
    assert!(cfg.validate().is_err(), "an IPv6 peer network is refused");
}

#[test]
fn repository_network_example_is_valid() {
    let cfg: NetworkConfig = toml::from_str(include_str!("../../../../config/network.toml"))
        .expect("the shipped network configuration must deserialize");
    cfg.validate()
        .expect("the shipped network configuration must validate");
}

/// Closing ICMP stays possible: the default is a choice, not a fixture.
#[test]
fn tunnel_icmp_can_be_closed_explicitly() {
    let toml = r#"
            wan_iface = "eth0"
            allow_tunnel_icmp = false
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
    let cfg: NetworkConfig = toml::from_str(toml).unwrap();
    assert!(!cfg.firewall_policy().allow_tunnel_icmp);
}

#[test]
fn identities_require_unique_host_vips() {
    let peer = |name: &str, key: &str, address: &str| WgPeer {
        name: name.into(),
        public_key: key.into(),
        address: address.into(),
        admin: false,
        preshared_key: None,
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
        persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    };
    let mut cfg = NetworkConfig {
        peers: vec![
            peer("a", "cle-a", "100.64.1.2/32"),
            peer("b", "cle-b", "100.64.1.2/32"),
        ],
        ..NetworkConfig::default()
    };
    assert!(cfg.validate_peer_identities().is_err());

    cfg.peers[1].address = "100.64.1.3/24".into();
    assert!(cfg.validate_peer_identities().is_err());

    cfg.peers[1].address = "100.64.1.3/32".into();
    assert!(cfg.validate_peer_identities().is_ok());
}

#[test]
fn key_negotiation_requires_a_distinct_nonzero_udp_port() {
    let mut config = NetworkConfig {
        key_negotiation_port: Some(0),
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_err());
    config.key_negotiation_port = Some(config.wg_listen_port);
    assert!(config.validate().is_err());
    config.key_negotiation_port = Some(51821);
    assert!(config.validate().is_ok());
}

#[test]
fn configured_services_cannot_claim_the_builtin_speedtest_port() {
    let mut config = NetworkConfig {
        key_negotiation_port: Some(SPEEDTEST_PORT),
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_err());

    config.key_negotiation_port = Some(51821);
    config.wg_listen_port = SPEEDTEST_PORT;
    assert!(config.validate().is_err());

    config.wg_listen_port = 51820;
    config.iperf_port = Some(SPEEDTEST_PORT);
    assert!(config.validate().is_err());

    config.iperf_port = Some(5201);
    assert!(config.validate().is_ok());
}

/// The API must listen on the tunnel address. On `127.0.0.1`, no Orion
/// client could reach provisioning, and the firewall rule filtering on
/// `admin_iface` could never apply.
#[test]
fn the_api_listens_on_the_tunnel_address() {
    let cfg = NetworkConfig {
        wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        wg_address: "100.64.0.1/10".into(),
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.api_bind(), "100.64.0.1:8080");
    assert_ne!(
        cfg.api_bind(),
        API_BIND_LOOPBACK,
        "on loopback, provisioning would be unreachable"
    );
}

#[test]
fn the_raw_speedtest_uses_the_fixed_in_tunnel_port() {
    let cfg = NetworkConfig {
        wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        wg_address: "100.64.0.1/10".into(),
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.speedtest_bind(), "100.64.0.1:55182");
    assert_eq!(NetworkConfig::default().speedtest_bind(), "127.0.0.1:55182");
}

/// Without a configured gateway, no reason to expose the API: loopback.
#[test]
fn falls_back_to_loopback_without_a_gateway() {
    assert_eq!(NetworkConfig::default().api_bind(), API_BIND_LOOPBACK);

    // Malformed address: we fall back rather than exposing anything.
    let cfg = NetworkConfig {
        wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        wg_address: "/10".into(),
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.api_bind(), API_BIND_LOOPBACK);
}

/// Serialises the tests that drive `HELIOS_NETWORK_CONFIG`.
///
/// The variable is **process-wide**, so two tests setting it run into each
/// other under the default parallel harness — one pointing the other's
/// `save()` at its own directory. A single test could ignore this; a second
/// one cannot, and adding a third without this lock would resurrect it.
#[cfg(unix)]
static NETWORK_CONFIG_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Production persistence never lets a runtime secret reach `network.toml`.
///
/// The projection is an allow-list, so a field added later stays off disk
/// until it is classified explicitly. This test complements that structural
/// guarantee by scanning the produced bytes for today's secrets themselves.
///
/// It scans the temporary files too — a secret written and renamed away is
/// still a secret that touched the disk.
#[cfg(unix)]
#[test]
fn production_save_excludes_runtime_secrets_and_development_keeps_only_identity() {
    let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());
    const PRIVATE_KEY: &str = "MOTIF-CLE-PRIVEE-GATEWAY-A-NE-JAMAIS-ECRIRE";
    const PSK: &str = "MOTIF-PSK-NEGOCIE-A-NE-JAMAIS-ECRIRE";

    let dir = std::env::temp_dir().join(format!(
        "aether-network-secrets-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test directory");
    let path = dir.join("network.toml");
    std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

    // Hand `save` the complete runtime value on purpose: the persistence
    // boundary, rather than each caller, owns the public projection.
    let mut cfg = NetworkConfig {
        wg_private_key: PRIVATE_KEY.into(),
        wg_address: "100.64.0.1/10".into(),
        ..NetworkConfig::default()
    };
    cfg.peers.push(WgPeer {
        name: "poste".into(),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        address: "100.64.1.2/32".into(),
        admin: false,
        preshared_key: Some(PSK.into()),
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: crate::key_negotiation::ProtectionMode::Classic,
        persistent_keepalive_secs: DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });

    let error = cfg.save().expect_err("secret-bearing save must fail");
    assert!(error
        .to_string()
        .contains("refusing to persist runtime secrets"));
    assert!(!path.exists(), "a refused save must not touch the file");

    cfg.save_redacted().expect("redacted save");

    for entry in std::fs::read_dir(&dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let bytes = std::fs::read(entry.path()).expect("read");
        for (label, secret) in [("private key", PRIVATE_KEY), ("PSK", PSK)] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "the {label} appears in {}",
                entry.path().display()
            );
        }
    }

    let persisted = NetworkConfig::load().expect("reload persisted config");
    assert!(persisted.wg_private_key.is_empty());
    assert_eq!(persisted.peers.len(), 1);
    assert_eq!(persisted.peers[0].name, "poste");
    assert_eq!(persisted.peers[0].preshared_key, None);

    // The dry-run exception is deliberately narrower than "save all": it
    // retains the simulated gateway identity and still excludes peer PSKs.
    cfg.save_for_development().expect("development save");
    let development = std::fs::read_to_string(&path).expect("development config");
    assert!(development.contains(PRIVATE_KEY));
    assert!(!development.contains(PSK));

    std::env::remove_var("HELIOS_NETWORK_CONFIG");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `network.toml` must never become world-readable, and above all not on a
/// **rewrite**.
///
/// This is the regression ADR-006 opens on: `save()` used to write its
/// temporary file with a plain `std::fs::write`, whose mode came from the
/// umask — 0644 for a daemon running as root. The `rename` carried that
/// mode onto the final file, silently undoing the `chmod 600` applied by
/// `scripts/target-bootstrap.sh`. The gateway lost it at its first peer
/// admission, and nothing said so.
///
/// Goes through `HELIOS_NETWORK_CONFIG`, which no other test in this crate
/// touches: there is nothing here to race against.
#[cfg(unix)]
#[test]
fn the_network_config_stays_private_across_rewrites() {
    use std::os::unix::fs::PermissionsExt as _;

    let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());

    let dir = std::env::temp_dir().join(format!(
        "aether-network-mode-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test directory");
    let path = dir.join("network.toml");
    std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

    let cfg = NetworkConfig {
        wg_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        wg_address: "100.64.0.1/10".into(),
        ..NetworkConfig::default()
    };
    cfg.save_redacted().expect("first save");
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600, "mode after the first save");

    cfg.save_redacted().expect("rewrite");
    assert_eq!(mode(&path), 0o600, "mode after a rewrite");

    std::env::remove_var("HELIOS_NETWORK_CONFIG");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn port_not_opened_if_the_gateway_is_not_ready() {
    // No private key -> we don't open a port with nothing behind it.
    let cfg = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.firewall_policy().wg_listen_port, None);
}
/// `auto` states an intent, and the daemon resolved it against the kernel
/// at startup. A reload must not put the marker back: every egress rule
/// and the masquerade would then be bound to an interface literally named
/// `auto`, and the gateway would drop its own traffic.
#[test]
fn a_reload_keeps_the_resolved_uplink_rather_than_the_marker() {
    let mut from_disk = NetworkConfig {
        wan_ifaces: vec!["auto".into()],
        ..NetworkConfig::default()
    };
    let running = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        ..NetworkConfig::default()
    };
    from_disk.adopt_runtime_secrets_from(&running);
    assert_eq!(from_disk.wan_ifaces, vec!["eth0".to_string()]);
    assert!(!from_disk.wan_iface_is_auto());
}

/// An operator who names an interface in the file gets that interface,
/// even if the running one was resolved: the file is the intent.
#[test]
fn a_reload_that_names_an_interface_replaces_the_resolved_one() {
    let mut from_disk = NetworkConfig {
        wan_ifaces: vec!["eth1".into()],
        ..NetworkConfig::default()
    };
    let running = NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        ..NetworkConfig::default()
    };
    from_disk.adopt_runtime_secrets_from(&running);
    assert_eq!(from_disk.wan_ifaces, vec!["eth1".to_string()]);
}

/// The marker is recognised however it is spelled and spaced, because a
/// missed one is a ruleset built around a device that does not exist.
#[test]
fn the_auto_marker_is_recognised_regardless_of_case_and_spacing() {
    for spelling in ["auto", "AUTO", " Auto ", "aUtO"] {
        let config = NetworkConfig {
            wan_ifaces: vec![spelling.into()],
            ..NetworkConfig::default()
        };
        assert!(config.wan_iface_is_auto(), "« {spelling} » is the marker");
    }
    let named = NetworkConfig {
        wan_ifaces: vec!["auto0".into()],
        ..NetworkConfig::default()
    };
    assert!(
        !named.wan_iface_is_auto(),
        "« auto0 » is a real interface name on some boards, not the marker"
    );
}
