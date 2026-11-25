//! Operator services on local bridges (`[[local_services]]`): validation,
//! persistence and projection to the firewall policy.

use super::*;

const FILE: &str = r#"
wan_iface = "eth0"

[[local_services]]
name = "vault"
iface = "vault0"
host = "10.88.7.17"
peer = "10.88.7.18"
port = 9443
"#;

fn service() -> LocalService {
    LocalService {
        name: "vault".into(),
        iface: "vault0".into(),
        host: Ipv4Addr::new(10, 88, 7, 17),
        peer: Ipv4Addr::new(10, 88, 7, 18),
        port: 9443,
    }
}

fn gateway(services: Vec<LocalService>) -> NetworkConfig {
    NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        lan_ifaces: vec!["eth1".into()],
        admin_ifaces: vec!["tailscale0".into()],
        allow_gateway_egress: true,
        nordvpn_meshnet: Some(NordvpnMeshnetConfig::default()),
        local_services: services,
        ..NetworkConfig::default()
    }
}

/// The refusal of `gateway` once `change` is applied to its one service.
fn refusal(change: impl FnOnce(&mut LocalService)) -> String {
    let mut changed = service();
    change(&mut changed);
    refusal_of(vec![changed])
}

fn refusal_of(services: Vec<LocalService>) -> String {
    match gateway(services).validate() {
        Err(HeliosError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn absent_by_default() {
    assert!(NetworkConfig::default().local_services.is_empty());
    assert!(NetworkConfig::default()
        .firewall_policy()
        .local_services
        .is_empty());
}

#[test]
fn a_declared_service_reaches_the_policy_whatever_the_tunnel() {
    let config = NetworkConfig::from_toml(FILE).expect("valid service");
    assert!(!config.wireguard_ready());
    assert_eq!(config.firewall_policy().local_services, [service()]);
}

#[test]
fn a_service_beside_every_other_role_is_accepted() {
    gateway(vec![service()]).validate().expect("valid service");
}

/// A typo must not leave a service half-declared, and no key can widen it.
#[test]
fn an_unknown_key_is_refused() {
    let error =
        NetworkConfig::from_toml(&format!("{FILE}protocol = \"udp\"\n")).expect_err("unknown key");
    assert!(error.to_string().contains("protocol"), "{error}");
}

#[test]
fn an_ipv6_address_is_refused() {
    let file = FILE.replace("10.88.7.18", "fd00::18");
    assert!(NetworkConfig::from_toml(&file).is_err());
}

#[test]
fn an_unusable_name_is_refused() {
    for name in ["", "Vault", "my vault", "vault\"", &"a".repeat(33)] {
        let error = refusal(|service| service.name = name.into());
        assert!(error.contains("name"), "{name}: {error}");
    }
}

/// `*` and `+` are interface wildcards elsewhere; the kernel limits a name to
/// 15 bytes.
#[test]
fn an_unusable_interface_name_is_refused() {
    for iface in [
        "",
        "vault*",
        "vault+",
        "va ult",
        "../x",
        ".",
        "a123456789012345",
    ] {
        let error = refusal(|service| service.iface = iface.into());
        assert!(error.contains("iface"), "{iface}: {error}");
    }
}

/// Each of these already has a role, whose rules a service would widen.
#[test]
fn an_interface_with_another_role_is_refused() {
    for iface in [
        "lo",
        "eth0",
        "eth1",
        "helios0",
        "tailscale0",
        "nordlynx",
        "astra0",
        "astra1",
    ] {
        let error = refusal(|service| service.iface = iface.into());
        assert!(error.contains(iface), "{iface}: {error}");
    }
}

#[test]
fn the_exclusive_administration_interface_is_refused() {
    let mut config = gateway(vec![service()]);
    config.admin_iface = Some("vault0".into());
    assert!(config.validate().is_err());
}

#[test]
fn an_address_outside_the_private_ranges_is_refused() {
    for address in [
        Ipv4Addr::new(203, 0, 113, 5),
        Ipv4Addr::new(100, 64, 0, 9),
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(169, 254, 1, 1),
    ] {
        let host = refusal(|service| service.host = address);
        assert!(host.contains(&address.to_string()), "{host}");
        let peer = refusal(|service| service.peer = address);
        assert!(peer.contains(&address.to_string()), "{peer}");
    }
}

/// `10.88.7.0/28` holds both Astra bridges, whose rules are fixed.
#[test]
fn an_astra_address_is_refused() {
    for last in [0, 2, 10, 15] {
        let address = Ipv4Addr::new(10, 88, 7, last);
        assert!(refusal(|service| service.peer = address).contains("Astra"));
        assert!(refusal(|service| service.host = address).contains("Astra"));
    }
}

#[test]
fn an_address_of_the_tunnel_network_is_refused() {
    let mut config = gateway(vec![service()]);
    config.wg_address = "10.88.0.1/16".into();
    assert!(config.validate().is_err());
}

#[test]
fn a_service_on_the_gateway_itself_is_refused() {
    let error = refusal(|service| service.peer = service.host);
    assert!(error.contains("distinct"), "{error}");
}

#[test]
fn port_zero_is_refused() {
    assert!(refusal(|service| service.port = 0).contains("port"));
}

#[test]
fn two_services_must_not_share_a_name_an_interface_or_an_endpoint() {
    let other = |change: fn(&mut LocalService)| {
        let mut other = LocalService {
            name: "other".into(),
            iface: "other0".into(),
            host: Ipv4Addr::new(10, 88, 8, 1),
            peer: Ipv4Addr::new(10, 88, 8, 2),
            port: 9443,
        };
        change(&mut other);
        vec![service(), other]
    };
    gateway(other(|_| ())).validate().expect("two services");
    assert!(refusal_of(other(|o| o.name = "vault".into())).contains("name"));
    assert!(refusal_of(other(|o| o.iface = "vault0".into())).contains("iface"));
    assert!(refusal_of(other(|o| o.peer = service().peer)).contains("10.88.7.18"));
}

#[test]
fn the_number_of_services_is_bounded() {
    let services = |count: u8| {
        (0..count)
            .map(|index| LocalService {
                name: format!("s{index}"),
                iface: format!("svc{index}"),
                host: Ipv4Addr::new(10, 90, index, 1),
                peer: Ipv4Addr::new(10, 90, index, 2),
                port: 9443,
            })
            .collect::<Vec<_>>()
    };
    gateway(services(4)).validate().expect("four services");
    assert!(refusal_of(services(5)).contains("at most 4"));
}

/// Dropped by a rewrite, the opening would close at the next peer admission.
#[test]
fn a_service_survives_the_persisted_projection() {
    let config = NetworkConfig::from_toml(FILE).expect("valid service");
    let raw = toml::to_string_pretty(&PersistedNetworkConfig::new(&config, false)).unwrap();
    let reread = NetworkConfig::from_toml(&raw).expect("rewritten file");
    assert_eq!(reread.local_services, [service()], "{raw}");
}

#[test]
fn nothing_is_written_back_without_a_service() {
    let raw = toml::to_string_pretty(&PersistedNetworkConfig::new(
        &NetworkConfig::default(),
        false,
    ))
    .unwrap();
    assert!(!raw.contains("local_services"), "{raw}");
}

#[test]
fn a_duplicate_keeps_the_services() {
    let config = gateway(vec![service()]);
    assert_eq!(config.duplicate().local_services, [service()]);
}

/// Removing the section from the file is the rollback: a reload must not
/// adopt the running services back.
#[test]
fn a_reload_follows_the_file() {
    let running = gateway(vec![service()]);
    let mut from_disk = gateway(Vec::new());
    from_disk.adopt_runtime_secrets_from(&running);
    assert!(from_disk.local_services.is_empty());
    from_disk.check_hot_reload(&running).expect("live change");
}
