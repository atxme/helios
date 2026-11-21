//! The single-peer `wg-quick` format: what is applied, what is reported as
//! not applied, and what is refused.

use std::net::Ipv4Addr;

use super::fixtures::{CLIENT_PRIVATE, GATEWAY_PUBLIC};
use crate::profile_import::{complete_profile_import, parse_profile_import};
use crate::ClientConfig;

/// `wg-quick` has no notion of invitation: a file without `PrivateKey`
/// is an incomplete file, and saying so early avoids a tunnel that never
/// mounts without explanation.
#[test]
fn wg_quick_without_a_private_key_stays_refused() {
    let raw = format!(
        r#"
            [Interface]
            Address = 100.64.1.2/32

            [Peer]
            PublicKey = {GATEWAY_PUBLIC}
            Endpoint = vpn.example.net:51820
        "#
    );
    let error = parse_profile_import(&raw, "portable.conf").unwrap_err();
    assert!(error.to_string().contains("PrivateKey"), "message: {error}");
}

#[test]
fn imports_wg_quick_with_one_peer() {
    let raw = format!(
        r#"
            # profile issued by the administrator
            [Interface]
            PrivateKey = {CLIENT_PRIVATE}
            Address = 100.64.1.2/32

            [Peer]
            PublicKey = {GATEWAY_PUBLIC}
            AllowedIPs = 0.0.0.0/0
            Endpoint = 203.0.113.10:51820
            PersistentKeepalive = 25
        "#
    );

    let profile = parse_profile_import(&raw, r"C:\Profils\site-labo.conf")
        .unwrap()
        .profile;
    assert_eq!(profile.name, "site-labo");
    assert_eq!(profile.endpoint, "203.0.113.10:51820");
    assert_eq!(profile.private_key.expose(), CLIENT_PRIVATE);
    assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
    assert_eq!(profile.persistent_keepalive, 25);
}

#[test]
fn refuses_multiple_peers() {
    let multiple = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\n[Peer]\nPublicKey={GATEWAY_PUBLIC}"
    );
    assert!(parse_profile_import(&multiple, "multi.conf")
        .unwrap_err()
        .to_string()
        .contains("un seul pair"));
}

/// An ordinary provider file carries `DNS`, `MTU`, `Table`. Refusing it
/// over them made Orion unable to open a normal WireGuard configuration;
/// dropping them without a word would hand back a different tunnel.
#[test]
fn an_ordinary_wireguard_file_imports_and_reports_what_is_not_applied() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\nDNS=100.64.0.1\nMTU=1380\nTable=off\nListenPort=51820\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nAllowedIPs=0.0.0.0/0\nPersistentKeepalive=25"
    );
    let imported = parse_profile_import(&contents, "fournisseur.conf").expect("import");
    assert_eq!(imported.profile.endpoint, "host:51820");
    assert_eq!(imported.profile.address.as_deref(), Some("100.64.1.2/32"));
    // `100.64.0.1` is CGNAT space, not a public resolver: the DNS notice
    // leads, because notices are sorted and it is the first field read.
    assert_eq!(imported.notices.len(), 4);
    assert!(imported.notices[0].starts_with("DNS = 100.64.0.1"));
    assert_eq!(imported.profile.dns, None);
    assert!(imported
        .notices
        .iter()
        .any(|notice| notice.contains("MTU = 1380")));
    assert!(imported
        .notices
        .iter()
        .any(|notice| notice.contains("Table = off")));
    // The DNS notice names the refused entry and the rule it broke.
    assert!(imported.notices[0].contains("100.64.0.1"));
    assert!(imported.notices[0].contains("seuls les résolveurs IPv4 publics"));
}

/// The `DNS =` line of a wg-quick file becomes the profile's resolvers, in
/// the order written, with no notice about it.
#[test]
fn a_dns_line_becomes_the_profile_dns() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\nDNS = 86.54.11.100, 1.1.1.1\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let imported = parse_profile_import(&contents, "dns.conf").expect("import");
    assert_eq!(
        imported.profile.dns,
        Some(vec![
            Ipv4Addr::new(86, 54, 11, 100),
            Ipv4Addr::new(1, 1, 1, 1)
        ])
    );
    assert!(!imported.notices.iter().any(|notice| notice.contains("DNS")));
}

/// IPv4 entries are kept; the IPv6 literal and the search domain are named,
/// not silently dropped.
#[test]
fn a_dns_line_keeps_ipv4_and_names_the_rest() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\nDNS = 1.1.1.1, 2606:4700::1111, corp.example\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let imported = parse_profile_import(&contents, "dns.conf").expect("import");
    assert_eq!(imported.profile.dns, Some(vec![Ipv4Addr::new(1, 1, 1, 1)]));
    let dns_notices: Vec<&String> = imported
        .notices
        .iter()
        .filter(|notice| notice.starts_with("DNS ="))
        .collect();
    assert_eq!(dns_notices.len(), 1, "notices: {:?}", imported.notices);
    assert!(dns_notices[0].contains("2606:4700::1111"));
    assert!(dns_notices[0].contains("corp.example"));
}

/// Without a public IPv4 resolver there is nothing to apply: the profile
/// keeps none, and the line is named.
#[test]
fn a_dns_line_without_ipv4_stays_a_notice() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\nDNS = 2606:4700::1111\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let imported = parse_profile_import(&contents, "dns.conf").expect("import");
    assert_eq!(imported.profile.dns, None);
    assert_eq!(imported.notices.len(), 1, "notices: {:?}", imported.notices);
    assert!(imported.notices[0].contains("2606:4700::1111"));
}

/// Private and duplicate IPv4 entries, and a fourth resolver, are refused by
/// the same rules as the gateway's list, and each one is named.
#[test]
fn a_dns_line_applies_the_resolver_rules_entry_by_entry() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n\
         DNS = 10.0.0.1, 1.1.1.1, 1.1.1.1, 8.8.8.8, 9.9.9.9, 4.4.4.4\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let imported = parse_profile_import(&contents, "dns.conf").expect("import");
    assert_eq!(
        imported.profile.dns,
        Some(vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 9, 9, 9),
        ])
    );
    let notice = imported
        .notices
        .iter()
        .find(|notice| notice.starts_with("DNS ="))
        .expect("un avis DNS");
    for refused in ["10.0.0.1", "1.1.1.1", "4.4.4.4"] {
        assert!(notice.contains(refused), "{refused} absent de : {notice}");
    }
}

/// The one class where refusing is right: a command the configuration
/// depends on, which Orion will not run.
#[test]
fn a_wireguard_file_that_runs_a_command_is_refused_by_name() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nPostUp=iptables -A FORWARD -i %i -j ACCEPT\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let error = parse_profile_import(&contents, "scripted.conf")
        .unwrap_err()
        .to_string();
    assert!(error.contains("postup"));
    assert!(error.contains("n'exécute aucune commande"));
}

/// A property nobody here knows about could mean anything, and guessing is
/// how a silent behaviour change gets shipped.
#[test]
fn an_unknown_wireguard_property_is_still_refused() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nQuantumTunnel=on\n\
         [Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    assert!(parse_profile_import(&contents, "odd.conf")
        .unwrap_err()
        .to_string()
        .contains("quantumtunnel"));
}

#[test]
fn refuses_invalid_keys_and_endpoint() {
    let bad_key = format!(
        "[Interface]\nPrivateKey=short\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    assert!(parse_profile_import(&bad_key, "invalid.conf").is_err());

    let url = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=https://vpn.example.net"
    );
    assert!(parse_profile_import(&url, "url.conf")
        .unwrap_err()
        .to_string()
        .contains("pas une URL"));
}

/// Absent is tolerated; **malformed** is refused.
///
/// The document used to be rejected for a missing virtual address, which
/// an invitation legitimately lacks — the VIP is assigned by the gateway
/// at admission. What must still be refused is an address that is present
/// and wrong: absent, the user fills it in; wrong, it produces a tunnel
/// that never routes and nothing says why.
#[test]
fn an_absent_address_is_tolerated_but_a_malformed_one_is_not() {
    let no_address = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let imported = parse_profile_import(&no_address, "no-address.conf")
        .expect("une invitation sans VIP doit se charger");
    assert_eq!(imported.profile.address, None);
    // …and the gap is named rather than passed over in silence.
    let completed =
        complete_profile_import(imported.profile, &ClientConfig::default(), Vec::new()).unwrap();
    assert!(completed
        .incomplete
        .expect("le manque doit être nommé")
        .contains("adresse"));

    let bad_address = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=pas-un-cidr\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    assert!(parse_profile_import(&bad_address, "bad-address.conf").is_err());
}

#[test]
fn refuses_an_unroutable_profile() {
    let no_keepalive = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nPersistentKeepalive=0"
    );
    assert!(parse_profile_import(&no_keepalive, "no-keepalive.conf")
        .unwrap_err()
        .to_string()
        .contains("supérieur à zéro"));
}

/// A file that states no `AllowedIPs` gets the full tunnel, both families.
///
/// Without `::/0` a dual-stack machine sends its IPv6 around the tunnel, in
/// clear, while the tunnel is up.
#[test]
fn an_absent_allowed_ips_imports_as_the_dual_stack_full_tunnel() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
    );
    let profile = parse_profile_import(&contents, "sans-allowedips.conf")
        .expect("import")
        .profile;
    assert_eq!(profile.allowed_ips, "0.0.0.0/0, ::/0");
    assert!(!profile.ipv6_uncaptured_full_tunnel());
}

/// A file that states `0.0.0.0/0` alone is imported as written, and named.
///
/// Widening it on the way in would route traffic its author did not list;
/// the import is a draft the user reviews, and the flag is what the screen
/// warns with.
#[test]
fn an_ipv4_only_full_tunnel_is_imported_as_written_and_flagged() {
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nAllowedIPs=0.0.0.0/0"
    );
    let profile = parse_profile_import(&contents, "ipv4.conf")
        .expect("import")
        .profile;
    assert_eq!(profile.allowed_ips, "0.0.0.0/0");
    assert!(profile.ipv6_uncaptured_full_tunnel());

    // The usual `wg-quick` spelling of the dual-stack tunnel lands in the
    // canonical form, flag down.
    let contents = format!(
        "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nAllowedIPs=0.0.0.0/0,::/0"
    );
    let profile = parse_profile_import(&contents, "dual.conf")
        .expect("import")
        .profile;
    assert_eq!(profile.allowed_ips, crate::DEFAULT_ALLOWED_IPS);
    assert!(!profile.ipv6_uncaptured_full_tunnel());
}
