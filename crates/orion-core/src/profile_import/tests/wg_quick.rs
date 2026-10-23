//! The single-peer `wg-quick` format: what is applied, what is reported as
//! not applied, and what is refused.

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
    assert_eq!(imported.notices.len(), 4);
    // Sorted, so two imports of one file report the same thing in the same
    // order.
    assert!(imported.notices[0].starts_with("DNS = 100.64.0.1"));
    assert!(imported
        .notices
        .iter()
        .any(|notice| notice.contains("MTU = 1380")));
    assert!(imported
        .notices
        .iter()
        .any(|notice| notice.contains("Table = off")));
    // The DNS notice names the consequence, which is the documented limit
    // the user has no other way to learn.
    assert!(imported.notices[0].contains("hors du tunnel"));
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
