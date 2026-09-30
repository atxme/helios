//! Per-field inspection of a profile: what is reported, what is refused, and
//! what an unfinished profile is allowed to leave empty.

use super::fixtures::{complete_profile, CLIENT_PRIVATE};
use crate::profile_import::{
    inspect_profile, tunnel_capture, validate_imported_profile, validate_ssh_target, TunnelCapture,
};
use crate::ClientProfile;

/// A mistyped IPv4 must not pass for a domain name.
///
/// `86.229.1286` is the real case: 1286 exceeds 255, but the string
/// remains syntactically acceptable as a sequence of labels. Without the
/// RFC 1123 rule on the numeric last label, the defect only showed up at
/// the first handshake, as a failing DNS resolution.
#[test]
fn a_malformed_ip_address_does_not_pass_for_a_hostname() {
    for accepted in [
        "86.229.12.86:51820",
        "vpn.example.net:51820",
        "gateway:51820",
        "[2a01:cb1e:101d:4b5c::1]:51820",
    ] {
        let profile = ClientProfile {
            endpoint: accepted.into(),
            ..complete_profile()
        };
        assert_eq!(
            inspect_profile(&profile).endpoint,
            None,
            "{accepted} should have been accepted"
        );
    }

    for refused in [
        "86.229.1286:51820",
        "256.1.1.1:51820",
        "10.0.0:51820",
        "[zz::1]:51820",
        "-mauvais.example.net:51820",
        "vpn..example.net:51820",
    ] {
        let profile = ClientProfile {
            endpoint: refused.into(),
            ..complete_profile()
        };
        assert!(
            inspect_profile(&profile).endpoint.is_some(),
            "{refused} should have been refused"
        );
    }
}

/// The message must say **what's expected**, not just that it's refused.
/// "base64 expected" doesn't help see that a copy-paste was truncated;
/// the observed length against the expected 44 characters does.
#[test]
fn the_message_for_an_invalid_key_gives_the_expected_length() {
    let truncated = &CLIENT_PRIVATE[..CLIENT_PRIVATE.len() - 4];
    let profile = ClientProfile {
        private_key: truncated.into(),
        ..complete_profile()
    };
    let message = inspect_profile(&profile)
        .private_key
        .expect("a truncated key must be refused");
    assert!(message.contains("44"), "message: {message}");
    assert!(message.contains("clé privée"), "message: {message}");

    let profile = ClientProfile {
        peer_public_key: "not base64 at all!".into(),
        ..complete_profile()
    };
    let message = inspect_profile(&profile)
        .peer_public_key
        .expect("forbidden characters must be refused");
    assert!(message.contains("44"), "message: {message}");
}

#[test]
fn a_valid_profile_reports_no_field() {
    assert!(!inspect_profile(&complete_profile()).any());
}

/// While typing, "not filled in yet" is not "impossible": marking a
/// fresh profile red would be noise.
#[test]
fn empty_fields_are_not_reported() {
    let issues = inspect_profile(&ClientProfile::default());
    assert_eq!(issues.endpoint, None);
    assert_eq!(issues.private_key, None);
    assert_eq!(issues.peer_public_key, None);
    assert_eq!(issues.address, None);
}

/// `AllowedIPs` is a list, and a split tunnel is why.
///
/// One prefix used to be the limit, so reaching both the VPN network and
/// a remote LAN — which share no supernet short of `0.0.0.0/0` — meant
/// choosing one or routing the whole Internet.
#[test]
fn allowed_ips_accepts_several_prefixes_and_names_the_faulty_one() {
    let several = ClientProfile {
        allowed_ips: "100.64.0.0/10, 192.168.1.0/24, fd00::/8".into(),
        ..complete_profile()
    };
    assert_eq!(inspect_profile(&several).allowed_ips, None);
    assert!(validate_imported_profile(several).is_ok());

    // Spelling is normalized on the way in: the screen writes one form,
    // a `wg-quick` file another, and a profile reloaded in a spelling it
    // was not saved in reads as modified.
    let unspaced = ClientProfile {
        allowed_ips: "100.64.0.0/10,192.168.1.0/24".into(),
        ..complete_profile()
    };
    assert_eq!(
        validate_imported_profile(unspaced)
            .expect("import")
            .allowed_ips,
        "100.64.0.0/10, 192.168.1.0/24"
    );

    // A faulty entry names its position: "the second is wrong" is what
    // turns a rejected list into a fixed one.
    let faulty = ClientProfile {
        allowed_ips: "100.64.0.0/10, 192.168.1.0/33".into(),
        ..complete_profile()
    };
    let reported = inspect_profile(&faulty)
        .allowed_ips
        .expect("the faulty prefix is reported");
    assert!(reported.contains("préfixe 2 sur 2"), "{reported}");

    // A prefix written twice is a list its author has lost track of.
    let duplicated = ClientProfile {
        allowed_ips: "10.0.0.0/8, 10.0.0.0/8".into(),
        ..complete_profile()
    };
    assert!(inspect_profile(&duplicated).allowed_ips.is_some());

    // And an empty list still cannot mount a tunnel that captures nothing.
    let empty = ClientProfile {
        allowed_ips: " , ".into(),
        ..complete_profile()
    };
    assert!(validate_imported_profile(empty).is_err());
}

/// The full tunnel stored before `::/0` joined the default is named, and
/// nothing else is.
///
/// A split tunnel is not a leak to report: routing one subnet and leaving the
/// rest alone is a decision the operator took. `0.0.0.0/0` alone is not a
/// decision of that kind — it is the old default, and a profile still holding
/// it believes it is protected while its IPv6 leaves in clear.
#[test]
fn only_an_ipv4_only_full_tunnel_is_flagged() {
    for (allowed_ips, expected) in [
        ("0.0.0.0/0", TunnelCapture::Ipv4Only),
        ("0.0.0.0/0, ::/0", TunnelCapture::Full),
        ("100.64.0.1/32, 10.0.0.0/8", TunnelCapture::Partial),
        ("::/0", TunnelCapture::Partial),
        // IPv6 routed in part is still IPv6 leaving in part.
        ("0.0.0.0/0, fd00::/8", TunnelCapture::Ipv4Only),
        // Read as the rest of the core reads the list: order, spacing and
        // empty entries change nothing.
        ("::/0,0.0.0.0/0", TunnelCapture::Full),
        (" 0.0.0.0/0 ,, ", TunnelCapture::Ipv4Only),
        ("  ::/0 , 10.0.0.0/8,0.0.0.0/0 ", TunnelCapture::Full),
        // The address of a whole-family prefix is irrelevant, as it is to
        // WireGuard: `/0` is the length that decides.
        ("10.1.2.3/0, 0::/0", TunnelCapture::Full),
        // What validation refuses captures nothing here either.
        ("0.0.0.0", TunnelCapture::Partial),
        ("0.0.0.0/0, ::/zero", TunnelCapture::Ipv4Only),
        ("", TunnelCapture::Partial),
    ] {
        assert_eq!(tunnel_capture(allowed_ips), expected, "{allowed_ips:?}");
        let profile = ClientProfile {
            allowed_ips: allowed_ips.into(),
            ..complete_profile()
        };
        assert_eq!(
            profile.ipv6_uncaptured_full_tunnel(),
            expected == TunnelCapture::Ipv4Only,
            "{allowed_ips:?}"
        );
    }
}

/// The allow-list holds against everything a shell could read as syntax.
///
/// This field becomes an argument of a spawned process, so the test is
/// written as a refusal list rather than an acceptance one: what matters
/// is not that `user@host` works, it is that nothing else does.
#[test]
fn an_ssh_target_refuses_everything_a_shell_could_read() {
    for accepted in [
        "christophe@100.64.0.1",
        "100.64.0.1",
        "gateway.example.net",
        "root@gw-01.internal:2222",
        "a_b.c-d@host_1.example",
    ] {
        assert!(
            validate_ssh_target(accepted).is_ok(),
            "`{accepted}` should be accepted"
        );
    }

    for refused in [
        "",
        "   ",
        // Command substitution and chaining, in every spelling.
        "user@host; rm -rf /",
        "user@host && calc.exe",
        "user@host | more",
        "user@$(whoami)",
        "user@`hostname`",
        "user@host\nsecond",
        // Quoting and expansion.
        "user@host'",
        "user@\"host\"",
        "user@${env:PATH}",
        // Argument injection into `ssh` itself: `-o` would set options,
        // and no amount of quoting by the launcher would stop it.
        "-oProxyCommand=calc",
        "-lroot",
        // Shape faults.
        "user@@host",
        "@host",
        "user@",
        "user@host:0",
        "user@host:notaport",
        "user @host",
    ] {
        assert!(
            validate_ssh_target(refused).is_err(),
            "`{refused}` should be refused"
        );
    }
}

/// A document carrying a hostile destination is refused as a whole.
///
/// The launcher is not the only gate, and must not be the first: a
/// profile that would never be safe to launch has no business being
/// stored, displayed as valid, or handed to another machine.
#[test]
fn a_document_with_a_hostile_ssh_target_does_not_import() {
    let hostile = ClientProfile {
        ssh_target: Some("user@host; calc.exe".into()),
        ..complete_profile()
    };
    assert!(inspect_profile(&hostile).ssh_target.is_some());
    assert!(validate_imported_profile(hostile).is_err());

    let sound = ClientProfile {
        ssh_target: Some("  christophe@100.64.0.1  ".into()),
        ..complete_profile()
    };
    assert_eq!(inspect_profile(&sound).ssh_target, None);
    assert_eq!(
        validate_imported_profile(sound).expect("import").ssh_target,
        Some("christophe@100.64.0.1".into()),
        "trimmed on the way in, so the launcher never sees padding"
    );
}

/// The point of inspection versus import: it doesn't stop at the first
/// fault, otherwise the UI would discover one per attempt.
#[test]
fn all_faulty_fields_are_reported_in_one_pass() {
    let profile = ClientProfile {
        endpoint: "https://vpn.example.net".into(),
        private_key: "not-base64".into(),
        peer_public_key: "AAAA".into(),
        address: Some("100.64.1.2".into()),
        allowed_ips: "0.0.0.0/33".into(),
        persistent_keepalive: 0,
        heliosd_url: Some("100.64.0.1:8080".into()),
        ..complete_profile()
    };
    let issues = inspect_profile(&profile);

    assert!(issues.any());
    for (field, value) in [
        ("endpoint", &issues.endpoint),
        ("private_key", &issues.private_key),
        ("peer_public_key", &issues.peer_public_key),
        ("address", &issues.address),
        ("allowed_ips", &issues.allowed_ips),
        ("persistent_keepalive", &issues.persistent_keepalive),
        ("heliosd_url", &issues.heliosd_url),
    ] {
        assert!(value.is_some(), "{field} should have been reported");
    }
}

/// Zero is not "empty": it's a value, and it cuts off the keepalive a
/// client behind NAT depends on.
#[test]
fn a_zero_keepalive_is_reported_while_an_absent_psk_is_not() {
    let profile = ClientProfile {
        persistent_keepalive: 0,
        preshared_key: None,
        ..complete_profile()
    };
    let issues = inspect_profile(&profile);
    assert!(issues.persistent_keepalive.is_some());
    assert_eq!(issues.preshared_key, None);
}
