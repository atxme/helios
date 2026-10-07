//! Layouts checked on data recorded from a real gateway (2026-10-07).

use super::*;
use serde_json::json;

fn ui() -> Ui {
    Ui::plain(None)
}

fn peer(name: &str, address: &str, key: &str, admin: bool, age: Option<u64>) -> serde_json::Value {
    json!({
        "name": name, "public_key": key, "address": address, "post_quantum": false,
        "admin": admin, "minimum_key_negotiation_mode": "ml_kem",
        "last_handshake_age_seconds": age, "endpoint": null, "rx_bytes": 0, "tx_bytes": 0
    })
}

fn status(peers: Vec<serde_json::Value>) -> Status {
    serde_json::from_value(json!({
        "state": "connecting", "version": "1.13.0",
        "wan_ifaces": ["enp3s0", "wlo1"], "lan_ifaces": [], "wg_peers": [],
        "allow_ssh_from": ["192.168.1.0/24"], "admin_ifaces": ["nordlynx", "tailscale0"],
        "peers": peers, "wg_iface": "helios0", "wg_listen_port": 51820,
        "key_negotiation_port": 51821, "dry_run": false, "split_tunnel_cidrs": [],
        "mss_clamp": null, "captive_portal_gateway": null,
        "handshake_stale_after_seconds": 150
    }))
    .unwrap()
}

fn gateway_peers() -> Vec<serde_json::Value> {
    vec![
        peer(
            "poste-windows",
            "100.89.226.187/32",
            "cm1DqUEUmH+XvzwAWOtOl/fPJpWpAVDKCmc7Fcmk6io=",
            true,
            None,
        ),
        peer(
            "PC_fixe",
            "100.107.188.1/32",
            "cDKSBeCalPSZlBLT5/0WSl0jQB0mGV/L9x3cbHHKhjA=",
            false,
            None,
        ),
        peer(
            "PC_FIXE",
            "100.113.230.223/32",
            "JYujqyV5xe61wq/ohMFtJCIMCvBc9aCGLTar1WG+gVM=",
            true,
            None,
        ),
    ]
}

#[test]
fn status_leads_with_the_state_and_points_to_the_peer_list() {
    let text = render_status(&ui(), &status(gateway_peers()));
    assert!(
        text.contains("● waiting for clients  0 of 3 peers online · heliosd v1.13.0 · real"),
        "{text}"
    );
    assert!(text.contains("  Uplinks       enp3s0, wlo1\n"), "{text}");
    assert!(
        text.contains("  Tunnel        helios0 · UDP 51820 · negotiation UDP 51821\n"),
        "{text}"
    );
    assert!(text.contains("  LAN           none\n"), "{text}");
    assert!(
        text.contains(
            "  SSH           from 192.168.1.0/24 · out-of-band via nordlynx, tailscale0\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("No peer online — /peer list shows the 3 admitted peers."),
        "{text}"
    );
    assert!(
        !text.contains("poste-windows"),
        "peers belong to /peer list: {text}"
    );
}

#[test]
fn status_lists_only_the_peers_that_are_online() {
    let mut peers = gateway_peers();
    peers[1]["last_handshake_age_seconds"] = json!(12);
    peers[1]["rx_bytes"] = json!(2 * 1024 * 1024);
    peers[1]["tx_bytes"] = json!(340 * 1024);
    peers[1]["endpoint"] = json!("203.0.113.7:51820");
    let mut online = status(peers);
    online.state = "up".into();
    let text = render_status(&ui(), &online);
    assert!(text.contains("● up  1 of 3 peers online"), "{text}");
    assert!(
        text.contains("NAME     ADDRESS        HANDSHAKE  TRAFFIC"),
        "{text}"
    );
    assert!(
        text.contains(
            "PC_fixe  100.107.188.1  12 s ago   ↓ 2.0 MiB  ↑ 340.0 KiB  –    203.0.113.7:51820"
        ),
        "{text}"
    );
    assert!(!text.contains("poste-windows"), "{text}");
}

#[test]
fn peer_list_is_a_table_with_roles_handshakes_and_short_keys() {
    let text = render_peers(&ui(), &status(gateway_peers()));
    assert!(
        text.contains("Peers  3 admitted · 2 admin · 0 online"),
        "{text}"
    );
    let header = text.lines().find(|line| line.contains("NAME")).unwrap();
    assert_eq!(
        header.split_whitespace().collect::<Vec<_>>(),
        ["NAME", "ADDRESS", "ROLE", "HANDSHAKE", "TRAFFIC", "KEY"]
    );
    assert!(
        text.contains("poste-windows  100.89.226.187   admin  never      –        cm1DqUEU"),
        "{text}"
    );
    assert!(
        text.contains("PC_fixe        100.107.188.1    –      never"),
        "{text}"
    );
    assert!(
        text.contains("Every peer requires ML-KEM key negotiation."),
        "{text}"
    );
    assert!(
        !text.contains("[key-nego]") && !text.contains("min="),
        "{text}"
    );
}

#[test]
fn mixed_negotiation_modes_get_their_own_column() {
    let mut peers = gateway_peers();
    peers[2]["minimum_key_negotiation_mode"] = json!("classic");
    let text = render_peers(&ui(), &status(peers));
    assert!(text.contains("MIN MODE"), "{text}");
    assert!(text.contains("classic"), "{text}");
    assert!(!text.contains("Every peer requires"), "{text}");
}

#[test]
fn network_groups_the_configuration_without_repeating_peers() {
    let view: NetworkConfigView = serde_json::from_value(json!({
        "wan_ifaces": ["enp3s0", "wlo1"], "lan_ifaces": [], "allow_ssh_from": ["192.168.1.0/24"],
        "admin_ifaces": ["nordlynx", "tailscale0"], "admin_iface": "helios0",
        "wg_iface": "helios0", "wg_private_key_configured": true,
        "wg_public_key": "6Y8gpK+aOPbZvSnQnIbdQGTBoe5trFFWksGJVKlH3wk=",
        "wg_address": "100.64.0.1/10", "wg_listen_port": 51820, "key_negotiation_port": 51821,
        "peers": []
    }))
    .unwrap();
    let text = render_network(&ui(), &view);
    for expected in [
        "  Tunnel        helios0 · 100.64.0.1/10 · UDP 51820\n",
        "  Negotiation   UDP 51821\n",
        "  Gateway key   6Y8gpK+aOPbZvSnQnIbdQGTBoe5trFFWksGJVKlH3wk= · private key present, never shown\n",
        "  Admin API     through helios0 only\n",
        "  Out-of-band   SSH via nordlynx, tailscale0\n",
        "  SSH from      192.168.1.0/24\n",
        "  Peers         0 admitted · 0 admin · 0 with pinned negotiation certificates — /peer list\n",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text}");
    }
}

#[test]
fn health_reads_cleanly_and_says_when_a_reading_is_missing() {
    let view = HealthView {
        uptime_seconds: Some(7 * 86_400 + 60),
        load: Some([0.04, 0.03, 0.0]),
        cpu_count: Some(16),
        memory_total_bytes: Some(16_000_000_000),
        memory_available_bytes: Some(14_500_000_000),
        temperature_celsius: Some(55.0),
        tpm: Some(TpmView {
            kind: "unsealed".into(),
            preserved_vaults: true,
        }),
    };
    let text = render_health(&ui(), &view);
    assert!(text.contains("  Uptime        7 d 00 h\n"), "{text}");
    assert!(
        text.contains("  Load          0.04 0.03 0.00 on 16 CPU\n"),
        "{text}"
    );
    assert!(text.contains("13.5 GiB free of 14.9 GiB (90 %)"), "{text}");
    assert!(
        text.contains("  TPM           unsealed · sealed vaults preserved\n"),
        "{text}"
    );
    let empty = HealthView {
        uptime_seconds: None,
        load: None,
        cpu_count: None,
        memory_total_bytes: None,
        memory_available_bytes: None,
        temperature_celsius: None,
        tpm: None,
    };
    let text = render_health(&ui(), &empty);
    assert!(text.contains("  TPM           not validated\n"), "{text}");
    assert_eq!(text.matches("unknown").count(), 4, "{text}");
}

const RULESET: &str = "table inet helios {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state invalid counter drop  # invalid conntrack state: dropped before every opening
    tcp dport 8080 iifname \"helios0\" accept  # administration API: only via the tunnel interface
    iifname \"lo\" accept
    iifname \"enp3s0\" udp dport 51820 accept  # WireGuard listener
    iifname \"wlo1\" udp dport 51820 accept  # WireGuard listener
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oifname \"lo\" accept
  }
}";

fn certificates() -> DomainView {
    let now = 1_791_400_000;
    let cert = |name: &str, key: &str, phase: ValidityPhase, days: i64| PeerCertView {
        name: name.into(),
        wg_public_key: key.into(),
        generation: 1,
        not_after: (now as i64 + days * 86_400) as u64,
        phase,
        revoked: false,
    };
    DomainView {
        trust_domain_id: "2b2c6cf0d361ca34f4b7fd17adb899d0".into(),
        server_name: "christophe-msi.tail1fc2ee.ts.net".into(),
        now_unix: now,
        ca_epoch: 1,
        ca_pq_fingerprint: "b09755924c6d9d10aa".into(),
        ca_transition_pending: false,
        gateway_identity_epoch: 1,
        gateway_tls_fingerprint: "203008d9ec8d1ee5".into(),
        gateway_pq_fingerprint: "e7a5faf2e538d1e5".into(),
        gateway_transition_pending: false,
        astra_authority_url: "https://christophe-msi.tail1fc2ee.ts.net".into(),
        issuer: Some(IssuerView {
            issuer_epoch: 1,
            not_after: now - (22 * 3_600 + 35 * 60),
            usable: false,
        }),
        peers: vec![
            cert("PC_FIXE", "JYujqyV5xe61", ValidityPhase::Valid, 807),
            cert(
                "recuperation-1",
                "Y8fR741ZQERM",
                ValidityPhase::Expired,
                -30,
            ),
            cert("PC_FIXE", "cDKSBeCalPSZ", ValidityPhase::Valid, 795),
            cert("phone\x1b[2J", "abcdefgh1234", ValidityPhase::RenewalDue, 5),
        ],
    }
}

#[test]
fn certificates_put_problems_first_and_tell_duplicates_apart() {
    let raw = render_certificates(&ui(), &certificates());
    assert!(!raw.contains('\x1b'));
    assert!(
        raw.contains("  Issuer        epoch 1 expired 22 h 35 min ago — clients cannot renew\n"),
        "{raw}"
    );
    assert!(
        raw.contains("Clients  4 total · 3 valid · 1 expired"),
        "{raw}"
    );
    let rows: Vec<&str> = raw.lines().filter(|line| line.contains("gen 1")).collect();
    assert!(
        rows[0].contains("✗")
            && rows[0].contains("recuperation-1")
            && rows[0].contains("expired 30 d 00 h ago"),
        "{raw}"
    );
    assert!(
        rows[1].contains("phone[2J") && rows[1].contains("renewal due · expires in 5 d 00 h"),
        "{raw}"
    );
    assert!(
        rows.iter()
            .any(|row| row.contains("PC_FIXE") && row.contains("JYujqyV5")),
        "{raw}"
    );
    assert!(
        rows.iter()
            .any(|row| row.contains("PC_FIXE") && row.contains("cDKSBeCa")),
        "{raw}"
    );
}

#[test]
fn trust_and_negotiation_labels_stay_in_their_column() {
    let view = TrustView {
        required_algs: vec!["ed25519".into(), "ml-dsa-65".into()],
        publisher_keys: vec![PublisherKeyView {
            key_epoch: 1,
            fingerprint: "a7e7ed37a0234a618af27106790e66d9".into(),
        }],
        development_keys: false,
        reseal_domain: "helios-tpm-reseal-v2".into(),
        reseal_format_version: 2,
    };
    let text = render_trust(&ui(), &view);
    assert!(
        text.contains("  Signatures    ed25519 + ml-dsa-65 (all required)\n"),
        "{text}"
    );
    assert!(
        text.contains("  Publisher     epoch 1 · a7e7ed37a0234a618af27106790e66d9\n"),
        "{text}"
    );
    assert!(
        text.contains("  TPM reseal    helios-tpm-reseal-v2 · format 2\n"),
        "{text}"
    );
}

#[test]
fn release_says_which_staged_releases_can_still_be_activated() {
    let view = UpdateStatus {
        highest_confirmed_sequence: 1_791_100_159,
        active_version: Some("1.13.0".into()),
        staged: vec![
            helios_update::FinalizedRelease {
                release_sequence: 1_788_289_254,
                version: "1.12.0".into(),
                sha256: "b9c01190d26f9346aa".into(),
            },
            helios_update::FinalizedRelease {
                release_sequence: 1_791_200_000,
                version: "1.14.0".into(),
                sha256: "0123456789abcdef".into(),
            },
        ],
        activation_pending: None,
        channel: "production".into(),
        target: "x86_64-unknown-linux-gnu".into(),
    };
    let text = render_release(&ui(), &view);
    assert!(
        text.contains("Release  heliosd 1.13.0 · production · x86_64-unknown-linux-gnu"),
        "{text}"
    );
    assert!(
        text.contains("1.12.0   1788289254  b9c01190d26f  superseded — cannot be activated"),
        "{text}"
    );
    assert!(
        text.contains("1.14.0   1791200000  0123456789ab  ready to activate"),
        "{text}"
    );
}

const JOURNAL: &str = "2026-10-07T20:20:45+02:00 christophe-MSI heliosd[53978]: 2026-10-07T18:20:45.012968Z  INFO helios_api::auth: admin command authenticated pair=local:uid=1000";

#[test]
fn log_lines_keep_time_level_and_message_only() {
    let text = render_log_line(&ui(), JOURNAL, false);
    assert_eq!(
        text,
        "  10-07 20:20:45  INFO   admin command authenticated pair=local:uid=1000\n"
    );
    let verbose = render_log_line(&ui(), JOURNAL, true);
    assert!(
        verbose.contains("INFO   helios_api::auth admin command"),
        "{verbose}"
    );
    assert_eq!(
        render_log_line(&ui(), "-- No entries --", false),
        "  -- No entries --\n"
    );
    let narrow = render_log_line(&Ui::plain(Some(50)), JOURNAL, false);
    let lines: Vec<&str> = narrow.lines().collect();
    assert!(lines.len() > 1, "{narrow}");
    assert!(lines[1].starts_with(&" ".repeat(25)), "{narrow}");
    assert!(
        lines.iter().all(|line| line.chars().count() < 50),
        "{narrow}"
    );
}

#[test]
fn journal_arguments_never_reach_a_shell() {
    assert_eq!(
        journal_args(50, false),
        [
            "--namespace=helios",
            "-u",
            "heliosd",
            "-n",
            "50",
            "--no-pager",
            "-o",
            "short-iso"
        ]
    );
    assert!(journal_args(10, true).contains(&"--follow".to_owned()));
}

fn healthy() -> DoctorInputs {
    let mut domain = certificates();
    domain.issuer = None;
    domain
        .peers
        .retain(|peer| peer.phase == ValidityPhase::Valid);
    DoctorInputs {
        transport: "local".into(),
        status: Ok(StatusFacts {
            state: "up".into(),
            dry_run: false,
            online: 2,
            total: 17,
        }),
        health: Ok(HealthView {
            uptime_seconds: Some(60),
            load: None,
            cpu_count: None,
            memory_total_bytes: Some(100),
            memory_available_bytes: Some(90),
            temperature_celsius: Some(55.0),
            tpm: Some(TpmView {
                kind: "unsealed".into(),
                preserved_vaults: true,
            }),
        }),
        firewall: Ok(FirewallView {
            rules: RULESET.into(),
            default_verdict: "drop".into(),
            dry_run: false,
        }),
        domain: Ok(Some(domain)),
        release: Ok(UpdateStatus {
            highest_confirmed_sequence: 1,
            active_version: Some("1.13.0".into()),
            staged: Vec::new(),
            activation_pending: None,
            channel: "production".into(),
            target: "x86_64-unknown-linux-gnu".into(),
        }),
    }
}

#[test]
fn a_healthy_gateway_passes_every_check() {
    let checks = diagnose(&healthy());
    assert!(
        checks.iter().all(|check| check.level == Level::Ok),
        "{checks:?}"
    );
    assert!(render_doctor(&ui(), &checks).contains("all checks passed"));
}

#[test]
fn the_doctor_says_why_a_check_fails() {
    let mut inputs = healthy();
    inputs.status = Ok(StatusFacts {
        state: "connecting".into(),
        dry_run: false,
        online: 0,
        total: 17,
    });
    inputs.domain = Ok(Some(certificates()));
    inputs.firewall.as_mut().unwrap().default_verdict = "accept".into();
    inputs.release = Err("403 Forbidden".into());
    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("Tunnel").level, Level::Warn);
    assert_eq!(find("Certificates").level, Level::Fail);
    assert_eq!(
        find("Certificates").detail,
        "issuer expired 22 h 35 min ago — clients cannot renew"
    );
    assert_eq!(find("Firewall").level, Level::Fail);
    assert_eq!(find("Release").level, Level::Fail);
    let text = render_doctor(&ui(), &checks);
    assert!(text.contains("3 failed, 1 warning"), "{text}");
    assert!(
        text.contains("waiting for clients · 0/17 peers online"),
        "{text}"
    );
}

#[test]
fn expiring_clients_are_named() {
    let mut inputs = healthy();
    let mut domain = certificates();
    domain.issuer = None;
    inputs.domain = Ok(Some(domain));
    let checks = diagnose(&inputs);
    let certificates = checks
        .iter()
        .find(|check| check.label == "Certificates")
        .unwrap();
    assert_eq!(certificates.level, Level::Warn);
    assert_eq!(
        certificates.detail,
        "1 client(s) expired or expiring: recuperation-1"
    );
}

#[test]
fn an_unreachable_api_is_one_failure_not_a_cascade_of_guesses() {
    let mut inputs = healthy();
    inputs.status = Err("connection refused".into());
    let checks = diagnose(&inputs);
    let api = checks.iter().find(|check| check.label == "API").unwrap();
    assert_eq!(api.level, Level::Fail);
    assert!(checks.iter().all(|check| check.label != "Tunnel"));
}
