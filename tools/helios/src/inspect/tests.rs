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

fn status_json(peers: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "state": "connecting", "version": "1.13.0",
        "wan_ifaces": ["enp3s0", "wlo1"], "lan_ifaces": [], "wg_peers": [],
        "allow_ssh_from": ["192.168.1.0/24"], "admin_ifaces": ["nordlynx", "tailscale0"],
        "peers": peers, "wg_iface": "helios0", "wg_listen_port": 51820,
        "key_negotiation_port": 51821, "dry_run": false, "split_tunnel_cidrs": [],
        "mss_clamp": null, "captive_portal_gateway": null,
        "handshake_stale_after_seconds": 150
    })
}

fn status(peers: Vec<serde_json::Value>) -> Status {
    serde_json::from_value(status_json(peers)).unwrap()
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
    peers[2]["minimum_key_negotiation_mode"] = json!(null);
    let text = render_peers(&ui(), &status(peers));
    assert!(text.contains("MIN MODE"), "{text}");
    assert!(text.contains("plain WireGuard"), "{text}");
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

fn loopback_client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("loopback client")
}

async fn doctor_fixture(replies: [(&'static str, String); 5]) -> Result<()> {
    let (base, server) = crate::tests::http_response_sequence(replies).await;
    let api = Api {
        client: loopback_client(),
        base,
        socket: None,
    };
    let result = doctor(&api).await;
    let requests = server.await.expect("doctor requests");
    let routes = requests
        .iter()
        .map(|request| request.lines().next().expect("request line"))
        .collect::<Vec<_>>();
    assert_eq!(
        routes,
        [
            "GET /api/status HTTP/1.1",
            "GET /api/health HTTP/1.1",
            "GET /api/firewall/rules HTTP/1.1",
            "GET /api/certificates HTTP/1.1",
            "GET /api/update HTTP/1.1",
        ]
    );
    result
}

fn firewall_json() -> String {
    json!({"rules": RULESET, "default_verdict": "drop", "dry_run": false}).to_string()
}

#[tokio::test]
async fn doctor_succeeds_when_the_optional_certificates_endpoint_is_absent() {
    let mut peers = gateway_peers();
    peers[0]["last_handshake_age_seconds"] = json!(12);
    let mut status = status_json(peers);
    status["state"] = json!("up");
    let outcome = doctor_fixture([
        ("200 OK", status.to_string()),
        (
            "200 OK",
            json!({
                "tpm": {"kind": "unsealed", "preserved_vaults": true},
                "memory_total_bytes": 100,
                "memory_available_bytes": 90,
                "temperature_celsius": 55.0
            })
            .to_string(),
        ),
        ("200 OK", firewall_json()),
        ("404 Not Found", "no trust domain".into()),
        (
            "200 OK",
            serde_json::to_string(&healthy().release.unwrap()).unwrap(),
        ),
    ])
    .await;

    outcome.expect("absence of a trust domain is only a warning");
}

#[tokio::test]
async fn doctor_collects_failures_across_all_routes_before_exiting() {
    let outcome = doctor_fixture([
        ("503 Service Unavailable", "gateway starting".into()),
        ("200 OK", r#"{"tpm":{"kind":null}}"#.into()),
        (
            "200 OK",
            json!({"rules": "", "default_verdict": "accept", "dry_run": false}).to_string(),
        ),
        ("403 Forbidden", "certificate inventory refused".into()),
        ("200 OK", "invalid JSON".into()),
    ])
    .await;

    assert_eq!(
        outcome.expect_err("all five checks failed").to_string(),
        "5 check(s) failed"
    );
}

#[tokio::test]
async fn negotiation_reads_public_material_for_open_and_closed_udp_ports() {
    for port in [Some(51821), None] {
        let body = json!({
            "port": port,
            "server_name": "gateway.example",
            "wireguard_public_key": "test-gateway-key",
            "pq_certificate_sha256": "test-fingerprint"
        });
        let (base, server) = crate::tests::one_response_server("200 OK", body.to_string()).await;

        negotiation(&loopback_client(), &base)
            .await
            .expect("public negotiation material is readable for either port state");
        assert!(server
            .await
            .unwrap()
            .starts_with("GET /api/key-negotiation HTTP/1.1\r\n"));
    }
}

#[tokio::test]
async fn negotiation_reports_a_gateway_that_has_no_public_material() {
    let (base, server) = crate::tests::one_response_server("404 Not Found", "not found").await;

    let error = negotiation(&loopback_client(), &base)
        .await
        .expect_err("missing negotiation material");
    assert_eq!(
        error.to_string(),
        "this gateway serves no key-negotiation material"
    );
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/key-negotiation HTTP/1.1\r\n"));
}

#[tokio::test]
async fn certificates_distinguishes_missing_domain_from_an_http_refusal() {
    for (status, expected) in [
        (
            "404 Not Found",
            "this gateway has no trust domain — run `heliosd init-trust-domain`",
        ),
        ("403 Forbidden", "403 Forbidden : inventory unavailable"),
    ] {
        let (base, server) =
            crate::tests::one_response_server(status, "inventory unavailable").await;
        let error = super::certificates(&loopback_client(), &base)
            .await
            .expect_err("certificate inventory not available");
        assert_eq!(error.to_string(), expected);
        assert!(server
            .await
            .unwrap()
            .starts_with("GET /api/certificates HTTP/1.1\r\n"));
    }
}

#[tokio::test]
async fn firewall_fetches_the_same_read_only_rules_for_raw_and_summary_modes() {
    for raw in [false, true] {
        let (base, server) = crate::tests::one_response_server("200 OK", firewall_json()).await;

        super::firewall(&loopback_client(), &base, raw)
            .await
            .expect("read kernel rules without applying them");
        assert!(server
            .await
            .unwrap()
            .starts_with("GET /api/firewall/rules HTTP/1.1\r\n"));
    }
}

#[tokio::test]
async fn certificates_accepts_an_inventory_with_rotations_pending() {
    let domain = json!({
        "trust_domain_id": "test-domain",
        "server_name": "gateway.example",
        "now_unix": 1_791_400_000,
        "ca_epoch": 1,
        "ca_pq_fingerprint": "test-ca-pq",
        "ca_transition_pending": true,
        "gateway_identity_epoch": 2,
        "gateway_tls_fingerprint": "test-gateway-tls",
        "gateway_pq_fingerprint": "test-gateway-pq",
        "gateway_transition_pending": true,
        "astra_authority_url": "https://astra.example",
        "issuer": null,
        "peers": []
    });
    let (base, server) = crate::tests::one_response_server("200 OK", domain.to_string()).await;

    super::certificates(&loopback_client(), &base)
        .await
        .expect("pending rotations are valid inventory data");
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/certificates HTTP/1.1\r\n"));
}

#[test]
fn trust_warns_when_development_keys_are_enabled_without_publisher_keys() {
    let text = render_trust(
        &ui(),
        &TrustView {
            required_algs: Vec::new(),
            publisher_keys: Vec::new(),
            development_keys: true,
            reseal_domain: "test-reseal".into(),
            reseal_format_version: 3,
        },
    );
    assert!(text.contains("(all required)"), "{text}");
    assert!(
        text.contains("development publisher keys are trusted"),
        "{text}"
    );
    assert!(
        text.contains("TPM reseal    test-reseal · format 3"),
        "{text}"
    );
    assert!(!text.contains("Publisher"), "{text}");
}

#[test]
fn release_shows_unknown_active_version_pending_activation_and_empty_staging() {
    let text = render_release(
        &ui(),
        &UpdateStatus {
            highest_confirmed_sequence: 42,
            active_version: None,
            staged: Vec::new(),
            activation_pending: Some(43),
            channel: "stable".into(),
            target: "x86_64-unknown-linux-gnu".into(),
        },
    );
    assert!(
        text.contains("heliosd unknown · stable · x86_64-unknown-linux-gnu"),
        "{text}"
    );
    assert!(text.contains("sequence 42"), "{text}");
    assert!(text.contains("sequence 43 pending"), "{text}");
    assert!(text.contains("Staged        none"), "{text}");
}

#[test]
fn release_marks_the_confirmed_boundary_as_superseded() {
    let mut view = healthy().release.unwrap();
    view.highest_confirmed_sequence = 42;
    view.staged = vec![helios_update::FinalizedRelease {
        release_sequence: 42,
        version: "1.13.0".into(),
        sha256: "abcdef0123456789".into(),
    }];
    let text = render_release(&ui(), &view);
    assert!(text.contains("superseded — cannot be activated"), "{text}");
    assert!(!text.contains("ready to activate"), "{text}");
}

#[test]
fn doctor_warns_for_simulation_disabled_tpm_low_memory_and_high_temperature() {
    let mut inputs = healthy();
    inputs.status.as_mut().unwrap().dry_run = true;
    inputs.health = Ok(HealthView {
        uptime_seconds: None,
        load: None,
        cpu_count: None,
        memory_total_bytes: Some(100),
        memory_available_bytes: Some(9),
        temperature_celsius: Some(85.0),
        tpm: Some(TpmView {
            kind: "disabled".into(),
            preserved_vaults: true,
        }),
    });
    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("Mode").level, Level::Warn);
    assert_eq!(find("TPM").level, Level::Warn);
    assert_eq!(find("Memory").level, Level::Warn);
    assert_eq!(find("Temperature").level, Level::Warn);
}

#[test]
fn doctor_treats_missing_firewall_and_release_reads_as_failures() {
    let mut inputs = healthy();
    inputs.firewall = Err("firewall endpoint unavailable".into());
    inputs.release = Err("release endpoint unavailable".into());
    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("Firewall").level, Level::Fail);
    assert_eq!(find("Firewall").detail, "firewall endpoint unavailable");
    assert_eq!(find("Release").level, Level::Fail);
    assert_eq!(find("Release").detail, "release endpoint unavailable");
    assert!(render_doctor(&ui(), &checks).contains("2 failed, 0 warnings"));
}

#[test]
fn doctor_warns_for_a_missing_trust_domain_and_pending_release() {
    let mut inputs = healthy();
    inputs.domain = Ok(None);
    inputs.release.as_mut().unwrap().activation_pending = Some(2);
    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("Certificates").level, Level::Warn);
    assert_eq!(
        find("Certificates").detail,
        "no trust domain on this gateway"
    );
    assert_eq!(find("Release").level, Level::Warn);
    assert!(find("Release")
        .detail
        .contains("activation of sequence 2 pending"));
}

#[tokio::test]
async fn trust_fetches_and_decodes_the_read_only_trust_view() {
    let body = json!({
        "required_algs": ["ml-dsa-65"],
        "publisher_keys": [],
        "development_keys": false,
        "reseal_domain": "helios-tpm-reseal-v2",
        "reseal_format_version": 2
    });
    let (base, server) = crate::tests::one_response_server("200 OK", body.to_string()).await;
    super::trust(&loopback_client(), &base)
        .await
        .expect("read trust settings");
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/trust HTTP/1.1\r\n"));
}

#[tokio::test]
async fn trust_propagates_an_http_refusal() {
    let (base, server) =
        crate::tests::one_response_server("403 Forbidden", "trust unavailable").await;
    let error = super::trust(&loopback_client(), &base)
        .await
        .expect_err("refuse an unavailable trust view");
    assert!(error.to_string().contains("403 Forbidden"), "{error:#}");
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/trust HTTP/1.1\r\n"));
}

#[tokio::test]
async fn release_fetches_and_decodes_the_read_only_update_view() {
    let body = serde_json::to_string(&healthy().release.unwrap()).unwrap();
    let (base, server) = crate::tests::one_response_server("200 OK", body).await;
    super::release(&loopback_client(), &base)
        .await
        .expect("read update status");
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/update HTTP/1.1\r\n"));
}

#[tokio::test]
async fn release_propagates_an_http_refusal() {
    let (base, server) =
        crate::tests::one_response_server("503 Service Unavailable", "update unavailable").await;
    let error = super::release(&loopback_client(), &base)
        .await
        .expect_err("refuse an unavailable update view");
    assert!(
        error.to_string().contains("503 Service Unavailable"),
        "{error:#}"
    );
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/update HTTP/1.1\r\n"));
}

#[tokio::test]
async fn firewall_propagates_an_http_refusal_without_applying_rules() {
    let (base, server) =
        crate::tests::one_response_server("503 Service Unavailable", "rules unavailable").await;
    let error = super::firewall(&loopback_client(), &base, false)
        .await
        .expect_err("unavailable rules cannot be reported as a successful inspection");
    assert!(
        error.to_string().contains("503 Service Unavailable"),
        "{error:#}"
    );
    assert!(server
        .await
        .unwrap()
        .starts_with("GET /api/firewall/rules HTTP/1.1\r\n"));
}

#[tokio::test]
async fn status_peers_and_network_fetch_their_expected_routes() {
    let network = json!({
        "wan_ifaces": [],
        "lan_ifaces": [],
        "allow_ssh_from": [],
        "admin_ifaces": [],
        "admin_iface": "helios0",
        "wg_iface": "helios0",
        "wg_private_key_configured": true,
        "wg_public_key": "test-public-key",
        "wg_address": "100.64.0.1/32",
        "wg_listen_port": 51820,
        "key_negotiation_port": null,
        "peers": []
    });
    let (base, server) = crate::tests::http_response_sequence([
        ("200 OK", status_json(Vec::new()).to_string()),
        ("200 OK", status_json(Vec::new()).to_string()),
        ("200 OK", network.to_string()),
    ])
    .await;
    let client = loopback_client();
    super::status(&client, &base).await.expect("read status");
    super::peers(&client, &base).await.expect("read peer list");
    super::network(&client, &base)
        .await
        .expect("read network config");
    let requests = server.await.expect("all inspection requests");
    let routes = requests
        .iter()
        .map(|request| request.lines().next().expect("request line"))
        .collect::<Vec<_>>();
    assert_eq!(
        routes,
        [
            "GET /api/status HTTP/1.1",
            "GET /api/status HTTP/1.1",
            "GET /api/network HTTP/1.1",
        ]
    );
}

#[test]
fn firewall_summary_explains_dry_run_and_keeps_accept_rules_visible() {
    let text = render_firewall(
        &ui(),
        &FirewallView {
            rules: r#"table inet helios {
 chain input {
 type filter hook input priority filter; policy accept;
 iifname "lo" accept  # local only
 }
}"#
            .into(),
            default_verdict: "accept".into(),
            dry_run: true,
        },
    );
    assert!(text.contains("default accept · dry-run"), "{text}");
    assert!(text.contains("Incoming"), "{text}");
    assert!(text.contains("allow"), "{text}");
    assert!(text.contains("local only"), "{text}");
}

#[test]
fn status_distinguishes_installed_and_degraded_ipv6() {
    let mut payload = status_json(Vec::new());
    payload["ipv6"] = json!("installed");
    let view = serde_json::from_value(payload.clone()).unwrap();
    let text = render_status(&ui(), &view);
    assert!(text.contains("  IPv6          installed\n"), "{text}");

    payload["ipv6"] = json!({"unavailable": {
        "reason": "tunnel_mtu_too_small", "tunnel_mtu": 1200, "minimum": 1280
    }});
    let view = serde_json::from_value(payload).unwrap();
    let text = render_status(&ui(), &view);
    assert!(
        text.contains("unavailable — IPv4 only (degraded)"),
        "{text}"
    );
    assert!(
        text.contains("1200 bytes is below the 1280 bytes"),
        "{text}"
    );
}

#[test]
fn status_reports_tunnel_policy_and_negotiated_peer() {
    let mut peer = gateway_peers().remove(0);
    peer["last_handshake_age_seconds"] = json!(0);
    peer["post_quantum"] = json!(true);
    let mut payload = status_json(vec![peer]);
    payload["state"] = json!("up");
    payload["wg_peers"] = json!(["branch-site"]);
    payload["split_tunnel_cidrs"] = json!(["192.0.2.0/24"]);
    payload["mss_clamp"] = json!(1380);
    payload["captive_portal_gateway"] = json!("192.0.2.1");
    let view = serde_json::from_value(payload).unwrap();
    let text = render_status(&ui(), &view);
    for expected in [
        "Site-to-site  branch-site",
        "Split tunnel  192.0.2.0/24",
        "MSS clamp     1380",
        "Captive portal 192.0.2.1",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text}");
    }
    assert!(
        text.lines()
            .any(|line| line.contains("poste-windows") && line.contains("ML-KEM")),
        "{text}"
    );
}

#[test]
fn network_reports_missing_identity_and_counts_only_complete_certificate_pins() {
    let mut peer = json!({
        "name": "full-pin", "public_key": "peer-1", "address": "100.64.0.2/32",
        "preshared_key_configured": false, "admin": true,
        "key_negotiation_certificate_sha256": "test-tls-fingerprint",
        "key_negotiation_pq_certificate_sha256": "test-pq-fingerprint",
        "minimum_key_negotiation_mode": "ml_kem",
    });
    let paired = peer.clone();
    peer["name"] = json!("partial-pin");
    peer["public_key"] = json!("peer-2");
    peer["address"] = json!("100.64.0.3/32");
    peer["key_negotiation_pq_certificate_sha256"] = serde_json::Value::Null;
    peer["preshared_key_configured"] = json!(true);
    peer["minimum_key_negotiation_mode"] = serde_json::Value::Null;
    peer["admin"] = json!(false);
    let view = serde_json::from_value(json!({
        "wan_ifaces": [], "lan_ifaces": [], "allow_ssh_from": [],
        "wg_iface": "helios0", "wg_private_key_configured": false,
        "wg_address": "100.64.0.1/32", "wg_listen_port": 51820,
        "peers": [paired, peer],
    }))
    .unwrap();
    let text = render_network(&ui(), &view);
    for expected in [
        "private key missing",
        "no tunnel interface: unreachable remotely",
        "2 admitted · 1 admin · 1 with pinned negotiation certificates · 1 with a static PSK · 1 plain WireGuard, no negotiation",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text}");
    }
}

#[test]
fn certificates_distinguish_unusable_issuer_from_near_expiry_and_future_validity() {
    let mut view = certificates();
    view.peers.truncate(3);
    for (peer, (name, phase)) in view.peers.iter_mut().zip([
        ("critical-peer", ValidityPhase::Critical),
        ("warning-peer", ValidityPhase::Warning),
        ("future-peer", ValidityPhase::NotYetValid),
    ]) {
        peer.name = name.into();
        peer.phase = phase;
        peer.not_after = view.now_unix + 2 * 86_400;
    }
    let issuer = view.issuer.as_mut().unwrap();
    issuer.not_after = view.now_unix + 86_400;
    let text = render_certificates(&ui(), &view);
    assert!(
        text.contains("epoch 1 not usable — clients cannot renew"),
        "{text}"
    );
    assert!(text.contains("3 total · 1 valid · 2 expiring"), "{text}");
    let rows: Vec<_> = text.lines().filter(|line| line.contains("gen 1")).collect();
    assert_eq!(rows.len(), 3, "{text}");
    assert!(
        rows[0].contains("critical-peer") && rows[0].contains("expires in 2 d"),
        "{text}"
    );
    assert!(
        rows[1].contains("warning-peer") && rows[1].contains("expires in 2 d"),
        "{text}"
    );
    assert!(
        rows[2].contains("future-peer") && rows[2].contains("not yet valid"),
        "{text}"
    );

    let check = certificates_check(&view);
    assert_eq!(check.level, Level::Fail);
    assert_eq!(check.detail, "issuer not usable — clients cannot renew");

    view.issuer.as_mut().unwrap().usable = true;
    let text = render_certificates(&ui(), &view);
    assert!(text.contains("epoch 1 · expires in 1 d 00 h"), "{text}");
}

#[test]
fn doctor_distinguishes_a_down_tunnel_from_an_unvalidated_tpm() {
    let mut inputs = healthy();
    inputs.status.as_mut().unwrap().state = "down".into();
    inputs.health.as_mut().unwrap().tpm = None;
    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("API").level, Level::Ok);
    assert_eq!(find("Tunnel").level, Level::Fail);
    assert_eq!(find("Tunnel").detail, "down · 2/17 peers online");
    assert_eq!(find("TPM").level, Level::Warn);
    assert_eq!(find("TPM").detail, "boot integrity not validated");
}

#[test]
fn health_and_doctor_report_lost_sealed_vaults() {
    let mut inputs = healthy();
    let health = inputs.health.as_mut().unwrap();
    health.tpm.as_mut().unwrap().preserved_vaults = false;
    health.temperature_celsius = Some(85.0);
    let text = render_health(&ui(), health);
    assert!(
        text.contains("unsealed · sealed vaults NOT preserved"),
        "{text}"
    );
    assert!(text.contains("85.0 °C"), "{text}");

    let checks = diagnose(&inputs);
    let find = |label: &str| checks.iter().find(|check| check.label == label).unwrap();
    assert_eq!(find("TPM").level, Level::Fail);
    assert_eq!(
        find("TPM").detail,
        "unsealed: the sealed vaults were not preserved this boot"
    );
    assert_eq!(find("Temperature").level, Level::Warn);
}

#[tokio::test]
async fn health_fetches_the_health_route_and_propagates_invalid_payloads() {
    let (base, server) = crate::tests::http_response_sequence([
        ("200 OK", json!({"uptime_seconds": 60}).to_string()),
        (
            "200 OK",
            json!({"uptime_seconds": "one minute"}).to_string(),
        ),
    ])
    .await;
    let client = loopback_client();
    health(&client, &base)
        .await
        .expect("accept a partial health reading");
    let error = health(&client, &base)
        .await
        .expect_err("reject a malformed reading");
    assert!(format!("{error:#}").contains("/api/health"), "{error:#}");
    let requests = server.await.expect("both health requests completed");
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("GET /api/health HTTP/1.1\r\n")),
        "{requests:?}"
    );
}

#[test]
fn log_rendering_preserves_plain_messages_and_wraps_long_unicode_words() {
    let line = "2026-10-07T20:20:45 heliosd[1]: Started gateway";
    let text = render_log_line(&ui(), line, true);
    assert_eq!(text, "  10-07 20:20:45         Started gateway\n");

    let word = "é".repeat(45);
    let line = format!("2026-10-07T20:20:45 heliosd[1]: DEBUG {word}");
    let text = render_log_line(&Ui::plain(Some(46)), &line, true);
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[0].contains("DEBUG"), "{text}");
    assert!(
        lines.iter().all(|line| line.chars().count() <= 46),
        "{text}"
    );
    assert_eq!(
        lines
            .iter()
            .flat_map(|line| line.chars())
            .filter(|&character| character == 'é')
            .count(),
        45
    );
}
