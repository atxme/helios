use super::*;
use base64::Engine as _;
use serde_json::json;
use std::{fs, path::Path};

const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const GATEWAY_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

async fn run(base: &str, args: &[&str]) -> Result<()> {
    let command = Cli::try_parse_from(
        ["helios", "--url", base]
            .into_iter()
            .chain(args.iter().copied()),
    )?
    .command
    .expect("test command");
    let api = transport::Api {
        client: Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()?,
        base: base.to_owned(),
        socket: None,
    };
    execute_command(&api, command).await
}

fn request_json(request: &str, route: &str) -> Value {
    assert!(request.starts_with(route), "{request}");
    let (headers, body) = request.split_once("\r\n\r\n").expect("HTTP request");
    assert!(headers
        .to_ascii_lowercase()
        .contains("\r\ncontent-type: application/json"));
    serde_json::from_str(body).expect("JSON request")
}

fn peer() -> Value {
    json!({
        "name": "portable",
        "public_key": CLIENT_KEY,
        "address": "100.64.1.2/32",
        "admin": false,
        "minimum_key_negotiation_mode": "ml_kem"
    })
}

fn peer_add() -> Vec<&'static str> {
    vec![
        "peer",
        "add",
        "--name",
        "portable",
        "--public-key",
        CLIENT_KEY,
    ]
}

#[tokio::test]
async fn peer_add_carries_both_certificate_files_and_canonical_pins() {
    use base64::engine::general_purpose::STANDARD;

    let root = tempfile::tempdir().unwrap();
    let ca = root.path().join("ca");
    let client = root.path().join("client");
    let offline = "http://127.0.0.1:0";
    run(
        offline,
        &[
            "key-nego",
            "init-client-ca",
            "--name",
            "CLI test CA",
            "--output-dir",
            ca.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    run(
        offline,
        &[
            "key-nego",
            "issue-client",
            "--name",
            "portable",
            "--ca-certificate",
            ca.join("orion-client-ca.der").to_str().unwrap(),
            "--ca-private-key",
            ca.join("orion-client-ca-key.der").to_str().unwrap(),
            "--ca-pq-private-key",
            ca.join("orion-client-pq-ca-private.bin").to_str().unwrap(),
            "--wireguard-public-key",
            CLIENT_KEY,
            "--output-dir",
            client.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    let tls = client.join("orion-client-cert.der");
    let pq = client.join("orion-client-pq-cert.json");
    let tls_bytes = fs::read(&tls).unwrap();
    let pq_bytes = fs::read(&pq).unwrap();
    let tls_pin = aether_key_negotiation::certificate_fingerprint_der(&tls_bytes);
    let pq_pin = serde_json::from_slice::<aether::key_negotiation::PqCertificate>(&pq_bytes)
        .unwrap()
        .fingerprint()
        .unwrap();
    let mut args = peer_add();
    args.extend([
        "--admin",
        "--certificate",
        tls.to_str().unwrap(),
        "--key-negotiation-certificate-sha256",
        &tls_pin,
        "--pq-certificate",
        pq.to_str().unwrap(),
    ]);

    let mut answer = peer();
    answer["admin"] = json!(true);
    let (base, server) = one_response_server("201 Created", answer.to_string()).await;
    run(&base, &args).await.unwrap();
    let request = request_json(&server.await.unwrap(), "POST /api/peers ");
    assert_eq!(
        request,
        json!({
            "name": "portable", "public_key": CLIENT_KEY, "admin": true,
            "minimum_key_negotiation_mode": "ml_kem",
            "key_negotiation_certificate_sha256": tls_pin,
            "key_negotiation_pq_certificate_sha256": pq_pin,
            "key_negotiation_certificate": STANDARD.encode(tls_bytes),
            "key_negotiation_pq_certificate": STANDARD.encode(pq_bytes)
        })
    );
}

#[tokio::test]
async fn peer_add_keeps_explicit_pin_only_policy_in_the_gateway_request() {
    let tls_pin = "ab".repeat(32);
    let pq_pin = "ef".repeat(32);
    let mut args = peer_add();
    args.extend([
        "--key-negotiation-certificate-sha256",
        &tls_pin,
        "--key-negotiation-pq-certificate-sha256",
        &pq_pin,
        "--minimum-mode",
        "static-psk",
    ]);
    let (base, server) = one_response_server("409 Conflict", "peer already admitted").await;

    let error = run(&base, &args).await.unwrap_err();
    assert!(error.to_string().contains("peer already admitted"));
    assert_eq!(
        request_json(&server.await.unwrap(), "POST /api/peers "),
        json!({
            "name": "portable", "public_key": CLIENT_KEY, "admin": false,
            "minimum_key_negotiation_mode": "static_psk",
            "key_negotiation_certificate_sha256": tls_pin,
            "key_negotiation_pq_certificate_sha256": pq_pin
        })
    );
}

#[tokio::test]
async fn peer_add_rejects_bad_certificate_inputs_before_contacting_gateway() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("missing.der");
    let tls = root.path().join("leaf.der");
    let pq = root.path().join("invalid.json");
    fs::write(&tls, b"fixture certificate bytes").unwrap();
    fs::write(&pq, "{incomplete").unwrap();
    let wrong_pin = "ac".repeat(32);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    for (options, message) in [
        (
            vec!["--certificate", absent.to_str().unwrap()],
            "missing.der",
        ),
        (
            vec!["--pq-certificate", pq.to_str().unwrap()],
            "not a readable JSON document",
        ),
        (
            vec![
                "--certificate",
                tls.to_str().unwrap(),
                "--key-negotiation-certificate-sha256",
                &wrong_pin,
            ],
            "does not match the leaf",
        ),
    ] {
        let mut args = peer_add();
        args.extend(options);
        let error = run(&base, &args).await.unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
    }
    assert_no_request(&listener).await;
}

async fn assert_no_request(listener: &tokio::net::TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn peer_revoke_submits_the_name_and_preserves_a_gateway_refusal() {
    let (base, server) = http_response_sequence([
        ("200 OK", peer().to_string()),
        ("404 Not Found", "peer is absent".into()),
    ])
    .await;
    let args = ["peer", "revoke", "--name", "portable"];
    run(&base, &args).await.unwrap();
    let error = run(&base, &args).await.unwrap_err();
    assert!(error.to_string().contains("peer is absent"));
    for request in server.await.unwrap() {
        assert_eq!(
            request_json(&request, "POST /api/peers/revoke "),
            json!({"name": "portable"})
        );
    }
}

fn network_view() -> Value {
    let mut admitted = peer();
    admitted["address_v6"] = json!("fd58:124::2/128");
    admitted["preshared_key_configured"] = json!(true);
    json!({
        "wan_ifaces": ["wan0"], "lan_ifaces": [], "allow_ssh_from": [],
        "wg_iface": "helios0", "wg_private_key_configured": true,
        "wg_public_key": GATEWAY_KEY, "wg_address": "100.64.0.1/10",
        "wg_listen_port": 51820, "peers": [admitted]
    })
}

fn emit_args(output: &Path) -> Vec<&str> {
    vec![
        "profile",
        "emit",
        "--name",
        "portable",
        "--endpoint",
        "vpn.example.net:51820",
        "--public-key",
        CLIENT_KEY,
        "--output",
        output.to_str().unwrap(),
    ]
}

#[tokio::test]
async fn profile_emit_reuses_dual_stack_admission_and_normalizes_operator_options() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("portable.orion");
    let mut args = emit_args(&output);
    args.extend([
        "--allowed-ips",
        " 100.64.0.0/10,fd58:124::/64 ",
        "--ssh-target",
        " operator@gateway.example:2222 ",
    ]);
    let (base, server) = one_response_server("200 OK", network_view().to_string()).await;

    run(&base, &args).await.unwrap();
    let original = fs::read_to_string(&output).unwrap();
    let imported = orion_core::parse_profile_import(&original, "portable.orion").unwrap();
    assert_eq!(imported.profile.address.as_deref(), Some("100.64.1.2/32"));
    assert_eq!(
        imported.profile.address_v6.as_deref(),
        Some("fd58:124::2/128")
    );
    assert_eq!(imported.profile.endpoint, "vpn.example.net:51820");
    assert_eq!(imported.profile.peer_public_key, GATEWAY_KEY);
    assert_eq!(imported.profile.allowed_ips, "100.64.0.0/10, fd58:124::/64");
    assert_eq!(
        imported.profile.ssh_target.as_deref(),
        Some("operator@gateway.example:2222")
    );
    let url = format!("http://100.64.0.1:{}", aether::API_PORT);
    assert_eq!(imported.profile.heliosd_url.as_deref(), Some(url.as_str()));
    let document: Value = serde_json::from_str(&original).unwrap();
    assert!(document["profile"].get("private_key").is_none());
    assert!(document["profile"].get("preshared_key").is_none());

    let request = server.await.unwrap();
    assert!(request.starts_with("GET /api/network "), "{request}");
}

#[tokio::test]
async fn profile_emit_rejects_bad_operator_options_without_network_access() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("portable.orion");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    for (option, value, expected) in [
        ("--allowed-ips", "100.64.0.0/33", "trafic capté invalide"),
        ("--ssh-target", "operator@gateway.example:0", "--ssh-target"),
    ] {
        let mut args = emit_args(&output);
        args.extend([option, value]);
        let error = run(&base, &args).await.unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
    let mut args = emit_args(&output);
    args[7] = "bad-key";
    assert!(run(&base, &args)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid client public key"));
    assert!(!output.exists());
    assert_no_request(&listener).await;
}
