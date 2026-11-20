use super::*;
mod operator;

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt as _;

    let mut request = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buffer))
                .await
                .expect("HTTP request arrives within the test deadline")
                .expect("read HTTP request");
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end + 4]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if request.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

pub(super) async fn one_response_server(
    status: &'static str,
    body: impl Into<String>,
) -> (String, tokio::task::JoinHandle<String>) {
    let (base, responses) = http_response_sequence([(status, body.into())]).await;
    let request = tokio::spawn(async move {
        responses
            .await
            .expect("mock HTTP server")
            .pop()
            .expect("one request")
    });
    (base, request)
}

pub(super) async fn http_response_sequence<const N: usize>(
    responses: [(&'static str, String); N],
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local HTTP listener");
    let address = listener.local_addr().expect("listener address");
    let task = tokio::spawn(async move {
        let mut requests = Vec::with_capacity(N);
        for (status, body) in responses {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                    .await
                    .expect("HTTP client connects within the test deadline")
                    .expect("HTTP request");
            requests.push(read_http_request(&mut stream).await);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stream.write_all(response.as_bytes()),
            )
            .await
            .expect("HTTP response is sent within the test deadline")
            .expect("write HTTP response");
        }
        requests
    });
    (format!("http://{address}"), task)
}

/// `network load` sends the operator's document, not a re-serialized
/// `NetworkConfig`. The gateway still has to be able to read it.
///
/// `NetworkConfig` has no `Serialize` — it carries the gateway identity
/// and every peer PSK — so this command converts the parsed TOML instead.
/// That is only sound if the conversion round-trips, including the
/// legacy plaintext identity a migration file still holds.
#[test]
fn a_pushed_document_round_trips_through_json() {
    const LEGACY: &str = r#"
            wan_iface = "eth0"
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            wg_address = "100.64.0.1/10"
            key_negotiation_port = 51821

            [[peers]]
            name = "alice"
            public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            address = "100.64.1.2/32"
            preshared_key = "cHNrLXN0YXRpcXVl"
        "#;

    for raw in [LEGACY, include_str!("../../../config/network.toml")] {
        let document: toml::Value = toml::from_str(raw).expect("the document parses");
        let body = serde_json::to_string(&document).expect("the document converts to JSON");
        let received: NetworkConfig =
            serde_json::from_str(&body).expect("the gateway reads back what was sent");
        received.validate().expect("and it validates there");

        let direct: NetworkConfig = toml::from_str(raw).expect("reference parse");
        assert_eq!(
            received, direct,
            "the document must reach the gateway unchanged"
        );
    }
}

#[test]
fn current_wireguard_status_is_deserializable() {
    let raw = r#"{
            "state":"down","version":"0.1.0","wan_ifaces":["enp3s0","wlo1"],
            "lan_ifaces":["eth1"],"wg_peers":[],"allow_ssh_from":[],
            "peers":[{"name":"orion","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"100.64.1.2/32","post_quantum":false}],
            "wg_iface":"helios0","wg_listen_port":51820,
            "key_negotiation_port":51821,"dry_run":true,
            "split_tunnel_cidrs":[],"mss_clamp":null,"captive_portal_gateway":null,
            "handshake_stale_after_seconds":150
        }"#;
    let status: Status = serde_json::from_str(raw).expect("valid status");
    assert_eq!(status.wg_iface, "helios0");
    assert_eq!(status.wan_ifaces, ["enp3s0", "wlo1"]);
    assert_eq!(status.peers[0].name, "orion");
}

#[test]
fn command_line_keeps_peer_security_parameters() {
    let cli = Cli::try_parse_from([
        "helios",
        "--url",
        "https://100.64.0.1:8080/",
        "peer",
        "add",
        "--name",
        "operator",
        "--public-key",
        "public",
        "--admin",
        "--key-negotiation-certificate-sha256",
        "tls",
        "--key-negotiation-pq-certificate-sha256",
        "pq",
        "--minimum-mode",
        "ml-kem",
    ])
    .unwrap();
    assert_eq!(cli.url.as_deref(), Some("https://100.64.0.1:8080/"));
    assert!(matches!(
        cli.command.unwrap(),
        Cmd::Peer {
            command: PeerCmd::Add {
                name,
                public_key,
                admin: true,
                key_negotiation_certificate_sha256: Some(tls),
                key_negotiation_pq_certificate_sha256: Some(pq),
                certificate: None,
                pq_certificate: None,
                minimum_mode: Some(key_nego::Mode::MlKem),
            }
        } if name == "operator" && public_key == "public" && tls == "tls" && pq == "pq"
    ));

    assert!(matches!(
        Cli::try_parse_from(["helios", "peer", "list"])
            .unwrap()
            .command
            .unwrap(),
        Cmd::Peer {
            command: PeerCmd::List
        }
    ));
    assert!(matches!(
        Cli::try_parse_from(["helios", "peer", "revoke", "--name", "old"])
            .unwrap()
            .command.unwrap(),
        Cmd::Peer {
            command: PeerCmd::Revoke { name }
        } if name == "old"
    ));
}

#[test]
fn command_line_covers_offline_and_diagnostic_commands() {
    for arguments in [
        vec!["helios"],
        vec!["helios", "shell"],
        vec!["helios", "update", "--check"],
        vec!["helios", "firmware", "list"],
        vec![
            "helios",
            "firmware",
            "update",
            "--plan",
            "firmware-plan.json",
            "--yes",
        ],
        vec!["helios", "status"],
        vec!["helios", "connect"],
        vec!["helios", "disconnect"],
        vec!["helios", "watch"],
        vec!["helios", "network", "show"],
        vec!["helios", "network", "load", "network.toml"],
        vec!["helios", "profile", "check", "client.orion"],
        vec!["helios", "escrow", "keygen", "--output-dir", "keys"],
        vec![
            "helios",
            "app-update",
            "--manifest",
            "heliosd.release.json",
            "--binary",
            "heliosd",
            "--yes",
        ],
        vec!["helios", "scenario", "flap"],
        vec!["helios", "campaign", "--generate-keys"],
    ] {
        Cli::try_parse_from(arguments).unwrap();
    }

    assert!(Cli::try_parse_from([
        "helios",
        "app-update",
        "--manifest",
        "heliosd.release.json",
        "--binary",
        "heliosd",
        "--stage-only",
        "--yes",
    ])
    .is_err());
}

#[test]
fn passive_update_check_cannot_be_combined_with_installation_confirmation() {
    assert!(Cli::try_parse_from(["helios", "update", "--check", "--yes"]).is_err());
    assert!(Cli::try_parse_from(["helios", "firmware", "update"]).is_err());
    assert!(Cli::try_parse_from(["helios"]).unwrap().command.is_none());
}

#[test]
fn websocket_urls_preserve_transport_security() {
    assert_eq!(ws_url("http://127.0.0.1:8080"), "ws://127.0.0.1:8080/ws");
    assert_eq!(
        ws_url("https://gateway.example"),
        "wss://gateway.example/ws"
    );
}

#[test]
fn display_helpers_cover_every_state_and_event_shape() {
    for state in ["up", "connecting", "captive_portal", "failed", "down"] {
        assert!(colored_state(state).contains(state));
        assert!(state_dot(state).contains('●'));
    }
    assert!(ok().contains('✓'));
    assert!(fail().contains('✗'));
    assert!(hh_mm_ss().contains(':'));

    print_ws_event(
        "00:00:00",
        &serde_json::json!({"type":"state_changed","state":"up"}),
    );
    for level in ["error", "warn", "info"] {
        print_ws_event(
            "00:00:00",
            &serde_json::json!({"type":"log","level":level,"message":"event"}),
        );
    }
    print_ws_event("00:00:00", &serde_json::json!({"type":"future"}));
    print_ws_event("00:00:00", &serde_json::Value::Null);
}

#[test]
fn command_responses_preserve_refusal_details() {
    assert!(ensure_command(
        CmdResp {
            ok: true,
            error: None,
        },
        "connect"
    )
    .is_ok());
    let explicit = ensure_command(
        CmdResp {
            ok: false,
            error: Some("policy denied".into()),
        },
        "connect",
    )
    .unwrap_err();
    assert!(explicit.to_string().contains("policy denied"));
    let unknown = ensure_command(
        CmdResp {
            ok: false,
            error: None,
        },
        "disconnect",
    )
    .unwrap_err();
    assert!(unknown.to_string().contains("unknown error"));
}

#[tokio::test]
async fn connect_and_disconnect_send_their_typed_commands_and_propagate_refusals() {
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP test client");

    let (base, server) = one_response_server("200 OK", r#"{"ok":true,"error":null}"#).await;
    cmd_connect(&client, &base)
        .await
        .expect("accepted start command succeeds");
    let request = server.await.expect("start server completes");
    assert!(request.starts_with("POST /api/tunnel/start "), "{request}");
    assert!(request.ends_with("{}"), "request body: {request}");

    let (base, server) = one_response_server("200 OK", r#"{"ok":false,"error":"busy"}"#).await;
    let error = cmd_disconnect(&client, &base)
        .await
        .expect_err("refused stop command must fail");
    assert!(error.to_string().contains("busy"), "{error:#}");
    let request = server.await.expect("stop server completes");
    assert!(request.starts_with("POST /api/tunnel/stop "), "{request}");
}

#[tokio::test]
async fn network_load_preserves_secrets_in_the_posted_configuration() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().expect("temporary network config directory");
    let path = directory.path().join("network.toml");
    let document = r#"
        wan_iface = "eth0"
        wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        wg_address = "100.64.0.1/10"
        [[peers]]
        name = "alice"
        public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        address = "100.64.1.2/32"
        preshared_key = "cHNrLXN0YXRpcXVl"
    "#;
    std::fs::File::create(&path)
        .expect("create config")
        .write_all(document.as_bytes())
        .expect("write config");

    let (base, server) = one_response_server("200 OK", r#"{"ok":true,"error":null}"#).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP test client");
    cmd_network_load(&client, &base, &path)
        .await
        .expect("valid network document is accepted");
    let request = server.await.expect("network server completes");
    assert!(request.starts_with("POST /api/network "), "{request}");
    let body = request
        .split_once("\r\n\r\n")
        .expect("HTTP request separator")
        .1;
    let received: NetworkConfig = serde_json::from_str(body).expect("gateway-readable JSON");
    assert_eq!(
        received.wg_private_key.expose(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(
        received.peers[0]
            .preshared_key
            .as_ref()
            .map(aether::secret::SecretString::expose),
        Some("cHNrLXN0YXRpcXVl")
    );
    received.validate().expect("received config validates");

    let (base, server) =
        one_response_server("200 OK", r#"{"ok":false,"error":"invalid config"}"#).await;
    let error = cmd_network_load(&client, &base, &path)
        .await
        .expect_err("gateway refusal must fail the load");
    assert!(error.to_string().contains("invalid config"), "{error:#}");
    assert!(server
        .await
        .expect("refusal server completes")
        .starts_with("POST /api/network "));
}

#[tokio::test]
async fn network_load_rejects_invalid_toml_before_contacting_the_gateway() {
    let directory = tempfile::tempdir().expect("temporary network config directory");
    let path = directory.path().join("invalid.toml");
    std::fs::write(&path, "wan_iface = [not valid TOML").expect("write invalid TOML");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local HTTP listener");
    let address = listener.local_addr().expect("listener address");
    let error = cmd_network_load(&reqwest::Client::new(), &format!("http://{address}"), &path)
        .await
        .expect_err("invalid TOML must be rejected locally");
    assert!(format!("{error:#}").contains("invalid TOML"), "{error:#}");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

/// Without `--url`, the transport decides (local socket or in-tunnel API):
/// the parser must not invent a TCP address.
#[test]
fn no_url_is_assumed_by_the_parser() {
    if std::env::var_os("HELIOS_URL").is_some() {
        return;
    }
    let cli = Cli::try_parse_from(["helios", "status"]).unwrap();
    assert_eq!(cli.url, None);
}

/// A peer is online when its last handshake is younger than the gateway's
/// staleness bound; a peer that never shook hands is not.
#[test]
fn online_peers_follow_the_gateway_staleness_bound() {
    let status: Status = serde_json::from_value(serde_json::json!({
        "state": "up", "version": "1.13.0", "wan_ifaces": [], "lan_ifaces": [],
        "wg_peers": [], "allow_ssh_from": [], "wg_iface": "helios0",
        "wg_listen_port": 51820, "dry_run": false, "split_tunnel_cidrs": [],
        "mss_clamp": null, "captive_portal_gateway": null,
        "handshake_stale_after_seconds": 150,
        "peers": [
            {"name": "a", "public_key": "k", "address": "100.64.1.2/32", "post_quantum": false, "last_handshake_age_seconds": 12},
            {"name": "b", "public_key": "k", "address": "100.64.1.3/32", "post_quantum": false, "last_handshake_age_seconds": 400},
            {"name": "c", "public_key": "k", "address": "100.64.1.4/32", "post_quantum": false, "last_handshake_age_seconds": null},
        ]
    }))
    .unwrap();
    assert_eq!(status.online_peers(), (1, 3));
}

/// A refusal from the gateway is a failed command: the shell then closes its
/// block with ✗, not with ✓ under a printed cross.
#[test]
fn a_gateway_refusal_fails_the_command() {
    let refused = CmdResp {
        ok: false,
        error: Some("tunnel already up".into()),
    };
    let error = accepted(refused).expect_err("a refusal must fail");
    assert_eq!(
        error.to_string(),
        "refused by the gateway: tunnel already up"
    );
    assert!(accepted(CmdResp {
        ok: true,
        error: None
    })
    .is_ok());
}

/// `profile emit` validates operator traffic selectors before admission and
/// stores the same canonical spelling Orion will show on import.
#[test]
fn allowed_ips_are_validated_before_emission_and_normalized() {
    assert_eq!(check_allowed_ips(None).unwrap(), None);
    assert_eq!(
        check_allowed_ips(Some(" 100.64.0.0/10,192.168.1.0/24 ".into())).unwrap(),
        Some("100.64.0.0/10, 192.168.1.0/24".into())
    );

    for invalid in [
        "",
        "   ",
        "100.64.0.0/10,not-a-prefix",
        "100.64.0.0/10, 100.64.0.0/10",
        "100.64.0.0/33",
    ] {
        let error = check_allowed_ips(Some(invalid.into())).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("trafic capté invalide"), "{message}");
        assert!(message.contains("--allowed-ips"), "{message}");
    }
}

/// The SSH destination is trimmed and checked before it can be persisted in
/// an emitted profile or passed to a spawned SSH process.
#[test]
fn ssh_targets_are_trimmed_and_reject_argument_or_shell_injection() {
    assert_eq!(check_ssh_target(None).unwrap(), None);
    assert_eq!(
        check_ssh_target(Some("  operator@gateway.example:2222  ".into())).unwrap(),
        Some("operator@gateway.example:2222".into())
    );

    for invalid in [
        "",
        "   ",
        "-oProxyCommand=evil",
        "operator@gateway.example;id",
        "operator@host:0",
        "operator@host:not-a-port",
        "user@@host",
    ] {
        let error = check_ssh_target(Some(invalid.into())).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("--ssh-target"), "{message}");
    }
}

/// `profile emit` re-emits the invitation of an admitted peer and nothing
/// else: the assisted mode and the admission role are gone from the command
/// line, not merely refused at run time (ADR-004 §6, 18 October 2026).
#[test]
fn profile_emit_has_neither_an_assisted_mode_nor_an_admission_role() {
    for option in ["--with-private-key", "--admin"] {
        let Err(error) = Cli::try_parse_from([
            "helios",
            "profile",
            "emit",
            "--name",
            "portable",
            "--endpoint",
            "vpn.example.net:51820",
            "--public-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            option,
        ]) else {
            panic!("{option} is still accepted");
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{option}"
        );
    }
}
