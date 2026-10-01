use super::*;

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
    assert_eq!(cli.url, "https://100.64.0.1:8080/");
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

    assert!(
        Cli::try_parse_from([
            "helios",
            "enroll",
            "--name",
            "client",
            "--endpoint",
            "vpn.example:51820",
            "--output",
            "client.orion",
            "--gateway-certificate",
            "gateway.der"
        ])
        .is_err(),
        "partial offline enrollment material must be refused"
    );
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
