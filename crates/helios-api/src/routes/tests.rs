use std::{sync::Arc, time::Duration};

use aether::{NetworkConfig, OrchestratorCmd, TunnelState, WgPeer};
use axum::extract::State;
use tokio::sync::{broadcast, mpsc, RwLock};

use super::*;

const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn network() -> NetworkConfig {
    NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        lan_ifaces: vec!["lan0".into()],
        admin_iface: Some("helios0".into()),
        wg_private_key: PRIVATE_KEY.into(),
        wg_address: "100.64.0.1/10".into(),
        wg_listen_port: 51820,
        key_negotiation_port: Some(51821),
        peers: vec![WgPeer {
            name: "test-workstation".into(),
            public_key: PEER_KEY.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: true,
            preshared_key: Some("pq-secret-must-not-leak".into()),
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: Some("aa".repeat(32)),
            minimum_key_negotiation_mode: Some(ProtectionMode::MlKem),
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    }
}

fn app_state(state: TunnelState) -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
    let network = network();
    let (event_tx, _) = broadcast::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let policy = network.firewall_policy();
    (
        AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(state)),
            event_tx,
            cmd_tx,
            // These tests don't touch provisioning: a channel that's
            // never served is enough.
            mpsc::channel(1).0,
            Arc::new(RwLock::new(policy)),
        ),
        cmd_rx,
    )
}

/// A data-plane observation, keyed like the peer the fixture configures.
fn observed(public_key_b64: &str, age: Duration) -> PeerStatus {
    use base64::Engine as _;
    PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(public_key_b64)
            .unwrap(),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(SystemTime::now() - age),
        endpoint: Some("203.0.113.9:51820".into()),
        rx_bytes: 4_096,
        tx_bytes: 8_192,
    }
}

#[tokio::test]
async fn status_attaches_the_runtime_observed_on_the_data_plane() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    *app.peer_runtime.write().await = vec![observed(PEER_KEY, Duration::from_secs(30))];

    let response = status(State(app)).await.0;

    let peer = &response.peers[0];
    assert_eq!(peer.endpoint.as_deref(), Some("203.0.113.9:51820"));
    assert_eq!(peer.rx_bytes, Some(4_096));
    assert_eq!(peer.tx_bytes, Some(8_192));
    let age = peer.last_handshake_age_seconds.expect("handshake observed");
    assert!((30..=31).contains(&age), "unexpected age: {age}");
}

#[tokio::test]
async fn status_reports_no_runtime_when_the_data_plane_was_not_observed() {
    let (app, _cmd_rx) = app_state(TunnelState::Down);

    let response = status(State(app)).await.0;

    // Absent, not zeroed: "never observed" and "transferred nothing" are
    // different facts, and the console renders them differently.
    let peer = &response.peers[0];
    assert_eq!(peer.rx_bytes, None);
    assert_eq!(peer.tx_bytes, None);
    assert_eq!(peer.last_handshake_age_seconds, None);
    assert_eq!(peer.endpoint, None);
}

#[tokio::test]
async fn runtime_is_matched_by_public_key_and_never_by_name() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    // Same peer name, a different key: this is what a stale observation
    // looks like after a client rotated its identity. Attaching it would
    // credit one client's traffic to another's row.
    let mut stale = observed(PEER_KEY, Duration::from_secs(10));
    stale.public_key = vec![0x42; 32];
    *app.peer_runtime.write().await = vec![stale];

    let response = status(State(app)).await.0;

    assert_eq!(response.peers[0].endpoint, None);
    assert_eq!(response.peers[0].rx_bytes, None);
}

#[tokio::test]
async fn a_handshake_dated_in_the_future_is_reported_as_unknown() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    let mut skewed = observed(PEER_KEY, Duration::from_secs(0));
    skewed.last_handshake = Some(SystemTime::now() + Duration::from_secs(3_600));
    *app.peer_runtime.write().await = vec![skewed];

    let response = status(State(app)).await.0;

    // Clocks disagree. Reporting the negative age as an unsigned number
    // would show the peer as dead for 584 942 years.
    assert_eq!(response.peers[0].last_handshake_age_seconds, None);
}

#[tokio::test]
async fn status_publishes_the_freshness_threshold_it_is_judged_by() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);

    let response = status(State(app)).await.0;

    assert_eq!(
        response.handshake_stale_after_seconds,
        helios_wireguard::HANDSHAKE_STALE_AFTER_SECS
    );
}

#[tokio::test]
async fn a_gateway_without_ipv6_reports_it_as_not_configured() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);

    let response = serde_json::to_value(status(State(app)).await.0).unwrap();

    assert_eq!(response["ipv6"], serde_json::json!("not_configured"));
}

/// The degraded IPv4-only start of `ADRESSAGE-IPV6.md` §6.2 must be visible
/// from the API, with the reason the orchestrator published.
#[tokio::test]
async fn status_exposes_an_unavailable_ipv6_with_its_reason() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    *app.ipv6.write().await = aether::net::Ipv6TunnelStatus::Unavailable(
        aether::net::Ipv6Unavailable::DisabledByKernel {
            setting: "net.ipv6.conf.all.disable_ipv6".into(),
        },
    );

    let response = serde_json::to_value(status(State(app)).await.0).unwrap();

    assert_eq!(
        response["ipv6"],
        serde_json::json!({
            "unavailable": {
                "reason": "disabled_by_kernel",
                "setting": "net.ipv6.conf.all.disable_ipv6"
            }
        })
    );
}

/// The console shows a client's IPv6 VIP next to its IPv4 one, from the row
/// it already polls: `null` without one, the persisted `/128` form with one.
#[tokio::test]
async fn status_carries_each_peer_ipv6_vip() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    let response = serde_json::to_value(status(State(app.clone())).await.0).unwrap();
    assert!(response["peers"][0]["address_v6"].is_null());

    app.network.write().await.peers[0].address_v6 =
        Some("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517".parse().unwrap());
    let response = serde_json::to_value(status(State(app)).await.0).unwrap();
    assert_eq!(
        response["peers"][0]["address_v6"],
        serde_json::json!("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128")
    );
}

#[tokio::test]
async fn status_exposes_useful_data_without_the_psk() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);

    let response = status(State(app)).await.0;

    assert_eq!(response.state, "up");
    assert_eq!(response.wg_listen_port, Some(51820));
    assert_eq!(response.peers.len(), 1);
    assert_eq!(response.peers[0].name, "test-workstation");
    assert!(response.peers[0].post_quantum);
    // Both ports are published: they are redirected together on the box,
    // and the UI states what the operator has to open.
    assert_eq!(response.key_negotiation_port, Some(51821));
    // The floor travels with the peer: the screen shows what this peer
    // can no longer fall back to.
    assert_eq!(
        response.peers[0].minimum_key_negotiation_mode,
        Some(ProtectionMode::MlKem)
    );
    let payload = serde_json::to_string(&response).unwrap();
    assert!(!payload.contains("pq-secret-must-not-leak"));
}

#[tokio::test]
async fn read_configuration_never_serializes_secrets() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);

    let response = network_get(State(app)).await.0;
    let payload = serde_json::to_string(&response).unwrap();

    assert!(response.wg_private_key_configured);
    assert!(response.peers[0].preshared_key_configured);
    assert!(!payload.contains(PRIVATE_KEY));
    assert!(!payload.contains("pq-secret-must-not-leak"));
    assert!(!payload.contains("wg_private_key\""));
    assert!(!payload.contains("preshared_key\""));
}

/// The IPv6 addresses are public configuration: the view carries them,
/// in their persisted text form, and `null` where there are none.
#[tokio::test]
async fn read_configuration_exposes_the_ipv6_addresses() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    let response = network_get(State(app.clone())).await.0;
    assert_eq!(response.wg_address_v6, None);
    assert_eq!(response.peers[0].address_v6, None);
    let payload = serde_json::to_value(&response).unwrap();
    assert!(payload["wg_address_v6"].is_null());
    assert!(payload["peers"][0]["address_v6"].is_null());

    {
        let mut network = app.network.write().await;
        network.wg_address_v6 = Some("FD3C:91A2:7E04::1/64".parse().unwrap());
        network.peers[0].address_v6 = Some("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517".parse().unwrap());
    }
    let response = network_get(State(app)).await.0;
    assert_eq!(
        response.wg_address_v6.as_deref(),
        Some("fd3c:91a2:7e04::1/64")
    );
    assert_eq!(
        response.peers[0].address_v6.as_deref(),
        Some("fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128")
    );
    let payload = serde_json::to_string(&response).unwrap();
    assert!(!payload.contains(PRIVATE_KEY));
    assert!(!payload.contains("pq-secret-must-not-leak"));
}

#[tokio::test]
async fn trust_publishes_the_required_hybrid_and_never_a_full_key() {
    let response = trust().await.0;

    // The UI must be able to assert "both, or reject": if someone ever
    // removes ML-DSA from REQUIRED_ALGS, this test breaks.
    assert_eq!(response.required_algs, vec!["ed25519", "ml-dsa-65"]);
    assert!(!response.publisher_keys.is_empty());
    assert_eq!(response.reseal_domain, "helios-tpm-reseal-v2");

    // A fingerprint truncated to 128 bits, not the key.
    let payload = serde_json::to_string(&response).unwrap();
    for keys in aether::sig::PUBLISHER_KEYS {
        assert_eq!(keys.fingerprint().len(), 32);
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(keys.ml_dsa_65);
        assert!(!payload.contains(&encoded));
    }
}

#[tokio::test]
async fn command_routes_forward_the_exact_intent() {
    let (app, mut cmd_rx) = app_state(TunnelState::Down);

    assert!(tunnel_start(State(app.clone())).await.0.ok);
    assert!(matches!(
        cmd_rx.recv().await,
        Some(OrchestratorCmd::Connect)
    ));

    assert!(
        split_tunnel_set(
            State(app.clone()),
            Json(SplitTunnelRequest {
                cidrs: vec!["10.0.0.0/8".into()]
            }),
        )
        .await
        .unwrap()
        .0
        .ok
    );
    match cmd_rx.recv().await {
        Some(OrchestratorCmd::SetSplitTunnel(cidrs)) => assert_eq!(cidrs, ["10.0.0.0/8"]),
        other => panic!("unexpected command: {other:?}"),
    }

    assert!(tunnel_stop(State(app)).await.0.ok);
    assert!(matches!(
        cmd_rx.recv().await,
        Some(OrchestratorCmd::Disconnect)
    ));
}

async fn set_split_tunnel(
    app: &AppState,
    cidrs: &[&str],
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    split_tunnel_set(
        State(app.clone()),
        Json(SplitTunnelRequest {
            cidrs: cidrs.iter().map(|cidr| cidr.to_string()).collect(),
        }),
    )
    .await
}

/// A CIDR the ruleset compiler would refuse is answered `400`, naming it, and
/// never reaches the orchestrator — which has no way to report it back.
#[tokio::test]
async fn an_invalid_split_tunnel_cidr_is_refused_before_the_orchestrator() {
    let (app, mut cmd_rx) = app_state(TunnelState::Up);

    for (cidrs, refused) in [
        (vec!["10.0.0.0/33"], "10.0.0.0/33"),
        (vec!["fd00::/129"], "fd00::/129"),
        (
            vec!["192.168.1.0/24", "not-a-cidr", "fd00::/64"],
            "not-a-cidr",
        ),
    ] {
        let (status, message) = set_split_tunnel(&app, &cidrs)
            .await
            .err()
            .unwrap_or_else(|| panic!("{cidrs:?} must be refused"));
        assert_eq!(status, StatusCode::BAD_REQUEST, "{cidrs:?}");
        assert!(message.contains(&format!("`{refused}`")), "{message}");
    }

    assert!(
        cmd_rx.try_recv().is_err(),
        "a refused list must send nothing to the orchestrator"
    );
}

#[tokio::test]
async fn a_valid_dual_stack_split_tunnel_list_is_sent_unchanged() {
    let (app, mut cmd_rx) = app_state(TunnelState::Up);
    let cidrs = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "fd00:1::/64",
        "2001:db8::/32",
    ];

    assert!(set_split_tunnel(&app, &cidrs).await.unwrap().0.ok);

    match cmd_rx.try_recv() {
        Ok(OrchestratorCmd::SetSplitTunnel(sent)) => assert_eq!(sent, cidrs),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn firewall_rendering_stays_fail_closed_outside_an_active_tunnel() {
    let (app, _cmd_rx) = app_state(TunnelState::Down);

    let response = firewall_rules_get(State(app)).await.unwrap().0;

    assert_eq!(response.default_verdict, "drop");
    assert!(response.rules.contains("udp dport 51820 accept"));
    assert!(!response.rules.contains("pq-secret-must-not-leak"));
}

/// The console shows the masquerade the Netlink backend applies, IPv4 guard
/// included: an unguarded line would describe an `inet` NAT that also
/// rewrites IPv6.
#[tokio::test]
async fn firewall_rendering_shows_the_ipv4_only_masquerade() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    app.policy.write().await.allow_client_internet = true;

    let response = firewall_rules_get(State(app)).await.unwrap().0;

    assert!(
        response
            .rules
            .contains("    meta nfproto ipv4 oifname \"eth0\" masquerade  #"),
        "{}",
        response.rules
    );
    assert!(!response.rules.contains("    oifname \"eth0\" masquerade"));
}

/// The console shows the `prerouting` chain the Netlink backend applies,
/// with its own `accept` policy: shown under the ruleset's `drop` default, it
/// would describe a gateway that cuts every packet before routing.
#[tokio::test]
async fn firewall_rendering_shows_the_prerouting_rejection_under_an_accept_policy() {
    let (app, _cmd_rx) = app_state(TunnelState::Down);

    let response = firewall_rules_get(State(app)).await.unwrap().0;

    assert_eq!(response.default_verdict, "drop");
    assert!(
        response.rules.contains(
            "  chain prerouting {\n    type filter hook prerouting priority filter; policy accept;\n"
        ),
        "{}",
        response.rules
    );
    assert!(
        response.rules.contains(
            "    meta nfproto ipv6 iifname \"helios0\" fib daddr oifname \"eth0\" \
             reject with icmpx admin-prohibited  #"
        ),
        "{}",
        response.rules
    );
}

#[tokio::test]
async fn firewall_rendering_describes_family_scoped_tunnel_mss_rules() {
    let (app, _cmd_rx) = app_state(TunnelState::Up);
    app.policy.write().await.mss_clamp = Some(1240);

    let response = firewall_rules_get(State(app.clone())).await.unwrap().0;
    assert!(response
        .rules
        .contains("type filter hook forward priority mangle;"));
    assert!(response.rules.contains(
        "iifname \"helios0\" meta nfproto ipv4 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set 1240"
    ));
    assert!(response.rules.contains(
        "oifname \"helios0\" meta nfproto ipv6 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set 1220"
    ));

    app.policy.write().await.mss_clamp = Some(1239);
    let response = firewall_rules_get(State(app.clone())).await.unwrap().0;
    assert!(response
        .rules
        .contains("meta nfproto ipv4 meta l4proto tcp"));
    assert!(!response
        .rules
        .contains("meta nfproto ipv6 meta l4proto tcp"));

    app.policy.write().await.wg_iface.clear();
    let response = firewall_rules_get(State(app)).await.unwrap().0;
    assert!(!response.rules.contains("chain mss"));
}

#[tokio::test]
async fn explicit_error_if_orchestrator_is_absent() {
    let (app, cmd_rx) = app_state(TunnelState::Down);
    drop(cmd_rx);

    let response = tunnel_start(State(app)).await.0;

    assert!(!response.ok);
    assert_eq!(response.error.as_deref(), Some("orchestrator unreachable"));
}
