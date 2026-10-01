use super::*;
use helios_firewall::FirewallCapabilities;

const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

struct UnsupportedMssFirewall {
    applied: AtomicBool,
}

#[async_trait::async_trait]
impl FirewallBackend for UnsupportedMssFirewall {
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities::default()
    }

    async fn apply(&self, _policy: &FirewallPolicy, _state: TunnelState) -> aether::Result<()> {
        self.applied.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn teardown(&self) -> aether::Result<()> {
        Ok(())
    }
}

fn configured_network() -> NetworkConfig {
    NetworkConfig {
        wan_ifaces: vec!["eth0".into()],
        wg_iface: "helios0".into(),
        wg_private_key: PRIVATE_KEY.into(),
        wg_address: "100.64.0.1/10".into(),
        wg_listen_port: WG_LISTEN_PORT,
        peers: vec![aether::WgPeer {
            name: "poste-test".into(),
            public_key: PEER_KEY.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: false,
            preshared_key: Some("psk-test".into()),
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    }
}

/// The poller must **not** write the state itself: it holds neither the
/// firewall backend nor the policy, and a direct write would leave the
/// ruleset frozen on the previous state. Since forward only exists in
/// states where traffic is allowed, it would never be applied — an "up"
/// tunnel that routes nothing, with nothing in the logs to explain it.
#[tokio::test]
async fn handshake_promotion_goes_through_the_main_loop() {
    let network = Arc::new(RwLock::new(configured_network()));
    let wireguard = Arc::new(helios_wireguard::DryRunBackend::with_handshakes());
    let (iface, peers) = wg_config(&*network.read().await);
    wireguard
        .up(&iface, &peers)
        .await
        .expect("dry-run bring-up");

    let state = Arc::new(RwLock::new(TunnelState::Connecting));
    let (event_tx, _rx) = broadcast::channel(16);
    let (internal_tx, mut internal_rx) = mpsc::channel(8);

    spawn_handshake_poller(
        wireguard,
        Arc::clone(&state),
        Arc::clone(&network),
        Arc::new(RwLock::new(Vec::new())),
        event_tx,
        internal_tx,
    );

    let received = time::timeout(Duration::from_secs(5), internal_rx.recv())
        .await
        .expect("the poller must signal the promotion");
    assert!(
        matches!(
            received,
            Some(OrchestratorCmd::TunnelStateInferred(TunnelState::Up))
        ),
        "unexpected command: {received:?}"
    );
    assert_eq!(
        *state.read().await,
        TunnelState::Connecting,
        "the poller wrote the state without going through firewall reapplication"
    );
}

fn connected_peer(endpoint: &str) -> helios_wireguard::PeerStatus {
    helios_wireguard::PeerStatus {
        public_key: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, PEER_KEY)
            .unwrap(),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(std::time::SystemTime::now()),
        endpoint: Some(endpoint.into()),
        rx_bytes: 0,
        tx_bytes: 0,
    }
}

/// The trace that lets us assert that it really is `heliosd` holding the
/// tunnel, and distinguish a classic session from a protected one.
#[tokio::test]
async fn a_peer_connection_is_logged_only_once() {
    let network = Arc::new(RwLock::new(configured_network()));
    let (event_tx, mut events) = broadcast::channel(16);
    let mut seen = std::collections::HashMap::new();
    let peers = vec![helios_wireguard::PeerStatus {
        public_key: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, PEER_KEY)
            .unwrap(),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(std::time::SystemTime::now()),
        endpoint: Some("203.0.113.7:51820".into()),
        rx_bytes: 0,
        tx_bytes: 0,
    }];

    log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
    let message = match events.try_recv() {
        Ok(HeliosEvent::Log { message, .. }) => message,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(message.contains("poste-test"), "message: {message}");
    assert!(message.contains("203.0.113.7:51820"), "message: {message}");
    assert!(
        message.contains("post-quantum"),
        "the peer carries a PSK, the protection must be reported: {message}"
    );

    // Second round, same state: nothing new to report. Without this
    // deduplication, the log would repeat the line every ten seconds.
    log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
    assert!(events.try_recv().is_err(), "connection logged twice");
}

/// A client that reactivates within the staleness window stays "fresh"
/// from one round to the next: without endpoint monitoring, its return
/// would be completely silent. This is what gave the impression that
/// the gateway saw nothing — and that an old session was resumed.
#[tokio::test]
async fn a_reconnection_within_the_staleness_window_is_visible() {
    let network = Arc::new(RwLock::new(configured_network()));
    let (event_tx, mut events) = broadcast::channel(16);
    let mut seen = std::collections::HashMap::new();

    let mut peers = vec![connected_peer("192.168.1.41:58466")];
    log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
    assert!(matches!(events.try_recv(), Ok(HeliosEvent::Log { .. })));

    // Same peer, still fresh, new source port: the Windows client
    // destroyed its interface and reopened a socket. This is a new
    // session, not the resumption of the old one.
    peers[0].endpoint = Some("192.168.1.41:56776".into());
    peers[0].last_handshake = Some(std::time::SystemTime::now());
    log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;

    let message = match events.try_recv() {
        Ok(HeliosEvent::Log { message, .. }) => message,
        other => panic!("the reconnection must be logged, got: {other:?}"),
    };
    assert!(message.contains("reconnected"), "message: {message}");
    assert!(message.contains("56776"), "message: {message}");
}

/// Without a PSK, the session is up on Curve25519 alone. Saying so
/// avoids believing a session is post-quantum protected when it is not
/// — this is step 1 of the ADR-001 sequence, not a flaw.
#[tokio::test]
async fn a_session_without_psk_is_reported_as_classic() {
    let network = Arc::new(RwLock::new(network_without_psk()));
    let (event_tx, mut events) = broadcast::channel(16);
    let mut seen = std::collections::HashMap::new();
    let peers = vec![helios_wireguard::PeerStatus {
        public_key: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, PEER_KEY)
            .unwrap(),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(std::time::SystemTime::now()),
        endpoint: None,
        rx_bytes: 0,
        tx_bytes: 0,
    }];

    log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
    let message = match events.try_recv() {
        Ok(HeliosEvent::Log { message, .. }) => message,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(message.contains("classic"), "message: {message}");
}

#[test]
fn wireguard_projection_keeps_the_interface_and_required_secrets() {
    let network = configured_network();

    let (iface, peers) = wg_config(&network);

    assert_eq!(iface.name, "helios0");
    assert_eq!(iface.private_key.as_str(), PRIVATE_KEY);
    assert_eq!(iface.listen_port, WG_LISTEN_PORT);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].allowed_ips, ["100.64.1.2/32"]);
    assert_eq!(
        peers[0].preshared_key.as_ref().map(|psk| psk.as_str()),
        Some("psk-test")
    );
}

#[test]
fn reading_proc_net_dev_recognizes_interface_and_counters() {
    let proc_net_dev = "Inter-|   Receive                                                |  Transmit\n\
                         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                           eth0: 42 3 1 0 0 0 0 0 84 4 2 0 0 0 0 0\n";

    assert_eq!(
        parse_proc_net_dev(proc_net_dev, "eth0"),
        Some((42, 84, 3, 4))
    );
    assert_eq!(parse_proc_net_dev(proc_net_dev, "eth1"), None);
}

#[test]
fn proc_net_dev_requires_the_exact_interface_and_complete_counters() {
    let content = "eth01: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n\
                       eth0: 100 invalid 7 0 0 0 0 0 200 9\n\
                       short: 1 2 3\n\
                       malformed without colon\n";

    assert_eq!(parse_proc_net_dev(content, "eth01"), Some((1, 9, 2, 10)));
    assert_eq!(
        parse_proc_net_dev(content, "eth0"),
        None,
        "a malformed counter must not shift every following column"
    );
    assert_eq!(parse_proc_net_dev(content, "short"), None);
    assert_eq!(parse_proc_net_dev(content, "eth"), None);
}

#[test]
fn handshake_freshness_covers_absent_recent_stale_and_future_timestamps() {
    let mut peer = connected_peer("192.0.2.1:51820");
    peer.last_handshake = None;
    assert!(!handshake_is_fresh(&peer));

    peer.last_handshake = Some(std::time::SystemTime::now());
    assert!(handshake_is_fresh(&peer));

    peer.last_handshake = Some(std::time::SystemTime::now() - HANDSHAKE_STALE_AFTER);
    assert!(!handshake_is_fresh(&peer));

    peer.last_handshake = Some(std::time::SystemTime::now() + Duration::from_secs(10));
    assert!(!handshake_is_fresh(&peer));
}

#[tokio::test]
async fn stale_peers_are_silent_until_they_disconnect_after_being_fresh() {
    let network = Arc::new(RwLock::new(configured_network()));
    let (event_tx, mut events) = broadcast::channel(16);
    let mut seen = std::collections::HashMap::new();
    let mut peer = connected_peer("192.0.2.1:51820");
    peer.last_handshake = Some(std::time::SystemTime::now() - Duration::from_secs(300));

    log_peer_transitions(&[peer.clone()], &network, &mut seen, &event_tx).await;
    assert!(
        events.try_recv().is_err(),
        "never-connected peers stay silent"
    );

    peer.last_handshake = Some(std::time::SystemTime::now());
    log_peer_transitions(&[peer.clone()], &network, &mut seen, &event_tx).await;
    assert!(matches!(events.try_recv(), Ok(HeliosEvent::Log { .. })));

    peer.last_handshake = Some(std::time::SystemTime::now() - Duration::from_secs(300));
    log_peer_transitions(&[peer], &network, &mut seen, &event_tx).await;
    let message = match events.try_recv() {
        Ok(HeliosEvent::Log { message, .. }) => message,
        other => panic!("expected disconnection log, got {other:?}"),
    };
    assert!(message.contains("inactive"), "message: {message}");
}

#[tokio::test]
async fn dry_run_mtu_probe_publishes_matching_event_and_command() {
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let (event_tx, mut events) = broadcast::channel(4);
    let (command_tx, mut commands) = mpsc::channel(4);

    spawn_mtu_probe_if_up("missing", true, &state, &event_tx, &command_tx).await;

    let event = time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        event,
        HeliosEvent::MtuDiscovered {
            mtu: 1420,
            mss: 1380
        }
    ));
    assert!(matches!(
        commands.recv().await,
        Some(OrchestratorCmd::SetMssClamp(1380))
    ));

    *state.write().await = TunnelState::Down;
    spawn_mtu_probe_if_up("missing", true, &state, &event_tx, &command_tx).await;
    tokio::task::yield_now().await;
    assert!(events.try_recv().is_err());
    assert!(commands.try_recv().is_err());
}

#[tokio::test]
async fn unsupported_mss_clamp_does_not_mutate_policy_or_reapply_firewall() {
    let firewall = UnsupportedMssFirewall {
        applied: AtomicBool::new(false),
    };
    let mut policy = configured_network().firewall_policy();

    let accepted = apply_mss_clamp(&firewall, &mut policy, TunnelState::Up, 1380)
        .await
        .unwrap();

    assert!(!accepted);
    assert_eq!(policy.mss_clamp, None);
    assert!(!firewall.applied.load(Ordering::Relaxed));
}

#[tokio::test]
async fn mss_discovery_rejects_missing_interfaces_and_bounds_small_mtus() {
    assert_eq!(discover_mss("interface-that-does-not-exist").await, None);
    assert_eq!(
        mtu_transport("interface-that-does-not-exist"),
        aether::mtu::MTU_TRANSPORT_DEFAUT
    );
    if std::path::Path::new("/sys/class/net/lo/mtu").exists() {
        let loopback_mtu: u32 = std::fs::read_to_string("/sys/class/net/lo/mtu")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(mtu_transport("lo"), loopback_mtu);
        let expected = u16::try_from(loopback_mtu)
            .ok()
            .map(|mtu| mtu.saturating_sub(100).max(576));
        assert_eq!(discover_mss("lo").await, expected);
    }
}

/// Network whose peer has no PSK yet: the starting state of a client
/// that just brought up its classic tunnel.
fn network_without_psk() -> NetworkConfig {
    let mut network = configured_network();
    network.peers[0].preshared_key = None;
    network
}

async fn request_installation(
    shared: &Arc<RwLock<NetworkConfig>>,
    wg: &dyn WireguardBackend,
    public_key: &str,
) -> Result<(), String> {
    let (events, _) = broadcast::channel(8);
    let (reply, response) = tokio::sync::oneshot::channel();
    install_peer_psk(
        InstallPskRequest {
            public_key: public_key.into(),
            address: "100.64.1.2/32".into(),
            psk: Some(aether::SecretString::new("psk-from-ml-kem")),
            reply,
        },
        shared,
        wg,
        &events,
    )
    .await;
    response
        .await
        .expect("the orchestrator must always acknowledge")
}

#[tokio::test]
async fn provisioned_psk_is_applied_to_the_data_plane() {
    let shared = Arc::new(RwLock::new(network_without_psk()));
    let wireguard = helios_wireguard::DryRunBackend::new();

    request_installation(&shared, &wireguard, PEER_KEY)
        .await
        .expect("the installation must succeed");

    // The in-memory config carries the PSK…
    assert_eq!(
        shared.read().await.peers[0]
            .preshared_key
            .as_ref()
            .map(aether::SecretString::expose),
        Some("psk-from-ml-kem")
    );
    // …and so does the data plane: it is what actually protects it.
    let peers = wireguard.peers().await.unwrap();
    assert_eq!(peers.len(), 1, "the peer must be present on the interface");
}

/// If the data plane refuses, the in-memory config must not stay ahead
/// of it: it would announce a PSK the interface does not carry, and a
/// later reconnection would apply it while the client has already
/// forgotten it.
#[tokio::test]
async fn data_plane_failure_rolls_back_the_in_memory_psk() {
    let shared = Arc::new(RwLock::new(network_without_psk()));
    let wireguard = helios_wireguard::DryRunBackend::failing_sync();

    let result = request_installation(&shared, &wireguard, PEER_KEY).await;

    assert!(result.is_err(), "the failure must propagate to the caller");
    assert_eq!(
        shared.read().await.peers[0].preshared_key,
        None,
        "INVARIANT VIOLATED: the config keeps a PSK the data plane \
             refused — the next handshake would fail with no explanation"
    );
}

/// The old PSK must be restored, not merely erased: a failed rotation
/// must not degrade a peer that was already protected.
#[tokio::test]
async fn failed_rotation_restores_the_previous_psk() {
    // `configured_network` starts with a PSK already in place.
    let shared = Arc::new(RwLock::new(configured_network()));
    let wireguard = helios_wireguard::DryRunBackend::failing_sync();

    let result = request_installation(&shared, &wireguard, PEER_KEY).await;

    assert!(result.is_err());
    assert_eq!(
        shared.read().await.peers[0]
            .preshared_key
            .as_ref()
            .map(aether::SecretString::expose),
        Some("psk-test"),
        "a failed rotation must return the peer to its prior state"
    );
}

/// The endpoint already verifies admission, but the orchestrator must
/// not rely on a caller: a peer absent from the config is refused.
#[tokio::test]
async fn a_peer_absent_from_the_configuration_is_refused() {
    let shared = Arc::new(RwLock::new(network_without_psk()));
    let wireguard = helios_wireguard::DryRunBackend::new();

    let result = request_installation(
        &shared,
        &wireguard,
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
    )
    .await;

    assert!(result.is_err(), "an undeclared peer must not be applied");
    assert_eq!(
        shared.read().await.peers[0].preshared_key,
        None,
        "the legitimate peer must not have been touched"
    );
}

#[tokio::test]
async fn dry_run_connection_stays_blocked_until_handshake() {
    let network = configured_network();
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let (events, _) = broadcast::channel(8);
    let firewall = DryRunBackend;
    let wireguard = helios_wireguard::DryRunBackend::new();

    do_connect(
        &network,
        &wireguard,
        &state,
        &events,
        &firewall,
        &network.firewall_policy(),
        true,
    )
    .await
    .unwrap();

    assert!(wireguard.is_up());
    assert_eq!(*state.read().await, TunnelState::Connecting);
    assert!(state.read().await.kill_switch_engaged());
}

#[tokio::test]
async fn disconnection_tears_down_wireguard_and_re_engages_the_kill_switch() {
    let network = configured_network();
    let shared_network = Arc::new(RwLock::new(network.duplicate()));
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let policy = Arc::new(RwLock::new(network.firewall_policy()));
    let (events, _) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let firewall = DryRunBackend;
    let wireguard = helios_wireguard::DryRunBackend::new();
    let (iface, peers) = wg_config(&network);
    wireguard.up(&iface, &peers).await.unwrap();
    let mut current_policy = network.firewall_policy();
    current_policy.mss_clamp = Some(1380);

    handle_external_cmd(
        OrchestratorCmd::Disconnect,
        &shared_network,
        true,
        &wireguard,
        &state,
        &events,
        &firewall,
        &mut current_policy,
        &internal_tx,
        &policy,
        // TPM disabled: this test does not perform a key rotation.
        &helios_tpm::BootDecision::Disabled,
    )
    .await
    .unwrap();

    assert!(!wireguard.is_up());
    assert_eq!(*state.read().await, TunnelState::Down);
    assert!(state.read().await.kill_switch_engaged());
    assert_eq!(policy.read().await.mss_clamp, None);
}

/// Hands `incoming` to the orchestrator as a reload, the way the API and the
/// `network.toml` watcher both do, and returns the events it emitted.
async fn reload(
    shared_network: &Arc<RwLock<NetworkConfig>>,
    incoming: NetworkConfig,
) -> Vec<HeliosEvent> {
    let running = shared_network.read().await.duplicate();
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let policy = Arc::new(RwLock::new(running.firewall_policy()));
    let mut current_policy = running.firewall_policy();
    let (events, mut received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let wireguard = helios_wireguard::DryRunBackend::new();

    handle_external_cmd(
        OrchestratorCmd::LoadNetworkConfig(Box::new(incoming)),
        shared_network,
        true,
        &wireguard,
        &state,
        &events,
        &DryRunBackend,
        &mut current_policy,
        &internal_tx,
        &policy,
        // TPM disabled: a reload performs no key rotation.
        &helios_tpm::BootDecision::Disabled,
    )
    .await
    .unwrap();

    let mut emitted = Vec::new();
    while let Ok(event) = received.try_recv() {
        emitted.push(event);
    }
    emitted
}

fn dual_stack_network() -> NetworkConfig {
    let mut network = configured_network();
    network.wg_address_v6 = Some("fd3c:91a2:7e04::1/64".parse().unwrap());
    network.peers[0].address_v6 = Some("fd3c:91a2:7e04::2".parse().unwrap());
    network
}

/// A peer's IPv6 VIP is part of the peer table: it reloads live
/// (`ADRESSAGE-IPV6.md` §5.4).
#[tokio::test]
async fn a_peer_ipv6_vip_change_is_applied_live() {
    let shared_network = Arc::new(RwLock::new(dual_stack_network()));
    let mut incoming = dual_stack_network();
    incoming.peers[0].address_v6 = Some("fd3c:91a2:7e04::3".parse().unwrap());

    reload(&shared_network, incoming).await;

    assert_eq!(
        shared_network.read().await.peers[0].address_v6,
        Some("fd3c:91a2:7e04::3".parse().unwrap())
    );
}

/// The tunnel prefix is applied at startup only: a reload that changes it is
/// not applied at all — not even its other changes — and says so on the
/// event stream the console reads.
#[tokio::test]
async fn a_tunnel_prefix_change_is_refused_until_restart() {
    let shared_network = Arc::new(RwLock::new(dual_stack_network()));
    let mut incoming = dual_stack_network();
    incoming.wg_address_v6 = Some("fd00:1:2::1/64".parse().unwrap());
    incoming.peers[0].address_v6 = Some("fd00:1:2::2".parse().unwrap());
    incoming.peers[0].name = "renamed".into();

    let events = reload(&shared_network, incoming).await;

    assert_eq!(*shared_network.read().await, dual_stack_network());
    let message = match events.as_slice() {
        [HeliosEvent::Log { level, message }] if level == "warn" => message,
        other => panic!("expected one warning, got {other:?}"),
    };
    assert!(message.contains("wg_address_v6"), "{message}");
    assert!(message.contains("restart"), "{message}");
}
