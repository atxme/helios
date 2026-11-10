use super::*;
use helios_firewall::FirewallCapabilities;
use std::sync::atomic::AtomicUsize;

struct ObservedPeersBackend {
    peers: Option<Vec<PeerStatus>>,
}

#[async_trait::async_trait]
impl WireguardBackend for ObservedPeersBackend {
    async fn up(&self, _: &InterfaceConfig, _: &[PeerConfig]) -> helios_wireguard::Result<()> {
        Err(WgError::Unavailable("unexpected up".into()))
    }
    async fn down(&self) -> helios_wireguard::Result<()> {
        Err(WgError::Unavailable("unexpected down".into()))
    }
    async fn sync_peers(&self, _: &[PeerConfig]) -> helios_wireguard::Result<()> {
        Err(WgError::Unavailable("unexpected sync".into()))
    }
    async fn peers(&self) -> helios_wireguard::Result<Vec<PeerStatus>> {
        self.peers
            .clone()
            .ok_or_else(|| WgError::Unavailable("peer read failed".into()))
    }
    fn is_up(&self) -> bool {
        true
    }
    fn kind(&self) -> &'static str {
        "test"
    }
}

#[tokio::test]
async fn handshake_observation_distinguishes_peer_absence_from_backend_failure() {
    async fn observe(
        backend: &ObservedPeersBackend,
        key: &str,
    ) -> Result<Option<std::time::SystemTime>, String> {
        let (reply, response) = tokio::sync::oneshot::channel();
        observe_peer_handshake(
            ObserveHandshakeRequest {
                public_key: key.into(),
                reply,
            },
            backend,
        )
        .await;
        response.await.expect("observation reply")
    }
    let mut observed = connected_peer("127.0.0.1:1234");
    let handshake = std::time::UNIX_EPOCH + Duration::from_secs(12345);
    observed.last_handshake = Some(handshake);
    let backend = ObservedPeersBackend {
        peers: Some(vec![observed.clone()]),
    };
    assert_eq!(
        observe(&backend, PEER_KEY).await.expect("read"),
        Some(handshake)
    );
    assert_eq!(observe(&backend, PRIVATE_KEY).await.expect("read"), None);
    observed.last_handshake = None;
    let without_handshake = ObservedPeersBackend {
        peers: Some(vec![observed]),
    };
    assert_eq!(
        observe(&without_handshake, PEER_KEY).await.expect("read"),
        None
    );
    let failed = ObservedPeersBackend { peers: None };
    assert!(observe(&failed, PEER_KEY)
        .await
        .expect_err("read failure must not be a handshake")
        .contains("peer read failed"));
}

const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

struct UnsupportedMssFirewall {
    applied: AtomicBool,
}

struct TransitionFirewall {
    states: std::sync::Mutex<Vec<TunnelState>>,
    refuse: bool,
}

#[async_trait::async_trait]
impl FirewallBackend for TransitionFirewall {
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities::default()
    }

    async fn apply(&self, _policy: &FirewallPolicy, state: TunnelState) -> aether::Result<()> {
        self.states
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(state);
        if self.refuse {
            Err(aether::HeliosError::Firewall("test refusal".into()))
        } else {
            Ok(())
        }
    }

    async fn teardown(&self) -> aether::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn transition_updates_state_broadcasts_and_applies_the_matching_policy_state() {
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let (event_tx, mut events) = broadcast::channel(4);
    let firewall = TransitionFirewall {
        states: std::sync::Mutex::new(Vec::new()),
        refuse: false,
    };
    let policy = configured_network().firewall_policy();

    transition(&state, &event_tx, TunnelState::Up, &firewall, &policy)
        .await
        .expect("firewall accepts the transition");

    assert_eq!(*state.read().await, TunnelState::Up);
    assert!(matches!(
        events.try_recv(),
        Ok(HeliosEvent::StateChanged {
            state: TunnelState::Up
        })
    ));
    assert_eq!(
        *firewall
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        [TunnelState::Up]
    );
}

#[tokio::test]
async fn transition_propagates_firewall_refusal() {
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let (event_tx, _events) = broadcast::channel(4);
    let firewall = TransitionFirewall {
        states: std::sync::Mutex::new(Vec::new()),
        refuse: true,
    };
    let policy = configured_network().firewall_policy();

    let error = transition(&state, &event_tx, TunnelState::Up, &firewall, &policy)
        .await
        .expect_err("firewall refusal must propagate");

    assert!(format!("{error:#}").contains("applying the firewall"));
    assert_eq!(
        *firewall
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        [TunnelState::Up]
    );
}

#[test]
fn emitted_logs_preserve_level_and_message_in_the_event_stream() {
    let (tx, mut events) = broadcast::channel(4);

    for (level, message) in [
        ("error", "failed"),
        ("warn", "degraded"),
        ("info", "ready"),
        ("other", "default level"),
    ] {
        emit_log(&tx, level, message);
        assert!(matches!(
            events.try_recv(),
            Ok(HeliosEvent::Log {
                level: event_level,
                message: event_message
            }) if event_level == level && event_message == message
        ));
    }
}

fn run_readiness_test_child(test_name: &str, path: &std::path::Path) {
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env("HELIOS_TEST_READY_CHILD", "1")
        .env("HELIOS_READY_PATH", path)
        .status()
        .expect("isolated readiness test starts");
    assert!(status.success(), "isolated readiness test must succeed");
}

#[test]
fn readiness_marker_reports_real_dry_run_and_maintenance_modes() {
    const CHILD: &str = "HELIOS_TEST_READY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().expect("temporary readiness directory");
        run_readiness_test_child(
            "orchestrator::tests::readiness_marker_reports_real_dry_run_and_maintenance_modes",
            &directory.path().join("nested/ready"),
        );
        return;
    }

    let path = std::path::PathBuf::from(
        std::env::var_os("HELIOS_READY_PATH").expect("child readiness path"),
    );

    publish_readiness(true, FirewallMode::Enforced).expect("publish dry-run readiness");
    let dry_run = std::fs::read_to_string(&path).expect("dry-run marker");
    assert!(dry_run.contains("mode_reel=false\n"));
    assert!(dry_run.contains("firewall_enforced=false\n"));

    publish_readiness(false, FirewallMode::Enforced).expect("publish real readiness");
    let enforced = std::fs::read_to_string(&path).expect("enforced marker");
    assert!(enforced.contains("mode_reel=true\n"));
    assert!(enforced.contains("firewall_enforced=true\n"));

    publish_readiness(false, FirewallMode::DisabledForMaintenance)
        .expect("publish maintenance readiness");
    let maintenance = std::fs::read_to_string(&path).expect("maintenance marker");
    assert!(maintenance.contains("mode_reel=true\n"));
    assert!(maintenance.contains("firewall_enforced=false\n"));
    assert!(!path.with_extension("tmp").exists());
}

#[test]
fn readiness_marker_refuses_parent_creation_errors_without_a_partial_marker() {
    const CHILD: &str = "HELIOS_TEST_READY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().expect("temporary readiness directory");
        let parent = directory.path().join("not-a-directory");
        std::fs::write(&parent, b"blocker").expect("create parent blocker");
        run_readiness_test_child(
            "orchestrator::tests::readiness_marker_refuses_parent_creation_errors_without_a_partial_marker",
            &parent.join("ready"),
        );
        return;
    }

    let path = std::path::PathBuf::from(
        std::env::var_os("HELIOS_READY_PATH").expect("child readiness path"),
    );
    let parent = path.parent().expect("parent blocker path");

    let result = publish_readiness(false, FirewallMode::Enforced);

    assert!(result.is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read(parent).expect("blocker remains"), b"blocker");
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
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    }
}

/// Exercise the file watcher in a child process: its configuration path is a
/// process-wide environment variable and must not affect concurrent tests.
#[tokio::test(start_paused = true)]
async fn network_watcher_keeps_runtime_secrets_and_refuses_invalid_changes() {
    const CHILD: &str = "HELIOS_TEST_NETWORK_WATCHER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().expect("temporary configuration directory");
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "orchestrator::tests::network_watcher_keeps_runtime_secrets_and_refuses_invalid_changes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("HELIOS_NETWORK_CONFIG", directory.path().join("network.toml"))
            .status()
            .expect("isolated watcher test starts");
        assert!(status.success(), "isolated watcher test must succeed");
        return;
    }

    let running = configured_network();
    running.save_redacted().expect("initial public config");
    let path = NetworkConfig::path();
    let initial_file = std::fs::read_to_string(&path).expect("public config");
    assert!(!initial_file.contains(PRIVATE_KEY));
    assert!(!initial_file.contains("psk-test"));
    let shared = Arc::new(RwLock::new(running));
    let (sender, mut received) = mpsc::channel(4);
    spawn_network_config_watcher(Arc::clone(&shared), sender);
    tokio::task::yield_now().await;

    std::fs::write(&path, "invalid = [").expect("invalid config");
    time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        received.try_recv().is_err(),
        "invalid TOML must not be applied"
    );

    let mut incompatible = shared.read().await.duplicate();
    incompatible.wg_address_v6 = Some("fd3c:91a2:7e04::1/64".parse().expect("prefix"));
    incompatible
        .save_redacted()
        .expect("config with changed prefix");
    let loaded = NetworkConfig::load().expect("changed prefix is valid on disk");
    assert!(loaded.check_hot_reload(&*shared.read().await).is_err());
    time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        received.try_recv().is_err(),
        "a new tunnel prefix requires restart"
    );

    let mut updated = shared.read().await.duplicate();
    updated.peers[0].name = "renamed workstation".into();
    updated.save_redacted().expect("changed public config");
    time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let command = received.try_recv().expect("reload command");
    let OrchestratorCmd::LoadNetworkConfig(config) = command else {
        panic!("expected a network reload");
    };
    assert_eq!(config.peers[0].name, "renamed workstation");
    assert_eq!(config.wg_private_key.expose(), PRIVATE_KEY);
    assert_eq!(
        config.peers[0]
            .preshared_key
            .as_ref()
            .expect("runtime PSK")
            .expose(),
        "psk-test"
    );
    *shared.write().await = *config;
    time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(
        received.try_recv().is_err(),
        "unchanged config must not reload twice"
    );
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
    let (iface, peers) = wg_config(&*network.read().await, &Ipv6TunnelStatus::NotConfigured);
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

    let (iface, peers) = wg_config(&network, &Ipv6TunnelStatus::NotConfigured);

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

#[test]
fn an_unreadable_wan_falls_back_to_ethernet() {
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
    }
}

#[test]
fn the_probe_derives_the_mss_from_the_interface_mtu_per_family() {
    // Ethernet. The probe used to subtract a 60-byte IPv4 outer overhead
    // (1500 − 100 = 1400) while the interface is sized with 80: a clamp at
    // 1400 announced segments of 1440 bytes into a 1420-byte interface.
    assert_eq!(
        tunnel_mss(1500),
        TunnelMss {
            tunnel_mtu: 1420,
            ipv4: 1380,
            ipv6: Some(1360),
        }
    );
    // PPPoE still carries IPv6.
    assert_eq!(
        tunnel_mss(1492),
        TunnelMss {
            tunnel_mtu: 1412,
            ipv4: 1372,
            ipv6: Some(1352),
        }
    );
    // WSL2: the tunnel is IPv4-only, so there is no IPv6 MSS.
    assert_eq!(
        tunnel_mss(1280),
        TunnelMss {
            tunnel_mtu: 1200,
            ipv4: 1160,
            ipv6: None,
        }
    );
}

#[test]
fn the_probe_and_the_interface_agree_on_the_tunnel_mtu() {
    // The clamp must fit the MTU `wg_config` sets, for any transport.
    for transport in [0, 576, 1280, 1359, 1360, 1492, 1500, 9000, 65536] {
        let probed = tunnel_mss(transport);
        assert_eq!(
            u32::from(probed.tunnel_mtu),
            aether::mtu::tunnel_mtu(transport)
        );
        assert!(
            u32::from(probed.ipv4) + aether::mtu::TCP_IPV4_HEADERS <= u32::from(probed.tunnel_mtu)
        );
        if let Some(ipv6) = probed.ipv6 {
            assert!(
                u32::from(ipv6) + aether::mtu::TCP_IPV6_HEADERS <= u32::from(probed.tunnel_mtu)
            );
        }
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
    request_installation_with(shared, wg, public_key, Ipv6TunnelStatus::NotConfigured).await
}

async fn request_installation_with(
    shared: &Arc<RwLock<NetworkConfig>>,
    wg: &dyn WireguardBackend,
    public_key: &str,
    ipv6: Ipv6TunnelStatus,
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
        &Arc::new(RwLock::new(ipv6)),
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
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
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
    let (iface, peers) = wg_config(&network, &Ipv6TunnelStatus::NotConfigured);
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
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await
    .unwrap();

    assert!(!wireguard.is_up());
    assert_eq!(*state.read().await, TunnelState::Down);
    assert!(state.read().await.kill_switch_engaged());
    assert_eq!(policy.read().await.mss_clamp, None);
}

/// A failed firewall transition must not prevent an explicit disconnect from
/// tearing down WireGuard. The command still reports the firewall failure.
#[tokio::test]
async fn disconnect_firewall_refusal_still_tears_down_wireguard() {
    let network = configured_network();
    let shared_network = Arc::new(RwLock::new(network.duplicate()));
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let shared_policy = Arc::new(RwLock::new(network.firewall_policy()));
    let mut current_policy = network.firewall_policy();
    let (events, mut received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let wireguard = helios_wireguard::DryRunBackend::new();
    let (iface, peers) = wg_config(&network, &Ipv6TunnelStatus::NotConfigured);
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");

    let result = handle_external_cmd(
        OrchestratorCmd::Disconnect,
        &shared_network,
        true,
        &wireguard,
        &state,
        &events,
        &RefusingFirewall,
        &mut current_policy,
        &internal_tx,
        &shared_policy,
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await;

    assert!(
        result.is_err(),
        "the refused firewall transition propagates"
    );
    assert_eq!(*state.read().await, TunnelState::Down);
    assert!(
        !wireguard.is_up(),
        "the explicit disconnect must tear down WireGuard despite the firewall error"
    );
    assert_eq!(*shared_policy.read().await, network.firewall_policy());
    let emitted: Vec<_> = std::iter::from_fn(|| received.try_recv().ok()).collect();
    assert!(emitted.iter().any(|event| matches!(
        event,
        HeliosEvent::StateChanged {
            state: TunnelState::Down
        }
    )));
}

#[tokio::test]
async fn disconnect_wireguard_teardown_failure_is_reported() {
    let network = configured_network();
    let shared_network = Arc::new(RwLock::new(network.duplicate()));
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let shared_policy = Arc::new(RwLock::new(network.firewall_policy()));
    let mut current_policy = network.firewall_policy();
    let (events, _received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let wireguard = PartiallyFailingWireguard::new(true, None);
    let (iface, peers) = wg_config(&network, &Ipv6TunnelStatus::NotConfigured);
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");

    let error = handle_external_cmd(
        OrchestratorCmd::Disconnect,
        &shared_network,
        true,
        &wireguard,
        &state,
        &events,
        &TrackingFirewall::accepting(),
        &mut current_policy,
        &internal_tx,
        &shared_policy,
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await
    .expect_err("a failed interface teardown must be reported");

    assert!(error.to_string().contains("WireGuard teardown refused"));
    assert_eq!(wireguard.down_attempts(), 1);
    assert!(wireguard.is_up());
}

#[tokio::test]
async fn disconnect_reports_both_firewall_and_wireguard_teardown_failures() {
    let network = configured_network();
    let shared_network = Arc::new(RwLock::new(network.duplicate()));
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let shared_policy = Arc::new(RwLock::new(network.firewall_policy()));
    let mut current_policy = network.firewall_policy();
    let (events, _received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let wireguard = PartiallyFailingWireguard::new(true, None);
    let (iface, peers) = wg_config(&network, &Ipv6TunnelStatus::NotConfigured);
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");

    let error = handle_external_cmd(
        OrchestratorCmd::Disconnect,
        &shared_network,
        true,
        &wireguard,
        &state,
        &events,
        &TrackingFirewall::refuses_down(),
        &mut current_policy,
        &internal_tx,
        &shared_policy,
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await
    .expect_err("both cleanup failures must be reported");

    let message = format!("{error:#}");
    assert!(message.contains("firewall down refused"), "{message}");
    assert!(message.contains("WireGuard teardown refused"), "{message}");
    assert_eq!(wireguard.down_attempts(), 1);
    assert!(wireguard.is_up());
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
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await
    .unwrap();

    let mut emitted = Vec::new();
    while let Ok(event) = received.try_recv() {
        emitted.push(event);
    }
    emitted
}

/// Exercise a reload while the data plane is already up. The regular `reload`
/// helper deliberately uses a down interface, so it does not reach the live
/// peer synchronization branch.
async fn reload_on_live_tunnel(
    shared_network: &Arc<RwLock<NetworkConfig>>,
    incoming: NetworkConfig,
    wireguard: &dyn WireguardBackend,
    firewall: &dyn FirewallBackend,
) -> (
    anyhow::Result<()>,
    Vec<HeliosEvent>,
    FirewallPolicy,
    Arc<RwLock<TunnelState>>,
    Arc<RwLock<FirewallPolicy>>,
) {
    let running = shared_network.read().await.duplicate();
    let state = Arc::new(RwLock::new(TunnelState::Up));
    let shared_policy = Arc::new(RwLock::new(running.firewall_policy()));
    let mut current_policy = running.firewall_policy();
    let (events, mut received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);

    let result = handle_external_cmd(
        OrchestratorCmd::LoadNetworkConfig(Box::new(incoming)),
        shared_network,
        true,
        wireguard,
        &state,
        &events,
        firewall,
        &mut current_policy,
        &internal_tx,
        &shared_policy,
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await;
    let mut emitted = Vec::new();
    while let Ok(event) = received.try_recv() {
        emitted.push(event);
    }
    (result, emitted, current_policy, state, shared_policy)
}

fn two_peer_test_network() -> NetworkConfig {
    let mut network = configured_network();
    network.peers.push(aether::WgPeer {
        name: "second workstation".into(),
        public_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [2u8; 32]),
        address: "100.64.1.3/32".into(),
        address_v6: None,
        admin: false,
        preshared_key: Some(aether::SecretString::new("second-psk")),
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: None,
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });
    network
}

fn duplicate_peer_config_for_test(peer: &PeerConfig) -> PeerConfig {
    PeerConfig {
        public_key: peer.public_key.clone(),
        allowed_ips: peer.allowed_ips.clone(),
        preshared_key: peer
            .preshared_key
            .as_ref()
            .map(|key| Zeroizing::new(key.to_string())),
        persistent_keepalive_secs: peer.persistent_keepalive_secs,
    }
}

/// A live reload synchronizes the actual peer table after the policy and
/// configuration have been accepted.
#[tokio::test]
async fn an_accepted_live_reload_synchronizes_wireguard_peers() {
    let running = configured_network();
    let shared_network = Arc::new(RwLock::new(running.duplicate()));
    let wireguard = helios_wireguard::DryRunBackend::new();
    let (iface, peers) = wg_config(&running, &Ipv6TunnelStatus::NotConfigured);
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");

    let mut incoming = running.duplicate();
    let added_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [2u8; 32]);
    let added = aether::WgPeer {
        name: "second workstation".into(),
        public_key: added_key.clone(),
        address: "100.64.1.3/32".into(),
        address_v6: None,
        admin: false,
        preshared_key: None,
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        minimum_key_negotiation_mode: None,
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    };
    incoming.peers.push(added);

    let (result, events, _, _, _) =
        reload_on_live_tunnel(&shared_network, incoming, &wireguard, &DryRunBackend).await;

    result.expect("the compatible reload applies");
    assert_eq!(shared_network.read().await.peers.len(), 2);
    let installed = wireguard.peers().await.expect("read live peers");
    assert_eq!(installed.len(), 2);
    assert!(installed.iter().any(|peer| peer.public_key
        == base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &added_key,)
            .expect("added public key")));
    assert!(events.iter().any(|event| matches!(
        event,
        HeliosEvent::Log { level, message }
            if level == "info" && message == "Network configuration applied"
    )));
}

/// A failed, partially mutating peer synchronization must keep the running
/// configuration and secrets, apply the fail-closed firewall state, and tear
/// down the interface before returning the error.
#[tokio::test]
async fn failed_live_reload_sync_preserves_config_and_closes_the_data_plane() {
    let running = two_peer_test_network();
    let shared_network = Arc::new(RwLock::new(running.duplicate()));
    let (iface, peers) = wg_config(&running, &Ipv6TunnelStatus::NotConfigured);
    let revoked_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, PEER_KEY)
        .expect("revoked fixture key");
    let wireguard =
        PartiallyFailingWireguard::new(false, Some(duplicate_peer_config_for_test(&peers[0])));
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");
    let mut incoming = running.duplicate();
    incoming.peers.remove(0);
    incoming.peers[0].address = "100.64.1.4/32".into();
    let firewall = TrackingFirewall::accepting();

    let (result, events, policy, state, shared_policy) =
        reload_on_live_tunnel(&shared_network, incoming, &wireguard, &firewall).await;

    let error = result.expect_err("a failed synchronization is reported");
    assert!(error.to_string().contains("partial peer synchronization"));
    assert_eq!(
        *shared_network.read().await,
        running,
        "retain secrets/config"
    );
    assert_eq!(
        shared_network.read().await.peers[0]
            .preshared_key
            .as_ref()
            .map(aether::SecretString::expose),
        Some("psk-test"),
        "the revoked peer's PSK remains in the retained running configuration"
    );
    assert_eq!(policy, running.firewall_policy());
    assert_eq!(*shared_policy.read().await, running.firewall_policy());
    assert_eq!(*state.read().await, TunnelState::Down);
    assert!(
        !wireguard.is_up(),
        "the interface is closed after sync failure"
    );
    let closed_peers = wireguard.peers().await.expect("closed peer table");
    assert!(closed_peers.is_empty());
    assert!(!closed_peers
        .iter()
        .any(|peer| peer.public_key == revoked_key));
    assert_eq!(
        firewall.applied_states(),
        [TunnelState::Up, TunnelState::Down]
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        HeliosEvent::Log { message, .. } if message == "Network configuration applied"
    )));
}

/// If both cleanup backends fail after partial peer mutation, surface all
/// failures and preserve the old configuration rather than claiming success.
#[tokio::test]
async fn failed_live_reload_reports_firewall_and_wireguard_teardown_errors() {
    let running = two_peer_test_network();
    let shared_network = Arc::new(RwLock::new(running.duplicate()));
    let (iface, peers) = wg_config(&running, &Ipv6TunnelStatus::NotConfigured);
    let revoked_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, PEER_KEY)
        .expect("revoked fixture key");
    let wireguard =
        PartiallyFailingWireguard::new(true, Some(duplicate_peer_config_for_test(&peers[0])));
    wireguard
        .up(&iface, &peers)
        .await
        .expect("initial interface");
    let mut incoming = running.duplicate();
    incoming.peers.remove(0);
    incoming.peers[0].address = "100.64.1.4/32".into();
    let firewall = TrackingFirewall::refuses_down();

    let (result, events, policy, state, shared_policy) =
        reload_on_live_tunnel(&shared_network, incoming, &wireguard, &firewall).await;

    let error = result.expect_err("cleanup failures are returned");
    let message = format!("{error:#}");
    assert!(
        message.contains("partial peer synchronization"),
        "{message}"
    );
    assert!(message.contains("firewall down refused"), "{message}");
    assert!(message.contains("WireGuard teardown refused"), "{message}");
    assert_eq!(
        *shared_network.read().await,
        running,
        "retain secrets/config"
    );
    assert_eq!(
        shared_network.read().await.peers[0]
            .preshared_key
            .as_ref()
            .map(aether::SecretString::expose),
        Some("psk-test")
    );
    assert_eq!(policy, running.firewall_policy());
    assert_eq!(*shared_policy.read().await, running.firewall_policy());
    assert_eq!(*state.read().await, TunnelState::Down);
    assert_eq!(wireguard.down_attempts(), 1, "teardown was attempted");
    assert!(
        wireguard.is_up(),
        "the fake refuses to remove the interface"
    );
    let installed = wireguard.peers().await.expect("partially changed peers");
    assert_eq!(installed.len(), 2);
    let retained_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [2u8; 32]),
    )
    .expect("retained peer key");
    assert!(installed.iter().any(|peer| peer.public_key == revoked_key));
    assert!(installed
        .iter()
        .any(|peer| { peer.public_key == retained_key && peer.allowed_ips == ["100.64.1.4/32"] }));
    assert!(!events.iter().any(|event| matches!(
        event,
        HeliosEvent::Log { message, .. } if message == "Network configuration applied"
    )));
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

// ─── Refused policy mutations ────────────────────────────────────────────────

/// A backend that refuses every ruleset, as the kernel refuses a batch.
struct RefusingFirewall;

#[async_trait::async_trait]
impl FirewallBackend for RefusingFirewall {
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities::default()
    }

    async fn apply(&self, _policy: &FirewallPolicy, _state: TunnelState) -> aether::Result<()> {
        Err(aether::HeliosError::Firewall(
            "transaction refused by the test backend".into(),
        ))
    }

    async fn teardown(&self) -> aether::Result<()> {
        Ok(())
    }
}

struct TrackingFirewall {
    applied: std::sync::Mutex<Vec<TunnelState>>,
    refuse_down: bool,
}

impl TrackingFirewall {
    fn accepting() -> Self {
        Self {
            applied: std::sync::Mutex::new(Vec::new()),
            refuse_down: false,
        }
    }

    fn refuses_down() -> Self {
        Self {
            applied: std::sync::Mutex::new(Vec::new()),
            refuse_down: true,
        }
    }

    fn applied_states(&self) -> Vec<TunnelState> {
        self.applied
            .lock()
            .expect("recorded firewall states")
            .clone()
    }
}

#[async_trait::async_trait]
impl FirewallBackend for TrackingFirewall {
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities::default()
    }

    async fn apply(&self, _policy: &FirewallPolicy, state: TunnelState) -> aether::Result<()> {
        self.applied
            .lock()
            .expect("record firewall state")
            .push(state);
        if self.refuse_down && state == TunnelState::Down {
            return Err(aether::HeliosError::Firewall(
                "firewall down refused".into(),
            ));
        }
        Ok(())
    }

    async fn teardown(&self) -> aether::Result<()> {
        Ok(())
    }
}

struct PartiallyFailingWireguard {
    inner: helios_wireguard::DryRunBackend,
    fail_down: bool,
    retained_peer: std::sync::Mutex<Option<PeerConfig>>,
    down_attempts: AtomicUsize,
}

impl PartiallyFailingWireguard {
    fn new(fail_down: bool, retained_peer: Option<PeerConfig>) -> Self {
        Self {
            inner: helios_wireguard::DryRunBackend::new(),
            fail_down,
            retained_peer: std::sync::Mutex::new(retained_peer),
            down_attempts: AtomicUsize::new(0),
        }
    }

    fn down_attempts(&self) -> usize {
        self.down_attempts.load(Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl WireguardBackend for PartiallyFailingWireguard {
    async fn up(
        &self,
        config: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> helios_wireguard::Result<()> {
        self.inner.up(config, peers).await
    }

    async fn down(&self) -> helios_wireguard::Result<()> {
        self.down_attempts.fetch_add(1, Ordering::Relaxed);
        if self.fail_down {
            return Err(WgError::Unavailable("WireGuard teardown refused".into()));
        }
        self.inner.down().await
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> helios_wireguard::Result<()> {
        let mut partially_applied: Vec<_> =
            peers.iter().map(duplicate_peer_config_for_test).collect();
        if let Some(stale_peer) = self.retained_peer.lock().expect("stale test peer").take() {
            partially_applied.push(stale_peer);
        }
        self.inner.sync_peers(&partially_applied).await?;
        Err(WgError::Unavailable(
            "partial peer synchronization refused".into(),
        ))
    }

    async fn peers(&self) -> helios_wireguard::Result<Vec<PeerStatus>> {
        self.inner.peers().await
    }

    fn is_up(&self) -> bool {
        self.inner.is_up()
    }

    fn kind(&self) -> &'static str {
        "partial-failure-test"
    }
}

/// What the main loop sees of one external command: its result — an `Err`
/// is what stops the loop — and the events it emitted.
async fn run_command(
    cmd: OrchestratorCmd,
    fw: &dyn FirewallBackend,
    state: TunnelState,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    policy: &mut FirewallPolicy,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
) -> (anyhow::Result<()>, Vec<HeliosEvent>) {
    let (events, mut received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);
    let result = handle_external_cmd(
        cmd,
        shared_network,
        true,
        &helios_wireguard::DryRunBackend::new(),
        &Arc::new(RwLock::new(state)),
        &events,
        fw,
        policy,
        &internal_tx,
        shared_policy,
        // TPM disabled: none of these commands rotates the gateway key.
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await;
    let mut emitted = Vec::new();
    while let Ok(event) = received.try_recv() {
        emitted.push(event);
    }
    (result, emitted)
}

/// The one error log the refusal emitted, and nothing else: in particular no
/// `SplitTunnelChanged` announcing a list that is not in force.
fn single_error(events: &[HeliosEvent]) -> &str {
    match events {
        [HeliosEvent::Log { level, message }] if level == "error" => message,
        other => panic!("expected one error log, got {other:?}"),
    }
}

fn policy_with_split_tunnel(cidrs: &[&str]) -> FirewallPolicy {
    let mut policy = configured_network().firewall_policy();
    policy.split_tunnel_cidrs = cidrs.iter().map(|cidr| cidr.to_string()).collect();
    policy
}

/// An invalid CIDR is refused in every state, not only in `Up` where the
/// ruleset reads it: accepted while down, it would stop the orchestrator at
/// the next promotion instead.
#[tokio::test]
async fn an_invalid_split_tunnel_cidr_keeps_the_running_policy() {
    for state in [TunnelState::Up, TunnelState::Down] {
        let running = policy_with_split_tunnel(&["192.168.1.0/24"]);
        let mut policy = running.clone();
        let shared_policy = Arc::new(RwLock::new(running.clone()));
        let shared_network = Arc::new(RwLock::new(configured_network()));

        let (result, events) = run_command(
            OrchestratorCmd::SetSplitTunnel(vec!["192.168.1.0/24".into(), "fd00::/129".into()]),
            &DryRunBackend,
            state,
            &shared_network,
            &mut policy,
            &shared_policy,
        )
        .await;

        result.unwrap_or_else(|error| panic!("{state:?}: the loop must continue: {error:#}"));
        assert_eq!(policy, running, "{state:?}");
        assert_eq!(*shared_policy.read().await, running, "{state:?}");
        let message = single_error(&events);
        assert!(message.contains("fd00::/129"), "{message}");
    }
}

/// The backend refusing a valid list leaves the previous one in force, and the
/// orchestrator still takes the next command.
#[tokio::test]
async fn a_split_tunnel_list_the_backend_refuses_keeps_the_running_policy() {
    let running = policy_with_split_tunnel(&["192.168.1.0/24"]);
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));
    let shared_network = Arc::new(RwLock::new(configured_network()));
    let requested = vec!["10.0.0.0/8".to_string(), "fd00:1::/64".to_string()];

    let (result, events) = run_command(
        OrchestratorCmd::SetSplitTunnel(requested.clone()),
        &RefusingFirewall,
        TunnelState::Up,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    result.expect("the loop must continue");
    assert_eq!(policy, running);
    assert_eq!(*shared_policy.read().await, running);
    let message = single_error(&events);
    assert!(message.contains("refused by the test backend"), "{message}");

    let (result, events) = run_command(
        OrchestratorCmd::SetSplitTunnel(requested.clone()),
        &DryRunBackend,
        TunnelState::Up,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    result.expect("a valid list applies");
    assert_eq!(policy.split_tunnel_cidrs, requested);
    assert_eq!(shared_policy.read().await.split_tunnel_cidrs, requested);
    assert!(matches!(
        events.as_slice(),
        [HeliosEvent::SplitTunnelChanged { cidrs }] if *cidrs == requested
    ));
}

/// A reload whose policy the firewall refuses is not applied at all — neither
/// the policy nor the rest of the configuration — and the loop continues.
#[tokio::test]
async fn a_reload_the_firewall_refuses_keeps_the_running_configuration() {
    let shared_network = Arc::new(RwLock::new(configured_network()));
    let running = configured_network().firewall_policy();
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));
    let mut incoming = configured_network();
    incoming.split_tunnel_cidrs = vec!["10.0.0.0/33".into()];
    incoming.peers[0].name = "renamed".into();

    let (result, events) = run_command(
        OrchestratorCmd::LoadNetworkConfig(Box::new(incoming)),
        &DryRunBackend,
        TunnelState::Down,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    result.expect("the loop must continue");
    assert_eq!(*shared_network.read().await, configured_network());
    assert_eq!(policy, running);
    assert_eq!(*shared_policy.read().await, running);
    let message = single_error(&events);
    assert!(message.contains("10.0.0.0/33"), "{message}");
}

// ─── IPv6 on the data plane (`ADRESSAGE-IPV6.md` §6.1, §6.2) ─────────────────

const PREFIX: &str = "fd3c:91a2:7e04::1/64";
const PEER_VIP_V6: &str = "fd3c:91a2:7e04::2/128";

fn addresses_and_allowed_ips(
    network: &NetworkConfig,
    ipv6: &Ipv6TunnelStatus,
) -> (Vec<String>, Vec<String>) {
    let (iface, peers) = wg_config(network, ipv6);
    (iface.addresses, peers[0].allowed_ips.clone())
}

/// Criterion 6: without `wg_address_v6`, nothing changes — whatever the
/// status says, since no status can conjure a prefix the file does not have.
#[test]
fn a_gateway_without_a_prefix_projects_exactly_the_ipv4_data_plane() {
    let network = configured_network();
    for ipv6 in [
        Ipv6TunnelStatus::NotConfigured,
        Ipv6TunnelStatus::Installed,
        Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::TunnelMtuTooSmall {
            tunnel_mtu: 1200,
            minimum: 1280,
        }),
    ] {
        let (iface, peers) = wg_config(&network, &ipv6);
        assert_eq!(iface.addresses, ["100.64.0.1/10"], "{ipv6:?}");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips, ["100.64.1.2/32"], "{ipv6:?}");
    }
    assert_eq!(
        ipv6_installability(&network, 576, std::path::Path::new("/nonexistent")),
        Ipv6TunnelStatus::NotConfigured,
        "a gateway without a prefix is not degraded, and nothing is read for it"
    );
}

/// Criterion 7: exactly `{v4/32, v6/128}` per peer and `[wg_address,
/// prefix::1/64]` on the interface.
#[test]
fn an_installed_prefix_adds_exactly_one_host_per_family() {
    let (addresses, allowed) =
        addresses_and_allowed_ips(&dual_stack_network(), &Ipv6TunnelStatus::Installed);
    assert_eq!(addresses, ["100.64.0.1/10", PREFIX]);
    assert_eq!(allowed, ["100.64.1.2/32", PEER_VIP_V6]);
}

/// A peer admitted before the gateway had a prefix keeps its IPv4 alone
/// (§8): the projection adds nothing it was not given.
#[test]
fn a_peer_without_an_ipv6_vip_keeps_its_ipv4_alone() {
    let mut network = dual_stack_network();
    network.peers[0].address_v6 = None;
    let (addresses, allowed) = addresses_and_allowed_ips(&network, &Ipv6TunnelStatus::Installed);
    assert_eq!(addresses, ["100.64.0.1/10", PREFIX]);
    assert_eq!(allowed, ["100.64.1.2/32"]);
}

/// Criterion 8, projection half: unavailable means absent from the interface
/// *and* from every `AllowedIPs`, or the data plane would contradict itself.
#[test]
fn an_unavailable_prefix_is_neither_on_the_interface_nor_in_allowed_ips() {
    let unavailable = Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::DisabledByKernel {
        setting: "net.ipv6.conf.all.disable_ipv6".into(),
    });
    let (addresses, allowed) = addresses_and_allowed_ips(&dual_stack_network(), &unavailable);
    assert_eq!(addresses, ["100.64.0.1/10"]);
    assert_eq!(allowed, ["100.64.1.2/32"]);
}

/// The VIP routing receives the prefix — and so runs `ip -6` at all — only
/// when the bring-up installed it.
#[test]
fn only_an_installed_prefix_reaches_the_vip_routing() {
    let network = dual_stack_network();
    assert_eq!(
        installed_prefix(&network, &Ipv6TunnelStatus::Installed),
        network.wg_address_v6
    );
    assert_eq!(
        installed_prefix(&network, &Ipv6TunnelStatus::NotConfigured),
        None
    );
    assert_eq!(
        installed_prefix(
            &network,
            &Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::NoKernelSupport {
                path: "/proc/sys/net/ipv6/conf/all/disable_ipv6".into(),
            })
        ),
        None
    );
    assert_eq!(
        installed_prefix(&configured_network(), &Ipv6TunnelStatus::Installed),
        None
    );
}

/// A kernel `conf` directory with the two settings the decision reads.
fn ipv6_conf(all: &str, default: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    for (scope, value) in [("all", all), ("default", default)] {
        std::fs::create_dir(directory.path().join(scope)).expect("scope directory");
        std::fs::write(directory.path().join(scope).join("disable_ipv6"), value).expect("setting");
    }
    directory
}

#[test]
fn ipv6_is_installable_on_a_wide_enough_tunnel_with_ipv6_enabled() {
    let conf = ipv6_conf("0\n", "0\n");
    assert_eq!(
        ipv6_installability(&dual_stack_network(), 1420, conf.path()),
        Ipv6TunnelStatus::Installed
    );
    assert_eq!(
        ipv6_installability(&dual_stack_network(), 1280, conf.path()),
        Ipv6TunnelStatus::Installed,
        "1280 is the IPv6 minimum itself, not below it"
    );
}

#[test]
fn a_tunnel_below_1280_bytes_cannot_carry_ipv6() {
    let conf = ipv6_conf("0\n", "0\n");
    assert_eq!(
        ipv6_installability(&dual_stack_network(), 1279, conf.path()),
        Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::TunnelMtuTooSmall {
            tunnel_mtu: 1279,
            minimum: 1280,
        })
    );
}

#[test]
fn disable_ipv6_for_new_or_all_interfaces_is_named() {
    for (all, default, scope) in [("1\n", "0\n", "all"), ("0\n", "1\n", "default")] {
        let conf = ipv6_conf(all, default);
        assert_eq!(
            ipv6_installability(&dual_stack_network(), 1420, conf.path()),
            Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::DisabledByKernel {
                setting: format!("net.ipv6.conf.{scope}.disable_ipv6"),
            })
        );
    }
}

#[test]
fn a_kernel_without_an_ipv6_stack_is_named() {
    let directory = tempfile::tempdir().expect("tempdir");
    let status = ipv6_installability(&dual_stack_network(), 1420, directory.path());
    assert!(
        matches!(
            &status,
            Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::NoKernelSupport { path })
                if path.ends_with("disable_ipv6")
        ),
        "{status:?}"
    );
}

/// What a bring-up left behind: the interface, the peers, the published
/// status and the events.
struct BringUp {
    wireguard: helios_wireguard::DryRunBackend,
    state: Arc<RwLock<TunnelState>>,
    ipv6: Ipv6TunnelStatus,
    events: Vec<HeliosEvent>,
}

async fn bring_up(
    network: &NetworkConfig,
    candidate: Ipv6TunnelStatus,
    wireguard: helios_wireguard::DryRunBackend,
) -> anyhow::Result<BringUp> {
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let shared_ipv6 = Arc::new(RwLock::new(Ipv6TunnelStatus::default()));
    let (event_tx, mut received) = broadcast::channel(32);
    connect_with_ipv6(
        network,
        candidate,
        &wireguard,
        &state,
        &event_tx,
        &DryRunBackend,
        &network.firewall_policy(),
        true,
        &shared_ipv6,
    )
    .await?;
    let mut events = Vec::new();
    while let Ok(event) = received.try_recv() {
        events.push(event);
    }
    let ipv6 = shared_ipv6.read().await.clone();
    Ok(BringUp {
        wireguard,
        state,
        ipv6,
        events,
    })
}

fn warnings(events: &[HeliosEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            HeliosEvent::Log { level, message } if level == "warn" => Some(message.as_str()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn an_installed_prefix_reaches_the_interface_and_the_peers() {
    let up = bring_up(
        &dual_stack_network(),
        Ipv6TunnelStatus::Installed,
        helios_wireguard::DryRunBackend::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        up.wireguard.interface_addresses(),
        ["100.64.0.1/10", PREFIX]
    );
    assert_eq!(
        up.wireguard.peers().await.unwrap()[0].allowed_ips,
        ["100.64.1.2/32", PEER_VIP_V6]
    );
    assert_eq!(up.ipv6, Ipv6TunnelStatus::Installed);
    assert!(warnings(&up.events).is_empty(), "{:?}", up.events);
}

/// Criterion 8: a prefix that cannot be installed leaves an IPv4-only
/// gateway, says why on the event stream, and publishes the reason.
#[tokio::test]
async fn a_tunnel_too_narrow_for_ipv6_starts_ipv4_only_and_says_so() {
    let reason = Ipv6Unavailable::TunnelMtuTooSmall {
        tunnel_mtu: 1200,
        minimum: 1280,
    };
    let up = bring_up(
        &dual_stack_network(),
        Ipv6TunnelStatus::Unavailable(reason.clone()),
        helios_wireguard::DryRunBackend::new(),
    )
    .await
    .unwrap();

    assert_eq!(up.wireguard.interface_addresses(), ["100.64.0.1/10"]);
    assert_eq!(
        up.wireguard.peers().await.unwrap()[0].allowed_ips,
        ["100.64.1.2/32"]
    );
    assert_eq!(up.ipv6, Ipv6TunnelStatus::Unavailable(reason));
    let warned = warnings(&up.events);
    assert!(
        warned
            .iter()
            .any(|message| message.contains("IPv6 not installed") && message.contains("1280")),
        "{warned:?}"
    );
    assert!(up.state.read().await.kill_switch_engaged());
}

/// Criterion 8, kernel half: the address the pre-checks could not foresee is
/// refused at bring-up; the half-configured interface is replaced by an
/// IPv4-only one, and the refusal is published verbatim.
#[tokio::test]
async fn a_kernel_refusing_the_ipv6_address_leaves_an_ipv4_only_gateway() {
    let up = bring_up(
        &dual_stack_network(),
        Ipv6TunnelStatus::Installed,
        helios_wireguard::DryRunBackend::without_ipv6(),
    )
    .await
    .unwrap();

    assert!(up.wireguard.is_up());
    assert_eq!(up.wireguard.interface_addresses(), ["100.64.0.1/10"]);
    assert_eq!(
        up.wireguard.peers().await.unwrap()[0].allowed_ips,
        ["100.64.1.2/32"]
    );
    match &up.ipv6 {
        Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::AddressRefused { address, detail }) => {
            assert_eq!(address, PREFIX);
            assert!(detail.contains("IPv6 is disabled"), "{detail}");
        }
        other => panic!("expected AddressRefused, got {other:?}"),
    }
    assert!(
        warnings(&up.events)
            .iter()
            .any(|message| message.contains("IPv6 not installed")),
        "{:?}",
        up.events
    );
    assert!(up.state.read().await.kill_switch_engaged());
}

/// If the kernel also refuses the IPv4-only retry, startup fails closed and
/// retains both failures in the diagnostic instead of reporting degradation.
#[tokio::test]
async fn a_failed_ipv4_only_retry_keeps_the_kill_switch_engaged() {
    let network = dual_stack_network();
    let wireguard = helios_wireguard::DryRunBackend::without_ipv6_or_retry();
    let state = Arc::new(RwLock::new(TunnelState::Down));
    let ipv6 = Arc::new(RwLock::new(Ipv6TunnelStatus::default()));
    let (events, _) = broadcast::channel(16);

    let error = connect_with_ipv6(
        &network,
        Ipv6TunnelStatus::Installed,
        &wireguard,
        &state,
        &events,
        &DryRunBackend,
        &network.firewall_policy(),
        true,
        &ipv6,
    )
    .await
    .expect_err("a refused IPv4-only retry must fail startup");

    let message = format!("{error:#}");
    assert!(message.contains("IPv4-only retry refused"), "{message}");
    assert!(message.contains("IPv6 is disabled"), "{message}");
    assert!(state.read().await.kill_switch_engaged());
    assert_eq!(*ipv6.read().await, Ipv6TunnelStatus::default());
}

/// Only a kernel-side refusal is retried: a configuration the backend
/// refuses before touching anything fails the start, as it always did.
#[tokio::test]
async fn a_refusal_that_is_not_the_kernels_is_not_retried_without_ipv6() {
    let mut network = dual_stack_network();
    network.peers[0].public_key = "AAAA".into();

    let error = bring_up(
        &network,
        Ipv6TunnelStatus::Installed,
        helios_wireguard::DryRunBackend::new(),
    )
    .await
    .err()
    .expect("an invalid peer key must fail the bring-up");

    assert!(
        error
            .to_string()
            .contains("bringing up the WireGuard interface"),
        "{error:#}"
    );
    assert!(!format!("{error:#}").contains("without IPv6"), "{error:#}");
}

/// The PSK path projects the peers again: it must keep the families the
/// bring-up installed, no more and no fewer.
#[tokio::test]
async fn a_psk_installation_keeps_the_installed_families() {
    for (ipv6, expected) in [
        (
            Ipv6TunnelStatus::Installed,
            vec!["100.64.1.2/32", PEER_VIP_V6],
        ),
        (
            Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::DisabledByKernel {
                setting: "net.ipv6.conf.all.disable_ipv6".into(),
            }),
            vec!["100.64.1.2/32"],
        ),
    ] {
        let mut network = dual_stack_network();
        network.peers[0].preshared_key = None;
        let shared = Arc::new(RwLock::new(network));
        let wireguard = helios_wireguard::DryRunBackend::new();

        request_installation_with(&shared, &wireguard, PEER_KEY, ipv6.clone())
            .await
            .expect("the installation must succeed");

        assert_eq!(
            wireguard.peers().await.unwrap()[0].allowed_ips,
            expected,
            "{ipv6:?}"
        );
    }
}

/// `heliosd status` names the prefix and, when it cannot be installed here,
/// the degraded start and its reason.
#[test]
fn the_status_command_describes_the_ipv6_outcome() {
    assert_eq!(
        describe_ipv6(&configured_network(), Ipv6TunnelStatus::NotConfigured),
        "not configured"
    );
    assert_eq!(
        describe_ipv6(&dual_stack_network(), Ipv6TunnelStatus::Installed),
        format!("{PREFIX} (installable on this host)")
    );
    let degraded = describe_ipv6(
        &dual_stack_network(),
        Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::TunnelMtuTooSmall {
            tunnel_mtu: 1200,
            minimum: 1280,
        }),
    );
    assert!(degraded.starts_with(PREFIX), "{degraded}");
    assert!(degraded.contains("IPv4-only"), "{degraded}");
    assert!(degraded.contains("1200"), "{degraded}");
}

/// A `network.toml` the `Down` ruleset accepts but `Up` would refuse stops
/// the start, naming the entry, instead of the first promotion.
#[test]
fn a_policy_that_does_not_compile_refuses_the_start() {
    let mut network = dual_stack_network();
    network.split_tunnel_cidrs = vec!["192.168.10.0/24".into(), "fd12:3456:789a::/48".into()];
    check_startup_policy(&network).unwrap();

    network.split_tunnel_cidrs.push("10.0.0.0/33".into());
    let refusal = format!("{:#}", check_startup_policy(&network).unwrap_err());
    assert!(refusal.contains("10.0.0.0/33"), "{refusal}");

    let mut network = configured_network();
    network.allow_ssh_from = vec!["fd00::/129".into()];
    let refusal = format!("{:#}", check_startup_policy(&network).unwrap_err());
    assert!(refusal.contains("fd00::/129"), "{refusal}");
}

// ─── `wan_iface = "auto"` following the kernel (`uplinks`) ───────────────────

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| name.to_string()).collect()
}

/// An adapter plugged in after startup is proposed once, and adopted as the
/// running set once applied; nothing is proposed while the kernel agrees.
#[test]
fn a_new_uplink_is_proposed_once_then_owned() {
    let mut tracker = UplinkTracker::new(names(&["eth0"]));
    let running = names(&["eth0"]);
    assert_eq!(
        tracker.step(&running, Some(names(&["eth0"]))),
        UplinkStep::Unchanged
    );

    let grown = names(&["eth0", "usb0"]);
    assert_eq!(
        tracker.step(&running, Some(grown.clone())),
        UplinkStep::Propose(grown.clone())
    );
    // Pending: not sent a second time.
    assert_eq!(
        tracker.step(&running, Some(grown.clone())),
        UplinkStep::Unchanged
    );
    // Applied by the main loop: it is now the watcher's own list.
    assert_eq!(
        tracker.step(&grown, Some(grown.clone())),
        UplinkStep::Unchanged
    );
    // Unplugged again: the set shrinks the same way.
    assert_eq!(
        tracker.step(&grown, Some(names(&["eth0"]))),
        UplinkStep::Propose(names(&["eth0"]))
    );
}

/// The kernel reordering two admitted links changes no rule: nothing is sent.
#[test]
fn a_preference_change_alone_rebuilds_nothing() {
    let running = names(&["eth0", "wlan0"]);
    let mut tracker = UplinkTracker::new(running.clone());
    assert_eq!(
        tracker.step(&running, Some(names(&["wlan0", "eth0"]))),
        UplinkStep::Unchanged
    );
}

/// Every cable out: the running set stays, it is not emptied.
#[test]
fn no_usable_uplink_keeps_the_running_set() {
    let running = names(&["eth0"]);
    let mut tracker = UplinkTracker::new(running.clone());
    assert_eq!(tracker.step(&running, None), UplinkStep::Unchanged);
}

/// A list the firewall refused is not proposed again on every tick, but a
/// different one is, and the kernel going back to the running set clears it.
#[test]
fn a_refused_set_is_not_retried_until_the_kernel_moves() {
    let running = names(&["eth0"]);
    let mut tracker = UplinkTracker::new(running.clone());
    let refused = names(&["eth0", "usb0"]);
    assert_eq!(
        tracker.step(&running, Some(refused.clone())),
        UplinkStep::Propose(refused.clone())
    );
    assert_eq!(
        tracker.step(&running, Some(refused.clone())),
        UplinkStep::Unchanged
    );
    assert_eq!(
        tracker.step(&running, Some(names(&["eth0"]))),
        UplinkStep::Unchanged
    );
    assert_eq!(
        tracker.step(&running, Some(refused.clone())),
        UplinkStep::Propose(refused)
    );
}

/// The operator naming the interfaces explicitly takes the list over.
#[test]
fn an_explicit_list_set_since_startup_stops_the_watcher() {
    let mut tracker = UplinkTracker::new(names(&["eth0"]));
    assert_eq!(
        tracker.step(&names(&["enp3s0"]), Some(names(&["eth0", "usb0"]))),
        UplinkStep::Relinquish
    );
}

async fn refresh(
    previous: &[&str],
    next: &[&str],
    fw: &dyn FirewallBackend,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    policy: &mut FirewallPolicy,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
) -> Vec<HeliosEvent> {
    let (events, mut received) = broadcast::channel(8);
    refresh_wan_ifaces(
        names(previous),
        names(next),
        shared_network,
        &Arc::new(RwLock::new(TunnelState::Up)),
        &events,
        fw,
        policy,
        shared_policy,
    )
    .await;
    let mut emitted = Vec::new();
    while let Ok(event) = received.try_recv() {
        emitted.push(event);
    }
    emitted
}

/// An accepted refresh moves the configuration, the policy and its published
/// copy together.
#[tokio::test]
async fn a_refreshed_uplink_set_is_applied_to_the_firewall() {
    let shared_network = Arc::new(RwLock::new(configured_network()));
    let mut policy = configured_network().firewall_policy();
    let shared_policy = Arc::new(RwLock::new(policy.clone()));

    let events = refresh(
        &["eth0"],
        &["eth0", "usb0"],
        &DryRunBackend,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    let expected = names(&["eth0", "usb0"]);
    assert_eq!(shared_network.read().await.wan_ifaces, expected);
    assert_eq!(policy.wan_ifaces, expected);
    assert_eq!(shared_policy.read().await.wan_ifaces, expected);
    assert!(matches!(
        events.as_slice(),
        [HeliosEvent::Log { level, .. }] if level == "info"
    ));
}

/// A ruleset the firewall refuses leaves the running one, and its interfaces,
/// in force.
#[tokio::test]
async fn a_refused_uplink_set_keeps_the_running_firewall() {
    let shared_network = Arc::new(RwLock::new(configured_network()));
    let running = configured_network().firewall_policy();
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));

    let events = refresh(
        &["eth0"],
        &["eth0", "usb0"],
        &RefusingFirewall,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    assert_eq!(*shared_network.read().await, configured_network());
    assert_eq!(policy, running);
    assert_eq!(*shared_policy.read().await, running);
    let message = single_error(&events);
    assert!(message.contains("refused by the test backend"), "{message}");
}

/// A reload that changed the list between the observation and the apply wins:
/// the refresh is dropped, not written over it.
#[tokio::test]
async fn a_refresh_based_on_a_stale_list_is_dropped() {
    // `NetworkConfig` is not `Clone` (it carries secrets): built twice.
    let network = || {
        let mut network = configured_network();
        network.wan_ifaces = names(&["enp3s0"]);
        network
    };
    let shared_network = Arc::new(RwLock::new(network()));
    let running = network().firewall_policy();
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));

    let events = refresh(
        &["eth0"],
        &["eth0", "usb0"],
        &DryRunBackend,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    assert_eq!(*shared_network.read().await, network());
    assert_eq!(policy, running);
    assert!(events.is_empty());
}

/// The API path cannot reach it: only the uplink watcher, in-process, sends it.
#[tokio::test]
async fn an_uplink_refresh_on_the_external_channel_is_ignored() {
    let shared_network = Arc::new(RwLock::new(configured_network()));
    let running = configured_network().firewall_policy();
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));

    let (result, _) = run_command(
        OrchestratorCmd::RefreshWanIfaces {
            previous: names(&["eth0"]),
            next: names(&["eth0", "usb0"]),
        },
        &DryRunBackend,
        TunnelState::Up,
        &shared_network,
        &mut policy,
        &shared_policy,
    )
    .await;

    result.expect("the loop must continue");
    assert_eq!(*shared_network.read().await, configured_network());
    assert_eq!(policy, running);
}

/// The handshake poller is the only source allowed to promote the state; an
/// API-originated copy of the internal command cannot change it.
#[tokio::test]
async fn an_inferred_tunnel_state_on_the_external_channel_is_ignored() {
    let network = configured_network();
    let shared_network = Arc::new(RwLock::new(network.duplicate()));
    let state = Arc::new(RwLock::new(TunnelState::Connecting));
    let running = network.firewall_policy();
    let mut policy = running.clone();
    let shared_policy = Arc::new(RwLock::new(running.clone()));
    let (events, mut received) = broadcast::channel(8);
    let (internal_tx, _internal_rx) = mpsc::channel(1);

    handle_external_cmd(
        OrchestratorCmd::TunnelStateInferred(TunnelState::Up),
        &shared_network,
        true,
        &helios_wireguard::DryRunBackend::new(),
        &state,
        &events,
        &DryRunBackend,
        &mut policy,
        &internal_tx,
        &shared_policy,
        &helios_tpm::BootDecision::Disabled,
        &Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
    )
    .await
    .expect("an untrusted internal command is ignored");

    assert_eq!(*state.read().await, TunnelState::Connecting);
    assert_eq!(policy, running);
    assert_eq!(*shared_policy.read().await, running);
    assert!(
        received.try_recv().is_err(),
        "the ignored internal command emits no state event"
    );
}
