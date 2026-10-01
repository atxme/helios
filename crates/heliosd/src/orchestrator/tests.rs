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
