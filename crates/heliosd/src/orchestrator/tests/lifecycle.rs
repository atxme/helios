use super::*;
use std::path::PathBuf;
use tokio::{sync::oneshot, task::JoinHandle};

const DEADLINE: Duration = Duration::from_secs(5);
const OTHER_PEER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

/// The file paths are process settings, so run the actor on a private runtime
/// in the existing readiness-test subprocess.
fn isolated_ready_path() -> Option<PathBuf> {
    if std::env::var_os("HELIOS_TEST_READY_CHILD").is_some() {
        let path = std::env::var_os("HELIOS_READY_PATH").expect("isolated readiness path");
        return Some(PathBuf::from(path));
    }
    let directory = tempfile::tempdir().expect("isolated readiness directory");
    let thread = std::thread::current();
    let test = thread
        .name()
        .expect("libtest runs this test on a named thread");
    run_readiness_test_child(test, &directory.path().join("ready"));
    None
}

struct Running {
    task: JoinHandle<anyhow::Result<()>>,
    commands: mpsc::Sender<OrchestratorCmd>,
    installs: mpsc::Sender<InstallPskRequest>,
    observations: mpsc::Sender<ObserveHandshakeRequest>,
    peers: Arc<RwLock<Vec<PeerStatus>>>,
    events: broadcast::Receiver<HeliosEvent>,
    state: Arc<RwLock<TunnelState>>,
    network: Arc<RwLock<NetworkConfig>>,
    policy: Arc<RwLock<FirewallPolicy>>,
}

impl Running {
    fn start(config: NetworkConfig, ready: bool) -> Self {
        let policy = Arc::new(RwLock::new(NetworkConfig::default().firewall_policy()));
        let network = Arc::new(RwLock::new(config));
        let state = Arc::new(RwLock::new(TunnelState::Down));
        let peers = Arc::new(RwLock::new(Vec::new()));
        let (event_tx, events) = broadcast::channel(64);
        let (commands, cmd_rx) = mpsc::channel(4);
        let (installs, psk_rx) = mpsc::channel(4);
        let (observations, handshake_rx) = mpsc::channel(4);
        let task = tokio::spawn(run(
            Arc::clone(&network),
            true,
            FirewallMode::Enforced,
            Arc::clone(&state),
            event_tx,
            cmd_rx,
            psk_rx,
            handshake_rx,
            Arc::clone(&policy),
            Arc::clone(&peers),
            Arc::new(RwLock::new(Ipv6TunnelStatus::NotConfigured)),
            helios_tpm::BootDecision::Disabled,
            helios_tpm::TpmSettings::default(),
            Arc::new(AtomicBool::new(ready)),
            false,
        ));
        Self {
            task,
            commands,
            installs,
            observations,
            peers,
            events,
            state,
            network,
            policy,
        }
    }

    async fn event(&mut self, predicate: impl Fn(&HeliosEvent) -> bool) -> HeliosEvent {
        time::timeout(DEADLINE, async {
            loop {
                let event = self.events.recv().await.expect("read orchestrator event");
                if predicate(&event) {
                    break event;
                }
            }
        })
        .await
        .expect("orchestrator emits expected event")
    }

    async fn state_change(&mut self, expected: TunnelState) {
        let event = self
            .event(|event| matches!(event, HeliosEvent::StateChanged { .. }))
            .await;
        let HeliosEvent::StateChanged { state } = event else {
            unreachable!("state change was selected");
        };
        assert_eq!(state, expected);
    }

    async fn observe(&self, public_key: &str) -> Option<std::time::SystemTime> {
        let (reply, response) = oneshot::channel();
        self.observations
            .send(ObserveHandshakeRequest {
                public_key: public_key.into(),
                reply,
            })
            .await
            .expect("observe through orchestrator");
        time::timeout(DEADLINE, response)
            .await
            .expect("observation answers")
            .expect("read observation reply")
            .expect("read simulated WireGuard")
    }

    async fn wait_for_peers(&self, expected: &[&str]) {
        time::timeout(Duration::from_secs(12), async {
            loop {
                let keys: Vec<_> = self
                    .peers
                    .read()
                    .await
                    .iter()
                    .map(PeerStatus::public_key_b64)
                    .collect();
                if keys == expected {
                    break;
                }
                time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("handshake poller publishes the expected peers");
    }

    async fn finish(self) {
        // Keep the other channel senders alive until the command close is seen.
        drop(self.commands);
        time::timeout(DEADLINE, self.task)
            .await
            .expect("shutdown completes")
            .expect("orchestrator task finishes")
            .expect("clean shutdown");
        assert_eq!(*self.state.read().await, TunnelState::Down);
    }
}

fn network() -> NetworkConfig {
    NetworkConfig {
        // Dry-run needs neither a real WAN nor actual peer reachability.
        wan_ifaces: vec!["fixture-wan".into()],
        allow_client_internet: false,
        ..configured_network()
    }
}

#[tokio::test(start_paused = true)]
async fn startup_waits_for_a_handshake_and_closing_commands_takes_the_tunnel_down() {
    let Some(path) = isolated_ready_path() else {
        return;
    };
    let mut running = Running::start(network(), true);
    running.state_change(TunnelState::Down).await;
    running.state_change(TunnelState::Connecting).await;
    running.wait_for_peers(&[PEER_KEY]).await;

    let marker = std::fs::read_to_string(path).expect("daemon readiness marker");
    assert!(marker.contains("mode_reel=false\n"));
    assert!(marker.contains("firewall_enforced=false\n"));
    assert_eq!(running.observe(PEER_KEY).await, None);

    let mut events = running.events.resubscribe();
    running.finish().await;
    assert!(matches!(
        events.try_recv(),
        Ok(HeliosEvent::StateChanged {
            state: TunnelState::Down
        })
    ));
}

#[tokio::test]
async fn a_gateway_without_a_key_stops_startup_before_readiness() {
    let Some(path) = isolated_ready_path() else {
        return;
    };
    let config = NetworkConfig {
        wg_private_key: "".into(),
        ..network()
    };
    let mut running = Running::start(config, true);

    running.state_change(TunnelState::Down).await;
    let error = time::timeout(DEADLINE, running.task)
        .await
        .expect("startup refusal completes")
        .expect("task returns")
        .expect_err("missing key must prevent startup");
    assert!(error.to_string().contains("gateway not configured"));
    assert!(!path.exists());
    assert_eq!(*running.state.read().await, TunnelState::Down);
}

#[tokio::test(start_paused = true)]
async fn an_api_that_never_binds_does_not_publish_readiness_or_promote_the_tunnel() {
    let Some(path) = isolated_ready_path() else {
        return;
    };
    let mut running = Running::start(network(), false);
    running.state_change(TunnelState::Down).await;
    running.state_change(TunnelState::Connecting).await;
    assert!(!path.exists());

    let error = time::timeout(Duration::from_secs(11), running.task)
        .await
        .expect("readiness deadline expires")
        .expect("task returns")
        .expect_err("listener did not bind");
    assert!(error
        .to_string()
        .contains("API did not reach its ready state"));
    assert!(!path.exists());
    assert_ne!(*running.state.read().await, TunnelState::Up);
}

#[tokio::test(start_paused = true)]
async fn disconnect_clears_the_backend_and_connect_brings_the_peer_back() {
    let Some(_) = isolated_ready_path() else {
        return;
    };
    let mut running = Running::start(network(), true);
    running.state_change(TunnelState::Down).await;
    running.state_change(TunnelState::Connecting).await;
    running.wait_for_peers(&[PEER_KEY]).await;

    running
        .commands
        .send(OrchestratorCmd::Disconnect)
        .await
        .unwrap();
    running.state_change(TunnelState::Down).await;
    running.wait_for_peers(&[]).await;

    running
        .commands
        .send(OrchestratorCmd::Connect)
        .await
        .unwrap();
    running.state_change(TunnelState::Connecting).await;
    running.wait_for_peers(&[PEER_KEY]).await;
    running.finish().await;
}

#[tokio::test]
async fn invalid_split_tunnel_update_keeps_the_last_policy_and_the_actor_running() {
    let Some(_) = isolated_ready_path() else {
        return;
    };
    let mut running = Running::start(network(), true);
    let allowed = vec!["192.0.2.0/24".to_string()];
    running
        .commands
        .send(OrchestratorCmd::SetSplitTunnel(allowed.clone()))
        .await
        .unwrap();
    running
        .event(
            |event| matches!(event, HeliosEvent::SplitTunnelChanged { cidrs } if cidrs == &allowed),
        )
        .await;

    running
        .commands
        .send(OrchestratorCmd::SetSplitTunnel(vec!["192.0.2.0/33".into()]))
        .await
        .unwrap();
    running.event(|event| matches!(event, HeliosEvent::Log { level, message } if level == "error" && message.contains("Split-tunneling not applied"))).await;
    assert_eq!(running.policy.read().await.split_tunnel_cidrs, allowed);
    assert_eq!(running.observe(PEER_KEY).await, None);
    running.finish().await;
}

#[tokio::test]
async fn the_provisioning_channel_distinguishes_admitted_and_unknown_peers() {
    let Some(_) = isolated_ready_path() else {
        return;
    };
    let running = Running::start(network(), true);
    for (public_key, should_accept) in [(OTHER_PEER_KEY, false), (PEER_KEY, true)] {
        let (reply, response) = oneshot::channel();
        running
            .installs
            .send(InstallPskRequest {
                public_key: public_key.into(),
                address: "100.64.1.2/32".into(),
                psk: None,
                reply,
            })
            .await
            .expect("send provisioning request");
        let result = time::timeout(DEADLINE, response)
            .await
            .expect("provisioning replies")
            .expect("acknowledgement");
        if should_accept {
            result.expect("known peer may clear the test PSK");
        } else {
            assert!(result
                .expect_err("unknown peer refused")
                .contains("peer unknown"));
            assert!(running.network.read().await.peers[0]
                .preshared_key
                .is_some());
        }
    }
    let network = running.network.read().await;
    assert!(network.peers[0].preshared_key.is_none());
    assert_eq!(network.peers[0].address, "100.64.1.2/32");
    drop(network);
    assert_eq!(running.observe(OTHER_PEER_KEY).await, None);
    running.finish().await;
}

#[tokio::test(start_paused = true)]
async fn a_disk_reload_updates_the_live_peer_list_and_keeps_runtime_credentials() {
    let Some(_) = isolated_ready_path() else {
        return;
    };
    let original = network();
    original
        .save_redacted()
        .expect("write isolated network fixture");
    let mut running = Running::start(original, true);
    running.state_change(TunnelState::Down).await;
    running.state_change(TunnelState::Connecting).await;
    running.wait_for_peers(&[PEER_KEY]).await;

    let mut updated = NetworkConfig::load().expect("read the public config");
    updated.peers.push(aether::WgPeer {
        name: "added-device".into(),
        public_key: OTHER_PEER_KEY.into(),
        address: "100.64.1.3/32".into(),
        preshared_key: None,
        address_v6: None,
        admin: false,
        minimum_key_negotiation_mode: None,
        key_negotiation_certificate_sha256: None,
        key_negotiation_pq_certificate_sha256: None,
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });
    updated
        .save()
        .expect("console-style reload writes only public state");

    running
        .event(|event| {
            matches!(event, HeliosEvent::Log { level, message }
        if level == "info" && message == "Network configuration applied")
        })
        .await;
    running.wait_for_peers(&[PEER_KEY, OTHER_PEER_KEY]).await;
    let state = running.network.read().await;
    assert!(!state.wg_private_key.is_empty());
    assert!(state.peers[0].preshared_key.is_some());
    drop(state);
    let disk = NetworkConfig::load().expect("read persisted config");
    assert!(disk.wg_private_key.is_empty());
    assert!(disk.peers.iter().all(|peer| peer.preshared_key.is_none()));
    running.finish().await;
}

#[tokio::test(start_paused = true)]
async fn a_reload_rejected_by_wireguard_keeps_the_previous_config_and_takes_the_tunnel_down() {
    let Some(_) = isolated_ready_path() else {
        return;
    };
    let mut running = Running::start(network(), true);
    running.state_change(TunnelState::Down).await;
    running.state_change(TunnelState::Connecting).await;
    running.wait_for_peers(&[PEER_KEY]).await;

    let mut changed = network();
    changed.peers[0].public_key = "invalid-fixture-key".into();
    running
        .commands
        .send(OrchestratorCmd::LoadNetworkConfig(Box::new(changed)))
        .await
        .expect("send candidate to the running actor");
    running.state_change(TunnelState::Down).await;

    let error = time::timeout(DEADLINE, running.task)
        .await
        .expect("failed reload stops the actor")
        .expect("task finishes")
        .expect_err("WireGuard refused the candidate peers");
    assert!(error
        .to_string()
        .contains("WireGuard peer synchronization failed"));
    let network = running.network.read().await;
    assert_eq!(network.peers[0].public_key, PEER_KEY);
    assert!(network.peers[0].preshared_key.is_some());
    assert_eq!(*running.state.read().await, TunnelState::Down);
}
