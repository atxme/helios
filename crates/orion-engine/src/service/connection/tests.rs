use super::*;
use aether::key_negotiation::ProtectionMode;
use orion_core::{
    vault::{DeviceRootKey, ProfileStore, RootKeyProvider, VaultError},
    ClientConfig, ClientProfile, KeyNegotiationSettings, PskKind,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "orion-connection-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TestRoot;

impl RootKeyProvider for TestRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(
            [0x5a; orion_core::vault::KEY_LEN],
        )))
    }

    fn hardware_backed(&self) -> bool {
        false
    }
}

fn test_store(root: &Path) -> Arc<ProfileStore> {
    Arc::new(
        ProfileStore::new(root.join("vault"), Box::new(TestRoot)).allowing_unencrypted_volume(true),
    )
}

fn settings(minimum_mode: ProtectionMode) -> KeyNegotiationSettings {
    KeyNegotiationSettings {
        mode: ProtectionMode::MlKem,
        minimum_mode,
        endpoint: "gateway.example:51821".into(),
        server_name: "gateway.example".into(),
        gateway_ca_der: String::new(),
        gateway_pq_certificate: String::new(),
        identity: "identity".into(),
        trust: None,
    }
}

fn profile(name: &str, minimum_mode: Option<ProtectionMode>) -> ClientProfile {
    let keypair = aether::wg::generate_keypair().expect("WireGuard keypair");
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: keypair.private_key,
        peer_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        key_negotiation: minimum_mode.map(settings),
        ..ClientProfile::default()
    }
}

fn config_with(profile: Option<ClientProfile>) -> Arc<Mutex<ClientConfig>> {
    Arc::new(Mutex::new(ClientConfig {
        profiles: profile.into_iter().collect(),
        selected: None,
    }))
}

async fn wait_for_config_task(config: &Mutex<ClientConfig>) {
    // Queue behind the spawned floor task while holding the config lock so
    // no-op branches are checked after that task has examined them.
    let held = config.lock().await;
    tokio::task::yield_now().await;
    drop(held);
    drop(config.lock().await);
}

async fn wait_for_floor(store: &ProfileStore, expected: ProtectionMode) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if store
                .load()
                .expect("vault remains readable")
                .profiles
                .first()
                .and_then(|profile| profile.key_negotiation.as_ref())
                .is_some_and(|settings| settings.minimum_mode == expected)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("raised floor reaches the sealed profile");
}

async fn run_floor_case(
    label: &str,
    observed: PskKind,
    initial: Option<ProtectionMode>,
    expected: Option<ProtectionMode>,
) {
    let scratch = Scratch::new(label);
    let store = test_store(scratch.path());
    let stored = profile("bureau", initial);
    store
        .save_profile(&stored)
        .expect("seed protected test profile");
    let config = config_with(Some(stored));
    raise_key_negotiation_floor(
        Arc::clone(&config),
        Arc::clone(&store),
        "bureau".into(),
        observed,
    );
    wait_for_config_task(&config).await;

    if let Some(expected) = expected {
        wait_for_floor(&store, expected).await;
        let memory = config.lock().await;
        assert_eq!(
            memory.profiles[0]
                .key_negotiation
                .as_ref()
                .expect("settings remain")
                .minimum_mode,
            expected
        );
        assert!(
            !store.legacy_present(),
            "raising a floor must not recreate profiles.toml"
        );
    } else {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let memory = config.lock().await;
        assert_eq!(
            memory.profiles[0]
                .key_negotiation
                .as_ref()
                .expect("settings remain")
                .minimum_mode,
            initial.expect("no-op case starts with a floor")
        );
        assert_eq!(
            store.load().expect("vault readable").profiles[0]
                .key_negotiation
                .as_ref()
                .expect("stored settings remain")
                .minimum_mode,
            initial.expect("no-op case starts with a floor")
        );
    }
}

#[tokio::test]
async fn no_protection_event_does_not_raise_a_floor() {
    let scratch = Scratch::new("floor-none");
    let store = test_store(scratch.path());
    let stored = profile("bureau", Some(ProtectionMode::StaticPsk));
    store.save_profile(&stored).expect("seed profile");
    let config = config_with(Some(stored));

    // None returns synchronously before spawning the persistence task.
    raise_key_negotiation_floor(
        Arc::clone(&config),
        Arc::clone(&store),
        "bureau".into(),
        PskKind::None,
    );

    assert_eq!(
        config.lock().await.profiles[0]
            .key_negotiation
            .as_ref()
            .unwrap()
            .minimum_mode,
        ProtectionMode::StaticPsk
    );
    assert_eq!(
        store.load().unwrap().profiles[0]
            .key_negotiation
            .as_ref()
            .unwrap()
            .minimum_mode,
        ProtectionMode::StaticPsk
    );
}

#[tokio::test]
async fn mlkem_observation_raises_a_static_floor_in_memory_and_in_the_vault() {
    run_floor_case(
        "floor-mlkem",
        PskKind::MlKem,
        Some(ProtectionMode::StaticPsk),
        Some(ProtectionMode::MlKem),
    )
    .await;
}

#[tokio::test]
async fn static_psk_observation_never_downgrades_an_mlkem_floor() {
    run_floor_case(
        "floor-static-no-downgrade",
        PskKind::Static,
        Some(ProtectionMode::MlKem),
        None,
    )
    .await;
}

#[tokio::test]
async fn static_psk_observation_is_idempotent_at_the_static_floor() {
    run_floor_case(
        "floor-static-idempotent",
        PskKind::Static,
        Some(ProtectionMode::StaticPsk),
        None,
    )
    .await;
}

#[tokio::test]
async fn an_unknown_profile_does_not_create_or_persist_a_floor() {
    let scratch = Scratch::new("floor-profile-absent");
    let store = test_store(scratch.path());
    let config = config_with(None);
    raise_key_negotiation_floor(
        Arc::clone(&config),
        Arc::clone(&store),
        "absent".into(),
        PskKind::MlKem,
    );
    wait_for_config_task(&config).await;
    assert!(config.lock().await.profiles.is_empty());
    assert!(!store.legacy_present());
}

#[tokio::test]
async fn a_profile_without_negotiation_settings_has_no_floor_to_raise() {
    let scratch = Scratch::new("floor-settings-absent");
    let store = test_store(scratch.path());
    let stored = profile("bureau", None);
    store.save_profile(&stored).expect("seed classic profile");
    let config = config_with(Some(stored));
    raise_key_negotiation_floor(
        Arc::clone(&config),
        Arc::clone(&store),
        "bureau".into(),
        PskKind::MlKem,
    );
    wait_for_config_task(&config).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(config.lock().await.profiles[0].key_negotiation.is_none());
    assert!(store.load().unwrap().profiles[0].key_negotiation.is_none());
}

#[cfg(not(target_os = "windows"))]
mod start_connection {
    use super::*;
    use crate::{events::EventQueue, service::EnginePaths};
    use orion_core::backend::{dryrun::DryRunBackend, VpnBackend};

    fn paths_under(root: &Path) -> EnginePaths {
        EnginePaths {
            root: root.to_path_buf(),
            vault: root.join("vault"),
            config: root.join("config.toml"),
            identities: root.join("identities"),
            log: root.join("orion.log"),
            user_sid: None,
            user_process: None,
        }
    }

    fn classic_profile(name: &str) -> ClientProfile {
        let keypair = aether::wg::generate_keypair().expect("WireGuard keypair");
        ClientProfile {
            name: name.into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: keypair.private_key,
            peer_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            ..ClientProfile::default()
        }
    }

    async fn wait_for_up(receiver: &mut tokio::sync::mpsc::Receiver<ClientEvent>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(event) = receiver.recv().await {
                if matches!(
                    event,
                    ClientEvent::StateChanged {
                        state: TunnelState::Up
                    }
                ) {
                    return;
                }
            }
            panic!("event stream ended before Up");
        })
        .await
        .expect("dry-run connection reaches Up");
    }

    #[tokio::test]
    async fn an_explicit_profile_connects_without_changing_the_selection() {
        let scratch = Scratch::new("explicit-profile");
        let mut backend = DryRunBackend::default();
        backend.negotiate_delay = std::time::Duration::from_millis(1);
        let backend = Arc::new(backend);
        let service = EngineService::open(paths_under(scratch.path()), backend, None, "0.0.0-test")
            .expect("service opens");
        {
            let mut config = service.config.lock().await;
            config.profiles = vec![classic_profile("selected"), classic_profile("target")];
            config.selected = Some("selected".into());
        }
        let (events, mut receiver) = EventQueue::new();

        service
            .start_connection(&events, Some("target".into()))
            .await
            .expect("named profile starts");
        wait_for_up(&mut receiver).await;
        assert_eq!(
            service.controller.mounted_profile().await.as_deref(),
            Some("target")
        );
        service
            .stop_connection(events.sink())
            .await
            .expect("disconnect");

        assert_eq!(
            service.config.lock().await.selected.as_deref(),
            Some("selected"),
            "connecting an explicit profile does not rewrite the user's selection"
        );
        assert_eq!(service.controller.state(), TunnelState::Down);
    }

    #[tokio::test]
    async fn absent_or_unknown_profile_is_refused_before_starting_a_poll_or_adapter() {
        let scratch = Scratch::new("profile-not-found");
        let backend = Arc::new(DryRunBackend::default());
        let backend_observed = Arc::clone(&backend);
        let service = EngineService::open(paths_under(scratch.path()), backend, None, "0.0.0-test")
            .expect("service opens");
        let (events, _receiver) = EventQueue::new();

        assert_eq!(
            service
                .start_connection(&events, None)
                .await
                .err()
                .as_deref(),
            Some("aucun profil sélectionné")
        );
        {
            let mut config = service.config.lock().await;
            config.profiles.push(classic_profile("selected"));
            config.selected = Some("selected".into());
        }
        assert_eq!(
            service
                .start_connection(&events, Some("absent".into()))
                .await
                .err()
                .as_deref(),
            Some("aucun profil sélectionné")
        );
        assert!(service.handshake_poll.lock().unwrap().is_none());
        assert_eq!(service.controller.state(), TunnelState::Down);
        assert!(!backend_observed.adapter_is_up());
    }

    #[tokio::test]
    async fn failed_handshake_keeps_the_adapter_until_explicit_disconnect() {
        use orion_core::backend::{dryrun::DryRunBackend, VpnBackend};

        let scratch = Scratch::new("failed-handshake-mounted");
        let mut backend = DryRunBackend::failing();
        backend.negotiate_delay = std::time::Duration::ZERO;
        let backend = Arc::new(backend);
        let backend_for_service: Arc<dyn VpnBackend> = backend.clone();
        let service = EngineService::open(
            paths_under(scratch.path()),
            backend_for_service,
            None,
            "0.0.0-test",
        )
        .expect("service opens");
        {
            let mut config = service.config.lock().await;
            config.profiles.push(classic_profile("bureau"));
            config.selected = Some("bureau".into());
        }
        let (events, mut receiver) = EventQueue::new();

        service
            .start_connection(&events, None)
            .await
            .expect("the asynchronous connection attempt starts");

        let (states, error) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut states = Vec::new();
            while let Some(event) = receiver.recv().await {
                match event {
                    ClientEvent::StateChanged { state } => {
                        states.push(state);
                    }
                    ClientEvent::Error { message } => return (states, message),
                    _ => {}
                }
            }
            panic!("event stream ended before the connection error");
        })
        .await
        .expect("the dry-run handshake failure is reported");

        assert_eq!(
            states,
            vec![
                TunnelState::Connecting,
                TunnelState::Connecting,
                TunnelState::Failed
            ]
        );
        assert!(error.contains("échec de connexion"), "{error}");
        assert!(error.contains("handshake impossible"), "{error}");
        assert_eq!(service.controller.state(), TunnelState::Failed);
        assert!(service.controller.adapter_is_up());
        assert!(backend.adapter_is_up());

        service
            .stop_connection(events.sink())
            .await
            .expect("explicit disconnect removes the failed adapter");
        assert_eq!(service.controller.state(), TunnelState::Down);
        assert!(!service.controller.adapter_is_up());
        assert!(!backend.adapter_is_up());

        let down = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while let Some(event) = receiver.recv().await {
                if matches!(
                    event,
                    ClientEvent::StateChanged {
                        state: TunnelState::Down
                    }
                ) {
                    return;
                }
            }
            panic!("event stream ended before the Down state");
        })
        .await;
        assert!(down.is_ok(), "explicit disconnect reports Down");
    }

    #[tokio::test]
    async fn handshake_poll_moves_stale_tunnel_to_connecting_and_fresh_back_to_up() {
        use orion_core::backend::{dryrun::DryRunBackend, VpnBackend, HANDSHAKE_STALE_AFTER};

        let scratch = Scratch::new("handshake-poll-stale-fresh");
        let mut backend = DryRunBackend::default();
        backend.negotiate_delay = std::time::Duration::ZERO;
        let backend = Arc::new(backend);
        let backend_for_service: Arc<dyn VpnBackend> = backend.clone();
        let service = EngineService::open(
            paths_under(scratch.path()),
            backend_for_service,
            None,
            "0.0.0-test",
        )
        .expect("service opens");
        {
            let mut config = service.config.lock().await;
            config.profiles.push(classic_profile("bureau"));
            config.selected = Some("bureau".into());
        }
        let (events, mut receiver) = EventQueue::new();

        service
            .start_connection(&events, None)
            .await
            .expect("connection starts");
        wait_for_up(&mut receiver).await;
        assert!(service.controller.adapter_is_up());

        backend.set_handshake_age(Some(
            HANDSHAKE_STALE_AFTER + std::time::Duration::from_secs(1),
        ));
        service.controller.poll_handshake(events.sink()).await;
        assert_eq!(service.controller.state(), TunnelState::Connecting);
        assert!(service.controller.adapter_is_up());

        let warning = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while let Some(event) = receiver.recv().await {
                if let ClientEvent::Log { level, message } = event {
                    if level == "warn" && message.contains("aucun handshake WireGuard") {
                        return message;
                    }
                }
            }
            panic!("event stream ended before the stale-handshake warning");
        })
        .await
        .expect("stale handshake warning is emitted");
        assert!(warning.contains(&HANDSHAKE_STALE_AFTER.as_secs().to_string()));

        backend.set_handshake_age(Some(std::time::Duration::ZERO));
        service.controller.poll_handshake(events.sink()).await;
        assert_eq!(service.controller.state(), TunnelState::Up);
        assert!(service.controller.adapter_is_up());

        service
            .stop_connection(events.sink())
            .await
            .expect("test leaves no mounted adapter");
    }
}
