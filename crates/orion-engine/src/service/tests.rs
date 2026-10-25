// Off Windows only: there the real root provider would create a key in the
// platform keystore for every scratch directory.
#![cfg(not(target_os = "windows"))]

use super::*;
use crate::command::{EngineCommand, EngineReply};
use crate::serve::Engine;
use aether::TunnelState;
use orion_core::backend::dryrun::DryRunBackend;
use orion_core::{ClientEvent, ClientProfile};
use std::path::{Path, PathBuf};

/// A scratch directory removed when the test ends, whatever its outcome.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("orion-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn paths_under(root: &Path) -> EnginePaths {
    EnginePaths {
        root: root.to_path_buf(),
        vault: root.join("vault"),
        config: root.join("config.toml"),
        identities: root.join("identities"),
        log: root.join("orion.log"),
    }
}

#[test]
fn open_builds_the_service_on_the_given_paths() {
    let scratch = Scratch::new("open-builds");
    let paths = paths_under(&scratch.0);

    let service = EngineService::open(
        paths.clone(),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");

    assert!(service.log_path.is_none());
    assert!(service.store.device_root_path().starts_with(&paths.vault));
}

#[test]
fn open_keeps_running_on_a_vault_it_cannot_read() {
    let scratch = Scratch::new("open-vault");
    let paths = paths_under(&scratch.0);

    let service = EngineService::open(
        paths,
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("an unreadable vault does not stop the service");

    // Outside Windows the root provider refuses, so the vault cannot load: the
    // service keeps an empty configuration and records why.
    assert!(service.vault_error.is_some());
    let config = service
        .config
        .try_lock()
        .expect("nothing holds the configuration yet");
    assert!(config.profiles.is_empty());
}

#[tokio::test]
async fn the_engine_answers_get_state_through_the_client() {
    let scratch = Scratch::new("answers-state");
    let service = EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");
    let (client, _events) = crate::client::in_process(service)
        .await
        .expect("the session opens");

    match client.call(EngineCommand::GetState).await {
        Ok(EngineReply::State(state)) => {
            assert_eq!(state, TunnelState::Down.as_str());
        }
        other => panic!("unexpected reply: {other:?}"),
    }
}

#[tokio::test]
async fn a_command_not_yet_served_is_refused() {
    let scratch = Scratch::new("refuses-unserved");
    let service = EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");
    let (client, _events) = crate::client::in_process(service)
        .await
        .expect("the session opens");

    assert_eq!(
        client.call(EngineCommand::GetConfig).await.err().as_deref(),
        Some(NOT_SERVED)
    );
}

#[tokio::test]
async fn about_reports_the_injected_log_path() {
    let scratch = Scratch::new("about-log-path");
    let log = scratch.0.join("orion.log");
    let service = EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        Some(log.clone()),
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");
    let (client, _events) = crate::client::in_process(service)
        .await
        .expect("the session opens");

    match client.call(EngineCommand::AboutOrion).await {
        Ok(EngineReply::About(about)) => {
            assert_eq!(about.log_path, Some(log.display().to_string()));
            assert_eq!(about.version, "0.0.0-test");
        }
        other => panic!("unexpected reply: {other:?}"),
    }
}

#[tokio::test]
async fn teardown_is_idempotent_on_a_disconnected_engine() {
    let scratch = Scratch::new("teardown-twice");
    let service = EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");

    service.teardown().await;
    service.teardown().await;

    assert_eq!(service.controller.state(), TunnelState::Down);
}

/// A profile that mounts without key negotiation, so the controller needs
/// nothing beyond the backend.
fn plain_profile(name: &str) -> ClientProfile {
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: "cHJpdmF0ZQ==".into(),
        peer_public_key: "cHVibGlj".into(),
        ..ClientProfile::default()
    }
}

/// A service on a fresh directory, holding one selected plain profile.
fn service_with_selected_profile(scratch: &Scratch) -> Arc<EngineService> {
    let service = EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");
    {
        let mut config = service.config.try_lock().expect("nothing holds it yet");
        config.profiles.push(plain_profile("bureau"));
        config.selected = Some("bureau".into());
    }
    service
}

/// Collects the state changes the session pushes until the tunnel is `Up`.
///
/// The dry-run backend takes its negotiation delay before it reports `Up`, so
/// a connection is only complete once that state arrives.
async fn states_until_up(
    events: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
) -> Vec<TunnelState> {
    let mut states = Vec::new();
    let collected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            if let ClientEvent::StateChanged { state } = event {
                states.push(state);
                if state == TunnelState::Up {
                    break;
                }
            }
        }
    })
    .await;
    assert!(
        collected.is_ok(),
        "the tunnel never reported Up: {states:?}"
    );
    states
}

#[tokio::test]
async fn a_connection_through_the_client_reports_its_states() {
    let scratch = Scratch::new("connect-states");
    let service = service_with_selected_profile(&scratch);
    let (client, mut events) = crate::client::in_process(Arc::clone(&service))
        .await
        .expect("the session opens");

    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");

    let states = states_until_up(&mut events).await;
    assert_eq!(
        states,
        vec![
            TunnelState::Connecting,
            TunnelState::Connecting,
            TunnelState::Up
        ]
    );
}

#[tokio::test]
async fn disconnect_brings_the_tunnel_down() {
    let scratch = Scratch::new("disconnect-down");
    let service = service_with_selected_profile(&scratch);
    let (client, mut events) = crate::client::in_process(Arc::clone(&service))
        .await
        .expect("the session opens");
    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the connection starts");
    states_until_up(&mut events).await;

    let reply = client.call(EngineCommand::Disconnect).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");

    assert_eq!(service.controller.state(), TunnelState::Down);
    assert!(!service.controller.adapter_is_up());
}

#[tokio::test]
async fn shutdown_tears_the_tunnel_down() {
    let scratch = Scratch::new("shutdown-down");
    let service = service_with_selected_profile(&scratch);
    let (client, mut events) = crate::client::in_process(Arc::clone(&service))
        .await
        .expect("the session opens");
    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the connection starts");
    states_until_up(&mut events).await;

    let reply = client.call(EngineCommand::Shutdown).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");
    tokio::time::timeout(std::time::Duration::from_secs(10), client.closed())
        .await
        .expect("the session ends after the shutdown");

    assert!(!service.controller.adapter_is_up());
}

#[tokio::test]
async fn renew_psk_without_a_tunnel_is_refused() {
    let scratch = Scratch::new("renew-refused");
    let service = service_with_selected_profile(&scratch);
    let (client, _events) = crate::client::in_process(service)
        .await
        .expect("the session opens");

    assert_eq!(
        client.call(EngineCommand::RenewPsk).await.err().as_deref(),
        Some("aucun tunnel ML-KEM monté : rien à renouveler")
    );
}
