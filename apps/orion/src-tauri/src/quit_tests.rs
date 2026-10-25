//! The quit path: the deadline that takes a connected tunnel down before Orion
//! exits. Off Windows only: opening the engine there would reach the platform
//! keystore.

use std::{path::PathBuf, sync::Arc, time::Duration};

use aether::TunnelState;
use orion_core::{
    backend::dryrun::DryRunBackend, protected_root::EnginePaths, ClientEvent, ClientProfile,
};
use orion_engine::{client::in_process, service::EngineService, EngineCommand, EngineReply};

use super::take_tunnel_down_blocking;

/// A scratch directory removed when the test ends, whatever its outcome.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("orion-quit-{name}-{}", std::process::id()));
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

/// An engine on a fresh directory, holding one selected profile that mounts
/// without key negotiation.
fn engine_with_selected_profile(scratch: &Scratch) -> Arc<EngineService> {
    let root = &scratch.0;
    let paths = EnginePaths {
        root: root.clone(),
        vault: root.join("vault"),
        config: root.join("config.toml"),
        identities: root.join("identities"),
        log: root.join("orion.log"),
    };
    let service = EngineService::open(
        paths,
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("the service opens on a fresh directory");
    {
        let mut config = service.config.try_lock().expect("nothing holds it yet");
        config.profiles.push(ClientProfile {
            name: "bureau".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            ..ClientProfile::default()
        });
        config.selected = Some("bureau".into());
    }
    service
}

/// A plain test, not a `tokio::test`: the quit path runs on a thread with no
/// runtime entered, which is exactly the situation the deadline must survive.
#[test]
fn quitting_takes_a_connected_tunnel_down() {
    let scratch = Scratch::new("takes-down");
    let service = engine_with_selected_profile(&scratch);
    let (client, mut events) =
        tauri::async_runtime::block_on(in_process(Arc::clone(&service))).expect("session opens");

    tauri::async_runtime::block_on(async {
        let reply = client.call(EngineCommand::Connect { name: None }).await;
        assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");
        let up = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                if matches!(
                    event,
                    ClientEvent::StateChanged {
                        state: TunnelState::Up
                    }
                ) {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(up, Ok(true), "the tunnel never reported Up");
    });

    take_tunnel_down_blocking(&client, Duration::from_secs(10));

    assert!(!service.controller.adapter_is_up());
}
