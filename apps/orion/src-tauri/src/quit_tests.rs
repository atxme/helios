use std::{path::PathBuf, sync::Arc, time::Duration};

use orion_core::{backend::dryrun::DryRunBackend, protected_root::EnginePaths};
use orion_engine::{client::in_process, service::EngineService, EngineCommand, EngineReply};

use super::{first_teardown, take_tunnel_down_blocking};

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

/// An engine on a fresh directory.
///
/// Off Windows no profile can be saved: the platform has no root key to seal
/// one with, so the session starts with nothing to connect. The connected
/// shutdown is covered inside the engine crate, where the tunnel can be set up.
fn engine_on(scratch: &Scratch) -> Arc<EngineService> {
    let root = &scratch.0;
    let paths = EnginePaths {
        root: root.clone(),
        vault: root.join("vault"),
        config: root.join("config.toml"),
        identities: root.join("identities"),
        log: root.join("orion.log"),
        user_sid: None,
        user_process: None,
    };
    EngineService::open(
        paths,
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
        Arc::new(orion_core::vault::UnavailablePassphraseSource),
    )
    .expect("the service opens on a fresh directory")
}

/// A plain test, not a `tokio::test`: the quit path runs on a thread with no
/// runtime entered, which is exactly the situation the deadline must survive.
#[test]
fn quitting_takes_the_engine_down_before_the_deadline() {
    let scratch = Scratch::new("takes-down");
    let service = engine_on(&scratch);
    let (client, _events) =
        tauri::async_runtime::block_on(in_process(Arc::clone(&service))).expect("session opens");

    let started = std::time::Instant::now();
    take_tunnel_down_blocking(&client, Duration::from_secs(10));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the shutdown waited for the whole deadline"
    );

    // The first session ends with its shutdown. A second one on the same engine
    // reads the adapter the engine still holds.
    let (observer, _events) =
        tauri::async_runtime::block_on(in_process(service)).expect("a second session opens");
    let adapter = tauri::async_runtime::block_on(observer.call(EngineCommand::AdapterIsUp));
    assert!(
        matches!(adapter, Ok(EngineReply::Flag(false))),
        "the adapter is still up: {adapter:?}"
    );
}

/// Only the first quit takes the tunnel down. The `Exit` that follows
/// `ExitRequested` must not send a second `Shutdown` and wait again.
#[test]
fn a_second_quit_does_not_wait_again() {
    let taken_down = std::sync::atomic::AtomicBool::new(false);
    assert!(first_teardown(&taken_down));
    assert!(!first_teardown(&taken_down));
    assert!(!first_teardown(&taken_down));
}

#[test]
fn shutdown_waits_for_the_session_to_close_even_when_the_engine_refuses_the_command() {
    use crate::commands::test_support::scripted_engine;

    let (client, mut engine) = tauri::async_runtime::block_on(scripted_engine());
    let (received, ready) = std::sync::mpsc::channel();
    let (close, release) = tokio::sync::oneshot::channel();
    let server = tauri::async_runtime::spawn(async move {
        engine
            .reply(|request| {
                assert!(matches!(request, EngineCommand::Shutdown));
                Err("fixture refusal".into())
            })
            .await;
        received.send(()).unwrap();
        release.await.expect("test releases the engine");
        drop(engine);
    });

    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            take_tunnel_down_blocking(&client, Duration::from_secs(5));
            done.send(()).unwrap();
        });
        ready
            .recv_timeout(Duration::from_secs(3))
            .expect("Shutdown reaches engine");
        let premature = finished.recv_timeout(Duration::from_millis(100));
        close.send(()).unwrap();
        assert!(matches!(
            premature,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        finished
            .recv_timeout(Duration::from_secs(3))
            .expect("quit completes after closure");
    });
    tauri::async_runtime::block_on(server).expect("scripted engine task completed");
    assert!(client.is_closed());
}

#[test]
fn shutdown_returns_at_the_grace_deadline_when_the_engine_keeps_its_session_open() {
    use crate::commands::test_support::scripted_engine;

    let (client, mut engine) = tauri::async_runtime::block_on(scripted_engine());
    let (close, release) = tokio::sync::oneshot::channel();
    let server = tauri::async_runtime::spawn(async move {
        engine
            .reply(|request| {
                assert!(matches!(request, EngineCommand::Shutdown));
                Ok(EngineReply::Unit)
            })
            .await;
        release
            .await
            .expect("test closes the engine after the grace bounds the wait");
        drop(engine);
    });

    let grace = Duration::from_millis(300);
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            let started = std::time::Instant::now();
            take_tunnel_down_blocking(&client, grace);
            done.send(started.elapsed()).unwrap();
        });
        let elapsed = finished.recv_timeout(Duration::from_secs(3));
        let was_open = !client.is_closed();
        close.send(()).unwrap();
        assert!(elapsed.expect("the grace period bounds shutdown") >= grace);
        assert!(
            was_open,
            "the fixture engine is still connected at the deadline"
        );
    });
    tauri::async_runtime::block_on(server).expect("Shutdown reached the scripted engine");
}

#[test]
fn an_already_closed_session_needs_no_grace_period() {
    use crate::commands::test_support::scripted_engine;

    let (client, engine) = tauri::async_runtime::block_on(scripted_engine());
    drop(engine);
    tauri::async_runtime::block_on(async {
        tokio::time::timeout(Duration::from_secs(3), client.closed())
            .await
            .expect("engine closure observed");
        // A second block_on here would panic: the closed fast path must return directly.
        take_tunnel_down_blocking(&client, Duration::from_secs(5));
    });
    assert!(client.is_closed());
}
