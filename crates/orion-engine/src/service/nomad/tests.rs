// Off Windows only, like the other service tests: the nomad flows run on a
// scratch vault with a fixed test root, and the passphrase comes from a script.
#![cfg(not(target_os = "windows"))]

use super::*;
use crate::client::EngineClient;
use crate::command::{EngineCommand, EngineReply, ProfileDraft};
use crate::events::EventQueue;
use crate::service::LockEvent;
use crate::wire::{EngineFrame, PROTOCOL_VERSION};
use aether::TunnelState;
use orion_core::backend::dryrun::DryRunBackend;
use orion_core::vault::{
    registry::ProfileMode, DeviceRootKey, PassphraseSource, ProfileStore, RootKeyProvider,
    UnavailablePassphraseSource, VaultError, KEY_LEN,
};
use orion_core::{ClientEvent, ClientProfile};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Mutex as StdMutex, Weak};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "cheval agile traverse la prairie";
const NEW_PASSPHRASE: &str = "le port de Brest sous la pluie";

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "orion-nomad-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
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
            [0x3c; KEY_LEN],
        )))
    }

    fn hardware_backed(&self) -> bool {
        false
    }
}

/// One scripted answer: a passphrase, or a cancelled prompt.
enum Answer {
    Give(&'static str),
    Cancel,
}

/// Answers from a queue, and records the purpose of every prompt.
struct Scripted {
    answers: StdMutex<VecDeque<Answer>>,
    purposes: StdMutex<Vec<PromptPurpose>>,
    native: bool,
}

impl Scripted {
    fn new(answers: Vec<Answer>, native: bool) -> Arc<Self> {
        Arc::new(Self {
            answers: StdMutex::new(answers.into()),
            purposes: StdMutex::new(Vec::new()),
            native,
        })
    }

    fn purposes(&self) -> Vec<PromptPurpose> {
        self.purposes.lock().expect("purposes").clone()
    }
}

impl PassphraseSource for Scripted {
    fn ask(
        &self,
        _profile: &str,
        purpose: &PromptPurpose,
    ) -> Result<Zeroizing<String>, VaultError> {
        self.purposes
            .lock()
            .expect("purposes")
            .push(purpose.clone());
        match self.answers.lock().expect("answers").pop_front() {
            Some(Answer::Give(value)) => Ok(Zeroizing::new(value.to_string())),
            Some(Answer::Cancel) | None => Err(VaultError::PassphraseCancelled),
        }
    }

    fn is_native_dialog(&self) -> bool {
        self.native
    }
}

fn store_at(dir: &Path) -> Arc<ProfileStore> {
    let store =
        ProfileStore::new(dir.join("vault"), Box::new(TestRoot)).allowing_unencrypted_volume(true);
    store.set_lock_watch(true);
    Arc::new(store)
}

fn profile(name: &str) -> ClientProfile {
    let pair = aether::wg::generate_keypair().expect("WireGuard keypair");
    let gateway = aether::wg::generate_keypair().expect("WireGuard keypair");
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: pair.private_key,
        peer_public_key: gateway.public_key,
        ..ClientProfile::default()
    }
}

/// A `nomade` profile sealed under `PASSPHRASE`, left for the next store to open.
fn seed_nomad(dir: &Path, name: &str) {
    store_at(dir)
        .save_new_nomad_profile(&profile(name), PASSPHRASE)
        .expect("a nomad profile is sealed");
}

/// A service on the store, with the source the test scripted.
fn service_on(dir: &Path, source: Arc<Scripted>) -> Arc<EngineService> {
    EngineService::on_store(
        store_at(dir),
        Arc::new(DryRunBackend::default()),
        dir.join("identities"),
        source,
    )
}

async fn client_of(
    service: Arc<EngineService>,
) -> (EngineClient, tokio::sync::mpsc::Receiver<ClientEvent>) {
    crate::client::in_process(service)
        .await
        .expect("the session opens")
}

fn assert_refused(reply: Result<EngineReply, String>, expected: &str) {
    match reply {
        Err(error) => assert_eq!(error, expected),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn config_of(reply: Result<EngineReply, String>) -> ConfigView {
    match reply {
        Ok(EngineReply::Config(view)) => view,
        other => panic!("unexpected reply: {other:?}"),
    }
}

fn mode_in(view: &ConfigView, name: &str) -> String {
    view.profiles
        .iter()
        .find(|profile| profile.name == name)
        .unwrap_or_else(|| panic!("{name} is listed"))
        .mode
        .clone()
}

/// Collects the state changes the session pushes until the tunnel is `Up`.
async fn states_until_up(events: &mut tokio::sync::mpsc::Receiver<ClientEvent>) {
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            if let ClientEvent::StateChanged { state } = event {
                if state == TunnelState::Up {
                    return;
                }
            }
        }
    })
    .await;
    assert!(reached.is_ok(), "the tunnel never reported Up");
}

#[tokio::test]
async fn connect_on_a_locked_profile_asks_once_then_connects() {
    let scratch = Scratch::new("connect-once");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, mut events) = client_of(service).await;

    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");
    states_until_up(&mut events).await;

    assert_eq!(source.purposes(), vec![PromptPurpose::Unlock]);
}

#[tokio::test]
async fn a_second_connect_in_the_session_does_not_ask() {
    let scratch = Scratch::new("connect-twice");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, mut events) = client_of(service).await;

    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the first connection starts");
    states_until_up(&mut events).await;
    client
        .call(EngineCommand::Disconnect)
        .await
        .expect("the tunnel comes down");
    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");

    assert_eq!(source.purposes(), vec![PromptPurpose::Unlock]);
}

#[tokio::test]
async fn cancel_leaves_the_profile_locked_and_says_so() {
    let scratch = Scratch::new("cancel");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Cancel], false);
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert_refused(reply, "Saisie annulée.");
    assert!(!service.store.is_unlocked("poste"));
    assert_eq!(source.purposes(), vec![PromptPurpose::Unlock]);
}

#[tokio::test]
async fn make_nomad_asks_new_then_confirm() {
    let scratch = Scratch::new("make-nomad");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let source = Scripted::new(
        vec![Answer::Give(PASSPHRASE), Answer::Give(PASSPHRASE)],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let view = config_of(
        client
            .call(EngineCommand::MakeNomad {
                name: "bureau".into(),
            })
            .await,
    );

    assert_eq!(mode_in(&view, "bureau"), "nomade");
    assert_eq!(
        source.purposes(),
        vec![PromptPurpose::New, PromptPurpose::Confirm]
    );
    assert!(service.store.is_unlocked("bureau"));
}

#[tokio::test]
async fn a_mismatch_changes_nothing() {
    let scratch = Scratch::new("mismatch");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let source = Scripted::new(
        vec![Answer::Give(PASSPHRASE), Answer::Give(NEW_PASSPHRASE)],
        false,
    );
    let service = service_on(scratch.path(), source);
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::MakeNomad {
            name: "bureau".into(),
        })
        .await;

    assert_refused(reply, "Les deux saisies diffèrent.");
    assert!(matches!(
        store_at(scratch.path()).mode_of("bureau"),
        Ok(Some(ProfileMode::Service))
    ));
}

#[tokio::test]
async fn a_refused_passphrase_is_asked_again_with_its_reason() {
    let scratch = Scratch::new("refused");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let source = Scripted::new(
        vec![
            Answer::Give("password"),
            Answer::Give(PASSPHRASE),
            Answer::Give(PASSPHRASE),
        ],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(service).await;

    let view = config_of(
        client
            .call(EngineCommand::MakeNomad {
                name: "bureau".into(),
            })
            .await,
    );

    assert_eq!(mode_in(&view, "bureau"), "nomade");
    let purposes = source.purposes();
    assert_eq!(purposes.len(), 3, "purposes: {purposes:?}");
    assert_eq!(purposes[0], PromptPurpose::New);
    assert!(
        matches!(&purposes[1], PromptPurpose::Retry(reason) if reason.contains("trop courante")),
        "purposes: {purposes:?}"
    );
    assert_eq!(purposes[2], PromptPurpose::Confirm);
}

#[tokio::test]
async fn change_passphrase_on_a_locked_profile_asks_current_first() {
    let scratch = Scratch::new("change");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(
        vec![
            Answer::Give(PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
        ],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let view = config_of(
        client
            .call(EngineCommand::ChangePassphrase {
                name: "poste".into(),
            })
            .await,
    );

    assert_eq!(mode_in(&view, "poste"), "nomade");
    assert_eq!(
        source.purposes(),
        vec![
            PromptPurpose::Current,
            PromptPurpose::New,
            PromptPurpose::Confirm
        ]
    );
    // The new passphrase is the one that opens the profile from now on.
    let reopened = store_at(scratch.path());
    reopened
        .unlock("poste", NEW_PASSPHRASE)
        .expect("the new passphrase opens the profile");
}

#[tokio::test]
async fn make_service_on_a_locked_profile_asks_current() {
    let scratch = Scratch::new("make-service");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let view = config_of(
        client
            .call(EngineCommand::MakeService {
                name: "poste".into(),
            })
            .await,
    );

    assert_eq!(mode_in(&view, "poste"), "service");
    assert_eq!(source.purposes(), vec![PromptPurpose::Current]);
    assert!(matches!(
        store_at(scratch.path()).mode_of("poste"),
        Ok(Some(ProfileMode::Service))
    ));
}

#[tokio::test]
async fn save_a_new_profile_as_nomad() {
    let scratch = Scratch::new("save-nomad");
    let source = Scripted::new(
        vec![Answer::Give(PASSPHRASE), Answer::Give(PASSPHRASE)],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;
    let public_key = match client.call(EngineCommand::GeneratePrivateKey).await {
        Ok(EngineReply::PublicKey(public_key)) => public_key,
        other => panic!("unexpected reply: {other:?}"),
    };
    let draft: ProfileDraft = serde_json::from_value(serde_json::json!({
        "name": "poste",
        "endpoint": "203.0.113.10:51820",
        "peer_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25,
        "useStagedKey": true,
        "nomad": true,
    }))
    .expect("a draft deserialises");

    let view = config_of(client.call(EngineCommand::SaveProfile { draft }).await);

    assert_eq!(mode_in(&view, "poste"), "nomade");
    assert!(!public_key.is_empty());
    assert_eq!(
        source.purposes(),
        vec![PromptPurpose::New, PromptPurpose::Confirm]
    );
    assert!(matches!(
        store_at(scratch.path()).mode_of("poste"),
        Ok(Some(ProfileMode::Nomad { .. }))
    ));
}

#[tokio::test]
async fn the_posture_offers_nomad_only_through_a_native_dialog() {
    let scratch = Scratch::new("posture");
    let refusing = service_on(scratch.path(), Scripted::new(Vec::new(), false));
    let posture = refusing.vault_posture().expect("the posture reads");
    assert!(!posture.nomad_available);
    assert!(posture.lock_watch_active);

    let native_dir = Scratch::new("posture-native");
    let native = EngineService::on_store(
        store_at(native_dir.path()),
        Arc::new(DryRunBackend::default()),
        native_dir.path().join("identities"),
        Scripted::new(Vec::new(), true),
    );
    assert!(
        native
            .vault_posture()
            .expect("the posture reads")
            .nomad_available
    );
}

#[tokio::test]
async fn the_unavailable_source_refuses_a_locked_connection() {
    let scratch = Scratch::new("unavailable");
    seed_nomad(scratch.path(), "poste");
    let service = EngineService::on_store(
        store_at(scratch.path()),
        Arc::new(DryRunBackend::default()),
        scratch.path().join("identities"),
        Arc::new(UnavailablePassphraseSource),
    );
    let (client, _events) = client_of(service).await;

    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert_refused(reply, &VaultError::NoNativePrompt.to_string());
}

/// Walks a serialised value: no key names a passphrase, and no string is the
/// scripted one.
fn assert_no_passphrase(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                assert!(
                    !key.to_lowercase().contains("passphrase"),
                    "key `{key}` names a passphrase"
                );
                assert_no_passphrase(inner);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(assert_no_passphrase),
        serde_json::Value::String(text) => {
            assert_ne!(text, PASSPHRASE, "a passphrase travelled as a value");
            assert_ne!(text, NEW_PASSPHRASE, "a passphrase travelled as a value");
        }
        _ => {}
    }
}

#[tokio::test]
async fn no_frame_carries_a_passphrase() {
    let scratch = Scratch::new("no-frame");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(
        vec![
            Answer::Give(PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
        ],
        false,
    );
    let service = service_on(scratch.path(), source);
    let (client, _events) = client_of(service).await;
    // Unlocked by the gesture itself, so the view below is a nomad profile
    // listed with its keys, not a locked one.
    config_of(
        client
            .call(EngineCommand::ChangePassphrase {
                name: "poste".into(),
            })
            .await,
    );

    let commands = [
        EngineCommand::MakeNomad {
            name: "poste".into(),
        },
        EngineCommand::ChangePassphrase {
            name: "poste".into(),
        },
        EngineCommand::MakeService {
            name: "poste".into(),
        },
    ];
    for command in &commands {
        let json = serde_json::to_value(command).expect("a command serialises");
        assert_no_passphrase(&json);
    }

    let view = config_of(client.call(EngineCommand::GetConfig).await);
    assert_eq!(mode_in(&view, "poste"), "nomade");
    let frame = EngineFrame::Reply {
        id: 1,
        result: Ok(Box::new(EngineReply::Config(view))),
    };
    let json = serde_json::to_value(&frame).expect("a frame serialises");
    assert_no_passphrase(&json);
}

#[test]
fn the_protocol_version_is_3() {
    assert_eq!(PROTOCOL_VERSION, 3);
}

// # Lock state machine

/// A source that locks the session from inside the dialog, as a session lock
/// landing while the native prompt is open would. The lock runs on the
/// blocking thread the prompt is asked on, through the runtime's handle.
struct LockingSource {
    service: StdMutex<Weak<EngineService>>,
    events: EventQueue,
    runtime: tokio::runtime::Handle,
}

impl PassphraseSource for LockingSource {
    fn ask(
        &self,
        _profile: &str,
        _purpose: &PromptPurpose,
    ) -> Result<Zeroizing<String>, VaultError> {
        let service = self
            .service
            .lock()
            .expect("service slot")
            .upgrade()
            .expect("the service outlives the prompt");
        self.runtime
            .block_on(service.on_lock_event(LockEvent::SessionLock, &self.events));
        Ok(Zeroizing::new(PASSPHRASE.to_string()))
    }

    fn is_native_dialog(&self) -> bool {
        true
    }
}

/// The nomad profile `name` is listed as locked, and no longer among the
/// profiles the engine can connect.
async fn assert_locked_and_unusable(service: &EngineService, name: &str) {
    let config = service.config.lock().await;
    assert!(
        config.locked.iter().any(|locked| locked.name == name),
        "{name} is listed as locked"
    );
    assert!(
        config.profiles.iter().all(|profile| profile.name != name),
        "{name} is no longer usable"
    );
}

#[tokio::test]
async fn each_event_closes_a_nomad_tunnel_and_locks() {
    let events = [
        LockEvent::SessionLock,
        LockEvent::SessionLogoff,
        LockEvent::SessionDisconnect,
        LockEvent::Suspend,
        LockEvent::EngineExit,
    ];
    for event in events {
        let scratch = Scratch::new(&format!("lock-{event:?}"));
        seed_nomad(scratch.path(), "poste");
        let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
        let service = service_on(scratch.path(), source);
        let (client, mut session) = client_of(Arc::clone(&service)).await;
        client
            .call(EngineCommand::Connect { name: None })
            .await
            .expect("the tunnel starts");
        states_until_up(&mut session).await;

        let (queue, _receiver) = EventQueue::new();
        service.on_lock_event(event, &queue).await;

        assert_eq!(service.controller.state(), TunnelState::Down, "{event:?}");
        assert!(
            service.controller.mounted_profile().await.is_none(),
            "{event:?}"
        );
        assert!(!service.store.is_unlocked("poste"), "{event:?}");
        assert_locked_and_unusable(&service, "poste").await;
    }
}

/// Collects what the session pushes until the profiles are reported moved.
async fn events_until_config_changed(
    events: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
) -> Vec<ClientEvent> {
    let mut seen = Vec::new();
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let done = matches!(event, ClientEvent::ConfigChanged);
            seen.push(event);
            if done {
                return;
            }
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "no config change reached the window: {seen:?}"
    );
    seen
}

#[tokio::test]
async fn a_lock_reaches_the_window_through_the_session() {
    let scratch = Scratch::new("lock-reaches-window");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), source);
    let (client, mut session) = client_of(Arc::clone(&service)).await;
    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the tunnel starts");
    states_until_up(&mut session).await;

    // The fallback is a queue nobody reads: only a session queue can deliver.
    let (fallback, _unread) = EventQueue::new();
    service
        .on_lock_event(LockEvent::SessionLock, &fallback)
        .await;

    let seen = events_until_config_changed(&mut session).await;
    assert!(
        seen.iter().any(|event| matches!(
            event,
            ClientEvent::StateChanged {
                state: TunnelState::Down
            }
        )),
        "the window is told the tunnel is down: {seen:?}"
    );
    let json = serde_json::to_string(&seen).expect("events serialise");
    assert!(
        !json.contains(PASSPHRASE),
        "no secret travels with the event"
    );
}

#[tokio::test]
async fn a_lock_without_a_session_falls_back_to_the_given_queue() {
    let scratch = Scratch::new("lock-fallback");
    seed_nomad(scratch.path(), "poste");
    let service = service_on(scratch.path(), Scripted::new(Vec::new(), false));

    let (fallback, mut raised) = EventQueue::new();
    service
        .on_lock_event(LockEvent::SessionLock, &fallback)
        .await;

    assert!(matches!(
        raised.recv().await,
        Some(ClientEvent::ConfigChanged)
    ));
}

#[tokio::test]
async fn a_locked_profile_can_be_selected_and_then_connected() {
    let scratch = Scratch::new("select-locked");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, mut session) = client_of(Arc::clone(&service)).await;

    let view = config_of(
        client
            .call(EngineCommand::SelectProfile {
                name: "poste".into(),
            })
            .await,
    );
    assert_eq!(view.selected.as_deref(), Some("poste"));
    assert!(view.locked.iter().any(|locked| locked.name == "poste"));

    // The connection without a name follows the selection, and opens it.
    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the locked profile connects");
    states_until_up(&mut session).await;
    assert_eq!(source.purposes(), vec![PromptPurpose::Unlock]);
    assert_eq!(
        service.controller.mounted_profile().await.as_deref(),
        Some("poste")
    );
}

#[tokio::test]
async fn a_service_tunnel_survives_a_lock() {
    let scratch = Scratch::new("lock-service");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let service = service_on(scratch.path(), Scripted::new(Vec::new(), false));
    let (client, mut session) = client_of(Arc::clone(&service)).await;
    client
        .call(EngineCommand::Connect {
            name: Some("bureau".into()),
        })
        .await
        .expect("the tunnel starts");
    states_until_up(&mut session).await;

    let (queue, _receiver) = EventQueue::new();
    service.on_lock_event(LockEvent::SessionLock, &queue).await;

    assert_eq!(service.controller.state(), TunnelState::Up);
    assert_eq!(
        service.controller.mounted_profile().await.as_deref(),
        Some("bureau")
    );
    let config = service.config.lock().await;
    assert!(config
        .profiles
        .iter()
        .any(|profile| profile.name == "bureau"));
    assert!(config.locked.is_empty());
}

#[tokio::test]
async fn after_a_lock_connect_asks_again() {
    let scratch = Scratch::new("lock-asks-again");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(
        vec![Answer::Give(PASSPHRASE), Answer::Give(PASSPHRASE)],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, mut session) = client_of(Arc::clone(&service)).await;
    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("the first connection starts");
    states_until_up(&mut session).await;

    let (queue, _receiver) = EventQueue::new();
    service.on_lock_event(LockEvent::SessionLock, &queue).await;
    let reply = client.call(EngineCommand::Connect { name: None }).await;
    assert!(matches!(reply, Ok(EngineReply::Unit)), "reply: {reply:?}");
    states_until_up(&mut session).await;

    assert_eq!(
        source.purposes(),
        vec![PromptPurpose::Unlock, PromptPurpose::Unlock]
    );
}

/// A service whose passphrase source locks the session from inside every prompt.
fn locking_service(dir: &Path) -> (Arc<EngineService>, Arc<LockingSource>) {
    let (events, _receiver) = EventQueue::new();
    let source = Arc::new(LockingSource {
        service: StdMutex::new(Weak::new()),
        events,
        runtime: tokio::runtime::Handle::current(),
    });
    let service = EngineService::on_store(
        store_at(dir),
        Arc::new(DryRunBackend::default()),
        dir.join("identities"),
        Arc::clone(&source) as Arc<dyn PassphraseSource>,
    );
    *source.service.lock().expect("service slot") = Arc::downgrade(&service);
    (service, source)
}

#[tokio::test]
async fn a_lock_while_the_dialog_is_open_wins() {
    let scratch = Scratch::new("lock-in-dialog");
    seed_nomad(scratch.path(), "poste");
    let (service, _source) = locking_service(scratch.path());
    let (client, _session) = client_of(Arc::clone(&service)).await;

    let reply = client.call(EngineCommand::Connect { name: None }).await;

    assert_refused(
        reply,
        &VaultError::ProfileLocked("poste".into()).to_string(),
    );
    assert!(!service.store.is_unlocked("poste"));
    assert_locked_and_unusable(&service, "poste").await;
}

#[tokio::test]
async fn a_lock_during_make_nomad_leaves_the_profile_locked() {
    let scratch = Scratch::new("lock-make-nomad");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let (service, _source) = locking_service(scratch.path());
    let (client, _session) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::MakeNomad {
            name: "bureau".into(),
        })
        .await;

    assert_refused(
        reply,
        &VaultError::ProfileLocked("bureau".into()).to_string(),
    );
    assert!(!service.store.is_unlocked("bureau"));
    assert_locked_and_unusable(&service, "bureau").await;
    // The seal itself was written: the profile is nomad, and locked.
    assert!(matches!(
        store_at(scratch.path()).mode_of("bureau"),
        Ok(Some(ProfileMode::Nomad { .. }))
    ));
}

#[tokio::test]
async fn a_lock_during_save_new_nomad_leaves_the_profile_locked() {
    let scratch = Scratch::new("lock-save-nomad");
    let (service, _source) = locking_service(scratch.path());
    let (client, _session) = client_of(Arc::clone(&service)).await;
    client
        .call(EngineCommand::GeneratePrivateKey)
        .await
        .expect("a key is generated");
    let draft: ProfileDraft = serde_json::from_value(serde_json::json!({
        "name": "poste",
        "endpoint": "203.0.113.10:51820",
        "peer_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25,
        "useStagedKey": true,
        "nomad": true,
    }))
    .expect("a draft deserialises");

    let reply = client.call(EngineCommand::SaveProfile { draft }).await;

    assert_refused(
        reply,
        &VaultError::ProfileLocked("poste".into()).to_string(),
    );
    assert!(!service.store.is_unlocked("poste"));
    assert_locked_and_unusable(&service, "poste").await;
    assert!(matches!(
        store_at(scratch.path()).mode_of("poste"),
        Ok(Some(ProfileMode::Nomad { .. }))
    ));
}

// # Final review fixes

/// A lock that lands after the unlock and before the controller mounts the
/// tunnel finds nothing mounted to take down. The mount must still not stand.
#[tokio::test]
async fn a_lock_between_the_unlock_and_the_mount_leaves_no_tunnel() {
    let scratch = Scratch::new("lock-before-mount");
    seed_nomad(scratch.path(), "poste");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = service_on(scratch.path(), source);
    let weak = Arc::downgrade(&service);
    *service.before_mount.lock().expect("hook slot") = Some(Box::new(move || {
        // What `on_lock_event` does first: the generation moves, and the keys
        // are forgotten. Nothing is mounted yet, so it has no tunnel to drop.
        let service = weak.upgrade().expect("the service is alive");
        service.lock_generation.fetch_add(1, AtomicOrdering::AcqRel);
        service.store.forget_unlocked();
    }));
    let (client, _session) = client_of(Arc::clone(&service)).await;

    let reply = client.call(EngineCommand::Connect { name: None }).await;

    assert_refused(
        reply,
        &VaultError::ProfileLocked("poste".into()).to_string(),
    );
    assert_eq!(service.controller.state(), TunnelState::Down);
    assert!(service.controller.mounted_profile().await.is_none());
    assert!(!service.store.is_unlocked("poste"));
    assert_locked_and_unusable(&service, "poste").await;
}

/// The same lock does not touch a `service` tunnel.
#[tokio::test]
async fn a_lock_before_the_mount_spares_a_service_profile() {
    let scratch = Scratch::new("lock-before-mount-service");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let service = service_on(scratch.path(), Scripted::new(Vec::new(), false));
    let weak = Arc::downgrade(&service);
    *service.before_mount.lock().expect("hook slot") = Some(Box::new(move || {
        let service = weak.upgrade().expect("the service is alive");
        service.lock_generation.fetch_add(1, AtomicOrdering::AcqRel);
    }));
    let (client, mut session) = client_of(Arc::clone(&service)).await;

    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("a service tunnel is not locked");
    states_until_up(&mut session).await;
}

/// The profile is unlocked in this session: the gestures still ask, and check.
fn unlocked_service(scratch: &Scratch, source: Arc<Scripted>) -> Arc<EngineService> {
    seed_nomad(scratch.path(), "poste");
    let service = service_on(scratch.path(), source);
    service
        .store
        .unlock("poste", PASSPHRASE)
        .expect("the profile opens");
    assert!(service.store.is_unlocked("poste"));
    service
}

#[tokio::test]
async fn change_passphrase_asks_current_even_when_the_profile_is_unlocked() {
    let scratch = Scratch::new("change-unlocked");
    let source = Scripted::new(
        vec![
            Answer::Give(PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
            Answer::Give(NEW_PASSPHRASE),
        ],
        false,
    );
    let service = unlocked_service(&scratch, Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    config_of(
        client
            .call(EngineCommand::ChangePassphrase {
                name: "poste".into(),
            })
            .await,
    );

    assert_eq!(
        source.purposes(),
        vec![
            PromptPurpose::Current,
            PromptPurpose::New,
            PromptPurpose::Confirm
        ]
    );
}

#[tokio::test]
async fn a_wrong_current_passphrase_stops_change_passphrase_on_an_unlocked_profile() {
    let scratch = Scratch::new("change-wrong");
    let source = Scripted::new(vec![Answer::Give(NEW_PASSPHRASE)], false);
    let service = unlocked_service(&scratch, Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::ChangePassphrase {
            name: "poste".into(),
        })
        .await;

    assert_refused(reply, &VaultError::WrongPassphrase.to_string());
    // Only the check was asked: no new passphrase, and the old one still opens.
    assert_eq!(source.purposes(), vec![PromptPurpose::Current]);
    store_at(scratch.path())
        .unlock("poste", PASSPHRASE)
        .expect("the passphrase did not change");
}

#[tokio::test]
async fn make_service_asks_current_even_when_the_profile_is_unlocked() {
    let scratch = Scratch::new("service-unlocked");
    let source = Scripted::new(vec![Answer::Give(PASSPHRASE)], false);
    let service = unlocked_service(&scratch, Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let view = config_of(
        client
            .call(EngineCommand::MakeService {
                name: "poste".into(),
            })
            .await,
    );

    assert_eq!(mode_in(&view, "poste"), "service");
    assert_eq!(source.purposes(), vec![PromptPurpose::Current]);
}

#[tokio::test]
async fn a_wrong_current_passphrase_keeps_an_unlocked_profile_nomad() {
    let scratch = Scratch::new("service-wrong");
    let source = Scripted::new(vec![Answer::Give(NEW_PASSPHRASE)], false);
    let service = unlocked_service(&scratch, Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::MakeService {
            name: "poste".into(),
        })
        .await;

    assert_refused(reply, &VaultError::WrongPassphrase.to_string());
    assert!(matches!(
        store_at(scratch.path()).mode_of("poste"),
        Ok(Some(ProfileMode::Nomad { .. }))
    ));
}

/// « Changer la passphrase » on a `service` profile would seal it as nomad
/// without the guard of « Passer en nomade »: the engine refuses it.
#[tokio::test]
async fn change_passphrase_refuses_a_service_profile() {
    let scratch = Scratch::new("change-service");
    store_at(scratch.path())
        .save_profile(&profile("bureau"))
        .expect("a service profile is saved");
    let source = Scripted::new(
        vec![Answer::Give(PASSPHRASE), Answer::Give(PASSPHRASE)],
        false,
    );
    let service = service_on(scratch.path(), Arc::clone(&source));
    let (client, _events) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::ChangePassphrase {
            name: "bureau".into(),
        })
        .await;

    assert_refused(reply, "le profil « bureau » n'est pas un profil nomade");
    assert!(source.purposes().is_empty(), "nothing is asked");
    assert!(matches!(
        store_at(scratch.path()).mode_of("bureau"),
        Ok(Some(ProfileMode::Service))
    ));
}

#[tokio::test]
async fn a_lock_during_change_passphrase_leaves_the_profile_locked() {
    let scratch = Scratch::new("lock-change");
    seed_nomad(scratch.path(), "poste");
    let (service, _source) = locking_service(scratch.path());
    let (client, _session) = client_of(Arc::clone(&service)).await;

    let reply = client
        .call(EngineCommand::ChangePassphrase {
            name: "poste".into(),
        })
        .await;

    assert_refused(
        reply,
        &VaultError::ProfileLocked("poste".into()).to_string(),
    );
    assert!(!service.store.is_unlocked("poste"));
    assert_locked_and_unusable(&service, "poste").await;
}
