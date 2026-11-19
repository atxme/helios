// Off Windows only, like the other service tests: the nomad flows run on a
// scratch vault with a fixed test root, and the passphrase comes from a script.
#![cfg(not(target_os = "windows"))]

use super::*;
use crate::client::EngineClient;
use crate::command::{EngineCommand, EngineReply, ProfileDraft};
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
use std::sync::Mutex as StdMutex;
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
