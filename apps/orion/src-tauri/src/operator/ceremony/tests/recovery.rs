use super::*;

fn key(serial: u8) -> Box<dyn Authenticator> {
    Box::new(enrolled_test_key(serial))
}

fn continue_press(revision: u64) -> (std::sync::mpsc::Sender<Press>, Receiver<Press>) {
    let (sender, receiver) = std::sync::mpsc::channel();
    sender
        .send(Press {
            action: OperatorAction::Continue,
            revision,
            owner: 0,
            terms: None,
        })
        .expect("queue continue");
    (sender, receiver)
}

fn check_ceremony() -> Ceremony {
    Ceremony::new(
        Id16::new([8; 16]).expect("session id"),
        OperationLocator {
            kind: OperationKind::VerifyKey,
            operation_id: None,
        },
    )
}

#[test]
fn verify_key_preflight_failure_publishes_refusal_without_requesting_key() {
    let domain = Domain::new_with_test_key("verify-missing-vault");
    let missing = domain.vault_path.with_file_name("missing-vault.json");
    let (_sender, presses) = continue_press(1);
    let mut ceremony = check_ceremony();
    let mut statuses = Vec::new();
    let result = verify_key_with(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &missing,
        &|_| panic!("preflight must happen before connecting a key"),
    );
    assert!(result.is_err());
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(statuses[0].gesture, GestureState::Failed);
    assert!(statuses[0].manifest.is_none());
}

#[test]
fn verify_key_publishes_fingerprint_manifest_before_touching_key() {
    let domain = Domain::new_with_test_key("verify-manifest");
    let original_vault = std::fs::read(&domain.vault_path).expect("fixture vault bytes");
    let vault = astra_operator::store::load(&domain.vault_path).expect("fixture vault");
    let expected_fingerprint = vault.fingerprint().expect("fingerprint");
    let (_sender, presses) = continue_press(1);
    let mut ceremony = check_ceremony();
    let mut statuses = Vec::new();
    let connected = std::cell::Cell::new(false);
    let result = verify_key_with(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
        &|_| {
            connected.set(true);
            Ok(key(1))
        },
    );
    result.expect("fixture credential opens vault");
    assert!(connected.get());
    let offered = statuses
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("operator sees key prompt");
    assert_eq!(offered.remote, RemoteState::AwaitingOperator);
    assert!(
        matches!(offered.manifest, Some(AstraManifest::KeyCheck(ref m)) if m.vault_fingerprint == expected_fingerprint)
    );
    let last = statuses.last().expect("terminal status");
    assert_eq!(last.gesture, GestureState::Done);
    assert_eq!(last.keys.len(), 1);
    assert_eq!(last.keys[0].label, "quotidienne");
    assert!(last.refusal.is_none());
    assert_eq!(
        std::fs::read(&domain.vault_path).expect("vault remains readable"),
        original_vault,
        "verification must not mutate vault bytes"
    );
}

#[test]
fn verify_key_cancellation_is_reported_without_connecting_or_claiming_failure() {
    let domain = Domain::new_with_test_key("verify-cancel");
    let (sender, presses) = std::sync::mpsc::channel();
    drop(sender);
    let mut ceremony = check_ceremony();
    let mut statuses = Vec::new();
    let result = verify_key_with(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
        &|_| panic!("cancelled prompt must not connect"),
    );
    result.expect("operator abandonment is not a processing error");
    assert_eq!(
        statuses.last().expect("cancel status").gesture,
        GestureState::Cancelled
    );
    assert_eq!(
        statuses.last().expect("cancel status").refusal,
        Some(Refusal::Cancelled)
    );
    assert!(statuses.last().expect("cancel status").keys.is_empty());
}

#[test]
fn verify_key_connect_failure_keeps_typed_refusal_and_no_slot_label() {
    let domain = Domain::new_with_test_key("verify-connect-failure");
    let (_sender, presses) = continue_press(1);
    let mut ceremony = check_ceremony();
    let mut statuses = Vec::new();
    let result = verify_key_with(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
        &|_| Err((Refusal::ForegroundUnavailable, "dialog unavailable".into())),
    );
    assert!(result.is_err());
    let last = statuses.last().expect("failure status");
    assert_eq!(last.refusal, Some(Refusal::ForegroundUnavailable));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(last.keys.is_empty());
}

#[test]
fn verify_key_rejects_an_unenrolled_credential_without_returning_a_label() {
    let domain = Domain::new_with_test_key("verify-wrong-key");
    let (_sender, presses) = continue_press(1);
    let mut ceremony = check_ceremony();
    let mut statuses = Vec::new();
    let result = verify_key_with(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
        &|_| Ok(key(99)),
    );
    assert!(result.is_err());
    let last = statuses.last().expect("failure status");
    assert_eq!(last.refusal, Some(Refusal::KeyDeclined));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(last.keys.is_empty());
}

#[test]
fn recovery_requires_an_operation_id_before_opening_the_vault_or_key() {
    let domain = Domain::new_with_test_key("recover-no-operation");
    let mut ceremony = Ceremony::new(
        Id16::new([7; 16]).expect("session id"),
        OperationLocator {
            kind: OperationKind::RecoverIdentity,
            operation_id: None,
        },
    );
    let (sender, presses) = std::sync::mpsc::channel();
    drop(sender);
    let mut statuses = Vec::new();
    let result = recover(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
    );
    assert!(result.is_err());
    assert!(statuses.is_empty());
}

#[test]
fn recovery_preflight_failure_is_published_before_a_key_is_requested() {
    let domain = Domain::new_with_test_key("recover-missing-vault");
    let missing = domain.vault_path.with_file_name("missing-vault.json");
    let mut ceremony = Ceremony::new(
        Id16::new([6; 16]).expect("session id"),
        OperationLocator {
            kind: OperationKind::RecoverIdentity,
            operation_id: Some(Id16::new([4; 16]).expect("operation id")),
        },
    );
    let (sender, presses) = std::sync::mpsc::channel();
    drop(sender);
    let mut statuses = Vec::new();
    let result = recover(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &missing,
    );
    assert!(result.is_err());
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(statuses[0].gesture, GestureState::Failed);
    assert!(statuses[0].manifest.is_none());
}

#[test]
fn recovery_refuses_a_vault_without_its_credential_manifest_before_touch() {
    let domain = Domain::new_with_test_key("recover-no-credentials");
    let mut ceremony = Ceremony::new(
        Id16::new([9; 16]).expect("session id"),
        OperationLocator {
            kind: OperationKind::RecoverIdentity,
            operation_id: Some(Id16::new([9; 16]).expect("operation id")),
        },
    );
    let (sender, presses) = std::sync::mpsc::channel();
    drop(sender);
    let mut statuses = Vec::new();
    let result = recover(
        &mut ceremony,
        &presses,
        &mut |status| statuses.push(status),
        &domain.vault_path,
    );
    assert!(result.is_err());
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(statuses[0].gesture, GestureState::Failed);
    assert!(statuses[0].manifest.is_none());
}
