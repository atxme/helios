//! Cancellation and concurrent polling around durable staging.

use super::*;

#[tokio::test]
async fn cancellation_after_gateway_stage_reuses_the_durable_authorization() {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let gate = TestGate::new();
    *fixture.gateway.stage_gate.lock().await = Some(gate.clone());

    let service = fixture.service.clone();
    let caller = client_key();
    let task = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("gateway persisted stage before blocking its reply");
    task.abort();
    let cancelled = task.await.expect_err("aborted read task must be cancelled");
    assert!(cancelled.is_cancelled());

    {
        let operations = fixture.service.operations.lock().await;
        let operation = operations
            .get(&id, &client_key(), NOW + 1)
            .expect("pending operation after cancellation");
        assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
        assert!(operation.receipt().is_none());
        assert!(operation.view(None, None).grant.is_none());
    }
    let before_retry: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.operations_path()).expect("durable journal before retry"),
    )
    .expect("durable journal JSON");
    assert!(before_retry["operations"][0]["grant"].is_null());

    let stage_before = fixture.gateway.stages.lock().await[0].clone();
    let durable_gateway: ClientCertificateState = serde_json::from_slice(
        &std::fs::read(&fixture.gateway.state_path).expect("durable gateway state"),
    )
    .expect("gateway state document");
    let durable_stage_id = durable_gateway
        .pending
        .as_ref()
        .expect("durable pending grant")
        .stage_id;
    assert_eq!(durable_stage_id, stage_before.stage_id);

    gate.open();
    *fixture.gateway.stage_gate.lock().await = None;
    fixture.gateway.view.lock().await.state = durable_gateway;
    fixture.reload().await;
    let retry = fixture.read(&id).await.expect("retry same operation");
    assert_eq!(retry.state, ClientRenewalOperationState::PendingCommit);
    let stages = fixture.gateway.stages.lock().await;
    assert_eq!(stages.len(), 2);
    assert_eq!(
        stages[1], stage_before,
        "retry must replay identical authorization bytes"
    );
    assert_eq!(stages[1].stage_id, durable_stage_id);
    assert_eq!(stages[1].next_generation, stages[0].next_generation);
}
#[tokio::test]
async fn concurrent_polls_do_not_publish_different_stages_for_one_operation() {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let gate = TestGate::new();
    *fixture.gateway.stage_gate.lock().await = Some(gate.clone());

    let service = fixture.service.clone();
    let caller = client_key();
    let first = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("first poll reached gateway stage");

    let service = fixture.service.clone();
    let caller = client_key();
    let id = fixture.operation_id();
    let second = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("second poll also reached gateway staging");
    assert_eq!(fixture.gateway.stage_calls.load(Ordering::SeqCst), 2);
    gate.open();
    gate.open();
    let first = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .expect("first poll completed")
        .expect("first poll task")
        .expect("first poll succeeded");
    let second = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("second poll completed")
        .expect("second poll task")
        .expect("second poll succeeded");
    assert_eq!(first.state, ClientRenewalOperationState::PendingCommit);
    assert_eq!(second.state, ClientRenewalOperationState::PendingCommit);
    assert_eq!(
        serde_json::to_value(&first.grant).expect("first grant JSON"),
        serde_json::to_value(&second.grant).expect("second grant JSON")
    );
    *fixture.gateway.stage_gate.lock().await = None;
    let stages = fixture.gateway.stages.lock().await;
    assert_eq!(stages.len(), 2);
    assert!(stages.iter().all(|stage| stage == &stages[0]));
    assert!(stages
        .iter()
        .all(|stage| stage.next_generation == stages[0].next_generation));
    drop(stages);
    fixture.reload().await;
    let durable = crate::operations::OperationStore::load(&fixture.operations_path(), NOW + 1)
        .expect("durable concurrent grant");
    let durable_grant = durable
        .get(&fixture.operation_id(), &client_key(), NOW + 1)
        .expect("durable operation")
        .view(None, None)
        .grant;
    assert_eq!(
        serde_json::to_value(&durable_grant).expect("durable grant JSON"),
        serde_json::to_value(&first.grant).expect("poll grant JSON")
    );
}

#[tokio::test]
async fn a_late_poll_cannot_replace_a_durable_grant_after_revocation() {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let gate = TestGate::new();
    *fixture.gateway.identity_gate.lock().await = Some(gate.clone());

    let service = fixture.service.clone();
    let caller = client_key();
    let first = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("first poll reached grant publication");

    let service = fixture.service.clone();
    let caller = client_key();
    let id = fixture.operation_id();
    let late = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("late poll reached grant publication");

    gate.open();
    let first_view = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .expect("first poll completed")
        .expect("first poll task")
        .expect("first poll published the grant");
    assert_eq!(first_view.state, ClientRenewalOperationState::PendingCommit);
    let journal_with_grant = std::fs::read(fixture.operations_path()).expect("durable grant");

    fixture
        .service
        .registry
        .lock()
        .await
        .revoke(&client_key(), 1, NOW + 1)
        .expect("revoke after grant publication");
    gate.open();
    let late_result = tokio::time::timeout(Duration::from_secs(10), late)
        .await
        .expect("late poll completed")
        .expect("late poll task");
    assert!(matches!(
        late_result,
        Err(RenewalError::Registry(RegistryError::NoRotation))
    ));
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("operation journal after late poll"),
        journal_with_grant,
        "a late poll must not overwrite or withdraw a durable grant"
    );
    let operations = fixture.service.operations.lock().await;
    let operation = operations
        .get(&fixture.operation_id(), &client_key(), NOW + 1)
        .expect("durable operation remains readable internally");
    assert_eq!(operation.state, ClientRenewalOperationState::PendingCommit);
    assert!(operation.view(None, None).grant.is_some());
}

#[derive(Clone, Copy)]
enum ReservationChange {
    StageId,
    RequestFingerprint,
    Candidate,
    Window,
    Lease,
}

async fn assert_replaced_reservation_blocks_grant(change: ReservationChange) {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let gate = TestGate::new();
    *fixture.gateway.identity_gate.lock().await = Some(gate.clone());

    let service = fixture.service.clone();
    let caller = client_key();
    let task = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("grant path reached the paused identity lookup");

    let expected_reservation = {
        let mut registry = fixture.service.registry.lock().await;
        let mut replacement = registry
            .peer(&client_key())
            .expect("reserved peer")
            .pending
            .clone()
            .expect("original stage reservation");
        registry
            .abandon_rotation(&client_key(), &replacement.stage_id, NOW + 1)
            .expect("abandon original ungranted reservation");
        match change {
            ReservationChange::StageId => {
                replacement.stage_id = Id16::new([0xe1; 16]).expect("replacement stage ID");
            }
            ReservationChange::RequestFingerprint => {
                replacement.request_fingerprint = Fingerprint::of(b"replacement request");
            }
            ReservationChange::Candidate => {
                replacement.candidate.generation += 1;
            }
            ReservationChange::Window => {
                replacement.window.activation_at += 1;
            }
            ReservationChange::Lease => {
                replacement.stage_expires_at += 1;
            }
        }
        registry
            .open_rotation(&client_key(), replacement.clone(), NOW + 1)
            .expect("open replacement reservation");
        replacement
    };

    gate.open();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("poll completed")
        .expect("poll task");
    assert!(matches!(
        result,
        Err(RenewalError::Operation(OperationError::Corrupt(
            "registry reservation changed before grant publication"
        )))
    ));

    let operations = fixture.service.operations.lock().await;
    let operation = operations
        .get(&fixture.operation_id(), &client_key(), NOW + 1)
        .expect("operation remains pending");
    assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
    assert!(operation.receipt().is_none());
    assert!(operation.view(None, None).grant.is_none());
    drop(operations);

    let durable: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.operations_path()).expect("journal"))
            .expect("journal JSON");
    let id_json = serde_json::to_value(fixture.operation_id()).expect("operation ID JSON");
    let durable_operation = durable["operations"]
        .as_array()
        .expect("operation list")
        .iter()
        .find(|operation| operation["operation_id"] == id_json)
        .expect("durable operation");
    assert!(durable_operation["grant"].is_null());
    assert!(durable_operation["receipt"].is_null());

    let registry = fixture.service.registry.lock().await;
    assert_eq!(
        registry.peer(&client_key()).expect("peer").pending.as_ref(),
        Some(&expected_reservation),
        "the refusal must preserve the replacement reservation"
    );
    drop(registry);
    let durable_registry = crate::registry::AstraRegistry::load(&fixture.registry_path(), None)
        .expect("durable replacement reservation");
    assert_eq!(
        durable_registry
            .peer(&client_key())
            .expect("durable peer")
            .pending
            .as_ref(),
        Some(&expected_reservation)
    );
}

#[tokio::test]
async fn changed_registry_reservation_blocks_grant_publication() {
    for change in [
        ReservationChange::StageId,
        ReservationChange::RequestFingerprint,
        ReservationChange::Candidate,
        ReservationChange::Window,
        ReservationChange::Lease,
    ] {
        assert_replaced_reservation_blocks_grant(change).await;
    }
}

#[tokio::test]
async fn revocation_during_gateway_identity_lookup_cannot_release_a_grant() {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let gate = TestGate::new();
    *fixture.gateway.identity_gate.lock().await = Some(gate.clone());

    let service = fixture.service.clone();
    let caller = client_key();
    let task = tokio::spawn(async move { read(&service, &caller, &id, NOW + 1).await });
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_entered())
        .await
        .expect("grant path reached gateway identity lookup");
    fixture
        .service
        .registry
        .lock()
        .await
        .revoke(&client_key(), 1, NOW + 1)
        .expect("revoke peer while identity lookup is suspended");
    gate.open();

    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("poll completed")
        .expect("poll task");
    let returned_revoked = matches!(result, Err(RenewalError::Revoked));
    let operations = fixture.service.operations.lock().await;
    let operation = operations
        .get(&id, &client_key(), NOW + 1)
        .expect("operation");
    let state_after_race = operation.state;
    let memory_grant_missing = operation.view(None, None).grant.is_none();
    let durable: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.operations_path()).expect("journal"))
            .expect("operation journal JSON");
    let id_json = serde_json::to_value(id).expect("operation ID JSON");
    let durable_operation = durable["operations"]
        .as_array()
        .expect("operation list")
        .iter()
        .find(|operation| operation["operation_id"] == id_json)
        .expect("durable operation");
    let disk_grant_missing = durable_operation["grant"].is_null();
    assert!(
        memory_grant_missing && disk_grant_missing,
        "revocation must not publish a grant: memory_missing={memory_grant_missing}, \
         disk_missing={disk_grant_missing}, state={state_after_race:?}"
    );
    assert_eq!(
        state_after_race,
        ClientRenewalOperationState::PendingGrant,
        "revocation must leave the operation awaiting grant"
    );
    drop(operations);

    let registry = fixture.service.registry.lock().await;
    let revoked_peer = registry.peer(&client_key()).expect("revoked peer");
    assert!(revoked_peer.revoked, "revocation remains durable in memory");
    assert!(
        revoked_peer.pending.is_none(),
        "revocation clears the staged candidate"
    );
    drop(registry);
    let durable_registry = crate::registry::AstraRegistry::load(&fixture.registry_path(), None)
        .expect("durable revoked registry");
    let durable_revoked_peer = durable_registry
        .peer(&client_key())
        .expect("durable revoked peer");
    assert!(durable_revoked_peer.revoked);
    assert!(durable_revoked_peer.pending.is_none());
    assert!(returned_revoked, "the concurrent poll must return Revoked");
}
