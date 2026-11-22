use super::authority_status;
use crate::commands::{
    adopt_connected_gateway, begin_vault_ceremony, operator_artifacts, operator_ceremony_status,
    operator_overview, operator_send_vault_copy, operator_vault_location, rename_operator_key,
    test_support::{answer_gateway, app_with_gateway, wait_for_operator_key},
    write_domain_relay,
};
use crate::operator::{rotations::VaultCopyOutcome, KeyRole, VaultGesture};
use crate::AppState;
use aether::certificates::{
    encoding::WireGuardKey,
    operator_session::{GestureState, OperatorAction},
    transport::OperatorVaultCopy,
};
use astra_operator::{
    handoff,
    operations::fixtures::{domain, gateway_key},
    store,
    vault_gestures::{RelayUpdate, SetupRefusal},
};
use std::time::Duration;
use tauri::Manager;
use tokio::net::TcpListener;

#[tokio::test]
async fn renaming_a_key_updates_the_public_overview_without_resealing_the_vault() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 0).await;
    let state = app.state::<AppState>();
    let location = operator_vault_location(state.clone())
        .await
        .expect("vault location");
    assert_eq!(location.path.as_deref(), domain.path.to_str());
    assert!(!location.is_default);
    assert!(location.error.is_none());

    let before = store::load(&domain.path).expect("original vault");
    let document = domain.registry();
    let overview = operator_overview(state.clone())
        .await
        .expect("original overview");
    let slot = &overview.slots[0];
    assert_eq!(slot.label, "Clé 1");
    assert_eq!(
        rename_operator_key(state.clone(), "invalid-id".into(), "Clé bureau".into()).await,
        Err("l'identifiant de la clé tient en 32 caractères hexadécimaux".into())
    );
    let after_refusal = store::load(&domain.path).expect("vault after refusal");
    assert!(
        after_refusal == before,
        "the refused rename changed the vault"
    );

    rename_operator_key(state.clone(), slot.slot_id.clone(), "  Clé bureau  ".into())
        .await
        .expect("rename");
    let updated = operator_overview(state).await.expect("updated overview");
    let mut expected_slots = overview.slots;
    expected_slots[0].label = "Clé bureau".into();
    assert_eq!(updated.slots, expected_slots);
    let after = store::load(&domain.path).expect("renamed vault");
    assert!(
        after.sealed_payload == before.sealed_payload,
        "the vault was resealed"
    );
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(domain.registry(), document);
    assert_eq!(domain.touches(), 0);
    engine.await.expect("no engine requests");
}

#[tokio::test]
async fn relay_changes_are_validated_as_a_whole_and_keep_the_gateway_binding() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 0).await;
    let state = app.state::<AppState>();
    let relay_path = handoff::path_beside(&domain.path);
    let original = std::fs::read(&relay_path).expect("original relay");
    let relay = domain.relay();
    let vault = std::fs::read(&domain.path).expect("original vault");

    let invalid = RelayUpdate {
        astra_service_key_epoch: Some(relay.astra_service_key_epoch.expect("service epoch") + 1),
        astra_authority_url: Some("https://astra.example/not-an-origin".into()),
        ..RelayUpdate::default()
    };
    let error = write_domain_relay(state.clone(), invalid)
        .await
        .expect_err("non-origin URL is refused");
    assert!(error.contains("origine"), "{error}");
    assert_eq!(
        std::fs::read(&relay_path).expect("preserved relay"),
        original
    );

    let other_gateway = RelayUpdate {
        gateway_wg_public_key: Some(WireGuardKey::from_bytes([0x42; 32]).to_base64()),
        ..RelayUpdate::default()
    };
    assert_eq!(
        write_domain_relay(state.clone(), other_gateway).await,
        Err(SetupRefusal::OtherGateway.to_string())
    );
    assert_eq!(std::fs::read(&relay_path).expect("bound relay"), original);

    let update = RelayUpdate {
        astra_authority_url: Some("  https://astra.example/  ".into()),
        ..RelayUpdate::default()
    };
    write_domain_relay(state, update)
        .await
        .expect("valid origin");
    let mut expected = relay;
    expected.astra_authority_url = Some("https://astra.example".into());
    assert_eq!(domain.relay(), expected);
    assert!(std::fs::read(&domain.path).expect("vault after relay update") == vault);
    assert_eq!(domain.touches(), 0);
    engine.await.expect("no engine requests");
}

#[tokio::test]
async fn an_open_vault_ceremony_blocks_edits_adoption_and_copy() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 0).await;
    let state = app.state::<AppState>();
    let slot_id = operator_overview(state.clone())
        .await
        .expect("overview")
        .slots[0]
        .slot_id
        .clone();
    let vault = std::fs::read(&domain.path).expect("original vault");
    let relay_path = handoff::path_beside(&domain.path);
    let relay = std::fs::read(&relay_path).expect("original relay");

    begin_vault_ceremony(
        state.clone(),
        VaultGesture::AddKey {
            label: "Clé de secours".into(),
            role: KeyRole::Recovery,
        },
    )
    .await
    .expect("start ceremony");
    let awaiting = wait_for_operator_key(&state.operator).await;
    let observed = operator_ceremony_status(state.clone())
        .await
        .expect("ceremony status")
        .expect("open ceremony");
    assert_eq!(observed.status.revision, awaiting.revision);
    assert!(!observed.automatic);
    assert!(operator_artifacts(state.clone())
        .await
        .expect("artifacts")
        .is_empty());

    let refusal = Err(super::super::CEREMONY_OPEN.to_string());
    assert_eq!(
        rename_operator_key(state.clone(), slot_id, "Clé bureau".into()).await,
        refusal
    );
    assert_eq!(
        write_domain_relay(
            state.clone(),
            RelayUpdate {
                astra_authority_url: Some("https://astra.example".into()),
                ..RelayUpdate::default()
            },
        )
        .await,
        refusal
    );
    assert_eq!(adopt_connected_gateway(state.clone()).await, refusal);
    assert_eq!(
        operator_send_vault_copy(state.clone(), false).await,
        Err(super::super::CEREMONY_OPEN.into())
    );
    let ended = state
        .operator
        .advance(OperatorAction::Cancel, awaiting.revision, 0)
        .await
        .expect("cancel before key touch");
    assert_eq!(ended.gesture, GestureState::Cancelled);
    assert!(std::fs::read(&domain.path).expect("vault after cancellation") == vault);
    assert_eq!(
        std::fs::read(&relay_path).expect("relay after cancellation"),
        relay
    );
    assert_eq!(domain.touches(), 0);
    engine.await.expect("no engine requests");
}

#[tokio::test]
async fn a_held_back_copy_without_a_document_reaches_the_page_without_retry() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let epoch = domain.registry().credential_registry_epoch;
    let vault = std::fs::read(&domain.path).expect("original vault");
    let expected =
        astra_operator::operations::rotation::vault_copy(&domain.path).expect("vault copy");
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let request = answer_gateway(
                &gateway,
                "GET /api/certificates/operator/status ",
                "200 OK",
                &authority_status(Some(epoch)),
            )
            .await;
            assert!(request.is_empty());
            let request = answer_gateway(
                &gateway,
                "POST /api/certificates/operator/vault-copy ",
                "409 Conflict",
                "{}",
            )
            .await;
            let copy: OperatorVaultCopy = serde_json::from_slice(&request).expect("copy request");
            assert!(!copy.replace_newer);
            assert!(copy.credentials.is_none());
            assert!(
                copy.vault_base64 == expected.vault_base64,
                "the copy differs from the sealed vault"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), gateway.accept())
                    .await
                    .is_err(),
                "a copy without a document cannot be retried without it"
            );
        })
        .await
        .expect("status and copy requests");
    });

    assert_eq!(
        operator_send_vault_copy(state, false).await,
        Ok(VaultCopyOutcome::HeldBack)
    );
    assert!(std::fs::read(&domain.path).expect("vault after sending") == vault);
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}
