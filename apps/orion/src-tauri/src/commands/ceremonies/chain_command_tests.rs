use super::public_chain_step;
use crate::commands::{
    begin_vault_ceremony, operator_chain_abandon, operator_chain_held, operator_chain_next,
    operator_chain_reopen, operator_chain_start,
    test_support::{answer_gateway, app_with_gateway, wait_for_operator_key},
};
use crate::operator::{rotations::ChainStepOutcome, KeyRole, VaultGesture};
use crate::AppState;
use aether::certificates::{
    encoding::{Id16, WireGuardKey},
    operator_session::{GestureState, OperatorAction},
    transport::{OperatorChainRefusal, OperatorChainStep, OperatorOpenAction, OperatorOpenRequest},
};
use astra_operator::operations::fixtures::{domain, gateway_key};
use serde_json::json;
use std::time::Duration;
use tauri::Manager;
use tokio::net::TcpListener;

#[tokio::test]
async fn chain_commands_pass_the_expected_step_and_hold_only_successful_replies() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine_task) = app_with_gateway(&domain, &gateway, gateway_key(), 4).await;
    let state = app.state::<AppState>();
    let opened = public_chain_step();
    let mut reopened = opened.clone();
    reopened.operation_id = Id16::new([0x33; 16]).expect("replacement operation id");
    let refusal = "Le plan a changé. Relisez l’étape.";
    let open_body = serde_json::to_string(&opened).expect("campaign reply");
    let reopen_body = serde_json::to_string(&OperatorChainStep::Opened(Box::new(reopened.clone())))
        .expect("reopen reply");
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let request = answer_gateway(
                &gateway,
                "POST /api/certificates/operator/campaigns ",
                "200 OK",
                &open_body,
            )
            .await;
            let request: OperatorOpenRequest =
                serde_json::from_slice(&request).expect("open campaign request");
            assert_eq!(request.action, OperatorOpenAction::ChainOpen);
            assert_eq!(request.reason, "Renouvellement");
            assert_eq!(request.requested_by, "Poste opérateur");

            let conflict = serde_json::to_string(&OperatorChainRefusal {
                message: refusal.into(),
            })
            .expect("conflict reply");
            for (route, status, response, step) in [
                ("next", "409 Conflict", conflict, 1),
                ("reopen", "200 OK", reopen_body, 2),
                (
                    "next",
                    "200 OK",
                    json!(OperatorChainStep::Finished).to_string(),
                    2,
                ),
            ] {
                let request = answer_gateway(
                    &gateway,
                    &format!("POST /api/certificates/operator/chain/{route} "),
                    status,
                    &response,
                )
                .await;
                let request: serde_json::Value =
                    serde_json::from_slice(&request).expect("chain step request");
                assert_eq!(request, json!({"expected_step": step}));
            }
        })
        .await
        .expect("four gateway requests");
    });

    assert_eq!(
        operator_chain_start(
            state.clone(),
            "Renouvellement".into(),
            "Poste opérateur".into()
        )
        .await,
        Ok(opened.clone())
    );
    assert_eq!(
        operator_chain_held(state.clone()).await,
        Ok(Some(opened.clone()))
    );
    assert_eq!(
        operator_chain_next(state.clone(), 1).await,
        Err(refusal.into())
    );
    assert_eq!(operator_chain_held(state.clone()).await, Ok(Some(opened)));
    assert_eq!(
        operator_chain_reopen(state.clone(), 2).await,
        Ok(reopened.clone())
    );
    assert_eq!(operator_chain_held(state.clone()).await, Ok(Some(reopened)));
    assert_eq!(
        operator_chain_next(state.clone(), 2).await,
        Ok(ChainStepOutcome::Finished)
    );
    assert_eq!(operator_chain_held(state).await, Ok(None));
    server.await.expect("gateway requests");
    engine_task.await.expect("engine requests");
}

#[tokio::test]
async fn an_open_ceremony_blocks_chain_progress_but_allows_abandon() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine_task) = app_with_gateway(&domain, &gateway, gateway_key(), 2).await;
    let state = app.state::<AppState>();
    let opened = public_chain_step();
    *state.chain_opened.lock().expect("held step") = Some(opened.clone());
    let before = std::fs::read(&domain.path).expect("vault before the ceremony");
    begin_vault_ceremony(
        state.clone(),
        VaultGesture::AddKey {
            label: "Clé de secours".into(),
            role: KeyRole::Recovery,
        },
    )
    .await
    .expect("open ceremony");
    let status = wait_for_operator_key(&state.operator).await;

    let refusal = super::super::CEREMONY_OPEN.to_string();
    assert_eq!(
        operator_chain_start(
            state.clone(),
            "Renouvellement".into(),
            "Poste opérateur".into()
        )
        .await,
        Err(refusal.clone())
    );
    assert_eq!(
        operator_chain_next(state.clone(), 0).await,
        Err(refusal.clone())
    );
    assert_eq!(operator_chain_reopen(state.clone(), 0).await, Err(refusal));

    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (status, body) in [
                ("403 Forbidden", r#"{"message":"Abandon refusé."}"#),
                ("204 No Content", ""),
            ] {
                let request = answer_gateway(
                    &gateway,
                    "POST /api/certificates/operator/chain/abandon ",
                    status,
                    body,
                )
                .await;
                assert!(request.is_empty());
            }
        })
        .await
        .expect("abandon requests");
    });
    let err = operator_chain_abandon(state.clone())
        .await
        .expect_err("refused abandon");
    assert!(err.contains("Abandon refusé."), "{err}");
    assert_eq!(operator_chain_held(state.clone()).await, Ok(Some(opened)));
    operator_chain_abandon(state.clone())
        .await
        .expect("abandon");
    assert_eq!(operator_chain_held(state.clone()).await, Ok(None));

    let ended = state
        .operator
        .advance(OperatorAction::Cancel, status.revision, 0)
        .await
        .expect("cancel before touching a key");
    assert_eq!(ended.gesture, GestureState::Cancelled);
    assert_eq!(
        std::fs::read(&domain.path).expect("vault after cancellation"),
        before
    );
    server.await.expect("gateway requests");
    engine_task.await.expect("engine requests");
}

#[tokio::test]
async fn a_chain_command_refuses_a_connected_gateway_from_another_domain() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let other_key = WireGuardKey::from_bytes([0x42; 32]);
    let (app, engine_task) = app_with_gateway(&domain, &gateway, other_key, 1).await;
    let state = app.state::<AppState>();
    let opened = public_chain_step();
    *state.chain_opened.lock().expect("held step") = Some(opened.clone());

    let (result, contact) = tokio::join!(
        operator_chain_reopen(state.clone(), 0),
        tokio::time::timeout(Duration::from_secs(1), gateway.accept())
    );
    let err = result.expect_err("another domain's gateway is refused");
    assert!(err.contains("nomme le relais du domaine"), "{err}");
    assert!(
        contact.is_err(),
        "the other gateway must receive no request"
    );
    assert_eq!(operator_chain_held(state).await, Ok(Some(opened)));
    engine_task.await.expect("engine requests");
}
