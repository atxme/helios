use crate::commands::{
    approve_rotation_ceremony, begin_revocation_ceremony, begin_rotation_ceremony,
    operator_artifacts, operator_ceremony_status, operator_chain_held, operator_open_campaign,
    operator_rotation_journal, operator_rotation_transition_file,
    test_support::{answer_gateway, app_with_gateway},
};
use crate::operator::{RevocationGesture, RotationGesture};
use crate::AppState;
use aether::certificates::{
    encoding::{Fingerprint, Id16, WireGuardKey},
    operator_session::{GestureState, OperatorStatus, Refusal},
    status::CampaignScope,
    transport::{OperatorOpenAction, OperatorOpenRequest, OperatorOpened},
};
use astra_operator::operations::{
    fixtures::{domain, gateway_key, NOW},
    revocation::{self, RevocationReasonChoice},
    rotation::RotationTerms,
};
use serde_json::{json, Value};
use std::time::Duration;
use tauri::{Manager, State};
use tokio::net::TcpListener;

async fn final_status(state: State<'_, AppState>) -> OperatorStatus {
    tokio::time::timeout(Duration::from_secs(5), state.operator.ended())
        .await
        .expect("ceremony ends");
    operator_ceremony_status(state)
        .await
        .expect("ceremony status")
        .expect("existing session")
        .status
}

#[tokio::test]
async fn manual_campaign_opening_sends_its_scope_and_returns_a_public_result_or_refusal() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 2).await;
    let state = app.state::<AppState>();
    let opened = OperatorOpened {
        operation_id: Id16::new([0x31; 16]).expect("operation id"),
        campaign_id: Id16::new([0x32; 16]).expect("campaign id"),
        campaign_fingerprint: Fingerprint::of(b"fleet campaign"),
        scope: CampaignScope::FleetLeafs,
        target_count: 3,
        required_credentials: 2,
        expires_at: NOW + 300,
        revocation_expiries: None,
        delegation_request: None,
        gateway_certificate: None,
    };
    let open_body = serde_json::to_string(&opened).expect("campaign result");
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (action, status, response) in [
                (OperatorOpenAction::FleetLeafs, "200 OK", open_body),
                (
                    OperatorOpenAction::IssuerDelegation,
                    "403 Forbidden",
                    "{}".into(),
                ),
            ] {
                let bytes = answer_gateway(
                    &gateway,
                    "POST /api/certificates/operator/campaigns ",
                    status,
                    &response,
                )
                .await;
                let request: OperatorOpenRequest =
                    serde_json::from_slice(&bytes).expect("typed campaign request");
                assert_eq!(request.action, action);
                assert_eq!(request.reason, "Renouvellement");
                assert_eq!(request.requested_by, "Poste opérateur");
                assert_eq!(request.window_secs, 300);
            }
        })
        .await
        .expect("two campaign requests");
    });

    assert_eq!(
        operator_open_campaign(
            state.clone(),
            OperatorOpenAction::FleetLeafs,
            "Renouvellement".into(),
            "Poste opérateur".into()
        )
        .await,
        Ok(opened)
    );
    let error = operator_open_campaign(
        state.clone(),
        OperatorOpenAction::IssuerDelegation,
        "Renouvellement".into(),
        "Poste opérateur".into(),
    )
    .await
    .expect_err("gateway refuses");
    assert!(error.contains("403"), "{error}");
    assert!(operator_ceremony_status(state.clone())
        .await
        .expect("status")
        .is_none());
    assert_eq!(operator_chain_held(state).await, Ok(None));
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn a_manual_opening_cannot_bypass_the_ca_rotation_ceremony() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;

    let (result, contact) = tokio::join!(
        operator_open_campaign(
            app.state::<AppState>(),
            OperatorOpenAction::TrustAuthorities,
            "Renouvellement".into(),
            "Poste opérateur".into()
        ),
        tokio::time::timeout(Duration::from_millis(250), gateway.accept()),
    );

    let error = result.expect_err("rotation requires its own approval");
    assert!(error.contains("« Approuver »"), "{error}");
    assert!(contact.is_err(), "no campaign must reach the gateway");
    assert_eq!(domain.touches(), 0);
    engine.await.expect("engine requests");
}

async fn answer_admitted_peer(gateway: &TcpListener, key: WireGuardKey) {
    let response = json!({
        "wg_public_key": gateway_key().to_base64(),
        "wg_address": "100.64.0.1",
        "peers": [{"name": "Poste bureau", "public_key": key.to_base64(), "address": "100.64.0.2"}],
    });
    let request = answer_gateway(
        gateway,
        "GET /api/network ",
        "200 OK",
        &response.to_string(),
    )
    .await;
    assert!(request.is_empty());
}

fn revoke(peer: WireGuardKey) -> RevocationGesture {
    RevocationGesture::Revoke {
        peer: peer.to_base64(),
        name: "Poste bureau".into(),
        reason: RevocationReasonChoice::NoLongerUsed,
    }
}

#[tokio::test]
async fn a_revocation_with_a_mismatched_peer_name_does_not_withdraw_admission() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            answer_admitted_peer(&gateway, WireGuardKey::from_bytes([0x51; 32])).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(250), gateway.accept())
                    .await
                    .is_err(),
                "a name bound to another key must not be withdrawn"
            );
        })
        .await
        .expect("admission read");
    });

    begin_revocation_ceremony(state.clone(), revoke(WireGuardKey::from_bytes([0x52; 32])))
        .await
        .expect("start revocation");
    let status = final_status(state).await;
    assert_eq!(status.gesture, GestureState::Failed);
    assert_eq!(status.refusal, Some(Refusal::PeerNameMismatch));
    assert!(!status.peer_cut);
    assert!(revocation::pending(&domain.path, NOW)
        .expect("pending decisions")
        .is_none());
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn a_revocation_reports_the_committed_cut_when_astra_is_unavailable() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let peer = WireGuardKey::from_bytes([0x53; 32]);
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            answer_admitted_peer(&gateway, peer).await;
            let request = answer_gateway(&gateway, "POST /api/peers/revoke ", "200 OK", "{}").await;
            let body: Value = serde_json::from_slice(&request).expect("withdrawal request");
            assert_eq!(body, json!({"name": "Poste bureau"}));
            let request = answer_gateway(
                &gateway,
                "GET /api/certificates/operator/status ",
                "503 Service Unavailable",
                "{}",
            )
            .await;
            assert!(request.is_empty());
        })
        .await
        .expect("admission and authority requests");
    });

    begin_revocation_ceremony(state.clone(), revoke(peer))
        .await
        .expect("start revocation");
    let status = final_status(state).await;
    assert_eq!(status.gesture, GestureState::Failed);
    assert_eq!(status.refusal, Some(Refusal::AuthorityUnreachable));
    assert!(status.peer_cut);
    assert!(status.operation_id.is_none());
    assert!(revocation::pending(&domain.path, NOW)
        .expect("pending decisions")
        .is_none());
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn rotation_without_a_campaign_stays_refused_when_an_astra_origin_is_recorded() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let vault = std::fs::read(&domain.path).expect("vault before rotation");

    assert!(domain.relay().astra_authority_url.is_some());
    let (status, contact) = tokio::join!(
        async {
            begin_rotation_ceremony(state.clone(), RotationGesture::ReplaceCaPqWithoutCampaign)
                .await
                .expect("start rotation");
            final_status(state.clone()).await
        },
        tokio::time::timeout(Duration::from_millis(250), gateway.accept()),
    );
    assert_eq!(status.gesture, GestureState::Failed);
    assert_eq!(status.refusal, Some(Refusal::ManifestMismatch));
    assert!(
        contact.is_err(),
        "the rotation must refuse before reaching the gateway"
    );

    let terms = RotationTerms {
        existing_operation: None,
        reason: "Renouvellement".into(),
        requested_by: "Poste opérateur".into(),
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 30,
        chain_step: None,
    };
    assert!(
        approve_rotation_ceremony(state.clone(), terms, status.revision)
            .await
            .is_err()
    );
    let journal = operator_rotation_journal(state.clone())
        .await
        .expect("rotation journal");
    assert!(!journal.resumable);
    assert!(journal.journal.is_none());
    assert!(operator_rotation_transition_file(state.clone())
        .await
        .expect("transition file")
        .is_none());
    assert!(operator_artifacts(state)
        .await
        .expect("artifacts")
        .is_empty());
    assert!(std::fs::read(&domain.path).expect("vault after refusal") == vault);
    assert_eq!(domain.touches(), 0);
    engine.await.expect("engine requests");
}
