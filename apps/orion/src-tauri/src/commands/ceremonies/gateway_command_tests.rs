use crate::commands::{
    begin_gateway_ceremony, operator_gateway_check_renewal,
    test_support::{answer_gateway, app_with_gateway},
};
use crate::operator::{GatewayGesture, GatewayRenewTermsArg, MAX_GATEWAY_TERM_DAYS};
use crate::AppState;
use aether::certificates::{
    encoding::Fingerprint,
    operator_session::{GestureState, Refusal},
};
use astra_operator::operations::{
    fixtures::{domain, gateway_key, NOW},
    gateway_identity::{
        carry, open_renewal, pending,
        tests::{Remote, Scenario},
        GatewayRefusal,
    },
};
use serde_json::{json, Value};
use std::time::Duration;
use tauri::Manager;
use tokio::net::TcpListener;

fn renewal_terms() -> GatewayRenewTermsArg {
    GatewayRenewTermsArg {
        rotate_tls: false,
        key_recovery: false,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 30,
    }
}

fn identity_view() -> Value {
    json!({
        "ca_pq_fingerprint": Fingerprint::of(b"fixture CA-PQ"),
        "gateway_identity_epoch": 1,
    })
}

async fn read_identity(gateway: &TcpListener, view: &Value) {
    let request = answer_gateway(
        gateway,
        "GET /api/certificates ",
        "200 OK",
        &view.to_string(),
    )
    .await;
    assert!(request.is_empty());
}

#[tokio::test]
async fn renewal_check_sends_the_options_and_rejects_an_incompatible_reuse() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 2).await;
    let state = app.state::<AppState>();
    let terms = GatewayRenewTermsArg {
        rotate_tls: true,
        key_recovery: true,
        ..renewal_terms()
    };
    let expires_at = NOW + 3_600;
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let view = identity_view();
            for (candidate_tls, key_recovery) in [
                (Some(Fingerprint::of(b"candidate TLS")), true),
                (None, false),
            ] {
                read_identity(&gateway, &view).await;
                read_identity(&gateway, &view).await;
                let prepared = json!({
                    "gateway_identity_epoch": 2,
                    "request_fingerprint": Fingerprint::of(b"prepared request"),
                    "candidate_tls_fingerprint": candidate_tls,
                    "expires_at": expires_at,
                    "reused": true,
                    "key_recovery": key_recovery,
                });
                let request = answer_gateway(
                    &gateway,
                    "POST /api/certificates/gateway-renewal ",
                    "200 OK",
                    &prepared.to_string(),
                )
                .await;
                let ask: Value = serde_json::from_slice(&request).expect("renewal request");
                assert_eq!(
                    ask,
                    json!({"rotate_tls": true, "key_recovery": true, "new_key": false})
                );
            }
        })
        .await
        .expect("renewal check requests");
    });

    assert_eq!(
        operator_gateway_check_renewal(state.clone(), terms).await,
        Ok(())
    );
    assert_eq!(
        operator_gateway_check_renewal(state.clone(), terms).await,
        Err(GatewayRefusal::PreparedRequestDiffers {
            cause: "la feuille TLS candidate et la perte de clé",
            expires_at,
        }
        .to_string())
    );
    assert!(state.operator.status().await.is_none());
    assert!(pending(&domain.path, NOW)
        .expect("pending record")
        .is_none());
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn invalid_renewal_terms_are_refused_before_looking_up_the_tunnel() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 0).await;
    engine.await.expect("no expected engine request");
    let state = app.state::<AppState>();

    let expected = Err(format!(
        "les durées se comptent en jours, de 1 à {MAX_GATEWAY_TERM_DAYS}"
    ));
    for terms in [
        GatewayRenewTermsArg {
            prepare_days: 0,
            ..renewal_terms()
        },
        GatewayRenewTermsArg {
            overlap_days: MAX_GATEWAY_TERM_DAYS + 1,
            ..renewal_terms()
        },
        GatewayRenewTermsArg {
            validity_days: 0,
            ..renewal_terms()
        },
    ] {
        assert_eq!(
            operator_gateway_check_renewal(state.clone(), terms).await,
            expected
        );
    }
    assert!(state.operator.status().await.is_none());
    assert_eq!(domain.touches(), 0);
}

#[tokio::test]
async fn abort_reports_that_the_gateway_has_no_staged_transition() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            read_identity(&gateway, &identity_view()).await;
            let request = answer_gateway(
                &gateway,
                "GET /api/certificates/gateway-transition ",
                "200 OK",
                r#"{"transition":null}"#,
            )
            .await;
            assert!(request.is_empty());
        })
        .await
        .expect("abort preflight requests");
    });

    assert_eq!(
        begin_gateway_ceremony(state.clone(), GatewayGesture::Abort).await,
        Err(GatewayRefusal::NothingToAbort.to_string())
    );
    let status = state.operator.status().await.expect("failed ceremony");
    assert_eq!(status.gesture, GestureState::Failed);
    assert!(status.operation_id.is_none());
    assert!(pending(&domain.path, NOW)
        .expect("pending record")
        .is_none());
    assert_eq!(domain.touches(), 0);
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn chained_renewal_without_a_held_campaign_refuses_before_http() {
    let domain = domain();
    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(&domain, &gateway, gateway_key(), 1).await;
    let state = app.state::<AppState>();
    let terms = renewal_terms();
    let gesture = GatewayGesture::Renew {
        rotate_tls: terms.rotate_tls,
        key_recovery: terms.key_recovery,
        prepare_days: terms.prepare_days,
        overlap_days: terms.overlap_days,
        validity_days: terms.validity_days,
        in_chain: true,
    };

    let (result, contact) = tokio::join!(
        begin_gateway_ceremony(state.clone(), gesture),
        tokio::time::timeout(Duration::from_millis(250), gateway.accept()),
    );

    assert_eq!(
        result,
        Err("La campagne de l'étape n'est plus connue d'Orion : rouvrir l'étape après son échéance.".into())
    );
    assert!(contact.is_err(), "the gateway must receive no request");
    let status = state.operator.status().await.expect("failed ceremony");
    assert_eq!(status.gesture, GestureState::Failed);
    assert_eq!(status.refusal, Some(Refusal::ManifestMismatch));
    assert_eq!(domain.touches(), 0);
    engine.await.expect("engine requests");
}

#[tokio::test]
async fn forced_discard_uses_the_gateways_activation_clock() {
    let scenario = Scenario::new(false);
    let domain = &scenario.domain;
    let remote = Remote::new(&scenario);
    remote.publish_replies.borrow_mut().push_back(Err(409));
    let mut opened = open_renewal(&remote, &domain.path, renewal_terms().options(), NOW)
        .expect("fixture renewal");
    opened
        .approve(&domain.keys[0], NOW)
        .expect("fixture approval");
    let decision = opened
        .sign_and_record(&domain.path, NOW)
        .expect("fixture decision");
    let refusal =
        carry(&remote, &domain.path, decision, NOW).expect_err("fixture refuses the publication");
    assert!(matches!(refusal, GatewayRefusal::GatewayRefused(_)));
    let waiting = pending(&domain.path, NOW).expect("pending record");
    assert!(waiting.as_ref().is_some_and(|decision| {
        decision.deposited && decision.installed && decision.publication_refused.is_some()
    }));
    let touches = domain.touches();
    let vault_before = std::fs::read(&domain.path).expect("fixture vault");
    let activation = remote.installed.borrow()[0].window.activation_at;

    let gateway = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
    let (app, engine) = app_with_gateway(domain, &gateway, gateway_key(), 2).await;
    let state = app.state::<AppState>();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut view = identity_view();
            view["gateway_activation_at"] = json!(activation);
            view["gateway_transition_pending"] = json!(true);
            for clock in [activation - 1, activation] {
                view["now_unix"] = json!(clock);
                read_identity(&gateway, &view).await;
            }
        })
        .await
        .expect("forced discard status requests");
    });

    assert_eq!(
        begin_gateway_ceremony(state.clone(), GatewayGesture::Discard).await,
        Err("la décision est installée sur la gateway mais pas encore publiée : la reprendre pour la publier. Rien n'a été jeté.".into())
    );
    assert_eq!(pending(&domain.path, NOW).expect("pending record"), waiting);
    assert_eq!(
        begin_gateway_ceremony(state.clone(), GatewayGesture::ForceDiscard).await,
        Err("la transition s'annule encore : choisir « Annuler ». Rien n'a été jeté.".into())
    );
    assert_eq!(pending(&domain.path, NOW).expect("pending record"), waiting);
    assert_eq!(
        begin_gateway_ceremony(state.clone(), GatewayGesture::ForceDiscard).await,
        Ok(())
    );

    assert!(pending(&domain.path, NOW)
        .expect("pending record")
        .is_none());
    assert_eq!(
        std::fs::read(&domain.path).expect("vault after discard"),
        vault_before
    );
    assert_eq!(domain.touches(), touches);
    assert!(state.operator.status().await.is_none());
    server.await.expect("gateway requests");
    engine.await.expect("engine requests");
}
