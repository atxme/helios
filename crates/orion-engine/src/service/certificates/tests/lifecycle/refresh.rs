use super::*;

use orion_core::trust_update::TrustUpdateOutcome;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

fn events() -> (EventSink, mpsc::UnboundedReceiver<ClientEvent>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let sink = Arc::new(move |event| {
        let _ = sender.send(event);
    });
    (sink, receiver)
}

#[tokio::test]
async fn a_trust_refresh_refusal_is_reported_without_attempting_network_access() {
    let (sink, mut events) = events();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());

    tokio::time::timeout(
        Duration::from_secs(3),
        spawn_trust_refresh(key_negotiation(" "), url, sink),
    )
    .await
    .expect("trust refresh completes")
    .expect("refresh task does not panic");
    let ClientEvent::Log { level, message } = events.try_recv().expect("refusal event") else {
        panic!("expected a user-visible trust refresh log");
    };
    assert_eq!(level, "warn");
    assert!(message.contains("aucune identité protégée"));
    assert!(message.contains("tunnel n'est pas affecté"));
    assert!(events.try_recv().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn trust_refresh_reports_signed_changes_once_and_keeps_current_state_quiet() {
    let (sink, mut events) = events();
    report_trust_refresh(Ok(TrustUpdateOutcome::UpToDate), &sink);
    assert!(events.try_recv().is_err());

    report_trust_refresh(Ok(TrustUpdateOutcome::Applied { objects: 3 }), &sink);
    let ClientEvent::Log { level, message } = events.try_recv().expect("applied event") else {
        panic!("expected a user-visible trust refresh log");
    };
    assert_eq!(level, "info");
    assert!(message.contains("3 objet(s) signé(s) appliqué(s)"));
    assert!(events.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_waits_for_refresh_before_inspecting_the_profile() {
    let scratch = Scratch::new("automatic-refresh-prerequisite");
    let service = service(&scratch);
    let (sink, mut events) = events();
    let (ready, prerequisite) = oneshot::channel();
    let refresh = tokio::spawn(async move {
        prerequisite.await.expect("refresh fixture is released");
    });

    let mut renewal = spawn_automatic_certificate_renewal(
        refresh,
        Arc::clone(&service.controller),
        Arc::clone(&service.renewals),
        "detached".into(),
        key_negotiation(""),
        "http://127.0.0.1:0".into(),
        sink,
    );
    assert!(tokio::time::timeout(Duration::from_secs(1), &mut renewal)
        .await
        .is_err());
    assert!(events.try_recv().is_err());

    ready.send(()).unwrap();
    renewal.await.expect("renewal task completes");
    assert!(service.renewals.lock().await.is_empty());
    assert!(events.try_recv().is_err());
}
