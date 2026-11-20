use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Waker};
use std::time::Duration;

use orion_core::backend::{dryrun::DryRunBackend, EventSink};
use orion_core::{CertificateFacts, CertificatePhase, ClientEvent, ClientProfile, VpnController};
use tokio::sync::mpsc;

use super::super::{run_automatic_certificate_renewal, RenewalProgress};

const PROFILE: &str = "bureau";
const RENEWAL_AT: u64 = 1_080;
const NOT_AFTER: u64 = 1_100;

fn certificate(phase: CertificatePhase) -> CertificateFacts {
    CertificateFacts {
        subject: "CN=test".into(),
        issuer: "CN=fixture CA".into(),
        fingerprint: "aa".repeat(32),
        not_before: 1_000,
        not_after: NOT_AFTER,
        renewal_at: RENEWAL_AT,
        phase,
    }
}

fn controller() -> VpnController {
    let mut backend = DryRunBackend::default();
    backend.negotiate_delay = Duration::ZERO;
    VpnController::new(Arc::new(backend))
}

fn event_sink() -> (EventSink, mpsc::UnboundedReceiver<ClientEvent>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (
        Arc::new(move |event| {
            let _ = sender.send(event);
        }),
        receiver,
    )
}

async fn mount(controller: &VpnController, name: &str) {
    let (sink, mut events) = event_sink();
    let pair = aether::wg::generate_keypair().expect("fixture WireGuard key pair");
    controller
        .connect(
            ClientProfile {
                name: name.into(),
                endpoint: "203.0.113.10:51820".into(),
                private_key: pair.private_key,
                peer_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                ..ClientProfile::default()
            },
            sink,
        )
        .await;

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let event = events.recv().await.expect("dry-run connection event");
            if matches!(
                event,
                ClientEvent::StateChanged {
                    state: aether::TunnelState::Up
                }
            ) {
                break;
            }
        }
    })
    .await
    .expect("dry-run connection reaches Up");
}

async fn disconnect(controller: &VpnController) {
    controller
        .disconnect(Arc::new(|_| {}))
        .await
        .expect("dry-run disconnect");
}

fn assert_pending(task: Pin<&mut impl Future<Output = ()>>) {
    assert!(task
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}

fn assert_log(
    events: &mut mpsc::UnboundedReceiver<ClientEvent>,
    expected_level: &str,
    details: &[&str],
) {
    let ClientEvent::Log { level, message } = events.try_recv().expect("renewal log event") else {
        panic!("expected a user-visible renewal log");
    };
    assert_eq!(level, expected_level);
    assert!(message.contains(PROFILE), "{message}");
    for detail in details {
        assert!(message.contains(detail), "{message}");
    }
    assert!(events.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_waits_until_the_local_threshold() {
    let controller = controller();
    mount(&controller, PROFILE).await;
    let (sink, mut events) = event_sink();
    let started = tokio::time::Instant::now();
    let mut renewal = pin!(run_automatic_certificate_renewal(
        &controller,
        PROFILE,
        Some(certificate(CertificatePhase::Valid)),
        RENEWAL_AT - 10,
        &sink,
        async {
            assert_eq!(started.elapsed(), Duration::from_secs(10));
            Ok(RenewalProgress::Committed { generation: 17 })
        },
    ));
    assert_pending(renewal.as_mut());
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_pending(renewal.as_mut());
    assert!(events.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    renewal.await;
    assert_log(
        &mut events,
        "info",
        &["renouvelés automatiquement", "génération 17"],
    );
    disconnect(&controller).await;
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_never_runs_for_the_profile_replaced_during_the_wait() {
    let controller = controller();
    mount(&controller, PROFILE).await;
    let (sink, mut events) = event_sink();
    let mut renewal = pin!(run_automatic_certificate_renewal(
        &controller,
        PROFILE,
        Some(certificate(CertificatePhase::Valid)),
        RENEWAL_AT - 10,
        &sink,
        async { panic!("renewing on a different mounted profile") },
    ));
    assert_pending(renewal.as_mut());
    mount(&controller, "autre profil").await;
    assert_eq!(
        controller.mounted_profile().await.as_deref(),
        Some("autre profil")
    );
    renewal.await;
    assert!(events.try_recv().is_err());
    disconnect(&controller).await;
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_skips_a_disconnected_profile_or_missing_certificate() {
    let controller = controller();
    let (sink, mut events) = event_sink();
    run_automatic_certificate_renewal(
        &controller,
        PROFILE,
        Some(certificate(CertificatePhase::RenewalDue)),
        RENEWAL_AT,
        &sink,
        async { panic!("renewing without a tunnel") },
    )
    .await;

    mount(&controller, PROFILE).await;
    run_automatic_certificate_renewal(&controller, PROFILE, None, RENEWAL_AT, &sink, async {
        panic!("renewing without a client certificate")
    })
    .await;
    assert!(events.try_recv().is_err());
    disconnect(&controller).await;
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_routes_an_expired_identity_to_recovery() {
    let controller = controller();
    mount(&controller, PROFILE).await;
    let (sink, mut events) = event_sink();
    run_automatic_certificate_renewal(
        &controller,
        PROFILE,
        Some(certificate(CertificatePhase::Expired)),
        NOT_AFTER + 1,
        &sink,
        async { panic!("ordinary renewal requires a certificate that has not expired") },
    )
    .await;
    assert_log(&mut events, "warn", &["expiré", "récupération YubiKey"]);
    disconnect(&controller).await;
}

#[tokio::test(start_paused = true)]
async fn automatic_renewal_reports_pending_or_failed_attempts_without_a_delay_after_threshold() {
    let controller = controller();
    mount(&controller, PROFILE).await;
    let (sink, mut events) = event_sink();
    for (outcome, detail) in [
        (
            Ok(RenewalProgress::Issuing {
                operation_id: "fixture".into(),
            }),
            "incomplet",
        ),
        (
            Err("Astra indisponible".to_owned()),
            "impossible : Astra indisponible",
        ),
    ] {
        let started = tokio::time::Instant::now();
        run_automatic_certificate_renewal(
            &controller,
            PROFILE,
            Some(certificate(CertificatePhase::RenewalDue)),
            RENEWAL_AT + 1,
            &sink,
            async {
                assert_eq!(started.elapsed(), Duration::ZERO);
                outcome
            },
        )
        .await;
        assert_log(&mut events, "warn", &[detail, "prochaine connexion"]);
    }
    disconnect(&controller).await;
}
