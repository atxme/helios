use super::*;
#[cfg(not(windows))]
use crate::commands::test_support::command_app;
use crate::commands::test_support::scripted_engine;
use orion_core::{SpeedTestMode, SpeedTestResult};

#[cfg(not(windows))]
#[tokio::test]
async fn state_backed_application_commands_dispatch_through_tauri_state() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);

    let (state, ()) = tokio::join!(
        get_state(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::GetState));
            Ok(EngineReply::State("up".into()))
        }),
    );
    assert_eq!(state.as_deref(), Ok("up"));

    let (backend, ()) = tokio::join!(
        backend_kind(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::BackendKind));
            Ok(EngineReply::Backend("wireguard".into()))
        }),
    );
    assert_eq!(backend.as_deref(), Ok("wireguard"));

    let (adapter, ()) = tokio::join!(
        adapter_is_up(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AdapterIsUp));
            Ok(EngineReply::Flag(true))
        }),
    );
    assert_eq!(adapter, Ok(true));

    let (about, ()) = tokio::join!(
        about_orion(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AboutOrion));
            Ok(EngineReply::About(AboutView {
                version: "4.8.12".into(),
                backend: "wireguard".into(),
                profile_extension: "orion".into(),
                log_path: None,
            }))
        }),
    );
    assert_eq!(about.expect("about command result").version, "4.8.12");

    let (support, ()) = tokio::join!(
        key_negotiation_support(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::KeyNegotiationSupport));
            Ok(EngineReply::KeyNegotiation(KeyNegotiationSupport {
                identity_store: true,
            }))
        }),
    );
    assert!(support.expect("support command result").identity_store);

    let (speedtest, ()) = tokio::join!(
        run_speed_test(app.state(), "udp".into()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RunSpeedTest { mode } if mode == "udp"));
            Ok(EngineReply::Unit)
        }),
    );
    assert!(matches!(speedtest, Err(error) if error == unexpected_engine_reply()));
    drop(app);
}

#[tokio::test]
async fn a_failed_tunnel_can_still_have_its_adapter_mounted() {
    let (client, mut engine) = scripted_engine().await;
    let (state, ()) = tokio::join!(
        get_state_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::GetState));
            Ok(EngineReply::State("failed".into()))
        }),
    );
    assert_eq!(state.as_deref(), Ok("failed"));

    let (mounted, ()) = tokio::join!(
        adapter_is_up_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AdapterIsUp));
            Ok(EngineReply::Flag(true))
        }),
    );
    assert_eq!(mounted, Ok(true));
}

#[tokio::test]
async fn application_diagnostics_report_the_backend_and_the_missing_protected_store() {
    let (client, mut engine) = scripted_engine().await;
    let (backend, ()) = tokio::join!(
        backend_kind_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::BackendKind));
            Ok(EngineReply::Backend("dry-run".into()))
        }),
    );
    assert_eq!(backend.as_deref(), Ok("dry-run"));

    let (support, ()) = tokio::join!(
        key_negotiation_support_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::KeyNegotiationSupport));
            Ok(EngineReply::KeyNegotiation(KeyNegotiationSupport {
                identity_store: false,
            }))
        }),
    );
    assert!(!support.expect("capability report").identity_store);
}

#[tokio::test]
async fn about_preserves_version_backend_file_extension_and_log_location() {
    let (client, mut engine) = scripted_engine().await;
    let (about, ()) = tokio::join!(
        about_orion_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AboutOrion));
            Ok(EngineReply::About(AboutView {
                version: "4.8.12".into(),
                backend: "dry-run".into(),
                profile_extension: "orion".into(),
                log_path: Some("orion-fixture.log".into()),
            }))
        }),
    );
    let about = about.expect("about report");
    assert_eq!(about.version, "4.8.12");
    assert_eq!(about.backend, "dry-run");
    assert_eq!(about.profile_extension, "orion");
    assert_eq!(about.log_path.as_deref(), Some("orion-fixture.log"));
}

#[tokio::test]
async fn speed_test_forwards_the_mode_and_keeps_the_optional_transport_measurements() {
    let expected = SpeedTestResult {
        latency_ms: 6.0,
        jitter_ms: 0.25,
        latency_p95_ms: 7.0,
        download_mbps: 42.0,
        upload_mbps: 24.0,
        download_variation_pct: 1.0,
        upload_variation_pct: 2.0,
        duration_ms: 4_000,
        download_bytes: 21_000_000,
        upload_bytes: 12_000_000,
        parallel_streams: 1,
        measurement_rounds: 1,
        mode: SpeedTestMode::Udp,
        tcp_download_mbps: None,
        tcp_upload_mbps: None,
        udp_download_mbps: Some(42.0),
        udp_upload_mbps: Some(24.0),
        udp_loss_pct: Some(0.25),
        udp_jitter_ms: Some(0.5),
        tcp_streams: 0,
        test_duration_secs: 4,
    };
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(
        run_speed_test_from(&client, "udp".into()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RunSpeedTest { mode } if mode == "udp"));
            Ok(EngineReply::SpeedTest(expected.clone()))
        }),
    );
    assert_eq!(result, Ok(expected));
}

#[tokio::test]
async fn a_backend_label_is_not_accepted_as_a_tunnel_state() {
    let (client, mut engine) = scripted_engine().await;
    let (state, ()) = tokio::join!(
        get_state_from(&client),
        engine.reply(|_| Ok(EngineReply::Backend("dry-run".into()))),
    );
    assert_eq!(state, Err(unexpected_engine_reply()));
}

#[tokio::test]
async fn application_diagnostics_reject_unrelated_replies_and_preserve_engine_errors() {
    let (client, mut engine) = scripted_engine().await;

    let (backend, ()) = tokio::join!(
        backend_kind_from(&client),
        engine.reply(|_| Ok(EngineReply::Flag(false))),
    );
    assert_eq!(backend, Err(unexpected_engine_reply()));

    let (adapter, ()) = tokio::join!(
        adapter_is_up_from(&client),
        engine.reply(|_| Ok(EngineReply::Backend("kernel".into()))),
    );
    assert_eq!(adapter, Err(unexpected_engine_reply()));

    let (about, ()) = tokio::join!(
        about_orion_from(&client),
        engine.reply(|_| Ok(EngineReply::Unit)),
    );
    assert!(matches!(about, Err(error) if error == unexpected_engine_reply()));

    let (support, ()) = tokio::join!(
        key_negotiation_support_from(&client),
        engine.reply(|_| Ok(EngineReply::Backend("kernel".into()))),
    );
    assert!(matches!(support, Err(error) if error == unexpected_engine_reply()));

    const ENGINE_ERROR: &str = "diagnostics unavailable";
    let (state, ()) = tokio::join!(
        get_state_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::GetState));
            Err(ENGINE_ERROR.into())
        }),
    );
    assert_eq!(state, Err(ENGINE_ERROR.into()));

    let (backend, ()) = tokio::join!(
        backend_kind_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::BackendKind));
            Err(ENGINE_ERROR.into())
        }),
    );
    assert_eq!(backend, Err(ENGINE_ERROR.into()));

    let (adapter, ()) = tokio::join!(
        adapter_is_up_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AdapterIsUp));
            Err(ENGINE_ERROR.into())
        }),
    );
    assert_eq!(adapter, Err(ENGINE_ERROR.into()));

    let (about, ()) = tokio::join!(
        about_orion_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::AboutOrion));
            Err(ENGINE_ERROR.into())
        }),
    );
    assert!(matches!(about, Err(error) if error == ENGINE_ERROR));

    let (support, ()) = tokio::join!(
        key_negotiation_support_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::KeyNegotiationSupport));
            Err(ENGINE_ERROR.into())
        }),
    );
    assert!(matches!(support, Err(error) if error == ENGINE_ERROR));
}

#[tokio::test]
async fn speed_test_rejects_an_unrelated_reply_and_preserves_engine_errors() {
    let (client, mut engine) = scripted_engine().await;

    let (wrong, ()) = tokio::join!(
        run_speed_test_from(&client, "full".into()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RunSpeedTest { mode } if mode == "full"));
            Ok(EngineReply::Unit)
        }),
    );
    assert_eq!(wrong, Err(unexpected_engine_reply()));

    let (failed, ()) = tokio::join!(
        run_speed_test_from(&client, "invalid".into()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RunSpeedTest { mode } if mode == "invalid"));
            Err("unsupported speed test mode".into())
        }),
    );
    assert_eq!(failed, Err("unsupported speed test mode".into()));
}

#[tokio::test]
async fn a_speed_test_refusal_is_delivered_without_a_result() {
    let (client, mut engine) = scripted_engine().await;
    const REFUSAL: &str = "Aucun tunnel actif pour mesurer le débit.";
    let (result, ()) = tokio::join!(
        run_speed_test_from(&client, "full".into()),
        engine.reply(|_| Err(REFUSAL.into())),
    );
    assert_eq!(result, Err(REFUSAL.into()));
}
