use super::*;
use orion_core::speedtest::SpeedTestPhase;

#[tokio::test]
async fn engine_events_route_progress_separately_without_reordering_frames() {
    let (send, receive) = tokio::sync::mpsc::channel(5);
    let progress = SpeedTestProgress {
        phase: SpeedTestPhase::TcpDownload,
        fraction: 0.5,
        current_mbps: 12.0,
        bytes: 4096,
        elapsed_ms: 100,
        message: "fixture progress".into(),
        latency_ms: Some(14.5),
    };
    for event in [
        ClientEvent::ConfigChanged,
        ClientEvent::SpeedTest {
            progress: progress.clone(),
        },
        ClientEvent::log("warn", "fixture log"),
    ] {
        send.send(event).await.unwrap();
    }
    drop(send);

    let expected = serde_json::to_value(&progress).unwrap();
    let emitted = std::cell::RefCell::new(Vec::new());
    forward_engine_events(
        receive,
        |event| {
            emitted
                .borrow_mut()
                .push(("general", serde_json::to_value(event).unwrap()))
        },
        |progress| {
            emitted
                .borrow_mut()
                .push(("speedtest", serde_json::to_value(progress).unwrap()))
        },
    )
    .await;
    assert_eq!(
        emitted.into_inner(),
        [
            ("general", serde_json::json!({"type":"config_changed"})),
            ("speedtest", expected),
            (
                "general",
                serde_json::json!({"type":"log", "level":"warn", "message":"fixture log"})
            ),
        ]
    );
}

#[tokio::test]
async fn an_open_ipc_session_does_not_report_loss_until_the_transport_closes() {
    use crate::commands::test_support::scripted_engine;

    let (client, mut engine) = scripted_engine().await;
    let report = std::cell::Cell::new(0);
    let watch = on_engine_session_closed(&client, || report.set(report.get() + 1));
    tokio::pin!(watch);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(watch.as_mut(), &mut context).is_pending());

    let (reply, ()) = tokio::join!(
        client.call(EngineCommand::GetState),
        engine.reply(|request| {
            assert!(matches!(request, EngineCommand::GetState));
            Ok(orion_engine::EngineReply::State("down".into()))
        })
    );
    assert!(matches!(reply, Ok(orion_engine::EngineReply::State(state)) if state == "down"));
    assert_eq!(report.get(), 0);
    assert!(std::future::Future::poll(watch.as_mut(), &mut context).is_pending());

    drop(engine);
    tokio::time::timeout(std::time::Duration::from_secs(3), watch)
        .await
        .expect("IPC close reaches the shell");
    assert_eq!(report.get(), 1);
}
