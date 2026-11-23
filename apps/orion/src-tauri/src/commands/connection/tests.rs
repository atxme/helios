use super::*;
use crate::commands::test_support::scripted_engine;
use orion_engine::ConfigView;
use std::cell::Cell;
use std::time::Duration;

const PROFILE: &str = "workstation";

fn config_reply() -> EngineReply {
    EngineReply::Config(ConfigView {
        profiles: Vec::new(),
        selected: Some(PROFILE.into()),
        locked: Vec::new(),
        vault_error: None,
    })
}

#[tokio::test]
async fn connect_forwards_an_explicit_name_and_preserves_the_default_selection_request() {
    let (client, mut engine) = scripted_engine().await;
    for name in [Some(PROFILE.to_owned()), None] {
        let (result, ()) = tokio::join!(
            connect_from(&client, name.clone()),
            engine.reply(|command| {
                assert!(
                    matches!(command, EngineCommand::Connect { name: actual } if actual == name)
                );
                Ok(EngineReply::Unit)
            }),
        );
        assert_eq!(result, Ok(()));
    }
}

#[tokio::test]
async fn tray_selects_before_emitting_the_change_and_connecting_to_that_profile() {
    let (client, mut engine) = scripted_engine().await;
    let notified = Cell::new(false);
    let (result, ()) = tokio::join!(
        select_and_connect_from(&client, PROFILE, || notified.set(true)),
        async {
            engine
                .reply(|command| {
                    assert!(
                        matches!(command, EngineCommand::SelectProfile { name } if name == PROFILE)
                    );
                    assert!(!notified.get());
                    Ok(config_reply())
                })
                .await;
            engine.reply(|command| {
                assert!(matches!(command, EngineCommand::Connect { name: Some(name) } if name == PROFILE));
                assert!(notified.get(), "selection is reported before connecting");
                Ok(EngineReply::Unit)
            }).await;
        },
    );
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn tray_stops_before_connecting_when_profile_selection_fails() {
    let (client, mut engine) = scripted_engine().await;
    let notified = Cell::new(false);
    for (reply, expected) in [
        (
            Err("profile is locked".into()),
            "profile is locked".to_string(),
        ),
        (Ok(EngineReply::Unit), unexpected_engine_reply()),
    ] {
        let (result, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(3),
                select_and_connect_from(&client, PROFILE, || notified.set(true)),
            ),
            engine.reply(|command| {
                assert!(
                    matches!(command, EngineCommand::SelectProfile { name } if name == PROFILE)
                );
                reply
            }),
        );
        assert_eq!(
            result.expect("refusal completes before another command"),
            Err(expected)
        );
        assert!(!notified.get());
    }
}

#[tokio::test]
async fn tray_keeps_the_selection_notification_when_connect_is_refused() {
    let (client, mut engine) = scripted_engine().await;
    let notified = Cell::new(false);
    let (result, ()) = tokio::join!(
        select_and_connect_from(&client, PROFILE, || notified.set(true)),
        async {
            engine
                .reply(|command| {
                    assert!(
                        matches!(command, EngineCommand::SelectProfile { name } if name == PROFILE)
                    );
                    Ok(config_reply())
                })
                .await;
            engine.reply(|command| {
                assert!(matches!(command, EngineCommand::Connect { name: Some(name) } if name == PROFILE));
                Err("backend refused connection".into())
            }).await;
        },
    );
    assert_eq!(result, Err("backend refused connection".into()));
    assert!(notified.get());
}

#[tokio::test]
async fn disconnect_sends_the_stop_command_and_returns_backend_failures() {
    let (client, mut engine) = scripted_engine().await;
    for (reply, expected) in [
        (Ok(EngineReply::Unit), Ok(())),
        (
            Err("interface teardown failed".into()),
            Err("interface teardown failed".into()),
        ),
        (Ok(EngineReply::Flag(false)), Err(unexpected_engine_reply())),
    ] {
        let (result, ()) = tokio::join!(
            disconnect_from(&client),
            engine.reply(|command| {
                assert!(matches!(command, EngineCommand::Disconnect));
                reply
            }),
        );
        assert_eq!(result, expected);
    }
}

#[tokio::test]
async fn renew_psk_acknowledges_start_and_rejects_an_unrelated_reply() {
    let (client, mut engine) = scripted_engine().await;
    for (reply, expected) in [
        (Ok(EngineReply::Unit), Ok(())),
        (Ok(EngineReply::Flag(true)), Err(unexpected_engine_reply())),
        (
            Err("renewal cannot start".into()),
            Err("renewal cannot start".into()),
        ),
    ] {
        let (result, ()) = tokio::join!(
            renew_psk_from(&client),
            engine.reply(|command| {
                assert!(matches!(command, EngineCommand::RenewPsk));
                reply
            }),
        );
        assert_eq!(result, expected);
    }
}

#[cfg(not(windows))]
#[tokio::test]
async fn connection_command_surfaces_engine_refusals_and_unexpected_replies() {
    let (client, mut engine) = scripted_engine().await;
    let app = crate::commands::test_support::command_app(client);
    for (reply, expected) in [
        (
            Err("interface is unavailable".into()),
            "interface is unavailable".into(),
        ),
        (Ok(EngineReply::Flag(true)), unexpected_engine_reply()),
    ] {
        let (result, ()) = tokio::join!(
            connect(app.state(), Some(PROFILE.into())),
            engine.reply(|command| {
                assert!(matches!(
                    command,
                    EngineCommand::Connect { name: Some(name) } if name == PROFILE
                ));
                reply
            }),
        );
        assert_eq!(result, Err(expected));
    }

    let (result, ()) = tokio::join!(
        renew_psk(app.state()),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RenewPsk));
            Ok(EngineReply::Unit)
        }),
    );
    assert_eq!(result, Ok(()));
}
