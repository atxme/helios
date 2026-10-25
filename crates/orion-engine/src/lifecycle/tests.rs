use super::*;

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn token() -> SessionToken {
    SessionToken::generate().expect("session token")
}

fn full_engine_args(token: &str) -> Vec<String> {
    strings(&[
        "--engine",
        "--pipe",
        r"\\.\pipe\orion-engine-1",
        "--ui-pid",
        "4242",
        "--ui-created",
        "133000000000000000",
        "--token",
        token,
    ])
}

fn valid_token_text() -> String {
    "ab".repeat(32)
}

const ALL_EVENTS: [LifecycleEvent; 9] = [
    LifecycleEvent::ParentMissing,
    LifecycleEvent::ParentExited,
    LifecycleEvent::HelloRefused,
    LifecycleEvent::ClientRefused,
    LifecycleEvent::ClientLeft,
    LifecycleEvent::ShutdownRequested,
    LifecycleEvent::EventsOverflowed,
    LifecycleEvent::ChannelBroken,
    LifecycleEvent::ConnectTimeout,
];

#[test]
fn every_lifecycle_event_tears_down_and_exits() {
    for event in ALL_EVENTS {
        assert_eq!(on_event(event), Action::TeardownAndExit, "{event:?}");
    }
}

#[test]
fn only_a_requested_shutdown_exits_cleanly() {
    for event in ALL_EVENTS {
        let expected = if event == LifecycleEvent::ShutdownRequested {
            0
        } else {
            1
        };
        assert_eq!(exit_code(event), expected, "{event:?}");
    }
    assert_eq!(BAD_ARGUMENTS, 2);
}

#[test]
fn every_serve_outcome_maps_to_an_event() {
    use crate::serve::ServeOutcome;
    use crate::session::SessionRefusal;
    use crate::wire::WireError;

    let cases = [
        (ServeOutcome::ClientLeft, LifecycleEvent::ClientLeft),
        (
            ServeOutcome::ShutdownRequested,
            LifecycleEvent::ShutdownRequested,
        ),
        (
            ServeOutcome::Refused(SessionRefusal::WrongToken),
            LifecycleEvent::HelloRefused,
        ),
        (
            ServeOutcome::EventsOverflowed,
            LifecycleEvent::EventsOverflowed,
        ),
        (ServeOutcome::Stopped, LifecycleEvent::ParentExited),
        (
            ServeOutcome::Broken(WireError::Malformed),
            LifecycleEvent::ChannelBroken,
        ),
    ];
    for (outcome, expected) in &cases {
        assert_eq!(LifecycleEvent::from(outcome), *expected);
    }
}

#[test]
fn engine_args_need_every_field() {
    let token = valid_token_text();
    let full = full_engine_args(&token);
    assert!(EngineArgs::parse(&full).is_ok());
    for index in (1..full.len()).step_by(2) {
        let mut missing = full.clone();
        missing.drain(index..=index + 1);
        assert!(
            EngineArgs::parse(&missing).is_err(),
            "accepted without {}",
            full[index]
        );
    }
}

#[test]
fn engine_args_round_trip() {
    let token_text = valid_token_text();
    let parsed = EngineArgs::parse(&full_engine_args(&token_text))
        .expect("parses")
        .expect("engine mode");
    assert_eq!(parsed.pipe, r"\\.\pipe\orion-engine-1");
    assert_eq!(parsed.ui_pid, 4242);
    assert_eq!(parsed.ui_created_at, 133_000_000_000_000_000);
    assert_eq!(parsed.token.as_str(), token_text);

    let again = EngineArgs::parse(&parsed.to_args())
        .expect("reparses")
        .expect("engine mode");
    assert_eq!(again.pipe, parsed.pipe);
    assert_eq!(again.ui_pid, parsed.ui_pid);
    assert_eq!(again.ui_created_at, parsed.ui_created_at);
    assert_eq!(again.token.as_str(), parsed.token.as_str());
}

#[test]
fn engine_args_accept_the_options_in_any_order() {
    let token = valid_token_text();
    let shuffled = strings(&[
        "--engine",
        "--token",
        &token,
        "--ui-created",
        "7",
        "--ui-pid",
        "9",
        "--pipe",
        r"\\.\pipe\orion-engine-x",
    ]);
    let parsed = EngineArgs::parse(&shuffled)
        .expect("parses")
        .expect("engine mode");
    assert_eq!(parsed.ui_pid, 9);
    assert_eq!(parsed.ui_created_at, 7);
}

#[test]
fn no_engine_flag_is_ui_mode() {
    assert!(matches!(EngineArgs::parse(&[]), Ok(None)));
    let ui_args = strings(&["--pipe", "whatever", "--token"]);
    assert!(matches!(EngineArgs::parse(&ui_args), Ok(None)));
}

#[test]
fn an_unknown_argument_in_engine_mode_is_refused() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args.push("--verbose".to_owned());
    assert!(EngineArgs::parse(&args).is_err());
}

#[test]
fn a_repeated_option_is_refused() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args.extend(strings(&["--ui-pid", "5"]));
    assert!(EngineArgs::parse(&args).is_err());
}

#[test]
fn engine_must_come_first() {
    let token = valid_token_text();
    let mut late = strings(&["--ui-pid", "4"]);
    late.extend(full_engine_args(&token));
    let message = EngineArgs::parse(&late).expect_err("not first");
    assert_eq!(message, "`--engine` doit être le premier argument.");
    assert!(EngineArgs::parse(&strings(&["--pipe", "x", "--engine"])).is_err());
}

#[test]
fn a_foreign_pipe_name_is_refused() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args[2] = r"\\.\pipe\other-1".to_owned();
    assert!(EngineArgs::parse(&args).is_err());
}

#[test]
fn an_unreadable_number_is_refused() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args[4] = "-1".to_owned();
    assert!(EngineArgs::parse(&args).is_err());
}

#[test]
fn a_refusal_never_echoes_the_token() {
    let malformed = "Z".repeat(64);
    let valid = valid_token_text();
    let refusals = [
        ("malformed --token", {
            let mut args = full_engine_args(&malformed);
            args[8] = malformed.clone();
            args
        }),
        ("valid token as --pipe", {
            let mut args = full_engine_args(&valid);
            args[2] = valid.clone();
            args
        }),
        ("valid token as --ui-pid", {
            let mut args = full_engine_args(&valid);
            args[4] = valid.clone();
            args
        }),
        ("valid token as --ui-created", {
            let mut args = full_engine_args(&valid);
            args[6] = valid.clone();
            args
        }),
        ("valid token as an unknown option", {
            let mut args = full_engine_args(&valid);
            args.push(valid.clone());
            args
        }),
        ("valid token right after --engine", {
            let mut args = full_engine_args(&valid);
            args.insert(1, valid.clone());
            args
        }),
        ("valid token as the value of an unknown option", {
            let mut args = full_engine_args(&valid);
            args.extend(strings(&["--bogus", &valid]));
            args
        }),
        ("valid token repeated as --token", {
            let mut args = full_engine_args(&valid);
            args.extend(strings(&["--token", &valid]));
            args
        }),
    ];
    for (place, args) in &refusals {
        let message = EngineArgs::parse(args).expect_err(place);
        assert!(
            !message.contains(&valid) && !message.contains(&malformed),
            "{place}: {message}"
        );
    }
}

#[test]
fn a_number_must_be_plain_decimal() {
    let token = valid_token_text();
    for bad in ["+5", " 5", "5 ", "", "\u{0663}"] {
        for index in [4, 6] {
            let mut args = full_engine_args(&token);
            args[index] = bad.to_owned();
            assert!(
                EngineArgs::parse(&args).is_err(),
                "accepted {bad:?} at {index}"
            );
        }
    }
}

#[test]
fn a_number_out_of_range_is_refused() {
    let token = valid_token_text();
    let mut pid = full_engine_args(&token);
    pid[4] = "4294967296".to_owned();
    assert!(EngineArgs::parse(&pid).is_err());

    let mut created = full_engine_args(&token);
    created[6] = "18446744073709551616".to_owned();
    assert!(EngineArgs::parse(&created).is_err());
}

#[test]
fn zero_is_an_accepted_number() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args[4] = "0".to_owned();
    args[6] = "0".to_owned();
    let parsed = EngineArgs::parse(&args)
        .expect("parses")
        .expect("engine mode");
    assert_eq!(parsed.ui_pid, 0);
    assert_eq!(parsed.ui_created_at, 0);
}

#[test]
fn an_option_without_its_value_is_refused_in_last_place() {
    let token = valid_token_text();
    let full = full_engine_args(&token);
    for index in (1..full.len()).step_by(2) {
        let name = &full[index];
        let mut args = full[..index].to_vec();
        args.push(name.clone());
        let message = EngineArgs::parse(&args).expect_err(name);
        assert!(
            message.contains("valeur manquante") && message.contains(name.as_str()),
            "{message}"
        );
    }
}

#[test]
fn a_second_engine_flag_is_refused() {
    let token = valid_token_text();
    let mut args = full_engine_args(&token);
    args.insert(1, "--engine".to_owned());
    assert!(EngineArgs::parse(&args).is_err());
}

#[test]
fn a_repeated_pipe_or_creation_time_is_refused() {
    let token = valid_token_text();
    let mut pipe = full_engine_args(&token);
    pipe.extend(strings(&["--pipe", r"\\.\pipe\orion-engine-2"]));
    let message = EngineArgs::parse(&pipe).expect_err("repeated --pipe");
    assert!(message.contains("option répétée : --pipe"), "{message}");

    let mut created = full_engine_args(&token);
    created.extend(strings(&["--ui-created", "9"]));
    let message = EngineArgs::parse(&created).expect_err("repeated --ui-created");
    assert!(
        message.contains("option répétée : --ui-created"),
        "{message}"
    );
}

#[test]
fn the_token_never_appears_in_debug_output() {
    let token = token();
    let secret = token.as_str().to_owned();
    let args = EngineArgs {
        pipe: r"\\.\pipe\orion-engine-1".to_owned(),
        ui_pid: 1,
        ui_created_at: 2,
        token,
    };
    assert!(!format!("{args:?}").contains(&secret));
}

#[test]
fn a_parent_gone_before_the_engine_starts_stops_it() {
    assert!(!parent_matches(5, None));
    assert!(!parent_matches(5, Some(6)));
    assert!(parent_matches(5, Some(5)));
}

#[test]
fn the_connect_timeout_is_ten_seconds() {
    assert_eq!(CONNECT_TIMEOUT, std::time::Duration::from_secs(10));
}
