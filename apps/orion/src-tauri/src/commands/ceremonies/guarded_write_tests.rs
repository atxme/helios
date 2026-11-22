use super::{guarded_operator_write, CEREMONY_OPEN};
use aether::certificates::operator_session::{
    GestureState, OperationKind, OperatorStatus, RemoteState,
};

fn open_status() -> OperatorStatus {
    OperatorStatus::new(
        aether::certificates::encoding::Id16::new([3; 16]).expect("session id"),
        1,
        OperationKind::AddKey,
        RemoteState::AwaitingOperator,
        GestureState::Verifying,
    )
}

#[test]
fn an_open_ceremony_stops_keyless_writes_before_the_write_closure() {
    let path = std::env::temp_dir().join(format!(
        "orion-guarded-write-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_file(&path);
    let status = open_status();

    let result = guarded_operator_write(Some(&status), || {
        std::fs::write(&path, b"must not be written").map_err(|error| error.to_string())
    });

    assert_eq!(result, Err(CEREMONY_OPEN.to_string()));
    assert!(!path.exists());
}

#[test]
fn with_no_open_ceremony_a_keyless_write_runs() {
    let path = std::env::temp_dir().join(format!(
        "orion-guarded-write-allowed-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    guarded_operator_write(None, || {
        std::fs::write(&path, b"public relay data").map_err(|error| error.to_string())
    })
    .expect("write allowed");

    assert_eq!(
        std::fs::read(&path).expect("write occurred"),
        b"public relay data"
    );
    let _ = std::fs::remove_file(path);
}
