use super::*;
use std::path::PathBuf;

const IMAGE: &str = r"C:\Program Files\Orion\orion.exe";
const CREATED: u64 = 133_500_000_000_000_000;

fn launcher(pid: u32, image: &str, created_at: u64) -> ObservedClient {
    ObservedClient {
        pid,
        image: PathBuf::from(image),
        created_at,
    }
}

fn expected() -> ExpectedClient {
    ExpectedClient {
        pid: 4242,
        image: PathBuf::from(IMAGE),
        created_at: CREATED,
    }
}

fn expected_with_created(created_at: u64) -> ExpectedClient {
    ExpectedClient {
        created_at,
        ..expected()
    }
}

#[test]
fn the_launching_ui_is_accepted() {
    let observed = launcher(4242, IMAGE, CREATED);
    assert_eq!(verify_client(&expected(), &observed), Ok(()));
}

#[test]
fn another_pid_is_refused() {
    let observed = launcher(4243, IMAGE, CREATED);
    assert_eq!(
        verify_client(&expected(), &observed),
        Err(ClientRefusal::OtherProcess)
    );
}

#[test]
fn another_image_is_refused() {
    let observed = launcher(4242, r"C:\Users\Public\tool.exe", CREATED);
    assert_eq!(
        verify_client(&expected(), &observed),
        Err(ClientRefusal::OtherImage)
    );
}

#[test]
fn the_same_image_in_another_case_is_accepted() {
    let observed = launcher(4242, r"c:\program files\orion\ORION.EXE", CREATED);
    assert_eq!(verify_client(&expected(), &observed), Ok(()));
}

#[test]
fn a_reused_pid_is_refused() {
    let later = launcher(4242, IMAGE, CREATED + 10_000_000);
    assert_eq!(
        verify_client(&expected(), &later),
        Err(ClientRefusal::ReusedPid)
    );
    let earlier = launcher(4242, IMAGE, CREATED - 10_000_000);
    assert_eq!(
        verify_client(&expected(), &earlier),
        Err(ClientRefusal::ReusedPid)
    );
}

#[test]
fn pipe_names_never_repeat() {
    let first = aether::random::secret_bytes::<16>().expect("randomness available");
    let second = aether::random::secret_bytes::<16>().expect("randomness available");
    assert_ne!(pipe_name(4242, &first), pipe_name(4242, &second));
}

#[test]
fn the_pipe_name_has_its_documented_shape() {
    assert_eq!(
        pipe_name(4242, &[0xab; 16]),
        format!(r"\\.\pipe\orion-engine-4242-{}", "ab".repeat(16))
    );
    assert_eq!(
        pipe_name(4242, &[0x0a; 16]),
        format!(r"\\.\pipe\orion-engine-4242-{}", "0a".repeat(16))
    );
}

#[test]
fn a_verbatim_prefix_does_not_change_the_image() {
    let plain = launcher(4242, IMAGE, CREATED);
    let verbatim = launcher(4242, r"\\?\C:\Program Files\Orion\orion.exe", CREATED);
    assert_eq!(verify_client(&expected(), &verbatim), Ok(()));
    let engine_verbatim = ExpectedClient {
        image: PathBuf::from(r"\\?\C:\Program Files\Orion\orion.exe"),
        ..expected()
    };
    assert_eq!(verify_client(&engine_verbatim, &plain), Ok(()));
    let launcher_expected = expected_from_launcher(
        launcher(4242, r"\\?\C:\Program Files\Orion\orion.exe", CREATED - 1),
        Path::new(IMAGE),
        CREATED,
    );
    assert!(launcher_expected.is_ok());
    let engine_expected = expected_from_launcher(
        launcher(4242, IMAGE, CREATED - 1),
        Path::new(r"\\?\C:\Program Files\Orion\orion.exe"),
        CREATED,
    );
    assert!(engine_expected.is_ok());
}

#[test]
fn a_launcher_started_after_the_engine_is_refused() {
    let same_moment = launcher(4242, IMAGE, CREATED);
    assert_eq!(
        expected_from_launcher(same_moment, Path::new(IMAGE), CREATED),
        Err(ClientRefusal::StartedAfterEngine)
    );
    let just_after = launcher(4242, IMAGE, CREATED + 1);
    assert_eq!(
        expected_from_launcher(just_after, Path::new(IMAGE), CREATED),
        Err(ClientRefusal::StartedAfterEngine)
    );
}

#[test]
fn a_launcher_with_another_image_is_refused() {
    let observed = launcher(4242, r"C:\Users\Public\tool.exe", CREATED - 1);
    assert_eq!(
        expected_from_launcher(observed, Path::new(IMAGE), CREATED),
        Err(ClientRefusal::OtherImage)
    );
}

#[test]
fn a_launcher_without_a_creation_time_is_refused() {
    let observed = launcher(4242, IMAGE, 0);
    assert_eq!(
        expected_from_launcher(observed, Path::new(IMAGE), CREATED),
        Err(ClientRefusal::ReusedPid)
    );
}

#[test]
fn the_launcher_becomes_the_expected_client() {
    let observed = launcher(4242, IMAGE, CREATED - 1);
    let expected = expected_from_launcher(observed, Path::new(IMAGE), CREATED)
        .expect("launcher started before the engine, same image");
    assert_eq!(expected, expected_with_created(CREATED - 1));
}

#[test]
fn a_lookalike_kelvin_sign_is_not_the_same_image() {
    assert!(!same_image(
        Path::new("c:\\x\\\u{212A}.exe"),
        Path::new("c:\\x\\k.exe")
    ));
}

#[test]
fn a_well_formed_sid_is_accepted() {
    assert!(is_plain_sid("S-1-5-18"));
    assert!(is_plain_sid("S-1-5-21-1-2-3-1001"));
}

#[test]
fn a_sid_with_sddl_syntax_is_refused() {
    assert!(!is_plain_sid("S-1-5-21-1)(A;;GA;;;WD"));
    assert!(!is_plain_sid(""));
    assert!(!is_plain_sid("1-5-21"));
}

#[test]
fn a_sid_with_an_empty_or_missing_segment_is_refused() {
    assert!(!is_plain_sid("S-"));
    assert!(!is_plain_sid("S--"));
    assert!(!is_plain_sid("S-1--2"));
    assert!(!is_plain_sid("S-1-5-"));
    assert!(!is_plain_sid("S-1"));
    assert!(!is_plain_sid("s-1-5-18"));
}
