use super::{init_logging, open_log_file, FileWriter};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("orion-logging-tests-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn opening_a_log_truncates_the_previous_run() {
    let dir = TestDir::new();
    let path = dir.path().join("orion.log");
    std::fs::write(&path, b"old run that must disappear").expect("seed previous log");

    let mut writer = open_log_file(&path).expect("open log");
    writer.write_all(b"new run\n").expect("write current run");
    writer.flush().expect("flush current run");

    assert_eq!(std::fs::read(path).expect("read log"), b"new run\n");
}

#[test]
fn cloned_writers_share_the_file_and_flush() {
    let dir = TestDir::new();
    let path = dir.path().join("nested/orion.log");
    let mut first = open_log_file(&path).expect("create parent and log");
    let mut second: FileWriter = first.clone();

    first.write_all(b"first ").expect("first write");
    second.write_all(b"second\n").expect("cloned writer write");
    second.flush().expect("flush cloned writer");

    assert_eq!(
        std::fs::read(path).expect("read shared log"),
        b"first second\n"
    );
}

#[test]
fn an_unusable_log_path_is_reported_as_unavailable() {
    let dir = TestDir::new();
    // File::create cannot replace a directory with a file.
    assert!(open_log_file(dir.path()).is_none());
}

#[test]
fn logging_initialization_writes_to_stdout_and_file_with_the_env_filter() {
    const CHILD: &str = "ORION_LOGGING_TEST_CHILD";
    const INFO: &str = "orion_logging_filter_info_marker";
    const WARN: &str = "orion_logging_filter_warn_marker";

    if std::env::var_os(CHILD).is_some() {
        let path = PathBuf::from(std::env::var_os("ORION_LOGGING_TEST_PATH").expect("log path"));
        assert_eq!(init_logging(Some(path.clone())), Some(path));
        tracing::info!("{INFO}");
        tracing::warn!("{WARN}");
        return;
    }

    let dir = TestDir::new();
    let path = dir.path().join("orion.log");
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "logging_tests::logging_initialization_writes_to_stdout_and_file_with_the_env_filter",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("ORION_LOGGING_TEST_PATH", &path)
        .env("RUST_LOG", "warn")
        .output()
        .expect("run isolated logging child");

    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let file = std::fs::read_to_string(path).expect("read initialized log");
    assert!(stdout.contains(WARN), "stdout missed warning: {stdout}");
    assert!(file.contains(WARN), "file missed warning: {file}");
    assert!(!stdout.contains(INFO), "stdout ignored RUST_LOG=warn");
    assert!(!file.contains(INFO), "file ignored RUST_LOG=warn");
}

#[test]
fn logging_still_outputs_when_the_file_cannot_be_created() {
    const CHILD: &str = "ORION_LOGGING_FALLBACK_CHILD";
    const MARKER: &str = "orion_logging_stdout_fallback_marker";

    if let Some(path) = std::env::var_os(CHILD) {
        assert_eq!(init_logging(Some(PathBuf::from(path))), None);
        tracing::info!("{MARKER}");
        return;
    }

    let dir = TestDir::new();
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "logging_tests::logging_still_outputs_when_the_file_cannot_be_created",
            "--nocapture",
        ])
        .env(CHILD, dir.path())
        .env_remove("RUST_LOG")
        .output()
        .expect("run isolated logging child");

    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(MARKER));
}
