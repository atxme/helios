#![cfg(target_os = "linux")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helios-installer-integration-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir_all(path.join("tmp")).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn archive(&self, name: &str, entries: &[&str]) -> PathBuf {
        let archive = self.0.join(name);
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(self.0.join("payload"))
            .args(entries)
            .status()
            .unwrap();
        assert!(status.success(), "fixture archive creation failed");
        archive
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_helios-installer"))
            .args(args)
            .current_dir(self.path())
            .env("TMPDIR", self.0.join("tmp"))
            .env("HELIOS_UPDATE_STAGING", self.0.join("staging"))
            .env("HELIOS_INSTALL_ROOT", self.0.join("releases"))
            .env("HELIOS_CURRENT_LINK", self.0.join("current"))
            .env("HELIOS_READY_PATH", self.0.join("ready"))
            .env("HELIOS_LIBEXEC_DIR", self.0.join("libexec"))
            .env("HELIOS_BIN_DIR", self.0.join("bin"))
            .env("HELIOS_SYSTEMD_DIR", self.0.join("systemd"))
            .env("HELIOS_NETWORK_CONFIG", self.0.join("network.toml"))
            .output()
            .unwrap()
    }

    fn assert_refused(&self, args: &[&str], diagnostic: &str) {
        let output = self.run(args);
        let actual = Self::diagnostic(&output);
        assert!(!output.status.success(), "command unexpectedly succeeded");
        assert!(
            actual.contains(diagnostic),
            "expected {diagnostic:?} in diagnostic: {actual}"
        );
    }

    fn diagnostic(output: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bootstrap_without_source_reports_cli_preflight_error() {
    let fixture = Fixture::new();
    fixture.assert_refused(
        &["bootstrap"],
        "provide --archive <file.tar.gz> or --dir <directory>",
    );
}

#[test]
fn bootstrap_directory_without_manifest_is_refused_before_installation() {
    let fixture = Fixture::new();
    let empty = fixture.path().join("empty-bundle");
    fs::create_dir(&empty).unwrap();

    fixture.assert_refused(
        &["bootstrap", "--dir", empty.to_str().unwrap()],
        "manifest missing or unreadable",
    );
}

#[test]
fn bootstrap_archive_failures_report_the_rejected_input() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path().join("payload/first")).unwrap();
    fs::create_dir_all(fixture.path().join("payload/second")).unwrap();
    fs::write(fixture.path().join("payload/first/manifest.json"), b"{}").unwrap();
    fs::write(fixture.path().join("payload/second/manifest.json"), b"{}").unwrap();
    fs::write(fixture.path().join("payload/root-file"), b"not a directory").unwrap();

    let multiple = fixture.archive("multiple.tar.gz", &["first", "second"]);
    fixture.assert_refused(
        &["bootstrap", "--archive", multiple.to_str().unwrap()],
        "a single root directory is expected, 2 entry(ies) found",
    );

    let file_root = fixture.archive("file-root.tar.gz", &["root-file"]);
    fixture.assert_refused(
        &["bootstrap", "--archive", file_root.to_str().unwrap()],
        "a single root directory is expected, 1 entry(ies) found",
    );

    let invalid = fixture.path().join("invalid.tar.gz");
    fs::write(&invalid, b"not a gzip archive").unwrap();
    fixture.assert_refused(
        &["bootstrap", "--archive", invalid.to_str().unwrap()],
        "extraction of",
    );

    let missing = fixture.path().join("missing.tar.gz");
    fixture.assert_refused(
        &["bootstrap", "--archive", missing.to_str().unwrap()],
        "not found",
    );
}
