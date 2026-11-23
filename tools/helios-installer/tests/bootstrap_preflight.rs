#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use aether::sig::{BinaryReleasePayload, BundlePayload, PublisherSigner};
use helios_update::{bundle, ActivationRequest, UpdateLayout, UpdateState};

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
        let fixture = Self(path);
        fixture.stub_systemctl();
        fixture
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
        self.run_with_fault(args, "")
    }

    fn run_with_fault(&self, args: &[&str], fault: &str) -> Output {
        let commands = self.0.join("commands");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let path =
            std::env::join_paths(std::iter::once(commands).chain(std::env::split_paths(&path)))
                .unwrap();
        Command::new(env!("CARGO_BIN_EXE_helios-installer"))
            .env("PATH", path)
            .env("HELIOS_FIXTURE_ROOT", &self.0)
            .env("HELIOS_FIXTURE_FAULT", fault)
            .env("HELIOS_SERVICE_NAME", "fixture-helios.service")
            .env("HELIOS_UPDATE_CHANNEL", "testing")
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

#[test]
fn install_pending_refuses_missing_and_malformed_requests_without_switching() {
    let fixture = Fixture::new();
    fixture.assert_refused(&["install-pending"], "reading activation");

    let staging = fixture.path().join("staging");
    fs::create_dir(&staging).unwrap();
    let request = staging.join("activate.json");
    fs::write(&request, b"not an activation request").unwrap();
    fixture.assert_refused(&["install-pending"], "reading activation");
    assert_eq!(fs::read(request).unwrap(), b"not an activation request");
    assert!(!fixture.path().join("current").exists());
}

#[test]
fn install_pending_refuses_an_unstaged_release_before_consuming_the_request() {
    let fixture = Fixture::new();
    let staging = fixture.path().join("staging");
    fs::create_dir(&staging).unwrap();
    let request = staging.join("activate.json");
    let body = br#"{"release_sequence":42,"requested_at_unix":0,"delay_seconds":0}"#;
    fs::write(&request, body).unwrap();

    fixture.assert_refused(&["install-pending"], "preparing the atomic switch");
    assert_eq!(fs::read(request).unwrap(), body);
    assert!(!fixture.path().join("current").exists());
}

const UPDATE_SEQUENCE: u64 = 42;
const PREVIOUS_SEQUENCE: u64 = 41;
const NEW_VERSION: &str = "2.0.0";
const OLD_VERSION: &str = "1.9.0";

fn development_signer() -> PublisherSigner {
    PublisherSigner::from_seed_material(
        1,
        b"helios-sign-ed25519-dev-seed-001",
        b"helios-sign-mldsa65-dev-seed-001",
    )
    .unwrap()
}

fn fake_elf() -> Vec<u8> {
    let machine: u16 = match helios_update::BUILD_TARGET.split('-').next().unwrap() {
        "x86_64" => 62,
        "aarch64" => 183,
        "riscv64" => 243,
        target => panic!("unsupported installer fixture target {target}"),
    };
    let mut binary = vec![0; 64];
    binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
    binary[18..20].copy_from_slice(&machine.to_le_bytes());
    binary
}

impl Fixture {
    fn switch_fixture(&self) -> UpdateLayout {
        let layout = UpdateLayout {
            staging_root: self.0.join("staging"),
            install_root: self.0.join("releases"),
            current_link: self.0.join("current"),
            state_path: self.0.join("staging/state.json"),
            activation_path: self.0.join("staging/activate.json"),
            ready_path: self.0.join("ready"),
            channel: "testing".into(),
            target: helios_update::BUILD_TARGET.into(),
        };
        let previous = layout.install_root.join(PREVIOUS_SEQUENCE.to_string());
        fs::create_dir_all(&previous).unwrap();
        fs::write(previous.join("heliosd"), b"previous release fixture").unwrap();
        symlink(previous, &layout.current_link).unwrap();

        let staged = layout.staged_dir(UPDATE_SEQUENCE);
        fs::create_dir_all(&staged).unwrap();
        let bytes = fake_elf();
        let binary = staged.join("heliosd");
        fs::write(&binary, &bytes).unwrap();
        let signed = development_signer()
            .sign(BinaryReleasePayload {
                product: "heliosd".into(),
                channel: layout.channel.clone(),
                release_sequence: UPDATE_SEQUENCE,
                version: NEW_VERSION.into(),
                git_commit: "0123456789abcdef".into(),
                target: layout.target.clone(),
                features: Vec::new(),
                binary_size: bytes.len() as u64,
                sha256: helios_update::sha256_file(&binary).unwrap(),
                minimum_installer_version: helios_update::INSTALLER_VERSION,
            })
            .unwrap();
        fs::write(
            staged.join("manifest.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        self.write_state(PREVIOUS_SEQUENCE, OLD_VERSION);
        fs::write(
            &layout.activation_path,
            serde_json::to_vec(&ActivationRequest {
                release_sequence: UPDATE_SEQUENCE,
                requested_at_unix: 0,
                delay_seconds: 0,
            })
            .unwrap(),
        )
        .unwrap();

        // Even an apparently valid but old marker must be removed before
        // asking the stub to restart the service.
        fs::write(&layout.ready_path, "version=2.0.0\nmode_reel=true\n").unwrap();
        layout
    }

    fn write_state(&self, sequence: u64, version: &str) {
        let state = UpdateState {
            highest_confirmed_sequence: sequence,
            active_version: Some(version.into()),
        };
        fs::write(
            self.0.join("staging/state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
    }

    fn assert_state(&self, sequence: u64, version: &str) {
        let state: UpdateState =
            serde_json::from_slice(&fs::read(self.0.join("staging/state.json")).unwrap()).unwrap();
        assert_eq!(
            state,
            UpdateState {
                highest_confirmed_sequence: sequence,
                active_version: Some(version.into()),
            }
        );
        assert_eq!(
            fs::read_link(self.0.join("current")).unwrap(),
            self.0.join("releases").join(sequence.to_string())
        );
    }

    fn stub_systemctl(&self) {
        let bin = self.0.join("commands");
        fs::create_dir(&bin).unwrap();
        let stub = bin.join("systemctl");
        fs::write(
            &stub,
            br#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HELIOS_FIXTURE_ROOT/systemctl.log"
if [ "$*" = 'daemon-reload' ]; then
    [ "$HELIOS_FIXTURE_FAULT" != reload ] || exit 7
    exit 0
fi
[ "$*" = 'restart fixture-helios.service' ] || exit 8
[ ! -e "$HELIOS_READY_PATH" ] || exit 9
if [ "$HELIOS_CURRENT_LINK/heliosd" -ef "$HELIOS_INSTALL_ROOT/42/heliosd" ]; then
    [ -f "$HELIOS_UPDATE_STAGING/activate.json" ] || exit 10
    [ "$HELIOS_FIXTURE_FAULT" != restart ] || exit 7
    [ "$HELIOS_FIXTURE_FAULT" != restart-and-rollback ] || exit 7
    printf 'version=2.0.0\nmode_reel=true\n' > "$HELIOS_READY_PATH"
else
    [ "$HELIOS_CURRENT_LINK/heliosd" -ef "$HELIOS_INSTALL_ROOT/41/heliosd" ] || exit 11
    [ ! -e "$HELIOS_UPDATE_STAGING/activate.json" ] || exit 12
    [ "$HELIOS_FIXTURE_FAULT" != restart-and-rollback ] || exit 6
    printf 'version=1.9.0\nmode_reel=true\n' > "$HELIOS_READY_PATH"
fi
"#,
        )
        .unwrap();
        fs::set_permissions(stub, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.0.join("systemctl.log")).unwrap()
    }
}

#[test]
fn install_pending_confirms_a_signed_release_after_verified_readiness() {
    let fixture = Fixture::new();
    let layout = fixture.switch_fixture();

    let output = fixture.run_with_fault(&["install-pending"], "");
    let diagnostic = Fixture::diagnostic(&output);
    assert!(output.status.success(), "{diagnostic}");
    assert!(diagnostic.contains("heliosd 2.0.0 sequence 42 confirmed"));
    fixture.assert_state(UPDATE_SEQUENCE, NEW_VERSION);
    assert!(!layout.activation_path.exists());
    assert_eq!(fixture.calls(), "restart fixture-helios.service\n");
    assert_eq!(
        fs::read(layout.current_link.join("heliosd")).unwrap(),
        fake_elf()
    );
}

#[test]
fn install_pending_restores_the_old_release_when_the_new_service_cannot_restart() {
    let fixture = Fixture::new();
    let layout = fixture.switch_fixture();

    let output = fixture.run_with_fault(&["install-pending"], "restart");
    let diagnostic = Fixture::diagnostic(&output);
    assert!(!output.status.success(), "{diagnostic}");
    assert!(
        diagnostic.contains("systemctl restart fixture-helios.service failed"),
        "{diagnostic}"
    );
    fixture.assert_state(PREVIOUS_SEQUENCE, OLD_VERSION);
    assert!(!layout.activation_path.exists());
    assert_eq!(
        fixture.calls(),
        "restart fixture-helios.service\n".repeat(2)
    );
    assert_eq!(
        fs::read_to_string(layout.ready_path).unwrap(),
        "version=1.9.0\nmode_reel=true\n"
    );
}

#[test]
fn install_pending_consumes_a_request_even_when_restored_service_cannot_restart() {
    let fixture = Fixture::new();
    let layout = fixture.switch_fixture();

    let output = fixture.run_with_fault(&["install-pending"], "restart-and-rollback");
    let diagnostic = Fixture::diagnostic(&output);
    assert!(!output.status.success(), "{diagnostic}");
    assert!(diagnostic.contains("rollback of the previous binary"));
    assert!(diagnostic.contains("exit status: 7"), "{diagnostic}");
    assert!(diagnostic.contains("exit status: 6"), "{diagnostic}");
    fixture.assert_state(PREVIOUS_SEQUENCE, OLD_VERSION);
    assert!(!layout.activation_path.exists());
    assert!(!layout.ready_path.exists());
    assert_eq!(
        fixture.calls(),
        "restart fixture-helios.service\n".repeat(2)
    );
}

#[test]
fn bootstrap_archive_keeps_configuration_and_reports_a_failed_unit_reload() {
    let fixture = Fixture::new();
    let bundle = fixture.0.join("payload/signed");
    fs::create_dir_all(bundle.join("systemd")).unwrap();
    for (name, content) in [
        ("heliosd", fake_elf()),
        ("helios", b"tool fixture".to_vec()),
        ("helios-installer", b"installer fixture".to_vec()),
        ("systemd/heliosd.service", b"unit fixture".to_vec()),
        ("network.toml.example", b"example configuration".to_vec()),
    ] {
        fs::write(bundle.join(name), content).unwrap();
    }
    let signed = development_signer()
        .sign(BundlePayload {
            product: bundle::BUNDLE_PRODUCT.into(),
            channel: "testing".into(),
            release_sequence: UPDATE_SEQUENCE,
            version: NEW_VERSION.into(),
            git_commit: "0123456789abcdef".into(),
            target: helios_update::BUILD_TARGET.into(),
            minimum_installer_version: helios_update::INSTALLER_VERSION,
            files: bundle::collect(&bundle).unwrap(),
        })
        .unwrap();
    fs::write(
        bundle.join(bundle::BUNDLE_MANIFEST_FILE),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    let archive = fixture.archive("signed.tar.gz", &["signed"]);
    fs::create_dir(fixture.0.join("bin")).unwrap();
    fs::write(fixture.0.join("bin/helios-ctl"), b"legacy fixture").unwrap();
    fs::write(fixture.0.join("network.toml"), b"existing configuration").unwrap();

    let output = fixture.run_with_fault(
        &["bootstrap", "--archive", archive.to_str().unwrap()],
        "reload",
    );
    let diagnostic = Fixture::diagnostic(&output);
    assert!(output.status.success(), "{diagnostic}");
    for expected in [
        "helios 2.0.0 sequence 42 installed (channel testing)",
        "network.toml kept as is",
        "helios-ctl removed (replaced by helios)",
        "WARNING: systemd units were not reloaded",
        "Next, with console access:",
    ] {
        assert!(diagnostic.contains(expected), "{expected}: {diagnostic}");
    }
    fixture.assert_state(UPDATE_SEQUENCE, NEW_VERSION);
    assert_eq!(
        fs::read(fixture.0.join("network.toml")).unwrap(),
        b"existing configuration"
    );
    assert_eq!(
        fs::read(fixture.0.join("systemd/heliosd.service")).unwrap(),
        b"unit fixture"
    );
    assert!(!fixture.0.join("bin/helios-ctl").exists());
    assert_eq!(fixture.calls(), "daemon-reload\n");
    assert_eq!(fs::read_dir(fixture.0.join("tmp")).unwrap().count(), 0);
}
