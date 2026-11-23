use std::{collections::HashSet, fs, path::Path, process::Command};

use aether::sig::{ResealRequest, SignedResealTicket, WireGuardRecoveryPayload};

fn publisher() -> Command {
    Command::new(env!("CARGO_BIN_EXE_helios-publisher"))
}

#[test]
fn full_cycle_produces_a_hybrid_ticket_and_refuses_any_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let keys = root.path().join("cles");

    let keygen = publisher()
        .args(["keygen", "--key-epoch", "9", "--output-dir"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for secret in ["ed25519-private.pk8", "ml-dsa-65-private.bin"] {
            assert_eq!(
                fs::metadata(keys.join(secret))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    let request = root.path().join("reseal-request.json");
    fs::write(
        &request,
        serde_json::to_vec(&ResealRequest {
            counter: 42,
            sealed_blob_anchor: [0; 32],
        })
        .unwrap(),
    )
    .unwrap();
    let ticket = root.path().join("reseal-ticket.json");
    let sign = publisher()
        .args(["reseal-ticket", "--request"])
        .arg(&request)
        .args(["--key-epoch", "9", "--ed25519-private-key"])
        .arg(keys.join("ed25519-private.pk8"))
        .arg("--ml-dsa-65-private-key")
        .arg(keys.join("ml-dsa-65-private.bin"))
        .arg("--keyring")
        .arg(keys.join("publisher-keyring.json"))
        .arg("--output")
        .arg(&ticket)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&fs::read(&ticket).unwrap()).unwrap();
    assert_eq!(json["key_epoch"], 9);
    assert_eq!(json["payload"]["counter"], 42);
    assert!(json["payload"]["expected_pcr_digest"].is_null());
    let algorithms: HashSet<_> = json["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["alg"].as_str().unwrap())
        .collect();
    assert_eq!(algorithms, HashSet::from(["ed25519", "ml-dsa-65"]));

    // Neither the keys nor the tickets must be silently overwritten.
    let overwrite_ticket = publisher()
        .args(["reseal-ticket", "--request"])
        .arg(&request)
        .args(["--key-epoch", "9", "--ed25519-private-key"])
        .arg(keys.join("ed25519-private.pk8"))
        .arg("--ml-dsa-65-private-key")
        .arg(keys.join("ml-dsa-65-private.bin"))
        .arg("--keyring")
        .arg(keys.join("publisher-keyring.json"))
        .arg("--output")
        .arg(&ticket)
        .output()
        .unwrap();
    assert!(!overwrite_ticket.status.success());

    let overwrite_keys = publisher()
        .args(["keygen", "--key-epoch", "10", "--output-dir"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(!overwrite_keys.status.success());
}

#[test]
fn security_arguments_reject_zero_and_malformed_pcr_digest() {
    let zero = publisher()
        .args(["keygen", "--key-epoch", "0", "--output-dir", "unused"])
        .output()
        .unwrap();
    assert!(!zero.status.success());
    assert!(String::from_utf8_lossy(&zero.stderr).contains("must be > 0"));

    let malformed = publisher()
        .args([
            "reseal-ticket",
            "--request",
            "request.json",
            "--key-epoch",
            "1",
            "--expected-pcr-digest",
            "abcd",
            "--ed25519-private-key",
            "ed",
            "--ml-dsa-65-private-key",
            "ml",
            "--keyring",
            "keyring",
            "--output",
            "ticket",
        ])
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("bytes instead of 32"));
}

#[test]
fn binary_manifest_signs_exactly_the_provided_bytes() {
    let root = tempfile::tempdir().unwrap();
    let keys = root.path().join("cles");
    assert!(publisher()
        .args(["keygen", "--key-epoch", "11", "--output-dir"])
        .arg(&keys)
        .status()
        .unwrap()
        .success());
    let binary = root.path().join("heliosd");
    let mut elf = vec![0u8; 64];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    fs::write(&binary, elf).unwrap();
    let manifest = root.path().join("heliosd.release.json");
    let output = publisher()
        .args([
            "binary-release",
            "--key-epoch",
            "11",
            "--release-sequence",
            "73",
            "--channel",
            "testing",
            "--version",
            "1.4.0",
            "--git-commit",
            "0123456789abcdef",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--features",
            "wireguard,embed-ui,netlink",
            "--binary",
        ])
        .arg(&binary)
        .arg("--ed25519-private-key")
        .arg(keys.join("ed25519-private.pk8"))
        .arg("--ml-dsa-65-private-key")
        .arg(keys.join("ml-dsa-65-private.bin"))
        .arg("--keyring")
        .arg(keys.join("publisher-keyring.json"))
        .arg("--output")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(json["payload"]["release_sequence"], 73);
    assert_eq!(
        json["payload"]["binary_size"],
        fs::metadata(binary).unwrap().len()
    );
    assert_eq!(
        json["payload"]["features"],
        serde_json::json!(["embed-ui", "netlink", "wireguard"])
    );
    assert_eq!(json["signatures"].as_array().unwrap().len(), 2);
}

#[test]
fn firmware_recovery_command_signs_the_exact_public_request_and_refuses_overwrite() {
    use aether::sig::{FirmwareRecoveryPayload, SignedFirmwareRecovery};
    let root = tempfile::tempdir().unwrap();
    let keys = root.path().join("keys");
    assert!(publisher()
        .args(["keygen", "--key-epoch", "9", "--output-dir"])
        .arg(&keys)
        .output()
        .unwrap()
        .status
        .success());
    let request_path = root.path().join("request.json");
    let output = root.path().join("authorization.json");
    let request = FirmwareRecoveryPayload {
        counter: 4,
        sealed_blob_anchor: [1; 32],
        secret_commitment: [2; 32],
        device_id: "5bc922b7bd1adb5b6f99592611404036bd9f42d0".into(),
        target_version: "2023".into(),
    };
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    let sign = || {
        publisher()
            .args(["firmware-recovery", "--key-epoch", "9", "--request"])
            .arg(&request_path)
            .arg("--ed25519-private-key")
            .arg(keys.join("ed25519-private.pk8"))
            .arg("--ml-dsa-65-private-key")
            .arg(keys.join("ml-dsa-65-private.bin"))
            .arg("--keyring")
            .arg(keys.join("publisher-keyring.json"))
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = sign();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let auth: SignedFirmwareRecovery = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(auth.payload, request);
    assert_eq!(auth.key_epoch, 9);
    assert_eq!(
        auth.signatures
            .iter()
            .map(|sig| sig.alg.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from(["ed25519", "ml-dsa-65"])
    );
    assert!(!sign().status.success());
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn generate_keys(root: &Path, epoch: &str) -> std::path::PathBuf {
    let keys = root.join("keys");
    assert!(publisher()
        .args(["keygen", "--key-epoch", epoch, "--output-dir"])
        .arg(&keys)
        .output()
        .unwrap()
        .status
        .success());
    keys
}

#[test]
fn reseal_ticket_signs_the_prepared_request() {
    let root = tempfile::tempdir().unwrap();
    let keys = generate_keys(root.path(), "9");
    let request_path = root.path().join("request.json");
    let output = root.path().join("ticket.json");
    write_json(
        &request_path,
        &ResealRequest {
            counter: 7,
            sealed_blob_anchor: [3; 32],
        },
    );
    let sign = publisher()
        .args(["reseal-ticket", "--request"])
        .arg(&request_path)
        .args([
            "--expected-pcr-digest",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "--key-epoch",
            "9",
            "--ed25519-private-key",
        ])
        .arg(keys.join("ed25519-private.pk8"))
        .arg("--ml-dsa-65-private-key")
        .arg(keys.join("ml-dsa-65-private.bin"))
        .arg("--keyring")
        .arg(keys.join("publisher-keyring.json"))
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let ticket: SignedResealTicket = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(ticket.payload.counter, 7);
    assert_eq!(ticket.payload.sealed_blob_anchor, [3; 32]);
    assert_eq!(ticket.payload.expected_pcr_digest, Some([0x44; 32]));
    assert_eq!(ticket.key_epoch, 9);
}

#[test]
fn reseal_ticket_refuses_a_request_with_unknown_fields() {
    let root = tempfile::tempdir().unwrap();
    let keys = generate_keys(root.path(), "9");
    let request_path = root.path().join("request.json");
    let output = root.path().join("ticket.json");
    fs::write(
        &request_path,
        format!(
            r#"{{"counter":7,"sealed_blob_anchor":"{}","version":7}}"#,
            "03".repeat(32)
        ),
    )
    .unwrap();
    let sign = publisher()
        .args(["reseal-ticket", "--request"])
        .arg(&request_path)
        .args(["--key-epoch", "9", "--ed25519-private-key"])
        .arg(keys.join("ed25519-private.pk8"))
        .arg("--ml-dsa-65-private-key")
        .arg(keys.join("ml-dsa-65-private.bin"))
        .arg("--keyring")
        .arg(keys.join("publisher-keyring.json"))
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!sign.status.success());
    assert!(String::from_utf8_lossy(&sign.stderr).contains("invalid reseal request"));
    assert!(!output.exists());
}

#[test]
fn wg_recovery_command_signs_the_exact_public_request_and_refuses_overwrite() {
    use aether::sig::SignedWireGuardRecovery;
    let root = tempfile::tempdir().unwrap();
    let keys = generate_keys(root.path(), "9");
    let request_path = root.path().join("request.json");
    let output = root.path().join("authorization.json");
    let request = WireGuardRecoveryPayload {
        counter: 5,
        gateway_public_key: [9; 32],
        expected_pcr_digest: Some([8; 32]),
    };
    write_json(&request_path, &request);
    let sign = || {
        publisher()
            .args(["wg-recovery", "--key-epoch", "9", "--request"])
            .arg(&request_path)
            .arg("--ed25519-private-key")
            .arg(keys.join("ed25519-private.pk8"))
            .arg("--ml-dsa-65-private-key")
            .arg(keys.join("ml-dsa-65-private.bin"))
            .arg("--keyring")
            .arg(keys.join("publisher-keyring.json"))
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = sign();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let auth: SignedWireGuardRecovery =
        serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(auth.payload, request);
    assert_eq!(auth.key_epoch, 9);
    assert_eq!(
        auth.signatures
            .iter()
            .map(|sig| sig.alg.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from(["ed25519", "ml-dsa-65"])
    );
    assert!(!sign().status.success());
}

struct ReleaseFixture {
    root: tempfile::TempDir,
    keys: std::path::PathBuf,
    bundle: std::path::PathBuf,
}

impl ReleaseFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let keys = generate_keys(root.path(), "11");
        let bundle = root.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        Self { root, keys, bundle }
    }

    fn write_daemon(&self, machine: u16) {
        let mut binary = vec![0u8; 64];
        binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
        binary[18..20].copy_from_slice(&machine.to_le_bytes());
        fs::write(self.bundle.join("heliosd"), binary).unwrap();
    }

    fn release(&self, kind: &str, version: &str, keyring: &Path) -> Command {
        let mut command = publisher();
        command
            .args([
                kind,
                "--key-epoch",
                "11",
                "--release-sequence",
                "73",
                "--channel",
                "testing",
                "--version",
                version,
                "--git-commit",
                "0123456789abcdef",
                "--target",
                "x86_64-unknown-linux-gnu",
            ])
            .arg("--ed25519-private-key")
            .arg(self.keys.join("ed25519-private.pk8"))
            .arg("--ml-dsa-65-private-key")
            .arg(self.keys.join("ml-dsa-65-private.bin"))
            .arg("--keyring")
            .arg(keyring);
        command
    }

    fn bundle(&self, version: &str, keyring: &Path) -> Command {
        let mut command = self.release("bundle", version, keyring);
        command.arg("--dir").arg(&self.bundle);
        command
    }

    fn keyring(&self) -> std::path::PathBuf {
        self.keys.join("publisher-keyring.json")
    }

    fn assert_refused(mut command: Command, expected: &str) {
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn bundle_command_signs_the_manifest_of_every_staged_file_and_preserves_it() {
    use aether::sig::PublisherPublicKeys;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use helios_update::bundle;

    let fixture = ReleaseFixture::new();
    fixture.write_daemon(62);
    fs::create_dir(fixture.bundle.join("systemd")).unwrap();
    fs::write(
        fixture.bundle.join("systemd/heliosd.service"),
        b"unit fixture",
    )
    .unwrap();
    let keyring = fixture.keyring();
    let output = fixture.bundle("1.4.0", &keyring).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("bundle 1.4.0 sequence 73, 2 file(s)"));

    let manifest = bundle::read_manifest(&fixture.bundle).unwrap();
    let keys: serde_json::Value = serde_json::from_slice(&fs::read(&keyring).unwrap()).unwrap();
    let keys = &keys[0];
    manifest
        .verify(&[PublisherPublicKeys {
            key_epoch: 11,
            ed25519: STANDARD
                .decode(keys["ed25519"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            ml_dsa_65: STANDARD
                .decode(keys["ml-dsa-65"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        }])
        .unwrap();
    bundle::verify_contents(&fixture.bundle, &manifest.payload).unwrap();
    assert_eq!(manifest.payload.release_sequence, 73);
    assert_eq!(
        manifest
            .payload
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        ["heliosd", "systemd/heliosd.service"]
    );
    for entry in &manifest.payload.files {
        assert!(stdout.contains(&format!("{} {}", hex::encode(entry.sha256), entry.path)));
    }
    let path = fixture.bundle.join(bundle::BUNDLE_MANIFEST_FILE);
    let signed = fs::read(&path).unwrap();
    ReleaseFixture::assert_refused(fixture.bundle("1.4.1", &keyring), "manifest.json");
    assert_eq!(fs::read(&path).unwrap(), signed);
}

#[test]
fn signing_requires_consistent_artifacts_and_complete_metadata() {
    let fixture = ReleaseFixture::new();
    let keyring = fixture.keyring();
    let binary = fixture.bundle.join("heliosd");
    let manifest = fixture.root.path().join("release.json");
    let release = |version| {
        let mut command = fixture.release("binary-release", version, &keyring);
        command
            .arg("--binary")
            .arg(&binary)
            .arg("--output")
            .arg(&manifest);
        command
    };
    ReleaseFixture::assert_refused(fixture.bundle("", &keyring), "version, commit, and target");
    ReleaseFixture::assert_refused(
        fixture.bundle("1.4.0", &keyring),
        "always contains the daemon",
    );
    ReleaseFixture::assert_refused(release(""), "version, commit, and target");
    ReleaseFixture::assert_refused(release("1.4.0"), "reading metadata");
    fs::write(&binary, []).unwrap();
    ReleaseFixture::assert_refused(release("1.4.0"), "binary size out of bounds");
    fixture.write_daemon(183);
    ReleaseFixture::assert_refused(fixture.bundle("1.4.0", &keyring), "ELF architecture 183");
    ReleaseFixture::assert_refused(release("1.4.0"), "ELF architecture 183");
    fixture.write_daemon(62);
    let mut empty_feature = release("1.4.0");
    empty_feature.args(["--features", " "]);
    ReleaseFixture::assert_refused(empty_feature, "empty feature is not allowed");

    assert!(!manifest.exists());
    assert!(!fixture
        .bundle
        .join(helios_update::bundle::BUNDLE_MANIFEST_FILE)
        .exists());
}

#[test]
fn bundle_signer_only_uses_a_unique_matching_publisher_keyring() {
    let fixture = ReleaseFixture::new();
    fixture.write_daemon(62);
    let published: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.keyring()).unwrap()).unwrap();
    let authorized = published[0].clone();
    let cases = [
        (serde_json::json!([]), "public keyring is empty"),
        (
            serde_json::json!([authorized, authorized]),
            "epoch 11 duplicated",
        ),
        (
            serde_json::json!([{"key_epoch": 11, "ed25519": "!", "ml-dsa-65": ""}]),
            "invalid base64 Ed25519",
        ),
        (
            serde_json::json!([{"key_epoch": 11, "ed25519": "AQ==", "ml-dsa-65": ""}]),
            "Ed25519 public key of 1 bytes instead of 32",
        ),
    ];
    let keyring = fixture.root.path().join("candidate-keyring.json");
    for (value, expected) in cases {
        write_json(&keyring, &value);
        ReleaseFixture::assert_refused(fixture.bundle("1.4.0", &keyring), expected);
    }
    let mut other_epoch = published;
    other_epoch[0]["key_epoch"] = serde_json::json!(12);
    write_json(&keyring, &other_epoch);
    ReleaseFixture::assert_refused(fixture.bundle("1.4.0", &keyring), "epoch 11 missing");
    let another = tempfile::tempdir().unwrap();
    let foreign = generate_keys(another.path(), "11").join("publisher-keyring.json");
    ReleaseFixture::assert_refused(
        fixture.bundle("1.4.0", &foreign),
        "private keys do not match epoch 11",
    );
    assert!(!fixture
        .bundle
        .join(helios_update::bundle::BUNDLE_MANIFEST_FILE)
        .exists());
}
