use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

fn signer(vault: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astra-signer"));
    command.arg("--vault").arg(vault).stdin(Stdio::null());
    command
}

fn assert_refusal(command: &mut Command, expected: &str) {
    let output = command.output().expect("run signer");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "command succeeded: {command:?}");
    assert!(
        stderr.contains(expected),
        "{command:?}: expected {expected:?} in {stderr}"
    );
    assert!(output.stdout.is_empty(), "{command:?} printed a result");
}

fn assert_nothing_to_resume(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("aucune rotation préparée"));
}

#[test]
fn list_resolves_the_vault_from_the_environment_and_cli_override() {
    let directory = tempfile::tempdir().expect("test directory");
    let env_vault = directory.path().join("env-vault.json");
    fs::write(&env_vault, b"not a vault").expect("corrupt vault fixture");

    let mut from_env = Command::new(env!("CARGO_BIN_EXE_astra-signer"));
    from_env.env("ASTRA_VAULT", &env_vault).arg("list");
    assert_refusal(&mut from_env, "lecture du coffre");

    let override_vault = directory.path().join("override-vault.json");
    assert_refusal(
        signer(&override_vault)
            .env("ASTRA_VAULT", &env_vault)
            .arg("list"),
        "aucun coffre d'autorité",
    );
    assert_eq!(fs::read(&env_vault).expect("read vault"), b"not a vault");
    assert!(!override_vault.exists());
}

#[test]
fn local_vault_operations_reject_corrupt_state_without_writing() {
    let directory = tempfile::tempdir().expect("test directory");
    let vault = directory.path().join("authority-vault.json");
    fs::write(&vault, b"not a vault").expect("corrupt vault fixture");

    for args in [
        &["domain", "--server-name", "gateway.example.test"][..],
        &[
            "rename",
            "--slot",
            "01010101010101010101010101010101",
            "--label",
            "backup",
        ],
        &["issue-ca-tls", "--days", "30"],
    ] {
        assert_refusal(signer(&vault).args(args), "lecture du coffre");
        assert_eq!(fs::read(&vault).expect("read vault"), b"not a vault");
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("list directory")
                .count(),
            1
        );
    }
}

#[test]
fn resume_rotation_requires_one_transport() {
    let directory = tempfile::tempdir().expect("test directory");
    let vault = directory.path().join("authority-vault.json");

    assert_refusal(signer(&vault).arg("resume-rotation"), "aucun transport");
    assert_refusal(
        signer(&vault).args([
            "resume-rotation",
            "--authority-url",
            "https://astra.example.test",
            "--heliosd-url",
            "http://127.0.0.1:8080",
        ]),
        "cannot be used with",
    );
    assert_refusal(
        signer(&vault).args(["resume-rotation", "--heliosd-url", "127.0.0.1:8080"]),
        "doit commencer par http:// ou https://",
    );
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list directory")
            .count(),
        0
    );
}

#[test]
fn resume_rotation_without_a_prepared_record_is_a_noop_for_either_transport() {
    let directory = tempfile::tempdir().expect("test directory");
    let vault = directory.path().join("authority-vault.json");

    for (option, url) in [
        ("--authority-url", "https://astra.example.test"),
        ("--heliosd-url", "http://127.0.0.1:8080"),
    ] {
        assert_nothing_to_resume(
            signer(&vault)
                .args(["resume-rotation", option, url])
                .output()
                .expect("run signer"),
        );
    }
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list directory")
            .count(),
        0
    );
}
