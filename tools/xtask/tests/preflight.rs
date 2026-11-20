//! Exercise preflight failures using the actual CLI and no external build tools.

use std::process::{Command, Output};

fn xtask(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(arguments)
        .env("PATH", "")
        .env_remove("HELIOS_PUBLISHER_KEYRING_PATH")
        .output()
        .expect("run xtask preflight")
}

#[test]
fn app_and_bundle_require_a_publisher_keyring_before_building() {
    for command in ["app", "bundle"] {
        let output = xtask(&[
            command,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--skip-frontend",
        ]);
        assert!(
            !output.status.success(),
            "{command} started without a keyring"
        );
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(
                "HELIOS_PUBLISHER_KEYRING_PATH must point to the publisher's public keyring"
            ),
            "{command}: {error}"
        );
    }
}

#[cfg(not(windows))]
#[test]
fn msi_command_refuses_to_build_outside_windows_even_with_an_unsigned_request() {
    let output = xtask(&["orion-msi", "--unsigned", "--skip-npm-ci"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("an MSI can only be built on Windows"),
        "{error}"
    );
}
