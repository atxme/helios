//! Process-level startup refusals that must happen before daemon services start.

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn run_dev(directory: &Path, config: &str) -> Output {
    let network_config = directory.join("network.toml");
    fs::write(&network_config, config).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_heliosd"))
        .args(["run", "--dev"])
        .env("HELIOS_NETWORK_CONFIG", &network_config)
        .env("HELIOS_UPDATE_STAGING", directory.join("updates"))
        .env("HELIOS_UPDATE_CHANNEL", "daemon-lifecycle-test")
        .env(
            "HELIOS_CERTIFICATE_REGISTRY",
            directory.join("certificate-registry.json"),
        )
        .env("HELIOS_ADMIN_SOCKET", directory.join("admin.sock"))
        .env("RUST_LOG", "info,tss_esapi=warn")
        .env("HELIOS_READY_PATH", directory.join("ready"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run isolated heliosd process");
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().expect("poll heliosd").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("reap heliosd");
            panic!(
                "invalid configuration did not stop startup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("collect heliosd output")
}

fn assert_startup_refused(directory: &Path, config: &str, expected: &[&str]) {
    let output = run_dev(directory, config);
    assert!(
        !output.status.success(),
        "invalid configuration must stop startup"
    );
    assert!(output.stdout.is_empty());
    for name in ["ready", "admin.sock", "certificate-registry.json"] {
        assert!(!directory.join(name).exists(), "startup created {name}");
    }
    assert_eq!(
        fs::read_to_string(directory.join("network.toml")).unwrap(),
        config
    );
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    for message in expected {
        assert!(
            diagnostics.contains(message),
            "missing {message:?} in {diagnostics}"
        );
    }
}

#[test]
fn dev_start_refuses_an_uncompilable_policy_before_opening_services() {
    let directory = tempfile::tempdir().unwrap();
    assert_startup_refused(
        directory.path(),
        "wan_iface = \"wan-test\"\nsplit_tunnel_cidrs = [\"10.0.0.0/33\"]\n",
        &["10.0.0.0/33", "firewall policy does not compile"],
    );
}

#[test]
fn dev_start_refuses_invalid_toml_during_migration_and_invalid_types_during_load() {
    let syntax = tempfile::tempdir().unwrap();
    assert_startup_refused(
        syntax.path(),
        "wan_iface = [\"wan-test\"\n",
        &[
            "migrating the legacy classic key-negotiation floors",
            "TOML parse error",
        ],
    );

    let typed = tempfile::tempdir().unwrap();
    assert_startup_refused(
        typed.path(),
        "wan_iface = 12\n",
        &["loading the network config", "wan_iface"],
    );
}
