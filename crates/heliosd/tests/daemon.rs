//! Process-level startup refusals that must happen before daemon services start.

use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn dev_start_refuses_an_uncompilable_policy_before_opening_services() {
    let directory = tempfile::tempdir().unwrap();
    let network_config = directory.path().join("network.toml");
    fs::write(
        &network_config,
        "wan_iface = \"wan-test\"\nsplit_tunnel_cidrs = [\"10.0.0.0/33\"]\n",
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_heliosd"))
        .args(["run", "--dev"])
        .env("HELIOS_NETWORK_CONFIG", &network_config)
        .env("HELIOS_UPDATE_STAGING", directory.path().join("updates"))
        .env("HELIOS_UPDATE_CHANNEL", "daemon-lifecycle-test")
        .env(
            "HELIOS_CERTIFICATE_REGISTRY",
            directory.path().join("certificate-registry.json"),
        )
        .env("HELIOS_ADMIN_SOCKET", directory.path().join("admin.sock"))
        .env("RUST_LOG", "info,tss_esapi=warn")
        .env("HELIOS_READY_PATH", directory.path().join("ready"))
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
                "invalid policy did not stop startup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect heliosd output");

    assert!(!output.status.success(), "invalid policy must stop startup");
    assert!(output.stdout.is_empty());
    assert!(!directory.path().join("ready").exists());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostics.contains("10.0.0.0/33"),
        "startup refusal should identify the invalid policy entry: {diagnostics}"
    );
    assert!(
        diagnostics.contains("firewall policy does not compile"),
        "startup should refuse during policy preflight: {diagnostics}"
    );
    assert!(
        !directory.path().join("admin.sock").exists(),
        "startup refusal must not create a local administration socket"
    );
    assert!(
        !directory.path().join("certificate-registry.json").exists(),
        "startup refusal must not open or create the certificate registry"
    );
}
