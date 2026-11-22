//! Offline diagnostics and configuration changes through the gateway binary.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const GATEWAY_PRIVATE_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
const PEER_PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const STATIC_PSK: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

fn heliosd(root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heliosd"))
        .args(arguments)
        .env("HELIOS_NETWORK_CONFIG", root.join("network.toml"))
        .env("HELIOS_UPDATE_STAGING", root.join("updates"))
        .env("HELIOS_ASTRA_CHANNEL", root.join("astra-channel.json"))
        .env("HELIOS_UPDATE_CHANNEL", "cli-test")
        .env("RUST_LOG", "info,tss_esapi=warn")
        .output()
        .expect("run heliosd")
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "heliosd failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

fn reported<'a>(output: &'a str, field: &str) -> &'a str {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(label, _)| label.trim() == field)
        .map(|(_, value)| value.trim())
        .unwrap_or_else(|| panic!("missing {field} in {output}"))
}

fn configured_gateway(address: &str) -> String {
    format!(
        r#"wan_iface = ["wan-test0", "wan-test1"]
lan_ifaces = ["lan-test"]
wg_iface = "wg-test"
wg_address = "{address}"
wg_private_key = "{GATEWAY_PRIVATE_KEY}"
wg_listen_port = 51991

[[peers]]
name = "operator"
public_key = "{PEER_PUBLIC_KEY}"
address = "100.64.1.2/32"
admin = true
preshared_key = "{STATIC_PSK}"
"#
    )
}

#[test]
fn status_displays_gateway_and_peer_details_without_disclosing_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("network.toml");
    let original = configured_gateway("100.64.0.1/10");
    fs::write(&config, &original).unwrap();

    let output = heliosd(directory.path(), &["status"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("randomness provider"));
    for secret in [GATEWAY_PRIVATE_KEY, STATIC_PSK] {
        assert!(!stderr.contains(secret), "diagnostic logged a secret");
    }
    let printed = stdout(output);
    assert!(!printed.contains("randomness provider"));
    assert!(printed.starts_with(concat!("heliosd v", env!("CARGO_PKG_VERSION"))));
    assert_eq!(reported(&printed, "WAN"), "wan-test0, wan-test1");
    assert_eq!(reported(&printed, "LAN"), "[\"lan-test\"]");
    assert_eq!(reported(&printed, "WG interface"), "wg-test (UDP 51991)");
    assert_eq!(
        reported(&printed, "web interface"),
        format!(
            "http://100.64.0.1:{}",
            aether::config::API_BIND_LOOPBACK.port()
        )
    );
    assert_eq!(reported(&printed, "ready"), "yes");
    assert_eq!(reported(&printed, "peers"), "1");
    assert!(printed.contains("operator -> 100.64.1.2/32  [PQ]"));
    for secret in [GATEWAY_PRIVATE_KEY, STATIC_PSK] {
        assert!(!printed.contains(secret), "diagnostic printed a secret");
    }
    assert_eq!(fs::read_to_string(config).unwrap(), original);
}

#[test]
fn status_keeps_diagnostics_when_the_gateway_address_cannot_bind_the_api() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("network.toml"),
        configured_gateway("fd00:1:2::1/64"),
    )
    .unwrap();

    let printed = stdout(heliosd(directory.path(), &["status"]));
    let interface = reported(&printed, "web interface");
    assert!(interface.starts_with("none"));
    assert!(interface.contains("no IPv4 host"));
    assert!(!interface.contains("127.0.0.1"));
    assert_eq!(reported(&printed, "WG address"), "fd00:1:2::1/64");
    assert_eq!(reported(&printed, "peers"), "1");
}

#[test]
fn unconfigured_status_explains_readiness_and_uses_a_loopback_api() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("network.toml"),
        "wan_iface = \"wan-test\"\n",
    )
    .unwrap();

    let printed = stdout(heliosd(directory.path(), &["status"]));
    assert_eq!(
        reported(&printed, "web interface"),
        format!("http://{}", aether::config::API_BIND_LOOPBACK)
    );
    assert_eq!(reported(&printed, "ready"), "no (private key missing)");
    assert_eq!(reported(&printed, "IPv6 tunnel"), "not configured");
    assert_eq!(reported(&printed, "peers"), "0");
}

#[test]
fn offline_peer_listing_keeps_roles_and_public_keys_without_disclosing_psks() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("network.toml");
    let args = ["peer", "list"];
    assert_eq!(
        stdout(heliosd(directory.path(), &args)).trim(),
        "no admitted peers"
    );

    let original = configured_gateway("100.64.0.1/10");
    fs::write(&config, &original).unwrap();
    let printed = stdout(heliosd(directory.path(), &args));
    assert_eq!(
        printed.trim(),
        format!("operator\t100.64.1.2/32\t{PEER_PUBLIC_KEY} [admin] [PQ]")
    );
    assert_eq!(fs::read_to_string(config).unwrap(), original);
}

#[test]
fn ipv6_prefix_initialization_persists_a_stable_prefix_visible_to_status() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("network.toml");
    fs::write(&config, "wan_iface = \"wan-test\"\n").unwrap();

    let first = stdout(heliosd(directory.path(), &["init-ipv6-prefix"]));
    let original = fs::read_to_string(&config).unwrap();
    let prefix = reported(&first, "IPv6 tunnel prefix configured");
    let parsed = prefix.parse::<aether::net::TunnelPrefixV6>().unwrap();
    assert!(original.contains(&format!("wg_address_v6 = \"{parsed}\"")));
    assert!(first.contains("Restart heliosd to apply the tunnel prefix."));

    let second = stdout(heliosd(directory.path(), &["init-ipv6-prefix"]));
    assert_eq!(
        reported(&second, "IPv6 tunnel prefix already configured"),
        prefix
    );
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    let status = stdout(heliosd(directory.path(), &["status"]));
    assert!(reported(&status, "IPv6 tunnel").starts_with(prefix));
}

#[test]
fn check_update_reads_only_the_isolated_staging_directory() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("updates");
    let args = ["check-update"];
    let empty = stdout(heliosd(directory.path(), &args));
    assert_eq!(reported(&empty, "channel"), "cli-test");
    assert_eq!(reported(&empty, "active sequence"), "0");
    assert_eq!(reported(&empty, "staged releases"), "0");
    assert!(!empty.contains("confirmed version"));
    assert!(!staging.exists());

    fs::create_dir(&staging).unwrap();
    let invalid = b"{\"highest_confirmed_sequence\":\"corrupted\"}";
    fs::write(staging.join("state.json"), invalid).unwrap();
    let output = heliosd(directory.path(), &args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid type"));
    assert_eq!(fs::read(staging.join("state.json")).unwrap(), invalid);
}

#[test]
fn startup_migrates_legacy_peer_floors_before_validating_other_network_settings() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("network.toml");
    let original = format!(
        r#"wan_iface = [""]

[[peers]]
name = "plain"
public_key = "{PEER_PUBLIC_KEY}"
address = "100.64.1.2/32"
minimum_key_negotiation_mode = "classic"

[[peers]]
name = "with-pq"
public_key = "{STATIC_PSK}"
address = "100.64.1.3/32"
key_negotiation_certificate_sha256 = "{fingerprint}"
key_negotiation_pq_certificate_sha256 = "{fingerprint}"
minimum_key_negotiation_mode = "classic"
"#,
        fingerprint = "a".repeat(64),
    );
    fs::write(&config, &original).unwrap();

    let status = heliosd(directory.path(), &["status"]);
    assert!(!status.status.success());
    assert!(String::from_utf8_lossy(&status.stderr).contains("no longer a protection mode"));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);

    let startup = heliosd(directory.path(), &["run", "--dev"]);
    assert!(!startup.status.success());
    assert!(startup.stdout.is_empty());
    let diagnostics = String::from_utf8_lossy(&startup.stderr);
    assert!(diagnostics.contains("plain WireGuard, no negotiation"));
    assert!(diagnostics.contains("floor raised to ml_kem"));
    assert!(
        diagnostics.contains("an empty interface name"),
        "{diagnostics}"
    );
    let migrated = fs::read_to_string(&config).unwrap();
    assert!(!migrated.contains("classic"));
    assert_eq!(migrated.matches("minimum_key_negotiation_mode").count(), 1);
    assert!(migrated.contains("minimum_key_negotiation_mode = \"ml_kem\""));
}

fn astra_pin(
    root: &Path,
    file: &str,
    name: &str,
    usage: rcgen::ExtendedKeyUsagePurpose,
) -> std::path::PathBuf {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let destination = root.join(file);
    fs::write(&destination, cert.der().as_ref()).unwrap();
    destination
}

fn channel_init(pin: &Path) -> Vec<&str> {
    vec![
        "init-astra-channel",
        "--bind",
        "10.88.0.1:8444",
        "--astra-certificate",
        pin.to_str().unwrap(),
    ]
}

fn channel_fields(output: &str) -> std::collections::BTreeMap<&str, &str> {
    output
        .lines()
        .take_while(|line| !line.is_empty())
        .map(|line| line.split_once('=').unwrap())
        .collect()
}

fn assert_public_channel_certificate(
    fields: &std::collections::BTreeMap<&str, &str>,
    prefix: &str,
) {
    use aether::certificates::encoding::DerCertificate;

    let certificate = DerCertificate::parse(fields[format!("{prefix}_certificate").as_str()])
        .expect("public certificate encoded in stdout");
    assert_eq!(
        fields[format!("{prefix}_fingerprint").as_str()],
        certificate.fingerprint().to_hex(),
    );
}

#[test]
fn astra_channel_init_prints_the_public_server_certificate_and_resumes_idempotently() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let pin = astra_pin(
        root,
        "astra-client.der",
        "astra.internal",
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let args = channel_init(&pin);

    let output = stdout(heliosd(root, &args));
    let fields = channel_fields(&output);
    assert_eq!(fields.len(), 3);
    assert_eq!(fields["bind"], "10.88.0.1:8444");
    assert_public_channel_certificate(&fields, "gateway_channel");

    let state_path = root.join("astra-channel.json");
    let originally_written = fs::read(&state_path).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&originally_written).unwrap();
    assert_eq!(
        document["certificate"],
        fields["gateway_channel_certificate"]
    );
    let key = document["private_key"]
        .as_str()
        .expect("test transport key");
    assert!(!key.is_empty());
    assert!(!output.contains(key));
    assert_eq!(stdout(heliosd(root, &args)), output);
    assert!(
        fs::read(&state_path).unwrap() == originally_written,
        "repeat changed the channel state"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn astra_channel_init_prints_distinct_certificates_for_the_two_directions() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let pin = astra_pin(
        root,
        "astra-client.der",
        "astra.internal",
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let authority = astra_pin(
        root,
        "astra-authority.der",
        astra_channel::ASTRA_INTERNAL_SERVER_NAME,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let mut args = channel_init(&pin);
    args.extend([
        "--authority",
        "10.88.0.2:8444",
        "--astra-authority-certificate",
        authority.to_str().unwrap(),
    ]);

    let output = stdout(heliosd(root, &args));
    let fields = channel_fields(&output);
    assert_eq!(fields.len(), 5);
    assert_public_channel_certificate(&fields, "gateway_channel");
    assert_public_channel_certificate(&fields, "gateway_client");
    assert_ne!(
        fields["gateway_channel_certificate"],
        fields["gateway_client_certificate"]
    );

    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("astra-channel.json")).unwrap()).unwrap();
    assert_eq!(stored["authority"], "10.88.0.2:8444");
    assert_eq!(
        stored["client_certificate"],
        fields["gateway_client_certificate"]
    );
    assert!(!output.contains(stored["client_private_key"].as_str().unwrap()));
}

#[test]
fn astra_channel_init_refuses_incomplete_pairing_or_wildcard_binding() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let missing = root.join("pin-not-read.der");
    let mut partial = channel_init(&missing);
    partial.extend(["--authority", "10.88.0.2:8444"]);
    let mut wildcard = channel_init(&missing);
    wildcard[2] = "0.0.0.0:8444";

    for (args, reason) in [
        (partial, "dialling half needs both"),
        (
            wildcard,
            "private lifecycle API belongs on the gateway's veth address",
        ),
    ] {
        let output = heliosd(root, &args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains(reason), "{diagnostic}");
        assert!(!root.join("astra-channel.json").exists());
    }
}

#[cfg(target_os = "linux")]
mod firmware_commands {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;

    fn run(root: &Path, arguments: &[&str], input: &[u8]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_heliosd"));
        let mut child = command
            .args(arguments)
            .env("HELIOS_NETWORK_CONFIG", root.join("network.toml"))
            .env("HELIOS_TEST_SERVICE_LOG", root.join("systemctl.log"))
            // Only the fixture's systemctl can be reached from this process.
            .env("PATH", root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start heliosd with isolated tools");
        if !input.is_empty() {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        child.wait_with_output().expect("read heliosd result")
    }

    fn assert_refusal(output: Output, message: &str) {
        assert!(!output.status.success(), "command must refuse the request");
        assert!(
            output.stdout.is_empty(),
            "refusal must not produce a result"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "expected {message:?}: {stderr}");
    }

    fn fake_service_status(root: &Path, code: u8) {
        let script = root.join("systemctl");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HELIOS_TEST_SERVICE_LOG\"\nexit {code}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn assert_service_probe(root: &Path) {
        assert_eq!(
            fs::read_to_string(root.join("systemctl.log")).unwrap(),
            "is-active\n--quiet\nheliosd.service\n"
        );
    }

    #[test]
    fn firmware_preflight_refuses_malformed_or_oversized_stdin() {
        let directory = tempfile::tempdir().unwrap();
        for input in [&b""[..], &b"{\"payload\":"[..]] {
            assert_refusal(
                run(directory.path(), &["tpm", "firmware-preflight"], input),
                "invalid firmware authorization",
            );
        }
        let input = vec![b' '; helios_tpm::firmware_recovery::MAX_RESTORE_FRAME + 1];
        assert_refusal(
            run(directory.path(), &["tpm", "firmware-preflight"], &input),
            "firmware input exceeds 64 KiB",
        );
    }

    #[test]
    fn firmware_restore_requires_systemd_to_confirm_the_daemon_is_inactive() {
        let directory = tempfile::tempdir().unwrap();
        for status in [0, 1, 4] {
            fake_service_status(directory.path(), status);
            assert_refusal(
                run(directory.path(), &["tpm", "restore-firmware"], b""),
                "stop heliosd.service before restoring its TPM root",
            );
            assert_service_probe(directory.path());
        }
    }

    #[test]
    fn firmware_restore_refuses_a_truncated_frame_when_the_daemon_is_inactive() {
        let directory = tempfile::tempdir().unwrap();
        fake_service_status(directory.path(), 3);
        assert_refusal(
            run(directory.path(), &["tpm", "restore-firmware"], &[0; 3]),
            "invalid recovery frame size",
        );
        assert_service_probe(directory.path());
    }

    #[test]
    fn firmware_export_refuses_an_invalid_escrow_key_encoding() {
        let directory = tempfile::tempdir().unwrap();
        assert_refusal(
            run(
                directory.path(),
                &[
                    "tpm",
                    "export-firmware",
                    "--operator-public-key",
                    "!!!!",
                    "--device",
                    "5bc922b7bd1adb5b6f99592611404036bd9f42d0",
                    "--target-version",
                    "2026.11",
                ],
                b"",
            ),
            "Invalid symbol",
        );
    }
}
