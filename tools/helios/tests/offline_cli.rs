//! Exercise the offline operator commands through the shipped CLI.

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

fn helios(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_helios"));
    command
        .current_dir(root)
        .env_remove("HELIOS_URL")
        .env("HELIOS_ADMIN_SOCKET", root.join("absent.sock"))
        .env("NO_COLOR", "1");
    command
}

fn successful_stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn profile_check_reports_presence_of_the_private_key_without_printing_it() {
    let temp = tempfile::tempdir().unwrap();
    let client = aether::wg::generate_keypair().unwrap();
    let gateway = aether::wg::generate_keypair().unwrap();
    let document = format!(
        "[Interface]\nPrivateKey = {}\nAddress = 100.64.1.2/32\n\n\
         [Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51820\n",
        client.private_key.expose(),
        gateway.public_key,
    );
    let path = temp.path().join("portable.conf");
    fs::write(&path, document).unwrap();

    let output = helios(temp.path())
        .args(["profile", "check", "portable.conf"])
        .output()
        .unwrap();
    let stdout = successful_stdout(&output);
    assert!(stdout.contains("Readable by Orion"), "{stdout}");
    assert!(stdout
        .lines()
        .any(|line| line.contains("Private key") && line.ends_with("included")));
    assert!(stdout.contains("IPv4-only full tunnel"));
    assert!(!stdout.contains(client.private_key.expose()));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(client.private_key.expose()));
}

#[test]
fn offline_escrow_recovery_prints_no_private_key_and_refuses_to_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let keygen = helios(temp.path())
        .args(["escrow", "keygen", "--output-dir", "operator"])
        .output()
        .unwrap();
    let operator_public = successful_stdout(&keygen);
    let operator_private =
        fs::read_to_string(temp.path().join("operator/escrow-private.key")).unwrap();
    assert_eq!(
        operator_public.trim(),
        fs::read_to_string(temp.path().join("operator/escrow-public.key")).unwrap()
    );
    assert!(!operator_public.contains(&operator_private));
    assert!(!String::from_utf8_lossy(&keygen.stderr).contains(&operator_private));

    let gateway = aether::wg::generate_keypair().unwrap();
    let public = STANDARD.decode(operator_public.trim()).unwrap();
    let metadata = helios_escrow::EscrowMetadata {
        counter: Some(5),
        gateway_public_key: STANDARD
            .decode(&gateway.public_key)
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let blob = helios_escrow::seal_to_operator(
        &public,
        gateway.private_key.expose().as_bytes(),
        &metadata,
    )
    .unwrap();
    fs::write(temp.path().join("wg.escrow"), blob).unwrap();

    // The retired `escrow open` must no longer exist.
    let retired = helios(temp.path())
        .args(["escrow", "open", "--escrow", "wg.escrow"])
        .output()
        .unwrap();
    assert!(!retired.status.success());

    let prepare = helios(temp.path())
        .args([
            "escrow",
            "prepare-recovery",
            "--escrow",
            "wg.escrow",
            "--private-key",
            "operator/escrow-private.key",
            "--output",
            "request.json",
        ])
        .output()
        .unwrap();
    assert_eq!(successful_stdout(&prepare).trim(), gateway.public_key);
    assert!(!String::from_utf8_lossy(&prepare.stderr).contains(gateway.private_key.expose()));
    let request = fs::read_to_string(temp.path().join("request.json")).unwrap();
    assert!(request.contains("\"counter\": 6"), "{request}");
    assert!(!request.contains(gateway.private_key.expose()));

    // The publisher signs the request with the development keys.
    let payload: aether::sig::WireGuardRecoveryPayload = serde_json::from_str(&request).unwrap();
    let authorization = aether::sig::PublisherSigner::from_seed_material(
        1,
        b"helios-sign-ed25519-dev-seed-001",
        b"helios-sign-mldsa65-dev-seed-001",
    )
    .unwrap()
    .sign(payload)
    .unwrap();
    fs::write(
        temp.path().join("authorization.json"),
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();

    let args = [
        "escrow",
        "assemble-recovery",
        "--escrow",
        "wg.escrow",
        "--private-key",
        "operator/escrow-private.key",
        "--request",
        "request.json",
        "--authorization",
        "authorization.json",
        "--output",
        "wg-key.recovery",
    ];
    let assembled = helios(temp.path()).args(args).output().unwrap();
    assert_eq!(successful_stdout(&assembled).trim(), gateway.public_key);
    for stream in [&assembled.stdout, &assembled.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains(gateway.private_key.expose()));
    }
    let frame = fs::read(temp.path().join("wg-key.recovery")).unwrap();
    let (decoded, key) = helios_escrow::recovery::decode_recovery_frame(&frame).unwrap();
    assert_eq!(decoded, authorization);
    assert_eq!(
        key.as_slice(),
        STANDARD.decode(gateway.private_key.expose()).unwrap()
    );

    let repeated = helios(temp.path()).args(args).output().unwrap();
    assert!(!repeated.status.success());
    assert!(repeated.stdout.is_empty());
    assert_eq!(
        fs::read(temp.path().join("wg-key.recovery")).unwrap(),
        frame
    );
}

#[test]
fn campaign_key_generation_prints_two_shell_assignments_with_matching_keys() {
    let root = tempfile::tempdir().unwrap();
    let output = helios(root.path())
        .args(["campaign", "--generate-keys"])
        .output()
        .unwrap();
    let stdout = successful_stdout(&output);
    let assignments = stdout.lines().collect::<Vec<_>>();
    let [private, public] = assignments.as_slice() else {
        panic!("expected two key assignments");
    };
    let private = private.strip_prefix("WG_PRIVATE_KEY=").unwrap();
    let public = public.strip_prefix("WG_PUBLIC_KEY=").unwrap();
    let key: [u8; 32] = STANDARD.decode(private).unwrap().try_into().unwrap();
    assert_eq!(
        public,
        STANDARD.encode(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(key)).as_bytes()
        )
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Declare the peer on the gateway"));
    assert!(stderr.contains(public));
    assert!(!stderr.contains(private));
}

#[test]
fn unconfigured_campaign_reports_environment_skips_and_runs_offline_scenarios() {
    let root = tempfile::tempdir().unwrap();
    let output = helios(root.path())
        .env_remove("HELIOS_CAMPAIGN_CLIENT_KEY")
        .env_remove("HELIOS_CAMPAIGN_GATEWAY_KEY")
        .args(["campaign", "--repeat", "2"])
        .output()
        .unwrap();
    let stdout = successful_stdout(&output);
    assert!(stdout.contains("pass 1/2"));
    assert!(stdout.contains("pass 2/2"));
    assert!(stdout.contains("--client-key required for network scenarios"));
    assert!(stdout.contains("--wg-iface absent (target only)"));
    assert!(stdout.contains("--profile <nom> required to reach the gateway"));
    assert!(stdout.contains("18 scenario(s)"));
}

#[cfg(debug_assertions)]
#[test]
fn negotiation_campaign_reports_missing_or_unreadable_selected_profile() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("orion-config.toml");
    for (body, expected) in [
        (b"profiles = []\n".as_slice(), "aucun profil Orion"),
        (b"not TOML".as_slice(), "lecture de la configuration Orion"),
    ] {
        fs::write(&config, body).unwrap();
        let output = helios(root.path())
            .env("ORION_CONFIG", &config)
            .args([
                "campaign",
                "--only",
                "negociation-de-cle",
                "--profile",
                "workstation",
            ])
            .output()
            .unwrap();

        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(expected), "{stdout}");
        assert!(
            stdout.contains("1 failure(s) out of 7 scenario(s)"),
            "{stdout}"
        );
    }
}

#[cfg(target_os = "linux")]
mod data_plane_campaign {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    const INTERFACE: &str = "fixture-wg";
    const FOREIGN_PEER: &str = "different-peer-fixture";
    const TEST_PSK: &str = "psk-fixture-must-not-be-printed";

    struct Fixture {
        directory: tempfile::TempDir,
        client: aether::wg::Keypair,
        gateway: aether::wg::Keypair,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                directory: tempfile::tempdir().unwrap(),
                client: aether::wg::generate_keypair().unwrap(),
                gateway: aether::wg::generate_keypair().unwrap(),
            }
        }

        fn write_dump(&self, peers: &str) {
            fs::write(
                self.directory.path().join("wg.dump"),
                format!("fixture-interface-header\n{peers}"),
            )
            .unwrap();
            self.stub(b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$HELIOS_TEST_WG_CALLS\"\n/bin/cat -- \"$HELIOS_TEST_WG_DUMP\"\n");
        }

        fn stub(&self, script: &[u8]) {
            let path = self.directory.path().join("wg");
            fs::write(&path, script).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn command(&self) -> Command {
            let mut command = helios(self.directory.path());
            command
                .env("PATH", self.directory.path())
                .env("HELIOS_TEST_WG_DUMP", self.directory.path().join("wg.dump"))
                .env(
                    "HELIOS_TEST_WG_CALLS",
                    self.directory.path().join("wg.calls"),
                )
                .args([
                    "campaign",
                    "--only",
                    "plan-de-donnees",
                    "--wg-iface",
                    INTERFACE,
                    "--client-key",
                    self.client.private_key.expose(),
                    "--gateway-key",
                    &self.gateway.public_key,
                ]);
            command
        }

        fn peer(&self, psk: &str, timestamp: &str) -> String {
            format!(
                "{}\t{psk}\t(none)\t100.64.1.2/32\t{timestamp}\t0\t0\t0\n",
                self.client.public_key
            )
        }

        fn run(&self, success: bool) -> String {
            let output = self.command().output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), success, "{stdout}\n{stderr}");
            for output in [&*stdout, &*stderr] {
                assert!(!output.contains(TEST_PSK));
                assert!(!output.contains(self.client.private_key.expose()));
            }
            stdout
        }
    }

    #[test]
    fn data_plane_accepts_only_the_selected_peers_live_handshake() {
        let fixture = Fixture::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        fixture.write_dump(&format!(
            "{FOREIGN_PEER}\t(none)\t(none)\t100.64.1.3/32\t0\t0\t0\t0\n{}",
            fixture.peer(TEST_PSK, &timestamp.to_string())
        ));

        let stdout = fixture.run(true);
        assert!(stdout.contains("PresharedKey slot populated"));
        assert!(stdout.contains("last handshake"));
        assert!(stdout.contains("2 scenario(s)"));
        assert_eq!(
            fs::read_to_string(fixture.directory.path().join("wg.calls")).unwrap(),
            format!("show {INTERFACE} dump\n").repeat(2)
        );
    }

    #[test]
    fn data_plane_reports_missing_psk_and_absent_or_unreadable_handshakes() {
        for (psk, timestamp) in [("(none)", "0"), ("", "invalid")] {
            let fixture = Fixture::new();
            fixture.write_dump(&fixture.peer(psk, timestamp));
            let stdout = fixture.run(false);
            assert!(stdout.contains("empty PresharedKey slot"));
            assert!(stdout.contains("no handshake since the PSK was installed"));
            assert!(stdout.contains("2 failure(s) out of 2 scenario(s)"));
        }
    }

    #[test]
    fn data_plane_rejects_stale_or_missing_peer_without_reporting_success() {
        let fixture = Fixture::new();
        fixture.write_dump(&fixture.peer(TEST_PSK, "1"));
        let stdout = fixture.run(false);
        assert!(stdout.contains("the session is dead"));
        assert!(stdout.contains("1 failure(s) out of 2 scenario(s)"));

        fixture.write_dump(FOREIGN_PEER);
        let stdout = fixture.run(false);
        assert!(stdout.contains("provisioning did not install it"));
        assert!(stdout.contains("2 failure(s) out of 2 scenario(s)"));
    }

    #[test]
    fn data_plane_reports_failed_or_unavailable_wireguard_command() {
        let fixture = Fixture::new();
        let stdout = fixture.run(false);
        assert!(stdout.contains("tool available on the target only"));
        fixture.stub(b"#!/bin/sh\nprintf 'fixture interface unavailable\\n' >&2\nexit 9\n");
        let stdout = fixture.run(false);
        assert!(stdout.contains("fixture interface unavailable"));
        assert!(stdout.contains("2 failure(s) out of 2 scenario(s)"));
    }
}
