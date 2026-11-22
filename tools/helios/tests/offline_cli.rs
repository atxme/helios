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
