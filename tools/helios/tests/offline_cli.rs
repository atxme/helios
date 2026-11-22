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
fn offline_escrow_commands_print_only_the_public_keys_and_leave_a_recovery_file() {
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
        counter: Some(1),
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
    let args = [
        "escrow",
        "open",
        "--escrow",
        "wg.escrow",
        "--private-key",
        "operator/escrow-private.key",
        "--output",
        "recovery.key",
    ];
    let opened = helios(temp.path()).args(args).output().unwrap();
    assert_eq!(successful_stdout(&opened).trim(), gateway.public_key);
    assert!(!String::from_utf8_lossy(&opened.stderr).contains(gateway.private_key.expose()));
    let recovered = fs::read_to_string(temp.path().join("recovery.key")).unwrap();
    assert!(
        recovered == gateway.private_key.expose(),
        "the recovery key differs"
    );
    let repeated = helios(temp.path()).args(args).output().unwrap();
    assert!(!repeated.status.success());
    assert!(repeated.stdout.is_empty());
    assert!(fs::read_to_string(temp.path().join("recovery.key")).unwrap() == recovered);
}
