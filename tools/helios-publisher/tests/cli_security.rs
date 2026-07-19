use std::{collections::HashSet, fs, process::Command};

fn publisher() -> Command {
    Command::new(env!("CARGO_BIN_EXE_helios-publisher"))
}

#[test]
fn cycle_complet_produit_un_billet_hybride_et_refuse_tout_ecrasement() {
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

    let ticket = root.path().join("reseal-ticket.json");
    let sign = publisher()
        .args([
            "reseal-ticket",
            "--key-epoch",
            "9",
            "--version",
            "42",
            "--ed25519-private-key",
        ])
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
    assert_eq!(json["payload"]["version"], 42);
    assert!(json["payload"]["expected_pcr_digest"].is_null());
    let algorithms: HashSet<_> = json["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["alg"].as_str().unwrap())
        .collect();
    assert_eq!(algorithms, HashSet::from(["ed25519", "ml-dsa-65"]));

    // Ni les clés ni les billets ne doivent être écrasés silencieusement.
    let overwrite_ticket = publisher()
        .args([
            "reseal-ticket",
            "--key-epoch",
            "9",
            "--version",
            "43",
            "--ed25519-private-key",
        ])
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
fn arguments_de_securite_refusent_zero_et_digest_pcr_malforme() {
    let zero = publisher()
        .args(["keygen", "--key-epoch", "0", "--output-dir", "inutilise"])
        .output()
        .unwrap();
    assert!(!zero.status.success());
    assert!(String::from_utf8_lossy(&zero.stderr).contains("doit être > 0"));

    let malformed = publisher()
        .args([
            "reseal-ticket",
            "--key-epoch",
            "1",
            "--version",
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
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("octets au lieu de 32"));
}
