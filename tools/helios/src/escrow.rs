//! Escrow of the gateway identity, from the **operator workstation**.
//!
//! On each sealing, the gateway writes a copy of its WireGuard private key,
//! encrypted to the operator's public key (`helios_escrow`). This is the
//! only way to recover a gateway's identity after a PCR change — new kernel,
//! bootloader, or firmware — without SSH access.
//!
//! The code existed on both sides without any tool exposing it: the
//! `escrow_public_key` line in `network.toml` was a comment nobody could
//! honor. These two commands close the loop.
//!
//! # Where the operator private key lives
//!
//! **Never on the gateway it rescues.** An escrow deposited next to its own
//! decryption key no longer protects anything: it adds a plaintext copy of
//! the identity, exactly what TPM sealing exists to prevent. It lives
//! offline, on the operator workstation (ADR-004 §2).

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const PRIVATE_FILE: &str = "escrow-private.key";
const PUBLIC_FILE: &str = "escrow-public.key";

/// Generates the operator's escrow key pair in a fresh directory.
pub fn keygen(output_dir: &Path) -> Result<()> {
    crate::files::create_private_dir(output_dir)?;
    let (private_key, public_key) = helios_escrow::generate_operator_keypair()
        .map_err(|e| anyhow::anyhow!("generating the escrow key pair: {e}"))?;

    let public_b64 = B64.encode(public_key);
    crate::files::write_new(
        &output_dir.join(PRIVATE_FILE),
        B64.encode(private_key.as_slice()).as_bytes(),
        true,
    )?;
    crate::files::write_new(&output_dir.join(PUBLIC_FILE), public_b64.as_bytes(), false)?;

    println!("{public_b64}");
    eprintln!();
    eprintln!("  Escrow public key above. Declare it on the gateway:");
    eprintln!();
    eprintln!("    escrow_public_key = \"{public_b64}\"");
    eprintln!();
    eprintln!(
        "  {} must stay offline and off the gateway: it is the only",
        output_dir.join(PRIVATE_FILE).display()
    );
    eprintln!("  half able to open an escrow.");
    Ok(())
}

/// Opens an escrow and writes the recovery file to deposit on the gateway.
///
/// The recovered key is **not** displayed: only its public half is, which is
/// enough to verify the escrow of the expected gateway was opened, without
/// scrolling the secret through a terminal or a log.
pub fn open(escrow_path: &Path, private_key_path: &Path, output: &Path) -> Result<()> {
    let blob = std::fs::read(escrow_path)
        .with_context(|| format!("reading escrow {}", escrow_path.display()))?;
    let private_b64 = std::fs::read_to_string(private_key_path)
        .with_context(|| format!("reading {}", private_key_path.display()))?;
    let private_key = B64
        .decode(private_b64.trim())
        .context("unreadable escrow private key (expected base64)")?;
    if private_key.len() != helios_escrow::KEY_LEN {
        bail!(
            "escrow private key is {} bytes instead of {}",
            private_key.len(),
            helios_escrow::KEY_LEN
        );
    }

    let recovered = helios_escrow::open_as_operator(&private_key, &blob)
        .map_err(|e| anyhow::anyhow!("could not open escrow: {e}"))?;
    let wg_private_key = std::str::from_utf8(recovered.as_slice())
        .context("escrow does not contain a base64 WireGuard key")?
        .trim()
        .to_string();
    let wg_public_key = aether::wg::public_from_private(&wg_private_key)
        .context("escrow does not contain a valid WireGuard key")?;

    crate::files::write_new(output, wg_private_key.as_bytes(), true)?;

    println!("{wg_public_key}");
    eprintln!();
    eprintln!("  Identity recovered: the public key above must match the one");
    eprintln!("  clients already know. If it differs, this escrow does not");
    eprintln!("  belong to this gateway — do not deposit it.");
    eprintln!();
    eprintln!(
        "  Deposit {} at /var/lib/helios/wg-key.recovery on the gateway, then",
        output.display()
    );
    eprintln!("  restart it: it reseals the key and erases the file.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WG_PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn test_directory(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "helios-escrow-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn key_generation_creates_both_halves_and_refuses_replacement() {
        let directory = test_directory("keygen");
        keygen(&directory).expect("generate operator identity");

        let private = B64
            .decode(std::fs::read_to_string(directory.join(PRIVATE_FILE)).unwrap())
            .unwrap();
        let public = B64
            .decode(std::fs::read_to_string(directory.join(PUBLIC_FILE)).unwrap())
            .unwrap();
        assert_eq!(private.len(), helios_escrow::KEY_LEN);
        assert_eq!(public.len(), helios_escrow::KEY_LEN);
        assert!(
            keygen(&directory).is_err(),
            "existing keys must not be replaced"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(directory.join(PRIVATE_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn operator_command_recovers_a_wireguard_key_without_printing_it() {
        let directory = test_directory("open");
        std::fs::create_dir_all(&directory).unwrap();
        let (private, public) = helios_escrow::generate_operator_keypair().unwrap();
        let blob = helios_escrow::seal_to_operator(&public, WG_PRIVATE_KEY.as_bytes()).unwrap();
        let escrow_path = directory.join("wg-key.escrow");
        let private_path = directory.join(PRIVATE_FILE);
        let output = directory.join("recovery.key");
        std::fs::write(&escrow_path, blob).unwrap();
        std::fs::write(&private_path, B64.encode(private.as_slice())).unwrap();

        open(&escrow_path, &private_path, &output).expect("recover identity");
        assert_eq!(std::fs::read_to_string(&output).unwrap(), WG_PRIVATE_KEY);
        assert!(
            open(&escrow_path, &private_path, &output).is_err(),
            "the recovery command must not overwrite an existing key"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_operator_keys_are_rejected_before_opening_the_escrow() {
        let directory = test_directory("bad-key");
        std::fs::create_dir_all(&directory).unwrap();
        let escrow_path = directory.join("blob");
        let private_path = directory.join("private");
        let output = directory.join("output");
        std::fs::write(&escrow_path, b"not an escrow").unwrap();

        std::fs::write(&private_path, "not base64").unwrap();
        assert!(open(&escrow_path, &private_path, &output)
            .unwrap_err()
            .to_string()
            .contains("base64"));

        std::fs::write(&private_path, B64.encode([0u8; 4])).unwrap();
        let error = open(&escrow_path, &private_path, &output).unwrap_err();
        assert!(error.to_string().contains("4 bytes"), "message: {error}");
        assert!(!output.exists());

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovered_plaintext_must_be_utf8_and_a_valid_wireguard_key() {
        let directory = test_directory("bad-content");
        std::fs::create_dir_all(&directory).unwrap();
        let (private, public) = helios_escrow::generate_operator_keypair().unwrap();
        let private_path = directory.join("private");
        let escrow_path = directory.join("blob");
        let output = directory.join("output");
        std::fs::write(&private_path, B64.encode(private.as_slice())).unwrap();

        let non_utf8 = helios_escrow::seal_to_operator(&public, &[0xff, 0xfe]).unwrap();
        std::fs::write(&escrow_path, non_utf8).unwrap();
        assert!(open(&escrow_path, &private_path, &output)
            .unwrap_err()
            .to_string()
            .contains("base64 WireGuard key"));

        let invalid = helios_escrow::seal_to_operator(&public, b"not-a-wg-key").unwrap();
        std::fs::write(&escrow_path, invalid).unwrap();
        assert!(open(&escrow_path, &private_path, &output)
            .unwrap_err()
            .to_string()
            .contains("valid WireGuard key"));
        assert!(!output.exists());

        std::fs::remove_dir_all(directory).unwrap();
    }
}
