//! Escrow of the gateway identity, from the **operator workstation**.
//!
//! On each sealing, the gateway writes a copy of its WireGuard private key,
//! encrypted to the operator's public key (`helios_escrow`). This is the
//! only way to recover a gateway's identity after a PCR change — new kernel,
//! bootloader, or firmware — without SSH access.
//!
//! Recovery is a three-step ceremony, all offline (`helios_escrow::recovery`):
//!
//! 1. `prepare-recovery` opens the escrow and writes the public request to
//!    sign. No private key is printed or written.
//! 2. The publisher signs the request (`helios-publisher wg-recovery`).
//! 3. `assemble-recovery` opens the escrow again, verifies the publisher's
//!    authorization, and writes the recovery frame to deposit on the gateway.
//!
//! # Where the operator private key lives
//!
//! **Never on the gateway it rescues.** An escrow deposited next to its own
//! decryption key no longer protects anything: it adds a plaintext copy of
//! the identity, exactly what TPM sealing exists to prevent. It lives
//! offline, on the operator workstation (ADR-004 §2).

use std::path::Path;

use aether::sig::{SignedWireGuardRecovery, WireGuardRecoveryPayload};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use helios_escrow::recovery::{self, CounterSource, RecoveryError};
use zeroize::Zeroizing;

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

/// Parses an expected PCR digest given as 64 hex digits.
pub fn parse_pcr_digest(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|e| format!("expected PCR digest is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "expected PCR digest must be 32 bytes (64 hex digits)".to_string())
}

/// Writes the request to sign for a recovery, after checking the escrow.
///
/// Nothing is written when the escrow or the key is refused.
pub fn prepare_recovery(
    escrow_path: &Path,
    private_key_path: &Path,
    counter: Option<u64>,
    expected_pcr_digest: Option<[u8; 32]>,
    output: &Path,
) -> Result<()> {
    let escrow = read_escrow(escrow_path)?;
    let private_key = read_operator_private_key(private_key_path)?;
    let request = recovery::prepare(&escrow, &private_key, counter, expected_pcr_digest)
        .map_err(|error| refused("preparing the recovery request", error))?;

    let json =
        serde_json::to_vec_pretty(&request.payload).context("encoding the recovery request")?;
    crate::files::write_new(output, &json, false)?;

    println!("{}", request.gateway_public_key_b64);
    eprintln!();
    match request.counter_source {
        CounterSource::Given => eprintln!(
            "  Counter {}: fourni par l'opérateur.",
            request.payload.counter
        ),
        CounterSource::EscrowAfterTicket => eprintln!(
            "  Counter {}: lu dans le séquestre, suppose un billet consommé — vérifier `/var/lib/helios/anti-rollback.json` sur la gateway avant de signer.",
            request.payload.counter
        ),
    }
    eprintln!(
        "  Request written to {}: send it to the publisher",
        output.display()
    );
    eprintln!("  (helios-publisher wg-recovery). It holds no private key.");
    Ok(())
}

/// Verifies the publisher's authorization against the escrow and writes the
/// recovery frame to deposit on the gateway.
///
/// The request must be the file `prepare-recovery` wrote. Any refusal leaves
/// the filesystem untouched.
pub fn assemble_recovery(
    escrow_path: &Path,
    private_key_path: &Path,
    request_path: &Path,
    authorization_path: &Path,
    output: &Path,
) -> Result<()> {
    let escrow = read_escrow(escrow_path)?;
    let private_key = read_operator_private_key(private_key_path)?;
    let request: WireGuardRecoveryPayload = read_json(request_path, "recovery request")?;
    let authorization: SignedWireGuardRecovery =
        read_json(authorization_path, "recovery authorization")?;

    let frame = recovery::assemble(&escrow, &private_key, &request, &authorization)
        .map_err(|error| refused("assembling the recovery frame", error))?;
    crate::files::write_new(output, &frame, true)?;

    println!("{}", B64.encode(authorization.payload.gateway_public_key));
    eprintln!();
    eprintln!(
        "  Recovery frame written to {}. It contains the WireGuard private key in clear:",
        output.display()
    );
    eprintln!("  deposit it at /var/lib/helios/wg-key.recovery on the gateway, then");
    eprintln!("  restart it: it reseals the key and erases the file.");
    Ok(())
}

/// Turns a refusal of the recovery ceremony into an operator-facing error.
/// Nothing has been written when this is reported.
fn refused(action: &str, error: RecoveryError) -> anyhow::Error {
    anyhow!("{action} refused: {error}. Nothing was written.")
}

fn read_escrow(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading escrow {}", path.display()))
}

/// Reads the operator's escrow private key, as `keygen` writes it.
fn read_operator_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let private_key = Zeroizing::new(
        B64.decode(text.trim())
            .context("unreadable escrow private key (expected base64)")?,
    );
    if private_key.len() != helios_escrow::KEY_LEN {
        bail!(
            "escrow private key is {} bytes instead of {}",
            private_key.len(),
            helios_escrow::KEY_LEN
        );
    }
    Ok(private_key)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading {what} {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid {what} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aether::sig::{PublisherSigner, PUBLISHER_KEYS};

    use super::*;

    // Development seeds of the publisher, matching the development keyring
    // compiled into `aether`: the authorizations signed here verify through
    // the real keyring, as `heliosd` checks them.
    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";

    fn test_directory(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "helios-escrow-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    /// Writes an operator key pair in `directory`: the private half to a file,
    /// the public half returned.
    fn operator(directory: &Path) -> (std::path::PathBuf, [u8; 32]) {
        let (private, public) = helios_escrow::generate_operator_keypair().unwrap();
        let path = directory.join(PRIVATE_FILE);
        fs::write(&path, B64.encode(private.as_slice())).unwrap();
        (path, public)
    }

    /// Writes the escrow of a WireGuard private key, sealed to the operator.
    fn seal(
        directory: &Path,
        operator_public: &[u8; 32],
        wg_private: &str,
        counter: u64,
    ) -> std::path::PathBuf {
        let public = B64
            .decode(aether::wg::public_from_private(wg_private).unwrap())
            .unwrap();
        let metadata = helios_escrow::EscrowMetadata {
            counter: Some(counter),
            gateway_public_key: public.try_into().unwrap(),
        };
        let blob =
            helios_escrow::seal_to_operator(operator_public, wg_private.as_bytes(), &metadata)
                .unwrap();
        let path = directory.join("wg-key.escrow");
        fs::write(&path, blob).unwrap();
        path
    }

    fn gateway_private() -> String {
        aether::wg::generate_keypair()
            .unwrap()
            .private_key
            .expose()
            .to_string()
    }

    fn sign(payload: WireGuardRecoveryPayload) -> SignedWireGuardRecovery {
        PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED)
            .unwrap()
            .sign(payload)
            .unwrap()
    }

    fn write_authorization(
        directory: &Path,
        name: &str,
        auth: &SignedWireGuardRecovery,
    ) -> std::path::PathBuf {
        let path = directory.join(name);
        fs::write(&path, serde_json::to_vec(auth).unwrap()).unwrap();
        path
    }

    fn gateway_public(wg_private: &str) -> [u8; 32] {
        B64.decode(aether::wg::public_from_private(wg_private).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
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
    fn prepare_then_assemble_produces_a_frame_heliosd_accepts() {
        let directory = tempfile::tempdir().unwrap();
        let (operator_private, operator_public) = operator(directory.path());
        let wg = gateway_private();
        let escrow = seal(directory.path(), &operator_public, &wg, 5);

        let request_path = directory.path().join("request.json");
        prepare_recovery(&escrow, &operator_private, None, None, &request_path).unwrap();
        let request: WireGuardRecoveryPayload =
            serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
        assert_eq!(request.counter, 6, "a recovery follows a consumed ticket");
        assert_eq!(request.gateway_public_key, gateway_public(&wg));

        let auth = sign(request);
        let auth_path = write_authorization(directory.path(), "authorization.json", &auth);
        let frame_path = directory.path().join("wg-key.recovery");
        assemble_recovery(
            &escrow,
            &operator_private,
            &request_path,
            &auth_path,
            &frame_path,
        )
        .unwrap();

        let frame = fs::read(&frame_path).unwrap();
        let (decoded, key) = recovery::decode_recovery_frame(&frame).unwrap();
        assert_eq!(decoded, auth);
        assert_eq!(key.as_slice(), B64.decode(&wg).unwrap().as_slice());
        aether::sig::verify_wireguard_recovery(&decoded, PUBLISHER_KEYS, &key).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&frame_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn assemble_refuses_an_authorization_for_another_request() {
        let directory = tempfile::tempdir().unwrap();
        let (operator_private, operator_public) = operator(directory.path());
        let wg = gateway_private();
        let escrow = seal(directory.path(), &operator_public, &wg, 5);

        // The operator prepared a request for counter 6; the publisher signed
        // counter 7 for the same gateway.
        let request_path = directory.path().join("request.json");
        prepare_recovery(&escrow, &operator_private, Some(6), None, &request_path).unwrap();
        let auth = sign(WireGuardRecoveryPayload {
            counter: 7,
            gateway_public_key: gateway_public(&wg),
            expected_pcr_digest: None,
        });
        let auth_path = write_authorization(directory.path(), "authorization.json", &auth);
        let frame_path = directory.path().join("wg-key.recovery");

        let error = assemble_recovery(
            &escrow,
            &operator_private,
            &request_path,
            &auth_path,
            &frame_path,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("does not match the request"),
            "message: {error}"
        );
        assert!(!frame_path.exists(), "a refusal writes nothing");
    }

    #[test]
    fn assemble_refuses_to_overwrite_and_writes_nothing_on_a_foreign_authorization() {
        let directory = tempfile::tempdir().unwrap();
        let (operator_private, operator_public) = operator(directory.path());
        let wg = gateway_private();
        let escrow = seal(directory.path(), &operator_public, &wg, 5);

        let request_path = directory.path().join("request.json");
        prepare_recovery(&escrow, &operator_private, Some(6), None, &request_path).unwrap();
        let foreign = sign(WireGuardRecoveryPayload {
            counter: 6,
            gateway_public_key: gateway_public(&gateway_private()),
            expected_pcr_digest: None,
        });
        let foreign_path = write_authorization(directory.path(), "foreign.json", &foreign);

        let frame_path = directory.path().join("wg-key.recovery");
        fs::write(&frame_path, "keep").unwrap();
        let error = assemble_recovery(
            &escrow,
            &operator_private,
            &request_path,
            &foreign_path,
            &frame_path,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("another gateway"),
            "message: {error}"
        );
        assert_eq!(fs::read_to_string(&frame_path).unwrap(), "keep");

        let own = sign(WireGuardRecoveryPayload {
            counter: 6,
            gateway_public_key: gateway_public(&wg),
            expected_pcr_digest: None,
        });
        let own_path = write_authorization(directory.path(), "own.json", &own);
        assert!(
            assemble_recovery(
                &escrow,
                &operator_private,
                &request_path,
                &own_path,
                &frame_path
            )
            .is_err(),
            "an existing frame must never be overwritten"
        );
        assert_eq!(fs::read_to_string(&frame_path).unwrap(), "keep");
    }

    #[test]
    fn malformed_operator_keys_are_refused_before_anything_is_written() {
        let directory = test_directory("bad-key");
        std::fs::create_dir_all(&directory).unwrap();
        let escrow_path = directory.join("blob");
        let private_path = directory.join("private");
        let output = directory.join("request.json");
        fs::write(&escrow_path, b"not an escrow").unwrap();

        fs::write(&private_path, "not base64").unwrap();
        assert!(
            prepare_recovery(&escrow_path, &private_path, None, None, &output)
                .unwrap_err()
                .to_string()
                .contains("base64")
        );

        fs::write(&private_path, B64.encode([0u8; 4])).unwrap();
        let error = prepare_recovery(&escrow_path, &private_path, None, None, &output).unwrap_err();
        assert!(error.to_string().contains("4 bytes"), "message: {error}");
        assert!(!output.exists());

        std::fs::remove_dir_all(directory).unwrap();
    }
}
