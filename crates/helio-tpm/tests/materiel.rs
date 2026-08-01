//! Real hardware TPM trials — target only.
//!
//! The crate's 27 unit tests run against `DryRunTpm`: they verify the
//! decision *logic*, never the silicon. This file closes the gap, by
//! exercising `/dev/tpmrm0` for real.
//!
//! # What these trials write, and why it is reversible
//!
//! The real backend only uses `create_primary` (a **transient** primary key,
//! never made persistent), `create`, `load`, `policy_pcr` and `unseal`. No NV
//! write, no `evict_control`, no hierarchy change, no `clear`. All Helios
//! state lives in the files designated by `TpmSettings` — here a temporary
//! directory, never `/var/lib/helios`.
//!
//! Deleting this directory therefore returns the machine to its initial
//! state. This is what distinguishes these trials from the RAUC cycle
//! trials, which touched boot slots and could render the target unbootable.
//!
//! No PCR is extended: an extension is irreversible until the next reboot.
//! PCR binding is exercised by rewriting the selection *recorded in the
//! blob* — the TPM then answers `TPM2_RC_POLICY_FAIL`, without the platform
//! state having been touched.
//!
//! # Execution
//!
//! These trials only run if `HELIOS_TPM_MATERIEL=1` is set:
//! `cargo test --all-features` must remain runnable on a machine without a
//! TPM, WSL2 included. The target campaign sets the variable, which
//! guarantees they actually run somewhere.
//!
//! ```sh
//! HELIOS_TPM_MATERIEL=1 cargo test -p helio-tpm --features tpm --test materiel
//! ```
#![cfg(feature = "tpm")]

use helio_tpm::{BootController, BootDecision, SealedKeystore, TpmSettings};

/// Indicates whether hardware trials are requested.
///
/// The absence of the variable is not a failure: it is an environment that
/// cannot settle the question. The message says so explicitly rather than
/// letting it look like a success.
fn hardware_requested(name: &str) -> bool {
    if std::env::var("HELIOS_TPM_MATERIEL").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("[out of scope] {name}: set HELIOS_TPM_MATERIEL=1 on a TPM-equipped target");
    false
}

/// Settings pointing to a disposable directory, provisioning allowed.
fn settings(dir: &std::path::Path, allow_provisioning: bool) -> TpmSettings {
    TpmSettings {
        enabled: true,
        enforce: true,
        allow_provisioning,
        device: "/dev/tpmrm0".to_string(),
        pcr_bank: "sha256".to_string(),
        pcr_selection: vec![0, 4, 7],
        sealed_blob_path: dir.join("sealed.key").to_string_lossy().into_owned(),
        ticket_path: dir
            .join("reseal-ticket.json")
            .to_string_lossy()
            .into_owned(),
        state_path: dir.join("tpm-state.json").to_string_lossy().into_owned(),
    }
}

fn disposable_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("helios-tpm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creation of the test directory");
    dir
}

#[test]
fn the_provisioned_secret_is_retrieved_identically() {
    if !hardware_requested("seal then unseal") {
        return;
    }
    let dir = disposable_dir("aller-retour");

    // First boot: no blob, provisioning allowed.
    let provisioned = match BootController::unlock(&settings(&dir, true)) {
        Ok(BootDecision::Provisioned(secret)) => secret,
        other => panic!("provisioning expected, got: {other:?}"),
    };
    assert!(dir.join("sealed.key").exists(), "no sealed blob written");

    // Next boot: the blob exists, provisioning is no longer allowed.
    let unsealed = match BootController::unlock(&settings(&dir, false)) {
        Ok(BootDecision::Unsealed(secret)) => secret,
        other => panic!("unseal expected, got: {other:?}"),
    };

    // The heart of the trial: the equality of the two secrets proves that
    // the TPM really sealed then unsealed, and not that a degraded path
    // returned two plausible values.
    assert_eq!(
        provisioned.as_bytes(),
        unsealed.as_bytes(),
        "the unsealed secret differs from the sealed secret"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_missing_blob_outside_provisioning_is_refused() {
    if !hardware_requested("fail-closed on missing blob") {
        return;
    }
    let dir = disposable_dir("blob-absent");

    let outcome = BootController::unlock(&settings(&dir, false));
    assert!(
        outcome.is_err(),
        "a missing blob outside provisioning must fail, got: {outcome:?}"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_tampered_blob_is_refused() {
    if !hardware_requested("refusal of a tampered blob") {
        return;
    }
    let dir = disposable_dir("blob-altere");
    let blob = dir.join("sealed.key");

    BootController::unlock(&settings(&dir, true)).expect("initial provisioning");

    // Flip a byte in the middle of the blob: the TPM must refuse to load it
    // or to derive the secret from it. An unseal that succeeded would
    // signal that integrity is not verified.
    let mut bytes = std::fs::read(&blob).expect("reading the blob");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&blob, &bytes).expect("writing the tampered blob");

    let outcome = BootController::unlock(&settings(&dir, false));
    assert!(
        outcome.is_err(),
        "a tampered blob must be refused, got: {outcome:?}"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_tampered_pcr_selection_in_the_blob_refuses_unseal() {
    if !hardware_requested("PCR binding actually enforced") {
        return;
    }
    let dir = disposable_dir("pcr-alteres");
    let blob = dir.join("sealed.key");

    BootController::unlock(&settings(&dir, true)).expect("provisioning under PCR 0,4,7");

    // The PCR selection applied at unseal time comes from the **blob**, not
    // from the settings: the blob is self-describing (`unmarshal_blob`).
    // Modifying `TpmSettings::pcr_selection` would therefore have no effect
    // here, and a trial built on that would pass green without proving anything.
    //
    // The property that matters is elsewhere: the policy digest is frozen
    // into the sealed object at creation time. Rewriting the selection
    // recorded in the blob produces a policy that no longer matches, and
    // the TPM must refuse. This is what prevents an attacker from unsealing
    // by declaring a weaker binding than the original one.
    //
    // Blob layout: MAGIC(4) | VERSION(1) | BANK(1) | n(1) | indices(n).
    const OFFSET_INDICES: usize = 7;
    let mut bytes = std::fs::read(&blob).expect("reading the blob");
    assert_eq!(
        bytes[OFFSET_INDICES - 1],
        3,
        "three PCR indices expected in the blob"
    );
    assert_eq!(
        &bytes[OFFSET_INDICES..OFFSET_INDICES + 3],
        &[0, 4, 7],
        "unexpected PCR selection in the blob"
    );
    // PCR 7 (Secure Boot) -> PCR 6: different binding, object unchanged.
    bytes[OFFSET_INDICES + 2] = 6;
    std::fs::write(&blob, &bytes).expect("writing the tampered blob");

    let outcome = BootController::unlock(&settings(&dir, false));
    assert!(
        outcome.is_err(),
        "a rewritten PCR selection must refuse unseal, got: {outcome:?}"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn the_wireguard_key_survives_a_sealed_round_trip() {
    if !hardware_requested("WireGuard key vault") {
        return;
    }
    let dir = disposable_dir("keystore");

    let secret = match BootController::unlock(&settings(&dir, true)) {
        Ok(BootDecision::Provisioned(secret)) => secret,
        other => panic!("provisioning expected, got: {other:?}"),
    };

    // A WireGuard private key is 32 bytes; we verify it comes back intact
    // from the vault encrypted by the TPM-derived secret.
    let key: Vec<u8> = (0u8..32).collect();
    let vault = SealedKeystore::new(dir.join("wg-key.sealed"), helio_tpm::DOMAIN_GATEWAY_WG_KEY);
    vault
        .store(&secret, &helio_tpm::Context::new(), &key)
        .expect("sealing the key");
    assert!(vault.exists(), "the vault was not written");

    let reread = vault
        .load(&secret, &helio_tpm::Context::new())
        .expect("re-reading the key");
    assert_eq!(reread.as_slice(), key.as_slice(), "WireGuard key tampered");

    vault.remove().expect("removing the vault");
    assert!(!vault.exists(), "the vault still exists after removal");

    std::fs::remove_dir_all(&dir).expect("cleanup");
}
