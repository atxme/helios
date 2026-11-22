//! Real ESAPI TPM trials — hardware target or explicit software TPM.
//!
//! The crate's unit tests run against `DryRunTpm`: they verify the decision
//! *logic*, never the silicon. This file closes the gap, by exercising
//! `/dev/tpmrm0` for real, or the TCTI explicitly selected by the caller.
//!
//! # What these trials write, and why it is reversible
//!
//! The sealing path only uses `create_primary` (a **transient** primary key,
//! never made persistent), `create`, `load`, `policy_pcr` and `unseal`. No
//! `evict_control`, no hierarchy change, no `clear`. All Helios state lives
//! in the files designated by `TpmSettings` — here a temporary directory,
//! never `/var/lib/helios`.
//!
//! Deleting this directory therefore returns the machine to its initial
//! state, with **one exception**: the update-window trial defines an NV index
//! and writes it, because that write is the very thing it proves. It uses a
//! disposable index — `0x01804846`, one past the production one — so a real
//! gateway's window is never touched. The index survives the trial; remove it
//! with `tpm2_nvundefine 0x01804846` if the machine is not disposable.
//!
//! The anti-rollback counter trial likewise defines a disposable counter,
//! `0x01804848` (production: `0x01804847`), removable with
//! `tpm2_nvundefine 0x01804848`.
//!
//! This is what distinguishes these trials from the RAUC cycle trials, which
//! touched boot slots and could render the target unbootable.
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
//! HELIOS_TPM_MATERIEL=1 cargo test -p helios-tpm --features tpm --test materiel
//! ```
//!
//! `HELIOS_TPM_TCTI` may name a complete TCTI such as
//! `swtpm:host=127.0.0.1,port=2321`. This exercises the real ESAPI policy path
//! against a software TPM; it does not replace the target PCR measurements.
#![cfg(feature = "tpm")]

use helios_tpm::{BootController, BootDecision, SealedKeystore, TpmSettings};
use std::str::FromStr as _;

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
        device: std::env::var("HELIOS_TPM_TCTI").unwrap_or_else(|_| "/dev/tpmrm0".into()),
        pcr_bank: "sha256".to_string(),
        pcr_selection: vec![0, 4, 7],
        sealed_blob_path: dir.join("sealed.key").to_string_lossy().into_owned(),
        ticket_path: dir
            .join("reseal-ticket.json")
            .to_string_lossy()
            .into_owned(),
        update_window_pcr_selection: vec![0, 7],
        update_window_marker_path: dir
            .join("update-window.marker")
            .to_string_lossy()
            .into_owned(),
        // Disposable index, distinct from the production one: a hardware
        // trial must never undefine the index a real gateway relies on.
        update_window_nv_index: 0x0180_4846,
        update_window_seconds: 300,
        // The production counter index is reserved; the trial uses its own.
        anti_rollback_nv_index: 0x0180_4847,
        simulated_counter_path: dir
            .join("simulated-nv-counter")
            .to_string_lossy()
            .into_owned(),
        counter_status_path: dir
            .join("anti-rollback.json")
            .to_string_lossy()
            .into_owned(),
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
    let vault = SealedKeystore::new(dir.join("wg-key.sealed"), helios_tpm::DOMAIN_GATEWAY_WG_KEY);
    vault
        .store(&secret, &helios_tpm::Context::new(), &key)
        .expect("sealing the key");
    assert!(vault.exists(), "the vault was not written");

    let reread = vault
        .load(&secret, &helios_tpm::Context::new())
        .expect("re-reading the key");
    assert_eq!(reread.as_slice(), key.as_slice(), "WireGuard key tampered");

    vault.remove().expect("removing the vault");
    assert!(!vault.exists(), "the vault still exists after removal");

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// Arming, then revoking, must be observable on a real TPM.
///
/// The part no hardware trial can cover here is the one that matters most:
/// consuming a window requires PCR 4 to have actually moved, hence a kernel
/// upgrade and a controlled reboot. That stays a manual procedure —
/// see `docs/testing/TESTING.md`. What this proves is the half that can be
/// proven in one process: the NV payload is policy-readable after arming and
/// really overwritten after revocation.
#[test]
fn an_update_window_is_armed_then_revoked_on_the_tpm() {
    if !hardware_requested("update window NV lifecycle") {
        return;
    }
    let dir = disposable_dir("fenetre-maj");
    let cfg = settings(&dir, true);

    let provisioned = BootController::unlock(&cfg).expect("initial provisioning");
    assert!(
        !BootController::update_window_armed(&cfg).expect("reading the window state"),
        "no window may be armed before one is asked for"
    );

    // Arming refuses anything but a nominal unseal, so re-unlock first.
    let unsealed = BootController::unlock(&settings(&dir, false)).expect("nominal unseal");
    assert!(matches!(unsealed, BootDecision::Unsealed(_)));
    assert_eq!(
        provisioned.secret().map(|s| s.as_bytes()),
        unsealed.secret().map(|s| s.as_bytes())
    );

    BootController::arm_update_window(&cfg, &unsealed).expect("arming the window");
    assert!(
        BootController::update_window_armed(&cfg).expect("reading the window state"),
        "the NV payload must be live after arming"
    );
    assert!(
        std::path::Path::new(&cfg.update_window_marker_path).exists(),
        "no window marker written"
    );
    let copied_marker = std::fs::read(&cfg.update_window_marker_path).expect("copying marker");

    BootController::cancel_update_window(&cfg).expect("revoking the window");
    assert!(
        !BootController::update_window_armed(&cfg).expect("reading the window state"),
        "the NV index must be written after revocation"
    );
    assert!(
        !std::path::Path::new(&cfg.update_window_marker_path).exists(),
        "the window marker outlived its revocation"
    );

    // Restoring everything the disk ever held must not restore the secret:
    // the only payload lived in NV and was overwritten there.
    std::fs::write(&cfg.update_window_marker_path, copied_marker).expect("restoring marker");
    assert!(
        !BootController::update_window_armed(&cfg).expect("reading restored marker state"),
        "a disk marker resurrected a revoked NV payload"
    );
    BootController::cancel_update_window(&cfg).expect("removing restored marker");

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// Both counter trials use the same disposable index: serialised, so that one
/// never undefines the counter the other is measuring.
static COUNTER_INDEX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Disposable counter index, distinct from the production one.
const DISPOSABLE_COUNTER_INDEX: u32 = 0x0180_4848;

/// Removes the disposable counter if it is defined; a missing index is the
/// normal starting state of a trial.
fn undefine_disposable_counter(tcti: &str) {
    use tss_esapi::{
        handles::NvIndexTpmHandle, interface_types::resource_handles::Provision, Context,
        TctiNameConf,
    };
    let mut ctx =
        Context::new(TctiNameConf::from_str(tcti).expect("TCTI name")).expect("TPM context");
    let tpm_handle = NvIndexTpmHandle::new(DISPOSABLE_COUNTER_INDEX).expect("NV index");
    let Ok(object) = ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle.into()))
    else {
        return;
    };
    let handle = tss_esapi::handles::NvIndexHandle::from(object);
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, handle))
        .expect("undefining the disposable counter");
}

/// Defines the disposable counter exactly as the gateway does, but without the
/// first increment: the state a power cut leaves between the two commands.
fn define_disposable_counter_without_increment(tcti: &str) {
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        constants::nv_index_type::NvIndexType,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
        structures::{Digest, NvPublicBuilder},
        Context, TctiNameConf,
    };
    let mut ctx =
        Context::new(TctiNameConf::from_str(tcti).expect("TCTI name")).expect("TPM context");
    let attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_nv_index_type(NvIndexType::Counter)
        .with_no_da(true)
        .build()
        .expect("NV attributes");
    let public = NvPublicBuilder::new()
        .with_nv_index(NvIndexTpmHandle::new(DISPOSABLE_COUNTER_INDEX).expect("NV index"))
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_index_auth_policy(Digest::try_from(Vec::<u8>::new()).expect("empty digest"))
        .with_data_area_size(8)
        .build()
        .expect("NV public");
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_define_space(Provision::Owner, None, public))
        .expect("defining the disposable counter");
}

/// A counter defined but never incremented (power cut between the two
/// commands) must be completed by `ensure`, not left unreadable forever.
#[test]
fn a_defined_but_unincremented_counter_is_completed_on_the_tpm() {
    if !hardware_requested("anti-rollback counter completion") {
        return;
    }
    let _serial = COUNTER_INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = disposable_dir("compteur-non-incremente");
    let tcti = std::env::var("HELIOS_TPM_TCTI").unwrap_or_else(|_| "/dev/tpmrm0".into());
    let cfg = TpmSettings {
        anti_rollback_nv_index: DISPOSABLE_COUNTER_INDEX,
        ..settings(&dir, false)
    };

    // A counter redefined after an undefine resumes from the highest value it
    // reached: the TPM does not let an undefine roll it back. The expected
    // value is therefore relative to the value read before the undefine.
    let before = helios_tpm::anti_rollback::current(&cfg).ok().unwrap_or(0);
    undefine_disposable_counter(&tcti);
    define_disposable_counter_without_increment(&tcti);
    assert!(
        helios_tpm::anti_rollback::current(&cfg).is_err(),
        "an unwritten counter must not be readable before ensure"
    );

    // ensure completes the owed first increment; advance adds its own.
    let advanced = helios_tpm::anti_rollback::advance(&cfg)
        .expect("advance must complete the unwritten counter");
    assert_eq!(
        advanced,
        before + 2,
        "ensure's first increment, then advance's own, from the preserved value"
    );
    assert_eq!(
        helios_tpm::anti_rollback::current(&cfg).expect("reading the completed counter"),
        advanced
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The anti-rollback counter moves forward on the TPM and only there: each
/// `advance` survives a new connection, and the value never goes back.
///
/// Uses the disposable index `0x01804848`, distinct from the production
/// counter `0x01804847`. The index survives the trial; remove it with
/// `tpm2_nvundefine 0x01804848` if the machine is not disposable.
#[test]
fn the_anti_rollback_counter_only_moves_forward_on_the_tpm() {
    if !hardware_requested("anti-rollback NV counter") {
        return;
    }
    let _serial = COUNTER_INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = disposable_dir("compteur-anti-rollback");
    let cfg = TpmSettings {
        anti_rollback_nv_index: DISPOSABLE_COUNTER_INDEX,
        ..settings(&dir, false)
    };

    let first =
        helios_tpm::anti_rollback::advance(&cfg).expect("defining and advancing the counter");
    assert_eq!(
        helios_tpm::anti_rollback::current(&cfg).expect("reading the counter on a new connection"),
        first,
        "the counter must persist on the TPM across connections"
    );

    let second = helios_tpm::anti_rollback::advance(&cfg).expect("advancing the counter again");
    assert_eq!(
        second,
        first + 1,
        "each advance moves the counter by exactly one"
    );
    assert_eq!(
        helios_tpm::anti_rollback::current(&cfg).expect("reading the counter after advance"),
        second
    );

    let published: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&cfg.counter_status_path).expect("reading the published status"),
    )
    .expect("the status is JSON");
    assert_eq!(published, serde_json::json!({ "counter": second }));

    let _ = std::fs::remove_dir_all(&dir);
}
