//! The TPM vault: first provisioning, and the update window that carries its
//! secret across an OS upgrade.
//!
//! Also the single door every other offline command goes through to unseal:
//! `unlock_tpm_for_offline_command` makes the process non-dumpable first.

use anyhow::Context;
use helios_tpm::{BootController, BootDecision, TpmSettings};
use tracing::{info, warn};

use crate::process_guards::forbid_core_dumps;
use crate::TpmCommand;

/// Drives the update window (see `helios_tpm::update_window`).
pub(crate) fn tpm_command(command: TpmCommand) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    match command {
        TpmCommand::PrepareUpdate { reboot } => prepare_update(&tpm, reboot),
        TpmCommand::CancelUpdate => {
            BootController::cancel_update_window(&tpm).context("revoking the update window")?;
            info!("update window revoked");
            Ok(())
        }
        TpmCommand::ExpireWindow => expire_update_window(&tpm),
        TpmCommand::UpdateStatus => {
            match BootController::update_window_armed(&tpm).context("reading the window state")? {
                true => println!("armed"),
                false => println!("none"),
            }
            Ok(())
        }
        TpmCommand::UpdateReadiness => update_readiness(&tpm),
    }
}

/// Answers whether `prepare-update` would succeed, without arming anything.
///
/// Three answers on stdout, because they lead to three different operations:
///
/// - `ready` — the boot unsealed nominally, a window can carry that verdict;
/// - `disabled` — nothing is sealed to the PCRs, so an OS upgrade has no
///   secret to lose and needs no window;
/// - `unavailable` — the TPM answers but this boot is not a nominal unseal
///   (bypassed, provisioned, resealed). The reason is logged, on stderr.
///
/// An unreachable TPM is none of the three: the command fails, and the caller
/// must treat that as a refusal rather than as an absent window. That
/// distinction is the whole point of asking *before* upgrading — after
/// `apt upgrade` there is no answer left that saves the vaults.
///
/// The probe runs the **same** unlock as arming, deliberately: a prediction
/// made by a different path would be a different question. It inherits that
/// path's effects — on a boot whose PCRs have already moved it can consume a
/// reseal ticket, exactly as `prepare-update` would have.
fn update_readiness(tpm: &TpmSettings) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(tpm).context("unlocking the TPM vault")?;
    match boot {
        BootDecision::Unsealed(_) => println!("ready"),
        BootDecision::Disabled => println!("disabled"),
        other => {
            warn!(
                "the current boot is {other:?}, not a nominal unseal — no update \
                 window can be armed from it"
            );
            println!("unavailable");
        }
    }
    Ok(())
}

/// Revokes an armed window whose explicit marker deadline has passed.
fn expire_update_window(tpm: &TpmSettings) -> anyhow::Result<()> {
    if !BootController::expire_update_window(tpm).context("expiring the update window")? {
        return Ok(());
    }
    warn!(
        "update window expired without a reboot — revoked. Arm a new one when the \
         upgrade is actually ready."
    );
    Ok(())
}

/// Arms the window, then optionally reboots.
///
/// Arming requires a **nominal** unseal here and now: the window carries an
/// integrity verdict across a reboot, it does not create one. A gateway that
/// is already running on a resealed or bypassed secret is refused, loudly,
/// rather than propagating a state the boot chain never vouched for.
fn prepare_update(tpm: &TpmSettings, reboot: bool) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(tpm).context("unlocking the TPM vault")?;
    if !matches!(boot, BootDecision::Unsealed(_)) {
        anyhow::bail!(
            "the current boot is {boot:?}, not a nominal unseal — an update window \
             may only be armed from a boot whose integrity the TPM confirmed"
        );
    }

    let deadline = BootController::arm_update_window(tpm, &boot)
        .map_err(|e| anyhow::anyhow!("arming the update window: {e}"))?;

    warn!(
        deadline,
        "update window armed — it expires on its own, and any boot that unseals \
         nominally revokes it. Reboot now, or run `heliosd tpm cancel-update`."
    );
    if !reboot {
        println!("window armed until unix {deadline} — reboot before then");
        return Ok(());
    }

    println!("window armed until unix {deadline} — rebooting");
    let status = std::process::Command::new("systemctl")
        .arg("reboot")
        .status()
        .context("invoking systemctl reboot")?;
    anyhow::ensure!(
        status.success(),
        "systemctl reboot failed ({status}) — the window stays armed; reboot by hand \
         or run `heliosd tpm cancel-update`"
    );
    Ok(())
}

/// Seals a fresh secret into the TPM, on first deployment only.
///
/// `TpmSettings::default()` carries `allow_provisioning = false`: this is
/// deliberate, an absent vault in the field signals it may have been erased
/// to force a fake first boot. Nominal startup must therefore stop there.
///
/// A path for the first sealing is nonetheless needed, without which a
/// gateway built with the `tpm` feature could never start. This command is
/// that path: explicit, distinct from startup, and refusing to overwrite an
/// existing vault — an overwrite would destroy the gateway's identity with
/// no way back.
pub(crate) fn provision_tpm() -> anyhow::Result<()> {
    let mut tpm = TpmSettings::default();

    validate_provisioning_request(&tpm)?;

    tpm.allow_provisioning = true;
    match unlock_tpm_for_offline_command(&tpm)
        .map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?
    {
        BootDecision::Provisioned(_) => {
            info!(
                "TPM vault provisioned in {} — bound to PCR {:?} of bank {}",
                tpm.sealed_blob_path, tpm.pcr_selection, tpm.pcr_bank
            );
            info!(
                "start heliosd: the plaintext WireGuard key from network.toml will be \
                 sealed automatically, after which `wg_private_key` can be removed from it"
            );
            Ok(())
        }
        other => anyhow::bail!("expected provisioning, got: {other:?}"),
    }
}

/// Refuses unsafe provisioning requests before opening the TPM device.
fn validate_provisioning_request(tpm: &TpmSettings) -> anyhow::Result<()> {
    if !tpm.enabled {
        anyhow::bail!(
            "binary built without the `tpm` feature: no sealing possible. \
             Rebuild with --features tpm on the target."
        );
    }

    if std::path::Path::new(&tpm.sealed_blob_path).exists() {
        anyhow::bail!(
            "a vault already exists in {} — refusing to overwrite it. Deleting it \
             would lose the gateway's sealed identity.",
            tpm.sealed_blob_path
        );
    }
    Ok(())
}

/// Applies process-memory protection before an offline command can create or
/// unseal the TPM root secret.
pub(crate) fn unlock_tpm_for_offline_command(tpm: &TpmSettings) -> anyhow::Result<BootDecision> {
    forbid_core_dumps(false)?;
    BootController::unlock(tpm).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_refuses_a_disabled_tpm_and_an_existing_vault() {
        let disabled = TpmSettings {
            enabled: false,
            ..TpmSettings::default()
        };
        assert!(validate_provisioning_request(&disabled)
            .unwrap_err()
            .to_string()
            .contains("without the `tpm` feature"));

        let directory = std::env::temp_dir().join(format!(
            "helios-provisioning-guard-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let blob = directory.join("sealed.key");
        std::fs::write(&blob, b"existing vault").unwrap();
        let existing = TpmSettings {
            enabled: true,
            sealed_blob_path: blob.to_string_lossy().into_owned(),
            ..TpmSettings::default()
        };
        assert!(validate_provisioning_request(&existing)
            .unwrap_err()
            .to_string()
            .contains("refusing to overwrite"));

        std::fs::remove_dir_all(directory).unwrap();
    }
}
