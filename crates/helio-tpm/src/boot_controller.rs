use crate::settings::TpmSettings;
use tracing::{error, info, warn};

use crate::{
    blob_store::BlobStore, provisioning, secret::SecretKey, tpm_interface::TpmSealer, Result,
    TpmError,
};

/// Outcome of the boot-time unlock sequence.
#[derive(Debug)]
pub enum BootDecision {
    /// Validation disabled (`tpm.enabled = false`) — dev/WSL2, no secret.
    Disabled,
    /// Failure ignored because `enforce = false` (DEBUG) — no secret.
    Bypassed,
    /// Nominal unseal: integrity confirmed, existing secret retrieved.
    Unsealed(SecretKey),
    /// First boot: secret provisioned (TOFU). Credentials must be (re)encrypted.
    Provisioned(SecretKey),
    /// Post-OTA resealing authorized: new secret. Credentials must be (re)encrypted.
    Resealed(SecretKey),
}

impl BootDecision {
    /// Unlock secret if available (used to decrypt the WireGuard secrets).
    pub fn secret(&self) -> Option<&SecretKey> {
        match self {
            BootDecision::Unsealed(s)
            | BootDecision::Provisioned(s)
            | BootDecision::Resealed(s) => Some(s),
            BootDecision::Disabled | BootDecision::Bypassed => None,
        }
    }
}

/// Flow controller: single entry point of the integrity validation.
///
/// Must be called **first** in `heliosd::run()`, before any network initialization.
pub struct BootController;

impl BootController {
    pub fn unlock(cfg: &TpmSettings) -> Result<BootDecision> {
        if !cfg.enabled {
            info!("TPM sealing disabled (tpm.enabled = false) — booting without verification");
            return Ok(BootDecision::Disabled);
        }

        match Self::unlock_inner(cfg) {
            Ok(decision) => Ok(decision),
            Err(e) if !cfg.enforce => {
                warn!(
                    "TPM failure ignored (enforce=false, DEBUG ONLY — \
                     never use in production): {e}"
                );
                Ok(BootDecision::Bypassed)
            }
            Err(e) => {
                error!("INTEGRITY VALIDATION FAILED — stopping: {e}");
                Err(e)
            }
        }
    }

    fn unlock_inner(cfg: &TpmSettings) -> Result<BootDecision> {
        let mut tpm = open_tpm(cfg)?;
        let store = BlobStore::new(cfg);
        Self::run_flow(cfg, &mut tpm, &store)
    }

    /// Decision logic, generic over the TPM backend (testable with `DryRunTpm`).
    fn run_flow<T: TpmSealer>(
        cfg: &TpmSettings,
        tpm: &mut T,
        store: &BlobStore<'_>,
    ) -> Result<BootDecision> {
        match store.load_blob()? {
            // Blob present -> attempt unseal (nominal case).
            Some(blob) => match tpm.unseal(&blob) {
                Ok(secret) => {
                    info!("unseal succeeded — boot integrity confirmed");
                    Ok(BootDecision::Unsealed(secret))
                }
                Err(TpmError::UnsealPolicyFail) => {
                    // PCRs changed: legitimate OTA (ticket) or attack (refusal).
                    warn!("unseal refused (PCRs changed) — looking for a reseal ticket");
                    let secret = provisioning::reseal(tpm, store)?;
                    Ok(BootDecision::Resealed(secret))
                }
                Err(e) => Err(e),
            },
            // No blob -> provisioning only if explicitly allowed.
            None => {
                if cfg.allow_provisioning {
                    let secret = provisioning::provision(tpm, store)?;
                    Ok(BootDecision::Provisioned(secret))
                } else {
                    Err(TpmError::MissingBlobOnField)
                }
            }
        }
    }
}

/// Opens the TPM backend: real on target (`feature tpm`), simulated otherwise.
fn open_tpm(cfg: &TpmSettings) -> Result<impl TpmSealer> {
    #[cfg(feature = "tpm")]
    {
        crate::tpm_interface::TpmDevice::new(cfg)
    }
    #[cfg(not(feature = "tpm"))]
    {
        let _ = cfg;
        Ok(crate::tpm_interface::DryRunTpm::from_env())
    }
}

#[cfg(test)]
mod tests {
    use aether::sig::{PublisherSigner, ResealPayload};

    use super::*;
    use crate::tpm_interface::DryRunTpm;

    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";

    /// Builds a TPM config pointing to a temporary directory.
    fn test_cfg(dir: &std::path::Path, allow_provisioning: bool) -> TpmSettings {
        TpmSettings {
            enabled: true,
            enforce: true,
            allow_provisioning,
            device: "/dev/tpmrm0".into(),
            pcr_bank: "sha256".into(),
            pcr_selection: vec![0, 4, 7],
            sealed_blob_path: dir.join("sealed.key").to_string_lossy().into(),
            ticket_path: dir.join("ticket.json").to_string_lossy().into(),
            state_path: dir.join("state.json").to_string_lossy().into(),
        }
    }

    /// Writes a ticket signed by the development key to disk.
    fn write_ticket(path: &std::path::Path, version: u64, expected_pcr_digest: Option<[u8; 32]>) {
        let signer = PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED).unwrap();
        let ticket = signer
            .sign(ResealPayload {
                version,
                expected_pcr_digest,
            })
            .unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&ticket).unwrap()).unwrap();
    }

    #[test]
    fn provisioning_then_nominal_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        // First boot: no blob -> provisioning.
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        let d = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d, BootDecision::Provisioned(_)));

        // Next boot, same PCRs -> nominal unseal, same secret.
        let secret1 = d.secret().unwrap().as_bytes().to_vec();
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        let d2 = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d2, BootDecision::Unsealed(_)));
        assert_eq!(d2.secret().unwrap().as_bytes().to_vec(), secret1);
    }

    #[test]
    fn missing_blob_in_field_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), false); // provisioning forbidden
        let store = BlobStore::new(&cfg);
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::MissingBlobOnField)
        ));
    }

    #[test]
    fn changed_pcrs_without_ticket_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap(); // provision

        // Modified kernel (different PCRs) without ticket -> refusal.
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::UnsealFailedNoTicket)
        ));
    }

    #[test]
    fn ota_with_valid_ticket_reseals() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap(); // provision, version 0

        // OTA: new PCRs + signed ticket version 1.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        let d = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d, BootDecision::Resealed(_)));

        // Ticket consumed; next boot on the same new PCRs -> nominal unseal.
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        let d2 = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d2, BootDecision::Unsealed(_)));
    }

    #[test]
    fn replayed_ticket_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap();

        // First resealing with ticket version 1 -> state version 1.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap();

        // Replay of the same version-1 ticket on new PCRs -> anti-rollback.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([3u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::TicketRollback { .. })
        ));
    }
}
