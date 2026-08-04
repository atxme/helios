use crate::settings::TpmSettings;
use tracing::{error, info, warn};

use crate::{
    blob_store::BlobStore, provisioning, secret::SecretKey, tpm_interface::TpmSealer,
    update_window::WindowMarker, Result, TpmError,
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
    /// Planned OS upgrade: the update window carried the **same** secret
    /// across the reboot and it has been resealed on the new PCR state.
    ///
    /// Distinct from [`Self::Resealed`] because the consequence is opposite:
    /// nothing was re-keyed, every vault still opens, no client is affected.
    WindowResealed(SecretKey),
}

impl BootDecision {
    /// Unlock secret if available (used to decrypt the WireGuard secrets).
    pub fn secret(&self) -> Option<&SecretKey> {
        match self {
            BootDecision::Unsealed(s)
            | BootDecision::Provisioned(s)
            | BootDecision::Resealed(s)
            | BootDecision::WindowResealed(s) => Some(s),
            BootDecision::Disabled | BootDecision::Bypassed => None,
        }
    }

    /// Non-secret name of this decision, safe to publish.
    ///
    /// Exists so the console can report the gateway's sealing posture without
    /// the API ever holding a [`BootDecision`] — which carries the unlock
    /// secret, and must not transit through the API crate.
    pub fn kind(&self) -> &'static str {
        match self {
            BootDecision::Disabled => "disabled",
            BootDecision::Bypassed => "bypassed",
            BootDecision::Unsealed(_) => "unsealed",
            BootDecision::Provisioned(_) => "provisioned",
            BootDecision::Resealed(_) => "resealed",
            BootDecision::WindowResealed(_) => "window_resealed",
        }
    }

    /// Did this boot preserve the secret the vaults were encrypted under?
    ///
    /// The two decisions that answer `false` are the ones after which
    /// `wg-key.sealed` and the key-negotiation identity no longer open.
    pub fn preserved_vaults(&self) -> bool {
        matches!(
            self,
            BootDecision::Unsealed(_) | BootDecision::WindowResealed(_)
        )
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

    /// Arms an update window carrying the secret of `decision` across one
    /// planned reboot.
    ///
    /// Refuses anything but [`BootDecision::Unsealed`]. A window armed from a
    /// bypassed or freshly resealed boot would extend a state the boot chain
    /// has not vouched for — the window is meant to *carry* an integrity
    /// verdict across a reboot, never to manufacture one.
    pub fn arm_update_window(cfg: &TpmSettings, decision: &BootDecision) -> Result<u64> {
        let BootDecision::Unsealed(secret) = decision else {
            return Err(TpmError::UpdateWindowUnavailable);
        };
        let deadline = now_unix()?.saturating_add(cfg.update_window_seconds);
        let mut tpm = open_tpm(cfg)?;
        let store = BlobStore::new(cfg);
        provisioning::arm_window(&mut tpm, &store, secret, deadline)?;
        Ok(deadline)
    }

    /// Revokes an armed window and removes its non-secret marker. Idempotent.
    pub fn cancel_update_window(cfg: &TpmSettings) -> Result<()> {
        let mut tpm = open_tpm(cfg)?;
        provisioning::disarm_window(&mut tpm, &BlobStore::new(cfg))
    }

    /// Is a window armed on this TPM, and until when?
    ///
    /// This reads only the payload magic, never the secret or deadline.
    pub fn update_window_armed(cfg: &TpmSettings) -> Result<bool> {
        open_tpm(cfg)?.update_window_armed()
    }

    /// Revokes a stale window using its non-secret marker deadline.
    ///
    /// A malformed marker is revoked fail-closed. A missing marker means no
    /// legitimate live window because the valid arm sequence persists it
    /// durably before putting the secret in NV.
    pub fn expire_update_window(cfg: &TpmSettings) -> Result<bool> {
        let mut tpm = open_tpm(cfg)?;
        let store = BlobStore::new(cfg);
        Self::expire_update_window_at(&mut tpm, &store, now_unix()?, cfg.update_window_seconds)
    }

    fn expire_update_window_at<T: TpmSealer>(
        tpm: &mut T,
        store: &BlobStore<'_>,
        now: u64,
        maximum_duration: u64,
    ) -> Result<bool> {
        let marker = store.load_window_marker()?;
        let Some(marker) = marker else {
            // A valid arm persists the marker durably before writing the NV
            // payload, so no legitimate live window exists without it.
            return Ok(false);
        };

        let marker = match WindowMarker::decode(marker.as_bytes()) {
            Ok(marker) => marker,
            Err(_) => {
                provisioning::disarm_window(tpm, store)?;
                return Ok(true);
            }
        };
        // A deadline farther away than a freshly armed window indicates a
        // clock rollback or marker tampering. Both are safer to revoke than to
        // reinterpret as an extension.
        let implausibly_future = marker.deadline.saturating_sub(now) > maximum_duration;
        if now <= marker.deadline && !implausibly_future {
            return Ok(false);
        }

        provisioning::disarm_window(tpm, store)?;
        Ok(true)
    }

    /// Decision logic, generic over the TPM backend (testable with `DryRunTpm`).
    fn run_flow<T: TpmSealer>(
        cfg: &TpmSettings,
        tpm: &mut T,
        store: &BlobStore<'_>,
    ) -> Result<BootDecision> {
        Self::run_flow_at(cfg, tpm, store, now_unix()?)
    }

    /// Same flow with an injected clock, so the window's deadline is testable.
    fn run_flow_at<T: TpmSealer>(
        cfg: &TpmSettings,
        tpm: &mut T,
        store: &BlobStore<'_>,
        now: u64,
    ) -> Result<BootDecision> {
        match store.load_blob()? {
            // Blob present -> attempt unseal (nominal case).
            Some(blob) => match tpm.unseal(&blob) {
                Ok(secret) => {
                    info!("unseal succeeded — boot integrity confirmed");
                    // The upgrade did not move the PCRs after all — a window
                    // that stayed armed would be a standing invitation.
                    Self::close_unused_window(tpm, store)?;
                    Ok(BootDecision::Unsealed(secret))
                }
                Err(TpmError::UnsealPolicyFail) => {
                    // PCRs changed: planned upgrade (window), legitimate OTA
                    // (ticket), or attack (refusal). The window is tried
                    // first because it is the only path that costs nothing —
                    // it carries the existing secret instead of replacing it.
                    warn!("unseal refused (PCRs changed) — looking for an update window");
                    match Self::try_window(tpm, store, now)? {
                        Some(secret) => Ok(BootDecision::WindowResealed(secret)),
                        None => {
                            warn!("no usable update window — looking for a reseal ticket");
                            let secret = provisioning::reseal(tpm, store)?;
                            Ok(BootDecision::Resealed(secret))
                        }
                    }
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

impl BootController {
    /// Tries the armed window, if any.
    ///
    /// Only a window that is confirmed unusable and successfully revoked may
    /// fall through to the ticket path. An I/O or TPM failure is fatal: using
    /// a ticket while an old-secret window might still be live would create
    /// two competing identities.
    fn try_window<T: TpmSealer>(
        tpm: &mut T,
        store: &BlobStore<'_>,
        now: u64,
    ) -> Result<Option<SecretKey>> {
        match provisioning::consume_window(tpm, store, now) {
            Ok(secret) => Ok(Some(secret)),
            Err(error @ TpmError::UpdateWindowCleanupFailed(_)) => Err(error),
            Err(
                error @ (TpmError::UpdateWindowUnavailable
                | TpmError::UpdateWindowExpired { .. }
                | TpmError::UpdateWindowForeign
                | TpmError::UpdateWindowMalformed(_)
                | TpmError::UnsealPolicyFail),
            ) => {
                // Either PCR 0/7 moved too — a firmware or Secure Boot
                // change, out of the window's scope — or the metadata/payload
                // is absent, expired, or inconsistent. Owner write does not
                // depend on the read policy, so erase any residual payload
                // before a ticket is allowed to generate a different secret.
                warn!(
                    %error,
                    "update window is unusable — revoking any residual NV payload before \
                     considering a reseal ticket"
                );
                provisioning::disarm_window(tpm, store)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Closes a window left armed by an upgrade that turned out not to move
    /// the PCRs. A live payload that cannot be overwritten is fatal: starting
    /// the gateway would knowingly leave a second path to its identity open.
    fn close_unused_window<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<()> {
        match tpm.update_window_armed() {
            Ok(false) => {
                // Nothing armed. A leftover marker is inert, but remove it so
                // `status` does not report a window that cannot be used.
                if let Err(error) = store.remove_window_marker() {
                    warn!(%error, "could not remove an inert update-window marker");
                }
                Ok(())
            }
            Ok(true) => {
                warn!("update window still armed after a nominal unseal — revoking it");
                provisioning::disarm_window(tpm, store)
            }
            Err(error) => Err(error),
        }
    }
}

/// Wall clock in Unix seconds.
///
/// A clock before the Unix epoch is rejected rather than making every old
/// window appear fresh. The clock is operational expiry, not the TPM policy,
/// but its failure must still be fail-closed.
fn now_unix() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|error| TpmError::Connection(format!("system clock is invalid: {error}")))
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
            update_window_pcr_selection: vec![0, 7],
            update_window_marker_path: dir.join("update-window.marker").to_string_lossy().into(),
            update_window_nv_index: 0x0180_4845,
            update_window_seconds: 1800,
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

    // ── Update window ────────────────────────────────────────────────────────

    /// Boots the flow on a simulated machine: `boot` is the PCR 0/4/7 state,
    /// `window` the PCR 0/7 one, and `nv` is the TPM's non-volatile state,
    /// which survives across calls exactly as it does across reboots.
    fn boot_with(
        cfg: &TpmSettings,
        store: &BlobStore<'_>,
        nv: &crate::tpm_interface::NvState,
        boot: [u8; 32],
        window: [u8; 32],
        now: u64,
    ) -> Result<BootDecision> {
        let mut tpm = DryRunTpm::with_digest(boot)
            .with_window_digest(window)
            .sharing_nv(nv);
        BootController::run_flow_at(cfg, &mut tpm, store, now)
    }

    struct FailingRevokeTpm(DryRunTpm);

    impl TpmSealer for FailingRevokeTpm {
        fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
            self.0.current_pcr_digest()
        }

        fn seal(&mut self, secret: &SecretKey) -> Result<crate::tpm_interface::SealedBlob> {
            self.0.seal(secret)
        }

        fn unseal(&mut self, blob: &crate::tpm_interface::SealedBlob) -> Result<SecretKey> {
            self.0.unseal(blob)
        }

        fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
            self.0.arm_update_window(payload)
        }

        fn unseal_update_window(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            self.0.unseal_update_window()
        }

        fn revoke_update_window(&mut self) -> Result<()> {
            Err(TpmError::Connection("injected NV write failure".into()))
        }

        fn update_window_armed(&mut self) -> Result<bool> {
            self.0.update_window_armed()
        }
    }

    struct LostArmResponseTpm {
        inner: DryRunTpm,
        revoke_fails: bool,
    }

    impl TpmSealer for LostArmResponseTpm {
        fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
            self.inner.current_pcr_digest()
        }

        fn seal(&mut self, secret: &SecretKey) -> Result<crate::tpm_interface::SealedBlob> {
            self.inner.seal(secret)
        }

        fn unseal(&mut self, blob: &crate::tpm_interface::SealedBlob) -> Result<SecretKey> {
            self.inner.unseal(blob)
        }

        fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
            self.inner.arm_update_window(payload)?;
            Err(TpmError::Connection("injected lost arm response".into()))
        }

        fn unseal_update_window(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            self.inner.unseal_update_window()
        }

        fn revoke_update_window(&mut self) -> Result<()> {
            if self.revoke_fails {
                return Err(TpmError::Connection("injected NV write failure".into()));
            }
            self.inner.revoke_update_window()
        }

        fn update_window_armed(&mut self) -> Result<bool> {
            self.inner.update_window_armed()
        }
    }

    /// The property the whole mode exists for: after a kernel upgrade, the
    /// gateway comes back with the **same** secret. Every vault keyed to it —
    /// the WireGuard identity, the key-negotiation identity, and through the
    /// latter the static-PSK table — still opens, and no client is re-enrolled.
    #[test]
    fn a_window_carries_the_same_secret_across_a_pcr_change() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let before = provisioned.secret().unwrap().as_bytes().to_vec();

        // Still running: the operator arms the window before rebooting.
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();

        // New kernel: PCR 4 moved, PCR 0/7 did not.
        let after = boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 500).unwrap();
        assert!(matches!(after, BootDecision::WindowResealed(_)));
        assert_eq!(after.secret().unwrap().as_bytes().to_vec(), before);
        assert!(after.preserved_vaults());

        // And the next boot is nominal again: the window resealed on the new state.
        let next = boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 600).unwrap();
        assert!(matches!(next, BootDecision::Unsealed(_)));
        assert_eq!(next.secret().unwrap().as_bytes().to_vec(), before);
    }

    #[test]
    fn a_lost_arm_response_is_compensated_before_the_marker_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();
        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();

        let mut tpm = LostArmResponseTpm {
            inner: DryRunTpm::with_digest([1u8; 32])
                .with_window_digest([9u8; 32])
                .sharing_nv(&nv),
            revoke_fails: false,
        };
        assert!(matches!(
            provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000),
            Err(TpmError::Connection(message)) if message == "injected lost arm response"
        ));
        assert!(!tpm.update_window_armed().unwrap());
        assert!(!std::path::Path::new(&cfg.update_window_marker_path).exists());
    }

    #[test]
    fn an_uncertain_arm_keeps_its_marker_when_compensation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();
        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();

        let mut tpm = LostArmResponseTpm {
            inner: DryRunTpm::with_digest([1u8; 32])
                .with_window_digest([9u8; 32])
                .sharing_nv(&nv),
            revoke_fails: true,
        };
        assert!(matches!(
            provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000),
            Err(TpmError::UpdateWindowCleanupFailed(_))
        ));
        assert!(tpm.update_window_armed().unwrap());
        assert!(std::path::Path::new(&cfg.update_window_marker_path).exists());
    }

    #[test]
    fn a_post_reseal_revocation_failure_never_falls_through_to_a_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let before = provisioned.secret().unwrap().as_bytes().to_vec();
        let mut arm_tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut arm_tpm, &store, provisioned.secret().unwrap(), 1_000)
            .unwrap();
        // A ticket must not be consumed after the same-secret nominal blob has
        // already been committed.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);

        let mut failing = FailingRevokeTpm(
            DryRunTpm::with_digest([2u8; 32])
                .with_window_digest([9u8; 32])
                .sharing_nv(&nv),
        );
        assert!(matches!(
            BootController::run_flow_at(&cfg, &mut failing, &store, 500),
            Err(TpmError::UpdateWindowCleanupFailed(_))
        ));

        // The committed blob still contains the original secret; the ticket
        // was neither used nor needed.
        let recovered = boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 600).unwrap();
        assert!(matches!(recovered, BootDecision::Unsealed(_)));
        assert_eq!(recovered.secret().unwrap().as_bytes(), before.as_slice());
        assert!(std::path::Path::new(&cfg.ticket_path).exists());
    }

    /// A window is good for one consumption. The second reboot must not be
    /// able to spend it again: the payload was overwritten inside the TPM.
    #[test]
    fn a_spent_window_stays_spent_even_if_the_marker_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();

        // A copied disk marker carries no secret; restoring it cannot restore
        // the NV payload after revocation.
        let stolen = std::fs::read(&cfg.update_window_marker_path).unwrap();

        boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 500).unwrap();

        // Blob back in place, PCRs moved again, no ticket: it must not open.
        std::fs::write(&cfg.update_window_marker_path, &stolen).unwrap();
        assert!(matches!(
            boot_with(&cfg, &store, &nv, [3u8; 32], [9u8; 32], 600),
            Err(TpmError::UnsealFailedNoTicket)
        ));
    }

    /// A window whose deadline has passed must not unlock anything.
    #[test]
    fn an_expired_window_falls_back_to_the_ticket_path() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();

        assert!(matches!(
            boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 1_001),
            Err(TpmError::UnsealFailedNoTicket)
        ));
        let mut status = DryRunTpm::with_digest([2u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        assert!(!status.update_window_armed().unwrap());
        assert!(!std::path::Path::new(&cfg.update_window_marker_path).exists());
    }

    #[test]
    fn a_missing_marker_revokes_any_residual_nv_payload() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();
        store.remove_window_marker().unwrap();

        assert!(matches!(
            boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 500),
            Err(TpmError::UnsealFailedNoTicket)
        ));
        assert!(!tpm.update_window_armed().unwrap());
    }

    #[test]
    fn expiry_revokes_the_nv_payload_without_unsealing_it() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();

        assert!(!BootController::expire_update_window_at(&mut tpm, &store, 999, 1_000).unwrap());
        assert!(tpm.update_window_armed().unwrap());
        assert!(BootController::expire_update_window_at(&mut tpm, &store, 1_001, 1_000).unwrap());
        assert!(!tpm.update_window_armed().unwrap());
        assert!(!std::path::Path::new(&cfg.update_window_marker_path).exists());
    }

    #[test]
    fn an_implausibly_future_marker_is_revoked_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 10_000).unwrap();

        assert!(BootController::expire_update_window_at(&mut tpm, &store, 100, 1_000).unwrap());
        assert!(!tpm.update_window_armed().unwrap());
    }

    /// PCR 0 or 7 moving — firmware, Secure Boot — is out of the window's
    /// scope by construction: the TPM itself refuses to open it.
    #[test]
    fn a_firmware_change_closes_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();

        assert!(matches!(
            boot_with(&cfg, &store, &nv, [2u8; 32], [8u8; 32], 500),
            Err(TpmError::UnsealFailedNoTicket)
        ));
        let mut original_policy = DryRunTpm::with_digest([2u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        assert!(!original_policy.update_window_armed().unwrap());
    }

    /// An upgrade that did not move the PCRs must not leave a live window
    /// behind — otherwise every uneventful upgrade widens the attack surface
    /// permanently.
    #[test]
    fn a_nominal_unseal_revokes_a_window_left_armed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut tpm, &store, provisioned.secret().unwrap(), 1_000).unwrap();
        let stolen = std::fs::read(&cfg.update_window_marker_path).unwrap();

        // Same PCRs: the upgrade shipped nothing that boots.
        let nominal = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 500).unwrap();
        assert!(matches!(nominal, BootDecision::Unsealed(_)));
        assert!(!std::path::Path::new(&cfg.update_window_marker_path).exists());

        // The window is dead in the TPM, not merely deleted from disk.
        std::fs::write(&cfg.update_window_marker_path, &stolen).unwrap();
        assert!(matches!(
            boot_with(&cfg, &store, &nv, [2u8; 32], [9u8; 32], 600),
            Err(TpmError::UnsealFailedNoTicket)
        ));
    }

    #[test]
    fn a_nominal_boot_fails_closed_if_the_live_window_cannot_be_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);
        let nv = crate::tpm_interface::NvState::default();

        let provisioned = boot_with(&cfg, &store, &nv, [1u8; 32], [9u8; 32], 0).unwrap();
        let mut arm_tpm = DryRunTpm::with_digest([1u8; 32])
            .with_window_digest([9u8; 32])
            .sharing_nv(&nv);
        provisioning::arm_window(&mut arm_tpm, &store, provisioned.secret().unwrap(), 1_000)
            .unwrap();

        let mut failing = FailingRevokeTpm(
            DryRunTpm::with_digest([1u8; 32])
                .with_window_digest([9u8; 32])
                .sharing_nv(&nv),
        );
        assert!(matches!(
            BootController::run_flow_at(&cfg, &mut failing, &store, 500),
            Err(TpmError::Connection(message)) if message == "injected NV write failure"
        ));
    }

    /// Arming from anything but a nominal unseal would let the window
    /// manufacture an integrity verdict instead of carrying one.
    #[test]
    fn only_a_nominal_unseal_may_arm_a_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path(), true);
        cfg.enabled = false;

        for decision in [
            BootDecision::Disabled,
            BootDecision::Bypassed,
            BootDecision::Provisioned(SecretKey::from_bytes([1u8; 32])),
            BootDecision::Resealed(SecretKey::from_bytes([1u8; 32])),
            BootDecision::WindowResealed(SecretKey::from_bytes([1u8; 32])),
        ] {
            assert!(
                matches!(
                    BootController::arm_update_window(&cfg, &decision),
                    Err(TpmError::UpdateWindowUnavailable)
                ),
                "{decision:?} must not be able to arm a window"
            );
        }
    }

    /// Only the two decisions that keep the secret may claim the vaults survived.
    #[test]
    fn preserved_vaults_names_the_decisions_that_keep_the_secret() {
        let key = || SecretKey::from_bytes([1u8; 32]);

        assert!(BootDecision::Unsealed(key()).preserved_vaults());
        assert!(BootDecision::WindowResealed(key()).preserved_vaults());
        assert!(!BootDecision::Resealed(key()).preserved_vaults());
        assert!(!BootDecision::Provisioned(key()).preserved_vaults());
        assert!(!BootDecision::Disabled.preserved_vaults());
        assert!(!BootDecision::Bypassed.preserved_vaults());
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
