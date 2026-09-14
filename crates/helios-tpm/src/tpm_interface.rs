use zeroize::Zeroizing;

use crate::{secret::SecretKey, Result};

/// Opaque sealed blob, as stored on the configuration partition.
#[derive(Debug, Clone)]
pub(crate) struct SealedBlob(pub Vec<u8>);

impl SealedBlob {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Sealing primitives exposed by the TPM (real or simulated).
///
/// PCR indices/bank are carried by the implementation (from config), not
/// passed to `seal`: sealing and unsealing thus stay consistent.
pub(crate) trait TpmSealer {
    /// Identity digest of the current PCR state (used to bind the reseal ticket).
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]>;
    /// Seals `secret` against the current PCR policy; returns the blob to persist.
    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob>;
    /// Attempts to unseal the blob; `UnsealPolicyFail` if the PCRs changed.
    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey>;

    // ── Update window (see `crate::update_window`) ───────────────────────────

    /// Arms the window by writing `payload` into a policy-protected NV index.
    fn arm_update_window(&mut self, payload: &[u8]) -> Result<()>;
    /// Reads the window payload through its PCR 0/7 policy.
    fn unseal_update_window(&mut self) -> Result<Zeroizing<Vec<u8>>>;
    /// Revokes the window by overwriting its NV payload. Idempotent.
    ///
    /// This is the one operation that must not be skipped: it destroys the
    /// only protected copy of the window secret.
    fn revoke_update_window(&mut self) -> Result<()>;
    /// Does the policy-protected NV slot contain a live Helios payload?
    fn update_window_armed(&mut self) -> Result<bool>;
}

// ───────────────────────── Simulated backend (WSL2 / dev) ─────────────────────────

/// Simulated TPM: faithfully reproduces PCR-binding semantics without hardware.
///
/// `seal` records the current PCR digest in the blob; `unseal` only returns
/// the secret if the current digest is identical. Changing `pcr_digest`
/// between two instances simulates a kernel/bootloader change (OTA or attack).
///
/// **Not secure** (the secret is in the clear in the blob) — reserved for
/// dev/tests. Compiled outside `feature tpm` (default backend) and for tests.
#[cfg(any(not(feature = "tpm"), test))]
pub(crate) struct DryRunTpm {
    pcr_digest: [u8; 32],
    window_digest: [u8; 32],
    nv: NvState,
}

/// The part of a simulated TPM that **survives a reboot**.
///
/// The NV index does not live on the configuration partition, so a test that
/// models a reboot by building a fresh [`DryRunTpm`] must carry it across —
/// otherwise revocation would look like it works while the property under
/// test, "a spent window stays spent", is never exercised.
#[cfg(any(not(feature = "tpm"), test))]
#[derive(Clone, Default)]
pub(crate) struct NvState(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

#[cfg(any(not(feature = "tpm"), test))]
impl NvState {
    fn get(&self) -> Option<Vec<u8>> {
        self.0.lock().expect("simulated NV state poisoned").clone()
    }

    fn set(&self, value: Option<Vec<u8>>) {
        let mut state = self.0.lock().expect("simulated NV state poisoned");
        if let Some(previous) = state.as_mut() {
            zeroize::Zeroize::zeroize(previous);
        }
        *state = value;
    }
}

#[cfg(any(not(feature = "tpm"), test))]
impl DryRunTpm {
    /// Builds from the environment: `HELIOS_TPM_FAKE_PCR` (32-byte hex) or zeros.
    #[cfg(not(feature = "tpm"))]
    pub(crate) fn from_env() -> Self {
        let pcr_digest = std::env::var("HELIOS_TPM_FAKE_PCR")
            .ok()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0u8; 32]);
        let window_digest = std::env::var("HELIOS_TPM_FAKE_WINDOW_PCR")
            .ok()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0u8; 32]);
        tracing::warn!(
            "simulated TPM ('tpm' feature not compiled) — NO hardware guarantee. \
             Recompile with --features tpm on the target."
        );
        Self {
            pcr_digest,
            window_digest,
            nv: NvState::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_digest(pcr_digest: [u8; 32]) -> Self {
        Self {
            pcr_digest,
            window_digest: [0u8; 32],
            nv: NvState::default(),
        }
    }

    /// Sets the PCR 0/7 state the window is bound to, separately from the
    /// nominal 0/4/7 state — that separation is the whole point of the
    /// window, so a test that cannot move one without the other proves
    /// nothing.
    #[cfg(test)]
    pub(crate) fn with_window_digest(mut self, window_digest: [u8; 32]) -> Self {
        self.window_digest = window_digest;
        self
    }

    /// Shares the non-volatile state with another instance, i.e. models the
    /// same TPM across a reboot.
    #[cfg(test)]
    pub(crate) fn sharing_nv(mut self, nv: &NvState) -> Self {
        self.nv = nv.clone();
        self
    }
}

#[cfg(any(not(feature = "tpm"), test))]
impl TpmSealer for DryRunTpm {
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.pcr_digest)
    }

    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob> {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&self.pcr_digest);
        blob.extend_from_slice(secret.as_bytes());
        Ok(SealedBlob::from_bytes(blob))
    }

    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey> {
        let bytes = blob.as_bytes();
        if bytes.len() != 64 {
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        let bound = &bytes[..32];
        if bound != self.pcr_digest {
            // Current PCRs differ from those at sealing time -> the TPM would refuse.
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[32..]);
        Ok(SecretKey::from_bytes(key))
    }

    fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(32 + payload.len());
        data.extend_from_slice(&self.window_digest);
        data.extend_from_slice(payload);
        self.nv.set(Some(data));
        Ok(())
    }

    fn unseal_update_window(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self
            .nv
            .get()
            .ok_or(crate::TpmError::UpdateWindowUnavailable)?;
        if bytes.len() < 32 || bytes[..32] != self.window_digest {
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        if !crate::update_window::is_armed_payload(&bytes[32..]) {
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        Ok(Zeroizing::new(bytes[32..].to_vec()))
    }

    fn revoke_update_window(&mut self) -> Result<()> {
        self.nv.set(None);
        Ok(())
    }

    fn update_window_armed(&mut self) -> Result<bool> {
        Ok(self.nv.get().is_some_and(|bytes| {
            bytes.len() >= 36 && crate::update_window::is_armed_prefix(&bytes[32..36])
        }))
    }
}

// ───────────────────────── Real backend (target, feature tpm) ─────────────────────────
//
// The real TPM2 implementation (hardened sealing/unsealing, encrypted
// sessions) lives in `tpm_real.rs` to keep this file readable. Re-exported
// here so `boot_controller` keeps the `crate::tpm_interface::TpmDevice` path.
#[cfg(feature = "tpm")]
pub(crate) use crate::tpm_real::TpmDevice;
