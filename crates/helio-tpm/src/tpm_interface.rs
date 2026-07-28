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
        tracing::warn!(
            "simulated TPM ('tpm' feature not compiled) — NO hardware guarantee. \
             Recompile with --features tpm on the target."
        );
        Self { pcr_digest }
    }

    #[cfg(test)]
    pub(crate) fn with_digest(pcr_digest: [u8; 32]) -> Self {
        Self { pcr_digest }
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
}

// ───────────────────────── Real backend (target, feature tpm) ─────────────────────────
//
// The real TPM2 implementation (hardened sealing/unsealing, encrypted
// sessions) lives in `tpm_real.rs` to keep this file readable. Re-exported
// here so `boot_controller` keeps the `crate::tpm_interface::TpmDevice` path.
#[cfg(feature = "tpm")]
pub(crate) use crate::tpm_real::TpmDevice;
