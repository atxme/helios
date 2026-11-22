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

    // ── Anti-rollback counter (see `crate::anti_rollback`) ───────────────────

    /// Defines the counter index if it is missing (counter type, owner
    /// read/write, `no_da`), then makes the first increment. Idempotent: an
    /// already-advanced counter does not move.
    fn ensure_counter(&mut self) -> Result<()>;
    /// Reads the current counter value.
    fn read_counter(&mut self) -> Result<u64>;
    /// Increments the counter and returns the new value.
    fn increment_counter(&mut self) -> Result<u64>;
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
    counter: CounterState,
    /// Where the simulated counter survives between instances; `None` keeps it
    /// in memory only (tests).
    counter_path: Option<String>,
}

/// The simulated anti-rollback counter.
///
/// `Unreadable` keeps a corrupt or unreadable counter file as a state rather
/// than failing the whole TPM: `open_tpm` serves sealing and unsealing too,
/// and those must keep working. The counter operations report the cause.
#[cfg(any(not(feature = "tpm"), test))]
#[derive(Clone, Default)]
pub(crate) struct CounterState(std::sync::Arc<std::sync::Mutex<CounterCell>>);

#[cfg(any(not(feature = "tpm"), test))]
#[derive(Clone, Default)]
pub(crate) enum CounterCell {
    /// The index is not defined (no counter file).
    #[default]
    Undefined,
    Value(u64),
    /// The counter file exists but cannot be used; the cause is kept.
    Unreadable(String),
}

#[cfg(any(not(feature = "tpm"), test))]
impl CounterState {
    fn get(&self) -> CounterCell {
        self.0
            .lock()
            .expect("simulated counter state poisoned")
            .clone()
    }

    fn set(&self, cell: CounterCell) {
        *self.0.lock().expect("simulated counter state poisoned") = cell;
    }
}

/// The part of a simulated TPM that **survives a reboot**.
///
/// The NV indices do not live on the configuration partition, so a test that
/// models a reboot by building a fresh [`DryRunTpm`] must carry them across —
/// otherwise revocation would look like it works while the property under
/// test, "a spent window stays spent", is never exercised. The anti-rollback
/// counter is one of those indices.
#[cfg(any(not(feature = "tpm"), test))]
#[derive(Clone, Default)]
pub(crate) struct NvState {
    window: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// Only tests share NV state between instances, so only tests carry this.
    #[cfg(test)]
    counter: CounterState,
}

#[cfg(any(not(feature = "tpm"), test))]
impl NvState {
    fn get(&self) -> Option<Vec<u8>> {
        self.window
            .lock()
            .expect("simulated NV state poisoned")
            .clone()
    }

    fn set(&self, value: Option<Vec<u8>>) {
        let mut state = self.window.lock().expect("simulated NV state poisoned");
        if let Some(previous) = state.as_mut() {
            zeroize::Zeroize::zeroize(previous);
        }
        *state = value;
    }
}

#[cfg(any(not(feature = "tpm"), test))]
impl DryRunTpm {
    /// Builds from the environment: `HELIOS_TPM_FAKE_PCR` (32-byte hex) or zeros.
    ///
    /// The simulated counter is loaded from `cfg.simulated_counter_path`: a
    /// new instance is built on every `open_tpm`, so the counter must live on
    /// disk to stay monotonic. An absent file means the index is undefined; an
    /// unreadable one is kept as such and refuses the counter operations, never
    /// a reset to zero. Loading cannot fail: sealing must not depend on it.
    pub(crate) fn from_env(cfg: &crate::settings::TpmSettings) -> Self {
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
        let counter = CounterState::default();
        counter.set(load_simulated_counter(&cfg.simulated_counter_path));
        Self {
            pcr_digest,
            window_digest,
            nv: NvState::default(),
            counter,
            counter_path: Some(cfg.simulated_counter_path.clone()),
        }
    }

    /// Writes `value` to the counter file before it becomes visible in memory,
    /// so a failed write leaves the previous value in force.
    fn store_counter(&self, value: u64) -> Result<()> {
        if let Some(path) = &self.counter_path {
            crate::blob_store::atomic_write(path, value.to_string().as_bytes())
                .map_err(|error| crate::TpmError::CounterUnavailable(error.to_string()))?;
        }
        self.counter.set(CounterCell::Value(value));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_digest(pcr_digest: [u8; 32]) -> Self {
        Self {
            pcr_digest,
            window_digest: [0u8; 32],
            nv: NvState::default(),
            counter: CounterState::default(),
            counter_path: None,
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

    /// Shares the non-volatile state, counter included, with another
    /// instance, i.e. models the same TPM across a reboot.
    #[cfg(test)]
    pub(crate) fn sharing_nv(mut self, nv: &NvState) -> Self {
        self.counter = nv.counter.clone();
        self.nv = nv.clone();
        self
    }

    /// The anti-rollback counter of this instance, to share it with another
    /// instance that models the same TPM.
    #[cfg(test)]
    pub(crate) fn counter_handle(&self) -> CounterState {
        self.counter.clone()
    }

    /// Shares the anti-rollback counter with another instance, i.e. models the
    /// same TPM across a reboot.
    #[cfg(test)]
    pub(crate) fn sharing_counter(mut self, counter: &CounterState) -> Self {
        self.counter = counter.clone();
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

    fn ensure_counter(&mut self) -> Result<()> {
        match self.counter.get() {
            CounterCell::Undefined => self.store_counter(1),
            CounterCell::Value(_) => Ok(()),
            CounterCell::Unreadable(cause) => Err(crate::TpmError::CounterUnavailable(cause)),
        }
    }

    fn read_counter(&mut self) -> Result<u64> {
        match self.counter.get() {
            CounterCell::Value(value) => Ok(value),
            CounterCell::Undefined => Err(crate::TpmError::CounterUnavailable(
                "counter not defined".into(),
            )),
            CounterCell::Unreadable(cause) => Err(crate::TpmError::CounterUnavailable(cause)),
        }
    }

    fn increment_counter(&mut self) -> Result<u64> {
        let next = self
            .read_counter()?
            .checked_add(1)
            .ok_or_else(|| crate::TpmError::CounterUnavailable("counter overflow".into()))?;
        self.store_counter(next)?;
        Ok(next)
    }
}

/// Loads the simulated counter file. Absent is `Undefined`; anything that is not
/// a decimal u64 or cannot be read is `Unreadable`, never a reset.
#[cfg(any(not(feature = "tpm"), test))]
fn load_simulated_counter(path: &str) -> CounterCell {
    match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u64>() {
            Ok(value) => CounterCell::Value(value),
            Err(_) => CounterCell::Unreadable("simulated counter file is not a decimal u64".into()),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CounterCell::Undefined,
        Err(error) => CounterCell::Unreadable(format!("simulated counter file {path}: {error}")),
    }
}

// ───────────────────────── Real backend (target, feature tpm) ─────────────────────────
//
// The real TPM2 implementation (hardened sealing/unsealing, encrypted
// sessions) lives in `tpm_real.rs` to keep this file readable. Re-exported
// here so `boot_controller` keeps the `crate::tpm_interface::TpmDevice` path.
#[cfg(feature = "tpm")]
pub(crate) use crate::tpm_real::TpmDevice;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::TpmSettings;

    /// A corrupt counter file refuses the counter operations, but sealing and
    /// unsealing — served by the same `open_tpm` — keep working.
    #[test]
    fn a_corrupt_simulated_counter_refuses_the_counter_not_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = TpmSettings {
            simulated_counter_path: dir.path().join("counter").to_string_lossy().into(),
            ..TpmSettings::default()
        };
        std::fs::write(&cfg.simulated_counter_path, b"not a number").unwrap();
        let mut tpm = DryRunTpm::from_env(&cfg);

        let secret = SecretKey::generate().unwrap();
        let blob = tpm.seal(&secret).unwrap();
        let unsealed = tpm.unseal(&blob).unwrap();
        assert_eq!(unsealed.as_bytes(), secret.as_bytes());

        assert!(matches!(
            tpm.read_counter(),
            Err(crate::TpmError::CounterUnavailable(_))
        ));
        assert!(matches!(
            tpm.increment_counter(),
            Err(crate::TpmError::CounterUnavailable(_))
        ));
        assert!(matches!(
            tpm.ensure_counter(),
            Err(crate::TpmError::CounterUnavailable(_))
        ));
        assert_eq!(
            std::fs::read(&cfg.simulated_counter_path).unwrap(),
            b"not a number",
            "an unreadable counter must never be overwritten"
        );
    }
}
