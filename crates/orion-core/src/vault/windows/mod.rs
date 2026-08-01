//! Platform layers of the Orion vault (ADR-006 §3).
//!
//! Four pieces, three of which only exist on Windows:
//!
//! * [`tpm`] — the non-exportable key in the *Microsoft Platform Crypto
//!   Provider*, and the four checks performed before trusting it;
//! * [`dpapi`] — the user-scope envelope over the TPM blob, never a second
//!   envelope of the root;
//! * [`bitlocker`] — the volume-encryption posture that gates import, migration
//!   and auto-connect;
//! * [`prompt`] — the native passphrase dialog for the `nomade` profile;
//! * [`dumps`] — excluding secret pages from Windows Error Reporting.
//!
//! Each module compiles everywhere and **refuses** off Windows rather than
//! offering a software substitute. The refusal is the specified behaviour, not
//! a placeholder: a protection that silently is not one is worse than none,
//! because the screen keeps promising it.

pub mod bitlocker;
pub mod dpapi;
pub mod dumps;
pub mod prompt;
pub mod tpm;

use zeroize::Zeroizing;

use super::{keys::KEY_LEN, DeviceRootKey, RootKeyProvider, VaultError};

/// Composes the layers ADR-006 §3 requires, in order.
///
/// ```text
/// device_root_key ──wrap──► TPM (non-exportable) ──wrap──► DPAPI (user scope)
/// ```
///
/// The composition is a **conjunction**. Losing the TPM loses the root, and
/// DPAPI does not bring it back — there is deliberately no second envelope for
/// it to hold. That is the ambiguity the amendment closed, and the reason
/// `TpmKeyLost` says "re-enrol" rather than "try the other path".
pub struct PlatformRootKeyProvider {
    /// Where the doubly-wrapped root lives. Carries no secret readable without
    /// both layers.
    path: std::path::PathBuf,
    /// Degraded mode: DPAPI alone, no hardware binding.
    ///
    /// Set only by `danger_allow_software_keystore`. It is a **downgrade**, not
    /// a recovery, and every guarantee about inter-machine copying, hardware
    /// rollback and a domain administrator holding DPAPI backup keys is
    /// withdrawn with it.
    software_only: bool,
}

impl PlatformRootKeyProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            software_only: false,
        }
    }

    /// Enables the degraded mode. Callers must surface it in the posture panel
    /// and log a `WARN` at every start (ADR-006 §3).
    #[must_use]
    pub fn allowing_software_keystore(mut self, allowed: bool) -> Self {
        self.software_only = allowed;
        self
    }

    fn create(&self) -> Result<DeviceRootKey, VaultError> {
        let root = DeviceRootKey::generate()?;
        let wrapped = if self.software_only {
            root.expose_for_wrapping().to_vec()
        } else {
            tpm::wrap_root(root.expose_for_wrapping())?
        };
        let sealed = dpapi::protect(&wrapped)?;
        if let Some(parent) = self.path.parent() {
            aether::private_file::create_private_dir(parent).map_err(|e| VaultError::Io {
                path: parent.to_path_buf(),
                cause: e.to_string(),
            })?;
        }
        // Written only once every layer succeeded: a file left behind by a
        // half-built root would be adopted by the next run.
        aether::private_file::write_private_atomic(&self.path, &sealed).map_err(|e| {
            VaultError::Io {
                path: self.path.clone(),
                cause: e.to_string(),
            }
        })?;
        Ok(root)
    }

    fn open(&self) -> Result<DeviceRootKey, VaultError> {
        let sealed = std::fs::read(&self.path).map_err(|e| VaultError::Io {
            path: self.path.clone(),
            cause: e.to_string(),
        })?;
        let wrapped = dpapi::unprotect(&sealed)?;
        if self.software_only {
            let bytes: [u8; KEY_LEN] = wrapped
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Tpm("stored root has the wrong length".into()))?;
            return Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(bytes)));
        }
        Ok(DeviceRootKey::from_unwrapped(tpm::unwrap_root(&wrapped)?))
    }
}

impl RootKeyProvider for PlatformRootKeyProvider {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        if self.path.exists() {
            self.open()
        } else {
            self.create()
        }
    }

    fn hardware_backed(&self) -> bool {
        // Never `true` in software mode, and never `true` off Windows: the
        // posture panel must not be able to display "TPM" where there is none.
        !self.software_only && cfg!(windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The posture panel reads this. It must not claim hardware it does not
    /// have, in either direction.
    #[test]
    fn the_degraded_mode_never_claims_hardware() {
        let provider = PlatformRootKeyProvider::new("/tmp/unused-root");
        assert_eq!(provider.hardware_backed(), cfg!(windows));

        let degraded =
            PlatformRootKeyProvider::new("/tmp/unused-root").allowing_software_keystore(true);
        assert!(
            !degraded.hardware_backed(),
            "danger_allow_software_keystore must withdraw the hardware claim"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_provider_refuses_rather_than_writing_a_root() {
        let dir = std::env::temp_dir().join(format!(
            "orion-root-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("device-root");

        let provider = PlatformRootKeyProvider::new(&path);
        assert!(matches!(
            provider.root_key(),
            Err(VaultError::NoHardwareRoot)
        ));
        assert!(
            !path.exists(),
            "a refused root must leave nothing behind for a later run to adopt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
