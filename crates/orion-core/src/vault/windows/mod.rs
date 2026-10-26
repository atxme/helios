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
    /// The TPM key the root is wrapped under. [`tpm::KeyScope::User`] unless the
    /// engine names the machine key with [`Self::with_scope`].
    scope: tpm::KeyScope,
    /// Degraded mode: DPAPI alone, no hardware binding.
    ///
    /// Set only by `danger_allow_software_keystore`. It is a **downgrade**, not
    /// a recovery, and every guarantee about inter-machine copying, hardware
    /// rollback and a domain administrator holding DPAPI backup keys is
    /// withdrawn with it.
    software_only: bool,
    /// Outcome of the last **real** attempt to obtain the root.
    ///
    /// `hardware_backed` used to answer from `cfg!(windows)` and this flag
    /// alone, which verified nothing: on a Windows machine whose TPM was
    /// absent, cleared or refusing the key, the posture panel displayed
    /// "scellés au TPM" while every profile failed to open — the screen
    /// promising exactly what nothing backed.
    ///
    /// The four checks ADR-006 §3 demands live in [`tpm::verify`] and run on
    /// the key's use, so this records whether that path actually succeeded.
    /// Unknown reads as **not** hardware-backed: a measurement that has not
    /// been taken is not a guarantee.
    hardware: std::sync::atomic::AtomicU8,
}

/// No attempt has been made yet.
const HARDWARE_UNKNOWN: u8 = 0;
/// A root was obtained through the TPM, with [`tpm::verify`] satisfied.
const HARDWARE_VERIFIED: u8 = 1;
/// An attempt was made and hardware did not back it.
const HARDWARE_ABSENT: u8 = 2;

impl PlatformRootKeyProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            scope: tpm::KeyScope::User,
            software_only: false,
            hardware: std::sync::atomic::AtomicU8::new(HARDWARE_UNKNOWN),
        }
    }

    /// Names the TPM key the root is wrapped under.
    #[must_use]
    pub fn with_scope(mut self, scope: tpm::KeyScope) -> Self {
        self.scope = scope;
        self
    }

    /// Records what the last attempt actually established.
    fn record(&self, verified: bool) {
        self.hardware.store(
            if verified {
                HARDWARE_VERIFIED
            } else {
                HARDWARE_ABSENT
            },
            std::sync::atomic::Ordering::Relaxed,
        );
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
        self.seal_existing(&root)?;
        Ok(root)
    }

    /// Seals `root` under the layers of this provider and writes it to its
    /// path. The one writer of the device root: `create` calls it for a
    /// fresh root, and the migration for a root that already exists.
    pub fn seal_existing(&self, root: &DeviceRootKey) -> Result<(), VaultError> {
        let wrapped = if self.software_only {
            self.record(false);
            // `Zeroizing`: in the degraded mode this buffer *is* the root key in
            // the clear, on its way to DPAPI. A plain `Vec` would leave it in a
            // freed allocation nothing wipes (ADR-006 §5).
            Zeroizing::new(root.expose_for_wrapping().to_vec())
        } else {
            // Recorded on both outcomes: a failure here is precisely what the
            // panel must stop calling "scellés au TPM".
            let wrapped = tpm::wrap_root(&self.scope, root.expose_for_wrapping());
            self.record(wrapped.is_ok());
            Zeroizing::new(wrapped?)
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
        })
    }

    fn open(&self) -> Result<DeviceRootKey, VaultError> {
        // Same bound as every other sealed file: the wrapped root is a few
        // hundred bytes, and the path is one an attacker with local write
        // access can point at something enormous (ADR-006 §2).
        let sealed = aether_vault::read_file_bounded(&self.path).map_err(VaultError::Container)?;
        let wrapped = dpapi::unprotect(&sealed)?;
        if self.software_only {
            self.record(false);
            let bytes: [u8; KEY_LEN] = wrapped
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Tpm("stored root has the wrong length".into()))?;
            return Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(bytes)));
        }
        let unwrapped = tpm::unwrap_root(&self.scope, &wrapped);
        self.record(unwrapped.is_ok());
        Ok(DeviceRootKey::from_unwrapped(unwrapped?))
    }
}

impl RootKeyProvider for PlatformRootKeyProvider {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        // Which branch was taken, and what came of it. Without this the whole
        // startup showed a single downstream error — "coffre illisible" — with
        // nothing saying whether the root was created, opened, or never
        // reached.
        let existing = self.path.exists();
        tracing::info!(
            racine = %self.path.display(),
            existante = existing,
            logiciel = self.software_only,
            portee = self.scope.label(),
            "obtention de la racine d'installation"
        );
        let outcome = if existing { self.open() } else { self.create() };
        match &outcome {
            Ok(_) => tracing::info!(
                materielle = self.hardware_backed(),
                "racine d'installation obtenue"
            ),
            Err(error) => tracing::warn!(%error, "racine d'installation indisponible"),
        }
        outcome
    }

    fn hardware_backed(&self) -> bool {
        // A measured fact, not a compile-time one. `cfg!(windows)` used to
        // stand in for it, which meant the answer was `true` on any Windows
        // build whose flag was off — TPM working or not.
        //
        // `HARDWARE_UNKNOWN` reads as `false`: nothing has been measured yet,
        // and the panel must never state a guarantee it has not established.
        // `ProfileStore::posture` therefore obtains the root before asking.
        !self.software_only
            && self.hardware.load(std::sync::atomic::Ordering::Relaxed) == HARDWARE_VERIFIED
    }
}

/// The machine target of a migration: the device root is sealed under the
/// machine key of the interactive user, and the copied identities are opened
/// with the protected store.
#[cfg(windows)]
pub struct MachineTarget {
    /// The machine key the root is wrapped under, named by the user's SID.
    pub scope: tpm::KeyScope,
    /// The `danger_allow_software_keystore` choice, carried over unchanged.
    pub software_only: bool,
}

#[cfg(windows)]
impl MachineTarget {
    fn provider_for(&self, device_root_file: &std::path::Path) -> PlatformRootKeyProvider {
        PlatformRootKeyProvider::new(device_root_file)
            .with_scope(self.scope.clone())
            .allowing_software_keystore(self.software_only)
    }
}

#[cfg(windows)]
impl super::relocation::RelocationTarget for MachineTarget {
    fn seal_root(
        &self,
        root: &DeviceRootKey,
        device_root_file: &std::path::Path,
    ) -> Result<(), VaultError> {
        self.provider_for(device_root_file).seal_existing(root)
    }

    fn provider(&self, device_root_file: &std::path::Path) -> Box<dyn RootKeyProvider> {
        Box::new(self.provider_for(device_root_file))
    }

    fn key_slot(&self) -> String {
        self.scope.key_name()
    }

    fn verify_identity(&self, file: &std::path::Path) -> Result<(), VaultError> {
        let directory = file.parent().ok_or_else(|| VaultError::Io {
            path: file.to_path_buf(),
            cause: "identité sans dossier parent".into(),
        })?;
        let name = file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| VaultError::Io {
                path: file.to_path_buf(),
                cause: "nom d'identité illisible".into(),
            })?;
        crate::identity_store::ProtectedIdentityStore::at(directory.to_path_buf())
            .open_named(name)
            .map(|_| ())
            .map_err(|error| VaultError::Relocation(format!("identité illisible : {error:#}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The posture panel reads this. It must not claim hardware it does not
    /// have, in either direction.
    #[test]
    fn the_degraded_mode_never_claims_hardware() {
        let degraded =
            PlatformRootKeyProvider::new("/tmp/unused-root").allowing_software_keystore(true);
        assert!(
            !degraded.hardware_backed(),
            "danger_allow_software_keystore must withdraw the hardware claim"
        );
    }

    /// A guarantee that has not been measured is not a guarantee.
    ///
    /// This is the defect the field replaced: the answer came from
    /// `cfg!(windows)` and the flag, so any Windows build with the flag off
    /// claimed hardware — TPM present, absent, cleared or refusing alike.
    #[test]
    fn an_unmeasured_provider_never_claims_hardware() {
        let provider = PlatformRootKeyProvider::new("/tmp/unused-root");
        assert!(
            !provider.hardware_backed(),
            "a provider that has never obtained a root must not claim a TPM"
        );
    }

    /// The claim follows the **last** measurement, in both directions.
    ///
    /// Recording only the success would let a provider that once verified a
    /// TPM keep claiming one after the hardware went away.
    #[test]
    fn the_claim_follows_the_last_measurement() {
        let provider = PlatformRootKeyProvider::new("/tmp/unused-root");
        assert!(!provider.hardware_backed(), "unmeasured");

        provider.record(true);
        assert!(provider.hardware_backed(), "a verified TPM is claimed");

        provider.record(false);
        assert!(
            !provider.hardware_backed(),
            "hardware that went away must withdraw the claim, not keep it"
        );
    }

    /// A failed attempt must leave the claim withdrawn.
    #[cfg(not(windows))]
    #[test]
    fn a_failed_attempt_withdraws_the_claim() {
        let dir = std::env::temp_dir().join(format!(
            "orion-hardware-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let provider = PlatformRootKeyProvider::new(dir.join("device-root"));

        assert!(provider.root_key().is_err(), "no TPM off Windows");
        assert!(
            !provider.hardware_backed(),
            "a refused root must not leave a hardware claim standing"
        );
        let _ = std::fs::remove_dir_all(&dir);
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

    #[cfg(windows)]
    fn test_root_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!(
                "orion-platform-root-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ))
            .join("device-root")
    }

    /// The explicit degraded mode still has a real Windows account boundary:
    /// it is DPAPI-only, not plaintext-only.
    #[cfg(windows)]
    #[test]
    fn software_keystore_creates_and_reopens_the_same_dpapi_root() {
        let path = test_root_path("round-trip");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let provider = PlatformRootKeyProvider::new(&path).allowing_software_keystore(true);

        let first = provider.root_key().unwrap();
        let expected = *first.expose_for_wrapping();
        drop(first);
        let sealed = std::fs::read(&path).unwrap();
        assert!(
            !sealed
                .windows(expected.len())
                .any(|window| window == expected),
            "DPAPI-only mode must not write the root in plaintext"
        );
        let reopened = provider.root_key().unwrap();
        assert_eq!(reopened.expose_for_wrapping(), &expected);
        assert!(!provider.hardware_backed());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// A valid DPAPI envelope with the wrong payload shape must be refused;
    /// otherwise a truncated root could silently become key material.
    #[cfg(windows)]
    #[test]
    fn software_keystore_rejects_a_root_with_the_wrong_length() {
        let path = test_root_path("wrong-length");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, dpapi::protect(&[7u8; KEY_LEN - 1]).unwrap()).unwrap();
        let provider = PlatformRootKeyProvider::new(&path).allowing_software_keystore(true);

        assert!(
            matches!(provider.root_key(), Err(VaultError::Tpm(message)) if message.contains("wrong length"))
        );
        assert!(!provider.hardware_backed());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
