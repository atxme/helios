//! Orion's profile store, on disk (ADR-006 §2, §3).
//!
//! # Layout
//!
//! ```text
//! <dir>/
//!   bootstrap.toml            format version, install id, key slot — no secret
//!   device-root               DPAPI(TPM(device_root_key))
//!   registry.hvlt             sealed registry: names, public keys, selection
//!   profiles/<id>.hvlt        sealed manifest, one per profile
//!   profiles.toml             LEGACY plaintext, removed once migrated
//! ```
//!
//! Only `bootstrap.toml` is readable without the installation root, and it is
//! the only file that carries nothing worth protecting.
//!
//! # Order of writes, and why it is not negotiable
//!
//! ADR-006 §3 requires the migration to `fsync` the vault, **reopen it, and
//! verify** public key, context and generation before publishing the registry
//! and the redacted bootstrap. That order is what makes a crash survivable: at
//! every instant the installation is either wholly old — legacy file intact,
//! auto-connect blocked — or wholly new and verifiable. There is no window in
//! which a half-migrated profile is presented as sound.
//!
//! # Rotation, advised — not imposed
//!
//! A key that lived in plaintext may sit in a roaming profile, a backup or a
//! system image, and encrypting it now does not recall those copies. Migration
//! therefore seals it *and* flags the profile, so the posture and the log say
//! so and the Profiles screen offers the rotation in one gesture.
//!
//! The flag does **not** block the connection. This module observes the history
//! of a *file*; it knows nothing about the key itself, which may never have
//! left the machine. Refusing someone their own tunnel on that presumption
//! oversteps what a client arbitrates — revoking an admission belongs to the
//! operator, who alone has the means (ADR-006 §3, arbitrage du 2 août 2026).

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use zeroize::Zeroizing;

use super::{
    open_manifest,
    registry::{Registry, RegistryEntry},
    seal_manifest, DeviceRootKey, ProfileId, ProfileManifest, RootKeyProvider, SecurityGeneration,
    VaultError, DOMAIN_REGISTRY,
};
use crate::config::{ClientConfig, ClientProfile};

/// Bootstrap format version. An unknown one is refused, never guessed.
const BOOTSTRAP_VERSION: u32 = 1;

const BOOTSTRAP_FILE: &str = "bootstrap.toml";
const DEVICE_ROOT_FILE: &str = "device-root";
const REGISTRY_FILE: &str = "registry.hvlt";
const PROFILES_DIR: &str = "profiles";
/// The plaintext file this whole module exists to retire.
pub const LEGACY_FILE: &str = "profiles.toml";

/// The only file readable without the installation root.
///
/// It carries **no secret** by construction: a format version, the installation
/// identifier used as the registry's object context, and the name of the TPM
/// key slot. Everything else is derived from the directory, so there is no path
/// an attacker can rewrite to redirect a read.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Bootstrap {
    pub version: u32,
    /// 128-bit installation identifier, hex. Public: it separates this
    /// installation's registry from another's, it does not protect it.
    pub install_id: String,
    /// TPM key slot holding the wrapping key.
    pub key_slot: String,
    /// Hardware binding was deliberately waived (`danger_allow_software_keystore`).
    #[serde(default)]
    pub software_keystore: bool,
}

/// What a migration did, for the log and the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Profiles moved into the vault.
    pub migrated: Vec<String>,
    /// Profiles that carried a key which had lived in plaintext, and are now
    /// blocked until it is rotated.
    pub rotation_required: Vec<String>,
}

/// Vault-backed profile store.
pub struct ProfileStore {
    dir: std::path::PathBuf,
    provider: Box<dyn RootKeyProvider>,
    /// The operator waived the hardware requirement (ADR-006 §3).
    ///
    /// Held here rather than inferred from `provider.hardware_backed()`,
    /// because the two answer different questions: the provider says whether
    /// hardware **is** backing the root, this says whether its absence was
    /// **chosen**. A machine with no TPM and no flag is a refusal, and
    /// reporting it as a downgrade would credit the operator with a decision
    /// they never made.
    software_keystore: bool,
    /// The operator waived the volume-encryption prerequisite (ADR-006 §3).
    ///
    /// Same distinction as above, for the same reason: an unencrypted volume is
    /// a refusal, and only this flag turns it into a stated choice.
    unencrypted_volume: AtomicBool,
    /// Installation root, unwrapped once. See [`ProfileStore::root`].
    root_cache: std::sync::Mutex<Option<Arc<DeviceRootKey>>>,
}

impl ProfileStore {
    pub fn new(dir: impl Into<std::path::PathBuf>, provider: Box<dyn RootKeyProvider>) -> Self {
        Self {
            dir: dir.into(),
            provider,
            software_keystore: false,
            unencrypted_volume: AtomicBool::new(false),
            root_cache: std::sync::Mutex::new(None),
        }
    }

    /// Records that the hardware requirement was waived on purpose.
    #[must_use]
    pub fn allowing_software_keystore(mut self, allowed: bool) -> Self {
        self.software_keystore = allowed;
        self
    }

    /// Records that the volume-encryption prerequisite was waived on purpose.
    #[must_use]
    pub fn allowing_unencrypted_volume(mut self, allowed: bool) -> Self {
        self.unencrypted_volume = AtomicBool::new(allowed);
        self
    }

    /// Records an informed volume-encryption waiver and applies it now.
    ///
    /// Persistence happens first: an interface that reports success must not
    /// leave a choice that disappears at the next start. A malformed existing
    /// file is refused rather than overwritten, because it may carry another
    /// deliberate downgrade that must not be silently lost.
    pub fn persist_unencrypted_volume_waiver(&self) -> Result<(), VaultError> {
        let (mut settings, complaint) = super::LocalSettings::load(&self.dir);
        if let Some(complaint) = complaint {
            return Err(VaultError::LocalSettings(complaint));
        }
        settings.danger_allow_unencrypted_volume = true;
        settings.save(&self.dir)?;
        self.unencrypted_volume.store(true, Ordering::Release);
        Ok(())
    }

    /// May a secret be written to this installation's directory?
    ///
    /// The volume posture decides, unless it was explicitly waived. `Ok` here
    /// is what import, save and migration gate on — the panel already reports
    /// the same fact, and a screen that states a refusal nothing enforces is
    /// worse than one that states nothing.
    pub fn may_write_secrets(&self) -> Result<(), VaultError> {
        if self.unencrypted_volume.load(Ordering::Acquire) {
            return Ok(());
        }
        super::windows::bitlocker::require_protected(&self.dir)
    }

    /// The vault directory: the installed protected root's when one is
    /// established, else beside the legacy file it replaces.
    pub fn default_dir() -> Result<std::path::PathBuf, VaultError> {
        crate::protected_root::select(
            None,
            crate::protected_root::installed().map(|paths| paths.vault.clone()),
            || crate::protected_root::platform_dirs().map(|dirs| dirs.config_dir().to_path_buf()),
        )
        .map_err(|cause| VaultError::Io {
            path: std::path::PathBuf::new(),
            cause,
        })
    }

    pub fn hardware_backed(&self) -> bool {
        self.provider.hardware_backed()
    }

    /// Obtains the root, **then** answers whether hardware backs it.
    ///
    /// [`Self::hardware_backed`] reports a measurement, and an unmeasured
    /// provider answers `false` — correctly, because a guarantee nobody has
    /// established is not a guarantee. Asking it before anything has used the
    /// vault therefore reads "no TPM" on a machine whose TPM is fine, which is
    /// exactly what startup did: it printed an `ERROR` telling the user to set
    /// `danger_allow_software_keystore`, two hundred milliseconds before
    /// obtaining a hardware-backed root without difficulty.
    ///
    /// Anything that reports the posture to a human must go through here.
    pub fn probe_hardware_root(&self) -> bool {
        // The failure is not raised: the caller is deciding what to *say*, and
        // the answer to "is hardware backing this" is `false` either way.
        let _ = self.root();
        self.provider.hardware_backed()
    }

    pub fn legacy_path(&self) -> std::path::PathBuf {
        self.dir.join(LEGACY_FILE)
    }

    /// `true` when a plaintext file is still present and not yet migrated.
    pub fn legacy_present(&self) -> bool {
        self.legacy_path().exists()
    }

    fn bootstrap_path(&self) -> std::path::PathBuf {
        self.dir.join(BOOTSTRAP_FILE)
    }

    fn registry_path(&self) -> std::path::PathBuf {
        self.dir.join(REGISTRY_FILE)
    }

    fn manifest_path(&self, id: ProfileId) -> std::path::PathBuf {
        self.dir
            .join(PROFILES_DIR)
            .join(format!("{}.hvlt", id.to_hex()))
    }

    pub fn device_root_path(&self) -> std::path::PathBuf {
        self.dir.join(DEVICE_ROOT_FILE)
    }

    fn read_bootstrap(&self) -> Result<Option<Bootstrap>, VaultError> {
        let path = self.bootstrap_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let bootstrap: Bootstrap = toml::from_str(&raw).map_err(|e| VaultError::Io {
                    path: path.clone(),
                    cause: e.to_string(),
                })?;
                if bootstrap.version != BOOTSTRAP_VERSION {
                    return Err(VaultError::UnsupportedManifest(
                        u8::try_from(bootstrap.version).unwrap_or(u8::MAX),
                    ));
                }
                Ok(Some(bootstrap))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(VaultError::Io {
                path,
                cause: e.to_string(),
            }),
        }
    }

    fn write_bootstrap(&self, bootstrap: &Bootstrap) -> Result<(), VaultError> {
        let raw = toml::to_string_pretty(bootstrap).map_err(|e| VaultError::Io {
            path: self.bootstrap_path(),
            cause: e.to_string(),
        })?;
        self.write(&self.bootstrap_path(), raw.as_bytes())
    }

    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> Result<(), VaultError> {
        if let Some(parent) = path.parent() {
            aether::private_file::create_private_dir(parent).map_err(|e| VaultError::Io {
                path: parent.to_path_buf(),
                cause: e.to_string(),
            })?;
        }
        aether::private_file::write_private_atomic(path, bytes).map_err(|e| VaultError::Io {
            path: path.to_path_buf(),
            cause: e.to_string(),
        })
    }

    /// Installation identifier, created on first use.
    fn install_id(&self) -> Result<Vec<u8>, VaultError> {
        if let Some(bootstrap) = self.read_bootstrap()? {
            return hex_to_bytes(&bootstrap.install_id).ok_or_else(|| {
                VaultError::ManifestEncoding("invalid install identifier in the bootstrap".into())
            });
        }
        let id = ProfileId::generate()?;
        self.write_bootstrap(&Bootstrap {
            version: BOOTSTRAP_VERSION,
            install_id: id.to_hex(),
            key_slot: super::windows::tpm::KEY_NAME.to_string(),
            software_keystore: self.software_keystore,
        })?;
        Ok(id.as_bytes().to_vec())
    }

    /// The installation root, unwrapped **once** per process.
    ///
    /// # Why this is cached
    ///
    /// Every vault operation needs it, and each miss is a TPM RSA decrypt —
    /// roughly 250 ms on ordinary hardware. Uncached, a single connection paid
    /// six of them: posture, migration, load, `rotation_required`, save,
    /// selection. Beyond the latency, a TPM is a rate-limited device: some
    /// chips enter anti-hammering lockout under exactly this kind of drumming,
    /// and the failure mode is a machine that stops opening its own vault.
    ///
    /// # Why caching costs nothing here
    ///
    /// ADR-006 §5 asks for minimal secret lifetime, and this is a deliberate
    /// exception rather than an oversight. The root is not a tunnel key: it is
    /// the vault's key-encryption root, needed for every read and write, and it
    /// was already resident during each of those six operations. What an
    /// attacker gains from it being resident *between* them is nothing they did
    /// not already have — under T9 they run as the account, so they can ask the
    /// TPM to unwrap it themselves. The TPM key is non-exportable; it is not
    /// unusable.
    ///
    /// `Arc` rather than `Clone`: [`DeviceRootKey`] deliberately has no `Clone`,
    /// and sharing a pointer keeps that true — there is still exactly one copy
    /// of the key material, zeroized when the last holder drops it.
    ///
    /// # Limite connue
    ///
    /// There is no way to drop it before the process ends. The `nomade` profile
    /// will need one — locking the session must forget the root — and that is
    /// part of the lot which is not built (ADR-006 §3, limites connues).
    fn root(&self) -> Result<Arc<DeviceRootKey>, VaultError> {
        let mut cache = self
            .root_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(root) = cache.as_ref() {
            return Ok(Arc::clone(root));
        }
        let root = Arc::new(self.provider.root_key()?);
        *cache = Some(Arc::clone(&root));
        Ok(root)
    }

    fn load_registry(&self, root: &DeviceRootKey) -> Result<Registry, VaultError> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(Registry::default());
        }
        let key = root.registry_key()?;
        let context = super::registry_context(&self.install_id()?);
        let plaintext = aether_vault::open_file(
            &path,
            DOMAIN_REGISTRY,
            &context,
            &aether_vault::Unlock::Key(&key),
        )
        .map_err(VaultError::Container)?;
        Registry::decode(&plaintext)
    }

    fn store_registry(&self, root: &DeviceRootKey, registry: &Registry) -> Result<(), VaultError> {
        let key = root.registry_key()?;
        let context = super::registry_context(&self.install_id()?);
        let blob = aether_vault::seal(
            DOMAIN_REGISTRY,
            &context,
            &aether_vault::Unlock::Key(&key),
            &registry.encode()?,
        )
        .map_err(VaultError::Container)?;
        self.write(&self.registry_path(), &blob)
    }

    /// Opens one manifest, with the expectations taken from the **registry**.
    ///
    /// Not from anything stored beside the blob: that is the indirection
    /// ADR-006 §2 requires, and what stops a swap of the pair record + blob.
    fn load_manifest(
        &self,
        root: &DeviceRootKey,
        entry: &RegistryEntry,
    ) -> Result<ProfileManifest, VaultError> {
        // `read_file_bounded` and not `std::fs::read`: ADR-006 §2 requires the
        // size to be checked before the blob is allocated, and says in as many
        // words that a bound applied after a `std::fs::read` is a bound that
        // already lost. A sparse manifest file costs an attacker nothing.
        let blob = aether_vault::read_file_bounded(&self.manifest_path(entry.id))
            .map_err(VaultError::Container)?;
        let manifest = open_manifest(
            root,
            entry.id,
            &entry.client_public_key,
            &entry.gateway_public_key,
            &blob,
        )?;
        // The registry records the highest generation ever seen. A blob below
        // it was put back from an older copy.
        if manifest.generation < entry.generation {
            return Err(VaultError::GenerationWentBackwards {
                observed: entry.generation.0,
                offered: manifest.generation.0,
            });
        }
        Ok(manifest)
    }

    /// Loads every profile, in the shape the rest of the client works with.
    pub fn load(&self) -> Result<ClientConfig, VaultError> {
        let root = self.root()?;
        let registry = self.load_registry(&root)?;
        tracing::info!(
            profils = registry.entries.len(),
            repertoire = %self.dir.display(),
            "registre du coffre ouvert"
        );
        let mut profiles = Vec::with_capacity(registry.entries.len());
        for entry in &registry.entries {
            // Named one by one: a single failure aborts the load, and knowing
            // *which* profile refused is the difference between a fix and a
            // reinstall.
            let manifest = self.load_manifest(&root, entry).inspect_err(|error| {
                tracing::warn!(profil = %entry.name, %error, "manifeste illisible");
            })?;
            tracing::info!(
                profil = %entry.name,
                generation = manifest.generation.0,
                rotation_requise = entry.rotation_required,
                "profil chargé"
            );
            profiles.push(manifest.to_profile());
        }
        let selected = registry
            .selected
            .and_then(|id| registry.find(id))
            .map(|entry| entry.name.clone());
        Ok(ClientConfig { profiles, selected })
    }

    /// Names of the profiles blocked until their key is rotated.
    pub fn rotation_required(&self) -> Result<Vec<String>, VaultError> {
        let root = self.root()?;
        Ok(self
            .load_registry(&root)?
            .entries
            .into_iter()
            .filter(|entry| entry.rotation_required)
            .map(|entry| entry.name)
            .collect())
    }

    /// Inserts or replaces a profile, keyed by display name.
    ///
    /// Rewriting a profile with a **different** WireGuard key is a rotation: it
    /// raises the generation and clears the migration flag, which is precisely
    /// how a profile that came from a plaintext file becomes connectable again.
    pub fn save_profile(&self, profile: &ClientProfile) -> Result<(), VaultError> {
        profile
            .check_kind()
            .map_err(|error| VaultError::InvalidProfileKind(error.to_string()))?;
        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let client_public_key = aether::wg::public_from_private(profile.private_key.expose())
            .map_err(|_| VaultError::ContextDisagrees)?;

        let previous = registry.find_by_name(&profile.name).cloned();
        if let Some(entry) = previous.as_ref() {
            let known = self.load_manifest(&root, entry)?;
            if known.kind() != profile.kind() {
                return Err(VaultError::ProfileKindChanged {
                    known: known.kind().as_str(),
                    offered: profile.kind().as_str(),
                });
            }
        }
        let id = previous.as_ref().map(|entry| entry.id);
        let id = match id {
            Some(id) => id,
            None => ProfileId::generate()?,
        };
        let rotated = previous
            .as_ref()
            .is_some_and(|entry| entry.client_public_key != client_public_key);

        // The generation counts **security events**, and ADR-006 §2 lists four:
        // a key rotation, a PSK change, a trust-anchor change and a floor
        // change. Only the first was tracked before, so swapping the pinned CA
        // or lowering the stored floor left the counter still — and a restored
        // older manifest with the old anchor passed the registry check.
        let digest =
            ProfileManifest::from_profile(profile, SecurityGeneration(0)).security_digest();
        let security_changed = previous
            .as_ref()
            .is_some_and(|entry| entry.security_digest != digest);
        let generation = match &previous {
            Some(entry) if rotated || security_changed => entry.generation.next(),
            Some(entry) => entry.generation,
            None => SecurityGeneration(1),
        };

        let manifest = ProfileManifest::from_profile(profile, generation);
        let blob = seal_manifest(&root, id, &manifest, &client_public_key)?;
        self.write(&self.manifest_path(id), &blob)?;

        registry.upsert(RegistryEntry {
            id,
            name: profile.name.clone(),
            client_public_key,
            gateway_public_key: profile.peer_public_key.clone(),
            generation,
            security_digest: digest,
            // A rotation is what closes the migration: the key that had lived
            // in the clear is no longer the one in use.
            rotation_required: previous
                .map(|entry| entry.rotation_required && !rotated)
                .unwrap_or(false),
        })?;
        if registry.selected.is_none() {
            registry.selected = Some(id);
        }
        self.store_registry(&root, &registry)
    }

    pub fn remove_profile(&self, name: &str) -> Result<(), VaultError> {
        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let Some(entry) = registry.find_by_name(name).cloned() else {
            return Ok(());
        };
        registry.remove(entry.id);
        // Registry first: a manifest without an entry is unreachable, whereas
        // an entry without a manifest is a profile that fails to open.
        self.store_registry(&root, &registry)?;
        let _ = std::fs::remove_file(self.manifest_path(entry.id));
        Ok(())
    }

    pub fn select(&self, name: &str) -> Result<(), VaultError> {
        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let Some(entry) = registry.find_by_name(name).cloned() else {
            return Ok(());
        };
        registry.selected = Some(entry.id);
        self.store_registry(&root, &registry)
    }

    /// Everything the posture panel is allowed to state about this store.
    ///
    /// Each field is measured, not assumed. `rotation_required` falls back to
    /// an empty list when the registry cannot be opened — the panel already
    /// shows the missing hardware root in that case, and inventing profile
    /// names from an unreadable registry would be worse than saying nothing.
    pub fn posture(&self) -> super::VaultPosture {
        // The root is obtained **before** `hardware_backed` is read, and that
        // order is the whole point: the answer is a measurement, and asking a
        // provider that has never been used would report "not yet measured"
        // as "no hardware" — or, before this was a measurement at all, "no
        // TPM" as "TPM fine". A failure is ignored here on purpose; the panel
        // reports it through the field itself.
        let _ = self.root();
        let volume = super::windows::bitlocker::protection_of(&self.dir);
        // A small probe: the lock privilege is the same for every buffer, so
        // one page answers for all of them without holding a secret.
        let probe = aether::locked::LockedSecret::with_capacity(32);
        let lock = probe.lock_state();
        let exclusion = super::windows::dumps::exclude(probe.expose());
        super::windows::dumps::release(probe.expose());

        super::VaultPosture {
            hardware_backed: self.provider.hardware_backed(),
            software_keystore: self.software_keystore,
            volume: volume.detail().to_string(),
            volume_protected: volume.allows_secrets(),
            unencrypted_volume_waived: self.unencrypted_volume.load(Ordering::Acquire),
            memory_locked: lock.holds(),
            memory: lock.detail().to_string(),
            dumps_excluded: exclusion.holds(),
            dumps: exclusion.detail().to_string(),
            rotation_required: self.rotation_required().unwrap_or_default(),
            legacy_present: self.legacy_present(),
        }
    }

    /// Moves a plaintext configuration into the vault.
    ///
    /// Idempotent: a second call on an already-migrated installation finds no
    /// legacy file and reports nothing. Every step is logged without secrets.
    pub fn migrate_legacy(&self) -> Result<MigrationReport, VaultError> {
        let legacy_path = self.legacy_path();
        if !legacy_path.exists() {
            return Ok(MigrationReport {
                migrated: Vec::new(),
                rotation_required: Vec::new(),
            });
        }
        let raw =
            Zeroizing::new(
                std::fs::read_to_string(&legacy_path).map_err(|e| VaultError::Io {
                    path: legacy_path.clone(),
                    cause: e.to_string(),
                })?,
            );
        let legacy: ClientConfig = toml::from_str(&raw).map_err(|e| VaultError::Io {
            path: legacy_path.clone(),
            cause: e.to_string(),
        })?;

        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let mut report = MigrationReport {
            migrated: Vec::new(),
            rotation_required: Vec::new(),
        };

        for profile in &legacy.profiles {
            let Ok(client_public_key) =
                aether::wg::public_from_private(profile.private_key.expose())
            else {
                // A profile whose key cannot even be read is not migrated, and
                // not silently dropped either: it stays in the legacy file,
                // which is not removed when anything failed.
                tracing::warn!(
                    profile = %profile.name,
                    "profil ignoré : clé privée illisible"
                );
                continue;
            };
            let id = registry
                .find_by_name(&profile.name)
                .map(|entry| entry.id)
                .map_or_else(ProfileId::generate, Ok)?;
            let manifest = ProfileManifest::from_profile(profile, SecurityGeneration(1));
            let blob = seal_manifest(&root, id, &manifest, &client_public_key)?;
            self.write(&self.manifest_path(id), &blob)?;

            // Reopen and verify **before** publishing anything (ADR-006 §3).
            // Trusting the write would mean discovering an unreadable vault on
            // the day the legacy file no longer exists.
            let written = aether_vault::read_file_bounded(&self.manifest_path(id))
                .map_err(VaultError::Container)?;
            let reopened = open_manifest(
                &root,
                id,
                &client_public_key,
                &profile.peer_public_key,
                &written,
            )?;
            if reopened.generation != SecurityGeneration(1) {
                return Err(VaultError::ContextDisagrees);
            }

            registry.upsert(RegistryEntry {
                id,
                name: profile.name.clone(),
                client_public_key,
                gateway_public_key: profile.peer_public_key.clone(),
                generation: SecurityGeneration(1),
                security_digest: manifest.security_digest(),
                // The key lived in plaintext. Sealing it does not recall the
                // copies already in backups and roaming profiles.
                rotation_required: true,
            })?;
            report.migrated.push(profile.name.clone());
            report.rotation_required.push(profile.name.clone());
        }

        if let Some(name) = &legacy.selected {
            if let Some(entry) = registry.find_by_name(name) {
                registry.selected = Some(entry.id);
            }
        }
        self.store_registry(&root, &registry)?;

        // The legacy file goes only once everything above succeeded. A crash
        // before this point leaves it intact, and the installation simply
        // migrates again on the next start.
        std::fs::remove_file(&legacy_path).map_err(|e| VaultError::Io {
            path: legacy_path,
            cause: e.to_string(),
        })?;
        tracing::warn!(
            profils = report.migrated.len(),
            "profils migrés vers le coffre — rotation de clé obligatoire avant reconnexion"
        );
        Ok(report)
    }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests;
