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
//!   profiles/<id>.g<n>.next.hvlt
//!                             a manifest step waiting to replace the one above
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};

use zeroize::Zeroizing;

use super::{
    nomad::PassphraseKey,
    open_manifest,
    registry::{entry_digest, ProfileMode, Registry, RegistryEntry},
    seal_manifest, DeviceRootKey, ManifestKey, ProfileId, ProfileManifest, RootKeyProvider,
    SecurityGeneration, VaultError, DOMAIN_REGISTRY,
};
use crate::config::{ClientConfig, ClientProfile, LockedProfile};

/// Bootstrap format version. An unknown one is refused, never guessed.
const BOOTSTRAP_VERSION: u32 = 1;

pub(crate) const BOOTSTRAP_FILE: &str = "bootstrap.toml";
pub(crate) const DEVICE_ROOT_FILE: &str = "device-root";
pub(crate) const REGISTRY_FILE: &str = "registry.hvlt";
pub(crate) const PROFILES_DIR: &str = "profiles";
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
    /// Name of the TPM key the root was wrapped under when the installation was
    /// created. Informational: nothing reads it to choose a key.
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
    /// Name of the TPM key in use, written to the bootstrap. Informational:
    /// nothing reads it to choose a key.
    key_slot: String,
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
    root_cache: Mutex<Option<Arc<DeviceRootKey>>>,
    /// Passphrase keys of the `nomade` profiles unlocked in this session, by
    /// identifier. Emptied by [`ProfileStore::forget_unlocked`].
    unlocked: Mutex<HashMap<ProfileId, PassphraseKey>>,
    /// Bumped, under `unlocked`, by every [`ProfileStore::forget_unlocked`].
    /// An unlock that began before a bump must not keep its key.
    lock_epoch: AtomicU64,
    /// The engine receives the lock and suspend notifications (spec §5.5).
    /// Without them a nomad profile could stay open after the session locked,
    /// so unlocking is refused.
    lock_watch: AtomicBool,
    /// Test seam: runs between the derivation of a passphrase key and its
    /// storage, to stage a lock that lands in that window.
    #[cfg(test)]
    between_derivation_and_store: Option<LockHook>,
}

/// The shape of [`ProfileStore::between_derivation_and_store`].
#[cfg(test)]
type LockHook = Box<dyn Fn(&ProfileStore) + Send + Sync>;

impl ProfileStore {
    pub fn new(dir: impl Into<std::path::PathBuf>, provider: Box<dyn RootKeyProvider>) -> Self {
        Self {
            dir: dir.into(),
            provider,
            software_keystore: false,
            key_slot: super::windows::tpm::KEY_NAME.to_string(),
            unencrypted_volume: AtomicBool::new(false),
            root_cache: Mutex::new(None),
            unlocked: Mutex::new(HashMap::new()),
            lock_epoch: AtomicU64::new(0),
            lock_watch: AtomicBool::new(false),
            #[cfg(test)]
            between_derivation_and_store: None,
        }
    }

    /// Names the TPM key in use. The bootstrap records it when the installation
    /// is created; the key itself is chosen by the provider, not from this name.
    #[must_use]
    pub fn with_key_slot(mut self, slot: String) -> Self {
        self.key_slot = slot;
        self
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

    /// Where a manifest step waits before it replaces the current manifest
    /// (spec §5.7). The only place this name is built.
    pub(crate) fn next_manifest_path(
        &self,
        id: ProfileId,
        generation: SecurityGeneration,
    ) -> PathBuf {
        self.dir
            .join(PROFILES_DIR)
            .join(format!("{}.g{}.next.hvlt", id.to_hex(), generation.0))
    }

    fn unlocked_keys(&self) -> MutexGuard<'_, HashMap<ProfileId, PassphraseKey>> {
        self.unlocked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
            key_slot: self.key_slot.clone(),
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
    /// Locking the session forgets it ([`ProfileStore::forget_unlocked`]): the
    /// next operation unwraps it again, which is what a `nomade` profile needs
    /// after a lock.
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

    /// Opens one manifest with `key`, the expectations taken from the **registry**.
    ///
    /// Not from anything stored beside the blob: that is the indirection
    /// ADR-006 §2 requires, and what stops a swap of the pair record + blob.
    fn load_manifest(
        &self,
        root: &DeviceRootKey,
        entry: &RegistryEntry,
        key: ManifestKey<'_>,
    ) -> Result<ProfileManifest, VaultError> {
        // `read_file_bounded` and not `std::fs::read`: ADR-006 §2 requires the
        // size to be checked before the blob is allocated, and says in as many
        // words that a bound applied after a `std::fs::read` is a bound that
        // already lost. A sparse manifest file costs an attacker nothing.
        let blob = aether_vault::read_file_bounded(&self.manifest_path(entry.id))
            .map_err(VaultError::Container)?;
        Self::open_entry(root, entry, &blob, key)
    }

    /// Opens a manifest blob already read, then checks its generation.
    fn open_entry(
        root: &DeviceRootKey,
        entry: &RegistryEntry,
        blob: &[u8],
        key: ManifestKey<'_>,
    ) -> Result<ProfileManifest, VaultError> {
        let manifest = open_manifest(
            root,
            entry.id,
            &entry.client_public_key,
            &entry.gateway_public_key,
            blob,
            key,
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

    /// Settles a manifest step that a crash interrupted (spec §5.7).
    ///
    /// Decided from file names and the registry alone: nothing is decrypted
    /// here. A step above the registry's generation never became authoritative
    /// and is deleted; one at the registry's generation was already recorded,
    /// so its rename was the only step left and it is promoted. The normal open
    /// still checks the authenticated generation afterwards.
    fn recover_manifest_steps(&self, registry: &Registry) -> Result<(), VaultError> {
        let dir = self.dir.join(PROFILES_DIR);
        let listing = match std::fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(VaultError::Io {
                    path: dir,
                    cause: error.to_string(),
                })
            }
        };
        for item in listing.flatten() {
            let path = item.path();
            let Some((id, generation)) = self.parse_manifest_step(&path) else {
                continue;
            };
            let io = |cause: std::io::Error| VaultError::Io {
                path: path.clone(),
                cause: cause.to_string(),
            };
            match registry.find(id) {
                Some(entry) if entry.generation == generation => {
                    tracing::warn!(
                        profil = %entry.name,
                        "étape de manifeste interrompue : promue"
                    );
                    std::fs::rename(&path, self.manifest_path(id)).map_err(io)?;
                }
                _ => {
                    tracing::warn!("étape de manifeste sans entrée valide : supprimée");
                    std::fs::remove_file(&path).map_err(io)?;
                }
            }
        }
        Ok(())
    }

    /// Reads the identifier and generation from a step's file name. Only the
    /// exact name [`Self::next_manifest_path`] builds counts as a step.
    fn parse_manifest_step(&self, path: &Path) -> Option<(ProfileId, SecurityGeneration)> {
        let name = path.file_name()?.to_str()?;
        let stem = name.strip_suffix(".next.hvlt")?;
        let (hex, generation) = stem.rsplit_once(".g")?;
        let bytes: [u8; 16] = hex_to_bytes(hex)?.try_into().ok()?;
        let id = ProfileId::from_bytes(bytes);
        let generation = SecurityGeneration(generation.parse().ok()?);
        (self.next_manifest_path(id, generation) == path).then_some((id, generation))
    }

    /// Loads every profile, in the shape the rest of the client works with.
    ///
    /// A `nomade` profile whose key is not held is **not opened**: its name and
    /// public keys come from the registry alone, and it is listed as locked.
    pub fn load(&self) -> Result<ClientConfig, VaultError> {
        let root = self.root()?;
        let registry = self.load_registry(&root)?;
        self.recover_manifest_steps(&registry)?;
        tracing::info!(
            profils = registry.entries.len(),
            repertoire = %self.dir.display(),
            "registre du coffre ouvert"
        );
        let unlocked = self.unlocked_keys();
        let mut profiles = Vec::with_capacity(registry.entries.len());
        let mut locked = Vec::new();
        for entry in &registry.entries {
            let key = match entry.mode {
                ProfileMode::Service => ManifestKey::Service,
                ProfileMode::Nomad { .. } => match unlocked.get(&entry.id) {
                    Some(key) => ManifestKey::Nomad(key),
                    None => {
                        locked.push(LockedProfile {
                            name: entry.name.clone(),
                            client_public_key: entry.client_public_key.clone(),
                            gateway_public_key: entry.gateway_public_key.clone(),
                        });
                        continue;
                    }
                },
            };
            // Named one by one: a single failure aborts the load, and knowing
            // *which* profile refused is the difference between a fix and a
            // reinstall.
            let manifest = self.load_manifest(&root, entry, key).inspect_err(|error| {
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
        Ok(ClientConfig {
            profiles,
            selected,
            locked,
        })
    }

    /// Turns the lock watch on or off. Off by default: an unlock is refused
    /// until the engine has the notifications that will lock the session again.
    pub fn set_lock_watch(&self, active: bool) {
        self.lock_watch.store(active, Ordering::Release);
    }

    pub fn lock_watch_active(&self) -> bool {
        self.lock_watch.load(Ordering::Acquire)
    }

    /// The mode of a profile, read from the registry. No key is needed.
    pub fn mode_of(&self, name: &str) -> Result<Option<ProfileMode>, VaultError> {
        let root = self.root()?;
        Ok(self
            .load_registry(&root)?
            .find_by_name(name)
            .map(|entry| entry.mode))
    }

    /// Opens a `nomade` profile with its passphrase, and keeps the key.
    ///
    /// Refused without the lock watch. A wrong passphrase, or a manifest that
    /// does not open under it, leaves the profile locked and says so. A lock
    /// that lands during the unlock discards the key. Unlocking a `service`
    /// profile, or a name that does not exist, does nothing.
    pub fn unlock(&self, name: &str, passphrase: &str) -> Result<(), VaultError> {
        if !self.lock_watch_active() {
            return Err(VaultError::LockWatchUnavailable);
        }
        let root = self.root()?;
        let registry = self.load_registry(&root)?;
        let Some(entry) = registry.find_by_name(name).cloned() else {
            return Ok(());
        };
        let ProfileMode::Nomad { salt, .. } = entry.mode else {
            return Ok(());
        };
        // Read before the derivation: a lock during it bumps the epoch, and is
        // seen by the check below.
        let epoch = self.lock_epoch.load(Ordering::Acquire);
        let key = PassphraseKey::derive(passphrase, &salt)?;
        let blob = aether_vault::read_file_bounded(&self.manifest_path(entry.id))
            .map_err(VaultError::Container)?;
        Self::open_entry(&root, &entry, &blob, ManifestKey::Nomad(&key)).map_err(|error| {
            match error {
                // The AEAD and the container cannot tell a wrong passphrase
                // from an altered profile, and neither does the message.
                VaultError::Container(_) => VaultError::WrongPassphrase,
                other => other,
            }
        })?;
        #[cfg(test)]
        if let Some(hook) = &self.between_derivation_and_store {
            hook(self);
        }
        let mut unlocked = self.unlocked_keys();
        if self.lock_epoch.load(Ordering::Acquire) != epoch {
            // The key is dropped with `key` here, never stored.
            return Err(VaultError::ProfileLocked(name.to_string()));
        }
        unlocked.insert(entry.id, key);
        Ok(())
    }

    /// Whether a `nomade` profile's key is held in this session.
    pub fn is_unlocked(&self, name: &str) -> bool {
        let Ok(root) = self.root() else {
            return false;
        };
        let Ok(registry) = self.load_registry(&root) else {
            return false;
        };
        registry
            .find_by_name(name)
            .is_some_and(|entry| self.unlocked_keys().contains_key(&entry.id))
    }

    /// Locks every `nomade` profile again, and forgets the installation root
    /// with them. Called on session lock, sleep, disconnect and engine exit.
    pub fn forget_unlocked(&self) {
        let mut unlocked = self.unlocked_keys();
        self.lock_epoch.fetch_add(1, Ordering::AcqRel);
        unlocked.clear();
        drop(unlocked);
        *self
            .root_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Number of entries in the registry. A migration checks the loaded
    /// profiles against it, and cannot use [`Self::load`] to count.
    pub(crate) fn registered_count(&self) -> Result<usize, VaultError> {
        let root = self.root()?;
        Ok(self.load_registry(&root)?.entries.len())
    }

    /// Test seam: creates a `nomade` profile the way the enrolment gesture will,
    /// sealed under `passphrase` with a fresh salt. No key is left held.
    #[cfg(test)]
    pub(crate) fn enrol_nomad_for_test(
        &self,
        profile: &ClientProfile,
        passphrase: &str,
    ) -> Result<(), VaultError> {
        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let client_public_key = aether::wg::public_from_private(profile.private_key.expose())
            .map_err(|_| VaultError::ContextDisagrees)?;
        let salt = super::nomad::new_salt()?;
        let key = PassphraseKey::derive(passphrase, &salt)?;
        let id = ProfileId::generate()?;
        let manifest = ProfileManifest::from_profile(profile, SecurityGeneration(1));
        let blob = seal_manifest(
            &root,
            id,
            &manifest,
            &client_public_key,
            ManifestKey::Nomad(&key),
        )?;
        self.write(&self.manifest_path(id), &blob)?;
        let mode = ProfileMode::Nomad {
            kdf: super::registry::KDF_PBKDF2_HMAC_SHA512,
            salt,
        };
        registry.upsert(RegistryEntry {
            id,
            name: profile.name.clone(),
            client_public_key,
            gateway_public_key: profile.peer_public_key.clone(),
            generation: SecurityGeneration(1),
            security_digest: entry_digest(manifest.security_digest(), &mode),
            rotation_required: false,
            mode,
        })?;
        if registry.selected.is_none() {
            registry.selected = Some(id);
        }
        self.store_registry(&root, &registry)
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
        // The key is decided before anything is read or sealed: a nomad profile
        // whose passphrase key is not held is refused here, and never falls
        // back to a service seal.
        let unlocked = self.unlocked_keys();
        let key = match previous.as_ref() {
            Some(entry) => key_for(entry, &unlocked)?,
            None => ManifestKey::Service,
        };
        if let Some(entry) = previous.as_ref() {
            let known = self.load_manifest(&root, entry, key)?;
            if known.kind() != profile.kind() {
                return Err(VaultError::ProfileKindChanged {
                    known: known.kind().as_str(),
                    offered: profile.kind().as_str(),
                });
            }
        }
        let id = match previous.as_ref() {
            Some(entry) => entry.id,
            None => ProfileId::generate()?,
        };
        // An existing profile keeps its mode: a save never changes it, and
        // only the explicit gesture does (spec §5.6).
        let mode = previous
            .as_ref()
            .map_or(ProfileMode::Service, |entry| entry.mode);
        let rotated = previous
            .as_ref()
            .is_some_and(|entry| entry.client_public_key != client_public_key);

        // The generation counts **security events**, and ADR-006 §2 lists four:
        // a key rotation, a PSK change, a trust-anchor change and a floor
        // change. Only the first was tracked before, so swapping the pinned CA
        // or lowering the stored floor left the counter still — and a restored
        // older manifest with the old anchor passed the registry check.
        let manifest_digest =
            ProfileManifest::from_profile(profile, SecurityGeneration(0)).security_digest();
        let digest = entry_digest(manifest_digest, &mode);
        let security_changed = previous
            .as_ref()
            .is_some_and(|entry| entry.security_digest != digest);
        let generation = match &previous {
            Some(entry) if rotated || security_changed => entry.generation.next(),
            Some(entry) => entry.generation,
            None => SecurityGeneration(1),
        };

        let manifest = ProfileManifest::from_profile(profile, generation);
        let blob = seal_manifest(&root, id, &manifest, &client_public_key, key)?;
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
            mode,
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
            if registry
                .find_by_name(&profile.name)
                .is_some_and(|entry| entry.mode.is_nomad())
            {
                // A migration seals service manifests. Over a nomad profile it
                // would drop the passphrase silently, so it is refused.
                return Err(VaultError::ProfileLocked(profile.name.clone()));
            }
            let id = registry
                .find_by_name(&profile.name)
                .map(|entry| entry.id)
                .map_or_else(ProfileId::generate, Ok)?;
            let manifest = ProfileManifest::from_profile(profile, SecurityGeneration(1));
            let blob = seal_manifest(
                &root,
                id,
                &manifest,
                &client_public_key,
                ManifestKey::Service,
            )?;
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
                ManifestKey::Service,
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
                mode: ProfileMode::Service,
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

/// Rewrites the key slot of the bootstrap in `dir`, and nothing else.
///
/// A migration moves the root under another TPM key. Every other field of the
/// bootstrap, the installation identifier above all, must come through
/// unchanged. A bootstrap that does not exist yet is left absent: the store
/// writes one on first use, naming the slot it was given.
pub(crate) fn set_key_slot(dir: &std::path::Path, slot: &str) -> Result<(), VaultError> {
    let path = dir.join(BOOTSTRAP_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(VaultError::Io {
                path,
                cause: error.to_string(),
            })
        }
    };
    let mut bootstrap: Bootstrap = toml::from_str(&raw).map_err(|e| VaultError::Io {
        path: path.clone(),
        cause: e.to_string(),
    })?;
    bootstrap.key_slot = slot.to_string();
    let encoded = toml::to_string_pretty(&bootstrap).map_err(|e| VaultError::Io {
        path: path.clone(),
        cause: e.to_string(),
    })?;
    aether::private_file::write_private_atomic(&path, encoded.as_bytes()).map_err(|e| {
        VaultError::Io {
            path,
            cause: e.to_string(),
        }
    })
}

/// The key that opens and seals `entry`'s manifest: the installation root alone
/// for a `service` profile, the held passphrase key for a `nomade` one. A
/// `nomade` profile whose key is not held is `ProfileLocked`, never a service
/// seal.
fn key_for<'a>(
    entry: &RegistryEntry,
    unlocked: &'a HashMap<ProfileId, PassphraseKey>,
) -> Result<ManifestKey<'a>, VaultError> {
    match entry.mode {
        ProfileMode::Service => Ok(ManifestKey::Service),
        ProfileMode::Nomad { .. } => unlocked
            .get(&entry.id)
            .map(ManifestKey::Nomad)
            .ok_or_else(|| VaultError::ProfileLocked(entry.name.clone())),
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
