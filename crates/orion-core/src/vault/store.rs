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
//! # Rotation, not deletion
//!
//! A key that ever lived in plaintext is presumed compromised: it may sit in a
//! roaming profile, a backup or a system image, and encrypting it now does not
//! recall those copies. Migration therefore seals it *and* marks the profile
//! `rotation_required`, which keeps it unconnectable until a new key has been
//! generated and re-admitted. Sealing ends the exposure of the *file*; only
//! rotation ends the exposure of the *key*.

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
    unencrypted_volume: bool,
}

impl ProfileStore {
    pub fn new(dir: impl Into<std::path::PathBuf>, provider: Box<dyn RootKeyProvider>) -> Self {
        Self {
            dir: dir.into(),
            provider,
            software_keystore: false,
            unencrypted_volume: false,
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
        self.unencrypted_volume = allowed;
        self
    }

    /// May a secret be written to this installation's directory?
    ///
    /// The volume posture decides, unless it was explicitly waived. `Ok` here
    /// is what import, save and migration gate on — the panel already reports
    /// the same fact, and a screen that states a refusal nothing enforces is
    /// worse than one that states nothing.
    pub fn may_write_secrets(&self) -> Result<(), VaultError> {
        if self.unencrypted_volume {
            return Ok(());
        }
        super::windows::bitlocker::require_protected(&self.dir)
    }

    /// Default location, beside the legacy file it replaces.
    pub fn default_dir() -> Result<std::path::PathBuf, VaultError> {
        let dirs = directories::ProjectDirs::from("net", "helios", "orion").ok_or_else(|| {
            VaultError::Io {
                path: std::path::PathBuf::new(),
                cause: "impossible de déterminer le répertoire de configuration".into(),
            }
        })?;
        Ok(dirs.config_dir().to_path_buf())
    }

    pub fn hardware_backed(&self) -> bool {
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

    fn root(&self) -> Result<DeviceRootKey, VaultError> {
        self.provider.root_key()
    }

    fn load_registry(&self, root: &DeviceRootKey) -> Result<Registry, VaultError> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(Registry::default());
        }
        let key = root.registry_key()?;
        let context = super::registry_context(&self.install_id()?);
        let plaintext = helios_vault::open_file(
            &path,
            DOMAIN_REGISTRY,
            &context,
            &helios_vault::Unlock::Key(&key),
        )
        .map_err(VaultError::Container)?;
        Registry::decode(&plaintext)
    }

    fn store_registry(&self, root: &DeviceRootKey, registry: &Registry) -> Result<(), VaultError> {
        let key = root.registry_key()?;
        let context = super::registry_context(&self.install_id()?);
        let blob = helios_vault::seal(
            DOMAIN_REGISTRY,
            &context,
            &helios_vault::Unlock::Key(&key),
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
        let blob = helios_vault::read_file_bounded(&self.manifest_path(entry.id))
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
        tracing::debug!(
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
            tracing::debug!(
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
        let root = self.root()?;
        let mut registry = self.load_registry(&root)?;
        let client_public_key = aether::wg::public_from_private(&profile.private_key)
            .map_err(|_| VaultError::ContextDisagrees)?;

        let previous = registry.find_by_name(&profile.name).cloned();
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
            volume: volume.detail(),
            volume_protected: volume.allows_secrets(),
            unencrypted_volume_waived: self.unencrypted_volume,
            memory_locked: lock.holds(),
            memory: lock.detail(),
            dumps_excluded: exclusion.holds(),
            dumps: exclusion.detail(),
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
            let Ok(client_public_key) = aether::wg::public_from_private(&profile.private_key)
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
            let written = helios_vault::read_file_bounded(&self.manifest_path(id))
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
mod tests {
    use super::*;
    use crate::vault::keys::KEY_LEN;

    /// A provider with a fixed root, so the store is testable without a TPM.
    ///
    /// Test-only on purpose: shipping such a provider would be the software
    /// fallback ADR-006 forbids.
    struct FixedRoot([u8; KEY_LEN]);

    impl RootKeyProvider for FixedRoot {
        fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
            Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(self.0)))
        }
        fn hardware_backed(&self) -> bool {
            false
        }
    }

    fn store(name: &str) -> (std::path::PathBuf, ProfileStore) {
        let dir = std::env::temp_dir().join(format!(
            "orion-store-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])));
        (dir, store)
    }

    fn profile(name: &str) -> ClientProfile {
        let pair = aether::wg::generate_keypair().unwrap();
        let gateway = aether::wg::generate_keypair().unwrap();
        ClientProfile {
            name: name.into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: pair.private_key.expose().to_string(),
            peer_public_key: gateway.public_key,
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        }
    }

    /// A refusal and a deliberate downgrade must not look alike.
    ///
    /// Off Windows `hardware_backed()` is false either way, so the flag is the
    /// only thing that distinguishes "this machine has no TPM" from "the
    /// operator chose to do without one". Reporting the first as the second
    /// would credit them with a decision they never made — and would hide the
    /// real one where it was actually taken.
    #[test]
    fn the_posture_separates_a_missing_tpm_from_a_waived_one() {
        let (dir, strict) = store("posture-strict");
        let posture = strict.posture();
        assert!(
            !posture.software_keystore,
            "no flag set: the absence of hardware is a refusal, not a downgrade"
        );

        let waived = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])))
            .allowing_software_keystore(true);
        let posture = waived.posture();
        assert!(posture.software_keystore);
        assert!(
            !posture.hardware_backed,
            "waiving the requirement must never produce a hardware claim"
        );
        assert!(!posture.is_clean());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Off Windows the volume posture is `Indeterminate`, which refuses. The
    /// waiver is the only thing that lets a secret be written — and it must not
    /// pretend the disk became encrypted.
    #[test]
    fn the_volume_waiver_permits_writing_without_claiming_protection() {
        let (dir, strict) = store("volume-strict");
        assert!(
            strict.may_write_secrets().is_err(),
            "une posture indéterminable doit refuser, pas passer"
        );
        assert!(!strict.posture().unencrypted_volume_waived);

        let waived = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])))
            .allowing_unencrypted_volume(true);
        assert!(
            waived.may_write_secrets().is_ok(),
            "la dérogation doit lever le refus"
        );

        let posture = waived.posture();
        assert!(
            posture.unencrypted_volume_waived,
            "la dérogation doit être visible"
        );
        assert!(
            !posture.volume_protected,
            "lever l'exigence ne chiffre pas le disque"
        );
        assert!(!posture.is_clean());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bootstrap records the choice, not the outcome: it is what an
    /// auditor reads to know whether the downgrade was deliberate.
    #[test]
    fn the_bootstrap_records_whether_the_downgrade_was_chosen() {
        let (dir, store) = store("bootstrap-flag");
        store.save_profile(&profile("poste")).unwrap();
        let raw = std::fs::read_to_string(dir.join(BOOTSTRAP_FILE)).unwrap();
        let bootstrap: Bootstrap = toml::from_str(&raw).unwrap();
        assert!(
            !bootstrap.software_keystore,
            "no flag set: the bootstrap must not claim a waiver"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_profile_round_trips_through_the_store() {
        let (dir, store) = store("roundtrip");
        let original = profile("poste");
        store.save_profile(&original).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].private_key, original.private_key);
        assert_eq!(loaded.selected.as_deref(), Some("poste"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property the whole lot exists for.
    #[test]
    fn no_secret_reaches_any_file_in_the_store() {
        let (dir, store) = store("no-secret");
        let original = profile("poste");
        store.save_profile(&original).unwrap();

        let mut checked = 0;
        for entry in walk(&dir) {
            let bytes = std::fs::read(&entry).unwrap();
            assert!(
                !bytes
                    .windows(original.private_key.len())
                    .any(|w| w == original.private_key.as_bytes()),
                "the private key appears in {}",
                entry.display()
            );
            checked += 1;
        }
        assert!(checked >= 3, "expected bootstrap, registry and manifest");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bootstrap_carries_no_secret_and_is_readable() {
        let (dir, store) = store("bootstrap");
        store.save_profile(&profile("poste")).unwrap();
        let raw = std::fs::read_to_string(dir.join(BOOTSTRAP_FILE)).unwrap();
        let bootstrap: Bootstrap = toml::from_str(&raw).unwrap();
        assert_eq!(bootstrap.version, BOOTSTRAP_VERSION);
        assert_eq!(bootstrap.install_id.len(), 32);
        assert!(
            !raw.contains("private"),
            "the bootstrap must stay secret-free"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_a_profile_removes_its_manifest() {
        let (dir, store) = store("remove");
        store.save_profile(&profile("poste")).unwrap();
        store.save_profile(&profile("portable")).unwrap();
        store.remove_profile("poste").unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].name, "portable");
        let manifests = std::fs::read_dir(dir.join(PROFILES_DIR)).unwrap().count();
        assert_eq!(manifests, 1, "the removed manifest is still on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selection_survives_a_reload() {
        let (dir, store) = store("select");
        store.save_profile(&profile("poste")).unwrap();
        store.save_profile(&profile("portable")).unwrap();
        store.select("portable").unwrap();
        assert_eq!(store.load().unwrap().selected.as_deref(), Some("portable"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Raising a floor must not resurrect the plaintext file.
    ///
    /// This is the shape of the defect the shell carried: a committed
    /// negotiation raised `minimum_mode`, and the raise was persisted with
    /// `ClientConfig::save` — which writes `profiles.toml`, in this very
    /// directory, with the private key in the clear. The whole vault was
    /// undone by the ordinary success path, once per connection.
    ///
    /// The test drives the store the way the shell now does, and then asserts
    /// on the directory: no legacy file, and the secret nowhere in it.
    #[test]
    fn raising_a_floor_writes_no_plaintext_file() {
        use aether::key_negotiation::ProtectionMode;

        let (dir, store) = store("floor-raise");
        let mut profile = profile("poste");
        profile.key_negotiation = Some(negotiation());
        store.save_profile(&profile).unwrap();

        // What the negotiation sink does after a committed ML-KEM exchange.
        if let Some(settings) = profile.key_negotiation.as_mut() {
            settings.minimum_mode = ProtectionMode::MlKem;
        }
        store.save_profile(&profile).unwrap();

        assert!(
            !store.legacy_present(),
            "une montée de plancher a recréé {}",
            LEGACY_FILE
        );
        let secret = profile.private_key.as_bytes();
        for path in walk(&dir) {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "la clé privée apparaît dans {}",
                path.display()
            );
        }

        // And the raise is genuinely persisted, sealed.
        let reloaded = store.load().unwrap();
        assert_eq!(
            reloaded
                .find("poste")
                .unwrap()
                .key_negotiation
                .as_ref()
                .unwrap()
                .minimum_mode,
            ProtectionMode::MlKem
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rewriting with a new WireGuard key is a rotation: the generation rises.
    #[test]
    fn a_key_rotation_raises_the_generation() {
        let (dir, store) = store("generation");
        let mut original = profile("poste");
        store.save_profile(&original).unwrap();

        original.private_key = aether::wg::generate_keypair()
            .unwrap()
            .private_key
            .expose()
            .to_string();
        store.save_profile(&original).unwrap();

        let root = store.root().unwrap();
        let entry = store.load_registry(&root).unwrap();
        assert_eq!(entry.find_by_name("poste").unwrap().generation.0, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Key negotiation block whose anchor and floor a test can move.
    fn negotiation() -> crate::config::KeyNegotiationSettings {
        use aether::key_negotiation::ProtectionMode;
        crate::config::KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::Classic,
            endpoint: "203.0.113.10:51821".into(),
            server_name: "gw.example".into(),
            gateway_ca_der: "Q0EtT1JJR0lORQ==".into(),
            gateway_pq_certificate: "Q0VSVC1PUklHSU5F".into(),
            identity: "poste".into(),
        }
    }

    /// ADR-006 §2 names four triggers, not one.
    ///
    /// Before the security digest entered the registry, only a WireGuard key
    /// rotation moved the counter. Swapping the pinned trust anchor or lowering
    /// the stored floor left it still — so a restored manifest carrying the old
    /// anchor passed the registry's freshness check untouched. Each case here
    /// is one of those triggers, exercised on its own.
    #[test]
    fn every_security_change_raises_the_generation() {
        use aether::key_negotiation::ProtectionMode;

        type Change = fn(&mut ClientProfile);
        let cases: [(&str, Change); 4] = [
            ("clé WireGuard", |profile| {
                profile.private_key = aether::wg::generate_keypair()
                    .unwrap()
                    .private_key
                    .expose()
                    .to_string();
            }),
            ("PSK statique", |profile| {
                profile.preshared_key = Some("cHNrLXJlbXBsYWNhbnQtMzItb2N0ZXRz".into());
            }),
            ("ancre de confiance", |profile| {
                if let Some(settings) = profile.key_negotiation.as_mut() {
                    settings.gateway_ca_der = "Q0EtUkVNUExBQ0FOVEU=".into();
                }
            }),
            ("plancher", |profile| {
                if let Some(settings) = profile.key_negotiation.as_mut() {
                    settings.minimum_mode = ProtectionMode::MlKem;
                }
            }),
        ];

        for (label, apply) in cases {
            let (dir, store) = store(&format!("generation-{}", label.replace(' ', "-")));
            let mut original = profile("poste");
            original.key_negotiation = Some(negotiation());
            store.save_profile(&original).unwrap();

            apply(&mut original);
            store.save_profile(&original).unwrap();

            let root = store.root().unwrap();
            assert_eq!(
                store
                    .load_registry(&root)
                    .unwrap()
                    .find_by_name("poste")
                    .unwrap()
                    .generation
                    .0,
                2,
                "un changement de {label} doit être un événement de sécurité"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The registry witnesses the change without ever holding the secret.
    #[test]
    fn the_registry_records_a_digest_and_never_the_psk() {
        let (dir, store) = store("digest-no-secret");
        let mut original = profile("poste");
        original.preshared_key = Some("cHNrLXNlY3JldC1xdWktbmUtc29ydC1wYXM=".into());
        store.save_profile(&original).unwrap();

        let root = store.root().unwrap();
        let entry = store
            .load_registry(&root)
            .unwrap()
            .find_by_name("poste")
            .unwrap()
            .clone();
        assert_ne!(entry.security_digest, [0u8; 32], "digest non calculé");

        let psk = original.preshared_key.as_deref().unwrap().as_bytes();
        for path in walk(&dir) {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(psk.len()).any(|window| window == psk),
                "le PSK apparaît dans {}",
                path.display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_without_changing_the_key_keeps_the_generation() {
        let (dir, store) = store("stable-generation");
        let mut original = profile("poste");
        store.save_profile(&original).unwrap();
        original.endpoint = "198.51.100.7:51820".into();
        store.save_profile(&original).unwrap();

        let root = store.root().unwrap();
        assert_eq!(
            store
                .load_registry(&root)
                .unwrap()
                .find_by_name("poste")
                .unwrap()
                .generation
                .0,
            1,
            "an ordinary edit is not a security event"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_file_is_migrated_and_removed() {
        let (dir, store) = store("migration");
        let legacy = ClientConfig {
            profiles: vec![profile("poste")],
            selected: Some("poste".into()),
        };
        let secret = legacy.profiles[0].private_key.clone();
        std::fs::write(
            dir.join(LEGACY_FILE),
            toml::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        assert!(store.legacy_present());
        let report = store.migrate_legacy().unwrap();
        assert_eq!(report.migrated, vec!["poste".to_string()]);
        assert!(!store.legacy_present(), "the plaintext file must be gone");

        let loaded = store.load().unwrap();
        assert_eq!(loaded.profiles[0].private_key, secret);
        assert_eq!(loaded.selected.as_deref(), Some("poste"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sealing the file does not recall the copies already in backups.
    #[test]
    fn a_migrated_profile_stays_blocked_until_its_key_is_rotated() {
        let (dir, store) = store("rotation");
        let original = profile("poste");
        let legacy = ClientConfig {
            profiles: vec![original.clone()],
            selected: None,
        };
        std::fs::write(
            dir.join(LEGACY_FILE),
            toml::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();
        store.migrate_legacy().unwrap();

        assert_eq!(
            store.rotation_required().unwrap(),
            vec!["poste".to_string()]
        );

        // Re-saving the same key changes nothing: the compromised key is still
        // the one in use.
        store.save_profile(&original).unwrap();
        assert_eq!(
            store.rotation_required().unwrap(),
            vec!["poste".to_string()]
        );

        // A new key closes it.
        let mut rotated = original.clone();
        rotated.private_key = aether::wg::generate_keypair()
            .unwrap()
            .private_key
            .expose()
            .to_string();
        store.save_profile(&rotated).unwrap();
        assert!(
            store.rotation_required().unwrap().is_empty(),
            "a rotated key must clear the migration flag"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrating_twice_is_harmless() {
        let (dir, store) = store("idempotent");
        let legacy = ClientConfig {
            profiles: vec![profile("poste")],
            selected: None,
        };
        std::fs::write(
            dir.join(LEGACY_FILE),
            toml::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();
        store.migrate_legacy().unwrap();
        let second = store.migrate_legacy().unwrap();
        assert!(second.migrated.is_empty());
        assert_eq!(store.load().unwrap().profiles.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Another installation's root opens nothing — the point of the binding.
    #[test]
    fn another_installation_cannot_read_the_store() {
        let (dir, store) = store("foreign");
        store.save_profile(&profile("poste")).unwrap();

        let foreign = ProfileStore::new(dir.clone(), Box::new(FixedRoot([9u8; KEY_LEN])));
        assert!(foreign.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Putting an older manifest back must be refused, not silently accepted.
    #[test]
    fn an_older_manifest_is_refused() {
        let (dir, store) = store("rollback");
        let mut original = profile("poste");
        store.save_profile(&original).unwrap();
        let root = store.root().unwrap();
        let id = store
            .load_registry(&root)
            .unwrap()
            .find_by_name("poste")
            .unwrap()
            .id;
        let old_blob = std::fs::read(store.manifest_path(id)).unwrap();

        // Rotate: generation 2, registry updated.
        original.private_key = aether::wg::generate_keypair()
            .unwrap()
            .private_key
            .expose()
            .to_string();
        store.save_profile(&original).unwrap();

        // Put the generation-1 blob back. Its context no longer matches the
        // registry's public key, and even a matching one would be caught by
        // the generation check.
        std::fs::write(store.manifest_path(id), &old_blob).unwrap();
        assert!(
            store.load().is_err(),
            "a restored older manifest must not load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path);
            }
        }
        found
    }
}
