use super::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::config::{ClientConfig, ClientProfile};
use crate::vault::keys::KEY_LEN;
use crate::vault::store::{BOOTSTRAP_FILE, DEVICE_ROOT_FILE, LEGACY_FILE, PROFILES_DIR};
use crate::vault::{Bootstrap, ProfileStore};

/// The installation root of the legacy vault. The new vault wraps the same
/// root, so the profiles it holds open under the same key.
const ROOT: [u8; KEY_LEN] = [4u8; KEY_LEN];

/// The key slot the fake machine target reports.
const MACHINE_SLOT: &str = "Helios Orion device root v2 S-1-5-21-1-2-3-1001";

/// Stands in for the legacy per-user provider. Counts every unwrap, so a test
/// can prove the legacy root was never asked for.
struct LegacyRoot(Arc<AtomicUsize>);

impl RootKeyProvider for LegacyRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(ROOT)))
    }
    fn hardware_backed(&self) -> bool {
        false
    }
}

/// Stands in for the machine TPM. The device root is written in the clear to
/// the file, and read back from it; a missing file is created, as a real
/// provider creates its root on first use.
struct FileRoot(PathBuf);

impl RootKeyProvider for FileRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        let bytes = match std::fs::read(&self.0) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let fresh = [7u8; KEY_LEN];
                std::fs::write(&self.0, fresh).map_err(|error| VaultError::Io {
                    path: self.0.clone(),
                    cause: error.to_string(),
                })?;
                fresh.to_vec()
            }
            Err(error) => {
                return Err(VaultError::Io {
                    path: self.0.clone(),
                    cause: error.to_string(),
                })
            }
        };
        let array: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Tpm("device root of the wrong length".into()))?;
        Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(array)))
    }
    fn hardware_backed(&self) -> bool {
        true
    }
}

/// The machine target of the tests. `fail_verify` makes the verification of
/// the copied identities refuse, which is the failure the tests need.
struct FakeTarget {
    fail_verify: bool,
}

impl RelocationTarget for FakeTarget {
    fn seal_root(&self, root: &DeviceRootKey, device_root_file: &Path) -> Result<(), VaultError> {
        std::fs::write(device_root_file, root.expose_for_wrapping()).map_err(|error| {
            VaultError::Io {
                path: device_root_file.to_path_buf(),
                cause: error.to_string(),
            }
        })
    }

    fn provider(&self, device_root_file: &Path) -> Box<dyn RootKeyProvider> {
        Box::new(FileRoot(device_root_file.to_path_buf()))
    }

    fn key_slot(&self) -> String {
        MACHINE_SLOT.to_string()
    }

    fn verify_identity(&self, file: &Path) -> Result<(), VaultError> {
        if self.fail_verify {
            return Err(VaultError::Relocation("identité refusée (factice)".into()));
        }
        if file.extension() != Some(std::ffi::OsStr::new("identity")) {
            return Err(VaultError::Relocation(
                "fichier non identitaire (factice)".into(),
            ));
        }
        std::fs::metadata(file)
            .map(|_| ())
            .map_err(|error| VaultError::Io {
                path: file.to_path_buf(),
                cause: error.to_string(),
            })
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orion-relocation-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn profile(name: &str) -> ClientProfile {
    let pair = aether::wg::generate_keypair().unwrap();
    let gateway = aether::wg::generate_keypair().unwrap();
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: pair.private_key.duplicate(),
        peer_public_key: gateway.public_key,
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    }
}

/// A legacy layout under `base`, holding the given profiles and one identity.
/// The device root is written, so the legacy vault is a real one.
struct Legacy {
    layout: LegacyLayout,
    calls: Arc<AtomicUsize>,
}

fn legacy_vault(base: &Path, profiles: &[&str]) -> Legacy {
    let layout = LegacyLayout {
        config_dir: base.join("config"),
        identities_dir: base.join("data").join("identities"),
    };
    std::fs::create_dir_all(&layout.config_dir).unwrap();
    std::fs::create_dir_all(&layout.identities_dir).unwrap();
    std::fs::write(layout.config_dir.join(DEVICE_ROOT_FILE), ROOT).unwrap();
    std::fs::write(layout.identities_dir.join("poste.identity"), b"sealed").unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let store = ProfileStore::new(
        layout.config_dir.clone(),
        Box::new(LegacyRoot(Arc::clone(&calls))),
    );
    for name in profiles {
        store.save_profile(&profile(name)).unwrap();
    }
    Legacy { layout, calls }
}

fn legacy_root(calls: &Arc<AtomicUsize>) -> LegacyRoot {
    LegacyRoot(Arc::clone(calls))
}

fn target() -> FakeTarget {
    FakeTarget { fail_verify: false }
}

fn reopen(paths: &EnginePaths) -> ClientConfig {
    ProfileStore::new(
        paths.vault.clone(),
        Box::new(FileRoot(paths.vault.join(DEVICE_ROOT_FILE))),
    )
    .load()
    .unwrap()
}

/// Every file of a directory tree, with its bytes, sorted by path.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

#[test]
fn a_legacy_vault_is_moved_and_reopens() {
    let base = scratch("moved-and-reopens");
    let legacy = legacy_vault(&base, &["poste", "bureau"]);
    let paths = EnginePaths::under(&base.join("root"));

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::Moved {
            profiles: 2,
            identities: 1
        }
    );
    assert_eq!(reopen(&paths).profiles.len(), 2, "the new vault reopens");
    assert!(paths.vault.join(RELOCATED_MARKER).exists());
    assert!(paths.identities.join("poste.identity").exists());
    assert!(!legacy.layout.config_dir.join(DEVICE_ROOT_FILE).exists());
    assert!(!legacy.layout.config_dir.join(PROFILES_DIR).exists());
    assert!(!paths.root.join(STAGING_DIR).exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_failed_verification_leaves_the_legacy_vault_intact() {
    let base = scratch("failed-verification");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let before = snapshot(&legacy.layout.config_dir);
    let identities_before = snapshot(&legacy.layout.identities_dir);
    let refusing = FakeTarget { fail_verify: true };

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &refusing,
    );

    assert!(
        outcome.is_err(),
        "a failed verification must fail the migration"
    );
    assert_eq!(
        snapshot(&legacy.layout.config_dir),
        before,
        "the legacy vault is untouched"
    );
    assert_eq!(
        snapshot(&legacy.layout.identities_dir),
        identities_before,
        "the legacy identities are untouched"
    );
    assert!(!paths.vault.exists(), "no new vault was committed");
    assert!(
        !paths.root.join(STAGING_DIR).exists(),
        "the transit directory is removed"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_leftover_relocation_from_a_crash_is_discarded() {
    let base = scratch("leftover");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let leftover = paths.root.join(STAGING_DIR);
    std::fs::create_dir_all(leftover.join("vault")).unwrap();
    std::fs::write(leftover.join("junk.txt"), b"from a crash").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert!(!leftover.exists(), "the crashed transit is discarded");
    assert!(!paths.root.join("junk.txt").exists());
    assert_eq!(reopen(&paths).profiles.len(), 1);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_already_relocated_vault_is_left_alone() {
    let base = scratch("already-relocated");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();
    let relocated = snapshot(&paths.vault);
    let unwrapped_before = Arc::new(AtomicUsize::new(0));

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&unwrapped_before),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::AlreadyDone {
            legacy_removed: false
        }
    );
    assert_eq!(
        snapshot(&paths.vault),
        relocated,
        "the new vault is unchanged"
    );
    assert_eq!(
        unwrapped_before.load(Ordering::SeqCst),
        0,
        "no legacy root is unwrapped for a vault already relocated"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn nothing_to_move_on_a_fresh_install() {
    let base = scratch("fresh-install");
    let layout = LegacyLayout {
        config_dir: base.join("config"),
        identities_dir: base.join("data").join("identities"),
    };
    let paths = EnginePaths::under(&base.join("root"));
    let calls = Arc::new(AtomicUsize::new(0));

    let outcome = relocate(&layout, &paths, &legacy_root(&calls), &target());

    assert_eq!(outcome.unwrap(), Relocation::NothingToMove);
    assert!(!paths.vault.exists());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn profiles_are_copied_not_reencrypted() {
    let base = scratch("copied-not-reencrypted");
    let legacy = legacy_vault(&base, &["poste", "bureau"]);
    let paths = EnginePaths::under(&base.join("root"));
    let registry = legacy.layout.config_dir.join("registry.hvlt");
    let registry_before = std::fs::read(&registry).unwrap();
    let manifests_before = snapshot(&legacy.layout.config_dir.join(PROFILES_DIR));
    assert_eq!(manifests_before.len(), 2);

    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();

    assert_eq!(
        std::fs::read(paths.vault.join("registry.hvlt")).unwrap(),
        registry_before,
        "the registry is byte for byte the same"
    );
    let manifests_after = snapshot(&paths.vault.join(PROFILES_DIR));
    let names_before: Vec<_> = manifests_before
        .iter()
        .map(|(path, _)| path.file_name().unwrap().to_owned())
        .collect();
    let names_after: Vec<_> = manifests_after
        .iter()
        .map(|(path, _)| path.file_name().unwrap().to_owned())
        .collect();
    assert_eq!(names_after, names_before);
    for ((_, before), (_, after)) in manifests_before.iter().zip(&manifests_after) {
        assert_eq!(before, after, "a profile manifest is copied byte for byte");
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_vault_with_content_and_no_marker_keeps_the_legacy_one() {
    let base = scratch("no-marker");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::create_dir_all(&paths.vault).unwrap();
    std::fs::write(paths.vault.join("partial"), b"not ours").unwrap();
    let before = snapshot(&legacy.layout.config_dir);

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(outcome.unwrap(), Relocation::LegacyKept);
    assert_eq!(
        snapshot(&legacy.layout.config_dir),
        before,
        "the legacy vault is neither read nor removed"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_empty_vault_directory_does_not_block_the_migration() {
    let base = scratch("empty-vault");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::create_dir_all(&paths.vault).unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::Moved {
            profiles: 1,
            identities: 1
        }
    );
    assert_eq!(reopen(&paths).profiles.len(), 1);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_orphan_manifest_does_not_block_the_migration() {
    let base = scratch("orphan");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let profiles = legacy.layout.config_dir.join(PROFILES_DIR);
    let manifest = children_of(&profiles).remove(0);
    std::fs::copy(&manifest, profiles.join("orphan.hvlt")).unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { profiles: 1, .. })));
    assert!(
        paths.vault.join(PROFILES_DIR).join("orphan.hvlt").exists(),
        "the orphan is copied, not dropped"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_registry_entry_without_manifest_fails_the_verification() {
    let base = scratch("missing-manifest");
    let legacy = legacy_vault(&base, &["poste", "bureau"]);
    let paths = EnginePaths::under(&base.join("root"));
    let profiles = legacy.layout.config_dir.join(PROFILES_DIR);
    std::fs::remove_file(children_of(&profiles).remove(0)).unwrap();
    let before = snapshot(&legacy.layout.config_dir);

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(
        outcome.is_err(),
        "a profile without its manifest refuses the migration"
    );
    assert_eq!(snapshot(&legacy.layout.config_dir), before);
    assert!(!paths.vault.exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_cleanup_failure_after_the_commit_is_not_an_error() {
    let base = scratch("cleanup-failure");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();
    // The legacy vault reappears, and its identities folder is no longer a folder.
    std::fs::write(legacy.layout.config_dir.join(DEVICE_ROOT_FILE), ROOT).unwrap();
    std::fs::write(&legacy.layout.identities_dir, b"not a folder").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::AlreadyDone {
            legacy_removed: true
        }
    );
    assert!(!legacy.layout.config_dir.join(DEVICE_ROOT_FILE).exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_identity_name_collision_keeps_both_files() {
    let base = scratch("identity-collision");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::create_dir_all(&paths.identities).unwrap();
    std::fs::write(paths.identities.join("poste.identity"), b"existing").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(
        std::fs::read(paths.identities.join("poste.identity")).unwrap(),
        b"existing"
    );
    assert_eq!(
        std::fs::read(legacy.layout.identities_dir.join("poste.identity")).unwrap(),
        b"sealed",
        "the skipped legacy identity is kept"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_identities_only_legacy_is_moved() {
    let base = scratch("identities-only");
    let layout = LegacyLayout {
        config_dir: base.join("config"),
        identities_dir: base.join("data").join("identities"),
    };
    std::fs::create_dir_all(&layout.identities_dir).unwrap();
    std::fs::write(layout.identities_dir.join("poste.identity"), b"sealed").unwrap();
    let paths = EnginePaths::under(&base.join("root"));
    let calls = Arc::new(AtomicUsize::new(0));

    let outcome = relocate(&layout, &paths, &legacy_root(&calls), &target());

    assert_eq!(
        outcome.unwrap(),
        Relocation::Moved {
            profiles: 0,
            identities: 1
        }
    );
    assert!(paths.identities.join("poste.identity").exists());
    assert!(!layout.identities_dir.join("poste.identity").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_plaintext_only_legacy_lands_in_the_new_vault() {
    let base = scratch("plaintext-only");
    let config = base.join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join(LEGACY_FILE), b"[]").unwrap();
    let layout = LegacyLayout {
        config_dir: config.clone(),
        identities_dir: base.join("data").join("identities"),
    };
    let paths = EnginePaths::under(&base.join("root"));
    let calls = Arc::new(AtomicUsize::new(0));

    let outcome = relocate(&layout, &paths, &legacy_root(&calls), &target());

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(std::fs::read(paths.vault.join(LEGACY_FILE)).unwrap(), b"[]");
    assert!(!config.join(LEGACY_FILE).exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_retry_after_a_partial_merge_succeeds() {
    let base = scratch("partial-merge");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    // A previous attempt merged this store, then stopped before the commit.
    std::fs::create_dir_all(&paths.root).unwrap();
    std::fs::write(paths.root.join("trust_update"), b"trust").unwrap();
    std::fs::write(legacy.layout.config_dir.join("trust_update"), b"trust").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(reopen(&paths).profiles.len(), 1);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_crash_after_the_commit_is_cleaned_up_on_the_next_start() {
    let base = scratch("crash-after-commit");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();
    let config = &legacy.layout.config_dir;
    std::fs::write(config.join(DEVICE_ROOT_FILE), ROOT).unwrap();
    std::fs::write(config.join(LEGACY_FILE), b"[]").unwrap();
    std::fs::write(config.join("orion.log"), b"journal").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::AlreadyDone {
            legacy_removed: true
        }
    );
    assert!(!config.join(DEVICE_ROOT_FILE).exists());
    assert!(!config.join(LEGACY_FILE).exists());
    assert_eq!(std::fs::read(config.join("orion.log")).unwrap(), b"journal");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_stray_file_beside_the_identities_does_not_block_the_migration() {
    let base = scratch("stray-file");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::write(legacy.layout.identities_dir.join("notes.txt"), b"memo").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(
        std::fs::read(paths.identities.join("notes.txt")).unwrap(),
        b"memo",
        "the stray file is copied, without verification"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn a_symlink_in_the_legacy_tree_is_neither_copied_nor_followed() {
    let base = scratch("symlink-copy");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let outside = base.join("outside.txt");
    std::fs::write(&outside, b"not the vault").unwrap();
    let config = &legacy.layout.config_dir;
    std::os::unix::fs::symlink(&outside, config.join("trust_update")).unwrap();
    std::fs::create_dir_all(config.join("certificate_renewal")).unwrap();
    std::os::unix::fs::symlink(
        &outside,
        config.join("certificate_renewal").join("link.json"),
    )
    .unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert!(
        !paths.root.join("trust_update").exists(),
        "a link is not copied"
    );
    assert!(!paths
        .root
        .join("certificate_renewal")
        .join("link.json")
        .exists());
    assert_eq!(std::fs::read(&outside).unwrap(), b"not the vault");
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn the_cleanup_never_deletes_through_a_symlink() {
    let base = scratch("symlink-cleanup");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();
    let outside = base.join("outside.txt");
    std::fs::write(&outside, b"survivor").unwrap();
    let config = &legacy.layout.config_dir;
    std::os::unix::fs::symlink(&outside, config.join("trust_update")).unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::AlreadyDone { .. })));
    assert_eq!(std::fs::read(&outside).unwrap(), b"survivor");
    let _ = std::fs::remove_dir_all(&base);
}

/// Entries of a directory, sorted, for the tests.
fn children_of(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}
#[test]
fn the_logs_are_neither_moved_nor_deleted() {
    let base = scratch("logs");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let config = &legacy.layout.config_dir;
    std::fs::write(config.join("orion.log"), b"journal").unwrap();
    std::fs::write(config.join("orion-ui.log"), b"journal ui").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(std::fs::read(config.join("orion.log")).unwrap(), b"journal");
    assert_eq!(
        std::fs::read(config.join("orion-ui.log")).unwrap(),
        b"journal ui"
    );
    assert!(!paths.log.exists(), "a log is never moved into the root");
    assert!(!paths.root.join("orion-ui.log").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn stores_beside_the_config_land_in_the_root() {
    let base = scratch("stores");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let config = &legacy.layout.config_dir;
    std::fs::write(config.join("trust_update"), b"trust").unwrap();
    std::fs::create_dir_all(config.join("certificate_renewal")).unwrap();
    std::fs::write(
        config.join("certificate_renewal").join("x.json"),
        b"renewal",
    )
    .unwrap();

    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();

    assert_eq!(
        std::fs::read(paths.root.join("trust_update")).unwrap(),
        b"trust"
    );
    assert_eq!(
        std::fs::read(paths.root.join("certificate_renewal").join("x.json")).unwrap(),
        b"renewal"
    );
    assert!(!config.join("trust_update").exists());
    assert!(!config.join("certificate_renewal").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_legacy_root_is_never_created() {
    let base = scratch("no-device-root");
    let config = base.join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join(LEGACY_FILE), b"[]").unwrap();
    let layout = LegacyLayout {
        config_dir: config,
        identities_dir: base.join("data").join("identities"),
    };
    let paths = EnginePaths::under(&base.join("root"));
    let calls = Arc::new(AtomicUsize::new(0));

    let outcome = relocate(&layout, &paths, &legacy_root(&calls), &target());

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "without a legacy device root, the legacy provider is never asked"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_existing_file_is_not_overwritten_by_the_merge() {
    let base = scratch("no-overwrite");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::create_dir_all(&paths.root).unwrap();
    std::fs::write(paths.root.join("trust_update"), b"existing").unwrap();
    std::fs::write(legacy.layout.config_dir.join("trust_update"), b"legacy").unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert!(matches!(outcome, Ok(Relocation::Moved { .. })));
    assert_eq!(
        std::fs::read(paths.root.join("trust_update")).unwrap(),
        b"existing",
        "a file already at the destination is never overwritten"
    );
    assert_eq!(
        std::fs::read(legacy.layout.config_dir.join("trust_update")).unwrap(),
        b"legacy",
        "the skipped legacy file is kept"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// A store whose copy the merge skipped is the only copy left. A later run that
/// cleans up the legacy vault must keep it.
#[test]
fn a_skipped_store_survives_a_later_cleanup() {
    let base = scratch("skipped-survives");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    std::fs::create_dir_all(&paths.root).unwrap();
    std::fs::write(paths.root.join("trust_update"), b"existing").unwrap();
    std::fs::write(legacy.layout.config_dir.join("trust_update"), b"legacy").unwrap();
    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();

    let outcome = relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    );

    assert_eq!(
        outcome.unwrap(),
        Relocation::AlreadyDone {
            legacy_removed: false
        }
    );
    assert_eq!(
        std::fs::read(legacy.layout.config_dir.join("trust_update")).unwrap(),
        b"legacy",
        "the skipped legacy store is kept"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_bootstrap_names_the_machine_slot() {
    let base = scratch("bootstrap-slot");
    let legacy = legacy_vault(&base, &["poste"]);
    let paths = EnginePaths::under(&base.join("root"));
    let original: Bootstrap = toml::from_str(
        &std::fs::read_to_string(legacy.layout.config_dir.join(BOOTSTRAP_FILE)).unwrap(),
    )
    .unwrap();

    relocate(
        &legacy.layout,
        &paths,
        &legacy_root(&legacy.calls),
        &target(),
    )
    .unwrap();

    let moved: Bootstrap =
        toml::from_str(&std::fs::read_to_string(paths.vault.join(BOOTSTRAP_FILE)).unwrap())
            .unwrap();
    assert_eq!(moved.key_slot, MACHINE_SLOT, "the machine slot is named");
    assert_eq!(
        moved.install_id, original.install_id,
        "the installation identifier is kept"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_failure_message_names_the_kept_vault() {
    let message = failure_message(&VaultError::Relocation("cause".into()));
    assert_eq!(
        message,
        "La migration du coffre a échoué : l'ancien coffre est conservé. Cause : cause"
    );
}
