//! Migration of an existing vault into the protected root (F11, task 12).
//!
//! The vault moves from the per-user folder to `root/vault`. Nothing is
//! re-encrypted: the installation root keeps wrapping the registry and the
//! profiles, so their bytes are copied as they are. Only the device root is
//! sealed again, under the machine key. The old vault is removed once, and only
//! once, the new one carries [`RELOCATED_MARKER`] and has been reopened.
//!
//! # Order, and why it is not negotiable
//!
//! Everything up to the rename of the transit directory is reversible: a
//! failure removes the transit directory and leaves the legacy vault exactly as
//! it was. The rename is the commit point. Removing the legacy vault comes
//! after it, and a failure there is logged, not fatal.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::settings::SETTINGS_FILE;
use super::store::{
    self, BOOTSTRAP_FILE, DEVICE_ROOT_FILE, LEGACY_FILE, PROFILES_DIR, REGISTRY_FILE,
};
use super::{DeviceRootKey, ProfileStore, RootKeyProvider, VaultError};
use crate::protected_root::{EnginePaths, LOG_FILE};

/// Written into the new vault at the point of validation. Its presence is what
/// authorises the removal of the legacy vault.
pub const RELOCATED_MARKER: &str = ".relocated";

/// Transit directory under the protected root, beside the vault it prepares.
pub const STAGING_DIR: &str = ".relocating";

/// Name of the UI's log, which stays where it is.
const UI_LOG_FILE: &str = "orion-ui.log";

/// Files and directories of the legacy vault, in the configuration directory.
const VAULT_ENTRIES: [&str; 6] = [
    BOOTSTRAP_FILE,
    DEVICE_ROOT_FILE,
    REGISTRY_FILE,
    PROFILES_DIR,
    LEGACY_FILE,
    SETTINGS_FILE,
];

/// Logs, which are never moved and never removed.
const LOG_FILES: [&str; 2] = [LOG_FILE, UI_LOG_FILE];

/// Subdirectory of the transit directory that becomes the vault.
const STAGED_VAULT: &str = "vault";

/// Subdirectory of the transit directory that becomes the identities.
const STAGED_IDENTITIES: &str = "identities";

/// Size of the blocks compared when a copy is checked against its source.
const COMPARE_BLOCK: usize = 64 * 1024;

/// Extension of a sealed profile manifest.
const MANIFEST_EXTENSION: &str = "hvlt";

/// Where the legacy vault and its stores sat for the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyLayout {
    /// The per-user configuration directory. The vault, the sealed stores and
    /// the logs all sit in it.
    pub config_dir: PathBuf,
    /// The per-user directory of the sealed identities.
    pub identities_dir: PathBuf,
}

impl LegacyLayout {
    /// The current user's folders, as they were before the protected root.
    #[cfg(windows)]
    pub fn for_current_user() -> Result<Self, VaultError> {
        let dirs = directories::ProjectDirs::from("net", "helios", "orion").ok_or_else(|| {
            VaultError::Relocation("impossible de déterminer le répertoire de configuration".into())
        })?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            identities_dir: dirs.data_dir().join("identities"),
        })
    }
}

/// Where the vault goes: the machine key, in production; a fake in the tests.
pub trait RelocationTarget {
    /// Seals `root` under the target's key and writes it to `device_root_file`.
    fn seal_root(&self, root: &DeviceRootKey, device_root_file: &Path) -> Result<(), VaultError>;

    /// The provider that opens the device root written at `device_root_file`.
    fn provider(&self, device_root_file: &Path) -> Box<dyn RootKeyProvider>;

    /// Name of the key the device root is now wrapped under.
    fn key_slot(&self) -> String;

    /// Opens one copied identity with the target's protection.
    fn verify_identity(&self, file: &Path) -> Result<(), VaultError>;
}

/// What a relocation did.
#[derive(Debug, PartialEq, Eq)]
pub enum Relocation {
    /// No legacy vault exists: a fresh install.
    NothingToMove,
    /// The legacy vault was copied, verified and committed.
    Moved { profiles: usize, identities: usize },
    /// The new vault was already committed. `legacy_removed` says whether
    /// anything of the old one was still there and got removed.
    AlreadyDone { legacy_removed: bool },
    /// A new vault exists without its marker, so the legacy one was neither
    /// read nor removed.
    LegacyKept,
}

/// The provider of a start whose migration failed.
///
/// It refuses every root. Without it, the store of that start would create a
/// root on the new location while the legacy one still holds the installation's
/// profiles, and the two would then disagree for good.
pub struct RefusedRoot {
    message: String,
}

impl RefusedRoot {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl RootKeyProvider for RefusedRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        Err(VaultError::Relocation(self.message.clone()))
    }

    fn hardware_backed(&self) -> bool {
        false
    }
}

/// Moves the legacy vault under `paths`, verifying it before the commit.
///
/// `legacy_root` unwraps the legacy device root, and is asked only when that
/// root exists. `target` seals the root again and verifies the copies.
///
/// Up to the commit, every failure leaves the legacy vault untouched. After
/// the commit nothing is fatal: a problem removing the old copies is logged,
/// because the new vault already stands.
pub fn relocate(
    legacy: &LegacyLayout,
    paths: &EnginePaths,
    legacy_root: &dyn RootKeyProvider,
    target: &dyn RelocationTarget,
) -> Result<Relocation, VaultError> {
    let staging = paths.root.join(STAGING_DIR);
    if paths.vault.exists() && !is_vacant_dir(&paths.vault) {
        if paths.vault.join(RELOCATED_MARKER).exists() {
            discard_after_failure(&staging);
            let legacy_removed = remove_legacy(legacy, paths);
            return Ok(Relocation::AlreadyDone { legacy_removed });
        }
        // Without the marker the new vault is not known to be complete, so the
        // legacy one is the only trustworthy copy and stays where it is.
        return Ok(if legacy_present(legacy)? {
            Relocation::LegacyKept
        } else {
            Relocation::AlreadyDone {
                legacy_removed: false,
            }
        });
    }

    if !legacy_present(legacy)? {
        // Nothing to migrate: a leftover transit is only noise, logged if it
        // cannot be removed.
        discard_after_failure(&staging);
        return Ok(Relocation::NothingToMove);
    }
    // A transit directory left by an interrupted run is never trusted, and
    // here its removal is required: the migration cannot run beside it.
    discard(&staging)?;

    let entries = legacy_entries(legacy, true)?;
    let staged = match stage(legacy, &entries, &staging, legacy_root, target) {
        Ok(staged) => staged,
        Err(error) => {
            discard_after_failure(&staging);
            return Err(error);
        }
    };
    let sources = match commit(legacy, paths, &staging) {
        Ok(sources) => sources,
        Err(error) => {
            discard_after_failure(&staging);
            return Err(error);
        }
    };
    discard_after_failure(&staging);

    // The new vault is committed and reopened. From here nothing is fatal.
    // The copies of the vault and the entries that were merged are removed; an
    // entry skipped by the merge stays where it is.
    remove_paths(&entries.vault);
    remove_paths(&sources);
    remove_empty_dir(&legacy.identities_dir);

    tracing::info!(
        profils = staged.profiles,
        identites = staged.identities,
        "coffre repris sous la racine protégée"
    );
    Ok(Relocation::Moved {
        profiles: staged.profiles,
        identities: staged.identities,
    })
}

/// The message shown when a migration failed. The old vault is kept.
pub fn failure_message(error: &VaultError) -> String {
    format!("La migration du coffre a échoué : l'ancien coffre est conservé. Cause : {error}")
}

/// Counts of what the staged vault holds, once verified.
struct Staged {
    profiles: usize,
    identities: usize,
}

/// Builds the transit directory and verifies it. Nothing outside `staging`
/// is written by this step.
fn stage(
    legacy: &LegacyLayout,
    entries: &LegacyEntries,
    staging: &Path,
    legacy_root: &dyn RootKeyProvider,
    target: &dyn RelocationTarget,
) -> Result<Staged, VaultError> {
    let vault = staging.join(STAGED_VAULT);
    let identities = staging.join(STAGED_IDENTITIES);
    create_dir(&vault)?;
    create_dir(&identities)?;

    for source in &entries.vault {
        if child_name(source) == OsStr::new(DEVICE_ROOT_FILE) {
            continue;
        }
        copy_entry(source, &vault.join(child_name(source)))?;
    }
    for source in &entries.stores {
        copy_entry(source, &staging.join(child_name(source)))?;
    }
    for source in &entries.identities {
        copy_entry(source, &identities.join(child_name(source)))?;
    }

    let staged_device_root = vault.join(DEVICE_ROOT_FILE);
    let legacy_device_root = legacy.config_dir.join(DEVICE_ROOT_FILE);
    // Without a legacy device root there is nothing to unwrap, and the legacy
    // provider must not be asked: it would create a root that nothing needs.
    if legacy_device_root.symlink_metadata().is_ok() {
        if kind_of(&legacy_device_root) != Some(Kind::File) {
            return Err(VaultError::Relocation(
                "la racine héritée est un lien ou n'est pas un fichier : migration refusée".into(),
            ));
        }
        let root = legacy_root.root_key()?;
        target.seal_root(&root, &staged_device_root)?;
        store::set_key_slot(&vault, &target.key_slot())?;
    }

    let staged_store = ProfileStore::new(vault.clone(), target.provider(&staged_device_root))
        .with_key_slot(target.key_slot());
    let verified = staged_store.load()?;
    // The count is the registry's: a manifest without an entry is an orphan,
    // copied and reported, while an entry without a manifest fails the load.
    let registered = staged_store.registered_count()?;
    if verified.profiles.len() != registered {
        return Err(VaultError::Relocation(format!(
            "{} profils chargés pour {registered} entrées du registre",
            verified.profiles.len()
        )));
    }
    let manifests = count_manifests(&vault.join(PROFILES_DIR))?;
    if manifests > registered {
        tracing::warn!(
            orphelins = manifests - registered,
            "manifestes sans entrée au registre : copiés, non repris"
        );
    }

    let mut identity_count = 0;
    for file in children(&identities)? {
        if is_identity_file(&file) {
            target.verify_identity(&file)?;
            identity_count += 1;
        }
    }
    Ok(Staged {
        profiles: verified.profiles.len(),
        identities: identity_count,
    })
}

/// Moves the verified transit into the protected root, and marks it. Returns
/// the legacy paths whose copies were moved, which the cleanup may remove.
fn commit(
    legacy: &LegacyLayout,
    paths: &EnginePaths,
    staging: &Path,
) -> Result<Vec<PathBuf>, VaultError> {
    let vault = staging.join(STAGED_VAULT);
    let identities = staging.join(STAGED_IDENTITIES);
    create_dir(&paths.root)?;

    let mut sources = Vec::new();
    for staged in children(staging)? {
        let name = child_name(&staged);
        if name == OsStr::new(STAGED_VAULT) || name == OsStr::new(STAGED_IDENTITIES) {
            continue;
        }
        if merge(&staged, &paths.root.join(name))? {
            sources.push(legacy.config_dir.join(name));
        }
    }

    create_dir(&paths.identities)?;
    for staged in children(&identities)? {
        let name = child_name(&staged);
        if merge(&staged, &paths.identities.join(name))? {
            sources.push(legacy.identities_dir.join(name));
        }
    }

    write_synced(&vault.join(RELOCATED_MARKER))?;
    // An empty vault directory is an absent vault, and it must go before the
    // rename, which refuses to replace it.
    if is_vacant_dir(&paths.vault) {
        fs::remove_dir(&paths.vault).map_err(|error| io(&paths.vault, error))?;
    }
    // The commit point: from here the new vault is the vault.
    fs::rename(&vault, &paths.vault).map_err(|error| io(&paths.vault, error))?;
    Ok(sources)
}

/// Moves one transit entry to `destination`. A name already there is kept as
/// it is, and reported; `false` says the entry was not moved.
fn merge(staged: &Path, destination: &Path) -> Result<bool, VaultError> {
    if destination.symlink_metadata().is_ok() {
        tracing::warn!(
            destination = %destination.display(),
            "fichier déjà présent à la racine protégée : non écrasé"
        );
        return Ok(false);
    }
    fs::rename(staged, destination).map_err(|error| io(destination, error))?;
    Ok(true)
}

/// The kind of an entry, read without following a link. A link, a junction or
/// any other reparse point is `None`, and logged: nothing reads through it,
/// copies it or removes through it. A missing entry is `None` silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

fn kind_of(path: &Path) -> Option<Kind> {
    let metadata = path.symlink_metadata().ok()?;
    if is_reparse(&metadata) {
        tracing::warn!(chemin = %path.display(), "lien ignoré dans l'ancien coffre");
        return None;
    }
    if metadata.is_dir() {
        Some(Kind::Dir)
    } else if metadata.is_file() {
        Some(Kind::File)
    } else {
        None
    }
}

/// A symbolic link, or a reparse point on Windows (junction included).
#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const REPARSE_POINT: u32 = 0x400;

    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn is_identity_file(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("identity"))
}

/// What the legacy vault holds, as paths under the legacy layout.
struct LegacyEntries {
    /// Vault files and directories, the device root included.
    vault: Vec<PathBuf>,
    /// Stores written beside the configuration. Logs and vault names excluded.
    stores: Vec<PathBuf>,
    /// Identity entries: files only.
    identities: Vec<PathBuf>,
}

/// Lists the legacy vault. A `strict` listing fails on an unreadable folder,
/// which is what a migration must not do. A lenient one, used after the commit,
/// logs it and sees nothing there.
fn legacy_entries(legacy: &LegacyLayout, strict: bool) -> Result<LegacyEntries, VaultError> {
    let vault = VAULT_ENTRIES
        .iter()
        .map(|name| legacy.config_dir.join(name))
        .filter(|path| kind_of(path).is_some())
        .collect();
    let mut stores = Vec::new();
    for path in listing(&legacy.config_dir, strict)? {
        let name = child_name(&path);
        let reserved = VAULT_ENTRIES
            .iter()
            .chain(LOG_FILES.iter())
            .any(|reserved| OsStr::new(reserved) == name);
        if !reserved && kind_of(&path).is_some() {
            stores.push(path);
        }
    }
    let identities = listing(&legacy.identities_dir, strict)?
        .into_iter()
        .filter(|path| kind_of(path) == Some(Kind::File))
        .collect();
    Ok(LegacyEntries {
        vault,
        stores,
        identities,
    })
}

fn listing(dir: &Path, strict: bool) -> Result<Vec<PathBuf>, VaultError> {
    match children(dir) {
        Ok(paths) => Ok(paths),
        Err(error) if strict => Err(error),
        Err(error) => {
            tracing::warn!(%error, "dossier de l'ancien coffre illisible : ignoré");
            Ok(Vec::new())
        }
    }
}

/// Whether a legacy vault exists: a device root, a plaintext file, or an
/// identity.
fn legacy_present(legacy: &LegacyLayout) -> Result<bool, VaultError> {
    Ok(legacy
        .config_dir
        .join(DEVICE_ROOT_FILE)
        .symlink_metadata()
        .is_ok()
        || legacy
            .config_dir
            .join(LEGACY_FILE)
            .symlink_metadata()
            .is_ok()
        || listing(&legacy.identities_dir, true)?
            .iter()
            .any(|path| kind_of(path) == Some(Kind::File)))
}

/// Removes what remains of a legacy vault whose new copy is already committed.
/// Returns whether anything was removed. Never fails: a problem is logged.
///
/// The vault files go unconditionally: the committed vault replaced them, and
/// the device root is sealed again, so its bytes differ on purpose. A store or
/// an identity goes only when its copy in the protected root holds the same
/// bytes. A copy the merge skipped leaves the legacy file as the only one.
fn remove_legacy(legacy: &LegacyLayout, paths: &EnginePaths) -> bool {
    let entries = match legacy_entries(legacy, false) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    let mut removed = remove_paths(&entries.vault);
    let stores: Vec<PathBuf> = entries
        .stores
        .into_iter()
        .filter(|source| copy_is_identical(source, &paths.root.join(child_name(source))))
        .collect();
    removed |= remove_paths(&stores);
    let identities: Vec<PathBuf> = entries
        .identities
        .into_iter()
        .filter(|source| copy_is_identical(source, &paths.identities.join(child_name(source))))
        .collect();
    removed |= remove_paths(&identities);
    removed |= remove_empty_dir(&legacy.identities_dir);
    removed
}

/// Whether `copy` holds the same bytes as `source`, entry by entry. Anything
/// unreadable, or a link, counts as different, so the source stays.
fn copy_is_identical(source: &Path, copy: &Path) -> bool {
    match kind_of(source) {
        Some(Kind::Dir) => {
            if kind_of(copy) != Some(Kind::Dir) {
                return false;
            }
            match children(source) {
                Ok(entries) => entries
                    .iter()
                    .all(|entry| copy_is_identical(entry, &copy.join(child_name(entry)))),
                Err(_) => false,
            }
        }
        Some(Kind::File) => kind_of(copy) == Some(Kind::File) && same_bytes(source, copy),
        None => false,
    }
}

/// Compares two files in fixed-size blocks, so a large file is never held in
/// memory whole.
fn same_bytes(left: &Path, right: &Path) -> bool {
    let (Ok(mut left), Ok(mut right)) = (File::open(left), File::open(right)) else {
        return false;
    };
    let mut left_block = [0u8; COMPARE_BLOCK];
    let mut right_block = [0u8; COMPARE_BLOCK];
    loop {
        let (Ok(left_read), Ok(right_read)) = (
            fill(&mut left, &mut left_block),
            fill(&mut right, &mut right_block),
        ) else {
            return false;
        };
        if left_read != right_read || left_block[..left_read] != right_block[..right_read] {
            return false;
        }
        if left_read == 0 {
            return true;
        }
    }
}

/// Reads until the block is full or the file ends.
fn fill(reader: &mut impl Read, block: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < block.len() {
        let read = reader.read(&mut block[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

/// Removes each path that is a file or a real directory, logging a failure
/// without stopping. A link is never removed through. Returns whether anything
/// was removed.
fn remove_paths(paths: &[PathBuf]) -> bool {
    let mut removed = false;
    for path in paths {
        let outcome = match kind_of(path) {
            Some(Kind::Dir) => remove_tree(path),
            Some(Kind::File) => fs::remove_file(path).map(|()| true),
            None => continue,
        };
        match outcome {
            Ok(done) => removed |= done,
            Err(error) => tracing::warn!(
                chemin = %path.display(),
                %error,
                "suppression de l'ancien coffre impossible"
            ),
        }
    }
    removed
}

/// Removes the files of a directory tree, then each directory that is left
/// empty. Links are left alone, and so is anything else in a directory that
/// is not empty afterwards.
fn remove_tree(dir: &Path) -> std::io::Result<bool> {
    let mut removed = false;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        match kind_of(&path) {
            Some(Kind::Dir) => removed |= remove_tree(&path)?,
            Some(Kind::File) => {
                fs::remove_file(&path)?;
                removed = true;
            }
            None => {}
        }
    }
    if fs::read_dir(dir)?.next().is_none() {
        fs::remove_dir(dir)?;
        removed = true;
    }
    Ok(removed)
}

/// Removes a directory once it is empty. A non-empty directory is kept. A
/// failure is logged, not fatal.
fn remove_empty_dir(dir: &Path) -> bool {
    if kind_of(dir) != Some(Kind::Dir) {
        return false;
    }
    match children(dir) {
        Ok(entries) if entries.is_empty() => match fs::remove_dir(dir) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(chemin = %dir.display(), %error, "dossier d'identités non supprimé");
                false
            }
        },
        _ => false,
    }
}

/// Copies a file or a directory tree. Every file is synced. A link is skipped.
fn copy_entry(source: &Path, destination: &Path) -> Result<(), VaultError> {
    match kind_of(source) {
        Some(Kind::Dir) => {
            create_dir(destination)?;
            for child in children(source)? {
                copy_entry(&child, &destination.join(child_name(&child)))?;
            }
            Ok(())
        }
        Some(Kind::File) => copy_file(source, destination),
        None => Ok(()),
    }
}

/// Copies one file byte for byte, and syncs the copy before it can be named
/// by the commit.
fn copy_file(source: &Path, destination: &Path) -> Result<(), VaultError> {
    fs::copy(source, destination).map_err(|error| io(source, error))?;
    OpenOptions::new()
        .write(true)
        .open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| io(destination, error))
}

/// Writes an empty file and syncs it.
fn write_synced(path: &Path) -> Result<(), VaultError> {
    let mut file = File::create(path).map_err(|error| io(path, error))?;
    file.write_all(b"")
        .and_then(|()| file.sync_all())
        .map_err(|error| io(path, error))
}

fn count_manifests(dir: &Path) -> Result<usize, VaultError> {
    Ok(children(dir)?
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension == MANIFEST_EXTENSION)
        })
        .count())
}

/// Entries of a directory, sorted. A missing directory has none, and so does
/// a link standing in for one: a link is never followed.
fn children(dir: &Path) -> Result<Vec<PathBuf>, VaultError> {
    match dir.symlink_metadata() {
        Ok(metadata) if is_reparse(&metadata) => {
            tracing::warn!(chemin = %dir.display(), "lien ignoré dans l'ancien coffre");
            return Ok(Vec::new());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(dir, error)),
    }
    let entries = fs::read_dir(dir).map_err(|error| io(dir, error))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|error| io(dir, error))?.path());
    }
    paths.sort();
    Ok(paths)
}

/// An existing directory with nothing in it: an absent vault, for a migration.
fn is_vacant_dir(dir: &Path) -> bool {
    kind_of(dir) == Some(Kind::Dir) && children(dir).is_ok_and(|entries| entries.is_empty())
}

fn child_name(path: &Path) -> &OsStr {
    path.file_name().unwrap_or(OsStr::new(""))
}

fn create_dir(path: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(path).map_err(|error| io(path, error))
}

/// Removes the transit directory. Its absence is success.
fn discard(staging: &Path) -> Result<(), VaultError> {
    match fs::remove_dir_all(staging) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(staging, error)),
    }
}

/// Removes the transit directory where the outcome is already settled. The
/// error the person needs is not this one, so a failure here is only logged.
fn discard_after_failure(staging: &Path) {
    if let Err(error) = discard(staging) {
        tracing::warn!(%error, "zone de transit de la migration non supprimée");
    }
}

fn io(path: &Path, error: std::io::Error) -> VaultError {
    VaultError::Io {
        path: path.to_path_buf(),
        cause: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
