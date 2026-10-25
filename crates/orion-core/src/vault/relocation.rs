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

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

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
    /// The new vault was already committed. `cleanup_planned` says whether
    /// the plan returned with it removes anything of the old one.
    AlreadyDone { cleanup_planned: bool },
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
/// `relocate` deletes nothing in the legacy folder. On `Moved`, and on an
/// already-relocated vault, it returns the plan of what to remove there. The
/// caller runs the plan under the identity of the user who owns that folder
/// (see [`LegacyCleanup::run`]).
///
/// Up to the commit, every failure leaves the legacy vault untouched. After
/// the commit nothing is fatal.
pub fn relocate(
    legacy: &LegacyLayout,
    paths: &EnginePaths,
    legacy_root: &dyn RootKeyProvider,
    target: &dyn RelocationTarget,
) -> Result<(Relocation, Option<LegacyCleanup>), VaultError> {
    let staging = paths.root.join(STAGING_DIR);
    if paths.vault.exists() && !is_vacant_dir(&paths.vault) {
        if paths.vault.join(RELOCATED_MARKER).exists() {
            discard_after_failure(&staging);
            let cleanup = legacy_cleanup(legacy, paths)?;
            let cleanup_planned = !cleanup.paths.is_empty();
            return Ok((Relocation::AlreadyDone { cleanup_planned }, Some(cleanup)));
        }
        // Without the marker the new vault is not known to be complete, so the
        // legacy one is the only trustworthy copy and stays where it is.
        let relocation = if legacy_present(legacy)? {
            Relocation::LegacyKept
        } else {
            Relocation::AlreadyDone {
                cleanup_planned: false,
            }
        };
        return Ok((relocation, None));
    }

    if !legacy_present(legacy)? {
        // Nothing to migrate: a leftover transit is only noise, logged if it
        // cannot be removed.
        discard_after_failure(&staging);
        return Ok((Relocation::NothingToMove, None));
    }
    refuse_linked_vault_entries(legacy)?;
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

    // The new vault is committed and reopened. The old copies are planned for
    // removal: the vault files, and the entries the merge moved. An entry the
    // merge skipped stays where it is.
    let mut cleanup = LegacyCleanup { paths: Vec::new() };
    for path in entries.vault.iter().chain(&sources) {
        plan_removal(path, &mut cleanup.paths);
    }
    push_identities_folder(legacy, &mut cleanup.paths);

    tracing::info!(
        profils = staged.profiles,
        identites = staged.identities,
        "coffre repris sous la racine protégée"
    );
    Ok((
        Relocation::Moved {
            profiles: staged.profiles,
            identities: staged.identities,
        },
        Some(cleanup),
    ))
}

/// What a migration removes from the legacy folder once the new vault stands:
/// files first, then each folder that is empty by then.
///
/// The folder belongs to the user, and the engine runs elevated. Removal
/// therefore happens under the user's own identity, so that a folder swapped
/// for a link cannot make the engine delete anything the user could not.
#[derive(Debug)]
pub struct LegacyCleanup {
    paths: Vec<PathBuf>,
}

impl LegacyCleanup {
    /// Removes the planned entries, and returns how many were removed.
    ///
    /// Never through a link: an entry whose path crosses a link is skipped.
    /// A folder is removed only when empty. A failure is logged, not fatal.
    pub fn run(self) -> usize {
        let mut removed = 0;
        for path in &self.paths {
            if is_link_on_the_way(path) {
                tracing::warn!(
                    chemin = %path.display(),
                    "lien sur le chemin de l'ancien coffre : entrée ignorée"
                );
                continue;
            }
            let Ok(metadata) = path.symlink_metadata() else {
                // Already gone.
                continue;
            };
            let outcome = if metadata.is_dir() {
                match fs::read_dir(path) {
                    Ok(mut entries) => {
                        // A folder with something else in it stays.
                        if entries.next().is_some() {
                            continue;
                        }
                        fs::remove_dir(path)
                    }
                    Err(error) => Err(error),
                }
            } else {
                fs::remove_file(path)
            };
            match outcome {
                Ok(()) => removed += 1,
                Err(error) => tracing::warn!(
                    chemin = %path.display(),
                    %error,
                    "suppression de l'ancien coffre impossible"
                ),
            }
        }
        removed
    }
}

/// Whether `path`, or any folder it is under, is a link.
fn is_link_on_the_way(path: &Path) -> bool {
    path.ancestors().any(|ancestor| {
        ancestor
            .symlink_metadata()
            .is_ok_and(|metadata| is_reparse(&metadata))
    })
}

/// Appends `path`, and for a real folder everything under it, children first.
/// Links are neither followed nor planned.
fn plan_removal(path: &Path, out: &mut Vec<PathBuf>) {
    match kind_of(path) {
        Some(Kind::Dir) => {
            match children(path) {
                Ok(entries) => {
                    for entry in &entries {
                        plan_removal(entry, out);
                    }
                }
                Err(error) => tracing::warn!(%error, "dossier de l'ancien coffre illisible"),
            }
            out.push(path.to_path_buf());
        }
        Some(Kind::File) => out.push(path.to_path_buf()),
        None => {}
    }
}

/// The removal planned for an already-relocated vault: the vault files, and
/// the stores and identities whose copy holds the same bytes.
fn legacy_cleanup(legacy: &LegacyLayout, paths: &EnginePaths) -> Result<LegacyCleanup, VaultError> {
    let entries = legacy_entries(legacy, false)?;
    let mut planned = Vec::new();
    for path in &entries.vault {
        plan_removal(path, &mut planned);
    }
    for source in &entries.stores {
        if copy_is_identical(source, &paths.root.join(child_name(source))) {
            plan_removal(source, &mut planned);
        }
    }
    for source in &entries.identities {
        if copy_is_identical(source, &paths.identities.join(child_name(source))) {
            plan_removal(source, &mut planned);
        }
    }
    push_identities_folder(legacy, &mut planned);
    Ok(LegacyCleanup { paths: planned })
}

/// The legacy identities folder goes last, and only when it is a real folder.
/// Removal leaves it alone unless it is then empty.
fn push_identities_folder(legacy: &LegacyLayout, out: &mut Vec<PathBuf>) {
    if kind_of(&legacy.identities_dir) == Some(Kind::Dir) {
        out.push(legacy.identities_dir.clone());
    }
}

/// A vault entry that is a link refuses the migration. Its copy would silently
/// miss it, and an empty registry would then pass for a complete one.
fn refuse_linked_vault_entries(legacy: &LegacyLayout) -> Result<(), VaultError> {
    for name in VAULT_ENTRIES {
        let path = legacy.config_dir.join(name);
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| is_reparse(&metadata))
        {
            return Err(VaultError::Relocation(format!(
                "« {name} » est un lien dans l'ancien coffre : migration refusée"
            )));
        }
    }
    Ok(())
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
/// any other reparse point is `None`, and reported once: nothing reads through
/// it, copies it or removes through it. A missing entry is `None` silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

fn kind_of(path: &Path) -> Option<Kind> {
    let metadata = path.symlink_metadata().ok()?;
    if is_reparse(&metadata) {
        report_link(path);
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

/// Logs a link in the legacy tree, once per path for the whole process.
fn report_link(path: &Path) {
    if first_report_of(path) {
        tracing::warn!(chemin = %path.display(), "lien ignoré dans l'ancien coffre");
    }
}

/// Whether `path` is reported for the first time. Each path is reported once,
/// however many steps ask the same question about it.
fn first_report_of(path: &Path) -> bool {
    static REPORTED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let reported = REPORTED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut reported = reported
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reported.insert(path.to_path_buf())
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
/// which is what a migration must not do. A lenient one, used for an
/// already-relocated vault, logs it and sees nothing there.
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
            report_link(dir);
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
