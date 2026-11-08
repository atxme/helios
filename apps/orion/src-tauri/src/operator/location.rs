//! Where the operator vault lives, as the operator chose it.
//!
//! Every operator gesture opens the vault at [`VaultLocation::path`]: the
//! operator's choice when one was made, the tooling's default otherwise. The
//! choice is a path and nothing else — the setting holds no secret — and it is
//! made in a dialog of this process, never named by the WebView.
//!
//! A setting that cannot be read is an error, not the default: the operator
//! chose a vault, and a ceremony that silently opened another one would sign
//! under a domain they did not mean. Choosing again, or going back to the
//! default, replaces it — so the view still offers both, beside the error.
//!
//! The default folder is created, privately, when a gesture resolves the
//! vault there: nothing else creates it before the first vault. A chosen
//! folder never is.

use std::path::{Path, PathBuf};
#[cfg(any(windows, test))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The only file name a vault is accepted under, the tooling's own.
pub const VAULT_FILE_NAME: &str = "authority-vault.json";

/// Name of the setting, beside the rest of the operator material.
const SETTINGS_FILE_NAME: &str = "orion-operator.json";

/// A setting holds one path: anything longer was not written by Orion.
const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

/// Said when a second dialog is asked for while one is open.
#[cfg(any(windows, test))]
const PICKER_ALREADY_OPEN: &str = "un sélecteur d'emplacement est déjà ouvert";

/// What is written on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    vault_path: PathBuf,
}

/// The vault location this process opens, and the setting it comes from.
///
/// `choice` is what the setting said when it was last read or written: a
/// path, none, or why it could not be read. `picking` is set while a dialog
/// is open, so a second one is refused rather than stacked over it.
pub struct VaultLocation {
    settings: Result<PathBuf, String>,
    /// The tooling's own vault, opened while no choice is recorded.
    default: Result<PathBuf, String>,
    choice: Mutex<Result<Option<PathBuf>, String>>,
    #[cfg(any(windows, test))]
    picking: AtomicBool,
}

/// Holds the one open dialog; dropping it, on whatever path, frees the place.
#[cfg(any(windows, test))]
pub struct PickerGuard<'a>(&'a AtomicBool);

#[cfg(any(windows, test))]
impl Drop for PickerGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What the WebView is shown. A path to display, not one it may send back.
///
/// `path` is absent, and `error` says why, when the location cannot be
/// resolved — a setting that cannot be read, most often. The view is still
/// served, so the window keeps the two ways out: choosing again, and going
/// back to the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultLocationView {
    pub path: Option<String>,
    pub is_default: bool,
    pub picker_available: bool,
    pub error: Option<String>,
}

impl VaultLocation {
    /// Reads the setting at its usual place.
    pub fn load() -> Self {
        match settings_path() {
            Ok(settings) => Self::at(settings),
            Err(error) => {
                let message = format!("{error:#}");
                Self {
                    settings: Err(message.clone()),
                    default: default_vault(),
                    choice: Mutex::new(Err(message)),
                    #[cfg(any(windows, test))]
                    picking: AtomicBool::new(false),
                }
            }
        }
    }

    /// Reads the setting at `settings`.
    pub fn at(settings: PathBuf) -> Self {
        Self::with_default(settings, default_vault())
    }

    /// Reads the setting at `settings`, with `default` as the vault opened
    /// while no choice is recorded.
    fn with_default(settings: PathBuf, default: Result<PathBuf, String>) -> Self {
        let choice = read(&settings);
        Self {
            settings: Ok(settings),
            default,
            choice: Mutex::new(choice),
            #[cfg(any(windows, test))]
            picking: AtomicBool::new(false),
        }
    }

    /// The vault every gesture opens.
    ///
    /// At the default location, its folder is created first, privately: on a
    /// fresh machine nothing else does before the first vault, and the
    /// creation would be refused for a folder the operator never chose. A
    /// chosen folder is never created — an unplugged medium or a mistyped
    /// choice must stay visible. A default folder that cannot be created is
    /// left absent, and the vault's own check refuses it as
    /// `LocationUnavailable` (fail closed).
    pub fn path(&self) -> Result<PathBuf, String> {
        let choice = self.held();
        let path = resolved(&choice, &self.default)?;
        if matches!(choice, Ok(None)) {
            create_default_folder(&path);
        }
        Ok(path)
    }

    /// [`Self::path`] as a pure read: nothing is created. For a look that must not
    /// leave a folder on a machine that never opened Astra.
    pub fn path_to_look_at(&self) -> Result<PathBuf, String> {
        resolved(&self.held(), &self.default)
    }

    /// Where the vault is, or why that cannot be said, for the window.
    pub fn view(&self) -> VaultLocationView {
        view_of(&self.held(), &self.default)
    }

    /// Records `path` as the vault, once it is an absolute path to a file named
    /// [`VAULT_FILE_NAME`]. A refused path leaves the setting as it was.
    ///
    /// Reached only through [`pick`], which exists on Windows alone.
    #[cfg(any(windows, test))]
    pub fn choose(&self, path: PathBuf) -> Result<VaultLocationView, String> {
        validate(&path)?;
        let settings = self.settings.as_ref().map_err(Clone::clone)?;
        let mut choice = self.lock();
        write(settings, &path)?;
        *choice = Ok(Some(path));
        Ok(view_of(&choice, &self.default))
    }

    /// Takes the place of the one dialog, or refuses when it is taken.
    #[cfg(any(windows, test))]
    pub fn begin_pick(&self) -> Result<PickerGuard<'_>, String> {
        self.picking
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| PickerGuard(&self.picking))
            .map_err(|_| PICKER_ALREADY_OPEN.to_string())
    }

    /// Goes back to the default location by removing the setting.
    pub fn reset(&self) -> Result<VaultLocationView, String> {
        let settings = self.settings.as_ref().map_err(Clone::clone)?;
        let mut choice = self.lock();
        match std::fs::remove_file(settings) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("suppression de {} : {error}", settings.display()));
            }
        }
        *choice = Ok(None);
        Ok(view_of(&choice, &self.default))
    }

    fn held(&self) -> Result<Option<PathBuf>, String> {
        self.lock().clone()
    }

    /// A poisoned lock is recovered: it guards a plain value, rewritten whole.
    fn lock(&self) -> std::sync::MutexGuard<'_, Result<Option<PathBuf>, String>> {
        self.choice.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn default_vault() -> Result<PathBuf, String> {
    astra_operator::store::default_path().map_err(|error| format!("{error:#}"))
}

fn resolved(
    choice: &Result<Option<PathBuf>, String>,
    default: &Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    match choice {
        Ok(Some(path)) => Ok(path.clone()),
        Ok(None) => default.clone(),
        Err(error) => Err(error.clone()),
    }
}

/// Creates the folder of the default vault, private from creation, as the
/// vault store creates the folder it writes in. A failure is only logged: the
/// folder stays absent, which the creation check refuses.
fn create_default_folder(vault_path: &Path) {
    let Some(folder) = vault_path.parent() else {
        return;
    };
    if let Err(error) = aether::private_file::create_private_dir(folder) {
        tracing::warn!(
            folder = %folder.display(),
            %error,
            "dossier du coffre par défaut impossible à créer"
        );
    }
}

fn view_of(
    choice: &Result<Option<PathBuf>, String>,
    default: &Result<PathBuf, String>,
) -> VaultLocationView {
    let (path, error) = match resolved(choice, default) {
        Ok(path) => (Some(path.display().to_string()), None),
        Err(error) => (None, Some(error)),
    };
    VaultLocationView {
        path,
        is_default: matches!(choice, Ok(None)),
        picker_available: cfg!(windows),
        error,
    }
}

/// Absolute, so it does not follow the working directory; named as the
/// tooling names a vault, so a file that is something else is not picked.
fn validate(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "l'emplacement du coffre doit être un chemin absolu, pas {}",
            path.display()
        ));
    }
    if !path
        .file_name()
        .is_some_and(|name| names_a_vault(name, cfg!(windows)))
    {
        return Err(format!(
            "le coffre opérateur se nomme {VAULT_FILE_NAME}, pas {}",
            path.display()
        ));
    }
    Ok(())
}

/// Whether `name` is [`VAULT_FILE_NAME`]: exactly, or regardless of ASCII
/// case where the file system ignores it (Windows, `ignore_case`), so a name
/// the operator typed in another case still names the same file.
fn names_a_vault(name: &std::ffi::OsStr, ignore_case: bool) -> bool {
    if ignore_case {
        name.to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(VAULT_FILE_NAME))
    } else {
        name == VAULT_FILE_NAME
    }
}

/// The choice the setting records: none when there is no setting, an error
/// when there is one that cannot be read or that names no acceptable vault.
fn read(settings: &Path) -> Result<Option<PathBuf>, String> {
    let unreadable = |reason: String| {
        format!(
            "le réglage de l'emplacement du coffre ({}) est illisible : {reason}",
            settings.display()
        )
    };
    let metadata = match std::fs::metadata(settings) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(error.to_string())),
    };
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Err(unreadable(format!("{} octets", metadata.len())));
    }
    let bytes = std::fs::read(settings).map_err(|error| unreadable(error.to_string()))?;
    let parsed: Settings =
        serde_json::from_slice(&bytes).map_err(|error| unreadable(error.to_string()))?;
    validate(&parsed.vault_path).map_err(unreadable)?;
    Ok(Some(parsed.vault_path))
}

/// Replaces the setting atomically: a reader sees the old choice or the new
/// one, never half of either.
#[cfg(any(windows, test))]
fn write(settings: &Path, vault_path: &Path) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(&Settings {
        vault_path: vault_path.to_path_buf(),
    })
    .map_err(|error| format!("écriture du réglage de l'emplacement du coffre : {error}"))?;
    if let Some(parent) = settings.parent() {
        aether::private_file::create_private_dir(parent)
            .map_err(|error| format!("création de {} : {error}", parent.display()))?;
    }
    aether::private_file::write_private_atomic(settings, &bytes)
        .map_err(|error| format!("écriture de {} : {error}", settings.display()))
}

/// `%APPDATA%\helios\orion-operator.json` on Windows,
/// `~/.helios/orion-operator.json` elsewhere: beside the invitation registry.
fn settings_path() -> anyhow::Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(|base| PathBuf::from(base).join("helios"))
            .context("APPDATA n'est pas défini : impossible de situer le réglage du coffre")?
    } else {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".helios"))
            .context("HOME n'est pas défini : impossible de situer le réglage du coffre")?
    };
    Ok(base.join(SETTINGS_FILE_NAME))
}

/// Asks the operator where the vault is, in a save dialog owned by `owner`.
///
/// A save dialog rather than an open one: the vault may not exist yet, and
/// choosing an existing one is the usual case, so the dialog does not ask
/// before «overwriting» it — nothing is written here. `None` when the
/// operator cancels.
///
/// Blocking, and it sets the calling thread's COM apartment: call it from a
/// thread of its own, not from a runtime or pooled worker.
#[cfg(windows)]
pub fn pick(owner: isize, current: &Path) -> Result<Option<PathBuf>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::UI::Controls::Dialogs::{
        CommDlgExtendedError, GetSaveFileNameW, OFN_NOCHANGEDIR, OFN_NOREADONLYRETURN,
        OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };

    /// Balances a successful `CoInitializeEx`, on every return below.
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: only built after `CoInitializeEx` succeeded on this
            // thread, and dropped on it.
            unsafe { CoUninitialize() };
        }
    }

    // The longest path the dialog may return, with its terminating NUL.
    const FILE_BUFFER: usize = 32_768;

    // SAFETY: no pointer is passed; the dialog's shell views want a
    // single-threaded apartment on the thread that shows it.
    let initialized = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    // S_OK and S_FALSE both count and both must be balanced; a failure leaves
    // nothing to undo, and the dialog is still tried without it.
    let _apartment = (initialized >= 0).then_some(Apartment);

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let title = wide("Emplacement du coffre opérateur");
    // Appended when the operator types a name without an extension.
    let extension = wide("json");
    // Pairs of NUL-terminated strings, ended by an empty one.
    let filter: Vec<u16> = "Coffre opérateur (authority-vault.json)\0authority-vault.json\0\0"
        .encode_utf16()
        .collect();
    let directory: Vec<u16> = current
        .parent()
        .map(|parent| parent.as_os_str().encode_wide().collect::<Vec<u16>>())
        .unwrap_or_default()
        .into_iter()
        .chain(std::iter::once(0))
        .collect();
    let mut file = vec![0u16; FILE_BUFFER];
    for (slot, unit) in file.iter_mut().zip(VAULT_FILE_NAME.encode_utf16()) {
        *slot = unit;
    }

    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner as windows_sys::Win32::Foundation::HWND,
        lpstrFilter: filter.as_ptr(),
        lpstrFile: file.as_mut_ptr(),
        nMaxFile: FILE_BUFFER as u32,
        lpstrInitialDir: directory.as_ptr(),
        lpstrTitle: title.as_ptr(),
        lpstrDefExt: extension.as_ptr(),
        // `OFN_NOCHANGEDIR`: without it the dialog leaves this process's
        // working directory in the folder browsed, and a process whose
        // working directory is on a removable medium holds that medium — the
        // one the vault is often chosen on could then not be ejected.
        Flags: OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    // SAFETY: `dialog` and the five buffers it points at are alive for the
    // call; the strings are NUL-terminated, the filter doubly, and `nMaxFile`
    // is the length of `file`. A null owner is allowed.
    let chosen = unsafe { GetSaveFileNameW(&mut dialog) };
    if chosen == 0 {
        // SAFETY: reads the dialog's last error, with no pointer.
        let error = unsafe { CommDlgExtendedError() };
        return if error == 0 {
            Ok(None)
        } else {
            Err(format!(
                "la boîte de choix de l'emplacement du coffre a échoué (code {error:#x})"
            ))
        };
    }
    let length = file
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(file.len());
    Ok(Some(PathBuf::from(OsString::from_wide(&file[..length]))))
}

#[cfg(test)]
mod tests;
