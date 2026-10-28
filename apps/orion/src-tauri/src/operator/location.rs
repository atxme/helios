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
//! default, replaces it.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The only file name a vault is accepted under, the tooling's own.
pub const VAULT_FILE_NAME: &str = "authority-vault.json";

/// Name of the setting, beside the rest of the operator material.
const SETTINGS_FILE_NAME: &str = "orion-operator.json";

/// A setting holds one path: anything longer was not written by Orion.
const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

/// What is written on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    vault_path: PathBuf,
}

/// The vault location this process opens, and the setting it comes from.
///
/// `choice` is what the setting said when it was last read or written: a
/// path, none, or why it could not be read.
pub struct VaultLocation {
    settings: Result<PathBuf, String>,
    choice: Mutex<Result<Option<PathBuf>, String>>,
}

/// What the WebView is shown. A path to display, not one it may send back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultLocationView {
    pub path: String,
    pub is_default: bool,
    pub picker_available: bool,
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
                    choice: Mutex::new(Err(message)),
                }
            }
        }
    }

    /// Reads the setting at `settings`.
    pub fn at(settings: PathBuf) -> Self {
        let choice = read(&settings);
        Self {
            settings: Ok(settings),
            choice: Mutex::new(choice),
        }
    }

    /// The vault every gesture opens.
    pub fn path(&self) -> Result<PathBuf, String> {
        resolved(&self.held())
    }

    pub fn view(&self) -> Result<VaultLocationView, String> {
        view_of(&self.held())
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
        view_of(&choice)
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
        view_of(&choice)
    }

    fn held(&self) -> Result<Option<PathBuf>, String> {
        self.lock().clone()
    }

    /// A poisoned lock is recovered: it guards a plain value, rewritten whole.
    fn lock(&self) -> std::sync::MutexGuard<'_, Result<Option<PathBuf>, String>> {
        self.choice.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn resolved(choice: &Result<Option<PathBuf>, String>) -> Result<PathBuf, String> {
    match choice {
        Ok(Some(path)) => Ok(path.clone()),
        Ok(None) => astra_operator::store::default_path().map_err(|error| format!("{error:#}")),
        Err(error) => Err(error.clone()),
    }
}

fn view_of(choice: &Result<Option<PathBuf>, String>) -> Result<VaultLocationView, String> {
    let path = resolved(choice)?;
    Ok(VaultLocationView {
        path: path.display().to_string(),
        is_default: matches!(choice, Ok(None)),
        picker_available: cfg!(windows),
    })
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
    if path.file_name() != Some(std::ffi::OsStr::new(VAULT_FILE_NAME)) {
        return Err(format!(
            "le coffre opérateur se nomme {VAULT_FILE_NAME}, pas {}",
            path.display()
        ));
    }
    Ok(())
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
/// operator cancels. Blocking: run it off the async runtime.
#[cfg(windows)]
pub fn pick(owner: isize, current: &Path) -> Result<Option<PathBuf>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::UI::Controls::Dialogs::{
        CommDlgExtendedError, GetSaveFileNameW, OFN_NOREADONLYRETURN, OFN_PATHMUSTEXIST,
        OPENFILENAMEW,
    };

    // The longest path the dialog may return, with its terminating NUL.
    const FILE_BUFFER: usize = 32_768;

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let title = wide("Emplacement du coffre opérateur");
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
        Flags: OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN,
        ..Default::default()
    };
    // SAFETY: `dialog` and the four buffers it points at are alive for the
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
