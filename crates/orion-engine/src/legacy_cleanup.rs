//! Runs the cleanup of a legacy vault under the identity of the user who owns
//! it (F11, task 12).
//!
//! The engine runs elevated, and the per-user folder it cleans is writable by
//! the unelevated programs of the same account. A removal made with the
//! engine's own rights could be steered, through a junction swapped in during
//! the run, onto a folder the user does not own. So the removal runs under the
//! user's identity instead.
//!
//! The token used is a duplicate of the UI process's own token, at the
//! impersonation level. The linked token UAC keeps beside an elevated one is
//! not used: without `SeTcbPrivilege` it is an identification token, and no
//! file can be opened under it. Before use, the token must belong to the user
//! and must not be elevated (see [`may_impersonate`]).

#[cfg(windows)]
use orion_core::vault::relocation::LegacyCleanup;

#[cfg(windows)]
use std::io;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, RevertToSelf, SecurityImpersonation, TokenElevation,
    TokenImpersonation, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, SetThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Whether a token may be impersonated for the cleanup: it belongs to the user,
/// and it is not elevated. An elevated token is never used, whoever owns it.
pub fn may_impersonate(token_sid: &str, user_sid: &str, elevated: bool) -> bool {
    !elevated && token_sid == user_sid
}

/// Why the cleanup did not run to the end.
#[derive(Debug)]
pub enum CleanupError {
    /// The user's identity could not be taken on, so nothing was removed.
    Unavailable(String),
    /// The thread could not give its own identity back. The engine must not go
    /// on under the user's identity.
    RevertFailed(String),
}

/// Runs `cleanup` under a duplicate of the UI process's token, and returns how
/// many entries it removed.
///
/// `ui_pid` is the UI process, whose token belongs to the user. The token is
/// checked before use: its user must be `user_sid`, and it must not be elevated.
/// Nothing is removed unless the impersonation is in place. The impersonation
/// is undone on every path, and an undo that fails is reported, never ignored.
#[cfg(windows)]
pub fn run_as_user(
    cleanup: LegacyCleanup,
    ui_pid: u32,
    user_sid: &str,
) -> Result<usize, CleanupError> {
    let process = OwnedHandle(open_process(ui_pid).map_err(CleanupError::Unavailable)?);
    let token = process_token(&process).map_err(CleanupError::Unavailable)?;
    let token_sid =
        crate::pipe::token_user_sid(token.0, "de l'IHM").map_err(CleanupError::Unavailable)?;
    let elevated = token_is_elevated(token.0).map_err(CleanupError::Unavailable)?;
    if !may_impersonate(&token_sid, user_sid, elevated) {
        return Err(CleanupError::Unavailable(if elevated {
            "jeton de l'IHM élevé".to_string()
        } else {
            "jeton de l'IHM d'un autre compte".to_string()
        }));
    }
    let duplicate = duplicate_for_impersonation(token.0).map_err(CleanupError::Unavailable)?;
    // SAFETY: `duplicate` stays open until the end of this function, and
    // SetThreadToken changes the token of the calling thread only. The thread
    // is returned to its own identity by `Impersonation`, on every path.
    if unsafe { SetThreadToken(std::ptr::null_mut(), duplicate.0) } == 0 {
        return Err(CleanupError::Unavailable(format!(
            "usurpation refusée ({})",
            io::Error::last_os_error()
        )));
    }
    let impersonation = Impersonation { reverted: false };
    let removed = cleanup.run();
    impersonation.revert().map(|()| removed)
}

/// The identity of the calling thread while the user's token is in use.
///
/// Dropping it without [`Self::revert`] still gives the thread back its own
/// identity, so a panic inside the cleanup cannot leave it impersonating.
#[cfg(windows)]
struct Impersonation {
    reverted: bool,
}

#[cfg(windows)]
impl Impersonation {
    /// Gives the thread back its own identity, and reports a failure.
    fn revert(mut self) -> Result<(), CleanupError> {
        // SAFETY: RevertToSelf takes no argument. It restores the token of the
        // calling thread, which SetThreadToken replaced above.
        let reverted = unsafe { RevertToSelf() } != 0;
        self.reverted = true;
        if reverted {
            Ok(())
        } else {
            Err(CleanupError::RevertFailed(
                io::Error::last_os_error().to_string(),
            ))
        }
    }
}

#[cfg(windows)]
impl Drop for Impersonation {
    fn drop(&mut self) {
        if !self.reverted {
            // SAFETY: as in `revert`. A failure here has no caller to report
            // to; this path runs only when the cleanup panics.
            unsafe { RevertToSelf() };
        }
    }
}

/// A handle closed on drop.
#[cfg(windows)]
struct OwnedHandle(HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by a Win32 call that opened it,
            // and is closed exactly once, here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// A handle to the process with the given id, for reading its token.
#[cfg(windows)]
fn open_process(pid: u32) -> Result<HANDLE, String> {
    // SAFETY: OpenProcess takes no pointer; a null result is checked below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(format!(
            "processus de l'IHM {pid} inaccessible ({})",
            io::Error::last_os_error()
        ));
    }
    Ok(raw)
}

/// The token of `process`, opened for reading and for duplication.
#[cfg(windows)]
fn process_token(process: &OwnedHandle) -> Result<OwnedHandle, String> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid handle for the call. On success `raw`
    // receives a token handle, which the returned `OwnedHandle` closes.
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) };
    if opened == 0 {
        return Err(format!(
            "jeton de l'IHM illisible ({})",
            io::Error::last_os_error()
        ));
    }
    Ok(OwnedHandle(raw))
}

/// Whether `token` is an elevated token.
#[cfg(windows)]
fn token_is_elevated(token: HANDLE) -> Result<bool, String> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the class TokenElevation writes one TOKEN_ELEVATION, and the length
    // passed is its size, so the write stays inside `elevation`.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if read == 0 {
        return Err(format!(
            "élévation de l'IHM illisible ({})",
            io::Error::last_os_error()
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// A copy of `token` that may be set on a thread: impersonation level, and no
/// more access than the removal needs.
#[cfg(windows)]
fn duplicate_for_impersonation(token: HANDLE) -> Result<OwnedHandle, String> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is a valid token handle for the call, and `raw` receives
    // a handle that the returned `OwnedHandle` closes.
    let duplicated = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw,
        )
    };
    if duplicated == 0 {
        return Err(format!(
            "copie du jeton de l'IHM refusée ({})",
            io::Error::last_os_error()
        ));
    }
    Ok(OwnedHandle(raw))
}

#[cfg(test)]
mod tests;
