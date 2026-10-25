//! Runs the cleanup of a legacy vault under the identity of the user who owns
//! it (F11, task 12).
//!
//! The engine runs elevated, and the per-user folder it cleans is writable by
//! the unelevated programs of the same account. A removal made with the
//! engine's own rights could be steered, through a junction swapped in during
//! the run, onto a folder the user does not own. So the removal runs on the
//! user's linked token instead: the limited token UAC keeps beside an elevated
//! one. Whatever it removes, the user could already remove.

use std::ffi::c_void;
use std::io;

use orion_core::vault::relocation::LegacyCleanup;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, TokenLinkedToken,
    TOKEN_LINKED_TOKEN, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Why the cleanup did not run to the end.
#[derive(Debug)]
pub enum CleanupError {
    /// The user's identity could not be taken on, so nothing was removed.
    Unavailable(String),
    /// The thread could not give its own identity back. The engine must not go
    /// on under the user's identity.
    RevertFailed(String),
}

/// Runs `cleanup` under the user's linked token, and returns how many entries
/// it removed.
///
/// Nothing is removed unless the impersonation is in place. The impersonation
/// is undone on every path, and an undo that fails is reported, never ignored.
pub fn run_as_user(cleanup: LegacyCleanup) -> Result<usize, CleanupError> {
    let linked = linked_token().map_err(CleanupError::Unavailable)?;
    // SAFETY: `linked` is a token handle that stays open until the end of this
    // function. ImpersonateLoggedOnUser changes the identity of the calling
    // thread only, and the thread is returned to its own identity below.
    if unsafe { ImpersonateLoggedOnUser(linked.0) } == 0 {
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
struct Impersonation {
    reverted: bool,
}

impl Impersonation {
    /// Gives the thread back its own identity, and reports a failure.
    fn revert(mut self) -> Result<(), CleanupError> {
        // SAFETY: RevertToSelf takes no argument. It restores the token of the
        // calling thread, which ImpersonateLoggedOnUser replaced above.
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

impl Drop for Impersonation {
    fn drop(&mut self) {
        if !self.reverted {
            // SAFETY: as in `revert`. A failure here has no caller to report
            // to; `run_as_user` only reaches this path when it panics.
            unsafe { RevertToSelf() };
        }
    }
}

/// A handle closed on drop.
struct OwnedToken(HANDLE);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by OpenProcessToken or by
            // GetTokenInformation, and is closed exactly once, here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// The linked token of this process: the limited token of the same account.
/// Absent when the process has none, which is the case without UAC.
fn linked_token() -> Result<OwnedToken, String> {
    let mut process_token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
    // On success `process_token` receives a handle that `OwnedToken` closes.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process_token) };
    if opened == 0 {
        return Err(format!(
            "jeton du moteur illisible ({})",
            io::Error::last_os_error()
        ));
    }
    let process_token = OwnedToken(process_token);

    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: std::ptr::null_mut(),
    };
    let mut returned = 0u32;
    // SAFETY: the class TokenLinkedToken writes a TOKEN_LINKED_TOKEN, and the
    // length passed is the size of that structure, so the write stays inside
    // `linked`. The handle it receives is owned by `OwnedToken` below.
    let read = unsafe {
        GetTokenInformation(
            process_token.0,
            TokenLinkedToken,
            (&mut linked as *mut TOKEN_LINKED_TOKEN).cast::<c_void>(),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut returned,
        )
    };
    if read == 0 {
        return Err(format!(
            "jeton lié indisponible ({})",
            io::Error::last_os_error()
        ));
    }
    let linked = OwnedToken(linked.LinkedToken);
    if linked.0.is_null() {
        return Err("jeton lié absent".to_string());
    }
    Ok(linked)
}
