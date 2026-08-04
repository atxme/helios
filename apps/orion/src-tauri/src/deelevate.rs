//! Launching a process **below** Orion's own privilege level.
//!
//! # Why this module exists
//!
//! Orion runs elevated, always and by design: WireGuard-NT cannot be loaded
//! otherwise, and the shipped manifest asks for `requireAdministrator`. A
//! child process inherits its parent's token, so a terminal spawned the
//! ordinary way would be an **Administrator** terminal — an elevated shell
//! handed out from one click, with no UAC prompt of its own, to whoever can
//! reach the window or the command behind it.
//!
//! # Why a token, and not a thread
//!
//! Impersonating on a thread does not help, and believing otherwise is the
//! trap this module is written against: `CreateProcess` builds the child from
//! the **process** token, not from the calling thread's impersonation token.
//! A "de-elevated" launcher written that way looks right, runs, and produces
//! an Administrator shell anyway. The privilege level of a child is decided by
//! the token handed to `CreateProcessWithTokenW`, and by nothing else.
//!
//! # Which token
//!
//! The one `explorer.exe` already has. The desktop shell runs as the
//! interactive user at medium integrity, so its process token *is* the
//! standard-user token — and duplicating another process's **primary** token
//! yields a primary token, which is what `CreateProcessWithTokenW` demands.
//!
//! The obvious-looking route, `TokenLinkedToken` on our own elevated token,
//! does not survive contact: without `SeTcbPrivilege` Windows hands back an
//! *identification*-level impersonation token, and duplicating that into a
//! primary token fails with `ERROR_BAD_IMPERSONATION_LEVEL` (1346). That was
//! this module's first shape, and the error is what replaced it.
//!
//! # The post-condition is the actual safety property
//!
//! Every step below can fail in ways that are easy to miss, and the failure
//! mode that matters — spawning elevated — is invisible. So the token is
//! interrogated one last time, immediately before use: if Windows still says
//! it is elevated, nothing is launched. No step of this module is trusted on
//! the strength of having been written carefully; the check at the end is what
//! is trusted.
//!
//! # Limite connue
//!
//! Target-only, and **unexercised in this repository**: WSL2 has no MSVC
//! toolchain, so this file compiles nowhere here. It must be tried on Windows
//! before being relied upon — see [`docs/testing/TESTING.md`]. The refusal
//! paths are what to test first, not the happy one.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation, TokenPrimary,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, OpenProcess, OpenProcessToken, CREATE_NEW_CONSOLE, LOGON_WITH_PROFILE,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

/// A handle closed on drop — a token, or the shell process it came from.
///
/// Not a convenience: the refusal paths below are numerous and early, and a
/// hand-rolled `CloseHandle` on each of them is how one of them ends up
/// leaking a token handle to the user's standard account.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle was produced by OpenProcess,
            // OpenProcessToken or DuplicateTokenEx, and is closed exactly
            // once — `Token` is neither `Copy` nor `Clone`.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Runs `powershell.exe -NoExit -Command ssh <target>` as the standard user.
///
/// `target` must already have passed
/// [`orion_core::profile_import::validate_ssh_target`]: it is placed on a
/// command line, and the allow-list grammar is what makes that inert.
pub fn spawn_ssh_terminal(target: &str) -> Result<(), String> {
    let token = standard_user_token()?;

    // The last gate, and the one that counts. Everything above can be wrong
    // in a way that still returns a handle; only Windows can say what that
    // handle actually confers.
    if is_elevated(&token)? {
        return Err(
            "refus : le jeton obtenu est toujours élevé, le terminal ne sera pas ouvert".into(),
        );
    }

    let mut command: Vec<u16> =
        OsStr::new(&format!("powershell.exe -NoExit -Command ssh {target}"))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: `command` is NUL-terminated and stays alive for the call;
    // `startup` and `process` are correctly sized zeroed structures.
    let created = unsafe {
        CreateProcessWithTokenW(
            token.0,
            LOGON_WITH_PROFILE,
            std::ptr::null(),
            command.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            // NULL rather than our own block: with a null environment,
            // `CreateProcessWithTokenW` builds one from the profile of the
            // user the token designates — which is the standard user, not the
            // elevated context this process runs in.
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        return Err(format!(
            "ouverture du terminal impossible : CreateProcessWithTokenW a échoué ({})",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: both handles were produced by the successful call above.
    unsafe {
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    }
    tracing::info!(%target, "terminal SSH ouvert sous le compte standard");
    Ok(())
}

/// The interactive user's token, borrowed from the desktop shell.
///
/// Refuses rather than improvises when there is no shell: a service session,
/// or a machine where Explorer is not running, has no standard-user process to
/// borrow from — and the tempting fallback, "use our own token", is exactly
/// the escalation this module exists to prevent.
fn standard_user_token() -> Result<Token, String> {
    // SAFETY: returns the desktop shell window of this session, or null.
    let shell = unsafe { GetShellWindow() };
    if shell.is_null() {
        return Err("aucun shell de bureau : le terminal serait élevé, il n'est pas ouvert".into());
    }
    let mut pid = 0u32;
    // SAFETY: `shell` is a valid window handle; writes one u32.
    unsafe { GetWindowThreadProcessId(shell, &mut pid) };
    if pid == 0 {
        return Err("processus du shell introuvable, ouverture refusée".into());
    }

    // `PROCESS_QUERY_INFORMATION`, not its `_LIMITED_` cousin: the latter is
    // enough for most process queries and is **not** what `OpenProcessToken`
    // documents as its requirement.
    // SAFETY: opens the shell process; the handle is closed by `Token`.
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "ouverture du processus du shell impossible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let process = Token(process);

    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: writes one handle into `raw`.
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw) };
    if opened == 0 {
        return Err(format!(
            "lecture du jeton du shell impossible ({})",
            std::io::Error::last_os_error()
        ));
    }
    duplicate_primary(&Token(raw))
}

/// Duplicates a token into the primary token a process creation requires.
fn duplicate_primary(token: &Token) -> Result<Token, String> {
    let mut primary: HANDLE = std::ptr::null_mut();
    // SAFETY: writes one handle into `primary`.
    let ok = unsafe {
        DuplicateTokenEx(
            token.0,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    if ok == 0 {
        return Err(format!(
            "duplication du jeton impossible ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Token(primary))
}

/// Asks Windows, rather than deducing, whether this token confers elevation.
fn is_elevated(token: &Token) -> Result<bool, String> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: `TokenElevation` writes exactly one TOKEN_ELEVATION.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        // Unreadable is not "not elevated". Refusing here is what keeps an
        // unexpected failure from becoming an elevated terminal.
        return Err(format!(
            "élévation du jeton invérifiable, ouverture refusée ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}
