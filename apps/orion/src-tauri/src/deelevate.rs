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
//! Windows already has the right one. When a user elevates through UAC, their
//! elevated token keeps a **linked token**: the filtered, standard-user token
//! of that same session. `TokenLinkedToken` returns it. That is better than
//! anything this code could assemble — lowering the integrity level of our own
//! token, for instance, would leave the Administrators SIDs in place and
//! produce a medium-integrity *admin* token, which is not the same thing at
//! all.
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
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation,
    TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
    TokenElevationTypeLimited, TokenLinkedToken, TokenPrimary, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken, CREATE_NEW_CONSOLE,
    LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
};

/// A token handle closed on drop.
///
/// Not a convenience: the refusal paths below are numerous and early, and a
/// hand-rolled `CloseHandle` on each of them is how one of them ends up
/// leaking a token handle to the user's standard account.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle was produced by OpenProcessToken,
            // GetTokenInformation(TokenLinkedToken) or DuplicateTokenEx, and
            // is closed exactly once — `Token` is neither `Copy` nor `Clone`.
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

/// The standard-user token of the session Orion was elevated from.
///
/// Refuses rather than improvises when there is none. A gateway operator
/// running Orion as SYSTEM, or on a machine with UAC turned off, has no
/// filtered token to fall back to — and the tempting fallback, "spawn with
/// our own token", is exactly the escalation this module exists to prevent.
fn standard_user_token() -> Result<Token, String> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // `TOKEN_DUPLICATE` as well as `TOKEN_QUERY`: the already-limited branch
    // below duplicates this very handle, and `DuplicateTokenEx` refuses a
    // source opened for querying alone.
    // SAFETY: writes one handle into `raw`; the pseudo-handle from
    // GetCurrentProcess needs no closing.
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) };
    if opened == 0 {
        return Err(format!(
            "lecture du jeton du processus impossible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let own = Token(raw);

    match elevation_type(&own)? {
        // Elevated through UAC: the filtered token is right there.
        TokenElevationTypeFull => {}
        // Already a standard user. Orion should not reach this — its manifest
        // requires elevation — but if it ever does, its own token is already
        // the one we want, and duplicating it changes nothing.
        TokenElevationTypeLimited => return duplicate_primary(&own),
        // UAC disabled, built-in Administrator, or a service running as
        // SYSTEM. No linked token exists, and none can be synthesised.
        TokenElevationTypeDefault => {
            return Err(
                "aucun jeton d'utilisateur standard disponible sur cette machine (UAC désactivé, \
                 compte Administrateur intégré, ou exécution en tant que service). Le terminal \
                 serait élevé : il n'est pas ouvert. Copier la commande et l'ouvrir soi-même."
                    .into(),
            )
        }
        other => return Err(format!("type d'élévation inattendu ({other})")),
    }

    let mut linked: HANDLE = std::ptr::null_mut();
    let mut returned = 0u32;
    // SAFETY: `TokenLinkedToken` writes exactly one HANDLE-sized value.
    let ok = unsafe {
        GetTokenInformation(
            own.0,
            TokenLinkedToken,
            (&mut linked as *mut HANDLE).cast(),
            std::mem::size_of::<HANDLE>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(format!(
            "jeton d'utilisateur standard illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let linked = Token(linked);
    // `TokenLinkedToken` yields an impersonation token; `CreateProcessWithTokenW`
    // demands a primary one.
    duplicate_primary(&linked)
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

fn elevation_type(token: &Token) -> Result<TOKEN_ELEVATION_TYPE, String> {
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut returned = 0u32;
    // SAFETY: `TokenElevationType` writes exactly one i32.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(format!(
            "type d'élévation illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(kind)
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
