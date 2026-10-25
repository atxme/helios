//! Launching a child process from Orion's UI, and refusing to while the UI
//! runs elevated.
//!
//! # Why this module exists
//!
//! The UI runs at medium integrity, with a manifest asking for `asInvoker`:
//! WireGuard-NT is driven by the elevated engine, not by the window. A child
//! started the ordinary way then inherits a non-elevated token, so a terminal
//! or a companion cannot become an Administrator process by inheritance alone.
//! The UI can still be started elevated (from an elevated shell, say), and
//! then the refusal below is what keeps the terminal and the companion closed.
//!
//! # The post-condition is the actual safety property
//!
//! Inheritance is not what keeps a child unprivileged; the refusal is. Each
//! launch asks Windows, immediately before it starts, whether the UI's own
//! token is elevated, and starts nothing if it is or if the answer cannot be
//! read. The check is not trusted on the strength of the manifest having
//! been written as intended: it is what is trusted.
//!
//! # Limite connue
//!
//! The Windows half is **unexercised in this repository**: WSL2 has no MSVC
//! toolchain, so it compiles nowhere here. It must be tried on Windows before
//! being relied upon — see `docs/testing/TESTING.md`. The refusal paths are
//! what to test first, not the happy one.

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, CREATE_NEW_CONSOLE,
};

/// Whether a child may be started, given whether the UI's own token is elevated.
#[cfg(any(windows, test))]
pub(crate) fn should_launch(elevated: bool) -> bool {
    !elevated
}

/// A handle closed on drop — here, the UI's own token.
///
/// Not a convenience: the refusal paths are early, and a hand-rolled
/// `CloseHandle` on each of them is how one of them ends up leaking a token.
#[cfg(windows)]
struct Token(HANDLE);

#[cfg(windows)]
impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle was produced by OpenProcessToken, and is
            // closed exactly once — `Token` is neither `Copy` nor `Clone`.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Whether this process's own token is elevated. An unreadable token is an error,
/// never "not elevated": the engine refuses to start on it.
#[cfg(windows)]
pub fn current_token_is_elevated() -> Result<bool, String> {
    let token = own_token()?;
    is_elevated(&token)
}

/// Refuses to launch anything while the UI's own token is elevated.
#[cfg(windows)]
pub fn refuse_if_elevated() -> Result<(), String> {
    let elevated = current_token_is_elevated()?;
    if !should_launch(elevated) {
        return Err("Orion s'exécute en administrateur : lancement refusé.".into());
    }
    Ok(())
}

/// Outside Windows there is no UAC token to refuse, so nothing is refused.
#[cfg(not(windows))]
pub fn refuse_if_elevated() -> Result<(), String> {
    Ok(())
}

/// Opens `powershell.exe -NoExit -Command ssh <target>` in a new console.
///
/// `target` must already have passed
/// [`orion_core::profile_import::validate_ssh_target`]: it is placed on a
/// command line, and the allow-list grammar is what makes that inert.
#[cfg(windows)]
pub fn spawn_ssh_terminal(target: &str) -> Result<(), String> {
    refuse_if_elevated()?;
    let command = format!("ssh {target}");
    let _child = std::process::Command::new("powershell.exe")
        .args(["-NoExit", "-Command", command.as_str()])
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|error| format!("ouverture du terminal impossible : {error}"))?;
    tracing::info!(%target, "terminal SSH ouvert");
    Ok(())
}

/// Outside Windows no terminal is opened, and the refusal says so.
///
/// # Limite connue
///
/// No terminal is chosen for the other platforms. What would unblock it is
/// naming one for each of them.
#[cfg(not(windows))]
pub fn spawn_ssh_terminal(_target: &str) -> Result<(), String> {
    refuse_if_elevated()?;
    Err("l'ouverture d'un terminal SSH n'est disponible que sur Windows".into())
}

/// Starts the fixed Astra companion, in its own console.
///
/// The arguments come from the engine's renewal session; the program does
/// not. Keeping the executable literal at this boundary prevents a WebView or
/// profile value from turning this into a general process launcher. The child
/// is not waited for: Windows keeps no zombie.
#[cfg(windows)]
pub fn spawn_astra_signer(arguments: &[String]) -> Result<(), String> {
    refuse_if_elevated()?;
    let _child = std::process::Command::new("astra-signer")
        .args(arguments)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|error| format!("lancement du compagnon impossible : {error}"))?;
    Ok(())
}

/// The UI's own primary token, read from the current process.
#[cfg(windows)]
fn own_token() -> Result<Token, String> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: writes one handle into `raw`; the pseudo-handle returned by
    // GetCurrentProcess needs no closing.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
    if opened == 0 {
        return Err(format!(
            "lecture du jeton de l'IHM impossible, lancement refusé ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Token(raw))
}

/// Asks Windows, rather than deducing, whether this token confers elevation.
#[cfg(windows)]
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
        // unexpected failure from becoming an elevated launch.
        return Err(format!(
            "élévation du jeton invérifiable, lancement refusé ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}
