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
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation, TokenPrimary,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, OpenProcess, OpenProcessToken, CREATE_NEW_CONSOLE,
    CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    STARTUPINFOW,
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
    spawn_with_standard_token(
        None,
        format!("powershell.exe -NoExit -Command ssh {target}"),
        "ouverture du terminal",
        &[],
        CREATE_NEW_CONSOLE,
    )?;
    tracing::info!(%target, "terminal SSH ouvert sous le compte standard");
    Ok(())
}

/// Runs the fixed Astra companion as the standard user, in its own console.
///
/// The arguments come from the engine's renewal session; the program does
/// not. Keeping the executable literal at this boundary prevents a WebView or
/// profile value from turning this into a general process launcher.
pub fn spawn_astra_signer(arguments: &[String]) -> Result<(), String> {
    let command = windows_command_line("astra-signer", arguments);
    spawn_with_standard_token(
        None,
        command,
        "lancement du compagnon",
        &[],
        CREATE_NEW_CONSOLE,
    )
    .map(|_| ())
}

/// The user's environment block, with `additions` appended.
///
/// A Windows environment block is a run of NUL-terminated `NAME=VALUE` strings
/// ended by one further NUL. Held alive by the returned vector for the length
/// of the `CreateProcessWithTokenW` call, and zeroed on drop because one of
/// the values it carries is a session token.
struct EnvironmentBlock {
    block: Vec<u16>,
}

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        self.block.iter_mut().for_each(|unit| *unit = 0);
    }
}

fn environment_block(
    token: &Token,
    additions: &[(String, String)],
) -> Result<EnvironmentBlock, String> {
    let mut inherited: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `token` is a live primary token; the pointer is written by the
    // call and released below.
    let created = unsafe { CreateEnvironmentBlock(&mut inherited, token.0, 0) };
    if created == 0 {
        return Err(format!(
            "environnement de l'utilisateur indisponible : {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut block = Vec::new();
    // SAFETY: the block Windows returned is a NUL-separated run of UTF-16
    // strings terminated by an empty one; the walk stops on that terminator.
    unsafe {
        let mut cursor = inherited as *const u16;
        loop {
            let mut length = 0usize;
            while *cursor.add(length) != 0 {
                length += 1;
            }
            if length == 0 {
                break;
            }
            let entry = std::slice::from_raw_parts(cursor, length);
            let text = String::from_utf16_lossy(entry);
            let shadowed = additions.iter().any(|(name, _)| {
                text.get(..name.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
                    && text.as_bytes().get(name.len()) == Some(&b'=')
            });
            if !shadowed {
                block.extend_from_slice(entry);
                block.push(0);
            }
            cursor = cursor.add(length + 1);
        }
        DestroyEnvironmentBlock(inherited);
    }
    for (name, value) in additions {
        block.extend(OsStr::new(&format!("{name}={value}")).encode_wide());
        block.push(0);
    }
    // The block itself ends on an empty string.
    block.push(0);
    Ok(EnvironmentBlock { block })
}

/// Quotes one argument according to the Windows command-line grammar consumed
/// by `CommandLineToArgvW` and Rust/clap. No shell interprets the result.
fn quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
            quoted.push(character);
        }
        backslashes = 0;
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn windows_command_line(program: &str, arguments: &[String]) -> String {
    std::iter::once(program)
        .chain(arguments.iter().map(String::as_str))
        .map(quote_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

fn spawn_with_standard_token(
    application: Option<&Path>,
    command: String,
    action: &str,
    environment: &[(String, String)],
    creation_flags: u32,
) -> Result<u32, String> {
    let token = standard_user_token()?;
    if is_elevated(&token)? {
        return Err(format!(
            "refus : le jeton obtenu est toujours élevé, {action} annulé"
        ));
    }

    let mut command: Vec<u16> = OsStr::new(&command)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let application: Option<Vec<u16>> = application.map(|path| {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    });
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Built only when something is being added. With nothing to add, NULL is
    // the better answer: Windows then builds the block itself from the profile
    // `token` selects, which is what the companion has always relied on.
    let mut block = if environment.is_empty() {
        None
    } else {
        Some(environment_block(&token, environment)?)
    };
    let (environment_pointer, creation_flags) = match block.as_mut() {
        Some(block) => (
            block.block.as_ptr() as *const std::ffi::c_void,
            creation_flags | CREATE_UNICODE_ENVIRONMENT,
        ),
        None => (std::ptr::null(), creation_flags),
    };

    // SAFETY: `command` is NUL-terminated and remains alive for the call;
    // `startup` and `process` are correctly sized initialized structures.
    let created = unsafe {
        CreateProcessWithTokenW(
            token.0,
            LOGON_WITH_PROFILE,
            application
                .as_ref()
                .map_or(std::ptr::null(), |path| path.as_ptr()),
            command.as_mut_ptr(),
            creation_flags,
            // NULL unless something had to be added: Windows then builds the
            // block itself from the standard user's profile selected by
            // `token`. Never Orion's own environment.
            environment_pointer,
            std::ptr::null(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        return Err(format!(
            "{action} impossible : CreateProcessWithTokenW a échoué ({})",
            std::io::Error::last_os_error()
        ));
    }
    let process_id = process.dwProcessId;
    // SAFETY: both handles were returned by the successful call above.
    unsafe {
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    }
    tracing::info!(%action, "processus ouvert sous le compte standard");
    Ok(process_id)
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
