//! Launch of the elevated engine from the UI, and the end of the UI with it.
//!
//! The UI runs at medium integrity. It starts `orion.exe --engine ...` with
//! the `runas` verb, so Windows asks for administrator consent, then connects
//! to the pipe the engine creates. The engine must be the process the UI
//! started: that is checked before anything is sent. The Win32 calls are thin
//! and `cfg(windows)`; the decisions live here and in `orion_engine`, tested
//! under Linux.

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use orion_core::ClientEvent;
#[cfg(windows)]
use orion_engine::client::{connect, EngineClient};
#[cfg(windows)]
use orion_engine::lifecycle::{EngineArgs, CONNECT_TIMEOUT};
#[cfg(windows)]
use orion_engine::pipe::{connect_client, observe_process, pipe_name, server_process_id};
#[cfg(windows)]
use orion_engine::session::SessionToken;
#[cfg(windows)]
use orion_engine::EngineCommand;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(windows)]
use tokio::sync::mpsc;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, WAIT_OBJECT_0};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetProcessId, WaitForSingleObject, INFINITE};
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, SW_HIDE};

#[cfg(any(windows, test))]
use zeroize::Zeroizing;

/// Refusal of an engine argument that cannot be written on a command line.
#[cfg(any(windows, test))]
const ARGUMENT_REFUSED: &str = "argument du moteur non transmissible";

/// Message shown when the person refuses the administrator consent.
#[cfg(any(windows, test))]
pub(crate) const UAC_REFUSED: &str =
    "Orion a besoin de l'autorisation administrateur pour monter le tunnel.";

/// Message shown when the engine stops while the UI is running.
pub(crate) const ENGINE_STOPPED: &str = "Le moteur d'Orion s'est arrêté : Orion va se fermer.";

/// `ERROR_CANCELLED`: the person refused the elevation prompt.
#[cfg(any(windows, test))]
const ERROR_CANCELLED: i32 = 1223;

/// Joins the engine arguments into one command line.
///
/// Refused, without repeating their content, when an argument is empty or
/// holds a blank, a quote or a control character. The arguments `to_args`
/// produces never hold one, so nothing is quoted.
#[cfg(any(windows, test))]
pub(crate) fn engine_parameters(args: &[String]) -> Result<Zeroizing<String>, String> {
    let refused = args.iter().any(|arg| {
        arg.is_empty()
            || arg.chars().any(|character| {
                character.is_whitespace() || character == '"' || character.is_control()
            })
    });
    if refused {
        return Err(ARGUMENT_REFUSED.into());
    }
    Ok(Zeroizing::new(args.join(" ")))
}

/// The message for a failed launch, given the Win32 error code.
#[cfg(any(windows, test))]
pub(crate) fn launch_failure(code: i32) -> String {
    if code == ERROR_CANCELLED {
        return UAC_REFUSED.to_owned();
    }
    format!("Le moteur d'Orion n'a pas pu démarrer (erreur {code}).")
}

/// Shows a fatal message to the person, and logs it.
pub(crate) fn fatal(message: &str) {
    tracing::error!(%message, "moteur d'Orion : arrêt de l'IHM");
    show_error_box(message);
}

/// The engine's process, as the UI holds it: the handle closes on drop.
#[cfg(windows)]
pub(crate) struct EngineProcess {
    handle: OwnedHandle,
    pid: u32,
}

#[cfg(windows)]
impl EngineProcess {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Blocks the calling thread until the engine process exits.
    pub(crate) fn wait_for_exit(&self) {
        // SAFETY: the handle stays open until `self` drops, and INFINITE
        // waits without touching memory.
        unsafe { WaitForSingleObject(self.raw(), INFINITE) };
    }

    /// Waits at most `timeout` for the engine process to exit.
    ///
    /// Returns whether it has exited by then.
    pub(crate) fn wait_for_exit_within(&self, timeout: Duration) -> bool {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: as in `wait_for_exit`; the timeout bounds the wait.
        unsafe { WaitForSingleObject(self.raw(), milliseconds) == WAIT_OBJECT_0 }
    }

    /// Whether the engine process has already exited. Never waits.
    pub(crate) fn has_exited(&self) -> bool {
        // SAFETY: as in `wait_for_exit`; a zero timeout only polls.
        unsafe { WaitForSingleObject(self.raw(), 0) == WAIT_OBJECT_0 }
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

/// The engine's process is waited on from another thread, and shared.
#[cfg(windows)]
const _: fn() = assert_send_and_sync::<EngineProcess>;

#[cfg(windows)]
fn assert_send_and_sync<T: Send + Sync>() {}

/// Starts the engine elevated, connects to it, and checks the session is open.
///
/// Returns the client, its events, and the engine's process. Neither the
/// token nor the pipe name is ever formatted into a message.
#[cfg(windows)]
pub(crate) async fn start(
) -> Result<(EngineClient, mpsc::Receiver<ClientEvent>, EngineProcess), String> {
    let ui_pid = std::process::id();
    let nonce = aether::random::secret_bytes::<16>()
        .map_err(|error| format!("tirage du nom du tube : {error}"))?;
    let name = Zeroizing::new(pipe_name(ui_pid, &nonce));
    let token = SessionToken::generate()?;
    let ui_created_at = observe_process(ui_pid)?.created_at;
    // The arguments hold the token: erased as soon as they are joined.
    let args = Zeroizing::new(
        EngineArgs {
            pipe: name.as_str().to_owned(),
            ui_pid,
            ui_created_at,
            token: SessionToken::parse(token.as_str())?,
        }
        .to_args(),
    );
    let parameters = engine_parameters(&args)?;
    drop(args);

    let process = launch(&parameters)?;
    let stream = wait_for_pipe(&name, &process).await?;
    if server_process_id(&stream)? != process.pid() {
        return Err("le canal n'est pas servi par le moteur lancé par Orion".into());
    }
    let (client, events) = connect(stream, &token).await?;
    // The engine answers nothing to the hello itself: this call is what
    // proves it was accepted.
    client.call(EngineCommand::GetState).await?;
    Ok((client, events, process))
}

/// Starts `orion.exe --engine <parameters>` elevated, hidden, and not waited for.
#[cfg(windows)]
fn launch(parameters: &str) -> Result<EngineProcess, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("exécutable d'Orion introuvable ({error})"))?;
    let verb = wide("runas");
    let file: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // UTF-16 never has more units than UTF-8 has bytes: the buffer is sized
    // once, so growing it never leaves a copy of the parameters behind.
    let mut arguments: Zeroizing<Vec<u16>> =
        Zeroizing::new(Vec::with_capacity(parameters.len() + 1));
    arguments.extend(parameters.encode_utf16());
    arguments.push(0);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: `info` and the three buffers it points at are alive for the
    // call; every one is NUL-terminated.
    let started = unsafe { ShellExecuteExW(&mut info) };
    if started == 0 {
        // SAFETY: GetLastError reads the thread's last error, with no pointer.
        return Err(launch_failure(unsafe { GetLastError() } as i32));
    }
    if info.hProcess.is_null() {
        return Err(launch_failure(0));
    }
    // SAFETY: with SEE_MASK_NOCLOSEPROCESS, the handle is ours to close, once.
    // It is owned from here on, so every return below closes it.
    let handle = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // SAFETY: the handle is open until `handle` drops.
    let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
    if pid == 0 {
        // SAFETY: GetLastError reads the thread's last error, with no pointer.
        return Err(launch_failure(unsafe { GetLastError() } as i32));
    }
    Ok(EngineProcess { handle, pid })
}

/// Opens the engine's pipe, retrying until it exists and is free.
///
/// Stops early when the engine has already exited, and after
/// [`CONNECT_TIMEOUT`]. Any failure of the open is retried: the open's error
/// does not expose the Win32 code, and the deadline bounds the wait.
#[cfg(windows)]
async fn wait_for_pipe(name: &str, process: &EngineProcess) -> Result<NamedPipeClient, String> {
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        if let Ok(stream) = connect_client(name) {
            return Ok(stream);
        }
        if process.has_exited() {
            return Err("Le moteur d'Orion s'est arrêté avant de répondre.".into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Le moteur d'Orion ne répond pas.".into());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Pause between two attempts to open the pipe.
#[cfg(windows)]
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Shows the message in a modal error box, owned by no window.
#[cfg(windows)]
fn show_error_box(message: &str) {
    let text = wide(message);
    let caption = wide("Orion");
    // SAFETY: both buffers are NUL-terminated and alive for the call; a null
    // owner window is allowed.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

/// Outside Windows there is no engine process, and the message goes to stderr.
#[cfg(not(windows))]
fn show_error_box(message: &str) {
    eprintln!("{message}");
}

/// A NUL-terminated UTF-16 copy of `text`, for a Win32 call.
#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orion_engine::lifecycle::EngineArgs;
    use orion_engine::session::SessionToken;

    fn engine_args() -> EngineArgs {
        EngineArgs {
            pipe: r"\\.\pipe\orion-engine-42-00ff".to_owned(),
            ui_pid: 42,
            ui_created_at: 133_500_000_000_000_000,
            token: SessionToken::parse(&"ab".repeat(32)).expect("well-formed token"),
        }
    }

    #[test]
    fn parameters_join_the_engine_arguments() {
        let args = engine_args().to_args();
        let joined = engine_parameters(&args).expect("engine arguments are transmissible");
        let split: Vec<String> = joined.split(' ').map(str::to_owned).collect();
        let parsed = EngineArgs::parse(&split)
            .expect("the split arguments parse")
            .expect("engine mode");
        assert_eq!(parsed.to_args(), args);
    }

    #[test]
    fn an_argument_with_a_space_is_refused() {
        let args = vec!["--pipe".to_owned(), "two words".to_owned()];
        assert!(engine_parameters(&args).is_err());
    }

    #[test]
    fn an_empty_argument_is_refused() {
        let args = vec!["--token".to_owned(), String::new()];
        assert!(engine_parameters(&args).is_err());
    }

    #[test]
    fn a_quote_is_refused() {
        let args = vec!["--pipe\"x".to_owned()];
        assert!(engine_parameters(&args).is_err());
    }

    #[test]
    fn a_control_character_is_refused() {
        let args = vec!["--pipe\tx".to_owned()];
        assert!(engine_parameters(&args).is_err());
    }

    #[test]
    fn the_refusal_names_no_argument() {
        let secret = "s3cr3t-token-value with space";
        let args = vec![secret.to_owned()];
        let message = engine_parameters(&args).expect_err("refused");
        assert_eq!(message, "argument du moteur non transmissible");
        assert!(!message.contains("s3cr3t"));
    }

    #[test]
    fn a_cancelled_elevation_reads_as_the_uac_refusal() {
        assert_eq!(launch_failure(1223), UAC_REFUSED);
    }

    #[test]
    fn another_launch_failure_names_its_code() {
        assert!(launch_failure(2).contains("erreur 2"));
    }
}
