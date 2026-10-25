//! Engine mode: `orion.exe --engine ...` runs the elevated engine with no window.
//!
//! The engine serves exactly one UI over its named pipe, the one that launched
//! it, and tears everything down at any exit: a refused client, a lost parent,
//! a requested shutdown. It creates no window and starts no Tauri runtime. The
//! Win32 calls are thin and `cfg(windows)`; the decisions live in
//! `orion_engine::lifecycle` and `orion_engine::pipe`, tested under Linux.

#[cfg(any(windows, test))]
use std::path::{Path, PathBuf};

use orion_engine::lifecycle::EngineArgs;

#[cfg(not(windows))]
use orion_engine::lifecycle::BAD_ARGUMENTS;

#[cfg(windows)]
use std::fmt::Display;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use orion_core::default_backend;
#[cfg(windows)]
use orion_core::protected_root::EnginePaths;
#[cfg(windows)]
use orion_engine::lifecycle::{
    exit_code, on_event, parent_matches, Action, LifecycleEvent, CONNECT_TIMEOUT,
};
#[cfg(windows)]
use orion_engine::pipe::{
    create_server, expected_from_launcher, observe_client, observe_process, process_user_sid,
    verify_client, ExpectedClient,
};
#[cfg(windows)]
use orion_engine::serve::{serve, Engine};
#[cfg(windows)]
use orion_engine::service::EngineService;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::{
    AddDllDirectory, SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_USER_DIRS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

/// Exit code for a start-up failure that is not a session event.
#[cfg(windows)]
const STARTUP_FAILED: i32 = 1;

/// Runs the engine until its session ends, and returns the process exit code.
#[cfg(windows)]
pub fn run(args: EngineArgs) -> i32 {
    // SAFETY: a process-wide search policy, with no pointer argument. It comes
    // first, before anything in this function can load a DLL.
    if unsafe {
        SetDefaultDllDirectories(
            LOAD_LIBRARY_SEARCH_SYSTEM32
                | LOAD_LIBRARY_SEARCH_APPLICATION_DIR
                | LOAD_LIBRARY_SEARCH_USER_DIRS,
        )
    } == 0
    {
        eprintln!("le moteur d'Orion ne peut pas restreindre la recherche de DLL : arrêt.");
        return STARTUP_FAILED;
    }

    let log_path = crate::init_logging();
    let drbg = match aether::random::configure() {
        Ok(drbg) => drbg,
        Err(error) => return startup_failed(error),
    };
    tracing::info!(%drbg, "randomness provider");

    match crate::launch::current_token_is_elevated() {
        Ok(true) => {}
        Ok(false) => return startup_failed("le moteur d'Orion doit être élevé"),
        Err(error) => return startup_failed(error),
    }

    let parent = match ParentWatch::open(args.ui_pid, args.ui_created_at) {
        Ok(parent) => parent,
        Err(error) => return fail(LifecycleEvent::ParentMissing, error),
    };

    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return startup_failed(error),
    };
    let expected = match launcher_client(args.ui_pid, &current_exe) {
        Ok(expected) => expected,
        Err(error) => return fail(LifecycleEvent::ClientRefused, error),
    };
    let sid = match process_user_sid(args.ui_pid) {
        Ok(sid) => sid,
        Err(error) => return fail(LifecycleEvent::ClientRefused, error),
    };

    let source_dir = match crate::prepare_wireguard_nt_working_directory(cfg!(debug_assertions)) {
        Ok(dir) => dir,
        Err(error) => return startup_failed(error),
    };
    if current_exe.parent() != Some(source_dir.as_path()) {
        if let Err(error) = add_dll_directory(&source_dir) {
            return startup_failed(error);
        }
    }

    let backend = match default_backend() {
        Ok(backend) => backend,
        Err(error) => return startup_failed(error),
    };
    let paths = match EnginePaths::for_current_user() {
        Ok(paths) => paths,
        Err(error) => return startup_failed(error),
    };
    let engine = match EngineService::open(paths, backend, log_path, env!("CARGO_PKG_VERSION")) {
        Ok(engine) => engine,
        Err(error) => return startup_failed(error),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return startup_failed(error),
    };

    let event = runtime.block_on(session(&args, &expected, &sid, engine, parent));
    // The thread waiting on the UI's handle cannot be cancelled: do not let the
    // runtime's drop wait for it.
    runtime.shutdown_background();
    conclude(event)
}

/// The engine mode exists only on Windows: elsewhere it refuses to start.
#[cfg(not(windows))]
pub fn run(_args: EngineArgs) -> i32 {
    eprintln!("le mode moteur n'existe que sous Windows");
    BAD_ARGUMENTS
}

/// Where WireGuardNT is loaded from: beside the executable, or else in the
/// workspace when the caller allows that. The engine allows it in debug builds
/// only: an elevated process must not load a DLL from a folder the user can
/// write to.
#[cfg(any(windows, test))]
pub(crate) fn wireguard_source_dir(
    executable_dir: &Path,
    workspace: &Path,
    dll: &str,
    allow_workspace_fallback: bool,
) -> Result<PathBuf, String> {
    if executable_dir.join(dll).is_file() {
        return Ok(executable_dir.to_path_buf());
    }
    if !allow_workspace_fallback {
        return Err(format!(
            "WireGuardNT absent à côté de l'exécutable ({dll}) : le moteur ne charge pas de DLL depuis l'espace de travail."
        ));
    }
    if workspace.join(dll).is_file() {
        return Ok(workspace.to_path_buf());
    }
    Err(format!(
        "WireGuardNT est absent ({dll}) : reconstruisez Orion pour préparer ses dépendances Windows."
    ))
}

/// Logs a failure that is not a session event, and returns its exit code.
#[cfg(windows)]
fn startup_failed(error: impl Display) -> i32 {
    tracing::error!(%error, "moteur d'Orion impossible à démarrer");
    STARTUP_FAILED
}

/// Logs a start-up failure that has a session event, and returns its exit code.
#[cfg(windows)]
fn fail(event: LifecycleEvent, error: impl Display) -> i32 {
    tracing::error!(%error, ?event, "moteur d'Orion : démarrage refusé");
    conclude(event)
}

/// Logs the end of the engine and returns its exit code. The teardown has
/// already run, inside [`session`], for every event that reached it.
#[cfg(windows)]
fn conclude(event: LifecycleEvent) -> i32 {
    let code = exit_code(event);
    match on_event(event) {
        Action::TeardownAndExit => {}
    }
    tracing::info!(?event, code, "moteur d'Orion arrêté");
    code
}

/// Logs why a session ended early, and returns the event for it.
#[cfg(windows)]
fn session_event(event: LifecycleEvent, error: impl Display) -> LifecycleEvent {
    tracing::error!(%error, ?event, "session du moteur interrompue");
    event
}

/// The UI's launcher, as the engine expects it to be: this image, started
/// before the engine, and the same process the UI announced.
#[cfg(windows)]
fn launcher_client(ui_pid: u32, current_exe: &Path) -> Result<ExpectedClient, String> {
    let launcher = observe_process(ui_pid)?;
    let own_created_at = observe_process(std::process::id())?.created_at;
    expected_from_launcher(launcher, current_exe, own_created_at)
        .map_err(|refusal| refusal.to_string())
}

/// Adds `directory` to the DLL search, which [`run`] has restricted.
#[cfg(windows)]
fn add_dll_directory(directory: &Path) -> Result<(), String> {
    let wide: Vec<u16> = directory
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and alive for the call. The cookie is
    // not kept: the directory stays searched until the process exits.
    let cookie = unsafe { AddDllDirectory(wide.as_ptr()) };
    if cookie.is_null() {
        return Err(format!(
            "dossier de DLL refusé ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Serves the one UI until the session ends, then tears the engine down.
#[cfg(windows)]
async fn session(
    args: &EngineArgs,
    expected: &ExpectedClient,
    sid: &str,
    engine: Arc<EngineService>,
    parent: ParentWatch,
) -> LifecycleEvent {
    let event = serve_the_ui(args, expected, sid, &engine, parent).await;
    engine.teardown().await;
    event
}

#[cfg(windows)]
async fn serve_the_ui(
    args: &EngineArgs,
    expected: &ExpectedClient,
    sid: &str,
    engine: &Arc<EngineService>,
    parent: ParentWatch,
) -> LifecycleEvent {
    let server = match create_server(&args.pipe, sid) {
        Ok(server) => server,
        Err(error) => return session_event(LifecycleEvent::ChannelBroken, error),
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, server.connect()).await {
        Err(_) => {
            return session_event(
                LifecycleEvent::ConnectTimeout,
                "aucun client n'a ouvert le tube",
            )
        }
        Ok(Err(error)) => return session_event(LifecycleEvent::ChannelBroken, error),
        Ok(Ok(())) => {}
    }
    let observed = match observe_client(&server) {
        Ok(observed) => observed,
        Err(error) => return session_event(LifecycleEvent::ClientRefused, error),
    };
    if let Err(refusal) = verify_client(expected, &observed) {
        return session_event(LifecycleEvent::ClientRefused, refusal);
    }

    let parent_gone = tokio::task::spawn_blocking(move || parent.wait());
    tokio::select! {
        outcome = serve(server, &args.token, Arc::clone(engine)) => LifecycleEvent::from(&outcome),
        _ = parent_gone => LifecycleEvent::ParentExited,
    }
}

/// The UI's process handle, held for the whole session. It keeps the process
/// object alive, so the PID cannot be reused under it, and it is the handle the
/// engine waits on.
#[cfg(windows)]
struct ParentWatch(HANDLE);

// SAFETY: a process handle is usable from any thread. The watch moves into one
// blocking task that waits on it, and is never shared.
#[cfg(windows)]
unsafe impl Send for ParentWatch {}

#[cfg(windows)]
impl ParentWatch {
    /// Opens the UI at `pid`, and fails unless it was created at `created_at`.
    fn open(pid: u32, created_at: u64) -> Result<Self, String> {
        // SAFETY: OpenProcess takes no pointer; a null result is checked below.
        let raw = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if raw.is_null() {
            return Err(format!(
                "processus de l'IHM {pid} inaccessible ({})",
                std::io::Error::last_os_error()
            ));
        }
        // Owned from here on: the handle closes on drop, even when refused below.
        let watch = Self(raw);
        if !parent_matches(created_at, creation_time(raw)) {
            return Err(format!(
                "le processus {pid} n'est pas l'IHM qui a lancé le moteur"
            ));
        }
        Ok(watch)
    }

    fn wait(&self) {
        // SAFETY: the handle stays open for SYNCHRONIZE until `self` is dropped.
        unsafe { WaitForSingleObject(self.0, INFINITE) };
    }
}

#[cfg(windows)]
impl Drop for ParentWatch {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from OpenProcess and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// FILETIME of a process's creation, read from an open handle.
#[cfg(windows)]
fn creation_time(process: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the handle is open for PROCESS_QUERY_LIMITED_INFORMATION, and the
    // four out-parameters are valid, writable FILETIME structs.
    let timed =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    (timed != 0)
        .then(|| (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(test)]
mod tests;
