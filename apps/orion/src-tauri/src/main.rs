// Prevents opening a Windows console in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri shell of the Orion client.
//!
//! Thin wiring layer: it contains no WireGuard logic (delegated to
//! `orion-core`). Its role is to:
//! 1. expose `invoke` commands to the frontend (connect/disconnect, profile CRUD);
//! 2. relay the core's [`ClientEvent`]s to the frontend (`emit`);
//! 3. hand the tunnel's commands to the engine, which starts heliosd telemetry
//!    **only** when the tunnel goes `Up` (the web server lives behind WireGuard)
//!    and stops it on disconnection.
//!
//! Start-up, in order:
//! 1. `--engine` is the elevated engine's mode: dispatched before anything
//!    else, and it never returns to the window path.
//! 2. The single-instance plugin is registered first, so a second launch hands
//!    its profile over and leaves, without a UAC prompt.
//! 3. Off Windows the engine opens in this process. On Windows the UI runs at
//!    its caller's level and `setup` starts the elevated engine
//!    ([`engine_launch::start`]); the UI opens none of the engine's state.
//! 4. `setup` manages the [`AppState`] and only then builds the window. The
//!    configuration does not create it (`"create": false`), so it does not
//!    exist before `setup`, and it appears once the engine has answered.

/// Windows is the target platform: nothing is simulated there.
///
/// Without the `wireguard` feature, [`orion_core::default_backend`] falls back
/// to the dry-run backend — legitimate on WSL2, where the data plane does not
/// exist, and nowhere else. An installed Orion that mounts nothing while
/// displaying a profile, an address and a negotiated mode is a client that
/// protects nothing and says so only in a corner of the Connection screen.
///
/// Refusing at compile time rather than at startup is deliberate: the flag is
/// a build decision, and the person who forgot it is the one building. Use
/// `cargo xtask orion-msi`, which carries the features in one place.
#[cfg(all(target_os = "windows", not(feature = "wireguard")))]
compile_error!(
    "Orion for Windows must be built with --features wireguard: without it the shell falls \
     back to the simulated backend, which encrypts nothing. Build with `cargo xtask orion-msi`."
);

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
};

#[cfg(debug_assertions)]
use std::{
    net::{SocketAddr, TcpStream},
    process::{Child, Command},
    time::{Duration, Instant},
};

#[cfg(not(windows))]
use orion_core::default_backend;
use orion_core::{backend::EventSink, ClientEvent};
use orion_engine::client::EngineClient;
use orion_engine::lifecycle::{EngineArgs, BAD_ARGUMENTS};
#[cfg(not(windows))]
use orion_engine::service::EngineService;
use orion_engine::service::PROFILE_EXTENSION;
use orion_engine::EngineCommand;
#[cfg(target_os = "windows")]
use tauri::WindowEvent;
use tauri::{AppHandle, Emitter, Manager, State};

/// Engine mode: the elevated process the UI launches, with no window.
mod engine_host;

/// Launch of the elevated engine from the UI, and the end of the UI with it.
mod engine_launch;

/// Rights the UI grants Administrators on its process and token before the
/// launch, so an engine elevated under another account can observe it.
mod ui_access;

/// Launches from the UI (SSH terminal, Astra companion). Each one is refused
/// while the UI's own token is elevated; only that check is Windows-specific.
mod launch;

/// Fixed launcher of `astra-signer`. Its only caller is the CA-TLS rotation in
/// `astra`, until lot 5 brings that rotation into Orion; renewal approval no
/// longer uses it.
mod companion;

/// Notification-area menu. Its model and labels are portable and tested
/// everywhere; only the wiring inside is Windows-only.
mod tray;

/// The Astra CA-TLS ceremony, driven from this window and signed elsewhere.
/// The vault, the PIN and the FIDO gesture stay inside the companion; only
/// the public progress states cross into Orion.
mod astra;
mod operator;

/// The commands the frontend invokes, one child per capability.
mod commands;
use commands::*;

/// Shared application state, injected into each command via [`State`].
struct AppState {
    /// The shell's session with the engine. Commands go through it.
    client: orion_engine::client::EngineClient,
    pending_profile_paths: StdMutex<VecDeque<PathBuf>>,
    /// The Astra CA-TLS rotation this window is hosting, if one is open.
    ///
    /// Owned by Rust, not by the WebView: the ceremony outlives the view that
    /// started it — leaving the screen mid-rotation must not abandon a
    /// companion that is about to write a durable decision — and its phase is
    /// the one thing a reload has to be able to recover.
    astra: astra::Ceremony,
    /// The protocol-2 ceremony, which every operation but the `CA-TLS`
    /// rotation now runs through.
    operator: operator::OperatorCeremony,
    /// Where every operator gesture opens the vault, as the operator chose it.
    vault_location: operator::location::VaultLocation,
    /// Set when Orion is quitting: the engine's session ends on purpose, and
    /// that end is not a failure to report.
    quitting: AtomicBool,
    /// The elevated engine's process, which Quit waits for.
    #[cfg(windows)]
    engine: Arc<engine_launch::EngineProcess>,
    /// Set once the tunnel has been taken down: only the first quit does it.
    tunnel_taken_down: AtomicBool,
    /// Set once the engine's loss has been reported, so it is reported once.
    engine_lost: AtomicBool,
}

#[cfg(debug_assertions)]
const FRONTEND_DEV_PORT: u16 = 1420;

/// Vite server launched by Orion when the development binary is run
/// directly with Cargo. The Tauri CLI already starts it via
/// `beforeDevCommand`; in that case, Orion detects the open port and
/// doesn't create a second process.
#[cfg(debug_assertions)]
struct FrontendDevServer {
    child: Child,
}

#[cfg(debug_assertions)]
impl Drop for FrontendDevServer {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            if error.kind() != std::io::ErrorKind::InvalidInput {
                tracing::warn!(%error, "unable to stop Orion's Vite server");
            }
        }
        let _ = self.child.wait();
    }
}

#[cfg(debug_assertions)]
fn frontend_dev_is_ready() -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], FRONTEND_DEV_PORT));
    TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok()
}

/// Guarantees Tauri's `devUrl` responds before the window is created.
///
/// `cargo run` doesn't know about `beforeDevCommand`, unlike the Tauri CLI.
/// Without this bridge, WebKit loads `localhost:1420` while no frontend is
/// listening and the user gets an empty window.
#[cfg(debug_assertions)]
fn ensure_frontend_dev_server() -> anyhow::Result<Option<FrontendDevServer>> {
    if frontend_dev_is_ready() {
        return Ok(None);
    }

    let frontend_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Orion frontend directory not found"))?;
    let vite_entrypoint = frontend_dir.join("node_modules/vite/bin/vite.js");
    if !vite_entrypoint.is_file() {
        anyhow::bail!("Vite is missing; run `npm ci --prefix apps/orion` before launching Orion");
    }

    tracing::info!("automatically starting Orion's Vite frontend");
    let mut child = Command::new("node")
        .arg(vite_entrypoint)
        .args(["--host", "127.0.0.1", "--port"])
        .arg(FRONTEND_DEV_PORT.to_string())
        .arg("--strictPort")
        .current_dir(frontend_dir)
        .spawn()
        .map_err(|error| anyhow::anyhow!("unable to start Vite with Node.js: {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if frontend_dev_is_ready() {
            return Ok(Some(FrontendDevServer { child }));
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Vite stopped before serving the Orion UI ({status})");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Vite did not open port 1420 within the 15-second timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Builds a sink that relays each core event to the frontend.
///
/// It is also where the notification-area menu learns that the tunnel changed:
/// every path that mounts or drops one — the button, the tray, the handshake
/// poll that infers a loss — ends up here, and hooking the transition at this
/// single point is what keeps the menu from claiming a tunnel that is gone.
/// Only the transition, deliberately: telemetry arrives once a second, and
/// rebuilding the menu at that rate would rebuild it under the pointer.
fn emit_sink(app: AppHandle) -> EventSink {
    Arc::new(move |ev: ClientEvent| {
        if matches!(ev, ClientEvent::StateChanged { .. }) {
            tray::refresh(&app);
        }
        let _ = app.emit("helios://event", &ev);
    })
}

/// Relays what the engine pushes to the frontend.
///
/// Speedtest progress goes out on its own channel, as it always did. Every
/// other event takes the path the commands the shell still serves use.
fn relay_engine_events(app: AppHandle, mut events: tokio::sync::mpsc::Receiver<ClientEvent>) {
    let sink = emit_sink(app.clone());
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                ClientEvent::SpeedTest { progress } => {
                    let _ = app.emit("helios://speedtest", &progress);
                }
                other => sink(other),
            }
        }
    });
}

/// Whether the loss of the engine is to be reported now.
///
/// Nothing is reported while quitting: the engine ends on purpose then. A
/// loss is reported once, however many watches see it.
pub(crate) fn should_report_engine_loss(quitting: bool, already_reported: &AtomicBool) -> bool {
    if quitting {
        return false;
    }
    !already_reported.swap(true, Ordering::AcqRel)
}

/// Ends Orion because its engine is gone: the window cannot act without it.
fn engine_lost(app: &AppHandle) {
    let state = app.state::<AppState>();
    let quitting = state.quitting.load(Ordering::Acquire);
    if !should_report_engine_loss(quitting, &state.engine_lost) {
        return;
    }
    engine_launch::fatal(engine_launch::ENGINE_STOPPED);
    app.exit(1);
}

/// Ends Orion when the engine's session ends, however it ends.
fn exit_when_engine_closes(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        app.state::<AppState>().client.closed().await;
        engine_lost(&app);
    });
}

/// Ends Orion when the elevated engine's process ends.
///
/// The session can end before the process does, and the process can end with
/// the session still open: both are watched, and whichever comes first ends
/// Orion once.
#[cfg(windows)]
fn exit_when_engine_process_ends(app: AppHandle) {
    let engine = Arc::clone(&app.state::<AppState>().engine);
    std::thread::spawn(move || {
        // A failed wait is logged by `wait_for_exit`, and announces nothing:
        // the closed session stays the other way of learning the loss.
        if engine.wait_for_exit() {
            engine_lost(&app);
        }
    });
}

/// How long Quit waits for the engine to take the tunnel down.
///
/// The engine waits for the controller, which may be mid-handshake. Past this,
/// Orion exits anyway and says so in the log: a quit that never ends is worse
/// than a teardown left unfinished, and the log is where that would be seen.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Takes the tunnel down before Orion exits.
///
/// Quitting leaves nothing behind: the engine is asked to shut down, tears the
/// tunnel down, and only then closes the session. Whatever goes wrong here is
/// logged, and the exit goes ahead either way.
fn take_tunnel_down(app: &AppHandle) {
    let state = app.state::<AppState>();
    state.quitting.store(true, Ordering::Release);
    if !first_teardown(&state.tunnel_taken_down) {
        return;
    }
    let deadline = std::time::Instant::now() + SHUTDOWN_GRACE;
    take_tunnel_down_blocking(&state.client, SHUTDOWN_GRACE);
    wait_for_engine_exit(&state, deadline);
}

/// Whether this call is the first to take the tunnel down.
///
/// `ExitRequested` and `Exit` both lead to a quit: only the first one shuts the
/// engine down and waits for it. A later one would send `Shutdown` again on a
/// stream whose first write may have been cut short, and wait the grace period
/// a second time.
pub(crate) fn first_teardown(tunnel_taken_down: &AtomicBool) -> bool {
    !tunnel_taken_down.swap(true, Ordering::AcqRel)
}

/// Waits, until `deadline`, for the engine's process to end.
///
/// The session closing is not the process ending: the engine exits after it.
/// Past the deadline Orion exits anyway, and says so in the log.
#[cfg(windows)]
fn wait_for_engine_exit(state: &AppState, deadline: std::time::Instant) {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if !state.engine.wait_for_exit_within(remaining) {
        tracing::warn!(
            "arrêt du moteur non terminé après {} s : Orion sort quand même",
            SHUTDOWN_GRACE.as_secs()
        );
    }
}

/// Off Windows there is no engine process: the session's end is the whole of it.
#[cfg(not(windows))]
fn wait_for_engine_exit(_state: &AppState, _deadline: std::time::Instant) {}

/// Runs the shutdown of `client` to completion, or to `grace`, on the runtime.
///
/// The deadline is built inside the future `block_on` drives: a `timeout`
/// created on the event-loop thread has no runtime to register with.
///
/// The deadline cancels `call`, which `EngineClient::call` advises against: a
/// cancelled write leaves a partial frame. At process exit that is acceptable,
/// since nothing writes to this session again and the process ends right after.
///
/// A session that already ended has nothing left to shut down, and this says
/// nothing: the reason it ended is logged where it happened.
fn take_tunnel_down_blocking(client: &EngineClient, grace: std::time::Duration) {
    if client.is_closed() {
        return;
    }
    let outcome = tauri::async_runtime::block_on(async {
        tokio::time::timeout(grace, async {
            if let Err(error) = client.call(EngineCommand::Shutdown).await {
                tracing::warn!(%error, "arrêt du moteur sans réponse");
            }
            client.closed().await;
        })
        .await
    });
    if outcome.is_err() {
        tracing::warn!(
            "démontage du tunnel non terminé après {} s : Orion sort quand même",
            grace.as_secs()
        );
    }
}

/// Shows the main window after it was hidden in the Windows notification area.
fn reveal_main_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        window.unminimize()?;
        window.set_focus()?;
    }
    Ok(())
}

/// Turns the Windows title-bar close button into a hide-to-tray action.
#[cfg(target_os = "windows")]
fn hide_main_window_on_close(window: &tauri::Window, event: &WindowEvent) {
    if window.label() != "main" {
        return;
    }
    if let WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();
        if let Err(error) = window.hide() {
            tracing::warn!(%error, "unable to hide Orion in the notification area");
        }
    }
}

// ─── Commands invoked by the frontend ───────────────────────────────────────

// WireGuard has only one suite (ChaCha20-Poly1305). Post-quantum protection
// comes from the ML-KEM PSK, automatically negotiated after the classic
// tunnel is mounted as soon as the profile carries an internal Helios URL —
// see `orion_core::backend::upgrade_to_post_quantum`.

/// The extension distributed until August 2026.
///
/// Still accepted, and only accepted — nothing produces it anymore. A profile
/// on an operator's disk outlives the client that reads it, and refusing the
/// document Orion itself wrote last month would send the user back to an
/// enrolment they have no reason to redo. The installer no longer registers
/// it, so a double-click on such a file no longer starts Orion; dragging it
/// onto the import button still works.
const LEGACY_PROFILE_EXTENSION: &str = "orionprofile";

fn is_associated_profile_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case(PROFILE_EXTENSION)
                || extension.eq_ignore_ascii_case(LEGACY_PROFILE_EXTENSION)
        })
}

fn associated_profile_paths(args: &[String], cwd: &Path) -> Vec<PathBuf> {
    args.iter()
        .skip(1)
        .map(PathBuf::from)
        .filter(|path| is_associated_profile_path(path))
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        })
        .take(1)
        .collect()
}

/// `defguard_wireguard_rs 0.12` opens WireGuardNT via a relative path fixed
/// in its source. A double-click gives Orion a current directory that may
/// be the profile's; we replace it before building the backend.
///
/// Returns the directory it selected. `allow_workspace_fallback` is what the
/// engine turns off in release builds: see [`engine_host::wireguard_source_dir`].
#[cfg(all(target_os = "windows", feature = "wireguard"))]
fn prepare_wireguard_nt_working_directory(
    allow_workspace_fallback: bool,
) -> anyhow::Result<PathBuf> {
    #[cfg(target_arch = "x86_64")]
    const DLL: &str = "resources-windows/binaries/wireguard-amd64.dll";
    #[cfg(target_arch = "aarch64")]
    const DLL: &str = "resources-windows/binaries/wireguard-arm64.dll";

    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Orion binary directory not found"))?;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| anyhow::anyhow!("Orion workspace root not found"))?;
    let source_dir = engine_host::wireguard_source_dir(
        &executable_dir,
        workspace,
        DLL,
        allow_workspace_fallback,
    )
    .map_err(|message| anyhow::anyhow!(message))?;
    std::env::set_current_dir(&source_dir).map_err(|error| {
        anyhow::anyhow!(
            "unable to select WireGuardNT resources in {}: {error}",
            source_dir.display()
        )
    })?;
    Ok(source_dir)
}

/// Default log filter.
///
/// `info` everywhere, `debug` for the crates that are **ours**. A flat `info`
/// left the interesting half of a startup unsaid — which vault path was taken,
/// what the TPM answered, why a profile did not load — while a flat `debug`
/// buries it under `hyper`.
///
/// `quinn` and `rustls` are in, deliberately. Key negotiation fails *inside*
/// the QUIC handshake far more often than after it — a wrong certificate, a
/// path that will not carry the PQ material, a port nobody forwarded — and
/// none of that has a name until those two crates are allowed to speak. They
/// are quiet as long as nothing connects, so the cost is paid only where the
/// answer lives. `RUST_LOG` overrides the whole thing.
const DEFAULT_LOG_FILTER: &str = "info,orion=debug,orion_core=debug,aether=debug,\
                                  aether_vault=debug,aether_key_negotiation=debug,\
                                  quinn=debug,quinn_proto=debug,rustls=debug";

/// Log file, beside the vault it describes: the engine's, and the UI's off Windows.
const LOG_FILE: &str = "orion.log";

/// The Windows UI's own log. The engine keeps `orion.log`: two processes do
/// not write the same file.
const UI_LOG_FILE: &str = "orion-ui.log";

/// Shared handle to the log file.
///
/// `tracing-appender` would do this and is not in the lockfile; adding a
/// dependency for fifteen lines is the worse trade. Locking per event is fine
/// at the rate this application logs.
#[derive(Clone)]
struct FileWriter(Arc<StdMutex<std::fs::File>>);

impl std::io::Write for FileWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?
            .flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Opens the log file, truncating what a previous run left.
///
/// Truncating rather than appending, and rotating nothing: what is wanted is
/// *this* start, in full. A file that grows across weeks makes the operator
/// scroll past six boots to reach the one that failed, and a VPN client that
/// silently fills a disk is its own incident.
fn open_log_file(path: &Path) -> Option<FileWriter> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent).ok()?;
    }
    let file = std::fs::File::create(path).ok()?;
    Some(FileWriter(Arc::new(StdMutex::new(file))))
}

/// The UI's own log: in the per-user directory, which is not protected. The
/// engine writes its log under the protected root instead.
fn ui_log_path() -> Option<PathBuf> {
    orion_core::protected_root::user_dir()
        .ok()
        .map(|dir| dir.join(if cfg!(windows) { UI_LOG_FILE } else { LOG_FILE }))
}

/// Wires stdout **and** a file.
///
/// The file is what makes a release build diagnosable at all: `windows_subsystem
/// = "windows"` means an installed Orion has no console, so everything written
/// to stdout goes nowhere. Asking a user to reproduce under `cargo run` to see
/// a log is asking them to rebuild the product.
fn init_logging(path: Option<PathBuf>) -> Option<PathBuf> {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
    };

    let file = path.as_deref().and_then(open_log_file);
    match file {
        Some(file) => {
            use tracing_subscriber::layer::SubscriberExt as _;
            use tracing_subscriber::util::SubscriberInitExt as _;
            tracing_subscriber::registry()
                .with(filter())
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                .with(
                    tracing_subscriber::fmt::layer()
                        // No colour codes in a file somebody will paste back.
                        .with_ansi(false)
                        .with_writer(file),
                )
                .init();
            path
        }
        None => {
            tracing_subscriber::fmt().with_env_filter(filter()).init();
            None
        }
    }
}

fn main() {
    let Some(startup_args) = std::env::args_os()
        .map(|argument| argument.into_string().ok())
        .collect::<Option<Vec<String>>>()
    else {
        eprintln!("argument non lisible");
        std::process::exit(BAD_ARGUMENTS);
    };
    match EngineArgs::parse(startup_args.get(1..).unwrap_or(&[])) {
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(BAD_ARGUMENTS);
        }
        Ok(Some(engine)) => std::process::exit(engine_host::run(engine)),
        Ok(None) => {}
    }

    let log_path = init_logging(ui_log_path());
    if let Some(path) = &log_path {
        tracing::info!(fichier = %path.display(), "journal d'Orion");
    } else {
        tracing::warn!("journal fichier indisponible — sortie standard uniquement");
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        backend = if cfg!(feature = "wireguard") {
            "wireguard"
        } else {
            "dry-run"
        },
        "démarrage d'Orion"
    );

    // The randomness pipeline is named before anything draws from it, and an
    // unusable provider stops the start-up: a client that cannot draw a
    // transaction identifier cannot negotiate, and failing here says why
    // (NEGOCIATION-DE-CLE-V5 §4.3).
    let drbg = aether::random::configure().expect("no usable DRBG provider for the negotiation");
    tracing::info!(%drbg, "randomness provider");

    #[cfg(debug_assertions)]
    let _frontend_dev_server =
        ensure_frontend_dev_server().expect("unable to prepare Orion's development UI");

    let startup_cwd = std::env::current_dir().unwrap_or_default();
    let pending_profile_paths = associated_profile_paths(&startup_args, &startup_cwd).into();

    // Off Windows the engine is opened here, before the window exists, and
    // runs in this process. On Windows it is a separate elevated process that
    // `setup` starts: this process never opens the engine's state.
    #[cfg(not(windows))]
    let engine = {
        let backend = default_backend().expect(
            "real WireGuard backend unavailable — Orion refuses to start with implicit simulation",
        );
        // The engine's paths and its state are resolved here, once. Without them
        // the vault would fall back to the working directory, which is not
        // acceptable: Orion refuses to start instead.
        let paths =
            orion_core::protected_root::EnginePaths::for_current_user().unwrap_or_else(|error| {
                tracing::error!(%error, "emplacements d'Orion introuvables — Orion refuse de démarrer");
                std::process::exit(1)
            });
        EngineService::open(paths, backend, log_path, env!("CARGO_PKG_VERSION")).unwrap_or_else(
            |error| {
                tracing::error!(%error, "moteur d'Orion impossible à construire — Orion refuse de démarrer");
                std::process::exit(1)
            },
        )
    };

    tauri::Builder::default()
        // Must stay the first plugin registered: it intercepts the secondary
        // instance before other plugins can act.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            let paths = associated_profile_paths(&args, Path::new(&cwd));
            if !paths.is_empty() {
                match app.try_state::<AppState>() {
                    Some(state) => {
                        state.pending_profile_paths.lock().unwrap().extend(paths);
                        let _ = app.emit("helios://profile-path", ());
                    }
                    None => tracing::warn!("profil reçu avant la fin du démarrage : ignoré"),
                }
            }
            if let Err(error) = reveal_main_window(app) {
                tracing::warn!(%error, "unable to reveal Orion from the secondary instance");
            }
        }))
        .setup(move |app| {
            #[cfg(not(windows))]
            let (client, events) = match tauri::async_runtime::block_on(
                orion_engine::client::in_process(engine),
            ) {
                Ok(session) => session,
                Err(error) => {
                    tracing::error!(%error, "session avec le moteur d'Orion impossible — Orion refuse de démarrer");
                    std::process::exit(1)
                }
            };
            #[cfg(windows)]
            let (client, events, engine_process) =
                match tauri::async_runtime::block_on(engine_launch::start()) {
                    Ok(started) => started,
                    Err(message) => {
                        engine_launch::fatal(&message);
                        std::process::exit(1)
                    }
                };

            app.manage(AppState {
                client,
                pending_profile_paths: StdMutex::new(pending_profile_paths),
                astra: astra::Ceremony::default(),
                operator: operator::OperatorCeremony::default(),
                vault_location: operator::location::VaultLocation::load(),
                quitting: AtomicBool::new(false),
                #[cfg(windows)]
                engine: Arc::new(engine_process),
                tunnel_taken_down: AtomicBool::new(false),
                engine_lost: AtomicBool::new(false),
            });
            #[cfg(target_os = "windows")]
            tray::install(app)?;
            relay_engine_events(app.handle().clone(), events);
            exit_when_engine_closes(app.handle().clone());
            #[cfg(windows)]
            exit_when_engine_process_ends(app.handle().clone());

            // Built here, after the state: the configuration does not create
            // it, so no command can reach an unmanaged state.
            let config = app
                .config()
                .app
                .windows
                .first()
                .ok_or("fenêtre principale absente")?;
            tauri::WebviewWindowBuilder::from_config(app.handle(), config)?.build()?;
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(target_os = "windows")]
            hide_main_window_on_close(window, event);
            #[cfg(not(target_os = "windows"))]
            let _ = (window, event);
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            backend_kind,
            adapter_is_up,
            about_orion,
            get_config,
            import_profile,
            import_profile_path,
            preview_enrollment_invitation,
            begin_enrollment,
            list_pending_enrollments,
            discard_pending_enrollment,
            export_pending_request,
            save_profile,
            generate_private_key,
            adopt_private_key,
            discard_staged_key,
            adopt_preshared_key,
            discard_staged_psk,
            ssh_command,
            open_ssh_terminal,
            delete_profile,
            select_profile,
            connect,
            disconnect,
            renew_psk,
            export_logs,
            resize_for_view,
            validate_profile,
            allow_unencrypted_volume,
            key_negotiation_support,
            certificate_inventory,
            certificate_actions,
            certificate_approval_manifest,
            certificate_approval_needs_pin,
            approve_certificate_renewal,
            certificate_overview,
            run_certificate_action,
            resume_certificate_recovery,
            last_certificate_error,
            run_speed_test,
            vault_posture,
            start_astra_ca_tls_rotation,
            continue_astra_ca_tls_rotation,
            cancel_astra_ca_tls_rotation,
            astra_ca_tls_rotation_status,
            begin_operator_ceremony,
            begin_vault_ceremony,
            begin_issuer_ceremony,
            begin_rotation_ceremony,
            approve_rotation_ceremony,
            rename_operator_key,
            write_domain_relay,
            adopt_connected_gateway,
            operator_domain_defaults,
            begin_enrollment_ceremony,
            operator_artifacts,
            operator_invitations,
            revoke_invitation,
            advance_operator_ceremony,
            dismiss_operator_ceremony,
            operator_ceremony_status,
            operator_overview,
            operator_pending_operations,
            operator_vault_location,
            choose_vault_location,
            reset_vault_location,
        ])
        .build(tauri::generate_context!())
        .expect("error while launching Tauri")
        .run(|app, event| match event {
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => take_tunnel_down(app),
            _ => {}
        });
}

#[cfg(test)]
mod security_tests;

#[cfg(all(test, not(target_os = "windows")))]
mod quit_tests;

#[cfg(test)]
mod engine_loss_tests;
