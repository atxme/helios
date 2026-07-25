// Prevents opening a Windows console in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri shell of the Orion VPN client.
//!
//! Thin wiring layer: it contains no WireGuard logic (delegated to
//! `orion-core`). Its role is to:
//! 1. expose `invoke` commands to the frontend (connect/disconnect, profile CRUD);
//! 2. relay the core's [`ClientEvent`]s to the frontend (`emit`);
//! 3. start heliosd telemetry **only** when the tunnel goes `Up`
//!    (the web server lives behind WireGuard) and stop it on disconnection.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

#[cfg(debug_assertions)]
use std::{
    net::{SocketAddr, TcpStream},
    process::{Child, Command},
    time::{Duration, Instant},
};

use aether::TunnelState;
use orion_core::{
    backend::EventSink, complete_profile_import, default_backend, inspect_profile,
    parse_profile_import, read_profile_import_path, telemetry, ClientConfig, ClientEvent,
    ClientProfile, ProfileIssues, ProtectedIdentityStore, VpnController,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{watch, Mutex};

/// Shared application state, injected into each command via [`State`].
struct AppState {
    controller: Arc<VpnController>,
    config: Arc<Mutex<ClientConfig>>,
    telemetry: Arc<TelemetryManager>,
    pending_profile_paths: StdMutex<VecDeque<PathBuf>>,
}

/// Polling interval for the last WireGuard handshake.
///
/// WireGuard is connectionless: the `Up` state is inferred from handshake
/// freshness, it's never notified (ADR-001 §3). Without this loop, the UI
/// would stay stuck on the last known state.
const HANDSHAKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Manages the telemetry task's lifecycle (only one active at a time).
#[derive(Default)]
struct TelemetryManager {
    cancel: StdMutex<Option<watch::Sender<bool>>>,
}

impl TelemetryManager {
    /// Starts a telemetry loop toward `url`, cancelling any previous one.
    fn start(&self, url: String, sink: EventSink) {
        self.stop();
        let (tx, rx) = watch::channel(false);
        *self.cancel.lock().unwrap() = Some(tx);
        tokio::spawn(telemetry::run(url, sink, rx));
    }

    /// Cancels the current telemetry loop, if any.
    fn stop(&self) {
        if let Some(tx) = self.cancel.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }
}

/// Builds a sink that relays each core event to the frontend.
fn emit_sink(app: AppHandle) -> EventSink {
    Arc::new(move |ev: ClientEvent| {
        let _ = app.emit("helios://event", &ev);
    })
}

// ─── Commands invoked by the frontend ───────────────────────────────────────

// WireGuard has only one suite (ChaCha20-Poly1305). Post-quantum protection
// comes from the ML-KEM PSK, automatically negotiated after the classic
// tunnel is mounted as soon as the profile carries an internal Helios URL —
// see `orion_core::backend::upgrade_to_post_quantum`.

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> String {
    state.controller.state().as_str().to_string()
}

#[tauri::command]
fn backend_kind(state: State<'_, AppState>) -> &'static str {
    state.controller.backend_kind()
}

/// Indicates whether the WireGuard adapter is still mounted. On failure, it
/// must remain up to capture routes and prevent a clear-text leak.
#[tauri::command]
fn adapter_is_up(state: State<'_, AppState>) -> bool {
    state.controller.adapter_is_up()
}

/// What this build can do with the gateway's key-negotiation port.
///
/// The two facts are reported separately because they fail differently: a
/// binary compiled without the feature will never negotiate, while a build
/// that has it still needs the machine's protected certificate store to be
/// wired in. The screen states whichever is missing instead of letting the
/// user discover it when the connection fails.
#[derive(serde::Serialize)]
struct KeyNegotiationSupport {
    compiled: bool,
    identity_store: bool,
}

#[tauri::command]
fn key_negotiation_support(state: State<'_, AppState>) -> KeyNegotiationSupport {
    KeyNegotiationSupport {
        compiled: cfg!(feature = "key-negotiation"),
        identity_store: state.controller.key_negotiation_ready(),
    }
}

/// Is this profile's identity already sealed on this machine?
///
/// Answered without unsealing: the screen needs to know whether the import
/// still has to happen, and that question must not depend on the session
/// being able to decrypt. `false` also covers "no negotiation block" — a
/// profile that needs no identity needs no import either.
#[tauri::command]
fn key_negotiation_identity_sealed(profile: ClientProfile) -> bool {
    let Some(settings) = profile.key_negotiation.as_ref() else {
        return false;
    };
    ProtectedIdentityStore::for_current_user().is_ok_and(|store| store.contains(&settings.identity))
}

/// Fingerprint of the gateway PQ certificate pinned by a profile.
///
/// Same reasoning as [`profile_public_key`]: the value is derived on the Rust
/// side and displayed so the user can compare it, out loud or by phone, with
/// what `heliosd init-key-negotiation` printed on the gateway.
#[tauri::command]
fn key_negotiation_fingerprint(profile: ClientProfile) -> Option<String> {
    profile
        .key_negotiation
        .as_ref()
        .and_then(|settings| settings.gateway_pq_fingerprint())
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<ClientConfig, String> {
    Ok(state.config.lock().await.clone())
}

/// Result of an import: the draft profile, and what became of the identity.
///
/// The identity's fate is reported rather than raised because the two are
/// independent: a profile stays perfectly importable on a machine that cannot
/// seal, and hiding the profile behind that failure would leave the user with
/// nothing at all — not even the endpoint to check.
#[derive(serde::Serialize)]
struct ImportOutcome {
    profile: ClientProfile,
    /// `true` when the document carried an identity **and** it was sealed.
    identity_sealed: bool,
    /// Why sealing failed, when the document carried one and it did not.
    identity_error: Option<String>,
}

/// Seals the identity shipped with a document, if any.
///
/// Import is where this happens because it is the only moment the plaintext
/// exists: from here on the material lives sealed in the store, and the
/// profile keeps nothing but the name of the entry.
fn seal_identity(identity: Option<orion_core::ClientIdentityBundle>) -> (bool, Option<String>) {
    let Some(identity) = identity else {
        return (false, None);
    };
    let sealed = ProtectedIdentityStore::for_current_user()
        .and_then(|store| store.store(&identity))
        .map(|_| ());
    match sealed {
        Ok(()) => (true, None),
        // `{:#}` keeps the anyhow context chain: the platform reason is the
        // useful half of the message.
        Err(error) => (false, Some(format!("{error:#}"))),
    }
}

/// Decodes a document chosen by the user without persisting it.
///
/// The UI displays the result as a draft: a valid file therefore never
/// silently replaces a profile with the same name. The identity, on the other
/// hand, is sealed straight away — it is a secret, and the shorter it stays
/// in memory the better.
#[tauri::command]
async fn import_profile(
    state: State<'_, AppState>,
    contents: String,
    file_name: String,
) -> Result<ImportOutcome, String> {
    let imported =
        parse_profile_import(&contents, &file_name).map_err(|error| error.to_string())?;
    let (identity_sealed, identity_error) = seal_identity(imported.identity);
    let config = state.config.lock().await;
    let profile =
        complete_profile_import(imported.profile, &config).map_err(|error| error.to_string())?;
    Ok(ImportOutcome {
        profile,
        identity_sealed,
        identity_error,
    })
}

/// Rereads a profile whose path comes from the system association.
///
/// `path = None` consumes the next path queued at startup or forwarded by
/// the single-instance plugin. The frontend calls this form after
/// installing its listener, which makes the first double-click as reliable
/// as subsequent ones.
#[tauri::command]
async fn import_profile_path(
    state: State<'_, AppState>,
    path: Option<String>,
) -> Result<Option<ImportOutcome>, String> {
    let path = match path {
        Some(path) => PathBuf::from(path),
        None => match state.pending_profile_paths.lock().unwrap().pop_front() {
            Some(path) => path,
            None => return Ok(None),
        },
    };
    if !is_associated_profile_path(&path) {
        return Err("seuls les fichiers .orionprofile sont acceptés par cette commande".into());
    }
    let imported = read_profile_import_path(&path).map_err(|error| error.to_string())?;
    let (identity_sealed, identity_error) = seal_identity(imported.identity);
    let config = state.config.lock().await;
    let profile =
        complete_profile_import(imported.profile, &config).map_err(|error| error.to_string())?;
    Ok(Some(ImportOutcome {
        profile,
        identity_sealed,
        identity_error,
    }))
}

/// Public key corresponding to a profile's private key.
///
/// This is what the user communicates to the operator to be admitted on the
/// gateway (ADR-004 §6): deriving it here avoids making them manipulate
/// their private key in a terminal to obtain a value that is, itself, public.
#[tauri::command]
fn profile_public_key(profile: ClientProfile) -> Option<String> {
    profile.public_key()
}

#[tauri::command]
async fn save_profile(
    state: State<'_, AppState>,
    profile: ClientProfile,
) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    let selected = profile.name.clone();
    cfg.upsert(profile);
    cfg.selected = Some(selected);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn delete_profile(state: State<'_, AppState>, name: String) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    cfg.remove(&name);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn select_profile(state: State<'_, AppState>, name: String) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    cfg.selected = Some(name);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<(), String> {
    let profile = {
        let cfg = state.config.lock().await;
        match name {
            Some(n) => cfg.find(&n).cloned(),
            None => cfg.selected.as_deref().and_then(|n| cfg.find(n)).cloned(),
        }
        .ok_or_else(|| "aucun profil sélectionné".to_string())?
    };

    // Validates the WireGuard profile (endpoint + keys) BEFORE any side effect.
    profile.validate().map_err(|e| e.to_string())?;

    // Sink combining relay to the frontend AND telemetry control: telemetry
    // only starts on transition to Up (web behind the tunnel).
    let base = emit_sink(app.clone());
    let telemetry = Arc::clone(&state.telemetry);
    let heliosd_url = profile.heliosd_url.clone();
    let app_for_tel = app.clone();
    let negotiating = profile.key_negotiation.is_some();
    let negotiated_profile = profile.name.clone();
    let config = Arc::clone(&state.config);
    let sink: EventSink = Arc::new(move |ev: ClientEvent| {
        // Mirror of the gateway rule: a committed negotiation raises this
        // profile's floor for good. Helios does the same on its side and
        // would refuse a weaker mode afterwards — a client that kept
        // offering one would only produce a failed connection the user
        // couldn't explain.
        if negotiating {
            if let ClientEvent::Protection { psk } = &ev {
                raise_key_negotiation_floor(Arc::clone(&config), negotiated_profile.clone(), *psk);
            }
        }
        if let ClientEvent::StateChanged { state } = &ev {
            match state {
                TunnelState::Up => {
                    if let Some(url) = heliosd_url.clone() {
                        telemetry.start(url, emit_sink(app_for_tel.clone()));
                    }
                }
                TunnelState::Down | TunnelState::Failed => telemetry.stop(),
                _ => {}
            }
        }
        base(ev);
    });

    state.controller.connect(profile, sink.clone()).await;

    // State inference loop: WireGuard notifies nothing, we poll the age of
    // the last handshake. Never touches the adapter (ADR-001 §3 bis).
    let controller = Arc::clone(&state.controller);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HANDSHAKE_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            if controller.state() == TunnelState::Down {
                break; // explicit disconnection: nothing left to infer
            }
            controller.poll_handshake(sink.clone()).await;
        }
    });

    Ok(())
}

/// Persists a floor raise announced by a committed negotiation.
///
/// Runs in a task because the sink is synchronous while the configuration is
/// behind an async lock. A failed write is logged and nothing else: the
/// session in progress stays valid, and the gateway keeps its own floor —
/// which is the one that actually refuses a downgrade.
fn raise_key_negotiation_floor(
    config: Arc<Mutex<ClientConfig>>,
    name: String,
    observed: orion_core::PskKind,
) {
    use aether::key_negotiation::ProtectionMode;

    let reached = match observed {
        orion_core::PskKind::MlKem => ProtectionMode::MlKem,
        orion_core::PskKind::Static => ProtectionMode::StaticPsk,
        // Classic commits nothing to raise.
        orion_core::PskKind::None => return,
    };
    tokio::spawn(async move {
        let mut cfg = config.lock().await;
        let Some(settings) = cfg
            .profiles
            .iter_mut()
            .find(|profile| profile.name == name)
            .and_then(|profile| profile.key_negotiation.as_mut())
        else {
            return;
        };
        if settings.minimum_mode.satisfies(reached) {
            return;
        }
        settings.minimum_mode = reached;
        if let Err(error) = cfg.save() {
            tracing::warn!(%error, "unable to persist the raised key-negotiation floor");
        }
    });
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.telemetry.stop();
    state.controller.disconnect(emit_sink(app)).await;
    Ok(())
}

/// Reports the faulty fields of a profile being edited.
///
/// Validation stays **on the Rust side**: the UI highlights what the core
/// refuses, it doesn't reimplement its rules. Two rule sets would eventually
/// diverge, and the UI would accept values the connection rejects.
#[tauri::command]
fn validate_profile(profile: ClientProfile) -> ProfileIssues {
    inspect_profile(&profile)
}

/// Window dimensions depending on the displayed view.
///
/// Each view has different needs: connection fits in a narrow column, the
/// profile form needs two columns, the log wants width so it doesn't wrap
/// its lines. A single window would force taking the maximum of the three
/// at all times.
///
/// An unknown view falls back to the "connection" size: it's the startup
/// view, and a default size is better than an error for a label only the
/// UI produces.
fn window_size_for(view: &str) -> (f64, f64) {
    match view {
        "profiles" => (800.0, 720.0),
        "logs" => (760.0, 640.0),
        // Connection has only an orb, a state, and a button: giving it the
        // height of the other views only produced a hole in the middle.
        _ => (520.0, 560.0),
    }
}

/// Adjusts the window to the requested view.
///
/// Resizing lives **on the Rust side** because exposing it to the frontend
/// would require `core:window:allow-set-size` in the capabilities — a
/// general right over the window for three sizes known at compile time.
#[tauri::command]
fn resize_for_view(app: AppHandle, view: String) -> Result<(), String> {
    let (width, height) = window_size_for(&view);
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "fenêtre principale introuvable".to_string())?;
    window
        .set_size(tauri::LogicalSize::new(width, height))
        .map_err(|e| format!("redimensionnement de la fenêtre : {e}"))
}

/// Export bound. The frontend log is capped at 80 lines, but the command
/// doesn't trust that bound: it comes from the caller.
const MAX_LOG_EXPORT_BYTES: usize = 512 * 1024;

/// Reduces a label proposed by the frontend to a safe file name.
///
/// The frontend picks the label — it's the only one that knows the local
/// time — but never the path. Only ordinary name characters survive, which
/// at once eliminates separators, `..`, and disguised extensions: an export
/// must not be able to write anywhere but the directory the command chose.
fn sanitize_stem(proposed: &str) -> String {
    let cleaned: String = proposed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "orion-journal".to_string()
    } else {
        cleaned
    }
}

/// Writes the log to a file and returns its path.
///
/// Goes through a command rather than the `dialog`/`fs` plugins: Orion only
/// grants `core:default` as a capability, and opening general disk access
/// to the frontend for a simple export would be disproportionate.
#[tauri::command]
fn export_logs(app: AppHandle, stem: String, contents: String) -> Result<String, String> {
    if contents.len() > MAX_LOG_EXPORT_BYTES {
        return Err("journal trop volumineux pour être exporté".to_string());
    }
    let dir = app
        .path()
        .document_dir()
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| format!("aucun répertoire d'export disponible : {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("création de {} : {e}", dir.display()))?;
    let path = dir.join(format!("{}.log", sanitize_stem(&stem)));
    std::fs::write(&path, contents).map_err(|e| format!("écriture de {} : {e}", path.display()))?;
    Ok(path.display().to_string())
}

fn is_associated_profile_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("orionprofile"))
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

/// `defguard_wireguard_rs 0.11.0` opens WireGuardNT via a relative path fixed
/// in its source. A double-click gives Orion a current directory that may
/// be the profile's; we replace it before building the backend.
#[cfg(all(target_os = "windows", feature = "wireguard"))]
fn prepare_wireguard_nt_working_directory() -> anyhow::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const DLL: &str = "resources-windows/binaries/wireguard-amd64.dll";
    #[cfg(target_arch = "aarch64")]
    const DLL: &str = "resources-windows/binaries/wireguard-arm64.dll";

    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Orion binary directory not found"))?;
    let source_dir = if executable_dir.join(DLL).is_file() {
        executable_dir
    } else {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .ok_or_else(|| anyhow::anyhow!("Orion workspace root not found"))?;
        if !workspace.join(DLL).is_file() {
            anyhow::bail!(
                "WireGuardNT is missing ({DLL}); run `cargo xtask orion-deps` before Orion"
            );
        }
        workspace.to_path_buf()
    };
    std::env::set_current_dir(&source_dir).map_err(|error| {
        anyhow::anyhow!(
            "unable to select WireGuardNT resources in {}: {error}",
            source_dir.display()
        )
    })
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    #[cfg(debug_assertions)]
    let _frontend_dev_server =
        ensure_frontend_dev_server().expect("unable to prepare Orion's development UI");

    let startup_cwd = std::env::current_dir().unwrap_or_default();
    let startup_args: Vec<String> = std::env::args().collect();
    let pending_profile_paths = associated_profile_paths(&startup_args, &startup_cwd).into();

    #[cfg(all(target_os = "windows", feature = "wireguard"))]
    prepare_wireguard_nt_working_directory()
        .expect("unable to prepare the WireGuardNT DLL shipped with Orion");

    let backend = default_backend().expect(
        "real WireGuard backend unavailable — Orion refuses to start with implicit simulation",
    );
    let controller = VpnController::new(backend);
    // The protected store is the shell's job: `orion-core` states the
    // boundary, the platform implementation lives with the platform.
    #[cfg(feature = "key-negotiation")]
    let controller = match ProtectedIdentityStore::for_current_user() {
        Ok(store) => controller.with_key_negotiation_identities(Arc::new(store)),
        Err(error) => {
            // Not fatal: profiles without negotiation still connect, and the
            // Profiles screen reports the missing store rather than letting
            // the failure surface as an unexplained refused connection.
            tracing::warn!(%error, "no protected identity store on this machine");
            controller
        }
    };
    let controller = Arc::new(controller);
    let config = ClientConfig::load().unwrap_or_default();

    tauri::Builder::default()
        // Must stay the first plugin registered: it intercepts the secondary
        // instance before other plugins can act.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            let paths = associated_profile_paths(&args, Path::new(&cwd));
            if !paths.is_empty() {
                let state = app.state::<AppState>();
                state.pending_profile_paths.lock().unwrap().extend(paths);
                let _ = app.emit("helios://profile-path", ());
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState {
            controller,
            config: Arc::new(Mutex::new(config)),
            telemetry: Arc::new(TelemetryManager::default()),
            pending_profile_paths: StdMutex::new(pending_profile_paths),
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            backend_kind,
            adapter_is_up,
            get_config,
            import_profile,
            import_profile_path,
            profile_public_key,
            save_profile,
            delete_profile,
            select_profile,
            connect,
            disconnect,
            export_logs,
            resize_for_view,
            validate_profile,
            key_negotiation_support,
            key_negotiation_fingerprint,
            key_negotiation_identity_sealed,
        ])
        .run(tauri::generate_context!())
        .expect("error while launching Tauri");
}

#[cfg(test)]
mod security_tests {
    use super::{associated_profile_paths, sanitize_stem, window_size_for, Path, PathBuf};

    /// Each view has its size, and an unexpected label must not produce a
    /// degenerate window: it falls back to the startup view.
    #[test]
    fn each_view_has_its_size_and_unknown_falls_back_to_connect() {
        let connect = window_size_for("connect");
        assert_eq!(window_size_for("unknown"), connect);
        assert_ne!(window_size_for("profiles"), connect);
        assert_ne!(window_size_for("logs"), connect);
        // The profile form is the most demanding view of the three.
        for view in ["connect", "logs"] {
            assert!(window_size_for("profiles").0 >= window_size_for(view).0);
        }
        // No size drops below the minimum declared in tauri.conf.json.
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let window = &config["app"]["windows"][0];
        let (min_w, min_h) = (
            window["minWidth"].as_f64().expect("minWidth"),
            window["minHeight"].as_f64().expect("minHeight"),
        );
        for view in ["connect", "profiles", "logs"] {
            let (w, h) = window_size_for(view);
            assert!(w >= min_w, "{view} : {w} < {min_w}");
            assert!(h >= min_h, "{view} : {h} < {min_h}");
        }
    }

    /// The frontend names the export, it doesn't place it. Anything that
    /// could designate another directory must disappear from the label.
    #[test]
    fn the_export_name_cannot_designate_another_path() {
        assert_eq!(
            sanitize_stem("orion-journal-2026-07-23"),
            "orion-journal-2026-07-23"
        );
        assert_eq!(sanitize_stem("../../etc/passwd"), "etcpasswd");
        assert_eq!(
            sanitize_stem("C:\\Windows\\System32\\x"),
            "CWindowsSystem32x"
        );
        assert_eq!(sanitize_stem("journal.log.exe"), "journallogexe");
        // An empty or entirely filtered label falls back to a default name
        // rather than producing a hidden ".log" file.
        assert_eq!(sanitize_stem(""), "orion-journal");
        assert_eq!(sanitize_stem("../.."), "orion-journal");
        assert_eq!(sanitize_stem(&"a".repeat(200)).len(), 64);
    }

    #[test]
    fn cargo_run_server_aligns_with_the_tauri_dev_url() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let expected = format!("http://localhost:{}", super::FRONTEND_DEV_PORT);

        assert_eq!(config["build"]["devUrl"].as_str(), Some(expected.as_str()));
    }

    #[test]
    fn tauri_configuration_enforces_a_csp_and_freezes_prototypes() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let security = &config["app"]["security"];
        let csp = security["csp"].as_str().expect("Tauri CSP required");

        assert_eq!(security["freezePrototype"], true);
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src *"));
        assert!(!csp.contains("connect-src *"));
    }

    #[test]
    fn bundle_declares_association_and_linux_capability() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let association = &config["bundle"]["fileAssociations"][0];
        assert_eq!(association["ext"], serde_json::json!(["orionprofile"]));
        assert_eq!(
            config["bundle"]["linux"]["deb"]["postInstallScript"],
            "linux/postinst"
        );
        assert!(config["bundle"]["linux"]["deb"]["depends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dependency| dependency == "libcap2-bin"));
        let postinst = include_str!("../linux/postinst");
        assert!(postinst.contains("setcap cap_net_admin=ep"));
    }

    #[test]
    fn windows_bundle_ships_wireguard_and_requires_timestamped_signtool() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.windows.conf.json")).unwrap();
        assert_eq!(
            config["bundle"]["resources"]["../../../resources-windows/"],
            "resources-windows/"
        );
        let args = config["bundle"]["windows"]["signCommand"]["args"]
            .as_array()
            .unwrap();
        assert!(args.iter().any(|arg| arg == "windows/sign-orion.ps1"));
        let signer = include_str!("../windows/sign-orion.ps1");
        for required in ["ORION_TIMESTAMP_URL", "/tr", "/td", "SHA256", "/tw"] {
            assert!(signer.contains(required), "missing element: {required}");
        }
    }

    #[test]
    fn tauri_capabilities_stay_minimal() {
        let capabilities: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(capabilities["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capabilities["permissions"],
            serde_json::json!(["core:default"])
        );
    }

    #[test]
    fn association_only_forwards_orion_profiles() {
        let args = vec![
            "orion.exe".to_string(),
            "invitation.orionprofile".to_string(),
            "--unexpected".to_string(),
            "other.json".to_string(),
        ];
        assert_eq!(
            associated_profile_paths(&args, Path::new("/profils")),
            vec![PathBuf::from("/profils/invitation.orionprofile")]
        );
    }

    #[test]
    fn windows_manifest_requires_administrator_privileges() {
        let manifest = include_str!("../windows/orion-manifest.xml");
        assert!(manifest.contains("requireAdministrator"));
        assert!(manifest.contains("Microsoft.Windows.Common-Controls"));
    }
}
