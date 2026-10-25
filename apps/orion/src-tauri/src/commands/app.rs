//! The application itself: its state and backend, the about box, the speed
//! test, the window size and the log export.

use super::*;
use orion_engine::{AboutView, KeyNegotiationSupport};

#[tauri::command]
pub(crate) fn get_state(state: State<'_, AppState>) -> String {
    state.engine.controller.state().as_str().to_string()
}

#[tauri::command]
pub(crate) fn backend_kind(state: State<'_, AppState>) -> &'static str {
    state.engine.controller.backend_kind()
}

/// Indicates whether the WireGuard adapter is still mounted. On failure, it
/// must remain up to capture routes and prevent a clear-text leak.
#[tauri::command]
pub(crate) fn adapter_is_up(state: State<'_, AppState>) -> bool {
    state.engine.controller.adapter_is_up()
}

#[tauri::command]
pub(crate) fn about_orion(state: State<'_, AppState>) -> AboutView {
    AboutView {
        version: env!("CARGO_PKG_VERSION").to_string(),
        backend: state.engine.controller.backend_kind().to_string(),
        profile_extension: PROFILE_EXTENSION.to_string(),
        log_path: state
            .engine
            .log_path
            .as_ref()
            .map(|path| path.display().to_string()),
    }
}

#[tauri::command]
pub(crate) fn key_negotiation_support(state: State<'_, AppState>) -> KeyNegotiationSupport {
    KeyNegotiationSupport {
        identity_store: state.engine.controller.key_negotiation_ready(),
    }
}

/// Measures the raw WireGuard data path to the active gateway.
///
/// This command is intentionally available only while WireGuard is `Up`: the
/// gateway's API lives behind that tunnel, and the Rust engine targets its
/// fixed in-tunnel address. TCP/UDP data is exchanged on a dedicated socket;
/// this command only relays progress and keeps the expensive benchmark
/// serialized. The transfer implementation itself lives in `orion-core`, so
/// it remains testable without Tauri or WebView.
#[tauri::command]
pub(crate) async fn run_speed_test(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: String,
) -> Result<orion_core::SpeedTestResult, String> {
    let _exclusive = state
        .engine
        .speedtest
        .try_lock()
        .map_err(|_| "un speedtest est déjà en cours".to_string())?;
    if state.engine.controller.state() != TunnelState::Up
        || !state.engine.controller.adapter_is_up()
    {
        return Err("le speedtest nécessite un tunnel WireGuard connecté".into());
    }
    let mode = orion_core::SpeedTestMode::parse(&mode).map_err(|error| error.to_string())?;
    let progress_app = app.clone();
    let progress: orion_core::SpeedTestProgressSink = Arc::new(move |update| {
        let _ = progress_app.emit("helios://speedtest", &update);
    });
    orion_core::run_speedtest_with_progress(
        mode,
        aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
        // No override: the UI runs `full`, where the UDP quality legs take
        // their rate from the TCP throughput measured moments earlier.
        None,
        progress,
    )
    .await
    .map_err(|error| error.to_string())
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
pub(crate) fn window_size_for(view: &str) -> (f64, f64) {
    match view {
        "profiles" => (800.0, 720.0),
        // Certificates is a column of cards: a name, four dated rows and the
        // four actions of §12.2, wrapped rather than stacked. It was given the
        // width of a two-column form and the height of six profiles, and a
        // device that holds one spent the difference on empty paper. Beyond
        // what fits, the view scrolls.
        "certificates" => (680.0, 620.0),
        // The speedtest is a single centred column showing one state at a
        // time — the launch, the leg under way and its curve, or the finished
        // figures above the previous runs. It was given the width of a
        // two-column form and spent it on margins.
        "speedtest" => (520.0, 620.0),
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
pub(crate) fn resize_for_view(app: AppHandle, view: String) -> Result<(), String> {
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
pub(crate) fn sanitize_stem(proposed: &str) -> String {
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
pub(crate) fn export_logs(
    app: AppHandle,
    stem: String,
    contents: String,
) -> Result<String, String> {
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
