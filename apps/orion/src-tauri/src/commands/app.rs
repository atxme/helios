//! The application itself: its state and backend, the about box, the speed
//! test, the window size and the log export.

use super::*;
use orion_engine::{AboutView, EngineCommand, EngineReply, KeyNegotiationSupport};

#[tauri::command]
pub(crate) async fn get_state(state: State<'_, AppState>) -> Result<String, String> {
    match state.client.call(EngineCommand::GetState).await? {
        EngineReply::State(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn backend_kind(state: State<'_, AppState>) -> Result<String, String> {
    match state.client.call(EngineCommand::BackendKind).await? {
        EngineReply::Backend(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Indicates whether the WireGuard adapter is still mounted. On failure, it
/// must remain up to capture routes and prevent a clear-text leak.
#[tauri::command]
pub(crate) async fn adapter_is_up(state: State<'_, AppState>) -> Result<bool, String> {
    match state.client.call(EngineCommand::AdapterIsUp).await? {
        EngineReply::Flag(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn about_orion(state: State<'_, AppState>) -> Result<AboutView, String> {
    match state.client.call(EngineCommand::AboutOrion).await? {
        EngineReply::About(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn key_negotiation_support(
    state: State<'_, AppState>,
) -> Result<KeyNegotiationSupport, String> {
    match state
        .client
        .call(EngineCommand::KeyNegotiationSupport)
        .await?
    {
        EngineReply::KeyNegotiation(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Measures the raw WireGuard data path to the active gateway. The engine runs
/// it and relays its progress as events; see the speedtest bridge in `main.rs`.
#[tauri::command]
pub(crate) async fn run_speed_test(
    state: State<'_, AppState>,
    mode: String,
) -> Result<orion_core::SpeedTestResult, String> {
    match state
        .client
        .call(EngineCommand::RunSpeedTest { mode })
        .await?
    {
        EngineReply::SpeedTest(result) => Ok(result),
        _ => Err(unexpected_engine_reply()),
    }
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
