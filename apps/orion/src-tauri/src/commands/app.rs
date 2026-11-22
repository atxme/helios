//! The application itself: its state and backend, the about box, the speed
//! test, the window size and the log export.

use super::*;
use orion_engine::{AboutView, EngineCommand, EngineReply, KeyNegotiationSupport};

#[tauri::command]
pub(crate) async fn get_state(state: State<'_, AppState>) -> Result<String, String> {
    get_state_from(&state.client).await
}

async fn get_state_from(client: &EngineClient) -> Result<String, String> {
    match client.call(EngineCommand::GetState).await? {
        EngineReply::State(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn backend_kind(state: State<'_, AppState>) -> Result<String, String> {
    backend_kind_from(&state.client).await
}

async fn backend_kind_from(client: &EngineClient) -> Result<String, String> {
    match client.call(EngineCommand::BackendKind).await? {
        EngineReply::Backend(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Indicates whether the WireGuard adapter is still mounted. On failure, it
/// must remain up to capture routes and prevent a clear-text leak.
#[tauri::command]
pub(crate) async fn adapter_is_up(state: State<'_, AppState>) -> Result<bool, String> {
    adapter_is_up_from(&state.client).await
}

async fn adapter_is_up_from(client: &EngineClient) -> Result<bool, String> {
    match client.call(EngineCommand::AdapterIsUp).await? {
        EngineReply::Flag(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn about_orion(state: State<'_, AppState>) -> Result<AboutView, String> {
    about_orion_from(&state.client).await
}

async fn about_orion_from(client: &EngineClient) -> Result<AboutView, String> {
    match client.call(EngineCommand::AboutOrion).await? {
        EngineReply::About(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn key_negotiation_support(
    state: State<'_, AppState>,
) -> Result<KeyNegotiationSupport, String> {
    key_negotiation_support_from(&state.client).await
}

async fn key_negotiation_support_from(
    client: &EngineClient,
) -> Result<KeyNegotiationSupport, String> {
    match client.call(EngineCommand::KeyNegotiationSupport).await? {
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
    run_speed_test_from(&state.client, mode).await
}

async fn run_speed_test_from(
    client: &EngineClient,
    mode: String,
) -> Result<orion_core::SpeedTestResult, String> {
    match client.call(EngineCommand::RunSpeedTest { mode }).await? {
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
    validate_log_export_contents(&contents)?;
    let dir = app
        .path()
        .document_dir()
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| format!("aucun répertoire d'export disponible : {e}"))?;
    export_logs_to(&dir, &stem, &contents).map(|path| path.display().to_string())
}

fn export_logs_to(
    dir: &std::path::Path,
    stem: &str,
    contents: &str,
) -> Result<std::path::PathBuf, String> {
    validate_log_export_contents(contents)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("création de {} : {e}", dir.display()))?;
    let path = dir.join(format!("{}.log", sanitize_stem(stem)));
    std::fs::write(&path, contents).map_err(|e| format!("écriture de {} : {e}", path.display()))?;
    Ok(path)
}

fn validate_log_export_contents(contents: &str) -> Result<(), String> {
    if contents.len() > MAX_LOG_EXPORT_BYTES {
        return Err("journal trop volumineux pour être exporté".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{export_logs_to, sanitize_stem, window_size_for, MAX_LOG_EXPORT_BYTES};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            loop {
                let path = std::env::temp_dir().join(format!(
                    "orion-app-command-tests-{}-{}",
                    std::process::id(),
                    NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create scratch directory: {error}"),
                }
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sanitizes_export_stems_and_uses_a_fallback_when_empty() {
        assert_eq!(sanitize_stem("../session!2026"), "session2026");
        assert_eq!(sanitize_stem("é /.."), "orion-journal");
        assert_eq!(sanitize_stem(&"a".repeat(80)), "a".repeat(64));
    }

    #[test]
    fn assigns_each_view_its_window_size_and_unknown_views_use_connection_size() {
        assert_eq!(window_size_for("profiles"), (800.0, 720.0));
        assert_eq!(window_size_for("certificates"), (680.0, 620.0));
        assert_eq!(window_size_for("speedtest"), (520.0, 620.0));
        assert_eq!(window_size_for("logs"), (760.0, 640.0));
        assert_eq!(window_size_for("unknown"), (520.0, 560.0));
    }

    #[test]
    fn exports_only_to_a_sanitized_log_name() {
        let scratch = Scratch::new();
        let path = export_logs_to(&scratch.0, "../session!2026", "journal")
            .expect("the bounded journal is written");

        assert_eq!(path, scratch.0.join("session2026.log"));
        assert_eq!(
            std::fs::read_to_string(path).expect("read exported journal"),
            "journal"
        );
    }

    #[test]
    fn refuses_an_oversized_export_before_creating_its_directory() {
        let scratch = Scratch::new();
        let output = scratch.0.join("not-created");
        let contents = "x".repeat(MAX_LOG_EXPORT_BYTES + 1);

        let error = export_logs_to(&output, "journal", &contents)
            .expect_err("oversized frontend content is refused");

        assert_eq!(error, "journal trop volumineux pour être exporté");
        assert!(!output.exists());
    }

    #[test]
    fn an_export_at_the_byte_limit_preserves_the_whole_log() {
        let scratch = Scratch::new();
        let contents = "é".repeat(MAX_LOG_EXPORT_BYTES / 2);
        assert_eq!(contents.len(), MAX_LOG_EXPORT_BYTES);

        let path = export_logs_to(&scratch.0, "valid", &contents).expect("exact-size export");

        assert_eq!(std::fs::read(path).unwrap(), contents.as_bytes());
    }

    #[test]
    fn rejects_text_over_the_byte_limit_even_with_fewer_characters() {
        let scratch = Scratch::new();
        let directory = scratch.0.join("oversize");
        let mut contents = "é".repeat(MAX_LOG_EXPORT_BYTES / 2);
        contents.push('x');

        let error = export_logs_to(&directory, "journal", &contents).unwrap_err();

        assert_eq!(error, "journal trop volumineux pour être exporté");
        assert!(!directory.exists());
    }

    #[test]
    fn an_export_creates_missing_destination_directories() {
        let scratch = Scratch::new();
        let directory = scratch.0.join("reports/orion");

        let path = export_logs_to(&directory, "journal", "one line\n").expect("nested export");

        assert_eq!(path, directory.join("journal.log"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "one line\n");
    }

    #[test]
    fn reports_an_unwritable_log_destination_as_a_write_failure() {
        let scratch = Scratch::new();
        let path = scratch.0.join("session.log");
        std::fs::create_dir(&path).expect("reserve the export name as a directory");

        let error = export_logs_to(&scratch.0, "../session", "text").unwrap_err();

        assert!(error.starts_with(&format!("écriture de {} : ", path.display())));
        assert!(path.is_dir());
    }

    #[test]
    fn exporting_with_the_same_name_replaces_the_previous_contents() {
        let scratch = Scratch::new();
        let path = export_logs_to(&scratch.0, "journal", "older, longer text").unwrap();

        let second = export_logs_to(&scratch.0, "journal", "new").unwrap();

        assert_eq!(second, path);
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
    }

    #[test]
    fn reports_export_directory_creation_failures() {
        let scratch = Scratch::new();
        let blocking_file = scratch.0.join("file");
        std::fs::write(&blocking_file, "not a directory").expect("create blocking file");

        let error = export_logs_to(&blocking_file.join("child"), "journal", "text")
            .expect_err("a file cannot be used as an export directory");

        assert!(error.starts_with("création de "));
    }
}

#[cfg(test)]
mod ipc_tests;
