//! The tunnel: connecting, disconnecting and renewing the PSK on request.
//!
//! The engine does the work. These commands forward to it, and the
//! notification-area selection stays here until the profiles move.

use super::*;
use orion_engine::{EngineCommand, EngineReply};

#[tauri::command]
pub(crate) async fn connect(
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<(), String> {
    match state.client.call(EngineCommand::Connect { name }).await? {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Selects a profile, then connects to it — the two gestures the notification
/// area couples into one click.
///
/// Selecting first is not cosmetic: the connection reads the selected profile
/// when no name is given, and every screen derives what it shows from it. A
/// tray click that connected without selecting would leave the window
/// displaying one profile while the tunnel carried another.
///
/// Only the notification-area menu calls it, so outside Windows nothing does.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) async fn select_and_connect(app: &AppHandle, name: &str) -> Result<(), String> {
    {
        let state = app.state::<AppState>();
        let mut config = state.engine.config.lock().await;
        if config.find(name).is_none() {
            return Err(format!("profil « {name} » introuvable"));
        }
        state
            .engine
            .store
            .select(name)
            .map_err(|error| error.to_string())?;
        config.selected = Some(name.to_string());
    }
    // The window may be open behind the menu: it reads its profile list from
    // Rust, and nothing else would tell it the selection just moved.
    let _ = app.emit("helios://config-changed", ());
    let state = app.state::<AppState>();
    match state
        .client
        .call(EngineCommand::Connect {
            name: Some(name.to_string()),
        })
        .await?
    {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn disconnect(app: AppHandle) -> Result<(), String> {
    stop_connection(&app).await
}

/// Renews the ML-KEM PSK now, through the tunnel (design 2026-10-09).
///
/// Returns once the renewal is started: it runs in the background and reports
/// its outcome on the event stream, like the scheduled one.
#[tauri::command]
pub(crate) async fn renew_psk(state: State<'_, AppState>) -> Result<(), String> {
    match state.client.call(EngineCommand::RenewPsk).await? {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Unmounts the tunnel. Shared by the `disconnect` command, the tray menu and
/// the deletion of the mounted profile: each of them asks the engine, so none
/// can leave a tunnel behind that the others think is gone.
pub(crate) async fn stop_connection(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    match state.client.call(EngineCommand::Disconnect).await? {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}
