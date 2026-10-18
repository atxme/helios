//! The Astra CA-TLS rotation and the operator ceremonies, driven from this
//! window and signed in the companion.

use super::*;

/// Opens the two-key CA-TLS ceremony described in ADR-008 §9.4.
///
/// Everything that decides anything happens in the companion: the campaign is
/// fetched and verified there, under the Astra service key the vault's
/// hand-off pins, and the two credentials are exercised there. This command
/// starts it and returns the first state it publishes.
#[tauri::command]
pub(crate) async fn start_astra_ca_tls_rotation(
    state: State<'_, AppState>,
    input: astra::RotationInput,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state.astra.start(input).await
}

/// Takes the next step, once the operator says the requested key is plugged in.
#[tauri::command]
pub(crate) async fn continue_astra_ca_tls_rotation(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state
        .astra
        .advance(aether::certificates::operator_ipc::AstraIpcCommand::Continue)
        .await
}

/// Abandons the ceremony, which only the phases before the first durable write
/// accept.
#[tauri::command]
pub(crate) async fn cancel_astra_ca_tls_rotation(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state
        .astra
        .advance(aether::certificates::operator_ipc::AstraIpcCommand::Cancel)
        .await
}

/// The ceremony's current state, for a view that was opened after it started.
#[tauri::command]
pub(crate) async fn astra_ca_tls_rotation_status(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    Ok(state.astra.status().await)
}

/// Opens an operator ceremony for the operation the WebView names.
///
/// The locator is all it may name — a kind, and at most an identifier this
/// process itself opened. Everything else the helper resolves from the hand-off
/// pinned beside the vault it holds.
#[tauri::command]
pub(crate) async fn begin_operator_ceremony(
    state: State<'_, AppState>,
    locator: aether::certificates::operator_session::OperationLocator,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state.operator.begin(locator).await
}

/// The handle of the window the press came from, or `0` where there is none.
///
/// Read on the exact advance that opens a key dialog, so Orion can re-assert
/// its own foreground right before ceding it to the helper. The click was
/// delivered to the WebView's renderer process, and Windows grants that right
/// to whoever received the last input — not to the process that owns the
/// window around it.
fn owner_window(window: &tauri::Window) -> isize {
    #[cfg(target_os = "windows")]
    {
        window.hwnd().map(|handle| handle.0 as isize).unwrap_or(0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = window;
        0
    }
}

/// Takes the next step, or abandons, against the status the operator saw.
///
/// The revision is not decoration: a press on a screen the helper has already
/// left is refused here and again there, rather than applied to whatever
/// replaced it.
#[tauri::command]
pub(crate) async fn advance_operator_ceremony(
    state: State<'_, AppState>,
    window: tauri::Window,
    action: aether::certificates::operator_session::OperatorAction,
    revision: u64,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state
        .operator
        .advance(action, revision, owner_window(&window))
        .await
}

/// Removes the final status once the operator has acknowledged it.
#[tauri::command]
pub(crate) async fn dismiss_operator_ceremony(state: State<'_, AppState>) -> Result<(), String> {
    state.operator.dismiss().await
}

/// Everything waiting for an operator, through the gateway of one profile.
///
/// The gateway rather than Astra's public origin, and the difference is the
/// access control: the origin serves a §7.5 recovery without a tunnel, so a
/// list there would be readable by anyone who can reach it. Recoveries are
/// absent from what comes back — Orion already holds the identifier of the
/// ones it opened, and nothing else may enumerate them.
///
/// An unreachable gateway returns an empty list rather than an error: this
/// runs on a timer behind a navigation rail, and a tunnel that is down is
/// «rien en attente», not a red banner.
#[tauri::command]
pub(crate) async fn operator_pending_operations(
    state: State<'_, AppState>,
) -> Result<Vec<orion_core::operator_pending::OperatorPendingOperation>, String> {
    let gateways: Vec<String> = {
        let cfg = state.config.lock().await;
        let mut seen: Vec<String> = Vec::new();
        for profile in &cfg.profiles {
            if let Some(url) = profile.heliosd_url.as_ref() {
                if !seen.iter().any(|held| held == url) {
                    seen.push(url.clone());
                }
            }
        }
        seen
    };
    let mut pending = Vec::new();
    for gateway in gateways {
        match orion_core::operator_pending::pending(&gateway).await {
            Ok(list) => pending.extend(list.operations),
            Err(error) => {
                tracing::debug!(%gateway, %error, "aucune opération lisible sur cette gateway")
            }
        }
    }
    Ok(pending)
}

/// The ceremony's current state, for a view opened after it started.
#[tauri::command]
pub(crate) async fn operator_ceremony_status(
    state: State<'_, AppState>,
) -> Result<Option<aether::certificates::operator_session::OperatorStatus>, String> {
    Ok(state.operator.status().await)
}
