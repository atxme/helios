//! The Astra CA-TLS rotation and the operator ceremonies, driven from this
//! window and signed in the companion.

use super::*;

use orion_engine::{ConfigView, EngineCommand, EngineReply};

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
/// process itself opened. Everything else is resolved from the hand-off pinned
/// beside the vault the ceremony holds.
#[tauri::command]
pub(crate) async fn begin_operator_ceremony(
    state: State<'_, AppState>,
    locator: aether::certificates::operator_session::OperationLocator,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state.operator.begin(locator).await
}

/// The handle of the window the press came from, or `0` where there is none.
///
/// It is the owner of the WebAuthn dialog a key opens, so that dialog appears
/// over the window the operator is looking at. Read on every advance: a press
/// that opens no dialog carries it unused.
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
/// The revision is not decoration: a press on a screen the ceremony has already
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
        let view = match state.client.call(EngineCommand::GetConfig).await? {
            EngineReply::Config(view) => view,
            _ => return Err(unexpected_engine_reply()),
        };
        let mut seen: Vec<String> = Vec::new();
        for profile in &view.profiles {
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

/// The operator vault and its trust domain, read without any key.
///
/// Nothing is unwrapped: the slots come back as identifier, label and role, and
/// the domain as the public values of the relay beside the vault. No PIN and no
/// security key are involved, so this is safe to call whenever the tab opens.
#[tauri::command]
pub(crate) async fn operator_overview() -> Result<astra_operator::overview::VaultOverview, String> {
    let path = astra_operator::store::default_path().map_err(|error| error.to_string())?;
    astra_operator::overview::read(&path).map_err(|error| error.to_string())
}

const NO_CONNECTED_GATEWAY: &str = "Connectez d'abord le profil de la gateway, avec un pair \
                                    administrateur : l'admission passe par le tunnel.";

/// The control-plane address the operator gestures reach the gateway at.
///
/// Read here, from the engine, and never taken from the WebView: the page names
/// a gesture, not the machine it is carried out against. The profile must be
/// the selected one and its tunnel up, because the admission rides the tunnel
/// and a gateway reached any other way would not be the one the operator
/// connected to.
// The admission gestures that call it arrive in the next tasks of the lot.
#[allow(dead_code)]
async fn connected_gateway(state: &AppState) -> Result<String, String> {
    let tunnel = match state.client.call(EngineCommand::GetState).await? {
        EngineReply::State(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    let view = match state.client.call(EngineCommand::GetConfig).await? {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    gateway_url(&tunnel, &view)
}

/// The decision of [`connected_gateway`], on what the engine answered.
fn gateway_url(state: &str, view: &ConfigView) -> Result<String, String> {
    if aether::TunnelState::parse(state) != Some(aether::TunnelState::Up) {
        return Err(NO_CONNECTED_GATEWAY.to_string());
    }
    view.selected
        .as_deref()
        .and_then(|name| view.profiles.iter().find(|profile| profile.name == name))
        .and_then(|profile| profile.heliosd_url.as_deref())
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .ok_or_else(|| NO_CONNECTED_GATEWAY.to_string())
}

#[cfg(test)]
mod tests;
