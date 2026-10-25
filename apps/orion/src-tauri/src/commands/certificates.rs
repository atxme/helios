//! Certificates: inventory and overview, the actions on them, automatic
//! renewal and trust refresh, recovery, and the operator's approval.

use super::*;

use orion_engine::{
    ActionOutcome, EngineCommand, EngineReply, ProfileCertificates, RenewalProgress, SecretInput,
};

/// The four certificates a connection depends on, with their dates.
///
/// Read by the engine, which owns the protected identity store and the
/// validator the negotiation uses. See `orion_engine::service::certificates`.
#[tauri::command]
pub(crate) async fn certificate_inventory(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Result<orion_core::CertificateInventory, String> {
    match state
        .client
        .call(EngineCommand::CertificateInventory { key_negotiation })
        .await?
    {
        EngineReply::CertificateInventory(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn certificate_overview(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileCertificates>, String> {
    match state
        .client
        .call(EngineCommand::CertificateOverview)
        .await?
    {
        EngineReply::CertificateOverview(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// State of the four certificate actions of spec §12.2, for one profile.
#[tauri::command]
pub(crate) async fn certificate_actions(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Result<Vec<orion_core::CertificateActionState>, String> {
    match state
        .client
        .call(EngineCommand::CertificateActions { key_negotiation })
        .await?
    {
        EngineReply::CertificateActions(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Runs one of the four actions, or reports why it cannot run.
#[tauri::command]
pub(crate) async fn run_certificate_action(
    state: State<'_, AppState>,
    name: String,
    action: orion_core::CertificateAction,
) -> Result<ActionOutcome, String> {
    match state
        .client
        .call(EngineCommand::RunCertificateAction { name, action })
        .await?
    {
        EngineReply::ActionOutcome(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Resumes the recovery whose operator ceremony has just released its grant.
#[tauri::command]
pub(crate) async fn resume_certificate_recovery(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<ActionOutcome, String> {
    match state
        .client
        .call(EngineCommand::ResumeCertificateRecovery { operation_id })
        .await?
    {
        EngineReply::ActionOutcome(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Launches the companion for the operation held by one renewal session.
///
/// Only the profile name crosses IPC. The arguments come from the session the
/// engine owns, and the executable is fixed in `companion`, so the WebView
/// cannot turn this permission into a shell or retarget an approval to another
/// operation.
#[tauri::command]
pub(crate) async fn launch_certificate_companion(
    state: State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let arguments = match state
        .client
        .call(EngineCommand::CompanionArguments { name })
        .await?
    {
        EngineReply::CompanionArguments(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    companion::launch(&arguments)
}

pub(crate) fn companion_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("companion")
        .invoke_handler(tauri::generate_handler![launch_certificate_companion])
        .build()
}

/// Reads the approval request the open renewal is waiting on (§8.1.2 step 4a).
///
/// The engine verifies it against what the profile pins before it comes back.
#[tauri::command]
pub(crate) async fn certificate_approval_manifest(
    state: State<'_, AppState>,
    name: String,
) -> Result<orion_core::certificate_approval::ApprovalManifest, String> {
    match state
        .client
        .call(EngineCommand::CertificateApprovalManifest { name })
        .await?
    {
        EngineReply::ApprovalManifest(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Runs the ceremony and posts the assertion (§8.1.2 step 4b).
///
/// The engine runs the ceremony on a blocking thread and consumes the verified
/// request. The PIN crosses IPC once, here, and goes straight to the engine.
#[tauri::command]
pub(crate) async fn approve_certificate_renewal(
    state: State<'_, AppState>,
    name: String,
    pin: Option<String>,
) -> Result<RenewalProgress, String> {
    match state
        .client
        .call(EngineCommand::ApproveCertificateRenewal {
            name,
            pin: pin.map(SecretInput::from),
        })
        .await?
    {
        EngineReply::RenewalProgress(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Whether this machine's key collects its own PIN.
///
/// Asked rather than assumed: under Windows the platform API puts up its own
/// dialog and the PIN never enters this process, so prompting for one would be
/// asking the user for a secret Orion has no use for.
#[tauri::command]
pub(crate) async fn certificate_approval_needs_pin(
    state: State<'_, AppState>,
    name: String,
) -> Result<bool, String> {
    match state
        .client
        .call(EngineCommand::CertificateApprovalNeedsPin { name })
        .await?
    {
        EngineReply::Flag(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// The last certificate action that failed on this profile, if any.
#[tauri::command]
pub(crate) async fn last_certificate_error(
    state: State<'_, AppState>,
    name: String,
) -> Result<Option<String>, String> {
    match state
        .client
        .call(EngineCommand::LastCertificateError { name })
        .await?
    {
        EngineReply::LastError(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}
