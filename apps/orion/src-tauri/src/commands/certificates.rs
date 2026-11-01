//! Certificates: inventory and overview, the actions on them, automatic
//! renewal and trust refresh, recovery, and the operator's approval.

use super::*;

use aether_fido::authenticator::connect_owned;
use orion_core::certificate_approval::ApprovalError;
use orion_engine::{
    ActionOutcome, EngineCommand, EngineReply, ProfileCertificates, RenewalProgress,
    SubmittedApproval,
};
use zeroize::Zeroizing;

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

/// Runs the key ceremony in this process and hands the assertion to the engine
/// (spec §6.1).
///
/// The engine gives back public material only. The key is opened here, over
/// this window, on a blocking thread, and the PIN never leaves this process:
/// it is neither logged nor sent to the engine. The engine consumes the
/// verified request only when the assertion is submitted, so a failed attempt
/// can be retried.
#[tauri::command]
pub(crate) async fn approve_certificate_renewal(
    window: tauri::Window,
    state: State<'_, AppState>,
    name: String,
    pin: Option<String>,
) -> Result<RenewalProgress, String> {
    let owner = crate::operator::dialog_owner(ceremonies::owner_window(&window))?;
    let material = match state
        .client
        .call(EngineCommand::CertificateApprovalMaterial { name: name.clone() })
        .await?
    {
        EngineReply::ApprovalMaterial(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    let pin = Zeroizing::new(pin.unwrap_or_default());
    let approval = tauri::async_runtime::spawn_blocking(move || {
        let key = connect_owned(orion_core::certificate_approval::transport(), owner)
            .map_err(|_| ApprovalError::NoAuthenticator.to_string())?;
        material
            .approve(key.as_ref(), &pin, crate::operator::now_unix())
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "la cérémonie de la clé s'est interrompue".to_string())??;
    match state
        .client
        .call(EngineCommand::SubmitCertificateApproval {
            name,
            approval: SubmittedApproval::new(approval),
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
    window: tauri::Window,
    name: String,
) -> Result<bool, String> {
    let _ = name;
    let owner = crate::operator::dialog_owner(ceremonies::owner_window(&window))?;
    tauri::async_runtime::spawn_blocking(move || {
        connect_owned(orion_core::certificate_approval::transport(), owner)
            .map(|key| key.needs_pin())
            .map_err(|_| ApprovalError::NoAuthenticator.to_string())
    })
    .await
    .map_err(|_| "la cérémonie de la clé s'est interrompue".to_string())?
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
