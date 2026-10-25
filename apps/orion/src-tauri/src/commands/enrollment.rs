//! Enrollment v5 (NEGOCIATION-DE-CLE-V5 §15): the invitation preview, the
//! request, and the pending enrollments the protected store holds.
//!
//! Nothing here returns private material. The three key pairs are generated
//! and sealed by `orion_core::enrollment`, and only the request — public —
//! comes back to the screen.

use super::*;

use orion_core::enrollment::PendingEnrollment;
use orion_engine::{EngineCommand, EngineReply, InvitationPreviewView};

#[tauri::command]
pub(crate) async fn preview_enrollment_invitation(
    state: State<'_, AppState>,
    contents: String,
) -> Result<InvitationPreviewView, String> {
    match state
        .client
        .call(EngineCommand::PreviewEnrollmentInvitation { contents })
        .await?
    {
        EngineReply::InvitationPreview(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Generates the keys once the fingerprint is confirmed, seals them, and
/// returns the content of the `.helios-request` to hand to the operator.
#[tauri::command]
pub(crate) async fn begin_enrollment(
    state: State<'_, AppState>,
    invitation: String,
    confirmed_ca_fingerprint: String,
    requested_name: String,
) -> Result<String, String> {
    match state
        .client
        .call(EngineCommand::BeginEnrollment {
            invitation,
            confirmed_ca_fingerprint,
            requested_name,
        })
        .await?
    {
        EngineReply::EnrollmentStarted(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn list_pending_enrollments(
    state: State<'_, AppState>,
) -> Result<Vec<PendingEnrollment>, String> {
    match state
        .client
        .call(EngineCommand::ListPendingEnrollments)
        .await?
    {
        EngineReply::PendingEnrollments(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// The `.helios-request` of a pending enrollment, again: public, as
/// `begin_enrollment` first returned it.
#[tauri::command]
pub(crate) async fn export_pending_request(
    state: State<'_, AppState>,
    request_id: String,
) -> Result<String, String> {
    match state
        .client
        .call(EngineCommand::ExportPendingRequest { request_id })
        .await?
    {
        EngineReply::RequestFile(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Abandons a pending enrollment: its three private keys are destroyed.
#[tauri::command]
pub(crate) async fn discard_pending_enrollment(
    state: State<'_, AppState>,
    request_id: String,
) -> Result<(), String> {
    match state
        .client
        .call(EngineCommand::DiscardPendingEnrollment { request_id })
        .await?
    {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}
