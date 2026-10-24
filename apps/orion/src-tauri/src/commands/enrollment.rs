//! Enrollment v5 (NEGOCIATION-DE-CLE-V5 §15): the invitation preview, the
//! request, and the pending enrollments the protected store holds.
//!
//! Nothing here returns private material. The three key pairs are generated
//! and sealed by `orion_core::enrollment`, and only the request — public —
//! comes back to the screen.

use super::*;

use orion_core::enrollment::PendingEnrollment;

/// What the screen shows of an invitation before the user confirms it.
#[derive(Debug, serde::Serialize)]
pub(crate) struct InvitationPreviewView {
    pub(crate) server_name: String,
    /// The `CA-PQ` fingerprint, in groups of four, to compare with what the
    /// operator reads out.
    pub(crate) ca_fingerprint: String,
    pub(crate) expires_at_unix: u64,
    /// The invitation text, returned as received: the confirmation call sends
    /// it back, so the backend keeps no state between the two.
    pub(crate) invitation_token: String,
}

pub(crate) fn invitation_preview_view(
    bytes: &[u8],
    now: u64,
) -> Result<InvitationPreviewView, String> {
    let preview = orion_core::enrollment::preview_invitation(bytes, now)
        .map_err(|error| format!("{error:#}"))?;
    Ok(InvitationPreviewView {
        server_name: preview.server_name,
        ca_fingerprint: preview.ca_fingerprint,
        expires_at_unix: preview.expires_at_unix,
        invitation_token: aether::key_negotiation::encode_invitation_file(&preview.invitation),
    })
}

fn protected_store() -> Result<ProtectedIdentityStore, String> {
    ProtectedIdentityStore::for_current_user().map_err(|error| format!("{error:#}"))
}

#[tauri::command]
pub(crate) async fn preview_enrollment_invitation(
    contents: String,
) -> Result<InvitationPreviewView, String> {
    invitation_preview_view(contents.as_bytes(), now_unix())
}

/// Generates the keys once the fingerprint is confirmed, seals them, and
/// returns the content of the `.helios-request` to hand to the operator.
#[tauri::command]
pub(crate) async fn begin_enrollment(
    invitation: String,
    confirmed_ca_fingerprint: String,
    requested_name: String,
) -> Result<String, String> {
    let now = now_unix();
    let preview = orion_core::enrollment::preview_invitation(invitation.as_bytes(), now)
        .map_err(|error| format!("{error:#}"))?;
    let (_, request) = orion_core::enrollment::begin_enrollment(
        &protected_store()?,
        &preview.invitation,
        &confirmed_ca_fingerprint,
        &requested_name,
        now,
    )
    .map_err(|error| format!("{error:#}"))?;
    Ok(request)
}

#[tauri::command]
pub(crate) async fn list_pending_enrollments() -> Result<Vec<PendingEnrollment>, String> {
    orion_core::enrollment::pending_enrollments(&protected_store()?)
        .map_err(|error| format!("{error:#}"))
}

/// The `.helios-request` of a pending enrollment, again: public, as
/// `begin_enrollment` first returned it.
#[tauri::command]
pub(crate) async fn export_pending_request(request_id: String) -> Result<String, String> {
    let request_id = parse_request_id(&request_id)?;
    orion_core::enrollment::pending_request_file(&protected_store()?, &request_id)
        .map_err(|error| format!("{error:#}"))
}

fn parse_request_id(value: &str) -> Result<aether::certificates::encoding::Id16, String> {
    aether::certificates::encoding::Id16::parse_hex(value.trim())
        .map_err(|_| "identifiant de demande : 32 caractères hexadécimaux attendus".to_string())
}

/// Abandons a pending enrollment: its three private keys are destroyed.
#[tauri::command]
pub(crate) async fn discard_pending_enrollment(request_id: String) -> Result<(), String> {
    let request_id = parse_request_id(&request_id)?;
    orion_core::enrollment::discard_enrollment(&protected_store()?, &request_id)
        .map_err(|error| format!("{error:#}"))
}
