//! The enrollment family: the invitation preview, the request, and the pending
//! enrollments the protected store holds. The shell reaches them through the
//! engine.
//!
//! Nothing here returns private material. The three key pairs are generated
//! and sealed by `orion_core::enrollment`, and only the request — public —
//! comes back to the screen.

use orion_core::{enrollment::PendingEnrollment, ProtectedIdentityStore};

use super::certificates::now_unix;
use super::EngineService;
use crate::view::InvitationPreviewView;

pub fn invitation_preview_view(bytes: &[u8], now: u64) -> Result<InvitationPreviewView, String> {
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

fn parse_request_id(value: &str) -> Result<aether::certificates::encoding::Id16, String> {
    aether::certificates::encoding::Id16::parse_hex(value.trim())
        .map_err(|_| "identifiant de demande : 32 caractères hexadécimaux attendus".to_string())
}

impl EngineService {
    pub fn preview_enrollment_invitation(
        &self,
        contents: &str,
    ) -> Result<InvitationPreviewView, String> {
        invitation_preview_view(contents.as_bytes(), now_unix())
    }

    /// Generates the keys once the fingerprint is confirmed, seals them, and
    /// returns the content of the `.helios-request` to hand to the operator.
    pub fn begin_enrollment(
        &self,
        invitation: &str,
        confirmed_ca_fingerprint: &str,
        requested_name: &str,
    ) -> Result<String, String> {
        let now = now_unix();
        let preview = orion_core::enrollment::preview_invitation(invitation.as_bytes(), now)
            .map_err(|error| format!("{error:#}"))?;
        let (_, request) = orion_core::enrollment::begin_enrollment(
            &protected_store()?,
            &preview.invitation,
            confirmed_ca_fingerprint,
            requested_name,
            now,
        )
        .map_err(|error| format!("{error:#}"))?;
        Ok(request)
    }

    pub fn list_pending_enrollments(&self) -> Result<Vec<PendingEnrollment>, String> {
        orion_core::enrollment::pending_enrollments(&protected_store()?)
            .map_err(|error| format!("{error:#}"))
    }

    /// The `.helios-request` of a pending enrollment, again: public, as
    /// `begin_enrollment` first returned it.
    pub fn export_pending_request(&self, request_id: &str) -> Result<String, String> {
        let request_id = parse_request_id(request_id)?;
        orion_core::enrollment::pending_request_file(&protected_store()?, &request_id)
            .map_err(|error| format!("{error:#}"))
    }

    /// Abandons a pending enrollment: its three private keys are destroyed.
    pub fn discard_pending_enrollment(&self, request_id: &str) -> Result<(), String> {
        let request_id = parse_request_id(request_id)?;
        orion_core::enrollment::discard_enrollment(&protected_store()?, &request_id)
            .map_err(|error| format!("{error:#}"))
    }
}
