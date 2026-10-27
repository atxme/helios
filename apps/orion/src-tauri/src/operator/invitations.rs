//! The invitations of this machine's registry, as the Enrôlement screen lists
//! them, and their revocation.
//!
//! Nothing here opens the vault or asks for a key: the registry holds public
//! records and the state of each, and revoking is a write to that state alone.

use aether::certificates::encoding::Id16;
use astra_operator::enrollment::{InvitationRecord, InvitationRegistry, InvitationState};
use serde::Serialize;

/// One invitation, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvitationView {
    pub invitation_id: String,
    /// French label: « émise », « consommée », « révoquée » or « expirée ».
    pub state: String,
    pub not_after_unix: u64,
    /// The name the device asked for, known once Orion kept its acceptance.
    pub requested_name: Option<String>,
    /// Whether the device's WireGuard key is among the gateway's peers, or
    /// `None` when no connected gateway answered or the invitation has no
    /// device yet.
    pub peer_admitted: Option<bool>,
    /// An acceptance kept here can be resumed. The registry does not record
    /// whether the document was produced, so the screen cannot tell a
    /// finished acceptance from an interrupted one: it offers the resumption
    /// for every kept acceptance, and the ceremony itself skips what is done.
    pub resumable: bool,
}

/// Builds the views of `records`.
///
/// `kept` answers, for a consumed invitation, the requested name of the
/// acceptance kept here (`Ok(None)` for one accepted from the command line,
/// `Err` for a kept file that cannot be trusted, which is never resumable).
/// `admitted` is the gateway's peer keys, or `None` when it did not answer.
pub fn view_all(
    records: Vec<InvitationRecord>,
    kept: &dyn Fn(&InvitationRecord) -> Result<Option<String>, String>,
    admitted: Option<&[String]>,
) -> Vec<InvitationView> {
    records
        .into_iter()
        .map(|record| {
            let (requested_name, resumable, peer_admitted) = match &record.state {
                InvitationState::Consumed {
                    client_wg_public_key,
                    ..
                } => {
                    let kept = kept(&record).ok().flatten();
                    let device = client_wg_public_key.to_base64();
                    let peer =
                        admitted.map(|keys| keys.iter().any(|held| held.trim() == device.as_str()));
                    (kept.clone(), kept.is_some(), peer)
                }
                _ => (None, false, None),
            };
            InvitationView {
                invitation_id: record.invitation.invitation_id.to_hex(),
                state: record.state.label().to_string(),
                not_after_unix: record.invitation.not_after_unix,
                requested_name,
                peer_admitted,
                resumable,
            }
        })
        .collect()
}

/// Every invitation of the registry, lapsed ones marked expired first.
pub fn list(
    registry: &InvitationRegistry,
    now_unix: u64,
    admitted: Option<&[String]>,
) -> Result<Vec<InvitationView>, String> {
    let records = registry
        .list(now_unix)
        .map_err(|error| format!("{error:#}"))?;
    let kept = |record: &InvitationRecord| {
        registry
            .accepted(&record.invitation.invitation_id)
            .map(|found| found.map(|accepted| accepted.request.requested_name))
            .map_err(|error| format!("{error:#}"))
    };
    Ok(view_all(records, &kept, admitted))
}

/// Revokes an invitation still issued. No key: the registry refuses anything
/// else, and revoking destroys the invitation's proof key.
pub fn revoke(registry: &InvitationRegistry, id: &Id16, now_unix: u64) -> Result<(), String> {
    registry
        .revoke(id, now_unix)
        .map_err(|error| format!("{error:#}"))
}

#[cfg(test)]
mod tests;
