//! Revoking one workstation through Astra's door (spec §5.2 to §5.7, lot 5c).
//!
//! # Why the anchor is chosen before the campaign
//!
//! Astra checks a revocation under the anchor it serves, and during a `CA-PQ`
//! overlap that is the outgoing one. [`open`] therefore reads Astra's anchor,
//! picks the `CA-PQ` that matches it ([`revocation_anchor`]), and verifies the
//! credential document under that same key before a campaign exists. A campaign
//! blocks its family for five minutes, so nothing that can be refused by this
//! machine is left to be refused after it.
//!
//! # Why a key is approved before it opens the vault
//!
//! The approval names one credential, and the opening must come from that same
//! credential. [`OpenedRevocation::approve`] takes the assertion first and opens
//! the vault with that key only when the assertion is accepted for it, so a key
//! that declines loses nothing and can answer again.
//!
//! # Why the decision is recorded before the deposit
//!
//! [`OpenedRevocation::sign_and_record`] writes `pending-revocation.json` before
//! anything leaves. A deposit that loses its answer is then replayed with the same
//! bytes and no key. The record holds the signed public object and the campaign's
//! identifiers, and no token: a deposit asks the campaign again for a fresh one.

use std::path::Path;

use aether::certificates::encoding::{Id16, MlDsa87PublicKey, WireGuardKey};
use aether::certificates::revocation::{RevocationReason, RevocationScope};
use aether::certificates::status::AstraSignerResult;
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorOpenAction, OperatorOpenRequest, OperatorOpened,
    SigningOperationState, TrustUpdateObject,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::authenticator::{Authenticator, Opened};
use crate::credentials;
use crate::gestures;
use crate::handoff::{self, DomainHandoff};
use crate::operations::campaign_result;
use crate::operations::keys::{key_step_of_opening, KeyStep, ValidatedKeys, NO_PIN};
use crate::operations::rotation::ensure_same_vault;
use crate::origin::CampaignRequest;
use crate::signing::{
    revocation_anchor, sign_revocation, CampaignApprovalSession, DomainIdentity, RevocationAnchor,
    RevocationAnchorRefusal, RevocationDecision,
};
use crate::tunnel::{is_unreachable, Tunnel, TunnelRefusal};

/// The name of the record, beside the vault.
const PENDING_FILE: &str = "pending-revocation.json";

/// The window of the campaign, as the door opens it (spec §7.6).
const CAMPAIGN_WINDOW_SECS: u64 = 300;

/// What the campaign's text names as the requester: the console, not a person.
const REQUESTED_BY: &str = "Orion";

/// The reasons the operator picks, and the aether reason each one signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReasonChoice {
    /// « Volé ou perdu »: `suspected_compromise`.
    StolenOrLost,
    /// « Compromis »: `key_compromise`.
    Compromised,
    /// « Plus utilisé »: `cessation`.
    NoLongerUsed,
    /// « Remplacé »: `superseded`.
    Replaced,
}

impl RevocationReasonChoice {
    fn reason(self) -> RevocationReason {
        match self {
            Self::StolenOrLost => RevocationReason::SuspectedCompromise,
            Self::Compromised => RevocationReason::KeyCompromise,
            Self::NoLongerUsed => RevocationReason::Cessation,
            Self::Replaced => RevocationReason::Superseded,
        }
    }

    /// The text the campaign carries, which the operator reads on the door's screen.
    fn label(self) -> &'static str {
        match self {
            Self::StolenOrLost => "Volé ou perdu",
            Self::Compromised => "Compromis",
            Self::NoLongerUsed => "Plus utilisé",
            Self::Replaced => "Remplacé",
        }
    }
}

/// What the revocation needs from the far side of the tunnel.
pub trait RevocationRemote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened>;
    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest>;
    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState>;
    fn authority_status(&self) -> Result<OperatorAuthorityStatus>;
    /// When the outgoing `CA-PQ` stops being accepted, while an overlap runs.
    fn overlap_not_after(&self) -> Result<Option<u64>>;
}

impl RevocationRemote for Tunnel {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        Tunnel::open_campaign(self, request)
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        Tunnel::fetch_campaign(self, operation_id)
    }

    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        Tunnel::submit_campaign(self, operation_id, result_token, result)
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        Tunnel::authority_status(self)
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        Tunnel::gateway_overlap_not_after(self)
    }
}

/// Why no revocation was opened, or why it cannot be signed. Nothing was signed in
/// any of these cases, and nothing was touched for the ones before a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationRefusal {
    #[error("ce poste est déjà révoqué chez Astra. Rien n'a été signé.")]
    AlreadyRevoked,
    #[error("une révocation de ce poste attend déjà. Reprendre celle-ci.")]
    AlreadyPending,
    /// Astra refuses to open a revocation for a key it does not know.
    #[error("Astra ne connaît pas ce poste. Rien n'a été signé.")]
    PeerUnknown,
    /// The `CA-PQ` Astra checks is the outgoing one, and it may be signed under only
    /// until the margin before its retirement.
    #[error("révocation possible après le {}", utc_label(*.0))]
    NotBefore(u64),
    #[error("Astra vérifie sous une ancre que ce coffre ne détient pas. Rien n'a été signé.")]
    UnknownAnchor,
    #[error(
        "le document de credentials ne se vérifie pas sous l'ancre à signer. Rien n'a été signé."
    )]
    CredentialsUnverified,
    #[error("la campagne d'Astra ne nomme pas ce poste. Rien n'a été signé.")]
    CampaignMismatch,
    #[error("Astra injoignable. Rien n'a été signé.")]
    Unreachable,
    #[error("{0}")]
    Internal(String),
}

/// A UTC instant, for the refusal that names when signing becomes possible.
fn utc_label(at: u64) -> String {
    match i64::try_from(at)
        .ok()
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
    {
        Some(instant) => format!(
            "{:02}/{:02} à {:02}:{:02} UTC",
            instant.day(),
            instant.month() as u8,
            instant.hour(),
            instant.minute()
        ),
        None => format!("{at} (horodatage hors bornes)"),
    }
}

/// What a deposit found Astra holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationDeposit {
    /// Astra recorded the decision now.
    Accepted,
    /// Astra had already recorded it, so the answer was lost and not the decision.
    AlreadyRevoked,
}

/// A decision signed under the anchor Astra checks, with the approval that
/// authorizes it. Public: it crosses to Astra as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocation {
    pub operation_id: Id16,
    pub campaign_id: Id16,
    pub expires_at: u64,
    pub result: AstraSignerResult,
}

impl SignedRevocation {
    /// The workstation this decision revokes.
    fn peer(&self) -> Result<WireGuardKey> {
        match self.result.objects.first() {
            Some(TrustUpdateObject::CertificateRevocation(revocation)) => {
                Ok(revocation.identity_key)
            }
            _ => bail!("la décision enregistrée ne contient pas de révocation"),
        }
    }
}

/// A verified campaign, the anchor it is checked under, and the session its
/// approvals go into.
pub struct OpenedRevocation {
    keys: ValidatedKeys,
    request: Box<CampaignRequest>,
    anchor: RevocationAnchor,
    /// The identity as the anchor names it: the epoch of the `CA-PQ` that signs.
    identity: DomainIdentity,
    anchor_key: MlDsa87PublicKey,
    tls_not_after: u64,
    pq_not_after: u64,
    reason: RevocationReason,
    approval: CampaignApprovalSession,
    subject: String,
}

/// Opens the revocation of `peer`, or refuses it. Nothing before the last step
/// asks for a key.
pub fn open(
    remote: &dyn RevocationRemote,
    vault_path: &Path,
    peer: &WireGuardKey,
    reason: RevocationReasonChoice,
    now: u64,
) -> Result<OpenedRevocation, RevocationRefusal> {
    let mut authority = remote.authority_status().map_err(unreachable_or_internal)?;
    if authority.revoked_peers.contains(peer) {
        return Err(RevocationRefusal::AlreadyRevoked);
    }
    if pending(vault_path, now).map_err(internal)?.is_some() {
        return Err(RevocationRefusal::AlreadyPending);
    }

    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let overlap = remote
        .overlap_not_after()
        .map_err(unreachable_or_internal)?;
    let anchor = revocation_anchor(
        vault,
        &authority.ca_fingerprint,
        authority.ca_epoch,
        identity.ca_epoch,
        overlap,
        now,
    )
    .map_err(|refusal| match refusal {
        RevocationAnchorRefusal::NotBefore(at) => RevocationRefusal::NotBefore(at),
        RevocationAnchorRefusal::UnknownAnchor => RevocationRefusal::UnknownAnchor,
    })?;

    // The key and the epoch that the anchor names, which are the ones checked.
    let (anchor_key, anchor_identity) = match anchor {
        RevocationAnchor::Current => (
            MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).map_err(internal)?,
            identity.clone(),
        ),
        RevocationAnchor::Outgoing => {
            let (key, ca_epoch, _) = vault.retained_outgoing_ca_pq_public().ok_or_else(|| {
                RevocationRefusal::Internal("aucune CA-PQ sortante gardée".into())
            })?;
            (
                key,
                DomainIdentity {
                    ca_epoch,
                    ..identity.clone()
                },
            )
        }
    };

    // The document the approval is checked against: the one Astra serves under the
    // outgoing anchor, and the local one under the current anchor.
    let document = match anchor {
        RevocationAnchor::Current => credentials::load(&credentials::path_beside(vault_path))
            .map_err(internal)?
            .ok_or(RevocationRefusal::CredentialsUnverified)?,
        RevocationAnchor::Outgoing => authority
            .served_credentials
            .take()
            .map(|served| *served)
            .ok_or(RevocationRefusal::CredentialsUnverified)?,
    };
    document
        .verify(
            &anchor_key,
            &anchor_identity.trust_domain_id,
            &anchor_identity.gateway_wg_public_key,
            anchor_identity.ca_epoch,
            document.credential_registry_epoch,
        )
        .map_err(|_| RevocationRefusal::CredentialsUnverified)?;

    let opened = remote
        .open_campaign(&OperatorOpenRequest {
            action: OperatorOpenAction::ClientRevocation { peer: *peer },
            reason: reason.label().to_string(),
            requested_by: REQUESTED_BY.to_string(),
            window_secs: CAMPAIGN_WINDOW_SECS,
        })
        .map_err(|error| match error.downcast_ref::<TunnelRefusal>() {
            // The door answers an unknown peer with its coarse refusal, and the
            // wire carries nothing finer: a 403 here is read as that refusal.
            Some(refusal) if refusal.status == 403 => RevocationRefusal::PeerUnknown,
            _ => unreachable_or_internal(error),
        })?;
    let (Some(tls_not_after), Some(pq_not_after)) = opened
        .revocation_expiries
        .map(|expiries| (expiries.tls_not_after, expiries.pq_not_after))
        .unwrap_or((None, None))
    else {
        return Err(RevocationRefusal::Internal(
            "Astra n'a pas donné l'échéance des deux feuilles de ce poste : rien n'a été signé."
                .into(),
        ));
    };

    let request = remote
        .fetch_campaign(&opened.operation_id)
        .map_err(unreachable_or_internal)?;
    let authority_url = relay
        .astra_authority_url
        .clone()
        .ok_or_else(|| RevocationRefusal::Internal("l'origine de l'autorité est absente".into()))?;
    handoff::verify_campaign_request(&relay, vault, &request, &authority_url, now)
        .map_err(internal)?;
    let campaign = request.campaign.as_ref();
    let [target] = campaign.targets.as_slice() else {
        return Err(RevocationRefusal::CampaignMismatch);
    };
    if !campaign.scope.revokes() || target.identity_key != *peer {
        return Err(RevocationRefusal::CampaignMismatch);
    }

    let approval = CampaignApprovalSession::new(
        campaign,
        &document,
        &anchor_identity,
        &anchor_key,
        &vault.rp_id,
        &format!("https://{}", vault.rp_id),
        now,
    )
    .map_err(internal)?;
    let subject = target.identity_key.to_base64();
    Ok(OpenedRevocation {
        keys,
        request: Box::new(request),
        anchor,
        identity: anchor_identity,
        anchor_key,
        tls_not_after,
        pq_not_after,
        reason: reason.reason(),
        approval,
        subject,
    })
}

impl OpenedRevocation {
    /// The workstation the campaign names, as the campaign carries it.
    pub fn subject_name(&self) -> &str {
        &self.subject
    }

    /// The credentials that must answer.
    pub fn required_credentials(&self) -> u8 {
        self.request.campaign.required_credentials
    }

    /// The active credentials of the chosen document that have not answered yet.
    pub fn offered(&self) -> Vec<Vec<u8>> {
        self.approval.offered_credentials()
    }

    /// One key: its approval, then the proof that the same key opens the vault.
    ///
    /// Two touches, in that order. A refusal at either one loses nothing, and the
    /// same or another key can answer again.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        if now >= self.request.campaign.expires_at {
            // A dead campaign has no use for the openings, and they must not wait on
            // the caller dropping this value.
            self.keys.openings.clear();
            return Err(KeyStep::Expired);
        }
        let offered = self.offered();
        if offered.is_empty() {
            return Err(KeyStep::Repeated);
        }
        let assertion = key
            .approve(
                self.approval.webauthn_rp_id(),
                &offered,
                self.approval.client_data_json(),
                NO_PIN,
            )
            .map_err(|error| match error {
                crate::authenticator::AuthenticatorError::UnknownCredential => {
                    KeyStep::NotValidated
                }
                _ => KeyStep::Declined,
            })?;
        let credential_id = assertion.credential_id.clone();
        if !offered.contains(&credential_id) {
            return Err(KeyStep::NotApprovable);
        }
        let opened: Opened =
            gestures::open_with_credential(key, &self.keys.vault, &credential_id, NO_PIN)
                .map_err(key_step_of_opening)?;
        let label = self.keys.keep(opened)?;
        self.approval
            .accept_for(assertion, Some(&credential_id), now)
            .map_err(|_| KeyStep::NotValidated)?;
        Ok(label)
    }

    /// Signs the decision under the anchor Astra checks, and records it before any
    /// deposit. Moves nothing else.
    pub fn sign_and_record(self, vault_path: &Path, now: u64) -> Result<SignedRevocation> {
        let Self {
            keys,
            request,
            anchor,
            identity,
            anchor_key,
            tls_not_after,
            pq_not_after,
            reason,
            approval,
            ..
        } = self;
        if now >= request.campaign.expires_at || keys.openings.is_empty() {
            return Err(KeyStep::Expired.into());
        }
        ensure_same_vault(vault_path, &keys.vault)?;
        let approval = approval.finish(now)?;

        let campaign = request.campaign.as_ref();
        // Checked by `open`: one target, which is the peer's.
        let target = &campaign.targets[0];
        let ValidatedKeys {
            vault, openings, ..
        } = keys;
        let decision = RevocationDecision {
            scope: RevocationScope::Client,
            identity_key: target.identity_key,
            server_name: None,
            revocation_epoch: target
                .epoch
                .checked_add(1)
                .context("époque de révocation hors bornes")?,
            revoked_tls: Some((target.active_tls_certificate_fingerprint, tls_not_after)),
            revoked_pq: Some((target.active_pq_certificate_fingerprint, pq_not_after)),
            effective_at: now,
            reason,
            replacement_transition_fingerprint: None,
        };
        let revocation = sign_revocation(
            &vault,
            &openings[0],
            &identity,
            &anchor_key,
            &decision,
            target.epoch,
            anchor,
        )?;
        campaign
            .covers_revocation(&revocation)
            .context("la révocation signée ne correspond pas à la campagne approuvée")?;

        let signed = SignedRevocation {
            operation_id: request.operation_id,
            campaign_id: campaign.campaign_id,
            expires_at: campaign.expires_at,
            result: campaign_result(
                &approval,
                vec![TrustUpdateObject::CertificateRevocation(Box::new(
                    revocation,
                ))],
                None,
            ),
        };
        save(&record_path(vault_path), &signed)?;
        Ok(signed)
    }
}

/// Sends the recorded decision, and clears the record once Astra holds it.
///
/// A lost answer is replayed with the same bytes and no key: the campaign is asked
/// again for a fresh token, and Astra treats the identical result as the same one.
pub fn deposit(
    remote: &dyn RevocationRemote,
    vault_path: &Path,
    signed: &SignedRevocation,
) -> Result<RevocationDeposit> {
    let peer = signed.peer()?;
    if remote.authority_status()?.revoked_peers.contains(&peer) {
        clear(vault_path)?;
        return Ok(RevocationDeposit::AlreadyRevoked);
    }
    let request = remote.fetch_campaign(&signed.operation_id)?;
    if request.campaign.campaign_id != signed.campaign_id {
        bail!("la campagne relue n'est pas celle de la décision enregistrée");
    }
    match remote.submit_campaign(&signed.operation_id, &request.result_token, &signed.result) {
        Ok(SigningOperationState::Approved) => {
            clear(vault_path)?;
            Ok(RevocationDeposit::Accepted)
        }
        Ok(SigningOperationState::AwaitingOperator) => {
            bail!("Astra n'a pas enregistré ce dépôt")
        }
        // A refusal can mean the decision is already recorded, and the answer alone
        // was lost: the domain's word on it is the state, read again.
        Err(error)
            if matches!(
                error.downcast_ref::<TunnelRefusal>(),
                Some(TunnelRefusal {
                    status: 403 | 409,
                    ..
                })
            ) && remote.authority_status()?.revoked_peers.contains(&peer) =>
        {
            clear(vault_path)?;
            Ok(RevocationDeposit::AlreadyRevoked)
        }
        Err(error) => Err(error),
    }
}

/// The recorded decision, if one is waiting. A record whose campaign has expired is
/// discarded: an expired campaign cannot take it.
pub fn pending(vault_path: &Path, now: u64) -> Result<Option<SignedRevocation>> {
    let path = record_path(vault_path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("lecture de {}", path.display())),
    };
    let signed: SignedRevocation = serde_json::from_slice(&bytes)
        .with_context(|| format!("lecture de la révocation en attente {}", path.display()))?;
    if now >= signed.expires_at {
        clear(vault_path)?;
        return Ok(None);
    }
    Ok(Some(signed))
}

fn record_path(vault_path: &Path) -> std::path::PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(PENDING_FILE)
}

/// Writes the record, atomically and privately, like the rotation journal.
fn save(path: &Path, signed: &SignedRevocation) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(signed).context("sérialisation de la révocation")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

/// Removes the record. Already gone is success.
fn clear(vault_path: &Path) -> Result<()> {
    let path = record_path(vault_path);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("suppression de {}", path.display())),
    }
}

/// A call that failed for want of an answer is `Unreachable`; a gateway answer of
/// 503 says the same about Astra behind it. Anything else is a failure to name.
fn unreachable_or_internal(error: anyhow::Error) -> RevocationRefusal {
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refusal) if refusal.status == 503 => RevocationRefusal::Unreachable,
        _ if is_unreachable(&error) => RevocationRefusal::Unreachable,
        _ => RevocationRefusal::Internal(format!("{error:#}")),
    }
}

fn internal<E: Into<anyhow::Error>>(error: E) -> RevocationRefusal {
    RevocationRefusal::Internal(format!("{:#}", error.into()))
}

#[cfg(test)]
mod tests;
