//! Revoking the gateway's identity, with or without its emergency replacement (spec §7.1,
//! lot 6b).
//!
//! # Why the replacement is deposited before the revocation is signed
//!
//! Astra consumes one gateway campaign by its deposit before the next one opens (§7.1,
//! step 2). So the replacement is signed and recorded first, deposited with no key, and only
//! then is the revocation's campaign opened and signed. The revocation names the replacement's
//! fingerprint, read from the signed transition and not typed.
//!
//! # Why the record is written before the first deposit
//!
//! [`OpenedGatewayRevocation::sign_and_record`] writes `pending-gateway-revocation.json` as soon
//! as the replacement is signed. A lost deposit is replayed with the same bytes and no key. The
//! revocation joins the record once it is signed, and a step that needs a key says so.
//!
//! # Why the revocation is applied before the replacement is installed
//!
//! The gateway takes an emergency replacement only for a revoked identity awaiting exactly that
//! document (`state/gateway_identity.rs`, `install_transition`). [`carry_revocation`] keeps the
//! same order, so a refusal of the installation says why.
//!
//! # Which anchor each part is checked under
//!
//! The revocation follows the lot 5c rule ([`select_anchor`]): the anchor Astra checks, which is
//! the outgoing `CA-PQ` during an overlap. The replacement is verified by the gateway under the
//! key it holds as current (`state/gateway_identity.rs`, `install_transition`, which calls
//! `transition.verify(&self.current_ca_public_key, ...)`), and that is the outgoing key until the
//! overlap ends (`promote_ca_if_due`). The vault signs a transition only with its current key
//! (`signing/gateway.rs`, `sign_gateway_transition`), so no vault anchor fits during an overlap:
//! the replacement is refused with [`GatewayRefusal::ReplacementNotBefore`] before any key, and the
//! revocation without replacement stays open.

use std::path::Path;

use aether::certificates::encoding::MlDsa87PublicKey;
use aether::certificates::gateway::GatewayIdentityTransition;
use aether::certificates::operator_session::{AstraManifest, RevocationManifest};
use aether::certificates::revocation::{RevocationReason, RevocationScope};
use aether::certificates::transport::{OperatorOpenAction, OperatorOpenRequest, TrustUpdateObject};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::authenticator::Authenticator;
use crate::handoff::{self, DomainHandoff};
use crate::operations::campaign_result;
use crate::operations::gateway_identity::{
    self, before_signing, bound_to_domain, deposit_result, internal, open_renewal_as,
    refused_by_gateway, transition_of, GatewayIdentityRemote, GatewayRefusal, OpenedGatewayRenewal,
    RenewalOptions, SignedGatewayDecision, CAMPAIGN_WINDOW_SECS, REQUESTED_BY,
};
use crate::operations::keys::{approve_one, KeyStep, ValidatedKeys};
use crate::operations::revocation::{
    select_anchor, RevocationReasonChoice, RevocationRefusal, SelectedAnchor, SignedRevocation,
};
use crate::operations::rotation::ensure_same_vault;
use crate::origin::CampaignRequest;
use crate::signing::{
    sign_revocation, CampaignApprovalSession, DomainIdentity, RevocationAnchor, RevocationDecision,
};
use crate::tunnel::TunnelRefusal;
use crate::vault::AuthorityVault;

/// The name of the record, beside the vault.
const PENDING_FILE: &str = "pending-gateway-revocation.json";

/// The terms of the emergency replacement: the signer's defaults for a gateway transition.
/// Both leaves are revoked, so the TLS leaf is replaced too (`rotate_tls`), and the key is the
/// one the gateway holds (`key_recovery`: the revoked identity signs nothing for its successor).
/// The windows are inert on the gateway, which installs the replacement at once.
const REPLACEMENT_TERMS: RenewalOptions = RenewalOptions {
    rotate_tls: true,
    key_recovery: true,
    prepare_days: 7,
    overlap_days: 7,
    validity_days: 365,
};

/// The campaign label of the replacement round, which the operator reads on the door's screen.
const REPLACEMENT_LABEL: &str = "Identité de remplacement de la gateway, avant sa révocation";

/// What the gateway revocation has done so far, as the record holds it. Public: it is the
/// record the resume reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGatewayRevocation {
    /// The emergency transition the revocation names, when there is one. Its `deposited` flag
    /// says whether Astra holds it.
    pub replacement: Option<SignedGatewayDecision>,
    /// The revocation, once signed. Absent while only the replacement is recorded: the
    /// revocation's campaign opens after the replacement's deposit.
    pub revocation: Option<SignedRevocation>,
    /// Astra relayed the revocation to the gateway.
    pub revocation_applied: bool,
    /// The gateway holds the replacement.
    pub replacement_installed: bool,
}

/// A gateway revocation opened on its current round: the replacement's campaign, or the
/// revocation's. With a replacement there are two rounds, each with its own approval.
pub struct OpenedGatewayRevocation {
    stage: Stage,
}

enum Stage {
    /// The replacement's campaign: the transition is signed here.
    Replacement(Box<OpenedGatewayRenewal>),
    /// The revocation's campaign, with the keys proved so far.
    Revocation(Box<OpenedRevocation>),
}

/// The revocation's campaign, verified, and the session its approvals go into.
struct OpenedRevocation {
    keys: ValidatedKeys,
    campaign: Box<CampaignRequest>,
    anchor: RevocationAnchor,
    identity: DomainIdentity,
    anchor_key: MlDsa87PublicKey,
    tls_not_after: u64,
    pq_not_after: u64,
    reason: RevocationReason,
    /// The label the operator reads for the reason, as the manifest names it.
    reason_label: &'static str,
    approval: CampaignApprovalSession,
    /// The replacement the revocation names, deposited and recorded beside it.
    replacement: Option<SignedGatewayDecision>,
}

/// Opens the revocation of the gateway, or refuses it. Nothing before a key is asked for can
/// be refused after it.
///
/// With `with_replacement`, the first call opens the replacement's round; once that is
/// deposited, a second call opens the revocation's round. `reason` is the revocation's, and
/// it is read on the round that signs the revocation.
pub fn open_gateway_revocation(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    reason: RevocationReasonChoice,
    with_replacement: bool,
    now: u64,
) -> Result<OpenedGatewayRevocation, GatewayRefusal> {
    if gateway_identity::pending(vault_path, now)
        .map_err(internal)?
        .is_some()
    {
        return Err(GatewayRefusal::DecisionPending);
    }
    let Some(record) = pending_revocation(vault_path, now).map_err(internal)? else {
        return if with_replacement {
            open_replacement(remote, vault_path, now)
        } else {
            open_revocation(remote, vault_path, reason, None, now)
        };
    };
    // Only the revocation is left, and the replacement is deposited: the second round.
    match record.replacement {
        Some(replacement)
            if with_replacement && record.revocation.is_none() && replacement.deposited =>
        {
            open_revocation(remote, vault_path, reason, Some(replacement), now)
        }
        _ => Err(GatewayRefusal::RevocationAlreadyOpen),
    }
}

impl OpenedGatewayRevocation {
    /// How many credentials approve the current round's campaign.
    pub fn required_credentials(&self) -> u8 {
        match &self.stage {
            Stage::Replacement(renewal) => renewal.required_credentials(),
            Stage::Revocation(round) => round.campaign.campaign.required_credentials,
        }
    }

    /// When the current round's campaign closes.
    pub fn campaign_expires_at(&self) -> u64 {
        match &self.stage {
            Stage::Replacement(renewal) => renewal.campaign_expires_at(),
            Stage::Revocation(round) => round.campaign.campaign.expires_at,
        }
    }

    /// What the operator reads before the first key of the current round. The revocation's
    /// round names the replacement's fingerprint, read from the signed record, so the second
    /// approval shows the document the gateway will accept.
    pub fn manifest(&self, effective_at: u64) -> AstraManifest {
        match &self.stage {
            Stage::Replacement(renewal) => renewal.manifest(),
            Stage::Revocation(round) => {
                let target = &round.campaign.campaign.targets[0];
                AstraManifest::Revocation(RevocationManifest {
                    trust_domain_id: round.identity.trust_domain_id,
                    target: round.campaign.campaign.gateway_wg_public_key.to_base64(),
                    scope: "gateway".to_string(),
                    reason: round.reason_label.to_string(),
                    revocation_epoch: target.epoch.saturating_add(1),
                    effective_at,
                    replacement_transition_fingerprint: round
                        .replacement
                        .as_ref()
                        .and_then(|decision| transition_fingerprint(decision).ok()),
                })
            }
        }
    }

    /// One key: its approval, then the proof that the same key opens the vault.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        match &mut self.stage {
            Stage::Replacement(renewal) => renewal.approve(key, now),
            Stage::Revocation(round) => {
                let expires_at = round.campaign.campaign.expires_at;
                approve_one(&mut round.keys, &mut round.approval, expires_at, key, now)
            }
        }
    }

    /// Signs the current round's object and records it before anything is deposited.
    pub fn sign_and_record(
        self,
        vault_path: &Path,
        now: u64,
    ) -> Result<SignedGatewayRevocation, GatewayRefusal> {
        match self.stage {
            Stage::Replacement(renewal) => {
                let decision = renewal.sign_decision(vault_path, now, true)?;
                let signed = SignedGatewayRevocation {
                    replacement: Some(decision),
                    revocation: None,
                    revocation_applied: false,
                    replacement_installed: false,
                };
                save(&record_path(vault_path), &signed).map_err(internal)?;
                Ok(signed)
            }
            Stage::Revocation(round) => sign_revocation_round(*round, vault_path, now),
        }
    }
}

/// Carries the recorded gateway revocation: deposits the replacement, deposits the revocation,
/// installs the replacement, in that order, each step recorded before the next. A step is
/// replayed from the record with no key.
///
/// Returns [`GatewayRefusal::RevocationToSign`] once the replacement is deposited and the
/// revocation is still to sign: that step needs a key, and it is taken by a new round.
pub fn carry_revocation(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    mut signed: SignedGatewayRevocation,
    now: u64,
) -> Result<(), GatewayRefusal> {
    if let Some(replacement) = signed.replacement.as_ref().filter(|r| !r.deposited) {
        if now >= replacement.expires_at {
            clear(vault_path).map_err(internal)?;
            return Err(GatewayRefusal::Internal(
                "la campagne du remplaçant a expiré avant son dépôt : la décision est jetée. Reprendre la préparation."
                    .into(),
            ));
        }
        gateway_identity::deposit(remote, replacement)?;
        if let Some(replacement) = signed.replacement.as_mut() {
            replacement.deposited = true;
        }
        save(&record_path(vault_path), &signed).map_err(internal)?;
    }

    let Some(revocation) = signed.revocation.as_ref() else {
        return Err(GatewayRefusal::RevocationToSign);
    };
    if !signed.revocation_applied {
        if now >= revocation.expires_at {
            return probe_expired_revocation(remote, vault_path, signed);
        }
        if let Err(refusal) = deposit_result(
            remote,
            &revocation.operation_id,
            &revocation.campaign_id,
            &revocation.result,
        ) {
            // A definitive answer proves Astra did not accept the deposit: the revocation is
            // dropped and the replacement waits for a new signature. Other failures keep it.
            if matches!(refusal, GatewayRefusal::GatewayRefused(_)) {
                signed.revocation = None;
                keep(vault_path, &signed).map_err(internal)?;
            }
            return Err(refusal);
        }
        signed.revocation_applied = true;
        save(&record_path(vault_path), &signed).map_err(internal)?;
    }

    if let Some(replacement) = signed.replacement.as_ref() {
        if !signed.replacement_installed {
            // Only once the revocation is applied: the gateway takes its replacement then.
            remote
                .install(transition_of(replacement)?)
                .map_err(refused_by_gateway)?;
            signed.replacement_installed = true;
            save(&record_path(vault_path), &signed).map_err(internal)?;
        }
    }
    clear(vault_path).map_err(internal)
}

/// The revocation's campaign closed before its answer came back, so Astra may still hold it. The
/// gateway takes the replacement only once it is revoked and names it, which tells whether the
/// revocation applied: accepted, both steps are done; refused for good, it did not apply and the
/// revocation is dropped to be signed again; unreachable, the record is left as it is.
fn probe_expired_revocation(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    mut signed: SignedGatewayRevocation,
) -> Result<(), GatewayRefusal> {
    let Some(replacement) = signed.replacement.as_ref() else {
        // Without a replacement nothing tells whether the revocation applied: it is dropped.
        clear(vault_path).map_err(internal)?;
        return Err(GatewayRefusal::Internal(
            "la campagne de la révocation a expiré avant le dépôt : la révocation est jetée. Reprendre la préparation."
                .into(),
        ));
    };
    match remote.install(transition_of(replacement)?) {
        Ok(_) => {
            signed.revocation_applied = true;
            signed.replacement_installed = true;
            clear(vault_path).map_err(internal)
        }
        Err(error) => match refused_by_gateway(error) {
            GatewayRefusal::GatewayRefused(_) => {
                signed.revocation = None;
                keep(vault_path, &signed).map_err(internal)?;
                Err(GatewayRefusal::RevocationToSign)
            }
            other => Err(other),
        },
    }
}

/// The recorded gateway revocation, if one waits. A replacement that no campaign can deposit
/// any more is discarded with the record. An unapplied revocation past its campaign stays: the
/// next carry decides whether it applied.
pub fn pending_revocation(vault_path: &Path, now: u64) -> Result<Option<SignedGatewayRevocation>> {
    let path = record_path(vault_path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("lecture de {}", path.display())),
    };
    let signed: SignedGatewayRevocation = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "lecture de la révocation de la gateway en attente {}",
            path.display()
        )
    })?;
    if signed
        .replacement
        .as_ref()
        .is_some_and(|r| !r.deposited && now >= r.expires_at)
    {
        clear(vault_path)?;
        return Ok(None);
    }
    if signed.replacement.is_none() && signed.revocation.is_none() {
        clear(vault_path)?;
        return Ok(None);
    }
    Ok(Some(signed))
}

/// Removes the waiting record, when nothing is left to finish on it. A revocation whose
/// replacement is not installed is kept, and so is one whose state the record cannot tell
/// (deposited with its answer lost, or not deposited at all): « Reprendre » settles it. Offered
/// after a refusal for good, the record otherwise blocks every new gesture on the gateway.
pub fn discard_pending_revocation(vault_path: &Path) -> Result<(), GatewayRefusal> {
    let path = record_path(vault_path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(internal(anyhow::Error::from(error))),
    };
    let signed: SignedGatewayRevocation = serde_json::from_slice(&bytes).map_err(|error| {
        internal(anyhow::Error::from(error).context("lecture de la révocation à jeter"))
    })?;
    let work_left = signed.revocation.is_some()
        && !signed.replacement_installed
        && (signed.replacement.is_some() || !signed.revocation_applied);
    if work_left {
        return Err(GatewayRefusal::NotDiscardable(
            "la révocation de la gateway n'est pas finie : la reprendre pour la terminer. Rien n'a été jeté."
                .into(),
        ));
    }
    clear(vault_path).map_err(internal)
}

/// The replacement's round: the gateway's renewal, under the terms of a replacement.
fn open_replacement(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    now: u64,
) -> Result<OpenedGatewayRevocation, GatewayRefusal> {
    // Everything that can be refused without a key is refused first: an overlap refuses the
    // replacement whatever the keys are.
    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    let overlap = remote.overlap_not_after().map_err(before_signing)?;
    if let Some(refusal) = replacement_overlap(vault, overlap, now)? {
        return Err(refusal);
    }
    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let mut authority = remote.authority_status().map_err(before_signing)?;
    let selected = select_anchor(vault, vault_path, &mut authority, None, &identity, now)
        .map_err(from_revocation)?;
    if selected.anchor != RevocationAnchor::Current {
        return Err(GatewayRefusal::Internal(
            "Astra vérifie sous la CA-PQ sortante : le remplacement ne peut pas être signé. Rien n'a été signé."
                .into(),
        ));
    }
    let renewal = open_renewal_as(
        remote,
        vault_path,
        REPLACEMENT_TERMS,
        REPLACEMENT_LABEL,
        now,
    )?;
    Ok(OpenedGatewayRevocation {
        stage: Stage::Replacement(Box::new(renewal)),
    })
}

/// The revocation's round: its campaign is opened, its target and the replacement's are
/// checked, and nothing asks for a key until every check has passed.
fn open_revocation(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    reason: RevocationReasonChoice,
    replacement: Option<SignedGatewayDecision>,
    now: u64,
) -> Result<OpenedGatewayRevocation, GatewayRefusal> {
    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    let overlap = remote.overlap_not_after().map_err(before_signing)?;
    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let transition = replacement.as_ref().map(transition_of).transpose()?;
    if let Some(transition) = transition {
        bound_to_domain(transition, &identity)?;
        // The replacement is signed under the current anchor: an overlap started since refuses it.
        if let Some(refusal) = replacement_overlap(vault, overlap, now)? {
            return Err(refusal);
        }
    }
    let mut authority = remote.authority_status().map_err(before_signing)?;
    let selected = select_anchor(vault, vault_path, &mut authority, overlap, &identity, now)
        .map_err(from_revocation)?;

    let opened = remote
        .open_campaign(&OperatorOpenRequest {
            action: OperatorOpenAction::GatewayRevocation,
            reason: reason.label().to_string(),
            requested_by: REQUESTED_BY.to_string(),
            window_secs: CAMPAIGN_WINDOW_SECS,
        })
        .map_err(|error| match error.downcast_ref::<TunnelRefusal>() {
            Some(refusal) if refusal.status == 403 => refused_by_door(vault_path, now),
            _ => before_signing(error),
        })?;
    // Both leaves are withdrawn with their own expiries: a missing one refuses before a key.
    let expiries = opened.revocation_expiries.ok_or_else(missing_expiries)?;
    let (Some(tls_not_after), Some(pq_not_after)) = (expiries.tls_not_after, expiries.pq_not_after)
    else {
        return Err(missing_expiries());
    };

    let request = remote
        .fetch_campaign(&opened.operation_id)
        .map_err(before_signing)?;
    let authority_url = relay
        .astra_authority_url
        .clone()
        .ok_or_else(|| GatewayRefusal::Internal("l'origine de l'autorité est absente".into()))?;
    handoff::verify_campaign_request(&relay, vault, &request, &authority_url, now)
        .map_err(internal)?;

    let campaign = request.campaign.as_ref();
    let [target] = campaign.targets.as_slice() else {
        return Err(GatewayRefusal::CampaignMismatch);
    };
    if !campaign.scope.revokes()
        || target.identity_key != campaign.gateway_wg_public_key
        || campaign.gateway_wg_public_key != identity.gateway_wg_public_key
        || campaign.server_name != identity.server_name
    {
        return Err(GatewayRefusal::CampaignMismatch);
    }
    // The revocation withdraws the leaves the replacement replaces, at the epoch it names.
    if let Some(transition) = transition {
        let same_leaves = target
            .active_tls_certificate_fingerprint
            .matches(&transition.active_gateway_tls_certificate_fingerprint)
            && target
                .active_pq_certificate_fingerprint
                .matches(&transition.active_gateway_certificate_fingerprint);
        if !same_leaves || target.epoch.checked_add(1) != Some(transition.gateway_identity_epoch) {
            return Err(GatewayRefusal::CampaignMismatch);
        }
    }

    let approval = CampaignApprovalSession::new(
        campaign,
        &selected.document,
        &selected.identity,
        &selected.key,
        &vault.rp_id,
        &format!("https://{}", vault.rp_id),
        now,
    )
    .map_err(internal)?;
    let SelectedAnchor {
        anchor,
        key: anchor_key,
        identity: anchor_identity,
        ..
    } = selected;
    Ok(OpenedGatewayRevocation {
        stage: Stage::Revocation(Box::new(OpenedRevocation {
            keys,
            campaign: Box::new(request),
            anchor,
            identity: anchor_identity,
            anchor_key,
            tls_not_after,
            pq_not_after,
            reason: reason.reason(),
            reason_label: reason.label(),
            approval,
            replacement,
        })),
    })
}

/// Signs the revocation of the gateway's current leaves, names the replacement when there is
/// one, and records the revocation beside it.
fn sign_revocation_round(
    round: OpenedRevocation,
    vault_path: &Path,
    now: u64,
) -> Result<SignedGatewayRevocation, GatewayRefusal> {
    let OpenedRevocation {
        keys,
        campaign: request,
        anchor,
        identity,
        anchor_key,
        tls_not_after,
        pq_not_after,
        reason,
        reason_label: _,
        approval,
        replacement,
    } = round;
    let campaign = request.campaign.as_ref();
    if now >= campaign.expires_at || keys.openings.is_empty() {
        return Err(GatewayRefusal::Internal(
            "la campagne a expiré avant la signature : rien n'a été signé.".into(),
        ));
    }
    ensure_same_vault(vault_path, &keys.vault).map_err(internal)?;
    let approval = approval.finish(now).map_err(internal)?;

    // Checked by `open_revocation`: one target, which is the gateway's.
    let target = &campaign.targets[0];
    let decision = RevocationDecision {
        scope: RevocationScope::Gateway,
        identity_key: target.identity_key,
        server_name: Some(campaign.server_name.clone()),
        revocation_epoch: target
            .epoch
            .checked_add(1)
            .ok_or_else(|| GatewayRefusal::Internal("époque de révocation hors bornes".into()))?,
        revoked_tls: Some((target.active_tls_certificate_fingerprint, tls_not_after)),
        revoked_pq: Some((target.active_pq_certificate_fingerprint, pq_not_after)),
        effective_at: now,
        reason,
        replacement_transition_fingerprint: replacement
            .as_ref()
            .map(transition_fingerprint)
            .transpose()?,
    };
    let ValidatedKeys {
        vault, openings, ..
    } = keys;
    let revocation = sign_revocation(
        &vault,
        &openings[0],
        &identity,
        &anchor_key,
        &decision,
        target.epoch,
        anchor,
    )
    .map_err(internal)?;
    campaign.covers_revocation(&revocation).map_err(|_| {
        GatewayRefusal::Internal(
            "la révocation signée ne correspond pas à la campagne approuvée".into(),
        )
    })?;

    let signed_revocation = SignedRevocation {
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
    let signed = SignedGatewayRevocation {
        replacement,
        revocation: Some(signed_revocation),
        revocation_applied: false,
        replacement_installed: false,
    };
    save(&record_path(vault_path), &signed).map_err(internal)?;
    Ok(signed)
}

/// The fingerprint of the transition a revocation names, read from the signed transition.
fn transition_fingerprint(
    decision: &SignedGatewayDecision,
) -> Result<aether::certificates::encoding::Fingerprint, GatewayRefusal> {
    let transition: &GatewayIdentityTransition = transition_of(decision)?;
    transition.fingerprint().map_err(internal)
}

/// The refusal that keeps a replacement out of an overlap, if one runs. The end is the gateway's
/// retirement instant, or the instant the vault keeps for its outgoing key. An end already past
/// by this clock names no date.
fn replacement_overlap(
    vault: &AuthorityVault,
    overlap: Option<u64>,
    now: u64,
) -> Result<Option<GatewayRefusal>, GatewayRefusal> {
    let kept = match vault.retained_outgoing_ca_pq_public() {
        Some((_, _, not_after)) => Some(not_after),
        None if vault.retained_outgoing_ca_pq_public.is_some() => {
            return Err(GatewayRefusal::Internal(
                "la CA-PQ sortante gardée n'est pas lisible".into(),
            ))
        }
        None => None,
    };
    Ok(overlap.or(kept).map(|end| {
        if end > now {
            GatewayRefusal::ReplacementNotBefore(end)
        } else {
            GatewayRefusal::ReplacementAwaitsOverlap
        }
    }))
}

fn from_revocation(refusal: RevocationRefusal) -> GatewayRefusal {
    match refusal {
        RevocationRefusal::Unreachable => GatewayRefusal::UnreachableBeforeSigning,
        RevocationRefusal::Internal(message) => GatewayRefusal::Internal(message),
        other => GatewayRefusal::Revocation(other),
    }
}

fn missing_expiries() -> GatewayRefusal {
    GatewayRefusal::Internal(
        "Astra n'a pas donné l'échéance des deux feuilles de la gateway : rien n'a été signé."
            .into(),
    )
}

/// A 403 on the door's open call: the record decides, as the renewal's does.
fn refused_by_door(vault_path: &Path, now: u64) -> GatewayRefusal {
    match pending_revocation(vault_path, now) {
        Ok(Some(_)) => GatewayRefusal::RevocationAlreadyOpen,
        Ok(None) => {
            GatewayRefusal::Internal("Astra a refusé d'ouvrir la révocation de la gateway.".into())
        }
        Err(error) => internal(error),
    }
}

fn record_path(vault_path: &Path) -> std::path::PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(PENDING_FILE)
}

/// Writes the record, atomically and privately, like the other records of the registry.
fn save(path: &Path, signed: &SignedGatewayRevocation) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(signed)
        .context("sérialisation de la révocation de la gateway")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

/// Writes the record, or removes it once it holds nothing.
fn keep(vault_path: &Path, signed: &SignedGatewayRevocation) -> Result<()> {
    if signed.replacement.is_none() && signed.revocation.is_none() {
        clear(vault_path)
    } else {
        save(&record_path(vault_path), signed)
    }
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

#[cfg(any(test, feature = "test-fixtures"))]
pub mod tests;
