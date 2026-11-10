//! Renewing the gateway's identity through Astra's door (spec §5.2 to §5.7, lot 6b).
//!
//! # Why every refusal before a key comes first
//!
//! [`open_renewal`] reads the gateway, asks it to prepare its next identity, and
//! opens the campaign. Then it checks what the campaign froze against the leaf the
//! door serves, and the request against both. A campaign blocks its family for five
//! minutes, so nothing this machine can refuse is left to be refused after it, and
//! no key is asked for until every check has passed.
//!
//! # Why the terms are chosen before the keys
//!
//! [`RenewalOptions`] carries the windows the decision will name. They are fixed
//! before the first touch, so what the operator approves is what gets signed.
//!
//! # Why a key is approved before it opens the vault
//!
//! As for the revocation: [`OpenedGatewayRenewal::approve`] takes the assertion first
//! and opens the vault with that credential only when the assertion is accepted for it.
//!
//! # Why the decision is recorded before the deposit
//!
//! [`OpenedGatewayRenewal::sign_and_record`] writes `pending-gateway-decision.json`
//! before anything leaves. [`carry`] then records each step in that file: `installed`
//! once the gateway holds the transition, `published` once Astra relays it, and the
//! file is removed after that. A resume that finds `installed` set publishes without
//! asking for a key, and a deposit whose answer was lost is replayed with the same
//! bytes.

use std::path::Path;

use aether::certificates::approval::CredentialRegistry;
use aether::certificates::authority::RotationReason;
use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, MlDsa87PublicKey};
use aether::certificates::gateway::{
    pq_certificate_fingerprint, AbortReason, Continuity, GatewayCertificateRequest,
    GatewayIdentityTransition, GatewayTransitionAbort,
};
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerResult, CampaignFamily, CampaignScope, CampaignTarget,
    CertificateKind, CertificateServiceRollbackAuthorization,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorGatewayPublished, OperatorOpenAction, OperatorOpenRequest,
    OperatorOpened, SigningOperationState, TrustUpdateObject,
};
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::authenticator::Authenticator;
use crate::credentials;
use crate::handoff::{self, DomainHandoff};
use crate::operations::campaign_result;
use crate::operations::keys::{approve_one, KeyStep, ValidatedKeys};
use crate::operations::recovery::random_id;
use crate::operations::rotation::ensure_same_vault;
use crate::origin::CampaignRequest;
use crate::signing::{
    self, CampaignApprovalSession, DomainIdentity, GatewayAbortDecision, GatewayTransitionDecision,
    ServiceRollbackDecision,
};
use crate::tunnel::{
    is_unreachable, GatewayDecisionRead, GatewayIdentityRead, GatewayRenewalRead,
    GatewayRollbackRead, RenewalAsk, Tunnel, TunnelRefusal,
};
use crate::vault_gestures::DAY_SECS;

/// The name of the record, beside the vault.
const PENDING_FILE: &str = "pending-gateway-decision.json";

/// The window of the campaign, as the door opens it (spec §7.6).
const CAMPAIGN_WINDOW_SECS: u64 = 300;

/// What the campaign's text names as the requester: the console, not a person.
const REQUESTED_BY: &str = "Orion";

/// What the renewal needs from the far side of the tunnel.
///
/// The abort, the rollback and the staged transition are declared here with the renewal,
/// which reads the staged transition and which the cancellations act on.
pub trait GatewayIdentityRemote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened>;
    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest>;
    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState>;
    fn prepare_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead>;
    fn renewal_request(&self) -> Result<GatewayCertificateRequest>;
    fn candidate_tls(&self) -> Result<Option<DerCertificate>>;
    fn install(&self, transition: &GatewayIdentityTransition) -> Result<GatewayDecisionRead>;
    fn publish(&self, epoch: u64) -> Result<OperatorGatewayPublished>;
    fn abort(&self, abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead>;
    fn rollback(
        &self,
        authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead>;
    fn staged_transition(&self) -> Result<Option<GatewayIdentityTransition>>;
    fn gateway(&self) -> Result<GatewayIdentityRead>;
    fn authority_status(&self) -> Result<OperatorAuthorityStatus>;
    /// When the outgoing `CA-PQ` stops being accepted, while an overlap runs.
    fn overlap_not_after(&self) -> Result<Option<u64>>;
}

impl GatewayIdentityRemote for Tunnel {
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

    fn prepare_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead> {
        Tunnel::prepare_gateway_renewal(self, ask)
    }

    fn renewal_request(&self) -> Result<GatewayCertificateRequest> {
        Tunnel::gateway_renewal_request(self)
    }

    fn candidate_tls(&self) -> Result<Option<DerCertificate>> {
        Tunnel::gateway_candidate_tls(self)
    }

    fn install(&self, transition: &GatewayIdentityTransition) -> Result<GatewayDecisionRead> {
        Tunnel::install_gateway_transition(self, transition)
    }

    fn publish(&self, epoch: u64) -> Result<OperatorGatewayPublished> {
        Tunnel::publish_gateway_transition(self, epoch)
    }

    fn abort(&self, abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead> {
        Tunnel::abort_gateway_transition(self, abort)
    }

    fn rollback(
        &self,
        authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead> {
        Tunnel::install_gateway_rollback(self, authorization)
    }

    fn staged_transition(&self) -> Result<Option<GatewayIdentityTransition>> {
        Tunnel::staged_gateway_transition(self)
    }

    fn gateway(&self) -> Result<GatewayIdentityRead> {
        Tunnel::gateway_identity(self)
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        Tunnel::authority_status(self)
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        Tunnel::gateway_overlap_not_after(self)
    }
}

/// Why no renewal was opened, or why it cannot be carried. Nothing was signed in the
/// cases that say so, and nothing was touched for the ones before a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayRefusal {
    #[error("une transition de l'identité de la gateway est déjà en cours. Rien n'a été signé.")]
    TransitionInFlight,
    #[error(
        "un recouvrement de CA-PQ est en cours : l'identité de la gateway attend sa fin. Rien n'a été signé."
    )]
    CaPqOverlap,
    #[error("une décision d'identité de la gateway attend déjà. Reprendre celle-ci.")]
    AlreadyOpen,
    #[error("la campagne d'Astra ne nomme pas cette gateway. Rien n'a été signé.")]
    CampaignMismatch,
    #[error(
        "la feuille gateway en service n'est pas celle que la campagne fige. Rien n'a été signé."
    )]
    LeafMismatch,
    #[error("la demande de la gateway ne correspond pas à la campagne. Rien n'a été signé.")]
    RequestMismatch,
    #[error("Astra ou la gateway est injoignable. Rien n'est perdu : la reprise continue là où elle s'est arrêtée.")]
    Unreachable,
    /// Unreachable before anything was signed: the one case where nothing was signed.
    #[error("Astra ou la gateway est injoignable. Rien n'a été signé.")]
    UnreachableBeforeSigning,
    /// Nothing is staged on the gateway: there is no transition to cancel.
    #[error("aucune transition de l'identité de la gateway à annuler. Rien n'a été signé.")]
    NothingToAbort,
    /// The transition is published, or its activation is reached: it no longer cancels.
    #[error("la transition ne s'annule plus : elle est publiée, ou son activation est à {0} (horloge de la gateway). Rien n'a été signé.")]
    AbortTooLate(u64),
    /// No overlap runs on the gateway now: the outgoing identity is not the one in service.
    #[error("aucun recouvrement en cours : l'ancienne identité n'est pas celle qui sert. Rien n'a été signé.")]
    NoOverlap,
    /// The gateway is revoked: no outgoing identity can be selected for it.
    #[error("la gateway est révoquée : aucune identité ne la remplace. Rien n'a été signé.")]
    Revoked,
    /// The gateway refused the document for good, and said why.
    #[error("{0}")]
    GatewayRefused(String),
    #[error("{0}")]
    Internal(String),
}

/// What the renewal sets, chosen before any key is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalOptions {
    /// Replace the self-signed TLS leaf too.
    pub rotate_tls: bool,
    /// The gateway lost its key: the request carries no continuity signature.
    pub key_recovery: bool,
    /// When the new leaf takes over, counted from the signature.
    pub prepare_days: u64,
    /// How long the outgoing leaf keeps being accepted after that.
    pub overlap_days: u64,
    /// How long the new leaf is valid.
    pub validity_days: u64,
}

/// A decision signed under `CA-PQ`, with the approval that authorizes it. Public: it
/// crosses to Astra as it is, and it is the record the resume reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGatewayDecision {
    pub operation_id: Id16,
    pub campaign_id: Id16,
    pub expires_at: u64,
    /// One gateway transition.
    pub result: AstraSignerResult,
    /// Astra holds the decision: a resume deposits nothing again, and the record outlives
    /// the campaign, since installation and publication need no campaign.
    pub deposited: bool,
    /// The gateway holds the transition.
    pub installed: bool,
    /// Astra relayed the transition to the gateway.
    pub published: bool,
}

/// How a carried renewal ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayCarried {
    /// The gateway switches at `activation_at` and retires the outgoing leaf at `not_after`.
    Published { activation_at: u64, not_after: u64 },
}

/// A verified campaign, the request the gateway prepared, and the session its
/// approvals go into.
pub struct OpenedGatewayRenewal {
    keys: ValidatedKeys,
    campaign: Box<CampaignRequest>,
    renewal: Box<GatewayCertificateRequest>,
    candidate_tls: Option<DerCertificate>,
    identity: DomainIdentity,
    /// The `CA-PQ` the decision is signed under: the one the vault holds.
    anchor_key: MlDsa87PublicKey,
    approval: CampaignApprovalSession,
    options: RenewalOptions,
}

/// Opens the renewal of the gateway's identity, or refuses it. Nothing before the last
/// step asks for a key.
pub fn open_renewal(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    options: RenewalOptions,
    now: u64,
) -> Result<OpenedGatewayRenewal, GatewayRefusal> {
    // A decision still waiting belongs to a campaign that is open or was: a new one
    // would overwrite it before it is deposited.
    if pending(vault_path, now).map_err(internal)?.is_some() {
        return Err(GatewayRefusal::AlreadyOpen);
    }
    let gateway = remote.gateway().map_err(before_signing)?;
    if gateway.gateway_transition_pending {
        return Err(GatewayRefusal::TransitionInFlight);
    }
    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    if vault.retained_outgoing_ca_pq_public.is_some()
        || remote
            .overlap_not_after()
            .map_err(before_signing)?
            .is_some()
    {
        return Err(GatewayRefusal::CaPqOverlap);
    }

    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let anchor_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).map_err(internal)?;
    let prepared = remote
        .prepare_renewal(&RenewalAsk {
            rotate_tls: options.rotate_tls,
            new_key: false,
            key_recovery: options.key_recovery,
        })
        .map_err(before_signing)?;

    let opened = remote
        .open_campaign(&OperatorOpenRequest {
            action: OperatorOpenAction::GatewayIdentity,
            reason: reason_label(options).to_string(),
            requested_by: REQUESTED_BY.to_string(),
            window_secs: CAMPAIGN_WINDOW_SECS,
        })
        .map_err(|error| match error.downcast_ref::<TunnelRefusal>() {
            Some(refusal) if refusal.status == 403 => refused_by_door(vault_path, now),
            _ => before_signing(error),
        })?;
    let served = opened.gateway_certificate.ok_or_else(|| {
        GatewayRefusal::Internal(
            "Astra n'a pas donné la feuille gateway en service : rien n'a été signé.".into(),
        )
    })?;

    let request = remote
        .fetch_campaign(&opened.operation_id)
        .map_err(before_signing)?;
    let renewal = remote.renewal_request().map_err(before_signing)?;
    let candidate = remote.candidate_tls().map_err(before_signing)?;
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
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity)
        || target.identity_key != campaign.gateway_wg_public_key
        || campaign.gateway_wg_public_key != identity.gateway_wg_public_key
        || campaign.server_name != identity.server_name
    {
        return Err(GatewayRefusal::CampaignMismatch);
    }
    let epoch = target
        .epoch
        .checked_add(1)
        .ok_or_else(|| GatewayRefusal::Internal("époque de décision hors bornes".into()))?;
    if prepared.gateway_identity_epoch != epoch || renewal.gateway_identity_epoch != epoch {
        return Err(GatewayRefusal::CampaignMismatch);
    }

    let served_fingerprint = pq_certificate_fingerprint(&served).map_err(internal)?;
    if !target
        .active_pq_certificate_fingerprint
        .matches(&served_fingerprint)
    {
        return Err(GatewayRefusal::LeafMismatch);
    }

    // The continuity is proved under the leaf in service, which the campaign froze;
    // a recovery carries no continuity signature at all.
    let continuity_key = MlDsa87PublicKey::parse(&served.ml_dsa_87_public_key).map_err(internal)?;
    let continuity = if options.key_recovery {
        Continuity::WaivedForKeyRecovery
    } else {
        Continuity::Required(&continuity_key)
    };
    renewal
        .verify(
            continuity,
            &identity.trust_domain_id,
            target.epoch,
            &campaign.gateway_wg_public_key,
            &campaign.server_name,
            now,
        )
        .map_err(|_| GatewayRefusal::RequestMismatch)?;
    let announced = Fingerprint::parse_hex(&prepared.request_fingerprint)
        .map_err(|_| GatewayRefusal::RequestMismatch)?;
    if !announced.matches(&renewal.fingerprint()) || prepared.key_recovery != options.key_recovery {
        return Err(GatewayRefusal::RequestMismatch);
    }
    // The TLS leaf moves exactly when the terms say so: a candidate without the flag, or
    // the flag without a candidate, is not the renewal the operator approves.
    if prepared.candidate_tls_fingerprint.is_some() != options.rotate_tls
        || candidate.is_some() != options.rotate_tls
    {
        return Err(GatewayRefusal::RequestMismatch);
    }
    let candidate_tls = match (prepared.candidate_tls_fingerprint.as_deref(), candidate) {
        (None, None) => None,
        (Some(announced), Some(der)) => {
            let announced =
                Fingerprint::parse_hex(announced).map_err(|_| GatewayRefusal::RequestMismatch)?;
            if !announced.matches(&der.fingerprint()) {
                return Err(GatewayRefusal::RequestMismatch);
            }
            Some(der)
        }
        _ => return Err(GatewayRefusal::RequestMismatch),
    };

    let document = credential_document(vault_path)?;
    let approval = CampaignApprovalSession::new(
        campaign,
        &document,
        &identity,
        &anchor_key,
        &vault.rp_id,
        &format!("https://{}", vault.rp_id),
        now,
    )
    .map_err(internal)?;

    Ok(OpenedGatewayRenewal {
        keys,
        campaign: Box::new(request),
        renewal: Box::new(renewal),
        candidate_tls,
        identity,
        anchor_key,
        approval,
        options,
    })
}

impl OpenedGatewayRenewal {
    /// The keys the renewal has proved so far.
    pub fn keys(&self) -> &ValidatedKeys {
        &self.keys
    }

    /// One key: its approval, then the proof that the same key opens the vault.
    ///
    /// Two touches, in that order. A refusal at either one loses nothing, and the
    /// same or another key can answer again.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        approve_one(
            &mut self.keys,
            &mut self.approval,
            self.campaign.campaign.expires_at,
            key,
            now,
        )
    }

    /// Signs the renewal's transition under `CA-PQ`, and records it before any deposit.
    pub fn sign_and_record(
        self,
        vault_path: &Path,
        now: u64,
    ) -> Result<SignedGatewayDecision, GatewayRefusal> {
        self.sign_and_record_as(vault_path, now, false)
    }

    /// The signature with the reason named by the caller. Only the emergency replacement
    /// of Task 6 says `emergency_replacement`: the public terms never do.
    pub(crate) fn sign_and_record_as(
        self,
        vault_path: &Path,
        now: u64,
        emergency_replacement: bool,
    ) -> Result<SignedGatewayDecision, GatewayRefusal> {
        let Self {
            keys,
            campaign: request,
            renewal,
            candidate_tls,
            identity,
            anchor_key,
            approval,
            options,
        } = self;
        let campaign = request.campaign.as_ref();
        if now >= campaign.expires_at || keys.openings.is_empty() {
            return Err(GatewayRefusal::Internal(
                "la campagne a expiré avant la signature : rien n'a été signé.".into(),
            ));
        }
        ensure_same_vault(vault_path, &keys.vault).map_err(internal)?;
        let approval = approval.finish(now).map_err(internal)?;

        // Checked by `open_renewal`: one target, which is the gateway's.
        let target = &campaign.targets[0];
        let epoch = target
            .epoch
            .checked_add(1)
            .ok_or_else(|| GatewayRefusal::Internal("époque de décision hors bornes".into()))?;
        let activation_at = after(now, options.prepare_days)?;
        let window = TransitionWindow::new(
            now,
            activation_at,
            after(activation_at, options.overlap_days)?,
        )
        .map_err(internal)?;
        let ValidatedKeys {
            vault, openings, ..
        } = keys;
        let transition = signing::sign_gateway_transition(
            &vault,
            &openings[0],
            &identity,
            &anchor_key,
            &GatewayTransitionDecision {
                gateway_identity_epoch: epoch,
                gateway_wg_public_key: campaign.gateway_wg_public_key,
                server_name: campaign.server_name.clone(),
                active_tls_fingerprint: target.active_tls_certificate_fingerprint,
                active_pq_fingerprint: target.active_pq_certificate_fingerprint,
                next_pq_public_key: renewal.new_ml_dsa_87_public_key.clone(),
                next_tls_certificate: candidate_tls,
                window,
                leaf_validity: (now, after(now, options.validity_days)?),
                reason: renewal_reason(emergency_replacement, options.key_recovery),
                serial: random_id().map_err(internal)?,
            },
        )
        .map_err(internal)?;
        campaign
            .covers_gateway_transition(&transition)
            .map_err(|_| {
                GatewayRefusal::Internal(
                    "la transition signée ne correspond pas à la campagne approuvée".into(),
                )
            })?;

        let signed = SignedGatewayDecision {
            operation_id: request.operation_id,
            campaign_id: campaign.campaign_id,
            expires_at: campaign.expires_at,
            result: campaign_result(
                &approval,
                vec![TrustUpdateObject::GatewayIdentityTransition(Box::new(
                    transition,
                ))],
                None,
            ),
            deposited: false,
            installed: false,
            published: false,
        };
        save(&record_path(vault_path), &signed).map_err(internal)?;
        Ok(signed)
    }
}

/// Sends the recorded decision and installs it on the gateway, then has Astra publish
/// it. Each step is recorded in the record before the next one starts.
///
/// No key is asked for here. A decision whose deposit was not accepted, and whose
/// campaign has since expired, is discarded: the renewal starts again from
/// [`open_renewal`].
pub fn carry(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    mut decision: SignedGatewayDecision,
    now: u64,
) -> Result<GatewayCarried, GatewayRefusal> {
    let transition = transition_of(&decision)?.clone();
    if !decision.deposited {
        if now >= decision.expires_at {
            clear(vault_path).map_err(internal)?;
            return Err(GatewayRefusal::Internal(
                "la campagne a expiré avant le dépôt : la décision est jetée. Reprendre la préparation."
                    .into(),
            ));
        }
        deposit(remote, &decision)?;
        decision.deposited = true;
        save(&record_path(vault_path), &decision).map_err(internal)?;
    }
    if !decision.installed {
        remote.install(&transition).map_err(refused_by_gateway)?;
        decision.installed = true;
        save(&record_path(vault_path), &decision).map_err(internal)?;
    }
    let relay = remote
        .publish(transition.gateway_identity_epoch)
        .map_err(refused_by_gateway)?;
    if !relay.relayed {
        return Err(GatewayRefusal::Internal(
            "la gateway n'a pas confirmé la relève : reprendre pour la lui demander à nouveau."
                .into(),
        ));
    }
    decision.published = true;
    save(&record_path(vault_path), &decision).map_err(internal)?;
    clear(vault_path).map_err(internal)?;
    Ok(GatewayCarried::Published {
        activation_at: transition.window.activation_at,
        not_after: transition.window.not_after,
    })
}

/// The label the cancellation's campaign carries.
const ABORT_LABEL: &str = "Annulation de la transition de l'identité de la gateway";

/// A cancellation opened on the staged transition: the campaign Astra froze for it, the
/// keys proved so far, and the session the approvals go into.
pub struct OpenedGatewayAbort {
    keys: ValidatedKeys,
    campaign: Box<CampaignRequest>,
    transition: Box<GatewayIdentityTransition>,
    identity: DomainIdentity,
    anchor_key: MlDsa87PublicKey,
    approval: CampaignApprovalSession,
}

/// Opens the cancellation of the transition the gateway holds staged, or refuses it. The
/// transition comes from the gateway, never from a file the operator supplies, and
/// nothing before the last step asks for a key.
///
/// Before activation, on the gateway's clock: the gateway checks the same bound when it
/// installs the cancellation.
pub fn open_abort(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    now: u64,
) -> Result<OpenedGatewayAbort, GatewayRefusal> {
    if pending(vault_path, now).map_err(internal)?.is_some() {
        return Err(GatewayRefusal::AlreadyOpen);
    }
    let gateway = remote.gateway().map_err(before_signing)?;
    let transition = remote
        .staged_transition()
        .map_err(before_signing)?
        .ok_or(GatewayRefusal::NothingToAbort)?;
    let activation_at = transition.window.activation_at;
    if gateway.gateway_transition_published || gateway_clock(&gateway, now) >= activation_at {
        return Err(GatewayRefusal::AbortTooLate(activation_at));
    }

    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let anchor_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).map_err(internal)?;

    let opened = remote
        .open_campaign(&OperatorOpenRequest {
            action: OperatorOpenAction::GatewayIdentity,
            reason: ABORT_LABEL.to_string(),
            requested_by: REQUESTED_BY.to_string(),
            window_secs: CAMPAIGN_WINDOW_SECS,
        })
        .map_err(|error| match error.downcast_ref::<TunnelRefusal>() {
            Some(refusal) if refusal.status == 403 => refused_by_door(vault_path, now),
            _ => before_signing(error),
        })?;
    let request = remote
        .fetch_campaign(&opened.operation_id)
        .map_err(before_signing)?;
    let authority_url = relay
        .astra_authority_url
        .clone()
        .ok_or_else(|| GatewayRefusal::Internal("l'origine de l'autorité est absente".into()))?;
    handoff::verify_campaign_request(&relay, vault, &request, &authority_url, now)
        .map_err(internal)?;

    // The campaign names the decision being cancelled: one target, at its epoch.
    let campaign = request.campaign.as_ref();
    let [target] = campaign.targets.as_slice() else {
        return Err(GatewayRefusal::CampaignMismatch);
    };
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity)
        || target.identity_key != campaign.gateway_wg_public_key
        || campaign.gateway_wg_public_key != identity.gateway_wg_public_key
        || campaign.server_name != identity.server_name
        || target.epoch != transition.gateway_identity_epoch
    {
        return Err(GatewayRefusal::CampaignMismatch);
    }

    let document = credential_document(vault_path)?;
    let approval = CampaignApprovalSession::new(
        campaign,
        &document,
        &identity,
        &anchor_key,
        &vault.rp_id,
        &format!("https://{}", vault.rp_id),
        now,
    )
    .map_err(internal)?;

    Ok(OpenedGatewayAbort {
        keys,
        campaign: Box::new(request),
        transition: Box::new(transition),
        identity,
        anchor_key,
        approval,
    })
}

impl OpenedGatewayAbort {
    /// One key: its approval, then the proof that the same key opens the vault.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        approve_one(
            &mut self.keys,
            &mut self.approval,
            self.campaign.campaign.expires_at,
            key,
            now,
        )
    }

    /// Signs the cancellation under `CA-PQ`, and records it before any deposit.
    pub fn sign_and_record(
        self,
        vault_path: &Path,
        now: u64,
    ) -> Result<SignedGatewayDecision, GatewayRefusal> {
        let Self {
            keys,
            campaign: request,
            transition,
            identity,
            anchor_key,
            approval,
        } = self;
        let campaign = request.campaign.as_ref();
        if now >= campaign.expires_at || keys.openings.is_empty() {
            return Err(GatewayRefusal::Internal(
                "la campagne a expiré avant la signature : rien n'a été signé.".into(),
            ));
        }
        ensure_same_vault(vault_path, &keys.vault).map_err(internal)?;
        let approval = approval.finish(now).map_err(internal)?;

        let ValidatedKeys {
            vault, openings, ..
        } = keys;
        let abort = signing::sign_gateway_abort(
            &vault,
            &openings[0],
            &identity,
            &anchor_key,
            &GatewayAbortDecision {
                transition: &transition,
                reason: AbortReason::OperatorCancelled,
                campaign_fingerprint: campaign.fingerprint(),
                aborted_at: now,
            },
        )
        .map_err(internal)?;
        campaign.covers_gateway_abort(&abort).map_err(|_| {
            GatewayRefusal::Internal(
                "l'annulation signée ne correspond pas à la campagne approuvée".into(),
            )
        })?;

        let signed = SignedGatewayDecision {
            operation_id: request.operation_id,
            campaign_id: campaign.campaign_id,
            expires_at: campaign.expires_at,
            result: campaign_result(
                &approval,
                vec![TrustUpdateObject::GatewayTransitionAbort(Box::new(abort))],
                None,
            ),
            deposited: false,
            installed: false,
            published: false,
        };
        save(&record_path(vault_path), &signed).map_err(internal)?;
        Ok(signed)
    }
}

/// Sends the recorded cancellation to Astra, then installs it on the gateway. Each step is
/// recorded before the next one starts, as for the renewal. No key is asked for here.
pub fn carry_abort(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    mut decision: SignedGatewayDecision,
    now: u64,
) -> Result<(), GatewayRefusal> {
    let abort = abort_of(&decision)?.clone();
    if !decision.deposited {
        if now >= decision.expires_at {
            clear(vault_path).map_err(internal)?;
            return Err(GatewayRefusal::Internal(
                "la campagne a expiré avant le dépôt : l'annulation est jetée. Reprendre la préparation."
                    .into(),
            ));
        }
        deposit(remote, &decision)?;
        decision.deposited = true;
        save(&record_path(vault_path), &decision).map_err(internal)?;
    }
    if !decision.installed {
        remote.abort(&abort).map_err(refused_by_gateway)?;
        decision.installed = true;
        save(&record_path(vault_path), &decision).map_err(internal)?;
    }
    clear(vault_path).map_err(internal)
}

/// A rollback opened on the published transition: the campaign resolved here from that
/// transition, the keys proved so far, and the session the approval goes into.
pub struct OpenedGatewayRollback {
    keys: ValidatedKeys,
    campaign: Box<AstraRotationCampaign>,
    transition: Box<GatewayIdentityTransition>,
    identity: DomainIdentity,
    anchor_key: MlDsa87PublicKey,
    approval: CampaignApprovalSession,
}

/// Opens the selection of the outgoing gateway leaf, for the rest of the overlap, or refuses
/// it. Astra opens no campaign for it: a rollback moves no counter and reaches no client, so
/// its campaign is resolved from the transition the operator is shown, as the signer does.
///
/// The overlap is read on the gateway's clock, and the selection lasts `hours` at most,
/// never past `not_after`.
pub fn open_rollback(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    hours: u64,
    reason: &str,
    requested_by: &str,
    now: u64,
) -> Result<OpenedGatewayRollback, GatewayRefusal> {
    let gateway = remote.gateway().map_err(before_signing)?;
    let transition = remote
        .staged_transition()
        .map_err(before_signing)?
        .ok_or(GatewayRefusal::NoOverlap)?;
    let clock = gateway_clock(&gateway, now);
    let window = transition.window;
    if !gateway.gateway_transition_published
        || clock < window.activation_at
        || clock >= window.not_after
    {
        return Err(GatewayRefusal::NoOverlap);
    }
    let expires_at = hours
        .checked_mul(3_600)
        .and_then(|span| clock.checked_add(span))
        .map(|expiry| expiry.min(window.not_after))
        .ok_or_else(|| GatewayRefusal::Internal("durée hors bornes".into()))?;

    let keys = ValidatedKeys::new(vault_path).map_err(internal)?;
    let vault = &keys.vault;
    let relay = DomainHandoff::beside(vault_path, vault).map_err(internal)?;
    let identity = handoff::identity_of(&relay).map_err(internal)?;
    let anchor_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).map_err(internal)?;

    let campaign = AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new(random_id().map_err(internal)?).map_err(internal)?,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        server_name: identity.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::GatewayIdentity,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayTls,
            identity_key: identity.gateway_wg_public_key,
            epoch: transition.gateway_identity_epoch,
            generation: transition.gateway_identity_epoch,
            active_tls_certificate_fingerprint: transition
                .active_gateway_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: transition.active_gateway_certificate_fingerprint,
        }],
        reason: reason.to_string(),
        requested_by: requested_by.to_string(),
        policy_fingerprint: identity
            .policy()
            .map_err(internal)?
            .fingerprint()
            .map_err(internal)?,
        required_credentials: CampaignScope::GatewayIdentity.required_credentials(),
    };

    let document = credential_document(vault_path)?;
    let approval = CampaignApprovalSession::new(
        &campaign,
        &document,
        &identity,
        &anchor_key,
        &vault.rp_id,
        &format!("https://{}", vault.rp_id),
        now,
    )
    .map_err(internal)?;

    Ok(OpenedGatewayRollback {
        keys,
        campaign: Box::new(campaign),
        transition: Box::new(transition),
        identity,
        anchor_key,
        approval,
    })
}

impl OpenedGatewayRollback {
    /// One key: its approval, then the proof that the same key opens the vault.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        approve_one(
            &mut self.keys,
            &mut self.approval,
            self.campaign.expires_at,
            key,
            now,
        )
    }

    /// Signs the selection under `CA-PQ`. Nothing is recorded: the authorization goes to the
    /// gateway at once, and a refusal there needs a new approval.
    pub fn sign(
        self,
        vault_path: &Path,
        now: u64,
    ) -> Result<CertificateServiceRollbackAuthorization, GatewayRefusal> {
        let Self {
            keys,
            campaign,
            transition,
            identity,
            anchor_key,
            approval,
        } = self;
        if now >= campaign.expires_at || keys.openings.is_empty() {
            return Err(GatewayRefusal::Internal(
                "la campagne a expiré avant la signature : rien n'a été signé.".into(),
            ));
        }
        ensure_same_vault(vault_path, &keys.vault).map_err(internal)?;
        let approval = approval.finish(now).map_err(internal)?;

        let ValidatedKeys {
            vault, openings, ..
        } = keys;
        signing::sign_service_rollback(
            &vault,
            &openings[0],
            &identity,
            &anchor_key,
            &ServiceRollbackDecision {
                transition: &transition,
                campaign_fingerprint: approval.campaign_fingerprint,
                expires_at: campaign.expires_at,
            },
            now,
        )
        .map_err(internal)
    }
}

/// Installs the signed selection on the gateway. The gateway answers when it lapses.
pub fn carry_rollback(
    remote: &dyn GatewayIdentityRemote,
    authorization: CertificateServiceRollbackAuthorization,
) -> Result<GatewayRollbackRead, GatewayRefusal> {
    remote.rollback(&authorization).map_err(refused_by_gateway)
}

fn abort_of(decision: &SignedGatewayDecision) -> Result<&GatewayTransitionAbort, GatewayRefusal> {
    match decision.result.objects.first() {
        Some(TrustUpdateObject::GatewayTransitionAbort(abort)) => Ok(&**abort),
        _ => Err(GatewayRefusal::Internal(
            "la décision enregistrée ne contient pas d'annulation gateway.".into(),
        )),
    }
}

/// Sends the decision to Astra. A lost answer is replayed with the same bytes and no key:
/// the campaign is asked again for a fresh token, and Astra takes the identical result.
fn deposit(
    remote: &dyn GatewayIdentityRemote,
    decision: &SignedGatewayDecision,
) -> Result<(), GatewayRefusal> {
    let request = remote
        .fetch_campaign(&decision.operation_id)
        .map_err(unreachable_or_internal)?;
    if request.campaign.campaign_id != decision.campaign_id {
        return Err(GatewayRefusal::Internal(
            "la campagne relue n'est pas celle de la décision enregistrée.".into(),
        ));
    }
    match remote.submit_campaign(
        &decision.operation_id,
        &request.result_token,
        &decision.result,
    ) {
        Ok(SigningOperationState::Approved) => Ok(()),
        Ok(SigningOperationState::AwaitingOperator) => Err(GatewayRefusal::Internal(
            "Astra n'a pas enregistré ce dépôt.".into(),
        )),
        Err(error) => Err(refused_by_gateway(error)),
    }
}

/// The recorded decision, if one is waiting. A decision whose campaign has expired before
/// Astra accepted the deposit is discarded: an expired campaign cannot take it. Once it is
/// deposited it waits for the installation and the publication whatever the clock says.
pub fn pending(vault_path: &Path, now: u64) -> Result<Option<SignedGatewayDecision>> {
    let path = record_path(vault_path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("lecture de {}", path.display())),
    };
    let signed: SignedGatewayDecision = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "lecture de la décision d'identité gateway en attente {}",
            path.display()
        )
    })?;
    if now >= signed.expires_at && !signed.deposited {
        clear(vault_path)?;
        return Ok(None);
    }
    Ok(Some(signed))
}

fn transition_of(
    decision: &SignedGatewayDecision,
) -> Result<&GatewayIdentityTransition, GatewayRefusal> {
    match decision.result.objects.first() {
        Some(TrustUpdateObject::GatewayIdentityTransition(transition)) => Ok(&**transition),
        _ => Err(GatewayRefusal::Internal(
            "la décision enregistrée ne contient pas de transition gateway.".into(),
        )),
    }
}

fn renewal_reason(emergency_replacement: bool, key_recovery: bool) -> RotationReason {
    match (emergency_replacement, key_recovery) {
        (true, _) => RotationReason::EmergencyReplacement,
        (false, true) => RotationReason::KeyRecovery,
        (false, false) => RotationReason::Scheduled,
    }
}

/// The credential document beside the vault, which the approvals are checked against.
fn credential_document(vault_path: &Path) -> Result<CredentialRegistry, GatewayRefusal> {
    credentials::load(&credentials::path_beside(vault_path))
        .map_err(internal)?
        .ok_or_else(|| {
            GatewayRefusal::Internal(
                "aucun document de credentials : l'émettre par `astra-signer bindings`. Rien n'a été signé."
                    .into(),
            )
        })
}

/// The gateway's clock, which bounds the cancellation and the overlap. An older gateway
/// sends none, and the workstation's instant stands in: the gateway checks both bounds
/// again on its own clock when it installs the document, so this check only spares a
/// touch, and refusing here would block the gesture for no safety gain.
fn gateway_clock(gateway: &GatewayIdentityRead, now: u64) -> u64 {
    gateway.now_unix.unwrap_or(now)
}

/// The label the campaign carries, which the operator reads on the door's screen.
fn reason_label(options: RenewalOptions) -> &'static str {
    if options.key_recovery {
        "Récupération de la clé de la gateway"
    } else {
        "Renouvellement de l'identité de la gateway"
    }
}

/// `at` plus `days`, or a refusal when the span does not fit.
fn after(at: u64, days: u64) -> Result<u64, GatewayRefusal> {
    days.checked_mul(DAY_SECS)
        .and_then(|span| at.checked_add(span))
        .ok_or_else(|| GatewayRefusal::Internal("durée hors bornes".into()))
}

fn record_path(vault_path: &Path) -> std::path::PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(PENDING_FILE)
}

/// Writes the record, atomically and privately, like the rotation journal.
fn save(path: &Path, signed: &SignedGatewayDecision) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes =
        serde_json::to_vec_pretty(signed).context("sérialisation de la décision gateway")?;
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

/// A 403 on the door's open call. The door refuses a campaign it will not open, and a
/// second one while a decision waits, alike; the tunnel exposes only the status. So the
/// local record is read: a decision waiting is that fact, and anything else is an
/// unnamed refusal.
fn refused_by_door(vault_path: &Path, now: u64) -> GatewayRefusal {
    match pending(vault_path, now) {
        Ok(Some(_)) => GatewayRefusal::AlreadyOpen,
        Ok(None) => GatewayRefusal::Internal(
            "Astra a refusé d'ouvrir la campagne d'identité de la gateway.".into(),
        ),
        Err(error) => internal(error),
    }
}

/// A refusal the gateway or Astra gives for good (any status but the three that say only
/// that something could not answer) keeps its sentence. The record stays: nothing is
/// retried on its own.
fn refused_by_gateway(error: anyhow::Error) -> GatewayRefusal {
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refusal) if !matches!(refusal.status, 429 | 500 | 503) => {
            GatewayRefusal::GatewayRefused(refusal.to_string())
        }
        _ => unreachable_or_internal(error),
    }
}

/// An unreachable call before any signature says so.
fn before_signing(error: anyhow::Error) -> GatewayRefusal {
    match unreachable_or_internal(error) {
        GatewayRefusal::Unreachable => GatewayRefusal::UnreachableBeforeSigning,
        other => other,
    }
}

/// A call that failed for want of an answer is `Unreachable`; a gateway answer of 503
/// says the same about Astra behind it. Anything else is a failure to name.
fn unreachable_or_internal(error: anyhow::Error) -> GatewayRefusal {
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refusal) if refusal.status == 503 => GatewayRefusal::Unreachable,
        _ if is_unreachable(&error) => GatewayRefusal::Unreachable,
        _ => GatewayRefusal::Internal(format!("{error:#}")),
    }
}

fn internal<E: Into<anyhow::Error>>(error: E) -> GatewayRefusal {
    GatewayRefusal::Internal(format!("{:#}", error.into()))
}

#[cfg(test)]
mod tests;
