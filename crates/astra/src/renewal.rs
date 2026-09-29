//! The relayed ordinary renewal, from Astra's side — spec §7.2, §7.3, §8.1.2.
//!
//! # The order, and why every step of it is load-bearing
//!
//! ```text
//! Orion --WireGuard--> Helios --veth/mTLS--> Astra   open()
//!                                            Astra verifies the 80 % gate
//!                                            Astra issues the two leaves
//!                             <-- stage authorization on the veth --
//!                             -- signed receipt on the same link -->
//!                                            Astra releases the grant
//! Orion <-- grant, through Helios --
//! Orion -- commit --WireGuard--> Helios
//! ```
//!
//! Three properties are decided by that order alone:
//!
//! - **nothing is issued before the renewal window**. [`open`] refuses a
//!   request that is not yet due; after it, the signed request and the pinned
//!   delegated policy authorize only `active + 1`;
//! - **the authorization never touches Orion**. It is handed to the gateway on
//!   the veth and the receipt comes back on that same relationship (§8.3,
//!   amendment of 16 August 2026). The client is a client of the gateway's private API, not
//!   a courier between two authorities;
//! - **no grant before the receipt**. Astra cannot release the leaves it just
//!   signed until the gateway says, under its own served leaf, that the
//!   candidate is on its disk.
//!
//! # What a failure leaves behind
//!
//! Once the request is accepted, its exact fingerprint and the exact random
//! issuance bytes are persisted. A transport failure therefore leaves
//! `pending_grant`, not a second ceremony: polling the same `operation_id`
//! replays the same authorization. The gateway treats that stage idempotently
//! and its signed lease bounds any reservation that cannot be completed.
//!
//! # Scheduled and manual authorization
//!
//! An ordinary renewal is authorized automatically once its active leaf is
//! due. A manual campaign (§7.6) is approved once, for a set of targets,
//! **before** any of their requests exist. [`open`] looks the campaign up in
//! [`crate::signing::SigningOperationStore`], and if one covers this peer at
//! this exact state, the operation is born already approved and goes straight
//! to issuance.
//!
//! A campaign is also the one thing that legitimately overrides the 80 %
//! threshold: renewing ahead of it is what a manual action is *for*. It does
//! not override expiry — an ordinary rotation proves possession with a leaf no
//! validator accepts, and §7.5 is the only way back from there.

use std::sync::Arc;

use aether::certificates::transport::{ClientRenewalOperationView, ClientRenewalSignerRequest};
use aether::certificates::{
    approval::{
        AstraCampaignApprovalEvidence, AstraCredentialApprovalRequest, AstraRenewalApproval,
        AstraRenewalApprovalEvidence, MAX_APPROVAL_LIFETIME_SECS, PER_REQUEST_APPROVAL_CREDENTIALS,
    },
    capability::{CapabilityGrant, CapabilityRequirement, CapabilityScope},
    client::{ClientCertificateRotationRequest, IssuerKind},
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
    window::{TransitionWindow, MAX_OVERLAP_SECS, MAX_STAGE_LEASE_SECS},
    CERTIFICATE_FORMAT_VERSION,
};

use crate::operations::{Operation, OperationError};
use crate::planner::{urgency, RenewalUrgency};
use crate::registry::{PendingRotation, RegistryError};
use crate::service::AstraService;

/// Lease a staging authorization is given, in seconds.
///
/// One hour: comfortably inside the 24-hour ceiling of §7.2, and long enough
/// for a client to fetch its grant and commit even after a reboot. It is also
/// `activation_at`, because §7.2 requires `stage_expires_at <= activation_at`
/// and putting the two apart would only widen the span in which a candidate
/// exists and cannot be used.
pub const STAGE_LEASE_SECS: u64 = 3_600;

/// Life of a client leaf when the delegation allows at least that much.
///
/// Ninety days. The ceiling that actually applies is
/// `AstraIssuerAuthorization::maximum_leaf_lifetime_secs`, and the smaller of
/// the two wins — a delegation is an upper bound, never a target.
pub const DEFAULT_CLIENT_LEAF_LIFETIME_SECS: u64 = 90 * 24 * 3_600;

/// Life of a capability token, bounded by §8.2 and by the operation.
pub const CAPABILITY_TOKEN_LIFETIME_SECS: u64 = MAX_APPROVAL_LIFETIME_SECS;

/// Why a relayed renewal was refused.
///
/// Finer than what a client ever learns: the private link's caller is the
/// gateway, which holds the registry these reasons describe. The coarse class
/// is produced by [`RenewalError::refusal`].
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("the request names a peer other than the one the gateway resolved")]
    CallerMismatch,
    #[error("no admitted peer holds this identity")]
    UnknownPeer,
    #[error("this identity is revoked; no credential lifts that state")]
    Revoked,
    #[error(
        "this identity is not due for renewal: the ordinary window opens at 80 % of the leaf's \
         life (spec §4.3), and issuing before it would let a client renew on demand"
    )]
    NotDue,
    #[error(
        "this identity has expired: an ordinary renewal proves possession with a leaf that no \
         validator accepts, and the recovery path of §7.5 is the only way back"
    )]
    ExpiredIdentity,
    #[error(
        "automatic renewal is disabled until the current credential-free issuance policy has \
         been confirmed and delegated; an older policy pin cannot be broadened by a software \
         upgrade"
    )]
    AutomaticPolicyMigrationRequired,
    #[error("the request is refused: {0}")]
    Request(aether::certificates::CertificateError),
    #[error("the operator approval is refused: {0}")]
    Approval(aether::certificates::CertificateError),
    #[error("the capability token is refused: {0}")]
    Capability(aether::certificates::CertificateError),
    #[error(
        "this authority holds no credential document: no operator credential can approve a \
         renewal, so the ceremony has no allow-list to run against. Copy the one \
         `astra-signer bindings` emits."
    )]
    NoOperatorCredential,
    #[error("operation: {0}")]
    Operation(#[from] OperationError),
    #[error("registry: {0}")]
    Registry(#[from] RegistryError),
    #[error("delegated issuer: {0}")]
    Issuer(#[from] crate::issuer::IssuerError),
    #[error(
        "this authority has no delegated issuer: `AstraIssuerAuthorization` has to be signed by \
         the operator companion before any ordinary renewal can be issued"
    )]
    NoIssuer,
    #[error(
        "this authority has no private channel to its gateway: a staging authorization has \
         nowhere to go, and no receipt could come back"
    )]
    NoGatewayChannel,
    #[error("the gateway refused or could not be reached: {0}")]
    Gateway(String),
    #[error("the authority could not build this object: {0}")]
    Internal(aether::certificates::CertificateError),
}

impl RenewalError {
    /// The bounded class the gateway — and through it the client — learns.
    ///
    /// Everything that is not an authority-side failure collapses to
    /// `Rejected`: on this link the reason travels in the protected log, and a
    /// finer taxonomy relayed to a peer is an oracle on other peers' state.
    pub fn refusal(&self) -> aether::certificates::transport::TrustUpdateRefusal {
        use aether::certificates::transport::TrustUpdateRefusal as Refusal;
        match self {
            Self::Registry(RegistryError::Io(_) | RegistryError::Corrupt(_))
            | Self::Operation(OperationError::Persistence(_) | OperationError::Corrupt(_))
            | Self::Internal(_) => Refusal::Internal,
            Self::NoIssuer
            | Self::NoGatewayChannel
            | Self::Gateway(_)
            | Self::AutomaticPolicyMigrationRequired => Refusal::Unavailable,
            _ => Refusal::Rejected,
        }
    }
}

/// Learns a peer from the gateway, the first time it renews.
///
/// Astra does not admit anyone — the gateway does, and it is the end that was
/// handed the leaves at enrolment. So the registry is filled here, from the
/// private channel, rather than by a second admission an operator would have
/// to perform twice and keep equal. §8.3 already publishes the state; this
/// transcribes it.
///
/// Two checks before it is believed, even though the channel is mTLS and the
/// peer is the gateway: the leaf must name this WireGuard key, and it must
/// hash to the fingerprint of the active generation it comes with. They cost
/// nothing and turn a disagreement between the two registries into a refusal
/// instead of a renewal checked against the wrong public key.
///
/// Without a channel this is exactly the old behaviour — an unknown peer stays
/// unknown, and the renewal is refused by name.
pub(crate) async fn transcribe_peer(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    now_unix: u64,
) -> Result<astra_channel::PeerCertificateStateView, RenewalError> {
    // Le pair est **relu à chaque fois**, et non transcrit une seule fois.
    //
    // La gateway est ce qui promeut : elle seule sait quelle génération elle
    // sert aujourd'hui. Un enregistrement écrit une fois puis figé restait sur
    // la génération d'admission, et `open` vérifie les signatures sous la clé
    // PQ active que ce registre détient — donc une identité récupérée par le
    // §7.5 se voyait refuser son renouvellement suivant, sous une clé morte.
    //
    // Le coût est un appel sur le canal privé par opération de cycle de vie,
    // qui sont rares et qui passent de toute façon par ce canal ensuite. La
    // réconciliation n'écrit rien quand rien n'a bougé, et ne recule jamais.
    let Some(gateway) = service.gateway.as_ref() else {
        return Err(RenewalError::UnknownPeer);
    };
    let view = gateway
        .peer_state(caller)
        .await
        .map_err(|error| RenewalError::Gateway(error.to_string()))?;
    if view.active_pq_certificate.wireguard_public_key.trim() != caller.to_base64() {
        return Err(RenewalError::UnknownPeer);
    }
    let fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&view.active_pq_certificate)
            .map_err(RenewalError::Internal)?;
    if !fingerprint.matches(&view.state.active.pq_certificate_fingerprint) {
        return Err(RenewalError::UnknownPeer);
    }
    let record = crate::registry::PeerRecord {
        name: view.name.clone(),
        client_wg_public_key: *caller,
        active: view.state.active.clone(),
        active_pq_certificate: view.active_pq_certificate.clone(),
        pending: None,
        revoked: view.state.revoked,
        revocation_epoch: view.state.revocation_epoch,
        admission_pq_ca: view.admission_pq_ca.clone(),
    };
    service
        .registry
        .lock()
        .await
        .reconcile_peer(record, now_unix)?;
    Ok(view)
}

/// Step 1: opens an operation for a request the gateway just relayed.
///
/// Everything is verified before anything is stored: the caller owns the
/// request, the peer is admitted and not revoked, the active leaf is past its
/// 80 % threshold, and the three signatures of §7.1 verify under the **active**
/// PQ key the registry holds — never under a key the request supplied.
///
/// A due request proceeds immediately. The delegated issuer remains bounded
/// to an admitted, non-revoked peer and the exact `active + 1` generation.
pub async fn open(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    request: Box<ClientCertificateRotationRequest>,
    now_unix: u64,
) -> Result<ClientRenewalOperationView, RenewalError> {
    if request.client_wg_public_key != *caller {
        return Err(RenewalError::CallerMismatch);
    }
    transcribe_peer(service, caller, now_unix).await?;

    let (peer, trust_domain_id, gateway_key, server_name, policy_pin, rp_id, service_epoch) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        let peer = registry
            .peer(caller)
            .ok_or(RenewalError::UnknownPeer)?
            .clone();
        (
            peer,
            state.trust_domain_id,
            state.gateway_wg_public_key,
            state.server_name.clone(),
            state.astra_policy_fingerprint,
            state.webauthn_rp_id.clone(),
            state.astra_service_key_epoch,
        )
    };
    if peer.revoked {
        return Err(RenewalError::Revoked);
    }

    // An approved manual campaign covering this identity, in the exact state
    // the operator read (§7.6). Looked up before the threshold, because it is
    // the one thing that legitimately overrides it: a campaign exists to renew
    // ahead of 80 %, and refusing it there would make the manual action mean
    // «renew the peers that were going to renew anyway».
    let campaign = {
        let signing = service.signing.lock().await;
        signing
            .approved_for_client(
                caller,
                peer.active.generation,
                &peer.active.tls_certificate_fingerprint,
                &peer.active.pq_certificate_fingerprint,
                now_unix,
            )
            .map(|operation| {
                (
                    operation.campaign.clone(),
                    operation
                        .approval()
                        .cloned()
                        .expect("an approved operation holds its approval"),
                )
            })
    };

    // The threshold decides whether the delegated policy may act. A campaign
    // remains the explicit operator-authorized way to renew earlier.
    match urgency(&peer.active, now_unix).map_err(RenewalError::Internal)? {
        RenewalUrgency::Idle if campaign.is_none() => return Err(RenewalError::NotDue),
        // Expired is never lifted here, campaign or not: an ordinary rotation
        // proves possession with a leaf no validator accepts, and §7.5 is the
        // only way back. A campaign that could revive one would be a campaign
        // that re-admits.
        RenewalUrgency::Expired => return Err(RenewalError::ExpiredIdentity),
        _ => {}
    }

    let active_pq_key = MlDsa87PublicKey::parse(&peer.active_pq_certificate.ml_dsa_87_public_key)
        .map_err(RenewalError::Internal)?;
    request
        .verify(
            &active_pq_key,
            &trust_domain_id,
            &gateway_key,
            &server_name,
            &peer.active,
            caller,
            now_unix,
        )
        .map_err(RenewalError::Request)?;

    let operation_id = fresh_id().map_err(RenewalError::Internal)?;
    let approval_request = build_approval_request(
        service,
        operation_id,
        &request,
        &peer.active.generation,
        trust_domain_id,
        gateway_key,
        &rp_id,
        service.approval_credential_registry_epoch,
        service_epoch,
        now_unix,
    )?;

    let mut operation = Operation::awaiting_operator(
        operation_id,
        *caller,
        request,
        Box::new(approval_request),
        now_unix,
    );
    // A covering campaign is spent here, in the same durable write that opens
    // the operation: an operation persisted as `awaiting_operator` and only
    // then moved would ask an operator, on a restart between the two, for a
    // touch that has already happened.
    let campaign_authorized = if let Some((campaign, approval)) = campaign {
        let evidence = campaign_evidence(service, *campaign, approval).await?;
        let fingerprint = evidence.fingerprint().map_err(RenewalError::Internal)?;
        operation.consume_campaign_approval(fingerprint, Box::new(evidence))?;
        true
    } else {
        policy_pin
            .assert_allows_automatic_renewal(trust_domain_id, gateway_key, &server_name)
            .map_err(|_| RenewalError::AutomaticPolicyMigrationRequired)?;
        operation.authorize_automatic()?;
        false
    };
    let mut operations = service.operations.lock().await;
    operations.open(operation, now_unix)?;
    operations.persist()?;
    let requested_generation = operations
        .get(&operation_id, caller, now_unix)
        .map_err(RenewalError::Operation)?
        .request
        .requested_generation;
    drop(operations);

    let mut registry = service.registry.lock().await;
    if let Err(error) = registry.record(
        crate::audit::AuditEvent::ClientRenewalRequested {
            peer: peer.name.clone(),
            generation: requested_generation,
        },
        now_unix,
    ) {
        drop(registry);
        let mut operations = service.operations.lock().await;
        operations.remove(&operation_id);
        operations.persist()?;
        return Err(RenewalError::Registry(error));
    }
    if campaign_authorized {
        tracing::info!(
            peer = %peer.name,
            operation = %operation_id,
            generation = requested_generation,
            "renewal authorized by an approved campaign; no per-peer credential is asked"
        );
    } else {
        tracing::info!(
            peer = %peer.name,
            operation = %operation_id,
            generation = requested_generation,
            "due renewal authorized automatically by the delegated policy"
        );
    }
    drop(registry);
    // Both paths are already authorized: scheduled by the narrow delegation,
    // or manually by a previously approved campaign. A failure here leaves
    // `pending_grant`, which the next poll resumes with identical bytes.
    resume_stage(service, caller, &operation_id, now_unix).await?;
    let operations = service.operations.lock().await;
    let operation = operations.get(&operation_id, caller, now_unix)?;
    mint_view(service, operation, now_unix).await
}

/// Assembles the campaign evidence a delegated staging will carry (§7.2).
///
/// The credential registry and the WebAuthn origin come from **this** service,
/// not from the campaign: they are what the gateway re-derives the assertions
/// against, and a campaign that supplied them would be a campaign that chose
/// the allow-list it is checked under.
async fn campaign_evidence(
    service: &Arc<AstraService>,
    campaign: aether::certificates::status::AstraRotationCampaign,
    approval: aether::certificates::status::CampaignApproval,
) -> Result<AstraCampaignApprovalEvidence, RenewalError> {
    let registry = service
        .approval_credential_registry
        .as_deref()
        .cloned()
        .ok_or(RenewalError::NoOperatorCredential)?;
    let rp_id = service.registry.lock().await.state().webauthn_rp_id.clone();
    Ok(AstraCampaignApprovalEvidence {
        campaign,
        approval,
        credential_registry: registry,
        webauthn_origin: format!("https://{rp_id}"),
    })
}

/// Steps 3 and 7: reads one operation on behalf of the peer that owns it.
pub async fn read(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    now_unix: u64,
) -> Result<ClientRenewalOperationView, RenewalError> {
    let mut operations = service.operations.lock().await;
    // Re-mint the challenge when the current one can no longer be answered
    // inside its own five-minute window; §8.1.2 allows exactly that, and it
    // changes neither generation nor candidate keys.
    let needs_refresh = {
        let operation = operations.get(operation_id, caller, now_unix)?;
        operation.state
            == aether::certificates::transport::ClientRenewalOperationState::AwaitingOperator
            && now_unix >= operation.approval_request.expires_at
    };
    if needs_refresh {
        let refreshed =
            refresh_challenge(service, &mut operations, caller, operation_id, now_unix).await?;
        let operation = operations.get_mut(operation_id, caller, now_unix)?;
        operation.refresh_approval_request(Box::new(refreshed))?;
        operations.persist()?;
    }
    let state = operations.get(operation_id, caller, now_unix)?.state;
    drop(operations);
    match state {
        aether::certificates::transport::ClientRenewalOperationState::PendingGrant => {
            resume_stage(service, caller, operation_id, now_unix).await?;
        }
        aether::certificates::transport::ClientRenewalOperationState::PendingCommit => {
            reconcile_released_grant(service, caller, operation_id, now_unix).await?;
        }
        _ => {}
    }
    let operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    mint_view(service, operation, now_unix).await
}

/// Step 4a: what the companion has to display before it asks for a touch.
pub async fn signer_request(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    token: &str,
    now_unix: u64,
) -> Result<ClientRenewalSignerRequest, RenewalError> {
    let operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    authenticate(
        service,
        CapabilityScope::SignerRequestRead,
        operation,
        token,
        now_unix,
    )
    .await?;

    let (authority_url, webauthn_rp_id) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        (state.authority_url.clone(), state.webauthn_rp_id.clone())
    };
    // The allow-list travels with the document that authorizes it. Whoever
    // runs the ceremony verifies that document under `CA-PQ` themselves: an
    // allow-list this service merely asserted would let a compromised Astra
    // name a credential nobody ever enrolled.
    let credential_registry = service
        .approval_credential_registry
        .clone()
        .ok_or(RenewalError::NoOperatorCredential)?;
    Ok(ClientRenewalSignerRequest {
        operation_id: *operation_id,
        approval_request: operation.approval_request.clone(),
        credential_registry,
        authority_url,
        webauthn_rp_id,
    })
}

/// Steps 4b, 5, 6 and 7: the assertion arrives, and the rotation runs to a
/// grant or fails.
///
/// The approval is verified against **this operation's own** approval request,
/// which Astra holds — never against one the same message supplied. The three
/// independent proofs of [`AstraRenewalApprovalEvidence::verify`] then run in
/// their own order: the credential binding under `CA-PQ`, the assertion under
/// that credential's key, and the challenge re-derived from the request.
pub async fn signer_result(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    token: &str,
    approval: Box<AstraRenewalApproval>,
    now_unix: u64,
) -> Result<ClientRenewalOperationView, RenewalError> {
    let mut operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    authenticate(
        service,
        CapabilityScope::SignerResultSubmit,
        operation,
        token,
        now_unix,
    )
    .await?;

    let submission_fingerprint = approval.fingerprint();
    if operation.is_idempotent_submission(&submission_fingerprint)? {
        let state = operation.state;
        drop(operations);
        match state {
            aether::certificates::transport::ClientRenewalOperationState::PendingGrant => {
                resume_stage(service, caller, operation_id, now_unix).await?;
            }
            aether::certificates::transport::ClientRenewalOperationState::PendingCommit => {
                reconcile_released_grant(service, caller, operation_id, now_unix).await?;
            }
            _ => {}
        }
        let operations = service.operations.lock().await;
        let operation = operations.get(operation_id, caller, now_unix)?;
        return mint_view(service, operation, now_unix).await;
    }

    let approval_request = (*operation.approval_request).clone();
    let mut approval = *approval;
    let request_fingerprint = operation.request_fingerprint;

    let (
        trust_domain_id,
        gateway_key,
        rp_id,
        ca_public_key,
        ca_epoch,
        service_epoch,
        registry_epoch,
        peer,
    ) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        let peer = registry
            .peer(caller)
            .ok_or(RenewalError::UnknownPeer)?
            .clone();
        (
            state.trust_domain_id,
            state.gateway_wg_public_key,
            state.webauthn_rp_id.clone(),
            state.ca_public_key.clone(),
            state.ca_epoch,
            state.astra_service_key_epoch,
            service.approval_credential_registry_epoch,
            peer,
        )
    };
    if peer.revoked {
        return Err(RenewalError::Revoked);
    }

    // `astra-signer` cannot hold the online service key and deliberately
    // submits a placeholder signature.  Verify every independent proof before
    // countersigning it: otherwise a valid companion result is always refused
    // (full verification on the placeholder), or Astra signs invalid evidence
    // before discovering it.
    approval
        .verify_operator_evidence(
            &approval_request,
            &ca_public_key,
            service_epoch,
            &trust_domain_id,
            ca_epoch,
            registry_epoch,
            now_unix,
        )
        .map_err(RenewalError::Approval)?;
    approval = approval
        .sign(&service.service_private_key)
        .map_err(RenewalError::Approval)?;
    let evidence = AstraRenewalApprovalEvidence {
        approval_request,
        approval,
    };

    evidence
        .verify(
            &request_fingerprint,
            &ca_public_key,
            &service.service_public_key,
            service_epoch,
            &trust_domain_id,
            &gateway_key,
            caller,
            &rp_id,
            peer.active.generation,
            ca_epoch,
            registry_epoch,
            now_unix,
        )
        .map_err(RenewalError::Approval)?;

    // Recorded before anything is issued. The exact same companion document
    // can retrieve the completed operation after a lost response; different
    // bytes under this identifier can never authorize a second issuance.
    operations
        .get_mut(operation_id, caller, now_unix)?
        .consume_approval(submission_fingerprint, Box::new(evidence))?;
    operations.persist()?;
    drop(operations);

    resume_stage(service, caller, operation_id, now_unix).await?;

    let operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    mint_view(service, operation, now_unix).await
}

/// Steps 5 to 7: issue, stage on the veth, read the receipt back, grant.
///
/// Split out because it is the part that can fail after a human has already
/// touched a key. Every random output is persisted before it leaves Astra, so
/// retries resume this exact issuance rather than spending another approval.
async fn resume_stage(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    now_unix: u64,
) -> Result<(), RenewalError> {
    let issuer = service.issuer.as_ref().ok_or(RenewalError::NoIssuer)?;
    let gateway = service
        .gateway
        .as_ref()
        .ok_or(RenewalError::NoGatewayChannel)?;
    let (request, approval, stored_authorization, stored_receipt) = {
        let operations = service.operations.lock().await;
        let operation = operations.get(operation_id, caller, now_unix)?;
        if operation.state
            != aether::certificates::transport::ClientRenewalOperationState::PendingGrant
        {
            return Ok(());
        }
        (
            operation.request.clone(),
            operation
                .approval()
                .ok_or(OperationError::Corrupt("approval evidence missing"))?,
            operation.stage_authorization().cloned(),
            operation.receipt().cloned(),
        )
    };
    let peer = {
        let registry = service.registry.lock().await;
        registry
            .peer(caller)
            .ok_or(RenewalError::UnknownPeer)?
            .clone()
    };
    if peer.revoked {
        return Err(RenewalError::Revoked);
    }

    let authorization = match stored_authorization {
        Some(authorization) => authorization,
        None => {
            let plan = plan_window(
                &peer.active,
                request.expires_at,
                issuer.authorization.maximum_leaf_lifetime_secs,
                now_unix,
            )?;
            // The family, and therefore the reason, decided once: the leaves
            // are issued under the same reason the authorization will carry.
            let (tls_leaf, pq_leaf) = issuer.issue_generation(
                &request,
                &peer.name,
                &plan.window,
                (plan.leaf_not_before, plan.leaf_not_after),
                fresh_serial().map_err(RenewalError::Internal)?,
                approval.reason(),
            )?;
            let stage_id = fresh_id().map_err(RenewalError::Internal)?;
            let authorization = issuer.authorize_stage(
                &request,
                &peer.active,
                stage_id,
                // The anchor the peer's active generation already chains to.
                peer.active.tls_ca_certificate_fingerprint,
                tls_leaf,
                pq_leaf,
                plan.window,
                now_unix,
                plan.stage_expires_at,
                approval,
            )?;
            // Persist all random issuance material before reserving or sending
            // it. A restart replays these exact bytes and never creates a
            // second candidate under the same operator touch.
            let mut operations = service.operations.lock().await;
            operations
                .get_mut(operation_id, caller, now_unix)?
                .record_stage(Box::new(authorization.clone()))?;
            operations.persist()?;
            authorization
        }
    };
    let stage_id = authorization.stage_id;
    let candidate =
        crate::DelegatedIssuer::candidate(&authorization).map_err(RenewalError::Internal)?;

    // Reserved before the object leaves this process: a staging the gateway
    // accepts while the registry still believes nothing is in flight would let
    // a second request claim the same `active + 1`.
    {
        let mut registry = service.registry.lock().await;
        registry.open_rotation(
            caller,
            PendingRotation {
                stage_id,
                request_fingerprint: authorization.request_fingerprint,
                candidate,
                window: authorization.window,
                stage_expires_at: authorization.stage_expires_at,
                granted: false,
            },
            now_unix,
        )?;
    }
    // The authorization goes to the gateway and the receipt comes back on the
    // same relationship. Orion sees neither (§8.3, 16 August 2026).
    let receipt = match stored_receipt {
        Some(receipt) => receipt,
        None => gateway
            .stage(&authorization)
            .await
            .map_err(|error| RenewalError::Gateway(error.to_string()))?,
    };

    let gateway_leaf = &peer.active_pq_certificate;
    let _ = gateway_leaf;
    let (gateway_pq_key, gateway_leaf_fingerprint) = match gateway_identity(service).await {
        Ok(identity) => identity,
        Err(error) => {
            return Err(error);
        }
    };

    // The grant exists only against a receipt that verifies against this exact
    // authorization — every field, not only the identifier.
    let grant = match issuer.release_grant(
        &authorization,
        &receipt,
        &gateway_pq_key,
        &gateway_leaf_fingerprint,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            return Err(RenewalError::Issuer(error));
        }
    };

    {
        let mut operations = service.operations.lock().await;
        let operation = operations.get_mut(operation_id, caller, now_unix)?;
        operation.record_receipt(Box::new(receipt))?;
        operation.record_grant(Box::new(grant))?;
        operations.persist()?;
    }
    reconcile_released_grant(service, caller, operation_id, now_unix).await?;
    tracing::info!(
        peer = %peer.name,
        operation = %operation_id,
        stage = %stage_id,
        "grant released against the gateway's signed receipt"
    );
    Ok(())
}

/// Repairs the only cross-file cut in grant publication.
///
/// The complete signed grant is persisted in the operation journal first: at
/// that instant a client may already have received it, so Astra may never
/// withdraw it.  The registry audit bit is a second atomic file.  A crash
/// between both writes is repaired on the next poll by matching the exact
/// `stage_id` before setting the bit idempotently.
async fn reconcile_released_grant(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    now_unix: u64,
) -> Result<(), RenewalError> {
    let stage_id = {
        let operations = service.operations.lock().await;
        let operation = operations.get(operation_id, caller, now_unix)?;
        if operation.state
            != aether::certificates::transport::ClientRenewalOperationState::PendingCommit
        {
            return Ok(());
        }
        operation
            .stage_id()
            .ok_or(OperationError::Corrupt("granted operation has no stage"))?
    };

    let mut registry = service.registry.lock().await;
    let pending = registry
        .peer(caller)
        .ok_or(RenewalError::UnknownPeer)?
        .pending
        .as_ref()
        .ok_or(RegistryError::NoRotation)?;
    if pending.stage_id != stage_id {
        return Err(RenewalError::Operation(OperationError::Corrupt(
            "grant and registry name different stages",
        )));
    }
    registry.mark_granted(caller, now_unix)?;
    Ok(())
}

/// The gateway leaf a receipt must be signed by.
///
/// Read back over the private channel, from the daemon that serves it — never
/// from Astra's registry. The two differ exactly when it matters: a rotation
/// the gateway has not restarted for leaves a newer leaf on its disk that no
/// client is offered, and a receipt is signed by what is **served**. Verifying
/// against a copy Astra holds would be verifying against a key that signed
/// nothing.
///
/// The fingerprint is recomputed here rather than taken from the answer. The
/// gateway sends its own, and it is compared: a disagreement is then a
/// disagreement about identity, and not a signature failure three steps later.
async fn gateway_identity(
    service: &Arc<AstraService>,
) -> Result<(MlDsa87PublicKey, Fingerprint), RenewalError> {
    let channel = service
        .gateway
        .as_ref()
        .ok_or(RenewalError::NoGatewayChannel)?;
    let view = channel
        .gateway_identity()
        .await
        .map_err(|error| RenewalError::Gateway(error.to_string()))?;
    let fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&view.pq_certificate)
            .map_err(RenewalError::Internal)?;
    if !fingerprint.matches(&view.pq_certificate_fingerprint) {
        return Err(RenewalError::Gateway(
            "the gateway's leaf and the fingerprint it announced do not describe the same \
             identity"
                .into(),
        ));
    }
    let key = MlDsa87PublicKey::parse(&view.pq_certificate.ml_dsa_87_public_key)
        .map_err(RenewalError::Internal)?;
    Ok((key, fingerprint))
}

/// The instants one candidate generation is issued for.
struct WindowPlan {
    window: TransitionWindow,
    stage_expires_at: u64,
    leaf_not_before: u64,
    leaf_not_after: u64,
}

/// Computes the window, the lease and the leaf's own validity together.
///
/// They are computed in one place because they constrain each other, and a
/// value chosen apart from the others is how a candidate ends up expiring
/// inside the overlap it was supposed to carry:
///
/// - `stage_expires_at <= min(request.expires_at, activation_at)` and at most
///   24 hours (§7.2);
/// - `not_before < activation_at < not_after`, overlap at most 30 days (§4.1);
/// - the leaf covers the whole window and outlives it strictly, or
///   `assert_client_leaf` refuses it at the gateway.
fn plan_window(
    active: &aether::certificates::client::ClientCertificateGeneration,
    request_expires_at: u64,
    maximum_leaf_lifetime_secs: u64,
    now_unix: u64,
) -> Result<WindowPlan, RenewalError> {
    use aether::certificates::CertificateError;

    let desired_stage_expires_at = now_unix
        .checked_add(STAGE_LEASE_SECS)
        .ok_or(CertificateError::ArithmeticOverflow)
        .map_err(RenewalError::Internal)?
        .min(request_expires_at)
        .min(
            now_unix
                .checked_add(MAX_STAGE_LEASE_SECS)
                .ok_or(CertificateError::ArithmeticOverflow)
                .map_err(RenewalError::Internal)?,
        );
    // The outgoing generation must still be cryptographically valid at
    // activation and the overlap must remain strictly positive.  Shorten the
    // lease when necessary; never manufacture an overlap past the old leaf's
    // expiry as the previous code did.
    let last_activation = active
        .not_after
        .checked_sub(1)
        .ok_or(CertificateError::InvalidValidityPeriod)
        .map_err(RenewalError::Internal)?;
    let stage_expires_at = desired_stage_expires_at.min(last_activation);
    if stage_expires_at <= now_unix {
        return Err(RenewalError::Internal(CertificateError::InvalidLease));
    }
    let activation_at = stage_expires_at;
    let not_after = active.not_after.min(
        activation_at
            .checked_add(MAX_OVERLAP_SECS)
            .ok_or(CertificateError::ArithmeticOverflow)
            .map_err(RenewalError::Internal)?,
    );
    let window = TransitionWindow::new(now_unix, activation_at, not_after)
        .map_err(RenewalError::Internal)?;

    let lifetime = DEFAULT_CLIENT_LEAF_LIFETIME_SECS.min(maximum_leaf_lifetime_secs);
    let leaf_not_after = now_unix
        .checked_add(lifetime)
        .ok_or(CertificateError::ArithmeticOverflow)
        .map_err(RenewalError::Internal)?;
    if leaf_not_after <= not_after {
        // The delegation's ceiling is shorter than the overlap the candidate
        // would have to carry. Refused here rather than at the gateway, where
        // it would read as an unexplained rejection at 80 % of a leaf's life.
        return Err(RenewalError::Internal(
            CertificateError::InvalidValidityPeriod,
        ));
    }
    Ok(WindowPlan {
        window,
        stage_expires_at,
        leaf_not_before: now_unix,
        leaf_not_after,
    })
}

/// Builds and signs the request an operator is shown (spec §2.4).
#[allow(clippy::too_many_arguments)]
fn build_approval_request(
    service: &Arc<AstraService>,
    operation_id: Id16,
    request: &ClientCertificateRotationRequest,
    active_generation: &u64,
    trust_domain_id: aether::certificates::encoding::TrustDomainId,
    gateway_wg_public_key: WireGuardKey,
    webauthn_rp_id: &str,
    credential_registry_epoch: u64,
    astra_service_key_epoch: u64,
    now_unix: u64,
) -> Result<AstraCredentialApprovalRequest, RenewalError> {
    let allowed_credential_ids = service.approval_credential_ids.clone();
    if allowed_credential_ids.is_empty() {
        // No credential may approve, so no operator can. Named rather than
        // producing a request nothing can answer.
        return Err(RenewalError::Approval(
            aether::certificates::CertificateError::UnknownCredential,
        ));
    }
    let unsigned = AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id,
        request_fingerprint: request.fingerprint(),
        trust_domain_id,
        gateway_wg_public_key,
        client_wg_public_key: request.client_wg_public_key,
        active_generation: *active_generation,
        requested_generation: request.requested_generation,
        credential_registry_epoch,
        webauthn_rp_id: webauthn_rp_id.to_string(),
        webauthn_origin: format!("https://{webauthn_rp_id}"),
        allowed_credential_ids,
        required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
        created_at: now_unix,
        expires_at: now_unix
            .checked_add(MAX_APPROVAL_LIFETIME_SECS)
            .ok_or(aether::certificates::CertificateError::ArithmeticOverflow)
            .map_err(RenewalError::Internal)?,
        astra_service_key_epoch,
        astra_signature: MlDsa87Signature::placeholder(),
    };
    unsigned
        .sign(&service.service_private_key)
        .map_err(RenewalError::Internal)
}

/// Re-mints the challenge of an operation still waiting for an operator.
async fn refresh_challenge(
    service: &Arc<AstraService>,
    operations: &mut crate::operations::OperationStore,
    caller: &WireGuardKey,
    operation_id: &Id16,
    now_unix: u64,
) -> Result<AstraCredentialApprovalRequest, RenewalError> {
    let (request, active_generation) = {
        let operation = operations.get(operation_id, caller, now_unix)?;
        (
            operation.request.clone(),
            operation.approval_request.active_generation,
        )
    };
    let registry = service.registry.lock().await;
    let state = registry.state();
    let (domain, gateway, rp_id, service_epoch) = (
        state.trust_domain_id,
        state.gateway_wg_public_key,
        state.webauthn_rp_id.clone(),
        state.astra_service_key_epoch,
    );
    drop(registry);
    build_approval_request(
        service,
        *operation_id,
        &request,
        &active_generation,
        domain,
        gateway,
        &rp_id,
        service.approval_credential_registry_epoch,
        service_epoch,
        now_unix,
    )
}

/// Mints the two capability tokens of an operation and builds its view.
async fn mint_view(
    service: &Arc<AstraService>,
    operation: &Operation,
    now_unix: u64,
) -> Result<ClientRenewalOperationView, RenewalError> {
    let manifest = operation.manifest_fingerprint();
    let expires_at = (now_unix + CAPABILITY_TOKEN_LIFETIME_SECS).min(operation.expires_at);
    if expires_at <= now_unix {
        return Ok(operation.view(None, None));
    }
    let tokens = service.capabilities.lock().await;
    let mint = |scope| -> Option<String> {
        let grant = CapabilityGrant::new(
            scope,
            operation.operation_id,
            manifest,
            None,
            now_unix,
            expires_at,
        )
        .ok()?;
        tokens.issue(&grant, operation.expires_at).ok()
    };
    let read = mint(CapabilityScope::SignerRequestRead);
    let submit = mint(CapabilityScope::SignerResultSubmit);
    Ok(operation.view(read, submit))
}

/// Authenticates a bearer token against the route's own requirement.
///
/// Every field of the requirement comes from the operation Astra holds, never
/// from the token being checked: a requirement read out of the credential
/// would require nothing.
async fn authenticate(
    service: &Arc<AstraService>,
    scope: CapabilityScope,
    operation: &Operation,
    token: &str,
    now_unix: u64,
) -> Result<(), RenewalError> {
    let manifest = operation.manifest_fingerprint();
    let requirement = CapabilityRequirement {
        scope,
        operation_id: &operation.operation_id,
        operation_manifest_fingerprint: &manifest,
        encrypted_vault_fingerprint: None,
        operation_expires_at: operation.expires_at,
    };
    service
        .capabilities
        .lock()
        .await
        .authenticate(token, &requirement, now_unix)
        .map(|_| ())
        .map_err(RenewalError::Capability)
}

/// This process's clock, read the same way everywhere else in the crate.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// A non-zero 16-byte identifier from the approved DRBG (spec §2.3.2).
pub(crate) fn fresh_id() -> Result<Id16, aether::certificates::CertificateError> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|_| aether::certificates::CertificateError::RandomnessUnavailable)?;
    Id16::new(bytes)
}

/// A certificate serial from the same door.
fn fresh_serial() -> Result<[u8; 16], aether::certificates::CertificateError> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|_| aether::certificates::CertificateError::RandomnessUnavailable)?;
    Ok(bytes)
}

/// The `issuer_kind` this module produces, restated so a change is visible.
///
/// Always [`IssuerKind::Astra`]: a `master` staging is signed by `CA-PQ`, which
/// this process does not hold.
pub const RELAYED_ISSUER_KIND: IssuerKind = IssuerKind::Astra;

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::ClientCertificateGeneration;

    fn generation(not_before: u64, not_after: u64) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            not_before,
            not_after,
        }
    }

    /// The three constraints of §7.2 and §4.1 hold together, and the leaf
    /// strictly outlives the window it carries.
    #[test]
    fn a_planned_window_satisfies_every_bound_it_is_read_against() {
        let active = generation(0, 100 * 24 * 3_600);
        let now = 85 * 24 * 3_600;
        let plan = plan_window(
            &active,
            now + 24 * 3_600,
            DEFAULT_CLIENT_LEAF_LIFETIME_SECS,
            now,
        )
        .expect("plan");

        assert_eq!(plan.window.not_before, now);
        assert_eq!(plan.window.activation_at, now + STAGE_LEASE_SECS);
        assert_eq!(plan.stage_expires_at, plan.window.activation_at);
        assert!(plan.stage_expires_at <= now + MAX_STAGE_LEASE_SECS);
        assert!(plan.window.overlap_secs() <= MAX_OVERLAP_SECS);
        plan.window.validate().expect("window");
        assert!(
            plan.leaf_not_after > plan.window.not_after,
            "a leaf that expires inside its own overlap is refused by the gateway"
        );
        assert!(plan.leaf_not_before <= plan.window.activation_at);
    }

    /// A request that expires sooner than the default lease shortens the
    /// lease, never the other way round.
    #[test]
    fn a_short_request_shortens_the_stage_lease() {
        let active = generation(0, 100 * 24 * 3_600);
        let now = 85 * 24 * 3_600;
        let plan =
            plan_window(&active, now + 300, DEFAULT_CLIENT_LEAF_LIFETIME_SECS, now).expect("plan");
        assert_eq!(plan.stage_expires_at, now + 300);
        assert_eq!(plan.window.activation_at, now + 300);
    }

    /// A delegation whose ceiling is shorter than the overlap the candidate
    /// carries is refused here, not at the gateway.
    #[test]
    fn a_delegation_too_short_for_its_own_overlap_is_refused() {
        let active = generation(0, 100 * 24 * 3_600);
        let now = 85 * 24 * 3_600;
        assert!(
            plan_window(&active, now + 24 * 3_600, STAGE_LEASE_SECS, now).is_err(),
            "a ceiling under the window was accepted"
        );
    }

    /// An active leaf about to expire gets only the overlap it can honestly
    /// provide; the window never extends its validity on paper.
    #[test]
    fn an_almost_expired_leaf_still_gets_an_overlap() {
        let active = generation(0, 1_000);
        let plan =
            plan_window(&active, 100_000, DEFAULT_CLIENT_LEAF_LIFETIME_SECS, 990).expect("plan");
        plan.window.validate().expect("window");
        assert_eq!(plan.window.activation_at, 999);
        assert_eq!(plan.window.not_after, active.not_after);
        assert_eq!(plan.window.overlap_secs(), 1);
    }

    /// Only `scheduled` reaches the delegated issuer from this path.
    #[test]
    fn the_relayed_path_only_ever_delegates_a_scheduled_renewal() {
        assert!(RotationReason::Scheduled.is_delegable());
        assert_eq!(RELAYED_ISSUER_KIND, IssuerKind::Astra);
    }
}

/// Astra's private listener: the four routes the gateway relays into.
///
/// It is the mirror of [`astra_channel::router`], and it carries the
/// same three properties. Everything outside
/// [`astra_channel::ASTRA_INTERNAL_PREFIX`] is refused by the router
/// rather than by convention; every body is bounded before it is
/// deserialized; and every refusal collapses to the coarse class of
/// [`RenewalError::refusal`], because the finer reason is an oracle on other
/// peers' state and belongs in the protected log.
///
/// The caller travels **in the body**, not in the TLS identity: on this link
/// the authenticated party is the gateway, and the peer it resolved from a
/// source VIP is what the authority has to be told. Astra compares that
/// resolution against the object's own copy and refuses a mismatch — so a
/// gateway relaying somebody else's request is refused, not believed.
pub mod router {
    use std::sync::Arc;

    use aether::certificates::encoding::Id16;
    use astra_channel::{
        InternalRefusal, PreparedTrustUpdate, PreparedTrustUpdateTransaction,
        RelayedOperationQuery, RelayedRotationRequest, RelayedTrustUpdatePreparation,
        ASTRA_INTERNAL_PREFIX, ASTRA_TRUST_UPDATE_PREFIX, ROTATION_OPERATION_ROUTE,
        ROTATION_REQUEST_PATH, TRUST_UPDATE_PREPARE_PATH,
    };
    use axum::{
        extract::{DefaultBodyLimit, Path, State},
        http::{StatusCode, Uri},
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };

    use super::{now_unix, RenewalError};
    use crate::service::AstraService;

    /// Largest ordinary body this listener reads.
    ///
    /// A rotation request carries two certificate requests and three ML-DSA-87
    /// signatures; sixty-four kilobytes is well above that and far below what
    /// an allocation driven by a caller would be. A relayed preparation adds a
    /// peer snapshot and one PQ leaf to a request already bounded by
    /// [`aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES`],
    /// which stays inside the same ceiling. The operator result route has its
    /// own 64 KiB canonical body plus the fixed typed-identity envelope; its
    /// route-local limit is defined in [`crate::operator`].
    pub const MAX_PRIVATE_BODY_BYTES: usize = 64 * 1024;

    /// Builds the private router.
    pub fn router(service: Arc<AstraService>) -> Router {
        Router::new()
            .route(ROTATION_REQUEST_PATH, post(request))
            .route(ROTATION_OPERATION_ROUTE, post(operation))
            .route(TRUST_UPDATE_PREPARE_PATH, post(prepare_trust_update))
            // The third surface this listener serves (spec §8.5). Its routes
            // live in their own module for the reason they have their own
            // prefix: a campaign belongs to no peer, and a refusal log has to
            // be able to say which of the three surfaces was probed.
            .merge(crate::operator::private_routes())
            .fallback(refuse_unknown_route)
            .layer(DefaultBodyLimit::max(MAX_PRIVATE_BODY_BYTES))
            .with_state(service)
    }

    /// `POST /internal/v1/trust-update/prepare` (spec §0.6).
    ///
    /// The answer carries a transaction or nothing, and «nothing» is not an
    /// error: the gateway's comparison and this authority's registry answer
    /// two different questions, and where they disagree the honest reply is
    /// that there is nothing to hand over.
    async fn prepare_trust_update(
        State(service): State<Arc<AstraService>>,
        Json(relayed): Json<RelayedTrustUpdatePreparation>,
    ) -> Response {
        let now = now_unix();
        match crate::distribution::prepare(&service, &relayed, now).await {
            Ok(Some((manifest, chunks))) => (
                StatusCode::OK,
                Json(PreparedTrustUpdate {
                    transaction: Some(PreparedTrustUpdateTransaction { manifest, chunks }),
                }),
            )
                .into_response(),
            Ok(None) => (
                StatusCode::OK,
                Json(PreparedTrustUpdate { transaction: None }),
            )
                .into_response(),
            Err(error) => {
                tracing::warn!(route = TRUST_UPDATE_PREPARE_PATH, %error, "preparation refused");
                InternalRefusal::from(error.refusal()).into_response()
            }
        }
    }

    /// One refusal, logged with its real reason and answered with its class.
    fn refuse(route: &str, error: RenewalError) -> Response {
        tracing::warn!(route, %error, "private renewal route refused");
        InternalRefusal::from(error.refusal()).into_response()
    }

    fn operation_id(raw: &str) -> Result<Id16, InternalRefusal> {
        Id16::parse_hex(raw).map_err(|_| InternalRefusal::Protocol)
    }

    async fn request(
        State(service): State<Arc<AstraService>>,
        Json(relayed): Json<RelayedRotationRequest>,
    ) -> Response {
        match super::open(
            &service,
            &relayed.caller_wg_public_key,
            relayed.request,
            now_unix(),
        )
        .await
        {
            Ok(view) => (StatusCode::OK, Json(view)).into_response(),
            Err(error) => refuse("request", error),
        }
    }

    async fn operation(
        State(service): State<Arc<AstraService>>,
        Path(raw): Path<String>,
        Json(query): Json<RelayedOperationQuery>,
    ) -> Response {
        let id = match operation_id(&raw) {
            Ok(id) => id,
            Err(refusal) => return refusal.into_response(),
        };
        match super::read(&service, &query.caller_wg_public_key, &id, now_unix()).await {
            Ok(view) => (StatusCode::OK, Json(view)).into_response(),
            Err(error) => refuse("operation", error),
        }
    }

    /// Everything this listener does not serve.
    ///
    /// Named in the log rather than silently `404`: the public endpoint, the
    /// operator routes and the gateway's own lifecycle prefix all land here,
    /// and "the gateway probed something it should not" is worth reading.
    async fn refuse_unknown_route(uri: Uri) -> StatusCode {
        tracing::warn!(
            path = %uri.path(),
            "private renewal listener: route refused; it serves only \
             {ASTRA_INTERNAL_PREFIX}* and {ASTRA_TRUST_UPDATE_PREFIX}*"
        );
        StatusCode::NOT_FOUND
    }
}
