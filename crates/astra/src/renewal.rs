//! The relayed ordinary renewal, from Astra's side — spec §7.2, §7.3, §8.1.2.
//!
//! # The order, and why every step of it is load-bearing
//!
//! ```text
//! Orion --WireGuard--> Helios --veth/mTLS--> Astra   open()
//!                                            Astra prepares awaiting_operator
//!            companion assertion, through the same two hops
//!                                            Astra verifies the approval
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
//! - **nothing is issued before the assertion**. The 80 % threshold only
//!   decides that a request is admissible; [`open`] refuses a request that is
//!   not yet due and creates an operation that holds no certificate;
//! - **the authorization never touches Orion**. It is handed to the gateway on
//!   the veth and the receipt comes back on that same relationship (§8.3,
//!   amendment of 16 August 2026). The client is a client of `helios-api`, not
//!   a courier between two authorities;
//! - **no grant before the receipt**. Astra cannot release the leaves it just
//!   signed until the gateway says, under its own served leaf, that the
//!   candidate is on its disk.
//!
//! # What a failure leaves behind
//!
//! A staging refused by the gateway un-reserves the rotation in the registry
//! and fails the operation. It never leaves a reservation nobody can clear:
//! that would make `active + 1` unavailable until the lease ran out, for a
//! renewal that never happened.
//!
//! # Limite connue
//!
//! `RotationReason::Scheduled` only. `manual_global` — the campaign case §7.2
//! allows the delegated issuer to sign — needs an approved campaign object,
//! which needs the companion's signing commands (§12.3). It is refused by
//! [`RenewalError::ReasonNotDelegable`] rather than approximated, and
//! delivering `astra-signer`'s campaign signing is what unblocks it.

use std::sync::Arc;

use aether::certificates::{
    approval::{
        AstraCredentialApprovalRequest, AstraRenewalApproval, AstraRenewalApprovalEvidence,
        MAX_APPROVAL_LIFETIME_SECS, ORDINARY_APPROVAL_CREDENTIALS,
    },
    authority::RotationReason,
    capability::{CapabilityGrant, CapabilityRequirement, CapabilityScope},
    client::{ClientCertificateRotationRequest, IssuerKind},
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
    window::{TransitionWindow, MAX_OVERLAP_SECS, MAX_STAGE_LEASE_SECS},
    CERTIFICATE_FORMAT_VERSION,
};
use helios_api::internal::{ClientRenewalOperationView, ClientRenewalSignerRequest};

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

/// Shortest overlap a candidate is given.
///
/// A transition with no overlap cuts every client that has not observed it
/// yet, and [`TransitionWindow::validate`] refuses one. An hour is the floor
/// used when the active leaf is closer to expiry than that.
pub const MINIMUM_OVERLAP_SECS: u64 = 3_600;

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
    #[error("the request is refused: {0}")]
    Request(aether::certificates::CertificateError),
    #[error("the operator approval is refused: {0}")]
    Approval(aether::certificates::CertificateError),
    #[error("the capability token is refused: {0}")]
    Capability(aether::certificates::CertificateError),
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
    #[error(
        "only a scheduled renewal is delegable here; a campaign needs an approved campaign \
         object, which needs the operator companion's signing commands"
    )]
    ReasonNotDelegable,
    #[error("the authority could not build this object: {0}")]
    Internal(aether::certificates::CertificateError),
}

impl RenewalError {
    /// The bounded class the gateway — and through it the client — learns.
    ///
    /// Everything that is not an authority-side failure collapses to
    /// `Rejected`: on this link the reason travels in the protected log, and a
    /// finer taxonomy relayed to a peer is an oracle on other peers' state.
    pub fn refusal(&self) -> helios_api::certificates::TrustUpdateRefusal {
        use helios_api::certificates::TrustUpdateRefusal as Refusal;
        match self {
            Self::Registry(RegistryError::Io(_) | RegistryError::Corrupt(_))
            | Self::Internal(_) => Refusal::Internal,
            Self::NoIssuer | Self::NoGatewayChannel | Self::Gateway(_) => Refusal::Unavailable,
            _ => Refusal::Rejected,
        }
    }
}

/// Step 1: opens an operation for a request the gateway just relayed.
///
/// Everything is verified before anything is stored: the caller owns the
/// request, the peer is admitted and not revoked, the active leaf is past its
/// 80 % threshold, and the three signatures of §7.1 verify under the **active**
/// PQ key the registry holds — never under a key the request supplied.
///
/// What it does **not** do is issue. The answer is an `awaiting_operator`
/// operation, which is the entire point of the 15 August 2026 amendment.
pub async fn open(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    request: Box<ClientCertificateRotationRequest>,
    now_unix: u64,
) -> Result<ClientRenewalOperationView, RenewalError> {
    if request.client_wg_public_key != *caller {
        return Err(RenewalError::CallerMismatch);
    }

    let (peer, trust_domain_id, gateway_key, server_name, rp_id, registry_epoch, service_epoch) = {
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
            state.webauthn_rp_id.clone(),
            state.credential_registry_epoch,
            state.astra_service_key_epoch,
        )
    };
    if peer.revoked {
        return Err(RenewalError::Revoked);
    }

    // The threshold, and the only thing it decides: whether the request is
    // admissible at all. Past it, an operator still has to answer.
    match urgency(&peer.active, now_unix).map_err(RenewalError::Internal)? {
        RenewalUrgency::Idle => return Err(RenewalError::NotDue),
        RenewalUrgency::Expired => return Err(RenewalError::ExpiredIdentity),
        RenewalUrgency::Due | RenewalUrgency::Warning | RenewalUrgency::Critical => {}
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
        registry_epoch,
        service_epoch,
        now_unix,
    )?;

    let operation = Operation::awaiting_operator(
        operation_id,
        *caller,
        request,
        Box::new(approval_request),
        now_unix,
    );
    let mut operations = service.operations.lock().await;
    operations.open(operation, now_unix)?;
    let operation = operations
        .get(&operation_id, caller, now_unix)
        .map_err(RenewalError::Operation)?;

    let mut registry = service.registry.lock().await;
    registry.record(
        crate::audit::AuditEvent::ClientRenewalRequested {
            peer: peer.name.clone(),
            generation: operation.request.requested_generation,
        },
        now_unix,
    )?;
    tracing::info!(
        peer = %peer.name,
        operation = %operation_id,
        generation = operation.request.requested_generation,
        "renewal prepared and awaiting an operator credential"
    );
    drop(registry);
    mint_view(service, operation, now_unix).await
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
        operation.state == helios_api::internal::ClientRenewalOperationState::AwaitingOperator
            && now_unix >= operation.approval_request.expires_at
    };
    if needs_refresh {
        let refreshed =
            refresh_challenge(service, &mut operations, caller, operation_id, now_unix).await?;
        let operation = operations.get_mut(operation_id, caller, now_unix)?;
        operation.refresh_approval_request(Box::new(refreshed))?;
    }
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
    Ok(ClientRenewalSignerRequest {
        operation_id: *operation_id,
        approval_request: operation.approval_request.clone(),
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

    let evidence = AstraRenewalApprovalEvidence {
        approval_request: (*operation.approval_request).clone(),
        approval: *approval,
    };
    let request = operation.request.clone();
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
            state.credential_registry_epoch,
            peer,
        )
    };
    if peer.revoked {
        return Err(RenewalError::Revoked);
    }

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

    // Spent before anything is issued: a verification that succeeded twice
    // would authorize two issuances under one touch.
    let approval_fingerprint = evidence.fingerprint();
    operations
        .get_mut(operation_id, caller, now_unix)?
        .consume_approval(approval_fingerprint)?;
    drop(operations);

    match stage(
        service,
        caller,
        operation_id,
        &request,
        &peer,
        evidence,
        now_unix,
    )
    .await
    {
        Ok(()) => {}
        Err(error) => {
            // The operation ends here rather than pretending an operator may
            // try again: the capability token of this operation is spent.
            let mut operations = service.operations.lock().await;
            if let Ok(operation) = operations.get_mut(operation_id, caller, now_unix) {
                operation.fail();
            }
            tracing::error!(
                peer = %peer.name,
                operation = %operation_id,
                %error,
                "renewal failed after the operator approved it; the client has to open a new one"
            );
            return Err(error);
        }
    }

    let operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    mint_view(service, operation, now_unix).await
}

/// Steps 5 to 7: issue, stage on the veth, read the receipt back, grant.
///
/// Split out because it is the part that can fail after a human has already
/// touched a key, and its caller has to undo the operation as a whole when it
/// does.
async fn stage(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    operation_id: &Id16,
    request: &ClientCertificateRotationRequest,
    peer: &crate::registry::PeerRecord,
    evidence: AstraRenewalApprovalEvidence,
    now_unix: u64,
) -> Result<(), RenewalError> {
    let issuer = service.issuer.as_ref().ok_or(RenewalError::NoIssuer)?;
    let gateway = service
        .gateway
        .as_ref()
        .ok_or(RenewalError::NoGatewayChannel)?;
    if !RotationReason::Scheduled.is_delegable() {
        return Err(RenewalError::ReasonNotDelegable);
    }

    let plan = plan_window(
        &peer.active,
        request.expires_at,
        issuer.authorization.maximum_leaf_lifetime_secs,
        now_unix,
    )?;
    let (tls_leaf, pq_leaf) = issuer.issue_generation(
        request,
        &peer.name,
        &plan.window,
        (plan.leaf_not_before, plan.leaf_not_after),
        fresh_serial().map_err(RenewalError::Internal)?,
    )?;
    let stage_id = fresh_id().map_err(RenewalError::Internal)?;
    let authorization = issuer.authorize_stage(
        request,
        &peer.active,
        stage_id,
        // The anchor the peer's active generation already chains to. A
        // candidate that named another one would be describing a CA-TLS
        // rotation, which is a master-authority path and not this one.
        peer.active.tls_ca_certificate_fingerprint,
        tls_leaf,
        pq_leaf,
        plan.window,
        now_unix,
        plan.stage_expires_at,
        RotationReason::Scheduled,
        evidence,
    )?;
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
                window: plan.window,
                stage_expires_at: plan.stage_expires_at,
                granted: false,
            },
            now_unix,
        )?;
    }
    {
        let mut operations = service.operations.lock().await;
        operations
            .get_mut(operation_id, caller, now_unix)?
            .record_stage(stage_id);
    }

    // The authorization goes to the gateway and the receipt comes back on the
    // same relationship. Orion sees neither (§8.3, 16 August 2026).
    let receipt = match gateway.stage(&authorization).await {
        Ok(receipt) => receipt,
        Err(error) => {
            abandon(service, caller, stage_id, now_unix).await;
            return Err(RenewalError::Gateway(error.to_string()));
        }
    };

    let gateway_leaf = &peer.active_pq_certificate;
    let _ = gateway_leaf;
    let (gateway_pq_key, gateway_leaf_fingerprint) = match gateway_identity(service).await {
        Ok(identity) => identity,
        Err(error) => {
            abandon(service, caller, stage_id, now_unix).await;
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
            abandon(service, caller, stage_id, now_unix).await;
            return Err(RenewalError::Issuer(error));
        }
    };

    {
        let mut operations = service.operations.lock().await;
        let operation = operations.get_mut(operation_id, caller, now_unix)?;
        operation.record_receipt(Box::new(receipt))?;
        operation.record_grant(Box::new(grant))?;
    }
    let mut registry = service.registry.lock().await;
    registry.mark_granted(caller, now_unix)?;
    tracing::info!(
        peer = %peer.name,
        operation = %operation_id,
        stage = %stage_id,
        "grant released against the gateway's signed receipt"
    );
    Ok(())
}

/// Clears a reservation whose staging never completed.
///
/// Best effort and loud: a reservation nobody clears makes `active + 1`
/// unavailable until its lease runs out, for a renewal that did not happen.
async fn abandon(
    service: &Arc<AstraService>,
    caller: &WireGuardKey,
    stage_id: Id16,
    now_unix: u64,
) {
    let mut registry = service.registry.lock().await;
    if let Err(error) = registry.abandon_rotation(caller, &stage_id, now_unix) {
        tracing::error!(
            %error,
            stage = %stage_id,
            "a staging reservation could not be cleared; this peer cannot renew until its lease \
             expires"
        );
    }
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

    let stage_expires_at = (now_unix + STAGE_LEASE_SECS)
        .min(request_expires_at)
        .min(now_unix + MAX_STAGE_LEASE_SECS);
    if stage_expires_at <= now_unix {
        return Err(RenewalError::Internal(CertificateError::InvalidLease));
    }
    let activation_at = stage_expires_at;
    // The outgoing leaf stays acceptable until it expires, bounded by the
    // 30-day ceiling and floored so the overlap is never empty.
    let not_after = active
        .not_after
        .max(activation_at + MINIMUM_OVERLAP_SECS)
        .min(activation_at + MAX_OVERLAP_SECS);
    let window = TransitionWindow::new(now_unix, activation_at, not_after)
        .map_err(RenewalError::Internal)?;

    let lifetime = DEFAULT_CLIENT_LEAF_LIFETIME_SECS.min(maximum_leaf_lifetime_secs);
    let leaf_not_after = now_unix + lifetime;
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
        required_credentials: ORDINARY_APPROVAL_CREDENTIALS,
        created_at: now_unix,
        expires_at: now_unix + MAX_APPROVAL_LIFETIME_SECS,
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
    let (domain, gateway, rp_id, registry_epoch, service_epoch) = (
        state.trust_domain_id,
        state.gateway_wg_public_key,
        state.webauthn_rp_id.clone(),
        state.credential_registry_epoch,
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
        registry_epoch,
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
fn fresh_id() -> Result<Id16, aether::certificates::CertificateError> {
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

    /// An active leaf about to expire still gets a non-empty overlap: a
    /// transition with none cuts every client that has not observed it.
    #[test]
    fn an_almost_expired_leaf_still_gets_an_overlap() {
        let active = generation(0, 1_000);
        let plan =
            plan_window(&active, 100_000, DEFAULT_CLIENT_LEAF_LIFETIME_SECS, 990).expect("plan");
        plan.window.validate().expect("window");
        assert!(plan.window.overlap_secs() >= MINIMUM_OVERLAP_SECS);
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
/// It is the mirror of [`helios_api::internal::router`], and it carries the
/// same three properties. Everything outside
/// [`helios_api::internal::ASTRA_INTERNAL_PREFIX`] is refused by the router
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
    use axum::{
        extract::{DefaultBodyLimit, Path, State},
        http::{StatusCode, Uri},
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };
    use helios_api::internal::{
        InternalRefusal, RelayedOperationQuery, RelayedRotationRequest, ASTRA_INTERNAL_PREFIX,
        ROTATION_OPERATION_ROUTE, ROTATION_REQUEST_PATH, ROTATION_SIGNER_REQUEST_ROUTE,
        ROTATION_SIGNER_RESULT_ROUTE,
    };

    use super::{now_unix, RenewalError};
    use crate::service::AstraService;

    /// Largest body this listener reads.
    ///
    /// A rotation request carries two certificate requests and three ML-DSA-87
    /// signatures; sixty-four kilobytes is well above that and far below what
    /// an allocation driven by a caller would be.
    pub const MAX_PRIVATE_BODY_BYTES: usize = 64 * 1024;

    /// Builds the private router.
    pub fn router(service: Arc<AstraService>) -> Router {
        Router::new()
            .route(ROTATION_REQUEST_PATH, post(request))
            .route(ROTATION_OPERATION_ROUTE, post(operation))
            .route(ROTATION_SIGNER_REQUEST_ROUTE, post(signer_request))
            .route(ROTATION_SIGNER_RESULT_ROUTE, post(signer_result))
            .fallback(refuse_unknown_route)
            .layer(DefaultBodyLimit::max(MAX_PRIVATE_BODY_BYTES))
            .with_state(service)
    }

    /// One refusal, logged with its real reason and answered with its class.
    fn refuse(route: &str, error: RenewalError) -> Response {
        tracing::warn!(route, %error, "private renewal route refused");
        InternalRefusal::from(error.refusal()).into_response()
    }

    /// The capability token of §8.2, from the header it is allowed to be in.
    ///
    /// The `Authorization` header and nowhere else: never a query parameter,
    /// never a path segment, so it never reaches an access log.
    fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
        headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")
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

    async fn signer_request(
        State(service): State<Arc<AstraService>>,
        Path(raw): Path<String>,
        headers: axum::http::HeaderMap,
        Json(query): Json<RelayedOperationQuery>,
    ) -> Response {
        let id = match operation_id(&raw) {
            Ok(id) => id,
            Err(refusal) => return refusal.into_response(),
        };
        let Some(token) = bearer(&headers) else {
            return InternalRefusal::Protocol.into_response();
        };
        match super::signer_request(
            &service,
            &query.caller_wg_public_key,
            &id,
            token,
            now_unix(),
        )
        .await
        {
            Ok(view) => (StatusCode::OK, Json(view)).into_response(),
            Err(error) => refuse("signer-request", error),
        }
    }

    async fn signer_result(
        State(service): State<Arc<AstraService>>,
        Path(raw): Path<String>,
        headers: axum::http::HeaderMap,
        Json(result): Json<helios_api::internal::ClientRenewalSignerResult>,
    ) -> Response {
        let id = match operation_id(&raw) {
            Ok(id) => id,
            Err(refusal) => return refusal.into_response(),
        };
        let Some(token) = bearer(&headers) else {
            return InternalRefusal::Protocol.into_response();
        };
        match super::signer_result(
            &service,
            &result.caller_wg_public_key,
            &id,
            token,
            result.approval,
            now_unix(),
        )
        .await
        {
            Ok(view) => (StatusCode::OK, Json(view)).into_response(),
            Err(error) => refuse("signer-result", error),
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
            "private renewal listener: route refused; it serves only {ASTRA_INTERNAL_PREFIX}*"
        );
        StatusCode::NOT_FOUND
    }
}
