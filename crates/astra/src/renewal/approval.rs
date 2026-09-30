//! The renewal window, the approval request, its challenge, the operation
//! view and the authentication of an answer.

use super::*;

/// The instants one candidate generation is issued for.
pub(super) struct WindowPlan {
    pub(super) window: TransitionWindow,
    pub(super) stage_expires_at: u64,
    pub(super) leaf_not_before: u64,
    pub(super) leaf_not_after: u64,
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
pub(super) fn plan_window(
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
pub(super) fn build_approval_request(
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
pub(super) async fn refresh_challenge(
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
pub(super) async fn mint_view(
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
pub(super) async fn authenticate(
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
