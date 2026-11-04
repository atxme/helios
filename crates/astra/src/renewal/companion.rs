//! The operator companion's path: reading an operation, its signer request
//! and its signer result.

use super::*;

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
        operations.update_persisted(operation_id, caller, now_unix, |operation| {
            operation.refresh_approval_request(Box::new(refreshed))
        })?;
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
        .approval_credentials()
        .registry
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
            service.approval_credentials().epoch,
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
    operations.update_persisted(operation_id, caller, now_unix, |operation| {
        operation.consume_approval(submission_fingerprint, Box::new(evidence))
    })?;
    drop(operations);

    resume_stage(service, caller, operation_id, now_unix).await?;

    let operations = service.operations.lock().await;
    let operation = operations.get(operation_id, caller, now_unix)?;
    mint_view(service, operation, now_unix).await
}
