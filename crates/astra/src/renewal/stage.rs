//! Staging on the gateway, and releasing the grant once it receipts.

use super::*;

/// Steps 5 to 7: issue, stage on the veth, read the receipt back, grant.
///
/// Split out because it is the part that can fail after a human has already
/// touched a key. Every random output is persisted before it leaves Astra, so
/// retries resume this exact issuance rather than spending another approval.
pub(super) async fn resume_stage(
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
            let mut candidate = operations.get(operation_id, caller, now_unix)?.clone();
            candidate.record_stage(Box::new(authorization.clone()))?;
            let previous = std::mem::replace(
                operations.get_mut(operation_id, caller, now_unix)?,
                candidate,
            );
            if let Err(error) = operations.persist() {
                // Keep retries on the last durable operation. Otherwise a
                // cached authorization could leave Astra without being saved.
                *operations.get_mut(operation_id, caller, now_unix)? = previous;
                return Err(RenewalError::Operation(error));
            }
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
        let mut candidate = operations.get(operation_id, caller, now_unix)?.clone();
        candidate.record_receipt(Box::new(receipt))?;
        candidate.record_grant(Box::new(grant))?;
        let previous = std::mem::replace(
            operations.get_mut(operation_id, caller, now_unix)?,
            candidate,
        );
        if let Err(error) = operations.persist() {
            // A poll must not expose a grant absent from the durable journal.
            // The later registry repair is deliberately outside this rollback:
            // once this write succeeds, the grant can never be withdrawn.
            *operations.get_mut(operation_id, caller, now_unix)? = previous;
            return Err(RenewalError::Operation(error));
        }
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
pub(super) async fn reconcile_released_grant(
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
