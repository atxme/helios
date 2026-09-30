//! Opening a relayed renewal: the 80 % gate, the two leaves, and the
//! campaign evidence a manual request carries.

use super::*;

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
