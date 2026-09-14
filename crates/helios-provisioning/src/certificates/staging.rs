//! The client generation lifecycle: admission, staging, commit, purge and
//! revocation.
//!
//! All five mutate the same per-peer slot and take `&mut self`, so the
//! caller's lock is the serializer, and the clock is read once per operation
//! and passed in.

use super::{
    AstraCredentialBinding, CertificateError, CertificateRegistry, ClientCertificateGeneration,
    ClientCertificateRotationGrant, ClientCertificateStageAuthorization,
    ClientCertificateStageCommit, ClientCertificateState, Fingerprint,
    GatewayCertificateStageReceipt, InstallOutcome, IssuerKind, MlDsa87PublicKey, MlDsa87Signature,
    PeerCertificates, PendingStageState, PqCertificate, RegistryError, RegistryState,
    RevocationTombstone, RevokedFamily, RotationReason, WireGuardKey, CERTIFICATE_FORMAT_VERSION,
    CERTIFICATE_PROTOCOL_VERSION,
};

impl CertificateRegistry {
    /// Registers a peer's first generation, at admission (spec §13.1).
    pub fn admit(
        &mut self,
        name: &str,
        wg_public_key: &WireGuardKey,
        active: ClientCertificateGeneration,
        active_pq_certificate: PqCertificate,
    ) -> Result<(), RegistryError> {
        assert_fingerprints_free(
            &self.state,
            wg_public_key,
            &[
                active.tls_certificate_fingerprint,
                active.pq_certificate_fingerprint,
            ],
        )?;
        let mut candidate = self.state.clone();
        candidate.peers.insert(
            wg_public_key.to_base64(),
            PeerCertificates {
                name: name.to_string(),
                state: ClientCertificateState::new(active),
                active_pq_certificate,
                staged_pq_certificate: None,
                distribution: None,
            },
        );
        self.persist(candidate)
    }

    /// Persists a candidate generation and returns the receipt to be signed.
    ///
    /// `caller_wg_public_key` is the identity the transport proved — resolved
    /// from the tunnel source address, exactly like the release route. The
    /// authorization's own copy is only ever **compared** against it, so a
    /// stolen negotiation identity cannot aim a staging at another peer.
    ///
    /// The returned receipt carries a placeholder signature: the gateway's PQ
    /// private key is sealed and lives in `heliosd`, which calls
    /// [`GatewayCertificateStageReceipt::sign`] on it. The state is already on
    /// disk by then.
    pub fn stage(
        &mut self,
        caller_wg_public_key: &WireGuardKey,
        authorization: &ClientCertificateStageAuthorization,
        now_unix: u64,
    ) -> Result<GatewayCertificateStageReceipt, RegistryError> {
        if authorization.client_wg_public_key != *caller_wg_public_key {
            return Err(RegistryError::PeerMismatch);
        }
        let mut state = self.state.clone();
        // An expired stage must not block a fresh one, and the purge belongs
        // to the same serialized section — and the same write — as the staging
        // it competes with.
        purge_expired_in(&mut state, now_unix);

        let peer = state
            .peers
            .get(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        if peer.state.revoked {
            return Err(RegistryError::Certificate(CertificateError::Revoked));
        }

        authorization.verify(
            &state.gateway.current_ca_public_key,
            &state.trust_domain_id,
            state.gateway.ca_epoch,
            state.client_tls_ca.ca_tls_epoch,
            &state.gateway.gateway_wg_public_key,
            &state.gateway.server_name,
            caller_wg_public_key,
            &peer.state.active,
            &state.client_tls_ca.acceptable_anchors(now_unix),
            Some(&state.astra.astra_policy_fingerprint),
            None,
            now_unix,
        )?;

        // Which approval family has to be present is decided by the signed
        // `reason`, never by which field happens to be filled: reading the
        // presence would let an authorization choose the check it is put
        // through, and the two families do not prove the same thing. The one
        // the reason does not name must be absent — carrying both would leave
        // "which one was checked" to the reader.
        if authorization.issuer_kind == IssuerKind::Astra {
            match authorization.reason {
                RotationReason::Scheduled => {
                    if authorization.campaign_approval.is_some() {
                        return Err(CertificateError::ApprovalMismatch(
                            "a scheduled renewal carries no campaign approval",
                        )
                        .into());
                    }
                    if authorization.renewal_approval.is_some()
                        || !authorization
                            .renewal_authorization_fingerprint
                            .matches(&authorization.request_fingerprint)
                    {
                        return Err(CertificateError::ApprovalMismatch(
                            "automatic renewal request binding",
                        )
                        .into());
                    }
                }
                RotationReason::ManualGlobal => {
                    if authorization.renewal_approval.is_some() {
                        return Err(CertificateError::ApprovalMismatch(
                            "a campaign rotation carries no ordinary renewal approval",
                        )
                        .into());
                    }
                    let evidence = authorization.campaign_approval.as_deref().ok_or(
                        CertificateError::ApprovalMismatch("delegated campaign approval"),
                    )?;
                    if !evidence
                        .fingerprint()?
                        .matches(&authorization.renewal_authorization_fingerprint)
                    {
                        return Err(CertificateError::ApprovalMismatch(
                            "campaign approval fingerprint",
                        )
                        .into());
                    }
                    evidence.verify(
                        &state.gateway.current_ca_public_key,
                        &state.trust_domain_id,
                        &state.gateway.gateway_wg_public_key,
                        caller_wg_public_key,
                        peer.state.active.generation,
                        &peer.state.active.tls_certificate_fingerprint,
                        &peer.state.active.pq_certificate_fingerprint,
                        &state.astra.webauthn_rp_id,
                        state.astra.astra_policy_fingerprint.fingerprint(),
                        state.gateway.ca_epoch,
                        state.astra.credential_registry_epoch,
                        // Same instant as the ordinary family, for the same
                        // reason: the campaign's five-minute window bounds the
                        // *approval*, the stage lease bounds the replay.
                        authorization.issued_at,
                    )?;
                    // Only the rows that actually answered. A whole snapshot
                    // applied here would let a campaign advance decisions
                    // about credentials it never used.
                    let bindings: Vec<_> = evidence
                        .approval
                        .approvals
                        .iter()
                        .map(|answer| {
                            evidence
                                .credential_registry
                                .binding(&answer.credential_id)
                                .cloned()
                                .ok_or(CertificateError::UnknownCredential)
                        })
                        .collect::<Result<_, _>>()?;
                    for binding in &bindings {
                        state.astra.accept_credential_binding(binding)?;
                    }
                }
                _ => {
                    return Err(CertificateError::IssuerScopeViolation("reason").into());
                }
            }
        }
        let candidate = authorization.candidate()?;
        assert_fingerprints_free(
            &state,
            caller_wg_public_key,
            &[
                candidate.tls_certificate_fingerprint,
                candidate.pq_certificate_fingerprint,
            ],
        )?;

        let RegistryState { peers, ledger, .. } = &mut state;
        let peer = peers
            .get_mut(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        // The tombstones outlive the peer record, so a candidate carrying a
        // leaf this gateway already withdrew is refused even after a
        // readmission under a fresh identity.
        let outcome = peer.state.stage(authorization, ledger, now_unix)?;
        if outcome == InstallOutcome::Installed {
            peer.staged_pq_certificate = Some(authorization.next_pq_certificate.clone());
        }
        let active_generation = peer.state.active.generation;

        // Persisted, synced and adopted **before** the receipt exists: the
        // signature that follows is a statement about a durable fact.
        self.persist(state)?;

        Ok(GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            stage_id: authorization.stage_id,
            stage_authorization_fingerprint: authorization.fingerprint()?,
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            gateway_wg_public_key: self.state.gateway.gateway_wg_public_key,
            client_wg_public_key: *caller_wg_public_key,
            active_generation,
            staged_generation: candidate.generation,
            staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
            persisted_at: now_unix,
            stage_expires_at: authorization.stage_expires_at,
            active_gateway_identity_epoch: self.state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: self.state.gateway.gateway_decision_epoch,
            gateway_certificate_fingerprint: self.state.gateway.active_pq_fingerprint()?,
            gateway_signature: MlDsa87Signature::placeholder(),
        })
    }

    /// Turns the candidate into the committed `next` generation.
    ///
    /// # Why the grant is mandatory here
    ///
    /// The two client signatures prove who is asking, not that the authority
    /// released anything. A client holding both private keys — the ordinary
    /// case, it generated them — could otherwise commit the moment the staging
    /// authorization reached the gateway, before Astra ever saw the receipt and
    /// before any grant existed. That collapses the whole ordering the receipt
    /// exists to create.
    ///
    /// So the grant travels with the commit and is verified against what the
    /// gateway itself knows: the receipt it signed, the candidate it persisted
    /// and the generation that candidate follows. The commit's own
    /// `grant_fingerprint` and `stage_receipt_fingerprint` must then name
    /// exactly those objects.
    ///
    /// Every key used to verify comes from the registry — the active leaf it
    /// admitted, the candidate leaf it staged, its own gateway leaf — so
    /// nothing in the message chooses its own verifier.
    pub fn commit(
        &mut self,
        caller_wg_public_key: &WireGuardKey,
        commit: &ClientCertificateStageCommit,
        grant: &ClientCertificateRotationGrant,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        if commit.client_wg_public_key != *caller_wg_public_key {
            return Err(RegistryError::PeerMismatch);
        }
        let peer = self
            .state
            .peers
            .get(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        if peer.state.revoked {
            return Err(RegistryError::Certificate(CertificateError::Revoked));
        }
        // A replayed commit is recognised by the **signed document**, not by
        // the stage identifier: a second, differently-signed commit naming the
        // same stage is a conflict, and answering it with success would report
        // someone else's decision as landed. The candidate is gone by now, so
        // this is also the only comparison still available — which is why it
        // has to be the exact bytes that were verified the first time.
        let commit_fingerprint = commit.fingerprint();
        if let Some(committed) = &peer.state.last_committed_stage {
            if committed.stage_id == commit.stage_id && peer.state.next.is_some() {
                if committed.commit_fingerprint.matches(&commit_fingerprint) {
                    return Ok(InstallOutcome::AlreadyPresent);
                }
                return Err(RegistryError::Certificate(
                    CertificateError::GenerationConflict {
                        generation: peer.state.next.as_ref().map_or(0, |next| next.generation),
                    },
                ));
            }
        }
        let pending = peer
            .state
            .pending
            .as_ref()
            .ok_or(RegistryError::Certificate(CertificateError::UnknownStage))?;

        let gateway_pq_public_key = MlDsa87PublicKey::parse(
            &self
                .state
                .gateway
                .active_gateway_certificate
                .ml_dsa_87_public_key,
        )?;
        grant.verify_for_gateway(
            &self.state.gateway.current_ca_public_key,
            &gateway_pq_public_key,
            &self.state.gateway.active_pq_fingerprint()?,
            &self.state.trust_domain_id,
            self.state.gateway.ca_epoch,
            self.state.client_tls_ca.ca_tls_epoch,
            &self.state.gateway.gateway_wg_public_key,
            &self.state.gateway.server_name,
            caller_wg_public_key,
            peer.state.active.generation,
            &pending.candidate,
            &pending.stage_id,
            &self.state.client_tls_ca.acceptable_anchors(now_unix),
            Some(&self.state.astra.astra_policy_fingerprint),
            now_unix,
        )?;
        // The commit must name *this* grant and *this* receipt. One that
        // verified against one grant while naming another would let a stale
        // pair be replayed against a fresh candidate.
        if !commit.grant_fingerprint.matches(&grant.fingerprint()?) {
            return Err(RegistryError::Certificate(
                CertificateError::FingerprintMismatch("rotation grant"),
            ));
        }
        if !commit
            .stage_receipt_fingerprint
            .matches(&grant.stage_receipt_fingerprint)
        {
            return Err(RegistryError::Certificate(
                CertificateError::FingerprintMismatch("stage receipt"),
            ));
        }

        // Same family rule as the staging, and for the same reason: the
        // signed `reason` chooses the check, never which field is filled.
        let accepted_credential_bindings: Vec<AstraCredentialBinding> =
            if grant.issuer_kind == IssuerKind::Astra {
                match grant.reason {
                    RotationReason::Scheduled => {
                        if grant.campaign_approval.is_some() {
                            return Err(CertificateError::ApprovalMismatch(
                                "a scheduled renewal carries no campaign approval",
                            )
                            .into());
                        }
                        if grant.renewal_approval.is_some()
                            || !grant
                                .renewal_authorization_fingerprint
                                .matches(&grant.request_fingerprint)
                        {
                            return Err(CertificateError::ApprovalMismatch(
                                "automatic renewal request binding",
                            )
                            .into());
                        }
                        Vec::new()
                    }
                    RotationReason::ManualGlobal => {
                        if grant.renewal_approval.is_some() {
                            return Err(CertificateError::ApprovalMismatch(
                                "a campaign rotation carries no ordinary renewal approval",
                            )
                            .into());
                        }
                        let evidence = grant.campaign_approval.as_deref().ok_or(
                            CertificateError::ApprovalMismatch("delegated campaign approval"),
                        )?;
                        if !evidence
                            .fingerprint()?
                            .matches(&grant.renewal_authorization_fingerprint)
                        {
                            return Err(CertificateError::ApprovalMismatch(
                                "campaign approval fingerprint",
                            )
                            .into());
                        }
                        evidence.verify(
                            &self.state.gateway.current_ca_public_key,
                            &self.state.trust_domain_id,
                            &self.state.gateway.gateway_wg_public_key,
                            caller_wg_public_key,
                            peer.state.active.generation,
                            &peer.state.active.tls_certificate_fingerprint,
                            &peer.state.active.pq_certificate_fingerprint,
                            &self.state.astra.webauthn_rp_id,
                            self.state.astra.astra_policy_fingerprint.fingerprint(),
                            self.state.gateway.ca_epoch,
                            self.state.astra.credential_registry_epoch,
                            evidence.approval.approved_at,
                        )?;
                        evidence
                            .approval
                            .approvals
                            .iter()
                            .map(|answer| {
                                evidence
                                    .credential_registry
                                    .binding(&answer.credential_id)
                                    .cloned()
                                    .ok_or(CertificateError::UnknownCredential)
                            })
                            .collect::<Result<_, _>>()?
                    }
                    _ => return Err(CertificateError::IssuerScopeViolation("reason").into()),
                }
            } else {
                Vec::new()
            };

        // Reading the clock once, here, is what makes the race with the purge
        // deterministic: a commit at the deadline is late, not lucky.
        commit.verify(
            &peer.active_public_key()?,
            &peer.staged_public_key()?,
            &self.state.trust_domain_id,
            &self.state.gateway.gateway_wg_public_key,
            caller_wg_public_key,
            &pending.stage_id,
            &pending.candidate,
            peer.state.active.generation,
            pending.stage_expires_at,
            now_unix,
        )?;

        let stage_id = pending.stage_id;
        let mut state = self.state.clone();
        for binding in &accepted_credential_bindings {
            state.astra.accept_credential_binding(binding)?;
        }
        let peer = state
            .peers
            .get_mut(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        // Helios commits a candidate that is still `pending_grant`: the grant
        // travels to the client, not through here (spec §7.3).
        let outcome = peer.state.commit(
            &stage_id,
            &commit_fingerprint,
            PendingStageState::PendingGrant,
            now_unix,
        )?;
        self.persist(state)?;
        Ok(outcome)
    }

    /// Drops every candidate whose lease has run out, and returns their peers.
    pub fn purge_expired(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut state = self.state.clone();
        let purged = purge_expired_in(&mut state, now_unix);
        if !purged.is_empty() {
            self.persist(state)?;
        }
        Ok(purged)
    }

    /// Promotes every generation whose overlap has ended.
    ///
    /// The client TLS anchor moves here too, and on the same write: it is the
    /// same clock boundary, and a sweep that promoted the peers while leaving
    /// the anchor behind would keep accepting a chain the domain has retired.
    pub fn promote_due(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut state = self.state.clone();
        let mut promoted = Vec::new();
        // Both anchors on the same pass and the same write. A restart that
        // found one moved and the other not would either accept a chain the
        // domain has retired or refuse one it still issues under, and which of
        // the two it got would depend on where the crash landed.
        let mut anchors_moved = state.client_tls_ca.promote_if_due(now_unix);
        anchors_moved |= state.gateway.promote_ca_if_due(now_unix);
        for (key, peer) in state.peers.iter_mut() {
            if peer.state.promote_if_due(now_unix) {
                if let Some(certificate) = peer.staged_pq_certificate.take() {
                    peer.active_pq_certificate = certificate;
                }
                promoted.push(key.clone());
            }
        }
        if !promoted.is_empty() || anchors_moved {
            self.persist(state)?;
        }
        Ok(promoted)
    }

    /// Terminal revocation of a peer's certificate state.
    ///
    /// Called by the same path that removes the admission, under the same
    /// lock: `revoked` has to dominate a staging that is running concurrently,
    /// and it can only do that if both go through one serializer.
    pub fn revoke(
        &mut self,
        wg_public_key: &WireGuardKey,
        revocation_epoch: u64,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.clone();
        let peer = state
            .peers
            .get(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;

        // Remember what is being withdrawn *before* withdrawing it: `revoke`
        // clears the slots these fingerprints and their expiries are read
        // from. Without the tombstones, `peer remove` followed by a fresh
        // admission would let the very same leaf be staged again — the peer
        // record that carried `revoked` is gone by then.
        let mut tombstones = Vec::new();
        for generation in [
            Some(&peer.state.active),
            peer.state.next.as_ref(),
            peer.state
                .pending
                .as_ref()
                .map(|pending| &pending.candidate),
        ]
        .into_iter()
        .flatten()
        {
            for (family, fingerprint) in [
                (RevokedFamily::Tls, generation.tls_certificate_fingerprint),
                (RevokedFamily::Pq, generation.pq_certificate_fingerprint),
            ] {
                tombstones.push(RevocationTombstone {
                    scope: aether::certificates::revocation::RevocationScope::Client,
                    family,
                    fingerprint,
                    revocation_epoch,
                    expires_at: generation.not_after,
                    // A local `peer remove` is not a signed object, and
                    // inventing a fingerprint for it would misdescribe where
                    // the decision came from.
                    revocation_fingerprint: None,
                });
            }
        }
        for tombstone in tombstones {
            state.ledger.remember(tombstone, now_unix)?;
        }

        let peer = state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.state.revoke(revocation_epoch);
        peer.staged_pq_certificate = None;
        self.persist(state)
    }
}

/// Drops every candidate whose lease has run out, in place.
///
/// The same sweep forgets tombstones whose target could no longer be valid
/// anyway: the list is bounded, and a spent tombstone protects nothing while
/// occupying a slot a live revocation may need.
fn purge_expired_in(state: &mut RegistryState, now_unix: u64) -> Vec<String> {
    state.ledger.forget_expired(now_unix);
    let mut purged = Vec::new();
    for (key, peer) in state.peers.iter_mut() {
        if peer.state.purge_expired(now_unix) {
            // The staged leaf goes with the candidate: keeping it would leave
            // a certificate the registry can no longer name.
            if peer.state.next.is_none() {
                peer.staged_pq_certificate = None;
            }
            purged.push(key.clone());
        }
    }
    purged
}

/// Refuses a fingerprint already bound to another peer (spec §3.3).
///
/// Global across active, next **and** pending: a candidate that duplicated
/// another peer's fingerprint would make a future connection resolvable to two
/// identities.
fn assert_fingerprints_free(
    state: &RegistryState,
    owner: &WireGuardKey,
    fingerprints: &[Fingerprint],
) -> Result<(), RegistryError> {
    let owner = owner.to_base64();
    for (key, peer) in &state.peers {
        if *key == owner {
            continue;
        }
        for occupied in peer.state.occupied_fingerprints() {
            if fingerprints
                .iter()
                .any(|candidate| candidate.matches(&occupied))
            {
                return Err(RegistryError::FingerprintTaken(peer.name.clone()));
            }
        }
    }
    Ok(())
}
