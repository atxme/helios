//! The private channel's handlers: what Astra stages, commits and revokes
//! on the veth.

use super::*;

#[async_trait]
impl AstraStageHandler for CertificateService {
    /// Persists a stage authorization received from Astra on the private veth.
    ///
    /// The private listener calls this only after mutual TLS has authenticated
    /// Astra. The client identity comes from the signed authorization itself;
    /// Orion never relays this object and no in-tunnel route exposes it.
    async fn stage_from_astra(
        &self,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        let caller = authorization.client_wg_public_key;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        // Read here rather than inside the check, so the check is a pure
        // question about a state and a candidate — and can therefore be
        // exercised without a `/var/lib/helios` on the machine running it.
        let client_pq_ca =
            std::fs::read(crate::key_negotiation::CLIENT_PQ_CA_PATH).map_err(|error| {
                tracing::error!(
                    peer = %caller,
                    %error,
                    "staging from Astra refused: the client PQ CA the negotiation port \
                     authenticates under is unreadable"
                );
                TrustUpdateRefusal::Internal
            })?;
        assert_candidate_is_presentable(registry.state(), &client_pq_ca, &authorization).map_err(
            |reason| {
                tracing::error!(
                    peer = %caller,
                    %reason,
                    "staging from Astra refused: this gateway could not authenticate the candidate \
                     leaves once they became active, and staging them would lock the client out at \
                     the end of the overlap"
                );
                TrustUpdateRefusal::Rejected
            },
        )?;
        let receipt = registry
            .stage(&caller, &authorization, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller, %error, "staging from Astra refused");
                classify(error)
            })?;
        // `stage` has durably written the candidate before returning. Only then
        // may the served gateway leaf attest the receipt.
        let receipt = self
            .signer
            .sign_stage_receipt(receipt)
            .map_err(|_| TrustUpdateRefusal::Internal)?;
        Ok(Box::new(receipt))
    }
}

#[async_trait]
impl ::astra_channel::AstraChannelHandler for CertificateService {
    async fn revoke(
        &self,
        revocation: Box<aether::certificates::revocation::EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        use aether::certificates::revocation::RevocationScope;

        if revocation.scope == RevocationScope::Gateway {
            return self.revoke_gateway_identity(&revocation).await;
        }

        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let state = registry.state();
        // The peer is resolved **before** the signature is checked, because the
        // counter the signature is checked against belongs to that peer: two
        // peers' revocation counters are independent, and comparing against a
        // global one would let a busy peer's decisions block a quiet one's.
        let peer = registry.peer(&revocation.identity_key).ok_or_else(|| {
            tracing::warn!(
                identity = %revocation.identity_key,
                "revocation refused: no admitted peer holds this identity"
            );
            TrustUpdateRefusal::Rejected
        })?;
        let current_epoch = peer.state.revocation_epoch;
        // Under `CA-PQ` alone. The delegated issuer may renew a leaf; it may
        // never withdraw one (ADR-008 §3), and the object's own `ca_epoch`
        // pins which anchor it was signed under.
        revocation
            .verify(
                &state.gateway.current_ca_public_key,
                &state.trust_domain_id,
                state.gateway.ca_epoch,
                current_epoch,
            )
            .map_err(|error| {
                tracing::warn!(
                    identity = %revocation.identity_key, %error,
                    "revocation refused"
                );
                classify(RegistryError::Certificate(error))
            })?;

        registry
            .revoke(&revocation.identity_key, revocation.revocation_epoch, now)
            .map_err(|error| {
                tracing::warn!(
                    identity = %revocation.identity_key, %error,
                    "revocation could not be applied"
                );
                classify(error)
            })?;
        tracing::warn!(
            identity = %revocation.identity_key,
            revocation_epoch = revocation.revocation_epoch,
            "client certificate identity revoked by the authority"
        );
        Ok(())
    }

    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<::astra_channel::PeerCertificateStateView, TrustUpdateRefusal> {
        let registry = self.registry.lock().await;
        let peer = registry
            .peer(identity)
            .ok_or(TrustUpdateRefusal::Rejected)?;
        Ok(::astra_channel::PeerCertificateStateView {
            name: peer.name.clone(),
            state: peer.state.clone(),
            active_pq_certificate: peer.active_pq_certificate.clone(),
            // Lu ici plutôt que mémorisé : c'est le fichier que le port de
            // négociation lit lui-même, donc les deux ne peuvent pas diverger.
            // Absent, l'autorité garde le comportement d'avant — les feuilles
            // du domaine, et rien d'autre.
            admission_pq_ca: admission_pq_ca(),
        })
    }

    /// The served leaf and the two counters that date it.
    ///
    /// The certificate comes from the negotiation handler — what is *served* —
    /// while the epochs come from the registry, which is what every other
    /// object of the lifecycle is numbered against. They are read under the
    /// same lock as everything else so an authority never sees a certificate
    /// from one moment and a counter from another.
    async fn gateway_identity(
        &self,
    ) -> Result<::astra_channel::GatewayIdentityView, TrustUpdateRefusal> {
        let registry = self.registry.lock().await;
        let state = registry.state();
        let pq_certificate = self.signer.served_pq_certificate();
        let pq_certificate_fingerprint = aether::certificates::gateway::pq_certificate_fingerprint(
            &pq_certificate,
        )
        .map_err(|error| {
            tracing::error!(%error, "the served gateway leaf has no fingerprint");
            TrustUpdateRefusal::Internal
        })?;
        Ok(::astra_channel::GatewayIdentityView {
            pq_certificate_fingerprint,
            pq_certificate,
            tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
            tls_certificate_not_after: aether::certificates::x509::inspect(
                &state.gateway.active_gateway_tls_certificate,
            )
            .map_err(|error| {
                tracing::error!(%error, "the served gateway TLS leaf is unreadable");
                TrustUpdateRefusal::Internal
            })?
            .not_after,
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
        })
    }

    async fn gateway_transition_published(
        &self,
        published: ::astra_channel::GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal> {
        let mut registry = self.registry.lock().await;
        registry
            .publish_gateway_transition(
                published.gateway_identity_epoch,
                &published.transition_fingerprint,
            )
            .map_err(|error| {
                tracing::warn!(
                    epoch = published.gateway_identity_epoch,
                    %error,
                    "publication marker refused"
                );
                classify(error)
            })?;
        tracing::warn!(
            epoch = published.gateway_identity_epoch,
            "gateway transition published: it can no longer be aborted, and the identity switches \
             at activation_at"
        );
        Ok(())
    }

    /// Queues a pre-signed transaction for the peer its manifest names.
    ///
    /// Nothing here verifies a signature, and that is the design rather than
    /// an omission: this gateway holds neither `CA-PQ` nor Astra's service key,
    /// so any verification it wrote would have to pick an authority it does
    /// have — which is precisely the substitution the receiver's own check
    /// exists to refuse. It checks the addressing, the fragment set and the
    /// deadline; Orion checks the signatures, under anchors it already trusts.
    async fn distribute(
        &self,
        distribution: Box<::astra_channel::TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal> {
        let peer = distribution.manifest.client_wg_public_key;
        let mut registry = self.registry.lock().await;
        registry
            .stage_distribution(
                &peer,
                distribution.manifest,
                distribution.chunks,
                now_unix(),
            )
            .map_err(|error| {
                tracing::warn!(%peer, %error, "trust distribution refused");
                classify(error)
            })
    }

    /// The recovery commit of §7.3, and only a recovery.
    ///
    /// # What makes this safe on a link the client is not on
    ///
    /// Three things, and all three are needed. The peer is read off the
    /// **signed** commit, which carries the signatures of both the expired
    /// generation and the candidate — so the relay names nobody. The stage
    /// being closed must be the one this presented authorization opened,
    /// compared by the fingerprint the registry already recorded — so the
    /// relay describes nothing. And that authorization must be a `CA-PQ`
    /// recovery, which is a decision an operator made at a security key, in
    /// the companion, and which no online process can produce.
    ///
    /// Without the last check this route would be a way for the authority to
    /// commit an ordinary renewal in a client's place — the one operation the
    /// tunnel exists to keep the client's own.
    async fn commit_recovery(
        &self,
        relayed: Box<::astra_channel::RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        use aether::certificates::authority::RotationReason;
        use aether::certificates::client::IssuerKind;

        let ::astra_channel::RelayedStageCommit {
            authorization,
            commit,
            grant,
        } = *relayed;
        let peer = commit.client_wg_public_key;
        if authorization.issuer_kind != IssuerKind::Master
            || authorization.reason != RotationReason::ExpiredRecovery
        {
            tracing::warn!(
                %peer,
                "relayed commit refused: this link carries the recovery of an expired identity \
                 and nothing else; an ordinary renewal is committed by the client, in its tunnel"
            );
            return Err(TrustUpdateRefusal::Rejected);
        }

        let now = now_unix();
        let mut registry = self.registry.lock().await;
        // The presented authorization must be the exact document that opened
        // the stage being closed. Matching it here is what turns «the relay
        // says this is a recovery» into «the registry already verified this
        // recovery», which is a different sentence.
        let recorded = registry
            .peer(&peer)
            .and_then(|peer| peer.state.pending.as_ref())
            .map(|pending| pending.authorization_fingerprint);
        let expected = authorization.fingerprint().map_err(|error| {
            tracing::warn!(%peer, %error, "relayed commit refused: unreadable authorization");
            TrustUpdateRefusal::Rejected
        })?;
        match recorded {
            Some(recorded) if recorded.matches(&expected) => {}
            _ => {
                tracing::warn!(
                    %peer,
                    "relayed commit refused: no pending stage of this peer was opened by the \
                     recovery authorization presented"
                );
                return Err(TrustUpdateRefusal::Rejected);
            }
        }

        registry
            .commit(&peer, &commit, &grant, now)
            .map(|_| ())
            .map_err(|error| {
                tracing::warn!(%peer, %error, "relayed recovery commit refused");
                classify(error)
            })
    }
}

pub(super) fn assert_candidate_is_presentable(
    state: &helios_provisioning::certificates::RegistryState,
    client_pq_ca: &[u8],
    authorization: &aether::certificates::client::ClientCertificateStageAuthorization,
) -> Result<(), String> {
    use aether::certificates::x509;

    // The TLS half: the leaf must chain to an anchor this gateway holds. When
    // a delegation issued it, that means the intermediate itself has to be
    // issued by one of the two client TLS CAs the registry names.
    let anchors: Vec<_> = [
        Some(&state.client_tls_ca.active_client_tls_ca_certificate),
        state.client_tls_ca.next_client_tls_ca_certificate.as_ref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let direct = anchors
        .iter()
        .any(|anchor| x509::assert_issued_by(&authorization.next_tls_certificate, anchor).is_ok());
    let delegated = authorization
        .issuer_authorization
        .as_ref()
        .is_some_and(|delegation| {
            x509::assert_issued_by(
                &authorization.next_tls_certificate,
                &delegation.tls_intermediate_certificate,
            )
            .is_ok()
                && anchors.iter().any(|anchor| {
                    x509::assert_issued_by(&delegation.tls_intermediate_certificate, anchor).is_ok()
                })
        });
    if !direct && !delegated {
        return Err("the candidate TLS leaf chains to no client CA this gateway holds".into());
    }

    // The PQ half, asked as **exactly** the question the negotiation port will
    // answer: the same issuer set, in the same order. Asking a narrower one
    // here refuses candidates that would in fact authenticate; asking a wider
    // one stages a leaf that locks its owner out at the end of the overlap.
    // Either way the two must not drift, which is why both build the set from
    // the registry plus the key on disk.
    let now = now_unix();
    let mut issuers = vec![client_pq_ca.to_vec()];
    for key in state.client_leaf_issuers(now) {
        let bytes = key.as_bytes().to_vec();
        if !issuers.contains(&bytes) {
            issuers.push(bytes);
        }
    }
    let mut refusal = String::from("no issuer offered");
    let presentable = issuers.iter().any(|issuer| {
        match authorization.next_pq_certificate.verify(
            issuer,
            aether::key_negotiation::PqCertificateRole::Client,
            None,
            &authorization.client_wg_public_key.to_base64(),
            now,
        ) {
            Ok(()) => true,
            Err(error) => {
                refusal = error.to_string();
                false
            }
        }
    });
    if !presentable {
        return Err(format!(
            "the candidate PQ leaf is not verifiable by the negotiation port: {refusal}"
        ));
    }
    Ok(())
}
