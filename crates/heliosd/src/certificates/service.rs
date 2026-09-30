//! The certificate service: the one owner of the registry, and its
//! maintenance loop.

use super::*;

/// Owner of the registry, and the only writer of its file.
pub struct CertificateService {
    pub(super) registry: SharedRegistry,
    pub(super) signer: Arc<dyn StageReceiptSigner>,
    /// TPM-derived unlock material retained only so step 9 can atomically
    /// replace the sealed active gateway identity at `not_after`.
    pub(super) gateway_identity_secret: Option<helios_tpm::SecretKey>,
    /// The authority's transaction producer, when this gateway has one.
    ///
    /// `None` on a gateway deployed without Astra, and that is a supported
    /// shape, not a degraded one: such a domain distributes nothing, so a
    /// lagging client is told the authority has queued nothing — the same
    /// answer, reached without a call that could not succeed.
    authority: Option<Arc<dyn ::astra_channel::TrustUpdatePreparer>>,
}

impl CertificateService {
    pub fn new(registry: SharedRegistry, signer: Arc<dyn StageReceiptSigner>) -> Self {
        Self {
            registry,
            signer,
            gateway_identity_secret: None,
            authority: None,
        }
    }

    pub fn with_gateway_identity_secret(mut self, secret: Option<helios_tpm::SecretKey>) -> Self {
        self.gateway_identity_secret = secret;
        self
    }

    /// The same service, able to ask the authority to build a transaction.
    pub fn with_authority(
        mut self,
        authority: Arc<dyn ::astra_channel::TrustUpdatePreparer>,
    ) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Asks the authority to build what this lagging peer is missing, and
    /// queues it (spec §0.6).
    ///
    /// Every failure is swallowed into a log line rather than returned: the
    /// caller's next act is to read the queue again, and an empty queue is
    /// already the answer this path produces when nothing can be prepared. A
    /// distinct error here would only turn "the authority is down" into a
    /// second refusal class the client cannot act on differently.
    ///
    /// What is relayed is a **canonical object this gateway builds**: the
    /// client's authenticated request, the caller resolved from the source
    /// VIP, and the peer snapshot the registry holds. Never the client's
    /// method, path or headers.
    pub(super) async fn prepare_from_authority(
        &self,
        caller: &WireGuardKey,
        request: &aether::certificates::transport::AuthenticatedTrustUpdateRequest,
        now: u64,
    ) -> Result<(), TrustUpdateRefusal> {
        let Some(authority) = &self.authority else {
            return Ok(());
        };
        let peer = {
            let registry = self.registry.lock().await;
            let peer = registry.peer(caller).ok_or(TrustUpdateRefusal::Rejected)?;
            ::astra_channel::PeerCertificateStateView {
                name: peer.name.clone(),
                state: peer.state.clone(),
                active_pq_certificate: peer.active_pq_certificate.clone(),
                admission_pq_ca: admission_pq_ca(),
            }
        };
        let relayed = ::astra_channel::RelayedTrustUpdatePreparation {
            caller_wg_public_key: *caller,
            request: Box::new(request.clone()),
            peer: Box::new(peer),
        };
        let prepared = match authority.prepare(&relayed).await {
            Ok(prepared) => prepared,
            Err(refusal) => {
                tracing::warn!(
                    peer = %caller, ?refusal,
                    "the authority refused to prepare a transaction for this peer"
                );
                return Ok(());
            }
        };
        let Some(transaction) = prepared.transaction else {
            return Ok(());
        };
        let mut registry = self.registry.lock().await;
        if let Err(error) =
            registry.stage_distribution(caller, transaction.manifest, transaction.chunks, now)
        {
            // The authority built something this gateway will not queue. That
            // is a disagreement worth naming: the two ends hold the same
            // registry contract, and a refusal here means one of them moved.
            tracing::error!(
                peer = %caller, %error,
                "the authority prepared a transaction this gateway refused to queue"
            );
        }
        Ok(())
    }

    /// Records a peer's first generation, from the leaves admission carried.
    ///
    /// Shared by the two ways a peer is admitted — the API route, which runs
    /// inside this process, and the console inbox drained by
    /// [`spawn_admission_drain`]. One implementation, because a second one
    /// would eventually date a generation differently and the divergence would
    /// only show at a renewal.
    pub(super) async fn record_first_generation(
        &self,
        name: &str,
        peer_wg_public_key: &str,
        tls_certificate: aether::certificates::encoding::DerCertificate,
        pq_certificate: aether::key_negotiation::PqCertificate,
    ) -> Result<(), TrustUpdateRefusal> {
        use aether::certificates::client::ClientCertificateGeneration;

        let peer_key =
            WireGuardKey::parse(peer_wg_public_key).map_err(|_| TrustUpdateRefusal::Protocol)?;
        // The leaf must name the key it is being recorded against. Two halves
        // of two identities, assembled here, would be a pair the domain never
        // issued — §3.3 refuses exactly that at the other end.
        if pq_certificate.wireguard_public_key.trim() != peer_key.to_base64() {
            return Err(TrustUpdateRefusal::Rejected);
        }
        let facts = aether::certificates::x509::inspect(&tls_certificate)
            .map_err(|_| TrustUpdateRefusal::Protocol)?;
        // The narrower of the two windows, because the generation is only
        // presentable while **both** halves are. Taking the PQ window alone
        // would date a generation by a certificate the TLS layer has already
        // stopped accepting.
        let not_before = facts.not_before.max(pq_certificate.not_before_unix);
        let not_after = facts.not_after.min(pq_certificate.not_after_unix);
        if not_after <= not_before {
            return Err(TrustUpdateRefusal::Rejected);
        }

        let mut registry = self.registry.lock().await;
        let state = registry.state();
        let generation = ClientCertificateGeneration {
            generation: 1,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
            tls_ca_certificate_fingerprint: state
                .client_tls_ca
                .active_client_tls_ca_certificate
                .fingerprint(),
            tls_certificate_fingerprint: tls_certificate.fingerprint(),
            pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
                &pq_certificate,
            )
            .map_err(|_| TrustUpdateRefusal::Protocol)?,
            not_before,
            not_after,
        };
        // Idempotent for a peer already recorded at this exact generation: an
        // admission that failed to persist `network.toml` is re-run by the
        // operator, and refusing the second attempt would leave them with a
        // registry row they cannot get rid of.
        if let Some(existing) = registry.peer(&peer_key) {
            if existing.name == name
                && existing.state.active == generation
                && !existing.state.revoked
            {
                return Ok(());
            }
        }
        registry
            .admit(name, &peer_key, generation, pq_certificate)
            .map_err(|error| {
                tracing::warn!(peer = %name, %error, "certificate registry refused an admission");
                classify(error)
            })?;
        tracing::info!(peer = %name, "first certificate generation recorded");
        Ok(())
    }

    /// Reads one queued admission and records it.
    ///
    /// The two certificates are decoded here rather than by the console: the
    /// daemon is the end that will have to authenticate them, so it is the end
    /// that decides whether they are readable at all.
    pub(super) async fn record_queued_admission(&self, path: &std::path::Path) -> Result<String> {
        use base64::Engine as _;

        let encoded = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let queued: QueuedAdmission =
            serde_json::from_slice(&encoded).context("reading the queued admission")?;
        let decoder = base64::engine::general_purpose::STANDARD;
        let tls = aether::certificates::encoding::DerCertificate::new(
            decoder
                .decode(queued.tls_certificate.trim())
                .context("the TLS certificate is not base64")?,
        )
        .map_err(|error| anyhow::anyhow!("the TLS certificate is refused: {error}"))?;
        let pq: aether::key_negotiation::PqCertificate = serde_json::from_slice(
            &decoder
                .decode(queued.pq_certificate.trim())
                .context("the PQ certificate is not base64")?,
        )
        .context("the PQ certificate is not a JSON document")?;
        self.record_first_generation(&queued.name, &queued.client_wg_public_key, tls, pq)
            .await
            .map_err(|refusal| anyhow::anyhow!("the registry refused it: {refusal:?}"))?;
        Ok(queued.name)
    }

    /// Withdraws this gateway's own identity (spec §10.1, §6.3 `revoked`).
    ///
    /// Terminal, and nothing local repairs it: a revoked gateway offers no
    /// acceptable leaf, so a client refuses the handshake rather than
    /// negotiating with an identity the authority has withdrawn. The counter
    /// is the gateway's own axis (§4.2) and is read from the state this
    /// process holds, never from the object being checked.
    pub(super) async fn revoke_gateway_identity(
        &self,
        revocation: &aether::certificates::revocation::EmergencyCertificateRevocation,
    ) -> Result<(), TrustUpdateRefusal> {
        let mut registry = self.registry.lock().await;
        let state = registry.state();
        if revocation.identity_key != state.gateway.gateway_wg_public_key {
            tracing::warn!(
                identity = %revocation.identity_key,
                "gateway revocation refused: it names another gateway"
            );
            return Err(TrustUpdateRefusal::Rejected);
        }
        revocation
            .verify(
                &state.gateway.current_ca_public_key,
                &state.trust_domain_id,
                state.gateway.ca_epoch,
                state.gateway.revocation_epoch,
            )
            .map_err(|error| {
                tracing::warn!(%error, "gateway revocation refused");
                classify(RegistryError::Certificate(error))
            })?;

        let hit = registry
            .revoke_gateway(
                revocation.revoked_tls_fingerprint.as_ref(),
                revocation.revoked_pq_fingerprint.as_ref(),
                revocation.revocation_epoch,
                revocation.replacement_transition_fingerprint.as_ref(),
            )
            .map_err(|error| {
                tracing::warn!(%error, "gateway revocation could not be applied");
                classify(error)
            })?;
        if hit {
            tracing::error!(
                revocation_epoch = revocation.revocation_epoch,
                "gateway certificate identity revoked: no client will negotiate with it again"
            );
        } else {
            tracing::warn!(
                revocation_epoch = revocation.revocation_epoch,
                "gateway revocation recorded for a leaf this gateway does not hold; its counter \
                 is consumed and the leaf can no longer arrive through a transition"
            );
        }
        Ok(())
    }

    /// Drops expired candidates and promotes due generations.
    ///
    /// Run on the same lock as everything else, so a purge never races the
    /// commit it competes with.
    pub async fn maintain(&self, now_unix: u64) -> Result<()> {
        let mut registry = self.registry.lock().await;
        let purged = registry.purge_expired(now_unix)?;
        for peer in &purged {
            tracing::info!(peer = %peer, "staged certificate purged: its lease ran out");
        }
        let promoted = registry.promote_due(now_unix)?;
        for peer in &promoted {
            tracing::info!(peer = %peer, "certificate generation promoted at the end of its overlap");
        }
        if let Some(reason) =
            crate::key_negotiation::restart_due(Some(&registry.state().gateway), now_unix)
        {
            // Loud, and repeated every sweep: the gateway is presenting a leaf
            // the domain has moved past, and nothing in this process will fix
            // it. Silence here is what turned an expired rollback into a
            // gateway that quietly kept serving the outgoing identity.
            tracing::warn!(%reason, "the key-negotiation identity in service is out of date");
        }
        if crate::gateway_rotation::maintain_gateway_identity(
            &mut registry,
            self.gateway_identity_secret.as_ref(),
            now_unix,
        )
        .context("maintaining the gateway certificate identity")?
        {
            tracing::info!(
                "gateway certificate identity promoted; the outgoing sealed key was destroyed"
            );
        }
        Ok(())
    }
}

/// How often the lifecycle sweeps leases and overlaps.
///
/// A minute: the shortest deadline it enforces is a 24-hour lease, and the
/// commit path checks the clock itself, so the sweep is what turns "expired"
/// into "gone from disk" rather than what decides a race.
pub const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// Sweeps leases and overlaps for the life of the process.
pub fn spawn_maintenance(service: Arc<CertificateService>) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = service.maintain(now_unix()).await {
                // Not fatal: an unwritable registry must not take the tunnel
                // down, and the next sweep tries again. It is loud because a
                // lease that never expires is a candidate that never frees
                // `active + 1`.
                tracing::error!(%error, "certificate lifecycle maintenance failed");
            }
        }
    });
}
