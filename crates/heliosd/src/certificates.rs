//! The gateway's certificate lifecycle service: one owner, one serializer.
//!
//! [`helios_provisioning::certificates::CertificateRegistry`] is a plain state
//! machine that takes `&mut self` and the clock as an argument. Something has
//! to own it, hold the lock, read the clock once per operation and hold the
//! sealed gateway key that signs receipts. That is this module, and there is
//! deliberately exactly one instance: a second one would give one slot two
//! writers, the same reason the negotiation state machine is a singleton.
//!
//! # What the gateway signs, and what it never signs
//!
//! It signs **receipts** — statements that a candidate is on its disk — with
//! its own active PQ leaf. It never signs a certificate, never holds `CA-PQ`,
//! and never calls an authority key on demand: every object it distributes was
//! pre-signed by Astra or by the operator companion (spec §8.1).
//!
//! # The gateway is a queue, not an author
//!
//! A transition reaches a client in two hops: the authority leaves a signed
//! transaction on the private veth (`POST
//! /internal/v1/certificates/distribution`), and the client collects its
//! fragments through `trust-update`. Nothing in between verifies a signature,
//! and that is the design: this process holds neither `CA-PQ` nor Astra's
//! service key, so any check it wrote would have to name an authority it does
//! have — exactly the substitution the receiver's own verification exists to
//! refuse. What it checks is the addressing, the fragment set and the
//! deadline; Orion checks the signatures, under anchors it already trusts.
//!
//! A caller that is provably behind with nothing queued for it still receives
//! [`TrustUpdateRefusal::Unavailable`] — a `503` — rather than an empty update,
//! because an empty update tells a client the opposite of the truth and it
//! would stop asking.
//!
//! # Limite connue : la réponse ne porte jamais de statut signé
//!
//! A status is signed by the **Astra service key**, which this process does not
//! hold and must not hold. Answering with an unsigned status, or with one
//! signed by the gateway leaf, would be inventing an authority. A client that
//! needs a signed freshness statement asks the authority for it through the
//! public channel of §8.2; what it gets here is the transaction itself, which
//! is what it actually has to apply.

use std::path::PathBuf;
use std::sync::Arc;

use aether::certificates::client::GatewayCertificateStageReceipt;
use aether::certificates::{encoding::WireGuardKey, CertificateError};
use anyhow::{Context, Result};
use async_trait::async_trait;
use helios_api::certificates::GatewayActionRefusal;
use helios_api::certificates::{
    AstraStageHandler, StageCommitRequest, TrustUpdateHandler, TrustUpdateRefusal,
    TrustUpdateResponse,
};
use helios_provisioning::certificates::{CertificateRegistry, RegistryError};
use tokio::sync::Mutex;

/// Signs a staging receipt with the gateway's **served** PQ leaf.
///
/// A trait, and not a copy of the private key, because that key is unsealed
/// exactly once — by the negotiation service — and the receipt has to be
/// signed by the leaf the client already pins. Handing this module a second
/// copy of the secret would be a second place to leak it from, for no gain.
pub trait StageReceiptSigner: Send + Sync {
    fn sign_stage_receipt(
        &self,
        receipt: GatewayCertificateStageReceipt,
    ) -> Result<GatewayCertificateStageReceipt, CertificateError>;

    /// The leaf this daemon actually serves.
    ///
    /// The **served** one, and that is the whole point: a rotation the daemon
    /// has not restarted for leaves a newer certificate on disk that no client
    /// is offered, and an authority verifying a receipt against the file would
    /// be verifying against a key that signed nothing. It comes from the same
    /// holder as the private half, so the two cannot disagree.
    fn served_pq_certificate(&self) -> aether::key_negotiation::PqCertificate;
}

/// Opens the registry once, for both the lifecycle and the negotiation.
///
/// Called before the negotiation starts, because the negotiation needs to read
/// it and the lifecycle service is built afterwards — it signs its receipts
/// through the negotiation handler. Loading it twice would put two writers on
/// one file.
///
/// A missing file is `None`, and that is not an empty domain: without `CA-PQ`
/// there is no anchor to verify anything against, so the lifecycle routes stay
/// closed rather than accepting the first object that arrives, and the
/// negotiation keeps to the pins of `network.toml`.
pub fn open_registry(path: &std::path::Path) -> Result<Option<SharedRegistry>> {
    let Some(registry) = CertificateRegistry::load(path)
        .with_context(|| format!("reading the certificate registry {}", path.display()))?
    else {
        return Ok(None);
    };
    Ok(Some(Arc::new(Mutex::new(registry))))
}

/// A registry behind its one lock, shared by its owner and its readers.
///
/// The **writer** is [`CertificateService`], and there is only ever one. The
/// key negotiation holds the same handle to *read* it: a caller resolved by
/// the fingerprint mTLS proved has to be looked up in the thing that recorded
/// the last rotation, not in a file written once at admission. One lock, one
/// registry — a second `CertificateRegistry` over the same path would be two
/// writers of one slot, which is the arrangement this module exists to avoid.
pub type SharedRegistry = Arc<Mutex<CertificateRegistry>>;

/// Owner of the registry, and the only writer of its file.
pub struct CertificateService {
    registry: SharedRegistry,
    signer: Arc<dyn StageReceiptSigner>,
    /// TPM-derived unlock material retained only so step 9 can atomically
    /// replace the sealed active gateway identity at `not_after`.
    gateway_identity_secret: Option<helio_tpm::SecretKey>,
    /// The authority's transaction producer, when this gateway has one.
    ///
    /// `None` on a gateway deployed without Astra, and that is a supported
    /// shape, not a degraded one: such a domain distributes nothing, so a
    /// lagging client is told the authority has queued nothing — the same
    /// answer, reached without a call that could not succeed.
    authority: Option<Arc<dyn helios_api::internal::TrustUpdatePreparer>>,
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

    pub fn with_gateway_identity_secret(mut self, secret: Option<helio_tpm::SecretKey>) -> Self {
        self.gateway_identity_secret = secret;
        self
    }

    /// The same service, able to ask the authority to build a transaction.
    pub fn with_authority(
        mut self,
        authority: Arc<dyn helios_api::internal::TrustUpdatePreparer>,
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
    async fn prepare_from_authority(
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
            helios_api::internal::PeerCertificateStateView {
                name: peer.name.clone(),
                state: peer.state.clone(),
                active_pq_certificate: peer.active_pq_certificate.clone(),
            }
        };
        let relayed = helios_api::internal::RelayedTrustUpdatePreparation {
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
    /// [`Self::drain_admissions`]. One implementation, because a second one
    /// would eventually date a generation differently and the divergence would
    /// only show at a renewal.
    async fn record_first_generation(
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
    async fn record_queued_admission(&self, path: &std::path::Path) -> Result<String> {
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
    async fn revoke_gateway_identity(
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

#[async_trait]
impl helios_api::certificates::GatewayIdentityHandler for CertificateService {
    /// §11.1 steps 1 and 2, driven from the console instead of a terminal.
    ///
    /// The registry is the daemon's own, held under the same lock as every
    /// other mutation. The offline command loads a second copy from disk,
    /// which is only safe while this process is stopped — one file with two
    /// writers is the failure the whole module is built to avoid.
    async fn prepare_renewal(
        &self,
        request: helios_api::certificates::GatewayRenewalRequest,
    ) -> Result<helios_api::certificates::GatewayRenewalView, GatewayActionRefusal> {
        let now = now_unix();
        let registry = self.registry.lock().await;
        let prepared = crate::gateway_rotation::prepare_request(
            &registry,
            self.gateway_identity_secret.as_ref(),
            // Never the development key on this route: a console that sealed
            // a candidate under a file key would hand an operator a request
            // for an identity no TPM can ever serve.
            false,
            request.rotate_tls,
            request.new_key,
            request.key_recovery,
            now,
        )
        .map_err(|error| {
            tracing::warn!(%error, "gateway renewal refused");
            GatewayActionRefusal::new(format!("{error:#}"))
        })?;

        Ok(helios_api::certificates::GatewayRenewalView {
            gateway_identity_epoch: prepared.request.gateway_identity_epoch,
            request_id: prepared.request.request_id.to_hex(),
            request_fingerprint: prepared.request.fingerprint().to_hex(),
            expires_at: prepared.request.expires_at,
            candidate_tls_fingerprint: prepared
                .tls_certificate
                .as_ref()
                .map(|certificate| certificate.fingerprint().to_hex()),
            reused: prepared.reused,
            key_recovery: request.key_recovery,
        })
    }

    async fn install_transition(
        &self,
        transition: Box<aether::certificates::gateway::GatewayIdentityTransition>,
    ) -> Result<helios_api::certificates::GatewayDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let staged = crate::gateway_rotation::install_transition(&mut registry, *transition, now)
            .map_err(|error| {
            tracing::warn!(%error, "gateway transition refused");
            GatewayActionRefusal::new(format!("{error:#}"))
        })?;
        let fingerprint = staged.transition.fingerprint().map_err(|error| {
            GatewayActionRefusal::new(format!("fingerprinting the staged transition: {error}"))
        })?;
        tracing::warn!(
            epoch = staged.transition.gateway_identity_epoch,
            "gateway transition staged from the console; the identity in service is unchanged"
        );
        Ok(helios_api::certificates::GatewayDecisionView {
            gateway_identity_epoch: staged.transition.gateway_identity_epoch,
            fingerprint: fingerprint.to_hex(),
            already_present: staged.already_present,
            activation_at: Some(staged.transition.window.activation_at),
            not_after: Some(staged.transition.window.not_after),
        })
    }

    async fn abort_transition(
        &self,
        abort: Box<aether::certificates::gateway::GatewayTransitionAbort>,
    ) -> Result<helios_api::certificates::GatewayDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let aborted = crate::gateway_rotation::abort_transition(&mut registry, *abort, now)
            .map_err(|error| {
                tracing::warn!(%error, "gateway transition abort refused");
                GatewayActionRefusal::new(format!("{error:#}"))
            })?;
        tracing::warn!(
            epoch = aborted.abort.gateway_identity_epoch,
            "gateway transition cancelled from the console; the epoch stays consumed"
        );
        Ok(helios_api::certificates::GatewayDecisionView {
            gateway_identity_epoch: aborted.abort.gateway_identity_epoch,
            fingerprint: aborted.abort.fingerprint().to_hex(),
            already_present: aborted.already_present,
            activation_at: None,
            not_after: None,
        })
    }

    /// §11.1 step 8, driven from the console.
    ///
    /// Records the selection; it takes effect at the next start, because the
    /// leaf in service was unsealed once and is held for the life of this
    /// process. Nothing else moves: the candidate stays sealed and its
    /// promotion still happens at `not_after`.
    async fn install_rollback(
        &self,
        authorization: Box<aether::certificates::status::CertificateServiceRollbackAuthorization>,
    ) -> Result<helios_api::certificates::GatewayRollbackView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let installed =
            crate::gateway_rotation::install_rollback(&mut registry, *authorization, now).map_err(
                |error| {
                    tracing::warn!(%error, "gateway service rollback refused");
                    GatewayActionRefusal::new(format!("{error:#}"))
                },
            )?;
        tracing::warn!(
            epoch = installed.gateway_identity_epoch,
            expires_at = installed.expires_at,
            "gateway service rollback selected from the console; it applies at the next restart"
        );
        Ok(helios_api::certificates::GatewayRollbackView {
            gateway_identity_epoch: installed.gateway_identity_epoch,
            selected_certificate_fingerprint: installed.selected_certificate_fingerprint.to_hex(),
            expires_at: installed.expires_at,
            already_present: installed.already_present,
        })
    }

    /// §9.1, applied to the anchor this gateway pins.
    ///
    /// The registry is the daemon's own, under the same lock as every other
    /// mutation. The anchor does not move here: both verify from
    /// `activation_at`, and the outgoing one is retired by the maintenance
    /// pass at `not_after` — the same pass that promotes the client
    /// generations, and in the same write.
    async fn install_ca_transition(
        &self,
        transition: Box<aether::certificates::authority::CaTransition>,
    ) -> Result<helios_api::certificates::AnchorDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let outcome = registry
            .install_ca_transition(&transition, now)
            .map_err(|error| {
                tracing::warn!(%error, "CA-PQ rotation refused");
                GatewayActionRefusal::new(format!("{error:#}"))
            })?;
        tracing::warn!(
            next_ca_epoch = transition.next_ca_epoch,
            "CA-PQ rotation staged from the console; both anchors verify from activation_at"
        );
        Ok(helios_api::certificates::AnchorDecisionView {
            ca_epoch: transition.current_ca_epoch,
            next_ca_epoch: transition.next_ca_epoch,
            next_ca_fingerprint: transition.next_ca_fingerprint.to_hex(),
            activation_at: transition.window.activation_at,
            not_after: transition.window.not_after,
            already_present: matches!(
                outcome,
                aether::certificates::state::InstallOutcome::AlreadyPresent
            ),
        })
    }
}

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

/// The two other routes of the private veth API (spec §8.3).
///
/// Staging lives in [`AstraStageHandler`] above; this adds revocation and the
/// read-back of one peer's state. All three go through the **same** mutex as
/// the in-tunnel commit and the maintenance sweep: a revocation has to dominate
/// a staging that is running concurrently, and it can only do that if both take
/// one serializer.
///
/// # Limite connue
///
/// A revocation whose scope is `gateway` is refused. Withdrawing the gateway's
/// own leaf is not a registry mutation but the identity transition of spec §6 —
/// it changes what the negotiation service serves, and that identity is read
/// once at startup and served until the process stops. Applying it here would
/// mark a state nothing acts on, which is worse than refusing. Delivering §6's
/// transition path, with the restart it implies, is what unblocks it.
#[async_trait]
impl helios_api::internal::AstraChannelHandler for CertificateService {
    async fn revoke(
        &self,
        revocation: Box<aether::certificates::revocation::EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        use aether::certificates::revocation::RevocationScope;

        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let state = registry.state();

        if revocation.scope == RevocationScope::Gateway {
            return self.revoke_gateway_identity(&revocation).await;
        }
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
    ) -> Result<helios_api::internal::PeerCertificateStateView, TrustUpdateRefusal> {
        let registry = self.registry.lock().await;
        let peer = registry
            .peer(identity)
            .ok_or(TrustUpdateRefusal::Rejected)?;
        Ok(helios_api::internal::PeerCertificateStateView {
            name: peer.name.clone(),
            state: peer.state.clone(),
            active_pq_certificate: peer.active_pq_certificate.clone(),
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
    ) -> Result<helios_api::internal::GatewayIdentityView, TrustUpdateRefusal> {
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
        Ok(helios_api::internal::GatewayIdentityView {
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
        published: helios_api::internal::GatewayTransitionPublished,
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
        distribution: Box<helios_api::internal::TrustDistribution>,
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
        relayed: Box<helios_api::internal::RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        use aether::certificates::authority::RotationReason;
        use aether::certificates::client::IssuerKind;

        let helios_api::internal::RelayedStageCommit {
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

/// One admission, as the console leaves it for the daemon.
///
/// # Why an inbox and not a direct write
///
/// `heliosd peer add` runs in another process, and the daemon holds the
/// registry **in memory**: a second writer would either be overwritten at the
/// daemon's next persist, or would overwrite a staging in flight. So the
/// console writes what it knows — the two public leaves — and the daemon, which
/// is the single owner, performs the admission. It is the same shape as
/// `network.toml` being watched rather than pushed, and for the same reason.
///
/// Everything here is public. A file left behind by a daemon that was not
/// running is drained at its next start, which is what makes an offline
/// `peer add` followed by a boot equivalent to an online one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedAdmission {
    pub name: String,
    pub client_wg_public_key: String,
    /// The TLS leaf, DER in base64.
    pub tls_certificate: String,
    /// The PQ leaf, its JSON document in base64.
    pub pq_certificate: String,
}

/// Where the console leaves admissions for the daemon.
///
/// Beside the registry rather than at a fixed path, so a test — and a
/// `--dev` daemon — keeps both in the same disposable directory.
pub fn admission_inbox(registry_path: &std::path::Path) -> PathBuf {
    registry_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("admissions")
}

/// Leaves one admission for the daemon to record.
///
/// Named by the peer's WireGuard key, so a re-run of the same admission
/// replaces its own file instead of queueing a second one.
pub fn queue_admission(
    registry_path: &std::path::Path,
    admission: &QueuedAdmission,
) -> Result<PathBuf> {
    let directory = admission_inbox(registry_path);
    aether::private_file::create_private_dir(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let name = format!(
        "{}.json",
        aether::certificates::encoding::Fingerprint::of(admission.client_wg_public_key.as_bytes())
            .to_hex()
    );
    let path = directory.join(name);
    let encoded = serde_json::to_vec_pretty(admission).context("encoding the admission")?;
    aether::private_file::write_private_atomic(&path, &encoded)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// How often the daemon looks for admissions left by the console.
///
/// The same cadence as `network.toml` is watched at, and for the same reason:
/// an operator admits a peer and then immediately asks for its trust block.
/// Nothing is read unless a file is there, so the cost between two admissions
/// is one `read_dir` on an empty directory.
pub const ADMISSION_POLL_INTERVAL_SECS: u64 = 2;

/// Records the admissions the console left, and forgets the ones it recorded.
///
/// A refusal deletes the file too, and says so loudly: a queued admission that
/// this gateway will never accept — a leaf naming another peer, a window
/// already closed — would otherwise be retried every two seconds for as long
/// as the daemon runs, and the operator would read the same line for ever
/// instead of re-admitting.
pub fn spawn_admission_drain(service: Arc<CertificateService>, registry_path: PathBuf) {
    tokio::spawn(async move {
        let directory = admission_inbox(&registry_path);
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(ADMISSION_POLL_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                match service.record_queued_admission(&path).await {
                    Ok(name) => {
                        tracing::info!(peer = %name, "console admission recorded");
                    }
                    Err(error) => {
                        tracing::error!(
                            file = %path.display(),
                            %error,
                            "console admission refused: this peer has no certificate generation, \
                             so it will connect but never renew. Re-admit it."
                        );
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    });
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Whether the caller already holds everything this gateway would send it.
///
/// Every value the request declares is compared, and that exhaustiveness is
/// the property: a comparison that skipped a counter would answer "you are up
/// to date" to a client that is behind on exactly that counter, and the client
/// would stop asking. Since the only other answer this route can give today is
/// a `503`, a false "current" is the one outcome with no recovery — the client
/// has been told there is nothing to fetch.
///
/// Written as a free function over the persisted state so it can be exercised
/// without a runtime, a lock or a signer.
fn caller_is_current(
    state: &helios_provisioning::certificates::RegistryState,
    peer: &helios_provisioning::certificates::PeerCertificates,
    request: &aether::certificates::transport::TrustUpdateRequest,
) -> Result<bool, CertificateError> {
    let issuer_epoch = state
        .issuer
        .as_ref()
        .map_or(0, |issuer| issuer.issuer_epoch);
    Ok(request.ca_epoch == state.gateway.ca_epoch
        && request.ca_tls_epoch == state.client_tls_ca.ca_tls_epoch
        && request.astra_service_key_epoch == state.astra.astra_service_key_epoch
        && request.issuer_epoch == issuer_epoch
        && request.active_gateway_identity_epoch == state.gateway.active_gateway_identity_epoch
        && request.gateway_decision_epoch == state.gateway.gateway_decision_epoch
        && request
            .active_gateway_tls_certificate_fingerprint
            .matches(&state.gateway.active_tls_fingerprint())
        && request
            .active_gateway_certificate_fingerprint
            .matches(&state.gateway.active_pq_fingerprint()?)
        && request.client_identity_generation == peer.state.active.generation
        && request
            .active_client_tls_certificate_fingerprint
            .matches(&peer.state.active.tls_certificate_fingerprint)
        && request
            .active_client_pq_certificate_fingerprint
            .matches(&peer.state.active.pq_certificate_fingerprint))
}

/// The §19 trust block for one peer, from one reading of the registry.
///
/// A free function over the persisted state, like [`caller_is_current`] and
/// for the same reason: it can then be exercised without a runtime, a lock or
/// a signer — and the values it copies are exactly the ones a profile pins for
/// years.
pub fn enrolment_view(
    state: &helios_provisioning::certificates::RegistryState,
    peer: &helios_provisioning::certificates::PeerCertificates,
) -> helios_api::certificates::TrustEnrolmentView {
    use base64::Engine as _;

    let encoder = base64::engine::general_purpose::STANDARD;
    helios_api::certificates::TrustEnrolmentView {
        trust_domain_id: state.trust_domain_id.to_hex(),
        ca_epoch: state.gateway.ca_epoch,
        ca_pq_public_key: state.gateway.current_ca_public_key.to_base64(),
        ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
        client_tls_ca_der: encoder.encode(
            state
                .client_tls_ca
                .active_client_tls_ca_certificate
                .as_bytes(),
        ),
        client_generation: peer.state.active.generation,
        astra_authority_url: state.astra.authority_url.clone(),
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
        astra_policy_fingerprint: state.astra.astra_policy_fingerprint.fingerprint().to_hex(),
        credential_registry_epoch: state.astra.credential_registry_epoch,
        astra_credential_bindings: state.astra.credential_bindings.values().cloned().collect(),
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_service_public_key: state.astra.active_astra_service_public_key.to_base64(),
    }
}

/// The whole domain, from one reading of the registry (spec §12.1).
///
/// A free function over the persisted state, like [`enrolment_view`]: the
/// console's numbers are then exercised without a runtime, a lock or a signer,
/// and the arithmetic that decides a renewal is due is the protocol's own
/// rather than a second copy of it.
///
/// Nothing secret crosses: anchors, epochs, fingerprints, dates and counts.
/// The certificate bodies stay here — an operator acts on an expiry, never on
/// a DER blob — and so does every private key, which this process holds none
/// of anyway.
pub fn domain_view(
    state: &helios_provisioning::certificates::RegistryState,
    now_unix: u64,
) -> helios_api::certificates::CertificateDomainView {
    use aether::certificates::window::{ValidityPeriod, ValidityPhase};
    use helios_api::certificates::{IssuerView, PeerCertificateView, PendingStageView};

    let peers = state
        .peers
        .iter()
        .map(|(key, peer)| {
            let active = &peer.state.active;
            // A period the issuer wrote inconsistently cannot be placed on the
            // ladder. It is reported as expired rather than hidden: the leaf
            // is unusable either way, and a peer missing from the list is a
            // peer nobody investigates.
            let phase = ValidityPeriod::new(active.not_before, active.not_after)
                .map(|period| period.phase(now_unix))
                .unwrap_or(ValidityPhase::Expired);
            PeerCertificateView {
                name: peer.name.clone(),
                wg_public_key: key.clone(),
                generation: active.generation,
                not_before: active.not_before,
                not_after: active.not_after,
                phase,
                revoked: peer.state.revoked,
                pending: peer.state.pending.as_ref().map(|pending| PendingStageView {
                    generation: pending.candidate.generation,
                    state: pending.state,
                    stage_expires_at: pending.stage_expires_at,
                }),
                next_generation: peer.state.next.as_ref().map(|next| next.generation),
                activation_at: peer.state.activation_at,
                distribution_chunks_pending: peer
                    .distribution
                    .as_ref()
                    .map(|distribution| {
                        let served = usize::from(distribution.cursor);
                        u16::try_from(distribution.chunks.len().saturating_sub(served))
                            .unwrap_or(u16::MAX)
                    })
                    .unwrap_or(0),
            }
        })
        .collect();

    helios_api::certificates::CertificateDomainView {
        trust_domain_id: state.trust_domain_id.to_hex(),
        server_name: state.gateway.server_name.clone(),
        now_unix,
        ca_epoch: state.gateway.ca_epoch,
        ca_pq_fingerprint: state
            .gateway
            .current_ca_public_key
            .authority_fingerprint()
            .to_hex(),
        ca_transition_pending: state.gateway.next_ca_public_key.is_some(),
        ca_activation_at: state.gateway.ca_activation_at,
        ca_retire_active_at: state.gateway.ca_retire_active_at,
        next_ca_fingerprint: state
            .gateway
            .next_ca_public_key
            .as_ref()
            .map(|key| key.authority_fingerprint().to_hex()),
        client_tls_ca_epoch: state.client_tls_ca.ca_tls_epoch,
        client_tls_ca_transition_pending: state
            .client_tls_ca
            .next_client_tls_ca_certificate
            .is_some(),
        gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
        gateway_tls_fingerprint: state.gateway.active_tls_fingerprint().to_hex(),
        // An unreadable active leaf is the gateway's own identity failing to
        // parse. Empty rather than a panic: this is a read, and the console
        // showing a blank fingerprint beside populated epochs is a louder
        // symptom than a `500` an operator reads as "the console is broken".
        gateway_pq_fingerprint: state
            .gateway
            .active_pq_fingerprint()
            .map(|fingerprint| fingerprint.to_hex())
            .unwrap_or_default(),
        gateway_transition_pending: state.gateway.next_gateway_certificate.is_some(),
        gateway_activation_at: state.gateway.activation_at,
        gateway_retire_active_at: state.gateway.retire_active_at,
        gateway_transition_published: state.gateway.published,
        gateway_rollback_expires_at: state
            .gateway
            .active_service_rollback(now_unix)
            .map(|rollback| rollback.expires_at),
        gateway_restart_due: crate::key_negotiation::restart_due(Some(&state.gateway), now_unix),
        astra_authority_url: state.astra.authority_url.clone(),
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_policy_fingerprint: state.astra.astra_policy_fingerprint.fingerprint().to_hex(),
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
        credential_registry_epoch: state.astra.credential_registry_epoch,
        credential_bindings: state.astra.credential_bindings.len(),
        issuer: state.issuer.as_ref().map(|issuer| IssuerView {
            issuer_epoch: issuer.issuer_epoch,
            lifecycle: issuer.state,
            not_before: issuer.authorization.not_before,
            not_after: issuer.authorization.not_after,
            usable: issuer.is_usable(now_unix),
        }),
        peers,
    }
}

/// Refuses a candidate this gateway would not accept on the negotiation port.
///
/// # Why staging has to ask this at all
///
/// A staged generation becomes the client's only identity at the end of its
/// overlap. If the gateway cannot authenticate it then, the client is locked
/// out of the tunnel that was its only way to ask for help — and the operator
/// finds out days later, on a machine that no longer connects. So the question
/// is asked **before** the candidate is written, where the answer still costs
/// nothing.
///
/// # Why this asks the negotiation's own question
///
/// The negotiation now resolves callers from the registry and admits every
/// issuer the domain names — the anchor, its successor, the delegated issuer,
/// and the operator CA the first generation was signed by. This check builds
/// **the same set, the same way**. Two slightly different answers to "would
/// this leaf authenticate" is the failure that has no good outcome: the
/// narrower one refuses candidates that would have worked, and the wider one
/// stages a leaf whose owner is locked out at the end of the overlap, on a
/// machine whose only channel for saying so was the tunnel.
///
/// # Limite connue — the TLS root set is still read once, at startup
///
/// The QUIC endpoint loads the operator admission CA from
/// `/var/lib/helios/key-negotiation-client-ca.der`, then adds the domain
/// anchors the registry accepts at that instant. A delegated leaf therefore
/// validates when the client presents its intermediate. The set stays fixed
/// for the process lifetime: a `CA-TLS` transition installed before
/// `activation_at` still requires a restart during the overlap to offer its
/// successor, and another after retirement to stop offering the outgoing
/// root at the TLS layer. The paired TLS/PQ registry check remains
/// time-bounded on every request, so a root merely present in the endpoint is
/// never sufficient to admit a stale generation.
/// Every authority a client leaf may chain to, in the order the negotiation
/// port asks them.
///
/// Pure on purpose, like [`assert_candidate_is_presentable`]: the key is read
/// from disk by the caller, so this can be exercised without a
/// `/var/lib/helios` on the machine running it.
fn client_leaf_issuers<'a>(
    state: &'a helios_provisioning::certificates::RegistryState,
    operator_ca: &'a aether::certificates::encoding::MlDsa87PublicKey,
    now_unix: u64,
) -> Vec<&'a aether::certificates::encoding::MlDsa87PublicKey> {
    let mut issuers = vec![operator_ca];
    for key in state.client_leaf_issuers(now_unix) {
        if !issuers.contains(&key) {
            issuers.push(key);
        }
    }
    issuers
}

fn assert_candidate_is_presentable(
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

/// Maps a registry refusal to the bounded class the API may report.
///
/// The detail goes to the protected log. A peer learns only the class, exactly
/// as on the public negotiation port: a finer taxonomy on an
/// authenticated-but-hostile caller is an oracle on other peers' generations.
fn classify(error: RegistryError) -> TrustUpdateRefusal {
    match error {
        RegistryError::Io(_) | RegistryError::Corrupt(_) => TrustUpdateRefusal::Internal,
        RegistryError::Certificate(CertificateError::UnsupportedFormatVersion { .. })
        | RegistryError::Certificate(CertificateError::UnsupportedProtocolVersion { .. }) => {
            TrustUpdateRefusal::Protocol
        }
        _ => TrustUpdateRefusal::Rejected,
    }
}

#[async_trait]
impl TrustUpdateHandler for CertificateService {
    /// The public trust material a profile must carry for one peer (spec §19).
    ///
    /// Every value is read from the registry in one lock, and that matters: an
    /// epoch taken from one moment beside an anchor from another would produce
    /// a profile that pins a pair which never existed together, and the
    /// mismatch would only surface at the first renewal — 80 % into a leaf's
    /// life, on a client with no fallback.
    async fn admit_peer(
        &self,
        name: &str,
        peer_wg_public_key: &str,
        tls_certificate: aether::certificates::encoding::DerCertificate,
        pq_certificate: Box<aether::key_negotiation::PqCertificate>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.record_first_generation(name, peer_wg_public_key, tls_certificate, *pq_certificate)
            .await
    }

    async fn trust_enrolment(
        &self,
        peer_wg_public_key: &str,
    ) -> Result<helios_api::certificates::TrustEnrolmentView, TrustUpdateRefusal> {
        let peer_key =
            WireGuardKey::parse(peer_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let registry = self.registry.lock().await;
        let peer = registry
            .peer(&peer_key)
            .ok_or(TrustUpdateRefusal::Rejected)?;
        Ok(enrolment_view(registry.state(), peer))
    }

    async fn domain(
        &self,
    ) -> Result<helios_api::certificates::CertificateDomainView, TrustUpdateRefusal> {
        let now = now_unix();
        let registry = self.registry.lock().await;
        Ok(domain_view(registry.state(), now))
    }

    async fn trust_update(
        &self,
        caller_wg_public_key: &str,
        request: aether::certificates::transport::AuthenticatedTrustUpdateRequest,
    ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let registry = self.registry.lock().await;
        let state = registry.state();

        // Every authority that may have issued the caller's leaf, asked as
        // exactly the question the negotiation port answers: the operator CA
        // on disk, then the registry's anchors and the delegated issuer an
        // ordinary renewal chains to.
        //
        // The operator CA is not optional here. A client's *first* leaf is
        // issued under it at admission — only a renewal moves it to the
        // delegated issuer — so a set built from the registry alone refuses
        // every client that has never renewed, which on a fresh domain is all
        // of them. Both other sites that ask this question build it the same
        // way, and the three must not drift: this one did, and the symptom was
        // a `403` on every connection with nothing naming the cause.
        let operator_ca = std::fs::read(crate::key_negotiation::CLIENT_PQ_CA_PATH)
            .map_err(|error| {
                tracing::error!(
                    peer = %caller_wg_public_key,
                    %error,
                    "trust update refused: the client PQ CA the negotiation port authenticates \
                     under is unreadable"
                );
                TrustUpdateRefusal::Internal
            })
            .and_then(|bytes| {
                aether::certificates::encoding::MlDsa87PublicKey::new(bytes).map_err(|error| {
                    tracing::error!(
                        peer = %caller_wg_public_key,
                        %error,
                        "trust update refused: the client PQ CA on disk is not a readable \
                         ML-DSA-87 public key"
                    );
                    TrustUpdateRefusal::Internal
                })
            })?;
        let issuers = client_leaf_issuers(state, &operator_ca, now);

        request
            .verify(
                &issuers,
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                &caller,
                &registry.acceptable_pq_fingerprints(&caller, now),
                now,
            )
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust update refused");
                TrustUpdateRefusal::Rejected
            })?;

        let peer = registry.peer(&caller).ok_or(TrustUpdateRefusal::Rejected)?;
        let current = caller_is_current(state, peer, &request.request)
            .map_err(|_| TrustUpdateRefusal::Internal)?;

        if current {
            return Ok(TrustUpdateResponse {
                status: None,
                manifest: None,
                chunk: None,
            });
        }

        // Behind. Whether there is anything to hand over is a question about
        // the queue, not about the comparison — and the two are kept apart
        // because a client that is current must never pay for a queue read.
        let request_id = request.request.request_id;
        drop(registry);
        let mut registry = self.registry.lock().await;
        let served = registry
            .take_distribution_chunk(
                &caller,
                &request_id,
                &request.request.base_state_fingerprint,
                now,
            )
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust distribution unreadable");
                classify(error)
            })?;
        let served = match served {
            Some(served) => Some(served),
            // Nothing queued for this exact base state — either nothing was
            // ever queued, or what was queued described a state this client
            // has since left and the read above dropped it. Both mean the same
            // thing: ask the authority to build one for the state this request
            // signed (§0.6).
            None => {
                drop(registry);
                self.prepare_from_authority(&caller, &request, now).await?;
                let mut registry = self.registry.lock().await;
                registry
                    .take_distribution_chunk(
                        &caller,
                        &request_id,
                        &request.request.base_state_fingerprint,
                        now,
                    )
                    .map_err(|error| {
                        tracing::warn!(
                            peer = %caller_wg_public_key, %error,
                            "trust distribution unreadable after preparation"
                        );
                        classify(error)
                    })?
            }
        };
        match served {
            Some((manifest, chunk)) => Ok(TrustUpdateResponse {
                // Never a status: one is signed by Astra's service key, which
                // this gateway does not hold and must not hold. A client that
                // needs a signed freshness statement asks the authority for it
                // (§8.2); what it gets here is the transaction itself.
                status: None,
                manifest: Some(manifest),
                chunk: Some(chunk),
            }),
            None => {
                // Behind, and the authority has nothing for it. Saying so
                // beats claiming the client is up to date: an empty update is
                // the one answer a client does not recover from, because it
                // stops asking.
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    "trust update: the caller is behind and the authority has nothing for it"
                );
                Err(TrustUpdateRefusal::Unavailable)
            }
        }
    }

    async fn stage_commit(
        &self,
        caller_wg_public_key: &str,
        request: Box<StageCommitRequest>,
    ) -> Result<(), TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        registry
            .commit(&caller, &request.commit, &request.grant, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "commit refused");
                classify(error)
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, TrustDomainId,
    };
    use aether::certificates::state::{
        AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState,
    };
    use aether::certificates::transport::TrustUpdateRequest;
    use aether::certificates::CERTIFICATE_PROTOCOL_VERSION;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use helios_provisioning::certificates::{PeerCertificates, RegistryState};

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    fn generation() -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    /// A signed leaf: the fingerprint of a PQ certificate covers its
    /// signature, so an unsigned placeholder has no fingerprint at all.
    fn signed_leaf(role: PqCertificateRole, subject: &str, serial: u8) -> PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [serial; 16],
                subject: subject.into(),
                issuer: "CA-PQ".into(),
                role,
                wireguard_public_key: key(9).to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    fn gateway_leaf() -> PqCertificate {
        signed_leaf(PqCertificateRole::Gateway, "gateway.example", 1)
    }

    fn state() -> RegistryState {
        let (_, anchor) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
        RegistryState {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway: GatewayCertificateState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: key(9),
                server_name: "gateway.example".into(),
                ca_epoch: 1,
                current_ca_public_key: anchor,
                next_ca_public_key: None,
                next_ca_transition_fingerprint: None,
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 3,
                gateway_decision_epoch: 3,
                next_gateway_identity_epoch: None,
                next_transition_fingerprint: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_leaf(),
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
                service_rollback: None,
                awaited_replacement: None,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 2,
                // A genuine anchor, not a stub: the enrolment block ships this
                // certificate to every client, and Orion parses it at import.
                // A placeholder here would let the block pass these tests and
                // be refused on the machine it was emitted for.
                active_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
                    "workstation",
                )
                .authority,
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                    Fingerprint::of(b"policy"),
                )
                .expect("policy pin"),
                credential_registry_epoch: 1,
                credential_bindings: Default::default(),
                active_astra_service_public_key: service,
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 5,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer: None,
            peers: Default::default(),
            ledger: Default::default(),
        }
    }

    fn peer() -> PeerCertificates {
        PeerCertificates {
            name: "workstation".into(),
            state: ClientCertificateState::new(generation()),
            active_pq_certificate: signed_leaf(PqCertificateRole::Client, "workstation", 2),
            staged_pq_certificate: None,
            distribution: None,
        }
    }

    /// A relayed recovery commit whose shape is right and whose stage is not.
    ///
    /// The signatures are placeholders on purpose: every assertion that uses
    /// this refuses **before** any signature is read, and building real ones
    /// would hide which check actually fired.
    fn relayed_commit() -> helios_api::internal::RelayedStageCommit {
        use aether::certificates::authority::RotationReason;
        use aether::certificates::client::{
            ClientCertificateStageAuthorization, ClientCertificateStageCommit,
        };
        use aether::certificates::encoding::MlDsa87Signature;
        use aether::certificates::window::TransitionWindow;

        let stage_id = Id16::new([4; 16]).expect("id");
        let authorization = ClientCertificateStageAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 2,
            issuer_kind: aether::certificates::client::IssuerKind::Master,
            issuer_epoch: 1,
            issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
            issuer_authorization: None,
            stage_id,
            request_fingerprint: Fingerprint::of(b"recovery request"),
            renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
            renewal_approval: None,
            campaign_approval: None,
            gateway_wg_public_key: key(9),
            server_name: "gateway.example".into(),
            client_wg_public_key: key(2),
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            next_tls_certificate: DerCertificate::new(vec![2; 64]).expect("der"),
            next_pq_certificate: signed_leaf(PqCertificateRole::Client, "workstation", 5),
            issued_at: 1_000,
            stage_expires_at: 4_000,
            window: TransitionWindow::new(1_000, 2_000, 9_000).expect("window"),
            reason: RotationReason::ExpiredRecovery,
            signature: MlDsa87Signature::placeholder(),
        };
        let commit = ClientCertificateStageCommit {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            stage_id,
            grant_fingerprint: Fingerprint::of(b"grant"),
            stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
            staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
            stage_expires_at: 4_000,
            committed_at: 1_100,
            active_pq_signature: MlDsa87Signature::placeholder(),
            staged_pq_signature: MlDsa87Signature::placeholder(),
        };
        let grant = aether::certificates::client::ClientCertificateRotationGrant {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            ca_epoch: 1,
            ca_tls_epoch: 2,
            issuer_kind: authorization.issuer_kind,
            issuer_epoch: 1,
            issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
            issuer_authorization: None,
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            renewal_approval: None,
            campaign_approval: None,
            stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
            stage_receipt: aether::certificates::client::GatewayCertificateStageReceipt {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: authorization.trust_domain_id,
                stage_id,
                stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
                request_fingerprint: authorization.request_fingerprint,
                renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
                gateway_wg_public_key: authorization.gateway_wg_public_key,
                client_wg_public_key: authorization.client_wg_public_key,
                active_generation: 4,
                staged_generation: 5,
                staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
                staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
                persisted_at: 1_050,
                stage_expires_at: 4_000,
                active_gateway_identity_epoch: 3,
                gateway_decision_epoch: 3,
                gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
                gateway_signature: MlDsa87Signature::placeholder(),
            },
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            server_name: authorization.server_name.clone(),
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            next_tls_certificate: authorization.next_tls_certificate.clone(),
            next_pq_certificate: authorization.next_pq_certificate.clone(),
            stage_expires_at: 4_000,
            window: authorization.window,
            reason: authorization.reason,
            signature: MlDsa87Signature::placeholder(),
        };
        helios_api::internal::RelayedStageCommit {
            authorization: Box::new(authorization),
            commit: Box::new(commit),
            grant: Box::new(grant),
        }
    }

    /// A request that declares exactly what the gateway serves.
    fn request(state: &RegistryState, peer: &PeerCertificates) -> TrustUpdateRequest {
        TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            client_wg_public_key: key(2),
            ca_epoch: state.gateway.ca_epoch,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
            astra_service_key_epoch: state.astra.astra_service_key_epoch,
            issuer_epoch: 0,
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
            client_identity_generation: peer.state.active.generation,
            active_gateway_tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
            active_gateway_certificate_fingerprint: state
                .gateway
                .active_pq_fingerprint()
                .expect("fingerprint"),
            active_client_tls_certificate_fingerprint: peer
                .state
                .active
                .tls_certificate_fingerprint,
            active_client_pq_certificate_fingerprint: peer.state.active.pq_certificate_fingerprint,
            client_pq_certificate_fingerprint: Fingerprint::of(b"presented"),
            base_state_fingerprint: Fingerprint::of(b"base state"),
        }
    }

    /// A relayed request, whose signature this side never checks.
    ///
    /// `prepare_from_authority` relays and does not verify: the gateway
    /// already verified the request before deciding the caller was behind, and
    /// the authority verifies it again under the peer snapshot it is handed.
    /// A fixture that had to produce a real signature would be testing those
    /// two, not this one.
    fn authenticated_request(
        peer_key: &WireGuardKey,
    ) -> aether::certificates::transport::AuthenticatedTrustUpdateRequest {
        let mut state = state();
        state.peers.insert(peer_key.to_base64(), peer());
        let peer = state
            .peers
            .get(&peer_key.to_base64())
            .expect("peer")
            .clone();
        aether::certificates::transport::AuthenticatedTrustUpdateRequest {
            request: request(&state, &peer),
            certificate: peer.active_pq_certificate.clone(),
            ml_dsa_87_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        }
    }

    /// An authority that hands back exactly what it was built with.
    ///
    /// The gateway is not supposed to inspect a prepared transaction — the
    /// registry's own `stage_distribution` is the check — so the stub answers
    /// unconditionally and the test asserts on what the queue then holds.
    struct StubAuthority {
        prepared: helios_api::internal::PreparedTrustUpdate,
    }

    #[async_trait::async_trait]
    impl helios_api::internal::TrustUpdatePreparer for StubAuthority {
        async fn prepare(
            &self,
            _relayed: &helios_api::internal::RelayedTrustUpdatePreparation,
        ) -> Result<helios_api::internal::PreparedTrustUpdate, TrustUpdateRefusal> {
            Ok(self.prepared.clone())
        }
    }

    /// A registry on a disposable path, and a signer that signs nothing.
    ///
    /// `admit_peer` never reaches the signer — it records a generation the
    /// operator issued — so a stub that refuses is enough, and it makes the
    /// test say out loud that admission borrows no gateway key.
    struct RefusingSigner;

    impl StageReceiptSigner for RefusingSigner {
        fn sign_stage_receipt(
            &self,
            _receipt: GatewayCertificateStageReceipt,
        ) -> Result<GatewayCertificateStageReceipt, CertificateError> {
            Err(CertificateError::Signing)
        }

        fn served_pq_certificate(&self) -> PqCertificate {
            gateway_leaf()
        }
    }

    fn service(state: RegistryState) -> (CertificateService, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("tempdir");
        let registry =
            CertificateRegistry::bootstrap(directory.path().join("certificates.json"), state)
                .expect("registry");
        (
            CertificateService::new(Arc::new(Mutex::new(registry)), Arc::new(RefusingSigner)),
            directory,
        )
    }

    /// A client leaf issued to one exact WireGuard key, with a real signature.
    fn client_leaf(wg_public_key: &WireGuardKey, not_after: u64) -> PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: "workstation".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: wg_public_key.to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 100,
                not_after_unix: not_after,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    /// Admission is where a peer enters the registry, and it enters whole:
    /// both leaves, the anchor they chain to, and the window in which they may
    /// be presented. Without this row there is no trust block, therefore a
    /// profile that connects and can never renew — and nothing says so until
    /// 80 % of a leaf's life.
    #[tokio::test]
    async fn admission_records_the_first_generation_from_the_two_leaves() {
        let state = state();
        let anchor = state
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint();
        let (service, _directory) = service(state);
        let peer_key = key(2);
        let material = aether::certificates::test_x509::client_material("workstation");
        let leaf = client_leaf(&peer_key, 500_000);

        service
            .admit_peer(
                "workstation",
                &peer_key.to_base64(),
                material.leaf.clone(),
                Box::new(leaf.clone()),
            )
            .await
            .expect("admission");

        let registry = service.registry.lock().await;
        let recorded = registry.peer(&peer_key).expect("peer recorded");
        assert_eq!(recorded.name, "workstation");
        assert_eq!(recorded.state.active.generation, 1);
        assert_eq!(
            recorded.state.active.tls_certificate_fingerprint,
            material.leaf.fingerprint()
        );
        assert_eq!(
            recorded.state.active.pq_certificate_fingerprint,
            aether::certificates::gateway::pq_certificate_fingerprint(&leaf).expect("fingerprint")
        );
        assert_eq!(
            recorded.state.active.tls_ca_certificate_fingerprint, anchor,
            "the generation names the anchor the registry actually holds"
        );
        // The narrower of the two windows: the PQ leaf expires first here, and
        // a generation is only presentable while both halves are.
        assert_eq!(recorded.state.active.not_after, 500_000);
    }

    /// An interrupted admission is re-run by the operator. The second attempt
    /// has to finish it, not refuse it — otherwise the registry holds a row
    /// they cannot get rid of and cannot complete.
    #[tokio::test]
    async fn re_admitting_an_unchanged_peer_is_a_no_op() {
        let (service, _directory) = service(state());
        let peer_key = key(2);
        let material = aether::certificates::test_x509::client_material("workstation");
        let leaf = client_leaf(&peer_key, 500_000);

        for _ in 0..2 {
            service
                .admit_peer(
                    "workstation",
                    &peer_key.to_base64(),
                    material.leaf.clone(),
                    Box::new(leaf.clone()),
                )
                .await
                .expect("admission");
        }

        assert_eq!(service.registry.lock().await.state().peers.len(), 1);
    }

    /// The PQ leaf names the WireGuard key it belongs to. Recording it against
    /// another one assembles an identity the domain never issued — §3.3 refuses
    /// exactly that pair at the other end, and it must not be creatable here.
    #[tokio::test]
    async fn a_leaf_naming_another_peer_is_refused() {
        let (service, _directory) = service(state());
        let material = aether::certificates::test_x509::client_material("workstation");
        let leaf = client_leaf(&key(2), 500_000);

        let refusal = service
            .admit_peer(
                "workstation",
                &key(3).to_base64(),
                material.leaf,
                Box::new(leaf),
            )
            .await
            .expect_err("a leaf naming another peer must be refused");
        assert!(matches!(refusal, TrustUpdateRefusal::Rejected));
    }

    /// `heliosd peer add` runs in another process and may not write the
    /// registry — the daemon holds it in memory, and a second writer would be
    /// overwritten at the next persist. So the console queues, and the daemon
    /// records: this is that hand-off, end to end.
    #[tokio::test]
    async fn a_queued_console_admission_becomes_a_generation() {
        use base64::Engine as _;
        let (service, directory) = service(state());
        let registry_path = directory.path().join("certificates.json");
        let peer_key = key(2);
        let material = aether::certificates::test_x509::client_material("workstation");
        let leaf = client_leaf(&peer_key, 500_000);
        let encoder = base64::engine::general_purpose::STANDARD;

        let path = queue_admission(
            &registry_path,
            &QueuedAdmission {
                name: "workstation".into(),
                client_wg_public_key: peer_key.to_base64(),
                tls_certificate: encoder.encode(material.leaf.as_bytes()),
                pq_certificate: encoder.encode(serde_json::to_vec(&leaf).expect("json")),
            },
        )
        .expect("queued");

        let name = service
            .record_queued_admission(&path)
            .await
            .expect("recorded");

        assert_eq!(name, "workstation");
        let registry = service.registry.lock().await;
        assert_eq!(
            registry
                .peer(&peer_key)
                .expect("peer recorded")
                .state
                .active
                .generation,
            1
        );
    }

    /// The block a profile carries is exactly what the registry holds, and it
    /// is readable by the consumer that will use it. Eleven values copied by
    /// hand between two shells is eleven places to paste the wrong one, and
    /// the failure surfaces months later at 80 % of a leaf's life.
    #[test]
    fn the_enrolment_block_is_the_registry_and_orion_accepts_it() {
        let state = state();
        let peer = peer();
        let view = enrolment_view(&state, &peer);

        assert_eq!(view.trust_domain_id, state.trust_domain_id.to_hex());
        assert_eq!(view.ca_epoch, state.gateway.ca_epoch);
        assert_eq!(
            view.ca_pq_public_key,
            state.gateway.current_ca_public_key.to_base64()
        );
        assert_eq!(view.ca_tls_epoch, state.client_tls_ca.ca_tls_epoch);
        assert_eq!(view.client_generation, peer.state.active.generation);
        assert_eq!(
            view.astra_service_public_key,
            state.astra.active_astra_service_public_key.to_base64()
        );

        // The consumer is the judge: a block this gateway serves and Orion
        // refuses is a profile that cannot renew, discovered on the client.
        let material: orion_core::TrustMaterial =
            serde_json::from_value(serde_json::to_value(&view).expect("encode"))
                .expect("Orion reads what the gateway serves");
        material
            .validate()
            .expect("Orion accepts what the gateway serves");
    }

    #[test]
    fn a_caller_declaring_exactly_what_the_gateway_serves_is_current() {
        let state = state();
        let peer = peer();
        assert!(caller_is_current(&state, &peer, &request(&state, &peer)).expect("comparison"));
    }

    /// Every counter and every active fingerprint is compared. A gap in this
    /// list answers "you are up to date" to a client that is not, and the
    /// client stops asking — the one refusal with no recovery.
    #[test]
    fn a_caller_behind_on_any_single_value_is_not_current() {
        let state = state();
        let peer = peer();
        let stale = Fingerprint::of(b"an older certificate");

        /// One way of being behind, and the name it is reported under.
        type Mutation = (&'static str, fn(&mut TrustUpdateRequest, Fingerprint));

        let mutations: Vec<Mutation> = vec![
            ("ca_epoch", |request, _| request.ca_epoch -= 1),
            ("ca_tls_epoch", |request, _| request.ca_tls_epoch -= 1),
            ("astra_service_key_epoch", |request, _| {
                request.astra_service_key_epoch -= 1
            }),
            ("issuer_epoch", |request, _| request.issuer_epoch += 1),
            ("active_gateway_identity_epoch", |request, _| {
                request.active_gateway_identity_epoch -= 1
            }),
            ("gateway_decision_epoch", |request, _| {
                request.gateway_decision_epoch -= 1
            }),
            ("client_identity_generation", |request, _| {
                request.client_identity_generation -= 1
            }),
            ("gateway TLS leaf", |request, stale| {
                request.active_gateway_tls_certificate_fingerprint = stale
            }),
            ("gateway PQ leaf", |request, stale| {
                request.active_gateway_certificate_fingerprint = stale
            }),
            ("client TLS leaf", |request, stale| {
                request.active_client_tls_certificate_fingerprint = stale
            }),
            ("client PQ leaf", |request, stale| {
                request.active_client_pq_certificate_fingerprint = stale
            }),
        ];

        for (name, mutate) in mutations {
            let mut behind = request(&state, &peer);
            mutate(&mut behind, stale);
            assert!(
                !caller_is_current(&state, &peer, &behind).expect("comparison"),
                "a caller behind on {name} was reported as up to date"
            );
        }
    }

    /// The delegation counts too: a client that has never seen the installed
    /// issuer cannot verify a leaf renewed under it.
    #[test]
    fn a_caller_that_has_not_seen_the_installed_issuer_is_not_current() {
        let mut state = state();
        let peer = peer();
        let current = request(&state, &peer);

        let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
        state.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: 4,
            authorization: aether::certificates::authority::AstraIssuerAuthorization {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: state.trust_domain_id,
                ca_epoch: 1,
                ca_tls_epoch: 2,
                gateway_wg_public_key: state.gateway.gateway_wg_public_key,
                server_name: state.gateway.server_name.clone(),
                issuer_epoch: 4,
                pq_issuer_public_key: issuer_key,
                tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
                allowed_usage:
                    aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: 1_000_000,
                ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            },
            state: aether::certificates::state::IssuerLifecycle::Active,
        });

        assert!(!caller_is_current(&state, &peer, &current).expect("comparison"));
    }

    /// A queued transaction, at a chosen position, for the count below.
    fn distribution(
        cursor: u16,
        chunk_count: u16,
    ) -> helios_provisioning::certificates::PendingDistribution {
        use aether::certificates::transport::{
            ManifestAuthority, TrustUpdateChunk, TrustUpdateTransactionManifest,
        };

        let manifest = TrustUpdateTransactionManifest {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            transaction_id: Id16::new([9; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: key(9),
            client_wg_public_key: key(2),
            base_state_fingerprint: Fingerprint::of(b"base state"),
            created_at: 0,
            expires_at: 1_000,
            minimum_activation_at: 1_000,
            chunk_count,
            objects: Vec::new(),
            manifest_authority_kind: ManifestAuthority::AstraServiceKey,
            manifest_authority_epoch: 1,
            signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        };
        let manifest_fingerprint = manifest.fingerprint();
        helios_provisioning::certificates::PendingDistribution {
            manifest,
            chunks: (0..chunk_count)
                .map(|index| TrustUpdateChunk {
                    manifest_fingerprint,
                    chunk_index: index,
                    chunk_count,
                    first_object_index: index,
                    objects: Vec::new(),
                })
                .collect(),
            cursor,
            last_request_id: None,
        }
    }

    /// The gateway asks the authority when its queue holds nothing, and queues
    /// what comes back. This is the whole of the 503 fix on this side.
    /// The private link carries the recovery of §7.5 and nothing else.
    ///
    /// The refusal happens before the registry is even locked, and that is the
    /// point: an ordinary renewal is committed by its client, inside its
    /// tunnel, where the source address proves the peer. A veth that also
    /// accepted one would be a second path to the same write, reachable by a
    /// party that is not the client.
    #[tokio::test]
    async fn an_ordinary_renewal_is_never_committed_on_the_private_link() {
        use aether::certificates::authority::RotationReason;
        use aether::certificates::client::IssuerKind;
        use helios_api::internal::AstraChannelHandler;

        let mut state = state();
        state.peers.insert(key(2).to_base64(), peer());
        let (service, _directory) = service(state);

        let mut relayed = relayed_commit();
        relayed.authorization.issuer_kind = IssuerKind::Astra;
        assert!(
            service.commit_recovery(Box::new(relayed)).await.is_err(),
            "a delegated staging is not a recovery, whatever its reason says"
        );

        let mut relayed = relayed_commit();
        relayed.authorization.reason = RotationReason::Scheduled;
        assert!(
            service.commit_recovery(Box::new(relayed)).await.is_err(),
            "CA-PQ signing an ordinary renewal is still an ordinary renewal"
        );
    }

    /// A recovery whose authorization is not the one that opened the pending
    /// stage is refused: the relay may carry a decision, never describe one.
    #[tokio::test]
    async fn a_recovery_commit_must_name_the_staging_the_registry_recorded() {
        use helios_api::internal::AstraChannelHandler;

        let mut state = state();
        state.peers.insert(key(2).to_base64(), peer());
        let (service, _directory) = service(state);
        // `peer()` holds no pending stage at all, so there is nothing this
        // authorization could be the one that opened.
        assert!(service
            .commit_recovery(Box::new(relayed_commit()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_empty_queue_makes_the_gateway_ask_the_authority() {
        let mut state = state();
        state.peers.insert(key(2).to_base64(), peer());
        let (service, _directory) = service(state);
        let prepared = distribution(0, 1);
        let service = service.with_authority(Arc::new(StubAuthority {
            prepared: helios_api::internal::PreparedTrustUpdate {
                transaction: Some(helios_api::internal::PreparedTrustUpdateTransaction {
                    manifest: prepared.manifest.clone(),
                    chunks: prepared.chunks.clone(),
                }),
            },
        }));

        let request = authenticated_request(&key(2));
        service
            .prepare_from_authority(&key(2), &request, 0)
            .await
            .expect("preparation");

        let mut registry = service.registry.lock().await;
        let served = registry
            .take_distribution_chunk(
                &key(2),
                &Id16::new([4; 16]).expect("request id"),
                &Fingerprint::of(b"base state"),
                0,
            )
            .expect("readable")
            .expect("the prepared transaction is queued");
        assert_eq!(served.0.fingerprint(), prepared.manifest.fingerprint());
    }

    /// A gateway with no authority behaves exactly as before: it asks nobody
    /// and queues nothing. A domain without Astra is a supported shape.
    #[tokio::test]
    async fn a_gateway_without_an_authority_asks_no_one() {
        let mut state = state();
        state.peers.insert(key(2).to_base64(), peer());
        let (service, _directory) = service(state);

        let request = authenticated_request(&key(2));
        service
            .prepare_from_authority(&key(2), &request, 0)
            .await
            .expect("no authority is not a failure");

        let mut registry = service.registry.lock().await;
        assert!(registry
            .take_distribution_chunk(
                &key(2),
                &Id16::new([4; 16]).expect("request id"),
                &Fingerprint::of(b"base state"),
                0,
            )
            .expect("readable")
            .is_none());
    }

    /// The console draws the same rungs the protocol decides on.
    ///
    /// A screen with its own arithmetic is a screen that eventually says
    /// *valide* about a leaf the planner has already scheduled a renewal for —
    /// and the operator believes the screen.
    #[test]
    fn the_domain_view_places_a_leaf_on_the_protocol_ladder() {
        use aether::certificates::window::ValidityPhase;

        let mut state = state();
        state.peers.insert(key(2).to_base64(), peer());

        // The fixture generation runs from 0 to 1 000 000, so the thresholds
        // of spec §4.3 fall on round numbers.
        let phase_at = |now: u64| domain_view(&state, now).peers[0].phase;
        assert_eq!(phase_at(0), ValidityPhase::Valid);
        assert_eq!(phase_at(799_999), ValidityPhase::Valid);
        assert_eq!(phase_at(800_000), ValidityPhase::RenewalDue);
        assert_eq!(phase_at(900_000), ValidityPhase::Warning);
        assert_eq!(phase_at(950_000), ValidityPhase::Critical);
        assert_eq!(phase_at(1_000_000), ValidityPhase::Expired);
    }

    /// The count is what is **left**, not what was queued.
    ///
    /// A peer that has collected two of three fragments is still behind, and a
    /// console showing the total would report the same number before and after
    /// every poll — the one figure that says whether anything is moving.
    #[test]
    fn the_domain_view_counts_the_fragments_a_peer_has_not_collected() {
        let pending_after = |cursor: u16| {
            let mut state = state();
            let mut queued = peer();
            queued.distribution = Some(distribution(cursor, 3));
            state.peers.insert(key(2).to_base64(), queued);
            domain_view(&state, 0).peers[0].distribution_chunks_pending
        };

        assert_eq!(pending_after(1), 2);
        assert_eq!(pending_after(3), 0);
    }

    /// The operator read carries no certificate body, and no key.
    ///
    /// It is served on the admin surface, so nothing here is secret — but a
    /// view that grew a DER blob or a public key would be a view somebody
    /// later fed to a parser, and the registry's own copies are the ones that
    /// must decide. Fingerprints and dates are what an operator acts on.
    #[test]
    fn the_domain_view_carries_no_certificate_body() {
        let mut state = state();
        let peer = peer();
        let leaf_key = peer.active_pq_certificate.ml_dsa_87_public_key.clone();
        state.peers.insert(key(2).to_base64(), peer);

        let json = serde_json::to_string(&domain_view(&state, 0)).expect("serialise");
        assert!(
            !json.contains(&leaf_key),
            "the peer's public key must not travel"
        );
        assert!(
            !json.contains(&state.gateway.current_ca_public_key.to_base64()),
            "the anchor travels as a fingerprint, not as a key"
        );
        assert!(
            !json.contains(&state.astra.active_astra_service_public_key.to_base64()),
            "the Astra service key travels in the §19 block, not in this one"
        );
        // What it does carry: the values a screen shows.
        assert!(json.contains("gateway.example"));
        assert!(json.contains("\"generation\":4"));
    }

    /// An `active` delegation past its `not_after` signs nothing.
    ///
    /// The lifecycle field alone would let the console call it usable, and an
    /// operator would look everywhere but at the clock when renewals stop.
    #[test]
    fn the_domain_view_reads_the_issuer_clock_and_not_only_its_lifecycle() {
        let mut state = state();
        let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
        state.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: 4,
            authorization: aether::certificates::authority::AstraIssuerAuthorization {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: state.trust_domain_id,
                ca_epoch: 1,
                ca_tls_epoch: 2,
                gateway_wg_public_key: state.gateway.gateway_wg_public_key,
                server_name: state.gateway.server_name.clone(),
                issuer_epoch: 4,
                pq_issuer_public_key: issuer_key,
                tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
                allowed_usage:
                    aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: 1_000,
                ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            },
            state: aether::certificates::state::IssuerLifecycle::Active,
        });

        let inside = domain_view(&state, 999).issuer.expect("issuer");
        assert!(inside.usable);
        let outside = domain_view(&state, 1_000).issuer.expect("issuer");
        assert_eq!(
            outside.lifecycle,
            aether::certificates::state::IssuerLifecycle::Active
        );
        assert!(!outside.usable, "expiry decides, not the lifecycle field");
    }

    /// A leaf signed by a chosen key, for one exact WireGuard identity.
    fn leaf_from(
        issuer_private: &[u8],
        wg_public_key: &WireGuardKey,
        serial: u8,
    ) -> (
        PqCertificate,
        aether::certificates::encoding::MlDsa87PublicKey,
    ) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [serial; 16],
                subject: "workstation".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: wg_public_key.to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: u64::MAX / 2,
                ml_dsa_87_signature: String::new(),
            },
            issuer_private,
        )
        .expect("issue");
        (certificate, subject_public)
    }

    /// The staging check must accept exactly what the negotiation port will.
    ///
    /// An ordinary renewal is issued by the **delegated issuer**, not by the
    /// operator CA the first generation chained to. A gateway offering only
    /// the key on disk refuses to stage the one candidate the whole lifecycle
    /// exists to produce — and it refuses it silently enough that the operator
    /// looks at the authority rather than at the pinning.
    #[test]
    fn a_candidate_signed_by_the_delegated_issuer_is_presentable() {
        use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
        use aether::certificates::client::{ClientCertificateStageAuthorization, IssuerKind};
        use aether::certificates::encoding::MlDsa87Signature;
        use aether::certificates::window::TransitionWindow;

        let material = aether::certificates::test_x509::client_material("workstation");
        let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (candidate, _) = leaf_from(&issuer_private, &key(2), 7);
        // The key the negotiation port reads from disk. Deliberately unrelated
        // to the delegation: that is the whole situation being tested.
        let (_, on_disk_ca) = generate_ml_dsa_87_keypair().expect("keygen");

        let authorization = ClientCertificateStageAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 2,
            issuer_kind: IssuerKind::Astra,
            issuer_epoch: 4,
            issuer_authorization_fingerprint: Fingerprint::of(b"delegation"),
            issuer_authorization: None,
            stage_id: Id16::new([5; 16]).expect("stage"),
            request_fingerprint: Fingerprint::of(b"request"),
            renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
            renewal_approval: None,
            campaign_approval: None,
            gateway_wg_public_key: key(9),
            server_name: "gateway.example".into(),
            client_wg_public_key: key(2),
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            next_tls_ca_certificate_fingerprint: material.authority.fingerprint(),
            next_tls_certificate: material.leaf.clone(),
            next_pq_certificate: candidate,
            issued_at: 1_000,
            stage_expires_at: 50_000,
            window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
            reason: aether::certificates::authority::RotationReason::Scheduled,
            signature: MlDsa87Signature::placeholder(),
        };

        // Without the delegation the gateway knows only the key on disk, and
        // refuses — which is the behaviour that used to be permanent.
        let mut state = state();
        // One authority for both halves: `client_material` mints a fresh CA
        // per call, and a leaf checked against a different one would fail on
        // the TLS half before the PQ half — the half under test — is reached.
        state.client_tls_ca.active_client_tls_ca_certificate = material.authority.clone();
        let refusal =
            assert_candidate_is_presentable(&state, on_disk_ca.as_bytes(), &authorization)
                .expect_err("no issuer offered can verify this leaf");
        assert!(
            refusal.contains("not verifiable by the negotiation port"),
            "{refusal}"
        );

        // Installed, it is accepted — and the negotiation port admits the same
        // set, so what is staged here is what will authenticate later.
        state.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: 4,
            authorization: AstraIssuerAuthorization {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: state.trust_domain_id,
                ca_epoch: 1,
                ca_tls_epoch: 2,
                gateway_wg_public_key: state.gateway.gateway_wg_public_key,
                server_name: state.gateway.server_name.clone(),
                issuer_epoch: 4,
                pq_issuer_public_key: issuer_public,
                tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
                allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: u64::MAX / 2,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            },
            state: aether::certificates::state::IssuerLifecycle::Active,
        });
        assert_candidate_is_presentable(&state, on_disk_ca.as_bytes(), &authorization)
            .expect("the delegated issuer is one the negotiation admits");
    }

    /// The operator CA is the authority a client's **first** leaf is issued
    /// under: only a renewal moves it to the delegated issuer. A trust-update
    /// route that asked the registry alone therefore refused every client that
    /// had never renewed — on a fresh domain, all of them — with a bare `403`
    /// and nothing naming the cause.
    #[test]
    fn the_issuer_set_admits_a_client_that_has_never_renewed() {
        let (_, operator_ca) = generate_ml_dsa_87_keypair().expect("operator CA");
        let state = state();

        let issuers = client_leaf_issuers(&state, &operator_ca, 1_000);

        assert_eq!(
            issuers.first().copied(),
            Some(&operator_ca),
            "the operator CA is asked first, as the negotiation port asks it"
        );
        assert!(
            issuers.contains(&&state.gateway.current_ca_public_key),
            "the anchor stays in the set: a leaf reissued under CA-PQ must keep working"
        );
    }

    /// Asked twice, offered once. The registry may already carry the same key
    /// the gateway holds on disk, and a duplicated issuer would make every
    /// refusal report one more failed attempt than actually happened.
    #[test]
    fn the_issuer_set_does_not_repeat_an_authority_it_already_holds() {
        let state = state();
        let operator_ca = state.gateway.current_ca_public_key.clone();

        let issuers = client_leaf_issuers(&state, &operator_ca, 1_000);

        assert_eq!(
            issuers
                .iter()
                .filter(|issuer| ***issuer == operator_ca)
                .count(),
            1
        );
    }
}
