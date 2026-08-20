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

/// Owner of the registry, and the only writer of its file.
pub struct CertificateService {
    registry: Mutex<CertificateRegistry>,
    signer: Arc<dyn StageReceiptSigner>,
}

impl CertificateService {
    pub fn new(registry: CertificateRegistry, signer: Arc<dyn StageReceiptSigner>) -> Self {
        Self {
            registry: Mutex::new(registry),
            signer,
        }
    }

    /// Loads the registry, or reports that this gateway has no trust domain.
    ///
    /// A missing file is not an empty domain: without `CA-PQ` there is no
    /// anchor to verify anything against, and the routes stay closed rather
    /// than accepting the first object that arrives.
    ///
    /// A gateway that runs no negotiation service has no served leaf to sign
    /// receipts with either, so the lifecycle needs the signer to exist — the
    /// two are not independently deployable.
    pub fn load(path: PathBuf, signer: Arc<dyn StageReceiptSigner>) -> Result<Option<Arc<Self>>> {
        let Some(registry) = CertificateRegistry::load(&path)
            .with_context(|| format!("reading the certificate registry {}", path.display()))?
        else {
            return Ok(None);
        };
        Ok(Some(Arc::new(Self::new(registry, signer))))
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

    /// Drops expired candidates and promotes due generations.
    ///
    /// Run on the same lock as everything else, so a purge never races the
    /// commit it competes with.
    pub async fn maintain(&self, now_unix: u64) -> Result<(), RegistryError> {
        let mut registry = self.registry.lock().await;
        let purged = registry.purge_expired(now_unix)?;
        for peer in &purged {
            tracing::info!(peer = %peer, "staged certificate purged: its lease ran out");
        }
        let promoted = registry.promote_due(now_unix)?;
        for peer in &promoted {
            tracing::info!(peer = %peer, "certificate generation promoted at the end of its overlap");
        }
        Ok(())
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
        assert_candidate_is_presentable(registry.state(), &authorization).map_err(|reason| {
            tracing::error!(
                peer = %caller,
                %reason,
                "staging from Astra refused: this gateway could not authenticate the candidate \
                 leaves once they became active, and staging them would lock the client out at \
                 the end of the overlap"
            );
            TrustUpdateRefusal::Rejected
        })?;
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

        if revocation.scope != RevocationScope::Client {
            tracing::warn!(
                identity = %revocation.identity_key,
                "revocation refused: only a client scope is applied on the private channel; a \
                 gateway identity is withdrawn by the §6 transition, which this build does not \
                 implement"
            );
            return Err(TrustUpdateRefusal::Rejected);
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
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
        })
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
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_service_public_key: state.astra.active_astra_service_public_key.to_base64(),
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
/// # Limite connue — the two anchors are not the same one yet
///
/// The negotiation port authenticates a client under exactly one client TLS CA
/// and one client PQ CA, both read from `/var/lib/helios` at start-up. A
/// renewed leaf, however, is issued by Astra's delegated issuer: its TLS half
/// chains to the intermediate the delegation names, and its PQ half is signed
/// by the issuer's ML-DSA-87 key. Both are legitimate — every lifecycle object
/// says so — and neither is something this gateway's negotiation currently
/// verifies against.
///
/// Closing that is the next lot, and it is two things: the negotiation reading
/// the certificate registry (`acceptable_pq_fingerprints`, `resolve_pair` and
/// the delegated issuer's public key) instead of the frozen pins of
/// `network.toml`, and the client TLS anchor of the domain becoming the one
/// the authority actually issues under. Until both land, this check is what
/// keeps an installed delegation from producing a certificate nobody can use.
fn assert_candidate_is_presentable(
    state: &helios_provisioning::certificates::RegistryState,
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

    // The PQ half: the negotiation verifies a client leaf under one key, read
    // from disk. A candidate signed by anything else authenticates nowhere.
    let client_pq_ca = std::fs::read(crate::key_negotiation::CLIENT_PQ_CA_PATH)
        .map_err(|error| format!("the client PQ CA is unreadable: {error}"))?;
    authorization
        .next_pq_certificate
        .verify(
            &client_pq_ca,
            aether::key_negotiation::PqCertificateRole::Client,
            None,
            &authorization.client_wg_public_key.to_base64(),
            now_unix(),
        )
        .map_err(|error| {
            format!("the candidate PQ leaf is not verifiable by the negotiation port: {error}")
        })?;
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

        // Both authorities that may have issued the caller's leaf: the anchor,
        // and the delegated issuer an ordinary renewal chains to.
        let mut issuers = vec![&state.gateway.current_ca_public_key];
        if let Some(next) = &state.gateway.next_ca_public_key {
            issuers.push(next);
        }
        if let Some(issuer) = &state.issuer {
            issuers.push(&issuer.authorization.pq_issuer_public_key);
        }

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
            .take_distribution_chunk(&caller, &request_id, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust distribution unreadable");
                classify(error)
            })?;
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
                // Behind, and the authority has left nothing here. Saying so
                // beats claiming the client is up to date: an empty update is
                // the one answer a client does not recover from, because it
                // stops asking.
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    "trust update: the caller is behind and the authority has queued nothing \
                     for it"
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
            CertificateService::new(registry, Arc::new(RefusingSigner)),
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
}
