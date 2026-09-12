//! Gateway-side certificate registry: staging, receipt, commit, purge.
//!
//! This is the gateway half of spec §7. `network.toml` keeps admission — who
//! is allowed in and at which VIP — and this registry keeps the *generations*
//! of the identities those peers present. The two are deliberately separate
//! files: `network.toml` is hot-reloaded and operator-editable, while a
//! certificate generation is a counter that must never move because someone
//! edited a file by hand.
//!
//! # The ordering that makes the protocol safe
//!
//! [`CertificateRegistry::stage`] persists the candidate and `fsync`s **before**
//! producing the receipt the authority needs. That order is the whole point:
//! Astra will not release a grant without the receipt, so no client identity
//! is ever issued before the gateway has admitted it. Reversing the two would
//! reintroduce the failure the receipt exists to prevent — a leaf that exists
//! in the world and nowhere in the gateway's admission.
//!
//! # One serializer, three writers
//!
//! Staging, commit, purge and revocation all mutate the same slot. They take
//! `&mut self`, so the caller's lock is the serializer, and the clock is read
//! **once** per operation and passed in. A commit that arrives at the lease
//! deadline therefore loses the race against the purge deterministically,
//! instead of depending on which task read the clock first.
//!
//! # Written first, adopted second
//!
//! Every mutation is computed on a **copy** of the state, written to disk, and
//! only then swapped in. Mutating memory and saving afterwards leaves the two
//! disagreeing whenever the write fails: the in-memory registry would report a
//! commit as already present — and answer the retry with success — while the
//! disk still holds the candidate as pending. A restart would then undo a
//! commit the client was told had landed, and the client has no way to ask
//! again: from its side the transaction is closed.
//!
//! # Limite connue
//!
//! The registry stores the PQ leaf of each generation but not the TLS one: the
//! mTLS chain is validated by the TLS layer of `heliosd`, which holds the two
//! client CA anchors. What lives here is the binding — which TLS fingerprint
//! belongs to which generation — so a connection recognised under one
//! generation cannot present the PQ certificate of the other.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aether::certificates::{
    approval::{AstraCredentialBinding, AstraIssuancePolicy},
    authority::{CaTransition, ClientTlsCaTransition, RotationReason},
    client::{
        ClientCertificateGeneration, ClientCertificateRotationGrant,
        ClientCertificateStageAuthorization, ClientCertificateStageCommit,
        GatewayCertificateStageReceipt, IssuerKind,
    },
    encoding::{
        DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId,
        WireGuardKey,
    },
    gateway::{GatewayIdentityTransition, GatewayTransitionAbort},
    state::{
        AstraIssuerState, AstraProfile, ClientCertificateState, ClientTlsCaState,
        GatewayCertificateState, GatewayServiceRollback, InstallOutcome, PendingStageState,
        RevocationTombstone, RevokedFamily, TrustLedger,
    },
    status::CertificateServiceRollbackAuthorization,
    transport::{TrustUpdateChunk, TrustUpdateTransactionManifest},
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::PqCertificate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default location of the registry, beside `network.toml`.
const CERTIFICATE_REGISTRY_PATH: &str = "/var/lib/helios/certificates.json";

/// Refusal of a registry operation.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("certificate object refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("no admitted peer holds this WireGuard identity")]
    UnknownPeer,
    #[error("the authenticated caller is not the peer this object names")]
    PeerMismatch,
    #[error(
        "fingerprint already bound to peer « {0} »: a certificate identifies exactly one peer"
    )]
    FingerprintTaken(String),
    #[error("certificate registry input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate registry is unreadable: {0}")]
    Corrupt(String),
    #[error(
        "a certificate registry already exists at {0}: bootstrapping over it would give this \
         gateway a second history for the same domain — fresh epochs at 1 against clients that \
         already hold higher ones, and every one of them refused"
    )]
    AlreadyBootstrapped(PathBuf),
    #[error("legacy client CA-TLS bootstrap repair refused: {0}")]
    LegacyClientTlsCaRepair(&'static str),
    #[error(
        "delegation at issuer epoch {offered} does not advance past the installed epoch \
         {installed}: a spent epoch carrying different bytes is a substitution"
    )]
    IssuerEpochNotAdvancing { installed: u64, offered: u64 },
}

/// Result of checking the narrowly-scoped historical CA-TLS bootstrap bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapRepairOutcome {
    /// The legacy operator CA was replaced by the domain CA-TLS.
    Repaired,
    /// The registry already holds the supplied domain CA-TLS at epoch 1.
    AlreadyCorrect,
    /// A signed rotation has already advanced the registry past bootstrap.
    LaterEpoch,
}

/// One peer's certificate generations, with the PQ leaves they resolve to.
///
/// The leaves are kept because Helios has to *verify* signatures made by them:
/// a commit is signed by the active and the candidate key, and neither travels
/// with the commit. A registry holding only fingerprints could compare, but
/// never verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificates {
    /// Friendly name, mirrored from admission for logs and interfaces.
    pub name: String,
    pub state: ClientCertificateState,
    pub active_pq_certificate: PqCertificate,
    /// The candidate's leaf, while a stage or a committed `next` exists. The
    /// state machine guarantees `pending` and `next` are never both set, so a
    /// single slot covers both.
    pub staged_pq_certificate: Option<PqCertificate>,
    /// Pre-signed transaction waiting to be handed to this peer (spec §8.1.1).
    ///
    /// Absent for the whole life of a domain where nothing rotates, which is
    /// the ordinary case: `trust-update` then answers "you are current" and
    /// costs a comparison.
    #[serde(default)]
    pub distribution: Option<PendingDistribution>,
}

/// A signed transaction the authority left here for one peer.
///
/// # Why the gateway stores rather than builds
///
/// The manifest is signed by `CA-PQ` or by Astra's service key, and `heliosd`
/// holds neither — deliberately, and §8.1.1 says so: «la gateway n'appelle
/// jamais une clé CA et ne réalise aucune signature de CA à la demande». What
/// arrives over the veth is already signed for exactly this peer, against the
/// state snapshot that peer declared. The gateway is a queue, not an author.
///
/// # Why the cursor is here and not in the request
///
/// [`aether::certificates::transport::TrustUpdateRequest`] carries no chunk
/// index, by design: adding one would let a peer choose which fragment it is
/// served, and a peer that only ever asked for chunk 0 would sit forever on an
/// incomplete transaction while believing it was progressing. So the gateway
/// walks the fragments itself, one per fresh request. A repeated `request_id`
/// is served the **same** fragment — §8.1.1 allows an idempotent replay, and
/// advancing on a retransmission would skip a chunk over a lossy link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDistribution {
    pub manifest: TrustUpdateTransactionManifest,
    /// Every fragment, in index order. Held whole: a transaction is atomic for
    /// the receiver, and a queue that could lose one fragment would leave a
    /// client polling for something that will never arrive.
    pub chunks: Vec<TrustUpdateChunk>,
    /// Index of the fragment the next fresh request receives.
    pub cursor: u16,
    /// Request the current cursor position was already served to.
    pub last_request_id: Option<Id16>,
}

impl PendingDistribution {
    /// The fragment this request gets, and whether the cursor moved.
    ///
    /// Returns `None` once every fragment has been handed over: the peer has
    /// the whole transaction and either applied it or refused it, and neither
    /// outcome is the gateway's to retry.
    fn serve(&mut self, request_id: &Id16) -> Option<&TrustUpdateChunk> {
        if self.last_request_id.as_ref() == Some(request_id) {
            // A replay: the same fragment, at the position it was served from.
            let index = usize::from(self.cursor).checked_sub(1)?;
            return self.chunks.get(index);
        }
        let index = usize::from(self.cursor);
        let chunk = self.chunks.get(index)?;
        self.cursor = self.cursor.saturating_add(1);
        self.last_request_id = Some(*request_id);
        Some(chunk)
    }

    /// Whether the peer has been handed everything.
    fn drained(&self) -> bool {
        usize::from(self.cursor) >= self.chunks.len()
    }
}

impl PeerCertificates {
    fn active_public_key(&self) -> Result<MlDsa87PublicKey, CertificateError> {
        MlDsa87PublicKey::parse(&self.active_pq_certificate.ml_dsa_87_public_key)
    }

    fn staged_public_key(&self) -> Result<MlDsa87PublicKey, CertificateError> {
        let certificate = self
            .staged_pq_certificate
            .as_ref()
            .ok_or(CertificateError::UnknownStage)?;
        MlDsa87PublicKey::parse(&certificate.ml_dsa_87_public_key)
    }
}

/// Everything the gateway persists about the trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryState {
    pub trust_domain_id: TrustDomainId,
    pub gateway: GatewayCertificateState,
    pub client_tls_ca: ClientTlsCaState,
    pub astra: AstraProfile,
    pub issuer: Option<AstraIssuerState>,
    /// Keyed by the peer's WireGuard public key in base64 — its identity, and
    /// the only value the gateway ever resolves a caller to.
    pub peers: BTreeMap<String, PeerCertificates>,
    /// Fingerprints already withdrawn, and the counters that withdrew them.
    ///
    /// The gateway keeps them for the same reason Orion does: `revoked` on a
    /// peer only covers a peer that is still in the registry, and it says
    /// nothing about a fingerprint arriving later inside a staging
    /// authorization. A readmission under a fresh identity is legitimate; the
    /// **same** leaf coming back is what §10.2 forbids.
    pub ledger: TrustLedger,
}

/// One admitted identity, as the key negotiation needs to see it.
///
/// Deliberately a value and not a borrow: the negotiation reads this under the
/// registry lock and then does ML-DSA work with it, and holding the lock
/// across that would serialise every concurrent handshake behind one
/// signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationIdentity {
    /// Base64 WireGuard public key — the peer's identity, and the only value
    /// the gateway ever resolves a caller to.
    pub wg_public_key: String,
    pub name: String,
    /// The PQ leaf this exact caller may present, and no other.
    pub pq_certificate_fingerprint: Fingerprint,
}

impl RegistryState {
    /// Resolves the fingerprint mTLS proved to the identity that owns it.
    ///
    /// This is what lets a renewed client keep negotiating. The pins in
    /// `network.toml` are written once, at admission, and nothing updates them
    /// afterwards: a peer whose leaf has rotated presents a fingerprint that
    /// file has never heard of, and the gateway refuses it at the end of the
    /// overlap — locking the machine out of the only channel it had to ask for
    /// help. The registry, by contrast, is the thing that recorded the
    /// rotation.
    ///
    /// The PQ half returned is the **partner** of the TLS half, never the
    /// union of what the peer may hold: see
    /// [`ClientCertificateState::pq_paired_with_tls`].
    pub fn resolve_negotiation_identity(
        &self,
        tls: &Fingerprint,
        now_unix: u64,
    ) -> Option<NegotiationIdentity> {
        self.peers.iter().find_map(|(wg_public_key, peer)| {
            peer.state
                .pq_paired_with_tls(tls, now_unix)
                .map(|pq_certificate_fingerprint| NegotiationIdentity {
                    wg_public_key: wg_public_key.clone(),
                    name: peer.name.clone(),
                    pq_certificate_fingerprint,
                })
        })
    }

    /// Every ML-DSA-87 key that may have signed an admitted client's leaf.
    ///
    /// The domain anchor, its successor during a CA overlap, and the delegated
    /// issuer — which is what an *ordinary renewal* is issued under, and
    /// therefore the one a gateway pinning only the anchor would reject.
    ///
    /// A set, not a choice: which of them signed a given leaf is not knowable
    /// before the signature is checked, and asking the leaf would be asking
    /// the message to name its own authority.
    pub fn client_leaf_issuers(&self, now_unix: u64) -> Vec<&MlDsa87PublicKey> {
        let mut issuers = self.gateway.acceptable_anchors(now_unix);
        if let Some(issuer) = &self.issuer {
            if issuer.is_usable(now_unix) {
                issuers.push(&issuer.authorization.pq_issuer_public_key);
            }
        }
        issuers
    }

    /// The client TLS anchors this domain issues under, active first.
    pub fn client_tls_anchors(&self, now_unix: u64) -> Vec<&DerCertificate> {
        self.client_tls_ca.acceptable_anchors(now_unix)
    }
}

/// The registry, with its file.
#[derive(Debug)]
pub struct CertificateRegistry {
    path: PathBuf,
    state: RegistryState,
}

impl CertificateRegistry {
    /// Path of the registry. `HELIOS_CERTIFICATE_REGISTRY` isolates a test run
    /// exactly as `HELIOS_NETWORK_CONFIG` does for the network configuration.
    pub fn path() -> PathBuf {
        std::env::var_os("HELIOS_CERTIFICATE_REGISTRY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(CERTIFICATE_REGISTRY_PATH))
    }

    pub fn new(path: PathBuf, state: RegistryState) -> Self {
        Self { path, state }
    }

    /// Creates the registry of a trust domain, once and only once.
    ///
    /// The counterpart of `astra bootstrap` on this side of the wire, and it
    /// refuses an existing file for the same reason: a domain has one history,
    /// and a second one starting at epoch 1 would be refused by every client
    /// already holding a higher one — while looking, locally, like a clean
    /// install.
    ///
    /// Nothing here is secret. Every value is either public by construction
    /// (the leaves this gateway already serves, the anchors it is told to
    /// trust) or an identifier. The command that calls this therefore needs
    /// no TPM: it opens no vault and unseals nothing.
    pub fn bootstrap(path: PathBuf, state: RegistryState) -> Result<Self, RegistryError> {
        if path.exists() {
            return Err(RegistryError::AlreadyBootstrapped(path));
        }
        if let Some(parent) = path.parent() {
            aether::private_file::create_private_dir(parent)?;
        }
        let mut registry = Self::new(path, state.clone());
        registry.persist(state)?;
        Ok(registry)
    }

    /// Loads the registry, or reports that the domain is not bootstrapped.
    ///
    /// A missing file is **not** an empty registry: a gateway with no trust
    /// domain has no `CA-PQ` to verify anything against, and inventing an
    /// empty one would silently accept the first object that arrived.
    pub fn load(path: &Path) -> Result<Option<Self>, RegistryError> {
        match std::fs::read(path) {
            Ok(raw) => {
                let mut document: Value = serde_json::from_slice(&raw)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                let migrated = migrate_legacy_registry(&mut document)?;
                let state: RegistryState = serde_json::from_value(document)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                let mut registry = Self {
                    path: path.to_path_buf(),
                    state,
                };
                if migrated {
                    // The migration is part of loading, but it still follows
                    // the registry's normal written-first rule. A daemon
                    // restart therefore cannot leave a legacy document on
                    // disk after it has served the current state in memory.
                    let state = registry.state.clone();
                    registry.persist(state)?;
                    tracing::info!(
                        path = %path.display(),
                        "migrated the certificate registry to the current Astra trust schema"
                    );
                }
                Ok(Some(registry))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(RegistryError::Io(error)),
        }
    }

    pub fn state(&self) -> &RegistryState {
        &self.state
    }

    /// Writes a candidate state atomically, `fsync`s, then adopts it.
    ///
    /// The order is the invariant: on a failed write the live state is the one
    /// that is still on disk, so a retry sees exactly what a restart would.
    /// Adopting first and reporting the error afterwards would leave the
    /// running registry describing a transaction the disk never received.
    fn persist(&mut self, candidate: RegistryState) -> Result<(), RegistryError> {
        let encoded = serde_json::to_vec_pretty(&candidate)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
        self.state = candidate;
        Ok(())
    }

    pub fn peer(&self, wg_public_key: &WireGuardKey) -> Option<&PeerCertificates> {
        self.state.peers.get(&wg_public_key.to_base64())
    }

    /// PQ fingerprints this peer may present at `now_unix`.
    pub fn acceptable_pq_fingerprints(
        &self,
        wg_public_key: &WireGuardKey,
        now_unix: u64,
    ) -> Vec<Fingerprint> {
        self.peer(wg_public_key)
            .map(|peer| peer.state.acceptable_pq_fingerprints(now_unix))
            .unwrap_or_default()
    }

    /// Resolves a presented TLS/PQ pair to the peer that owns **both**.
    ///
    /// The two fingerprints are never looked up separately: that is the mixed
    /// pair of spec §3.3, where each half is valid under a different
    /// generation and the assembled identity was never issued.
    pub fn resolve_pair(
        &self,
        tls: &Fingerprint,
        pq: &Fingerprint,
        now_unix: u64,
    ) -> Option<&PeerCertificates> {
        self.state
            .peers
            .values()
            .find(|peer| peer.state.accepts_pair(tls, pq, now_unix))
    }

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

    /// Accepts a pre-signed transaction the authority left for one peer.
    ///
    /// # What is checked here, and what deliberately is not
    ///
    /// The gateway verifies that the transaction **addresses this domain and
    /// this peer**, that its fragments are the ones the manifest names, and
    /// that it has not already expired. It does **not** verify the manifest's
    /// signature or the objects inside it — it holds neither `CA-PQ` nor the
    /// service key, and a verification it cannot complete is worse than none:
    /// it would have to be written against whichever authority happened to be
    /// available, and that is exactly the check an attacker chooses.
    ///
    /// The receiver verifies, under anchors it already trusts. That is the
    /// whole shape of §8.1: an object is authorized by what the receiver holds,
    /// never by the envelope that delivered it — and here the gateway *is* the
    /// envelope.
    ///
    /// Replacing an undrained transaction is allowed and is the point: a newer
    /// decision supersedes an older one, and a client that never came back for
    /// its fragments must not pin the queue.
    pub fn stage_distribution(
        &mut self,
        wg_public_key: &WireGuardKey,
        manifest: TrustUpdateTransactionManifest,
        chunks: Vec<TrustUpdateChunk>,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.clone();
        if manifest.trust_domain_id != state.trust_domain_id {
            return Err(RegistryError::Certificate(
                CertificateError::TrustDomainMismatch,
            ));
        }
        if manifest.gateway_wg_public_key != state.gateway.gateway_wg_public_key {
            return Err(RegistryError::Certificate(
                CertificateError::GatewayIdentityMismatch,
            ));
        }
        if manifest.client_wg_public_key != *wg_public_key {
            return Err(RegistryError::Certificate(
                CertificateError::ClientIdentityMismatch,
            ));
        }
        if now_unix >= manifest.expires_at {
            return Err(RegistryError::Certificate(CertificateError::StageExpired));
        }
        if chunks.len() != usize::from(manifest.chunk_count) || chunks.is_empty() {
            return Err(RegistryError::Certificate(CertificateError::MissingProof(
                "transaction fragments",
            )));
        }
        // Each fragment must be the one the manifest expects at that index.
        // Serving a fragment the manifest does not cover would have the client
        // refuse the whole transaction after collecting all of it — a failure
        // that costs a full poll cycle to discover.
        let manifest_fingerprint = manifest.fingerprint();
        for (index, chunk) in chunks.iter().enumerate() {
            if usize::from(chunk.chunk_index) != index
                || chunk.chunk_count != manifest.chunk_count
                || !chunk.manifest_fingerprint.matches(&manifest_fingerprint)
            {
                return Err(RegistryError::Certificate(CertificateError::MissingProof(
                    "transaction fragment",
                )));
            }
        }

        let peer = state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.distribution = Some(PendingDistribution {
            manifest,
            chunks,
            cursor: 0,
            last_request_id: None,
        });
        self.persist(state)
    }

    /// The fragment this request is owed, if any.
    ///
    /// Returns the manifest alongside the fragment on **every** call and not
    /// only the first: a client that lost its copy between two polls would
    /// otherwise hold fragments it cannot attribute, and §8.1.1 has it refuse
    /// exactly that. Sending it again costs one signed object on a route that
    /// is already carrying the fragment.
    pub fn take_distribution_chunk(
        &mut self,
        wg_public_key: &WireGuardKey,
        request_id: &Id16,
        base_state_fingerprint: &Fingerprint,
        now_unix: u64,
    ) -> Result<Option<(TrustUpdateTransactionManifest, TrustUpdateChunk)>, RegistryError> {
        let mut state = self.state.clone();
        let peer = state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let Some(distribution) = peer.distribution.as_mut() else {
            return Ok(None);
        };
        // An expired transaction is dropped rather than served: past
        // `expires_at` the receiver refuses it, and handing it over would burn
        // a poll cycle to reach that refusal.
        if now_unix >= distribution.manifest.expires_at {
            peer.distribution = None;
            self.persist(state)?;
            return Ok(None);
        }
        // A transaction is a compare-and-swap decision for the exact local
        // state the client signed. Serving one built for an older snapshot
        // would spend a complete chunk cycle only to be refused at commit.
        // Drop it so the preparation relay can replace it from this request.
        if !distribution
            .manifest
            .base_state_fingerprint
            .matches(base_state_fingerprint)
        {
            peer.distribution = None;
            self.persist(state)?;
            return Ok(None);
        }
        let manifest = distribution.manifest.clone();
        let served = distribution
            .serve(request_id)
            .map(|chunk| (manifest, chunk.clone()));
        // Kept until it is drained **and** re-asked for: dropping it on the
        // last fragment would leave a client whose final poll was lost with no
        // way to ask again.
        let drained = distribution.drained();
        if served.is_none() && drained {
            peer.distribution = None;
        }
        self.persist(state)?;
        Ok(served)
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

    /// Stages a rotation of the domain anchor `CA-PQ` (spec §9.1).
    ///
    /// The state machine verifies it against the anchor this registry already
    /// pins — the outgoing `CA-PQ` authorises its successor, and the successor
    /// proves its own key — and refuses a second rotation while one is in
    /// flight, or one whose activation is already in the past.
    ///
    /// The anchor does **not** move here. Both are acceptable from
    /// `activation_at`, which is what [`TrustState::client_leaf_issuers`]
    /// already reads, and `promote_due` retires the outgoing one at
    /// `not_after`. Persisted only when the state moved.
    pub fn install_ca_transition(
        &mut self,
        transition: &CaTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let ledger = state.ledger.clone();
        let outcome = state
            .gateway
            .apply_ca_transition(transition, &ledger, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Stages a signed transition of the gateway's own identity (spec §6.3).
    ///
    /// The verification belongs to the state machine, against the anchors
    /// this registry already pins: `CA-PQ` and its epoch, the stable WireGuard
    /// identity, the server name and the two leaves in service. Nothing is
    /// re-derived here, and a transition a caller verified somewhere else is
    /// not accepted on that caller's word — the same rule the client side
    /// follows for the objects it receives.
    ///
    /// Persisted only when the state actually moved. Carrying the same signed
    /// document in twice is `AlreadyPresent` and writes nothing: an epoch is
    /// consumed by a decision, never by a repeated delivery of one.
    pub fn install_gateway_transition(
        &mut self,
        transition: &GatewayIdentityTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        // The ledger is read while the gateway slot is written, and both live
        // in this one value. One copy on a ceremony that happens once per
        // identity buys the revocation check the ledger this registry holds,
        // rather than one the caller passed in.
        let ledger = state.ledger.clone();
        let outcome = state
            .gateway
            .install_transition(transition, &ledger, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Selects the outgoing gateway leaf for the rest of the overlap (§4.4).
    ///
    /// The state machine verifies the authorization against the anchor, the
    /// staged transition and the leaf this registry holds, and refuses it
    /// outside an overlap. Persisted only when the state moved: an operator
    /// carrying the same document twice must not rewrite the registry.
    ///
    /// It moves no counter and removes no slot — `promote_gateway_if_due`
    /// still fires at `not_after`, and the selection dies with the overlap it
    /// lives in.
    pub fn install_gateway_rollback(
        &mut self,
        authorization: &CertificateServiceRollbackAuthorization,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let outcome = state
            .gateway
            .apply_service_rollback(authorization, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// The gateway selection in force at `now_unix`, if any.
    pub fn active_gateway_rollback(&self, now_unix: u64) -> Option<&GatewayServiceRollback> {
        self.state.gateway.active_service_rollback(now_unix)
    }

    /// Promotes the gateway identity once its published overlap has ended.
    ///
    /// The registry is persisted before this method reports success. The
    /// caller may therefore replace the sealed active slot only after `true`:
    /// a crash can leave the old key beside a registry that already names the
    /// new generation, but can never destroy the old key ahead of that durable
    /// decision. Retrying the private-slot synchronization then completes the
    /// operation without moving the epoch a second time.
    pub fn promote_gateway_if_due(&mut self, now_unix: u64) -> Result<bool, RegistryError> {
        let gateway = &self.state.gateway;
        let due = gateway
            .retire_active_at
            .is_some_and(|retire_at| now_unix >= retire_at)
            && gateway.next_gateway_identity_epoch.is_some();
        if !due {
            return Ok(false);
        }
        if !gateway.published {
            return Err(RegistryError::Certificate(
                CertificateError::IllegalStateTransition(
                    "an unpublished gateway transition cannot be promoted",
                ),
            ));
        }

        let mut state = self.state.clone();
        let promoted = state.gateway.promote_if_due(now_unix)?;
        if promoted {
            self.persist(state)?;
        }
        Ok(promoted)
    }

    /// Installs a rotation of the client `CA-TLS` (spec §9.4).
    ///
    /// Verified by the state machine against the anchor this registry already
    /// serves. Persisted only when the state moved: an operator carrying the
    /// same document twice must not consume a second epoch.
    pub fn install_client_tls_ca_transition(
        &mut self,
        transition: &ClientTlsCaTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let ledger = state.ledger.clone();
        let ca_pq = state.gateway.current_ca_public_key.clone();
        let trust_domain_id = state.trust_domain_id;
        let ca_epoch = state.gateway.ca_epoch;
        let outcome = state.client_tls_ca.apply_transition(
            transition,
            &ca_pq,
            &trust_domain_id,
            ca_epoch,
            &ledger,
            now_unix,
        )?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Records Astra's delegated issuer, and the policy that delegation names.
    ///
    /// The gateway has to hold the delegation itself, not merely see one
    /// inside an approval: [`RegistryState::client_leaf_issuers`] is what both
    /// the staging check and the negotiation port build their issuer set from,
    /// and the two must not drift — a staging check that trusted a delegation
    /// the port does not hold would stage a leaf that locks its owner out at
    /// the end of the overlap. So the delegation is durable state here, as it
    /// is on the authority side.
    ///
    /// It is verified under the `CA-PQ` this registry already holds before its
    /// policy is read, and its epoch must advance — a spent epoch carrying
    /// different bytes is a substitution, not a replay.
    ///
    /// The pinned policy is decided in the same call and written in the same
    /// atomic persist: a delegation recorded without the policy it names would
    /// be refused on the next read, and a policy adopted without its
    /// delegation would widen what may be issued before anything authorized
    /// it. See
    /// [`AstraPolicyPin::adopt_automatic_renewal_policy`](aether::certificates::approval::AstraPolicyPin::adopt_automatic_renewal_policy).
    /// Records the domain's operator credentials, from the `CA-PQ`-signed
    /// document the companion emits.
    ///
    /// # Why the gateway holds them at all
    ///
    /// It never approves anything with them: an approval is a WebAuthn
    /// assertion, verified by Astra and by the client. What the gateway owes
    /// them is *distribution* — the §19 enrolment block is the only thing a
    /// client reads before it has a tunnel, and recovering an expired identity
    /// (§7.5) begins by naming the credential that will approve it. A client
    /// that had to fetch the list would have to fetch it over the link it has
    /// just lost.
    ///
    /// Until this call the registry learned a row only by verifying an
    /// approval that named it, which is to say: never, on a domain where no
    /// renewal had yet been approved. A freshly bootstrapped domain therefore
    /// enrolled clients that could never recover.
    ///
    /// # What is checked
    ///
    /// Every row, under the `CA-PQ` this registry already holds — not only the
    /// rows about to be used. A document carrying one forged row beside honest
    /// ones would otherwise install it, and that row is what a later
    /// `supersedes` would be compared against.
    pub fn install_astra_credentials(
        &mut self,
        registry: &aether::certificates::approval::CredentialRegistry,
    ) -> Result<usize, RegistryError> {
        registry.verify(
            &self.state.gateway.current_ca_public_key,
            &self.state.trust_domain_id,
            &self.state.gateway.gateway_wg_public_key,
            self.state.gateway.ca_epoch,
            self.state.astra.credential_registry_epoch,
        )?;

        // One candidate, one persist: a registry left holding half a document
        // would answer an enrolment with a list nobody signed as a whole.
        let mut candidate = self.state.clone();
        let mut installed = 0usize;
        for binding in &registry.bindings {
            if matches!(
                candidate.astra.accept_credential_binding(binding)?,
                aether::certificates::state::InstallOutcome::Installed
            ) {
                installed += 1;
            }
        }
        if installed > 0 {
            self.persist(candidate)?;
        }
        Ok(installed)
    }

    pub fn install_astra_issuer(
        &mut self,
        delegation: &aether::certificates::authority::AstraIssuerAuthorization,
        now_unix: u64,
    ) -> Result<aether::certificates::approval::PolicyMigration, RegistryError> {
        use aether::certificates::approval::PolicyMigration;

        if let Some(installed) = &self.state.issuer {
            if &installed.authorization != delegation
                && delegation.issuer_epoch <= installed.issuer_epoch
            {
                return Err(RegistryError::IssuerEpochNotAdvancing {
                    installed: installed.issuer_epoch,
                    offered: delegation.issuer_epoch,
                });
            }
        }
        let gateway = &self.state.gateway;
        delegation.verify(
            &gateway.current_ca_public_key,
            &gateway.trust_domain_id,
            gateway.ca_epoch,
            self.state.client_tls_ca.ca_tls_epoch,
            &gateway.gateway_wg_public_key,
            &gateway.server_name,
            now_unix,
        )?;
        let migration = self
            .state
            .astra
            .astra_policy_fingerprint
            .adopt_automatic_renewal_policy(
                gateway.trust_domain_id,
                gateway.gateway_wg_public_key,
                &gateway.server_name,
                delegation,
            )?;
        let mut candidate = self.state.clone();
        if let PolicyMigration::Adopted(pin) = migration {
            candidate.astra.astra_policy_fingerprint = pin;
        }
        candidate.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: delegation.issuer_epoch,
            authorization: delegation.clone(),
            state: aether::certificates::state::IssuerLifecycle::Active,
        });
        self.persist(candidate)?;
        Ok(migration)
    }

    /// Repairs the one legacy bootstrap that stored the admission CA where
    /// the domain's client `CA-TLS` belongs.
    ///
    /// This is deliberately narrower than a rotation. It changes only an
    /// epoch-1 registry whose anchor and every first-generation peer still
    /// name the exact admission CA supplied by the caller. Any staged or
    /// committed certificate generation refuses the repair: after issuance
    /// has moved, only a signed §9.4 transition may move the anchor.
    ///
    /// Pending *distributions* are preserved. They are signed objects queued
    /// for a peer and may be precisely the domain transition that exposed the
    /// bad bootstrap; they are not certificate generations owned by this
    /// registry.
    pub fn repair_legacy_client_tls_ca_bootstrap(
        &mut self,
        admission_ca: &DerCertificate,
        domain_ca: &DerCertificate,
    ) -> Result<BootstrapRepairOutcome, RegistryError> {
        aether::certificates::x509::assert_certificate_authority(admission_ca)?;
        aether::certificates::x509::assert_certificate_authority(domain_ca)?;
        aether::certificates::x509::assert_issued_by(admission_ca, admission_ca)?;
        aether::certificates::x509::assert_issued_by(domain_ca, domain_ca)?;

        let admission_fingerprint = admission_ca.fingerprint();
        let domain_fingerprint = domain_ca.fingerprint();
        let client_tls_ca = &self.state.client_tls_ca;

        if client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&domain_fingerprint)
        {
            return Ok(BootstrapRepairOutcome::AlreadyCorrect);
        }
        if client_tls_ca.ca_tls_epoch > 1 {
            return Ok(BootstrapRepairOutcome::LaterEpoch);
        }
        if client_tls_ca.ca_tls_epoch != 1 {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "the registry is not at client CA-TLS epoch 1",
            ));
        }
        if !client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&admission_fingerprint)
        {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "the active anchor is not the operator admission CA",
            ));
        }
        if client_tls_ca.next_client_tls_ca_certificate.is_some()
            || client_tls_ca.next_transition_fingerprint.is_some()
            || client_tls_ca.activation_at.is_some()
            || client_tls_ca.retire_active_at.is_some()
        {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "a client CA-TLS rotation is already in flight",
            ));
        }
        self.state
            .ledger
            .assert_not_revoked(&[domain_fingerprint])?;

        let every_peer_is_first_generation = self.state.peers.values().all(|peer| {
            let certificates = &peer.state;
            certificates.active.generation == 1
                && certificates.active.ca_tls_epoch == 1
                && certificates
                    .active
                    .tls_ca_certificate_fingerprint
                    .matches(&admission_fingerprint)
                && certificates.pending.is_none()
                && certificates.next.is_none()
                && certificates.activation_at.is_none()
                && certificates.retire_active_at.is_none()
                && certificates.last_committed_stage.is_none()
        });
        if !every_peer_is_first_generation {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "at least one peer has left its untouched first generation",
            ));
        }

        let mut candidate = self.state.clone();
        candidate.client_tls_ca.active_client_tls_ca_certificate = domain_ca.clone();
        for peer in candidate.peers.values_mut() {
            peer.state.active.tls_ca_certificate_fingerprint = domain_fingerprint;
        }
        self.persist(candidate)?;
        Ok(BootstrapRepairOutcome::Repaired)
    }

    /// Records that the authority has let a staged transition leave (§6.3).
    ///
    /// Irreversible, and that is the point: past this marker a client may hold
    /// the decision, go offline and promote on its own at `not_after`.
    /// Cancelling on the gateway alone would leave two truths in one fleet.
    ///
    /// The publication names the exact document. An operator may have
    /// installed one transition by hand while the authority published
    /// another, and «publish whatever is staged» would then close the abort
    /// window on a decision nobody distributed.
    pub fn publish_gateway_transition(
        &mut self,
        gateway_identity_epoch: u64,
        transition_fingerprint: &Fingerprint,
    ) -> Result<(), RegistryError> {
        let gateway = &self.state.gateway;
        let names_the_staged_document = gateway.next_gateway_identity_epoch
            == Some(gateway_identity_epoch)
            && gateway
                .next_transition_fingerprint
                .is_some_and(|staged| staged.matches(transition_fingerprint));
        if !names_the_staged_document {
            return Err(RegistryError::Certificate(
                CertificateError::IllegalStateTransition(
                    "no staged transition matches this publication",
                ),
            ));
        }
        // A repeated report is the authority retrying a relay it could not
        // confirm, not a second decision.
        if gateway.published {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.gateway.mark_published()?;
        self.persist(state)
    }

    /// Cancels a staged, unpublished gateway transition (spec §6.3).
    ///
    /// The abort names the exact document it cancels, and the state machine
    /// refuses it once `published` is set or once the local clock has reached
    /// `activation_at` — backdating the object does not reopen a window the
    /// clients may already have acted on. The epoch stays consumed: the slot
    /// disappears, the tombstone takes its place, and the next attempt starts
    /// one decision higher.
    pub fn abort_gateway_transition(
        &mut self,
        abort: &GatewayTransitionAbort,
        transition: &GatewayIdentityTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let outcome = state.gateway.apply_abort(abort, transition, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Withdraws the gateway's own identity (spec §10.1).
    ///
    /// Returns whether a leaf this gateway actually holds was named. A
    /// revocation that names none is **not** an error: an offline document may
    /// carry decisions about leaves this state never saw, and its counter is
    /// consumed all the same — which is what stops the named leaf from
    /// arriving later through a transition.
    pub fn revoke_gateway(
        &mut self,
        revoked_tls_fingerprint: Option<&Fingerprint>,
        revoked_pq_fingerprint: Option<&Fingerprint>,
        revocation_epoch: u64,
        replacement_transition_fingerprint: Option<&Fingerprint>,
    ) -> Result<bool, RegistryError> {
        let mut state = self.state.clone();
        let hit = state.gateway.apply_revocation(
            revoked_tls_fingerprint,
            revoked_pq_fingerprint,
            revocation_epoch,
            replacement_transition_fingerprint,
        )?;
        self.persist(state)?;
        Ok(hit)
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

/// Adds fields introduced after the first trust-domain registry format.
///
/// The gateway registry is deliberately not bootstrapped again when a file is
/// already present: doing so would erase its certificate generations and
/// ledger. Newer binaries therefore migrate the small, deterministic Astra
/// profile extension in place. The policy pin is recomputed from the same
/// three public inputs used by `heliosd init-trust-domain`; it is never copied
/// from an operator-signed object or accepted from an untrusted default.
fn migrate_legacy_registry(document: &mut Value) -> Result<bool, RegistryError> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| RegistryError::Corrupt("registry root is not an object".into()))?;

    let trust_domain_id: TrustDomainId = serde_json::from_value(
        root.get("trust_domain_id")
            .cloned()
            .ok_or_else(|| RegistryError::Corrupt("missing field `trust_domain_id`".into()))?,
    )
    .map_err(|error| RegistryError::Corrupt(format!("invalid `trust_domain_id`: {error}")))?;

    let gateway = root
        .get("gateway")
        .and_then(Value::as_object)
        .ok_or_else(|| RegistryError::Corrupt("missing field `gateway`".into()))?;
    let gateway_wg_public_key: WireGuardKey = serde_json::from_value(
        gateway
            .get("gateway_wg_public_key")
            .cloned()
            .ok_or_else(|| {
                RegistryError::Corrupt("missing field `gateway.gateway_wg_public_key`".into())
            })?,
    )
    .map_err(|error| {
        RegistryError::Corrupt(format!("invalid `gateway.gateway_wg_public_key`: {error}"))
    })?;
    let server_name = gateway
        .get("server_name")
        .and_then(Value::as_str)
        .ok_or_else(|| RegistryError::Corrupt("missing field `gateway.server_name`".into()))?
        .to_owned();

    let astra = root
        .get_mut("astra")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| RegistryError::Corrupt("missing field `astra`".into()))?;

    let mut migrated = false;
    if !astra.contains_key("astra_policy_fingerprint") {
        let pin =
            AstraIssuancePolicy::standard(trust_domain_id, gateway_wg_public_key, server_name)
                .pin()
                .map_err(|error| {
                    RegistryError::Corrupt(format!("building the Astra policy pin: {error}"))
                })?;
        let encoded = serde_json::to_value(pin.fingerprint())
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        astra.insert("astra_policy_fingerprint".into(), encoded);
        migrated = true;
    }
    if !astra.contains_key("credential_registry_epoch") {
        astra.insert("credential_registry_epoch".into(), Value::from(1_u64));
        migrated = true;
    }
    if !astra.contains_key("credential_bindings") {
        astra.insert(
            "credential_bindings".into(),
            Value::Object(Default::default()),
        );
        migrated = true;
    }

    Ok(migrated)
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

#[cfg(all(test, feature = "certificate-signing"))]
#[path = "certificates/tests/mod.rs"]
mod tests;
