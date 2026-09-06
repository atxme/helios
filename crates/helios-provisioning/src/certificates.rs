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
mod tests {
    use super::*;
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::IssuerKind;
    use aether::certificates::encoding::Id16;
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, DerCertificate};
    use aether::certificates::gateway::AbortReason;
    use aether::certificates::window::TransitionWindow;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use zeroize::Zeroizing;

    const SERVER_NAME: &str = "gateway.example";

    struct Keys {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn keys() -> Keys {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Keys { private, public }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([1; 16]).expect("domain")
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([1; 32])
    }

    fn client_key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    fn leaf(
        ca: &Keys,
        subject: &Keys,
        role: PqCertificateRole,
        wg: &WireGuardKey,
        serial: u8,
    ) -> PqCertificate {
        let certificate = PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: if role == PqCertificateRole::Gateway {
                SERVER_NAME.into()
            } else {
                "orion".into()
            },
            issuer: "CA-PQ".into(),
            role,
            wireguard_public_key: wg.to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: String::new(),
        };
        issue_pq_certificate(certificate, &ca.private).expect("issue")
    }

    fn generation(index: u64, tls: &[u8], pq: &PqCertificate) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: index,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(tls),
            pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
                pq,
            )
            .expect("fingerprint"),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    struct Fixture {
        tls: aether::certificates::test_x509::TlsMaterial,
        registry: CertificateRegistry,
        ca: Keys,
        gateway_leaf_key: Keys,
        active_client: Keys,
        _directory: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temp dir");
        let tls = aether::certificates::test_x509::client_material("workstation");
        let ca = keys();
        let gateway_leaf_key = keys();
        let astra_key = keys();
        let active_client = keys();

        let gateway_leaf = leaf(
            &ca,
            &gateway_leaf_key,
            PqCertificateRole::Gateway,
            &gateway_key(),
            1,
        );
        let client_leaf = leaf(
            &ca,
            &active_client,
            PqCertificateRole::Client,
            &client_key(2),
            2,
        );

        let state = RegistryState {
            trust_domain_id: domain(),
            gateway: GatewayCertificateState {
                trust_domain_id: domain(),
                gateway_wg_public_key: gateway_key(),
                server_name: SERVER_NAME.into(),
                ca_epoch: 1,
                current_ca_public_key: ca.public.clone(),
                next_ca_public_key: None,
                next_ca_transition_fingerprint: None,
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                next_gateway_identity_epoch: None,
                next_transition_fingerprint: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_leaf,
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
                ca_tls_epoch: 1,
                active_client_tls_ca_certificate: tls.authority.clone(),
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint:
                    aether::certificates::approval::AstraIssuancePolicy::standard(
                        domain(),
                        gateway_key(),
                        SERVER_NAME.into(),
                    )
                    .pin()
                    .expect("policy"),
                credential_registry_epoch: 1,
                credential_bindings: Default::default(),
                active_astra_service_public_key: astra_key.public.clone(),
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 1,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer: None,
            peers: BTreeMap::new(),
            ledger: TrustLedger::default(),
        };

        let mut registry =
            CertificateRegistry::new(directory.path().join("certificates.json"), state);
        registry
            .admit(
                "workstation",
                &client_key(2),
                generation(4, b"active tls", &client_leaf),
                client_leaf,
            )
            .expect("admission");

        Fixture {
            tls,
            registry,
            ca,
            gateway_leaf_key,
            active_client,
            _directory: directory,
        }
    }

    /// A transaction as the authority signs one. The signature is never
    /// checked here — the gateway holds no authority key, and that is the
    /// point of these tests — so a placeholder is exactly right.
    fn distribution(
        client: &WireGuardKey,
        chunk_count: u16,
        expires_at: u64,
    ) -> (TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>) {
        let manifest = TrustUpdateTransactionManifest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            transaction_id: Id16::new([9; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: *client,
            base_state_fingerprint: Fingerprint::of(b"base state"),
            created_at: 0,
            expires_at,
            minimum_activation_at: expires_at,
            chunk_count,
            objects: Vec::new(),
            manifest_authority_kind:
                aether::certificates::transport::ManifestAuthority::AstraServiceKey,
            manifest_authority_epoch: 1,
            signature: MlDsa87Signature::placeholder(),
        };
        let manifest_fingerprint = manifest.fingerprint();
        let chunks = (0..chunk_count)
            .map(|index| TrustUpdateChunk {
                manifest_fingerprint,
                chunk_index: index,
                chunk_count,
                first_object_index: index,
                objects: Vec::new(),
            })
            .collect();
        (manifest, chunks)
    }

    /// The fragments come back in order, one per fresh request, and the
    /// manifest travels with every one of them.
    #[test]
    fn a_queued_transaction_is_served_one_fragment_per_request() {
        let mut fixture = fixture();
        let (manifest, chunks) = distribution(&client_key(2), 3, 10_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0)
            .expect("queued");

        for index in 0..3u16 {
            let request = Id16::new([index as u8 + 1; 16]).expect("request id");
            let (manifest, chunk) = fixture
                .registry
                .take_distribution_chunk(
                    &client_key(2),
                    &request,
                    &Fingerprint::of(b"base state"),
                    0,
                )
                .expect("readable")
                .expect("a fragment is owed");
            assert_eq!(chunk.chunk_index, index);
            assert_eq!(
                chunk.manifest_fingerprint,
                manifest.fingerprint(),
                "a client must be able to attribute every fragment it holds"
            );
        }

        // Drained: nothing more is owed, and the queue stops answering.
        let last = Id16::new([99; 16]).expect("request id");
        assert!(fixture
            .registry
            .take_distribution_chunk(&client_key(2), &last, &Fingerprint::of(b"base state"), 0,)
            .expect("readable")
            .is_none());
    }

    /// A retransmission gets the fragment it already got. Advancing on a
    /// replay would skip one over a lossy link, and the client would poll
    /// forever for a transaction it can never complete.
    #[test]
    fn a_repeated_request_is_served_the_same_fragment() {
        let mut fixture = fixture();
        let (manifest, chunks) = distribution(&client_key(2), 2, 10_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0)
            .expect("queued");

        let request = Id16::new([7; 16]).expect("request id");
        let first = fixture
            .registry
            .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
            .expect("readable")
            .expect("owed")
            .1;
        let replayed = fixture
            .registry
            .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
            .expect("readable")
            .expect("owed")
            .1;
        assert_eq!(first.chunk_index, 0);
        assert_eq!(replayed.chunk_index, 0);
    }

    /// Past its deadline the receiver refuses the whole transaction, so
    /// handing it over would only spend a poll cycle reaching that refusal.
    #[test]
    fn an_expired_transaction_is_dropped_rather_than_served() {
        let mut fixture = fixture();
        let (manifest, chunks) = distribution(&client_key(2), 1, 1_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0)
            .expect("queued");

        let request = Id16::new([7; 16]).expect("request id");
        assert!(fixture
            .registry
            .take_distribution_chunk(
                &client_key(2),
                &request,
                &Fingerprint::of(b"base state"),
                1_000,
            )
            .expect("readable")
            .is_none());
        assert!(
            fixture
                .registry
                .peer(&client_key(2))
                .expect("peer")
                .distribution
                .is_none(),
            "an expired transaction does not stay in the queue"
        );
    }

    /// The queue is only transport: it must not hand a client a decision
    /// computed for a state other than the one this request signed.
    #[test]
    fn a_transaction_for_another_base_state_is_dropped() {
        let mut fixture = fixture();
        let (manifest, chunks) = distribution(&client_key(2), 1, 10_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0)
            .expect("queued");

        let request = Id16::new([7; 16]).expect("request id");
        assert!(fixture
            .registry
            .take_distribution_chunk(
                &client_key(2),
                &request,
                &Fingerprint::of(b"new local state"),
                0,
            )
            .expect("readable")
            .is_none());
        assert!(fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .distribution
            .is_none());
    }

    /// A transaction addressed elsewhere is refused. The manifest names its
    /// target and the signature covers that name: queueing it under another
    /// peer would hand one client a decision signed for another.
    #[test]
    fn a_transaction_for_another_peer_is_refused() {
        let mut fixture = fixture();
        let (manifest, chunks) = distribution(&client_key(3), 1, 10_000);
        assert!(matches!(
            fixture
                .registry
                .stage_distribution(&client_key(2), manifest, chunks, 0),
            Err(RegistryError::Certificate(
                CertificateError::ClientIdentityMismatch
            ))
        ));
    }

    /// A fragment set that does not match the manifest is refused at the door.
    /// Accepting it would have the client collect everything and only then
    /// refuse — a full poll cycle spent to discover a fault the gateway could
    /// see immediately.
    #[test]
    fn a_fragment_set_that_contradicts_its_manifest_is_refused() {
        let mut fixture = fixture();
        let (manifest, mut chunks) = distribution(&client_key(2), 2, 10_000);
        chunks.pop();
        assert!(fixture
            .registry
            .stage_distribution(&client_key(2), manifest.clone(), chunks, 0)
            .is_err());

        let (_, mut reordered) = distribution(&client_key(2), 2, 10_000);
        reordered.reverse();
        assert!(fixture
            .registry
            .stage_distribution(&client_key(2), manifest, reordered, 0)
            .is_err());
    }

    /// A newer decision supersedes an older one. A client that never came back
    /// for its fragments must not pin the queue against the authority.
    #[test]
    fn a_newer_transaction_replaces_one_left_undrained() {
        let mut fixture = fixture();
        let (first, first_chunks) = distribution(&client_key(2), 3, 10_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), first, first_chunks, 0)
            .expect("queued");
        let (second, second_chunks) = distribution(&client_key(2), 1, 20_000);
        let expected = second.fingerprint();
        fixture
            .registry
            .stage_distribution(&client_key(2), second, second_chunks, 0)
            .expect("replaced");

        let request = Id16::new([7; 16]).expect("request id");
        let (manifest, chunk) = fixture
            .registry
            .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
            .expect("readable")
            .expect("owed");
        assert_eq!(manifest.fingerprint(), expected);
        assert_eq!(chunk.chunk_count, 1);
    }

    fn authorization(
        fixture: &Fixture,
        candidate_leaf: &PqCertificate,
        stage_id: u8,
        stage_expires_at: u64,
    ) -> ClientCertificateStageAuthorization {
        let authorization = ClientCertificateStageAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            issuer_kind: IssuerKind::Master,
            issuer_epoch: 0,
            issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
            issuer_authorization: None,
            stage_id: Id16::new([stage_id; 16]).expect("stage"),
            request_fingerprint: Fingerprint::of(b"request"),
            renewal_authorization_fingerprint: Fingerprint::of(b"operator approval"),
            renewal_approval: None,
            campaign_approval: None,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            client_wg_public_key: client_key(2),
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            active_pq_certificate_fingerprint: fixture
                .registry
                .peer(&client_key(2))
                .expect("peer")
                .state
                .active
                .pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: fixture.tls.authority.fingerprint(),
            next_tls_certificate: fixture.tls.leaf.clone(),
            next_pq_certificate: candidate_leaf.clone(),
            issued_at: 1_000,
            stage_expires_at,
            window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
            reason: RotationReason::Scheduled,
            signature: MlDsa87Signature::placeholder(),
        };
        authorization.sign(&fixture.ca.private).expect("sign")
    }

    /// The grant the authority releases against a receipt, signed by `CA-PQ`
    /// acting as the master issuer.
    fn grant_for(
        fixture: &Fixture,
        authorization: &ClientCertificateStageAuthorization,
        receipt: GatewayCertificateStageReceipt,
    ) -> ClientCertificateRotationGrant {
        ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            ca_epoch: authorization.ca_epoch,
            ca_tls_epoch: authorization.ca_tls_epoch,
            issuer_kind: authorization.issuer_kind,
            issuer_epoch: authorization.issuer_epoch,
            issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
            issuer_authorization: authorization.issuer_authorization.clone(),
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            renewal_approval: authorization.renewal_approval.clone(),
            campaign_approval: authorization.campaign_approval.clone(),
            stage_receipt_fingerprint: receipt.fingerprint(),
            stage_receipt: receipt,
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            server_name: authorization.server_name.clone(),
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: authorization.active_generation,
            next_generation: authorization.next_generation,
            active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            next_tls_certificate: authorization.next_tls_certificate.clone(),
            next_pq_certificate: authorization.next_pq_certificate.clone(),
            stage_expires_at: authorization.stage_expires_at,
            window: authorization.window,
            reason: authorization.reason,
            signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.ca.private)
        .expect("sign grant")
    }

    /// The commit a client sends once it holds the grant.
    fn commit_for(
        authorization: &ClientCertificateStageAuthorization,
        grant: &ClientCertificateRotationGrant,
        active_private: &[u8],
        candidate_private: &[u8],
        committed_at: u64,
    ) -> ClientCertificateStageCommit {
        let candidate = authorization.candidate().expect("candidate");
        ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            stage_id: authorization.stage_id,
            grant_fingerprint: grant.fingerprint().expect("fingerprint"),
            stage_receipt_fingerprint: grant.stage_receipt_fingerprint,
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: authorization.active_generation,
            staged_generation: candidate.generation,
            staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
            stage_expires_at: authorization.stage_expires_at,
            committed_at,
            active_pq_signature: MlDsa87Signature::placeholder(),
            staged_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(active_private, candidate_private)
        .expect("sign commit")
    }

    /// The receipt is produced only after the candidate is on disk: that
    /// ordering is what stops an identity from existing before its admission.
    #[test]
    fn a_receipt_describes_a_candidate_that_is_already_persisted() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging");

        let reloaded = CertificateRegistry::load(&fixture.registry.path)
            .expect("load")
            .expect("registry on disk");
        let peer = reloaded.peer(&client_key(2)).expect("peer");
        assert_eq!(
            peer.state
                .pending
                .as_ref()
                .expect("pending")
                .candidate
                .generation,
            5
        );

        // And the receipt verifies under the gateway leaf it names.
        let receipt = receipt
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign");
        receipt
            .verify(
                &fixture.gateway_leaf_key.public,
                &fixture
                    .registry
                    .state
                    .gateway
                    .active_pq_fingerprint()
                    .expect("fingerprint"),
                &authorization,
            )
            .expect("receipt verifies");
    }

    /// The last complete registry shape had no ledger. Accepting it with an
    /// empty default would forget every local peer-removal tombstone.
    #[test]
    fn a_registry_from_the_previous_shape_is_refused() {
        let fixture = fixture();
        let path = fixture.registry.path.clone();
        let mut previous =
            serde_json::to_value(fixture.registry.state()).expect("serialize registry");
        previous
            .as_object_mut()
            .expect("registry object")
            .remove("ledger");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&previous).expect("encode previous shape"),
        )
        .expect("write previous shape");

        assert!(matches!(
            CertificateRegistry::load(&path),
            Err(RegistryError::Corrupt(_))
        ));
    }

    /// The caller is resolved from the transport; the body is only compared.
    #[test]
    fn a_staging_aimed_at_another_peer_is_refused() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

        assert!(matches!(
            fixture
                .registry
                .stage(&client_key(9), &authorization, 1_100),
            Err(RegistryError::PeerMismatch)
        ));
    }

    #[test]
    fn a_commit_carrying_the_grant_promotes_the_candidate_to_next() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &authorization, receipt);
        let commit = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );

        assert_eq!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &grant, 1_300)
                .expect("commit"),
            InstallOutcome::Installed
        );
        let peer = fixture.registry.peer(&client_key(2)).expect("peer");
        assert!(peer.state.pending.is_none());
        assert_eq!(peer.state.next.as_ref().expect("next").generation, 5);

        // A retry over a lossy link must be a no-op, not a refusal.
        assert_eq!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &grant, 1_400)
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        );
    }

    /// A failed write must leave the registry describing what is on disk.
    ///
    /// Mutating memory and saving afterwards produces the worst outcome
    /// available here: the running gateway answers the client's retry with
    /// success, and a restart then reloads a candidate that is still pending.
    /// The transaction is closed on the client's side, so nothing asks again.
    #[test]
    fn a_commit_whose_write_fails_leaves_the_registry_on_what_is_on_disk() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &authorization, receipt);
        let commit = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );

        // Repoint the registry at a path no write can reach.
        let unwritable = fixture
            ._directory
            .path()
            .join("missing")
            .join("certificates.json");
        fixture.registry = CertificateRegistry::new(unwritable, fixture.registry.state().clone());

        assert!(matches!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &grant, 1_300),
            Err(RegistryError::Io(_))
        ));
        let peer = fixture.registry.peer(&client_key(2)).expect("peer");
        assert!(
            peer.state.pending.is_some() && peer.state.next.is_none(),
            "the live state must still describe the candidate the disk holds"
        );

        // And the retry is the same refusal, not a success invented in memory.
        assert!(matches!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &grant, 1_400),
            Err(RegistryError::Io(_))
        ));
    }

    /// Idempotency is the same signed document. A second, differently-signed
    /// commit naming the same stage is a conflict — answering it with success
    /// would report someone else's decision as landed.
    #[test]
    fn a_second_differently_signed_commit_for_the_same_stage_is_a_conflict() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &authorization, receipt);
        let commit = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300)
            .expect("commit");

        // Same stage, same candidate, a different signed document: only
        // `committed_at` moved.
        let other = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_250,
        );
        assert!(matches!(
            fixture
                .registry
                .commit(&client_key(2), &other, &grant, 1_400),
            Err(RegistryError::Certificate(
                CertificateError::GenerationConflict { .. }
            ))
        ));
    }

    /// A commit that arrives at the deadline loses the race against the purge,
    /// deterministically — the clock is read once, by the caller.
    #[test]
    fn a_commit_arriving_at_the_lease_deadline_is_refused() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &authorization, receipt);
        let commit = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );

        assert!(fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 5_000)
            .is_err());
        assert!(fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .state
            .next
            .is_none());
    }

    /// The point of the whole staging protocol: holding both private keys is
    /// not enough. Without a grant the authority released, the candidate the
    /// gateway persisted stays where it is.
    #[test]
    fn a_client_holding_both_keys_cannot_commit_without_a_grant() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");

        // A grant the client forged for itself: everything matches except the
        // authority that signed it.
        let impostor = keys();
        let forged = ClientCertificateRotationGrant {
            signature: MlDsa87Signature::placeholder(),
            ..grant_for(&fixture, &authorization, receipt.clone())
        }
        .sign(&impostor.private)
        .expect("sign");
        let commit = commit_for(
            &authorization,
            &forged,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );
        assert!(matches!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &forged, 1_300),
            Err(RegistryError::Certificate(
                CertificateError::InvalidSignature
            ))
        ));

        // And a commit naming a grant other than the one it carries is refused
        // before any state moves.
        let genuine = grant_for(&fixture, &authorization, receipt);
        let mismatched = ClientCertificateStageCommit {
            grant_fingerprint: Fingerprint::of(b"another grant"),
            ..commit_for(
                &authorization,
                &genuine,
                &fixture.active_client.private,
                &candidate.private,
                1_200,
            )
        };
        assert!(fixture
            .registry
            .commit(&client_key(2), &mismatched, &genuine, 1_300)
            .is_err());

        assert!(
            fixture
                .registry
                .peer(&client_key(2))
                .expect("peer")
                .state
                .next
                .is_none(),
            "no refusal may leave a committed slot behind"
        );
    }

    /// A commit that only proves the candidate key would let a leaked grant
    /// install an identity its owner never asked for.
    #[test]
    fn a_commit_missing_the_active_signature_is_refused() {
        let mut fixture = fixture();
        let candidate = keys();
        let stranger = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &authorization, receipt);
        // Signed by a key that is not the peer's active one: continuity is
        // exactly what this signature is there to prove.
        let commit = commit_for(
            &authorization,
            &grant,
            &stranger.private,
            &candidate.private,
            1_200,
        );

        assert!(matches!(
            fixture
                .registry
                .commit(&client_key(2), &commit, &grant, 1_300),
            Err(RegistryError::Certificate(CertificateError::MissingProof(
                "active client"
            )))
        ));
    }

    /// An orphaned stage is purged at its lease and frees `active + 1` again.
    #[test]
    fn an_orphaned_stage_is_purged_and_the_generation_becomes_requestable_again() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let first = authorization(&fixture, &candidate_leaf, 5, 5_000);
        fixture
            .registry
            .stage(&client_key(2), &first, 1_100)
            .expect("staging");

        // A second stage while the first lives is refused outright.
        let second = authorization(&fixture, &candidate_leaf, 6, 5_000);
        assert!(fixture
            .registry
            .stage(&client_key(2), &second, 1_200)
            .is_err());

        let purged = fixture.registry.purge_expired(5_000).expect("purge");
        assert_eq!(purged.len(), 1);
        assert!(fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .state
            .pending
            .is_none());

        // The same generation is requestable again, under a new stage id.
        let retry = authorization(&fixture, &candidate_leaf, 7, 9_000);
        fixture
            .registry
            .stage(&client_key(2), &retry, 5_100)
            .expect("re-staging");
    }

    /// A certificate identifies exactly one peer, active or staged.
    #[test]
    fn a_fingerprint_already_bound_to_another_peer_is_refused() {
        let mut fixture = fixture();
        let candidate = keys();
        // A leaf legitimately bound to peer 2 — so the authorization itself
        // verifies — but already recorded against another admitted peer.
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        fixture
            .registry
            .admit(
                "laptop",
                &client_key(3),
                generation(1, b"other tls", &candidate_leaf),
                candidate_leaf.clone(),
            )
            .expect("admission");

        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        assert!(matches!(
            fixture
                .registry
                .stage(&client_key(2), &authorization, 1_100),
            Err(RegistryError::FingerprintTaken(name)) if name == "laptop"
        ));
        // And the refusal changed nothing.
        assert!(fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .state
            .pending
            .is_none());
    }

    /// Revocation dominates a staging that is already persisted.
    #[test]
    fn revocation_removes_a_staged_candidate_and_refuses_the_commit() {
        let mut fixture = fixture();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging");

        fixture
            .registry
            .revoke(&client_key(2), 1, 1_000)
            .expect("revoke");
        let peer = fixture.registry.peer(&client_key(2)).expect("peer");
        assert!(peer.state.revoked);
        assert!(peer.state.pending.is_none());
        assert!(peer.staged_pq_certificate.is_none());

        // And nothing can be staged again for a revoked peer.
        assert!(matches!(
            fixture
                .registry
                .stage(&client_key(2), &authorization, 1_200),
            Err(RegistryError::Certificate(CertificateError::Revoked))
        ));
    }
    /// A domain has one history. Bootstrapping over an existing registry would
    /// restart the epochs at 1 while every client holds higher ones — a
    /// gateway that looks freshly installed and is refused by its whole park.
    #[test]
    fn a_second_bootstrap_never_lands_on_the_first() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("nested").join("certificates.json");
        let state = fixture().registry.state().clone();

        let registry =
            CertificateRegistry::bootstrap(path.clone(), state.clone()).expect("first bootstrap");
        assert_eq!(registry.state(), &state);
        assert!(matches!(
            CertificateRegistry::bootstrap(path, state),
            Err(RegistryError::AlreadyBootstrapped(_))
        ));
    }

    /// What `bootstrap` wrote is what `load` reads back: the registry is the
    /// file, and a lossy round trip would only surface at the first staging.
    #[test]
    fn a_bootstrapped_registry_reloads_identically() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("certificates.json");
        let state = fixture().registry.state().clone();

        CertificateRegistry::bootstrap(path.clone(), state.clone()).expect("bootstrap");
        let reloaded = CertificateRegistry::load(&path)
            .expect("load")
            .expect("a bootstrapped domain is not an absent one");
        assert_eq!(reloaded.state(), &state);
    }

    /// The crash matrix of the client staging path (spec §14.1).
    ///
    /// A gateway can die at any instant of a rotation. What comes back off
    /// disk is one of exactly three states — no candidate, `pending_grant`, or
    /// `next_committed` — and never a fourth: a peer is written by whole
    /// states, so there is no moment at which a reload finds a half one.
    #[test]
    fn a_crash_at_any_step_reloads_one_of_the_three_staging_states() {
        let mut fixture = fixture();
        let path = fixture.registry.path.clone();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

        let on_disk = |path: &std::path::Path| {
            let reloaded = CertificateRegistry::load(path)
                .expect("load")
                .expect("registry on disk");
            let peer = reloaded.peer(&client_key(2)).expect("peer").state.clone();
            (peer.pending, peer.next, peer.active.generation)
        };

        // Before the stage: no candidate, and the active generation alone.
        let (pending, next, active) = on_disk(&path);
        assert!(pending.is_none() && next.is_none());
        assert_eq!(active, 4);

        let receipt = fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");

        // A crash here reloads `pending_grant`, and no `next`.
        let (pending, next, active) = on_disk(&path);
        let pending = pending.expect("pending_grant");
        assert_eq!(pending.state, PendingStageState::PendingGrant);
        assert_eq!(pending.candidate.generation, 5);
        assert!(next.is_none(), "a candidate is never both pending and next");
        assert_eq!(active, 4, "the active generation keeps serving throughout");

        let grant = grant_for(&fixture, &authorization, receipt);
        let commit = commit_for(
            &authorization,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300)
            .expect("commit");

        // A crash after the commit reloads `next_committed`, and no pending.
        let (pending, next, active) = on_disk(&path);
        assert!(pending.is_none(), "the commit replaced the candidate");
        assert_eq!(next.expect("next_committed").generation, 5);
        assert_eq!(active, 4);
    }

    /// The third state of the matrix: a stage that never received its grant.
    ///
    /// The purge is a write like any other, so a crash after it reloads a peer
    /// with no candidate at all — not one whose lease has expired in memory
    /// and survived on disk.
    #[test]
    fn a_crash_after_the_purge_reloads_a_peer_without_a_candidate() {
        let mut fixture = fixture();
        let path = fixture.registry.path.clone();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
        fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100)
            .expect("staging");
        assert_eq!(
            fixture.registry.purge_expired(5_000).expect("purge").len(),
            1
        );

        let reloaded = CertificateRegistry::load(&path)
            .expect("load")
            .expect("registry on disk");
        let peer = reloaded.peer(&client_key(2)).expect("peer");
        assert!(peer.state.pending.is_none());
        assert!(peer.state.next.is_none());
        assert!(peer.staged_pq_certificate.is_none());
        assert_eq!(peer.state.active.generation, 4);
    }

    /// Two leafs per family is an invariant of the **state**, not of the
    /// process that was running when it was written (spec §14.1).
    ///
    /// A registry recovered from disk therefore refuses a third generation
    /// exactly as the one that staged the second did — a restart is not a way
    /// to obtain a candidate beside an already committed `next`.
    #[test]
    fn a_reloaded_registry_still_refuses_a_third_generation() {
        let mut fixture = fixture();
        let path = fixture.registry.path.clone();
        let candidate = keys();
        let candidate_leaf = leaf(
            &fixture.ca,
            &candidate,
            PqCertificateRole::Client,
            &client_key(2),
            3,
        );
        let first = authorization(&fixture, &candidate_leaf, 5, 5_000);
        let receipt = fixture
            .registry
            .stage(&client_key(2), &first, 1_100)
            .expect("staging")
            .sign(&fixture.gateway_leaf_key.private)
            .expect("sign receipt");
        let grant = grant_for(&fixture, &first, receipt);
        let commit = commit_for(
            &first,
            &grant,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        );
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300)
            .expect("commit");

        let mut reloaded = CertificateRegistry::load(&path)
            .expect("load")
            .expect("registry on disk");
        let third = authorization(&fixture, &candidate_leaf, 6, 9_000);
        assert!(matches!(
            reloaded.stage(&client_key(2), &third, 1_400),
            Err(RegistryError::Certificate(
                CertificateError::StageAlreadyPresent
            ))
        ));
        let peer = reloaded.peer(&client_key(2)).expect("peer");
        assert!(peer.state.pending.is_none());
        assert_eq!(peer.state.next.as_ref().expect("next").generation, 5);
    }

    /// Registries written before the Astra policy pin was added keep their
    /// generations and ledger, while the three deterministic Astra fields are
    /// filled and persisted on the first read by a current daemon.
    #[test]
    fn a_legacy_registry_is_migrated_without_losing_peers() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("certificates.json");
        let fixture = fixture();
        let state = fixture.registry.state().clone();
        let old_peer = state.peers.clone();
        let old_ledger = state.ledger.clone();
        let expected_policy = AstraIssuancePolicy::standard(
            state.trust_domain_id,
            state.gateway.gateway_wg_public_key,
            state.gateway.server_name.clone(),
        )
        .pin()
        .expect("standard policy");

        let mut legacy = serde_json::to_value(&state).expect("encode state");
        let astra = legacy
            .get_mut("astra")
            .and_then(Value::as_object_mut)
            .expect("astra object");
        astra.remove("astra_policy_fingerprint");
        astra.remove("credential_registry_epoch");
        astra.remove("credential_bindings");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&legacy).expect("encode legacy state"),
        )
        .expect("write legacy state");

        let migrated = CertificateRegistry::load(&path)
            .expect("migrate")
            .expect("registry");
        assert_eq!(migrated.state().peers, old_peer);
        assert_eq!(migrated.state().ledger, old_ledger);
        assert!(migrated
            .state()
            .astra
            .astra_policy_fingerprint
            .fingerprint()
            .matches(expected_policy.fingerprint()));
        assert_eq!(migrated.state().astra.credential_registry_epoch, 1);
        assert!(migrated.state().astra.credential_bindings.is_empty());

        // The migration is durable; a second load takes the normal path.
        let persisted: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("persisted JSON");
        let persisted_astra = persisted
            .get("astra")
            .and_then(Value::as_object)
            .expect("persisted Astra object");
        assert!(persisted_astra.contains_key("astra_policy_fingerprint"));
        assert!(persisted_astra.contains_key("credential_registry_epoch"));
        assert!(persisted_astra.contains_key("credential_bindings"));
        let reloaded = CertificateRegistry::load(&path)
            .expect("reload")
            .expect("registry");
        assert_eq!(reloaded.state(), migrated.state());
    }

    /// The fingerprint mTLS proved resolves to the peer that owns it.
    ///
    /// This is the lookup that replaces the pins of `network.toml`, which
    /// describe only the generation a peer was admitted with and are never
    /// updated afterwards.
    #[test]
    fn the_proved_tls_half_resolves_to_its_peer_and_its_own_pq_half() {
        let fixture = fixture();
        let expected = fixture
            .registry
            .peer(&client_key(2))
            .expect("admitted")
            .state
            .active
            .clone();

        let resolved = fixture
            .registry
            .state()
            .resolve_negotiation_identity(&expected.tls_certificate_fingerprint, 0)
            .expect("resolved");
        assert_eq!(resolved.wg_public_key, client_key(2).to_base64());
        assert_eq!(resolved.name, "workstation");
        assert_eq!(
            resolved.pq_certificate_fingerprint,
            expected.pq_certificate_fingerprint
        );

        // A fingerprint the domain never issued resolves to nobody — an
        // unknown caller must not become an anonymous one.
        assert!(fixture
            .registry
            .state()
            .resolve_negotiation_identity(&Fingerprint::of(b"never issued"), 0)
            .is_none());
    }

    /// An ordinary renewal is issued by the delegated issuer, not by the
    /// anchor the first generation chained to.
    ///
    /// A gateway offering only the anchor would refuse every leaf it has
    /// itself just renewed, which is the whole reason this returns a set.
    #[test]
    fn the_issuer_set_carries_the_delegation_an_ordinary_renewal_uses() {
        let fixture = fixture();
        let anchor = fixture
            .registry
            .state()
            .gateway
            .current_ca_public_key
            .clone();
        assert_eq!(
            fixture.registry.state().client_leaf_issuers(0),
            vec![&anchor],
            "with no delegation installed there is exactly the anchor"
        );

        let issuer = keys();
        let mut state = fixture.registry.state().clone();
        state.issuer = Some(AstraIssuerState {
            issuer_epoch: 1,
            authorization: aether::certificates::authority::AstraIssuerAuthorization {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: domain(),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                gateway_wg_public_key: gateway_key(),
                server_name: SERVER_NAME.into(),
                issuer_epoch: 1,
                pq_issuer_public_key: issuer.public.clone(),
                tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
                allowed_usage:
                    aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: 1_000,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            },
            state: aether::certificates::state::IssuerLifecycle::Active,
        });
        let registry =
            CertificateRegistry::new(fixture._directory.path().join("with-issuer.json"), state);

        assert_eq!(
            registry.state().client_leaf_issuers(0),
            vec![&anchor, &issuer.public]
        );
        // Past its own expiry the delegation signs nothing, whatever its
        // lifecycle field says.
        assert_eq!(registry.state().client_leaf_issuers(1_000), vec![&anchor]);
    }

    fn window() -> TransitionWindow {
        TransitionWindow {
            not_before: 1_000,
            activation_at: 2_000,
            not_after: 3_000,
        }
    }

    fn gateway_transition(
        fixture: &Fixture,
        next: &Keys,
        epoch: u64,
        window: TransitionWindow,
    ) -> GatewayIdentityTransition {
        let gateway = &fixture.registry.state().gateway;
        GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            gateway_identity_epoch: epoch,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            active_gateway_tls_certificate_fingerprint: gateway.active_tls_fingerprint(),
            next_gateway_tls_certificate: None,
            active_gateway_certificate_fingerprint: gateway
                .active_pq_fingerprint()
                .expect("active fingerprint"),
            next_gateway_certificate: Some(leaf(
                &fixture.ca,
                next,
                PqCertificateRole::Gateway,
                &gateway_key(),
                9,
            )),
            window,
            reason: RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.ca.private)
        .expect("sign the transition")
    }

    fn gateway_abort(
        fixture: &Fixture,
        transition: &GatewayIdentityTransition,
        aborted_at: u64,
    ) -> GatewayTransitionAbort {
        GatewayTransitionAbort {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            gateway_identity_epoch: transition.gateway_identity_epoch,
            gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
            aborted_at,
            reason: AbortReason::OperatorCancelled,
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.ca.private)
        .expect("sign the abort")
    }

    #[test]
    fn a_staged_transition_leaves_the_identity_in_service_untouched() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());

        let outcome = fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");

        assert_eq!(outcome, InstallOutcome::Installed);
        let gateway = &fixture.registry.state().gateway;
        assert_eq!(gateway.next_gateway_identity_epoch, Some(2));
        assert_eq!(gateway.activation_at, Some(2_000));
        assert_eq!(gateway.retire_active_at, Some(3_000));
        // The switch belongs to `activation_at`, not to the installation: a
        // staging that changed the served leaf would take the identity out of
        // service the moment the operator came back from the ceremony.
        assert_eq!(gateway.active_gateway_identity_epoch, 1);
        assert!(!gateway.published);

        // And it survives the process: the ceremony is measured in days.
        let reloaded = CertificateRegistry::load(
            fixture
                ._directory
                .path()
                .join("certificates.json")
                .as_path(),
        )
        .expect("reload")
        .expect("registry");
        assert_eq!(
            reloaded.state().gateway.next_gateway_identity_epoch,
            Some(2)
        );
    }

    #[test]
    fn the_same_transition_carried_in_twice_consumes_one_epoch() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");

        let outcome = fixture
            .registry
            .install_gateway_transition(&transition, 1_600)
            .expect("replay");

        assert_eq!(outcome, InstallOutcome::AlreadyPresent);
        assert_eq!(fixture.registry.state().gateway.gateway_decision_epoch, 2);
    }

    #[test]
    fn a_published_gateway_transition_is_promoted_durably_at_not_after() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        fixture
            .registry
            .state
            .gateway
            .mark_published()
            .expect("publish");

        assert!(!fixture
            .registry
            .promote_gateway_if_due(2_999)
            .expect("not due"));
        assert!(fixture
            .registry
            .promote_gateway_if_due(3_000)
            .expect("promote"));
        assert_eq!(
            fixture
                .registry
                .state()
                .gateway
                .active_gateway_identity_epoch,
            2
        );
        assert!(fixture
            .registry
            .state()
            .gateway
            .next_gateway_certificate
            .is_none());

        let reloaded = CertificateRegistry::load(
            fixture
                ._directory
                .path()
                .join("certificates.json")
                .as_path(),
        )
        .expect("reload")
        .expect("registry");
        assert_eq!(reloaded.state().gateway.active_gateway_identity_epoch, 2);
        assert!(!fixture
            .registry
            .promote_gateway_if_due(u64::MAX)
            .expect("idempotent"));
    }

    /// A `CA-PQ` rotation signed by the fixture's anchor and by its successor.
    fn ca_transition(
        fixture: &Fixture,
        next: &Keys,
        window: TransitionWindow,
    ) -> aether::certificates::authority::CaTransition {
        let transition = aether::certificates::authority::CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: fixture.ca.public.authority_fingerprint(),
            next_ca_public_key: next.public.clone(),
            next_ca_fingerprint: next.public.authority_fingerprint(),
            window,
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        };
        transition
            .sign(&fixture.ca.private, &next.private)
            .expect("sign")
    }

    /// §9.1 on the gateway: the anchor is staged, both verify during the
    /// overlap, and the epoch moves only at `not_after`.
    #[test]
    fn a_ca_rotation_keeps_both_anchors_until_the_end_of_its_overlap() {
        let mut fixture = fixture();
        let next = keys();
        let transition = ca_transition(&fixture, &next, window());

        assert!(matches!(
            fixture
                .registry
                .install_ca_transition(&transition, 1_500)
                .expect("install"),
            InstallOutcome::Installed
        ));
        assert_eq!(fixture.registry.state().gateway.ca_epoch, 1);
        assert_eq!(
            fixture.registry.state().client_leaf_issuers(1_999).len(),
            1,
            "prepared, not yet acceptable"
        );
        assert_eq!(
            fixture.registry.state().client_leaf_issuers(2_000).len(),
            2,
            "both anchors verify from activation_at"
        );

        // A repeat of the same signed document consumes nothing.
        assert!(matches!(
            fixture
                .registry
                .install_ca_transition(&transition, 1_600)
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        ));

        fixture.registry.promote_due(2_999).expect("not due");
        assert_eq!(fixture.registry.state().gateway.ca_epoch, 1);

        fixture.registry.promote_due(3_000).expect("promotion");
        assert_eq!(fixture.registry.state().gateway.ca_epoch, 2);
        assert_eq!(
            fixture
                .registry
                .state()
                .gateway
                .current_ca_public_key
                .authority_fingerprint()
                .to_hex(),
            next.public.authority_fingerprint().to_hex()
        );
        assert_eq!(
            fixture.registry.state().client_leaf_issuers(3_000).len(),
            1,
            "the outgoing anchor is gone, not merely unpreferred"
        );
    }

    /// The promotion is persisted, not merely computed: a restart must find
    /// the same anchor the pass moved to.
    #[test]
    fn the_promoted_anchor_survives_a_reopen() {
        let mut fixture = fixture();
        let next = keys();
        let transition = ca_transition(&fixture, &next, window());
        fixture
            .registry
            .install_ca_transition(&transition, 1_500)
            .expect("install");
        fixture.registry.promote_due(3_000).expect("promotion");

        let reopened = CertificateRegistry::load(&fixture.registry.path)
            .expect("load")
            .expect("registry on disk");
        assert_eq!(reopened.state().gateway.ca_epoch, 2);
        assert!(reopened.state().gateway.next_ca_public_key.is_none());
    }

    /// Two anchors at most: a second, different rotation while one is in
    /// flight would leave three, of which the domain names two.
    #[test]
    fn a_second_ca_rotation_is_refused_while_one_is_in_flight() {
        let mut fixture = fixture();
        let first = keys();
        let second = keys();
        fixture
            .registry
            .install_ca_transition(&ca_transition(&fixture, &first, window()), 1_500)
            .expect("install");

        let refusal = fixture
            .registry
            .install_ca_transition(&ca_transition(&fixture, &second, window()), 1_500)
            .expect_err("second rotation");
        assert!(matches!(
            refusal,
            RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
        ));
    }

    /// A rotation whose activation has already passed installs nothing: it
    /// would take effect the instant it landed, on a fleet that never saw it.
    #[test]
    fn a_ca_rotation_activating_in_the_past_is_refused() {
        let mut fixture = fixture();
        let next = keys();
        let refusal = fixture
            .registry
            .install_ca_transition(&ca_transition(&fixture, &next, window()), 2_500)
            .expect_err("late");
        assert!(matches!(
            refusal,
            RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
        ));
        assert!(fixture
            .registry
            .state()
            .gateway
            .next_ca_public_key
            .is_none());
    }

    /// A rollback authorization signed by the fixture's `CA-PQ` for its own
    /// staged overlap.
    fn rollback(
        fixture: &Fixture,
        transition: &GatewayIdentityTransition,
        expires_at: u64,
    ) -> aether::certificates::status::CertificateServiceRollbackAuthorization {
        let gateway = &fixture.registry.state().gateway;
        let authorization = aether::certificates::status::CertificateServiceRollbackAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            transition_fingerprint: transition.fingerprint().expect("fingerprint"),
            selected_certificate_fingerprint: gateway.active_tls_fingerprint(),
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            expires_at,
            ca_signature: MlDsa87Signature::placeholder(),
        };
        authorization.sign(&fixture.ca.private).expect("sign")
    }

    /// §11.1 step 8: the selection is persisted, and it moves nothing else —
    /// the promotion still fires at `not_after`, and it takes the selection
    /// with it.
    #[test]
    fn a_gateway_rollback_is_persisted_and_dies_with_the_overlap_it_lives_in() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        fixture
            .registry
            .publish_gateway_transition(2, &transition.fingerprint().expect("fingerprint"))
            .expect("publish");

        let authorization = rollback(&fixture, &transition, 2_800);
        assert!(matches!(
            fixture
                .registry
                .install_gateway_rollback(&authorization, 2_100)
                .expect("rollback"),
            InstallOutcome::Installed
        ));
        assert!(fixture.registry.active_gateway_rollback(2_100).is_some());
        assert_eq!(
            fixture
                .registry
                .state()
                .gateway
                .active_gateway_identity_epoch,
            1,
            "a service rollback moves no counter"
        );
        assert_eq!(
            fixture.registry.state().gateway.next_gateway_identity_epoch,
            Some(2),
            "and removes no slot"
        );

        assert!(fixture
            .registry
            .promote_gateway_if_due(3_000)
            .expect("promotion"));
        assert!(fixture.registry.active_gateway_rollback(3_000).is_none());
    }

    /// Before publication there is nothing to roll back from: the outgoing
    /// leaf is still the one served, and an abort is the gesture that applies.
    #[test]
    fn a_gateway_rollback_is_refused_outside_the_overlap() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");

        let authorization = rollback(&fixture, &transition, 2_800);
        let refusal = fixture
            .registry
            .install_gateway_rollback(&authorization, 2_100)
            .expect_err("unpublished");
        assert!(matches!(
            refusal,
            RegistryError::Certificate(CertificateError::RollbackUnavailable)
        ));
        assert!(fixture.registry.active_gateway_rollback(2_100).is_none());
    }

    #[test]
    fn an_unpublished_gateway_transition_never_reaches_the_active_slot() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");

        let refusal = fixture
            .registry
            .promote_gateway_if_due(3_000)
            .expect_err("unpublished transition");

        assert!(matches!(
            refusal,
            RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
        ));
        assert_eq!(
            fixture
                .registry
                .state()
                .gateway
                .active_gateway_identity_epoch,
            1
        );
        assert_eq!(
            fixture.registry.state().gateway.next_gateway_identity_epoch,
            Some(2)
        );
    }

    #[test]
    fn a_second_transition_is_refused_while_one_is_staged() {
        let mut fixture = fixture();
        let first = keys();
        let second = keys();
        let transition = gateway_transition(&fixture, &first, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");

        let refusal = fixture
            .registry
            .install_gateway_transition(&gateway_transition(&fixture, &second, 3, window()), 1_500)
            .expect_err("a second candidate at once");

        assert!(matches!(
            refusal,
            RegistryError::Certificate(CertificateError::IllegalStateTransition(_))
        ));
    }

    #[test]
    fn an_abort_clears_the_slot_and_leaves_the_epoch_consumed() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        let abort = gateway_abort(&fixture, &transition, 1_600);

        let outcome = fixture
            .registry
            .abort_gateway_transition(&abort, &transition, 1_700)
            .expect("abort");

        assert_eq!(outcome, InstallOutcome::Installed);
        let gateway = &fixture.registry.state().gateway;
        assert_eq!(gateway.next_gateway_identity_epoch, None);
        assert!(gateway.next_gateway_certificate.is_none());
        // The number stays spent. A client holding the tombstone refuses a
        // second decision at the same epoch, and it is right to.
        assert_eq!(gateway.gateway_decision_epoch, 2);
        assert!(gateway.last_aborted_transition.is_some());
    }

    /// §6.3: `revoked` dominates every phase and every date, and nothing
    /// local repairs it.
    #[test]
    fn revoking_the_served_leaf_is_terminal_for_the_gateway() {
        let mut fixture = fixture();
        let active_pq = fixture
            .registry
            .state()
            .gateway
            .active_pq_fingerprint()
            .expect("active fingerprint");

        let hit = fixture
            .registry
            .revoke_gateway(None, Some(&active_pq), 1, None)
            .expect("revoked");

        assert!(hit);
        let gateway = &fixture.registry.state().gateway;
        assert!(gateway.revoked);
        assert_eq!(gateway.revocation_epoch, 1);
    }

    /// §10.1 followed by §6.1, on the registry: a withdrawal that names its
    /// replacement is recoverable, and the replacement is served at once —
    /// there is no outgoing identity left to overlap with.
    #[test]
    fn a_revocation_naming_a_replacement_lets_the_gateway_come_back() {
        let mut fixture = fixture();
        let next = keys();
        let mut replacement = gateway_transition(&fixture, &next, 2, window());
        replacement.reason = RotationReason::EmergencyReplacement;
        let replacement = replacement.sign(&fixture.ca.private).expect("sign");
        let named = replacement.fingerprint().expect("fingerprint");
        let active_pq = fixture
            .registry
            .state()
            .gateway
            .active_pq_fingerprint()
            .expect("active fingerprint");

        assert!(fixture
            .registry
            .revoke_gateway(None, Some(&active_pq), 1, Some(&named))
            .expect("revoked"));
        assert!(fixture.registry.state().gateway.revoked);

        assert!(matches!(
            fixture
                .registry
                .install_gateway_transition(&replacement, 1_500)
                .expect("replacement"),
            InstallOutcome::Installed
        ));
        let gateway = &fixture.registry.state().gateway;
        assert!(!gateway.revoked);
        assert_eq!(gateway.active_gateway_identity_epoch, 2);
        assert!(gateway.next_gateway_identity_epoch.is_none());
        assert_eq!(
            gateway.revocation_epoch, 1,
            "the revocation counter never comes back down"
        );

        // And it survives a reopen: the decision is on disk, not in a clone.
        let reopened = CertificateRegistry::load(&fixture.registry.path)
            .expect("load")
            .expect("registry on disk");
        assert!(!reopened.state().gateway.revoked);
        assert_eq!(reopened.state().gateway.active_gateway_identity_epoch, 2);
    }

    /// A decision about a leaf this gateway never held is not an error — an
    /// offline document carries the fleet's decisions — but its counter is
    /// consumed, which is what stops that leaf arriving later by transition.
    #[test]
    fn revoking_a_leaf_this_gateway_never_held_consumes_the_counter() {
        let mut fixture = fixture();
        let stranger = Fingerprint::of(b"a leaf from elsewhere");

        let hit = fixture
            .registry
            .revoke_gateway(Some(&stranger), None, 4, None)
            .expect("recorded");

        assert!(!hit);
        let gateway = &fixture.registry.state().gateway;
        assert!(!gateway.revoked, "the identity in service is untouched");
        assert_eq!(gateway.revocation_epoch, 4);
    }

    /// A revocation reaching only the staged generation withdraws it and
    /// leaves the identity in service `active` (§6.3).
    #[test]
    fn revoking_the_staged_candidate_leaves_the_served_identity_active() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        let staged = aether::certificates::gateway::pq_certificate_fingerprint(
            transition
                .next_gateway_certificate
                .as_ref()
                .expect("staged leaf"),
        )
        .expect("fingerprint");

        let hit = fixture
            .registry
            .revoke_gateway(None, Some(&staged), 2, None)
            .expect("revoked");

        assert!(hit);
        let gateway = &fixture.registry.state().gateway;
        assert!(!gateway.revoked);
        assert_eq!(gateway.next_gateway_identity_epoch, None);
        assert_eq!(gateway.revocation_epoch, 2);
    }

    fn client_tls_ca_transition(
        fixture: &Fixture,
        current_epoch: u64,
        active: Fingerprint,
        window: TransitionWindow,
    ) -> aether::certificates::authority::ClientTlsCaTransition {
        use aether::certificates::authority::ClientTlsCaTransition;

        ClientTlsCaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            current_ca_tls_epoch: current_epoch,
            next_ca_tls_epoch: current_epoch + 1,
            active_client_tls_ca_fingerprint: active,
            next_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
                "successor",
            )
            .authority,
            window,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.ca.private)
        .expect("sign the rotation")
    }

    fn gateway_delegation_naming(
        ca: &Keys,
        policy_fingerprint: Fingerprint,
    ) -> aether::certificates::authority::AstraIssuerAuthorization {
        let (_, issuer_public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
        aether::certificates::authority::AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer_public,
            tls_intermediate_certificate: aether::certificates::test_x509::certificate_authority(
                "astra-issuer",
            ),
            allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 200_000,
            policy_fingerprint,
            not_before: 0,
            not_after: 1_000_000,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        }
        .sign(&ca.private)
        .expect("sign delegation")
    }

    /// Pins this fixture's registry to the superseded policy, as a gateway
    /// bootstrapped before the amendment of 6 September 2026 holds it.
    fn pin_to_superseded(fixture: &mut Fixture) -> Fingerprint {
        let superseded = aether::certificates::approval::superseded_per_request_policy_fingerprint(
            domain(),
            gateway_key(),
            SERVER_NAME,
        )
        .expect("superseded");
        let mut candidate = fixture.registry.state().clone();
        candidate.astra.astra_policy_fingerprint =
            aether::certificates::approval::AstraPolicyPin::new(superseded).expect("pin");
        fixture.registry.persist(candidate).expect("pinned");
        superseded
    }

    /// The gateway pins the policy for itself, so it has to be carried across
    /// by the same `CA-PQ`-signed evidence — and carrying it must move nothing
    /// else, least of all the peers whose renewals depend on their generation.
    #[test]
    fn a_superseded_gateway_pin_adopts_the_current_policy_and_keeps_every_peer() {
        use aether::certificates::approval::PolicyMigration;

        let mut fixture = fixture();
        pin_to_superseded(&mut fixture);
        let peers_before = fixture.registry.state().peers.clone();
        let ledger_before = fixture.registry.state().ledger.clone();
        let current = aether::certificates::approval::AstraIssuancePolicy::standard(
            domain(),
            gateway_key(),
            SERVER_NAME.into(),
        )
        .fingerprint()
        .expect("current");

        let migration = fixture
            .registry
            .install_astra_issuer(&gateway_delegation_naming(&fixture.ca, current), 1_000)
            .expect("migration");

        assert!(matches!(migration, PolicyMigration::Adopted(_)));
        assert!(fixture
            .registry
            .state()
            .astra
            .astra_policy_fingerprint
            .fingerprint()
            .matches(&current));
        // Without this the negotiation port cannot authenticate a renewed
        // leaf, and the staging check would refuse every candidate Astra
        // issues under the delegation it just accepted.
        let issuer = fixture
            .registry
            .state()
            .issuer
            .as_ref()
            .expect("the delegation is recorded");
        assert_eq!(issuer.issuer_epoch, 1);
        assert!(fixture
            .registry
            .state()
            .client_leaf_issuers(1_000)
            .contains(&&issuer.authorization.pq_issuer_public_key));
        assert_eq!(fixture.registry.state().peers, peers_before);
        assert_eq!(fixture.registry.state().ledger, ledger_before);
    }

    /// A spent epoch carrying different bytes is a substitution, not the
    /// replay of a delegation whose delivery was lost.
    #[test]
    fn a_delegation_that_does_not_advance_its_epoch_is_refused() {
        let mut fixture = fixture();
        pin_to_superseded(&mut fixture);
        let current = aether::certificates::approval::AstraIssuancePolicy::standard(
            domain(),
            gateway_key(),
            SERVER_NAME.into(),
        )
        .fingerprint()
        .expect("current");
        let installed = gateway_delegation_naming(&fixture.ca, current);
        fixture
            .registry
            .install_astra_issuer(&installed, 1_000)
            .expect("first install");

        // The same bytes again are a replay, and stay accepted.
        fixture
            .registry
            .install_astra_issuer(&installed, 1_000)
            .expect("replaying the same delegation is idempotent");

        // Different bytes at the same epoch are not.
        assert!(matches!(
            fixture
                .registry
                .install_astra_issuer(&gateway_delegation_naming(&fixture.ca, current), 1_000),
            Err(RegistryError::IssuerEpochNotAdvancing {
                installed: 1,
                offered: 1
            })
        ));
    }

    /// The evidence has to be this domain's. A delegation signed by another
    /// anchor names the right policy and still moves nothing.
    #[test]
    fn a_delegation_from_another_anchor_never_moves_the_gateway_pin() {
        let mut fixture = fixture();
        let superseded = pin_to_superseded(&mut fixture);
        let current = aether::certificates::approval::AstraIssuancePolicy::standard(
            domain(),
            gateway_key(),
            SERVER_NAME.into(),
        )
        .fingerprint()
        .expect("current");
        let stranger = keys();

        assert!(fixture
            .registry
            .install_astra_issuer(&gateway_delegation_naming(&stranger, current), 1_000)
            .is_err());
        assert!(fixture
            .registry
            .state()
            .astra
            .astra_policy_fingerprint
            .fingerprint()
            .matches(&superseded));
    }

    /// The migration fixes the bootstrap metadata and nothing else: peer
    /// identities, revocations and queued signed distributions survive the
    /// same atomic write.
    #[test]
    fn the_legacy_admission_ca_bootstrap_is_repaired_without_reenrolling_peers() {
        let mut fixture = fixture();
        let admission_ca = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .clone();
        let admission_fingerprint = admission_ca.fingerprint();
        let peer_key = client_key(2).to_base64();
        let peer = fixture
            .registry
            .state
            .peers
            .get_mut(&peer_key)
            .expect("peer");
        peer.state.active.generation = 1;
        peer.state.active.ca_tls_epoch = 1;
        peer.state.active.tls_ca_certificate_fingerprint = admission_fingerprint;
        let (manifest, chunks) = distribution(&client_key(2), 2, 10_000);
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0)
            .expect("queue a signed distribution");
        let peer = fixture.registry.state().peers.get(&peer_key).expect("peer");
        let peer_before = peer.clone();
        let ledger_before = fixture.registry.state().ledger.clone();
        let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
        let domain_fingerprint = domain_ca.fingerprint();

        assert_eq!(
            fixture
                .registry
                .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
                .expect("repair"),
            BootstrapRepairOutcome::Repaired
        );

        let state = fixture.registry.state();
        assert!(state
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&domain_fingerprint));
        let peer_after = state.peers.get(&peer_key).expect("peer preserved");
        assert_eq!(peer_after.name, peer_before.name);
        assert_eq!(
            peer_after.active_pq_certificate,
            peer_before.active_pq_certificate
        );
        assert_eq!(peer_after.distribution, peer_before.distribution);
        assert_eq!(state.ledger, ledger_before);
        assert!(peer_after
            .state
            .active
            .tls_ca_certificate_fingerprint
            .matches(&domain_fingerprint));

        let reloaded = CertificateRegistry::load(&fixture.registry.path)
            .expect("read repaired registry")
            .expect("registry present");
        assert_eq!(reloaded.state(), fixture.registry.state());
        assert_eq!(
            fixture
                .registry
                .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
                .expect("idempotent repair"),
            BootstrapRepairOutcome::AlreadyCorrect
        );
    }

    /// Once any peer has moved, rewriting its generation-one anchor would be
    /// an unsigned rotation rather than a bootstrap correction.
    #[test]
    fn the_legacy_bootstrap_repair_refuses_a_peer_that_already_moved() {
        let mut fixture = fixture();
        let admission_ca = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .clone();
        fixture.registry.state.peers.values_mut().for_each(|peer| {
            peer.state.active.tls_ca_certificate_fingerprint = admission_ca.fingerprint();
        });
        let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
        let before = fixture.registry.state().clone();

        let error = fixture
            .registry
            .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
            .expect_err("generation four is not a bootstrap state");

        assert!(matches!(
            error,
            RegistryError::LegacyClientTlsCaRepair(
                "at least one peer has left its untouched first generation"
            )
        ));
        assert_eq!(fixture.registry.state(), &before);
    }

    #[test]
    fn the_legacy_bootstrap_repair_refuses_a_foreign_active_anchor() {
        let mut fixture = fixture();
        let admission_ca = aether::certificates::test_x509::client_material("operator").authority;
        let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
        let before = fixture.registry.state().clone();

        let error = fixture
            .registry
            .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
            .expect_err("only the exact operator admission CA can be replaced");

        assert!(matches!(
            error,
            RegistryError::LegacyClientTlsCaRepair(
                "the active anchor is not the operator admission CA"
            )
        ));
        assert_eq!(fixture.registry.state(), &before);
    }

    #[test]
    fn the_bootstrap_repair_is_a_no_op_after_a_signed_rotation_epoch() {
        let mut fixture = fixture();
        let admission_ca = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .clone();
        fixture.registry.state.client_tls_ca.ca_tls_epoch = 2;
        let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
        let before = fixture.registry.state().clone();

        assert_eq!(
            fixture
                .registry
                .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
                .expect("a later signed epoch needs no bootstrap repair"),
            BootstrapRepairOutcome::LaterEpoch
        );
        assert_eq!(fixture.registry.state(), &before);
    }

    /// §9.4: both chains are acceptable during the overlap, and only then.
    #[test]
    fn a_client_tls_ca_rotation_is_accepted_from_its_activation() {
        let mut fixture = fixture();
        let active = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint();
        let transition = client_tls_ca_transition(&fixture, 1, active, window());

        fixture
            .registry
            .install_client_tls_ca_transition(&transition, 1_500)
            .expect("install");

        let anchors = fixture.registry.state().client_tls_anchors(1_999);
        assert_eq!(
            anchors.len(),
            1,
            "before activation only the anchor in service"
        );
        assert_eq!(fixture.registry.state().client_tls_anchors(2_000).len(), 2);
    }

    /// At `not_after` the outgoing anchor is gone, on the same write that
    /// promotes the peers: a sweep that moved one without the other would keep
    /// accepting a chain the domain retired.
    #[test]
    fn the_outgoing_client_tls_anchor_retires_with_the_generations() {
        let mut fixture = fixture();
        let active = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint();
        let transition = client_tls_ca_transition(&fixture, 1, active, window());
        fixture
            .registry
            .install_client_tls_ca_transition(&transition, 1_500)
            .expect("install");

        fixture.registry.promote_due(3_000).expect("promote");

        let state = fixture.registry.state();
        assert_eq!(state.client_tls_ca.ca_tls_epoch, 2);
        assert!(state.client_tls_ca.next_client_tls_ca_certificate.is_none());
        assert_eq!(fixture.registry.state().client_tls_anchors(3_000).len(), 1);
        assert!(
            !fixture
                .registry
                .state()
                .client_tls_ca
                .active_client_tls_ca_certificate
                .fingerprint()
                .matches(&active),
            "the successor is the one in service"
        );
    }

    /// One rotation in flight at a time: a second would leave two successors
    /// and no rule saying which the next handshake is verified under.
    #[test]
    fn a_second_client_tls_ca_rotation_is_refused_while_one_is_in_flight() {
        let mut fixture = fixture();
        let active = fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint();
        fixture
            .registry
            .install_client_tls_ca_transition(
                &client_tls_ca_transition(&fixture, 1, active, window()),
                1_500,
            )
            .expect("install");

        assert!(fixture
            .registry
            .install_client_tls_ca_transition(
                &client_tls_ca_transition(&fixture, 1, active, window()),
                1_500,
            )
            .is_err());
    }

    #[test]
    fn a_publication_names_the_document_it_lets_go() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        let fingerprint = transition.fingerprint().expect("fingerprint");

        // Another document at the same epoch: an operator may have installed
        // one transition by hand while the authority published another.
        let other = gateway_transition(&fixture, &keys(), 2, window());
        assert!(fixture
            .registry
            .publish_gateway_transition(2, &other.fingerprint().expect("fingerprint"))
            .is_err());
        // The right document at the wrong epoch is no better.
        assert!(fixture
            .registry
            .publish_gateway_transition(3, &fingerprint)
            .is_err());
        assert!(!fixture.registry.state().gateway.published);

        fixture
            .registry
            .publish_gateway_transition(2, &fingerprint)
            .expect("published");
        assert!(fixture.registry.state().gateway.published);
        // A retry of a relay the authority could not confirm is not a second
        // decision.
        fixture
            .registry
            .publish_gateway_transition(2, &fingerprint)
            .expect("idempotent");
    }

    #[test]
    fn an_abort_is_refused_once_the_transition_has_been_published() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        // What §6.3 makes irreversible: past this marker a client may already
        // hold the decision, go offline and promote on its own at `not_after`.
        let mut published = fixture.registry.state().clone();
        published.gateway.published = true;
        let mut registry =
            CertificateRegistry::new(fixture._directory.path().join("published.json"), published);
        let abort = gateway_abort(&fixture, &transition, 1_600);

        let refusal = registry
            .abort_gateway_transition(&abort, &transition, 1_700)
            .expect_err("an abort after publication");

        assert!(matches!(refusal, RegistryError::Certificate(_)));
        assert_eq!(
            registry.state().gateway.next_gateway_identity_epoch,
            Some(2)
        );
    }

    #[test]
    fn an_abort_is_refused_once_the_local_clock_reaches_activation() {
        let mut fixture = fixture();
        let next = keys();
        let transition = gateway_transition(&fixture, &next, 2, window());
        fixture
            .registry
            .install_gateway_transition(&transition, 1_500)
            .expect("install");
        // Backdated inside the document, read against a clock that has moved
        // past `activation_at`: the overlap has begun and cancelling it here
        // would leave two truths in the fleet.
        let abort = gateway_abort(&fixture, &transition, 1_600);

        let refusal = fixture
            .registry
            .abort_gateway_transition(&abort, &transition, 2_400)
            .expect_err("an abort during the overlap");

        assert!(matches!(refusal, RegistryError::Certificate(_)));
        assert_eq!(
            fixture.registry.state().gateway.next_gateway_identity_epoch,
            Some(2)
        );
    }
}
