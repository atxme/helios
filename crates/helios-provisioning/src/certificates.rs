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

mod distribution;
mod persistence;
mod staging;
mod transitions;
mod trust;

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
}

#[cfg(all(test, feature = "certificate-signing"))]
#[path = "certificates/tests/mod.rs"]
mod tests;
