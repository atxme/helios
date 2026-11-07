//! Astra's registry: what the authority knows about its domain.
//!
//! It is deliberately **not** a second copy of the gateway's admission. The
//! gateway decides who is admitted; Astra records which generation each
//! admitted identity is on, so it can answer three questions no one else can:
//! is this certificate the newest one, is it revoked, and when should its
//! owner renew it.
//!
//! # A restore is not a resume
//!
//! The registry ships with its audit chain, and [`AstraRegistry::load`] refuses
//! a file whose chain does not continue the head the operator recorded. A
//! backup that verifies internally but ends elsewhere is a fork, and an
//! authority that continued one would be issuing under two histories at once.

mod challenge;
mod delegation;
mod peer_lifecycle;
mod persistence;
mod transitions;

use std::collections::BTreeMap;
use std::path::PathBuf;

use aether::certificates::{
    approval::{AstraIssuancePolicy, AstraPolicyPin},
    client::ClientCertificateGeneration,
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey},
    state::AstraIssuerState,
    window::TransitionWindow,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditChain, AuditError, AuditEvent};

pub use challenge::{ChallengeStore, CHALLENGE_LIFETIME_SECS};

/// What Astra records about one admitted identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRecord {
    pub name: String,
    pub client_wg_public_key: WireGuardKey,
    /// Newest generation Astra has released a grant for.
    pub active: ClientCertificateGeneration,
    /// PQ leaf of that generation, kept to verify the proofs a renewal or a
    /// recovery carries.
    pub active_pq_certificate: aether::key_negotiation::PqCertificate,
    pub pending: Option<PendingRotation>,
    /// Terminal. No credential lifts it; only a fresh admission creates a new
    /// identity (spec §10.2).
    pub revoked: bool,
    pub revocation_epoch: u64,
    /// The operator admission anchor the gateway named when it transcribed
    /// this peer.
    ///
    /// A first-generation leaf is signed by it and by nothing this domain
    /// holds: enrolment is offline, so `CA-PQ` cannot sign it. Recorded so a
    /// §7.5 recovery can verify a leaf that has never been renewed — the only
    /// population that recovery is for.
    #[serde(default)]
    pub admission_pq_ca: Option<MlDsa87PublicKey>,
}

/// A rotation in flight, from the authority's point of view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRotation {
    pub stage_id: Id16,
    pub request_fingerprint: Fingerprint,
    pub candidate: ClientCertificateGeneration,
    pub window: TransitionWindow,
    pub stage_expires_at: u64,
    /// `true` once the grant has been released — the point past which Astra
    /// has nothing left to withhold.
    pub granted: bool,
}

/// One anchor transition the operator companion signed, held for delivery.
///
/// # Why the authority stores an object it cannot produce
///
/// §0.6 splits the two halves of a trust mutation. `CA-PQ` signs the object,
/// once, in the companion — the only program that ever holds it in the clear.
/// This authority's service key then signs as many per-client manifests as
/// there are peers to reach. Storing the object is therefore storing something
/// the storer could never forge, which is exactly what makes an online copy of
/// it harmless: a compromised service key can delay, omit or reorder delivery,
/// and cannot invent a single transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTransition {
    /// The campaign whose approval produced it. Audited, and the reason a
    /// stored object can always be traced back to a text an operator read.
    pub campaign_id: Id16,
    pub accepted_at: u64,
    /// Whether this object may leave the authority (spec §6.3).
    ///
    /// Only a gateway transition is held back: a `CA-PQ` transition and a
    /// revocation are distributable the moment they are accepted, while §11.1
    /// makes publication a step of its own — the last instant at which an
    /// operator may still cancel. Defaulted, so a registry written before this
    /// field existed still loads; the objects it holds are not gateway
    /// transitions, which could not be stored at all back then.
    #[serde(default)]
    pub published: bool,
    pub object: aether::certificates::transport::TrustUpdateObject,
    /// Operator credential rows re-signed under the anchor this object
    /// installs, when it installs one.
    ///
    /// Carried with the transition rather than beside it: a successor anchor
    /// and a credential document only its predecessor can verify would leave
    /// the domain unable to approve anything again — on the one path that
    /// repairs a domain.
    #[serde(default)]
    pub credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
}

/// Largest number of anchor transitions the registry keeps at once.
///
/// An anchor rotates on a human timescale and its overlap is measured in
/// weeks, so more than a handful alive means something is re-depositing. The
/// ceiling is a refusal, never an eviction: dropping the oldest would drop the
/// one a lagging peer is still missing.
pub const MAX_STORED_TRANSITIONS: usize = 8;
/// Revocations retained for redistribution while their signed leaves live.
///
/// Aligned with the holder-side tombstone ledger: accepting more here than a
/// recipient can remember would only defer a deterministic refusal.
pub const MAX_STORED_REVOCATIONS: usize = aether::certificates::state::MAX_REVOCATION_TOMBSTONES;

/// The incoming `CA-PQ` anchor Astra has accepted but not yet adopted.
///
/// The signed transition remains in the bounded public store. Keeping the
/// successor and its window together here makes the authority's active/next
/// state explicit and lets retirement move the pin without consulting an
/// object that may already have been pruned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaPqRotation {
    pub next_ca_epoch: u64,
    pub next_ca_public_key: MlDsa87PublicKey,
    pub activation_at: u64,
    pub retire_active_at: u64,
}

impl CaPqRotation {
    fn from_transition(transition: &aether::certificates::authority::CaTransition) -> Self {
        Self {
            next_ca_epoch: transition.next_ca_epoch,
            next_ca_public_key: transition.next_ca_public_key.clone(),
            activation_at: transition.window.activation_at,
            retire_active_at: transition.window.not_after,
        }
    }
}

/// The incoming client TLS anchor Astra has accepted but not yet adopted.
///
/// The complete certificate remains in the signed transition held below. The
/// registry only needs the state that becomes authoritative at retirement,
/// kept together so a partially described window is not representable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsCaRotation {
    pub next_ca_tls_epoch: u64,
    pub next_ca_tls_fingerprint: Fingerprint,
    pub activation_at: u64,
    pub retire_active_at: u64,
}

impl ClientTlsCaRotation {
    fn from_transition(
        transition: &aether::certificates::authority::ClientTlsCaTransition,
    ) -> Self {
        Self {
            next_ca_tls_epoch: transition.next_ca_tls_epoch,
            next_ca_tls_fingerprint: transition.next_client_tls_ca_certificate.fingerprint(),
            activation_at: transition.window.activation_at,
            retire_active_at: transition.window.not_after,
        }
    }
}

/// Everything Astra persists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraState {
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub authority_url: String,
    pub webauthn_rp_id: String,
    pub astra_policy_fingerprint: AstraPolicyPin,
    pub credential_registry_epoch: u64,

    pub ca_epoch: u64,
    pub ca_public_key: MlDsa87PublicKey,
    /// Signed `CA-PQ` successor awaiting retirement of the active anchor.
    ///
    /// Additive and defaulted so a registry written while Astra only
    /// redistributed this transition can recover the slot from that signed
    /// object when it next loads.
    #[serde(default)]
    pub ca_rotation: Option<CaPqRotation>,
    pub ca_tls_epoch: u64,
    /// SHA-256 of the client `CA-TLS` in service, confirmed out of band.
    ///
    /// `None` on a domain bootstrapped before this field existed. It is not
    /// defaulted to a placeholder, because a placeholder would be a value
    /// `ClientTlsCaTransition::verify` compares against and always accepts —
    /// pinning an epoch without pinning the anchor is what made a `CA-TLS`
    /// rotation impossible to check at all. Absent, the rotation is refused by
    /// name; `astra pin-ca-tls` records it once.
    #[serde(default)]
    pub ca_tls_fingerprint: Option<Fingerprint>,
    /// Signed `CA-TLS` successor awaiting retirement of the active anchor.
    ///
    /// Additive and defaulted so a registry written before Astra adopted the
    /// anchor it distributes still loads with no rotation in flight.
    #[serde(default)]
    pub ca_tls_rotation: Option<ClientTlsCaRotation>,

    pub astra_service_key_epoch: u64,
    pub astra_service_public_key: MlDsa87PublicKey,

    pub issuer: Option<AstraIssuerState>,
    /// Anchor transitions accepted from an approved authority campaign.
    ///
    /// Additive and defaulted: the file is on disk, and a registry written
    /// before this field existed must still load. A version bump would refuse
    /// the whole domain to add a list that starts empty.
    #[serde(default)]
    pub transitions: Vec<StoredTransition>,
    /// The credential document re-signed under the `CA-PQ` that was just
    /// promoted, until the file and the memory of the daemon carry it.
    ///
    /// Written in the same atomic registry write as the promotion, so a crash
    /// between the promotion and the file leaves the document here rather than
    /// a file signed under an anchor nobody pins any more. Cleared by
    /// [`AstraRegistry::take_promoted_credentials`] once adopted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_credentials: Option<Box<aether::certificates::approval::CredentialRegistry>>,
    pub peers: BTreeMap<String, PeerRecord>,
    /// Monotonic status counter per certificate fingerprint (spec §4.2).
    pub status_epochs: BTreeMap<String, u64>,
    pub audit: AuditChain,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("unknown peer")]
    UnknownPeer,
    #[error(
        "this authority already records generation {held} for that peer: adopting {offered} \
         would walk a client identity backwards"
    )]
    GenerationRegression { held: u64, offered: u64 },
    #[error(
        "generation {generation} is recorded here under a different leaf than the one served: \
         one number, two histories"
    )]
    GenerationDisagrees { generation: u64 },
    #[error("the gateway and this authority disagree about the peer's terminal revocation state")]
    RevocationDisagrees,
    #[error("the gateway offered another admission anchor for an existing peer")]
    AdmissionAnchorDisagrees,
    #[error("peer is revoked; no credential lifts that state")]
    Revoked,
    #[error("a rotation is already in flight for this peer")]
    RotationInFlight,
    #[error("no rotation in flight for this peer")]
    NoRotation,
    #[error("audit chain: {0}")]
    Audit(#[from] AuditError),
    #[error("registry input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("registry is unreadable: {0}")]
    Corrupt(String),
    #[error(
        "this authority already holds the delegation of epoch {installed}: installing epoch \
         {offered} would walk an issuer decision backwards"
    )]
    IssuerEpochNotAdvancing { installed: u64, offered: u64 },
    #[error(
        "this authority already holds {held} anchor transitions, the ceiling of \
         {MAX_STORED_TRANSITIONS}: a peer that is still missing one must not have it dropped to \
         make room"
    )]
    TransitionStoreFull { held: usize },
    #[error(
        "this authority already holds {held} live revocations, the ceiling of \
         {MAX_STORED_REVOCATIONS}; no live decision is evicted to make room"
    )]
    RevocationStoreFull { held: usize },
    #[error("the transition this campaign produced is refused: {0}")]
    Transition(#[from] aether::certificates::CertificateError),
}

/// The registry and its file.
#[derive(Debug)]
pub struct AstraRegistry {
    path: PathBuf,
    state: AstraState,
}

impl RegistryError {
    /// The registry could not be written, which nothing a caller sent is at fault
    /// for. The only two ways [`AstraRegistry::save`] fails.
    pub(crate) fn is_write_failure(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Corrupt(_))
    }
}

impl AstraRegistry {
    pub fn new(path: PathBuf, state: AstraState) -> Self {
        Self { path, state }
    }

    pub fn state(&self) -> &AstraState {
        &self.state
    }

    pub fn audit_head(&self) -> Fingerprint {
        self.state.audit.head()
    }

    pub fn save(&self) -> Result<(), RegistryError> {
        let encoded = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
        Ok(())
    }

    pub fn record(&mut self, event: AuditEvent, now_unix: u64) -> Result<(), RegistryError> {
        self.state.audit.append(event, now_unix);
        self.save()
    }

    /// Runs one write, and leaves memory exactly as it was if the write fails.
    ///
    /// A write changes the state and then saves it, so a save that fails
    /// leaves memory ahead of the file. A command that exits on the error
    /// throws that memory away; a service that keeps running would act on it —
    /// relay a publication the file does not hold, or persist an anchor with
    /// the next unrelated save. Restored, memory is what the file says, or at
    /// worst behind it when a save failed after its rename, which the same
    /// write asked again repairs.
    pub fn write_or_restore<T, E>(
        &mut self,
        write: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let before = self.state.clone();
        let outcome = write(self);
        if outcome.is_err() {
            self.state = before;
        }
        outcome
    }
}

#[cfg(test)]
#[path = "registry/tests/mod.rs"]
mod tests;
