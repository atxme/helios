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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aether::certificates::{
    approval::{AstraIssuancePolicy, AstraPolicyPin},
    client::ClientCertificateGeneration,
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey},
    state::AstraIssuerState,
    window::TransitionWindow,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditChain, AuditError, AuditEvent};

/// Lifetime of a public status challenge: 60 seconds, single use (spec §8.2).
pub const CHALLENGE_LIFETIME_SECS: u64 = 60;

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

impl AstraRegistry {
    pub fn new(path: PathBuf, state: AstraState) -> Self {
        Self { path, state }
    }

    /// Loads the registry, refusing a chain that forks away from `expected_head`.
    ///
    /// A registry written before [`AstraState::astra_policy_fingerprint`] and
    /// `credential_registry_epoch` existed is **migrated** rather than
    /// refused — see [`Self::migrate`]. Refusing it would leave an operator
    /// with an authority that has a history, a service key and a domain, and
    /// no way to read any of them.
    pub fn load(path: &Path, expected_head: Option<&Fingerprint>) -> Result<Self, RegistryError> {
        Self::load_with(path, expected_head, false)
    }

    /// Loads a registry for a daemon restart, accepting the unattended
    /// per-peer lifecycle appended since the operator recorded the witness.
    ///
    /// See [`crate::audit::AuditChain::verify_from_witness`] for where the line
    /// is drawn. What grew is logged rather than swallowed.
    pub fn load_allowing_unattended_tail(
        path: &Path,
        expected_head: Option<&Fingerprint>,
    ) -> Result<Self, RegistryError> {
        Self::load_with(path, expected_head, true)
    }

    fn load_with(
        path: &Path,
        expected_head: Option<&Fingerprint>,
        allow_unattended_tail: bool,
    ) -> Result<Self, RegistryError> {
        let raw = std::fs::read(path)?;
        let mut document: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        let mut migrated = Self::migrate(&mut document)?;
        let mut state: AstraState = serde_json::from_value(document)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        migrated |= Self::recover_ca_pq_rotation(&mut state)?;
        migrated |= Self::recover_client_tls_ca_rotation(&mut state)?;
        match expected_head {
            Some(expected) if allow_unattended_tail => {
                let growth = state.audit.verify_from_witness(expected)?;
                if growth.appended > 0 {
                    tracing::info!(
                        witnessed_sequence = growth.witnessed_sequence,
                        appended = growth.appended,
                        "the audit chain grew past the recorded witness; every record after it \
                         is per-peer lifecycle, which widens nothing this authority may do"
                    );
                }
            }
            _ => state.audit.verify(expected_head)?,
        }
        let registry = Self {
            path: path.to_path_buf(),
            state,
        };
        if migrated {
            // Written back so this happens once. The audit chain is untouched:
            // nothing was decided here, and appending an event for a field
            // that was always implied would fork the head an operator holds.
            registry.save()?;
            tracing::info!(
                path = %path.display(),
                "registry migrated: derived state was restored from the identity and signed \
                 transitions already recorded"
            );
        }
        Ok(registry)
    }

    /// Fills the two fields a registry written before them does not carry.
    ///
    /// Both are **derived**, which is the only reason this is a migration and
    /// not a decision:
    ///
    /// - the issuance policy pin is `AstraIssuancePolicy::standard` over the
    ///   trust domain, the gateway key and the server name — the three values
    ///   already in the file. Astra and Helios each compute it independently
    ///   at bootstrap and compare the result out of band, so recomputing it
    ///   here reproduces exactly what bootstrap would have written. It is not
    ///   read from anywhere, and a file that supplied its own would be
    ///   supplying a pin, which is the one thing a pin may never be;
    /// - the credential registry epoch starts at zero rather than at one.
    ///   Every consumer keeps the highest it has seen, so the lowest possible
    ///   value is the only safe one: starting higher would refuse the first
    ///   genuine credential document as a rollback.
    ///
    /// Returns whether anything was filled, so a file already current is not
    /// rewritten.
    fn migrate(document: &mut serde_json::Value) -> Result<bool, RegistryError> {
        let Some(object) = document.as_object_mut() else {
            return Err(RegistryError::Corrupt(
                "the registry is not a JSON object".into(),
            ));
        };
        let mut migrated = false;
        if !object.contains_key("credential_registry_epoch") {
            object.insert("credential_registry_epoch".into(), serde_json::json!(0));
            migrated = true;
        }
        if !object.contains_key("astra_policy_fingerprint") {
            let identity = |field: &str| -> Result<String, RegistryError> {
                object
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        RegistryError::Corrupt(format!(
                            "the registry carries no policy pin and no `{field}` to recompute it \
                             from"
                        ))
                    })
            };
            let trust_domain_id = TrustDomainId::parse_hex(&identity("trust_domain_id")?)
                .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            let gateway_wg_public_key = WireGuardKey::parse(&identity("gateway_wg_public_key")?)
                .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            let pin = AstraIssuancePolicy::standard(
                trust_domain_id,
                gateway_wg_public_key,
                identity("server_name")?,
            )
            .pin()
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            object.insert(
                "astra_policy_fingerprint".into(),
                serde_json::to_value(pin)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?,
            );
            migrated = true;
        }
        Ok(migrated)
    }

    /// Restores the `CA-TLS` window accepted by a registry written before the
    /// window itself was persisted.
    ///
    /// The transition is verified again against the active pin. Two different
    /// successors for the same epoch are refused as corruption rather than
    /// choosing one based on storage order.
    fn recover_client_tls_ca_rotation(state: &mut AstraState) -> Result<bool, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        if state.ca_tls_rotation.is_some() {
            return Ok(false);
        }
        let Some(active) = state.ca_tls_fingerprint else {
            return Ok(false);
        };
        let mut recovered = None;
        for transition in state
            .transitions
            .iter()
            .filter_map(|stored| match &stored.object {
                TrustUpdateObject::ClientTlsCaTransition(transition)
                    if transition.current_ca_tls_epoch == state.ca_tls_epoch
                        && transition.active_client_tls_ca_fingerprint.matches(&active) =>
                {
                    Some(transition.as_ref())
                }
                _ => None,
            })
        {
            transition.verify(
                &state.ca_public_key,
                &state.trust_domain_id,
                state.ca_epoch,
                state.ca_tls_epoch,
                &active,
            )?;
            if recovered.is_some() {
                return Err(RegistryError::Corrupt(
                    "multiple client CA-TLS rotations target the active epoch".into(),
                ));
            }
            recovered = Some(ClientTlsCaRotation::from_transition(transition));
        }
        let restored = recovered.is_some();
        state.ca_tls_rotation = recovered;
        Ok(restored)
    }

    /// Restores a `CA-PQ` window accepted before Astra persisted its own
    /// active/next anchor state.
    ///
    /// Recovery still verifies both signatures under the anchor already
    /// pinned in the registry. Ambiguous successors are corruption, never a
    /// storage-order choice.
    fn recover_ca_pq_rotation(state: &mut AstraState) -> Result<bool, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        if state.ca_rotation.is_some() {
            return Ok(false);
        }
        let active = state.ca_public_key.authority_fingerprint();
        let mut recovered = None;
        for transition in state
            .transitions
            .iter()
            .filter_map(|stored| match &stored.object {
                TrustUpdateObject::CaTransition(transition)
                    if transition.current_ca_epoch == state.ca_epoch
                        && transition.current_ca_fingerprint.matches(&active) =>
                {
                    Some(transition.as_ref())
                }
                _ => None,
            })
        {
            transition.verify(&state.ca_public_key, &state.trust_domain_id, state.ca_epoch)?;
            if recovered.is_some() {
                return Err(RegistryError::Corrupt(
                    "multiple CA-PQ rotations target the active epoch".into(),
                ));
            }
            recovered = Some(CaPqRotation::from_transition(transition));
        }
        let restored = recovered.is_some();
        state.ca_rotation = recovered;
        Ok(restored)
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

    pub fn peer(&self, key: &WireGuardKey) -> Option<&PeerRecord> {
        self.state.peers.get(&key.to_base64())
    }

    /// Records a peer's first generation.
    ///
    /// Astra does not decide admission — the gateway does — so this is a
    /// **transcription**: the record is built from what the gateway answers on
    /// the private channel, and it exists so a renewal can be checked against
    /// the generation the domain actually holds rather than the one a request
    /// claims. Re-transcribing an unchanged peer is a no-op, which is what
    /// makes the lazy path of [`crate::renewal`] safe to retry.
    pub fn admit(&mut self, record: PeerRecord, now_unix: u64) -> Result<(), RegistryError> {
        let key = record.client_wg_public_key.to_base64();
        if self.state.peers.get(&key) == Some(&record) {
            return Ok(());
        }
        let generation = record.active.generation;
        let name = record.name.clone();
        self.state.peers.insert(key, record);
        self.state.audit.append(
            AuditEvent::PeerAdmitted {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Adopts the gateway's view of a peer without ever moving it backwards.
    ///
    /// # Why this is not `admit`
    ///
    /// [`Self::admit`] writes a whole `PeerRecord`. Calling it to refresh a
    /// peer would drop `pending` — a rotation whose grant may already be in a
    /// client's hands — and would happily accept a generation lower than the
    /// one already recorded, which is how a stale or rolled-back gateway view
    /// would rewrite this authority's idea of who is current.
    ///
    /// So the rules are stated rather than implied:
    ///
    /// * a generation below the recorded one is refused, never adopted;
    /// * the same generation must describe the same leaf, or it is two
    ///   histories wearing one number and it is refused;
    /// * terminal revocation state must agree, and an admission anchor already
    ///   pinned here cannot be replaced by a later gateway view;
    /// * a rotation in flight survives an adoption it is still ahead of, and
    ///   is dropped only when the adopted generation has caught up with or
    ///   passed the candidate it was staging;
    /// * an unchanged record writes nothing and appends nothing.
    ///
    /// Returns whether anything moved. Idempotent by construction, which is
    /// what makes it safe to replay after a crash: the gateway is the one that
    /// promotes, and this only ever copies what it already serves.
    pub fn reconcile_peer(
        &mut self,
        record: PeerRecord,
        now_unix: u64,
    ) -> Result<bool, RegistryError> {
        let key = record.client_wg_public_key.to_base64();
        let Some(held) = self.state.peers.get(&key) else {
            self.admit(record, now_unix)?;
            return Ok(true);
        };
        if held.revoked != record.revoked || held.revocation_epoch != record.revocation_epoch {
            return Err(RegistryError::RevocationDisagrees);
        }
        if held
            .admission_pq_ca
            .as_ref()
            .is_some_and(|anchor| record.admission_pq_ca.as_ref() != Some(anchor))
        {
            return Err(RegistryError::AdmissionAnchorDisagrees);
        }
        let (held_generation, adopted) = (held.active.generation, record.active.generation);
        if adopted < held_generation {
            return Err(RegistryError::GenerationRegression {
                held: held_generation,
                offered: adopted,
            });
        }
        if adopted == held_generation
            && (held.active != record.active
                || held.active_pq_certificate != record.active_pq_certificate)
        {
            return Err(RegistryError::GenerationDisagrees {
                generation: adopted,
            });
        }

        // The rotation in flight is this authority's own, and the gateway view
        // knows nothing of it. It is kept while it still names a generation
        // ahead of what is served, and dropped once it no longer can: a
        // candidate at or below the adopted generation has either landed or
        // been overtaken, and either way nothing is left to grant.
        let pending = held
            .pending
            .clone()
            .filter(|rotation| rotation.candidate.generation > adopted);
        let dropped_stage = held.pending.is_some() && pending.is_none();
        let name = record.name.clone();
        let admission_pq_ca = held
            .admission_pq_ca
            .clone()
            .or(record.admission_pq_ca.clone());
        let refreshed = PeerRecord {
            pending,
            admission_pq_ca,
            ..record
        };
        if self.state.peers.get(&key) == Some(&refreshed) {
            return Ok(false);
        }
        self.state.peers.insert(key, refreshed);
        if dropped_stage {
            self.state.audit.append(
                AuditEvent::ClientStagePurged {
                    peer: name.clone(),
                    generation: adopted,
                },
                now_unix,
            );
        }
        if adopted > held_generation {
            self.state.audit.append(
                AuditEvent::PeerGenerationAdopted {
                    peer: name,
                    generation: adopted,
                },
                now_unix,
            );
        }
        self.save()?;
        Ok(true)
    }

    /// Installs the delegation the operator companion signed (spec §9.5).
    ///
    /// The epoch must move forward. A delegation reinstalled at an epoch
    /// already used would let a withdrawn intermediate come back under a
    /// signature that is still perfectly valid — the same walk-back the
    /// credential document refuses, and for the same reason.
    pub fn install_issuer(
        &mut self,
        issuer: AstraIssuerState,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        self.install_issuer_adopting_policy(issuer, None, now_unix)
    }

    /// Installs a delegation and, in the same durable write, the issuance
    /// policy it carried the domain onto.
    ///
    /// One write rather than two: a pin persisted without its delegation
    /// would widen what the authority may do unattended before anything
    /// authorized it, and a delegation persisted without its pin would be
    /// refused on the next read by the policy it was meant to install.
    pub fn install_issuer_adopting_policy(
        &mut self,
        issuer: AstraIssuerState,
        adopted_policy: Option<AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        if let Some(policy) = adopted_policy {
            self.state.astra_policy_fingerprint = policy;
            self.state.audit.append(
                AuditEvent::IssuancePolicyAdopted {
                    policy_fingerprint: policy.fingerprint().to_string(),
                },
                now_unix,
            );
        }
        if let Some(installed) = &self.state.issuer {
            // Installing the delegation already held is a no-op, not a
            // walk-back: a companion whose response was lost retries the same
            // bytes, and §8.2 makes that replay the repair. Only a *different*
            // delegation at a spent epoch is the substitution this refuses.
            if installed == &issuer {
                // The delegation is already held. The pin may still have moved
                // just above, so the write is not skipped with it.
                return if adopted_policy.is_some() {
                    self.save()
                } else {
                    Ok(())
                };
            }
            if issuer.issuer_epoch <= installed.issuer_epoch {
                return Err(RegistryError::IssuerEpochNotAdvancing {
                    installed: installed.issuer_epoch,
                    offered: issuer.issuer_epoch,
                });
            }
        }
        let issuer_epoch = issuer.issuer_epoch;
        self.state.issuer = Some(issuer);
        self.state
            .audit
            .append(AuditEvent::IssuerInstalled { issuer_epoch }, now_unix);
        self.save()
    }

    /// Records the anchor transitions an approved campaign produced (§0.6).
    ///
    /// Every object is verified **here**, under the anchor and the epoch this
    /// registry already holds, before a byte is written. That is the whole
    /// reason the online authority may hold them at all: it re-derives the
    /// `CA-PQ` proof rather than trusting the channel that delivered it, and a
    /// forged object fails against a key no online process possesses.
    ///
    /// Depositing the same object twice is a **no-op**, not a second entry: a
    /// companion that retries after a lost response must not make the peer
    /// collect the same transition under two fingerprints.
    pub fn accept_transitions(
        &mut self,
        campaign: &aether::certificates::status::AstraRotationCampaign,
        objects: &[aether::certificates::transport::TrustUpdateObject],
        credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
        now_unix: u64,
    ) -> Result<usize, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        let campaign_id = campaign.campaign_id;

        let mut fresh = Vec::new();
        let mut withdrawn = Vec::new();
        let mut ca_rotation = self.state.ca_rotation.clone();
        let mut ca_tls_rotation = self.state.ca_tls_rotation.clone();
        for object in objects {
            let fingerprint = object.fingerprint()?;
            let held = self.state.transitions.iter().try_fold(
                false,
                |found, stored| -> Result<bool, RegistryError> {
                    Ok(found || stored.object.fingerprint()?.matches(&fingerprint))
                },
            )?;
            let repeated_in_batch = fresh.iter().try_fold(
                false,
                |found, pending: &TrustUpdateObject| -> Result<bool, RegistryError> {
                    Ok(found || pending.fingerprint()?.matches(&fingerprint))
                },
            )?;
            // An identical retry names an object this registry has already
            // verified and applied. In particular, checking its old counter
            // against the now-advanced revocation counter would turn the
            // idempotent retry into a rollback error.
            if held || repeated_in_batch {
                continue;
            }
            match object {
                TrustUpdateObject::CaTransition(transition) => {
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                    )?;
                    if ca_rotation.is_some() {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "a CA-PQ rotation is already in flight",
                            ),
                        ));
                    }
                    ca_rotation = Some(CaPqRotation::from_transition(transition));
                }
                TrustUpdateObject::CertificateRevocation(revocation) => {
                    use aether::certificates::revocation::RevocationScope;

                    if revocation.effective_at > now_unix {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IssuerScopeViolation(
                                "this authority accepts only immediately effective revocations",
                            ),
                        ));
                    }
                    if revocation.scope == RevocationScope::Gateway {
                        // The gateway's own leaves were never recorded here,
                        // so the approved campaign is the only place their
                        // state is pinned — the same asymmetry as a gateway
                        // transition. `covers_revocation` ties identity,
                        // fingerprints and counter to the text an operator
                        // read at a security key; only then may the counter be
                        // read back from the object to verify its signature.
                        campaign.covers_revocation(revocation)?;
                        let current_epoch = revocation.revocation_epoch.checked_sub(1).ok_or(
                            RegistryError::Transition(
                                aether::certificates::CertificateError::CampaignMismatch,
                            ),
                        )?;
                        revocation.verify(
                            &self.state.ca_public_key,
                            &self.state.trust_domain_id,
                            self.state.ca_epoch,
                            current_epoch,
                        )?;
                        fresh.push(object.clone());
                        continue;
                    }
                    let key = revocation.identity_key.to_base64();
                    let peer = self
                        .state
                        .peers
                        .get(&key)
                        .ok_or(RegistryError::UnknownPeer)?;
                    revocation.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        peer.revocation_epoch,
                    )?;
                    let tls_matches = revocation
                        .revoked_tls_fingerprint
                        .zip(revocation.revoked_tls_not_after)
                        .is_none_or(|(fingerprint, not_after)| {
                            peer.active
                                .tls_certificate_fingerprint
                                .matches(&fingerprint)
                                && peer.active.not_after == not_after
                        });
                    let pq_matches = revocation
                        .revoked_pq_fingerprint
                        .zip(revocation.revoked_pq_not_after)
                        .is_none_or(|(fingerprint, not_after)| {
                            peer.active.pq_certificate_fingerprint.matches(&fingerprint)
                                && peer.active.not_after == not_after
                        });
                    if !tls_matches || !pq_matches {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::CampaignMismatch,
                        ));
                    }
                    withdrawn.push((key, revocation.revocation_epoch));
                }
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    // The campaign first, and it is not a formality here: this
                    // authority holds no gateway leaf, so the approved text is
                    // the only place the state this decision was taken against
                    // is pinned. Verifying the object against fingerprints it
                    // carries itself would be verifying nothing — it is
                    // `covers_gateway_transition` that ties them to what an
                    // operator read at a security key.
                    campaign.covers_gateway_transition(transition)?;
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        transition.gateway_identity_epoch.checked_sub(1).ok_or(
                            RegistryError::Transition(
                                aether::certificates::CertificateError::CampaignMismatch,
                            ),
                        )?,
                        &self.state.gateway_wg_public_key,
                        &self.state.server_name,
                        &transition.active_gateway_tls_certificate_fingerprint,
                        &transition.active_gateway_certificate_fingerprint,
                    )?;
                }
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    campaign.covers_gateway_abort(abort)?;
                    // An abort is verified against the exact document it
                    // cancels, so that document must already be here. It is
                    // the same rule the gateway applies, and it is why an
                    // abort deposited before its transition is refused rather
                    // than stored for a transition that may never arrive.
                    let cancelled = self
                        .state
                        .transitions
                        .iter()
                        .filter_map(|stored| match &stored.object {
                            TrustUpdateObject::GatewayIdentityTransition(held) => {
                                Some((held, stored.published))
                            }
                            _ => None,
                        })
                        .find(|(held, _)| {
                            held.fingerprint().is_ok_and(|held_fingerprint| {
                                held_fingerprint.matches(&abort.gateway_transition_fingerprint)
                            })
                        })
                        .ok_or(RegistryError::Transition(
                            aether::certificates::CertificateError::CampaignMismatch,
                        ))?;
                    // The publication marker this authority persisted, not a
                    // constant: past it a client may already hold the decision,
                    // and refusing the abort here is what keeps one fleet from
                    // holding two truths (spec §6.3).
                    abort.verify(
                        &self.state.ca_public_key,
                        cancelled.0,
                        cancelled.1,
                        now_unix,
                    )?;
                }
                TrustUpdateObject::ClientTlsCaTransition(transition) => {
                    // The anchor this registry pins, never one taken from the
                    // object: comparing a transition to the fingerprint it
                    // carries itself would be comparing a value to itself.
                    // A domain bootstrapped before that pin existed is refused
                    // by name rather than checked against nothing.
                    let active = self
                        .state
                        .ca_tls_fingerprint
                        .ok_or(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "no client CA-TLS anchor is pinned here: record it with \
                             `astra pin-ca-tls` before a rotation can be verified",
                            ),
                        ))?;
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        self.state.ca_tls_epoch,
                        &active,
                    )?;
                    if ca_tls_rotation.is_some() {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "a client CA-TLS rotation is already in flight",
                            ),
                        ));
                    }
                    ca_tls_rotation = Some(ClientTlsCaRotation::from_transition(transition));
                }
                _ => {
                    return Err(RegistryError::Transition(
                        aether::certificates::CertificateError::IssuerScopeViolation(
                            "this authority stores only a CA-PQ transition, a gateway identity \
                             decision or a client revocation",
                        ),
                    ))
                }
            }
            fresh.push(object.clone());
        }
        if fresh.is_empty() {
            return Ok(0);
        }
        let held_revocations = self
            .state
            .transitions
            .iter()
            .filter(|stored| {
                matches!(stored.object, TrustUpdateObject::CertificateRevocation(_))
                    && retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
            })
            .count();
        let fresh_revocations = fresh
            .iter()
            .filter(|object| matches!(object, TrustUpdateObject::CertificateRevocation(_)))
            .count();
        if held_revocations + fresh_revocations > MAX_STORED_REVOCATIONS {
            return Err(RegistryError::RevocationStoreFull {
                held: held_revocations,
            });
        }
        let held_transitions = self
            .state
            .transitions
            .iter()
            .filter(|stored| {
                !matches!(stored.object, TrustUpdateObject::CertificateRevocation(_))
                    && retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
            })
            .count();
        let fresh_transitions = fresh.len() - fresh_revocations;
        if held_transitions + fresh_transitions > MAX_STORED_TRANSITIONS {
            return Err(RegistryError::TransitionStoreFull {
                held: held_transitions,
            });
        }

        // Capacity has been proven without mutation. Only now remove expired
        // objects and commit the fresh batch, so a refused deposit leaves the
        // in-memory state exactly as it was.
        self.state.transitions.retain(|stored| {
            retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
        });
        self.state.ca_rotation = ca_rotation;
        self.state.ca_tls_rotation = ca_tls_rotation;
        let accepted = fresh.len();
        for object in fresh {
            // A gateway transition is held back until §11.1 step 6; every
            // other object is distributable the moment it is accepted.
            let published = !matches!(
                object,
                TrustUpdateObject::GatewayIdentityTransition(_)
                    | TrustUpdateObject::GatewayTransitionAbort(_)
            );
            self.state.transitions.push(StoredTransition {
                campaign_id,
                accepted_at: now_unix,
                object,
                published,
                credential_registry: credential_registry.clone(),
            });
        }
        // The authority stops issuing for the identity as part of accepting
        // the signed decision. Delivery to other clients may follow later;
        // it must never be a prerequisite for the local withdrawal.
        for (key, revocation_epoch) in withdrawn {
            if let Some(peer) = self.state.peers.get_mut(&key) {
                peer.revoked = true;
                peer.revocation_epoch = revocation_epoch;
                peer.pending = None;
                self.state.audit.append(
                    AuditEvent::CertificateRevoked {
                        target: peer.name.clone(),
                    },
                    now_unix,
                );
            }
        }
        if fresh_transitions > 0 {
            self.state.audit.append(
                AuditEvent::AnchorTransitionsAccepted {
                    campaign: campaign_id.to_hex(),
                    objects: fresh_transitions,
                },
                now_unix,
            );
        }
        self.save()?;
        Ok(accepted)
    }

    /// Adopts due `CA-PQ` and client TLS anchors, then drops transitions no
    /// peer can still be told about (spec §§4.1, 9.2 and 9.4).
    ///
    /// A transition past its `not_after` authorizes nothing: a client that
    /// received it would refuse it, and one that did not has to be repaired by
    /// an operator rather than by a delivery that arrives after the window it
    /// was signed for. Forgetting it is what keeps the bounded store from
    /// filling with objects that can no longer do anything. Promotion and the
    /// removal of the transition it consumes share this method and therefore
    /// one atomic registry write: after a restart Astra cannot observe one
    /// without the other.
    pub fn forget_expired_transitions(&mut self, now_unix: u64) -> Result<usize, RegistryError> {
        let before = self.state.transitions.len();
        self.state
            .transitions
            .retain(|stored| match retained_until(&stored.object) {
                Some(not_after) => now_unix < not_after,
                // Something with no window is something this store does not
                // hold; keeping it would be keeping an object nothing prunes.
                None => false,
            });
        let dropped = before - self.state.transitions.len();
        let due_ca_rotation = self
            .state
            .ca_rotation
            .as_ref()
            .filter(|rotation| now_unix >= rotation.retire_active_at)
            .cloned();
        let ca_promoted = if let Some(rotation) = due_ca_rotation {
            self.state.ca_epoch = rotation.next_ca_epoch;
            self.state.ca_public_key = rotation.next_ca_public_key;
            self.state.ca_rotation = None;
            true
        } else {
            false
        };
        let due_tls_rotation = self
            .state
            .ca_tls_rotation
            .as_ref()
            .filter(|rotation| now_unix >= rotation.retire_active_at)
            .cloned();
        let ca_tls_promoted = if let Some(rotation) = due_tls_rotation {
            self.state.ca_tls_epoch = rotation.next_ca_tls_epoch;
            self.state.ca_tls_fingerprint = Some(rotation.next_ca_tls_fingerprint);
            self.state.ca_tls_rotation = None;
            true
        } else {
            false
        };
        if dropped > 0 || ca_promoted || ca_tls_promoted {
            self.save()?;
        }
        Ok(dropped)
    }

    /// Opens a rotation, refusing a second one for the same peer.
    ///
    /// One in flight at a time is the same bound the gateway enforces: two
    /// candidates for one identity would make `active + 1` ambiguous.
    pub fn open_rotation(
        &mut self,
        key: &WireGuardKey,
        rotation: PendingRotation,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        if peer.revoked {
            return Err(RegistryError::Revoked);
        }
        if let Some(existing) = &peer.pending {
            if existing == &rotation {
                return Ok(());
            }
            // An expired stage is not "in flight": it is debris, and it must
            // not block the renewal it was supposed to perform.
            if now_unix < existing.stage_expires_at {
                return Err(RegistryError::RotationInFlight);
            }
        }
        let generation = rotation.candidate.generation;
        let name = peer.name.clone();
        peer.pending = Some(rotation);
        self.state.audit.append(
            AuditEvent::ClientStageAuthorized {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Un-reserves a rotation the gateway refused, before its lease runs out.
    ///
    /// A staging that fails must not leave the peer holding a reservation
    /// nobody can clear: `active + 1` would stay unavailable until the lease
    /// expired, for a renewal that never happened. It names the stage it is
    /// clearing and clears nothing else — a refusal arriving after a later
    /// rotation opened would otherwise cancel that one instead.
    ///
    /// A rotation already `granted` is **not** cleared. Past that point Astra
    /// has released the leaves and the client may commit at any moment; taking
    /// the reservation back would let a second candidate be issued for a
    /// generation the gateway is about to promote.
    pub fn abandon_rotation(
        &mut self,
        key: &WireGuardKey,
        stage_id: &Id16,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let rotation = peer.pending.as_ref().ok_or(RegistryError::NoRotation)?;
        if rotation.stage_id != *stage_id || rotation.granted {
            return Err(RegistryError::NoRotation);
        }
        let rotation = peer.pending.take().expect("checked immediately above");
        let name = peer.name.clone();
        self.state.audit.append(
            AuditEvent::ClientStagePurged {
                peer: name,
                generation: rotation.candidate.generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Marks a rotation as granted — the point past which Astra has released
    /// the leaves and can no longer withhold them.
    pub fn mark_granted(&mut self, key: &WireGuardKey, now_unix: u64) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let name = peer.name.clone();
        let rotation = peer.pending.as_mut().ok_or(RegistryError::NoRotation)?;
        if rotation.granted {
            return Ok(());
        }
        rotation.granted = true;
        let generation = rotation.candidate.generation;
        self.state.audit.append(
            AuditEvent::ClientGrantReleased {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Promotes the candidate once the client has committed it.
    pub fn complete_rotation(
        &mut self,
        key: &WireGuardKey,
        pq_certificate: aether::key_negotiation::PqCertificate,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let rotation = peer.pending.take().ok_or(RegistryError::NoRotation)?;
        peer.active = rotation.candidate;
        peer.active_pq_certificate = pq_certificate;
        let name = peer.name.clone();
        let generation = peer.active.generation;
        self.state.audit.append(
            AuditEvent::ClientGrantReleased {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Drops every rotation whose lease has run out.
    pub fn purge_expired(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut purged = Vec::new();
        for peer in self.state.peers.values_mut() {
            let expired = peer
                .pending
                .as_ref()
                .is_some_and(|rotation| now_unix >= rotation.stage_expires_at);
            if expired {
                let rotation = peer.pending.take().expect("checked");
                purged.push(peer.name.clone());
                self.state.audit.append(
                    AuditEvent::ClientStagePurged {
                        peer: peer.name.clone(),
                        generation: rotation.candidate.generation,
                    },
                    now_unix,
                );
            }
        }
        if !purged.is_empty() {
            self.save()?;
        }
        Ok(purged)
    }

    /// Terminal revocation. Dominates a rotation already in flight.
    pub fn revoke(
        &mut self,
        key: &WireGuardKey,
        revocation_epoch: u64,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.revoked = true;
        peer.revocation_epoch = revocation_epoch;
        peer.pending = None;
        let name = peer.name.clone();
        self.state
            .audit
            .append(AuditEvent::CertificateRevoked { target: name }, now_unix);
        self.save()
    }

    /// Next status counter for a target, strictly increasing (spec §4.2).
    pub fn next_status_epoch(&mut self, fingerprint: &Fingerprint) -> u64 {
        let entry = self
            .state
            .status_epochs
            .entry(fingerprint.to_hex())
            .or_insert(0);
        *entry += 1;
        *entry
    }

    /// Lets a stored gateway decision leave the authority (spec §11.1 step 6).
    ///
    /// Persisted **before** the first byte, and irreversible. A gateway
    /// transition that has been distributed can no longer be aborted: a client
    /// may hold it, go offline, and promote on its own at `not_after`.
    ///
    /// Idempotent, because the relay to the gateway that follows may fail
    /// after this write. Re-running the step must be able to finish the relay
    /// without asking `CA-PQ` to sign anything again.
    pub fn publish_gateway_transition(
        &mut self,
        gateway_identity_epoch: u64,
        now_unix: u64,
    ) -> Result<aether::certificates::gateway::GatewayIdentityTransition, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        let position = self
            .state
            .transitions
            .iter()
            .position(|stored| match &stored.object {
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    transition.gateway_identity_epoch == gateway_identity_epoch
                }
                _ => false,
            })
            .ok_or(RegistryError::UnknownPeer)?;
        let TrustUpdateObject::GatewayIdentityTransition(transition) =
            self.state.transitions[position].object.clone()
        else {
            return Err(RegistryError::UnknownPeer);
        };
        if self.state.transitions[position].published {
            return Ok(*transition);
        }
        // An aborted decision never becomes publishable: the tombstone that
        // cancelled it is itself a stored object at the same epoch.
        let cancelled = self
            .state
            .transitions
            .iter()
            .any(|stored| match &stored.object {
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    abort.gateway_identity_epoch == gateway_identity_epoch
                }
                _ => false,
            });
        if cancelled {
            return Err(RegistryError::Transition(
                aether::certificates::CertificateError::IllegalStateTransition(
                    "this transition was aborted; the epoch stays consumed",
                ),
            ));
        }
        self.state.transitions[position].published = true;
        self.state.audit.append(
            AuditEvent::GatewayTransitionPublished {
                gateway_identity_epoch,
            },
            now_unix,
        );
        self.save()?;
        Ok(*transition)
    }

    /// Records the client `CA-TLS` this domain serves, once (spec §9.4).
    ///
    /// Refuses to replace one already pinned: an anchor that a command can
    /// overwrite is an anchor an operator error can move, and §9.4 makes that
    /// move a signed transition instead.
    pub fn pin_client_tls_ca(
        &mut self,
        fingerprint: Fingerprint,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        if let Some(held) = self.state.ca_tls_fingerprint {
            if !held.matches(&fingerprint) {
                return Err(RegistryError::Transition(
                    aether::certificates::CertificateError::IllegalStateTransition(
                        "a client CA-TLS anchor is already pinned; replacing it is a rotation",
                    ),
                ));
            }
            return Ok(());
        }
        let mut state = self.state.clone();
        state.ca_tls_fingerprint = Some(fingerprint);
        state.audit.append(
            AuditEvent::ClientTlsCaPinned {
                ca_tls_epoch: state.ca_tls_epoch,
            },
            now_unix,
        );
        self.state = state;
        self.save()
    }

    pub fn record(&mut self, event: AuditEvent, now_unix: u64) -> Result<(), RegistryError> {
        self.state.audit.append(event, now_unix);
        self.save()
    }
}

/// Single-use challenges for the public status and recovery routes.
///
/// In memory and bounded: a challenge is a permission to spend one signature
/// verification, not a durable object. Restarting Astra invalidates the ones
/// in flight, which is the correct outcome — the client simply asks again.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    issued: BTreeMap<[u8; 32], u64>,
    capacity: usize,
}

impl ChallengeStore {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            issued: BTreeMap::new(),
            capacity,
        }
    }

    /// Records a freshly generated challenge.
    ///
    /// Returns `false` when the store is full: refusing is better than
    /// evicting, because eviction would let a flood of requests invalidate
    /// the challenges of legitimate clients.
    pub fn issue(&mut self, challenge: [u8; 32], now_unix: u64) -> bool {
        self.expire(now_unix);
        if self.issued.len() >= self.capacity {
            return false;
        }
        self.issued
            .insert(challenge, now_unix + CHALLENGE_LIFETIME_SECS);
        true
    }

    /// Consumes a challenge exactly once.
    pub fn consume(&mut self, challenge: &[u8; 32], now_unix: u64) -> bool {
        self.expire(now_unix);
        match self.issued.remove(challenge) {
            Some(expires_at) => now_unix < expires_at,
            None => false,
        }
    }

    fn expire(&mut self, now_unix: u64) {
        self.issued.retain(|_, expires_at| now_unix < *expires_at);
    }
}

/// The window an anchor transition is in force for, when it carries one.
///
/// Read from the object rather than recorded beside it: two copies of a
/// deadline drift, and the one that decides must be the one the signature
/// covers.
fn transition_window(
    object: &aether::certificates::transport::TrustUpdateObject,
) -> Option<&TransitionWindow> {
    use aether::certificates::transport::TrustUpdateObject;
    match object {
        TrustUpdateObject::CaTransition(transition) => Some(&transition.window),
        TrustUpdateObject::ClientTlsCaTransition(transition) => Some(&transition.window),
        TrustUpdateObject::GatewayIdentityTransition(transition) => Some(&transition.window),
        _ => None,
    }
}

/// Last instant at which a stored object can still affect a recipient.
fn retained_until(object: &aether::certificates::transport::TrustUpdateObject) -> Option<u64> {
    use aether::certificates::transport::TrustUpdateObject;

    if let TrustUpdateObject::CertificateRevocation(revocation) = object {
        return revocation
            .revoked_tls_not_after
            .into_iter()
            .chain(revocation.revoked_pq_not_after)
            .max();
    }
    transition_window(object).map(|window| window.not_after)
}

#[cfg(test)]
#[path = "registry/tests/mod.rs"]
mod tests;
