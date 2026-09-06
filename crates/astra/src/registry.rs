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

    /// Loads a registry for a daemon restart, accepting only a suffix made of
    /// legacy read-only status publications after the operator witness.
    pub fn load_allowing_status_tail(
        path: &Path,
        expected_head: Option<&Fingerprint>,
    ) -> Result<Self, RegistryError> {
        Self::load_with(path, expected_head, true)
    }

    fn load_with(
        path: &Path,
        expected_head: Option<&Fingerprint>,
        allow_status_tail: bool,
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
            Some(expected) if allow_status_tail => {
                state.audit.verify_after_status_tail(expected)?
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
mod tests {
    use super::*;
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    fn certificate() -> PqCertificate {
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: "orion".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
            ml_dsa_87_public_key: String::new(),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        }
    }

    fn generation(index: u64) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: index,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(&[index as u8, 1]),
            pq_certificate_fingerprint: Fingerprint::of(&[index as u8, 2]),
            not_before: 0,
            not_after: 100_000,
        }
    }

    /// The anchor-transition half of §0.6, with the private key that signs.
    ///
    /// A separate module because every test here needs the outgoing `CA-PQ`
    /// in hand: what is being asserted is that this registry re-derives the
    /// proof itself rather than trusting whatever reached it.
    mod anchor_transitions {
        use super::*;
        use aether::certificates::authority::CaTransition;
        use aether::certificates::transport::TrustUpdateObject;
        use aether::certificates::window::TransitionWindow;
        use aether::certificates::CERTIFICATE_FORMAT_VERSION;

        struct Anchored {
            registry: AstraRegistry,
            ca_private: zeroize::Zeroizing<Vec<u8>>,
            ca_public: MlDsa87PublicKey,
            _directory: tempfile::TempDir,
        }

        fn anchored() -> Anchored {
            let directory = tempfile::tempdir().expect("temp dir");
            let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
            let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
            let state = AstraState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                server_name: "gateway.example".into(),
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                    .expect("policy pin"),
                credential_registry_epoch: 1,
                ca_epoch: 1,
                ca_public_key: ca_public.clone(),
                ca_rotation: None,
                ca_tls_epoch: 1,
                ca_tls_fingerprint: Some(Fingerprint::of(b"client tls ca")),
                ca_tls_rotation: None,
                astra_service_key_epoch: 1,
                astra_service_public_key: service,
                issuer: None,
                transitions: Vec::new(),
                peers: BTreeMap::new(),
                status_epochs: BTreeMap::new(),
                audit: AuditChain::default(),
            };
            Anchored {
                registry: AstraRegistry::new(directory.path().join("astra.json"), state),
                ca_private,
                ca_public,
                _directory: directory,
            }
        }

        fn transition_from(
            registry: &AstraRegistry,
            current_private: &[u8],
            current_public: &MlDsa87PublicKey,
            current_epoch: u64,
            window: TransitionWindow,
        ) -> (
            TrustUpdateObject,
            zeroize::Zeroizing<Vec<u8>>,
            MlDsa87PublicKey,
        ) {
            let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
            let transition = CaTransition {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: registry.state().trust_domain_id,
                current_ca_epoch: current_epoch,
                next_ca_epoch: current_epoch + 1,
                current_ca_fingerprint: current_public.authority_fingerprint(),
                next_ca_fingerprint: next_public.authority_fingerprint(),
                next_ca_public_key: next_public.clone(),
                window,
                current_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(
                ),
                next_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(current_private, &next_private)
            .expect("signing");
            (
                TrustUpdateObject::CaTransition(Box::new(transition)),
                next_private,
                next_public,
            )
        }

        fn transition(anchored: &Anchored, current_epoch: u64) -> TrustUpdateObject {
            transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                current_epoch,
                TransitionWindow::new(1_000, 90_000, 200_000).expect("window"),
            )
            .0
        }

        fn campaign_id() -> Id16 {
            Id16::new([7; 16]).expect("id")
        }

        /// The approved text an acceptance is checked against.
        ///
        /// Only the gateway-identity arms read its rows; every other object
        /// carries the state it is verified against, or is verified against an
        /// anchor this registry pins. Which is exactly the asymmetry: the
        /// gateway's own leaves live nowhere here.
        fn campaign(
            scope: aether::certificates::status::CampaignScope,
            targets: Vec<aether::certificates::status::CampaignTarget>,
        ) -> aether::certificates::status::AstraRotationCampaign {
            aether::certificates::status::AstraRotationCampaign {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                campaign_id: campaign_id(),
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                server_name: "gateway.example".into(),
                created_at: 1_000,
                expires_at: 1_300,
                scope,
                targets,
                reason: "rotation".into(),
                requested_by: "operator".into(),
                policy_fingerprint: Fingerprint::of(b"policy"),
                required_credentials: scope.required_credentials(),
            }
        }

        fn anchor_campaign() -> aether::certificates::status::AstraRotationCampaign {
            campaign(
                aether::certificates::status::CampaignScope::TrustAuthorities,
                Vec::new(),
            )
        }

        fn admitted(anchored: &mut Anchored) -> WireGuardKey {
            let client = WireGuardKey::from_bytes([5; 32]);
            anchored.registry.state.peers.insert(
                client.to_base64(),
                PeerRecord {
                    name: "compromised workstation".into(),
                    client_wg_public_key: client,
                    active: generation(3),
                    active_pq_certificate: certificate(),
                    pending: Some(PendingRotation {
                        stage_id: Id16::new([4; 16]).expect("stage"),
                        request_fingerprint: Fingerprint::of(b"request"),
                        candidate: generation(4),
                        window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                        stage_expires_at: 3_000,
                        granted: false,
                    }),
                    revoked: false,
                    revocation_epoch: 0,
                    admission_pq_ca: None,
                },
            );
            client
        }

        fn revocation(
            anchored: &Anchored,
            client: WireGuardKey,
            effective_at: u64,
            not_after: u64,
        ) -> TrustUpdateObject {
            use aether::certificates::revocation::{
                EmergencyCertificateRevocation, RevocationReason, RevocationScope,
            };

            let active = generation(3);
            let object = EmergencyCertificateRevocation {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: anchored.registry.state().trust_domain_id,
                ca_epoch: 1,
                scope: RevocationScope::Client,
                identity_key: client,
                server_name: None,
                revocation_epoch: 1,
                revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
                revoked_tls_not_after: Some(not_after),
                revoked_pq_fingerprint: Some(active.pq_certificate_fingerprint),
                revoked_pq_not_after: Some(not_after),
                effective_at,
                reason: RevocationReason::KeyCompromise,
                replacement_transition_fingerprint: None,
                ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(&anchored.ca_private)
            .expect("signing");
            TrustUpdateObject::CertificateRevocation(Box::new(object))
        }

        fn gateway_campaign(
            epoch: u64,
            tls: Fingerprint,
            pq: Fingerprint,
        ) -> aether::certificates::status::AstraRotationCampaign {
            campaign(
                aether::certificates::status::CampaignScope::GatewayIdentity,
                vec![aether::certificates::status::CampaignTarget {
                    certificate_kind: aether::certificates::status::CertificateKind::GatewayPq,
                    identity_key: WireGuardKey::from_bytes([1; 32]),
                    epoch,
                    generation: epoch,
                    active_tls_certificate_fingerprint: tls,
                    active_pq_certificate_fingerprint: pq,
                }],
            )
        }

        /// The leaf a transition installs. A decision that installs neither
        /// half is refused as empty, and rightly: it would consume an epoch
        /// and move nothing.
        fn gateway_leaf(anchored: &Anchored, epoch: u64) -> PqCertificate {
            use base64::Engine as _;

            let (_, subject) = generate_ml_dsa_87_keypair().expect("keygen");
            aether::key_negotiation::issue_pq_certificate(
                PqCertificate {
                    version: PQ_CERTIFICATE_VERSION,
                    serial: [epoch as u8; 16],
                    subject: "gateway.example".into(),
                    issuer: "helios-ca-pq".into(),
                    role: PqCertificateRole::Gateway,
                    wireguard_public_key: WireGuardKey::from_bytes([1; 32]).to_base64(),
                    ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                        .encode(subject.as_bytes()),
                    not_before_unix: 0,
                    not_after_unix: 100_000,
                    ml_dsa_87_signature: String::new(),
                },
                &anchored.ca_private,
            )
            .expect("issue")
        }

        fn gateway_transition(
            anchored: &Anchored,
            epoch: u64,
            tls: Fingerprint,
            pq: Fingerprint,
        ) -> TrustUpdateObject {
            use aether::certificates::authority::RotationReason;
            use aether::certificates::gateway::GatewayIdentityTransition;

            let object = GatewayIdentityTransition {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: anchored.registry.state().trust_domain_id,
                ca_epoch: 1,
                gateway_identity_epoch: epoch,
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                server_name: "gateway.example".into(),
                active_gateway_tls_certificate_fingerprint: tls,
                next_gateway_tls_certificate: None,
                active_gateway_certificate_fingerprint: pq,
                next_gateway_certificate: Some(gateway_leaf(anchored, epoch)),
                window: TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
                reason: RotationReason::Scheduled,
                ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(&anchored.ca_private)
            .expect("signing");
            TrustUpdateObject::GatewayIdentityTransition(Box::new(object))
        }

        fn gateway_abort(
            anchored: &Anchored,
            transition: &TrustUpdateObject,
            aborted_at: u64,
        ) -> TrustUpdateObject {
            use aether::certificates::gateway::{AbortReason, GatewayTransitionAbort};

            let TrustUpdateObject::GatewayIdentityTransition(cancelled) = transition else {
                panic!("not a gateway transition");
            };
            let object = GatewayTransitionAbort {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: anchored.registry.state().trust_domain_id,
                ca_epoch: 1,
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                server_name: "gateway.example".into(),
                gateway_identity_epoch: cancelled.gateway_identity_epoch,
                gateway_transition_fingerprint: cancelled.fingerprint().expect("fingerprint"),
                aborted_at,
                reason: AbortReason::OperatorCancelled,
                campaign_fingerprint: Fingerprint::of(b"campaign"),
                ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(&anchored.ca_private)
            .expect("signing");
            TrustUpdateObject::GatewayTransitionAbort(Box::new(object))
        }

        /// A gateway revocation belongs to the **revocation** family, not to
        /// the gateway-identity one: it withdraws a leaf, it does not move an
        /// identity forward, and the two refuse each other's objects.
        fn gateway_revocation_campaign(
            epoch: u64,
            tls: Fingerprint,
            pq: Fingerprint,
        ) -> aether::certificates::status::AstraRotationCampaign {
            campaign(
                aether::certificates::status::CampaignScope::EmergencyRevocation,
                vec![aether::certificates::status::CampaignTarget {
                    certificate_kind: aether::certificates::status::CertificateKind::GatewayPq,
                    identity_key: WireGuardKey::from_bytes([1; 32]),
                    epoch,
                    generation: epoch,
                    active_tls_certificate_fingerprint: tls,
                    active_pq_certificate_fingerprint: pq,
                }],
            )
        }

        fn gateway_revocation(
            anchored: &Anchored,
            revocation_epoch: u64,
            tls: Fingerprint,
            pq: Fingerprint,
            effective_at: u64,
        ) -> TrustUpdateObject {
            use aether::certificates::revocation::{
                EmergencyCertificateRevocation, RevocationReason, RevocationScope,
            };

            let object = EmergencyCertificateRevocation {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: anchored.registry.state().trust_domain_id,
                ca_epoch: 1,
                scope: RevocationScope::Gateway,
                identity_key: WireGuardKey::from_bytes([1; 32]),
                server_name: Some("gateway.example".into()),
                revocation_epoch,
                revoked_tls_fingerprint: Some(tls),
                revoked_tls_not_after: Some(200_000),
                revoked_pq_fingerprint: Some(pq),
                revoked_pq_not_after: Some(300_000),
                effective_at,
                reason: RevocationReason::KeyCompromise,
                replacement_transition_fingerprint: None,
                ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(&anchored.ca_private)
            .expect("signing");
            TrustUpdateObject::CertificateRevocation(Box::new(object))
        }

        /// The gateway's leaves were never recorded here, so the campaign is
        /// the only place their state is pinned — as for a transition.
        #[test]
        fn a_gateway_revocation_is_stored_against_the_campaign_that_froze_it() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let object = gateway_revocation(&anchored, 5, tls, pq, 2_000);

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(
                        &gateway_revocation_campaign(4, tls, pq),
                        &[object],
                        None,
                        2_000,
                    )
                    .expect("accepted"),
                1
            );
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        /// A leaf the operator never read, under a signature that verifies.
        #[test]
        fn a_gateway_revocation_over_another_leaf_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let elsewhere =
                gateway_revocation(&anchored, 5, tls, Fingerprint::of(b"another leaf"), 2_000);

            assert!(anchored
                .registry
                .accept_transitions(
                    &gateway_revocation_campaign(4, tls, pq),
                    &[elsewhere],
                    None,
                    2_000,
                )
                .is_err());
            assert!(anchored.registry.state().transitions.is_empty());
        }

        /// The two gateway families refuse each other: withdrawing a leaf and
        /// moving an identity forward are not the same decision, and one
        /// approved text must not authorise the other.
        #[test]
        fn a_gateway_revocation_under_an_identity_campaign_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let object = gateway_revocation(&anchored, 5, tls, pq, 2_000);

            assert!(anchored
                .registry
                .accept_transitions(&gateway_campaign(4, tls, pq), &[object], None, 2_000)
                .is_err());
        }

        /// §10.2: a consumed counter never comes back down.
        #[test]
        fn a_gateway_revocation_replaying_a_counter_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let replayed = gateway_revocation(&anchored, 4, tls, pq, 2_000);

            assert!(anchored
                .registry
                .accept_transitions(
                    &gateway_revocation_campaign(4, tls, pq),
                    &[replayed],
                    None,
                    2_000,
                )
                .is_err());
        }

        /// A decision dated in the future is not this authority's to hold.
        #[test]
        fn a_gateway_revocation_that_is_not_yet_effective_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let later = gateway_revocation(&anchored, 5, tls, pq, 9_000);

            assert!(anchored
                .registry
                .accept_transitions(
                    &gateway_revocation_campaign(4, tls, pq),
                    &[later],
                    None,
                    2_000,
                )
                .is_err());
        }

        /// This authority holds no gateway leaf, so the approved text is the
        /// only place the state a decision was taken against is pinned.
        #[test]
        fn a_gateway_transition_is_stored_against_the_campaign_that_froze_it() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let object = gateway_transition(&anchored, 5, tls, pq);

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&gateway_campaign(4, tls, pq), &[object], None, 2_000)
                    .expect("accepted"),
                1
            );
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        /// A leaf the operator never read, under a signature that verifies.
        #[test]
        fn a_gateway_transition_over_another_leaf_in_service_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let elsewhere = gateway_transition(&anchored, 5, tls, Fingerprint::of(b"another leaf"));

            assert!(anchored
                .registry
                .accept_transitions(&gateway_campaign(4, tls, pq), &[elsewhere], None, 2_000)
                .is_err());
            assert!(anchored.registry.state().transitions.is_empty());
        }

        /// An abort is verified against the exact document it cancels, so that
        /// document has to be here — not promised for later.
        #[test]
        fn an_abort_without_its_transition_is_refused() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let transition = gateway_transition(&anchored, 5, tls, pq);
            let abort = gateway_abort(&anchored, &transition, 2_100);

            assert!(anchored
                .registry
                .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
                .is_err());
        }

        /// §6.3, at the authority: past the publication no abort is
        /// legitimate, because a client may already hold the decision.
        #[test]
        fn an_abort_is_refused_once_the_transition_has_been_published() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let transition = gateway_transition(&anchored, 5, tls, pq);
            anchored
                .registry
                .accept_transitions(
                    &gateway_campaign(4, tls, pq),
                    std::slice::from_ref(&transition),
                    None,
                    2_000,
                )
                .expect("staged");
            anchored
                .registry
                .publish_gateway_transition(5, 2_050)
                .expect("published");
            let abort = gateway_abort(&anchored, &transition, 2_100);

            assert!(anchored
                .registry
                .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
                .is_err());
        }

        /// A cancelled decision never becomes publishable again.
        #[test]
        fn an_aborted_transition_is_not_published_afterwards() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let transition = gateway_transition(&anchored, 5, tls, pq);
            anchored
                .registry
                .accept_transitions(
                    &gateway_campaign(4, tls, pq),
                    std::slice::from_ref(&transition),
                    None,
                    2_000,
                )
                .expect("staged");
            let abort = gateway_abort(&anchored, &transition, 2_100);
            anchored
                .registry
                .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
                .expect("cancelled");

            assert!(anchored
                .registry
                .publish_gateway_transition(5, 2_300)
                .is_err());
        }

        #[test]
        fn an_abort_cancels_the_transition_already_stored() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let transition = gateway_transition(&anchored, 5, tls, pq);
            anchored
                .registry
                .accept_transitions(
                    &gateway_campaign(4, tls, pq),
                    std::slice::from_ref(&transition),
                    None,
                    2_000,
                )
                .expect("staged");
            let abort = gateway_abort(&anchored, &transition, 2_100);

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&gateway_campaign(5, tls, pq), &[abort], None, 2_200)
                    .expect("cancelled"),
                1
            );
            assert_eq!(anchored.registry.state().transitions.len(), 2);
        }

        fn client_tls_ca_transition(
            anchored: &Anchored,
            current_epoch: u64,
            active: Fingerprint,
        ) -> (
            TrustUpdateObject,
            aether::certificates::encoding::DerCertificate,
        ) {
            client_tls_ca_transition_with_window(
                anchored,
                current_epoch,
                active,
                "successor",
                TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
            )
        }

        fn client_tls_ca_transition_with_window(
            anchored: &Anchored,
            current_epoch: u64,
            active: Fingerprint,
            successor_name: &str,
            window: TransitionWindow,
        ) -> (
            TrustUpdateObject,
            aether::certificates::encoding::DerCertificate,
        ) {
            use aether::certificates::authority::ClientTlsCaTransition;

            let next = aether::certificates::test_x509::client_material(successor_name).authority;
            let object = ClientTlsCaTransition {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: anchored.registry.state().trust_domain_id,
                ca_epoch: 1,
                current_ca_tls_epoch: current_epoch,
                next_ca_tls_epoch: current_epoch + 1,
                active_client_tls_ca_fingerprint: active,
                next_client_tls_ca_certificate: next.clone(),
                window,
                ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            }
            .sign(&anchored.ca_private)
            .expect("signing");
            (
                TrustUpdateObject::ClientTlsCaTransition(Box::new(object)),
                next,
            )
        }

        /// §9.4 was unverifiable while this registry pinned the epoch of that
        /// anchor without pinning the anchor: the only value to compare
        /// against came from the object itself.
        #[test]
        fn a_client_tls_ca_rotation_is_verified_against_the_pinned_anchor() {
            let mut anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned by the fixture");
            let (object, next) = client_tls_ca_transition(&anchored, 1, active);

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                    .expect("accepted"),
                1
            );
            assert_eq!(
                anchored.registry.state().ca_tls_rotation,
                Some(ClientTlsCaRotation {
                    next_ca_tls_epoch: 2,
                    next_ca_tls_fingerprint: next.fingerprint(),
                    activation_at: 3_000,
                    retire_active_at: 5_000,
                })
            );
        }

        #[test]
        fn a_client_tls_ca_rotation_does_not_promote_before_not_after() {
            let mut anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");
            let (object, next) = client_tls_ca_transition(&anchored, 1, active);
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");

            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(4_999)
                    .expect("sweep before retirement"),
                0
            );
            assert_eq!(anchored.registry.state().ca_tls_epoch, 1);
            assert_eq!(anchored.registry.state().ca_tls_fingerprint, Some(active));
            assert!(anchored.registry.state().ca_tls_rotation.is_some());
            assert_eq!(anchored.registry.state().transitions.len(), 1);
            assert!(!active.matches(&next.fingerprint()));
        }

        #[test]
        fn a_due_client_tls_ca_rotation_is_promoted_once_and_allows_the_next_rotation() {
            let mut anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");
            let (first, first_successor) = client_tls_ca_transition(&anchored, 1, active);
            let first_successor_fingerprint = first_successor.fingerprint();
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
                .expect("first rotation accepted");

            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(5_000)
                    .expect("promoted at retirement"),
                1
            );
            assert_eq!(anchored.registry.state().ca_tls_epoch, 2);
            assert_eq!(
                anchored.registry.state().ca_tls_fingerprint,
                Some(first_successor_fingerprint)
            );
            assert!(anchored.registry.state().ca_tls_rotation.is_none());
            assert!(anchored.registry.state().transitions.is_empty());

            anchored.registry =
                AstraRegistry::load(&anchored._directory.path().join("astra.json"), None)
                    .expect("the promotion and removal were persisted together");
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(5_000)
                    .expect("second promotion is a no-op"),
                0
            );
            assert_eq!(anchored.registry.state().ca_tls_epoch, 2);
            assert_eq!(
                anchored.registry.state().ca_tls_fingerprint,
                Some(first_successor_fingerprint)
            );

            let (second, second_successor) = client_tls_ca_transition_with_window(
                &anchored,
                2,
                first_successor_fingerprint,
                "second-successor",
                TransitionWindow::new(6_000, 7_000, 8_000).expect("second window"),
            );
            let second_campaign = campaign(
                aether::certificates::status::CampaignScope::TrustAuthorities,
                vec![aether::certificates::status::CampaignTarget {
                    certificate_kind: aether::certificates::status::CertificateKind::CaTls,
                    identity_key: anchored.registry.state().gateway_wg_public_key,
                    epoch: 2,
                    generation: 2,
                    active_tls_certificate_fingerprint: first_successor_fingerprint,
                    active_pq_certificate_fingerprint: first_successor_fingerprint,
                }],
            );
            second_campaign
                .covers_authority_object(&second)
                .expect("the next campaign describes the promoted anchor");
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&second_campaign, &[second], None, 6_500)
                    .expect("second rotation accepted"),
                1
            );
            assert_eq!(
                anchored.registry.state().ca_tls_rotation,
                Some(ClientTlsCaRotation {
                    next_ca_tls_epoch: 3,
                    next_ca_tls_fingerprint: second_successor.fingerprint(),
                    activation_at: 7_000,
                    retire_active_at: 8_000,
                })
            );
        }

        #[test]
        fn a_registry_recovers_a_stored_client_tls_ca_window_from_the_legacy_format() {
            let mut anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");
            let (object, _) = client_tls_ca_transition(&anchored, 1, active);
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");
            let expected = anchored.registry.state().ca_tls_rotation.clone();
            let mut encoded = serde_json::to_value(anchored.registry.state()).expect("encoding");
            encoded
                .as_object_mut()
                .expect("registry object")
                .remove("ca_tls_rotation");
            let path = anchored._directory.path().join("astra.json");
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(&encoded).expect("legacy encoding"),
            )
            .expect("legacy registry written");

            let restored = AstraRegistry::load(&path, None).expect("legacy registry loaded");
            assert_eq!(restored.state().ca_tls_rotation, expected);
        }

        #[test]
        fn a_second_client_tls_ca_rotation_is_refused_while_one_is_in_flight() {
            let mut anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");
            let (first, _) = client_tls_ca_transition(&anchored, 1, active);
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
                .expect("first accepted");
            let held = anchored.registry.state().ca_tls_rotation.clone();
            let (competing, _) = client_tls_ca_transition_with_window(
                &anchored,
                1,
                active,
                "competing-successor",
                TransitionWindow::new(1_000, 3_500, 5_500).expect("competing window"),
            );

            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[competing], None, 2_100)
                .is_err());
            assert_eq!(anchored.registry.state().ca_tls_rotation, held);
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        #[test]
        fn a_client_tls_ca_rotation_over_another_anchor_is_refused() {
            let mut anchored = anchored();
            let (object, _) =
                client_tls_ca_transition(&anchored, 1, Fingerprint::of(b"another anchor"));

            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .is_err());
            assert!(anchored.registry.state().transitions.is_empty());
        }

        /// A domain bootstrapped before the pin existed is refused by name,
        /// not checked against a placeholder that would always match.
        #[test]
        fn a_client_tls_ca_rotation_without_a_pinned_anchor_is_refused() {
            let anchored = anchored();
            let active = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");
            let (object, _) = client_tls_ca_transition(&anchored, 1, active);
            let mut unpinned = anchored.registry.state().clone();
            unpinned.ca_tls_fingerprint = None;
            let mut registry =
                AstraRegistry::new(anchored._directory.path().join("unpinned.json"), unpinned);

            let refusal = registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect_err("no anchor to verify against");
            assert!(format!("{refusal}").contains("pin-ca-tls"));
        }

        /// An anchor a command can overwrite is an anchor an operator error
        /// can move; §9.4 makes that move a signed transition.
        #[test]
        fn a_pinned_client_tls_ca_is_not_replaced_by_a_command() {
            let mut anchored = anchored();
            let held = anchored
                .registry
                .state()
                .ca_tls_fingerprint
                .expect("pinned");

            anchored
                .registry
                .pin_client_tls_ca(held, 2_000)
                .expect("idempotent");
            assert!(anchored
                .registry
                .pin_client_tls_ca(Fingerprint::of(b"elsewhere"), 2_000)
                .is_err());
            assert_eq!(anchored.registry.state().ca_tls_fingerprint, Some(held));
        }

        #[test]
        fn a_ca_pq_rotation_opens_an_active_next_window() {
            let mut anchored = anchored();
            let (object, _, next) = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
            );

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                    .expect("accepted"),
                1
            );
            assert_eq!(anchored.registry.state().ca_epoch, 1);
            assert_eq!(anchored.registry.state().ca_public_key, anchored.ca_public);
            assert_eq!(
                anchored.registry.state().ca_rotation,
                Some(CaPqRotation {
                    next_ca_epoch: 2,
                    next_ca_public_key: next,
                    activation_at: 3_000,
                    retire_active_at: 5_000,
                })
            );
        }

        #[test]
        fn a_ca_pq_rotation_does_not_promote_before_not_after() {
            let mut anchored = anchored();
            let object = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
            )
            .0;
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");

            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(4_999)
                    .expect("sweep before retirement"),
                0
            );
            assert_eq!(anchored.registry.state().ca_epoch, 1);
            assert_eq!(anchored.registry.state().ca_public_key, anchored.ca_public);
            assert!(anchored.registry.state().ca_rotation.is_some());
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        #[test]
        fn a_due_ca_pq_rotation_is_promoted_once_and_allows_the_next_rotation() {
            let mut anchored = anchored();
            let (first, first_successor_private, first_successor_public) = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_000, 5_000).expect("first window"),
            );
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
                .expect("first rotation accepted");

            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(5_000)
                    .expect("promoted at retirement"),
                1
            );
            assert_eq!(anchored.registry.state().ca_epoch, 2);
            assert_eq!(
                anchored.registry.state().ca_public_key,
                first_successor_public
            );
            assert!(anchored.registry.state().ca_rotation.is_none());
            assert!(anchored.registry.state().transitions.is_empty());

            anchored.registry =
                AstraRegistry::load(&anchored._directory.path().join("astra.json"), None)
                    .expect("the promotion and removal were persisted together");
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(5_000)
                    .expect("second promotion is a no-op"),
                0
            );
            assert_eq!(anchored.registry.state().ca_epoch, 2);

            let (second, _, second_successor_public) = transition_from(
                &anchored.registry,
                &first_successor_private,
                &first_successor_public,
                2,
                TransitionWindow::new(6_000, 7_000, 8_000).expect("second window"),
            );
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[second], None, 6_500)
                    .expect("second rotation accepted"),
                1
            );
            assert_eq!(
                anchored.registry.state().ca_rotation,
                Some(CaPqRotation {
                    next_ca_epoch: 3,
                    next_ca_public_key: second_successor_public,
                    activation_at: 7_000,
                    retire_active_at: 8_000,
                })
            );
        }

        /// Three offline CA transitions in a row, and never three anchors
        /// (spec §14.1).
        ///
        /// The bound is what makes an offline rotation safe to repeat: between
        /// two of them the registry holds one anchor, and during one it holds
        /// the outgoing key and its single successor. A third would mean a
        /// document signed by a key nobody can still place.
        #[test]
        fn three_successive_ca_pq_transitions_never_hold_three_anchors() {
            let mut anchored = anchored();
            let mut private = anchored.ca_private.clone();
            let mut public = anchored.ca_public.clone();
            let mut retired = vec![public.clone()];

            for round in 0..3u64 {
                let epoch = round + 1;
                let base = 10_000 * (round + 1);
                let window =
                    TransitionWindow::new(base, base + 1_000, base + 2_000).expect("window");
                let (object, next_private, next_public) =
                    transition_from(&anchored.registry, &private, &public, epoch, window);
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, base + 500)
                    .expect("successive rotation accepted");

                // Staged: the outgoing anchor and exactly one successor.
                let state = anchored.registry.state();
                assert_eq!(state.ca_epoch, epoch);
                assert_eq!(state.ca_public_key, public);
                let rotation = state.ca_rotation.clone().expect("a rotation is in flight");
                assert_eq!(rotation.next_ca_epoch, epoch + 1);
                assert_eq!(rotation.next_ca_public_key, next_public);
                assert_eq!(
                    state.transitions.len(),
                    1,
                    "one decision in flight, never two"
                );
                assert!(
                    !retired.contains(&rotation.next_ca_public_key),
                    "a rotation must not reinstate an anchor already retired"
                );

                // Promoted at retirement: the predecessor goes in the same
                // write that installs the successor.
                assert_eq!(
                    anchored
                        .registry
                        .forget_expired_transitions(base + 2_000)
                        .expect("promotion at retirement"),
                    1
                );
                let state = anchored.registry.state();
                assert_eq!(state.ca_epoch, epoch + 1);
                assert_eq!(state.ca_public_key, next_public);
                assert!(state.ca_rotation.is_none(), "no successor is kept around");
                assert!(state.transitions.is_empty());

                retired.push(public);
                private = next_private;
                public = next_public;
            }

            assert_eq!(anchored.registry.state().ca_epoch, 4);
            assert_eq!(
                retired.len(),
                4,
                "three predecessors and the anchor of \
                                          the fixture, none of them still held"
            );
        }

        #[test]
        fn a_registry_recovers_a_stored_ca_pq_window_from_the_legacy_format() {
            let mut anchored = anchored();
            let object = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_000, 5_000).expect("window"),
            )
            .0;
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");
            let expected = anchored.registry.state().ca_rotation.clone();
            let mut encoded = serde_json::to_value(anchored.registry.state()).expect("encoding");
            encoded
                .as_object_mut()
                .expect("registry object")
                .remove("ca_rotation");
            let path = anchored._directory.path().join("astra.json");
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(&encoded).expect("legacy encoding"),
            )
            .expect("legacy registry written");

            let restored = AstraRegistry::load(&path, None).expect("legacy registry loaded");
            assert_eq!(restored.state().ca_rotation, expected);
        }

        #[test]
        fn a_second_ca_pq_rotation_is_refused_while_one_is_in_flight() {
            let mut anchored = anchored();
            let first = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_000, 5_000).expect("first window"),
            )
            .0;
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[first], None, 2_000)
                .expect("first accepted");
            let held = anchored.registry.state().ca_rotation.clone();
            let competing = transition_from(
                &anchored.registry,
                &anchored.ca_private,
                &anchored.ca_public,
                1,
                TransitionWindow::new(1_000, 3_500, 5_500).expect("competing window"),
            )
            .0;

            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[competing], None, 2_100)
                .is_err());
            assert_eq!(anchored.registry.state().ca_rotation, held);
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        /// The one property that lets an online authority hold `CA-PQ` output
        /// at all: it re-derives the proof under the anchor it already pins.
        #[test]
        fn a_transition_is_verified_under_the_anchor_this_registry_pins() {
            let mut anchored = anchored();
            let object = transition(&anchored, 1);
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                    .expect("accepted"),
                1
            );
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        /// A transition leaving another epoch, or signed by another anchor, is
        /// refused — the check is the object's own `verify`, run here.
        #[test]
        fn a_transition_this_domain_did_not_authorize_is_refused() {
            let mut anchored = anchored();
            let wrong_epoch = transition(&anchored, 2);
            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[wrong_epoch], None, 2_000)
                .is_err());

            let other_domain = super::anchor_transitions::anchored();
            let foreign = transition(&other_domain, 1);
            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[foreign], None, 2_000)
                .is_err());
            assert!(anchored.registry.state().transitions.is_empty());
        }

        /// A companion that retries after a lost response must not make a peer
        /// collect the same transition under two fingerprints.
        #[test]
        fn depositing_the_same_transition_twice_stores_it_once() {
            let mut anchored = anchored();
            let object = transition(&anchored, 1);
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(
                        &anchor_campaign(),
                        std::slice::from_ref(&object),
                        None,
                        2_000
                    )
                    .expect("accepted"),
                1
            );
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, 2_100)
                    .expect("replayed"),
                0
            );
            assert_eq!(anchored.registry.state().transitions.len(), 1);
        }

        #[test]
        fn an_accepted_revocation_is_terminal_and_cancels_staging() {
            let mut anchored = anchored();
            let client = admitted(&mut anchored);
            let object = revocation(&anchored, client, 2_000, generation(3).not_after);
            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(
                        &anchor_campaign(),
                        std::slice::from_ref(&object),
                        None,
                        2_000,
                    )
                    .expect("accepted"),
                1
            );
            let peer = &anchored.registry.state().peers[&client.to_base64()];
            assert!(peer.revoked);
            assert_eq!(peer.revocation_epoch, 1);
            assert!(peer.pending.is_none());

            assert_eq!(
                anchored
                    .registry
                    .accept_transitions(&anchor_campaign(), &[object], None, 2_100)
                    .expect("identical retry"),
                0
            );
        }

        #[test]
        fn a_revocation_with_a_retyped_expiry_or_future_effect_is_refused_atomically() {
            let mut anchored = anchored();
            let client = admitted(&mut anchored);
            let wrong_expiry = revocation(&anchored, client, 2_000, 99_999);
            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[wrong_expiry], None, 2_000)
                .is_err());
            let future = revocation(&anchored, client, 2_001, generation(3).not_after);
            assert!(anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[future], None, 2_000)
                .is_err());
            let peer = &anchored.registry.state().peers[&client.to_base64()];
            assert!(!peer.revoked);
            assert!(anchored.registry.state().transitions.is_empty());
        }

        #[test]
        fn a_revocation_is_retained_until_its_signed_expiry() {
            let mut anchored = anchored();
            let client = admitted(&mut anchored);
            let expiry = generation(3).not_after;
            let object = revocation(&anchored, client, 2_000, expiry);
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(expiry - 1)
                    .expect("sweep"),
                0
            );
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(expiry)
                    .expect("sweep"),
                1
            );
        }

        /// The ceiling refuses rather than evicting: dropping the oldest would
        /// drop the one a lagging peer is still missing.
        #[test]
        fn the_store_refuses_rather_than_dropping_what_a_peer_still_needs() {
            let mut anchored = anchored();
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            for index in 0..MAX_STORED_TRANSITIONS {
                let active_epoch = index as u64 + 1;
                let object = gateway_transition(&anchored, active_epoch + 1, tls, pq);
                anchored
                    .registry
                    .accept_transitions(
                        &gateway_campaign(active_epoch, tls, pq),
                        &[object],
                        None,
                        2_000 + index as u64,
                    )
                    .expect("accepted");
            }
            let active_epoch = MAX_STORED_TRANSITIONS as u64 + 1;
            let overflow = gateway_transition(&anchored, active_epoch + 1, tls, pq);
            assert!(matches!(
                anchored.registry.accept_transitions(
                    &gateway_campaign(active_epoch, tls, pq),
                    &[overflow],
                    None,
                    3_000,
                ),
                Err(RegistryError::TransitionStoreFull { .. })
            ));
            assert_eq!(
                anchored.registry.state().transitions.len(),
                MAX_STORED_TRANSITIONS
            );
        }

        /// Past its `not_after` a transition authorizes nothing, and keeping
        /// it would fill a bounded store with objects that can no longer act.
        #[test]
        fn an_expired_transition_is_forgotten() {
            let mut anchored = anchored();
            let object = transition(&anchored, 1);
            anchored
                .registry
                .accept_transitions(&anchor_campaign(), &[object], None, 2_000)
                .expect("accepted");
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(199_999)
                    .expect("swept"),
                0
            );
            assert_eq!(
                anchored
                    .registry
                    .forget_expired_transitions(200_000)
                    .expect("swept"),
                1
            );
            assert!(anchored.registry.state().transitions.is_empty());
        }
    }

    fn registry() -> (AstraRegistry, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temp dir");
        let (_, ca) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
        let state = AstraState {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            server_name: "gateway.example".into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                .expect("policy pin"),
            credential_registry_epoch: 1,
            ca_epoch: 1,
            ca_public_key: ca,
            ca_rotation: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: Some(Fingerprint::of(b"client tls ca")),
            ca_tls_rotation: None,
            astra_service_key_epoch: 1,
            astra_service_public_key: service,
            issuer: None,
            transitions: Vec::new(),
            peers: BTreeMap::new(),
            status_epochs: BTreeMap::new(),
            audit: AuditChain::default(),
        };
        let mut registry = AstraRegistry::new(directory.path().join("astra.json"), state);
        registry
            .admit(
                PeerRecord {
                    name: "workstation".into(),
                    client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                    active: generation(4),
                    active_pq_certificate: certificate(),
                    pending: None,
                    revoked: false,
                    revocation_epoch: 0,
                    admission_pq_ca: None,
                },
                1_000,
            )
            .expect("admission");
        (registry, directory)
    }

    fn rotation(stage: u8, expires_at: u64) -> PendingRotation {
        PendingRotation {
            stage_id: Id16::new([stage; 16]).expect("stage"),
            request_fingerprint: Fingerprint::of(b"request"),
            candidate: generation(5),
            window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
            stage_expires_at: expires_at,
            granted: false,
        }
    }

    /// A delegation is installed by epoch, and the epoch only ever rises.
    /// Reinstalling one already used would let a withdrawn intermediate come
    /// back under a signature that is still perfectly valid.
    #[test]
    fn a_delegation_may_not_walk_its_epoch_backwards() {
        use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
        use aether::certificates::encoding::{DerCertificate, MlDsa87Signature};
        use aether::certificates::state::{AstraIssuerState, IssuerLifecycle};

        let (mut registry, _dir) = registry();
        let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
        let delegation = |epoch: u64| AstraIssuerState {
            issuer_epoch: epoch,
            authorization: AstraIssuerAuthorization {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                server_name: "gateway.example".into(),
                issuer_epoch: epoch,
                pq_issuer_public_key: issuer_key.clone(),
                tls_intermediate_certificate: DerCertificate::new(vec![9; 64]).expect("der"),
                allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: 100_000,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            },
            state: IssuerLifecycle::Active,
        };

        registry
            .install_issuer(delegation(1), 1_000)
            .expect("first");
        // The same delegation again is a replay of §8.2, not a walk-back: a
        // companion whose response was lost redeposits the same bytes.
        registry
            .install_issuer(delegation(1), 1_100)
            .expect("an identical delegation is a no-op");
        // A *different* delegation at a spent epoch is the substitution this
        // refuses — it would bring back an intermediate that was withdrawn,
        // under a signature that still verifies.
        let mut substituted = delegation(1);
        substituted.authorization.tls_intermediate_certificate =
            DerCertificate::new(vec![7; 64]).expect("der");
        assert!(matches!(
            registry.install_issuer(substituted, 1_150),
            Err(RegistryError::IssuerEpochNotAdvancing {
                installed: 1,
                offered: 1
            })
        ));
        registry
            .install_issuer(delegation(2), 1_200)
            .expect("second");
        assert_eq!(
            registry
                .state()
                .issuer
                .as_ref()
                .expect("issuer")
                .issuer_epoch,
            2
        );
    }

    /// The peer table is a transcription of the gateway's admission, and the
    /// lazy path re-runs it on every renewal. Re-transcribing an unchanged
    /// peer must not append an audit record — a chain that grew on every
    /// renewal would make its head useless as a restore witness.
    #[test]
    fn re_transcribing_an_unchanged_peer_appends_nothing() {
        let (mut registry, _dir) = registry();
        let head = registry.audit_head();
        let record = registry
            .peer(&WireGuardKey::from_bytes([2; 32]))
            .expect("peer")
            .clone();

        registry.admit(record, 2_000).expect("re-transcription");

        assert_eq!(registry.audit_head(), head);
    }

    #[test]
    fn only_one_rotation_may_be_in_flight_per_peer() {
        let (mut registry, _dir) = registry();
        let key = WireGuardKey::from_bytes([2; 32]);
        registry
            .open_rotation(&key, rotation(5, 5_000), 1_100)
            .expect("first rotation");
        assert!(matches!(
            registry.open_rotation(&key, rotation(6, 5_000), 1_200),
            Err(RegistryError::RotationInFlight)
        ));
    }

    /// Debris must not block the renewal it was supposed to perform.
    #[test]
    fn an_expired_rotation_does_not_block_the_next_one() {
        let (mut registry, _dir) = registry();
        let key = WireGuardKey::from_bytes([2; 32]);
        registry
            .open_rotation(&key, rotation(5, 5_000), 1_100)
            .expect("first rotation");
        registry
            .open_rotation(&key, rotation(6, 12_000), 5_000)
            .expect("second rotation after the lease");
    }

    #[test]
    fn revocation_dominates_a_rotation_in_flight() {
        let (mut registry, _dir) = registry();
        let key = WireGuardKey::from_bytes([2; 32]);
        registry
            .open_rotation(&key, rotation(5, 5_000), 1_100)
            .expect("rotation");
        registry.revoke(&key, 1, 1_200).expect("revocation");

        let peer = registry.peer(&key).expect("peer");
        assert!(peer.revoked);
        assert!(peer.pending.is_none());
        assert!(matches!(
            registry.open_rotation(&key, rotation(6, 9_000), 1_300),
            Err(RegistryError::Revoked)
        ));
    }

    #[test]
    fn a_status_epoch_only_ever_increases() {
        let (mut registry, _dir) = registry();
        let target = Fingerprint::of(b"leaf");
        assert_eq!(registry.next_status_epoch(&target), 1);
        assert_eq!(registry.next_status_epoch(&target), 2);
        assert_eq!(registry.next_status_epoch(&Fingerprint::of(b"other")), 1);
    }

    /// A backup that ends on another head is a fork, not a resume.
    #[test]
    fn loading_a_forked_chain_is_refused() {
        let (registry, directory) = registry();
        let head = registry.audit_head();
        let path = directory.path().join("astra.json");

        AstraRegistry::load(&path, Some(&head)).expect("same head");
        assert!(matches!(
            AstraRegistry::load(&path, Some(&Fingerprint::of(b"another history"))),
            Err(RegistryError::Audit(AuditError::Forked))
        ));
    }

    /// A challenge is spent once, and only inside its window.
    #[test]
    fn a_challenge_is_single_use_and_short_lived() {
        let mut store = ChallengeStore::with_capacity(4);
        assert!(store.issue([7; 32], 1_000));
        assert!(store.consume(&[7; 32], 1_030));
        assert!(!store.consume(&[7; 32], 1_030), "already spent");

        assert!(store.issue([8; 32], 1_000));
        assert!(
            !store.consume(&[8; 32], 1_000 + CHALLENGE_LIFETIME_SECS),
            "expired"
        );
    }

    /// Refusing beats evicting: a flood must not invalidate the challenges of
    /// clients that are mid-request.
    #[test]
    fn a_full_challenge_store_refuses_rather_than_evicting() {
        let mut store = ChallengeStore::with_capacity(2);
        assert!(store.issue([1; 32], 1_000));
        assert!(store.issue([2; 32], 1_000));
        assert!(!store.issue([3; 32], 1_000));
        assert!(store.consume(&[1; 32], 1_010), "the earlier one survived");
    }

    /// A registry written before the policy pin and the credential epoch
    /// existed still loads, and comes back describing the same domain.
    ///
    /// Refusing it is what actually happened on a live gateway: `astra status`
    /// failed, the deployment read that failure as "not bootstrapped", and the
    /// bootstrap then refused to start a second history over the first. The
    /// operator was left with an authority holding a service key, an audit
    /// chain and a domain, and no command that could read any of them.
    #[test]
    fn a_registry_written_before_the_policy_pin_is_migrated_rather_than_refused() {
        let (registry, directory) = registry();
        registry.save().expect("save");
        let path = directory.path().join("astra.json");

        // Exactly the older shape: the two fields simply are not there.
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let object = document.as_object_mut().unwrap();
        object.remove("astra_policy_fingerprint");
        object.remove("credential_registry_epoch");
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

        let loaded = AstraRegistry::load(&path, None).expect("the older registry loads");
        let state = loaded.state();
        assert_eq!(state.trust_domain_id, TrustDomainId::new([1; 16]).unwrap());
        assert_eq!(state.peers.len(), 1, "the peers survived the migration");
        // The lowest possible epoch: every consumer keeps the highest it has
        // seen, so starting higher would refuse the first genuine document.
        assert_eq!(state.credential_registry_epoch, 0);
        // Recomputed, never read: exactly what bootstrap would have written
        // for this identity.
        let expected = AstraIssuancePolicy::standard(
            state.trust_domain_id,
            state.gateway_wg_public_key,
            state.server_name.clone(),
        )
        .pin()
        .expect("pin");
        assert_eq!(&state.astra_policy_fingerprint, &expected);

        // Written back, so the migration happens once and the audit head is
        // the one the operator already holds.
        let reloaded = AstraRegistry::load(&path, Some(&registry.audit_head()))
            .expect("and the chain did not fork");
        assert_eq!(
            reloaded.state().astra_policy_fingerprint,
            state.astra_policy_fingerprint
        );
    }

    /// A registry that carries neither the pin nor the identity to recompute
    /// it from is refused by name. It is not a registry.
    #[test]
    fn a_registry_with_nothing_to_recompute_the_pin_from_is_refused() {
        let (registry, directory) = registry();
        registry.save().expect("save");
        let path = directory.path().join("astra.json");

        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let object = document.as_object_mut().unwrap();
        object.remove("astra_policy_fingerprint");
        object.remove("server_name");
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

        assert!(matches!(
            AstraRegistry::load(&path, None),
            Err(RegistryError::Corrupt(_))
        ));
    }
}
