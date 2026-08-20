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
    pub ca_tls_epoch: u64,

    pub astra_service_key_epoch: u64,
    pub astra_service_public_key: MlDsa87PublicKey,

    pub issuer: Option<AstraIssuerState>,
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
        let migrated = Self::migrate(&mut document)?;
        let state: AstraState = serde_json::from_value(document)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
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
                "registry migrated: the pinned issuance policy and the credential registry epoch \
                 were recomputed from the identity already recorded"
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
        if let Some(installed) = &self.state.issuer {
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
            ca_tls_epoch: 1,
            astra_service_key_epoch: 1,
            astra_service_public_key: service,
            issuer: None,
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
        assert!(matches!(
            registry.install_issuer(delegation(1), 1_100),
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
