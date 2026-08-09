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
    client::{
        ClientCertificateGeneration, ClientCertificateStageAuthorization,
        ClientCertificateStageCommit, GatewayCertificateStageReceipt,
    },
    encoding::{
        Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
    },
    state::{
        AstraIssuerState, AstraProfile, ClientCertificateState, ClientTlsCaState,
        GatewayCertificateState, InstallOutcome,
    },
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::PqCertificate;
use serde::{Deserialize, Serialize};

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

    /// Loads the registry, or reports that the domain is not bootstrapped.
    ///
    /// A missing file is **not** an empty registry: a gateway with no trust
    /// domain has no `CA-PQ` to verify anything against, and inventing an
    /// empty one would silently accept the first object that arrived.
    pub fn load(path: &Path) -> Result<Option<Self>, RegistryError> {
        match std::fs::read(path) {
            Ok(raw) => {
                let state: RegistryState = serde_json::from_slice(&raw)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                Ok(Some(Self {
                    path: path.to_path_buf(),
                    state,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(RegistryError::Io(error)),
        }
    }

    pub fn state(&self) -> &RegistryState {
        &self.state
    }

    /// Writes the registry atomically and `fsync`s file and directory.
    ///
    /// Called before any answer that would let another party believe the write
    /// happened. A receipt signed over an unsynced state is a signature over a
    /// fact that a power cut can still undo.
    pub fn save(&self) -> Result<(), RegistryError> {
        let encoded = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
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
        self.assert_fingerprints_free(
            wg_public_key,
            &[
                active.tls_certificate_fingerprint,
                active.pq_certificate_fingerprint,
            ],
        )?;
        self.state.peers.insert(
            wg_public_key.to_base64(),
            PeerCertificates {
                name: name.to_string(),
                state: ClientCertificateState::new(active),
                active_pq_certificate,
                staged_pq_certificate: None,
            },
        );
        self.save()
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
        // An expired stage must not block a fresh one, and the purge belongs
        // to the same serialized section as the staging it competes with.
        self.purge_expired(now_unix)?;

        let peer = self
            .state
            .peers
            .get(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        if peer.state.revoked {
            return Err(RegistryError::Certificate(CertificateError::Revoked));
        }

        authorization.verify(
            &self.state.gateway.current_ca_public_key,
            &self.state.trust_domain_id,
            self.state.gateway.ca_epoch,
            self.state.client_tls_ca.ca_tls_epoch,
            &self.state.gateway.gateway_wg_public_key,
            &self.state.gateway.server_name,
            caller_wg_public_key,
            &peer.state.active,
            None,
            now_unix,
        )?;

        let candidate = authorization.candidate()?;
        self.assert_fingerprints_free(
            caller_wg_public_key,
            &[
                candidate.tls_certificate_fingerprint,
                candidate.pq_certificate_fingerprint,
            ],
        )?;

        let peer = self
            .state
            .peers
            .get_mut(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let outcome = peer.state.stage(authorization, now_unix)?;
        if outcome == InstallOutcome::Installed {
            peer.staged_pq_certificate = Some(authorization.next_pq_certificate.clone());
        }
        let active_generation = peer.state.active.generation;

        // Persisted and synced **before** the receipt exists.
        self.save()?;

        Ok(GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            stage_id: authorization.stage_id,
            stage_authorization_fingerprint: authorization.fingerprint()?,
            request_fingerprint: authorization.request_fingerprint,
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

    /// Marks a staged candidate as released to the client.
    pub fn mark_pending_commit(
        &mut self,
        caller_wg_public_key: &WireGuardKey,
        stage_id: &Id16,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.state.mark_pending_commit(stage_id)?;
        self.save()
    }

    /// Turns the candidate into the committed `next` generation.
    ///
    /// Both signatures are verified here, under the keys the registry holds —
    /// the active leaf it admitted and the candidate leaf it staged. Neither
    /// comes from the commit message, so a commit cannot bring its own
    /// verifier.
    pub fn commit(
        &mut self,
        caller_wg_public_key: &WireGuardKey,
        commit: &ClientCertificateStageCommit,
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
        let pending = peer
            .state
            .pending
            .as_ref()
            .ok_or(RegistryError::Certificate(CertificateError::UnknownStage))?;
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
        let peer = self
            .state
            .peers
            .get_mut(&caller_wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let outcome = peer.state.commit(&stage_id, now_unix)?;
        self.save()?;
        Ok(outcome)
    }

    /// Drops every candidate whose lease has run out, and returns their peers.
    pub fn purge_expired(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut purged = Vec::new();
        for (key, peer) in self.state.peers.iter_mut() {
            if peer.state.purge_expired(now_unix) {
                // The staged leaf goes with the candidate: keeping it would
                // leave a certificate the registry can no longer name.
                if peer.state.next.is_none() {
                    peer.staged_pq_certificate = None;
                }
                purged.push(key.clone());
            }
        }
        if !purged.is_empty() {
            self.save()?;
        }
        Ok(purged)
    }

    /// Promotes every generation whose overlap has ended.
    pub fn promote_due(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut promoted = Vec::new();
        for (key, peer) in self.state.peers.iter_mut() {
            if peer.state.promote_if_due(now_unix) {
                if let Some(certificate) = peer.staged_pq_certificate.take() {
                    peer.active_pq_certificate = certificate;
                }
                promoted.push(key.clone());
            }
        }
        if !promoted.is_empty() {
            self.save()?;
        }
        Ok(promoted)
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
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.state.revoke(revocation_epoch);
        peer.staged_pq_certificate = None;
        self.save()
    }

    /// Refuses a fingerprint already bound to another peer (spec §3.3).
    ///
    /// Global across active, next **and** pending: a candidate that duplicated
    /// another peer's fingerprint would make a future connection resolvable to
    /// two identities.
    fn assert_fingerprints_free(
        &self,
        owner: &WireGuardKey,
        fingerprints: &[Fingerprint],
    ) -> Result<(), RegistryError> {
        let owner = owner.to_base64();
        for (key, peer) in &self.state.peers {
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
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::IssuerKind;
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, DerCertificate};
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
        registry: CertificateRegistry,
        ca: Keys,
        gateway_leaf_key: Keys,
        active_client: Keys,
        _directory: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temp dir");
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
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                next_gateway_identity_epoch: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_leaf,
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 1,
                active_client_tls_ca_certificate: DerCertificate::new(vec![2; 64]).expect("der"),
                next_client_tls_ca_certificate: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                active_astra_service_public_key: astra_key.public.clone(),
                next_astra_service_public_key: None,
                astra_service_key_epoch: 1,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
            },
            issuer: None,
            peers: BTreeMap::new(),
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
            registry,
            ca,
            gateway_leaf_key,
            active_client,
            _directory: directory,
        }
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
            next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            next_tls_certificate: DerCertificate::new(vec![7; 128]).expect("der"),
            next_pq_certificate: candidate_leaf.clone(),
            issued_at: 1_000,
            stage_expires_at,
            window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
            reason: RotationReason::Scheduled,
            signature: MlDsa87Signature::placeholder(),
        };
        authorization.sign(&fixture.ca.private).expect("sign")
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
    fn a_commit_signed_by_both_keys_promotes_the_candidate_to_next() {
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
        let generation = authorization.candidate().expect("candidate");

        let commit = ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id: authorization.stage_id,
            grant_fingerprint: Fingerprint::of(b"grant"),
            stage_receipt_fingerprint: receipt.fingerprint(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(2),
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: generation.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: generation.pq_certificate_fingerprint,
            stage_expires_at: 5_000,
            committed_at: 1_200,
            active_pq_signature: MlDsa87Signature::placeholder(),
            staged_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.active_client.private, &candidate.private)
        .expect("sign");

        assert_eq!(
            fixture
                .registry
                .commit(&client_key(2), &commit, 1_300)
                .expect("commit"),
            InstallOutcome::Installed
        );
        let peer = fixture.registry.peer(&client_key(2)).expect("peer");
        assert!(peer.state.pending.is_none());
        assert_eq!(peer.state.next.as_ref().expect("next").generation, 5);

        // Late is late: past the lease the same commit is refused.
        let mut late = fixture;
        assert!(late
            .registry
            .commit(&client_key(2), &commit, 5_000)
            .is_err());
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
            .expect("staging");
        let generation = authorization.candidate().expect("candidate");

        let commit = ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id: authorization.stage_id,
            grant_fingerprint: Fingerprint::of(b"grant"),
            stage_receipt_fingerprint: receipt.fingerprint(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(2),
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: generation.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: generation.pq_certificate_fingerprint,
            stage_expires_at: 5_000,
            committed_at: 1_200,
            active_pq_signature: MlDsa87Signature::placeholder(),
            staged_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&stranger.private, &candidate.private)
        .expect("sign");

        assert!(matches!(
            fixture.registry.commit(&client_key(2), &commit, 1_300),
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

        fixture.registry.revoke(&client_key(2), 1).expect("revoke");
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
}
