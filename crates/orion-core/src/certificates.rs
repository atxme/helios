//! Orion's trust store: anchors, slots, the 80 % planner and atomic apply.
//!
//! This is the client half of spec §4.3 and §8. It holds what a profile pins —
//! `CA-PQ`, the trust domain, the gateway's active and next leaves, the Astra
//! service key, and its own certificate generations — and it applies trust
//! updates in **one** local write.
//!
//! # Why the renewal instant is derived, not drawn
//!
//! The window opens at 80 % of the leaf's life, and every client in a fleet
//! reaches it at nearly the same moment. Drawing a random instant inside it
//! would disperse them — until the first restart, when a fresh draw would
//! bunch them up again or move a renewal that was about to happen.
//!
//! [`renewal_instant`] instead derives the instant from values that do not
//! change: the client's WireGuard key, the generation and the certificate's
//! own period. It is stable across restarts by construction — there is nothing
//! to persist, and therefore nothing that can be lost — and it is uniform
//! across the fleet because the keys are.
//!
//! # Why nothing is applied halfway
//!
//! A trust update can move the CA, the TLS CA, the Astra service key, the
//! gateway identity and the client's own candidate. Applying them as they
//! arrive would produce a store that trusts the new anchor and still pins the
//! old gateway — a state no participant ever intended. [`TrustStore::apply`]
//! verifies the whole ordered set first and commits it with a single write;
//! a failure anywhere leaves the live state untouched.

use std::path::{Path, PathBuf};

use aether::certificates::{
    client::ClientCertificateGeneration,
    encoding::{Fingerprint, TrustDomainId, WireGuardKey},
    gateway::GatewayIdentityTransition,
    state::{
        base_state_fingerprint, AstraProfile, ClientCertificateState, ClientTlsCaState,
        GatewayCertificateState, InstallOutcome,
    },
    transport::{OrionTrustUpdateDocument, TrustUpdateObject},
    CertificateError,
};
use serde::{Deserialize, Serialize};

/// Everything a `helios_key_negotiation` profile pins, in one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    pub trust_domain_id: TrustDomainId,
    pub client_wg_public_key: WireGuardKey,
    pub gateway: GatewayCertificateState,
    pub client_tls_ca: ClientTlsCaState,
    pub astra: AstraProfile,
    pub issuer_epoch: u64,
    pub certificates: ClientCertificateState,
    /// The staged gateway transition itself, not just its slots.
    ///
    /// An abort names the exact document it cancels, and verifying it needs
    /// that document. Keeping only the certificates would make a tombstone
    /// unverifiable, and a client that cannot apply an abort refuses the next
    /// epoch for good — the sequential counter would never advance again.
    pub staged_gateway_transition: Option<GatewayIdentityTransition>,
    /// Last `(astra_service_key_epoch, status_epoch)` accepted, so a replayed
    /// older status cannot move the local view backwards.
    pub last_status: Option<(u64, u64)>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("trust object refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust store is unreadable: {0}")]
    Corrupt(String),
}

/// The store and its file.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    state: TrustState,
}

impl TrustStore {
    pub fn new(path: PathBuf, state: TrustState) -> Self {
        Self { path, state }
    }

    pub fn load(path: &Path) -> Result<Option<Self>, TrustError> {
        match std::fs::read(path) {
            Ok(raw) => {
                let state: TrustState = serde_json::from_slice(&raw)
                    .map_err(|error| TrustError::Corrupt(error.to_string()))?;
                Ok(Some(Self {
                    path: path.to_path_buf(),
                    state,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(TrustError::Io(error)),
        }
    }

    pub fn state(&self) -> &TrustState {
        &self.state
    }

    pub fn save(&self) -> Result<(), TrustError> {
        let encoded = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| TrustError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
        Ok(())
    }

    /// SHA-256 of the complete live state, as a manifest binds it (spec §8.1).
    pub fn base_state_fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        base_state_fingerprint(
            &self.state.gateway,
            &self.state.client_tls_ca,
            &self.state.astra,
            self.state.issuer_epoch,
            &self.state.certificates,
        )
    }

    /// The gateway PQ leaf this client may accept right now.
    pub fn acceptable_gateway_fingerprints(
        &self,
        now_unix: u64,
    ) -> Result<Vec<Fingerprint>, CertificateError> {
        self.state.gateway.acceptable_pq_fingerprints(now_unix)
    }

    /// Instant at which this client should open its own renewal.
    pub fn renewal_at(&self) -> Result<u64, CertificateError> {
        renewal_instant(
            &self.state.certificates.active,
            &self.state.client_wg_public_key,
        )
    }

    /// Applies a verified, complete set of trust objects in one write.
    ///
    /// The objects arrive in the apply order the manifest declared; each is
    /// verified against the anchors the store **already** holds, in a
    /// temporary copy. Only if every one of them lands does the copy replace
    /// the live state. A partial success is not exposed, because there is no
    /// instant at which it exists.
    pub fn apply(
        &mut self,
        objects: &[TrustUpdateObject],
        now_unix: u64,
    ) -> Result<usize, TrustError> {
        let mut candidate = self.state.clone();
        let mut applied = 0usize;

        for object in objects {
            match object {
                TrustUpdateObject::CaTransition(transition) => {
                    if candidate
                        .gateway
                        .apply_ca_transition(transition, now_unix)?
                        == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::ClientTlsCaTransition(transition) => {
                    if candidate.client_tls_ca.apply_transition(
                        transition,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        now_unix,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::AstraServiceKeyTransition(transition) => {
                    if candidate.astra.apply_service_key_transition(
                        transition,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::AstraServiceKeyEmergencyReplacement(replacement) => {
                    if candidate.astra.apply_emergency_replacement(
                        replacement,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        candidate.certificates.revocation_epoch,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    if candidate.gateway.install_transition(transition, now_unix)?
                        == InstallOutcome::Installed
                    {
                        candidate.staged_gateway_transition = Some((**transition).clone());
                        applied += 1;
                    }
                }
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    // The store holds one staged transition at a time, so the
                    // document an abort must name is that one. Without it the
                    // abort is unverifiable, and refusing is the only safe
                    // answer: applying a cancellation on trust would let a
                    // forged tombstone remove a legitimate decision.
                    let staged = candidate.staged_gateway_transition.clone().ok_or(
                        CertificateError::IllegalStateTransition("no staged transition to abort"),
                    )?;
                    if candidate.gateway.apply_abort(abort, &staged, now_unix)?
                        == InstallOutcome::Installed
                    {
                        candidate.staged_gateway_transition = None;
                        applied += 1;
                    }
                }
                TrustUpdateObject::CertificateRevocation(revocation) => {
                    revocation.verify(
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        candidate.certificates.revocation_epoch,
                    )?;
                    // A revocation naming this client's own identity is
                    // terminal, and it dominates whatever else the transaction
                    // carried for it.
                    let active = candidate.certificates.active.pq_certificate_fingerprint;
                    if revocation.revokes(&active, now_unix) {
                        candidate.certificates.revoke(revocation.revocation_epoch);
                    }
                    applied += 1;
                }
                // The delegation, the staging and the grant are not trust
                // anchors: they are checked and installed by the rotation
                // flow, which holds the private keys they refer to.
                TrustUpdateObject::AstraIssuerAuthorization(_)
                | TrustUpdateObject::ClientCertificateStageAuthorization(_)
                | TrustUpdateObject::ClientCertificateRotationGrant(_)
                | TrustUpdateObject::CertificateStatus(_) => {}
            }
        }

        // One write, after everything verified. A failure above returned
        // already, and the live state was never touched.
        self.state = candidate;
        self.save()?;
        Ok(applied)
    }

    /// Applies an offline `orion-trust-update` document (spec §8.4).
    ///
    /// The signature is checked under the CA active at the **start** of the
    /// import, taken from this store and never from the document.
    pub fn apply_document(
        &mut self,
        document: &OrionTrustUpdateDocument,
        now_unix: u64,
    ) -> Result<usize, TrustError> {
        document.verify(
            &self.state.gateway.current_ca_public_key,
            &self.state.trust_domain_id,
        )?;
        self.apply(&document.objects, now_unix)
    }

    /// Promotes every slot whose overlap has ended.
    pub fn promote_due(&mut self, now_unix: u64) -> Result<bool, TrustError> {
        let mut moved = self.state.gateway.promote_if_due(now_unix)?;
        if moved {
            // The staged document has done its job: keeping it would let a
            // late abort name a transition that is already the active one.
            self.state.staged_gateway_transition = None;
        }
        moved |= self.state.gateway.promote_ca_if_due(now_unix);
        moved |= self.state.client_tls_ca.promote_if_due(now_unix);
        moved |= self.state.astra.promote_service_key_if_due(now_unix);
        moved |= self.state.certificates.promote_if_due(now_unix);
        if moved {
            self.save()?;
        }
        Ok(moved)
    }
}

/// The instant this client opens its renewal window (spec §4.3).
///
/// Derived, never drawn: the offset inside `[renewal_at, not_after)` comes
/// from the client's WireGuard key, the generation and the certificate period.
/// Restarting recomputes the same value, so a renewal that was about to happen
/// still happens, and the fleet stays spread out.
pub fn renewal_instant(
    generation: &ClientCertificateGeneration,
    client_wg_public_key: &WireGuardKey,
) -> Result<u64, CertificateError> {
    let validity = generation.validity()?;
    let renewal_at = validity.renewal_at()?;
    let span = validity
        .not_after
        .checked_sub(renewal_at)
        .filter(|span| *span > 0)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(b"helios-client-renewal-dispersion-v5");
    input.extend_from_slice(client_wg_public_key.as_bytes());
    input.extend_from_slice(&generation.generation.to_be_bytes());
    input.extend_from_slice(&validity.not_before.to_be_bytes());
    input.extend_from_slice(&validity.not_after.to_be_bytes());
    let digest = Fingerprint::of(&input);
    let offset = u64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("a fingerprint is 32 bytes"),
    ) % span;

    renewal_at
        .checked_add(offset)
        .ok_or(CertificateError::ArithmeticOverflow)
}

/// Whether a renewal is due at `now_unix`.
pub fn renewal_is_due(
    generation: &ClientCertificateGeneration,
    client_wg_public_key: &WireGuardKey,
    now_unix: u64,
) -> Result<bool, CertificateError> {
    Ok(now_unix >= renewal_instant(generation, client_wg_public_key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "certificate-signing")]
    use aether::certificates::encoding::DerCertificate;
    #[cfg(feature = "certificate-signing")]
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    fn generation(index: u64) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: index,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(&[index as u8, 1]),
            pq_certificate_fingerprint: Fingerprint::of(&[index as u8, 2]),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    /// Derived, not drawn: the same inputs always give the same instant, so a
    /// restart never moves a renewal that was about to happen.
    #[test]
    fn the_renewal_instant_is_stable_across_restarts() {
        let generation = generation(4);
        let first = renewal_instant(&generation, &key(1)).expect("instant");
        let second = renewal_instant(&generation, &key(1)).expect("instant");
        assert_eq!(first, second);
    }

    /// And it is inside the window it belongs to — never before 80 %, never at
    /// or after the expiry.
    #[test]
    fn the_renewal_instant_stays_inside_the_window() {
        let generation = generation(4);
        let validity = generation.validity().expect("validity");
        let renewal_at = validity.renewal_at().expect("renewal");
        for seed in 0..64u8 {
            let instant = renewal_instant(&generation, &key(seed)).expect("instant");
            assert!(instant >= renewal_at, "seed {seed}");
            assert!(instant < validity.not_after, "seed {seed}");
        }
    }

    /// Different clients land on different instants: that dispersion is the
    /// whole point, and a fleet arriving together is what it prevents.
    #[test]
    fn two_clients_do_not_renew_at_the_same_instant() {
        let generation = generation(4);
        let instants: std::collections::BTreeSet<_> = (0..32u8)
            .map(|seed| renewal_instant(&generation, &key(seed)).expect("instant"))
            .collect();
        assert!(
            instants.len() > 24,
            "expected a spread, got {} distinct instants",
            instants.len()
        );
    }

    /// A new generation moves the instant even for the same client, so two
    /// consecutive renewals do not fall on the same offset.
    #[test]
    fn a_new_generation_moves_the_instant() {
        assert_ne!(
            renewal_instant(&generation(4), &key(1)).expect("instant"),
            renewal_instant(&generation(5), &key(1)).expect("instant")
        );
    }

    #[test]
    fn a_renewal_is_due_only_from_its_own_instant() {
        let generation = generation(4);
        let instant = renewal_instant(&generation, &key(1)).expect("instant");
        assert!(!renewal_is_due(&generation, &key(1), instant - 1).expect("due"));
        assert!(renewal_is_due(&generation, &key(1), instant).expect("due"));
    }

    #[cfg(feature = "certificate-signing")]
    fn gateway_leaf() -> PqCertificate {
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: key(9).to_base64(),
            ml_dsa_87_public_key: String::new(),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: String::new(),
        }
    }

    #[cfg(feature = "certificate-signing")]
    fn store(
        path: PathBuf,
        anchor: aether::certificates::encoding::MlDsa87PublicKey,
        service: aether::certificates::encoding::MlDsa87PublicKey,
    ) -> TrustStore {
        TrustStore::new(
            path,
            TrustState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                client_wg_public_key: key(2),
                gateway: GatewayCertificateState {
                    trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                    gateway_wg_public_key: key(9),
                    server_name: "gateway.example".into(),
                    ca_epoch: 1,
                    current_ca_public_key: anchor,
                    next_ca_public_key: None,
                    ca_activation_at: None,
                    ca_retire_active_at: None,
                    active_gateway_identity_epoch: 1,
                    gateway_decision_epoch: 1,
                    next_gateway_identity_epoch: None,
                    last_aborted_transition: None,
                    active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                    next_gateway_tls_certificate: None,
                    active_gateway_certificate: gateway_leaf(),
                    next_gateway_certificate: None,
                    activation_at: None,
                    retire_active_at: None,
                    published: false,
                },
                client_tls_ca: ClientTlsCaState {
                    ca_tls_epoch: 1,
                    active_client_tls_ca_certificate: DerCertificate::new(vec![2; 64])
                        .expect("der"),
                    next_client_tls_ca_certificate: None,
                    activation_at: None,
                    retire_active_at: None,
                },
                astra: AstraProfile {
                    authority_url: "https://astra.example".into(),
                    webauthn_rp_id: "astra.example".into(),
                    active_astra_service_public_key: service,
                    next_astra_service_public_key: None,
                    astra_service_key_epoch: 1,
                    service_key_activation_at: None,
                    service_key_retire_active_at: None,
                },
                issuer_epoch: 1,
                certificates: ClientCertificateState::new(generation(4)),
                staged_gateway_transition: None,
                last_status: None,
            },
        )
    }

    /// A transaction that fails anywhere leaves the live state untouched —
    /// the property that keeps a mixed trust store from ever existing.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_transaction_that_fails_leaves_the_live_state_untouched() {
        use aether::certificates::authority::CaTransition;
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::window::TransitionWindow;

        let directory = tempfile::tempdir().expect("temp dir");
        let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public.clone(),
            service_public,
        );
        let before = store.state().clone();

        let valid = CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: anchor_public.authority_fingerprint(),
            next_ca_public_key: next_public.clone(),
            next_ca_fingerprint: next_public.authority_fingerprint(),
            window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private, &next_private)
        .expect("sign");

        // A **different** second CA transition cannot install: the store
        // already holds a rotation in flight after the first one, and it never
        // holds three anchors. (An identical replay would be idempotent — that
        // is the rule of spec §4.2, and a different one is the conflict.)
        let (other_private, other_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let conflicting = CaTransition {
            next_ca_public_key: other_public.clone(),
            next_ca_fingerprint: other_public.authority_fingerprint(),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
            ..valid.clone()
        }
        .sign(&anchor_private, &other_private)
        .expect("sign");
        let objects = vec![
            TrustUpdateObject::CaTransition(Box::new(valid)),
            TrustUpdateObject::CaTransition(Box::new(conflicting)),
        ];
        assert!(store.apply(&objects, 500).is_err());
        assert_eq!(
            store.state(),
            &before,
            "a failed transaction must not move the live state"
        );
        assert!(
            TrustStore::load(&directory.path().join("trust.json"))
                .expect("load")
                .is_none(),
            "and it must not have written anything at all"
        );
    }
}
