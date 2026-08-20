//! Bounded states and their transitions — spec §3.2, §3.3, §4.2 and §4.4.
//!
//! Everything here holds **at most two** of anything: two CA anchors, two
//! gateway leaves per family, two client generations, two Astra service keys.
//! That is not an optimisation. An open-ended list of acceptable fingerprints
//! is an open-ended list of things an attacker can try to get added, and a
//! verifier that loops over a list has no natural place to say "this one is
//! current".
//!
//! # Counters decide, clocks only schedule
//!
//! A generation is persisted before an identity is served. Once promoted, the
//! outgoing slot is gone, and a clock moved backwards finds nothing to
//! reactivate — the state has no memory of it. Conversely, no counter ever
//! moves because time passed: promotion happens at `not_after` because the
//! decision that scheduled it was persisted, not because the date arrived.
//!
//! # `revoked` dominates
//!
//! A revoked identity refuses staging, commit, promotion and rollback, and no
//! operator credential lifts it. Only a fresh admission creates a new
//! identity. This is the one state that wins every race in this module.
//!
//! # Two scopes, two counters, two effects
//!
//! A revocation names either the gateway or a client, and the two axes never
//! meet. [`TrustLedger`] holds the gateway counter, [`ClientCertificateState`]
//! its own, and [`TrustLedger::apply_due`] routes each decision to the state it
//! actually removes something from. Sharing one counter would let a gateway
//! revocation consume a client's, and then the client's own revocation would
//! be refused as a rollback — the decision would exist, be signed, be
//! verified, and change nothing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::key_negotiation::PqCertificate;

use super::{
    approval::{AstraCredentialBinding, AstraPolicyPin},
    authority::{
        AstraIssuerAuthorization, AstraServiceKeyTransition, CaTransition, ClientTlsCaTransition,
        EmergencyAstraServiceKeyReplacement,
    },
    client::{
        ClientCertificateGeneration, ClientCertificateRotationGrant,
        ClientCertificateStageAuthorization,
    },
    encoding::{
        CanonicalBytes, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId,
        WireGuardKey,
    },
    gateway::{
        pq_certificate_fingerprint, GatewayIdentityTransition, GatewayTransitionAbort,
        GatewayTransitionAbortTombstone,
    },
    revocation::{EmergencyCertificateRevocation, RevocationScope},
    status::AstraCertificateStatus,
    window::TransitionWindow,
    CertificateError,
};

const BASE_STATE_DOMAIN: &[u8] = b"helios-trust-base-state-v5";

/// What installing an object did, once it verified.
///
/// The distinction is the idempotency rule of spec §4.2: the same bytes at the
/// same generation change nothing and succeed; different bytes at the same
/// generation are a conflict, which the verifiers refuse before reaching here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The state moved.
    Installed,
    /// The state already held exactly this decision.
    AlreadyPresent,
}

/// The gateway identity and the anchors it hangs from (spec §3.2).
///
/// Fingerprints are **derived**, never stored beside the certificates they
/// describe: two fields that must agree are two fields that can disagree, and
/// the one an attacker gets to choose would be the one a comparison used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCertificateState {
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,

    pub ca_epoch: u64,
    pub current_ca_public_key: MlDsa87PublicKey,
    pub next_ca_public_key: Option<MlDsa87PublicKey>,
    /// Fingerprint of the `CaTransition` document that staged `next_ca`.
    pub next_ca_transition_fingerprint: Option<Fingerprint>,
    pub ca_activation_at: Option<u64>,
    pub ca_retire_active_at: Option<u64>,

    /// Epoch of the leaf actually served.
    pub active_gateway_identity_epoch: u64,
    /// Highest transition **or abort** number accepted. Equal to the active
    /// epoch outside an abort that has not yet been followed by a promotion.
    pub gateway_decision_epoch: u64,
    pub next_gateway_identity_epoch: Option<u64>,
    /// Fingerprint of the staged transition **document**.
    ///
    /// Idempotency is "the same signed bytes", not "the same leaves": two
    /// transitions can install identical certificates under different windows,
    /// reasons or epochs, and treating the second as a replay would silently
    /// keep the first decision while the sender believed the second landed.
    pub next_transition_fingerprint: Option<Fingerprint>,
    pub last_aborted_transition: Option<GatewayTransitionAbortTombstone>,

    pub active_gateway_tls_certificate: DerCertificate,
    pub next_gateway_tls_certificate: Option<DerCertificate>,
    pub active_gateway_certificate: PqCertificate,
    pub next_gateway_certificate: Option<PqCertificate>,

    pub activation_at: Option<u64>,
    pub retire_active_at: Option<u64>,
    /// Set while a staged transition has not yet been distributed. Once
    /// `true`, an abort is refused for good (spec §6.3).
    pub published: bool,
    /// Terminal: the served gateway identity has been revoked (spec §10.1).
    ///
    /// Nothing local repairs it. A revoked gateway offers no acceptable leaf,
    /// so the client refuses the handshake instead of negotiating with an
    /// identity the authority has withdrawn.
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revocation_epoch: u64,
}

impl GatewayCertificateState {
    pub fn active_tls_fingerprint(&self) -> Fingerprint {
        self.active_gateway_tls_certificate.fingerprint()
    }

    pub fn active_pq_fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        pq_certificate_fingerprint(&self.active_gateway_certificate)
    }

    /// The PQ leaves a client may accept at `now_unix`.
    ///
    /// The next one only from `activation_at`: before that it is prepared, not
    /// served, and accepting it early would let a transition take effect
    /// ahead of the schedule every other participant persisted.
    pub fn acceptable_pq_fingerprints(
        &self,
        now_unix: u64,
    ) -> Result<Vec<Fingerprint>, CertificateError> {
        if self.revoked {
            return Ok(Vec::new());
        }
        let mut fingerprints = vec![self.active_pq_fingerprint()?];
        if let (Some(certificate), Some(activation_at)) =
            (&self.next_gateway_certificate, self.activation_at)
        {
            if now_unix >= activation_at {
                fingerprints.push(pq_certificate_fingerprint(certificate)?);
            }
        }
        Ok(fingerprints)
    }

    /// Installs a verified transition into the `next` slots.
    ///
    /// Verification happens **here**, against the anchors this state already
    /// holds — a caller cannot hand in a transition it verified against
    /// something else.
    pub fn install_transition(
        &mut self,
        transition: &GatewayIdentityTransition,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        // A revoked leaf never comes back, whatever signs the document that
        // carries it (spec §10.2).
        ledger.assert_not_revoked(&transition.installed_fingerprints()?)?;
        // An identical decision already held is a no-op, and it must be
        // recognised before the generation rule refuses `current` as a repeat.
        // "Identical" is the whole signed document: the same leaves under a
        // different window are a different decision.
        let fingerprint = transition.fingerprint()?;
        if self
            .next_transition_fingerprint
            .is_some_and(|staged| staged.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if self.next_gateway_identity_epoch.is_some() {
            return Err(CertificateError::IllegalStateTransition(
                "a transition is already staged",
            ));
        }
        transition.verify(
            &self.current_ca_public_key,
            &self.trust_domain_id,
            self.ca_epoch,
            self.gateway_decision_epoch,
            &self.gateway_wg_public_key,
            &self.server_name,
            &self.active_tls_fingerprint(),
            &self.active_pq_fingerprint()?,
        )?;
        if now_unix >= transition.window.activation_at {
            return Err(CertificateError::IllegalStateTransition(
                "transition activates in the past",
            ));
        }

        self.gateway_decision_epoch = transition.gateway_identity_epoch;
        self.next_gateway_identity_epoch = Some(transition.gateway_identity_epoch);
        self.next_transition_fingerprint = Some(fingerprint);
        if transition.next_gateway_tls_certificate.is_some() {
            self.next_gateway_tls_certificate = transition.next_gateway_tls_certificate.clone();
        }
        if transition.next_gateway_certificate.is_some() {
            self.next_gateway_certificate = transition.next_gateway_certificate.clone();
        }
        self.activation_at = Some(transition.window.activation_at);
        self.retire_active_at = Some(transition.window.not_after);
        self.published = false;
        Ok(InstallOutcome::Installed)
    }

    /// Marks the staged transition as distributable. Irreversible.
    ///
    /// Persisted **before** the first byte leaves the gateway: a failure after
    /// this write stays published, because the recipient may already hold the
    /// answer (spec §6.3).
    pub fn mark_published(&mut self) -> Result<(), CertificateError> {
        if self.next_gateway_identity_epoch.is_none() {
            return Err(CertificateError::IllegalStateTransition("nothing staged"));
        }
        self.published = true;
        Ok(())
    }

    /// Cancels a staged, unpublished transition (spec §6.3).
    ///
    /// The slot is removed and the tombstone persisted in one write. The epoch
    /// stays consumed: the next attempt uses `decision_epoch + 1`.
    pub fn apply_abort(
        &mut self,
        abort: &GatewayTransitionAbort,
        transition: &GatewayIdentityTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if let Some(tombstone) = &self.last_aborted_transition {
            if tombstone.abort_fingerprint.matches(&abort.fingerprint()) {
                return Ok(InstallOutcome::AlreadyPresent);
            }
        }
        if self.next_gateway_identity_epoch != Some(abort.gateway_identity_epoch) {
            return Err(CertificateError::IllegalStateTransition(
                "no staged transition at this epoch",
            ));
        }
        abort.verify(
            &self.current_ca_public_key,
            transition,
            self.published,
            now_unix,
        )?;

        self.next_gateway_identity_epoch = None;
        self.next_transition_fingerprint = None;
        self.next_gateway_tls_certificate = None;
        self.next_gateway_certificate = None;
        self.activation_at = None;
        self.retire_active_at = None;
        self.last_aborted_transition = Some(abort.tombstone());
        Ok(InstallOutcome::Installed)
    }

    /// Promotes the staged identity at `not_after`, deleting the outgoing one.
    ///
    /// Returns whether anything moved. Promotion is definitive even for a
    /// client that never observed the transition: the decision was persisted,
    /// and the alternative is a fleet that waits forever on its slowest member.
    pub fn promote_if_due(&mut self, now_unix: u64) -> Result<bool, CertificateError> {
        let Some(retire_at) = self.retire_active_at else {
            return Ok(false);
        };
        if now_unix < retire_at {
            return Ok(false);
        }
        let Some(epoch) = self.next_gateway_identity_epoch else {
            return Ok(false);
        };
        if let Some(certificate) = self.next_gateway_tls_certificate.take() {
            self.active_gateway_tls_certificate = certificate;
        }
        if let Some(certificate) = self.next_gateway_certificate.take() {
            self.active_gateway_certificate = certificate;
        }
        self.active_gateway_identity_epoch = epoch;
        self.next_gateway_identity_epoch = None;
        self.next_transition_fingerprint = None;
        self.activation_at = None;
        self.retire_active_at = None;
        self.published = false;
        Ok(true)
    }

    /// Withdraws the named gateway leaves (spec §10.1).
    ///
    /// Two outcomes, and the difference is which slot the fingerprints hit:
    ///
    /// - a leaf that is **served** makes the state terminal. There is no
    ///   partial gateway identity: the generation is indivisible, so naming
    ///   only its TLS half still removes the whole of it, and `acceptable_pq_
    ///   fingerprints` then returns nothing at all;
    /// - a leaf that is merely **staged** cancels the transition and leaves
    ///   the active identity alone. That is not leniency — the staged leaf was
    ///   never served, and retiring a working gateway because its successor
    ///   was compromised would take the fleet down for nothing.
    ///
    /// Returns whether anything moved.
    pub fn apply_revocation(
        &mut self,
        revoked_tls_fingerprint: Option<&Fingerprint>,
        revoked_pq_fingerprint: Option<&Fingerprint>,
        revocation_epoch: u64,
    ) -> Result<bool, CertificateError> {
        let named = |candidate: &Fingerprint| {
            [revoked_tls_fingerprint, revoked_pq_fingerprint]
                .into_iter()
                .flatten()
                .any(|revoked| revoked.matches(candidate))
        };

        if named(&self.active_tls_fingerprint()) || named(&self.active_pq_fingerprint()?) {
            self.revoked = true;
            self.revocation_epoch = self.revocation_epoch.max(revocation_epoch);
            self.next_gateway_identity_epoch = None;
            self.next_transition_fingerprint = None;
            self.next_gateway_tls_certificate = None;
            self.next_gateway_certificate = None;
            self.activation_at = None;
            self.retire_active_at = None;
            self.published = false;
            return Ok(true);
        }

        let staged_hit = self
            .next_gateway_tls_certificate
            .as_ref()
            .map(DerCertificate::fingerprint)
            .is_some_and(|fingerprint| named(&fingerprint))
            || self
                .next_gateway_certificate
                .as_ref()
                .map(pq_certificate_fingerprint)
                .transpose()?
                .is_some_and(|fingerprint| named(&fingerprint));
        if staged_hit {
            self.revocation_epoch = self.revocation_epoch.max(revocation_epoch);
            self.next_gateway_identity_epoch = None;
            self.next_transition_fingerprint = None;
            self.next_gateway_tls_certificate = None;
            self.next_gateway_certificate = None;
            self.activation_at = None;
            self.retire_active_at = None;
            self.published = false;
            return Ok(true);
        }
        // A revocation naming a leaf this state never held is not an error —
        // an offline document may carry the fleet's decisions — but its epoch
        // is still consumed by the caller, so it can never be replayed. The
        // tombstone written beside it is what stops that leaf from arriving
        // later through a transition.
        self.revocation_epoch = self.revocation_epoch.max(revocation_epoch);
        Ok(false)
    }

    /// Installs a CA rotation, keeping at most two anchors (spec §9.2).
    pub fn apply_ca_transition(
        &mut self,
        transition: &CaTransition,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        ledger.assert_not_revoked(&[transition.next_ca_fingerprint])?;
        let fingerprint = transition.fingerprint();
        if self
            .next_ca_transition_fingerprint
            .is_some_and(|staged| staged.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if self.next_ca_public_key.is_some() {
            return Err(CertificateError::IllegalStateTransition(
                "a CA rotation is already in flight",
            ));
        }
        transition.verify(
            &self.current_ca_public_key,
            &self.trust_domain_id,
            self.ca_epoch,
        )?;
        if now_unix >= transition.window.activation_at {
            return Err(CertificateError::IllegalStateTransition(
                "CA rotation activates in the past",
            ));
        }
        self.next_ca_public_key = Some(transition.next_ca_public_key.clone());
        self.next_ca_transition_fingerprint = Some(fingerprint);
        self.ca_activation_at = Some(transition.window.activation_at);
        self.ca_retire_active_at = Some(transition.window.not_after);
        Ok(InstallOutcome::Installed)
    }

    /// Retires the outgoing anchor at the end of its overlap.
    pub fn promote_ca_if_due(&mut self, now_unix: u64) -> bool {
        let Some(retire_at) = self.ca_retire_active_at else {
            return false;
        };
        if now_unix < retire_at {
            return false;
        }
        let Some(next) = self.next_ca_public_key.take() else {
            return false;
        };
        self.current_ca_public_key = next;
        self.ca_epoch += 1;
        self.next_ca_transition_fingerprint = None;
        self.ca_activation_at = None;
        self.ca_retire_active_at = None;
        true
    }

    /// The anchors a signature may be verified under at `now_unix`.
    pub fn acceptable_anchors(&self, now_unix: u64) -> Vec<&MlDsa87PublicKey> {
        let mut anchors = vec![&self.current_ca_public_key];
        if let (Some(next), Some(activation_at)) = (&self.next_ca_public_key, self.ca_activation_at)
        {
            if now_unix >= activation_at {
                anchors.push(next);
            }
        }
        anchors
    }

    pub(crate) fn snapshot(&self, bytes: &mut CanonicalBytes) -> Result<(), CertificateError> {
        bytes
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .fingerprint(&self.current_ca_public_key.authority_fingerprint())
            .optional_fingerprint(
                self.next_ca_public_key
                    .as_ref()
                    .map(MlDsa87PublicKey::authority_fingerprint)
                    .as_ref(),
            )
            .u64(self.active_gateway_identity_epoch)
            .u64(self.gateway_decision_epoch)
            .fingerprint(&self.active_tls_fingerprint())
            .fingerprint(&self.active_pq_fingerprint()?)
            .optional_fingerprint(
                self.next_gateway_tls_certificate
                    .as_ref()
                    .map(DerCertificate::fingerprint)
                    .as_ref(),
            )
            .optional_fingerprint(
                self.next_gateway_certificate
                    .as_ref()
                    .map(pq_certificate_fingerprint)
                    .transpose()?
                    .as_ref(),
            )
            .optional_fingerprint(
                self.last_aborted_transition
                    .as_ref()
                    .map(|tombstone| tombstone.abort_fingerprint)
                    .as_ref(),
            )
            .optional_fingerprint(self.next_transition_fingerprint.as_ref())
            .optional_fingerprint(self.next_ca_transition_fingerprint.as_ref())
            .u64(self.activation_at.unwrap_or(0))
            .u64(self.retire_active_at.unwrap_or(0))
            .u64(self.ca_activation_at.unwrap_or(0))
            .u64(self.ca_retire_active_at.unwrap_or(0))
            .u8(u8::from(self.published))
            .u8(u8::from(self.revoked))
            .u64(self.revocation_epoch);
        Ok(())
    }
}

/// The two client TLS anchors (spec §9.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsCaState {
    pub ca_tls_epoch: u64,
    pub active_client_tls_ca_certificate: DerCertificate,
    pub next_client_tls_ca_certificate: Option<DerCertificate>,
    /// Fingerprint of the `ClientTlsCaTransition` document that staged it.
    pub next_transition_fingerprint: Option<Fingerprint>,
    pub activation_at: Option<u64>,
    pub retire_active_at: Option<u64>,
}

impl ClientTlsCaState {
    /// Installs a rotation of the client TLS anchor, authorized by `CA-PQ`.
    pub fn apply_transition(
        &mut self,
        transition: &ClientTlsCaTransition,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        ledger.assert_not_revoked(&[transition.next_client_tls_ca_certificate.fingerprint()])?;
        let fingerprint = transition.fingerprint();
        if self
            .next_transition_fingerprint
            .is_some_and(|staged| staged.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if self.next_client_tls_ca_certificate.is_some() {
            return Err(CertificateError::IllegalStateTransition(
                "a TLS CA rotation is already in flight",
            ));
        }
        transition.verify(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            self.ca_tls_epoch,
            &self.active_client_tls_ca_certificate.fingerprint(),
        )?;
        if now_unix >= transition.window.activation_at {
            return Err(CertificateError::IllegalStateTransition(
                "TLS CA rotation activates in the past",
            ));
        }
        self.next_client_tls_ca_certificate =
            Some(transition.next_client_tls_ca_certificate.clone());
        self.next_transition_fingerprint = Some(fingerprint);
        self.activation_at = Some(transition.window.activation_at);
        self.retire_active_at = Some(transition.window.not_after);
        Ok(InstallOutcome::Installed)
    }

    pub fn promote_if_due(&mut self, now_unix: u64) -> bool {
        let Some(retire_at) = self.retire_active_at else {
            return false;
        };
        if now_unix < retire_at {
            return false;
        }
        let Some(next) = self.next_client_tls_ca_certificate.take() else {
            return false;
        };
        self.active_client_tls_ca_certificate = next;
        self.ca_tls_epoch += 1;
        self.next_transition_fingerprint = None;
        self.activation_at = None;
        self.retire_active_at = None;
        true
    }

    pub(crate) fn snapshot(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u64(self.ca_tls_epoch)
            .fingerprint(&self.active_client_tls_ca_certificate.fingerprint())
            .optional_fingerprint(
                self.next_client_tls_ca_certificate
                    .as_ref()
                    .map(DerCertificate::fingerprint)
                    .as_ref(),
            )
            .optional_fingerprint(self.next_transition_fingerprint.as_ref())
            .u64(self.activation_at.unwrap_or(0))
            .u64(self.retire_active_at.unwrap_or(0));
    }

    /// The chains an mTLS verifier accepts at `now_unix` — two at most.
    pub fn acceptable_anchors(&self, now_unix: u64) -> Vec<&DerCertificate> {
        let mut anchors = vec![&self.active_client_tls_ca_certificate];
        if let (Some(next), Some(activation_at)) =
            (&self.next_client_tls_ca_certificate, self.activation_at)
        {
            if now_unix >= activation_at {
                anchors.push(next);
            }
        }
        anchors
    }
}

/// Where a candidate generation sits in the staging protocol (spec §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStageState {
    /// The gateway has persisted the candidate; the client has no grant yet.
    PendingGrant,
    /// The client holds the grant and has not committed yet.
    PendingCommit,
}

/// A candidate generation held under a bounded lease (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificatePendingStage {
    pub stage_id: Id16,
    /// Fingerprint of the **signed** staging authorization that created it.
    ///
    /// The idempotency rule of spec §4.2 is "the same signed bytes", and this
    /// is what makes that literally true here. Comparing the candidate, the
    /// lease and the request fingerprint compares consequences: two
    /// authorizations differing only in their window, their reason or their
    /// signature would look identical, and the second sender would be told its
    /// decision landed when the first one is what the state still holds.
    pub authorization_fingerprint: Fingerprint,
    pub request_fingerprint: Fingerprint,
    pub candidate: ClientCertificateGeneration,
    pub state: PendingStageState,
    pub stage_expires_at: u64,
    /// Window the candidate will follow once committed.
    pub window: TransitionWindow,
}

/// The commit that produced the current `next` generation.
///
/// Both halves are needed: the identifier says *which* stage, the fingerprint
/// says *which document* closed it. A retry over a lossy link replays the same
/// signed commit and must be a no-op; a different commit naming the same stage
/// is a conflict, not a second success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedStage {
    pub stage_id: Id16,
    pub commit_fingerprint: Fingerprint,
}

/// Active generation, candidate and next — never more (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateState {
    pub active: ClientCertificateGeneration,
    pub pending: Option<ClientCertificatePendingStage>,
    pub next: Option<ClientCertificateGeneration>,
    pub activation_at: Option<u64>,
    pub retire_active_at: Option<u64>,
    /// Commit that produced the current `next`, so a replayed one is
    /// recognised as the same one instead of finding an empty `pending`.
    ///
    /// Without it, the second delivery of a successful commit looks exactly
    /// like a commit for a stage that never existed, and a retry over a lossy
    /// link would be reported as a refusal.
    pub last_committed_stage: Option<CommittedStage>,
    /// Terminal. No credential, campaign or grant lifts it.
    pub revoked: bool,
    pub revocation_epoch: u64,
}

impl ClientCertificateState {
    pub fn new(active: ClientCertificateGeneration) -> Self {
        Self {
            active,
            pending: None,
            next: None,
            activation_at: None,
            retire_active_at: None,
            last_committed_stage: None,
            revoked: false,
            revocation_epoch: 0,
        }
    }

    /// Persists a candidate under its lease, in state `pending_grant`.
    ///
    /// `pending` and `next` are never both set: the commit replaces the first
    /// by the second in one write, so there is no instant at which a peer has
    /// three generations.
    pub fn stage(
        &mut self,
        authorization: &ClientCertificateStageAuthorization,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        let candidate = authorization.candidate()?;
        ledger.assert_not_revoked(&[
            candidate.tls_certificate_fingerprint,
            candidate.pq_certificate_fingerprint,
        ])?;
        let authorization_fingerprint = authorization.fingerprint()?;
        if let Some(pending) = &self.pending {
            if pending.stage_id == authorization.stage_id {
                // Idempotency is the **same signed document**, not the same
                // consequences: two authorizations with identical candidates
                // and leases can still differ in window, reason or signature.
                if pending
                    .authorization_fingerprint
                    .matches(&authorization_fingerprint)
                {
                    return Ok(InstallOutcome::AlreadyPresent);
                }
                return Err(CertificateError::GenerationConflict {
                    generation: candidate.generation,
                });
            }
            return Err(CertificateError::StageAlreadyPresent);
        }
        if self.next.is_some() {
            return Err(CertificateError::StageAlreadyPresent);
        }
        if now_unix >= authorization.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        self.pending = Some(ClientCertificatePendingStage {
            stage_id: authorization.stage_id,
            authorization_fingerprint,
            request_fingerprint: authorization.request_fingerprint,
            candidate,
            state: PendingStageState::PendingGrant,
            stage_expires_at: authorization.stage_expires_at,
            window: authorization.window,
        });
        Ok(InstallOutcome::Installed)
    }

    /// Persists a candidate from the **grant**, as Orion does (spec §8.1.2).
    ///
    /// The two ends stage from different documents, and that asymmetry is the
    /// §0.5 amendment rather than an accident: `ClientCertificateStageAuthorization`
    /// travels Astra → Helios on the veth and Orion never carries it. What
    /// Orion holds is the grant, and the grant embeds the receipt the gateway
    /// signed over that authorization — so the stage identifier, the
    /// authorization fingerprint and the lease are all attested here, none of
    /// them taken on the client's word.
    ///
    /// The candidate lands directly in [`PendingStageState::PendingCommit`]:
    /// on this end there is no earlier moment. A client holds no candidate at
    /// all until the grant exists, and `pending_grant` would describe a state
    /// Orion is never in.
    ///
    /// The caller must have verified the grant first. This installs; it does
    /// not authenticate.
    pub fn stage_from_grant(
        &mut self,
        grant: &ClientCertificateRotationGrant,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        let candidate = grant.candidate()?;
        ledger.assert_not_revoked(&[
            candidate.tls_certificate_fingerprint,
            candidate.pq_certificate_fingerprint,
        ])?;
        let receipt = &grant.stage_receipt;
        if let Some(pending) = &self.pending {
            if pending.stage_id == receipt.stage_id {
                // Same rule as `stage`, read through the receipt: the identity
                // of a staging is the signed authorization behind it, not the
                // consequences two authorizations happen to share.
                if pending
                    .authorization_fingerprint
                    .matches(&receipt.stage_authorization_fingerprint)
                {
                    return Ok(InstallOutcome::AlreadyPresent);
                }
                return Err(CertificateError::GenerationConflict {
                    generation: candidate.generation,
                });
            }
            return Err(CertificateError::StageAlreadyPresent);
        }
        if self.next.is_some() {
            return Err(CertificateError::StageAlreadyPresent);
        }
        if now_unix >= receipt.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        self.pending = Some(ClientCertificatePendingStage {
            stage_id: receipt.stage_id,
            authorization_fingerprint: receipt.stage_authorization_fingerprint,
            request_fingerprint: receipt.request_fingerprint,
            candidate,
            state: PendingStageState::PendingCommit,
            stage_expires_at: receipt.stage_expires_at,
            window: grant.window,
        });
        Ok(InstallOutcome::Installed)
    }

    /// Marks the candidate as released to the client, still not activable.
    ///
    /// **Orion's** step, and only Orion's: the gateway never sees the grant
    /// travel, so its candidate stays `pending_grant` until the commit arrives
    /// (spec §7.3). A gateway that moved its own candidate here would then
    /// commit from a state it is not supposed to commit from.
    pub fn mark_pending_commit(&mut self, stage_id: &Id16) -> Result<(), CertificateError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(CertificateError::UnknownStage)?;
        if pending.stage_id != *stage_id {
            return Err(CertificateError::UnknownStage);
        }
        pending.state = PendingStageState::PendingCommit;
        Ok(())
    }

    /// Turns the candidate into the `next` generation, atomically.
    ///
    /// `required_state` is what the candidate must already be in, and the two
    /// ends require different things: Helios commits a candidate that is still
    /// `pending_grant` — it never sees the grant travel to the client — while
    /// Orion commits its own only once it holds the grant and has marked it
    /// `pending_commit` (spec §7.3). Passing the state in, rather than
    /// accepting whichever one is there, is what keeps one end from silently
    /// adopting the other's rule.
    ///
    /// The clock is read once by the caller, under the same serializer as
    /// revocation and purge: a commit that arrives at the deadline loses the
    /// race rather than winning it by a rounding.
    pub fn commit(
        &mut self,
        stage_id: &Id16,
        commit_fingerprint: &Fingerprint,
        required_state: PendingStageState,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        // A replay is recognised by the signed commit that produced the slot,
        // not by "there is a `next` roughly where one would be". Two things
        // follow: a different stage landing on the same generation is a
        // conflict, and a *different document* closing the same stage is a
        // conflict too — otherwise the second sender would be told its commit
        // landed while the first one is what the state holds.
        if let Some(committed) = &self.last_committed_stage {
            if committed.stage_id == *stage_id && self.next.is_some() {
                if committed.commit_fingerprint.matches(commit_fingerprint) {
                    return Ok(InstallOutcome::AlreadyPresent);
                }
                return Err(CertificateError::GenerationConflict {
                    generation: self.next.as_ref().map_or(0, |next| next.generation),
                });
            }
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(CertificateError::UnknownStage)?;
        if pending.stage_id != *stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if pending.state != required_state {
            return Err(CertificateError::IllegalStateTransition(
                "candidate is not in the state this end commits from",
            ));
        }
        if now_unix >= pending.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }
        let window = pending.window;
        let candidate = pending.candidate.clone();
        self.pending = None;
        self.next = Some(candidate);
        self.last_committed_stage = Some(CommittedStage {
            stage_id: *stage_id,
            commit_fingerprint: *commit_fingerprint,
        });
        self.activation_at = Some(window.activation_at);
        self.retire_active_at = Some(window.not_after);
        Ok(InstallOutcome::Installed)
    }

    /// Drops an uncommitted candidate at its lease expiry (spec §7.3).
    pub fn purge_expired(&mut self, now_unix: u64) -> bool {
        let Some(pending) = &self.pending else {
            return false;
        };
        if now_unix < pending.stage_expires_at {
            return false;
        }
        self.pending = None;
        true
    }

    /// Promotes `next` at `not_after`. The outgoing generation is deleted.
    pub fn promote_if_due(&mut self, now_unix: u64) -> bool {
        let Some(retire_at) = self.retire_active_at else {
            return false;
        };
        if now_unix < retire_at {
            return false;
        }
        let Some(next) = self.next.take() else {
            return false;
        };
        self.active = next;
        self.activation_at = None;
        self.retire_active_at = None;
        true
    }

    /// Terminal revocation: dominates staging, commit, promotion and rollback.
    /// The counter never moves backwards. Two revocations dated for different
    /// instants are applied in clock order, not in counter order, so the later
    /// decision can reach `effective_at` first — and writing its predecessor's
    /// number afterwards would make an already-consumed epoch deliverable
    /// again.
    pub fn revoke(&mut self, revocation_epoch: u64) {
        self.revoked = true;
        self.revocation_epoch = self.revocation_epoch.max(revocation_epoch);
        self.pending = None;
        self.next = None;
        self.activation_at = None;
        self.retire_active_at = None;
    }

    /// Whether the peer may present this exact TLS/PQ pair at `now_unix`.
    ///
    /// The pair is resolved against **one** generation: mixing the TLS of one
    /// with the PQ of the other is refused even though each half is valid.
    pub fn accepts_pair(&self, tls: &Fingerprint, pq: &Fingerprint, now_unix: u64) -> bool {
        if self.revoked {
            return false;
        }
        if self.active.accepts_pair(tls, pq) && self.active.is_valid_at(now_unix) {
            return true;
        }
        match (&self.next, self.activation_at) {
            (Some(next), Some(activation_at)) if now_unix >= activation_at => {
                next.accepts_pair(tls, pq) && next.is_valid_at(now_unix)
            }
            _ => false,
        }
    }

    /// The PQ fingerprint belonging to the **same generation** as `tls`.
    ///
    /// The negotiation resolves a caller by the fingerprint mTLS proved, then
    /// has to know which PQ leaf that caller may present. Returning the union
    /// of both generations would accept the mixed pair of spec §3.3 — the TLS
    /// of the outgoing identity beside the PQ of the incoming one, an identity
    /// the domain never issued. So the answer is one fingerprint: the partner
    /// of the half already proved.
    pub fn pq_paired_with_tls(&self, tls: &Fingerprint, now_unix: u64) -> Option<Fingerprint> {
        if self.revoked {
            return None;
        }
        if self.active.tls_certificate_fingerprint.matches(tls) && self.active.is_valid_at(now_unix)
        {
            return Some(self.active.pq_certificate_fingerprint);
        }
        match (&self.next, self.activation_at) {
            (Some(next), Some(activation_at))
                if now_unix >= activation_at
                    && next.tls_certificate_fingerprint.matches(tls)
                    && next.is_valid_at(now_unix) =>
            {
                Some(next.pq_certificate_fingerprint)
            }
            _ => None,
        }
    }

    /// PQ fingerprints acceptable at `now_unix`, for the trust-update route.
    pub fn acceptable_pq_fingerprints(&self, now_unix: u64) -> Vec<Fingerprint> {
        if self.revoked {
            return Vec::new();
        }
        let mut fingerprints = vec![self.active.pq_certificate_fingerprint];
        if let (Some(next), Some(activation_at)) = (&self.next, self.activation_at) {
            if now_unix >= activation_at {
                fingerprints.push(next.pq_certificate_fingerprint);
            }
        }
        fingerprints
    }

    /// Every fingerprint this peer occupies, for the global uniqueness rule.
    pub fn occupied_fingerprints(&self) -> Vec<Fingerprint> {
        let mut fingerprints = vec![
            self.active.tls_certificate_fingerprint,
            self.active.pq_certificate_fingerprint,
        ];
        for generation in [
            self.next.as_ref(),
            self.pending.as_ref().map(|p| &p.candidate),
        ]
        .into_iter()
        .flatten()
        {
            fingerprints.push(generation.tls_certificate_fingerprint);
            fingerprints.push(generation.pq_certificate_fingerprint);
        }
        fingerprints
    }

    /// Every value a decision about this peer could depend on (spec §8.1).
    ///
    /// Both families of both slots, the instants, the counters and the
    /// terminal flag. A snapshot that summarised only the PQ side would let a
    /// manifest be built against a state whose TLS half had already moved, and
    /// the transaction would then apply to a world it was not computed for —
    /// which is the exact failure `base_state_fingerprint` exists to catch.
    pub(crate) fn snapshot(&self, bytes: &mut CanonicalBytes) {
        generation_snapshot(bytes, &self.active);
        match &self.next {
            Some(next) => {
                bytes.u8(1);
                generation_snapshot(bytes, next);
            }
            None => {
                bytes.u8(0);
            }
        }
        match &self.pending {
            Some(pending) => {
                bytes
                    .u8(1)
                    .id(&pending.stage_id)
                    .fingerprint(&pending.authorization_fingerprint)
                    .fingerprint(&pending.request_fingerprint);
                generation_snapshot(bytes, &pending.candidate);
                bytes
                    .u8(match pending.state {
                        PendingStageState::PendingGrant => 0,
                        PendingStageState::PendingCommit => 1,
                    })
                    .u64(pending.stage_expires_at)
                    .u64(pending.window.not_before)
                    .u64(pending.window.activation_at)
                    .u64(pending.window.not_after);
            }
            None => {
                bytes.u8(0);
            }
        }
        match &self.last_committed_stage {
            Some(committed) => {
                bytes
                    .u8(1)
                    .id(&committed.stage_id)
                    .fingerprint(&committed.commit_fingerprint);
            }
            None => {
                bytes.u8(0);
            }
        }
        bytes
            .u64(self.activation_at.unwrap_or(0))
            .u64(self.retire_active_at.unwrap_or(0))
            .u64(self.revocation_epoch)
            .u8(u8::from(self.revoked));
    }
}

/// Every field of one generation, for the state fingerprint.
///
/// Written once and reused for all three slots: a snapshot that summarised
/// `next` and `pending` more coarsely than `active` would let a manifest be
/// built against a state whose candidate had already moved.
fn generation_snapshot(bytes: &mut CanonicalBytes, generation: &ClientCertificateGeneration) {
    bytes
        .u64(generation.generation)
        .u64(generation.ca_tls_epoch)
        .fingerprint(&generation.tls_ca_certificate_fingerprint)
        .fingerprint(&generation.tls_certificate_fingerprint)
        .fingerprint(&generation.pq_certificate_fingerprint)
        .u64(generation.not_before)
        .u64(generation.not_after);
}

/// Astra's identity as a client pins it (spec §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraProfile {
    pub authority_url: String,
    pub webauthn_rp_id: String,
    /// Policy confirmed independently of any CA-PQ-signed delegation.
    pub astra_policy_fingerprint: AstraPolicyPin,
    /// Highest credential-registry epoch accepted by this consumer.
    pub credential_registry_epoch: u64,
    /// Last CA-PQ-signed decision per credential identifier. The global epoch
    /// alone cannot make `revoked` terminal against a later forged restore.
    #[serde(default)]
    pub credential_bindings: BTreeMap<String, AstraCredentialBinding>,
    pub active_astra_service_public_key: MlDsa87PublicKey,
    pub next_astra_service_public_key: Option<MlDsa87PublicKey>,
    /// Fingerprint of the `AstraServiceKeyTransition` document that staged it.
    pub next_service_key_transition_fingerprint: Option<Fingerprint>,
    pub astra_service_key_epoch: u64,
    pub service_key_activation_at: Option<u64>,
    pub service_key_retire_active_at: Option<u64>,
    /// Revocation counter of the **Astra service key**, on its own axis.
    ///
    /// It used to borrow the client's, which is a domain-wide decision read
    /// against a per-peer counter: two clients at different counters would
    /// accept or refuse the same global replacement differently, and whichever
    /// accepted it would burn a number its own revocations then need.
    #[serde(default)]
    pub service_key_revocation_epoch: u64,
    /// The emergency replacement already applied, by signed document.
    #[serde(default)]
    pub last_emergency_replacement_fingerprint: Option<Fingerprint>,
}

impl AstraProfile {
    /// Applies one credential decision without allowing rollback or revival.
    pub fn accept_credential_binding(
        &mut self,
        binding: &AstraCredentialBinding,
    ) -> Result<InstallOutcome, CertificateError> {
        if binding.credential_registry_epoch < self.credential_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: self.credential_registry_epoch,
                proposed: binding.credential_registry_epoch,
            });
        }
        let key = Fingerprint::of(&binding.credential_id).to_string();
        let previous = self.credential_bindings.get(&key);
        binding.supersedes(previous)?;
        if previous.is_some_and(|known| known.fingerprint().matches(&binding.fingerprint())) {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        self.credential_registry_epoch = self
            .credential_registry_epoch
            .max(binding.credential_registry_epoch);
        self.credential_bindings.insert(key, binding.clone());
        Ok(InstallOutcome::Installed)
    }

    /// The key that verifies a response announcing `epoch`.
    ///
    /// A response never selects its own verifier: the epoch it declares is
    /// resolved against the pinned pair, and after `retire_active_at` the
    /// outgoing key is refused whatever `status_epoch` it carries.
    pub fn service_key_for(&self, epoch: u64, now_unix: u64) -> Option<&MlDsa87PublicKey> {
        if epoch == self.astra_service_key_epoch {
            if let Some(retire_at) = self.service_key_retire_active_at {
                if now_unix >= retire_at {
                    return None;
                }
            }
            return Some(&self.active_astra_service_public_key);
        }
        if epoch == self.astra_service_key_epoch + 1 {
            let activation_at = self.service_key_activation_at?;
            if now_unix >= activation_at {
                return self.next_astra_service_public_key.as_ref();
            }
        }
        None
    }

    /// Installs a planned rotation (spec §9.6).
    pub fn apply_service_key_transition(
        &mut self,
        transition: &AstraServiceKeyTransition,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ledger: &TrustLedger,
    ) -> Result<InstallOutcome, CertificateError> {
        ledger.assert_not_revoked(&[transition.next_service_public_key.authority_fingerprint()])?;
        let fingerprint = transition.fingerprint();
        if self
            .next_service_key_transition_fingerprint
            .is_some_and(|staged| staged.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if self.next_astra_service_public_key.is_some() {
            return Err(CertificateError::IllegalStateTransition(
                "a service key rotation is already in flight",
            ));
        }
        transition.verify(
            ca_pq,
            &self.active_astra_service_public_key,
            trust_domain_id,
            ca_epoch,
            self.astra_service_key_epoch,
        )?;
        self.next_astra_service_public_key = Some(transition.next_service_public_key.clone());
        self.next_service_key_transition_fingerprint = Some(fingerprint);
        self.service_key_activation_at = Some(transition.window.activation_at);
        self.service_key_retire_active_at = Some(transition.window.not_after);
        Ok(InstallOutcome::Installed)
    }

    /// Immediate replacement of a compromised key: no overlap at all.
    ///
    /// The counter compared here is this profile's own
    /// `service_key_revocation_epoch`, never a client's: the decision is
    /// domain-wide, and reading it against a per-peer axis makes the same
    /// signed object land differently on two clients of one fleet.
    pub fn apply_emergency_replacement(
        &mut self,
        replacement: &EmergencyAstraServiceKeyReplacement,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ledger: &TrustLedger,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        ledger.assert_not_revoked(&[replacement.next_service_key_fingerprint])?;
        // Idempotency on the signed document. Comparing "same epoch, same next
        // key" would swallow a *different* replacement that happens to install
        // the same key — a different revocation epoch, a different effective
        // instant — and report it as already applied.
        let fingerprint = replacement.fingerprint();
        if self
            .last_emergency_replacement_fingerprint
            .is_some_and(|applied| applied.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        replacement.verify(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            self.astra_service_key_epoch,
            self.service_key_revocation_epoch,
        )?;
        // The object must retire the key this profile is actually serving. One
        // naming another fingerprint is a valid signature over someone else's
        // decision, and applying it would evict a key nobody revoked.
        if !replacement
            .revoked_service_key_fingerprint
            .matches(&self.active_astra_service_public_key.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("revoked service key"));
        }
        // `effective_at` is a date, not a formality: a replacement announced
        // for tomorrow must not retire today's key today.
        if now_unix < replacement.effective_at {
            return Err(CertificateError::IllegalStateTransition(
                "emergency replacement is not effective yet",
            ));
        }
        self.active_astra_service_public_key = replacement.next_service_public_key.clone();
        self.astra_service_key_epoch = replacement.next_service_key_epoch;
        self.service_key_revocation_epoch = replacement.revocation_epoch;
        self.last_emergency_replacement_fingerprint = Some(fingerprint);
        self.next_astra_service_public_key = None;
        self.next_service_key_transition_fingerprint = None;
        self.service_key_activation_at = None;
        self.service_key_retire_active_at = None;
        Ok(InstallOutcome::Installed)
    }

    pub(crate) fn snapshot(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u64(self.astra_service_key_epoch)
            .fingerprint(&self.active_astra_service_public_key.authority_fingerprint())
            .optional_fingerprint(
                self.next_astra_service_public_key
                    .as_ref()
                    .map(MlDsa87PublicKey::authority_fingerprint)
                    .as_ref(),
            )
            .optional_fingerprint(self.next_service_key_transition_fingerprint.as_ref())
            .u64(self.service_key_activation_at.unwrap_or(0))
            .u64(self.service_key_retire_active_at.unwrap_or(0))
            .u64(self.service_key_revocation_epoch)
            .optional_fingerprint(self.last_emergency_replacement_fingerprint.as_ref());
    }

    pub fn promote_service_key_if_due(&mut self, now_unix: u64) -> bool {
        let Some(retire_at) = self.service_key_retire_active_at else {
            return false;
        };
        if now_unix < retire_at {
            return false;
        }
        let Some(next) = self.next_astra_service_public_key.take() else {
            return false;
        };
        self.active_astra_service_public_key = next;
        self.astra_service_key_epoch += 1;
        self.next_service_key_transition_fingerprint = None;
        self.service_key_activation_at = None;
        self.service_key_retire_active_at = None;
        true
    }
}

/// State of the online delegated issuer (spec §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerLifecycle {
    Active,
    Expiring,
    Revoked,
}

/// The delegation as Helios and Orion hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraIssuerState {
    pub issuer_epoch: u64,
    pub authorization: AstraIssuerAuthorization,
    pub state: IssuerLifecycle,
}

impl AstraIssuerState {
    /// Whether this delegation may sign anything at `now_unix`.
    pub fn is_usable(&self, now_unix: u64) -> bool {
        self.state != IssuerLifecycle::Revoked
            && now_unix >= self.authorization.not_before
            && now_unix < self.authorization.not_after
    }
}

/// Largest number of revocations held before their effective instant.
///
/// A ceiling rather than an unbounded list: an identity can only ever be
/// revoked once, so more than a handful in flight means something is wrong,
/// and growing a bounded state on a remote party's say-so is how it stops
/// being bounded.
pub const MAX_SCHEDULED_REVOCATIONS: usize = 8;

/// Largest number of revoked fingerprints remembered at once.
///
/// Generous next to the number of slots a holder has, because a tombstone may
/// name something it never held. When it fills, [`TrustLedger::remember`]
/// refuses rather than evicting: forgetting a revocation restores the ability
/// to reinstall the leaf, and nothing later would notice.
pub const MAX_REVOCATION_TOMBSTONES: usize = 32;

/// Largest number of status-ordering entries kept.
///
/// The targets are drawn from the slots the holder already has — two anchors,
/// two gateway leaves per family, three client generations — so the map is
/// naturally bounded. The ceiling is what makes that a checked property
/// instead of an argument.
pub const MAX_TRACKED_STATUS_TARGETS: usize = 24;

/// A verified revocation waiting for its own instant (spec §10.1).
///
/// Its scope is kept, and it is the whole point: the object named either the
/// gateway or a client, and applying it to the other one would remove an
/// identity nobody revoked while leaving the compromised one in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledRevocation {
    pub scope: RevocationScope,
    pub revocation_epoch: u64,
    pub effective_at: u64,
    pub revoked_tls_fingerprint: Option<Fingerprint>,
    pub revoked_tls_not_after: Option<u64>,
    pub revoked_pq_fingerprint: Option<Fingerprint>,
    pub revoked_pq_not_after: Option<u64>,
    /// Fingerprint of the signed revocation, carried through to the tombstone.
    pub revocation_fingerprint: Option<Fingerprint>,
}

impl ScheduledRevocation {
    /// Whether this revocation withdraws any fingerprint a client holds.
    ///
    /// Both families are checked. A revocation naming only the TLS half is a
    /// revocation: the generation is indivisible, and letting the PQ half
    /// survive would leave an identity that mTLS refuses and the negotiation
    /// still accepts.
    fn hits_client(&self, certificates: &ClientCertificateState) -> bool {
        let occupied = certificates.occupied_fingerprints();
        [self.revoked_tls_fingerprint, self.revoked_pq_fingerprint]
            .into_iter()
            .flatten()
            .any(|revoked| occupied.iter().any(|held| held.matches(&revoked)))
    }
}

/// Which half of a generation a revoked fingerprint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokedFamily {
    Tls,
    Pq,
}

/// A revoked fingerprint, remembered after the decision took effect (§10.2).
///
/// Applying a revocation and then forgetting the fingerprint is the subtle
/// half of the rule. Removing a leaf the holder currently has is visible and
/// easy; what matters just as much is a revocation naming a leaf the holder
/// does **not** have yet — a candidate still in flight, or a gateway leaf that
/// has not been distributed. Consumed and then dropped, the decision is gone:
/// the epoch has been spent, so the object can never be delivered again, and
/// the next transition carrying that very leaf installs it as if nothing had
/// happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTombstone {
    pub scope: RevocationScope,
    pub family: RevokedFamily,
    pub fingerprint: Fingerprint,
    pub revocation_epoch: u64,
    /// Instant past which the revoked certificate could not have been valid.
    /// Signed into a remote revocation and read from the generation for a
    /// local `peer remove`, so it is available even if this holder never saw
    /// the certificate itself.
    pub expires_at: u64,
    /// The signed revocation this came from.
    ///
    /// `None` for a local operator decision — `peer remove` on the gateway has
    /// no signed object at all, and recording its absence is more honest than
    /// fabricating a fingerprint for it.
    pub revocation_fingerprint: Option<Fingerprint>,
}

/// Ordering key of the last status accepted for one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusOrdering {
    pub astra_service_key_epoch: u64,
    pub status_epoch: u64,
}

impl StatusOrdering {
    fn key(self) -> (u64, u64) {
        (self.astra_service_key_epoch, self.status_epoch)
    }
}

/// What a trust holder knows that belongs to no single authority family.
///
/// Two things live here because they are cross-cutting: the revocations that
/// have been verified but not yet reached their instant, and the last status
/// ordering **per target**. The second is deliberately not one global pair —
/// Astra counts statuses per certificate, so a freshly rotated leaf starts at
/// epoch 1 and would be refused for good behind the high epoch of the leaf it
/// replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustLedger {
    /// Revocation counter of the **gateway** identity, on its own axis.
    #[serde(default)]
    pub gateway_revocation_epoch: u64,
    #[serde(default)]
    pub scheduled_revocations: Vec<ScheduledRevocation>,
    /// Fingerprints already withdrawn, kept so no later object reinstalls one.
    pub revoked: Vec<RevocationTombstone>,
    /// Keyed by the target's fingerprint in lowercase hex.
    #[serde(default)]
    pub last_statuses: BTreeMap<String, StatusOrdering>,
}

impl TrustLedger {
    /// Records a revocation whose object has already been verified.
    ///
    /// A revocation dated in the future is **kept**: its epoch is consumed the
    /// moment it verifies, so dropping it would discard a decision the
    /// authority already made and that can never be delivered again.
    pub fn schedule(
        &mut self,
        revocation: &EmergencyCertificateRevocation,
        gateway: &GatewayCertificateState,
        client: &ClientCertificateState,
    ) -> Result<(), CertificateError> {
        if self.scheduled_revocations.len() >= MAX_SCHEDULED_REVOCATIONS {
            return Err(CertificateError::InvalidTransaction(
                "too many pending revocations",
            ));
        }
        for (fingerprint, signed_expiry) in [
            (
                revocation.revoked_tls_fingerprint,
                revocation.revoked_tls_not_after,
            ),
            (
                revocation.revoked_pq_fingerprint,
                revocation.revoked_pq_not_after,
            ),
        ] {
            if let (Some(fingerprint), Some(signed_expiry)) = (fingerprint, signed_expiry) {
                if known_expiry(gateway, client, &fingerprint)
                    .is_some_and(|held_expiry| held_expiry != signed_expiry)
                {
                    return Err(CertificateError::InvalidTransaction(
                        "revocation expiry does not match the held certificate",
                    ));
                }
            }
        }
        if revocation.scope == RevocationScope::Gateway {
            self.gateway_revocation_epoch = revocation.revocation_epoch;
        }
        self.scheduled_revocations.push(ScheduledRevocation {
            scope: revocation.scope,
            revocation_epoch: revocation.revocation_epoch,
            effective_at: revocation.effective_at,
            revoked_tls_fingerprint: revocation.revoked_tls_fingerprint,
            revoked_tls_not_after: revocation.revoked_tls_not_after,
            revoked_pq_fingerprint: revocation.revoked_pq_fingerprint,
            revoked_pq_not_after: revocation.revoked_pq_not_after,
            revocation_fingerprint: Some(revocation.fingerprint()),
        });
        Ok(())
    }

    /// Applies every revocation that has reached its instant, to the state its
    /// scope names, and remembers the fingerprints it withdrew.
    ///
    /// The tombstone is written **before** the decision is applied: applying
    /// it clears the very slot the cryptographic expiry would have been read
    /// from. The signed expiry remains available when this holder never had
    /// the certificate at all.
    pub fn apply_due(
        &mut self,
        gateway: &mut GatewayCertificateState,
        client: &mut ClientCertificateState,
        now_unix: u64,
    ) -> Result<bool, CertificateError> {
        let mut moved = false;
        let mut remaining = Vec::with_capacity(self.scheduled_revocations.len());
        for revocation in std::mem::take(&mut self.scheduled_revocations) {
            if now_unix < revocation.effective_at {
                remaining.push(revocation);
                continue;
            }
            for (family, fingerprint, signed_expiry) in [
                (
                    RevokedFamily::Tls,
                    revocation.revoked_tls_fingerprint,
                    revocation.revoked_tls_not_after,
                ),
                (
                    RevokedFamily::Pq,
                    revocation.revoked_pq_fingerprint,
                    revocation.revoked_pq_not_after,
                ),
            ] {
                let (Some(fingerprint), Some(expires_at)) = (fingerprint, signed_expiry) else {
                    continue;
                };
                if known_expiry(gateway, client, &fingerprint)
                    .is_some_and(|held_expiry| held_expiry != expires_at)
                {
                    return Err(CertificateError::InvalidTransaction(
                        "revocation expiry does not match the held certificate",
                    ));
                }
                self.remember(
                    RevocationTombstone {
                        scope: revocation.scope,
                        family,
                        fingerprint,
                        revocation_epoch: revocation.revocation_epoch,
                        expires_at,
                        revocation_fingerprint: revocation.revocation_fingerprint,
                    },
                    now_unix,
                )?;
            }
            match revocation.scope {
                RevocationScope::Client => {
                    if revocation.hits_client(client) {
                        client.revoke(revocation.revocation_epoch);
                    }
                }
                RevocationScope::Gateway => {
                    gateway.apply_revocation(
                        revocation.revoked_tls_fingerprint.as_ref(),
                        revocation.revoked_pq_fingerprint.as_ref(),
                        revocation.revocation_epoch,
                    )?;
                }
            }
            moved = true;
        }
        self.scheduled_revocations = remaining;
        Ok(moved)
    }

    /// Records a withdrawn fingerprint, or refuses rather than forgetting one.
    ///
    /// When the list is full, tombstones whose cryptographic validity has run
    /// out are dropped first — they can no longer protect anything. If that
    /// frees nothing, the operation is **refused**. Evicting a live tombstone
    /// to make room would silently restore the ability to reinstall a revoked
    /// leaf, and a refused trust update is recoverable in a way that is not.
    pub fn remember(
        &mut self,
        tombstone: RevocationTombstone,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        self.forget_expired(now_unix);
        if now_unix >= tombstone.expires_at {
            return Ok(());
        }
        if let Some(existing) = self.revoked.iter_mut().find(|held| {
            held.scope == tombstone.scope
                && held.family == tombstone.family
                && held.fingerprint.matches(&tombstone.fingerprint)
        }) {
            // Keep the whole newest decision together. Updating only the
            // counter would leave it pointing at the older signed document.
            if tombstone.revocation_epoch > existing.revocation_epoch {
                *existing = tombstone;
            }
            return Ok(());
        }
        if self.revoked.len() >= MAX_REVOCATION_TOMBSTONES {
            return Err(CertificateError::InvalidTransaction(
                "no room left for a revocation tombstone",
            ));
        }
        self.revoked.push(tombstone);
        Ok(())
    }

    /// Drops tombstones whose target could no longer be valid anyway.
    ///
    /// Remote expiry is part of the signed revocation, so a certificate the
    /// holder never saw is just as reclaimable as one it once installed.
    pub fn forget_expired(&mut self, now_unix: u64) -> bool {
        let before = self.revoked.len();
        self.revoked
            .retain(|tombstone| now_unix < tombstone.expires_at);
        self.revoked.len() != before
    }

    pub fn is_revoked(&self, fingerprint: &Fingerprint) -> bool {
        self.revoked
            .iter()
            .any(|tombstone| tombstone.fingerprint.matches(fingerprint))
    }

    /// Refuses an installation that would reintroduce a revoked fingerprint.
    ///
    /// Every install path calls this, which is why it is a parameter of each
    /// of them rather than a check a caller may remember to do: a revoked leaf
    /// coming back through a path nobody wired up is indistinguishable, from
    /// the outside, from a revocation that was never delivered.
    pub fn assert_not_revoked(&self, fingerprints: &[Fingerprint]) -> Result<(), CertificateError> {
        if fingerprints
            .iter()
            .any(|fingerprint| self.is_revoked(fingerprint))
        {
            return Err(CertificateError::Revoked);
        }
        Ok(())
    }

    pub fn last_status_for(&self, target: &Fingerprint) -> Option<(u64, u64)> {
        self.last_statuses
            .get(&target.to_hex())
            .map(|ordering| ordering.key())
    }

    /// Records the ordering of an accepted status for one target.
    pub fn record_status(
        &mut self,
        target: &Fingerprint,
        status: &AstraCertificateStatus,
    ) -> Result<(), CertificateError> {
        let key = target.to_hex();
        if !self.last_statuses.contains_key(&key)
            && self.last_statuses.len() >= MAX_TRACKED_STATUS_TARGETS
        {
            return Err(CertificateError::InvalidTransaction(
                "too many status targets",
            ));
        }
        self.last_statuses.insert(
            key,
            StatusOrdering {
                astra_service_key_epoch: status.astra_service_key_epoch,
                status_epoch: status.status_epoch,
            },
        );
        Ok(())
    }

    /// Forgets the ordering of targets the holder no longer has a slot for.
    ///
    /// A promoted generation is gone from the state, so keeping its counter
    /// would only ever consume room in a bounded map.
    pub fn prune_statuses(&mut self, held: &[Fingerprint]) {
        self.last_statuses
            .retain(|key, _| held.iter().any(|fingerprint| fingerprint.to_hex() == *key));
    }

    fn snapshot(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u64(self.gateway_revocation_epoch)
            .u16(self.scheduled_revocations.len() as u16);
        for revocation in &self.scheduled_revocations {
            bytes
                .u8(scope_byte(revocation.scope))
                .u64(revocation.revocation_epoch)
                .u64(revocation.effective_at)
                .optional_fingerprint(revocation.revoked_tls_fingerprint.as_ref())
                .optional_u64(revocation.revoked_tls_not_after)
                .optional_fingerprint(revocation.revoked_pq_fingerprint.as_ref())
                .optional_u64(revocation.revoked_pq_not_after)
                .optional_fingerprint(revocation.revocation_fingerprint.as_ref());
        }
        bytes.u16(self.revoked.len() as u16);
        for tombstone in &self.revoked {
            bytes
                .u8(scope_byte(tombstone.scope))
                .u8(match tombstone.family {
                    RevokedFamily::Tls => 0,
                    RevokedFamily::Pq => 1,
                })
                .fingerprint(&tombstone.fingerprint)
                .u64(tombstone.revocation_epoch)
                .u64(tombstone.expires_at)
                .optional_fingerprint(tombstone.revocation_fingerprint.as_ref());
        }
        bytes.u16(self.last_statuses.len() as u16);
        for (target, ordering) in &self.last_statuses {
            bytes
                .text(target)
                .u64(ordering.astra_service_key_epoch)
                .u64(ordering.status_epoch);
        }
    }
}

const fn scope_byte(scope: RevocationScope) -> u8 {
    match scope {
        RevocationScope::Gateway => 0,
        RevocationScope::Client => 1,
    }
}

/// The instant a fingerprint the holder currently has stops being valid.
///
/// Read from the slots, never from the revocation: the object names what to
/// withdraw, not how long the withdrawn thing would have lived. `None` when
/// this holder has no such certificate — the case the tombstone exists for,
/// and the one where an invented expiry would quietly drop the record.
fn known_expiry(
    gateway: &GatewayCertificateState,
    client: &ClientCertificateState,
    fingerprint: &Fingerprint,
) -> Option<u64> {
    for generation in [
        Some(&client.active),
        client.next.as_ref(),
        client.pending.as_ref().map(|pending| &pending.candidate),
    ]
    .into_iter()
    .flatten()
    {
        if generation.tls_certificate_fingerprint.matches(fingerprint)
            || generation.pq_certificate_fingerprint.matches(fingerprint)
        {
            return Some(generation.not_after);
        }
    }

    for (certificate, tls) in [
        (Some(&gateway.active_gateway_certificate), None),
        (gateway.next_gateway_certificate.as_ref(), None),
        (None, Some(&gateway.active_gateway_tls_certificate)),
        (None, gateway.next_gateway_tls_certificate.as_ref()),
    ] {
        if let Some(certificate) = certificate {
            if pq_certificate_fingerprint(certificate).is_ok_and(|held| held.matches(fingerprint)) {
                return Some(certificate.not_after_unix);
            }
        }
        if let Some(tls) = tls {
            if tls.fingerprint().matches(fingerprint) {
                return crate::certificates::x509::inspect(tls)
                    .ok()
                    .map(|facts| facts.not_after);
            }
        }
    }
    None
}

/// The complete state a transaction is computed against (spec §8.1).
///
/// Passed as one value rather than five arguments because the point is
/// exhaustiveness: adding a slot to the trust store and forgetting to bind it
/// here is what lets a manifest be built against a world that has since moved.
pub struct TrustSnapshot<'a> {
    pub gateway: &'a GatewayCertificateState,
    pub client_tls_ca: &'a ClientTlsCaState,
    pub astra: &'a AstraProfile,
    /// The anti-rollback counter, held **separately** from the delegation.
    ///
    /// A holder that has revoked its issuer, or never installed one, still
    /// carries a counter that only moves forward. Deriving this number from
    /// `issuer` would leave it out of the fingerprint in exactly that case,
    /// and a transaction built before the counter advanced would still match.
    pub issuer_epoch: u64,
    pub issuer: Option<&'a AstraIssuerState>,
    pub client: &'a ClientCertificateState,
    pub ledger: &'a TrustLedger,
}

/// SHA-256 of the receiver's complete trust state (spec §8.1).
///
/// A manifest is bound to this value, so a transaction built against a state
/// that has since moved is refused instead of being applied to a world it was
/// never computed for.
pub fn base_state_fingerprint(snapshot: &TrustSnapshot) -> Result<Fingerprint, CertificateError> {
    let mut bytes = CanonicalBytes::new(BASE_STATE_DOMAIN);
    snapshot.gateway.snapshot(&mut bytes)?;
    snapshot.client_tls_ca.snapshot(&mut bytes);
    snapshot.astra.snapshot(&mut bytes);
    bytes.u64(snapshot.issuer_epoch);
    match snapshot.issuer {
        // The whole delegation, not just its number: an issuer swapped at the
        // same epoch changes which key may certify the next client leaf.
        Some(issuer) => {
            bytes
                .u8(1)
                .u64(issuer.issuer_epoch)
                .fingerprint(&issuer.authorization.fingerprint())
                .u8(match issuer.state {
                    IssuerLifecycle::Active => 0,
                    IssuerLifecycle::Expiring => 1,
                    IssuerLifecycle::Revoked => 2,
                });
        }
        None => {
            bytes.u8(0);
        }
    }
    snapshot.client.snapshot(&mut bytes);
    snapshot.ledger.snapshot(&mut bytes);
    Ok(Fingerprint::of(&bytes.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::window::TransitionWindow;

    fn generation(index: u64, seed: u8) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: index,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(&[seed, 1]),
            pq_certificate_fingerprint: Fingerprint::of(&[seed, 2]),
            not_before: 0,
            not_after: 100_000,
        }
    }

    /// A distinct signed-commit identity per seed.
    fn commit_fingerprint(seed: u8) -> Fingerprint {
        Fingerprint::of(&[seed, 0xC0])
    }

    fn staged_state() -> ClientCertificateState {
        let mut state = ClientCertificateState::new(generation(4, 1));
        state.pending = Some(ClientCertificatePendingStage {
            stage_id: Id16::new([3; 16]).expect("stage"),
            authorization_fingerprint: Fingerprint::of(b"authorization"),
            request_fingerprint: Fingerprint::of(b"request"),
            candidate: generation(5, 2),
            state: PendingStageState::PendingGrant,
            stage_expires_at: 5_000,
            window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
        });
        state
    }

    /// The negotiation resolves a caller by the TLS half mTLS proved, and
    /// must then know which PQ leaf that caller may present.
    ///
    /// The answer is the partner of that exact half, never the union of both
    /// generations: the union accepts the mixed pair of §3.3 — the TLS of the
    /// outgoing identity beside the PQ of the incoming one — which is an
    /// identity the domain never issued.
    #[test]
    fn the_pq_half_returned_belongs_to_the_generation_the_tls_half_named() {
        let active = generation(4, 1);
        let next = generation(5, 2);
        let mut state = ClientCertificateState::new(active.clone());
        state.next = Some(next.clone());
        state.activation_at = Some(1_000);

        assert_eq!(
            state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
            Some(active.pq_certificate_fingerprint)
        );
        assert_eq!(
            state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 2_000),
            Some(next.pq_certificate_fingerprint)
        );
        // Never the other one's, from either side.
        assert_ne!(
            state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
            Some(next.pq_certificate_fingerprint)
        );
    }

    /// Before its activation instant the successor is not an identity yet.
    #[test]
    fn a_successor_resolves_nothing_until_its_activation() {
        let active = generation(4, 1);
        let next = generation(5, 2);
        let mut state = ClientCertificateState::new(active.clone());
        state.next = Some(next.clone());
        state.activation_at = Some(1_000);

        assert_eq!(
            state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 999),
            None
        );
        assert_eq!(
            state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 1_000),
            Some(next.pq_certificate_fingerprint)
        );
    }

    /// Revocation dominates: neither half of either generation resolves.
    #[test]
    fn a_revoked_peer_resolves_no_pq_half_at_all() {
        let active = generation(4, 1);
        let next = generation(5, 2);
        let mut state = ClientCertificateState::new(active.clone());
        state.next = Some(next.clone());
        state.activation_at = Some(1_000);
        state.revoke(7);

        assert_eq!(
            state.pq_paired_with_tls(&active.tls_certificate_fingerprint, 2_000),
            None
        );
        assert_eq!(
            state.pq_paired_with_tls(&next.tls_certificate_fingerprint, 2_000),
            None
        );
    }

    /// A candidate under lease is not presentable, so it resolves nothing —
    /// the same rule `accepts_pair` applies, stated for the half the
    /// negotiation actually looks up.
    #[test]
    fn a_candidate_under_lease_resolves_no_pq_half() {
        let state = staged_state();
        let candidate = generation(5, 2);
        assert_eq!(
            state.pq_paired_with_tls(&candidate.tls_certificate_fingerprint, 2_000),
            None
        );
    }

    /// The commit is the moment a candidate becomes usable, and not before.
    #[test]
    fn a_candidate_is_not_presentable_until_it_is_committed() {
        let mut state = staged_state();
        let candidate = generation(5, 2);
        assert!(!state.accepts_pair(
            &candidate.tls_certificate_fingerprint,
            &candidate.pq_certificate_fingerprint,
            15_000
        ));

        state
            .commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000,
            )
            .expect("commit");
        assert!(state.pending.is_none());
        assert!(state.next.is_some());
        // Committed, but only presentable from `activation_at`.
        assert!(!state.accepts_pair(
            &candidate.tls_certificate_fingerprint,
            &candidate.pq_certificate_fingerprint,
            9_999
        ));
        assert!(state.accepts_pair(
            &candidate.tls_certificate_fingerprint,
            &candidate.pq_certificate_fingerprint,
            10_000
        ));
    }

    /// The two mixed pairs of spec §3.3, at the state level this time.
    #[test]
    fn a_state_in_overlap_refuses_a_pair_split_across_generations() {
        let mut state = staged_state();
        state
            .commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000,
            )
            .unwrap();
        let active = generation(4, 1);
        let next = generation(5, 2);

        assert!(state.accepts_pair(
            &active.tls_certificate_fingerprint,
            &active.pq_certificate_fingerprint,
            15_000
        ));
        assert!(!state.accepts_pair(
            &active.tls_certificate_fingerprint,
            &next.pq_certificate_fingerprint,
            15_000
        ));
        assert!(!state.accepts_pair(
            &next.tls_certificate_fingerprint,
            &active.pq_certificate_fingerprint,
            15_000
        ));
    }

    #[test]
    fn an_uncommitted_candidate_is_purged_at_its_lease() {
        let mut state = staged_state();
        assert!(!state.purge_expired(4_999));
        assert!(state.purge_expired(5_000));
        assert!(state.pending.is_none());

        // And a commit arriving afterwards has nothing to commit.
        assert!(matches!(
            state.commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                5_001
            ),
            Err(CertificateError::UnknownStage)
        ));
    }

    #[test]
    fn a_commit_at_the_deadline_loses_the_race_against_the_purge() {
        let mut state = staged_state();
        assert!(matches!(
            state.commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                5_000
            ),
            Err(CertificateError::StageExpired)
        ));
    }

    /// The two ends commit from different states, and neither may adopt the
    /// other's rule: Orion must hold the grant first.
    #[test]
    fn each_end_commits_only_from_the_state_it_owns() {
        let mut orion = staged_state();
        assert!(matches!(
            orion.commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingCommit,
                2_000
            ),
            Err(CertificateError::IllegalStateTransition(_))
        ));

        orion
            .mark_pending_commit(&Id16::new([3; 16]).unwrap())
            .expect("grant persisted");
        orion
            .commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingCommit,
                2_000,
            )
            .expect("commit");
        assert!(orion.next.is_some());
    }

    /// A retry over a lossy link is a no-op, and it is recognised by the exact
    /// signed commit — not by "there is a `next` roughly here", and not by the
    /// stage identifier alone.
    #[test]
    fn a_replayed_commit_is_idempotent_only_for_its_own_signed_document() {
        let mut state = staged_state();
        let stage = Id16::new([3; 16]).unwrap();
        state
            .commit(
                &stage,
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000,
            )
            .expect("commit");

        assert_eq!(
            state
                .commit(
                    &stage,
                    &commit_fingerprint(1),
                    PendingStageState::PendingGrant,
                    2_100
                )
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        );
        // A *different* document closing the same stage is a conflict: telling
        // its sender the commit landed would report someone else's decision as
        // theirs.
        assert!(matches!(
            state.commit(
                &stage,
                &commit_fingerprint(2),
                PendingStageState::PendingGrant,
                2_100
            ),
            Err(CertificateError::GenerationConflict { .. })
        ));
        // And another stage landing on the same generation is refused.
        assert!(matches!(
            state.commit(
                &Id16::new([4; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_100
            ),
            Err(CertificateError::UnknownStage)
        ));
    }

    #[test]
    fn a_commit_naming_another_stage_is_refused() {
        let mut state = staged_state();
        assert!(matches!(
            state.commit(
                &Id16::new([9; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000
            ),
            Err(CertificateError::UnknownStage)
        ));
        assert!(state.pending.is_some());
    }

    /// Revocation wins every race, and no later object undoes it.
    #[test]
    fn revocation_dominates_staging_commit_and_promotion() {
        let mut state = staged_state();
        state.revoke(1);
        assert!(state.pending.is_none());
        assert!(state.next.is_none());
        assert!(matches!(
            state.commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000
            ),
            Err(CertificateError::Revoked)
        ));
        assert!(!state.promote_if_due(u64::MAX));
        let active = generation(4, 1);
        assert!(!state.accepts_pair(
            &active.tls_certificate_fingerprint,
            &active.pq_certificate_fingerprint,
            1_000
        ));
        assert!(state.acceptable_pq_fingerprints(1_000).is_empty());
    }

    /// Promotion deletes the outgoing generation, so a clock moved backwards
    /// finds nothing to reactivate.
    #[test]
    fn a_promoted_generation_never_comes_back_when_the_clock_moves_backwards() {
        let mut state = staged_state();
        state
            .commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000,
            )
            .unwrap();
        assert!(state.promote_if_due(20_000));
        assert_eq!(state.active.generation, 5);
        assert!(state.next.is_none());

        let old = generation(4, 1);
        assert!(!state.accepts_pair(
            &old.tls_certificate_fingerprint,
            &old.pq_certificate_fingerprint,
            1_000
        ));
        assert!(!state.promote_if_due(u64::MAX));
    }

    #[test]
    fn a_peer_never_holds_three_generations_at_once() {
        let mut state = staged_state();
        assert_eq!(state.occupied_fingerprints().len(), 4);
        state
            .commit(
                &Id16::new([3; 16]).unwrap(),
                &commit_fingerprint(1),
                PendingStageState::PendingGrant,
                2_000,
            )
            .unwrap();
        assert_eq!(state.occupied_fingerprints().len(), 4);
        assert!(state.pending.is_none() || state.next.is_none());
    }

    /// The `staged -> published -> overlap -> promoted` machine of spec §6.3,
    /// and the one door that closes: an abort after publication.
    #[cfg(feature = "key-negotiation-signing")]
    mod gateway_machine {
        use super::*;
        use crate::certificates::authority::RotationReason;
        use crate::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use crate::certificates::gateway::AbortReason;
        use crate::certificates::{CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION};
        use crate::key_negotiation::{
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

        fn gateway_key() -> WireGuardKey {
            WireGuardKey::from_bytes([5; 32])
        }

        fn leaf(ca: &Keys, subject: &Keys, serial: u8) -> PqCertificate {
            let certificate = PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [serial; 16],
                subject: SERVER_NAME.into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key().to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: 100_000,
                ml_dsa_87_signature: String::new(),
            };
            issue_pq_certificate(certificate, &ca.private).expect("issue")
        }

        fn state(ca: &Keys, active: PqCertificate) -> GatewayCertificateState {
            GatewayCertificateState {
                trust_domain_id: TrustDomainId::new([4; 16]).expect("domain"),
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
                active_gateway_certificate: active,
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
            }
        }

        fn transition(
            ca: &Keys,
            state: &GatewayCertificateState,
            epoch: u64,
            next: PqCertificate,
        ) -> GatewayIdentityTransition {
            let transition = GatewayIdentityTransition {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: state.trust_domain_id,
                ca_epoch: state.ca_epoch,
                gateway_identity_epoch: epoch,
                gateway_wg_public_key: state.gateway_wg_public_key,
                server_name: state.server_name.clone(),
                active_gateway_tls_certificate_fingerprint: state.active_tls_fingerprint(),
                next_gateway_tls_certificate: None,
                active_gateway_certificate_fingerprint: state
                    .active_pq_fingerprint()
                    .expect("fingerprint"),
                next_gateway_certificate: Some(next),
                window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                reason: RotationReason::Scheduled,
                ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
            };
            transition.sign(&ca.private).expect("sign")
        }

        fn abort(
            ca: &Keys,
            transition: &GatewayIdentityTransition,
            aborted_at: u64,
        ) -> GatewayTransitionAbort {
            let abort = GatewayTransitionAbort {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: transition.trust_domain_id,
                ca_epoch: transition.ca_epoch,
                gateway_wg_public_key: transition.gateway_wg_public_key,
                server_name: transition.server_name.clone(),
                gateway_identity_epoch: transition.gateway_identity_epoch,
                gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
                aborted_at,
                reason: AbortReason::OperatorCancelled,
                campaign_fingerprint: Fingerprint::of(b"campaign"),
                ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
            };
            abort.sign(&ca.private).expect("sign")
        }

        #[test]
        fn a_staged_transition_is_promoted_at_the_end_of_its_overlap() {
            let ca = keys();
            let active = keys();
            let candidate = keys();
            let mut state = state(&ca, leaf(&ca, &active, 1));
            let next = leaf(&ca, &candidate, 2);
            let transition = transition(&ca, &state, 2, next.clone());

            assert_eq!(
                state
                    .install_transition(&transition, &TrustLedger::default(), 500)
                    .expect("install"),
                InstallOutcome::Installed
            );
            assert_eq!(state.gateway_decision_epoch, 2);
            assert_eq!(state.active_gateway_identity_epoch, 1);

            // Prepared, not served: the client accepts only the active leaf.
            assert_eq!(state.acceptable_pq_fingerprints(1_999).unwrap().len(), 1);
            // Overlap: both.
            assert_eq!(state.acceptable_pq_fingerprints(2_000).unwrap().len(), 2);

            assert!(!state.promote_if_due(2_999).expect("promotion"), "not due");
            assert!(state.promote_if_due(3_000).expect("promotion"));
            assert_eq!(state.active_gateway_identity_epoch, 2);
            assert!(state.next_gateway_certificate.is_none());
            assert_eq!(
                state.acceptable_pq_fingerprints(3_000).unwrap().len(),
                1,
                "the outgoing leaf is gone, not merely unpreferred"
            );
            assert!(!state.promote_if_due(u64::MAX).expect("idempotent"));
        }

        /// Publication is the point of no return: after it, only a forward
        /// transition or the bounded service rollback remain.
        #[test]
        fn an_abort_is_refused_once_the_transition_has_been_published() {
            let ca = keys();
            let active = keys();
            let candidate = keys();
            let mut state = state(&ca, leaf(&ca, &active, 1));
            let transition = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
            state
                .install_transition(&transition, &TrustLedger::default(), 500)
                .expect("install");
            state.mark_published().expect("publish");

            let abort = abort(&ca, &transition, 1_500);
            assert!(matches!(
                state.apply_abort(&abort, &transition, 1_600),
                Err(CertificateError::AlreadyPublished)
            ));
            assert!(state.next_gateway_certificate.is_some());
        }

        /// An aborted epoch stays consumed: the next attempt is `current + 1`,
        /// never a second document under the same number.
        #[test]
        fn an_aborted_epoch_is_never_reused() {
            let ca = keys();
            let active = keys();
            let candidate = keys();
            let mut state = state(&ca, leaf(&ca, &active, 1));
            let staged = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
            state
                .install_transition(&staged, &TrustLedger::default(), 500)
                .expect("install");

            let abort = abort(&ca, &staged, 1_500);
            assert_eq!(
                state.apply_abort(&abort, &staged, 1_600).expect("abort"),
                InstallOutcome::Installed
            );
            assert!(state.next_gateway_certificate.is_none());
            assert_eq!(state.gateway_decision_epoch, 2, "the epoch is consumed");
            assert_eq!(state.active_gateway_identity_epoch, 1);
            assert!(state.last_aborted_transition.is_some());

            // Replaying the same abort changes nothing.
            assert_eq!(
                state.apply_abort(&abort, &staged, 1_700).expect("replay"),
                InstallOutcome::AlreadyPresent
            );

            // A second attempt at the consumed epoch is refused; epoch 3 works.
            let retry = transition(&ca, &state, 2, leaf(&ca, &candidate, 3));
            assert!(state
                .install_transition(&retry, &TrustLedger::default(), 500)
                .is_err());
            let forward = transition(&ca, &state, 3, leaf(&ca, &candidate, 4));
            assert_eq!(
                state
                    .install_transition(&forward, &TrustLedger::default(), 500)
                    .expect("install"),
                InstallOutcome::Installed
            );
        }

        /// Two staged transitions at once would give the state two futures.
        #[test]
        fn a_second_transition_cannot_be_staged_over_the_first() {
            let ca = keys();
            let active = keys();
            let candidate = keys();
            let mut state = state(&ca, leaf(&ca, &active, 1));
            let first = transition(&ca, &state, 2, leaf(&ca, &candidate, 2));
            state
                .install_transition(&first, &TrustLedger::default(), 500)
                .expect("install");

            let second = transition(&ca, &state, 3, leaf(&ca, &candidate, 3));
            assert!(matches!(
                state.install_transition(&second, &TrustLedger::default(), 500),
                Err(CertificateError::IllegalStateTransition(_))
            ));

            // The identical one is an idempotent replay, not a refusal.
            assert_eq!(
                state
                    .install_transition(&first, &TrustLedger::default(), 500)
                    .expect("replay"),
                InstallOutcome::AlreadyPresent
            );
        }

        /// A revoked leaf never comes back through a later transition.
        ///
        /// This is the case a revocation applied and then forgotten misses
        /// entirely: the decision named a leaf the holder did not have yet, so
        /// nothing was removed and nothing was remembered — and the very next
        /// transition installs it as though the revocation had never existed.
        #[test]
        fn a_revoked_leaf_is_refused_by_a_later_transition() {
            let ca = keys();
            let active = keys();
            let candidate = keys();
            let mut state = state(&ca, leaf(&ca, &active, 1));
            let next = leaf(&ca, &candidate, 2);
            let transition = transition(&ca, &state, 2, next.clone());

            let mut ledger = TrustLedger::default();
            ledger
                .remember(
                    RevocationTombstone {
                        scope: RevocationScope::Gateway,
                        family: RevokedFamily::Pq,
                        fingerprint: pq_certificate_fingerprint(&next).expect("fingerprint"),
                        revocation_epoch: 1,
                        // Never held, but the signed revocation still carries the
                        // cryptographic expiry.
                        expires_at: next.not_after_unix,
                        revocation_fingerprint: Some(Fingerprint::of(b"the signed revocation")),
                    },
                    500,
                )
                .expect("tombstone");

            assert!(matches!(
                state.install_transition(&transition, &ledger, 500),
                Err(CertificateError::Revoked)
            ));
            assert!(state.next_gateway_certificate.is_none());

            // And without the tombstone the very same document installs — so
            // the refusal above is the tombstone's doing, not the window's.
            assert_eq!(
                state
                    .install_transition(&transition, &TrustLedger::default(), 500)
                    .expect("install"),
                InstallOutcome::Installed
            );
        }
    }

    /// A live tombstone is never traded away to make room for another.
    #[test]
    fn a_full_tombstone_list_refuses_rather_than_forgetting_a_revocation() {
        let tombstone = |seed: u8, expires_at| RevocationTombstone {
            scope: RevocationScope::Client,
            family: RevokedFamily::Pq,
            fingerprint: Fingerprint::of(&[seed]),
            revocation_epoch: u64::from(seed),
            expires_at,
            revocation_fingerprint: None,
        };

        let mut ledger = TrustLedger::default();
        for seed in 0..MAX_REVOCATION_TOMBSTONES as u8 {
            ledger
                .remember(tombstone(seed, 10_000), 1_000)
                .expect("room");
        }
        assert!(matches!(
            ledger.remember(tombstone(200, 10_000), 1_000),
            Err(CertificateError::InvalidTransaction(_))
        ));
        assert!(
            ledger.is_revoked(&Fingerprint::of(&[0u8])),
            "the first tombstone was not evicted to make room"
        );

        // Recording the same fingerprint twice is one decision, not two slots.
        assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
        ledger.remember(tombstone(0, 9_000), 1_000).expect("merge");
        assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
    }

    /// Expired entries are reclaimed before the ceiling can refuse a new one.
    #[test]
    fn an_expired_tombstone_makes_room_for_a_new_revocation() {
        let mut ledger = TrustLedger::default();
        for seed in 0..MAX_REVOCATION_TOMBSTONES as u8 {
            ledger
                .remember(
                    RevocationTombstone {
                        scope: RevocationScope::Client,
                        family: RevokedFamily::Tls,
                        fingerprint: Fingerprint::of(&[seed]),
                        revocation_epoch: u64::from(seed),
                        expires_at: if seed == 0 { 5_000 } else { 10_000 },
                        revocation_fingerprint: None,
                    },
                    1_000,
                )
                .expect("tombstone");
        }

        ledger
            .remember(
                RevocationTombstone {
                    scope: RevocationScope::Client,
                    family: RevokedFamily::Pq,
                    fingerprint: Fingerprint::of(b"new decision"),
                    revocation_epoch: 33,
                    expires_at: 12_000,
                    revocation_fingerprint: None,
                },
                5_000,
            )
            .expect("tombstone");

        assert_eq!(ledger.revoked.len(), MAX_REVOCATION_TOMBSTONES);
        assert!(!ledger.is_revoked(&Fingerprint::of(&[0])));
        assert!(ledger.is_revoked(&Fingerprint::of(b"new decision")));
    }

    /// Updating a decision updates its counter and signed provenance together.
    #[test]
    fn a_newer_revocation_of_the_same_leaf_replaces_the_whole_tombstone() {
        let mut ledger = TrustLedger::default();
        let first_document = Fingerprint::of(b"first revocation");
        let second_document = Fingerprint::of(b"second revocation");
        ledger
            .remember(
                RevocationTombstone {
                    scope: RevocationScope::Client,
                    family: RevokedFamily::Pq,
                    fingerprint: Fingerprint::of(b"same leaf"),
                    revocation_epoch: 1,
                    expires_at: 9_000,
                    revocation_fingerprint: Some(first_document),
                },
                1_000,
            )
            .expect("tombstone");
        ledger
            .remember(
                RevocationTombstone {
                    scope: RevocationScope::Client,
                    family: RevokedFamily::Pq,
                    fingerprint: Fingerprint::of(b"same leaf"),
                    revocation_epoch: 2,
                    expires_at: 9_000,
                    revocation_fingerprint: Some(second_document),
                },
                1_000,
            )
            .expect("replace");

        assert_eq!(ledger.revoked.len(), 1);
        assert_eq!(ledger.revoked[0].revocation_epoch, 2);
        assert_eq!(
            ledger.revoked[0].revocation_fingerprint,
            Some(second_document)
        );
    }

    /// After the outgoing key is retired, no `status_epoch` revives it.
    #[test]
    fn a_retired_astra_service_key_is_refused_whatever_it_signs() {
        let key = |seed: u8| {
            // A syntactically valid ML-DSA-87 key is 2 592 bytes; the profile
            // only ever compares and selects them here.
            MlDsa87PublicKey::new(vec![seed; 2_592])
        };
        // A byte string of the right length is not necessarily a decodable
        // key, so this test only runs when one can be built.
        let (Ok(active), Ok(next)) = (key(0), key(1)) else {
            return;
        };
        let profile = AstraProfile {
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                .expect("policy"),
            credential_registry_epoch: 1,
            credential_bindings: BTreeMap::new(),
            active_astra_service_public_key: active,
            next_astra_service_public_key: Some(next),
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 3,
            service_key_activation_at: Some(1_000),
            service_key_retire_active_at: Some(2_000),
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        };
        assert!(profile.service_key_for(3, 999).is_some());
        assert!(profile.service_key_for(4, 999).is_none());
        assert!(profile.service_key_for(4, 1_000).is_some());
        assert!(profile.service_key_for(3, 2_000).is_none());
    }

    #[test]
    fn the_astra_profile_refuses_a_binding_older_than_its_global_registry() {
        let Ok(service_key) = MlDsa87PublicKey::new(vec![1; 2_592]) else {
            return;
        };
        let mut profile = AstraProfile {
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                .expect("policy"),
            credential_registry_epoch: 7,
            credential_bindings: BTreeMap::new(),
            active_astra_service_public_key: service_key,
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 1,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        };
        let stale = AstraCredentialBinding {
            format_version: crate::certificates::CERTIFICATE_FORMAT_VERSION,
            credential_id: vec![1],
            credential_public_key: vec![1],
            aaguid: [0; 16],
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            state: crate::certificates::approval::CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 6,
            ca_epoch: 1,
            created_at: 1,
            ca_pq_signature: super::super::encoding::MlDsa87Signature::placeholder(),
        };
        assert!(matches!(
            profile.accept_credential_binding(&stale),
            Err(CertificateError::GenerationRollback {
                current: 7,
                proposed: 6
            })
        ));
    }
}
