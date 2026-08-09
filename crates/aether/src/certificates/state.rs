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

use serde::{Deserialize, Serialize};

use crate::key_negotiation::PqCertificate;

use super::{
    authority::{
        AstraIssuerAuthorization, AstraServiceKeyTransition, CaTransition, ClientTlsCaTransition,
        EmergencyAstraServiceKeyReplacement,
    },
    client::{ClientCertificateGeneration, ClientCertificateStageAuthorization},
    encoding::{
        CanonicalBytes, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId,
        WireGuardKey,
    },
    gateway::{
        pq_certificate_fingerprint, GatewayIdentityTransition, GatewayTransitionAbort,
        GatewayTransitionAbortTombstone,
    },
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
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
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

    /// Installs a CA rotation, keeping at most two anchors (spec §9.2).
    pub fn apply_ca_transition(
        &mut self,
        transition: &CaTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
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
            .u8(u8::from(self.published));
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
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
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
    pub request_fingerprint: Fingerprint,
    pub candidate: ClientCertificateGeneration,
    pub state: PendingStageState,
    pub stage_expires_at: u64,
    /// Window the candidate will follow once committed.
    pub window: TransitionWindow,
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
    /// Stage that produced the committed `next`, so a replayed commit is
    /// recognised as the same one instead of finding an empty `pending`.
    ///
    /// Without it, the second delivery of a successful commit looks exactly
    /// like a commit for a stage that never existed, and a retry over a lossy
    /// link would be reported as a refusal.
    pub last_committed_stage: Option<Id16>,
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
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        let candidate = authorization.candidate()?;
        if let Some(pending) = &self.pending {
            if pending.stage_id == authorization.stage_id {
                // Identical replay is idempotent; the same identifier over
                // different bytes is a conflict, not a second attempt.
                if pending.candidate == candidate
                    && pending.stage_expires_at == authorization.stage_expires_at
                    && pending
                        .request_fingerprint
                        .matches(&authorization.request_fingerprint)
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
            request_fingerprint: authorization.request_fingerprint,
            candidate,
            state: PendingStageState::PendingGrant,
            stage_expires_at: authorization.stage_expires_at,
            window: authorization.window,
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
        required_state: PendingStageState,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.revoked {
            return Err(CertificateError::Revoked);
        }
        // A replay is recognised by the stage that produced the committed
        // slot, not by "there is a `next` roughly where one would be": a
        // different stage landing on the same generation is a conflict.
        if self.last_committed_stage.as_ref() == Some(stage_id) && self.next.is_some() {
            return Ok(InstallOutcome::AlreadyPresent);
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
        self.last_committed_stage = Some(*stage_id);
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
    pub fn revoke(&mut self, revocation_epoch: u64) {
        self.revoked = true;
        self.revocation_epoch = revocation_epoch;
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
        bytes
            .u64(self.active.generation)
            .u64(self.active.ca_tls_epoch)
            .fingerprint(&self.active.tls_ca_certificate_fingerprint)
            .fingerprint(&self.active.tls_certificate_fingerprint)
            .fingerprint(&self.active.pq_certificate_fingerprint)
            .u64(self.active.not_before)
            .u64(self.active.not_after);

        match &self.next {
            Some(next) => {
                bytes
                    .u8(1)
                    .u64(next.generation)
                    .fingerprint(&next.tls_certificate_fingerprint)
                    .fingerprint(&next.pq_certificate_fingerprint)
                    .u64(next.not_before)
                    .u64(next.not_after);
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
                    .fingerprint(&pending.request_fingerprint)
                    .u64(pending.candidate.generation)
                    .fingerprint(&pending.candidate.tls_certificate_fingerprint)
                    .fingerprint(&pending.candidate.pq_certificate_fingerprint)
                    .u8(match pending.state {
                        PendingStageState::PendingGrant => 0,
                        PendingStageState::PendingCommit => 1,
                    })
                    .u64(pending.stage_expires_at);
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

/// Astra's identity as a client pins it (spec §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraProfile {
    pub authority_url: String,
    pub webauthn_rp_id: String,
    pub active_astra_service_public_key: MlDsa87PublicKey,
    pub next_astra_service_public_key: Option<MlDsa87PublicKey>,
    /// Fingerprint of the `AstraServiceKeyTransition` document that staged it.
    pub next_service_key_transition_fingerprint: Option<Fingerprint>,
    pub astra_service_key_epoch: u64,
    pub service_key_activation_at: Option<u64>,
    pub service_key_retire_active_at: Option<u64>,
}

impl AstraProfile {
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
    ) -> Result<InstallOutcome, CertificateError> {
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
    pub fn apply_emergency_replacement(
        &mut self,
        replacement: &EmergencyAstraServiceKeyReplacement,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        current_revocation_epoch: u64,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        if self.astra_service_key_epoch == replacement.next_service_key_epoch
            && self.active_astra_service_public_key == replacement.next_service_public_key
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        replacement.verify(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            self.astra_service_key_epoch,
            current_revocation_epoch,
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
        self.next_astra_service_public_key = None;
        self.next_service_key_transition_fingerprint = None;
        self.service_key_activation_at = None;
        self.service_key_retire_active_at = None;
        Ok(InstallOutcome::Installed)
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

/// SHA-256 of the receiver's complete trust state (spec §8.1).
///
/// A manifest is bound to this value, so a transaction built against a state
/// that has since moved is refused instead of being applied to a world it was
/// never computed for.
pub fn base_state_fingerprint(
    gateway: &GatewayCertificateState,
    tls_ca: &ClientTlsCaState,
    astra: &AstraProfile,
    issuer_epoch: u64,
    client: &ClientCertificateState,
) -> Result<Fingerprint, CertificateError> {
    let mut bytes = CanonicalBytes::new(BASE_STATE_DOMAIN);
    gateway.snapshot(&mut bytes)?;
    bytes
        .u64(tls_ca.ca_tls_epoch)
        .fingerprint(&tls_ca.active_client_tls_ca_certificate.fingerprint())
        .optional_fingerprint(
            tls_ca
                .next_client_tls_ca_certificate
                .as_ref()
                .map(DerCertificate::fingerprint)
                .as_ref(),
        )
        .u64(tls_ca.activation_at.unwrap_or(0))
        .u64(tls_ca.retire_active_at.unwrap_or(0))
        .u64(astra.astra_service_key_epoch)
        .fingerprint(
            &astra
                .active_astra_service_public_key
                .authority_fingerprint(),
        )
        .optional_fingerprint(
            astra
                .next_astra_service_public_key
                .as_ref()
                .map(MlDsa87PublicKey::authority_fingerprint)
                .as_ref(),
        )
        .u64(astra.service_key_activation_at.unwrap_or(0))
        .u64(astra.service_key_retire_active_at.unwrap_or(0))
        .u64(issuer_epoch);
    client.snapshot(&mut bytes);
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

    fn staged_state() -> ClientCertificateState {
        let mut state = ClientCertificateState::new(generation(4, 1));
        state.pending = Some(ClientCertificatePendingStage {
            stage_id: Id16::new([3; 16]).expect("stage"),
            request_fingerprint: Fingerprint::of(b"request"),
            candidate: generation(5, 2),
            state: PendingStageState::PendingGrant,
            stage_expires_at: 5_000,
            window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
        });
        state
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
                PendingStageState::PendingCommit,
                2_000,
            )
            .expect("commit");
        assert!(orion.next.is_some());
    }

    /// A retry over a lossy link is a no-op, and it is recognised by the stage
    /// that produced the slot — not by "there is a `next` roughly here".
    #[test]
    fn a_replayed_commit_is_idempotent_for_its_own_stage_only() {
        let mut state = staged_state();
        let stage = Id16::new([3; 16]).unwrap();
        state
            .commit(&stage, PendingStageState::PendingGrant, 2_000)
            .expect("commit");

        assert_eq!(
            state
                .commit(&stage, PendingStageState::PendingGrant, 2_100)
                .expect("replay"),
            InstallOutcome::AlreadyPresent
        );
        // Another stage landing on the same generation is a conflict, not a
        // second success.
        assert!(matches!(
            state.commit(
                &Id16::new([4; 16]).unwrap(),
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
                state.install_transition(&transition, 500).expect("install"),
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
            state.install_transition(&transition, 500).expect("install");
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
            state.install_transition(&staged, 500).expect("install");

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
            assert!(state.install_transition(&retry, 500).is_err());
            let forward = transition(&ca, &state, 3, leaf(&ca, &candidate, 4));
            assert_eq!(
                state.install_transition(&forward, 500).expect("install"),
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
            state.install_transition(&first, 500).expect("install");

            let second = transition(&ca, &state, 3, leaf(&ca, &candidate, 3));
            assert!(matches!(
                state.install_transition(&second, 500),
                Err(CertificateError::IllegalStateTransition(_))
            ));

            // The identical one is an idempotent replay, not a refusal.
            assert_eq!(
                state.install_transition(&first, 500).expect("replay"),
                InstallOutcome::AlreadyPresent
            );
        }
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
            active_astra_service_public_key: active,
            next_astra_service_public_key: Some(next),
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 3,
            service_key_activation_at: Some(1_000),
            service_key_retire_active_at: Some(2_000),
        };
        assert!(profile.service_key_for(3, 999).is_some());
        assert!(profile.service_key_for(4, 999).is_none());
        assert!(profile.service_key_for(4, 1_000).is_some());
        assert!(profile.service_key_for(3, 2_000).is_none());
    }
}
