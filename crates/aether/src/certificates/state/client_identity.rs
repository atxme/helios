//! Client identities: the client TLS CA, pending stages and the at most two
//! generations a peer holds.

use super::*;

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
