//! The gateway's own identity: CA anchors, served leaves, their transitions
//! and the service rollback.

use super::*;

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
    /// A manual selection of the outgoing leaf, in force during the overlap.
    ///
    /// Absent outside a rollback, which is the resting state (spec §4.4).
    #[serde(default)]
    pub service_rollback: Option<GatewayServiceRollback>,
    /// The one transition a revoked identity will still accept (spec §10.1).
    ///
    /// Set from `replacement_transition_fingerprint` when a revocation
    /// withdraws the served identity and names what replaces it. Without it a
    /// revoked gateway has no way back at all: every transition is refused,
    /// and the domain has to be rebuilt to bring the service up again.
    ///
    /// It names **one exact signed document**, so it is not a re-opening of
    /// the state — nothing else installs, and the revoked leaves stay in the
    /// ledger where `install_transition` already refuses them.
    #[serde(default)]
    pub awaited_replacement: Option<Fingerprint>,
}

/// A bounded, manual selection of the outgoing identity (spec §4.4).
///
/// It is a **service** rollback and never a state rollback: no counter moves,
/// no slot is removed, and the decision it lives inside is untouched. It only
/// says which of the two leaves the gateway presents while the overlap lasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayServiceRollback {
    /// Fingerprint of the authorization that installed it.
    ///
    /// So the same signed document carried twice is a replay, and a different
    /// one — a later expiry, say — is a second decision rather than a silent
    /// extension of the first.
    pub authorization_fingerprint: Fingerprint,
    /// The leaf selected. Always the outgoing one; the authorization cannot
    /// name another, and this state re-checks it.
    pub selected_certificate_fingerprint: Fingerprint,
    /// At most the transition's `not_after`: a rollback cannot outlive the
    /// overlap it rolls back within.
    pub expires_at: u64,
}

impl GatewayServiceRollback {
    /// Whether this selection is still the one to serve at `now_unix`.
    pub const fn in_force(&self, now_unix: u64) -> bool {
        now_unix < self.expires_at
    }
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
        // A revoked leaf never comes back, whatever signs the document that
        // carries it (spec §10.2).
        ledger.assert_not_revoked(&transition.installed_fingerprints()?)?;
        // An identical decision already held is a no-op, and it must be
        // recognised before the generation rule refuses `current` as a repeat.
        // "Identical" is the whole signed document: the same leaves under a
        // different window are a different decision.
        let fingerprint = transition.fingerprint()?;
        let replaces_revoked = self.awaits_replacement(&fingerprint);
        if self.revoked && !replaces_revoked {
            return Err(CertificateError::Revoked);
        }
        // The reason is not decoration: an emergency replacement is the one
        // transition that installs straight into the served slot, so it is
        // accepted **only** where that is what §10 asks for. Offered on a
        // healthy identity it would be an immediate, unscheduled swap that no
        // client has been told about.
        if (transition.reason == RotationReason::EmergencyReplacement) != replaces_revoked {
            return Err(CertificateError::IllegalStateTransition(
                "emergency_replacement belongs to a revoked identity awaiting exactly this \
                 document, and nothing else does",
            ));
        }
        if self
            .next_transition_fingerprint
            .is_some_and(|staged| staged.matches(&fingerprint))
        {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if !replaces_revoked && self.next_gateway_identity_epoch.is_some() {
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
        if replaces_revoked {
            return self.replace_revoked_identity(transition);
        }
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

    /// Whether this exact document is the replacement a revocation named.
    fn awaits_replacement(&self, fingerprint: &Fingerprint) -> bool {
        self.revoked
            && self
                .awaited_replacement
                .is_some_and(|awaited| awaited.matches(fingerprint))
    }

    /// Installs the replacement of a revoked identity (spec §6.1, §10.2).
    ///
    /// # Why it does not go through the window
    ///
    /// §4.1 schedules an **ordinary** transition: prepared, then served, with
    /// the outgoing identity accepted throughout. Here the outgoing identity
    /// has been withdrawn — §10.2 makes the revocation dominate `staged`,
    /// `overlap` and any rollback — so there is nothing to overlap with.
    /// Staging this one would leave the gateway serving nothing at all until
    /// `activation_at`, on an incident where the service is already down.
    ///
    /// So it lands in the served slot directly, and the decision counter moves
    /// with it. What keeps that from being a way back into a revoked identity
    /// is upstream: the ledger refuses the retired fingerprints, and this path
    /// is only reachable for the one document the revocation itself named.
    fn replace_revoked_identity(
        &mut self,
        transition: &GatewayIdentityTransition,
    ) -> Result<InstallOutcome, CertificateError> {
        if let Some(certificate) = &transition.next_gateway_tls_certificate {
            self.active_gateway_tls_certificate = certificate.clone();
        }
        if let Some(certificate) = &transition.next_gateway_certificate {
            self.active_gateway_certificate = certificate.clone();
        }
        self.active_gateway_identity_epoch = transition.gateway_identity_epoch;
        self.gateway_decision_epoch = transition.gateway_identity_epoch;
        // Nothing staged, nothing to promote, nothing to roll back to: the
        // identity this replaces is gone rather than outgoing.
        self.next_gateway_identity_epoch = None;
        self.next_transition_fingerprint = None;
        self.next_gateway_tls_certificate = None;
        self.next_gateway_certificate = None;
        self.activation_at = None;
        self.retire_active_at = None;
        self.published = false;
        self.service_rollback = None;
        self.awaited_replacement = None;
        // The revocation counter keeps its value. It is a separate axis
        // (§4.2), and lowering it would make an already-consumed decision
        // deliverable a second time.
        self.revoked = false;
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
    /// Whether an overlap is in force at `now_unix` (spec §6.2).
    ///
    /// Exactly the window in which the daemon would otherwise serve the
    /// incoming leaf: staged, published, past `activation_at` and short of
    /// `not_after`. A rollback is available there and nowhere else — before
    /// publication the outgoing leaf is already the one served, and after
    /// `not_after` reviving it would be a state rollback.
    pub fn in_overlap(&self, now_unix: u64) -> bool {
        if self.revoked || !self.published || self.next_gateway_identity_epoch.is_none() {
            return false;
        }
        matches!(
            (self.activation_at, self.retire_active_at),
            (Some(activation_at), Some(retire_at))
                if now_unix >= activation_at && now_unix < retire_at
        )
    }

    /// Selects the outgoing leaf for the rest of the overlap (spec §4.4).
    ///
    /// Changes no counter and removes no slot: the transition it lives inside
    /// is exactly as it was, and `promote_if_due` will still fire at
    /// `not_after`. What it changes is which of the two leaves the daemon
    /// serves — and that is read at startup, not mid-process.
    ///
    /// Refused outside an overlap, on a revoked identity, for any leaf other
    /// than the outgoing one, and for an expiry past the overlap's end.
    ///
    /// Verification happens **here**, against the anchor, the transition and
    /// the leaf this state already holds — as for every other document it
    /// installs, a caller cannot hand in an authorization it verified against
    /// something else.
    pub fn apply_service_rollback(
        &mut self,
        authorization: &CertificateServiceRollbackAuthorization,
        now_unix: u64,
    ) -> Result<InstallOutcome, CertificateError> {
        // The state question before the cryptographic one: an operator who
        // asks for a rollback outside an overlap should be told that, not told
        // their signature failed against fields that do not exist yet.
        if !self.in_overlap(now_unix) {
            return Err(CertificateError::RollbackUnavailable);
        }
        let staged = self
            .next_transition_fingerprint
            .ok_or(CertificateError::RollbackUnavailable)?;
        let retire_at = self
            .retire_active_at
            .ok_or(CertificateError::RollbackUnavailable)?;
        // `verify` is what refuses a leaf other than the outgoing one and an
        // expiry past the overlap: both are checked against the values this
        // state holds, which is the point of passing them from here.
        authorization.verify(
            &self.current_ca_public_key,
            &self.trust_domain_id,
            self.ca_epoch,
            &self.gateway_wg_public_key,
            &self.server_name,
            &staged,
            &self.active_tls_fingerprint(),
            retire_at,
            now_unix,
        )?;
        let fingerprint = authorization.fingerprint()?;
        if let Some(existing) = &self.service_rollback {
            if existing.authorization_fingerprint.matches(&fingerprint) {
                return Ok(InstallOutcome::AlreadyPresent);
            }
        }
        self.service_rollback = Some(GatewayServiceRollback {
            authorization_fingerprint: fingerprint,
            selected_certificate_fingerprint: authorization.selected_certificate_fingerprint,
            expires_at: authorization.expires_at,
        });
        Ok(InstallOutcome::Installed)
    }

    /// The selection in force at `now_unix`, if any.
    ///
    /// Expiry is answered by the clock rather than by a purge: a rollback that
    /// has run out stops being served the second it does, whether or not
    /// anything has written to the registry since.
    pub fn active_service_rollback(&self, now_unix: u64) -> Option<&GatewayServiceRollback> {
        self.service_rollback
            .as_ref()
            .filter(|rollback| rollback.in_force(now_unix))
    }

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
        // The overlap is over, so its selection is too. Keeping it would leave
        // a document naming a leaf this state no longer holds.
        self.service_rollback = None;
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
        replacement_transition_fingerprint: Option<&Fingerprint>,
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
            self.service_rollback = None;
            // The one document that will still install here. Without it a
            // revoked gateway has no way back: every transition is refused,
            // and the service stays down until the domain is rebuilt.
            self.awaited_replacement = replacement_transition_fingerprint.copied();
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
            self.service_rollback = None;
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
