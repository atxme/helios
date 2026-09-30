//! The gateway's own identity and the domain anchor `CA-PQ`: staging,
//! publication, abort, rollback, promotion and revocation.
//!
//! These all write [`RegistryState::gateway`](super::RegistryState::gateway),
//! and each persists only when the state actually moved — an epoch is consumed
//! by a decision, never by a repeated delivery of one.

use super::{
    CaTransition, CertificateError, CertificateRegistry, CertificateServiceRollbackAuthorization,
    Fingerprint, GatewayIdentityTransition, GatewayServiceRollback, GatewayTransitionAbort,
    InstallOutcome, RegistryError,
};

impl CertificateRegistry {
    /// Stages a rotation of the domain anchor `CA-PQ` (spec §9.1).
    ///
    /// The state machine verifies it against the anchor this registry already
    /// pins — the outgoing `CA-PQ` authorises its successor, and the successor
    /// proves its own key — and refuses a second rotation while one is in
    /// flight, or one whose activation is already in the past.
    ///
    /// The anchor does **not** move here. Both are acceptable from
    /// `activation_at`, which is what [`RegistryState::client_leaf_issuers`](super::RegistryState::client_leaf_issuers)
    /// already reads, and `promote_due` retires the outgoing one at
    /// `not_after`. Persisted only when the state moved.
    pub fn install_ca_transition(
        &mut self,
        transition: &CaTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let ledger = state.ledger.clone();
        let outcome = state
            .gateway
            .apply_ca_transition(transition, &ledger, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Stages a signed transition of the gateway's own identity (spec §6.3).
    ///
    /// The verification belongs to the state machine, against the anchors
    /// this registry already pins: `CA-PQ` and its epoch, the stable WireGuard
    /// identity, the server name and the two leaves in service. Nothing is
    /// re-derived here, and a transition a caller verified somewhere else is
    /// not accepted on that caller's word — the same rule the client side
    /// follows for the objects it receives.
    ///
    /// Persisted only when the state actually moved. Carrying the same signed
    /// document in twice is `AlreadyPresent` and writes nothing: an epoch is
    /// consumed by a decision, never by a repeated delivery of one.
    pub fn install_gateway_transition(
        &mut self,
        transition: &GatewayIdentityTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        // The ledger is read while the gateway slot is written, and both live
        // in this one value. One copy on a ceremony that happens once per
        // identity buys the revocation check the ledger this registry holds,
        // rather than one the caller passed in.
        let ledger = state.ledger.clone();
        let outcome = state
            .gateway
            .install_transition(transition, &ledger, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Selects the outgoing gateway leaf for the rest of the overlap (§4.4).
    ///
    /// The state machine verifies the authorization against the anchor, the
    /// staged transition and the leaf this registry holds, and refuses it
    /// outside an overlap. Persisted only when the state moved: an operator
    /// carrying the same document twice must not rewrite the registry.
    ///
    /// It moves no counter and removes no slot — `promote_gateway_if_due`
    /// still fires at `not_after`, and the selection dies with the overlap it
    /// lives in.
    pub fn install_gateway_rollback(
        &mut self,
        authorization: &CertificateServiceRollbackAuthorization,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let outcome = state
            .gateway
            .apply_service_rollback(authorization, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// The gateway selection in force at `now_unix`, if any.
    pub fn active_gateway_rollback(&self, now_unix: u64) -> Option<&GatewayServiceRollback> {
        self.state.gateway.active_service_rollback(now_unix)
    }

    /// Promotes the gateway identity once its published overlap has ended.
    ///
    /// The registry is persisted before this method reports success. The
    /// caller may therefore replace the sealed active slot only after `true`:
    /// a crash can leave the old key beside a registry that already names the
    /// new generation, but can never destroy the old key ahead of that durable
    /// decision. Retrying the private-slot synchronization then completes the
    /// operation without moving the epoch a second time.
    pub fn promote_gateway_if_due(&mut self, now_unix: u64) -> Result<bool, RegistryError> {
        let gateway = &self.state.gateway;
        let due = gateway
            .retire_active_at
            .is_some_and(|retire_at| now_unix >= retire_at)
            && gateway.next_gateway_identity_epoch.is_some();
        if !due {
            return Ok(false);
        }
        if !gateway.published {
            return Err(RegistryError::Certificate(
                CertificateError::IllegalStateTransition(
                    "an unpublished gateway transition cannot be promoted",
                ),
            ));
        }

        let mut state = self.state.clone();
        let promoted = state.gateway.promote_if_due(now_unix)?;
        if promoted {
            self.persist(state)?;
        }
        Ok(promoted)
    }

    /// Records that the authority has let a staged transition leave (§6.3).
    ///
    /// Irreversible, and that is the point: past this marker a client may hold
    /// the decision, go offline and promote on its own at `not_after`.
    /// Cancelling on the gateway alone would leave two truths in one fleet.
    ///
    /// The publication names the exact document. An operator may have
    /// installed one transition by hand while the authority published
    /// another, and «publish whatever is staged» would then close the abort
    /// window on a decision nobody distributed.
    pub fn publish_gateway_transition(
        &mut self,
        gateway_identity_epoch: u64,
        transition_fingerprint: &Fingerprint,
    ) -> Result<(), RegistryError> {
        let gateway = &self.state.gateway;
        let names_the_staged_document = gateway.next_gateway_identity_epoch
            == Some(gateway_identity_epoch)
            && gateway
                .next_transition_fingerprint
                .is_some_and(|staged| staged.matches(transition_fingerprint));
        if !names_the_staged_document {
            return Err(RegistryError::Certificate(
                CertificateError::IllegalStateTransition(
                    "no staged transition matches this publication",
                ),
            ));
        }
        // A repeated report is the authority retrying a relay it could not
        // confirm, not a second decision.
        if gateway.published {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.gateway.mark_published()?;
        self.persist(state)
    }

    /// Cancels a staged, unpublished gateway transition (spec §6.3).
    ///
    /// The abort names the exact document it cancels, and the state machine
    /// refuses it once `published` is set or once the local clock has reached
    /// `activation_at` — backdating the object does not reopen a window the
    /// clients may already have acted on. The epoch stays consumed: the slot
    /// disappears, the tombstone takes its place, and the next attempt starts
    /// one decision higher.
    pub fn abort_gateway_transition(
        &mut self,
        abort: &GatewayTransitionAbort,
        transition: &GatewayIdentityTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let outcome = state.gateway.apply_abort(abort, transition, now_unix)?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Withdraws the gateway's own identity (spec §10.1).
    ///
    /// Returns whether a leaf this gateway actually holds was named. A
    /// revocation that names none is **not** an error: an offline document may
    /// carry decisions about leaves this state never saw, and its counter is
    /// consumed all the same — which is what stops the named leaf from
    /// arriving later through a transition.
    pub fn revoke_gateway(
        &mut self,
        revoked_tls_fingerprint: Option<&Fingerprint>,
        revoked_pq_fingerprint: Option<&Fingerprint>,
        revocation_epoch: u64,
        replacement_transition_fingerprint: Option<&Fingerprint>,
    ) -> Result<bool, RegistryError> {
        let mut state = self.state.clone();
        let hit = state.gateway.apply_revocation(
            revoked_tls_fingerprint,
            revoked_pq_fingerprint,
            revocation_epoch,
            replacement_transition_fingerprint,
        )?;
        self.persist(state)?;
        Ok(hit)
    }
}
