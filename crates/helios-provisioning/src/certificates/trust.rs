//! The anchors and the issuer a client leaf is issued under: the client
//! `CA-TLS`, Astra's delegated issuer and the credentials that approve a
//! rotation.
//!
//! This is the state [`RegistryState::client_leaf_issuers`](super::RegistryState::client_leaf_issuers)
//! and [`RegistryState::client_tls_anchors`](super::RegistryState::client_tls_anchors)
//! are read from.

use super::{
    BootstrapRepairOutcome, CertificateRegistry, ClientTlsCaTransition, DerCertificate,
    InstallOutcome, RegistryError,
};

impl CertificateRegistry {
    /// Installs a rotation of the client `CA-TLS` (spec §9.4).
    ///
    /// Verified by the state machine against the anchor this registry already
    /// serves. Persisted only when the state moved: an operator carrying the
    /// same document twice must not consume a second epoch.
    pub fn install_client_tls_ca_transition(
        &mut self,
        transition: &ClientTlsCaTransition,
        now_unix: u64,
    ) -> Result<InstallOutcome, RegistryError> {
        let mut state = self.state.clone();
        let ledger = state.ledger.clone();
        let ca_pq = state.gateway.current_ca_public_key.clone();
        let trust_domain_id = state.trust_domain_id;
        let ca_epoch = state.gateway.ca_epoch;
        let outcome = state.client_tls_ca.apply_transition(
            transition,
            &ca_pq,
            &trust_domain_id,
            ca_epoch,
            &ledger,
            now_unix,
        )?;
        if matches!(outcome, InstallOutcome::Installed) {
            self.persist(state)?;
        }
        Ok(outcome)
    }

    /// Records the domain's operator credentials, from the `CA-PQ`-signed
    /// document the companion emits.
    ///
    /// # Why the gateway holds them at all
    ///
    /// It never approves anything with them: an approval is a WebAuthn
    /// assertion, verified by Astra and by the client. What the gateway owes
    /// them is *distribution* — the §19 enrolment block is the only thing a
    /// client reads before it has a tunnel, and recovering an expired identity
    /// (§7.5) begins by naming the credential that will approve it. A client
    /// that had to fetch the list would have to fetch it over the link it has
    /// just lost.
    ///
    /// Until this call the registry learned a row only by verifying an
    /// approval that named it, which is to say: never, on a domain where no
    /// renewal had yet been approved. A freshly bootstrapped domain therefore
    /// enrolled clients that could never recover.
    ///
    /// # What is checked
    ///
    /// Every row, under the `CA-PQ` this registry already holds — not only the
    /// rows about to be used. A document carrying one forged row beside honest
    /// ones would otherwise install it, and that row is what a later
    /// `supersedes` would be compared against.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] if the document or any binding fails
    /// signature, domain, gateway, epoch, or binding validation. No partial
    /// document is persisted when validation or installation fails.
    ///
    /// # Side effects
    ///
    /// Persists all newly accepted bindings in one state transition and
    /// returns their count. Replayed bindings are accepted as no-ops.
    pub fn install_astra_credentials(
        &mut self,
        registry: &aether::certificates::approval::CredentialRegistry,
    ) -> Result<usize, RegistryError> {
        registry.verify(
            &self.state.gateway.current_ca_public_key,
            &self.state.trust_domain_id,
            &self.state.gateway.gateway_wg_public_key,
            self.state.gateway.ca_epoch,
            self.state.astra.credential_registry_epoch,
        )?;

        // One candidate, one persist: a registry left holding half a document
        // would answer an enrolment with a list nobody signed as a whole.
        let mut candidate = self.state.clone();
        let mut installed = 0usize;
        for binding in &registry.bindings {
            if matches!(
                candidate.astra.accept_credential_binding(binding)?,
                aether::certificates::state::InstallOutcome::Installed
            ) {
                installed += 1;
            }
        }
        if installed > 0 {
            self.persist(candidate)?;
        }
        Ok(installed)
    }

    /// Records Astra's delegated issuer and the automatic-renewal policy it
    /// names.
    ///
    /// The gateway holds the delegation itself, not merely one embedded in an
    /// approval: [`RegistryState::client_leaf_issuers`](super::RegistryState::client_leaf_issuers)
    /// is used both by staging and by the negotiation port. Keeping those
    /// views aligned prevents a leaf from being staged under an issuer that
    /// the port does not serve.
    ///
    /// The delegation is verified under the registry's current `CA-PQ`, its
    /// epoch must advance when its bytes change, and the policy pin is adopted
    /// in the same persisted state transition. A delegation and its policy are
    /// therefore never persisted separately.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when the delegation signature, domain,
    /// gateway identity, certificate epoch, validity window, or issuer epoch
    /// is invalid. Persistence errors are returned unchanged.
    ///
    /// # Side effects
    ///
    /// On success, persists the issuer as active and may update the pinned
    /// automatic-renewal policy. `now_unix` is the Unix timestamp used for
    /// validity checking.
    pub fn install_astra_issuer(
        &mut self,
        delegation: &aether::certificates::authority::AstraIssuerAuthorization,
        now_unix: u64,
    ) -> Result<aether::certificates::approval::PolicyMigration, RegistryError> {
        use aether::certificates::approval::PolicyMigration;

        if let Some(installed) = &self.state.issuer {
            if &installed.authorization != delegation
                && delegation.issuer_epoch <= installed.issuer_epoch
            {
                return Err(RegistryError::IssuerEpochNotAdvancing {
                    installed: installed.issuer_epoch,
                    offered: delegation.issuer_epoch,
                });
            }
        }
        let gateway = &self.state.gateway;
        delegation.verify(
            &gateway.current_ca_public_key,
            &gateway.trust_domain_id,
            gateway.ca_epoch,
            self.state.client_tls_ca.ca_tls_epoch,
            &gateway.gateway_wg_public_key,
            &gateway.server_name,
            now_unix,
        )?;
        let migration = self
            .state
            .astra
            .astra_policy_fingerprint
            .adopt_automatic_renewal_policy(
                gateway.trust_domain_id,
                gateway.gateway_wg_public_key,
                &gateway.server_name,
                delegation,
            )?;
        let mut candidate = self.state.clone();
        if let PolicyMigration::Adopted(pin) = migration {
            candidate.astra.astra_policy_fingerprint = pin;
        }
        candidate.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: delegation.issuer_epoch,
            authorization: delegation.clone(),
            state: aether::certificates::state::IssuerLifecycle::Active,
        });
        self.persist(candidate)?;
        Ok(migration)
    }

    /// Repairs the one legacy bootstrap that stored the admission CA where
    /// the domain's client `CA-TLS` belongs.
    ///
    /// This is deliberately narrower than a rotation. It changes only an
    /// epoch-1 registry whose anchor and every first-generation peer still
    /// name the exact admission CA supplied by the caller. Any staged or
    /// committed certificate generation refuses the repair: after issuance
    /// has moved, only a signed §9.4 transition may move the anchor.
    ///
    /// Pending *distributions* are preserved. They are signed objects queued
    /// for a peer and may be precisely the domain transition that exposed the
    /// bad bootstrap; they are not certificate generations owned by this
    /// registry.
    pub fn repair_legacy_client_tls_ca_bootstrap(
        &mut self,
        admission_ca: &DerCertificate,
        domain_ca: &DerCertificate,
    ) -> Result<BootstrapRepairOutcome, RegistryError> {
        aether::certificates::x509::assert_certificate_authority(admission_ca)?;
        aether::certificates::x509::assert_certificate_authority(domain_ca)?;
        aether::certificates::x509::assert_issued_by(admission_ca, admission_ca)?;
        aether::certificates::x509::assert_issued_by(domain_ca, domain_ca)?;

        let admission_fingerprint = admission_ca.fingerprint();
        let domain_fingerprint = domain_ca.fingerprint();
        let client_tls_ca = &self.state.client_tls_ca;

        if client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&domain_fingerprint)
        {
            return Ok(BootstrapRepairOutcome::AlreadyCorrect);
        }
        if client_tls_ca.ca_tls_epoch > 1 {
            return Ok(BootstrapRepairOutcome::LaterEpoch);
        }
        if client_tls_ca.ca_tls_epoch != 1 {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "the registry is not at client CA-TLS epoch 1",
            ));
        }
        if !client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&admission_fingerprint)
        {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "the active anchor is not the operator admission CA",
            ));
        }
        if client_tls_ca.next_client_tls_ca_certificate.is_some()
            || client_tls_ca.next_transition_fingerprint.is_some()
            || client_tls_ca.activation_at.is_some()
            || client_tls_ca.retire_active_at.is_some()
        {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "a client CA-TLS rotation is already in flight",
            ));
        }
        self.state
            .ledger
            .assert_not_revoked(&[domain_fingerprint])?;

        let every_peer_is_first_generation = self.state.peers.values().all(|peer| {
            let certificates = &peer.state;
            certificates.active.generation == 1
                && certificates.active.ca_tls_epoch == 1
                && certificates
                    .active
                    .tls_ca_certificate_fingerprint
                    .matches(&admission_fingerprint)
                && certificates.pending.is_none()
                && certificates.next.is_none()
                && certificates.activation_at.is_none()
                && certificates.retire_active_at.is_none()
                && certificates.last_committed_stage.is_none()
        });
        if !every_peer_is_first_generation {
            return Err(RegistryError::LegacyClientTlsCaRepair(
                "at least one peer has left its untouched first generation",
            ));
        }

        let mut candidate = self.state.clone();
        candidate.client_tls_ca.active_client_tls_ca_certificate = domain_ca.clone();
        for peer in candidate.peers.values_mut() {
            peer.state.active.tls_ca_certificate_fingerprint = domain_fingerprint;
        }
        self.persist(candidate)?;
        Ok(BootstrapRepairOutcome::Repaired)
    }
}
