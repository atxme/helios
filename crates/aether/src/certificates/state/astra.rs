//! Astra as the holder pins it: its profile, service keys and delegated
//! issuer.

use super::*;

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
