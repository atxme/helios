//! Operator credentials: a security key's binding under the anchor, and the
//! bounded registry of them.

use super::*;

/// State of one registered operator credential (spec §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Active,
    /// The token is missing but not known to be in anyone's hands. It cannot
    /// approve, and it can still be restored by a later signed decision.
    Lost,
    /// Terminal: no later decision restores it (spec §2.4).
    Revoked,
}

impl CredentialState {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Lost => 1,
            Self::Revoked => 2,
        }
    }
}

/// The public binding of one FIDO2 credential, signed by `CA-PQ` (spec §2.4).
///
/// This is the anchor that lets Helios and Orion check an approval without
/// trusting Astra's online registry: the credential's public key arrives under
/// the same authority as everything else in the domain, and a revocation of it
/// is a signed decision rather than a row Astra can quietly change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCredentialBinding {
    pub format_version: u16,
    pub credential_id: Vec<u8>,
    /// COSE public key of the credential, as the authenticator registered it.
    pub credential_public_key: Vec<u8>,
    /// Authenticator model identifier. Frequently all-zero by design, so it is
    /// raw bytes rather than an [`Id16`], which refuses that value.
    pub aaguid: [u8; 16],
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub state: CredentialState,
    pub credential_epoch: u64,
    pub credential_registry_epoch: u64,
    pub ca_epoch: u64,
    pub created_at: u64,
    pub ca_pq_signature: MlDsa87Signature,
}

impl AstraCredentialBinding {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(CREDENTIAL_BINDING_DOMAIN);
        bytes
            .u16(self.format_version)
            .length_prefixed(&self.credential_id)
            .length_prefixed(&self.credential_public_key)
            .raw(&self.aaguid)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .u8(self.state.domain_byte())
            .u64(self.credential_epoch)
            .u64(self.credential_registry_epoch)
            .u64(self.ca_epoch)
            .u64(self.created_at);
        bytes.finish_signed()
    }

    /// The `credential_fingerprint` an approval carries.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.ca_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Authenticity and identity of the binding, never its usability.
    ///
    /// A `revoked` binding is a legitimately signed decision that has to
    /// verify — refusing it here would make the terminal state unreadable, and
    /// §2.4 requires the opposite: `revoked` dominates precisely because it is
    /// still a valid document. Usability is [`Self::assert_can_approve`], and
    /// the split follows [`AstraIssuerAuthorization::verify`] versus
    /// `authorize_renewal` for the same reason.
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.ca_epoch == 0 || self.credential_epoch == 0 || self.credential_registry_epoch == 0 {
            return Err(CertificateError::InvalidCredentialBinding("zero epoch"));
        }
        if self.credential_id.is_empty()
            || self.credential_id.len() > crate::certificates::client::MAX_CREDENTIAL_ID_BYTES
        {
            return Err(CertificateError::InvalidCredentialBinding("credential id"));
        }
        if self.credential_public_key.is_empty()
            || self.credential_public_key.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES
        {
            return Err(CertificateError::InvalidCredentialBinding("public key"));
        }
        // A key this build could not verify an assertion under is refused at
        // registration rather than at approval time — the one moment there is
        // no fallback.
        assert_supported_credential_key(&self.credential_public_key)?;
        // The registry epoch never walks back: every consumer keeps the
        // highest it has seen (spec §2.4).
        if self.credential_registry_epoch < minimum_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: minimum_registry_epoch,
                proposed: self.credential_registry_epoch,
            });
        }
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_pq_signature)
    }

    /// Whether this credential may approve anything at all.
    pub fn assert_can_approve(&self) -> Result<(), CertificateError> {
        match self.state {
            CredentialState::Active => Ok(()),
            CredentialState::Lost => Err(CertificateError::InvalidCredentialBinding("lost")),
            CredentialState::Revoked => Err(CertificateError::Revoked),
        }
    }

    /// Whether this decision may replace the one already held.
    ///
    /// Three rules, in the order that matters: it must be about the same
    /// credential, a revocation is terminal, and the registry epoch only ever
    /// rises. Without the second, a restored backup of an `active` row at a
    /// higher epoch would un-revoke a token somebody else is holding.
    pub fn supersedes(&self, previous: Option<&Self>) -> Result<(), CertificateError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        if previous.credential_id != self.credential_id {
            return Err(CertificateError::InvalidCredentialBinding("credential id"));
        }
        if previous.state == CredentialState::Revoked && self.state != CredentialState::Revoked {
            return Err(CertificateError::Revoked);
        }
        // A credential identifier names one authenticator key for its whole
        // life.  Letting a later registry row replace that key (or its AAGUID)
        // would turn the monotonic counter into a re-enrolment primitive.
        if self.credential_public_key != previous.credential_public_key
            || self.aaguid != previous.aaguid
        {
            return Err(CertificateError::InvalidCredentialBinding(
                "credential identity changed",
            ));
        }
        if self.credential_epoch < previous.credential_epoch {
            return Err(CertificateError::GenerationRollback {
                current: previous.credential_epoch,
                proposed: self.credential_epoch,
            });
        }
        if self.credential_registry_epoch < previous.credential_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: previous.credential_registry_epoch,
                proposed: self.credential_registry_epoch,
            });
        }
        if self.credential_registry_epoch == previous.credential_registry_epoch
            && !self.fingerprint().matches(&previous.fingerprint())
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.credential_registry_epoch,
            });
        }
        let state_changed = self.state != previous.state;
        let expected_credential_epoch = if state_changed {
            previous
                .credential_epoch
                .checked_add(1)
                .ok_or(CertificateError::ArithmeticOverflow)?
        } else {
            previous.credential_epoch
        };
        if self.credential_epoch != expected_credential_epoch {
            return Err(CertificateError::GenerationConflict {
                generation: self.credential_epoch,
            });
        }
        Ok(())
    }
}

/// Largest number of credential decisions one document may carry.
///
/// Eight key-slots plus the credentials they replaced, with headroom. Bounded
/// before a file is parsed rather than after: a document is read from disk on
/// three machines, and an unbounded list is an allocation driven by whoever
/// wrote the file.
pub const MAX_CREDENTIAL_BINDINGS: usize = 64;

/// Every signed credential decision of one trust domain (spec §2.4).
///
/// One document rather than loose bindings, and one **definition** rather than
/// one per consumer: the companion writes it, Astra reads it to decide which
/// credentials a renewal may name, and the two disagreeing about a field is
/// the kind of gap that surfaces at the first approval — the one moment there
/// is no fallback.
///
/// It is never *edited*. Every change of the key-slot table rebuilds it from
/// that table: one `active` row per slot present, one `revoked` row per
/// credential withdrawn. A row describing a slot the vault no longer holds is
/// therefore not refused — it is constructed by nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRegistry {
    pub trust_domain_id: TrustDomainId,
    /// The gateway the rows are bound to. Fixed at the first emission and
    /// compared afterwards: a binding under another gateway is a binding for
    /// another domain's consumers, and would verify nowhere.
    pub gateway_wg_public_key: WireGuardKey,
    pub ca_epoch: u64,
    /// Only ever rises, and every consumer keeps the highest it has seen.
    pub credential_registry_epoch: u64,
    pub bindings: Vec<AstraCredentialBinding>,
}

impl CredentialRegistry {
    /// The row of one credential identifier, if this document holds one.
    pub fn binding(&self, credential_id: &[u8]) -> Option<&AstraCredentialBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.credential_id == credential_id)
    }

    /// The rows a renewal approval may be answered by.
    ///
    /// `active` only: a request naming a lost or revoked credential asks an
    /// operator for a touch the verifier then refuses, which is a ceremony
    /// spent on a refusal.
    pub fn approvable(&self) -> Vec<&AstraCredentialBinding> {
        self.bindings
            .iter()
            .filter(|binding| binding.state == CredentialState::Active)
            .collect()
    }

    /// Refuses a document that does not describe the domain it was loaded for.
    pub fn assert_describes(
        &self,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
    ) -> Result<(), CertificateError> {
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        Ok(())
    }

    /// Every row, under `CA-PQ`, for the domain this consumer already pins.
    ///
    /// A consumer that verified only the rows it intended to use would accept
    /// a document carrying one forged row beside the honest ones — and the
    /// forged row is exactly what a later `supersedes` would be compared
    /// against. Two identical credential identifiers are refused for the same
    /// reason: which of the two decides is then a question of iteration order.
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
    ) -> Result<(), CertificateError> {
        self.assert_describes(trust_domain_id, gateway_wg_public_key)?;
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.ca_epoch == 0 || self.credential_registry_epoch == 0 {
            return Err(CertificateError::InvalidCredentialBinding("zero epoch"));
        }
        if self.credential_registry_epoch < minimum_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: minimum_registry_epoch,
                proposed: self.credential_registry_epoch,
            });
        }
        if self.bindings.is_empty() {
            return Err(CertificateError::InvalidCredentialBinding("empty document"));
        }
        if self.bindings.len() > MAX_CREDENTIAL_BINDINGS {
            return Err(CertificateError::TooManyObjects);
        }
        let mut seen: Vec<&[u8]> = Vec::with_capacity(self.bindings.len());
        for binding in &self.bindings {
            if seen.contains(&binding.credential_id.as_slice()) {
                return Err(CertificateError::InvalidCredentialBinding(
                    "duplicate credential",
                ));
            }
            seen.push(&binding.credential_id);
            // A registry is one signed snapshot, not a bag of decisions from
            // several historical snapshots.  Without equality here its clear
            // header could advertise epoch N while all authenticated rows
            // still belonged to N-1.
            if binding.credential_registry_epoch != self.credential_registry_epoch {
                return Err(CertificateError::InvalidCredentialBinding(
                    "mixed registry epochs",
                ));
            }
            binding.verify(
                ca_pq,
                trust_domain_id,
                gateway_wg_public_key,
                ca_epoch,
                minimum_registry_epoch,
            )?;
        }
        Ok(())
    }
}
