//! Astra's pinned issuance policy and operator credentials — spec §2.4.
//!
//! Scheduled client renewal is automatic from 80 % and is authorized by the
//! narrow delegated issuer policy. The WebAuthn objects in this module remain
//! for recovery, campaigns and strict decoding of persisted pre-amendment
//! renewal records; current scheduled staging refuses them.
//!
//! # Legacy per-request approval objects
//!
//! [`AstraCredentialApprovalRequest`] states what is about to be renewed and
//! fixes the WebAuthn challenge as the SHA-256 of its own canonical form.
//! [`AstraRenewalApproval`] carries the assertion that answered that exact
//! challenge, together with the [`AstraCredentialBinding`] of the credential
//! that produced it, signed by `CA-PQ`.
//!
//! Their property is that **Astra's word alone authorizes nothing**. Astra signs
//! the approval, and that signature is checked — but a consumer that stopped
//! there would be trusting the online service the delegation exists to
//! distrust. So [`AstraRenewalApproval::verify`] independently re-derives the
//! challenge from the request, re-checks the assertion under the credential's
//! own public key, and re-checks that key's binding under the anchor. Any one
//! of the three failing refuses the approval, whatever Astra signed.
//!
//! # The token signs nothing
//!
//! Worth restating where it is easiest to get wrong: a YubiKey produces no
//! ML-DSA-87 signature, and no field here holds one from it. The assertion
//! historically authorized the use of the delegated issuer. It does not open
//! the authority vault and never becomes a signature of the certificate
//! lifecycle.
//!
//! # Why the policy is pinned rather than delegated
//!
//! [`AstraPolicyPin`] is confirmed out of band, displayed next to the `CA-PQ`
//! fingerprint at enrolment, and then compared **before** any delegated right
//! is read. A `CA-PQ` signature over a different policy does not replace it:
//! that is the difference between "the operator agreed to these ceilings" and
//! "whoever holds the anchor agreed to these ceilings", and the anchor is
//! exactly what a delegation is supposed to keep out of the online path.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

use super::{
    authority::{AllowedUsage, AstraIssuerAuthorization},
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, Fingerprint, Id16,
        MlDsa87PublicKey, MlDsa87Signature, SignedTranscript, TrustDomainId, WireGuardKey,
    },
    webauthn::{
        assert_supported_credential_key, validate_https_origin, verify_assertion,
        AssertionExpectation, WebAuthnAssertion, MAX_CREDENTIAL_PUBLIC_KEY_BYTES,
    },
    window::{require_next_generation, MAX_OVERLAP_SECS, MAX_STAGE_LEASE_SECS},
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

/// Hash domain of the issuance policy (spec §2.4).
///
/// A `v1` domain rather than `v5`: the policy has its own version, and the
/// specification is explicit that v1 defines no online transition of it.
const ISSUANCE_POLICY_DOMAIN: &[u8] = b"helios-astra-issuance-policy-v1";

/// ML-DSA-87 domain of a credential binding.
const CREDENTIAL_BINDING_DOMAIN: &[u8] = b"helios-astra-credential-binding-v5";

/// ML-DSA-87 domain of an approval request.
const CREDENTIAL_APPROVAL_REQUEST_DOMAIN: &[u8] = b"helios-astra-credential-approval-request-v5";

/// ML-DSA-87 domain of a persisted approval.
const RENEWAL_APPROVAL_DOMAIN: &[u8] = b"helios-astra-renewal-approval-v5";

/// Hash domain of the WebAuthn challenge an ordinary renewal is approved with.
///
/// Named in §2.3.1 as a challenge domain and **not** as an ML-DSA context: no
/// key signs under it, which is why it is absent from the registry of
/// [`crate::ml_dsa`].
const CLIENT_RENEWAL_APPROVAL_DOMAIN: &[u8] = b"helios-astra-client-renewal-approval-v5";

/// Hash domain of the WebAuthn challenge a §7.5 recovery is approved with.
///
/// A challenge domain, not an ML-DSA context: no key signs under it. It is
/// distinct from the ordinary renewal's so an assertion produced for one can
/// never be presented as the other — the two authorize very different things,
/// since a recovery bypasses the validity period an ordinary renewal respects.
const EXPIRED_RECOVERY_APPROVAL_DOMAIN: &[u8] = b"helios-astra-expired-recovery-approval-v5";

/// Version of the issuance policy this build computes and pins.
pub const ISSUANCE_POLICY_FORMAT_VERSION: u16 = 1;

/// Percentage of a leaf's life at which a renewal is prepared (spec §4.3).
pub const POLICY_RENEWAL_START_PERCENT: u8 = 80;

/// Credentials a scheduled client renewal requires: none.
pub const AUTOMATIC_RENEWAL_CREDENTIALS: u8 = 0;

/// Credentials carried by the superseded per-request approval document.
/// Kept only so older persisted documents remain strictly parseable.
pub const PER_REQUEST_APPROVAL_CREDENTIALS: u8 = 1;

/// Credentials an anchor or admission mutation requires: exactly two.
pub const AUTHORITY_MUTATION_CREDENTIALS: u8 = 2;

/// Most credentials an approval request may enumerate (spec §2.4).
pub const MAX_ALLOWED_CREDENTIALS: usize = 8;

/// Longest life of an approval request and of an approval (spec §2.4).
pub const MAX_APPROVAL_LIFETIME_SECS: u64 = 300;

/// The ceilings and counts an operator confirmed out of band (spec §2.4).
///
/// Not a signed object: it is a **computation**, and its result is the pin.
/// Making it signable would reintroduce the thing §2.4 refuses — a policy that
/// an anchor's signature can move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraIssuancePolicy {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub allowed_usage: AllowedUsage,
    pub maximum_leaf_lifetime_secs: u64,
    pub maximum_stage_lease_secs: u64,
    pub maximum_overlap_secs: u64,
    pub renewal_start_percent: u8,
    pub scheduled_renewal_credentials: u8,
    pub expired_recovery_credentials: u8,
    pub authority_mutation_credentials: u8,
}

impl AstraIssuancePolicy {
    /// The fixed policy profile shipped by this protocol version.
    ///
    /// Both Astra and Helios compute it independently from the gateway identity
    /// during bootstrap.  The resulting fingerprint is then displayed and
    /// carried by enrollment documents; it is never learned from a delegation.
    pub fn standard(
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: String,
    ) -> Self {
        Self {
            format_version: ISSUANCE_POLICY_FORMAT_VERSION,
            trust_domain_id,
            gateway_wg_public_key,
            server_name,
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 90 * 86_400,
            maximum_stage_lease_secs: MAX_STAGE_LEASE_SECS,
            maximum_overlap_secs: MAX_OVERLAP_SECS,
            renewal_start_percent: POLICY_RENEWAL_START_PERCENT,
            scheduled_renewal_credentials: AUTOMATIC_RENEWAL_CREDENTIALS,
            expired_recovery_credentials: 1,
            authority_mutation_credentials: AUTHORITY_MUTATION_CREDENTIALS,
        }
    }

    /// Every bound §2.4 fixes, refused by name rather than clamped.
    ///
    /// A policy outside these bounds has no fingerprint at all — see
    /// [`Self::fingerprint`] — so two ends can never pin a ceiling the
    /// specification does not allow and then agree with each other about it.
    pub fn validate(&self) -> Result<(), CertificateError> {
        if self.format_version != ISSUANCE_POLICY_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: ISSUANCE_POLICY_FORMAT_VERSION,
            });
        }
        validate_server_name(&self.server_name)?;
        if self.allowed_usage != AllowedUsage::AdmittedClientLeafRenewal {
            return Err(CertificateError::InvalidPolicy("allowed usage"));
        }
        if self.maximum_leaf_lifetime_secs == 0 {
            return Err(CertificateError::InvalidPolicy("leaf lifetime"));
        }
        if self.maximum_stage_lease_secs == 0
            || self.maximum_stage_lease_secs > MAX_STAGE_LEASE_SECS
        {
            return Err(CertificateError::InvalidPolicy("stage lease"));
        }
        if self.maximum_overlap_secs == 0 || self.maximum_overlap_secs > MAX_OVERLAP_SECS {
            return Err(CertificateError::InvalidPolicy("overlap"));
        }
        if self.renewal_start_percent != POLICY_RENEWAL_START_PERCENT {
            return Err(CertificateError::InvalidPolicy("renewal start"));
        }
        if self.scheduled_renewal_credentials != AUTOMATIC_RENEWAL_CREDENTIALS {
            return Err(CertificateError::InvalidPolicy(
                "scheduled renewal credentials",
            ));
        }
        if self.expired_recovery_credentials != 1 && self.expired_recovery_credentials != 2 {
            return Err(CertificateError::InvalidPolicy("recovery credentials"));
        }
        if self.authority_mutation_credentials != AUTHORITY_MUTATION_CREDENTIALS {
            return Err(CertificateError::InvalidPolicy("authority credentials"));
        }
        Ok(())
    }

    /// SHA-256 of the canonical form of §2.4, once the policy is in bounds.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.validate()?;
        let mut bytes = CanonicalBytes::new(ISSUANCE_POLICY_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u8(self.allowed_usage.domain_byte())
            .u64(self.maximum_leaf_lifetime_secs)
            .u64(self.maximum_stage_lease_secs)
            .u64(self.maximum_overlap_secs)
            .u8(self.renewal_start_percent)
            .u8(self.scheduled_renewal_credentials)
            .u8(self.expired_recovery_credentials)
            .u8(self.authority_mutation_credentials);
        Ok(Fingerprint::of(&bytes.finish()))
    }

    /// The value a profile and a registry store.
    pub fn pin(&self) -> Result<AstraPolicyPin, CertificateError> {
        AstraPolicyPin::new(self.fingerprint()?)
    }
}

/// The out-of-band pin of the issuance policy (spec §2.4).
///
/// A newtype rather than a bare [`Fingerprint`], for one reason: the zero
/// value is what an unset field deserializes to, and a pin that compares equal
/// to nothing has to be impossible to hold rather than merely unlikely. §14.1
/// asks for exactly that refusal — "profil refusé avec une empreinte de
/// politique nulle".
///
/// There is deliberately no constructor taking a signed object. The pin is
/// confirmed by a human against the `CA-PQ` fingerprint at enrolment; learning
/// it from a document would make it a delegation, which §2.4 refuses in as
/// many words.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AstraPolicyPin(Fingerprint);

impl AstraPolicyPin {
    pub fn new(fingerprint: Fingerprint) -> Result<Self, CertificateError> {
        if fingerprint.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CertificateError::PolicyNotPinned);
        }
        Ok(Self(fingerprint))
    }

    pub const fn fingerprint(&self) -> &Fingerprint {
        &self.0
    }

    /// Compares a presented policy fingerprint against the pin.
    pub fn assert_matches(&self, presented: &Fingerprint) -> Result<(), CertificateError> {
        if !self.0.matches(presented) {
            return Err(CertificateError::FingerprintMismatch(
                "Astra issuance policy",
            ));
        }
        Ok(())
    }

    /// The §2.4 ordering: the pin decides before any delegated right is read.
    ///
    /// Calling `AstraIssuerAuthorization::verify` first would establish that
    /// `CA-PQ` signed *a* delegation — which is true of a delegation carrying
    /// any policy at all, including one that raises every ceiling.
    pub fn assert_authorizes(
        &self,
        delegation: &AstraIssuerAuthorization,
    ) -> Result<(), CertificateError> {
        self.assert_matches(&delegation.policy_fingerprint)
    }

    /// Refuses to reinterpret a pin confirmed under an older issuance policy
    /// as permission for credential-free scheduled renewal.
    ///
    /// Removing the per-request credential changes the authority represented
    /// by the policy fingerprint.  A deployment must therefore confirm the
    /// current standard policy out of band before this path is enabled; merely
    /// upgrading the binaries cannot silently broaden an older delegation.
    pub fn assert_allows_automatic_renewal(
        &self,
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: &str,
    ) -> Result<(), CertificateError> {
        let expected = AstraIssuancePolicy::standard(
            trust_domain_id,
            gateway_wg_public_key,
            server_name.to_owned(),
        )
        .fingerprint()?;
        self.assert_matches(&expected)
    }
}

impl std::fmt::Debug for AstraPolicyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AstraPolicyPin({})", self.0)
    }
}

impl<'de> Deserialize<'de> for AstraPolicyPin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Fingerprint::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

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
    fn signing_bytes(&self) -> SignedTranscript {
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
            || self.credential_id.len() > super::client::MAX_CREDENTIAL_ID_BYTES
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
        if previous.state == CredentialState::Revoked {
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

/// What Astra asks an operator to approve, before any certificate exists.
///
/// It is signed by the Astra service key so the companion can display fields
/// it did not choose, and it fixes the WebAuthn challenge as the hash of its
/// own canonical form — which is what makes the resulting assertion unmovable
/// to another peer, generation or deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCredentialApprovalRequest {
    pub format_version: u16,
    pub operation_id: Id16,
    /// SHA-256 of the client rotation request of §7.1, signatures included.
    pub request_fingerprint: Fingerprint,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub requested_generation: u64,
    pub credential_registry_epoch: u64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub allowed_credential_ids: Vec<Vec<u8>>,
    pub required_credentials: u8,
    pub created_at: u64,
    pub expires_at: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraCredentialApprovalRequest {
    /// The field sequence §2.4 fixes for the challenge, reused by the
    /// signature so the two can never describe different operations.
    fn body(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u16(self.format_version)
            .id(&self.operation_id)
            .fingerprint(&self.request_fingerprint)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.requested_generation)
            .u64(self.credential_registry_epoch)
            .text(&self.webauthn_rp_id)
            .text(&self.webauthn_origin);
        for credential_id in &self.allowed_credential_ids {
            bytes.length_prefixed(credential_id);
        }
        bytes.u64(self.created_at).u64(self.expires_at);
    }

    /// The WebAuthn challenge of §2.4: SHA-256 of the canonical request.
    ///
    /// Not an ML-DSA context and not signed by anyone — it is the 32 bytes the
    /// authenticator answers, and the reason an assertion cannot be carried to
    /// a second operation.
    pub fn challenge(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(CLIENT_RENEWAL_APPROVAL_DOMAIN);
        self.body(&mut bytes);
        Fingerprint::of(&bytes.finish())
    }

    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(CREDENTIAL_APPROVAL_REQUEST_DOMAIN);
        self.body(&mut bytes);
        bytes
            .u8(self.required_credentials)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// Identifies this request, signature included, for the approval chain.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.astra_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verified under the service key the consumer **already pins**.
    ///
    /// `active_generation` is the consumer's own persisted generation, not a
    /// value read from the request: an approval request that named its own
    /// starting point could ask an operator to approve a renewal of a
    /// generation that is no longer current.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        webauthn_rp_id: &str,
        active_generation: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        // The relying party identifier is pinned in the profile and survives a
        // rotation of Astra's public TLS certificate, so it is compared rather
        // than learned (spec §2.4).
        if self.webauthn_rp_id != webauthn_rp_id {
            return Err(CertificateError::InvalidServerName);
        }
        validate_server_name(&self.webauthn_rp_id)?;
        validate_https_origin(&self.webauthn_origin, &self.webauthn_rp_id)?;
        if self.active_generation != active_generation {
            return Err(CertificateError::GenerationRollback {
                current: active_generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.requested_generation)?;
        if self.required_credentials != PER_REQUEST_APPROVAL_CREDENTIALS {
            return Err(CertificateError::InsufficientApprovals {
                required: PER_REQUEST_APPROVAL_CREDENTIALS,
                provided: self.required_credentials,
            });
        }
        self.validate_credential_list()?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_APPROVAL_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    fn validate_credential_list(&self) -> Result<(), CertificateError> {
        if self.allowed_credential_ids.is_empty()
            || self.allowed_credential_ids.len() > MAX_ALLOWED_CREDENTIALS
        {
            return Err(CertificateError::UnknownCredential);
        }
        for (index, credential_id) in self.allowed_credential_ids.iter().enumerate() {
            if credential_id.is_empty()
                || credential_id.len() > super::client::MAX_CREDENTIAL_ID_BYTES
            {
                return Err(CertificateError::UnknownCredential);
            }
            // A repeated identifier would let the same credential fill two
            // slots of a list whose length is the only thing bounding how many
            // tokens an operation may be answered by.
            if self.allowed_credential_ids[..index].contains(credential_id) {
                return Err(CertificateError::UnknownCredential);
            }
        }
        Ok(())
    }

    fn allows(&self, credential_id: &[u8]) -> bool {
        self.allowed_credential_ids
            .iter()
            .any(|allowed| allowed.as_slice() == credential_id)
    }
}

/// The approval Astra persists once an assertion answered the challenge.
///
/// It travels to Helios with the staging authorization and its fingerprint
/// enters both the stage and the grant, which is what makes it impossible to
/// issue a leaf that no operator approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRenewalApproval {
    pub format_version: u16,
    pub operation_id: Id16,
    /// Fingerprint of the client rotation request of spec §7.1.
    ///
    /// This deliberately has the same meaning as
    /// [`AstraCredentialApprovalRequest::request_fingerprint`].  The signed
    /// approval-request document has its own fingerprint below; conflating the
    /// two made two interoperable implementations impossible.
    pub request_fingerprint: Fingerprint,
    /// Fingerprint of the signed [`AstraCredentialApprovalRequest`] whose
    /// WebAuthn challenge was answered.
    pub approval_request_fingerprint: Fingerprint,
    /// The `CA-PQ`-signed binding of the credential that answered, carried
    /// whole so no consumer has to ask Astra's registry what it means.
    pub credential_binding: AstraCredentialBinding,
    pub credential_fingerprint: Fingerprint,
    pub assertion_fingerprint: Fingerprint,
    pub webauthn_assertion: WebAuthnAssertion,
    pub approved_at: u64,
    pub expires_at: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraRenewalApproval {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(RENEWAL_APPROVAL_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.operation_id)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.approval_request_fingerprint)
            .fingerprint(&self.credential_fingerprint)
            .fingerprint(&self.assertion_fingerprint)
            .u64(self.approved_at)
            .u64(self.expires_at)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// The `renewal_authorization_fingerprint` of the stage and of the grant.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.astra_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// The three independent proofs, then Astra's own signature.
    ///
    /// The order is the argument of this module: the binding is checked under
    /// the anchor, the assertion under the credential's own key, and the
    /// challenge is re-derived from the request — all before Astra's signature
    /// is looked at, so that no step can be satisfied by Astra's assertion
    /// that it happened.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        request: &AstraCredentialApprovalRequest,
        ca_pq: &MlDsa87PublicKey,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        self.verify_operator_evidence(
            request,
            ca_pq,
            service_key_epoch,
            trust_domain_id,
            ca_epoch,
            minimum_registry_epoch,
            now_unix,
        )?;
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    /// Verifies what the offline companion produced, before Astra signs it.
    ///
    /// The companion deliberately cannot create `astra_signature`.  Astra
    /// must therefore establish the request binding, the `CA-PQ` credential
    /// binding and the WebAuthn assertion first, then countersign that proven
    /// fact.  Calling [`Self::verify`] on the placeholder would reject every
    /// legitimate approval; signing first would make the online key sign
    /// attacker-chosen invalid evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_operator_evidence(
        &self,
        request: &AstraCredentialApprovalRequest,
        ca_pq: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.operation_id != request.operation_id {
            return Err(CertificateError::ApprovalMismatch("operation"));
        }
        // The binding to the exact request: the amendment of 15 August 2026
        // makes this the difference between an approval and a licence.
        if !self
            .request_fingerprint
            .matches(&request.request_fingerprint)
        {
            return Err(CertificateError::ApprovalMismatch("request fingerprint"));
        }
        if !self
            .approval_request_fingerprint
            .matches(&request.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch(
                "approval request fingerprint",
            ));
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        // `approved_at <= expires_at <= min(request.expires_at, approved_at +
        // 300)`, read under the consumer's clock rather than Astra's.
        if self.expires_at < self.approved_at
            || self.expires_at > request.expires_at
            || self
                .expires_at
                .checked_sub(self.approved_at)
                .ok_or(CertificateError::ArithmeticOverflow)?
                > MAX_APPROVAL_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }

        if !self
            .credential_fingerprint
            .matches(&self.credential_binding.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch("credential binding"));
        }
        self.credential_binding.verify(
            ca_pq,
            trust_domain_id,
            &request.gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        self.credential_binding.assert_can_approve()?;
        // The registry epoch the operator was shown must not be older than the
        // one the request named, or a credential revoked between the two would
        // still approve.
        if self.credential_binding.credential_registry_epoch < request.credential_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: request.credential_registry_epoch,
                proposed: self.credential_binding.credential_registry_epoch,
            });
        }
        if !request.allows(&self.credential_binding.credential_id) {
            return Err(CertificateError::UnknownCredential);
        }

        if !self
            .assertion_fingerprint
            .matches(&self.webauthn_assertion.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch("assertion"));
        }
        let challenge = request.challenge();
        verify_assertion(
            &self.webauthn_assertion,
            &self.credential_binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: &request.webauthn_rp_id,
                origin: &request.webauthn_origin,
                challenge: &challenge,
            },
        )?;

        Ok(())
    }
}

/// The complete evidence transported with a delegated client renewal.
///
/// A fingerprint alone cannot be checked by Helios or Orion: both consumers
/// need the service-signed request to reconstruct the WebAuthn challenge and
/// the approval carrying the assertion and the CA-PQ-signed credential
/// binding.  Keeping the pair in one strict object prevents a route or a
/// persistence layer from accidentally forwarding only the convenient half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRenewalApprovalEvidence {
    pub approval_request: AstraCredentialApprovalRequest,
    pub approval: AstraRenewalApproval,
}

impl AstraRenewalApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint` by stage, receipt
    /// and grant.
    pub fn fingerprint(&self) -> Fingerprint {
        self.approval.fingerprint()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_rotation_request: &Fingerprint,
        ca_pq: &MlDsa87PublicKey,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        webauthn_rp_id: &str,
        active_generation: u64,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if !self
            .approval_request
            .request_fingerprint
            .matches(expected_rotation_request)
        {
            return Err(CertificateError::ApprovalMismatch(
                "rotation request fingerprint",
            ));
        }
        self.approval_request.verify(
            service_key,
            service_key_epoch,
            trust_domain_id,
            gateway_wg_public_key,
            client_wg_public_key,
            webauthn_rp_id,
            active_generation,
            now_unix,
        )?;
        self.approval.verify(
            &self.approval_request,
            ca_pq,
            service_key,
            service_key_epoch,
            trust_domain_id,
            ca_epoch,
            minimum_registry_epoch,
            now_unix,
        )
    }
}

/// The complete evidence transported with a campaign-authorized rotation.
///
/// The other approval family of §7.2. An ordinary renewal is approved once,
/// for one request that already exists; a campaign is approved once for a set
/// of targets, before any of their rotation requests are written. So the
/// document a consumer has to check is not the same one, and neither is the
/// thing it binds to: [`AstraRenewalApprovalEvidence`] binds to a request
/// fingerprint, this binds to the target's *current state*.
///
/// # Why the registry travels with it
///
/// [`CampaignApproval::verify`] resolves each credential against a
/// `CA-PQ`-signed [`CredentialRegistry`]. Helios holds the per-credential
/// decisions it has already accepted, not that document, so the document comes
/// along and is verified under the `CA-PQ` the consumer already pins — never
/// believed for being present. The rows are then what the assertions are
/// checked against, and the caller applies them to its own state afterwards,
/// where `supersedes` refuses a revival.
///
/// # Why the origin travels with it, and the relying party does not
///
/// The relying party is domain state: the consumer pins it and compares. The
/// origin is not carried anywhere the consumer can reach, so it comes with the
/// evidence — and is admissible only if it is an HTTPS origin *of that pinned
/// relying party*, which is what stops a supplied origin from being a supplied
/// answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCampaignApprovalEvidence {
    pub campaign: super::status::AstraRotationCampaign,
    pub approval: super::status::CampaignApproval,
    pub credential_registry: CredentialRegistry,
    pub webauthn_origin: String,
}

impl AstraCampaignApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint` (spec §7.2).
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.approval.fingerprint()
    }

    /// Re-derives every claim against material the consumer already holds.
    ///
    /// `now_unix` is the instant the *authorization* was signed, not the
    /// instant it is read: a campaign carries a five-minute window, and it is
    /// the staging lease — not the campaign — that bounds replay afterwards.
    /// This mirrors what the ordinary family already does.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        active_tls_certificate_fingerprint: &Fingerprint,
        active_pq_certificate_fingerprint: &Fingerprint,
        webauthn_rp_id: &str,
        astra_policy_fingerprint: &Fingerprint,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        // The domain, before anything is read from the campaign: a campaign
        // for another gateway would resolve credentials that verify nowhere.
        if self.campaign.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.campaign.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        // §2.4: the policy pin is confirmed out of band and no CA-PQ signature
        // replaces it. A campaign naming another policy was resolved against
        // another set of rules.
        if !self
            .campaign
            .policy_fingerprint
            .matches(astra_policy_fingerprint)
        {
            return Err(CertificateError::PolicyNotPinned);
        }
        self.credential_registry.verify(
            ca_pq,
            trust_domain_id,
            gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        // Supplied, therefore checked against something that was not: an
        // origin that does not belong to the pinned relying party is refused
        // before any assertion is looked at.
        validate_https_origin(&self.webauthn_origin, webauthn_rp_id)?;
        self.approval.verify(
            &self.campaign,
            &self.credential_registry,
            webauthn_rp_id,
            &self.webauthn_origin,
            now_unix,
        )?;
        // Last, and the reason this family exists at all: the operator
        // approved *this* identity at *this* state.
        self.campaign.covers_client(
            client_wg_public_key,
            active_generation,
            active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint,
        )
    }
}

/// The operator authorization behind one delegated client rotation (§7.2).
///
/// # Why the reason and the evidence are one value
///
/// A staging authorization carries both a `reason` and an approval object,
/// and only two of their combinations mean anything: `scheduled` with an
/// ordinary renewal approval, `manual_global` with a campaign approval. Passed
/// as two arguments they can disagree, and a disagreement here is a rotation
/// authorized by a document that never described it. Passed as one value they
/// cannot: the reason is *derived* from the family, at the only place that
/// One operator credential's answer to a §7.5 recovery challenge.
///
/// # Why this is a third family and not a variant of the other two
///
/// A recovery is the one operation that reaches past a validity period. Its
/// challenge therefore has its own hash domain, so an assertion taken for an
/// ordinary renewal — which the operator was shown as a routine rotation —
/// can never be replayed as authorization to revive an expired identity. The
/// two documents are not interchangeable, and making them one type is how they
/// would become so.
///
/// It is also **not** what makes the staging legitimate: a recovery staging is
/// signed by `CA-PQ` itself (`IssuerKind::Master`), inside the companion, and
/// that signature is the operator's decision. This document is what lets Astra
/// check, before relaying anything, that the touch answered *this* request —
/// and what consumes the challenge so a second relay finds nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryApproval {
    /// Fingerprint of the [`super::client::ExpiredCertificateRecoveryRequest`].
    pub request_fingerprint: Fingerprint,
    /// The nonce Astra issued and will consume.
    pub astra_challenge: [u8; 32],
    pub approved_at: u64,
    pub expires_at: u64,
    pub credential_id: Vec<u8>,
    pub credential_fingerprint: Fingerprint,
    pub assertion_fingerprint: Fingerprint,
    pub webauthn_assertion: WebAuthnAssertion,
}

impl ExpiredRecoveryApproval {
    /// The 32 bytes the authenticator answers (spec §7.5).
    ///
    /// The request, the nonce and the deadline. Binding all three is what
    /// stops an assertion from surviving its window or naming another request:
    /// change any of them and the authenticator's signature covers a challenge
    /// nobody will recompute.
    pub fn challenge(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(EXPIRED_RECOVERY_APPROVAL_DOMAIN);
        bytes
            .fingerprint(&self.request_fingerprint)
            .raw(&self.astra_challenge)
            .u64(self.expires_at);
        Fingerprint::of(&bytes.finish())
    }

    /// Identifies the exact document, assertion included.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }
}

/// A recovery approval and everything needed to check it (spec §7.5).
///
/// The registry travels for the same reason it does with a campaign: the
/// credential's public key comes from a row `CA-PQ` signed, and no consumer of
/// a recovery holds Astra's document. The origin travels for the same reason
/// too, and is admissible only as an HTTPS origin of the **pinned** relying
/// party — a supplied origin must never be a supplied answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryApprovalEvidence {
    pub approval: ExpiredRecoveryApproval,
    pub credential_registry: CredentialRegistry,
    pub webauthn_origin: String,
}

impl ExpiredRecoveryApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint`.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.approval.fingerprint()
    }

    /// Re-derives every claim against material the consumer already holds.
    ///
    /// The request fingerprint and the nonce come from the caller, never from
    /// the document: an approval that named the request it answers would be an
    /// approval of whatever it chose.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        expected_request_fingerprint: &Fingerprint,
        expected_challenge: &[u8; 32],
        webauthn_rp_id: &str,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if !self
            .approval
            .request_fingerprint
            .matches(expected_request_fingerprint)
        {
            return Err(CertificateError::ApprovalMismatch(
                "recovery request fingerprint",
            ));
        }
        if self.approval.astra_challenge != *expected_challenge
            || self.approval.astra_challenge.iter().all(|byte| *byte == 0)
        {
            return Err(CertificateError::InvalidChallenge);
        }
        if self.approval.expires_at <= self.approval.approved_at
            || self.approval.expires_at - self.approval.approved_at > MAX_APPROVAL_LIFETIME_SECS
            || now_unix >= self.approval.expires_at
        {
            return Err(CertificateError::InvalidLease);
        }
        self.credential_registry.verify(
            ca_pq,
            trust_domain_id,
            gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        validate_https_origin(&self.webauthn_origin, webauthn_rp_id)?;

        // `approvable` and not `binding`: §7.5 requires an **active** operator
        // credential. A lost or revoked one that still resolves would let a
        // withdrawn key revive an expired identity, which is the one operation
        // that reaches past a validity period.
        let binding = self
            .credential_registry
            .approvable()
            .into_iter()
            .find(|binding| binding.credential_id == self.approval.credential_id)
            .ok_or(CertificateError::UnknownCredential)?;
        if !binding
            .fingerprint()
            .matches(&self.approval.credential_fingerprint)
        {
            return Err(CertificateError::InvalidCredentialBinding(
                "credential fingerprint",
            ));
        }
        if !self
            .approval
            .webauthn_assertion
            .fingerprint()
            .matches(&self.approval.assertion_fingerprint)
        {
            return Err(CertificateError::InvalidAssertion("assertion fingerprint"));
        }
        let challenge = self.approval.challenge();
        verify_assertion(
            &self.approval.webauthn_assertion,
            &binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: webauthn_rp_id,
                origin: &self.webauthn_origin,
                challenge: &challenge,
            },
        )
    }
}

/// knows which one it holds.
///
/// The two other reasons an issuer may not sign for at all are refused by
/// [`super::authority::RotationReason::is_delegable`], which this never
/// widens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedApproval {
    /// A due ordinary renewal authorized by the pinned delegated-issuer
    /// policy. The request fingerprint is carried so the stage and grant bind
    /// the automatic decision to the exact continuity and possession proofs
    /// the client submitted.
    Automatic(Fingerprint),
    /// One request, approved once, by one credential. Kept for decoding an
    /// operation opened by an older Astra; current scheduled renewals never
    /// create this variant.
    Renewal(Box<AstraRenewalApprovalEvidence>),
    /// One campaign, approved once, covering this target among others (§7.6).
    Campaign(Box<AstraCampaignApprovalEvidence>),
}

impl DelegatedApproval {
    /// The rotation reason this family — and only this family — authorizes.
    pub const fn reason(&self) -> super::authority::RotationReason {
        match self {
            Self::Automatic(_) => super::authority::RotationReason::Scheduled,
            Self::Renewal(_) => super::authority::RotationReason::Scheduled,
            Self::Campaign(_) => super::authority::RotationReason::ManualGlobal,
        }
    }

    /// The value carried as `renewal_authorization_fingerprint`.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        match self {
            Self::Automatic(request_fingerprint) => Ok(*request_fingerprint),
            Self::Renewal(evidence) => Ok(evidence.fingerprint()),
            Self::Campaign(evidence) => evidence.fingerprint(),
        }
    }
}

/// Signing side of the approval objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl AstraCredentialBinding {
        /// Signed by `CA-PQ`, in the same companion operation that changed the
        /// vault's key-slots (spec §2.4).
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl AstraCredentialApprovalRequest {
        pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl AstraRenewalApproval {
        pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;
    use crate::certificates::encoding::generate_ml_dsa_87_keypair;
    use crate::certificates::webauthn::test_credentials::Credential;
    use aws_lc_rs::digest;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use zeroize::Zeroizing;

    const RELYING_PARTY: &str = "astra.example";
    const ORIGIN: &str = "https://astra.example";

    struct Key {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn key() -> Key {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Key { private, public }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([9; 16]).expect("domain")
    }

    fn gateway() -> WireGuardKey {
        WireGuardKey::from_bytes([2; 32])
    }

    fn client() -> WireGuardKey {
        WireGuardKey::from_bytes([3; 32])
    }

    fn policy() -> AstraIssuancePolicy {
        AstraIssuancePolicy {
            format_version: ISSUANCE_POLICY_FORMAT_VERSION,
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway(),
            server_name: "gateway.example".into(),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 90 * 86_400,
            maximum_stage_lease_secs: 3_600,
            maximum_overlap_secs: 7 * 86_400,
            renewal_start_percent: POLICY_RENEWAL_START_PERCENT,
            scheduled_renewal_credentials: AUTOMATIC_RENEWAL_CREDENTIALS,
            expired_recovery_credentials: 2,
            authority_mutation_credentials: AUTHORITY_MUTATION_CREDENTIALS,
        }
    }

    fn binding(
        ca: &Key,
        credential: &Credential,
        state: CredentialState,
    ) -> AstraCredentialBinding {
        AstraCredentialBinding {
            format_version: CERTIFICATE_FORMAT_VERSION,
            credential_id: b"credential-one".to_vec(),
            credential_public_key: credential.cose_public_key(),
            aaguid: [0; 16],
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway(),
            state,
            credential_epoch: 1,
            credential_registry_epoch: 4,
            ca_epoch: 1,
            created_at: 1_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca.private)
        .expect("sign")
    }

    fn request(service: &Key) -> AstraCredentialApprovalRequest {
        AstraCredentialApprovalRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: Id16::new([5; 16]).expect("operation"),
            request_fingerprint: Fingerprint::of(b"rotation request"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway(),
            client_wg_public_key: client(),
            active_generation: 4,
            requested_generation: 5,
            credential_registry_epoch: 4,
            webauthn_rp_id: RELYING_PARTY.into(),
            webauthn_origin: ORIGIN.into(),
            allowed_credential_ids: vec![b"credential-one".to_vec()],
            required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
            created_at: 1_000,
            expires_at: 1_240,
            astra_service_key_epoch: 7,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&service.private)
        .expect("sign")
    }

    fn assertion(credential: &Credential, challenge: &Fingerprint) -> WebAuthnAssertion {
        let mut authenticator_data = Fingerprint::of(RELYING_PARTY.as_bytes())
            .as_bytes()
            .to_vec();
        // User presence and user verification.
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&11u32.to_be_bytes());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
            URL_SAFE_NO_PAD.encode(challenge.as_bytes())
        )
        .into_bytes();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
        WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: credential.sign(&message),
        }
    }

    /// The §7.5 family: what an operator's touch authorizes when an identity
    /// has already expired.
    mod expired_recovery {
        use super::*;

        fn evidence(
            ca: &Key,
            credential: &Credential,
            state: CredentialState,
            request_fingerprint: Fingerprint,
            challenge_bytes: [u8; 32],
        ) -> ExpiredRecoveryApprovalEvidence {
            let row = binding(ca, credential, state);
            let mut approval = ExpiredRecoveryApproval {
                request_fingerprint,
                astra_challenge: challenge_bytes,
                approved_at: 1_000,
                expires_at: 1_200,
                credential_id: row.credential_id.clone(),
                credential_fingerprint: row.fingerprint(),
                assertion_fingerprint: Fingerprint::from_bytes([0; 32]),
                webauthn_assertion: WebAuthnAssertion {
                    authenticator_data: Vec::new(),
                    client_data_json: Vec::new(),
                    signature: Vec::new(),
                },
            };
            let signed = assertion(credential, &approval.challenge());
            approval.assertion_fingerprint = signed.fingerprint();
            approval.webauthn_assertion = signed;
            ExpiredRecoveryApprovalEvidence {
                approval,
                credential_registry: CredentialRegistry {
                    trust_domain_id: domain(),
                    gateway_wg_public_key: gateway(),
                    ca_epoch: 1,
                    credential_registry_epoch: 4,
                    bindings: vec![row],
                },
                webauthn_origin: ORIGIN.into(),
            }
        }

        /// The happy path, and the shape of every refusal below: the caller
        /// supplies the request and the nonce, the document supplies neither.
        #[test]
        fn a_touch_authorizes_the_request_and_the_nonce_it_answered() {
            let ca = key();
            let credential = Credential::generate();
            let request = Fingerprint::of(b"recovery request");
            let challenge = [7u8; 32];
            let evidence = evidence(
                &ca,
                &credential,
                CredentialState::Active,
                request,
                challenge,
            );
            assert!(evidence
                .verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &request,
                    &challenge,
                    RELYING_PARTY,
                    1,
                    4,
                    1_100,
                )
                .is_ok());

            // Another request, same touch: the challenge no longer recomputes.
            assert!(matches!(
                evidence.verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &Fingerprint::of(b"another request"),
                    &challenge,
                    RELYING_PARTY,
                    1,
                    4,
                    1_100,
                ),
                Err(CertificateError::ApprovalMismatch(_))
            ));

            // Another nonce: same refusal, on the axis that stops a replay
            // against a challenge the authority has already consumed.
            assert!(matches!(
                evidence.verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &request,
                    &[8u8; 32],
                    RELYING_PARTY,
                    1,
                    4,
                    1_100,
                ),
                Err(CertificateError::InvalidChallenge)
            ));
        }

        /// A recovery is the one operation that reaches past a validity
        /// period. A withdrawn credential must not be the thing that reaches.
        #[test]
        fn only_an_active_credential_revives_an_expired_identity() {
            let ca = key();
            let credential = Credential::generate();
            let request = Fingerprint::of(b"recovery request");
            let challenge = [7u8; 32];
            for state in [CredentialState::Lost, CredentialState::Revoked] {
                let evidence = evidence(&ca, &credential, state, request, challenge);
                assert!(matches!(
                    evidence.verify(
                        &ca.public,
                        &domain(),
                        &gateway(),
                        &request,
                        &challenge,
                        RELYING_PARTY,
                        1,
                        4,
                        1_100,
                    ),
                    Err(CertificateError::UnknownCredential)
                ));
            }
        }

        /// The assertion answers a challenge derived here, so an approval that
        /// outlived its own window answers a challenge nobody recomputes.
        #[test]
        fn an_approval_past_its_window_is_refused() {
            let ca = key();
            let credential = Credential::generate();
            let request = Fingerprint::of(b"recovery request");
            let challenge = [7u8; 32];
            let evidence = evidence(
                &ca,
                &credential,
                CredentialState::Active,
                request,
                challenge,
            );
            assert!(matches!(
                evidence.verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &request,
                    &challenge,
                    RELYING_PARTY,
                    1,
                    4,
                    1_200,
                ),
                Err(CertificateError::InvalidLease)
            ));
        }

        /// The origin travels with the evidence, so it must be admissible for
        /// the relying party the consumer already pins — never a supplied
        /// answer to a question the consumer asked.
        #[test]
        fn an_origin_outside_the_pinned_relying_party_is_refused() {
            let ca = key();
            let credential = Credential::generate();
            let request = Fingerprint::of(b"recovery request");
            let challenge = [7u8; 32];
            let mut evidence = evidence(
                &ca,
                &credential,
                CredentialState::Active,
                request,
                challenge,
            );
            evidence.webauthn_origin = "https://astra.example.evil".into();
            assert!(evidence
                .verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &request,
                    &challenge,
                    RELYING_PARTY,
                    1,
                    4,
                    1_100,
                )
                .is_err());
        }

        /// Two of the three inputs to the challenge, moved one at a time. A
        /// derivation that dropped any of them would let one touch answer for
        /// a different request, a different nonce or a longer window.
        #[test]
        fn the_challenge_binds_the_request_the_nonce_and_the_deadline() {
            let base = ExpiredRecoveryApproval {
                request_fingerprint: Fingerprint::of(b"request"),
                astra_challenge: [1; 32],
                approved_at: 1_000,
                expires_at: 1_200,
                credential_id: b"credential-one".to_vec(),
                credential_fingerprint: Fingerprint::of(b"row"),
                assertion_fingerprint: Fingerprint::of(b"assertion"),
                webauthn_assertion: WebAuthnAssertion {
                    authenticator_data: Vec::new(),
                    client_data_json: Vec::new(),
                    signature: Vec::new(),
                },
            };
            let reference = base.challenge();

            let mut moved = base.clone();
            moved.request_fingerprint = Fingerprint::of(b"other request");
            assert!(!moved.challenge().matches(&reference));

            let mut moved = base.clone();
            moved.astra_challenge = [2; 32];
            assert!(!moved.challenge().matches(&reference));

            let mut moved = base;
            moved.expires_at = 1_500;
            assert!(!moved.challenge().matches(&reference));
        }
    }

    fn approval(
        service: &Key,
        binding: &AstraCredentialBinding,
        request: &AstraCredentialApprovalRequest,
        assertion: WebAuthnAssertion,
    ) -> AstraRenewalApproval {
        AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: request.operation_id,
            request_fingerprint: request.request_fingerprint,
            approval_request_fingerprint: request.fingerprint(),
            credential_binding: binding.clone(),
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: assertion.fingerprint(),
            webauthn_assertion: assertion,
            approved_at: 1_050,
            expires_at: 1_240,
            astra_service_key_epoch: 7,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&service.private)
        .expect("sign")
    }

    struct Fixture {
        ca: Key,
        service: Key,
        binding: AstraCredentialBinding,
        request: AstraCredentialApprovalRequest,
        approval: AstraRenewalApproval,
    }

    fn fixture() -> Fixture {
        let ca = key();
        let service = key();
        let credential = Credential::generate();
        let binding = binding(&ca, &credential, CredentialState::Active);
        let request = request(&service);
        let assertion = assertion(&credential, &request.challenge());
        let approval = approval(&service, &binding, &request, assertion);
        Fixture {
            ca,
            service,
            binding,
            request,
            approval,
        }
    }

    fn verify(fixture: &Fixture, approval: &AstraRenewalApproval) -> Result<(), CertificateError> {
        approval.verify(
            &fixture.request,
            &fixture.ca.public,
            &fixture.service.public,
            7,
            &domain(),
            1,
            4,
            1_100,
        )
    }

    #[test]
    fn an_approval_bound_to_its_request_verifies_under_the_anchor_and_the_credential() {
        let fixture = fixture();
        fixture
            .request
            .verify(
                &fixture.service.public,
                7,
                &domain(),
                &gateway(),
                &client(),
                RELYING_PARTY,
                4,
                1_100,
            )
            .expect("request");
        verify(&fixture, &fixture.approval).expect("approval");
    }

    #[test]
    fn astra_verifies_the_companion_evidence_before_adding_its_signature() {
        let fixture = fixture();
        let mut companion = fixture.approval.clone();
        companion.astra_signature = MlDsa87Signature::placeholder();

        companion
            .verify_operator_evidence(
                &fixture.request,
                &fixture.ca.public,
                7,
                &domain(),
                1,
                4,
                1_100,
            )
            .expect("the independent evidence is complete");
        assert!(matches!(
            verify(&fixture, &companion),
            Err(CertificateError::InvalidSignature)
        ));
        let countersigned = companion
            .sign(&fixture.service.private)
            .expect("countersign");
        verify(&fixture, &countersigned).expect("the completed approval verifies");
    }

    /// The refusal the amendment of 15 August 2026 exists for.
    #[test]
    fn an_approval_bound_to_another_request_hash_is_refused() {
        let fixture = fixture();
        let mut moved = fixture.approval.clone();
        moved.request_fingerprint = Fingerprint::of(b"another request");
        let moved = moved.sign(&fixture.service.private).expect("sign");
        assert!(matches!(
            verify(&fixture, &moved),
            Err(CertificateError::ApprovalMismatch("request fingerprint"))
        ));
    }

    /// A byte moved anywhere in the request moves the challenge, so the
    /// assertion no longer answers it — even though Astra re-signed both.
    #[test]
    fn a_mutated_request_breaks_the_chain_that_the_assertion_answers() {
        let fixture = fixture();
        let mut altered = fixture.request.clone();
        altered.requested_generation = 6;
        let altered = altered.sign(&fixture.service.private).expect("sign");
        let mut approval = fixture.approval.clone();
        approval.request_fingerprint = altered.request_fingerprint;
        approval.approval_request_fingerprint = altered.fingerprint();
        let approval = approval.sign(&fixture.service.private).expect("sign");
        assert!(matches!(
            approval.verify(
                &altered,
                &fixture.ca.public,
                &fixture.service.public,
                7,
                &domain(),
                1,
                4,
                1_100
            ),
            Err(CertificateError::InvalidAssertion("challenge binding"))
        ));
    }

    #[test]
    fn an_approval_by_a_credential_the_request_did_not_list_is_refused() {
        let fixture = fixture();
        let mut narrowed = fixture.request.clone();
        narrowed.allowed_credential_ids = vec![b"credential-two".to_vec()];
        let narrowed = narrowed.sign(&fixture.service.private).expect("sign");
        let mut approval = fixture.approval.clone();
        approval.request_fingerprint = narrowed.request_fingerprint;
        approval.approval_request_fingerprint = narrowed.fingerprint();
        let approval = approval.sign(&fixture.service.private).expect("sign");
        assert!(matches!(
            approval.verify(
                &narrowed,
                &fixture.ca.public,
                &fixture.service.public,
                7,
                &domain(),
                1,
                4,
                1_100
            ),
            Err(CertificateError::UnknownCredential)
        ));
    }

    /// Astra's own signature is not allowed to stand in for the anchor's.
    #[test]
    fn a_credential_binding_not_signed_by_ca_pq_is_refused() {
        let fixture = fixture();
        let impostor = key();
        let forged = fixture
            .binding
            .clone()
            .sign(&impostor.private)
            .expect("sign");
        let mut approval = fixture.approval.clone();
        approval.credential_fingerprint = forged.fingerprint();
        approval.credential_binding = forged;
        let approval = approval.sign(&fixture.service.private).expect("sign");
        assert!(matches!(
            verify(&fixture, &approval),
            Err(CertificateError::InvalidSignature)
        ));
    }

    #[test]
    fn a_lost_or_revoked_credential_cannot_approve_a_renewal() {
        for (state, expected) in [
            (CredentialState::Lost, "lost"),
            (CredentialState::Revoked, "revoked"),
        ] {
            let ca = key();
            let service = key();
            let credential = Credential::generate();
            let binding = binding(&ca, &credential, state);
            let request = request(&service);
            let assertion = assertion(&credential, &request.challenge());
            let approval = approval(&service, &binding, &request, assertion);
            let outcome = approval.verify(
                &request,
                &ca.public,
                &service.public,
                7,
                &domain(),
                1,
                4,
                1_100,
            );
            match (state, outcome) {
                (
                    CredentialState::Lost,
                    Err(CertificateError::InvalidCredentialBinding("lost")),
                ) => {}
                (CredentialState::Revoked, Err(CertificateError::Revoked)) => {}
                (_, other) => panic!("{expected} credential accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn a_credential_binding_at_a_rolled_back_registry_epoch_is_refused() {
        let fixture = fixture();
        assert!(matches!(
            fixture.binding.verify(
                &fixture.ca.public,
                &domain(),
                &gateway(),
                1,
                5, // the consumer has already seen epoch 5
            ),
            Err(CertificateError::GenerationRollback { .. })
        ));
    }

    /// `revoked` is terminal: a restored backup at a higher epoch does not
    /// bring a token back.
    #[test]
    fn a_revocation_dominates_a_later_active_decision() {
        let ca = key();
        let credential = Credential::generate();
        let revoked = binding(&ca, &credential, CredentialState::Revoked);
        let mut restored = binding(&ca, &credential, CredentialState::Active);
        restored.credential_registry_epoch = 9;
        let restored = restored.sign(&ca.private).expect("sign");
        assert!(matches!(
            restored.supersedes(Some(&revoked)),
            Err(CertificateError::Revoked)
        ));
    }

    #[test]
    fn a_registry_cannot_claim_an_epoch_its_signed_rows_do_not_carry() {
        let fixture = fixture();
        let mut registry = CredentialRegistry {
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway(),
            ca_epoch: 1,
            credential_registry_epoch: fixture.binding.credential_registry_epoch,
            bindings: vec![fixture.binding.clone()],
        };
        registry
            .verify(&fixture.ca.public, &domain(), &gateway(), 1, 4)
            .expect("one coherent snapshot");

        registry.credential_registry_epoch += 1;
        assert!(matches!(
            registry.verify(&fixture.ca.public, &domain(), &gateway(), 1, 4),
            Err(CertificateError::InvalidCredentialBinding(
                "mixed registry epochs"
            ))
        ));
    }

    #[test]
    fn a_credential_counter_moves_exactly_with_its_decision_and_never_its_key() {
        let fixture = fixture();

        let mut changed_state = fixture.binding.clone();
        changed_state.state = CredentialState::Lost;
        changed_state.credential_registry_epoch += 1;
        let changed_state = changed_state.sign(&fixture.ca.private).expect("sign");
        assert!(matches!(
            changed_state.supersedes(Some(&fixture.binding)),
            Err(CertificateError::GenerationConflict { .. })
        ));

        let other_credential = Credential::generate();
        let mut changed_key = fixture.binding.clone();
        changed_key.credential_public_key = other_credential.cose_public_key();
        changed_key.credential_registry_epoch += 1;
        let changed_key = changed_key.sign(&fixture.ca.private).expect("sign");
        assert!(matches!(
            changed_key.supersedes(Some(&fixture.binding)),
            Err(CertificateError::InvalidCredentialBinding(
                "credential identity changed"
            ))
        ));
    }

    #[test]
    fn an_approval_request_older_than_five_minutes_is_refused() {
        let service = key();
        let mut stretched = request(&service);
        stretched.expires_at = stretched.created_at + MAX_APPROVAL_LIFETIME_SECS + 1;
        let stretched = stretched.sign(&service.private).expect("sign");
        assert!(matches!(
            stretched.verify(
                &service.public,
                7,
                &domain(),
                &gateway(),
                &client(),
                RELYING_PARTY,
                4,
                1_100
            ),
            Err(CertificateError::InvalidLease)
        ));

        let expired = request(&service);
        assert!(matches!(
            expired.verify(
                &service.public,
                7,
                &domain(),
                &gateway(),
                &client(),
                RELYING_PARTY,
                4,
                1_240
            ),
            Err(CertificateError::StageExpired)
        ));
    }

    #[test]
    fn an_approval_request_for_another_peer_relying_party_or_generation_is_refused() {
        let service = key();
        let request = request(&service);
        let checks: [(&str, Result<(), CertificateError>); 4] = [
            (
                "gateway",
                request.verify(
                    &service.public,
                    7,
                    &domain(),
                    &WireGuardKey::from_bytes([8; 32]),
                    &client(),
                    RELYING_PARTY,
                    4,
                    1_100,
                ),
            ),
            (
                "client",
                request.verify(
                    &service.public,
                    7,
                    &domain(),
                    &gateway(),
                    &WireGuardKey::from_bytes([8; 32]),
                    RELYING_PARTY,
                    4,
                    1_100,
                ),
            ),
            (
                "relying party",
                request.verify(
                    &service.public,
                    7,
                    &domain(),
                    &gateway(),
                    &client(),
                    "other.example",
                    4,
                    1_100,
                ),
            ),
            (
                "generation",
                request.verify(
                    &service.public,
                    7,
                    &domain(),
                    &gateway(),
                    &client(),
                    RELYING_PARTY,
                    5,
                    1_100,
                ),
            ),
        ];
        for (name, outcome) in checks {
            assert!(outcome.is_err(), "{name} mismatch accepted");
        }
    }

    #[test]
    fn an_approval_outliving_its_request_is_refused() {
        let fixture = fixture();
        let mut stretched = fixture.approval.clone();
        stretched.expires_at = fixture.request.expires_at + 1;
        let stretched = stretched.sign(&fixture.service.private).expect("sign");
        assert!(matches!(
            verify(&fixture, &stretched),
            Err(CertificateError::InvalidLease)
        ));
    }

    #[test]
    fn a_policy_fingerprint_is_zero_free_and_covers_every_ceiling() {
        let pin = policy().pin().expect("pin");
        for mutate in [
            (|policy: &mut AstraIssuancePolicy| policy.maximum_leaf_lifetime_secs += 1)
                as fn(&mut AstraIssuancePolicy),
            |policy| policy.maximum_stage_lease_secs += 1,
            |policy| policy.maximum_overlap_secs += 1,
            |policy| policy.expired_recovery_credentials = 1,
            |policy| policy.server_name = "other.example".into(),
            |policy| policy.gateway_wg_public_key = WireGuardKey::from_bytes([4; 32]),
        ] {
            let mut altered = policy();
            mutate(&mut altered);
            assert!(
                pin.assert_matches(&altered.fingerprint().expect("fingerprint"))
                    .is_err(),
                "a changed ceiling produced the same pin"
            );
        }
        assert!(matches!(
            AstraPolicyPin::new(Fingerprint::from_bytes([0; 32])),
            Err(CertificateError::PolicyNotPinned)
        ));
    }

    #[test]
    fn a_policy_outside_the_bounds_of_the_specification_has_no_fingerprint() {
        for mutate in [
            (|policy: &mut AstraIssuancePolicy| policy.maximum_stage_lease_secs = 86_401)
                as fn(&mut AstraIssuancePolicy),
            |policy| policy.maximum_overlap_secs = MAX_OVERLAP_SECS + 1,
            |policy| policy.expired_recovery_credentials = 3,
            |policy| policy.renewal_start_percent = 50,
            |policy| policy.scheduled_renewal_credentials = 1,
            |policy| policy.authority_mutation_credentials = 1,
            |policy| policy.maximum_leaf_lifetime_secs = 0,
        ] {
            let mut altered = policy();
            mutate(&mut altered);
            assert!(
                altered.fingerprint().is_err(),
                "out-of-bounds policy hashed"
            );
        }
    }

    /// §14.1: "délégation refusée quand `policy_fingerprint` diffère du pin
    /// hors bande du profil, même sous une signature `CA-PQ` valide".
    #[test]
    fn a_delegation_carrying_another_policy_is_refused_under_a_valid_ca_pq_signature() {
        use crate::certificates::authority::AstraIssuerAuthorization;

        let ca = key();
        let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut widened = policy();
        widened.maximum_leaf_lifetime_secs = 10 * 365 * 86_400;
        let delegation = AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway(),
            server_name: "gateway.example".into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer,
            tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
                "astra-issuer",
            ),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: widened.maximum_leaf_lifetime_secs,
            policy_fingerprint: widened.fingerprint().expect("fingerprint"),
            not_before: 1_000,
            not_after: 100_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca.private)
        .expect("sign");

        // `CA-PQ` really did sign it.
        delegation
            .verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway(),
                "gateway.example",
                2_000,
            )
            .expect("delegation");
        // And the pin still refuses it.
        let pin = policy().pin().expect("pin");
        assert!(matches!(
            pin.assert_authorizes(&delegation),
            Err(CertificateError::FingerprintMismatch(
                "Astra issuance policy"
            ))
        ));
    }
}
