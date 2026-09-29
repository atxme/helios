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

mod campaign;
mod credentials;
mod policy;
mod recovery;
mod renewal;

pub use campaign::AstraCampaignApprovalEvidence;
pub use credentials::{
    AstraCredentialBinding, CredentialRegistry, CredentialState, MAX_CREDENTIAL_BINDINGS,
};
pub use policy::{
    superseded_per_request_policy_fingerprint, AstraIssuancePolicy, AstraPolicyPin, PolicyMigration,
};
pub use recovery::{ExpiredRecoveryApproval, ExpiredRecoveryApprovalEvidence};
pub use renewal::{
    AstraCredentialApprovalRequest, AstraRenewalApproval, AstraRenewalApprovalEvidence,
};

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
mod signing;

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests;
