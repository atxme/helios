//! Certificate lifecycle of the v5 negotiation PKI — ADR-008 and the
//! [rotation specification](../../../../docs/specification/ROTATION-CERTIFICATS.md).
//!
//! [`crate::key_negotiation`] holds the identities a tunnel is established
//! with. This module holds everything that makes those identities *change*
//! without cutting the fleet: authority transitions, bounded active/next
//! states, the staged issuance of a client generation, revocation, and the
//! signed objects that carry all of it between Astra, Helios and Orion.
//!
//! # What this module is, and is not
//!
//! It is **pure**: types, canonical encodings, signature verification and
//! state machines. It reads no clock of its own, opens no socket and writes no
//! file. The clock is an argument, so a test can place a client three weeks
//! into an overlap without waiting for one.
//!
//! It is not the authority. No path here holds `CA-PQ`: signing lives in the
//! operator companion, behind the `key-negotiation-signing` feature and behind
//! a hardware credential (ADR-008 §4). The gateway verifies, the client
//! verifies, and neither can mint what it verifies.
//!
//! # The three properties everything else rests on
//!
//! - **An anchor is never carried by the object it authorizes.** A transition
//!   is valid only under a CA the verifier already trusts. `CaTransition` is
//!   the single exception, and it costs two signatures: the trusted anchor
//!   authorizes its successor, and the successor proves its own key.
//! - **Two slots, never a list.** Gateway identity, client generation and CA
//!   each hold an active and at most one next. An open-ended set of acceptable
//!   fingerprints is an open-ended set of things that can be made acceptable.
//! - **A counter, not a clock, decides what is current.** Generations are
//!   persisted before an identity is served, so a clock moved backwards
//!   re-activates nothing.
//!
//! # Limite connue
//!
//! The operator credential layer of ADR-008 §4 is only half exercisable here.
//! The **verifying** half is real code with real arithmetic:
//! [`approval::AstraCredentialBinding`] is checked under `CA-PQ` and
//! [`webauthn::verify_assertion`] checks an assertion under the credential's
//! own public key, both on synthetic material. The **producing** half — a
//! FIDO2 `hmac-secret` key slot, a physical touch, the `astra-signer`
//! companion — needs an authenticator no WSL2 build can provide.
//!
//! It is worth being exact about what that layer does, because the obvious
//! guess is wrong. The authenticator **never signs anything verified here**,
//! and it could not: a YubiKey holds RSA, P-256/P-384 and Ed25519, and every
//! signature field in this module is an `MlDsa87Signature`. What presence and
//! user verification release is either an authorization — the assertion of
//! [`approval::AstraRenewalApproval`], which opens no key-slot — or a
//! `hmac-secret` output, which unwraps a key-slot of the authority vault so
//! that the anchors inside it can sign. The objects here also carry the
//! campaign fingerprint the companion **displays**
//! ([`status::AstraRotationCampaign`]) and refuse an operation whose campaign
//! does not match. See
//! [`docs/testing/TESTING.md`](../../../../docs/testing/TESTING.md).

pub mod approval;
pub mod authority;
pub mod capability;
pub mod client;
pub mod encoding;
pub mod gateway;
pub mod revocation;
pub mod state;
pub mod status;
pub mod transport;
pub mod webauthn;
pub mod window;
pub mod x509;

/// Real X.509 material, for the tests of every crate that verifies a chain.
///
/// The verifiers parse what they are handed, so a placeholder byte string is
/// refused — which is the point. Building genuine certificates here keeps every
/// test honest about what it exercises, and keeps four crates from each
/// growing their own slightly different fixture.
///
/// Behind the signing feature: a gateway that only verifies does not link an
/// issuance library.
#[cfg(feature = "key-negotiation-signing")]
pub mod test_x509 {
    use super::encoding::DerCertificate;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    /// A client TLS anchor, the leaf it issued and the CSR that leaf answers.
    pub struct TlsMaterial {
        pub authority: DerCertificate,
        pub leaf: DerCertificate,
        pub csr: DerCertificate,
    }

    /// A complete, genuine client TLS chain.
    pub fn client_material(common_name: &str) -> TlsMaterial {
        use rcgen::ExtendedKeyUsagePurpose;

        let mut authority_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        authority_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut authority_name = DistinguishedName::new();
        authority_name.push(DnType::CommonName, "CA-TLS");
        authority_params.distinguished_name = authority_name;
        // Every link of a chain is checked against the clock, anchors included,
        // so the test anchor has to cover the same synthetic era as its leaf.
        authority_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        authority_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        let authority_key = KeyPair::generate().expect("key");
        let authority = authority_params
            .self_signed(&authority_key)
            .expect("authority");

        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, common_name);
        leaf_params.distinguished_name = leaf_name;
        // The tests drive synthetic clocks starting near the Unix epoch, so
        // the leaf has to be valid there. Real material never looks like this.
        leaf_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        let leaf_key = KeyPair::generate().expect("key");
        let csr = leaf_params.serialize_request(&leaf_key).expect("csr");
        let leaf = leaf_params
            .signed_by(&leaf_key, &authority, &authority_key)
            .expect("leaf");

        TlsMaterial {
            authority: DerCertificate::new(authority.der().to_vec()).expect("der"),
            leaf: DerCertificate::new(leaf.der().to_vec()).expect("der"),
            csr: DerCertificate::new(csr.der().to_vec()).expect("der"),
        }
    }

    /// A certification authority able to sign certificates.
    pub fn certificate_authority(common_name: &str) -> DerCertificate {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        let key = KeyPair::generate().expect("key");
        let certificate = params.self_signed(&key).expect("authority");
        DerCertificate::new(certificate.der().to_vec()).expect("der")
    }
}

pub use approval::{
    AstraCredentialApprovalRequest, AstraCredentialBinding, AstraIssuancePolicy, AstraPolicyPin,
    AstraRenewalApproval, CredentialState,
};
pub use capability::{CapabilityGrant, CapabilityRequirement, CapabilityScope, CapabilityTokens};
pub use encoding::{
    verify_ml_dsa_87, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId, WireGuardKey,
};
pub use webauthn::WebAuthnAssertion;
pub use window::{
    classify_generation, GenerationStep, TransitionWindow, ValidityPeriod, WindowPhase,
};

/// Format version of every object defined in this module.
///
/// Distinct from the negotiation's `protocol_version`: the wire protocol and
/// the lifecycle documents evolve on their own schedules, and an object that
/// carried only one of the two would eventually be read under the wrong rules.
pub const CERTIFICATE_FORMAT_VERSION: u16 = 1;

/// Negotiation protocol these documents belong to.
pub const CERTIFICATE_PROTOCOL_VERSION: u16 = crate::key_negotiation::KEY_NEGOTIATION_VERSION;

/// Refusal of a lifecycle object.
///
/// Each variant names a rule of the specification. The distinction matters on
/// the **private** side — an operator has to know whether a transition was
/// refused for its window or for its signature. What crosses a public
/// boundary is collapsed to a bounded status by the transport layer, exactly
/// as the negotiation port collapses its own refusals to three codes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificateError {
    #[error("fingerprint must be 64 lowercase SHA-256 hexadecimal characters")]
    InvalidFingerprint,
    #[error("identifier must be 32 lowercase hexadecimal characters")]
    InvalidIdentifier,
    #[error("identifier must not be all zeroes")]
    ZeroIdentifier,
    #[error("WireGuard public key is invalid")]
    InvalidWireGuardKey,
    #[error("ML-DSA-87 public key is malformed")]
    InvalidPublicKey,
    #[error("ML-DSA-87 private key is malformed")]
    InvalidPrivateKey,
    #[error("ML-DSA-87 signature is not the expected length")]
    InvalidSignatureEncoding,
    #[error("ML-DSA-87 signature does not verify over the canonical transcript")]
    InvalidSignature,
    #[error("the ML-DSA-87 context is not the domain opening the transcript")]
    InvalidSigningContext,
    #[error("DER certificate is empty or larger than the bound")]
    InvalidDerCertificate,
    #[error("X.509 certificate refused: {0}")]
    InvalidX509(&'static str),
    #[error("server name is not in the canonical DNS form of the v5 negotiation")]
    InvalidServerName,
    #[error("signing operation failed")]
    Signing,
    #[error("the approved randomness provider produced no bytes")]
    RandomnessUnavailable,

    #[error("transition window must satisfy not_before < activation_at < not_after")]
    InvalidWindow,
    #[error("overlap of {overlap_secs}s exceeds the {maximum_secs}s ceiling")]
    OverlapTooLong {
        overlap_secs: u64,
        maximum_secs: u64,
    },
    #[error("validity period must satisfy not_before < not_after")]
    InvalidValidityPeriod,
    #[error("certificate is outside its validity period")]
    OutsideValidityPeriod,
    #[error("checked arithmetic on a time or generation value overflowed")]
    ArithmeticOverflow,

    #[error("generation {proposed} is behind the persisted {current}: this is a rollback")]
    GenerationRollback { current: u64, proposed: u64 },
    #[error(
        "generation {proposed} skips {expected}; intermediate decisions must be applied first"
    )]
    GenerationSkipped {
        current: u64,
        proposed: u64,
        expected: u64,
    },
    #[error("generation {generation} already carries different signed bytes")]
    GenerationConflict { generation: u64 },

    #[error("lease is empty, or outlives a deadline it depends on")]
    InvalidLease,
    #[error("lease of {duration_secs}s exceeds the {maximum_secs}s ceiling")]
    LeaseTooLong {
        duration_secs: u64,
        maximum_secs: u64,
    },
    #[error("staging lease has expired")]
    StageExpired,
    #[error("no staged candidate matches this identifier")]
    UnknownStage,
    #[error("a candidate is already staged for this identity")]
    StageAlreadyPresent,

    #[error("format version {received} is unsupported; expected {supported}")]
    UnsupportedFormatVersion { received: u16, supported: u16 },
    #[error("protocol version {received} is unsupported; expected {supported}")]
    UnsupportedProtocolVersion { received: u16, supported: u16 },
    #[error("object belongs to another trust domain")]
    TrustDomainMismatch,
    #[error("object names another gateway identity")]
    GatewayIdentityMismatch,
    #[error("object names another client identity")]
    ClientIdentityMismatch,
    #[error("object does not match the expected {0} fingerprint")]
    FingerprintMismatch(&'static str),
    #[error("object carries neither a next TLS leaf nor a next PQ leaf")]
    EmptyTransition,
    #[error("TLS and PQ fingerprints belong to different client generations")]
    MixedGeneration,
    #[error("fingerprint is already bound to another admitted identity")]
    DuplicateFingerprint,

    #[error("issuer is not authorized for this operation")]
    UnauthorizedIssuer,
    #[error("delegated issuer authorization does not cover this operation: {0}")]
    IssuerScopeViolation(&'static str),
    #[error("issuer authorization is outside its validity window")]
    IssuerAuthorizationExpired,
    #[error("identity is revoked; no credential can lift that state")]
    Revoked,
    #[error("proof of possession of the {0} key is missing or invalid")]
    MissingProof(&'static str),
    #[error("challenge is unknown, already consumed or expired")]
    InvalidChallenge,
    #[error("operator approval does not cover this campaign")]
    CampaignMismatch,
    #[error("this operation requires {required} operator credentials, {provided} given")]
    InsufficientApprovals { required: u8, provided: u8 },
    #[error("Astra issuance policy is outside the bounds of the specification: {0}")]
    InvalidPolicy(&'static str),
    #[error(
        "the Astra issuance policy fingerprint is unset; it is confirmed out of band, never learned from a signature"
    )]
    PolicyNotPinned,
    #[error("operator credential binding refused: {0}")]
    InvalidCredentialBinding(&'static str),
    #[error("the approving credential is not one this operation admits")]
    UnknownCredential,
    #[error("operator approval does not cover this operation: {0}")]
    ApprovalMismatch(&'static str),
    #[error("WebAuthn assertion refused: {0}")]
    InvalidAssertion(&'static str),
    #[error("the credential's COSE algorithm is not one this build can verify")]
    UnsupportedCredentialAlgorithm,
    #[error("WebAuthn origin is not an HTTPS origin governed by the relying party")]
    InvalidOrigin,

    #[error("capability token is malformed or not authenticated")]
    InvalidCapabilityToken,
    #[error("capability token is outside its window, or outlives its operation")]
    CapabilityTokenExpired,
    #[error("capability token has already been consumed")]
    CapabilityTokenConsumed,
    #[error("capability token confers nothing here: {0}")]
    CapabilityScopeViolation(&'static str),

    #[error("transition is not in a state where this operation is allowed: {0}")]
    IllegalStateTransition(&'static str),
    #[error("transition has been published and can no longer be aborted")]
    AlreadyPublished,
    #[error("rollback is only available during an existing overlap")]
    RollbackUnavailable,

    #[error("trust-update transaction is incomplete or inconsistent: {0}")]
    InvalidTransaction(&'static str),
    #[error("object is larger than the per-object ceiling")]
    ObjectTooLarge,
    #[error("transaction carries more objects than the bound allows")]
    TooManyObjects,
}
