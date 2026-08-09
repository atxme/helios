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
//! The operator credential layer of ADR-008 §4 — FIDO2 `hmac-secret` key
//! slots, the `astra-signer` companion and the two-credential approval policy
//! — is not exercised by this crate: it needs a physical authenticator, which
//! no WSL2 build can provide. The objects here carry the campaign fingerprint
//! that a credential approves ([`status::AstraRotationCampaign`]), and refuse
//! an operation whose campaign does not match, but the assertion itself is
//! verified by the Astra coordinator. See
//! [`docs/testing/TESTING.md`](../../../../docs/testing/TESTING.md).

pub mod authority;
pub mod client;
pub mod encoding;
pub mod gateway;
pub mod revocation;
pub mod state;
pub mod status;
pub mod transport;
pub mod window;

pub use encoding::{
    verify_ml_dsa_87, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId, WireGuardKey,
};
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
    #[error("DER certificate is empty or larger than the bound")]
    InvalidDerCertificate,
    #[error("server name is not in the canonical DNS form of the v5 negotiation")]
    InvalidServerName,
    #[error("signing operation failed")]
    Signing,

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
