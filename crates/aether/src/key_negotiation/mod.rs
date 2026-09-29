//! Versioned contract for pre-WireGuard key negotiation — protocol v5.
//!
//! The negotiation runs on a dedicated UDP/QUIC port before the WireGuard
//! handshake. TLS authenticates the transport; this module is the
//! post-quantum boundary. It binds, into one signed transcript and into the
//! derived PSK: a gateway-issued single-use challenge, the transaction, the
//! selected mode, both WireGuard identities and the gateway the client
//! believes it is talking to.
//!
//! Three properties distinguish v5 from v4 and are the reason the wire format
//! is incompatible:
//!
//! - **Replay is impossible, not improbable.** A request carries a
//!   `server_challenge` the gateway issued for that connection and consumes
//!   exactly once. v4 relied on a bounded, volatile cache and a clock window.
//! - **A request names its destination.** `gateway_wg_public_key`,
//!   `server_name` and the pinned certificate fingerprint are signed, so an
//!   authentic request for one gateway cannot be replayed against another
//!   sharing the operator CA.
//! - **Authentication is ML-DSA-87**, category 5, matching ML-KEM-1024
//!   instead of sitting a category below it.
//!
//! See [`NEGOCIATION-DE-CLE-V5.md`](../../../docs/NEGOCIATION-DE-CLE-V5.md)
//! for the normative specification and
//! [`ADR-005`](../../../docs/adr/ADR-005-NEGOCIATION-DE-CLE.md) for the
//! reasoning behind the reversals.
//!
//! # Limite connue
//!
//! The `Classic` mode is still accepted by the types, and removed on
//! **2027-02-01** (spec §19). It leaves the first handshake unprotected
//! against a future quantum adversary; no new admission selects it.

use aws_lc_rs::{digest, hkdf, hmac};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fips204::{
    ml_dsa_87::{self, PublicKey},
    traits::SerDes,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pq::SharedSecret;

/// Default UDP port of the key-negotiation service.
pub const DEFAULT_KEY_NEGOTIATION_PORT: u16 = 51821;
/// Current wire protocol version.
pub const KEY_NEGOTIATION_VERSION: u16 = 5;
/// Upper bound for one framed protocol message.
///
/// ML-DSA-87 grows the worst case: a `ml_kem` request carries a 1 568-byte KEM
/// key as a JSON integer array, a certificate holding a 2 592-byte public key
/// and a 4 627-byte signature in base64, plus its own 4 627-byte signature —
/// roughly 23 KiB. The bound keeps a factor of two and a half, and
/// `the_worst_case_frame_fits_the_bound` proves it rather than deducing it.
pub const MAX_KEY_NEGOTIATION_MESSAGE_BYTES: usize = 64 * 1024;
/// Length of transaction identifiers and nonces.
pub const KEY_NEGOTIATION_NONCE_LEN: usize = 16;
/// Length of the gateway-issued challenge.
pub const SERVER_CHALLENGE_LEN: usize = 32;

const KEY_NEGOTIATION_DOMAIN: &[u8] = b"helios-key-negotiation-psk-v5";
const PQ_CERTIFICATE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-certificate-v2";
const PQ_REQUEST_DOMAIN: &[u8] = b"helios-key-negotiation-pq-request-v5";
const PQ_RESPONSE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-response-v5";
const PQ_CONFIRMATION_DOMAIN: &[u8] = b"helios-key-negotiation-pq-confirmation-v5";
const PQ_COMMIT_DOMAIN: &[u8] = b"helios-key-negotiation-pq-commit-v5";
/// Distinct from the domain of the withdrawn public QUIC message, so that no
/// signature produced by the old path is valid on the internal API.
const PQ_IN_TUNNEL_RELEASE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-in-tunnel-release-v5";
const STATIC_PSK_COMMITMENT_LABEL: &[u8] = b"helios-static-psk-commitment-v5";

/// Certificate format version. `2` carries ML-DSA-87; `1` carried ML-DSA-65
/// and is refused outright — the migration reissues the whole PKI.
pub const PQ_CERTIFICATE_VERSION: u16 = 2;

/// Size of a serialized ML-DSA-87 public key (FIPS 204), 2 592 bytes.
///
/// Deliberately **here** and not in [`crate::sig`], which holds the
/// publisher's ML-DSA-65 lengths. The two parameter sets coexist and do not
/// replace one another, so the only safe arrangement is for each PKI to name
/// its own sizes: validating negotiation material against
/// `sig::ML_DSA_65_PUBLIC_KEY_LEN` compiles, reads plausibly, and refuses
/// every real ML-DSA-87 key — which is exactly the mistake this constant
/// exists to make impossible.
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = ml_dsa_87::PK_LEN;
/// Size of an ML-DSA-87 signature (FIPS 204), 4 627 bytes.
pub const ML_DSA_87_SIGNATURE_LEN: usize = ml_dsa_87::SIG_LEN;

/// A WireGuard `PresharedKey` slot, and therefore a static PSK, is 32 bytes.
pub const STATIC_PSK_LEN: usize = 32;

/// How long a negotiated `ml_kem` PSK lives before the gateway reclaims it.
///
/// Twenty-four hours. WireGuard rekeys its session keys on its own, but the
/// PSK feeding every one of those derivations does not change while it is
/// installed: a tunnel left up for months would protect all of it with a
/// single ML-KEM secret.
///
/// Announced in the signed response so the client learns the deadline it has
/// to renegotiate before, rather than discovering it when the tunnel stops.
pub const NEGOTIATED_PSK_LIFETIME_SECS: u32 = 24 * 3600;

/// Narrowest confirmation delay a client accepts from a gateway.
pub const MIN_CONFIRMATION_TIMEOUT_SECS: u32 = 1;
/// Widest confirmation delay a client accepts from a gateway.
///
/// A signed value is not a trusted value. v4 took whatever the gateway sent,
/// so a compromised one could pin a client on an arbitrarily long wait and
/// have the signature vouch for it. The bound is local, applied after
/// signature verification, and a value outside it is a refusal rather than a
/// clamp: no legitimate gateway emits one, so silently accepting a smaller
/// number would hide the misconfiguration that produced it.
pub const MAX_CONFIRMATION_TIMEOUT_SECS: u32 = 45;

mod authentication;
mod derivation;
mod messages;

// One glob per part: several items exist only with `key-negotiation-signing`,
// and a glob follows their `cfg` where an explicit list would have to repeat it.
pub use self::{derivation::*, messages::*};
// Everything public in `authentication` is signing-only; the canonical bytes
// the other parts verify against exist in both builds.
#[cfg(feature = "key-negotiation-signing")]
pub use self::authentication::*;
#[cfg(not(feature = "key-negotiation-signing"))]
use self::authentication::*;

fn validate_hex_sha256(value: &str) -> Result<(), KeyNegotiationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(KeyNegotiationError::InvalidCertificateFingerprint);
    }
    Ok(())
}

/// Validates the canonical SHA-256 form used to bind a certificate to a peer.
pub fn validate_certificate_fingerprint(value: &str) -> Result<(), KeyNegotiationError> {
    validate_hex_sha256(value)
}

fn decode_exact<const N: usize>(
    encoded: &str,
    error: KeyNegotiationError,
) -> Result<[u8; N], KeyNegotiationError> {
    let bytes = STANDARD.decode(encoded).map_err(|_| error.clone())?;
    bytes.try_into().map_err(|_| error)
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeyNegotiationError> {
    let length = u32::try_from(bytes.len()).map_err(|_| KeyNegotiationError::CanonicalEncoding)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_optional_bytes(
    output: &mut Vec<u8>,
    bytes: Option<&[u8]>,
) -> Result<(), KeyNegotiationError> {
    match bytes {
        Some(bytes) => {
            output.push(1);
            append_bytes(output, bytes)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum KeyNegotiationError {
    #[error("key-negotiation protocol version {received} is unsupported; expected {supported}")]
    VersionMismatch { received: u16, supported: u16 },
    #[error("WireGuard public key is invalid")]
    InvalidWireGuardKey,
    #[error("transaction identifier must not be all zeroes")]
    ZeroTransaction,
    #[error("server challenge must not be all zeroes")]
    ZeroChallenge,
    #[error("response challenge does not match the request")]
    ChallengeMismatch,
    #[error("request carries no signing timestamp")]
    MissingTimestamp,
    #[error(
        "request clock is off by {drift_secs}s, more than the {tolerance_secs}s tolerated; \
         synchronise the client clock (NTP)"
    )]
    StaleRequest {
        drift_secs: u64,
        tolerance_secs: u64,
    },
    #[error("mode-specific material is inconsistent with the selected mode")]
    UnexpectedModeMaterial,
    #[error("static PSK commitment is missing")]
    MissingStaticPskCommitment,
    #[error("static PSK commitment must be a lowercase HMAC-SHA-256 hexadecimal value")]
    InvalidStaticPskCommitment,
    #[error("static PSK must decode to exactly {STATIC_PSK_LEN} bytes")]
    InvalidStaticPsk,
    #[error("certificate fingerprint must be a lowercase SHA-256 hexadecimal value")]
    InvalidCertificateFingerprint,
    #[error("ML-KEM public key is missing")]
    MissingKemPublicKey,
    #[error("ML-KEM public key has length {received}; expected {expected}")]
    InvalidKemPublicKeyLength { received: usize, expected: usize },
    #[error("ML-KEM ciphertext is missing")]
    MissingKemCiphertext,
    #[error("ML-KEM ciphertext has length {received}; expected {expected}")]
    InvalidKemCiphertextLength { received: usize, expected: usize },
    #[error("response transaction does not match the request")]
    TransactionMismatch,
    #[error("server selected a different protection mode")]
    ModeDowngrade,
    #[error("gateway identity does not match the profile")]
    GatewayIdentityMismatch,
    #[error(
        "confirmation timeout {received}s is outside the locally accepted range \
         {min}s..={max}s; a signed value is not a trusted value"
    )]
    ConfirmationTimeoutOutOfRange { received: u32, min: u32, max: u32 },
    #[error(
        "announced PSK lifetime {received}s does not match the {expected}s this mode requires"
    )]
    PskLifetimeMismatch { received: u32, expected: u32 },
    #[error(
        "`classic` is not a negotiable v5 mode: a tunnel with no preshared key \
         is a plain WireGuard profile, not a negotiation outcome"
    )]
    ClassicNotNegotiable,
    #[error("PSK derivation is only valid for ML-KEM mode")]
    PskDerivationOutsideMlKem,
    #[error("key derivation failed")]
    Kdf,
    #[error("PQ certificate is invalid or outside its validity period")]
    InvalidPqCertificate,
    #[error("PQ certificate issuer signature is invalid")]
    InvalidPqCertificateSignature,
    #[error("PQ certificate does not match the admitted identity")]
    PqCertificateFingerprintMismatch,
    #[error("PQ certificate is issued by an authority this peer carries no anchor for")]
    MissingPqCertificateAnchor,
    #[error("PQ protocol transcript signature is invalid")]
    InvalidPqProtocolSignature,
    #[error("PQ private key is invalid")]
    InvalidPqPrivateKey,
    #[error("PQ signing operation failed")]
    PqSigning,
    #[error("canonical protocol encoding failed")]
    CanonicalEncoding,
}

#[cfg(test)]
mod tests;
