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
    traits::{SerDes, Verifier},
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
const PQ_RELEASE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-release-v5";
const PQ_RELEASED_DOMAIN: &[u8] = b"helios-key-negotiation-pq-released-v5";
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

/// Protection selected by Orion for the upcoming WireGuard session.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    /// WireGuard Curve25519 without a preshared key.
    ///
    /// Retired on 2027-02-01 (spec §19). Kept only for peers admitted before
    /// v5; no new admission selects it.
    #[default]
    Classic,
    /// A preconfigured PSK proven by a transaction-bound commitment.
    StaticPsk,
    /// A fresh PSK derived from an ML-KEM-1024 encapsulation.
    MlKem,
}

impl ProtectionMode {
    pub const fn security_level(self) -> u8 {
        match self {
            Self::Classic => 0,
            Self::StaticPsk => 1,
            Self::MlKem => 2,
        }
    }

    pub const fn satisfies(self, minimum: Self) -> bool {
        self.security_level() >= minimum.security_level()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCertificateRole {
    Gateway,
    Client,
}

impl PqCertificateRole {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Gateway => 0,
            Self::Client => 1,
        }
    }
}

/// Application-level ML-DSA-87 certificate.
///
/// TLS remains a QUIC transport requirement, but this certificate and the
/// signed protocol transcript are the post-quantum authentication boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqCertificate {
    pub version: u16,
    pub serial: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub subject: String,
    pub issuer: String,
    pub role: PqCertificateRole,
    pub wireguard_public_key: String,
    /// Base64-encoded ML-DSA-87 subject public key.
    pub ml_dsa_87_public_key: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    /// Base64-encoded ML-DSA-87 issuer signature.
    pub ml_dsa_87_signature: String,
}

impl PqCertificate {
    pub fn verify(
        &self,
        issuer_public_key: &[u8],
        expected_role: PqCertificateRole,
        expected_subject: Option<&str>,
        expected_wireguard_public_key: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        if self.version != PQ_CERTIFICATE_VERSION
            || self.serial.iter().all(|byte| *byte == 0)
            || self.subject.trim().is_empty()
            || self.issuer.trim().is_empty()
            || self.role != expected_role
            || expected_subject.is_some_and(|subject| self.subject != subject)
            || self.wireguard_public_key != expected_wireguard_public_key
            || self.not_before_unix > now_unix
            || now_unix > self.not_after_unix
            || self.not_after_unix <= self.not_before_unix
        {
            return Err(KeyNegotiationError::InvalidPqCertificate);
        }
        crate::wg::validate_key(&self.wireguard_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let subject_public_key = decode_exact::<{ ml_dsa_87::PK_LEN }>(
            &self.ml_dsa_87_public_key,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        PublicKey::try_from_bytes(subject_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let issuer_public_key = <[u8; ml_dsa_87::PK_LEN]>::try_from(issuer_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let issuer_public_key = PublicKey::try_from_bytes(issuer_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let signature = decode_exact::<{ ml_dsa_87::SIG_LEN }>(
            &self.ml_dsa_87_signature,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        if !issuer_public_key.verify(&pq_certificate_signing_bytes(self)?, &signature, &[]) {
            return Err(KeyNegotiationError::InvalidPqCertificateSignature);
        }
        Ok(())
    }

    pub fn verify_self_signed(
        &self,
        expected_role: PqCertificateRole,
        expected_subject: Option<&str>,
        expected_wireguard_public_key: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        let public_key = STANDARD
            .decode(&self.ml_dsa_87_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        self.verify(
            &public_key,
            expected_role,
            expected_subject,
            expected_wireguard_public_key,
            now_unix,
        )
    }

    /// SHA-256 of the canonical binary encoding — the signed bytes, then the
    /// signature length-prefixed.
    ///
    /// v4 also accepted a fingerprint over the `serde_json` serialization for
    /// peers admitted earlier. v5 has **one** representation: the migration
    /// reissues every certificate anyway, and keeping two acceptable forms of
    /// the same identity is two things to get wrong.
    pub fn fingerprint(&self) -> Result<String, KeyNegotiationError> {
        let mut encoded = pq_certificate_signing_bytes(self)?;
        let signature = decode_exact::<{ ml_dsa_87::SIG_LEN }>(
            &self.ml_dsa_87_signature,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        append_bytes(&mut encoded, &signature)?;
        Ok(hex::encode(digest::digest(&digest::SHA256, &encoded)))
    }
}

/// Gateway answer to a `challenge_request`, before any client authentication.
///
/// Deliberately **unsigned**. Signing it would buy an unauthenticated peer one
/// ML-DSA-87 operation per connection, which is a denial-of-service amplifier
/// on the exact surface the Retry and rate limits exist to protect. It costs
/// nothing to forge, and forging it gains nothing: the gateway only accepts a
/// challenge it issued on that connection, so an injected one is a `rejected`.
///
/// It names the gateway so that a client detects a wrong endpoint before
/// spending a signature on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyNegotiationChallenge {
    pub protocol_version: u16,
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub gateway_wg_public_key: String,
    pub server_name: String,
    pub expires_in_secs: u32,
}

impl KeyNegotiationChallenge {
    /// Checks the announced identity against what the profile pins.
    ///
    /// A mismatch is a local failure that names both values: reaching the
    /// wrong gateway and reaching a tampered one look identical from here, and
    /// only the operator can tell them apart.
    pub fn validate_against(
        &self,
        expected_gateway_wg_public_key: &str,
        expected_server_name: &str,
    ) -> Result<(), KeyNegotiationError> {
        if self.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        if self.server_challenge.iter().all(|byte| *byte == 0) {
            return Err(KeyNegotiationError::ZeroChallenge);
        }
        if self.gateway_wg_public_key != expected_gateway_wg_public_key
            || self.server_name != expected_server_name
        {
            return Err(KeyNegotiationError::GatewayIdentityMismatch);
        }
        Ok(())
    }
}

/// Request plus a PQ certificate and a signature covering the whole transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationRequest {
    pub request: KeyNegotiationRequest,
    pub certificate: PqCertificate,
    /// Base64-encoded ML-DSA-87 signature.
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedKeyNegotiationRequest {
    /// Verifies everything the gateway can check without touching its own
    /// identity or the peer table.
    ///
    /// The caller must still check the challenge against the connection state
    /// and the gateway binding against the served identity — see
    /// [`KeyNegotiationRequest::assert_addressed_to`]. Both are gateway state,
    /// not transcript properties.
    pub fn verify(
        &self,
        issuer_public_key: &[u8],
        expected_certificate_fingerprint: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        self.request.validate()?;
        // Freshness first: it costs a subtraction, while everything below is
        // an ML-DSA verification. A stale request must not buy that work.
        self.request.assert_fresh(now_unix)?;
        self.certificate.verify(
            issuer_public_key,
            PqCertificateRole::Client,
            None,
            &self.request.client_wg_public_key,
            now_unix,
        )?;
        if self.certificate.fingerprint()? != expected_certificate_fingerprint {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            &pq_request_signing_bytes(&self.request, &self.certificate)?,
            &self.ml_dsa_87_signature,
        )
    }
}

/// Response signed by the gateway's PQ identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationResponse {
    pub response: KeyNegotiationResponse,
    pub certificate: PqCertificate,
    /// Base64-encoded ML-DSA-87 signature.
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedKeyNegotiationResponse {
    pub fn verify(
        &self,
        request: &KeyNegotiationRequest,
        pinned_certificate: &PqCertificate,
        expected_subject: &str,
        expected_gateway_wireguard_key: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        self.response
            .validate_for(request, expected_gateway_wireguard_key)?;
        self.certificate.verify_self_signed(
            PqCertificateRole::Gateway,
            Some(expected_subject),
            expected_gateway_wireguard_key,
            now_unix,
        )?;
        if self.certificate.fingerprint()? != pinned_certificate.fingerprint()? {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            &pq_response_signing_bytes(&self.response, &self.certificate)?,
            &self.ml_dsa_87_signature,
        )
    }
}

/// First authenticated message sent by Orion, after it holds a challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyNegotiationRequest {
    pub protocol_version: u16,
    /// Single-use challenge issued by the gateway for this connection.
    ///
    /// The anti-replay mechanism of v5. It replaces the bounded, volatile
    /// transaction cache as a *security property*; the cache survives only as
    /// defence in depth.
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub mode: ProtectionMode,
    /// WireGuard identity bound to the authenticated client certificate.
    pub client_wg_public_key: String,
    /// WireGuard identity of the gateway this request is **for**.
    ///
    /// Signed, and checked by the gateway against the key it actually serves.
    /// Without it, an authentic request for one gateway could be replayed
    /// against another sharing the same operator CA.
    pub gateway_wg_public_key: String,
    /// Server name this request is for, checked the same way.
    pub server_name: String,
    /// Fingerprint of the gateway PQ certificate the client has pinned.
    pub gateway_certificate_fingerprint: String,
    pub client_nonce: [u8; KEY_NEGOTIATION_NONCE_LEN],
    /// Unix time at which the client signed this request.
    ///
    /// A **secondary** control since v5. It rejects a delayed request before
    /// any cryptography, and names a drifting clock in the operator log. The
    /// challenge, not this, is what makes replay impossible.
    pub timestamp_unix: u64,
    /// ML-KEM-1024 encapsulation key. Present only in `ml_kem` mode.
    pub kem_public_key: Option<Vec<u8>>,
    /// Transaction-bound HMAC commitment. Present only in `static_psk` mode.
    ///
    /// v4 sent `SHA-256(static_psk)`, a stable value that let an observer
    /// correlate two negotiations as using the same secret. See
    /// [`static_psk_commitment`].
    pub static_psk_commitment: Option<String>,
}

/// Accepted drift between the client's clock and the gateway's.
///
/// Thirty seconds each way: wide enough for hosts synchronised by NTP over a
/// slow link, narrow enough to discard a delayed request early.
///
/// A client whose clock is off by more is refused with a message that says so
/// — an unexplained refusal here would be diagnosed as anything but a clock.
pub const MAX_REQUEST_CLOCK_SKEW_SECS: u64 = 30;

impl KeyNegotiationRequest {
    /// Rejects malformed or ambiguous payloads before any cryptography.
    pub fn validate(&self) -> Result<(), KeyNegotiationError> {
        if self.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        crate::wg::validate_key(&self.client_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        crate::wg::validate_key(&self.gateway_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        if self.server_name.trim().is_empty() {
            return Err(KeyNegotiationError::GatewayIdentityMismatch);
        }
        validate_certificate_fingerprint(&self.gateway_certificate_fingerprint)?;
        if self.server_challenge.iter().all(|byte| *byte == 0) {
            return Err(KeyNegotiationError::ZeroChallenge);
        }
        if self.transaction_id.iter().all(|byte| *byte == 0) {
            return Err(KeyNegotiationError::ZeroTransaction);
        }
        if self.timestamp_unix == 0 {
            return Err(KeyNegotiationError::MissingTimestamp);
        }

        match self.mode {
            // Refused at the v5 decoder, not merely discouraged.
            //
            // `classic` asks the gateway to run a challenge, an ML-DSA-87
            // verification and a signed commit in order to arrive at **no
            // preshared key at all** — the exact configuration a plain
            // WireGuard profile expresses without touching this port. Keeping
            // it as a negotiable mode meant the protocol's own floor could be
            // satisfied by the absence of protection, and that anyone able to
            // steer a client into it downgraded the tunnel while every
            // signature still verified.
            //
            // A client that wants generic WireGuard uses a generic WireGuard
            // profile. The variant survives in the type only so an existing
            // `network.toml` still parses — see the module's known limitation.
            ProtectionMode::Classic => return Err(KeyNegotiationError::ClassicNotNegotiable),
            ProtectionMode::StaticPsk => {
                if self.kem_public_key.is_some() {
                    return Err(KeyNegotiationError::UnexpectedModeMaterial);
                }
                let commitment = self
                    .static_psk_commitment
                    .as_deref()
                    .ok_or(KeyNegotiationError::MissingStaticPskCommitment)?;
                validate_hex_sha256(commitment)
                    .map_err(|_| KeyNegotiationError::InvalidStaticPskCommitment)?;
            }
            ProtectionMode::MlKem => {
                if self.static_psk_commitment.is_some() {
                    return Err(KeyNegotiationError::UnexpectedModeMaterial);
                }
                let key = self
                    .kem_public_key
                    .as_deref()
                    .ok_or(KeyNegotiationError::MissingKemPublicKey)?;
                if key.len() != crate::pq::PUBLIC_KEY_LEN {
                    return Err(KeyNegotiationError::InvalidKemPublicKeyLength {
                        received: key.len(),
                        expected: crate::pq::PUBLIC_KEY_LEN,
                    });
                }
            }
        }
        Ok(())
    }

    /// Rejects a request meant for a different gateway.
    ///
    /// Checked **before** any slot is touched. The three fields together name
    /// a gateway: its data-plane identity, its TLS name, and the certificate
    /// the client pinned. All three are covered by the request signature, so
    /// an attacker cannot retarget an authentic request by editing them.
    pub fn assert_addressed_to(
        &self,
        served_wg_public_key: &str,
        served_name: &str,
        served_certificate_fingerprint: &str,
    ) -> Result<(), KeyNegotiationError> {
        if self.gateway_wg_public_key != served_wg_public_key
            || self.server_name != served_name
            || self.gateway_certificate_fingerprint != served_certificate_fingerprint
        {
            return Err(KeyNegotiationError::GatewayIdentityMismatch);
        }
        Ok(())
    }

    /// Rejects a request whose clock is too far from the verifier's.
    ///
    /// Symmetric: a request from the future is as suspect as one from the
    /// past. Since v5 this only bounds delayed requests and surfaces clock
    /// drift; the challenge is what stops replay.
    pub fn assert_fresh(&self, now_unix: u64) -> Result<(), KeyNegotiationError> {
        let drift = now_unix.abs_diff(self.timestamp_unix);
        if drift > MAX_REQUEST_CLOCK_SKEW_SECS {
            return Err(KeyNegotiationError::StaleRequest {
                drift_secs: drift,
                tolerance_secs: MAX_REQUEST_CLOCK_SKEW_SECS,
            });
        }
        Ok(())
    }
}

/// Helios response after it has prepared the selected PSK slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyNegotiationResponse {
    pub protocol_version: u16,
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub selected_mode: ProtectionMode,
    pub gateway_wg_public_key: String,
    pub client_wg_public_key: String,
    pub gateway_nonce: [u8; KEY_NEGOTIATION_NONCE_LEN],
    /// ML-KEM ciphertext. Present only in `ml_kem` mode.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// Time allowed for a confirming WireGuard handshake, bounded locally by
    /// the client to [`MAX_CONFIRMATION_TIMEOUT_SECS`].
    pub confirmation_timeout_secs: u32,
    /// How long the gateway will keep this PSK before reclaiming it.
    ///
    /// [`NEGOTIATED_PSK_LIFETIME_SECS`] in `ml_kem`, and `0` in `static_psk`
    /// — where the value is configuration rather than a transactional secret
    /// and therefore never expires.
    ///
    /// Signed, and checked against those two exact values rather than merely
    /// read. The deadline is the gateway's, but the consequence is the
    /// client's: it is the client that has to renegotiate before the slot is
    /// emptied under a working tunnel. A value the client accepted without
    /// checking would let a compromised gateway advertise a deadline that
    /// does not match the one it enforces, and the tunnel would then die at a
    /// moment neither end had announced.
    pub psk_lifetime_secs: u32,
}

impl KeyNegotiationResponse {
    pub fn validate_for(
        &self,
        request: &KeyNegotiationRequest,
        expected_gateway_key: &str,
    ) -> Result<(), KeyNegotiationError> {
        if self.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        if self.transaction_id != request.transaction_id {
            return Err(KeyNegotiationError::TransactionMismatch);
        }
        if self.server_challenge != request.server_challenge {
            return Err(KeyNegotiationError::ChallengeMismatch);
        }
        if self.selected_mode != request.mode {
            return Err(KeyNegotiationError::ModeDowngrade);
        }
        if self.client_wg_public_key != request.client_wg_public_key {
            return Err(KeyNegotiationError::TransactionMismatch);
        }
        if self.gateway_wg_public_key != expected_gateway_key {
            return Err(KeyNegotiationError::GatewayIdentityMismatch);
        }
        crate::wg::validate_key(&self.gateway_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        if !(MIN_CONFIRMATION_TIMEOUT_SECS..=MAX_CONFIRMATION_TIMEOUT_SECS)
            .contains(&self.confirmation_timeout_secs)
        {
            return Err(KeyNegotiationError::ConfirmationTimeoutOutOfRange {
                received: self.confirmation_timeout_secs,
                min: MIN_CONFIRMATION_TIMEOUT_SECS,
                max: MAX_CONFIRMATION_TIMEOUT_SECS,
            });
        }
        let expected_lifetime = match self.selected_mode {
            ProtectionMode::StaticPsk => 0,
            _ => NEGOTIATED_PSK_LIFETIME_SECS,
        };
        if self.psk_lifetime_secs != expected_lifetime {
            return Err(KeyNegotiationError::PskLifetimeMismatch {
                received: self.psk_lifetime_secs,
                expected: expected_lifetime,
            });
        }
        match self.selected_mode {
            ProtectionMode::MlKem => {
                let ciphertext = self
                    .kem_ciphertext
                    .as_deref()
                    .ok_or(KeyNegotiationError::MissingKemCiphertext)?;
                if ciphertext.len() != crate::pq::CIPHERTEXT_LEN {
                    return Err(KeyNegotiationError::InvalidKemCiphertextLength {
                        received: ciphertext.len(),
                        expected: crate::pq::CIPHERTEXT_LEN,
                    });
                }
            }
            ProtectionMode::Classic | ProtectionMode::StaticPsk => {
                if self.kem_ciphertext.is_some() {
                    return Err(KeyNegotiationError::UnexpectedModeMaterial);
                }
            }
        }
        Ok(())
    }
}

/// Final acknowledgment, sent once Orion has seen a WireGuard handshake
/// succeed **with the newly installed PSK**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyNegotiationConfirmation {
    pub protocol_version: u16,
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationConfirmation {
    pub confirmation: KeyNegotiationConfirmation,
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedKeyNegotiationConfirmation {
    pub fn verify(&self, client_public_key: &str) -> Result<(), KeyNegotiationError> {
        if self.confirmation.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.confirmation.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        verify_protocol_signature(
            client_public_key,
            &pq_transaction_signing_bytes(
                PQ_CONFIRMATION_DOMAIN,
                self.confirmation.protocol_version,
                &self.confirmation.server_challenge,
                &self.confirmation.transaction_id,
            ),
            &self.ml_dsa_87_signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationCommit {
    pub protocol_version: u16,
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedKeyNegotiationCommit {
    pub fn verify(&self, gateway_public_key: &str) -> Result<(), KeyNegotiationError> {
        if self.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        verify_protocol_signature(
            gateway_public_key,
            &pq_transaction_signing_bytes(
                PQ_COMMIT_DOMAIN,
                self.protocol_version,
                &self.server_challenge,
                &self.transaction_id,
            ),
            &self.ml_dsa_87_signature,
        )
    }
}

/// Explicit teardown, carrying what the closed QUIC link no longer signals.
///
/// Travels on a **new** connection with its own challenge phase, and follows
/// exactly the same authentication path as a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PskRelease {
    pub protocol_version: u16,
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    /// Transaction that installed the PSK being released.
    ///
    /// The gateway only clears the slot if this names its current owner, so a
    /// delayed release cannot tear down a tunnel established by a **later**
    /// negotiation.
    pub installed_transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub client_wg_public_key: String,
    pub gateway_wg_public_key: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPskRelease {
    pub release: PskRelease,
    pub certificate: PqCertificate,
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedPskRelease {
    pub fn verify(
        &self,
        issuer_public_key: &[u8],
        expected_certificate_fingerprint: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        if self.release.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.release.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        if self.release.server_challenge.iter().all(|byte| *byte == 0) {
            return Err(KeyNegotiationError::ZeroChallenge);
        }
        if self
            .release
            .installed_transaction_id
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(KeyNegotiationError::ZeroTransaction);
        }
        crate::wg::validate_key(&self.release.client_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        crate::wg::validate_key(&self.release.gateway_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        let drift = now_unix.abs_diff(self.release.timestamp_unix);
        if drift > MAX_REQUEST_CLOCK_SKEW_SECS {
            return Err(KeyNegotiationError::StaleRequest {
                drift_secs: drift,
                tolerance_secs: MAX_REQUEST_CLOCK_SKEW_SECS,
            });
        }
        self.certificate.verify(
            issuer_public_key,
            PqCertificateRole::Client,
            None,
            &self.release.client_wg_public_key,
            now_unix,
        )?;
        if self.certificate.fingerprint()? != expected_certificate_fingerprint {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            &pq_release_signing_bytes(&self.release, &self.certificate)?,
            &self.ml_dsa_87_signature,
        )
    }
}

/// Idempotent, **signed** acknowledgment of a release.
///
/// Signed by the same rule that covers the commit: every gateway statement
/// about the state of a slot is signed. The impact of a forged one is small —
/// Orion is disconnecting anyway — but the rule is easier to hold than the
/// exception, and the signature costs one operation on a connection that is
/// already authenticated, so it amplifies nothing.
///
/// The same value is returned whether the slot was cleared, was already empty,
/// or belongs to another transaction: distinguishing them would be an oracle
/// on a peer's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PskReleased {
    pub protocol_version: u16,
    pub server_challenge: [u8; SERVER_CHALLENGE_LEN],
    pub installed_transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPskReleased {
    pub released: PskReleased,
    pub certificate: PqCertificate,
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedPskReleased {
    pub fn verify(
        &self,
        release: &PskRelease,
        pinned_certificate: &PqCertificate,
    ) -> Result<(), KeyNegotiationError> {
        if self.released.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.released.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        if self.released.server_challenge != release.server_challenge {
            return Err(KeyNegotiationError::ChallengeMismatch);
        }
        if self.released.installed_transaction_id != release.installed_transaction_id {
            return Err(KeyNegotiationError::TransactionMismatch);
        }
        if self.certificate.fingerprint()? != pinned_certificate.fingerprint()? {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            &pq_released_signing_bytes(&self.released, &self.certificate)?,
            &self.ml_dsa_87_signature,
        )
    }
}

/// Output length of the derivation: one WireGuard `PresharedKey`.
///
/// HKDF's expand length is normally taken from the digest, which would give
/// SHA-512's 64 bytes. The PSK slot holds 32, so the length is stated here
/// rather than truncated at the call site.
struct PskLength;

impl hkdf::KeyType for PskLength {
    fn len(&self) -> usize {
        crate::pq::SHARED_SECRET_LEN
    }
}

/// Derives the WireGuard PSK, binding the whole negotiation context.
///
/// The salt carries the gateway challenge on top of v4's transaction and
/// nonces: a derived secret is tied to an authorization the gateway issued for
/// one connection. `info` carries the server name on top of both WireGuard
/// keys, so the same transcript replayed against a different gateway identity
/// cannot produce the same key.
pub fn derive_negotiated_psk(
    shared_secret: &SharedSecret,
    request: &KeyNegotiationRequest,
    response: &KeyNegotiationResponse,
) -> Result<Zeroizing<[u8; STATIC_PSK_LEN]>, KeyNegotiationError> {
    if request.mode != ProtectionMode::MlKem || response.selected_mode != ProtectionMode::MlKem {
        return Err(KeyNegotiationError::PskDerivationOutsideMlKem);
    }
    response.validate_for(request, &response.gateway_wg_public_key)?;

    let mut salt = Vec::with_capacity(SERVER_CHALLENGE_LEN + KEY_NEGOTIATION_NONCE_LEN * 3);
    salt.extend_from_slice(&request.server_challenge);
    salt.extend_from_slice(&request.transaction_id);
    salt.extend_from_slice(&request.client_nonce);
    salt.extend_from_slice(&response.gateway_nonce);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, &salt);
    let prk = salt.extract(shared_secret.as_slice());

    let name = request.server_name.as_bytes();
    let client = request.client_wg_public_key.as_bytes();
    let gateway = response.gateway_wg_public_key.as_bytes();
    let name_len = (name.len() as u16).to_be_bytes();
    let client_len = (client.len() as u16).to_be_bytes();
    let gateway_len = (gateway.len() as u16).to_be_bytes();
    let mode = [request.mode.security_level()];
    let version = request.protocol_version.to_be_bytes();
    let timestamp = request.timestamp_unix.to_be_bytes();
    // Every variable-length field is length-prefixed: no two field boundaries
    // can be shifted to produce the same concatenation.
    let info: [&[u8]; 10] = [
        KEY_NEGOTIATION_DOMAIN,
        &version,
        &mode,
        &timestamp,
        &name_len,
        name,
        &client_len,
        client,
        &gateway_len,
        gateway,
    ];
    // The output length is the PSK slot's, not the digest's: expanding to
    // SHA-512's 64 bytes and truncating would be the same secret, but it
    // would leave the caller to do the truncating.
    let okm = prk
        .expand(&info, PskLength)
        .map_err(|_| KeyNegotiationError::Kdf)?;
    let mut psk = Zeroizing::new([0u8; STATIC_PSK_LEN]);
    okm.fill(psk.as_mut_slice())
        .map_err(|_| KeyNegotiationError::Kdf)?;
    Ok(psk)
}

/// Decodes and checks a configured static PSK.
///
/// **Exactly 32 bytes** after decoding — the size of the slot it will occupy.
/// Anything else is refused when the configuration loads, not when a
/// negotiation runs: a gateway carrying a malformed PSK must not start.
///
/// What the code cannot check, the tooling must guarantee: the value must come
/// from the TRNG → seed/reseed → DRBG pipeline of the specification. A
/// passphrase is also 32 bytes once hashed, and no length check will ever say
/// otherwise. That is why no interface offers free-text entry for this field.
pub fn validate_static_psk(
    psk_base64: &str,
) -> Result<Zeroizing<[u8; STATIC_PSK_LEN]>, KeyNegotiationError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(psk_base64.trim())
            .map_err(|_| KeyNegotiationError::InvalidStaticPsk)?,
    );
    let bytes: [u8; STATIC_PSK_LEN] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| KeyNegotiationError::InvalidStaticPsk)?;
    Ok(Zeroizing::new(bytes))
}

/// Proves possession of a static PSK **for one transaction only**.
///
/// v4 sent `SHA-256(static_psk)`. The size and randomness now required rule
/// out an offline search, but that value is stable: an observer of the public
/// port could correlate two negotiations as using the same secret. An HMAC
/// keyed by the PSK over the transaction context is a different value every
/// time, and the gateway — which knows the PSK — recomputes and compares it in
/// constant time.
pub fn static_psk_commitment(
    psk_base64: &str,
    transaction_id: &[u8; KEY_NEGOTIATION_NONCE_LEN],
    client_nonce: &[u8; KEY_NEGOTIATION_NONCE_LEN],
    server_challenge: &[u8; SERVER_CHALLENGE_LEN],
    client_wg_public_key: &str,
    gateway_wg_public_key: &str,
) -> Result<String, KeyNegotiationError> {
    let psk = validate_static_psk(psk_base64)?;
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(STATIC_PSK_COMMITMENT_LABEL);
    message.extend_from_slice(transaction_id);
    message.extend_from_slice(client_nonce);
    message.extend_from_slice(server_challenge);
    append_bytes(&mut message, client_wg_public_key.as_bytes())?;
    append_bytes(&mut message, gateway_wg_public_key.as_bytes())?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, psk.as_slice());
    Ok(hex::encode(hmac::sign(&key, &message).as_ref()))
}

/// Constant-time comparison of two commitments.
///
/// Both are hex strings of the same length; a byte-wise early return would
/// leak how many leading nibbles an attacker guessed right.
pub fn commitments_match(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

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

fn pq_certificate_signing_bytes(
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let public_key = STANDARD
        .decode(&certificate.ml_dsa_87_public_key)
        .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
    if public_key.len() != ml_dsa_87::PK_LEN {
        return Err(KeyNegotiationError::InvalidPqCertificate);
    }
    let mut output = Vec::with_capacity(256 + public_key.len());
    output.extend_from_slice(PQ_CERTIFICATE_DOMAIN);
    output.extend_from_slice(&certificate.version.to_be_bytes());
    output.extend_from_slice(&certificate.serial);
    output.push(certificate.role.domain_byte());
    append_bytes(&mut output, certificate.subject.as_bytes())?;
    append_bytes(&mut output, certificate.issuer.as_bytes())?;
    append_bytes(&mut output, certificate.wireguard_public_key.as_bytes())?;
    append_bytes(&mut output, &public_key)?;
    output.extend_from_slice(&certificate.not_before_unix.to_be_bytes());
    output.extend_from_slice(&certificate.not_after_unix.to_be_bytes());
    Ok(output)
}

fn pq_request_signing_bytes(
    request: &KeyNegotiationRequest,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(2048);
    output.extend_from_slice(PQ_REQUEST_DOMAIN);
    output.extend_from_slice(&request.protocol_version.to_be_bytes());
    output.extend_from_slice(&request.server_challenge);
    output.extend_from_slice(&request.transaction_id);
    output.push(request.mode.security_level());
    append_bytes(&mut output, request.client_wg_public_key.as_bytes())?;
    append_bytes(&mut output, request.gateway_wg_public_key.as_bytes())?;
    append_bytes(&mut output, request.server_name.as_bytes())?;
    append_bytes(
        &mut output,
        request.gateway_certificate_fingerprint.as_bytes(),
    )?;
    output.extend_from_slice(&request.client_nonce);
    output.extend_from_slice(&request.timestamp_unix.to_be_bytes());
    append_optional_bytes(&mut output, request.kem_public_key.as_deref())?;
    append_optional_bytes(
        &mut output,
        request.static_psk_commitment.as_deref().map(str::as_bytes),
    )?;
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

fn pq_response_signing_bytes(
    response: &KeyNegotiationResponse,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(2048);
    output.extend_from_slice(PQ_RESPONSE_DOMAIN);
    output.extend_from_slice(&response.protocol_version.to_be_bytes());
    output.extend_from_slice(&response.transaction_id);
    output.extend_from_slice(&response.server_challenge);
    output.push(response.selected_mode.security_level());
    append_bytes(&mut output, response.gateway_wg_public_key.as_bytes())?;
    append_bytes(&mut output, response.client_wg_public_key.as_bytes())?;
    output.extend_from_slice(&response.gateway_nonce);
    append_optional_bytes(&mut output, response.kem_ciphertext.as_deref())?;
    output.extend_from_slice(&response.confirmation_timeout_secs.to_be_bytes());
    output.extend_from_slice(&response.psk_lifetime_secs.to_be_bytes());
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

fn pq_release_signing_bytes(
    release: &PskRelease,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(PQ_RELEASE_DOMAIN);
    output.extend_from_slice(&release.protocol_version.to_be_bytes());
    output.extend_from_slice(&release.server_challenge);
    output.extend_from_slice(&release.installed_transaction_id);
    append_bytes(&mut output, release.client_wg_public_key.as_bytes())?;
    append_bytes(&mut output, release.gateway_wg_public_key.as_bytes())?;
    output.extend_from_slice(&release.timestamp_unix.to_be_bytes());
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

fn pq_released_signing_bytes(
    released: &PskReleased,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(PQ_RELEASED_DOMAIN);
    output.extend_from_slice(&released.protocol_version.to_be_bytes());
    output.extend_from_slice(&released.server_challenge);
    output.extend_from_slice(&released.installed_transaction_id);
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

fn pq_transaction_signing_bytes(
    domain: &[u8],
    protocol_version: u16,
    server_challenge: &[u8; SERVER_CHALLENGE_LEN],
    transaction_id: &[u8; KEY_NEGOTIATION_NONCE_LEN],
) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(domain.len() + 2 + SERVER_CHALLENGE_LEN + KEY_NEGOTIATION_NONCE_LEN);
    output.extend_from_slice(domain);
    output.extend_from_slice(&protocol_version.to_be_bytes());
    output.extend_from_slice(server_challenge);
    output.extend_from_slice(transaction_id);
    output
}

fn verify_protocol_signature(
    public_key: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), KeyNegotiationError> {
    let public_key = decode_exact::<{ ml_dsa_87::PK_LEN }>(
        public_key,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    let public_key = PublicKey::try_from_bytes(public_key)
        .map_err(|_| KeyNegotiationError::InvalidPqProtocolSignature)?;
    let signature = decode_exact::<{ ml_dsa_87::SIG_LEN }>(
        signature,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    if !public_key.verify(message, &signature, &[]) {
        return Err(KeyNegotiationError::InvalidPqProtocolSignature);
    }
    Ok(())
}

#[cfg(feature = "key-negotiation-signing")]
fn sign_ml_dsa_87(private_key: &[u8], message: &[u8]) -> Result<String, KeyNegotiationError> {
    use fips204::{
        ml_dsa_87::PrivateKey,
        traits::{SerDes as _, Signer as _},
    };

    let private_key = <[u8; ml_dsa_87::SK_LEN]>::try_from(private_key)
        .map_err(|_| KeyNegotiationError::InvalidPqPrivateKey)?;
    let private_key = PrivateKey::try_from_bytes(private_key)
        .map_err(|_| KeyNegotiationError::InvalidPqPrivateKey)?;
    let signature = private_key
        .try_sign(message, &[])
        .map_err(|_| KeyNegotiationError::PqSigning)?;
    Ok(STANDARD.encode(signature))
}

/// Generates an ML-DSA-87 identity. The private half is zeroized on drop.
#[cfg(feature = "key-negotiation-signing")]
pub fn generate_ml_dsa_87_keypair() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), KeyNegotiationError> {
    use fips204::traits::SerDes as _;

    let (public_key, private_key) =
        ml_dsa_87::try_keygen().map_err(|_| KeyNegotiationError::PqSigning)?;
    Ok((
        Zeroizing::new(private_key.into_bytes().to_vec()),
        public_key.into_bytes().to_vec(),
    ))
}

/// Signs a new PQ certificate with an ML-DSA-87 issuer key.
#[cfg(feature = "key-negotiation-signing")]
pub fn issue_pq_certificate(
    mut certificate: PqCertificate,
    issuer_private_key: &[u8],
) -> Result<PqCertificate, KeyNegotiationError> {
    certificate.ml_dsa_87_signature.clear();
    certificate.ml_dsa_87_signature = sign_ml_dsa_87(
        issuer_private_key,
        &pq_certificate_signing_bytes(&certificate)?,
    )?;
    Ok(certificate)
}

/// Signs an Orion request, including its challenge and gateway binding.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_request(
    request: KeyNegotiationRequest,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationRequest, KeyNegotiationError> {
    request.validate()?;
    let signature = sign_ml_dsa_87(
        subject_private_key,
        &pq_request_signing_bytes(&request, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationRequest {
        request,
        certificate,
        ml_dsa_87_signature: signature,
    })
}

/// Signs the Helios response containing the ML-KEM ciphertext.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_response(
    response: KeyNegotiationResponse,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationResponse, KeyNegotiationError> {
    let signature = sign_ml_dsa_87(
        subject_private_key,
        &pq_response_signing_bytes(&response, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationResponse {
        response,
        certificate,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_confirmation(
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    client_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationConfirmation, KeyNegotiationError> {
    let confirmation = KeyNegotiationConfirmation {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge,
        transaction_id,
    };
    let signature = sign_ml_dsa_87(
        client_private_key,
        &pq_transaction_signing_bytes(
            PQ_CONFIRMATION_DOMAIN,
            confirmation.protocol_version,
            &confirmation.server_challenge,
            &confirmation.transaction_id,
        ),
    )?;
    Ok(AuthenticatedKeyNegotiationConfirmation {
        confirmation,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_commit(
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    gateway_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationCommit, KeyNegotiationError> {
    let protocol_version = KEY_NEGOTIATION_VERSION;
    let signature = sign_ml_dsa_87(
        gateway_private_key,
        &pq_transaction_signing_bytes(
            PQ_COMMIT_DOMAIN,
            protocol_version,
            &server_challenge,
            &transaction_id,
        ),
    )?;
    Ok(AuthenticatedKeyNegotiationCommit {
        protocol_version,
        server_challenge,
        transaction_id,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_release(
    release: PskRelease,
    certificate: PqCertificate,
    client_private_key: &[u8],
) -> Result<AuthenticatedPskRelease, KeyNegotiationError> {
    let signature = sign_ml_dsa_87(
        client_private_key,
        &pq_release_signing_bytes(&release, &certificate)?,
    )?;
    Ok(AuthenticatedPskRelease {
        release,
        certificate,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_released(
    released: PskReleased,
    certificate: PqCertificate,
    gateway_private_key: &[u8],
) -> Result<AuthenticatedPskReleased, KeyNegotiationError> {
    let signature = sign_ml_dsa_87(
        gateway_private_key,
        &pq_released_signing_bytes(&released, &certificate)?,
    )?;
    Ok(AuthenticatedPskReleased {
        released,
        certificate,
        ml_dsa_87_signature: signature,
    })
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
mod tests {
    use super::*;
    use crate::pq::{Kem, MlKem1024Kem};

    const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const SERVER_NAME: &str = "gateway.example";
    const GATEWAY_FINGERPRINT: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Horloge des tests : les requêtes doivent être fraîches pour passer le
    /// contrôle secondaire de fraîcheur.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn challenge() -> [u8; SERVER_CHALLENGE_LEN] {
        [5; SERVER_CHALLENGE_LEN]
    }

    /// The static PSK the test fixtures commit to.
    fn test_static_psk() -> String {
        STANDARD.encode([7u8; STATIC_PSK_LEN])
    }

    /// A request carrying whatever its mode requires.
    ///
    /// `static_psk` is the default of these tests because it is the cheapest
    /// mode that a v5 decoder actually accepts: `classic` is refused outright
    /// since the mode stopped being negotiable, and `ml_kem` costs a keypair
    /// on every call.
    fn request(mode: ProtectionMode) -> KeyNegotiationRequest {
        let transaction_id = [1; KEY_NEGOTIATION_NONCE_LEN];
        let client_nonce = [2; KEY_NEGOTIATION_NONCE_LEN];
        let static_psk_commitment = (mode == ProtectionMode::StaticPsk).then(|| {
            static_psk_commitment(
                &test_static_psk(),
                &transaction_id,
                &client_nonce,
                &challenge(),
                CLIENT_WG_KEY,
                GATEWAY_WG_KEY,
            )
            .unwrap()
        });
        let kem_public_key = (mode == ProtectionMode::MlKem).then(|| {
            use crate::pq::Kem as _;
            crate::pq::MlKem1024Kem::generate().unwrap().1
        });
        KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: challenge(),
            transaction_id,
            mode,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: SERVER_NAME.into(),
            gateway_certificate_fingerprint: GATEWAY_FINGERPRINT.into(),
            client_nonce,
            timestamp_unix: test_now(),
            kem_public_key,
            static_psk_commitment,
        }
    }

    fn response(request: &KeyNegotiationRequest, mode: ProtectionMode) -> KeyNegotiationResponse {
        KeyNegotiationResponse {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: request.transaction_id,
            server_challenge: request.server_challenge,
            selected_mode: mode,
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            client_wg_public_key: request.client_wg_public_key.clone(),
            gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
            kem_ciphertext: None,
            confirmation_timeout_secs: 45,
            psk_lifetime_secs: match mode {
                ProtectionMode::StaticPsk => 0,
                _ => NEGOTIATED_PSK_LIFETIME_SECS,
            },
        }
    }

    #[test]
    fn an_announced_psk_lifetime_must_match_the_mode() {
        let request = request(ProtectionMode::MlKem);

        let mut honest = response(&request, ProtectionMode::MlKem);
        // `ml_kem` also requires a ciphertext; supplying one keeps this test
        // focused on the lifetime rather than tripping over an earlier check.
        honest.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
        assert_eq!(honest.psk_lifetime_secs, NEGOTIATED_PSK_LIFETIME_SECS);
        assert!(honest.validate_for(&request, GATEWAY_WG_KEY).is_ok());

        // A gateway advertising a deadline it does not enforce: the client
        // would plan its renewal around a lie and lose the tunnel at a moment
        // neither end announced.
        let mut lying = response(&request, ProtectionMode::MlKem);
        lying.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
        lying.psk_lifetime_secs = 60;
        assert!(matches!(
            lying.validate_for(&request, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::PskLifetimeMismatch { .. })
        ));

        // A static PSK expires never, and saying otherwise is equally wrong:
        // it would have the client renegotiate for a value only the operator
        // can change.
        let static_request = self::request(ProtectionMode::StaticPsk);
        let mut expiring = response(&static_request, ProtectionMode::StaticPsk);
        assert_eq!(expiring.psk_lifetime_secs, 0);
        expiring.psk_lifetime_secs = NEGOTIATED_PSK_LIFETIME_SECS;
        assert!(matches!(
            expiring.validate_for(&static_request, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::PskLifetimeMismatch { .. })
        ));
    }

    #[test]
    fn a_request_outside_the_clock_window_is_refused() {
        let now = test_now();
        let fresh = KeyNegotiationRequest {
            timestamp_unix: now,
            ..request(ProtectionMode::StaticPsk)
        };
        assert!(fresh.assert_fresh(now).is_ok());

        // Aux bornes exactes : accepté, la tolérance est inclusive.
        assert!(fresh
            .assert_fresh(now + MAX_REQUEST_CLOCK_SKEW_SECS)
            .is_ok());
        assert!(fresh
            .assert_fresh(now - MAX_REQUEST_CLOCK_SKEW_SECS)
            .is_ok());

        for drift in [
            MAX_REQUEST_CLOCK_SKEW_SECS + 1,
            MAX_REQUEST_CLOCK_SKEW_SECS + 3600,
        ] {
            assert!(matches!(
                fresh.assert_fresh(now + drift),
                Err(KeyNegotiationError::StaleRequest { .. })
            ));
            assert!(matches!(
                fresh.assert_fresh(now - drift),
                Err(KeyNegotiationError::StaleRequest { .. })
            ));
        }

        let undated = KeyNegotiationRequest {
            timestamp_unix: 0,
            ..request(ProtectionMode::StaticPsk)
        };
        assert_eq!(
            undated.validate(),
            Err(KeyNegotiationError::MissingTimestamp)
        );
    }

    /// Le challenge entre dans le sel : une transcription rejouée sous un
    /// challenge différent ne peut pas produire le même PSK.
    #[test]
    fn the_challenge_and_the_timestamp_are_bound_into_the_derived_psk() {
        let (secret_key, public_key) = MlKem1024Kem::generate().unwrap();
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(public_key);
        let (ciphertext, gateway_secret) =
            MlKem1024Kem::encapsulate(plain.kem_public_key.as_ref().unwrap()).unwrap();
        let mut answer = response(&plain, ProtectionMode::MlKem);
        answer.kem_ciphertext = Some(ciphertext.clone());

        let client_secret = MlKem1024Kem::decapsulate(&secret_key, &ciphertext).unwrap();
        let reference = derive_negotiated_psk(&gateway_secret, &plain, &answer).unwrap();
        assert_eq!(
            *reference,
            *derive_negotiated_psk(&client_secret, &plain, &answer).unwrap(),
            "les deux bouts doivent dériver le même PSK"
        );
        assert_eq!(reference.len(), 32, "un slot PresharedKey fait 32 octets");

        let mut other_challenge = plain.clone();
        other_challenge.server_challenge[0] ^= 1;
        let mut rebound = answer.clone();
        rebound.server_challenge = other_challenge.server_challenge;
        assert_ne!(
            *reference,
            *derive_negotiated_psk(&gateway_secret, &other_challenge, &rebound).unwrap(),
            "changer le challenge doit changer le PSK"
        );

        let replayed = KeyNegotiationRequest {
            timestamp_unix: plain.timestamp_unix + 1,
            ..plain.clone()
        };
        assert_ne!(
            *reference,
            *derive_negotiated_psk(&gateway_secret, &replayed, &answer).unwrap(),
            "changer l'horodatage doit changer le PSK"
        );
    }

    /// Le nom du serveur entre dans `info` : deux gateways partageant la même
    /// CA ne dérivent pas le même secret d'une transcription identique.
    #[test]
    fn the_server_name_is_bound_into_the_derived_psk() {
        let (_, public_key) = MlKem1024Kem::generate().unwrap();
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(public_key);
        let (ciphertext, secret) =
            MlKem1024Kem::encapsulate(plain.kem_public_key.as_ref().unwrap()).unwrap();
        let mut answer = response(&plain, ProtectionMode::MlKem);
        answer.kem_ciphertext = Some(ciphertext);

        let reference = derive_negotiated_psk(&secret, &plain, &answer).unwrap();
        let elsewhere = KeyNegotiationRequest {
            server_name: "other.example".into(),
            ..plain
        };
        assert_ne!(
            *reference,
            *derive_negotiated_psk(&secret, &elsewhere, &answer).unwrap()
        );
    }

    #[test]
    fn each_mode_rejects_material_from_another_mode() {
        // `classic` is refused before its material is even looked at: it is
        // not a mode with the wrong contents, it is not a v5 mode.
        let mut classic = request(ProtectionMode::Classic);
        assert_eq!(
            classic.validate(),
            Err(KeyNegotiationError::ClassicNotNegotiable)
        );
        classic.static_psk_commitment = Some("a".repeat(64));
        assert_eq!(
            classic.validate(),
            Err(KeyNegotiationError::ClassicNotNegotiable),
            "adding material must not turn a retired mode into a negotiable one"
        );

        let mut static_psk = request(ProtectionMode::StaticPsk);
        static_psk.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);
        assert_eq!(
            static_psk.validate(),
            Err(KeyNegotiationError::UnexpectedModeMaterial)
        );

        let mut ml_kem = request(ProtectionMode::MlKem);
        ml_kem.static_psk_commitment = Some("a".repeat(64));
        assert_eq!(
            ml_kem.validate(),
            Err(KeyNegotiationError::UnexpectedModeMaterial)
        );
    }

    #[test]
    fn a_request_naming_another_gateway_is_refused() {
        let plain = request(ProtectionMode::StaticPsk);
        plain
            .assert_addressed_to(GATEWAY_WG_KEY, SERVER_NAME, GATEWAY_FINGERPRINT)
            .unwrap();

        // Chacun des trois champs, seul, suffit à disqualifier la requête.
        assert_eq!(
            plain.assert_addressed_to(CLIENT_WG_KEY, SERVER_NAME, GATEWAY_FINGERPRINT),
            Err(KeyNegotiationError::GatewayIdentityMismatch)
        );
        assert_eq!(
            plain.assert_addressed_to(GATEWAY_WG_KEY, "other.example", GATEWAY_FINGERPRINT),
            Err(KeyNegotiationError::GatewayIdentityMismatch)
        );
        assert_eq!(
            plain.assert_addressed_to(GATEWAY_WG_KEY, SERVER_NAME, &"2".repeat(64)),
            Err(KeyNegotiationError::GatewayIdentityMismatch)
        );
    }

    #[test]
    fn response_refuses_mode_downgrade_transaction_and_challenge_replay() {
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);

        let mut answer = response(&plain, ProtectionMode::StaticPsk);
        assert_eq!(
            answer.validate_for(&plain, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::ModeDowngrade)
        );

        answer.selected_mode = ProtectionMode::MlKem;
        answer.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
        answer.transaction_id = [9; KEY_NEGOTIATION_NONCE_LEN];
        assert_eq!(
            answer.validate_for(&plain, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::TransactionMismatch)
        );

        answer.transaction_id = plain.transaction_id;
        answer.server_challenge[0] ^= 1;
        assert_eq!(
            answer.validate_for(&plain, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::ChallengeMismatch)
        );
    }

    /// Une valeur signée n'est pas une valeur de confiance : la borne est
    /// locale, et sortir de la plage est un refus, pas un rognage.
    #[test]
    fn a_confirmation_timeout_outside_the_local_range_is_refused() {
        let plain = request(ProtectionMode::StaticPsk);
        for accepted in [MIN_CONFIRMATION_TIMEOUT_SECS, MAX_CONFIRMATION_TIMEOUT_SECS] {
            let answer = KeyNegotiationResponse {
                confirmation_timeout_secs: accepted,
                ..response(&plain, ProtectionMode::StaticPsk)
            };
            answer.validate_for(&plain, GATEWAY_WG_KEY).unwrap();
        }

        for refused in [0, MAX_CONFIRMATION_TIMEOUT_SECS + 1, 86_400] {
            let answer = KeyNegotiationResponse {
                confirmation_timeout_secs: refused,
                ..response(&plain, ProtectionMode::StaticPsk)
            };
            assert!(matches!(
                answer.validate_for(&plain, GATEWAY_WG_KEY),
                Err(KeyNegotiationError::ConfirmationTimeoutOutOfRange { .. })
            ));
        }
    }

    /// L'engagement remplace une empreinte stable : deux négociations avec le
    /// **même** PSK ne produisent pas la même valeur, donc rien à corréler.
    #[test]
    fn the_static_psk_commitment_differs_across_transactions() {
        let psk = STANDARD.encode([7u8; STATIC_PSK_LEN]);
        let first = static_psk_commitment(
            &psk,
            &[1; KEY_NEGOTIATION_NONCE_LEN],
            &[2; KEY_NEGOTIATION_NONCE_LEN],
            &challenge(),
            CLIENT_WG_KEY,
            GATEWAY_WG_KEY,
        )
        .unwrap();
        assert_eq!(first.len(), 64);
        assert!(!first.contains(&psk));

        // Chaque composante du contexte, changée seule, change l'engagement.
        let other_transaction = static_psk_commitment(
            &psk,
            &[9; KEY_NEGOTIATION_NONCE_LEN],
            &[2; KEY_NEGOTIATION_NONCE_LEN],
            &challenge(),
            CLIENT_WG_KEY,
            GATEWAY_WG_KEY,
        )
        .unwrap();
        let other_challenge = static_psk_commitment(
            &psk,
            &[1; KEY_NEGOTIATION_NONCE_LEN],
            &[2; KEY_NEGOTIATION_NONCE_LEN],
            &[6; SERVER_CHALLENGE_LEN],
            CLIENT_WG_KEY,
            GATEWAY_WG_KEY,
        )
        .unwrap();
        let other_gateway = static_psk_commitment(
            &psk,
            &[1; KEY_NEGOTIATION_NONCE_LEN],
            &[2; KEY_NEGOTIATION_NONCE_LEN],
            &challenge(),
            CLIENT_WG_KEY,
            CLIENT_WG_KEY,
        )
        .unwrap();
        for different in [&other_transaction, &other_challenge, &other_gateway] {
            assert_ne!(&first, different);
        }

        // Le même contexte et le même PSK se recalculent à l'identique : c'est
        // ce qui permet à la gateway de vérifier.
        assert!(commitments_match(
            &first,
            &static_psk_commitment(
                &psk,
                &[1; KEY_NEGOTIATION_NONCE_LEN],
                &[2; KEY_NEGOTIATION_NONCE_LEN],
                &challenge(),
                CLIENT_WG_KEY,
                GATEWAY_WG_KEY,
            )
            .unwrap()
        ));
        assert!(!commitments_match(&first, &other_transaction));
    }

    /// Un PSK statique fait exactement 32 octets : ni 31, ni 33, ni une phrase.
    #[test]
    fn a_static_psk_is_exactly_thirty_two_bytes() {
        validate_static_psk(&STANDARD.encode([7u8; STATIC_PSK_LEN])).unwrap();
        for wrong in [
            STANDARD.encode([7u8; 31]),
            STANDARD.encode([7u8; 33]),
            STANDARD.encode(b"correct horse battery staple"),
            "not-base64!".to_string(),
            String::new(),
        ] {
            assert_eq!(
                validate_static_psk(&wrong).map(|_| ()),
                Err(KeyNegotiationError::InvalidStaticPsk),
                "{wrong} ne doit pas passer pour un PSK"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = format!(
            r#"{{
                "protocol_version":5,
                "server_challenge":[{challenge}],
                "transaction_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "mode":"classic",
                "client_wg_public_key":"{CLIENT_WG_KEY}",
                "gateway_wg_public_key":"{GATEWAY_WG_KEY}",
                "server_name":"{SERVER_NAME}",
                "gateway_certificate_fingerprint":"{GATEWAY_FINGERPRINT}",
                "client_nonce":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "timestamp_unix":1,
                "kem_public_key":null,
                "static_psk_commitment":null,
                "ignored":"downgrade"
            }}"#,
            challenge = vec!["5"; SERVER_CHALLENGE_LEN].join(",")
        );
        assert!(serde_json::from_str::<KeyNegotiationRequest>(&json).is_err());
    }

    #[test]
    fn protection_floor_is_monotone() {
        assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::Classic));
        assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::StaticPsk));
        assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::MlKem));
        assert!(!ProtectionMode::Classic.satisfies(ProtectionMode::StaticPsk));
        assert!(!ProtectionMode::Classic.satisfies(ProtectionMode::MlKem));
        assert!(!ProtectionMode::StaticPsk.satisfies(ProtectionMode::MlKem));
    }

    #[cfg(feature = "key-negotiation-signing")]
    fn pq_certificate(
        role: PqCertificateRole,
        subject: &str,
        wireguard_key: &str,
        subject_public_key: &[u8],
        issuer_private_key: &[u8],
    ) -> PqCertificate {
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [7; 16],
                subject: subject.into(),
                issuer: "test-ca".into(),
                role,
                wireguard_public_key: wireguard_key.into(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            issuer_private_key,
        )
        .unwrap()
    }

    /// Le pire cas ML-DSA-87 doit tenir sous la borne de trame — vérifié, pas
    /// déduit d'un calcul au dos d'une enveloppe.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn the_worst_case_frame_fits_the_bound() {
        let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(vec![0xff; crate::pq::PUBLIC_KEY_LEN]);
        let authenticated =
            authenticate_request(plain, certificate, client_private.as_slice()).unwrap();
        let encoded = serde_json::to_vec(&authenticated).unwrap();
        assert!(
            encoded.len() < MAX_KEY_NEGOTIATION_MESSAGE_BYTES,
            "la requête ml_kem pèse {} octets, borne {MAX_KEY_NEGOTIATION_MESSAGE_BYTES}",
            encoded.len()
        );
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn editing_the_timestamp_breaks_pq_authentication() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let fingerprint = certificate.fingerprint().unwrap();
        let mut authenticated = authenticate_request(
            request(ProtectionMode::StaticPsk),
            certificate,
            client_private.as_slice(),
        )
        .unwrap();
        authenticated
            .verify(&ca_public, &fingerprint, test_now())
            .unwrap();

        authenticated.request.timestamp_unix += 1;
        assert_eq!(
            authenticated.verify(&ca_public, &fingerprint, test_now()),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }

    /// La liaison à la gateway est **signée** : la retoucher pour viser une
    /// autre gateway invalide la requête avant toute pose de slot.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn retargeting_a_request_to_another_gateway_breaks_its_signature() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let fingerprint = certificate.fingerprint().unwrap();
        let authenticated = authenticate_request(
            request(ProtectionMode::StaticPsk),
            certificate,
            client_private.as_slice(),
        )
        .unwrap();
        authenticated
            .verify(&ca_public, &fingerprint, test_now())
            .unwrap();

        for retarget in [
            |r: &mut KeyNegotiationRequest| r.server_name = "other.example".into(),
            |r: &mut KeyNegotiationRequest| r.gateway_wg_public_key = CLIENT_WG_KEY.into(),
            |r: &mut KeyNegotiationRequest| r.gateway_certificate_fingerprint = "2".repeat(64),
        ] {
            let mut tampered = authenticated.clone();
            retarget(&mut tampered.request);
            assert_eq!(
                tampered.verify(&ca_public, &fingerprint, test_now()),
                Err(KeyNegotiationError::InvalidPqProtocolSignature)
            );
        }
    }

    /// Le challenge est signé : le remplacer par un autre, même valide
    /// ailleurs, invalide la requête.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn substituting_the_challenge_breaks_pq_authentication() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let fingerprint = certificate.fingerprint().unwrap();
        let mut authenticated = authenticate_request(
            request(ProtectionMode::StaticPsk),
            certificate,
            client_private.as_slice(),
        )
        .unwrap();
        authenticated.request.server_challenge[0] ^= 1;
        assert_eq!(
            authenticated.verify(&ca_public, &fingerprint, test_now()),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn substituting_the_ml_kem_public_key_breaks_pq_authentication() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let fingerprint = certificate.fingerprint().unwrap();
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(vec![3; crate::pq::PUBLIC_KEY_LEN]);
        let mut authenticated =
            authenticate_request(plain, certificate, client_private.as_slice()).unwrap();
        authenticated
            .verify(&ca_public, &fingerprint, test_now())
            .unwrap();

        authenticated.request.kem_public_key.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            authenticated.verify(&ca_public, &fingerprint, test_now()),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn substituting_the_ml_kem_ciphertext_breaks_gateway_authentication() {
        let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Gateway,
            SERVER_NAME,
            GATEWAY_WG_KEY,
            &gateway_public,
            gateway_private.as_slice(),
        );
        let mut plain = request(ProtectionMode::MlKem);
        plain.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
        let mut answer = response(&plain, ProtectionMode::MlKem);
        answer.kem_ciphertext = Some(vec![5; crate::pq::CIPHERTEXT_LEN]);
        let mut authenticated =
            authenticate_response(answer, certificate.clone(), gateway_private.as_slice()).unwrap();
        authenticated
            .verify(&plain, &certificate, SERVER_NAME, GATEWAY_WG_KEY, 100)
            .unwrap();

        authenticated.response.kem_ciphertext.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            authenticated.verify(&plain, &certificate, SERVER_NAME, GATEWAY_WG_KEY, 100),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }

    /// Le `release` suit le même chemin d'authentification qu'une requête, et
    /// son accusé est signé : la gateway ne fait aucune affirmation non signée
    /// sur l'état d'un slot.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_release_and_its_acknowledgment_are_both_authenticated() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
        let client_certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let gateway_certificate = pq_certificate(
            PqCertificateRole::Gateway,
            SERVER_NAME,
            GATEWAY_WG_KEY,
            &gateway_public,
            gateway_private.as_slice(),
        );
        let fingerprint = client_certificate.fingerprint().unwrap();

        let release = PskRelease {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: challenge(),
            installed_transaction_id: [4; KEY_NEGOTIATION_NONCE_LEN],
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            timestamp_unix: test_now(),
        };
        let mut authenticated = authenticate_release(
            release.clone(),
            client_certificate,
            client_private.as_slice(),
        )
        .unwrap();
        authenticated
            .verify(&ca_public, &fingerprint, test_now())
            .unwrap();

        // Rediriger un release vers une autre transaction casse sa signature.
        authenticated.release.installed_transaction_id[0] ^= 1;
        assert_eq!(
            authenticated.verify(&ca_public, &fingerprint, test_now()),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );

        let acknowledged = authenticate_released(
            PskReleased {
                protocol_version: KEY_NEGOTIATION_VERSION,
                server_challenge: release.server_challenge,
                installed_transaction_id: release.installed_transaction_id,
            },
            gateway_certificate.clone(),
            gateway_private.as_slice(),
        )
        .unwrap();
        acknowledged.verify(&release, &gateway_certificate).unwrap();

        let mut forged = acknowledged;
        forged.released.installed_transaction_id[0] ^= 1;
        assert_eq!(
            forged.verify(&release, &gateway_certificate),
            Err(KeyNegotiationError::TransactionMismatch)
        );
    }

    /// Un certificat v1 (ML-DSA-65) n'est pas lu comme un certificat v5 : la
    /// migration réémet, elle ne tolère pas.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_version_one_certificate_is_refused() {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (_, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let mut certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        certificate.version = 1;
        assert_eq!(
            certificate.verify(
                &ca_public,
                PqCertificateRole::Client,
                None,
                CLIENT_WG_KEY,
                test_now()
            ),
            Err(KeyNegotiationError::InvalidPqCertificate)
        );
    }
}
