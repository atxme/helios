//! Versioned contract for pre-WireGuard key negotiation.
//!
//! The negotiation runs on a dedicated UDP/QUIC port before the WireGuard
//! handshake. TLS authenticates the peer certificates; this module binds the
//! selected mode, transaction, nonces and WireGuard identities into the PSK.
//! A transcript cannot therefore be replayed for another peer or downgraded
//! from ML-KEM to classic mode.

use aws_lc_rs::{digest, hkdf};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fips204::{
    ml_dsa_65::{self, PublicKey},
    traits::{SerDes, Verifier},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pq::SharedSecret;

/// Default UDP port of the key-negotiation service.
pub const DEFAULT_KEY_NEGOTIATION_PORT: u16 = 51821;
/// Current wire protocol version.
pub const KEY_NEGOTIATION_VERSION: u16 = 4;
/// Upper bound for one framed protocol message.
pub const MAX_KEY_NEGOTIATION_MESSAGE_BYTES: usize = 64 * 1024;
/// Length of transaction identifiers and nonces.
pub const KEY_NEGOTIATION_NONCE_LEN: usize = 16;

const KEY_NEGOTIATION_DOMAIN: &[u8] = b"helios-key-negotiation-psk-v4";
const PQ_CERTIFICATE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-certificate-v1";
const PQ_REQUEST_DOMAIN: &[u8] = b"helios-key-negotiation-pq-request-v4";
const PQ_RESPONSE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-response-v4";
const PQ_CONFIRMATION_DOMAIN: &[u8] = b"helios-key-negotiation-pq-confirmation-v4";
const PQ_COMMIT_DOMAIN: &[u8] = b"helios-key-negotiation-pq-commit-v4";
pub const PQ_CERTIFICATE_VERSION: u16 = 1;

/// Protection selected by Orion for the upcoming WireGuard session.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    /// WireGuard Curve25519 without a preshared key.
    #[default]
    Classic,
    /// A preconfigured PSK identified by its fingerprint.
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

/// Application-level ML-DSA-65 certificate.
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
    /// Base64-encoded ML-DSA-65 subject public key.
    pub ml_dsa_65_public_key: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    /// Base64-encoded ML-DSA-65 issuer signature.
    pub ml_dsa_65_signature: String,
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
        let subject_public_key = decode_exact::<{ ml_dsa_65::PK_LEN }>(
            &self.ml_dsa_65_public_key,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        PublicKey::try_from_bytes(subject_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let issuer_public_key = <[u8; ml_dsa_65::PK_LEN]>::try_from(issuer_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let issuer_public_key = PublicKey::try_from_bytes(issuer_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        let signature = decode_exact::<{ ml_dsa_65::SIG_LEN }>(
            &self.ml_dsa_65_signature,
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
            .decode(&self.ml_dsa_65_public_key)
            .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
        self.verify(
            &public_key,
            expected_role,
            expected_subject,
            expected_wireguard_public_key,
            now_unix,
        )
    }

    pub fn fingerprint(&self) -> Result<String, KeyNegotiationError> {
        let mut encoded = pq_certificate_signing_bytes(self)?;
        let signature = decode_exact::<{ ml_dsa_65::SIG_LEN }>(
            &self.ml_dsa_65_signature,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        append_bytes(&mut encoded, &signature)?;
        Ok(hex::encode(digest::digest(&digest::SHA256, &encoded)))
    }

    fn legacy_json_fingerprint(&self) -> Result<String, KeyNegotiationError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| KeyNegotiationError::CanonicalEncoding)?;
        Ok(hex::encode(digest::digest(&digest::SHA256, &encoded)))
    }
}

/// Request plus a PQ certificate and a signature covering its KEM public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationRequest {
    pub request: KeyNegotiationRequest,
    pub certificate: PqCertificate,
    /// Base64-encoded ML-DSA-65 signature.
    pub ml_dsa_65_signature: String,
}

impl AuthenticatedKeyNegotiationRequest {
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
        if self.certificate.fingerprint()? != expected_certificate_fingerprint
            && self.certificate.legacy_json_fingerprint()? != expected_certificate_fingerprint
        {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_65_public_key,
            &pq_request_signing_bytes(&self.request, &self.certificate)?,
            &self.ml_dsa_65_signature,
        )
    }
}

/// Response signed by the gateway's PQ identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationResponse {
    pub response: KeyNegotiationResponse,
    pub certificate: PqCertificate,
    /// Base64-encoded ML-DSA-65 signature.
    pub ml_dsa_65_signature: String,
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
            &self.certificate.ml_dsa_65_public_key,
            &pq_response_signing_bytes(&self.response, &self.certificate)?,
            &self.ml_dsa_65_signature,
        )
    }
}

/// First application message sent by Orion over authenticated QUIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyNegotiationRequest {
    pub protocol_version: u16,
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub mode: ProtectionMode,
    /// WireGuard identity bound to the authenticated client certificate.
    pub client_wg_public_key: String,
    pub client_nonce: [u8; KEY_NEGOTIATION_NONCE_LEN],
    /// Unix time at which the client signed this request.
    ///
    /// Covered by the ML-DSA signature and by the PSK derivation. The signature
    /// prevents an active transport attacker from refreshing a captured
    /// request. The freshness check limits an unchanged replay to the accepted
    /// clock window; the transaction cache rejects duplicates in that window.
    pub timestamp_unix: u64,
    /// ML-KEM-1024 encapsulation key. Present only in `ml_kem` mode.
    pub kem_public_key: Option<Vec<u8>>,
    /// Lowercase SHA-256 fingerprint. Present only in `static_psk` mode.
    pub static_psk_fingerprint: Option<String>,
}

/// Accepted drift between the client's clock and the gateway's.
///
/// Thirty seconds each way: wide enough for hosts synchronised by NTP over a
/// slow link, narrow enough that a captured request stops being replayable
/// long before an attacker could exhaust the anti-replay cache.
///
/// A client whose clock is off by more is refused with a message that says so
/// — an unexplained refusal here would be diagnosed as anything but a clock.
pub const MAX_REQUEST_CLOCK_SKEW_SECS: u64 = 30;

impl KeyNegotiationRequest {
    /// Rejects ambiguous mode payloads before any cryptographic operation.
    pub fn validate(&self) -> Result<(), KeyNegotiationError> {
        if self.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
        }
        crate::wg::validate_key(&self.client_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        if self.transaction_id.iter().all(|byte| *byte == 0) {
            return Err(KeyNegotiationError::ZeroTransaction);
        }
        if self.timestamp_unix == 0 {
            return Err(KeyNegotiationError::MissingTimestamp);
        }

        match self.mode {
            ProtectionMode::Classic => {
                if self.kem_public_key.is_some() || self.static_psk_fingerprint.is_some() {
                    return Err(KeyNegotiationError::UnexpectedModeMaterial);
                }
            }
            ProtectionMode::StaticPsk => {
                if self.kem_public_key.is_some() {
                    return Err(KeyNegotiationError::UnexpectedModeMaterial);
                }
                let fingerprint = self
                    .static_psk_fingerprint
                    .as_deref()
                    .ok_or(KeyNegotiationError::MissingStaticPskFingerprint)?;
                validate_fingerprint(fingerprint)?;
            }
            ProtectionMode::MlKem => {
                if self.static_psk_fingerprint.is_some() {
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

    /// Rejects a request whose clock is too far from the verifier's.
    ///
    /// Bounds replay **in time**, where the anti-replay cache bounds it in
    /// count. The two are complementary and neither replaces the other: the
    /// cache stops an immediate replay of a live transaction, this stops the
    /// replay of a transaction captured long ago — including after an
    /// attacker has flushed the cache with traffic of its own.
    ///
    /// Symmetric: a request from the future is as suspect as one from the
    /// past, and accepting it would let an attacker bank a transaction for
    /// later.
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
    pub selected_mode: ProtectionMode,
    pub gateway_wg_public_key: String,
    pub gateway_nonce: [u8; KEY_NEGOTIATION_NONCE_LEN],
    /// ML-KEM ciphertext. Present only in `ml_kem` mode.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// Time allowed for a confirming WireGuard handshake.
    pub confirmation_timeout_secs: u32,
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
        if self.selected_mode != request.mode {
            return Err(KeyNegotiationError::ModeDowngrade);
        }
        if self.gateway_wg_public_key != expected_gateway_key {
            return Err(KeyNegotiationError::GatewayIdentityMismatch);
        }
        crate::wg::validate_key(&self.gateway_wg_public_key)
            .map_err(|_| KeyNegotiationError::InvalidWireGuardKey)?;
        if self.confirmation_timeout_secs == 0 {
            return Err(KeyNegotiationError::InvalidConfirmationTimeout);
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
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationConfirmation {
    pub confirmation: KeyNegotiationConfirmation,
    pub ml_dsa_65_signature: String,
}

impl AuthenticatedKeyNegotiationConfirmation {
    pub fn verify(&self, client_public_key: &str) -> Result<(), KeyNegotiationError> {
        verify_protocol_signature(
            client_public_key,
            &pq_transaction_signing_bytes(
                PQ_CONFIRMATION_DOMAIN,
                self.confirmation.protocol_version,
                self.confirmation.transaction_id,
            ),
            &self.ml_dsa_65_signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedKeyNegotiationCommit {
    pub protocol_version: u16,
    pub transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub ml_dsa_65_signature: String,
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
                self.transaction_id,
            ),
            &self.ml_dsa_65_signature,
        )
    }
}

/// Derives the WireGuard PSK while binding the complete negotiation context.
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

pub fn derive_negotiated_psk(
    shared_secret: &SharedSecret,
    request: &KeyNegotiationRequest,
    response: &KeyNegotiationResponse,
) -> Result<Zeroizing<[u8; 32]>, KeyNegotiationError> {
    if request.mode != ProtectionMode::MlKem || response.selected_mode != ProtectionMode::MlKem {
        return Err(KeyNegotiationError::PskDerivationOutsideMlKem);
    }
    response.validate_for(request, &response.gateway_wg_public_key)?;

    let mut salt = Vec::with_capacity(KEY_NEGOTIATION_NONCE_LEN * 3);
    salt.extend_from_slice(&request.transaction_id);
    salt.extend_from_slice(&request.client_nonce);
    salt.extend_from_slice(&response.gateway_nonce);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, &salt);
    let prk = salt.extract(shared_secret.as_slice());

    let client = request.client_wg_public_key.as_bytes();
    let gateway = response.gateway_wg_public_key.as_bytes();
    let client_len = (client.len() as u16).to_be_bytes();
    let gateway_len = (gateway.len() as u16).to_be_bytes();
    let mode = [request.mode.security_level()];
    let version = request.protocol_version.to_be_bytes();
    // The timestamp is bound in: a request replayed with an edited clock would
    // derive a different PSK, so the transcript cannot be reused in time any
    // more than it can across peers.
    let timestamp = request.timestamp_unix.to_be_bytes();
    // Both WireGuard keys are length-prefixed: no two field boundaries can be
    // shifted to produce the same concatenation.
    let info: [&[u8]; 8] = [
        KEY_NEGOTIATION_DOMAIN,
        &version,
        &mode,
        &timestamp,
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
    let mut psk = Zeroizing::new([0u8; 32]);
    okm.fill(psk.as_mut_slice())
        .map_err(|_| KeyNegotiationError::Kdf)?;
    Ok(psk)
}

/// Stable non-secret identifier for a 32-byte base64 WireGuard PSK.
pub fn static_psk_fingerprint(psk_base64: &str) -> Result<String, KeyNegotiationError> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(psk_base64.trim())
        .map_err(|_| KeyNegotiationError::InvalidStaticPsk)?;
    if decoded.len() != 32 {
        return Err(KeyNegotiationError::InvalidStaticPsk);
    }
    Ok(hex::encode(
        digest::digest(&digest::SHA256, &decoded).as_ref(),
    ))
}

fn validate_fingerprint(value: &str) -> Result<(), KeyNegotiationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(KeyNegotiationError::InvalidStaticPskFingerprint);
    }
    Ok(())
}

/// Validates the canonical SHA-256 form used to bind a certificate to a peer.
pub fn validate_certificate_fingerprint(value: &str) -> Result<(), KeyNegotiationError> {
    validate_fingerprint(value)
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
        .decode(&certificate.ml_dsa_65_public_key)
        .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
    if public_key.len() != ml_dsa_65::PK_LEN {
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
    output.extend_from_slice(&request.transaction_id);
    output.push(request.mode.security_level());
    append_bytes(&mut output, request.client_wg_public_key.as_bytes())?;
    output.extend_from_slice(&request.client_nonce);
    output.extend_from_slice(&request.timestamp_unix.to_be_bytes());
    append_optional_bytes(&mut output, request.kem_public_key.as_deref())?;
    append_optional_bytes(
        &mut output,
        request.static_psk_fingerprint.as_deref().map(str::as_bytes),
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
    output.push(response.selected_mode.security_level());
    append_bytes(&mut output, response.gateway_wg_public_key.as_bytes())?;
    output.extend_from_slice(&response.gateway_nonce);
    append_optional_bytes(&mut output, response.kem_ciphertext.as_deref())?;
    output.extend_from_slice(&response.confirmation_timeout_secs.to_be_bytes());
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

fn pq_transaction_signing_bytes(
    domain: &[u8],
    protocol_version: u16,
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 2 + transaction_id.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(&protocol_version.to_be_bytes());
    output.extend_from_slice(&transaction_id);
    output
}

fn verify_protocol_signature(
    public_key: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), KeyNegotiationError> {
    let public_key = decode_exact::<{ ml_dsa_65::PK_LEN }>(
        public_key,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    let public_key = PublicKey::try_from_bytes(public_key)
        .map_err(|_| KeyNegotiationError::InvalidPqProtocolSignature)?;
    let signature = decode_exact::<{ ml_dsa_65::SIG_LEN }>(
        signature,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    if !public_key.verify(message, &signature, &[]) {
        return Err(KeyNegotiationError::InvalidPqProtocolSignature);
    }
    Ok(())
}

#[cfg(feature = "key-negotiation-signing")]
fn sign_ml_dsa_65(private_key: &[u8], message: &[u8]) -> Result<String, KeyNegotiationError> {
    use fips204::{
        ml_dsa_65::PrivateKey,
        traits::{SerDes as _, Signer as _},
    };

    let private_key = <[u8; ml_dsa_65::SK_LEN]>::try_from(private_key)
        .map_err(|_| KeyNegotiationError::InvalidPqPrivateKey)?;
    let private_key = PrivateKey::try_from_bytes(private_key)
        .map_err(|_| KeyNegotiationError::InvalidPqPrivateKey)?;
    let signature = private_key
        .try_sign(message, &[])
        .map_err(|_| KeyNegotiationError::PqSigning)?;
    Ok(STANDARD.encode(signature))
}

/// Generates an ML-DSA-65 identity. The private half is zeroized on drop.
#[cfg(feature = "key-negotiation-signing")]
pub fn generate_ml_dsa_65_keypair() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), KeyNegotiationError> {
    use fips204::traits::SerDes as _;

    let (public_key, private_key) =
        ml_dsa_65::try_keygen().map_err(|_| KeyNegotiationError::PqSigning)?;
    Ok((
        Zeroizing::new(private_key.into_bytes().to_vec()),
        public_key.into_bytes().to_vec(),
    ))
}

/// Signs a new PQ certificate with an ML-DSA-65 issuer key.
#[cfg(feature = "key-negotiation-signing")]
pub fn issue_pq_certificate(
    mut certificate: PqCertificate,
    issuer_private_key: &[u8],
) -> Result<PqCertificate, KeyNegotiationError> {
    certificate.ml_dsa_65_signature.clear();
    certificate.ml_dsa_65_signature = sign_ml_dsa_65(
        issuer_private_key,
        &pq_certificate_signing_bytes(&certificate)?,
    )?;
    Ok(certificate)
}

/// Signs an Orion request, including its ephemeral ML-KEM public key.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_request(
    request: KeyNegotiationRequest,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationRequest, KeyNegotiationError> {
    request.validate()?;
    let signature = sign_ml_dsa_65(
        subject_private_key,
        &pq_request_signing_bytes(&request, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationRequest {
        request,
        certificate,
        ml_dsa_65_signature: signature,
    })
}

/// Signs the Helios response containing the ML-KEM ciphertext.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_response(
    response: KeyNegotiationResponse,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationResponse, KeyNegotiationError> {
    let signature = sign_ml_dsa_65(
        subject_private_key,
        &pq_response_signing_bytes(&response, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationResponse {
        response,
        certificate,
        ml_dsa_65_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_confirmation(
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    client_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationConfirmation, KeyNegotiationError> {
    let confirmation = KeyNegotiationConfirmation {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id,
    };
    let signature = sign_ml_dsa_65(
        client_private_key,
        &pq_transaction_signing_bytes(
            PQ_CONFIRMATION_DOMAIN,
            confirmation.protocol_version,
            confirmation.transaction_id,
        ),
    )?;
    Ok(AuthenticatedKeyNegotiationConfirmation {
        confirmation,
        ml_dsa_65_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_commit(
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    gateway_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationCommit, KeyNegotiationError> {
    let protocol_version = KEY_NEGOTIATION_VERSION;
    let signature = sign_ml_dsa_65(
        gateway_private_key,
        &pq_transaction_signing_bytes(PQ_COMMIT_DOMAIN, protocol_version, transaction_id),
    )?;
    Ok(AuthenticatedKeyNegotiationCommit {
        protocol_version,
        transaction_id,
        ml_dsa_65_signature: signature,
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
    #[error("static PSK fingerprint is missing")]
    MissingStaticPskFingerprint,
    #[error("static PSK fingerprint must be a lowercase SHA-256 hexadecimal value")]
    InvalidStaticPskFingerprint,
    #[error("static PSK is not a 32-byte base64 WireGuard key")]
    InvalidStaticPsk,
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
    #[error("gateway WireGuard identity does not match the profile")]
    GatewayIdentityMismatch,
    #[error("confirmation timeout must be positive")]
    InvalidConfirmationTimeout,
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

    /// Horloge des tests : les requêtes doivent être fraîches pour passer la
    /// fenêtre anti-rejeu.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Le cache anti-rejeu est borné, donc évinçable : un attaquant capable de
    /// le remplir ferait oublier un vieil identifiant et rejouerait la
    /// transaction correspondante. Une horloge, elle, ne s'évince pas.
    #[test]
    fn a_request_outside_the_clock_window_is_refused() {
        let now = test_now();
        let fresh = KeyNegotiationRequest {
            timestamp_unix: now,
            ..request(ProtectionMode::Classic)
        };
        assert!(fresh.assert_fresh(now).is_ok());

        // Aux bornes exactes : accepté, la tolérance est inclusive.
        assert!(fresh
            .assert_fresh(now + MAX_REQUEST_CLOCK_SKEW_SECS)
            .is_ok());
        assert!(fresh
            .assert_fresh(now - MAX_REQUEST_CLOCK_SKEW_SECS)
            .is_ok());

        // Au-delà, dans les deux sens : une requête venue du futur est aussi
        // suspecte qu'une vieille, et l'accepter permettrait d'en mettre une
        // de côté pour plus tard.
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

        // Un horodatage absent ne doit pas passer pour l'époque Unix.
        let undated = KeyNegotiationRequest {
            timestamp_unix: 0,
            ..request(ProtectionMode::Classic)
        };
        assert_eq!(
            undated.validate(),
            Err(KeyNegotiationError::MissingTimestamp)
        );
    }

    /// L'horodatage entre dans la dérivation : une transcription rejouée avec
    /// une horloge retouchée ne peut pas produire le même PSK.
    #[test]
    fn the_timestamp_is_bound_into_the_derived_psk() {
        let (secret_key, public_key) = MlKem1024Kem::generate().unwrap();
        let mut request = request(ProtectionMode::MlKem);
        request.kem_public_key = Some(public_key);
        let (ciphertext, gateway_secret) =
            MlKem1024Kem::encapsulate(request.kem_public_key.as_ref().unwrap()).unwrap();
        let response = KeyNegotiationResponse {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: request.transaction_id,
            selected_mode: ProtectionMode::MlKem,
            gateway_wg_public_key: GATEWAY_WG_KEY.to_string(),
            gateway_nonce: [9; KEY_NEGOTIATION_NONCE_LEN],
            kem_ciphertext: Some(ciphertext.clone()),
            confirmation_timeout_secs: 180,
        };

        let client_secret = MlKem1024Kem::decapsulate(&secret_key, &ciphertext).unwrap();
        let reference = derive_negotiated_psk(&gateway_secret, &request, &response).unwrap();
        assert_eq!(
            *reference,
            *derive_negotiated_psk(&client_secret, &request, &response).unwrap(),
            "les deux bouts doivent dériver le même PSK"
        );
        assert_eq!(reference.len(), 32, "un slot PresharedKey fait 32 octets");

        let replayed = KeyNegotiationRequest {
            timestamp_unix: request.timestamp_unix + 1,
            ..request.clone()
        };
        assert_ne!(
            *reference,
            *derive_negotiated_psk(&gateway_secret, &replayed, &response).unwrap(),
            "changer l'horodatage doit changer le PSK"
        );
    }

    use crate::pq::{Kem, MlKem1024Kem};

    const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn request(mode: ProtectionMode) -> KeyNegotiationRequest {
        KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: [1; KEY_NEGOTIATION_NONCE_LEN],
            mode,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            client_nonce: [2; KEY_NEGOTIATION_NONCE_LEN],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: None,
        }
    }

    #[test]
    fn each_mode_rejects_material_from_another_mode() {
        let mut classic = request(ProtectionMode::Classic);
        classic.static_psk_fingerprint = Some("a".repeat(64));
        assert_eq!(
            classic.validate(),
            Err(KeyNegotiationError::UnexpectedModeMaterial)
        );

        let mut static_psk = request(ProtectionMode::StaticPsk);
        static_psk.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);
        assert_eq!(
            static_psk.validate(),
            Err(KeyNegotiationError::UnexpectedModeMaterial)
        );

        let mut ml_kem = request(ProtectionMode::MlKem);
        ml_kem.static_psk_fingerprint = Some("a".repeat(64));
        assert_eq!(
            ml_kem.validate(),
            Err(KeyNegotiationError::UnexpectedModeMaterial)
        );
    }

    #[test]
    fn response_refuses_mode_downgrade_and_transaction_replay() {
        let mut request = request(ProtectionMode::MlKem);
        request.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);
        let mut response = KeyNegotiationResponse {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: request.transaction_id,
            selected_mode: ProtectionMode::Classic,
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
            kem_ciphertext: None,
            confirmation_timeout_secs: 180,
        };
        assert_eq!(
            response.validate_for(&request, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::ModeDowngrade)
        );

        response.selected_mode = ProtectionMode::MlKem;
        response.transaction_id = [9; KEY_NEGOTIATION_NONCE_LEN];
        response.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
        assert_eq!(
            response.validate_for(&request, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::TransactionMismatch)
        );
    }

    #[test]
    fn ml_kem_round_trip_derives_the_same_context_bound_psk() {
        let (secret_key, public_key) = MlKem1024Kem::generate().unwrap();
        let (ciphertext, server_secret) = MlKem1024Kem::encapsulate(&public_key).unwrap();
        let client_secret = MlKem1024Kem::decapsulate(&secret_key, &ciphertext).unwrap();

        let mut request = request(ProtectionMode::MlKem);
        request.kem_public_key = Some(public_key);
        request.validate().unwrap();
        let response = KeyNegotiationResponse {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: request.transaction_id,
            selected_mode: ProtectionMode::MlKem,
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
            kem_ciphertext: Some(ciphertext),
            confirmation_timeout_secs: 180,
        };
        response.validate_for(&request, GATEWAY_WG_KEY).unwrap();

        let server_psk = derive_negotiated_psk(&server_secret, &request, &response).unwrap();
        let client_psk = derive_negotiated_psk(&client_secret, &request, &response).unwrap();
        assert_eq!(*server_psk, *client_psk);

        request.transaction_id[0] ^= 1;
        let rebound = KeyNegotiationResponse {
            transaction_id: request.transaction_id,
            ..response
        };
        let other = derive_negotiated_psk(&client_secret, &request, &rebound).unwrap();
        assert_ne!(*client_psk, *other);
    }

    #[test]
    fn static_psk_fingerprint_is_strict_and_non_secret() {
        let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fingerprint = static_psk_fingerprint(&psk).unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(!fingerprint.contains(&psk));
        assert_eq!(
            static_psk_fingerprint("not-a-key"),
            Err(KeyNegotiationError::InvalidStaticPsk)
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = format!(
            r#"{{
                "protocol_version":1,
                "transaction_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "mode":"classic",
                "client_wg_public_key":"{CLIENT_WG_KEY}",
                "client_nonce":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "kem_public_key":null,
                "static_psk_fingerprint":null,
                "ignored":"downgrade"
            }}"#
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
                ml_dsa_65_public_key: STANDARD.encode(subject_public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_65_signature: String::new(),
            },
            issuer_private_key,
        )
        .unwrap()
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn editing_the_timestamp_breaks_pq_authentication() {
        let (ca_private, ca_public) = generate_ml_dsa_65_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_65_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let fingerprint = certificate.fingerprint().unwrap();
        let mut authenticated = authenticate_request(
            request(ProtectionMode::Classic),
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

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn legacy_json_certificate_fingerprints_remain_admitted() {
        let (ca_private, ca_public) = generate_ml_dsa_65_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_65_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Client,
            "orion",
            CLIENT_WG_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let legacy_fingerprint = certificate.legacy_json_fingerprint().unwrap();
        assert_ne!(certificate.fingerprint().unwrap(), legacy_fingerprint);
        let authenticated = authenticate_request(
            request(ProtectionMode::Classic),
            certificate,
            client_private.as_slice(),
        )
        .unwrap();

        authenticated
            .verify(&ca_public, &legacy_fingerprint, test_now())
            .unwrap();
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn substituting_the_ml_kem_public_key_breaks_pq_authentication() {
        let (ca_private, ca_public) = generate_ml_dsa_65_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_65_keypair().unwrap();
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
        let (gateway_private, gateway_public) = generate_ml_dsa_65_keypair().unwrap();
        let certificate = pq_certificate(
            PqCertificateRole::Gateway,
            "gateway.example",
            GATEWAY_WG_KEY,
            &gateway_public,
            gateway_private.as_slice(),
        );
        let mut request = request(ProtectionMode::MlKem);
        request.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
        let response = KeyNegotiationResponse {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: request.transaction_id,
            selected_mode: ProtectionMode::MlKem,
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
            kem_ciphertext: Some(vec![5; crate::pq::CIPHERTEXT_LEN]),
            confirmation_timeout_secs: 180,
        };
        let mut authenticated =
            authenticate_response(response, certificate.clone(), gateway_private.as_slice())
                .unwrap();
        authenticated
            .verify(
                &request,
                &certificate,
                "gateway.example",
                GATEWAY_WG_KEY,
                100,
            )
            .unwrap();

        authenticated.response.kem_ciphertext.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            authenticated.verify(
                &request,
                &certificate,
                "gateway.example",
                GATEWAY_WG_KEY,
                100,
            ),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }
}
