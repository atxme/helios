//! The wire types of negotiation v5: certificates, challenge, request,
//! response, confirmation, commit and release, with their validation.

use super::*;

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
    pub(super) const fn domain_byte(self) -> u8 {
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
        let signature = decode_exact::<{ ml_dsa_87::SIG_LEN }>(
            &self.ml_dsa_87_signature,
            KeyNegotiationError::InvalidPqCertificate,
        )?;
        crate::ml_dsa::verify(
            issuer_public_key,
            signing_context(PQ_CERTIFICATE_DOMAIN)?,
            &pq_certificate_signing_bytes(self)?,
            &signature,
        )
        // A malformed issuer key is a malformed certificate, not a signature
        // that failed to verify: the two send an operator looking in different
        // places, even though the public port collapses both to `rejected`.
        .map_err(|error| match error {
            crate::ml_dsa::MlDsaError::InvalidPublicKey => {
                KeyNegotiationError::InvalidPqCertificate
            }
            _ => KeyNegotiationError::InvalidPqCertificateSignature,
        })
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
        self.verify_against(
            &[issuer_public_key],
            &[expected_certificate_fingerprint],
            now_unix,
        )
    }

    /// The same verification, against every identity the gateway currently
    /// admits for this peer.
    ///
    /// # Why a set and not one value
    ///
    /// A client that renews is, for the length of its overlap, two identities:
    /// the outgoing generation and the incoming one. And once the delegated
    /// issuer of ADR-008 §3.4 is installed, the incoming leaf is signed by
    /// that issuer rather than by the anchor the outgoing one chains to. A
    /// gateway holding a single fingerprint and a single issuer therefore
    /// locks out every client it has just renewed — at the end of the overlap,
    /// on a machine whose only way to ask for help was the tunnel it can no
    /// longer open.
    ///
    /// # Why the fingerprint decides first
    ///
    /// The digest is a hash; each issuer trial is an ML-DSA-87 verification.
    /// Matching the fingerprint first pins **which** generation is being
    /// claimed before any signature work is spent, so a caller presenting a
    /// certificate this gateway never issued buys a hash and nothing more.
    /// It also keeps the pair unmixed: the accepted fingerprint names one
    /// generation, and the issuers are the domain's, not that generation's
    /// claim about itself.
    ///
    /// Both sets are the gateway's own state. Neither is ever taken from the
    /// message being checked, and an empty set refuses everything — an
    /// unknown peer must not be an unauthenticated one.
    pub fn verify_against(
        &self,
        issuer_public_keys: &[&[u8]],
        acceptable_certificate_fingerprints: &[&str],
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        self.request.validate()?;
        // Freshness first: it costs a subtraction, while everything below is
        // an ML-DSA verification. A stale request must not buy that work.
        self.request.assert_fresh(now_unix)?;
        let presented = self.certificate.fingerprint()?;
        if !acceptable_certificate_fingerprints
            .iter()
            .any(|acceptable| *acceptable == presented)
        {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        let mut refusal = KeyNegotiationError::InvalidPqCertificate;
        let accepted = issuer_public_keys.iter().any(|issuer| {
            match self.certificate.verify(
                issuer,
                PqCertificateRole::Client,
                None,
                &self.request.client_wg_public_key,
                now_unix,
            ) {
                Ok(()) => true,
                Err(error) => {
                    // The last refusal is kept rather than the first: a
                    // signature that failed under the real issuer is a more
                    // useful diagnosis than a malformed-key complaint from an
                    // anchor this leaf was never meant to chain to.
                    refusal = error;
                    false
                }
            }
        });
        if !accepted {
            return Err(refusal);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            PQ_REQUEST_DOMAIN,
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
    /// `ca_pq_public_key` is the anchor of the trust domain the caller belongs
    /// to, and `None` when it belongs to none.
    ///
    /// A gateway serves one of two certificate shapes, and which one is not the
    /// caller's choice: self-signed while it carries no trust domain, issued by
    /// `CA-PQ` once `heliosd init-trust-domain` has run (ADR-008 §13.1).
    /// Verifying a `CA-PQ`-issued leaf against its own subject key — which is
    /// what `verify_self_signed` does — rejects every gateway that has an
    /// authority, which is to say every gateway the authority is for.
    ///
    /// The shape is read off `issuer == subject`, never off the presence of an
    /// anchor, so the two cases cannot swap silently: a CA-issued leaf reaching
    /// a peer that holds no anchor is refused rather than checked against
    /// itself.
    pub fn verify(
        &self,
        request: &KeyNegotiationRequest,
        pinned_certificate: &PqCertificate,
        expected_subject: &str,
        expected_gateway_wireguard_key: &str,
        ca_pq_public_key: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        self.response
            .validate_for(request, expected_gateway_wireguard_key)?;
        if self.certificate.issuer == self.certificate.subject {
            self.certificate.verify_self_signed(
                PqCertificateRole::Gateway,
                Some(expected_subject),
                expected_gateway_wireguard_key,
                now_unix,
            )?;
        } else {
            let anchor = ca_pq_public_key.ok_or(KeyNegotiationError::MissingPqCertificateAnchor)?;
            self.certificate.verify(
                anchor,
                PqCertificateRole::Gateway,
                Some(expected_subject),
                expected_gateway_wireguard_key,
                now_unix,
            )?;
        }
        if self.certificate.fingerprint()? != pinned_certificate.fingerprint()? {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            PQ_RESPONSE_DOMAIN,
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
            PQ_CONFIRMATION_DOMAIN,
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
            PQ_COMMIT_DOMAIN,
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
/// Travels **inside the WireGuard tunnel**, on `POST
/// /api/key-negotiation/release` of the internal API — not on the public
/// negotiation port. The negotiation itself has to cross the Internet before
/// WireGuard exists, which is what the public port is for; an explicit
/// disconnection happens after a successful handshake, when an encrypted and
/// mutually authenticated channel to the gateway is already there. Reopening
/// the public port to announce a teardown re-authenticated by mTLS, challenge
/// and ML-DSA a machine that had nothing left to prove.
///
/// Hence no `server_challenge` and no timestamp: WireGuard rejects replayed
/// network packets, and at the application layer `installed_transaction_id`
/// makes a stale command harmless — the gateway only clears the slot whose
/// current `committed` owner it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PskRelease {
    pub protocol_version: u16,
    /// Transaction that installed the PSK being released.
    ///
    /// The gateway only clears the slot if this names its current owner, so a
    /// delayed release cannot tear down a tunnel established by a **later**
    /// negotiation.
    pub installed_transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    pub client_wg_public_key: String,
    pub gateway_wg_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPskRelease {
    pub release: PskRelease,
    pub certificate: PqCertificate,
    pub ml_dsa_87_signature: String,
}

impl AuthenticatedPskRelease {
    /// `now_unix` is only the clock the **certificate** validity is read
    /// against. The release itself carries no timestamp: there is no clock
    /// window to widen or narrow, and therefore none to get wrong.
    pub fn verify(
        &self,
        issuer_public_key: &[u8],
        expected_certificate_fingerprint: &str,
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        self.verify_against(
            &[issuer_public_key],
            &[expected_certificate_fingerprint],
            now_unix,
        )
    }

    /// The same verification, against every identity the gateway admits for
    /// this peer — see
    /// [`AuthenticatedKeyNegotiationRequest::verify_against`].
    ///
    /// The acceptable set here is the **union** of the peer's live
    /// generations, and that is correct rather than lax: no TLS half is
    /// presented on this route, because the tunnel is the proof and the caller
    /// was resolved from its source VIP. There is no pair to mix.
    pub fn verify_against(
        &self,
        issuer_public_keys: &[&[u8]],
        acceptable_certificate_fingerprints: &[&str],
        now_unix: u64,
    ) -> Result<(), KeyNegotiationError> {
        if self.release.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(KeyNegotiationError::VersionMismatch {
                received: self.release.protocol_version,
                supported: KEY_NEGOTIATION_VERSION,
            });
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
        let presented = self.certificate.fingerprint()?;
        if !acceptable_certificate_fingerprints
            .iter()
            .any(|acceptable| *acceptable == presented)
        {
            return Err(KeyNegotiationError::PqCertificateFingerprintMismatch);
        }
        let mut refusal = KeyNegotiationError::InvalidPqCertificate;
        let accepted = issuer_public_keys.iter().any(|issuer| {
            match self.certificate.verify(
                issuer,
                PqCertificateRole::Client,
                None,
                &self.release.client_wg_public_key,
                now_unix,
            ) {
                Ok(()) => true,
                Err(error) => {
                    refusal = error;
                    false
                }
            }
        });
        if !accepted {
            return Err(refusal);
        }
        verify_protocol_signature(
            &self.certificate.ml_dsa_87_public_key,
            PQ_IN_TUNNEL_RELEASE_DOMAIN,
            &pq_release_signing_bytes(&self.release, &self.certificate)?,
            &self.ml_dsa_87_signature,
        )
    }
}
