//! Recovering an expired leaf, under a hardware-key approval bound to an
//! Astra challenge.

use super::*;

/// Recovery of an identity whose leaf has already expired (spec §7.5).
///
/// The expired certificate is a **historical proof**, never a credential: it
/// is refused by mTLS, by QUIC and by every ordinary validator, and the
/// separate validator used here checks signature, chain, identities,
/// fingerprints and last known generation — everything except the period. It
/// is a distinct type precisely so the negotiation path cannot reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredCertificateRecoveryRequest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub astra_challenge: [u8; 32],
    pub request_id: Id16,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub expired_generation: u64,
    pub requested_generation: u64,
    /// The complete expired leaves, so the historical validator can check the
    /// chain rather than trust a fingerprint the requester chose.
    pub expired_tls_certificate: DerCertificate,
    pub expired_pq_certificate: PqCertificate,
    pub tls_csr: DerCertificate,
    pub new_ml_dsa_87_public_key: MlDsa87PublicKey,
    /// Identifier of the operator credential that will approve the request.
    pub credential_id: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    /// Signed by the private key of the expired generation.
    pub expired_pq_signature: MlDsa87Signature,
    pub new_pq_signature: MlDsa87Signature,
}

impl ExpiredCertificateRecoveryRequest {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(RECOVERY_REQUEST_DOMAIN);
        bytes
            .id(&self.trust_domain_id)
            .raw(&self.astra_challenge)
            .id(&self.request_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.expired_generation)
            .u64(self.requested_generation)
            .fingerprint(&self.expired_tls_certificate.fingerprint())
            .fingerprint(
                &pq_certificate_fingerprint(&self.expired_pq_certificate)
                    .unwrap_or_else(|_| Fingerprint::from_bytes([0; 32])),
            )
            .fingerprint(&self.tls_csr.fingerprint())
            .length_prefixed(self.new_ml_dsa_87_public_key.as_bytes())
            .fingerprint(&Fingerprint::of(&self.credential_id))
            .u64(self.created_at)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.expired_pq_signature.as_bytes())
            .length_prefixed(self.new_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// The historical validator of spec §7.5.
    ///
    /// It ignores the validity period **and nothing else**, and only after
    /// everything else has passed. `last_known` is the last generation Astra
    /// recorded for this peer: a request naming an older one, or one for which
    /// a newer generation exists, is refused before any signature work that
    /// would confirm the peer exists.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_historical(
        &self,
        issuers: &[&MlDsa87PublicKey],
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        last_known: &ClientCertificateGeneration,
        expected_challenge: &[u8; 32],
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.protocol_version != CERTIFICATE_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocolVersion {
                received: self.protocol_version,
                supported: CERTIFICATE_PROTOCOL_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.astra_challenge != *expected_challenge
            || self.astra_challenge.iter().all(|byte| *byte == 0)
        {
            return Err(CertificateError::InvalidChallenge);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(CertificateError::CampaignMismatch);
        }
        if self.expired_generation != last_known.generation {
            return Err(CertificateError::GenerationRollback {
                current: last_known.generation,
                proposed: self.expired_generation,
            });
        }
        require_next_generation(self.expired_generation, self.requested_generation)?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_RECOVERY_REQUEST_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }
        // The expired leaves must be exactly the last recorded ones. This is
        // where an attacker holding *some* old certificate of the peer is
        // stopped: only the newest one can prove continuity.
        if !self
            .expired_tls_certificate
            .fingerprint()
            .matches(&last_known.tls_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("expired TLS leaf"));
        }
        let expired_pq = pq_certificate_fingerprint(&self.expired_pq_certificate)?;
        if !expired_pq.matches(&last_known.pq_certificate_fingerprint) {
            return Err(CertificateError::FingerprintMismatch("expired PQ leaf"));
        }
        // The chain is verified at an instant **inside** the expired leaf's own
        // validity: this validator waives the period, it does not waive the
        // issuer signature, the role or the WireGuard binding. The leaf may
        // have been issued by a delegated issuer of an earlier epoch, so the
        // caller supplies every authority that could legitimately have signed
        // it.
        verify_client_leaf_under_any(
            &self.expired_pq_certificate,
            issuers,
            client_wg_public_key,
            self.expired_pq_certificate.not_before_unix,
        )?;

        let expired_key =
            MlDsa87PublicKey::parse(&self.expired_pq_certificate.ml_dsa_87_public_key)?;
        let transcript = self.signing_bytes();
        verify_ml_dsa_87(&expired_key, &transcript, &self.expired_pq_signature)
            .map_err(|_| CertificateError::MissingProof("expired client"))?;
        verify_ml_dsa_87(
            &self.new_ml_dsa_87_public_key,
            &transcript,
            &self.new_pq_signature,
        )
        .map_err(|_| CertificateError::MissingProof("new client"))
    }

    /// The exact operation an operator confirms for this request.
    ///
    /// Not something the token signs: a YubiKey signs no ML-DSA, and nothing
    /// here verifies a WebAuthn assertion. This is the value `astra-signer`
    /// displays before the touch that unwraps the vault, and the value the
    /// resulting `CA-PQ` signature is bound to.
    pub fn approval_challenge(&self) -> Fingerprint {
        expired_recovery_approval_challenge(
            &self.fingerprint(),
            &self.astra_challenge,
            self.expires_at,
        )
    }
}

/// The operation hash bound to one recovery request (spec §7.5).
///
/// It is what makes an approval unmovable: displayed before the unlock and
/// bound into the signature that follows, it cannot be carried to another
/// peer, another generation or a later deadline.
pub fn expired_recovery_approval_challenge(
    request_fingerprint: &Fingerprint,
    astra_challenge: &[u8; 32],
    expires_at: u64,
) -> Fingerprint {
    let mut bytes = CanonicalBytes::new(RECOVERY_APPROVAL_DOMAIN);
    bytes
        .fingerprint(request_fingerprint)
        .raw(astra_challenge)
        .u64(expires_at);
    Fingerprint::of(&bytes.finish())
}
