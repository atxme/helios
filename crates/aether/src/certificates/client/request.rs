//! The rotation request: the client proves its active key and names the
//! generation it asks for.

use super::*;

/// Renewal asked for by an Orion whose identity is still active (spec §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateRotationRequest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub request_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    /// Unchanged by a rotation: a new WireGuard key is a readmission, not a
    /// renewal (spec §7.3).
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub requested_generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
    /// PKCS#10 certification request, DER, signed by the new TLS key.
    pub tls_csr: DerCertificate,
    pub new_ml_dsa_87_public_key: MlDsa87PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    /// Continuity, by the PQ key of the active generation.
    pub active_pq_signature: MlDsa87Signature,
    /// Possession, by the PQ key being certified.
    pub new_pq_signature: MlDsa87Signature,
}

impl ClientCertificateRotationRequest {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(ROTATION_REQUEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .id(&self.request_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.requested_generation)
            .fingerprint(&self.active_tls_certificate_fingerprint)
            .fingerprint(&self.active_pq_certificate_fingerprint)
            .fingerprint(&self.tls_csr.fingerprint())
            .length_prefixed(self.new_ml_dsa_87_public_key.as_bytes())
            .u64(self.created_at)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    /// Spec §7.2: the signed bytes, then each signature length-prefixed.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.active_pq_signature.as_bytes())
            .length_prefixed(self.new_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the three proofs and the binding to the admitted peer.
    ///
    /// `active_pq_public_key` comes from the admitted generation, never from
    /// the request: taking the key out of the object that the key is supposed
    /// to authenticate proves nothing at all.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        active_pq_public_key: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        active: &ClientCertificateGeneration,
        client_wg_public_key: &WireGuardKey,
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
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        validate_server_name(&self.server_name)?;
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.active_generation != active.generation {
            return Err(CertificateError::GenerationRollback {
                current: active.generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.requested_generation)?;
        if !self
            .active_tls_certificate_fingerprint
            .matches(&active.tls_certificate_fingerprint)
            || !self
                .active_pq_certificate_fingerprint
                .matches(&active.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active client"));
        }
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_REQUEST_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(active_pq_public_key, &transcript, &self.active_pq_signature)
            .map_err(|_| CertificateError::MissingProof("active client"))?;
        verify_ml_dsa_87(
            &self.new_ml_dsa_87_public_key,
            &transcript,
            &self.new_pq_signature,
        )
        .map_err(|_| CertificateError::MissingProof("new client"))
    }
}
