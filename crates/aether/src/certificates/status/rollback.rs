//! The bounded service rollback of the gateway's identity.

use super::*;

/// Temporary selection of the outgoing identity during an overlap (spec §4.4).
///
/// It changes no counter and removes no slot. It is refused outside an
/// existing overlap, and it expires at `not_after` at the latest — a rollback
/// cannot outlive the transition it rolls back within.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateServiceRollbackAuthorization {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    /// Transition whose overlap this rollback lives inside.
    pub transition_fingerprint: Fingerprint,
    /// Fingerprint of the slot to serve — always the outgoing one.
    pub selected_certificate_fingerprint: Fingerprint,
    pub campaign_fingerprint: Fingerprint,
    pub expires_at: u64,
    pub ca_signature: MlDsa87Signature,
}

impl CertificateServiceRollbackAuthorization {
    /// Everything this document is, as bytes.
    ///
    /// The gateway stores it so that carrying the same authorization twice is
    /// a replay, while a different one — a later expiry, another slot — is a
    /// second decision rather than a silent extension of the first.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }

    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(SERVICE_ROLLBACK_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .fingerprint(&self.transition_fingerprint)
            .fingerprint(&self.selected_certificate_fingerprint)
            .fingerprint(&self.campaign_fingerprint)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    /// Verifies the authorization against the overlap it claims to be inside.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        transition_fingerprint: &Fingerprint,
        active_fingerprint: &Fingerprint,
        overlap_not_after: u64,
        now_unix: u64,
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
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if !self.transition_fingerprint.matches(transition_fingerprint) {
            return Err(CertificateError::FingerprintMismatch("transition"));
        }
        // Only the outgoing slot can be selected. A rollback that could name
        // an arbitrary fingerprint would be a downgrade primitive.
        if !self
            .selected_certificate_fingerprint
            .matches(active_fingerprint)
        {
            return Err(CertificateError::RollbackUnavailable);
        }
        if self.expires_at > overlap_not_after || now_unix >= self.expires_at {
            return Err(CertificateError::RollbackUnavailable);
        }
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_signature)
    }
}
