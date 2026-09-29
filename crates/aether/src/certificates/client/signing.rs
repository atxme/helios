use super::*;
use crate::certificates::encoding::sign_ml_dsa_87;

impl ClientCertificateRotationRequest {
    pub fn sign(
        mut self,
        active_pq_private_key: &[u8],
        new_pq_private_key: &[u8],
    ) -> Result<Self, CertificateError> {
        let transcript = self.signing_bytes();
        self.active_pq_signature = sign_ml_dsa_87(active_pq_private_key, &transcript)?;
        self.new_pq_signature = sign_ml_dsa_87(new_pq_private_key, &transcript)?;
        Ok(self)
    }
}

impl ClientCertificateStageAuthorization {
    /// Signed by `CA-PQ` under [`IssuerKind::Master`], by the delegated
    /// issuer under [`IssuerKind::Astra`]. Which key is legitimate is
    /// decided by `issuer_kind`, and the verifier checks both.
    pub fn sign(mut self, issuer_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.signature = sign_ml_dsa_87(issuer_private_key, &self.signing_bytes()?)?;
        Ok(self)
    }
}

impl GatewayCertificateStageReceipt {
    /// Signed **after** the candidate is on disk and `fsync`ed. A receipt
    /// produced before that write would be a signature over a fact that
    /// has not happened yet.
    pub fn sign(mut self, gateway_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.gateway_signature = sign_ml_dsa_87(gateway_pq_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}

impl ClientCertificateRotationGrant {
    pub fn sign(mut self, issuer_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.signature = sign_ml_dsa_87(issuer_private_key, &self.signing_bytes()?)?;
        Ok(self)
    }
}

impl ClientCertificateStageCommit {
    pub fn sign(
        mut self,
        active_pq_private_key: &[u8],
        staged_pq_private_key: &[u8],
    ) -> Result<Self, CertificateError> {
        let transcript = self.signing_bytes();
        self.active_pq_signature = sign_ml_dsa_87(active_pq_private_key, &transcript)?;
        self.staged_pq_signature = sign_ml_dsa_87(staged_pq_private_key, &transcript)?;
        Ok(self)
    }
}

impl ExpiredCertificateRecoveryRequest {
    pub fn sign(
        mut self,
        expired_pq_private_key: &[u8],
        new_pq_private_key: &[u8],
    ) -> Result<Self, CertificateError> {
        let transcript = self.signing_bytes();
        self.expired_pq_signature = sign_ml_dsa_87(expired_pq_private_key, &transcript)?;
        self.new_pq_signature = sign_ml_dsa_87(new_pq_private_key, &transcript)?;
        Ok(self)
    }
}
