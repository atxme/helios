use super::*;
use crate::certificates::encoding::sign_ml_dsa_87;

impl AstraCredentialBinding {
    /// Signed by `CA-PQ`, in the same companion operation that changed the
    /// vault's key-slots (spec §2.4).
    pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}

impl AstraCredentialApprovalRequest {
    pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}

impl AstraRenewalApproval {
    pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}
