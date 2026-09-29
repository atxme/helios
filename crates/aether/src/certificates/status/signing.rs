use super::*;
use crate::certificates::encoding::sign_ml_dsa_87;

impl AstraCertificateStatus {
    pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}

impl AstraSignerRequest {
    pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}

impl CertificateServiceRollbackAuthorization {
    pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
        self.ca_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
        Ok(self)
    }
}
