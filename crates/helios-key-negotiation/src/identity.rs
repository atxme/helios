use std::any::Any;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use zeroize::Zeroize as _;

use crate::TransportError;

/// DER material loaded from a protected local store.
pub struct TlsIdentity {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}

impl TlsIdentity {
    pub(crate) fn certificates(&self) -> Vec<CertificateDer<'static>> {
        self.certificate_chain
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect()
    }

    pub(crate) fn private_key(&self) -> Result<PrivateKeyDer<'static>, TransportError> {
        PrivateKeyDer::try_from(self.private_key.clone())
            .map_err(|_| TransportError::InvalidPrivateKey)
    }

    pub(crate) fn leaf_fingerprint(&self) -> String {
        self.certificate_chain
            .first()
            .map(|leaf| certificate_fingerprint_der(leaf))
            .unwrap_or_else(|| "aucune".into())
    }
}

impl Drop for TlsIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

pub(crate) fn peer_certificate_sha256(
    connection: &quinn::Connection,
) -> Result<String, TransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::MissingPeerCertificate)?;
    certificate_fingerprint(identity.as_ref())
}

fn certificate_fingerprint(identity: &dyn Any) -> Result<String, TransportError> {
    let chain = identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .ok_or(TransportError::MissingPeerCertificate)?;
    let leaf = chain
        .first()
        .ok_or(TransportError::MissingPeerCertificate)?;
    Ok(certificate_fingerprint_der(leaf.as_ref()))
}

/// SHA-256 fingerprint used to bind a certificate to an admitted WireGuard peer.
pub fn certificate_fingerprint_der(bytes: &[u8]) -> String {
    hex::encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes))
}
