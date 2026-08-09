//! X.509 checks the lifecycle actually depends on.
//!
//! Until this module existed, [`DerCertificate`] only proved that a byte
//! string was neither empty nor huge. Every "the TLS chain is verified"
//! sentence in the specification was therefore aspirational: a transition
//! could install a CA that was not a CA, and a grant could carry a leaf that
//! certified a key nobody held.
//!
//! # What is checked, and where
//!
//! - a **CA** must parse, be self-signed, carry `basicConstraints:CA=true` and
//!   `keyUsage:keyCertSign`. Self-signature is possession: without it, an
//!   authorization could name any public key as the next anchor;
//! - a **client leaf** must parse, not be a CA, carry the `clientAuth`
//!   extended usage, be inside its validity at the instant it will be used,
//!   and chain to an anchor the verifier already holds;
//! - a **CSR** must carry the same public key as the leaf issued from it.
//!   Without that check a grant can be perfectly signed and still install a
//!   certificate for a private key the client never generated.
//!
//! # What is deliberately not checked
//!
//! Name constraints, policy OIDs, CRL distribution points and path lengths
//! beyond the single intermediate this PKI uses. The chain here is at most
//! `leaf -> intermediate -> CA-TLS`, fixed by the delegation format, so a
//! general path builder would be more code and more surface for no property.

use x509_parser::prelude::*;

use super::{encoding::DerCertificate, CertificateError};

/// What the lifecycle needs to know about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Facts {
    pub is_certificate_authority: bool,
    pub can_sign_certificates: bool,
    pub is_client_authentication_leaf: bool,
    pub not_before: u64,
    pub not_after: u64,
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, CertificateError> {
    let (rest, certificate) =
        X509Certificate::from_der(der).map_err(|_| CertificateError::InvalidX509("unparsable"))?;
    if !rest.is_empty() {
        // Trailing bytes are not a certificate. Accepting them would let two
        // different byte strings carry the same certificate — and the
        // fingerprint that binds it is taken over the **whole** DER.
        return Err(CertificateError::InvalidX509("trailing bytes"));
    }
    Ok(certificate)
}

/// Reads the facts the lifecycle decides on.
pub fn inspect(certificate: &DerCertificate) -> Result<X509Facts, CertificateError> {
    let parsed = parse(certificate.as_bytes())?;
    let is_certificate_authority = parsed
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.ca);
    let can_sign_certificates = parsed
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.key_cert_sign());
    let is_client_authentication_leaf = parsed
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.client_auth);
    let not_before = parsed.validity().not_before.timestamp().max(0) as u64;
    let not_after = parsed.validity().not_after.timestamp().max(0) as u64;
    Ok(X509Facts {
        is_certificate_authority,
        can_sign_certificates,
        is_client_authentication_leaf,
        not_before,
        not_after,
    })
}

/// A certificate authority: self-signed, `CA=true`, able to sign certificates.
pub fn assert_certificate_authority(certificate: &DerCertificate) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if !facts.is_certificate_authority {
        return Err(CertificateError::InvalidX509("not a certificate authority"));
    }
    if !facts.can_sign_certificates {
        return Err(CertificateError::InvalidX509("cannot sign certificates"));
    }
    let parsed = parse(certificate.as_bytes())?;
    parsed
        .verify_signature(None)
        .map_err(|_| CertificateError::InvalidX509("self-signature does not verify"))?;
    Ok(())
}

/// `issuer` really issued `leaf`.
pub fn assert_issued_by(
    leaf: &DerCertificate,
    issuer: &DerCertificate,
) -> Result<(), CertificateError> {
    let leaf = parse(leaf.as_bytes())?;
    let issuer = parse(issuer.as_bytes())?;
    if leaf.issuer() != issuer.subject() {
        return Err(CertificateError::InvalidX509("issuer name mismatch"));
    }
    leaf.verify_signature(Some(issuer.public_key()))
        .map_err(|_| CertificateError::InvalidX509("issuer signature does not verify"))
}

/// A client mTLS leaf: not a CA, `clientAuth`, and inside its validity.
pub fn assert_client_leaf(
    certificate: &DerCertificate,
    now_unix: u64,
) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if facts.is_certificate_authority {
        return Err(CertificateError::InvalidX509("client leaf is a CA"));
    }
    if !facts.is_client_authentication_leaf {
        return Err(CertificateError::InvalidX509("no clientAuth usage"));
    }
    if now_unix < facts.not_before || now_unix >= facts.not_after {
        return Err(CertificateError::InvalidX509("outside validity"));
    }
    Ok(())
}

/// Chains `leaf` to one of the anchors the verifier already holds.
///
/// `intermediates` are tried between the two — the delegated issuer's
/// client-auth intermediate is the only one this PKI has. A leaf that chains
/// to nothing is refused; a leaf that chains to an anchor the caller did not
/// supply is refused for the same reason.
pub fn assert_chains_to(
    leaf: &DerCertificate,
    intermediates: &[&DerCertificate],
    anchors: &[&DerCertificate],
) -> Result<(), CertificateError> {
    if anchors.is_empty() {
        return Err(CertificateError::InvalidX509("no trust anchor"));
    }
    for anchor in anchors {
        if assert_issued_by(leaf, anchor).is_ok() {
            return Ok(());
        }
        for intermediate in intermediates {
            if assert_issued_by(leaf, intermediate).is_ok()
                && assert_issued_by(intermediate, anchor).is_ok()
            {
                return Ok(());
            }
        }
    }
    Err(CertificateError::InvalidX509("no path to a trust anchor"))
}

/// The leaf certifies the key the CSR proved possession of.
///
/// The signature on a grant says the authority meant to issue *something*; it
/// says nothing about whose key ended up inside. Without this, a grant can be
/// perfectly valid and still hand a client a certificate it has no private key
/// for — and the failure only appears at the next mTLS handshake, after the
/// old generation has been retired.
pub fn assert_csr_matches(
    csr: &DerCertificate,
    certificate: &DerCertificate,
) -> Result<(), CertificateError> {
    let (rest, request) = X509CertificationRequest::from_der(csr.as_bytes())
        .map_err(|_| CertificateError::InvalidX509("unparsable CSR"))?;
    if !rest.is_empty() {
        return Err(CertificateError::InvalidX509("trailing bytes after CSR"));
    }
    // The CSR is self-signed by the very key it presents: that is what makes
    // it a proof of possession rather than a claim.
    request
        .verify_signature()
        .map_err(|_| CertificateError::InvalidX509("CSR signature does not verify"))?;
    let certificate = parse(certificate.as_bytes())?;
    if request.certification_request_info.subject_pki.raw != certificate.public_key().raw {
        return Err(CertificateError::InvalidX509(
            "certificate does not certify the CSR's key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    fn name(common: &str) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common);
        name
    }

    fn authority(common: &str) -> (DerCertificate, rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name = name(common);
        let key = KeyPair::generate().expect("key");
        let certificate = params.self_signed(&key).expect("ca");
        (
            DerCertificate::new(certificate.der().to_vec()).expect("der"),
            certificate,
            key,
        )
    }

    fn client_leaf(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
    ) -> (DerCertificate, DerCertificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.distinguished_name = name("workstation");
        let key = KeyPair::generate().expect("key");
        let csr = params.serialize_request(&key).expect("csr");
        let leaf = params.signed_by(&key, issuer, issuer_key).expect("leaf");
        (
            DerCertificate::new(leaf.der().to_vec()).expect("der"),
            DerCertificate::new(csr.der().to_vec()).expect("der"),
            key,
        )
    }

    #[test]
    fn a_certificate_authority_must_be_self_signed_and_say_it_is_one() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");
        assert_certificate_authority(&ca_der).expect("a real CA");

        // A leaf is not a CA, whatever a caller hopes.
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        assert!(matches!(
            assert_certificate_authority(&leaf),
            Err(CertificateError::InvalidX509("not a certificate authority"))
        ));
    }

    #[test]
    fn a_byte_string_that_is_not_a_certificate_is_refused() {
        let garbage = DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00]).expect("der");
        assert!(matches!(
            inspect(&garbage),
            Err(CertificateError::InvalidX509(_))
        ));
    }

    /// Trailing bytes would let two byte strings carry one certificate, while
    /// the fingerprint that binds it covers the whole DER.
    #[test]
    fn trailing_bytes_after_a_certificate_are_refused() {
        let (ca_der, _, _) = authority("CA-TLS");
        let mut padded = ca_der.as_bytes().to_vec();
        padded.push(0);
        let padded = DerCertificate::new(padded).expect("der");
        assert!(matches!(
            inspect(&padded),
            Err(CertificateError::InvalidX509("trailing bytes"))
        ));
    }

    #[test]
    fn a_client_leaf_chains_to_its_anchor_and_not_to_another() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");
        let (other_der, _, _) = authority("another-CA");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);

        assert_chains_to(&leaf, &[], &[&ca_der]).expect("chains to its own CA");
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[&other_der]),
            Err(CertificateError::InvalidX509("no path to a trust anchor"))
        ));
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[]),
            Err(CertificateError::InvalidX509("no trust anchor"))
        ));
    }

    /// The three-link path the delegated issuer produces.
    #[test]
    fn a_leaf_chains_through_the_delegated_intermediate() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");

        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name = name("astra-issuer");
        let intermediate_key = KeyPair::generate().expect("key");
        let intermediate = params
            .signed_by(&intermediate_key, &ca, &ca_key)
            .expect("intermediate");
        let intermediate_der = DerCertificate::new(intermediate.der().to_vec()).expect("der");

        let (leaf, _, _) = client_leaf(&intermediate, &intermediate_key);
        assert_chains_to(&leaf, &[&intermediate_der], &[&ca_der]).expect("three-link path");
        // Without the intermediate the path does not exist.
        assert!(assert_chains_to(&leaf, &[], &[&ca_der]).is_err());
    }

    #[test]
    fn a_client_leaf_must_carry_client_auth_and_be_inside_its_validity() {
        let (_, ca, ca_key) = authority("CA-TLS");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        let facts = inspect(&leaf).expect("facts");

        assert_client_leaf(&leaf, facts.not_before + 1).expect("valid leaf");
        assert!(matches!(
            assert_client_leaf(&leaf, facts.not_before - 1),
            Err(CertificateError::InvalidX509("outside validity"))
        ));
        assert!(matches!(
            assert_client_leaf(&leaf, facts.not_after),
            Err(CertificateError::InvalidX509("outside validity"))
        ));
    }

    /// A grant can be perfectly signed and still certify the wrong key.
    #[test]
    fn a_certificate_must_certify_the_key_its_csr_proved() {
        let (_, ca, ca_key) = authority("CA-TLS");
        let (leaf, csr, _) = client_leaf(&ca, &ca_key);
        assert_csr_matches(&csr, &leaf).expect("the leaf certifies the CSR's key");

        let (other_leaf, _, _) = client_leaf(&ca, &ca_key);
        assert!(matches!(
            assert_csr_matches(&csr, &other_leaf),
            Err(CertificateError::InvalidX509(
                "certificate does not certify the CSR's key"
            ))
        ));
    }
}
