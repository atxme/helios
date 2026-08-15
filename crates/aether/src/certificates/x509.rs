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
//! - a **CA** must parse, name itself as its own issuer, be self-signed, carry
//!   `basicConstraints:CA=true` and `keyUsage:keyCertSign`. Self-signature is
//!   possession: without it, an authorization could name any public key as the
//!   next anchor. The issuer/subject comparison is not redundant with it — a
//!   certificate can verify under its own key while naming another authority,
//!   and a chain builder that matched on name would then follow it;
//! - a **client leaf** must parse, not be a CA, carry the `clientAuth`
//!   extended usage, carry `digitalSignature` when it declares a `keyUsage` at
//!   all, stay valid over its **whole** window, and chain to an anchor the
//!   verifier already holds;
//! - a pinned **gateway TLS leaf** must parse, not be a CA, carry `serverAuth`,
//!   name the expected DNS endpoint, verify its self-signature and cover its
//!   whole transition window. The pin authorizes the key, but it does not turn
//!   arbitrary DER into a usable TLS identity;
//! - a **CSR** must carry the same public key as the leaf issued from it.
//!   Without that check a grant can be perfectly signed and still install a
//!   certificate for a private key the client never generated.
//!
//! # Every link, over the whole window — not one link at one instant
//!
//! [`assert_chains_to`] takes the **span** the chain will be in service for
//! and refuses a path whose intermediate or anchor does not cover all of it,
//! or whose intermediate is not a CA. Two classic holes meet here: verifying
//! only the leaf's dates lets an expired anchor go on issuing perfectly-dated
//! leaves, and verifying a single instant lets a link retire in the middle of
//! the overlap it exists to carry — after the outgoing generation has already
//! been scheduled for retirement, so there is nothing to fall back to.
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
    pub is_server_authentication_leaf: bool,
    /// Whether the certificate declares a `keyUsage` extension at all.
    ///
    /// The distinction matters: an absent extension asserts nothing, while a
    /// present one that omits `digitalSignature` says the key may **not** sign
    /// a handshake. Collapsing the two would either refuse legacy leaves or
    /// accept a key its own issuer restricted.
    pub declares_key_usage: bool,
    pub can_digitally_sign: bool,
    /// Issuer and subject names are equal — a necessary condition of a root.
    pub is_self_issued: bool,
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
    let key_usage = parsed.key_usage().ok().flatten();
    let can_sign_certificates = key_usage
        .as_ref()
        .is_some_and(|extension| extension.value.key_cert_sign());
    let can_digitally_sign = key_usage
        .as_ref()
        .is_some_and(|extension| extension.value.digital_signature());
    let is_client_authentication_leaf = parsed
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.client_auth);
    let is_server_authentication_leaf = parsed
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.server_auth);
    let not_before = parsed.validity().not_before.timestamp().max(0) as u64;
    let not_after = parsed.validity().not_after.timestamp().max(0) as u64;
    Ok(X509Facts {
        is_certificate_authority,
        can_sign_certificates,
        is_client_authentication_leaf,
        is_server_authentication_leaf,
        declares_key_usage: key_usage.is_some(),
        can_digitally_sign,
        is_self_issued: parsed.issuer() == parsed.subject(),
        not_before,
        not_after,
    })
}

/// A self-signed gateway TLS leaf protected by an out-of-band pin.
///
/// The CA-PQ signature authorizes installing the DER fingerprint; this check
/// proves the bytes are also a TLS server identity for the gateway being
/// rotated. Requiring the self-signature is possession of the embedded public
/// key. Requiring a DNS SAN follows TLS name validation instead of falling
/// back to the legacy common name.
pub fn assert_pinned_gateway_leaf(
    certificate: &DerCertificate,
    server_name: &str,
    from_unix: u64,
    until_unix: u64,
) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if facts.is_certificate_authority {
        return Err(CertificateError::InvalidX509("gateway leaf is a CA"));
    }
    if !facts.is_server_authentication_leaf {
        return Err(CertificateError::InvalidX509("no serverAuth usage"));
    }
    if facts.declares_key_usage && !facts.can_digitally_sign {
        return Err(CertificateError::InvalidX509("no digitalSignature usage"));
    }
    if !facts.is_self_issued {
        return Err(CertificateError::InvalidX509(
            "pinned gateway leaf is not self-issued",
        ));
    }

    let parsed = parse(certificate.as_bytes())?;
    let names_expected_gateway = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|extension| {
            extension
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(dns) if *dns == server_name))
        });
    if !names_expected_gateway {
        return Err(CertificateError::InvalidX509(
            "gateway DNS name is not in subjectAltName",
        ));
    }
    parsed
        .verify_signature(None)
        .map_err(|_| CertificateError::InvalidX509("self-signature does not verify"))?;
    assert_covers(certificate, from_unix, until_unix)
}

/// The certificate covers the whole span it will be in service for.
///
/// `not_before <= from_unix` **and** `not_after > until_unix`, per spec §4.1.
/// Checking a single instant is the subtler half of the same hole as checking
/// only the leaf: a certificate valid at `activation_at` can expire in the
/// middle of the overlap, and the generation it belongs to is then half-dead
/// while the state machine still considers it current — with the outgoing
/// generation already retired and nothing left to fall back to.
pub fn assert_covers(
    certificate: &DerCertificate,
    from_unix: u64,
    until_unix: u64,
) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if facts.not_before > from_unix {
        return Err(CertificateError::InvalidX509("not valid yet at activation"));
    }
    if facts.not_after <= until_unix {
        return Err(CertificateError::InvalidX509("expires inside its window"));
    }
    Ok(())
}

/// A certificate authority: self-issued, self-signed, `CA=true`, able to sign.
///
/// Deliberately says nothing about dates. An anchor staged for a future
/// activation is legitimately not valid today, and this is the structural
/// check; [`assert_covers`] is the temporal one, applied against the window
/// the anchor is being installed for.
pub fn assert_certificate_authority(certificate: &DerCertificate) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if !facts.is_certificate_authority {
        return Err(CertificateError::InvalidX509("not a certificate authority"));
    }
    if !facts.can_sign_certificates {
        return Err(CertificateError::InvalidX509("cannot sign certificates"));
    }
    if !facts.is_self_issued {
        // A certificate can verify under its own key and still name another
        // authority as its issuer. Accepting it as a root would let a name
        // that belongs to someone else be treated as this anchor's own.
        return Err(CertificateError::InvalidX509("root is not self-issued"));
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

/// A client mTLS leaf: not a CA, `clientAuth`, and valid for its whole window.
///
/// The span is `[from_unix, until_unix]` — in practice `activation_at` to the
/// end of the overlap, not a single instant.
pub fn assert_client_leaf(
    certificate: &DerCertificate,
    from_unix: u64,
    until_unix: u64,
) -> Result<(), CertificateError> {
    let facts = inspect(certificate)?;
    if facts.is_certificate_authority {
        return Err(CertificateError::InvalidX509("client leaf is a CA"));
    }
    if !facts.is_client_authentication_leaf {
        return Err(CertificateError::InvalidX509("no clientAuth usage"));
    }
    // An absent `keyUsage` asserts nothing; a present one that omits
    // `digitalSignature` says this key may not sign a handshake, which is the
    // only thing a client leaf is ever used for.
    if facts.declares_key_usage && !facts.can_digitally_sign {
        return Err(CertificateError::InvalidX509("no digitalSignature usage"));
    }
    assert_covers(certificate, from_unix, until_unix)
}

/// Chains `leaf` to one of the anchors the verifier already holds, over the
/// whole span `[from_unix, until_unix]`.
///
/// `intermediates` are tried between the two — the delegated issuer's
/// client-auth intermediate is the only one this PKI has. A leaf that chains
/// to nothing is refused; a leaf that chains to an anchor the caller did not
/// supply is refused for the same reason.
///
/// Every link above the leaf must be a CA **and** cover the whole span.
/// Checking only the leaf leaves an expired anchor issuing perfectly-dated
/// certificates; checking a single instant lets an anchor retire in the middle
/// of the overlap it was supposed to carry.
pub fn assert_chains_to(
    leaf: &DerCertificate,
    intermediates: &[&DerCertificate],
    anchors: &[&DerCertificate],
    from_unix: u64,
    until_unix: u64,
) -> Result<(), CertificateError> {
    if anchors.is_empty() {
        return Err(CertificateError::InvalidX509("no trust anchor"));
    }
    let usable = |certificate: &DerCertificate| -> bool {
        inspect(certificate).is_ok_and(|facts| {
            facts.is_certificate_authority
                && facts.can_sign_certificates
                && facts.not_before <= from_unix
                && facts.not_after > until_unix
        })
    };
    let mut saw_expired_link = false;
    for anchor in anchors {
        if assert_issued_by(leaf, anchor).is_ok() {
            if usable(anchor) {
                return Ok(());
            }
            saw_expired_link = true;
            continue;
        }
        for intermediate in intermediates {
            if assert_issued_by(leaf, intermediate).is_ok()
                && assert_issued_by(intermediate, anchor).is_ok()
            {
                if usable(intermediate) && usable(anchor) {
                    return Ok(());
                }
                saw_expired_link = true;
            }
        }
    }
    if saw_expired_link {
        // The signatures line up and the path exists; what fails is that a
        // link is outside its validity or is not an authority. Saying "no
        // path" there sends an operator looking for the wrong problem.
        return Err(CertificateError::InvalidX509("unusable chain link"));
    }
    Err(CertificateError::InvalidX509("no path to a trust anchor"))
}

/// The distinguished names an interface displays: subject, then issuer.
///
/// Reading them here rather than in each consumer keeps `x509-parser` behind
/// this module: it is the one place in the workspace that decides what a
/// certificate says, and a second parser would eventually disagree with it.
pub fn subject_and_issuer(
    certificate: &DerCertificate,
) -> Result<(String, String), CertificateError> {
    let parsed = parse(certificate.as_bytes())?;
    Ok((parsed.subject().to_string(), parsed.issuer().to_string()))
}

/// The certificate's `SubjectPublicKeyInfo`, DER-encoded.
///
/// What a holder of the matching private key can compare against to prove the
/// two belong together. A daemon that only checks its key files *exist* starts
/// up announcing an issuer it cannot actually issue with, and the mismatch
/// surfaces at the first renewal — at 80 % of a leaf's life, on a client that
/// has no fallback.
pub fn subject_public_key_info(certificate: &DerCertificate) -> Result<Vec<u8>, CertificateError> {
    Ok(parse(certificate.as_bytes())?.public_key().raw.to_vec())
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

    /// An instant at which the whole freshly-generated material is valid.
    fn inside(certificate: &DerCertificate) -> u64 {
        inspect(certificate).expect("facts").not_before + 1
    }

    #[test]
    fn a_client_leaf_chains_to_its_anchor_and_not_to_another() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");
        let (other_der, _, _) = authority("another-CA");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        let now = inside(&ca_der);

        assert_chains_to(&leaf, &[], &[&ca_der], now, now).expect("chains to its own CA");
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[&other_der], now, now),
            Err(CertificateError::InvalidX509("no path to a trust anchor"))
        ));
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[], now, now),
            Err(CertificateError::InvalidX509("no trust anchor"))
        ));
    }

    /// An expired anchor keeps issuing perfectly-dated leaves. The chain is
    /// where that has to be caught, because nothing downstream looks.
    #[test]
    fn a_chain_through_an_expired_anchor_is_refused() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        let anchor = inspect(&ca_der).expect("facts");

        assert_chains_to(
            &leaf,
            &[],
            &[&ca_der],
            anchor.not_before + 1,
            anchor.not_before + 1,
        )
        .expect("inside validity");
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[&ca_der], anchor.not_after, anchor.not_after),
            Err(CertificateError::InvalidX509("unusable chain link"))
        ));
        assert!(matches!(
            assert_chains_to(
                &leaf,
                &[],
                &[&ca_der],
                anchor.not_before - 1,
                anchor.not_before - 1
            ),
            Err(CertificateError::InvalidX509("unusable chain link"))
        ));
    }

    /// A certificate that verifies under its own key while naming another
    /// issuer is not a root: a name-matching path builder would follow it.
    #[test]
    fn a_self_signed_certificate_naming_another_issuer_is_not_a_root() {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name = name("impostor");
        // rcgen signs with the given key while writing the *issuer* name of the
        // certificate it is signed by, so this is self-signed and not
        // self-issued.
        let key = KeyPair::generate().expect("key");
        let (_, issuer, _) = authority("CA-TLS");
        let certificate = params
            .signed_by(&key, &issuer, &key)
            .expect("self-signed under another name");
        let der = DerCertificate::new(certificate.der().to_vec()).expect("der");
        assert!(matches!(
            assert_certificate_authority(&der),
            Err(CertificateError::InvalidX509("root is not self-issued"))
        ));
    }

    /// A `keyUsage` that omits `digitalSignature` forbids the one thing a
    /// client leaf does.
    #[test]
    fn a_client_leaf_without_digital_signature_usage_is_refused() {
        let (_, ca, ca_key) = authority("CA-TLS");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.distinguished_name = name("workstation");
        let key = KeyPair::generate().expect("key");
        let leaf = params.signed_by(&key, &ca, &ca_key).expect("leaf");
        let leaf = DerCertificate::new(leaf.der().to_vec()).expect("der");
        let now = inside(&leaf);
        assert!(matches!(
            assert_client_leaf(&leaf, now, now),
            Err(CertificateError::InvalidX509("no digitalSignature usage"))
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
        let now = inside(&ca_der);
        assert_chains_to(&leaf, &[&intermediate_der], &[&ca_der], now, now)
            .expect("three-link path");
        // Without the intermediate the path does not exist.
        assert!(assert_chains_to(&leaf, &[], &[&ca_der], now, now).is_err());
    }

    /// A leaf must cover the whole window it is installed for, not merely be
    /// alive on the day it activates.
    #[test]
    fn a_client_leaf_must_carry_client_auth_and_cover_its_whole_window() {
        let (_, ca, ca_key) = authority("CA-TLS");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        let facts = inspect(&leaf).expect("facts");
        let activation = facts.not_before + 1;

        assert_client_leaf(&leaf, activation, facts.not_after - 1).expect("covers its window");
        assert!(matches!(
            assert_client_leaf(&leaf, facts.not_before - 1, facts.not_after - 1),
            Err(CertificateError::InvalidX509("not valid yet at activation"))
        ));
        // Valid at activation, gone before the end of the overlap: the exact
        // half-dead generation §4.1 forbids.
        assert!(matches!(
            assert_client_leaf(&leaf, activation, facts.not_after),
            Err(CertificateError::InvalidX509("expires inside its window"))
        ));
    }

    /// The same rule on a chain: an anchor that retires mid-overlap takes
    /// every leaf under it with it, after the outgoing one was retired.
    #[test]
    fn a_chain_whose_anchor_retires_mid_window_is_refused() {
        let (ca_der, ca, ca_key) = authority("CA-TLS");
        let (leaf, _, _) = client_leaf(&ca, &ca_key);
        let anchor = inspect(&ca_der).expect("facts");
        let activation = anchor.not_before + 1;

        assert_chains_to(&leaf, &[], &[&ca_der], activation, anchor.not_after - 1)
            .expect("the anchor outlasts the window");
        assert!(matches!(
            assert_chains_to(&leaf, &[], &[&ca_der], activation, anchor.not_after),
            Err(CertificateError::InvalidX509("unusable chain link"))
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
