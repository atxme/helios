//! The candidate identity written at commit time: the name it is sealed
//! under, the chain the bundle carries for a delegated or a master-issued
//! leaf, and the private keys this machine generated.

use aether::certificates::client::{ClientCertificateRotationGrant, IssuerKind};
use aether::certificates::encoding::{
    derive_ml_dsa_87_public_key, generate_ml_dsa_87_keypair, DerCertificate, Fingerprint,
    MlDsa87Signature,
};
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};

use super::fixtures::{grant, session, window};
use crate::certificate_renewal::{candidate_identity_of, RenewalSession};
use crate::test_domain::*;

/// The candidate is sealed beside the active identity, never over it: the
/// active generation keeps connecting for the length of the overlap.
#[test]
fn the_candidate_is_sealed_under_a_name_of_its_own() {
    assert_eq!(candidate_identity_of("poste-windows"), "poste-windows-next");
    assert_ne!(candidate_identity_of("poste"), "poste");
}

/// The same grant, but issued by a delegation: an intermediate signed by
/// `CA-TLS`, and a leaf signed by that intermediate.
fn delegated_grant(
    domain: &Domain,
    session: &RenewalSession,
    window: TransitionWindow,
) -> (ClientCertificateRotationGrant, DerCertificate) {
    use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};

    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    intermediate_params.distinguished_name = name("astra delegated issuer 1");
    intermediate_params.not_before = seconds_since_epoch(window.not_before);
    intermediate_params.not_after = seconds_since_epoch(window.not_after + 172_800);
    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate = intermediate_params
        .signed_by(
            &intermediate_key,
            &Issuer::from_ca_cert_der(domain.tls_ca.der(), &domain.tls_ca_key)
                .expect("CA-TLS issuer"),
        )
        .expect("intermediate");
    let intermediate_der = DerCertificate::new(intermediate.der().to_vec()).expect("der");

    let request = session.request();
    let csr =
        CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().to_vec().into())
            .expect("csr");
    let mut params = csr.params.clone();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = seconds_since_epoch(window.not_before);
    params.not_after = seconds_since_epoch(window.not_after + 86_400);
    let leaf = CertificateSigningRequestParams {
        params,
        public_key: csr.public_key,
    }
    .signed_by(
        &Issuer::from_ca_cert_der(intermediate.der(), &intermediate_key)
            .expect("intermediate issuer"),
    )
    .expect("delegated leaf");

    let (_, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer key");
    let mut grant = grant(domain, session, window);
    grant.issuer_kind = IssuerKind::Astra;
    grant.issuer_epoch = 1;
    grant.next_tls_certificate = DerCertificate::new(leaf.der().to_vec()).expect("der");
    grant.issuer_authorization = Some(AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain_id(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: intermediate_der.clone(),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 90 * 86_400,
        policy_fingerprint: Fingerprint::of(b"policy"),
        not_before: window.not_before,
        not_after: window.not_after + 172_800,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    });
    (grant, intermediate_der)
}

/// A delegated leaf is signed by the delegation's intermediate, and the
/// gateway's listener holds only the anchor: it builds the path from what
/// the client presents. A chain of one would be a leaf attached to nothing
/// the gateway trusts — and the handshake fails at the end of the overlap,
/// on the machine whose only channel for saying so was that tunnel.
#[test]
fn a_delegated_candidate_carries_the_intermediate_that_signed_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let session = session(&store, &domain);
    let (grant, intermediate) = delegated_grant(&domain, &session, window());

    let bundle = session
        .candidate_bundle("poste-windows", &grant)
        .expect("bundle");

    assert_eq!(
        bundle.certificate_chain.len(),
        2,
        "the delegated chain is leaf then intermediate"
    );
    assert_eq!(
        STANDARD
            .decode(&bundle.certificate_chain[0])
            .expect("leaf der"),
        grant.next_tls_certificate.as_bytes(),
        "the leaf stays first: every reader takes index 0 as the identity"
    );
    assert_eq!(
        STANDARD
            .decode(&bundle.certificate_chain[1])
            .expect("intermediate der"),
        intermediate.as_bytes()
    );
}

/// Carrying a delegation is not the same as having been signed by it. A
/// master-issued leaf chains to the anchor directly, and appending an
/// intermediate that signed nothing would make the gateway reject a path
/// it would otherwise have built.
#[test]
fn a_master_issued_candidate_carries_the_leaf_alone() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let session = session(&store, &domain);
    let (delegated, _) = delegated_grant(&domain, &session, window());
    let mut grant = grant(&domain, &session, window());
    // The delegation object, beside a leaf the master signed.
    grant.issuer_authorization = delegated.issuer_authorization;

    let bundle = session
        .candidate_bundle("poste-windows", &grant)
        .expect("bundle");

    assert_eq!(bundle.certificate_chain.len(), 1);
}

/// The bundle written at commit time carries the candidate's own private
/// keys — the ones this process generated and never sent anywhere.
#[test]
fn the_candidate_bundle_holds_the_keys_this_machine_generated() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let session = session(&store, &domain);
    let grant = grant(&domain, &session, window());

    let bundle = session
        .candidate_bundle("poste-windows", &grant)
        .expect("bundle");
    assert_eq!(bundle.identity, "poste-windows");
    let certificate = STANDARD
        .decode(&bundle.certificate_chain[0])
        .expect("leaf der");
    assert_eq!(certificate, grant.next_tls_certificate.as_bytes());
    let pq_private = STANDARD.decode(&bundle.pq_private_key).expect("pq key");
    assert_eq!(
        derive_ml_dsa_87_public_key(&pq_private)
            .expect("derive public")
            .to_base64(),
        grant.next_pq_certificate.ml_dsa_87_public_key,
        "the sealed private key is the one the candidate leaf certifies"
    );
}
