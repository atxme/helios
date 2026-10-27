use super::*;
use crate::TrustMaterial;
use aether::certificates::encoding::{DerCertificate, MlDsa87PublicKey};
use aether::key_negotiation::{
    EnrollmentDocument, EnrollmentRequest, PqCertificate, PqCertificateRole,
};
use anyhow::Result;

use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87Signature, WireGuardKey};
use aether::key_negotiation::{
    generate_ml_dsa_87_keypair, issue_pq_certificate, ENROLLMENT_FORMAT_VERSION,
    ENROLLMENT_PROTOCOL_VERSION, PQ_CERTIFICATE_VERSION,
};
use base64::engine::general_purpose::STANDARD;

const SERVER_NAME: &str = "vpn.example.net";

struct Fixture {
    request: EnrollmentRequest,
    tls_certificate: DerCertificate,
    pq_certificate: PqCertificate,
    material: GatewayMaterial,
    trust: TrustMaterial,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn pq_leaf(
    ca: &[u8],
    role: PqCertificateRole,
    subject: &str,
    wireguard: &str,
    ml_dsa: &str,
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [5; 16],
            subject: subject.into(),
            issuer: "CA-PQ".into(),
            role,
            wireguard_public_key: wireguard.into(),
            ml_dsa_87_public_key: ml_dsa.into(),
            not_before_unix: now() - 60,
            not_after_unix: now() + 86_400,
            ml_dsa_87_signature: String::new(),
        },
        ca,
    )
    .unwrap()
}

fn tls_leaf(csr: &DerCertificate) -> (DerCertificate, DerCertificate) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let request = rcgen::CertificateSigningRequestParams::from_der(&csr.as_bytes().into()).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_der(ca.der(), &ca_key).unwrap();
    (
        DerCertificate::new(request.signed_by(&issuer).unwrap().der().to_vec()).unwrap(),
        DerCertificate::new(ca.der().to_vec()).unwrap(),
    )
}

fn fixture() -> Fixture {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let ca_public = MlDsa87PublicKey::new(ca_public).unwrap();
    let (_, client_ml_dsa) = generate_ml_dsa_87_keypair().unwrap();
    let client_ml_dsa = MlDsa87PublicKey::new(client_ml_dsa).unwrap();
    let client_wg = aether::wg::generate_keypair().unwrap();
    let gateway_wg = aether::wg::generate_keypair().unwrap();
    let csr = aether::certificates::x509::client_rotation_csr("poste-windows").unwrap();
    let request = EnrollmentRequest {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([1; 16]).unwrap(),
        invitation_fingerprint: Fingerprint::from_bytes([2; 32]),
        request_id: Id16::new([3; 16]).unwrap(),
        timestamp_unix: now(),
        requested_name: "poste-windows".into(),
        client_wg_public_key: WireGuardKey::parse(&client_wg.public_key).unwrap(),
        tls_csr: csr.csr,
        client_ml_dsa_87_public_key: client_ml_dsa.clone(),
        wireguard_proof: [0; 32],
        client_signature: MlDsa87Signature::placeholder(),
    };
    let (tls_certificate, tls_ca) = tls_leaf(&request.tls_csr);
    let pq_certificate = pq_leaf(
        &ca_private,
        PqCertificateRole::Client,
        "poste-windows",
        &client_wg.public_key,
        &client_ml_dsa.to_base64(),
    );
    let (_, gateway_ml_dsa) = generate_ml_dsa_87_keypair().unwrap();
    let gateway = pq_leaf(
        &ca_private,
        PqCertificateRole::Gateway,
        SERVER_NAME,
        &gateway_wg.public_key,
        &STANDARD.encode(&gateway_ml_dsa),
    );
    Fixture {
        material: GatewayMaterial {
            server_name: SERVER_NAME.into(),
            gateway_ca_der: STANDARD.encode([0x30, 0x82, 0x01, 0x00]),
            gateway_pq_certificate: STANDARD.encode(serde_json::to_vec(&gateway).unwrap()),
            wireguard_public_key: gateway_wg.public_key,
            pq_certificate_sha256: gateway.fingerprint().unwrap(),
            negotiation_port: Some(51821),
        },
        trust: TrustMaterial {
            trust_domain_id: "11".repeat(16),
            ca_epoch: 1,
            ca_pq_public_key: ca_public.to_base64(),
            ca_tls_epoch: 1,
            client_tls_ca_der: STANDARD.encode(tls_ca.as_bytes()),
            client_generation: 1,
            astra_authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: Fingerprint::of(b"policy").to_hex(),
            credential_registry_epoch: 1,
            astra_credential_bindings: Vec::new(),
            astra_service_key_epoch: 1,
            astra_service_public_key: ca_public.to_base64(),
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
        },
        request,
        tls_certificate,
        pq_certificate,
    }
}

fn draft(fixture: &Fixture, trust: Option<TrustMaterial>) -> Result<EnrollmentDocument> {
    build_draft(DraftInput {
        request: &fixture.request,
        tls_certificate: fixture.tls_certificate.clone(),
        pq_certificate: &fixture.pq_certificate,
        material: &fixture.material,
        admission: Admission {
            address: "100.64.1.2/32".into(),
            address_v6: None,
            heliosd_url: None,
            trust,
        },
        endpoint: "vpn.example.net:51820",
        negotiation_endpoint: "vpn.example.net:51821".into(),
        allowed_ips: None,
        ssh_target: None,
        now_unix: now(),
    })
}

#[test]
fn a_draft_without_a_trust_domain_is_refused() {
    let fixture = fixture();
    let error = format!("{:#}", draft(&fixture, None).expect_err("refused"));
    assert!(error.contains("domaine de confiance"), "{error}");
    assert!(error.contains("heliosd init-trust-domain"), "{error}");
}

#[test]
fn a_draft_for_leaves_that_do_not_certify_the_request_is_refused() {
    let mine = fixture();
    let other = fixture();
    assert!(check_leaves(&mine.request, &other.tls_certificate, &mine.pq_certificate).is_err());
    assert!(check_leaves(&mine.request, &mine.tls_certificate, &other.pq_certificate).is_err());
    check_leaves(&mine.request, &mine.tls_certificate, &mine.pq_certificate)
        .expect("the leaves of this request");
    // Leaves of this request, under another domain's CA-PQ.
    let mut foreign = other.trust.clone();
    foreign.client_tls_ca_der = mine.trust.client_tls_ca_der.clone();
    assert!(draft(&mine, Some(foreign)).is_err());
}

#[test]
fn a_draft_carries_no_identity_and_no_signature() {
    let fixture = fixture();
    let document = draft(&fixture, Some(fixture.trust.clone())).expect("draft");
    assert!(document.operator_signature.is_none());
    assert_eq!(document.request_fingerprint, fixture.request.fingerprint());
    assert_eq!(
        document.operator_ca_fingerprint,
        MlDsa87PublicKey::parse(&fixture.trust.ca_pq_public_key)
            .unwrap()
            .authority_fingerprint()
    );
    let json = document.to_json().unwrap();
    for absent in [
        "key_negotiation_identity",
        "private_key",
        "operator_signature",
        "\"identity\"",
        "preshared_key",
    ] {
        assert!(!json.contains(absent), "{absent} in {json}");
    }
    let imported = crate::parse_profile_import(&json, "draft.orion").expect("Orion reads it");
    assert!(imported.enrollment.is_some());
    assert_eq!(imported.profile.name, "poste-windows");
}

/// The negotiation port is the gateway's to state: hardcoding 51821 would
/// silently produce unreachable profiles on a gateway that moved it.
#[test]
fn the_negotiation_endpoint_keeps_the_host_and_takes_the_published_port() {
    assert_eq!(
        resolve_negotiation_endpoint("vpn.example.net:51820", None, Some(51821)).unwrap(),
        "vpn.example.net:51821"
    );
    assert_eq!(
        resolve_negotiation_endpoint("[2001:db8::1]:51820", None, Some(7777)).unwrap(),
        "[2001:db8::1]:7777"
    );
    assert_eq!(
        resolve_negotiation_endpoint(
            "vpn.example.net:51820",
            Some("autre.example.net:51821"),
            None
        )
        .unwrap(),
        "autre.example.net:51821"
    );
    assert!(resolve_negotiation_endpoint("vpn.example.net:51820", None, None).is_err());
}
