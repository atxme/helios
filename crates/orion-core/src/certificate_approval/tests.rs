use super::*;
use crate::test_domain::{client_key, domain, domain_id, gateway_key, NOW};
use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraCredentialBinding, CredentialRegistry, CredentialState,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, TrustDomainId,
};
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use zeroize::Zeroizing;

const RP_ID: &str = "astra.example";

struct Fixture {
    served: ClientRenewalSignerRequest,
    state: TrustState,
    service_private: Zeroizing<Vec<u8>>,
}

fn cose_es256_key() -> Vec<u8> {
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[3; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[5; 32]);
    key
}

fn binding(
    ca_private: &[u8],
    id: &[u8],
    state: CredentialState,
    registry_epoch: u64,
) -> AstraCredentialBinding {
    AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: id.to_vec(),
        credential_public_key: cose_es256_key(),
        aaguid: [0; 16],
        trust_domain_id: domain_id(),
        gateway_wg_public_key: gateway_key(),
        state,
        credential_epoch: 1,
        credential_registry_epoch: registry_epoch,
        ca_epoch: 1,
        created_at: NOW,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("CA-PQ signs credential binding")
}

fn fixture() -> Fixture {
    let domain = domain();
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service key");
    let mut state = crate::test_domain::store(std::path::Path::new(""), &domain)
        .state()
        .clone();
    state.astra.active_astra_service_public_key = service_public;

    let registry_epoch = state.astra.credential_registry_epoch;
    let registry = CredentialRegistry {
        trust_domain_id: domain_id(),
        gateway_wg_public_key: gateway_key(),
        ca_epoch: 1,
        credential_registry_epoch: registry_epoch,
        bindings: vec![
            binding(
                &domain.ca_pq_private,
                b"eligible-one",
                CredentialState::Active,
                registry_epoch,
            ),
            binding(
                &domain.ca_pq_private,
                b"eligible-two",
                CredentialState::Active,
                registry_epoch,
            ),
            binding(
                &domain.ca_pq_private,
                b"lost",
                CredentialState::Lost,
                registry_epoch,
            ),
            binding(
                &domain.ca_pq_private,
                b"not-allowed",
                CredentialState::Active,
                registry_epoch,
            ),
        ],
    };
    let request = AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: Id16::new([5; 16]).expect("operation id"),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        trust_domain_id: domain_id(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: state.certificates.active.generation,
        requested_generation: state.certificates.active.generation + 1,
        credential_registry_epoch: registry_epoch,
        webauthn_rp_id: RP_ID.into(),
        webauthn_origin: format!("https://{RP_ID}"),
        allowed_credential_ids: vec![
            b"eligible-one".to_vec(),
            b"eligible-two".to_vec(),
            b"lost".to_vec(),
        ],
        required_credentials: aether::certificates::approval::PER_REQUEST_APPROVAL_CREDENTIALS,
        created_at: NOW,
        expires_at: NOW + 240,
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service_private)
    .expect("Astra signs request");

    Fixture {
        served: ClientRenewalSignerRequest {
            operation_id: request.operation_id,
            approval_request: Box::new(request),
            credential_registry: Box::new(registry),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: RP_ID.into(),
        },
        state,
        service_private,
    }
}

#[test]
fn verifies_signed_request_and_ca_registry_against_profile_pins() {
    let fixture = fixture();
    assert!(VerifiedApproval::verify(fixture.served, &fixture.state, NOW).is_ok());
}

#[test]
fn refuses_foreign_rp_and_mismatched_operation_id() {
    let fixture = fixture();
    let mut foreign_rp = fixture.served.clone();
    foreign_rp.webauthn_rp_id = "other.example".into();
    assert!(matches!(
        VerifiedApproval::verify(foreign_rp, &fixture.state, NOW),
        Err(ApprovalError::ForeignRelyingParty { .. })
    ));

    let mut wrong_operation = fixture.served;
    wrong_operation.operation_id = Id16::new([6; 16]).expect("operation id");
    assert!(matches!(
        VerifiedApproval::verify(wrong_operation, &fixture.state, NOW),
        Err(ApprovalError::OperationMismatch { .. })
    ));
}

#[test]
fn refuses_tampering_with_signed_request_and_expired_request() {
    let fixture = fixture();
    let mut tampered = fixture.served.clone();
    tampered.approval_request.request_fingerprint = Fingerprint::of(b"changed request");
    assert!(matches!(
        VerifiedApproval::verify(tampered, &fixture.state, NOW),
        Err(ApprovalError::Certificate(_))
    ));

    let expires_at = fixture.served.approval_request.expires_at;
    VerifiedApproval::verify(fixture.served.clone(), &fixture.state, expires_at - 1)
        .expect("valid immediately before expiry");
    assert!(matches!(
        VerifiedApproval::verify(fixture.served, &fixture.state, expires_at),
        Err(ApprovalError::Certificate(
            aether::certificates::CertificateError::StageExpired
        ))
    ));
}

#[test]
fn refuses_unpinned_service_key_wrong_domain_and_bad_registry_signature() {
    let fixture = fixture();
    let (_, other_public) = generate_ml_dsa_87_keypair().expect("other service key");
    let mut wrong_profile_key = fixture.state.clone();
    wrong_profile_key.astra.active_astra_service_public_key = other_public;
    assert!(matches!(
        VerifiedApproval::verify(fixture.served.clone(), &wrong_profile_key, NOW),
        Err(ApprovalError::Certificate(_))
    ));

    let mut wrong_domain = fixture.served.clone();
    wrong_domain.approval_request.trust_domain_id = TrustDomainId::new([8; 16]).expect("domain");
    wrong_domain.approval_request = Box::new(
        (*wrong_domain.approval_request)
            .sign(&fixture.service_private)
            .expect("sign request for another domain"),
    );
    assert!(matches!(
        VerifiedApproval::verify(wrong_domain, &fixture.state, NOW),
        Err(ApprovalError::Certificate(_))
    ));

    let mut invalid_registry = fixture.served;
    invalid_registry.credential_registry.bindings[0].credential_id = b"forged".to_vec();
    assert!(matches!(
        VerifiedApproval::verify(invalid_registry, &fixture.state, NOW),
        Err(ApprovalError::Certificate(_))
    ));
}

#[test]
fn manifest_uses_verified_fields_and_counts_only_allowed_active_credentials() {
    let fixture = fixture();
    let expected = &fixture.served.approval_request;
    let verified = VerifiedApproval::verify(fixture.served.clone(), &fixture.state, NOW)
        .expect("valid signed approval request");
    assert_eq!(
        verified.manifest(),
        ApprovalManifest {
            operation_id: expected.operation_id.to_hex(),
            client_wg_public_key: expected.client_wg_public_key.to_base64(),
            active_generation: expected.active_generation,
            requested_generation: expected.requested_generation,
            request_fingerprint: expected.request_fingerprint.to_hex(),
            expires_at: expected.expires_at,
            eligible_credentials: 2,
        }
    );
}
