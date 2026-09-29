use super::*;
use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
use crate::certificates::window::MAX_OVERLAP_SECS;
use zeroize::Zeroizing;

struct Authority {
    private: Zeroizing<Vec<u8>>,
    public: MlDsa87PublicKey,
}

fn authority() -> Authority {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    Authority { private, public }
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([9; 16]).expect("domain")
}

fn window() -> TransitionWindow {
    TransitionWindow::new(1_000, 2_000, 2_000 + MAX_OVERLAP_SECS).expect("window")
}

fn ca_transition(current: &Authority, next: &Authority) -> CaTransition {
    let mut transition = CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        current_ca_epoch: 1,
        next_ca_epoch: 2,
        current_ca_fingerprint: current.public.authority_fingerprint(),
        next_ca_public_key: next.public.clone(),
        next_ca_fingerprint: next.public.authority_fingerprint(),
        window: window(),
        current_ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        next_ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
    };
    let transcript = transition.signing_bytes();
    transition.current_ca_signature =
        sign_ml_dsa_87(&current.private, &transcript).expect("sign current");
    transition.next_ca_signature = sign_ml_dsa_87(&next.private, &transcript).expect("sign next");
    transition
}

#[test]
fn a_ca_transition_needs_both_the_continuity_and_the_possession_signature() {
    let current = authority();
    let next = authority();
    let transition = ca_transition(&current, &next);
    assert!(transition.verify(&current.public, &domain(), 1).is_ok());

    // Continuity alone: the successor's own signature is replaced by one
    // from a key nobody authorized.
    let impostor = authority();
    let mut forged = transition.clone();
    forged.next_ca_signature =
        sign_ml_dsa_87(&impostor.private, &transition.signing_bytes()).expect("sign");
    assert!(matches!(
        forged.verify(&current.public, &domain(), 1),
        Err(CertificateError::InvalidSignature)
    ));

    // Possession alone: the document is not authorized by the trusted
    // anchor at all.
    let mut unauthorized = transition.clone();
    unauthorized.current_ca_signature =
        sign_ml_dsa_87(&impostor.private, &transition.signing_bytes()).expect("sign");
    assert!(matches!(
        unauthorized.verify(&current.public, &domain(), 1),
        Err(CertificateError::InvalidSignature)
    ));
}

/// The anchor comes from the local trust store. A document signed by a CA
/// the verifier does not already hold proves nothing about the domain.
#[test]
fn a_ca_transition_under_an_unknown_anchor_is_refused() {
    let current = authority();
    let next = authority();
    let stranger = authority();
    let transition = ca_transition(&current, &next);
    assert!(matches!(
        transition.verify(&stranger.public, &domain(), 1),
        Err(CertificateError::FingerprintMismatch("current CA"))
    ));
}

#[test]
fn a_ca_transition_refuses_a_skipped_or_reversed_epoch() {
    let current = authority();
    let next = authority();
    let transition = ca_transition(&current, &next);
    assert!(matches!(
        transition.verify(&current.public, &domain(), 2),
        Err(CertificateError::GenerationRollback { .. })
    ));
    assert!(matches!(
        transition.verify(&current.public, &domain(), 0),
        Err(CertificateError::GenerationRollback { .. })
    ));
}

#[test]
fn a_ca_transition_for_another_domain_is_refused_before_any_signature() {
    let current = authority();
    let next = authority();
    let mut transition = ca_transition(&current, &next);
    transition.trust_domain_id = TrustDomainId::new([1; 16]).expect("domain");
    assert!(matches!(
        transition.verify(&current.public, &domain(), 1),
        Err(CertificateError::TrustDomainMismatch)
    ));
}

fn issuer_authorization(ca: &Authority, issuer: &MlDsa87PublicKey) -> AstraIssuerAuthorization {
    let mut authorization = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        server_name: "gateway.example".into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer.clone(),
        tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
            "astra-issuer",
        ),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 90 * 86_400,
        policy_fingerprint: Fingerprint::of(b"policy"),
        not_before: 1_000,
        not_after: 100_000,
        ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
    };
    authorization.ca_pq_signature =
        sign_ml_dsa_87(&ca.private, &authorization.signing_bytes()).expect("sign");
    authorization
}

#[test]
fn a_delegation_is_bound_to_one_gateway_one_domain_and_one_window() {
    let ca = authority();
    let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
    let authorization = issuer_authorization(&ca, &issuer);
    let gateway = WireGuardKey::from_bytes([2; 32]);

    assert!(authorization
        .verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway,
            "gateway.example",
            2_000
        )
        .is_ok());

    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &WireGuardKey::from_bytes([7; 32]),
            "gateway.example",
            2_000
        ),
        Err(CertificateError::GatewayIdentityMismatch)
    ));
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway,
            "other.example",
            2_000
        ),
        Err(CertificateError::GatewayIdentityMismatch)
    ));
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway,
            "gateway.example",
            100_001
        ),
        Err(CertificateError::IssuerAuthorizationExpired)
    ));
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            2,
            1,
            &gateway,
            "gateway.example",
            2_000
        ),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

/// The four refusals that make the delegation worth having: an online
/// issuer renews tomorrow's leaf of an admitted peer, and nothing else.
#[test]
fn a_delegation_covers_only_the_next_generation_of_an_ordinary_renewal() {
    let ca = authority();
    let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
    let authorization = issuer_authorization(&ca, &issuer);

    assert!(authorization
        .authorize_renewal(4, 5, 30 * 86_400, RotationReason::Scheduled)
        .is_ok());
    assert!(authorization
        .authorize_renewal(4, 5, 30 * 86_400, RotationReason::ManualGlobal)
        .is_ok());

    for forbidden in [
        RotationReason::ExpiredRecovery,
        RotationReason::Readmission,
        RotationReason::EmergencyReplacement,
        RotationReason::KeyRecovery,
    ] {
        assert!(matches!(
            authorization.authorize_renewal(4, 5, 30 * 86_400, forbidden),
            Err(CertificateError::IssuerScopeViolation("reason"))
        ));
    }
    assert!(matches!(
        authorization.authorize_renewal(4, 6, 30 * 86_400, RotationReason::Scheduled),
        Err(CertificateError::IssuerScopeViolation("generation"))
    ));
    assert!(matches!(
        authorization.authorize_renewal(4, 5, 91 * 86_400, RotationReason::Scheduled),
        Err(CertificateError::IssuerScopeViolation("leaf lifetime"))
    ));
}

#[test]
fn a_planned_service_key_rotation_needs_all_three_signatures() {
    let ca = authority();
    let current = authority();
    let next = authority();

    let mut transition = AstraServiceKeyTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        current_service_key_epoch: 3,
        next_service_key_epoch: 4,
        current_service_key_fingerprint: current.public.authority_fingerprint(),
        next_service_public_key: next.public.clone(),
        next_service_key_fingerprint: next.public.authority_fingerprint(),
        window: window(),
        reason: RotationReason::Scheduled,
        current_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        next_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let transcript = transition.signing_bytes();
    transition.current_service_key_signature =
        sign_ml_dsa_87(&current.private, &transcript).unwrap();
    transition.next_service_key_signature = sign_ml_dsa_87(&next.private, &transcript).unwrap();
    transition.ca_pq_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();

    assert!(transition
        .verify(&ca.public, &current.public, &domain(), 1, 3)
        .is_ok());

    for missing in 0..3 {
        let mut broken = transition.clone();
        let stranger = authority();
        let forged = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
        match missing {
            0 => broken.current_service_key_signature = forged,
            1 => broken.next_service_key_signature = forged,
            _ => broken.ca_pq_signature = forged,
        }
        assert!(matches!(
            broken.verify(&ca.public, &current.public, &domain(), 1, 3),
            Err(CertificateError::InvalidSignature)
        ));
    }
}

/// A compromised key must not be able to block its own eviction, so the
/// emergency object carries no signature from it.
#[test]
fn an_emergency_replacement_needs_ca_pq_and_the_new_key_only() {
    let ca = authority();
    let next = authority();

    let mut replacement = EmergencyAstraServiceKeyReplacement {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        current_service_key_epoch: 3,
        next_service_key_epoch: 4,
        revoked_service_key_fingerprint: Fingerprint::of(b"revoked"),
        next_service_public_key: next.public.clone(),
        next_service_key_fingerprint: next.public.authority_fingerprint(),
        revocation_epoch: 1,
        effective_at: 1_000,
        reason: RotationReason::EmergencyReplacement,
        next_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let transcript = replacement.signing_bytes();
    replacement.next_service_key_signature = sign_ml_dsa_87(&next.private, &transcript).unwrap();
    replacement.ca_pq_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();

    assert!(replacement.verify(&ca.public, &domain(), 1, 3, 0).is_ok());

    // The revocation counter advances on its own axis and cannot stand still.
    assert!(matches!(
        replacement.verify(&ca.public, &domain(), 1, 3, 1),
        Err(CertificateError::GenerationConflict { .. })
    ));

    let stranger = authority();
    let mut forged = replacement.clone();
    forged.ca_pq_signature = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
    assert!(matches!(
        forged.verify(&ca.public, &domain(), 1, 3, 0),
        Err(CertificateError::InvalidSignature)
    ));
}
