use super::*;
use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
use crate::key_negotiation::{issue_pq_certificate, PQ_CERTIFICATE_VERSION};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use zeroize::Zeroizing;

const SERVER_NAME: &str = "gateway.example";

struct Keys {
    private: Zeroizing<Vec<u8>>,
    public: MlDsa87PublicKey,
}

fn keys() -> Keys {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    Keys { private, public }
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([4; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([5; 32])
}

fn window() -> TransitionWindow {
    TransitionWindow::new(1_000, 2_000, 3_000).expect("window")
}

/// A gateway leaf issued by `CA-PQ`, valid across the whole window.
fn gateway_leaf(ca: &Keys, subject: &Keys) -> PqCertificate {
    let certificate = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [1; 16],
        subject: SERVER_NAME.into(),
        issuer: "CA-PQ".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: gateway_key().to_base64(),
        ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
        not_before_unix: 0,
        not_after_unix: 100_000,
        ml_dsa_87_signature: String::new(),
    };
    issue_pq_certificate(certificate, &ca.private).expect("issue")
}

fn gateway_tls_leaf(server_name: &str, not_after_year: i32) -> DerCertificate {
    let mut params = CertificateParams::new(vec![server_name.to_string()]).expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
    let key = KeyPair::generate().expect("TLS key");
    let certificate = params.self_signed(&key).expect("TLS certificate");
    DerCertificate::new(certificate.der().to_vec()).expect("DER")
}

#[test]
fn a_bootstrap_request_proves_the_key_sealed_by_the_gateway() {
    let gateway = keys();
    let request = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        ml_dsa_87_public_key: gateway.public.clone(),
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway.private)
    .expect("sign request");

    request.verify().expect("verify request");

    let mut substituted = request;
    substituted.gateway_wg_public_key = WireGuardKey::from_bytes([9; 32]);
    assert!(matches!(
        substituted.verify(),
        Err(CertificateError::MissingProof("bootstrap gateway"))
    ));
}

fn transition(ca: &Keys, next_leaf: Option<PqCertificate>) -> GatewayIdentityTransition {
    let mut transition = GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        gateway_identity_epoch: 2,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: Fingerprint::of(b"active pq"),
        next_gateway_certificate: next_leaf,
        window: window(),
        reason: RotationReason::Scheduled,
        ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
    };
    let transcript = transition.signing_bytes().expect("transcript");
    transition.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
    transition
}

/// §6.1 admits three reasons; `RotationReason` carries six, and the other
/// three describe a client decision. Nothing downstream reads this field,
/// which is why an unchecked value would be a signed lie nobody notices.
#[test]
fn a_transition_carries_only_the_three_reasons_of_the_gateway() {
    let ca = keys();
    let subject = keys();
    let leaf = gateway_leaf(&ca, &subject);

    for reason in [
        RotationReason::Scheduled,
        RotationReason::KeyRecovery,
        RotationReason::EmergencyReplacement,
    ] {
        let mut accepted = transition(&ca, Some(leaf.clone()));
        accepted.reason = reason;
        let signed = resign(accepted, &ca);
        verify(&signed, &ca, 1).unwrap_or_else(|error| panic!("{reason:?}: {error}"));
    }

    for reason in [
        RotationReason::ManualGlobal,
        RotationReason::ExpiredRecovery,
        RotationReason::Readmission,
    ] {
        let mut refused = transition(&ca, Some(leaf.clone()));
        refused.reason = reason;
        let signed = resign(refused, &ca);
        assert!(
            matches!(
                verify(&signed, &ca, 1),
                Err(CertificateError::IssuerScopeViolation(_))
            ),
            "{reason:?} was accepted on a gateway transition"
        );
    }
}

fn resign(mut transition: GatewayIdentityTransition, ca: &Keys) -> GatewayIdentityTransition {
    let transcript = transition.signing_bytes().expect("transcript");
    transition.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
    transition
}

fn verify(
    transition: &GatewayIdentityTransition,
    ca: &Keys,
    decision_epoch: u64,
) -> Result<(), CertificateError> {
    transition.verify(
        &ca.public,
        &domain(),
        1,
        decision_epoch,
        &gateway_key(),
        SERVER_NAME,
        &Fingerprint::of(b"active tls"),
        &Fingerprint::of(b"active pq"),
    )
}

#[test]
fn a_transition_may_carry_tls_alone_pq_alone_or_both() {
    let ca = keys();
    let subject = keys();
    let leaf = gateway_leaf(&ca, &subject);

    let pq_only = transition(&ca, Some(leaf.clone()));
    assert!(verify(&pq_only, &ca, 1).is_ok());

    let tls_leaf = gateway_tls_leaf(SERVER_NAME, 4096);
    let mut tls_only = transition(&ca, None);
    tls_only.next_gateway_tls_certificate = Some(tls_leaf.clone());
    let transcript = tls_only.signing_bytes().unwrap();
    tls_only.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    assert!(verify(&tls_only, &ca, 1).is_ok());

    let mut both = transition(&ca, Some(leaf));
    both.next_gateway_tls_certificate = Some(tls_leaf);
    let transcript = both.signing_bytes().unwrap();
    both.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    assert!(verify(&both, &ca, 1).is_ok());
}

#[test]
fn a_gateway_tls_leaf_must_be_a_valid_self_signed_server_identity() {
    let ca = keys();
    let mut malformed = transition(&ca, None);
    malformed.next_gateway_tls_certificate =
        Some(DerCertificate::new(vec![7; 64]).expect("bounded DER"));
    let transcript = malformed.signing_bytes().expect("transcript");
    malformed.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
    assert!(matches!(
        verify(&malformed, &ca, 1),
        Err(CertificateError::InvalidX509("unparsable"))
    ));

    let mut wrong_name = transition(&ca, None);
    wrong_name.next_gateway_tls_certificate = Some(gateway_tls_leaf("other.example", 4096));
    let transcript = wrong_name.signing_bytes().expect("transcript");
    wrong_name.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
    assert!(matches!(
        verify(&wrong_name, &ca, 1),
        Err(CertificateError::InvalidX509(
            "gateway DNS name is not in subjectAltName"
        ))
    ));
}

/// A transition that installs nothing is not a decision.
#[test]
fn a_transition_with_neither_leaf_is_refused() {
    let ca = keys();
    let empty = transition(&ca, None);
    assert!(matches!(
        verify(&empty, &ca, 1),
        Err(CertificateError::EmptyTransition)
    ));
}

/// The signed transcript carries the leaf's fingerprint, so swapping the
/// certificate changes the signature — the parser catches it before ever
/// verifying a chain.
#[test]
fn substituting_the_embedded_leaf_breaks_the_signature() {
    let ca = keys();
    let subject = keys();
    let other = keys();
    let mut forged = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    forged.next_gateway_certificate = Some(gateway_leaf(&ca, &other));
    assert!(matches!(
        verify(&forged, &ca, 1),
        Err(CertificateError::InvalidSignature)
    ));
}

/// A leaf that dies inside the overlap would promote the fleet onto an
/// already-expired identity.
#[test]
fn a_next_leaf_must_outlive_the_overlap() {
    let ca = keys();
    let subject = keys();
    let mut leaf = gateway_leaf(&ca, &subject);
    leaf.not_after_unix = 2_500;
    let leaf = issue_pq_certificate(leaf, &ca.private).expect("reissue");
    let short_lived_transition = transition(&ca, Some(leaf));
    assert!(matches!(
        verify(&short_lived_transition, &ca, 1),
        Err(CertificateError::OutsideValidityPeriod)
    ));

    let mut equal = gateway_leaf(&ca, &subject);
    equal.not_after_unix = window().not_after;
    let equal = issue_pq_certificate(equal, &ca.private).expect("reissue");
    assert!(matches!(
        verify(&transition(&ca, Some(equal)), &ca, 1),
        Err(CertificateError::OutsideValidityPeriod)
    ));
}

/// A leaf signed by anything other than the pinned `CA-PQ` is not a
/// gateway identity, whatever else the document proves.
#[test]
fn a_next_leaf_under_an_unpinned_authority_is_refused() {
    let ca = keys();
    let rogue = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&rogue, &subject)));
    assert!(matches!(
        verify(&transition, &ca, 1),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

#[test]
fn a_transition_is_bound_to_the_stable_gateway_identity() {
    let ca = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    assert!(matches!(
        transition.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &WireGuardKey::from_bytes([8; 32]),
            SERVER_NAME,
            &Fingerprint::of(b"active tls"),
            &Fingerprint::of(b"active pq"),
        ),
        Err(CertificateError::GatewayIdentityMismatch)
    ));
    assert!(matches!(
        transition.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &Fingerprint::of(b"another tls"),
            &Fingerprint::of(b"active pq"),
        ),
        Err(CertificateError::FingerprintMismatch("active gateway TLS"))
    ));
}

#[test]
fn a_transition_epoch_is_exactly_the_decision_epoch_plus_one() {
    let ca = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    assert!(verify(&transition, &ca, 1).is_ok());
    assert!(matches!(
        verify(&transition, &ca, 2),
        Err(CertificateError::GenerationConflict { .. })
    ));
    assert!(matches!(
        verify(&transition, &ca, 0),
        Err(CertificateError::GenerationSkipped { .. })
    ));
    assert!(matches!(
        verify(&transition, &ca, 3),
        Err(CertificateError::GenerationRollback { .. })
    ));
}

fn abort(
    ca: &Keys,
    transition: &GatewayIdentityTransition,
    aborted_at: u64,
) -> GatewayTransitionAbort {
    let mut abort = GatewayTransitionAbort {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: transition.trust_domain_id,
        ca_epoch: transition.ca_epoch,
        gateway_wg_public_key: transition.gateway_wg_public_key,
        server_name: transition.server_name.clone(),
        gateway_identity_epoch: transition.gateway_identity_epoch,
        gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        aborted_at,
        reason: AbortReason::OperatorCancelled,
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
    };
    abort.ca_signature = sign_ml_dsa_87(&ca.private, &abort.signing_bytes()).expect("sign");
    abort
}

#[test]
fn an_abort_is_accepted_only_before_publication_and_before_activation() {
    let ca = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    let abort = abort(&ca, &transition, 1_500);

    assert!(abort.verify(&ca.public, &transition, false, 1_600).is_ok());
    assert!(matches!(
        abort.verify(&ca.public, &transition, true, 1_600),
        Err(CertificateError::AlreadyPublished)
    ));
}

/// Antedating the object is not enough: the clock is read under the lock
/// that holds the staged slot, and it must also be before activation.
#[test]
fn an_antedated_abort_arriving_after_activation_is_refused() {
    let ca = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    let abort = abort(&ca, &transition, 1_500);
    assert!(matches!(
        abort.verify(&ca.public, &transition, false, 2_001),
        Err(CertificateError::IllegalStateTransition(_))
    ));
}

#[test]
fn an_abort_naming_another_transition_is_refused() {
    let ca = keys();
    let subject = keys();
    let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
    let mut abort = abort(&ca, &transition, 1_500);
    abort.gateway_transition_fingerprint = Fingerprint::of(b"another transition");
    abort.ca_signature = sign_ml_dsa_87(&ca.private, &abort.signing_bytes()).unwrap();
    assert!(matches!(
        abort.verify(&ca.public, &transition, false, 1_600),
        Err(CertificateError::FingerprintMismatch("gateway transition"))
    ));
}

#[test]
fn a_gateway_request_proves_the_new_key_and_the_continuity_of_the_old_one() {
    let active = keys();
    let candidate = keys();
    let mut request = GatewayCertificateRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        gateway_identity_epoch: 2,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        new_ml_dsa_87_public_key: candidate.public.clone(),
        request_id: Id16::new([6; 16]).expect("id"),
        created_at: 1_000,
        expires_at: 1_000 + 3_600,
        new_key_proof: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        current_key_authorization: None,
    };
    let transcript = request.signing_bytes();
    request.new_key_proof = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

    // Without the continuity signature, an ordinary renewal is refused.
    assert!(matches!(
        request.verify(
            Continuity::Required(&active.public),
            &domain(),
            1,
            &gateway_key(),
            SERVER_NAME,
            1_100
        ),
        Err(CertificateError::MissingProof("active gateway"))
    ));

    request.current_key_authorization = Some(sign_ml_dsa_87(&active.private, &transcript).unwrap());
    assert!(request
        .verify(
            Continuity::Required(&active.public),
            &domain(),
            1,
            &gateway_key(),
            SERVER_NAME,
            1_100
        )
        .is_ok());

    // On the recovery path the field must be absent, not merely unchecked.
    assert!(matches!(
        request.verify(
            Continuity::WaivedForKeyRecovery,
            &domain(),
            1,
            &gateway_key(),
            SERVER_NAME,
            1_100
        ),
        Err(CertificateError::IllegalStateTransition(_))
    ));
}

#[test]
fn an_expired_gateway_request_is_refused() {
    let candidate = keys();
    let mut request = GatewayCertificateRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        gateway_identity_epoch: 2,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        new_ml_dsa_87_public_key: candidate.public.clone(),
        request_id: Id16::new([6; 16]).expect("id"),
        created_at: 1_000,
        expires_at: 1_100,
        new_key_proof: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        current_key_authorization: None,
    };
    request.new_key_proof = sign_ml_dsa_87(&candidate.private, &request.signing_bytes()).unwrap();
    assert!(matches!(
        request.verify(
            Continuity::WaivedForKeyRecovery,
            &domain(),
            1,
            &gateway_key(),
            SERVER_NAME,
            1_100
        ),
        Err(CertificateError::StageExpired)
    ));

    // A lifetime beyond 24 hours is refused whatever the clock says.
    request.expires_at = 1_000 + MAX_REQUEST_LIFETIME_SECS + 1;
    request.new_key_proof = sign_ml_dsa_87(&candidate.private, &request.signing_bytes()).unwrap();
    assert!(matches!(
        request.verify(
            Continuity::WaivedForKeyRecovery,
            &domain(),
            1,
            &gateway_key(),
            SERVER_NAME,
            1_100
        ),
        Err(CertificateError::InvalidLease)
    ));
}
