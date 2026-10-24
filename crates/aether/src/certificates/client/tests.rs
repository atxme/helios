use super::*;
use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
use crate::key_negotiation::{issue_pq_certificate, PQ_CERTIFICATE_VERSION};
use base64::{engine::general_purpose::STANDARD, Engine as _};
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
    TrustDomainId::new([3; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([1; 32])
}

fn client_key() -> WireGuardKey {
    WireGuardKey::from_bytes([2; 32])
}

fn automatic_policy_fingerprint() -> Fingerprint {
    crate::certificates::approval::AstraIssuancePolicy::standard(
        domain(),
        gateway_key(),
        SERVER_NAME.into(),
    )
    .fingerprint()
    .expect("automatic policy")
}

fn client_leaf(ca: &Keys, subject: &Keys, serial: u8) -> PqCertificate {
    client_leaf_valid_during(ca, subject, serial, 0, 100_000)
}

fn client_leaf_valid_during(
    ca: &Keys,
    subject: &Keys,
    serial: u8,
    not_before_unix: u64,
    not_after_unix: u64,
) -> PqCertificate {
    let certificate = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [serial; 16],
        subject: "orion".into(),
        issuer: "CA-PQ".into(),
        role: PqCertificateRole::Client,
        wireguard_public_key: client_key().to_base64(),
        ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
        not_before_unix,
        not_after_unix,
        ml_dsa_87_signature: String::new(),
    };
    issue_pq_certificate(certificate, &ca.private).expect("issue")
}

fn tls_material() -> crate::certificates::test_x509::TlsMaterial {
    crate::certificates::test_x509::client_material("workstation")
}

fn active_generation() -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        not_before: 0,
        not_after: 100_000,
    }
}

fn request(active: &Keys, candidate: &Keys) -> ClientCertificateRotationRequest {
    let mut request = ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([8; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        requested_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        tls_csr: DerCertificate::new(vec![9; 256]).expect("csr"),
        new_ml_dsa_87_public_key: candidate.public.clone(),
        created_at: 1_000,
        expires_at: 1_000 + 3_600,
        active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        new_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let transcript = request.signing_bytes();
    request.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
    request.new_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();
    request
}

#[test]
fn a_rotation_request_needs_continuity_and_possession() {
    let active = keys();
    let candidate = keys();
    let request = request(&active, &candidate);

    assert!(request
        .verify(
            &active.public,
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(),
            &client_key(),
            1_100
        )
        .is_ok());

    let stranger = keys();
    let mut forged = request.clone();
    forged.active_pq_signature =
        sign_ml_dsa_87(&stranger.private, &request.signing_bytes()).unwrap();
    assert!(matches!(
        forged.verify(
            &active.public,
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(),
            &client_key(),
            1_100
        ),
        Err(CertificateError::MissingProof("active client"))
    ));

    let mut unproven = request.clone();
    unproven.new_pq_signature =
        sign_ml_dsa_87(&stranger.private, &request.signing_bytes()).unwrap();
    assert!(matches!(
        unproven.verify(
            &active.public,
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(),
            &client_key(),
            1_100
        ),
        Err(CertificateError::MissingProof("new client"))
    ));
}

/// A renewal never moves the WireGuard identity: that is a readmission.
#[test]
fn a_rotation_request_for_another_peer_is_refused() {
    let active = keys();
    let candidate = keys();
    let request = request(&active, &candidate);
    assert!(matches!(
        request.verify(
            &active.public,
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(),
            &WireGuardKey::from_bytes([9; 32]),
            1_100
        ),
        Err(CertificateError::ClientIdentityMismatch)
    ));
}

#[test]
fn a_rotation_request_asks_for_exactly_the_next_generation() {
    let active = keys();
    let candidate = keys();
    let mut request = request(&active, &candidate);
    request.requested_generation = 6;
    let transcript = request.signing_bytes();
    request.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
    request.new_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();
    assert!(matches!(
        request.verify(
            &active.public,
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(),
            &client_key(),
            1_100
        ),
        Err(CertificateError::GenerationSkipped { .. })
    ));
}

/// The two mixed pairs of spec §3.3, refused by the generation itself.
#[test]
fn a_generation_refuses_a_mixed_tls_and_pq_pair() {
    let generation = active_generation();
    assert!(generation.accepts_pair(
        &Fingerprint::of(b"active tls"),
        &Fingerprint::of(b"active pq")
    ));
    assert!(!generation.accepts_pair(
        &Fingerprint::of(b"active tls"),
        &Fingerprint::of(b"next pq")
    ));
    assert!(!generation.accepts_pair(
        &Fingerprint::of(b"next tls"),
        &Fingerprint::of(b"active pq")
    ));
}

fn authorization(
    issuer: &Keys,
    ca: &Keys,
    candidate_leaf: PqCertificate,
    request_fingerprint: Fingerprint,
    tls: &crate::certificates::test_x509::TlsMaterial,
) -> ClientCertificateStageAuthorization {
    let mut authorization = ClientCertificateStageAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        stage_id: Id16::new([5; 16]).expect("stage"),
        request_fingerprint,
        renewal_authorization_fingerprint: Fingerprint::of(b"operator approval"),
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        next_tls_ca_certificate_fingerprint: tls.authority.fingerprint(),
        next_tls_certificate: tls.leaf.clone(),
        next_pq_certificate: candidate_leaf,
        issued_at: 1_000,
        stage_expires_at: 1_000 + 3_600,
        window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
        reason: RotationReason::Scheduled,
        signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let _ = issuer;
    let transcript = authorization.signing_bytes().expect("transcript");
    authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    authorization
}

#[test]
fn a_master_authorization_verifies_directly_under_ca_pq() {
    let ca = keys();
    let subject = keys();
    let leaf = client_leaf(&ca, &subject, 2);
    let tls = tls_material();
    let authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);

    assert!(authorization
        .verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            None,
            1_100,
        )
        .is_ok());
}

/// A `master` authorization that also carries a delegation is refused:
/// two authorities named at once is one authority too many.
#[test]
fn a_master_authorization_carrying_a_delegation_is_refused() {
    let ca = keys();
    let subject = keys();
    let leaf = client_leaf(&ca, &subject, 2);
    let tls = tls_material();
    let mut authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);
    authorization.issuer_authorization_fingerprint = Fingerprint::of(b"delegation");
    let transcript = authorization.signing_bytes().unwrap();
    authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            None,
            1_100,
        ),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

/// A leaf issued by the delegated issuer chains to **that issuer**, and
/// the delegation is what makes the issuer stand for the authority. Both
/// halves matter: reading the leaf under `CA-PQ` would refuse every
/// ordinary renewal, and skipping the delegation check would accept a leaf
/// nobody authorized.
#[test]
fn an_astra_issued_leaf_chains_to_the_delegation_not_to_ca_pq() {
    use crate::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};

    let ca = keys();
    let issuer = keys();
    let subject = keys();
    let tls = tls_material();

    let delegation = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 3,
        pq_issuer_public_key: issuer.public.clone(),
        tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
            "astra-issuer",
        ),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 200_000,
        policy_fingerprint: automatic_policy_fingerprint(),
        not_before: 0,
        not_after: 500_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("sign delegation");

    let delegated_leaf = client_leaf(&issuer, &subject, 4);
    let mut authorization =
        authorization(&ca, &ca, delegated_leaf, Fingerprint::of(b"request"), &tls);
    authorization.issuer_kind = IssuerKind::Astra;
    authorization.issuer_epoch = 3;
    authorization.issuer_authorization_fingerprint = delegation.fingerprint();
    authorization.issuer_authorization = Some(delegation.clone());
    authorization.renewal_authorization_fingerprint = authorization.request_fingerprint;
    authorization.renewal_approval = None;
    let authorization = authorization.sign(&issuer.private).expect("sign");

    authorization
        .verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            Some(&AstraPolicyPin::new(automatic_policy_fingerprint()).expect("policy pin")),
            None,
            1_100,
        )
        .expect("a delegated leaf verifies under its delegation");

    let mut missing_binding = authorization.clone();
    missing_binding.renewal_authorization_fingerprint = Fingerprint::of(b"another request");
    let missing_binding = missing_binding.sign(&issuer.private).expect("sign");
    assert!(matches!(
        missing_binding.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            Some(&AstraPolicyPin::new(automatic_policy_fingerprint()).expect("policy pin"),),
            None,
            1_100,
        ),
        Err(CertificateError::ApprovalMismatch(
            "automatic renewal request binding"
        ))
    ));

    // The same object carrying a leaf issued by `CA-PQ` instead does not:
    // the delegation names the issuer, and the leaf must match it.
    let master_leaf = client_leaf(&ca, &subject, 5);
    let mut mismatched = authorization.clone();
    mismatched.next_pq_certificate = master_leaf;
    let mismatched = mismatched.sign(&issuer.private).expect("sign");
    assert!(matches!(
        mismatched.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            Some(&AstraPolicyPin::new(automatic_policy_fingerprint()).expect("policy pin"),),
            None,
            1_100,
        ),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

#[test]
fn a_staging_lease_never_outlives_activation_or_twenty_four_hours() {
    let ca = keys();
    let subject = keys();
    let leaf = client_leaf(&ca, &subject, 2);
    let tls = tls_material();
    let mut authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);

    authorization.stage_expires_at = authorization.window.activation_at + 1;
    let transcript = authorization.signing_bytes().unwrap();
    authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            None,
            1_100,
        ),
        Err(CertificateError::InvalidLease)
    ));

    authorization.stage_expires_at = authorization.issued_at + MAX_STAGE_LEASE_SECS + 1;
    authorization.window =
        TransitionWindow::new(1_000, 1_000 + MAX_STAGE_LEASE_SECS + 100, 200_000).unwrap();
    let transcript = authorization.signing_bytes().unwrap();
    authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
    assert!(matches!(
        authorization.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            None,
            1_100,
        ),
        Err(CertificateError::LeaseTooLong { .. })
    ));
}

/// Recovery is the only family whose activation can already be reached
/// while its stage lease remains open. The candidate is still unusable
/// until commit moves it out of `pending_grant`; ordinary rotations keep
/// the stricter lease-before-activation rule.
#[test]
fn an_expired_recovery_stage_can_outlive_immediate_activation() {
    let ca = keys();
    let subject = keys();
    let leaf = client_leaf(&ca, &subject, 2);
    let tls = tls_material();
    let mut authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);
    authorization.reason = RotationReason::ExpiredRecovery;
    authorization.window = TransitionWindow::new(900, 1_000, 20_000).expect("window");
    authorization.stage_expires_at = 4_600;
    let authorization = authorization.sign(&ca.private).expect("sign recovery");

    authorization
        .verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            Some(4_600),
            1_100,
        )
        .expect("a committed recovery may activate immediately");

    let mut ordinary = authorization;
    ordinary.reason = RotationReason::Scheduled;
    let ordinary = ordinary.sign(&ca.private).expect("sign ordinary rotation");
    assert!(matches!(
        ordinary.verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active_generation(),
            &[&tls.authority],
            None,
            Some(4_600),
            1_100,
        ),
        Err(CertificateError::InvalidLease)
    ));
}

#[test]
fn a_commit_needs_both_the_active_and_the_candidate_signature() {
    let active = keys();
    let candidate = keys();
    let generation = ClientCertificateGeneration {
        generation: 5,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
        not_before: 0,
        not_after: 100_000,
    };
    let stage_id = Id16::new([5; 16]).expect("stage");

    let mut commit = ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id,
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
        stage_expires_at: 5_000,
        committed_at: 1_200,
        active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        staged_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let transcript = commit.signing_bytes();
    commit.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
    commit.staged_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

    let verify = |commit: &ClientCertificateStageCommit, now: u64| {
        commit.verify(
            &active.public,
            &candidate.public,
            &domain(),
            &gateway_key(),
            &client_key(),
            &stage_id,
            &generation,
            4,
            5_000,
            now,
        )
    };
    assert!(verify(&commit, 1_300).is_ok());

    let stranger = keys();
    let mut half = commit.clone();
    half.staged_pq_signature = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
    assert!(matches!(
        verify(&half, 1_300),
        Err(CertificateError::MissingProof("staged client"))
    ));
}

/// Antedating the commit does not win the race against the purge: the
/// clock the gateway reads is checked too.
#[test]
fn an_antedated_commit_arriving_after_the_lease_is_refused() {
    let active = keys();
    let candidate = keys();
    let generation = ClientCertificateGeneration {
        generation: 5,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
        not_before: 0,
        not_after: 100_000,
    };
    let stage_id = Id16::new([5; 16]).expect("stage");
    let mut commit = ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id,
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
        stage_expires_at: 5_000,
        committed_at: 4_999,
        active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        staged_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let transcript = commit.signing_bytes();
    commit.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
    commit.staged_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

    assert!(matches!(
        commit.verify(
            &active.public,
            &candidate.public,
            &domain(),
            &gateway_key(),
            &client_key(),
            &stage_id,
            &generation,
            4,
            5_000,
            5_001,
        ),
        Err(CertificateError::StageExpired)
    ));
}

/// The approved operation is bound to the exact request, its challenge and
/// its deadline: none of the three can be moved afterwards.
/// Builds a recovery request whose expired leaf is genuinely expired.
///
/// `ca` is the authority that issued it, `expired` the identity being
/// recovered, `fresh` the one asking to be certified.
fn recovery_request(
    ca: &Keys,
    expired: &Keys,
    fresh: &Keys,
    last_known: &ClientCertificateGeneration,
    challenge: [u8; 32],
) -> ExpiredCertificateRecoveryRequest {
    let tls = tls_material();
    recovery_request_with_tls(ca, expired, fresh, last_known, challenge, &tls)
}

fn recovery_request_with_tls(
    ca: &Keys,
    expired: &Keys,
    fresh: &Keys,
    last_known: &ClientCertificateGeneration,
    challenge: [u8; 32],
    tls: &crate::certificates::test_x509::TlsMaterial,
) -> ExpiredCertificateRecoveryRequest {
    ExpiredCertificateRecoveryRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        astra_challenge: challenge,
        request_id: Id16::new([9; 16]).expect("request id"),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        expired_generation: last_known.generation,
        requested_generation: last_known.generation + 1,
        expired_tls_certificate: tls.leaf.clone(),
        expired_pq_certificate: client_leaf(ca, expired, 4),
        tls_csr: tls.csr.clone(),
        new_ml_dsa_87_public_key: fresh.public.clone(),
        credential_id: vec![1, 2, 3],
        created_at: 500_000,
        expires_at: 500_120,
        expired_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&expired.private, &fresh.private)
    .expect("sign")
}

/// The generation the registry still records for a peer whose leaf died.
fn expired_generation_of(
    request: &ExpiredCertificateRecoveryRequest,
) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: request.expired_tls_certificate.fingerprint(),
        pq_certificate_fingerprint: pq_certificate_fingerprint(&request.expired_pq_certificate)
            .expect("fingerprint"),
        not_before: 0,
        not_after: 100_000,
    }
}

/// The period, and **only** the period, is waived (spec §7.5).
///
/// This is the validator's whole reason to exist as a separate type: an
/// expired leaf is refused by mTLS, by QUIC and by every ordinary
/// validator, and here it is a historical proof rather than a credential.
/// Waiving one check is safe only while every other one still runs.
#[test]
fn a_leaf_long_past_its_expiry_still_proves_continuity() {
    let ca = keys();
    let expired = keys();
    let fresh = keys();
    let challenge = [7u8; 32];
    let mut last_known = active_generation();
    let request = recovery_request(&ca, &expired, &fresh, &last_known, challenge);
    last_known = expired_generation_of(&request);

    // Four hundred thousand seconds past the leaf's `not_after`.
    request
        .verify_historical(
            &[&ca.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &challenge,
            500_050,
        )
        .expect("an expired leaf is exactly what this validator is given");
}

/// Waiving the period does not waive the issuer.
#[test]
fn a_leaf_no_authority_of_this_domain_signed_is_refused() {
    let ca = keys();
    let stranger = keys();
    let expired = keys();
    let fresh = keys();
    let challenge = [7u8; 32];
    let request = recovery_request(&ca, &expired, &fresh, &active_generation(), challenge);
    let last_known = expired_generation_of(&request);

    assert!(matches!(
        request.verify_historical(
            &[&stranger.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &challenge,
            500_050,
        ),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

/// Only the **newest** recorded leaf proves continuity.
///
/// An attacker holding *some* old certificate of the peer is stopped here:
/// accepting any leaf the domain ever issued would make every superseded
/// generation a permanent key to the identity.
#[test]
fn an_older_leaf_of_the_same_peer_is_refused() {
    let ca = keys();
    let expired = keys();
    let fresh = keys();
    let challenge = [7u8; 32];
    let request = recovery_request(&ca, &expired, &fresh, &active_generation(), challenge);
    let mut last_known = expired_generation_of(&request);
    // The registry has since recorded a different leaf under the same
    // generation number.
    last_known.pq_certificate_fingerprint = Fingerprint::of(b"a newer leaf");

    assert!(matches!(
        request.verify_historical(
            &[&ca.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &challenge,
            500_050,
        ),
        Err(CertificateError::FingerprintMismatch("expired PQ leaf"))
    ));
}

/// The challenge is Astra's, single-use, and not the requester's to pick.
#[test]
fn a_request_answering_another_challenge_is_refused() {
    let ca = keys();
    let expired = keys();
    let fresh = keys();
    let request = recovery_request(&ca, &expired, &fresh, &active_generation(), [7u8; 32]);
    let last_known = expired_generation_of(&request);

    assert!(matches!(
        request.verify_historical(
            &[&ca.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &[8u8; 32],
            500_050,
        ),
        Err(CertificateError::InvalidChallenge)
    ));
}

/// Continuity is a signature by the expired identity, not its certificate.
///
/// Holding the old leaf is public knowledge — it travelled in every
/// handshake. Only its private half proves the recovery is asked for by
/// the machine that owned the identity.
#[test]
fn holding_the_expired_leaf_without_its_private_key_proves_nothing() {
    let ca = keys();
    let expired = keys();
    let thief = keys();
    let fresh = keys();
    let challenge = [7u8; 32];
    let mut request = recovery_request(&ca, &expired, &fresh, &active_generation(), challenge);
    // The leaf stays the peer's; the continuity signature is the thief's.
    request = request.sign(&thief.private, &fresh.private).expect("sign");
    let last_known = expired_generation_of(&request);

    assert!(matches!(
        request.verify_historical(
            &[&ca.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &challenge,
            500_050,
        ),
        Err(CertificateError::MissingProof("expired client"))
    ));
}

/// A recovery is the **next** generation, never a jump or a rollback.
#[test]
fn a_recovery_may_not_skip_a_generation() {
    let ca = keys();
    let expired = keys();
    let fresh = keys();
    let challenge = [7u8; 32];
    let mut request = recovery_request(&ca, &expired, &fresh, &active_generation(), challenge);
    request.requested_generation = 9;
    let request = request
        .sign(&expired.private, &fresh.private)
        .expect("sign");
    let last_known = expired_generation_of(&request);

    assert!(matches!(
        request.verify_historical(
            &[&ca.public],
            &domain(),
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &last_known,
            &challenge,
            500_050,
        ),
        Err(CertificateError::GenerationSkipped { .. })
    ));
}

#[test]
fn the_recovery_approval_challenge_binds_request_challenge_and_deadline() {
    let request = Fingerprint::of(b"request");
    let challenge = [7u8; 32];
    let base = expired_recovery_approval_challenge(&request, &challenge, 1_000);
    assert_ne!(
        base,
        expired_recovery_approval_challenge(&Fingerprint::of(b"other"), &challenge, 1_000)
    );
    assert_ne!(
        base,
        expired_recovery_approval_challenge(&request, &[8u8; 32], 1_000)
    );
    assert_ne!(
        base,
        expired_recovery_approval_challenge(&request, &challenge, 1_001)
    );
}

/// The bug this pairing exists to prevent, pinned as a test.
///
/// Orion once posted a bare commit to a gateway that had always required
/// the pair. Both ends compiled, both ends were self-consistent, and the
/// disagreement surfaced only as an unreadable body on a real renewal.
/// The shape now lives here, and a bare commit must not pass for a request.
#[test]
fn a_bare_commit_is_not_a_stage_commit_request() {
    let commit = ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id: Id16::new([5; 16]).expect("stage"),
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
        stage_expires_at: 5_000,
        committed_at: 1_200,
        active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        staged_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    let bare = serde_json::to_vec(&commit).expect("encode");
    assert!(
        serde_json::from_slice::<StageCommitRequest>(&bare).is_err(),
        "a bare commit must not deserialize as the paired request"
    );
    // And the field the reader complains about is the first one it meets,
    // which is exactly the message the gateway logged.
    let error = serde_json::from_slice::<StageCommitRequest>(&bare)
        .expect_err("bare commit")
        .to_string();
    assert!(error.contains("format_version"), "{error}");
}

/// Four client objects built from constant bytes only, and the fingerprints
/// they must keep.
///
/// These fingerprints are what the next object in the chain binds: the stage
/// authorization names the request's, the grant names the receipt's, the
/// commit names the grant's (spec §7). Orion, Astra and the gateway compute
/// them independently, so moving these types around — splitting this module
/// included — must not move a byte of their canonical transcripts. Every other
/// test compares two fingerprints computed by the same code and would not
/// notice. The stage authorization and the grant are left out: they embed
/// signed certificates and approval evidence that constant bytes cannot
/// produce. A change of these values is a wire-format change and needs new
/// domains, not new constants here.
#[test]
fn the_client_object_fingerprints_are_pinned() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let id = |byte: u8| Id16::new([byte; 16]).expect("id");
    let key = |byte: u8| WireGuardKey::from_bytes([byte; 32]);
    let signature = |byte: u8| {
        MlDsa87Signature::new(vec![byte; crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN])
            .expect("signature")
    };
    let domain = TrustDomainId::new([1; 16]).expect("domain");

    let request = ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: id(2),
        trust_domain_id: domain,
        gateway_wg_public_key: key(3),
        server_name: "gateway.example".into(),
        client_wg_public_key: key(4),
        active_generation: 1,
        requested_generation: 2,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        tls_csr: DerCertificate::new(vec![5; 64]).expect("csr"),
        created_at: 1_000,
        expires_at: 2_000,
        new_ml_dsa_87_public_key: MlDsa87PublicKey::new(vec![22; 2592]).expect("key"),
        active_pq_signature: signature(6),
        new_pq_signature: signature(7),
    };
    let receipt = GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        stage_id: id(8),
        stage_authorization_fingerprint: Fingerprint::of(b"stage authorization"),
        request_fingerprint: request.fingerprint(),
        renewal_authorization_fingerprint: Fingerprint::of(b"renewal authorization"),
        gateway_wg_public_key: key(3),
        client_wg_public_key: key(4),
        active_generation: 1,
        staged_generation: 2,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
        persisted_at: 1_100,
        stage_expires_at: 1_700,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: Fingerprint::of(b"gateway leaf"),
        gateway_signature: signature(9),
    };
    let commit = ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        stage_id: id(8),
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: receipt.fingerprint(),
        gateway_wg_public_key: key(3),
        client_wg_public_key: key(4),
        active_generation: 1,
        staged_generation: 2,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
        stage_expires_at: 1_700,
        committed_at: 1_200,
        active_pq_signature: signature(10),
        staged_pq_signature: signature(11),
    };
    let recovery = ExpiredCertificateRecoveryRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        astra_challenge: [12; 32],
        request_id: id(13),
        gateway_wg_public_key: key(3),
        server_name: "gateway.example".into(),
        client_wg_public_key: key(4),
        expired_generation: 1,
        requested_generation: 2,
        expired_tls_certificate: DerCertificate::new(vec![14; 64]).expect("der"),
        expired_pq_certificate: PqCertificate {
            version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [15; 16],
            subject: "client".into(),
            issuer: "CA-PQ".into(),
            role: crate::key_negotiation::PqCertificateRole::Client,
            wireguard_public_key: key(4).to_base64(),
            // Constant bytes of the exact lengths: a real ML-DSA signature is
            // randomized, which a pinned value cannot be.
            ml_dsa_87_public_key: STANDARD
                .encode([16; crate::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN]),
            not_before_unix: 0,
            not_after_unix: 900,
            ml_dsa_87_signature: STANDARD
                .encode([17; crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN]),
        },
        tls_csr: DerCertificate::new(vec![18; 64]).expect("csr"),
        credential_id: vec![19; 16],
        created_at: 1_000,
        expires_at: 2_000,
        new_ml_dsa_87_public_key: MlDsa87PublicKey::new(vec![23; 2592]).expect("key"),
        expired_pq_signature: signature(20),
        new_pq_signature: signature(21),
    };

    assert_eq!(
        [
            request.fingerprint().to_hex(),
            receipt.fingerprint().to_hex(),
            commit.fingerprint().to_hex(),
            recovery.fingerprint().to_hex(),
        ],
        [
            "fb00902615b864f5d65968bdd751252c9113dbb4a385a05d3f6eb140a361a296",
            "8e9c869f226af2d8bf41bf4e3ba53a96a5b8d509d8bdde531995212ef4ff5f4f",
            "8806e00f531885fd1fa25fd15087b07aa08c153346419cb97558accf2f709549",
            "717703958f6f7a7089547c4d433d6dcdad7c18b42b6c355d85b173e866f9e167",
        ]
    );
}

fn signed_grant(issuer: &Keys, ca: &Keys) -> ClientCertificateRotationGrant {
    let subject = keys();
    let receipt = GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id: Id16::new([5; 16]).expect("stage"),
        stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"candidate tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"candidate pq"),
        persisted_at: 1_100,
        stage_expires_at: 4_600,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: Fingerprint::of(b"gateway leaf"),
        gateway_signature: MlDsa87Signature::placeholder(),
    };
    // The grant signature tests need a well-formed grant transcript. Full
    // receipt/leaf-chain checks belong to the role-specific verification.
    let mut grant = ClientCertificateRotationGrant {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: receipt.fingerprint(),
        stage_receipt: receipt,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        next_tls_certificate: DerCertificate::new(vec![1]).expect("DER wrapper"),
        next_pq_certificate: client_leaf(ca, &subject, 5),
        stage_expires_at: 4_600,
        window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
        reason: RotationReason::ExpiredRecovery,
        signature: MlDsa87Signature::placeholder(),
    };
    grant.signature = sign_ml_dsa_87(&issuer.private, &grant.signing_bytes().expect("transcript"))
        .expect("grant signature");
    grant
}

fn recovery_grant(
    ca: &Keys,
    gateway: &Keys,
    request: &ExpiredCertificateRecoveryRequest,
    tls: &crate::certificates::test_x509::TlsMaterial,
) -> ClientCertificateRotationGrant {
    let gateway_fingerprint = Fingerprint::of(b"pinned gateway certificate");
    let candidate = client_leaf_valid_during(
        ca,
        &Keys {
            private: Zeroizing::new(Vec::new()),
            public: request.new_ml_dsa_87_public_key.clone(),
        },
        5,
        500_000,
        700_000,
    );
    // `candidate` is signed by CA-PQ and carries the new public key named by
    // the recovery request. Its validity covers the complete transition.
    let mut receipt = GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id: Id16::new([5; 16]).expect("stage"),
        stage_authorization_fingerprint: Fingerprint::of(b"recovery authorization"),
        request_fingerprint: request.fingerprint(),
        renewal_authorization_fingerprint: Fingerprint::of(b"operator approval"),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: request.expired_generation,
        staged_generation: request.requested_generation,
        staged_tls_certificate_fingerprint: tls.leaf.fingerprint(),
        staged_pq_certificate_fingerprint: pq_certificate_fingerprint(&candidate)
            .expect("candidate fingerprint"),
        persisted_at: 500_010,
        stage_expires_at: 500_300,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: gateway_fingerprint,
        gateway_signature: MlDsa87Signature::placeholder(),
    };
    receipt = receipt.sign(&gateway.private).expect("receipt signature");

    let mut grant = ClientCertificateRotationGrant {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        request_fingerprint: request.fingerprint(),
        renewal_authorization_fingerprint: receipt.renewal_authorization_fingerprint,
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: receipt.fingerprint(),
        stage_receipt: receipt,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: request.expired_generation,
        next_generation: request.requested_generation,
        active_tls_certificate_fingerprint: request.expired_tls_certificate.fingerprint(),
        active_pq_certificate_fingerprint: pq_certificate_fingerprint(
            &request.expired_pq_certificate,
        )
        .expect("expired PQ fingerprint"),
        next_tls_ca_certificate_fingerprint: tls.authority.fingerprint(),
        next_tls_certificate: tls.leaf.clone(),
        next_pq_certificate: candidate,
        stage_expires_at: 500_300,
        window: TransitionWindow::new(500_000, 500_200, 700_000).expect("window"),
        reason: RotationReason::ExpiredRecovery,
        signature: MlDsa87Signature::placeholder(),
    };
    grant.signature = sign_ml_dsa_87(&ca.private, &grant.signing_bytes().expect("transcript"))
        .expect("grant signature");
    grant
}

fn resign_recovery_grant(
    mut grant: ClientCertificateRotationGrant,
    receipt_signer: &Keys,
    ca: &Keys,
) -> ClientCertificateRotationGrant {
    grant.stage_receipt = grant
        .stage_receipt
        .clone()
        .sign(&receipt_signer.private)
        .expect("receipt signature");
    grant.stage_receipt_fingerprint = grant.stage_receipt.fingerprint();
    grant.signature = sign_ml_dsa_87(&ca.private, &grant.signing_bytes().expect("transcript"))
        .expect("grant signature");
    grant
}

#[allow(clippy::too_many_arguments)]
fn verify_recovery_fixture(
    grant: &ClientCertificateRotationGrant,
    ca: &Keys,
    gateway: &Keys,
    gateway_fingerprint: &Fingerprint,
    trust_domain: &TrustDomainId,
    gateway_wg_key: &WireGuardKey,
    client_wg_key: &WireGuardKey,
    request: &ExpiredCertificateRecoveryRequest,
    tls_anchor: &DerCertificate,
    now: u64,
) -> Result<(), CertificateError> {
    grant.verify_for_recovery(
        &ca.public,
        &gateway.public,
        gateway_fingerprint,
        trust_domain,
        1,
        1,
        gateway_wg_key,
        SERVER_NAME,
        client_wg_key,
        request,
        &[tls_anchor],
        None,
        now,
    )
}

#[test]
fn a_relay_can_check_the_grant_signature_but_not_authorize_installation() {
    let ca = keys();
    let grant = signed_grant(&ca, &ca);
    grant
        .verify_signed_by(&ca.public)
        .expect("issuer signature");
    assert!(matches!(
        grant.verify_signed_by(&keys().public),
        Err(CertificateError::InvalidSignature)
    ));

    let mut altered = grant;
    altered.stage_expires_at += 1;
    assert!(matches!(
        altered.verify_signed_by(&ca.public),
        Err(CertificateError::InvalidSignature)
    ));
}

#[test]
fn a_delegated_or_ordinary_grant_cannot_enter_the_recovery_verifier() {
    let ca = keys();
    let request = recovery_request(&ca, &keys(), &keys(), &active_generation(), [7; 32]);
    let mut grant = signed_grant(&ca, &ca);

    grant.issuer_kind = IssuerKind::Astra;
    assert!(matches!(
        grant.verify_for_recovery(
            &ca.public,
            &keys().public,
            &Fingerprint::of(b"gateway"),
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &request,
            &[],
            None,
            1_000
        ),
        Err(CertificateError::IssuerScopeViolation(
            "only CA-PQ grants the recovery of an expired identity"
        ))
    ));

    grant.issuer_kind = IssuerKind::Master;
    grant.reason = RotationReason::Scheduled;
    // The wrong-reason guard runs before signatures or certificate material.
    assert!(matches!(
        grant.verify_for_recovery(
            &ca.public,
            &keys().public,
            &Fingerprint::of(b"gateway"),
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &request,
            &[],
            None,
            1_000
        ),
        Err(CertificateError::IssuerScopeViolation(
            "this grant was issued for another reason"
        ))
    ));
}

#[test]
fn a_ca_pq_recovery_grant_verifies_and_stays_bound_to_the_historical_request() {
    let ca = keys();
    let gateway = keys();
    let expired = keys();
    let fresh = keys();
    let tls = tls_material();
    let request =
        recovery_request_with_tls(&ca, &expired, &fresh, &active_generation(), [7; 32], &tls);
    let grant = recovery_grant(&ca, &gateway, &request, &tls);
    let gateway_fingerprint = grant.stage_receipt.gateway_certificate_fingerprint;

    verify_recovery_fixture(
        &grant,
        &ca,
        &gateway,
        &gateway_fingerprint,
        &domain(),
        &gateway_key(),
        &client_key(),
        &request,
        &tls.authority,
        500_050,
    )
    .expect("valid CA-PQ recovery grant");

    let mut wrong_epoch = grant.clone();
    wrong_epoch.ca_epoch = 2;
    assert!(matches!(
        verify_recovery_fixture(
            &wrong_epoch,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::UnauthorizedIssuer)
    ));

    let other_tls = tls_material();
    let mut wrong_csr_request = request.clone();
    wrong_csr_request.tls_csr = other_tls.csr;
    assert!(matches!(
        verify_recovery_fixture(
            &grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &wrong_csr_request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::InvalidX509(
            "certificate does not certify the CSR's key"
        ))
    ));

    let mut wrong_key_request = request.clone();
    wrong_key_request.new_ml_dsa_87_public_key = keys().public;
    let mut wrong_key_grant = grant.clone();
    wrong_key_grant.request_fingerprint = wrong_key_request.fingerprint();
    wrong_key_grant.stage_receipt.request_fingerprint = wrong_key_request.fingerprint();
    wrong_key_grant = resign_recovery_grant(wrong_key_grant, &gateway, &ca);
    assert!(matches!(
        verify_recovery_fixture(
            &wrong_key_grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &wrong_key_request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::MissingProof("new client"))
    ));

    let stranger_gateway = keys();
    let wrong_receipt_signer = resign_recovery_grant(grant.clone(), &stranger_gateway, &ca);
    assert!(matches!(
        verify_recovery_fixture(
            &wrong_receipt_signer,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::MissingProof("gateway receipt"))
    ));

    let other_domain = TrustDomainId::new([4; 16]).expect("other domain");
    assert!(matches!(
        verify_recovery_fixture(
            &grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &other_domain,
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::TrustDomainMismatch)
    ));
    let other_client = WireGuardKey::from_bytes([44; 32]);
    assert!(matches!(
        verify_recovery_fixture(
            &grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &other_client,
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::ClientIdentityMismatch)
    ));

    assert!(matches!(
        verify_recovery_fixture(
            &grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_300
        ),
        Err(CertificateError::StageExpired)
    ));

    let mut corrupt_signature = grant.clone();
    corrupt_signature.signature = MlDsa87Signature::new(vec![1; 4_627]).expect("signature");
    assert!(matches!(
        verify_recovery_fixture(
            &corrupt_signature,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::InvalidSignature)
    ));

    let mut changed_request = request.clone();
    changed_request.created_at += 1;
    assert!(matches!(
        verify_recovery_fixture(
            &grant,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &changed_request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::FingerprintMismatch("recovery request"))
    ));

    let mut skipped = grant;
    skipped.next_generation = 6;
    assert!(matches!(
        verify_recovery_fixture(
            &skipped,
            &ca,
            &gateway,
            &gateway_fingerprint,
            &domain(),
            &gateway_key(),
            &client_key(),
            &request,
            &tls.authority,
            500_050
        ),
        Err(CertificateError::FingerprintMismatch("stage receipt"))
    ));
}
