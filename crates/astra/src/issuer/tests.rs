use super::*;
use aether::certificates::approval::AstraRenewalApprovalEvidence;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::{
    approval::{
        AstraCredentialApprovalRequest, AstraCredentialBinding, AstraIssuancePolicy,
        AstraPolicyPin, AstraRenewalApproval, CredentialState,
    },
    authority::AllowedUsage,
    webauthn::WebAuthnAssertion,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose,
};

const SERVER_NAME: &str = "gateway.example";

struct Fixture {
    issuer: DelegatedIssuer,
    /// The delegated intermediate, self-signed here so it is both the
    /// intermediate and the anchor a test verifier holds.
    tls_anchor: DerCertificate,
    ca_public: MlDsa87PublicKey,
    client_active: Zeroizing<Vec<u8>>,
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([1; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([1; 32])
}

fn client_key() -> WireGuardKey {
    WireGuardKey::from_bytes([2; 32])
}

fn automatic_policy_fingerprint() -> Fingerprint {
    AstraIssuancePolicy::standard(domain(), gateway_key(), SERVER_NAME.into())
        .fingerprint()
        .expect("automatic policy")
}

fn intermediate() -> (DerCertificate, Zeroizing<Vec<u8>>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "astra-issuer");
    params.distinguished_name = name;
    // Every link of a chain is read against the clock, this one included,
    // and these tests drive a synthetic clock near the Unix epoch.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let key = KeyPair::generate().expect("key");
    let certificate = params.self_signed(&key).expect("intermediate");
    (
        DerCertificate::new(certificate.der().to_vec()).expect("der"),
        Zeroizing::new(key.serialize_der()),
    )
}

fn fixture() -> Fixture {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (client_active, _client_active_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (intermediate_der, intermediate_key) = intermediate();

    let authorization = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: intermediate_der,
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 200_000,
        policy_fingerprint: automatic_policy_fingerprint(),
        not_before: 0,
        not_after: 1_000_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("sign delegation");

    Fixture {
        tls_anchor: authorization.tls_intermediate_certificate.clone(),
        issuer: DelegatedIssuer::new(authorization, issuer_private, intermediate_key),
        ca_public,
        client_active,
    }
}

fn csr() -> (DerCertificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "workstation");
    params.distinguished_name = name;
    // The tests drive synthetic clocks near the Unix epoch, so the leaf
    // issued from this request has to be valid there.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let key = KeyPair::generate().expect("key");
    let request = params.serialize_request(&key).expect("csr");
    (
        DerCertificate::new(request.der().to_vec()).expect("der"),
        key,
    )
}

fn active() -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        not_before: 0,
        not_after: 1_000_000,
    }
}

fn request(
    fixture: &Fixture,
    csr: DerCertificate,
    new_public: &MlDsa87PublicKey,
    new_private: &[u8],
    requested_generation: u64,
) -> ClientCertificateRotationRequest {
    ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([3; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        requested_generation,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        tls_csr: csr,
        new_ml_dsa_87_public_key: new_public.clone(),
        created_at: 1_000,
        expires_at: 1_000 + 3_600,
        active_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.client_active, new_private)
    .expect("sign request")
}

/// Syntactically complete approval evidence for issuer unit tests.
///
/// The cryptographic verification of this object is covered in `aether`;
/// these tests exercise only the delegated issuer's field propagation.
fn approval_evidence(request: &ClientCertificateRotationRequest) -> AstraRenewalApprovalEvidence {
    let operation_id = Id16::new([8; 16]).expect("operation");
    let approval_request = AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id,
        request_fingerprint: request.fingerprint(),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        requested_generation: 5,
        credential_registry_epoch: 1,
        webauthn_rp_id: "astra.example".into(),
        webauthn_origin: "https://astra.example".into(),
        allowed_credential_ids: vec![vec![1]],
        required_credentials: 1,
        created_at: 1_000,
        expires_at: 1_300,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    };
    let assertion = WebAuthnAssertion {
        authenticator_data: vec![1],
        client_data_json: vec![1],
        signature: vec![1],
    };
    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: vec![1],
        credential_public_key: vec![1],
        aaguid: [0; 16],
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 1_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    };
    let approval = AstraRenewalApproval {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id,
        request_fingerprint: request.fingerprint(),
        approval_request_fingerprint: approval_request.fingerprint(),
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: assertion.fingerprint(),
        credential_binding: binding,
        webauthn_assertion: assertion,
        approved_at: 1_000,
        expires_at: 1_300,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    };
    AstraRenewalApprovalEvidence {
        approval_request,
        approval,
    }
}

/// The whole point of the delegation: the leaves it issues verify under
/// **it**, and the object it signs verifies as an `astra` issuance.
#[test]
fn an_issued_generation_verifies_under_the_delegation() {
    let fixture = fixture();
    let (csr_der, _csr_key) = csr();
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let request = request(&fixture, csr_der, &new_public, &new_private, 5);

    let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");
    let (tls_leaf, pq_leaf) = fixture
        .issuer
        .issue_generation(
            &request,
            "workstation",
            &window,
            (0, 100_000),
            [9; 16],
            RotationReason::Scheduled,
        )
        .expect("issuance");

    let authorization = fixture
        .issuer
        .authorize_stage(
            &request,
            &active(),
            Id16::new([4; 16]).expect("stage"),
            fixture.tls_anchor.fingerprint(),
            tls_leaf,
            pq_leaf,
            window,
            1_000,
            1_000 + 3_600,
            DelegatedApproval::Automatic(request.fingerprint()),
        )
        .expect("authorization");

    authorization
        .verify(
            &fixture.ca_public,
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &active(),
            &[&fixture.tls_anchor],
            Some(&AstraPolicyPin::new(automatic_policy_fingerprint()).expect("policy pin")),
            None,
            1_100,
        )
        .expect("the gateway accepts a delegated staging");
}

/// A domain on disk, pinned to one policy, holding everything `adopt` reads.
struct PinnedDomain {
    registry: crate::registry::AstraRegistry,
    ca_private: Zeroizing<Vec<u8>>,
    issuer_public: MlDsa87PublicKey,
    pq_key: std::path::PathBuf,
    tls_key: std::path::PathBuf,
    intermediate_der: DerCertificate,
    /// Keeps the directory the two key paths point into alive.
    _directory: tempfile::TempDir,
}

/// Builds a registry pinned to `policy`, with the private issuer material
/// on disk beside it.
fn domain_pinned_to(policy: Fingerprint) -> PinnedDomain {
    let directory = tempfile::tempdir().expect("temp dir");
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
    let (intermediate_der, intermediate_key) = intermediate();

    let pq_key = directory.path().join("issuer-pq.bin");
    let tls_key = directory.path().join("issuer-tls.der");
    std::fs::write(&pq_key, issuer_private.as_slice()).expect("pq key");
    std::fs::write(&tls_key, intermediate_key.as_slice()).expect("tls key");

    let state = crate::registry::AstraState {
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: AstraPolicyPin::new(policy).expect("policy pin"),
        credential_registry_epoch: 1,
        ca_epoch: 1,
        ca_public_key: ca_public,
        ca_rotation: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: Some(Fingerprint::of(b"client tls ca")),
        ca_tls_rotation: None,
        astra_service_key_epoch: 1,
        astra_service_public_key: service,
        issuer: None,
        transitions: Vec::new(),
        peers: std::collections::BTreeMap::new(),
        status_epochs: std::collections::BTreeMap::new(),
        audit: crate::audit::AuditChain::default(),
    };
    PinnedDomain {
        registry: crate::registry::AstraRegistry::new(directory.path().join("astra.json"), state),
        ca_private,
        issuer_public,
        pq_key,
        tls_key,
        intermediate_der,
        _directory: directory,
    }
}

fn delegation_naming(
    ca_private: &[u8],
    issuer_public: MlDsa87PublicKey,
    intermediate_der: DerCertificate,
    policy_fingerprint: Fingerprint,
) -> AstraIssuerAuthorization {
    AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: intermediate_der,
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 200_000,
        policy_fingerprint,
        not_before: 0,
        not_after: 1_000_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("sign delegation")
}

/// The migration of 6 September 2026, through the door it actually uses:
/// installing a delegation. The pin and the delegation land together, so a
/// crash can never leave an authority allowed to issue unattended under a
/// policy nobody confirmed.
#[test]
fn installing_a_delegation_that_names_the_current_policy_migrates_a_superseded_domain() {
    let superseded = aether::certificates::approval::superseded_per_request_policy_fingerprint(
        domain(),
        gateway_key(),
        SERVER_NAME,
    )
    .expect("superseded");
    let mut pinned = domain_pinned_to(superseded);

    adopt(
        &mut pinned.registry,
        delegation_naming(
            &pinned.ca_private,
            pinned.issuer_public.clone(),
            pinned.intermediate_der.clone(),
            automatic_policy_fingerprint(),
        ),
        &pinned.pq_key,
        &pinned.tls_key,
        1_000,
    )
    .expect("the migration is accepted");

    assert!(pinned
        .registry
        .state()
        .astra_policy_fingerprint
        .fingerprint()
        .matches(&automatic_policy_fingerprint()));
    assert!(
        pinned.registry.state().issuer.is_some(),
        "the delegation is installed by the same write"
    );
}

/// A `CA-PQ` signature makes a delegation genuine, not applicable. One
/// naming a third policy leaves a superseded domain exactly where it was —
/// still refusing unattended issuance.
#[test]
fn a_delegation_naming_a_third_policy_migrates_nothing() {
    let superseded = aether::certificates::approval::superseded_per_request_policy_fingerprint(
        domain(),
        gateway_key(),
        SERVER_NAME,
    )
    .expect("superseded");
    let mut pinned = domain_pinned_to(superseded);
    let mut widened = AstraIssuancePolicy::standard(domain(), gateway_key(), SERVER_NAME.into());
    widened.maximum_leaf_lifetime_secs = 10 * 365 * 86_400;

    assert!(matches!(
        adopt(
            &mut pinned.registry,
            delegation_naming(
                &pinned.ca_private,
                pinned.issuer_public.clone(),
                pinned.intermediate_der.clone(),
                widened.fingerprint().expect("widened"),
            ),
            &pinned.pq_key,
            &pinned.tls_key,
            1_000,
        ),
        Err(AdoptionError::Policy(_))
    ));
    assert!(pinned
        .registry
        .state()
        .astra_policy_fingerprint
        .fingerprint()
        .matches(&superseded));
    assert!(pinned.registry.state().issuer.is_none());
}

/// Present is not correct. The delegation and the two private keys arrive
/// from different places, and a mismatch that startup lets through only
/// surfaces at the first renewal — on a client with no fallback.
#[test]
fn loading_refuses_private_material_that_does_not_match_the_delegation() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (intermediate_der, intermediate_key) = intermediate();
    let authorization = AstraIssuerAuthorization {
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: intermediate_der,
        ca_pq_signature: MlDsa87Signature::placeholder(),
        ..fixture().issuer.authorization.clone()
    }
    .sign(&ca_private)
    .expect("sign delegation");

    // The genuine triple loads.
    DelegatedIssuer::load(
        authorization.clone(),
        issuer_private.clone(),
        intermediate_key.clone(),
    )
    .expect("the genuine material loads");

    // A stranger's PQ key signs perfectly and verifies under nothing this
    // delegation names.
    let (stranger_pq, _) = generate_ml_dsa_87_keypair().expect("keygen");
    assert!(matches!(
        DelegatedIssuer::load(authorization.clone(), stranger_pq, intermediate_key),
        Err(IssuerError::IssuerKeyMismatch("ML-DSA-87"))
    ));

    // And a TLS key that is not the intermediate's.
    let (_, other_tls_key) = intermediate();
    assert!(matches!(
        DelegatedIssuer::load(authorization, issuer_private, other_tls_key),
        Err(IssuerError::IssuerKeyMismatch("TLS"))
    ));
}

/// The four things the delegation withholds, checked before any signature
/// exists — so a compromised Astra never produces the object at all.
#[test]
fn the_issuer_refuses_a_skipped_generation_and_an_undelegable_reason() {
    let fixture = fixture();
    let (csr_der, _csr_key) = csr();
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");

    let skipped = request(&fixture, csr_der.clone(), &new_public, &new_private, 6);
    assert!(matches!(
        fixture.issuer.issue_generation(
            &skipped,
            "workstation",
            &window,
            (0, 100_000),
            [9; 16],
            RotationReason::Scheduled,
        ),
        Err(IssuerError::Certificate(
            CertificateError::IssuerScopeViolation("generation")
        ))
    ));

    let request = request(&fixture, csr_der, &new_public, &new_private, 5);
    let (tls_leaf, pq_leaf) = fixture
        .issuer
        .issue_generation(
            &request,
            "workstation",
            &window,
            (0, 100_000),
            [9; 16],
            RotationReason::Scheduled,
        )
        .expect("issuance");
    let _ = (tls_leaf, pq_leaf);
    // The four reasons this issuer may not sign for are no longer
    // *expressible* here: `authorize_stage` reads the reason off the
    // approval family, and neither family names one of them. The guard
    // inside it stays as the belt to that suspenders, and this asserts the
    // property the type now carries.
    for forbidden in [
        RotationReason::ExpiredRecovery,
        RotationReason::Readmission,
        RotationReason::EmergencyReplacement,
        RotationReason::KeyRecovery,
    ] {
        assert!(!forbidden.is_delegable());
    }
}

/// The two families produce two different authorizations, and never a
/// hybrid: `authorize_stage` reads the reason off the evidence, so the
/// field that is filled and the reason that is signed always agree.
#[test]
fn each_approval_family_names_its_own_reason_and_fills_its_own_field() {
    use aether::certificates::approval::AstraCampaignApprovalEvidence;
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignApproval, CampaignScope, CampaignTarget, CertificateKind,
    };

    let fixture = fixture();
    let (csr_der, _csr_key) = csr();
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let window = TransitionWindow {
        not_before: 0,
        activation_at: 1_000,
        not_after: 100_000,
    };
    let request = request(&fixture, csr_der, &new_public, &new_private, 5);

    let campaign = AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new([7; 16]).expect("id"),
        trust_domain_id: fixture.issuer.authorization.trust_domain_id,
        gateway_wg_public_key: fixture.issuer.authorization.gateway_wg_public_key,
        server_name: fixture.issuer.authorization.server_name.clone(),
        created_at: 900,
        expires_at: 1_200,
        scope: CampaignScope::FleetLeafs,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: request.client_wg_public_key,
            epoch: 1,
            generation: active().generation,
            active_tls_certificate_fingerprint: active().tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: active().pq_certificate_fingerprint,
        }],
        reason: "campagne trimestrielle".into(),
        requested_by: "operator".into(),
        policy_fingerprint: Fingerprint::of(b"policy"),
        required_credentials: CampaignScope::FleetLeafs.required_credentials(),
    };
    let approval = CampaignApproval {
        campaign_id: campaign.campaign_id,
        campaign_fingerprint: campaign.fingerprint(),
        required_credentials: campaign.required_credentials,
        approved_at: 1_000,
        approvals: Vec::new(),
    };
    let evidence = AstraCampaignApprovalEvidence {
        campaign,
        approval,
        credential_registry: aether::certificates::approval::CredentialRegistry {
            trust_domain_id: fixture.issuer.authorization.trust_domain_id,
            gateway_wg_public_key: fixture.issuer.authorization.gateway_wg_public_key,
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        },
        webauthn_origin: "https://astra.example".into(),
    };
    let campaign_approval = DelegatedApproval::Campaign(Box::new(evidence));
    assert_eq!(campaign_approval.reason(), RotationReason::ManualGlobal);

    let (tls_leaf, pq_leaf) = fixture
        .issuer
        .issue_generation(
            &request,
            "workstation",
            &window,
            (0, 100_000),
            [9; 16],
            campaign_approval.reason(),
        )
        .expect("a campaign is delegable");
    let expected = campaign_approval.fingerprint().expect("fingerprint");
    let authorization = fixture
        .issuer
        .authorize_stage(
            &request,
            &active(),
            Id16::new([4; 16]).expect("stage"),
            fixture.tls_anchor.fingerprint(),
            tls_leaf,
            pq_leaf,
            window,
            1_000,
            1_000 + 3_600,
            campaign_approval,
        )
        .expect("authorization");

    assert_eq!(authorization.reason, RotationReason::ManualGlobal);
    assert!(authorization.campaign_approval.is_some());
    // The other family must be absent, not merely unused: an object
    // carrying both would leave "which one was checked" to its reader.
    assert!(authorization.renewal_approval.is_none());
    assert!(authorization
        .renewal_authorization_fingerprint
        .matches(&expected));
}

/// A lifetime beyond the delegation's ceiling is refused before issuance.
#[test]
fn the_issuer_refuses_a_leaf_longer_than_its_ceiling() {
    let fixture = fixture();
    let (csr_der, _csr_key) = csr();
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let request = request(&fixture, csr_der, &new_public, &new_private, 5);
    let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");

    assert!(matches!(
        fixture.issuer.issue_generation(
            &request,
            "workstation",
            &window,
            (0, 300_000),
            [9; 16],
            RotationReason::Scheduled,
        ),
        Err(IssuerError::Certificate(
            CertificateError::IssuerScopeViolation("leaf lifetime")
        ))
    ));
}

/// No receipt, no grant — the ordering the whole staging protocol exists
/// to enforce.
#[test]
fn a_grant_is_refused_without_a_matching_receipt() {
    let fixture = fixture();
    let (csr_der, _csr_key) = csr();
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let request = request(&fixture, csr_der, &new_public, &new_private, 5);
    let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");
    let (tls_leaf, pq_leaf) = fixture
        .issuer
        .issue_generation(
            &request,
            "workstation",
            &window,
            (0, 100_000),
            [9; 16],
            RotationReason::Scheduled,
        )
        .expect("issuance");
    let authorization = fixture
        .issuer
        .authorize_stage(
            &request,
            &active(),
            Id16::new([4; 16]).expect("stage"),
            fixture.tls_anchor.fingerprint(),
            tls_leaf,
            pq_leaf,
            window,
            1_000,
            1_000 + 3_600,
            DelegatedApproval::Renewal(Box::new(approval_evidence(&request))),
        )
        .expect("authorization");

    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let candidate = DelegatedIssuer::candidate(&authorization).expect("candidate");
    let gateway_fingerprint = Fingerprint::of(b"gateway leaf");

    // A receipt describing another generation carries a valid signature
    // over the wrong fact, and is refused on the field comparison.
    let wrong = GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        stage_id: authorization.stage_id,
        stage_authorization_fingerprint: authorization.fingerprint().expect("fingerprint"),
        request_fingerprint: authorization.request_fingerprint,
        renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: 4,
        staged_generation: 9,
        staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
        staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
        persisted_at: 1_100,
        stage_expires_at: authorization.stage_expires_at,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: gateway_fingerprint,
        gateway_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway_private)
    .expect("sign receipt");

    assert!(matches!(
        fixture.issuer.release_grant(
            &authorization,
            &wrong,
            &gateway_public,
            &gateway_fingerprint
        ),
        Err(IssuerError::ReceiptMismatch)
    ));
}
