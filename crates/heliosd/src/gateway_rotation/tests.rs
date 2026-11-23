use super::*;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::state::GatewayCertificateState;
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};

const NOW: u64 = 1_700_000_000;

fn gateway_leaf() -> PqCertificate {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: NOW + 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("issue")
}

fn gateway() -> GatewayCertificateState {
    let (_, anchor) = generate_ml_dsa_87_keypair().expect("keygen");
    GatewayCertificateState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        server_name: "gateway.example".into(),
        ca_epoch: 1,
        current_ca_public_key: anchor,
        next_ca_public_key: None,
        next_ca_transition_fingerprint: None,
        ca_activation_at: None,
        ca_retire_active_at: None,
        active_gateway_identity_epoch: 3,
        gateway_decision_epoch: 3,
        next_gateway_identity_epoch: None,
        next_transition_fingerprint: None,
        last_aborted_transition: None,
        active_gateway_tls_certificate: aether::certificates::encoding::DerCertificate::new(vec![
            1;
            64
        ])
        .expect("der"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate: gateway_leaf(),
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: false,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    }
}

fn request(epoch: u64, expires_at: u64) -> GatewayCertificateRequest {
    let (_, candidate) = generate_ml_dsa_87_keypair().expect("keygen");
    GatewayCertificateRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        server_name: "gateway.example".into(),
        new_ml_dsa_87_public_key: MlDsa87PublicKey::new(candidate.as_bytes().to_vec())
            .expect("public key"),
        request_id: Id16::new([7; 16]).expect("id"),
        created_at: NOW,
        expires_at,
        new_key_proof: MlDsa87Signature::placeholder(),
        current_key_authorization: None,
    }
}

#[test]
fn a_first_preparation_seals_the_epoch_after_the_last_decision() {
    assert_eq!(
        plan(&gateway(), None, false, false, NOW).expect("plan"),
        Plan::Seal { epoch: 4 }
    );
}

#[test]
fn preparation_refuses_to_wrap_the_gateway_decision_epoch() {
    let mut gateway = gateway();
    gateway.gateway_decision_epoch = u64::MAX;

    let error = plan(&gateway, None, true, false, NOW)
        .expect_err("a new candidate must not wrap the decision epoch");

    assert!(error.to_string().contains("maximum"));
}

/// The operator holds one fingerprint. Re-signing would hand them a second.
#[test]
fn a_valid_request_for_the_same_epoch_is_returned_unchanged() {
    let held = request(4, NOW + 3600);
    let Plan::Reuse(reused) =
        plan(&gateway(), Some(held.clone()), false, false, NOW).expect("plan")
    else {
        panic!("a valid request must be reused");
    };
    assert_eq!(*reused, held);
}

/// §5 caps a request at 24 hours; a ceremony is not bound by that clock.
#[test]
fn an_expired_request_is_resigned_over_the_key_already_sealed() {
    let held = request(4, NOW - 1);
    let expected = held.new_ml_dsa_87_public_key.clone();
    assert_eq!(
        plan(&gateway(), Some(held), false, false, NOW).expect("plan"),
        Plan::Resign {
            epoch: 4,
            pq_public_key: expected,
        }
    );
}

#[test]
fn a_request_expiring_at_the_current_instant_is_resigned() {
    let held = request(4, NOW);
    let expected = held.new_ml_dsa_87_public_key.clone();

    assert_eq!(
        plan(&gateway(), Some(held), false, false, NOW).expect("plan"),
        Plan::Resign {
            epoch: 4,
            pq_public_key: expected,
        }
    );
}

#[test]
fn new_key_replaces_the_candidate_even_while_its_request_is_valid() {
    assert_eq!(
        plan(&gateway(), Some(request(4, NOW + 3600)), true, false, NOW).expect("plan"),
        Plan::Seal { epoch: 4 }
    );
}

/// A request left from a decision this gateway has moved past describes a
/// candidate that is no longer the one being prepared.
#[test]
fn a_request_from_an_earlier_epoch_is_not_a_resumption() {
    assert_eq!(
        plan(&gateway(), Some(request(3, NOW + 3600)), false, false, NOW).expect("plan"),
        Plan::Seal { epoch: 4 }
    );
}

#[test]
fn a_request_from_a_future_epoch_is_not_a_resumption() {
    assert_eq!(
        plan(&gateway(), Some(request(5, NOW + 3600)), false, false, NOW).expect("plan"),
        Plan::Seal { epoch: 4 }
    );
}

/// §6.3: one candidate at a time. The staged transition already owns
/// epoch 4, and a second request would seal a key for the same number.
#[test]
fn a_staged_transition_refuses_a_second_request() {
    let mut gateway = gateway();
    gateway.gateway_decision_epoch = 4;
    gateway.next_gateway_identity_epoch = Some(4);
    let error =
        plan(&gateway, None, false, false, NOW).expect_err("a staged transition must refuse");
    assert!(
        error.to_string().contains("already staged"),
        "unexpected refusal: {error}"
    );
}

/// A revoked identity may not sign for its successor: §5's continuity
/// signature is exactly the right a withdrawal removes.
#[test]
fn a_revoked_gateway_prepares_nothing_that_claims_continuity() {
    let mut gateway = gateway();
    gateway.revoked = true;
    gateway.revocation_epoch = 2;
    let error =
        plan(&gateway, None, false, false, NOW).expect_err("a revoked identity must refuse");
    assert!(
        error.to_string().contains("revoked"),
        "unexpected refusal: {error}"
    );
}

/// But it prepares the §10.1 replacement, without continuity. Refusing
/// that too would make `replacement_transition_fingerprint` unusable and
/// every withdrawal terminal in practice.
#[test]
fn a_revoked_gateway_prepares_its_replacement_under_key_recovery() {
    let mut gateway = gateway();
    gateway.revoked = true;
    gateway.revocation_epoch = 2;
    assert_eq!(
        plan(&gateway, None, false, true, NOW).expect("replacement"),
        Plan::Seal {
            epoch: gateway.gateway_decision_epoch + 1
        }
    );
}

#[test]
fn a_pending_request_survives_its_own_encoding() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("gateway-certificate-request.json");
    let held = request(4, NOW + 3600);
    write_pending(&path, &held).expect("write");
    assert_eq!(read_pending(&path).expect("read"), Some(held));
}

#[test]
fn an_absent_request_is_not_an_error() {
    let directory = tempfile::tempdir().expect("temporary directory");
    assert_eq!(
        read_pending(&directory.path().join("absent.json")).expect("read"),
        None
    );
}

#[test]
fn preparation_resumes_persisted_material_and_preserves_it_on_refusal() {
    const CHILD: &str = "HELIOS_TEST_GATEWAY_PREPARATION";
    const TEST_NAME: &str =
        "gateway_rotation::tests::preparation_resumes_persisted_material_and_preserves_it_on_refusal";

    let Some(directory) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD, root)
            .env("HELIOS_GATEWAY_REQUEST", root.join("request.json"))
            .env("HELIOS_KEY_NEGO_NEXT_CERT", root.join("candidate.der"))
            .env("HELIOS_KEY_NEGO_NEXT_KEY", root.join("candidate.vault"))
            .output()
            .expect("start isolated test");
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };

    let request_path = directory.join("request.json");
    let tls_path = directory.join("candidate.der");
    let registry = registry_in(&directory, gateway());
    let prepare = || prepare_request(&registry, None, false, false, false, false, NOW);

    let error = prepare()
        .err()
        .expect("a first candidate needs the sealed secret");
    assert!(
        error.to_string().contains("TPM secret unavailable"),
        "{error:#}"
    );
    assert!(!request_path.exists());
    assert!(!tls_path.exists());

    let held = request(4, NOW + 3_600);
    write_pending(&request_path, &held).expect("persist ceremony request");
    let request_before = std::fs::read(&request_path).expect("saved request");

    let prepared = prepare().expect("reuse a valid request without a TLS candidate");
    assert!(prepared.reused);
    assert_eq!(prepared.request, held);
    assert_eq!(prepared.path, request_path);
    assert!(prepared.tls_certificate.is_none());

    let tls = DerCertificate::new(vec![8; 64]).expect("bounded TLS certificate bytes");
    std::fs::write(&tls_path, tls.as_bytes()).expect("persist public TLS leaf");
    let prepared = prepare().expect("reuse while exporting the TLS candidate");
    assert_eq!(prepared.tls_certificate, Some(tls));
    assert_eq!(std::fs::read(&request_path).unwrap(), request_before);

    std::fs::write(&tls_path, []).expect("write an empty candidate");
    let error = prepare()
        .err()
        .expect("an empty TLS candidate must not be treated as absent");
    assert!(format!("{error:#}").contains("candidate.der"));
    assert_eq!(std::fs::read(&request_path).unwrap(), request_before);

    std::fs::remove_file(&tls_path).expect("clear the invalid fixture candidate");
    let expired = request(4, NOW - 1);
    write_pending(&request_path, &expired).expect("persist expired request");
    let error = prepare()
        .err()
        .expect("re-signing requires the sealed candidate secret");
    assert!(
        error.to_string().contains("TPM secret unavailable"),
        "{error:#}"
    );
    assert_eq!(read_pending(&request_path).unwrap(), Some(expired));
}

#[test]
fn a_malformed_pending_request_is_not_treated_as_absent() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("gateway-certificate-request.json");
    std::fs::write(&path, b"{not-json").expect("write malformed request");

    let error = read_pending(&path).expect_err("malformed state must fail closed");

    assert!(error.to_string().contains("decoding the pending request"));
}

fn leaf_for(public_key: &MlDsa87PublicKey) -> PqCertificate {
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    leaf_for_ca(public_key, &ca_private)
}

fn leaf_for_ca(public_key: &MlDsa87PublicKey, ca_private: &[u8]) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [2; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
            ml_dsa_87_public_key: public_key.to_base64(),
            not_before_unix: 0,
            not_after_unix: NOW + 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        ca_private,
    )
    .expect("issue")
}

fn transition(
    epoch: u64,
    pq: Option<PqCertificate>,
    tls: Option<DerCertificate>,
) -> GatewayIdentityTransition {
    GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        server_name: "gateway.example".into(),
        active_gateway_tls_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
            b"active tls",
        ),
        next_gateway_tls_certificate: tls,
        active_gateway_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
            b"active pq",
        ),
        next_gateway_certificate: pq,
        window: aether::certificates::window::TransitionWindow {
            not_before: NOW,
            activation_at: NOW + 1_000,
            not_after: NOW + 2_000,
        },
        reason: aether::certificates::authority::RotationReason::Scheduled,
        ca_signature: MlDsa87Signature::placeholder(),
    }
}

#[test]
fn a_transition_installing_the_sealed_candidate_is_accepted() {
    let held = request(4, NOW + 3_600);
    let leaf = leaf_for(&held.new_ml_dsa_87_public_key);

    candidate_is_held(&transition(4, Some(leaf), None), Some(&held), None)
        .expect("the leaf this gateway sealed");
}

/// The check no signature makes: `CA-PQ` certifies that a leaf is
/// authentic, never that its private half is on this machine.
#[test]
fn a_transition_installing_a_key_sealed_elsewhere_is_refused() {
    let held = request(4, NOW + 3_600);
    let (_, elsewhere) = generate_ml_dsa_87_keypair().expect("keygen");
    let stranger =
        leaf_for(&MlDsa87PublicKey::new(elsewhere.as_bytes().to_vec()).expect("public key"));

    let refusal = candidate_is_held(&transition(4, Some(stranger), None), Some(&held), None)
        .expect_err("a leaf whose private half is elsewhere");

    assert!(refusal.to_string().contains("did not seal"));
}

#[test]
fn a_transition_answering_no_pending_request_is_refused() {
    let (_, orphan) = generate_ml_dsa_87_keypair().expect("keygen");
    let leaf = leaf_for(&MlDsa87PublicKey::new(orphan.as_bytes().to_vec()).expect("key"));

    candidate_is_held(&transition(4, Some(leaf), None), None, None)
        .expect_err("no candidate sealed here");
}

/// A request from an epoch already decided describes a candidate this
/// gateway has moved past.
#[test]
fn a_transition_for_another_epoch_than_the_pending_request_is_refused() {
    let held = request(4, NOW + 3_600);
    let leaf = leaf_for(&held.new_ml_dsa_87_public_key);

    let refusal = candidate_is_held(&transition(5, Some(leaf), None), Some(&held), None)
        .expect_err("an epoch the sealed candidate was not prepared for");

    assert!(refusal.to_string().contains("epoch"));
}

#[test]
fn a_tls_leaf_that_is_not_the_candidate_is_refused() {
    let held = request(4, NOW + 3_600);
    let leaf = leaf_for(&held.new_ml_dsa_87_public_key);
    let candidate = DerCertificate::new(vec![1; 64]).expect("der");
    let stranger = DerCertificate::new(vec![2; 64]).expect("der");

    candidate_is_held(
        &transition(4, Some(leaf), Some(stranger)),
        Some(&held),
        Some(&candidate),
    )
    .expect_err("a TLS leaf sealed elsewhere");
}

#[test]
fn a_tls_leaf_with_no_candidate_sealed_here_is_refused() {
    let held = request(4, NOW + 3_600);
    let leaf = leaf_for(&held.new_ml_dsa_87_public_key);
    let tls = DerCertificate::new(vec![3; 64]).expect("der");

    let refusal = candidate_is_held(&transition(4, Some(leaf), Some(tls)), Some(&held), None)
        .expect_err("a TLS leaf this gateway never prepared");

    assert!(refusal.to_string().contains("--rotate-tls"));
}

#[test]
fn a_transition_that_keeps_both_gateway_leaves_needs_no_local_candidate() {
    candidate_is_held(&transition(4, None, None), None, None)
        .expect("an unchanged identity has no candidate to compare");
}

/// A registry on disk, so the promotion path is exercised where it runs.
fn registry_in(
    directory: &std::path::Path,
    gateway: GatewayCertificateState,
) -> CertificateRegistry {
    use helios_provisioning::certificates::RegistryState;

    let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
    let state = RegistryState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway,
        client_tls_ca: aether::certificates::state::ClientTlsCaState {
            ca_tls_epoch: 1,
            active_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
                "workstation",
            )
            .authority,
            next_client_tls_ca_certificate: None,
            next_transition_fingerprint: None,
            activation_at: None,
            retire_active_at: None,
        },
        astra: aether::certificates::state::AstraProfile {
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                aether::certificates::encoding::Fingerprint::of(b"policy"),
            )
            .expect("policy pin"),
            credential_registry_epoch: 1,
            credential_bindings: Default::default(),
            active_astra_service_public_key: service,
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 1,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer: None,
        peers: Default::default(),
        ledger: Default::default(),
    };
    CertificateRegistry::new(directory.join("certificates.json"), state)
}

fn documents_in(directory: &std::path::Path) -> IdentityDocuments {
    IdentityDocuments {
        transition: directory.join("transition.json"),
        marker: directory.join("promotion.json"),
        pending_request: directory.join("request.json"),
    }
}

fn staged_transition(epoch: u64) -> GatewayIdentityTransition {
    GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        server_name: "gateway.example".into(),
        active_gateway_tls_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
            b"active tls",
        ),
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
            b"active pq",
        ),
        next_gateway_certificate: None,
        window: aether::certificates::window::TransitionWindow {
            not_before: NOW,
            activation_at: NOW + 1_000,
            not_after: NOW + 2_000,
        },
        reason: aether::certificates::authority::RotationReason::Scheduled,
        ca_signature: MlDsa87Signature::placeholder(),
    }
}

struct InstallationFixture {
    directory: tempfile::TempDir,
    registry: CertificateRegistry,
    documents: IdentityDocuments,
    request: GatewayCertificateRequest,
    transition: GatewayIdentityTransition,
    rollback: CertificateServiceRollbackAuthorization,
}

impl InstallationFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary installation directory");
        let documents = documents_in(directory.path());
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let mut gateway = gateway();
        let active_public =
            MlDsa87PublicKey::parse(&gateway.active_gateway_certificate.ml_dsa_87_public_key)
                .expect("active gateway public key");
        gateway.active_gateway_certificate = leaf_for_ca(&active_public, &ca_private);
        gateway.current_ca_public_key = ca_public;
        let registry = registry_in(directory.path(), gateway);
        let registry = CertificateRegistry::bootstrap(
            directory.path().join("certificates.json"),
            registry.state().clone(),
        )
        .expect("persist initial registry");

        let gateway = &registry.state().gateway;
        let request = request(gateway.gateway_decision_epoch + 1, NOW + 3_600);
        let candidate = leaf_for_ca(&request.new_ml_dsa_87_public_key, &ca_private);
        let mut transition = transition(request.gateway_identity_epoch, Some(candidate), None);
        transition.active_gateway_tls_certificate_fingerprint = gateway.active_tls_fingerprint();
        transition.active_gateway_certificate_fingerprint = gateway
            .active_pq_fingerprint()
            .expect("active PQ fingerprint");
        let transition = transition.sign(&ca_private).expect("sign transition");
        let rollback = CertificateServiceRollbackAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: gateway.trust_domain_id,
            ca_epoch: gateway.ca_epoch,
            gateway_wg_public_key: gateway.gateway_wg_public_key,
            server_name: gateway.server_name.clone(),
            transition_fingerprint: transition.fingerprint().expect("transition fingerprint"),
            selected_certificate_fingerprint: gateway.active_tls_fingerprint(),
            campaign_fingerprint: Fingerprint::of(b"operator campaign"),
            expires_at: transition.window.not_after,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_private)
        .expect("sign rollback");

        Self {
            directory,
            registry,
            documents,
            request,
            transition,
            rollback,
        }
    }

    fn install(&mut self) -> Result<StagedTransition> {
        install_transition_at(
            &mut self.registry,
            self.transition.clone(),
            NOW,
            Some(&self.request),
            None,
            self.documents.transition.clone(),
        )
    }

    fn registry_path(&self) -> std::path::PathBuf {
        self.directory.path().join("certificates.json")
    }
}

#[test]
fn installing_a_signed_transition_keeps_the_outgoing_identity_and_restores_its_document_on_replay()
{
    let mut fixture = InstallationFixture::new();
    let outgoing = fixture.registry.state().gateway.clone();

    let staged = fixture.install().expect("stage signed transition");
    assert!(!staged.already_present);
    assert_eq!(staged.path, fixture.documents.transition);
    assert_eq!(staged.transition, fixture.transition);
    let registry_path = fixture.registry_path();
    let persisted = std::fs::read(&registry_path).expect("read staged registry");
    let reloaded = CertificateRegistry::load(&registry_path)
        .expect("reload registry")
        .expect("registry exists");
    let gateway = &reloaded.state().gateway;
    assert_eq!(
        gateway.active_gateway_identity_epoch,
        outgoing.active_gateway_identity_epoch
    );
    assert_eq!(
        gateway.active_pq_fingerprint().expect("active PQ"),
        outgoing.active_pq_fingerprint().expect("outgoing PQ")
    );
    assert_eq!(
        gateway.active_tls_fingerprint(),
        outgoing.active_tls_fingerprint()
    );
    assert_eq!(
        gateway.next_gateway_identity_epoch,
        Some(staged.transition.gateway_identity_epoch)
    );
    assert_eq!(
        gateway.next_transition_fingerprint,
        Some(staged.transition.fingerprint().expect("fingerprint"))
    );
    assert!(!gateway.published);

    std::fs::remove_file(&staged.path).expect("simulate a missing staged document");
    let replay = fixture.install().expect("replay signed transition");
    assert!(replay.already_present);
    assert_eq!(
        read_staged_transition(&replay.path).expect("read restored document"),
        Some(fixture.transition)
    );
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        persisted
    );
}

#[test]
fn a_candidate_mismatch_cannot_overwrite_a_staged_document() {
    let mut fixture = InstallationFixture::new();
    let staged = fixture.install().expect("stage signed transition");
    let previous_document = std::fs::read(&staged.path).expect("read staged document");
    let registry_path = fixture.registry_path();
    let previous_registry = std::fs::read(&registry_path).expect("read staged registry");

    fixture.request = request(fixture.transition.gateway_identity_epoch, NOW + 3_600);
    let Err(error) = fixture.install() else {
        panic!("a different local candidate must be refused");
    };
    assert!(
        error.to_string().contains("key this gateway did not seal"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(staged.path).expect("read staged document again"),
        previous_document
    );
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        previous_registry
    );
}

#[test]
fn a_transition_signed_by_another_ca_cannot_overwrite_the_retained_document() {
    let mut fixture = InstallationFixture::new();
    let document = &fixture.documents.transition;
    std::fs::write(document, b"retained transition").expect("write retained document");
    let registry_path = fixture.registry_path();
    let previous_registry = std::fs::read(&registry_path).expect("read original registry");
    let (wrong_ca, _) = generate_ml_dsa_87_keypair().expect("other CA keypair");
    fixture.transition = fixture
        .transition
        .sign(&wrong_ca)
        .expect("sign with other CA");

    let Err(error) = fixture.install() else {
        panic!("the registry must refuse an untrusted signature");
    };
    assert!(
        error.to_string().contains("verifying the transition"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(&fixture.documents.transition).expect("read retained document"),
        b"retained transition"
    );
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        previous_registry
    );
    assert!(fixture
        .registry
        .state()
        .gateway
        .next_gateway_identity_epoch
        .is_none());
}

#[test]
fn a_blocked_transition_document_leaves_the_registry_unchanged() {
    let mut fixture = InstallationFixture::new();
    let registry_path = fixture.registry_path();
    let previous_registry = std::fs::read(&registry_path).expect("read original registry");
    std::fs::create_dir(&fixture.documents.transition).expect("block atomic replacement");

    let Err(error) = fixture.install() else {
        panic!("staging must require the transition document to reach disk");
    };
    assert!(
        error.to_string().contains("atomically replacing"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        previous_registry
    );
    assert!(fixture
        .registry
        .state()
        .gateway
        .next_gateway_identity_epoch
        .is_none());
}

#[test]
fn a_rollback_is_refused_without_a_published_overlap() {
    let mut fixture = InstallationFixture::new();
    let now = fixture.transition.window.activation_at;
    let Err(error) = install_rollback(&mut fixture.registry, fixture.rollback.clone(), now) else {
        panic!("rollback requires a staged transition");
    };
    assert!(
        error
            .to_string()
            .contains("no gateway transition is staged"),
        "{error:#}"
    );

    fixture.install().expect("stage signed transition");
    let registry_path = fixture.registry_path();
    let previous_registry = std::fs::read(&registry_path).expect("read staged registry");
    let Err(error) = install_rollback(&mut fixture.registry, fixture.rollback, now) else {
        panic!("rollback requires publication");
    };
    assert!(
        matches!(
            error.downcast_ref::<helios_provisioning::certificates::RegistryError>(),
            Some(
                helios_provisioning::certificates::RegistryError::Certificate(
                    aether::certificates::CertificateError::RollbackUnavailable
                )
            )
        ),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        previous_registry
    );
}

#[test]
fn an_installed_rollback_persists_the_old_leaf_selection_without_losing_the_candidate() {
    let mut fixture = InstallationFixture::new();
    let staged = fixture.install().expect("stage signed transition");
    let epoch = staged.transition.gateway_identity_epoch;
    fixture
        .registry
        .publish_gateway_transition(
            epoch,
            &staged.transition.fingerprint().expect("fingerprint"),
        )
        .expect("publish staged transition");
    let now = staged.transition.window.activation_at;
    let old_epoch = fixture
        .registry
        .state()
        .gateway
        .active_gateway_identity_epoch;
    let selected = install_rollback(&mut fixture.registry, fixture.rollback.clone(), now)
        .expect("install rollback within overlap");
    assert!(!selected.already_present);
    assert_eq!(selected.gateway_identity_epoch, epoch);
    assert_eq!(
        selected.selected_certificate_fingerprint,
        fixture.rollback.selected_certificate_fingerprint
    );
    assert_eq!(selected.expires_at, staged.transition.window.not_after);

    let registry_path = fixture.registry_path();
    let persisted = std::fs::read(&registry_path).expect("read rollback registry");
    let reloaded = CertificateRegistry::load(&registry_path)
        .expect("reload")
        .expect("registry exists");
    assert!(reloaded.active_gateway_rollback(now).is_some());
    assert!(reloaded
        .active_gateway_rollback(selected.expires_at)
        .is_none());
    let gateway = &reloaded.state().gateway;
    assert_eq!(gateway.active_gateway_identity_epoch, old_epoch);
    assert_eq!(gateway.next_gateway_identity_epoch, Some(epoch));
    assert_eq!(
        read_staged_transition(&staged.path).expect("read retained document"),
        Some(staged.transition)
    );

    let replay = install_rollback(&mut fixture.registry, fixture.rollback, now)
        .expect("repeat the same rollback");
    assert!(replay.already_present);
    assert_eq!(
        std::fs::read(registry_path).expect("read registry again"),
        persisted
    );
}

fn promoted_registry_and_transition(
    mut gateway: GatewayCertificateState,
    rotate_tls: bool,
    rotate_pq: bool,
) -> (GatewayCertificateState, GatewayIdentityTransition) {
    let mut transition = staged_transition(gateway.active_gateway_identity_epoch + 1);
    transition.active_gateway_tls_certificate_fingerprint = gateway.active_tls_fingerprint();
    transition.active_gateway_certificate_fingerprint = gateway
        .active_pq_fingerprint()
        .expect("outgoing PQ fingerprint");

    if rotate_tls {
        let new_leaf = aether::certificates::encoding::DerCertificate::new(vec![2; 64])
            .expect("candidate TLS leaf");
        transition.next_gateway_tls_certificate = Some(new_leaf.clone());
        gateway.active_gateway_tls_certificate = new_leaf;
    }
    if rotate_pq {
        let new_leaf = gateway_leaf();
        transition.next_gateway_certificate = Some(new_leaf.clone());
        gateway.active_gateway_certificate = new_leaf;
    }
    gateway.active_gateway_identity_epoch = transition.gateway_identity_epoch;
    gateway.gateway_decision_epoch = transition.gateway_identity_epoch;
    (gateway, transition)
}

#[test]
fn promotion_guard_accepts_partial_and_full_leaf_rotations() {
    for (rotate_tls, rotate_pq) in [(true, false), (false, true), (true, true)] {
        let (gateway, transition) =
            promoted_registry_and_transition(gateway(), rotate_tls, rotate_pq);
        crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
            .expect("the registry agrees with the promoted transition");
    }
}

#[test]
fn promotion_guard_rejects_a_registry_still_at_the_outgoing_epoch() {
    let (mut gateway, transition) = promoted_registry_and_transition(gateway(), true, true);
    gateway.active_gateway_identity_epoch -= 1;

    let error = crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
        .expect_err("wrong active epoch");
    assert!(error.to_string().contains("registry is at gateway epoch 3"));
}

#[test]
fn promotion_guard_rejects_a_transition_for_another_gateway() {
    let (gateway, mut transition) = promoted_registry_and_transition(gateway(), true, true);
    transition.gateway_wg_public_key = WireGuardKey::from_bytes([10; 32]);

    let error = crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
        .expect_err("wrong gateway");
    assert_eq!(
        error.to_string(),
        "the retained transition belongs to another gateway identity"
    );
}

#[test]
fn promotion_guard_rejects_the_outgoing_tls_leaf_when_tls_was_rotated() {
    let outgoing = gateway();
    let outgoing_tls = outgoing.active_gateway_tls_certificate.clone();
    let (mut gateway, transition) = promoted_registry_and_transition(outgoing, true, false);
    gateway.active_gateway_tls_certificate = outgoing_tls;

    let error = crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
        .expect_err("the outgoing TLS leaf is still active");
    assert_eq!(
        error.to_string(),
        "the promoted TLS leaf does not match the retained transition"
    );
}

#[test]
fn promotion_guard_rejects_the_outgoing_pq_leaf_when_pq_was_rotated() {
    let outgoing = gateway();
    let outgoing_pq = outgoing.active_gateway_certificate.clone();
    let (mut gateway, transition) = promoted_registry_and_transition(outgoing, false, true);
    gateway.active_gateway_certificate = outgoing_pq;

    let error = crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
        .expect_err("the outgoing PQ leaf is still active");
    assert_eq!(
        error.to_string(),
        "the promoted PQ leaf does not match the retained transition"
    );
}

#[test]
fn promotion_guard_rejects_a_candidate_pq_leaf_with_no_canonical_fingerprint() {
    let (gateway, mut transition) = promoted_registry_and_transition(gateway(), false, true);
    transition
        .next_gateway_certificate
        .as_mut()
        .expect("candidate PQ certificate")
        .ml_dsa_87_signature
        .clear();

    let error = crate::key_negotiation::validate_promoted_gateway_identity(&gateway, &transition)
        .expect_err("the candidate no longer contains a well-formed signature");
    assert_eq!(
        error.to_string(),
        "fingerprinting the retained candidate PQ leaf"
    );
}

#[test]
fn a_gateway_with_nothing_in_flight_is_left_alone() {
    let directory = tempfile::tempdir().expect("temp dir");
    let mut registry = registry_in(directory.path(), gateway());

    assert!(!maintain_gateway_identity_in(
        &mut registry,
        None,
        NOW,
        &documents_in(directory.path())
    )
    .expect("nothing to do"));
}

/// Before `not_after` the overlap is still running: both identities are
/// legitimate, and promoting early would retire one the fleet still uses.
#[test]
fn a_staged_transition_is_not_promoted_before_its_not_after() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    let transition = staged_transition(4);
    write_document(&documents.transition, &transition, "transition").expect("write");
    let mut gateway = gateway();
    gateway.next_gateway_identity_epoch = Some(4);
    gateway.activation_at = Some(NOW + 1_000);
    gateway.retire_active_at = Some(NOW + 2_000);
    gateway.published = true;
    let mut registry = registry_in(directory.path(), gateway);

    assert!(
        !maintain_gateway_identity_in(&mut registry, None, NOW + 1_999, &documents)
            .expect("still in overlap")
    );
    assert!(documents.transition.exists());
}

#[test]
fn a_due_transition_for_another_epoch_fails_without_changing_the_registry() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    write_document(&documents.transition, &staged_transition(5), "transition")
        .expect("write transition");
    let mut gateway = gateway();
    gateway.next_gateway_identity_epoch = Some(4);
    gateway.activation_at = Some(NOW + 1_000);
    gateway.retire_active_at = Some(NOW + 2_000);
    gateway.published = true;
    let mut registry = registry_in(directory.path(), gateway);

    let error = maintain_gateway_identity_in(&mut registry, None, NOW + 2_000, &documents)
        .expect_err("the due transition must match the staged epoch");

    assert!(error
        .to_string()
        .contains("while epoch 4 must be finalized"));
    assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 3);
    assert!(documents.transition.exists());
}

#[test]
fn malformed_retained_transition_fails_without_changing_the_registry() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    std::fs::write(&documents.transition, b"{not-json").expect("write malformed transition");
    let mut registry = registry_in(directory.path(), gateway());

    let error = maintain_gateway_identity_in(&mut registry, None, NOW, &documents)
        .expect_err("malformed persisted state must fail closed");

    assert!(error
        .to_string()
        .contains("decoding the staged gateway transition"));
    assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 3);
    assert!(documents.transition.exists());
}

/// §11.1 forbids promoting what was never distributed: the fleet would be
/// asked to follow a decision it was never offered.
#[test]
fn a_due_transition_that_was_never_published_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    write_document(&documents.transition, &staged_transition(4), "transition").expect("write");
    let mut gateway = gateway();
    gateway.next_gateway_identity_epoch = Some(4);
    gateway.activation_at = Some(NOW + 1_000);
    gateway.retire_active_at = Some(NOW + 2_000);
    gateway.published = false;
    let mut registry = registry_in(directory.path(), gateway);

    let refusal = maintain_gateway_identity_in(&mut registry, None, NOW + 2_000, &documents)
        .expect_err("an unpublished promotion");
    assert!(refusal.to_string().contains("published"));
    assert_eq!(
        registry.state().gateway.active_gateway_identity_epoch,
        3,
        "the identity in service must not have moved"
    );
}

/// The candidate is sealed. Without the TPM secret the promotion cannot be
/// completed, and the registry must not record one that the machine cannot
/// then serve.
#[test]
fn a_due_transition_without_the_tpm_secret_moves_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    write_document(&documents.transition, &staged_transition(4), "transition").expect("write");
    let mut gateway = gateway();
    gateway.next_gateway_identity_epoch = Some(4);
    gateway.activation_at = Some(NOW + 1_000);
    gateway.retire_active_at = Some(NOW + 2_000);
    gateway.published = true;
    let mut registry = registry_in(directory.path(), gateway);

    assert!(maintain_gateway_identity_in(&mut registry, None, NOW + 2_000, &documents).is_err());
    assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 3);
    assert!(documents.transition.exists());
}

/// The one crash window the marker exists for: the sealed vault is already
/// the new one, the registry is already promoted, and the outgoing
/// documents had not been removed yet. The replay must finish the cleanup
/// without asking for a secret and without moving the epoch again.
#[test]
fn a_crash_between_the_vault_and_the_cleanup_is_replayed() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    let transition = staged_transition(4);
    write_document(&documents.transition, &transition, "transition").expect("write");
    write_document(
        &documents.marker,
        &PromotionMarker {
            gateway_identity_epoch: 4,
            transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        },
        "marker",
    )
    .expect("write");
    let mut gateway = gateway();
    gateway.active_gateway_identity_epoch = 4;
    gateway.gateway_decision_epoch = 4;
    let mut registry = registry_in(directory.path(), gateway);
    // The candidate slot lives in this run's own directory, never in the
    // machine's.
    std::env::set_var(
        "HELIOS_KEY_NEGO_NEXT_KEY",
        directory.path().join("next.sealed"),
    );
    std::env::set_var(
        "HELIOS_KEY_NEGO_NEXT_CERT",
        directory.path().join("next.der"),
    );

    assert!(
        maintain_gateway_identity_in(&mut registry, None, NOW + 3_000, &documents)
            .expect("replayed"),
        "the interrupted promotion must finish"
    );
    assert!(!documents.transition.exists());
    assert!(!documents.marker.exists());
    assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 4);
}

/// A marker naming another document would let a crash finish a promotion
/// that never happened.
#[test]
fn a_marker_naming_another_transition_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    let transition = staged_transition(4);
    write_document(&documents.transition, &transition, "transition").expect("write");
    write_document(
        &documents.marker,
        &PromotionMarker {
            gateway_identity_epoch: 4,
            transition_fingerprint: aether::certificates::encoding::Fingerprint::of(
                b"another decision",
            ),
        },
        "marker",
    )
    .expect("write");
    let mut gateway = gateway();
    gateway.active_gateway_identity_epoch = 4;
    gateway.gateway_decision_epoch = 4;
    let mut registry = registry_in(directory.path(), gateway);

    assert!(maintain_gateway_identity_in(&mut registry, None, NOW + 3_000, &documents).is_err());
    assert!(documents.transition.exists());
}

/// A marker left behind with nothing staged is a completed promotion whose
/// last write was lost. It is cleared, not acted on.
#[test]
fn a_marker_for_the_identity_in_service_is_swept() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    write_document(
        &documents.marker,
        &PromotionMarker {
            gateway_identity_epoch: 3,
            transition_fingerprint: aether::certificates::encoding::Fingerprint::of(b"spent"),
        },
        "marker",
    )
    .expect("write");
    let mut registry = registry_in(directory.path(), gateway());

    assert!(!maintain_gateway_identity_in(&mut registry, None, NOW, &documents).expect("swept"));
    assert!(!documents.marker.exists());
}

/// The same marker at an epoch this gateway never reached describes a
/// promotion of something else entirely.
#[test]
fn a_marker_for_an_epoch_never_reached_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    write_document(
        &documents.marker,
        &PromotionMarker {
            gateway_identity_epoch: 9,
            transition_fingerprint: aether::certificates::encoding::Fingerprint::of(b"other"),
        },
        "marker",
    )
    .expect("write");
    let mut registry = registry_in(directory.path(), gateway());

    assert!(maintain_gateway_identity_in(&mut registry, None, NOW, &documents).is_err());
    assert!(documents.marker.exists());
}

/// The console reads the staged document while the overlap runs: the
/// rollback and the abort both need the exact bytes the registry staged.
#[test]
fn staged_transition_is_served_until_promotion() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    let transition = staged_transition(4);
    write_document(&documents.transition, &transition, "transition").expect("write");
    let mut gateway = gateway();
    gateway.next_gateway_identity_epoch = Some(4);
    gateway.activation_at = Some(NOW + 1_000);
    gateway.retire_active_at = Some(NOW + 2_000);
    gateway.published = true;
    let mut registry = registry_in(directory.path(), gateway);

    assert_eq!(
        read_staged_transition(&documents.transition).expect("read"),
        Some(transition.clone())
    );
    assert!(
        !maintain_gateway_identity_in(&mut registry, None, NOW + 1_999, &documents)
            .expect("still in overlap")
    );
    assert_eq!(
        read_staged_transition(&documents.transition).expect("read"),
        Some(transition)
    );
}

#[test]
fn staged_transition_is_null_without_one() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());

    assert_eq!(
        read_staged_transition(&documents.transition).expect("read"),
        None
    );
}

/// What a preparation writes is what the console reads back: the request for
/// the ceremony and the candidate TLS leaf, both public.
#[test]
fn renewal_request_and_candidate_tls_are_readable_after_prepare() {
    let directory = tempfile::tempdir().expect("temp dir");
    let documents = documents_in(directory.path());
    let prepared = request(4, NOW + 1_000);
    write_pending(&documents.pending_request, &prepared).expect("write request");
    assert_eq!(
        read_pending(&documents.pending_request).expect("read request"),
        Some(prepared)
    );

    let candidate = aether::certificates::encoding::DerCertificate::new(vec![7; 64]).expect("der");
    let candidate_path = directory.path().join("next.der");
    std::fs::write(&candidate_path, candidate.as_bytes()).expect("write candidate");
    assert_eq!(
        crate::key_negotiation::read_candidate_tls_certificate(&candidate_path)
            .expect("read candidate"),
        Some(candidate)
    );
    assert_eq!(
        crate::key_negotiation::read_candidate_tls_certificate(
            &directory.path().join("absent.der")
        )
        .expect("read absent candidate"),
        None
    );
}

/// A registered transition whose document is gone cannot be rolled back or
/// aborted: the console is told so, rather than shown an empty answer.
#[test]
fn a_staged_transition_without_its_document_is_refused() {
    let error = staged_answer(true, None).expect_err("the document is required");
    assert!(
        error
            .to_string()
            .contains("la transition en cours n'a plus son document"),
        "{error:#}"
    );
}

/// A document left by a preparation whose installation was refused is stale
/// outside a transition, and must not be served as one.
#[test]
fn a_stale_document_outside_a_transition_reads_null() {
    assert_eq!(
        staged_answer(false, Some(staged_transition(4))).expect("answer"),
        None
    );
}

#[test]
fn a_staged_document_is_returned_while_its_transition_is_registered() {
    let transition = staged_transition(4);

    assert_eq!(
        staged_answer(true, Some(transition.clone())).expect("answer"),
        Some(transition)
    );
}

#[test]
fn an_optional_document_distinguishes_absent_and_malformed_files() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("transition.json");
    assert_eq!(
        read_staged_transition(&path).expect("absent is optional"),
        None
    );

    std::fs::write(&path, b"{not-json").expect("write malformed document");
    let error = read_staged_transition(&path).expect_err("malformed persisted state fails closed");
    assert!(error
        .to_string()
        .contains("decoding the staged gateway transition"));
}

#[test]
fn document_writes_create_parents_and_replace_the_old_file() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory
        .path()
        .join("nested")
        .join("gateway-transition.json");
    let first = staged_transition(4);
    write_document(&path, &first, "transition").expect("initial write");
    let replacement = staged_transition(5);
    write_document(&path, &replacement, "transition").expect("atomic replacement");

    assert_eq!(
        read_staged_transition(&path).expect("read replacement"),
        Some(replacement)
    );
    assert!(!path.with_extension("tmp").exists());
}

#[test]
fn document_writes_refuse_a_parent_that_is_a_file() {
    let directory = tempfile::tempdir().expect("temp dir");
    let parent = directory.path().join("not-a-directory");
    std::fs::write(&parent, b"occupied").expect("write parent file");
    let path = parent.join("transition.json");

    let error = write_document(&path, &staged_transition(4), "transition")
        .expect_err("a non-directory parent must refuse the write");

    assert!(error.to_string().contains("creating"));
}

#[test]
fn removing_a_document_is_idempotent_but_surfaces_other_io_errors() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("transition.json");
    remove_document(&path).expect("missing documents are already removed");

    std::fs::write(&path, b"document").expect("write document");
    remove_document(&path).expect("remove existing document");
    remove_document(&path).expect("second removal is harmless");

    let error = remove_document(directory.path()).expect_err("directories are not documents");
    assert!(error.to_string().contains("removing"));
}

#[test]
fn signed_document_reader_reports_missing_and_malformed_inputs() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("abort.json");
    assert!(read_signed_document::<GatewayTransitionAbort>(&path, "abort").is_err());

    std::fs::write(&path, b"{not-json").expect("write malformed document");
    let error = read_signed_document::<GatewayTransitionAbort>(&path, "abort")
        .expect_err("malformed signed input is refused");
    assert!(error.to_string().contains("decoding the abort"));
}
