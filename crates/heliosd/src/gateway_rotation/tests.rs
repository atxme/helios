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

fn leaf_for(public_key: &MlDsa87PublicKey) -> PqCertificate {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [2; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(public_key.as_bytes()),
            not_before_unix: 0,
            not_after_unix: NOW + 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
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
