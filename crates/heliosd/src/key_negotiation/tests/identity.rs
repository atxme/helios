//! Served identity: bootstrap certificate, restart selection and promotion.

use super::super::*;
use super::fixtures::*;

fn bootstrap_fixture() -> (
    aether::certificates::gateway::GatewayBootstrapRequest,
    Vec<u8>,
    aether::certificates::encoding::MlDsa87PublicKey,
    Vec<u8>,
    u64,
) {
    use aether::certificates::{
        encoding::{MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
        gateway::GatewayBootstrapRequest,
        CERTIFICATE_FORMAT_VERSION,
    };

    let now = test_now();
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let gateway_public =
        MlDsa87PublicKey::parse(&base64::engine::general_purpose::STANDARD.encode(gateway_public))
            .expect("gateway public key");
    let request = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: WireGuardKey::parse(GATEWAY_KEY).expect("WireGuard key"),
        server_name: "gateway.example".into(),
        ml_dsa_87_public_key: gateway_public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway_private)
    .expect("request");
    let (ca_private, ca_public_bytes) = generate_ml_dsa_87_keypair().expect("CA key");
    let ca_public = MlDsa87PublicKey::new(ca_public_bytes).expect("CA public key");
    (
        request,
        gateway_private.to_vec(),
        ca_public,
        ca_private.to_vec(),
        now,
    )
}

fn bootstrap_leaf(
    request: &aether::certificates::gateway::GatewayBootstrapRequest,
    public_key: &[u8],
    issuer_private_key: &[u8],
    not_before_unix: u64,
    not_after_unix: u64,
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [0x31; 16],
            subject: request.server_name.clone(),
            issuer: "helios-ca-pq".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: request.gateway_wg_public_key.to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            not_before_unix,
            not_after_unix,
            ml_dsa_87_signature: String::new(),
        },
        issuer_private_key,
    )
    .expect("CA-signed bootstrap leaf")
}

#[test]
fn trust_bootstrap_accepts_only_the_ca_pq_issued_leaf() {
    use aether::certificates::{
        encoding::{MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
        gateway::GatewayBootstrapRequest,
        CERTIFICATE_FORMAT_VERSION,
    };

    let now = test_now();
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let gateway_public =
        MlDsa87PublicKey::parse(&base64::engine::general_purpose::STANDARD.encode(gateway_public))
            .expect("gateway public key");
    let request = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: WireGuardKey::parse(GATEWAY_KEY).expect("WireGuard key"),
        server_name: "gateway.example".into(),
        ml_dsa_87_public_key: gateway_public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway_private)
    .expect("request");
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("CA key");
    let ca_public =
        MlDsa87PublicKey::parse(&base64::engine::general_purpose::STANDARD.encode(ca_public))
            .expect("CA public key");
    let unsigned = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [3; 16],
        subject: request.server_name.clone(),
        issuer: "helios-ca-pq".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: GATEWAY_KEY.into(),
        ml_dsa_87_public_key: request.ml_dsa_87_public_key.to_base64(),
        not_before_unix: now.saturating_sub(1),
        not_after_unix: now + 3_600,
        ml_dsa_87_signature: String::new(),
    };
    let ca_leaf = issue_pq_certificate(unsigned.clone(), &ca_private).expect("CA leaf");
    verify_gateway_bootstrap_certificate(&request, &ca_leaf, &ca_public, now).expect("CA-PQ leaf");

    let mut self_issued = unsigned;
    self_issued.issuer = self_issued.subject.clone();
    let self_signed =
        issue_pq_certificate(self_issued, &gateway_private).expect("self-signed leaf");
    assert!(matches!(
        verify_gateway_bootstrap_certificate(&request, &self_signed, &ca_public, now),
        Err(GatewayBootstrapCertificateError::SelfSignedGatewayCertificate)
    ));
}

#[test]
fn trust_bootstrap_rejects_a_request_whose_identity_proof_was_changed() {
    let (mut request, _gateway_private, ca_public, ca_private, now) = bootstrap_fixture();
    let leaf = bootstrap_leaf(
        &request,
        request.ml_dsa_87_public_key.as_bytes(),
        &ca_private,
        now.saturating_sub(1),
        now.saturating_add(3_600),
    );
    request.server_name = "attacker.example".into();

    let error = verify_gateway_bootstrap_certificate(&request, &leaf, &ca_public, now)
        .expect_err("the request proof binds the server name");

    assert!(matches!(
        error,
        GatewayBootstrapCertificateError::InvalidRequest(_)
    ));
}

#[test]
fn trust_bootstrap_rejects_a_leaf_signed_by_an_untrusted_ca() {
    let (request, _gateway_private, ca_public, _ca_private, now) = bootstrap_fixture();
    let (rogue_private, _) = generate_ml_dsa_87_keypair().expect("rogue CA key");
    let leaf = bootstrap_leaf(
        &request,
        request.ml_dsa_87_public_key.as_bytes(),
        &rogue_private,
        now.saturating_sub(1),
        now.saturating_add(3_600),
    );

    let error = verify_gateway_bootstrap_certificate(&request, &leaf, &ca_public, now)
        .expect_err("the configured CA must issue the gateway leaf");

    assert!(matches!(
        error,
        GatewayBootstrapCertificateError::InvalidCertificate(_)
    ));
}

#[test]
fn trust_bootstrap_rejects_a_ca_signed_leaf_for_a_different_gateway_key() {
    let (request, _gateway_private, ca_public, ca_private, now) = bootstrap_fixture();
    let (_, other_gateway_public) = generate_ml_dsa_87_keypair().expect("other gateway key");
    let leaf = bootstrap_leaf(
        &request,
        &other_gateway_public,
        &ca_private,
        now.saturating_sub(1),
        now.saturating_add(3_600),
    );

    let error = verify_gateway_bootstrap_certificate(&request, &leaf, &ca_public, now)
        .expect_err("the signed leaf must carry the locally sealed key");

    assert!(matches!(
        error,
        GatewayBootstrapCertificateError::IdentityMismatch
    ));
}

#[test]
fn trust_bootstrap_rejects_not_yet_valid_and_expired_ca_leaves() {
    let (request, _gateway_private, ca_public, ca_private, now) = bootstrap_fixture();
    let not_yet_valid = bootstrap_leaf(
        &request,
        request.ml_dsa_87_public_key.as_bytes(),
        &ca_private,
        now.saturating_add(1),
        now.saturating_add(3_600),
    );
    let expired = bootstrap_leaf(
        &request,
        request.ml_dsa_87_public_key.as_bytes(),
        &ca_private,
        now.saturating_sub(3_600),
        now.saturating_sub(1),
    );

    assert!(matches!(
        verify_gateway_bootstrap_certificate(&request, &not_yet_valid, &ca_public, now),
        Err(GatewayBootstrapCertificateError::InvalidCertificate(_))
    ));
    assert!(matches!(
        verify_gateway_bootstrap_certificate(&request, &expired, &ca_public, now),
        Err(GatewayBootstrapCertificateError::InvalidCertificate(_))
    ));
}

#[test]
fn a_restart_selects_only_a_published_candidate_inside_the_overlap() {
    assert_eq!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, false, 199)
            .expect("before activation"),
        ServedIdentitySlot::Active
    );
    assert_eq!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, false, 200)
            .expect("published overlap"),
        ServedIdentitySlot::Candidate { epoch: 2 }
    );
    assert!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), false, false, 200,)
            .is_err()
    );
    assert!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, false, 300,)
            .is_err()
    );
}

/// A rollback puts the overlap back on the outgoing leaf without moving
/// the end of the decision it lives in (spec §4.4, §11.1 step 8).
#[test]
fn a_service_rollback_returns_the_restart_to_the_outgoing_leaf() {
    assert_eq!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, true, 250)
            .expect("rolled back"),
        ServedIdentitySlot::Active
    );
    assert!(
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, true, 300,)
            .is_err(),
        "a rollback postpones which leaf is served, never the end of the overlap"
    );
    assert!(
        select_served_identity_slot(true, Some(2), Some(200), Some(300), true, true, 250,).is_err(),
        "a revoked identity serves nothing, rolled back or not"
    );
}

/// The bounded rollback of §4.4 ends by the clock, and nothing in this
/// daemon restarts it when it does. The served leaf is unsealed once and
/// held for the life of the process, deliberately — so what was missing
/// was never the swap, it was saying that the swap is due.
#[test]
fn an_expired_rollback_says_a_restart_is_due_rather_than_going_quiet() {
    // Serving the outgoing leaf under a rollback that has since expired:
    // a fresh start would present the staged identity.
    assert!(restart_reason(
        ServedIdentitySlot::Active,
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, false, 250),
    )
    .expect("a restart is due")
    .contains("epoch 2 is due"));

    // The other direction: a rollback installed after this process chose
    // the candidate. Installing it records the decision; a restart applies
    // it.
    assert!(restart_reason(
        ServedIdentitySlot::Candidate { epoch: 2 },
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, true, 250),
    )
    .expect("a restart is due")
    .contains("service rollback"));

    // Unchanged is silent: a warning on every sweep of a healthy gateway
    // is a warning nobody reads when it matters.
    assert!(restart_reason(
        ServedIdentitySlot::Candidate { epoch: 2 },
        select_served_identity_slot(false, Some(2), Some(200), Some(300), true, false, 250),
    )
    .is_none());

    // A start that would refuse carries its reason rather than a verdict:
    // restarting blind is exactly what must not happen here.
    assert!(restart_reason(
        ServedIdentitySlot::Active,
        select_served_identity_slot(true, Some(2), Some(200), Some(300), true, false, 250),
    )
    .expect("a restart would refuse")
    .contains("would refuse"));
}

#[test]
fn promotion_composes_only_the_halves_named_by_the_transition() {
    let active = StoredPrivateIdentity {
        tls_private_key: "active-tls".into(),
        pq_private_key: "active-pq".into(),
    };
    let candidate = StoredCandidateIdentity {
        tls_private_key: Some("candidate-tls".into()),
        pq_private_key: "candidate-pq".into(),
    };
    let promoted =
        compose_private_identity(active, candidate, true, false).expect("TLS-only rotation");
    assert_eq!(promoted.tls_private_key, "candidate-tls");
    assert_eq!(promoted.pq_private_key, "active-pq");

    let active = StoredPrivateIdentity {
        tls_private_key: "active-tls".into(),
        pq_private_key: "active-pq".into(),
    };
    let candidate = StoredCandidateIdentity {
        tls_private_key: None,
        pq_private_key: "candidate-pq".into(),
    };
    let promoted =
        compose_private_identity(active, candidate, false, true).expect("PQ-only rotation");
    assert_eq!(promoted.tls_private_key, "active-tls");
    assert_eq!(promoted.pq_private_key, "candidate-pq");
}

#[test]
fn promotion_refuses_a_tls_rotation_without_a_sealed_candidate_tls_key() {
    let active = StoredPrivateIdentity {
        tls_private_key: "active-tls".into(),
        pq_private_key: "active-pq".into(),
    };
    let candidate = StoredCandidateIdentity {
        tls_private_key: None,
        pq_private_key: "candidate-pq".into(),
    };

    let error = match compose_private_identity(active, candidate, true, false) {
        Ok(_) => panic!("a TLS transition cannot silently retain the outgoing key"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("candidate has no TLS private key"));
}

#[test]
fn a_fresh_start_uses_the_active_slot_when_no_candidate_is_recorded() {
    assert_eq!(
        select_served_identity_slot(false, None, None, None, false, false, 200)
            .expect("no transition means the active identity remains selected"),
        ServedIdentitySlot::Active
    );
}

#[test]
fn a_staged_identity_without_its_activation_or_retirement_is_rejected() {
    let missing_activation =
        select_served_identity_slot(false, Some(2), None, Some(300), true, false, 200)
            .expect_err("a staged identity needs an activation time");
    assert!(format!("{missing_activation:#}").contains("no activation_at"));

    let missing_retirement =
        select_served_identity_slot(false, Some(2), Some(200), None, true, false, 200)
            .expect_err("a staged identity needs a hard end to its overlap");
    assert!(format!("{missing_retirement:#}").contains("no retire_active_at"));
}

#[cfg(unix)]
#[test]
fn development_private_identity_requires_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    const CHILD: &str = "HELIOS_TEST_DEV_IDENTITY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().expect("temporary dev identity directory");
        let path = directory.path().join("dev-key.json");
        std::fs::write(
            &path,
            br#"{"tls_private_key":"dGxz","pq_private_key":"cHE="}"#,
        )
        .expect("write test key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("set private permissions");
        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable"),
        )
        .args([
            "--exact",
            "key_negotiation::tests::identity::development_private_identity_requires_owner_only_permissions",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("HELIOS_KEY_NEGO_DEV_KEY_DER", &path)
        .status()
        .expect("isolated dev identity test starts");
        assert!(status.success(), "isolated dev identity test must succeed");
        return;
    }

    let path = std::path::PathBuf::from(
        std::env::var_os("HELIOS_KEY_NEGO_DEV_KEY_DER").expect("child dev key path"),
    );
    let loaded = load_active_private_identity(None, true, GATEWAY_KEY)
        .expect("owner-only development key loads");
    assert_eq!(loaded.tls_private_key, "dGxz");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .expect("set group-readable permissions");
    let error = match load_active_private_identity(None, true, GATEWAY_KEY) {
        Ok(_) => panic!("a development private key must not be group-readable"),
        Err(error) => error,
    };

    assert!(format!("{error:#}").contains("expected 0600 or stricter"));
}
