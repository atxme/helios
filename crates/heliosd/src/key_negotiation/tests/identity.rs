//! Served identity: bootstrap certificate, restart selection and promotion.

use super::super::*;
use super::fixtures::*;

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
