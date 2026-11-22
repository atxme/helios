use super::*;
use orion_core::gateway_admin::GatewayAdminError;

const GATEWAY: &str = "http://gateway.invalid";

fn assert_refused_before_gateway(domain: &Domain, terms: Resume<'_>, refusal: Refusal) -> String {
    let id = terms.invitation_id;
    let before = registry_snapshot(domain, &id);
    let (outcome, published, artifacts) = run_resume_of(
        domain,
        terms,
        &|_| panic!("local preflight must finish before reading the gateway"),
        &|_| panic!("local preflight must finish before checking admission"),
    );
    assert_eq!(
        published.last().expect("refused status").refusal,
        Some(refusal)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
    assert_eq!(registry_snapshot(domain, &id), before);
    outcome.expect_err("resumption is refused")
}

#[test]
fn a_blank_endpoint_refuses_resumption_before_any_gateway_read() {
    let domain = Domain::new("resume-empty-endpoint").with_ca_tls();
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let mut terms = resume_of(enrolment.invitation.invitation_id, Some(GATEWAY));
    terms.delivery.endpoint = " \t ";
    let error = assert_refused_before_gateway(&domain, terms, Refusal::ManifestMismatch);
    assert!(error.contains("adresse publique"));
}

#[test]
fn a_revoked_invitation_cannot_be_resumed() {
    let domain = Domain::new("resume-revoked").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let id = enrolment.invitation.invitation_id;
    domain.registry.revoke(&id, now_unix()).expect("revoke");
    let error = assert_refused_before_gateway(
        &domain,
        resume_of(id, Some(GATEWAY)),
        Refusal::InvitationExpired,
    );
    assert!(error.contains("révoquée"));
}

#[test]
fn a_corrupt_accepted_record_is_preserved_and_refused() {
    let domain = Domain::new("resume-corrupt-acceptance").with_ca_tls();
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let path = domain
        .registry
        .directory()
        .join(format!("{}.accepted.json", id.to_hex()));
    std::fs::write(path, b"{").expect("simulate an unreadable accepted record");
    let error =
        assert_refused_before_gateway(&domain, resume_of(id, Some(GATEWAY)), Refusal::Internal);
    assert!(error.contains("demande acceptée lisible"));
}

#[test]
fn a_missing_vault_stops_resumption_and_keeps_the_accepted_record() {
    let domain = Domain::new("resume-vault-missing").with_ca_tls();
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    std::fs::remove_file(&domain.vault_path).expect("remove fixture vault");
    assert_refused_before_gateway(
        &domain,
        resume_of(id, Some(GATEWAY)),
        Refusal::VaultUnavailable,
    );
}

#[test]
fn a_different_vault_cannot_resume_the_stored_acceptance() {
    let mut domain = Domain::new("resume-other-vault").with_ca_tls();
    let other = Domain::new("resume-unrelated-vault").with_ca_tls();
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    domain.vault_path = other.vault_path.clone();
    let error = assert_refused_before_gateway(
        &domain,
        resume_of(id, Some(GATEWAY)),
        Refusal::HandoffMismatch,
    );
    assert!(error.contains("CA-PQ de ce coffre"));
}

#[test]
fn a_gateway_refusal_hands_over_the_kept_leaves_without_requesting_a_key() {
    let domain = Domain::new("resume-gateway-refused").with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let before = registry_snapshot(&domain, &id);
    let (outcome, published, artifacts) = run_resume(
        &domain,
        id,
        Some(GATEWAY),
        &|base| {
            assert_eq!(base, GATEWAY);
            Err(GatewayAdminError::Forbidden)
        },
        &|_| panic!("admission cannot be checked without a verified gateway"),
    );
    assert!(outcome.expect_err("gateway refuses").contains("admin"));
    assert_eq!(
        published.last().expect("failed status").refusal,
        Some(Refusal::GatewayForbidden)
    );
    assert!(no_key_was_asked(&published));
    assert_eq!(artifacts.len(), 3);
    let tls = DerCertificate::parse(&artifacts[0].contents).expect("kept TLS leaf");
    assert_eq!(tls.as_bytes(), accepted.tls_certificate.as_bytes());
    assert_eq!(artifacts[2].file_name, "admission.txt");
    assert_eq!(registry_snapshot(&domain, &id), before);
}

#[test]
fn an_unavailable_admission_list_does_not_count_as_admission() {
    let domain = Domain::new("resume-unknown-admission").with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let before = registry_snapshot(&domain, &id);
    let terms = resume_of(id, Some(GATEWAY));
    let read = |base: &str| {
        assert_eq!(base, GATEWAY);
        answer(SERVER_NAME, &domain.gateway_key)
    };
    let checked = prepare_resumption(
        &domain.vault_path,
        &domain.registry,
        &terms,
        &read,
        &|base| {
            assert_eq!(base, GATEWAY);
            Err(GatewayAdminError::Unreachable)
        },
    )
    .expect("an unavailable list still allows preparing the resumption");
    assert!(!checked.admitted);
    assert!(checked.gateway_error.is_none());
    assert_eq!(
        checked.accepted.request.fingerprint(),
        accepted.request.fingerprint()
    );
    assert_eq!(registry_snapshot(&domain, &id), before);
}
