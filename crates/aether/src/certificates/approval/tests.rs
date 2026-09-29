use super::*;
use crate::certificates::encoding::generate_ml_dsa_87_keypair;
use crate::certificates::webauthn::test_credentials::Credential;
use aws_lc_rs::digest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

const RELYING_PARTY: &str = "astra.example";
const ORIGIN: &str = "https://astra.example";

struct Key {
    private: Zeroizing<Vec<u8>>,
    public: MlDsa87PublicKey,
}

fn key() -> Key {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    Key { private, public }
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([9; 16]).expect("domain")
}

fn gateway() -> WireGuardKey {
    WireGuardKey::from_bytes([2; 32])
}

fn client() -> WireGuardKey {
    WireGuardKey::from_bytes([3; 32])
}

fn policy() -> AstraIssuancePolicy {
    AstraIssuancePolicy {
        format_version: ISSUANCE_POLICY_FORMAT_VERSION,
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway(),
        server_name: "gateway.example".into(),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 90 * 86_400,
        maximum_stage_lease_secs: 3_600,
        maximum_overlap_secs: 7 * 86_400,
        renewal_start_percent: POLICY_RENEWAL_START_PERCENT,
        scheduled_renewal_credentials: AUTOMATIC_RENEWAL_CREDENTIALS,
        expired_recovery_credentials: 2,
        authority_mutation_credentials: AUTHORITY_MUTATION_CREDENTIALS,
    }
}

fn binding(ca: &Key, credential: &Credential, state: CredentialState) -> AstraCredentialBinding {
    AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: b"credential-one".to_vec(),
        credential_public_key: credential.cose_public_key(),
        aaguid: [0; 16],
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway(),
        state,
        credential_epoch: 1,
        credential_registry_epoch: 4,
        ca_epoch: 1,
        created_at: 1_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("sign")
}

fn request(service: &Key) -> AstraCredentialApprovalRequest {
    AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: Id16::new([5; 16]).expect("operation"),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway(),
        client_wg_public_key: client(),
        active_generation: 4,
        requested_generation: 5,
        credential_registry_epoch: 4,
        webauthn_rp_id: RELYING_PARTY.into(),
        webauthn_origin: ORIGIN.into(),
        allowed_credential_ids: vec![b"credential-one".to_vec()],
        required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
        created_at: 1_000,
        expires_at: 1_240,
        astra_service_key_epoch: 7,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service.private)
    .expect("sign")
}

fn assertion(credential: &Credential, challenge: &Fingerprint) -> WebAuthnAssertion {
    let mut authenticator_data = Fingerprint::of(RELYING_PARTY.as_bytes())
        .as_bytes()
        .to_vec();
    // User presence and user verification.
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&11u32.to_be_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge.as_bytes())
    )
    .into_bytes();
    let mut message = authenticator_data.clone();
    message.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
    WebAuthnAssertion {
        authenticator_data,
        client_data_json,
        signature: credential.sign(&message),
    }
}

/// The §7.5 family: what an operator's touch authorizes when an identity
/// has already expired.
mod expired_recovery {
    use super::*;

    fn evidence(
        ca: &Key,
        credential: &Credential,
        state: CredentialState,
        request_fingerprint: Fingerprint,
        challenge_bytes: [u8; 32],
    ) -> ExpiredRecoveryApprovalEvidence {
        let row = binding(ca, credential, state);
        let mut approval = ExpiredRecoveryApproval {
            request_fingerprint,
            astra_challenge: challenge_bytes,
            approved_at: 1_000,
            expires_at: 1_200,
            credential_id: row.credential_id.clone(),
            credential_fingerprint: row.fingerprint(),
            assertion_fingerprint: Fingerprint::from_bytes([0; 32]),
            webauthn_assertion: WebAuthnAssertion {
                authenticator_data: Vec::new(),
                client_data_json: Vec::new(),
                signature: Vec::new(),
            },
        };
        let signed = assertion(credential, &approval.challenge());
        approval.assertion_fingerprint = signed.fingerprint();
        approval.webauthn_assertion = signed;
        ExpiredRecoveryApprovalEvidence {
            approval,
            credential_registry: CredentialRegistry {
                trust_domain_id: domain(),
                gateway_wg_public_key: gateway(),
                ca_epoch: 1,
                credential_registry_epoch: 4,
                bindings: vec![row],
            },
            webauthn_origin: ORIGIN.into(),
        }
    }

    /// The happy path, and the shape of every refusal below: the caller
    /// supplies the request and the nonce, the document supplies neither.
    #[test]
    fn a_touch_authorizes_the_request_and_the_nonce_it_answered() {
        let ca = key();
        let credential = Credential::generate();
        let request = Fingerprint::of(b"recovery request");
        let challenge = [7u8; 32];
        let evidence = evidence(
            &ca,
            &credential,
            CredentialState::Active,
            request,
            challenge,
        );
        assert!(evidence
            .verify(
                &ca.public,
                &domain(),
                &gateway(),
                &request,
                &challenge,
                RELYING_PARTY,
                1,
                4,
                1_100,
            )
            .is_ok());

        // Another request, same touch: the challenge no longer recomputes.
        assert!(matches!(
            evidence.verify(
                &ca.public,
                &domain(),
                &gateway(),
                &Fingerprint::of(b"another request"),
                &challenge,
                RELYING_PARTY,
                1,
                4,
                1_100,
            ),
            Err(CertificateError::ApprovalMismatch(_))
        ));

        // Another nonce: same refusal, on the axis that stops a replay
        // against a challenge the authority has already consumed.
        assert!(matches!(
            evidence.verify(
                &ca.public,
                &domain(),
                &gateway(),
                &request,
                &[8u8; 32],
                RELYING_PARTY,
                1,
                4,
                1_100,
            ),
            Err(CertificateError::InvalidChallenge)
        ));
    }

    /// A recovery is the one operation that reaches past a validity
    /// period. A withdrawn credential must not be the thing that reaches.
    #[test]
    fn only_an_active_credential_revives_an_expired_identity() {
        let ca = key();
        let credential = Credential::generate();
        let request = Fingerprint::of(b"recovery request");
        let challenge = [7u8; 32];
        for state in [CredentialState::Lost, CredentialState::Revoked] {
            let evidence = evidence(&ca, &credential, state, request, challenge);
            assert!(matches!(
                evidence.verify(
                    &ca.public,
                    &domain(),
                    &gateway(),
                    &request,
                    &challenge,
                    RELYING_PARTY,
                    1,
                    4,
                    1_100,
                ),
                Err(CertificateError::UnknownCredential)
            ));
        }
    }

    /// The assertion answers a challenge derived here, so an approval that
    /// outlived its own window answers a challenge nobody recomputes.
    #[test]
    fn an_approval_past_its_window_is_refused() {
        let ca = key();
        let credential = Credential::generate();
        let request = Fingerprint::of(b"recovery request");
        let challenge = [7u8; 32];
        let evidence = evidence(
            &ca,
            &credential,
            CredentialState::Active,
            request,
            challenge,
        );
        assert!(matches!(
            evidence.verify(
                &ca.public,
                &domain(),
                &gateway(),
                &request,
                &challenge,
                RELYING_PARTY,
                1,
                4,
                1_200,
            ),
            Err(CertificateError::InvalidLease)
        ));
    }

    /// The origin travels with the evidence, so it must be admissible for
    /// the relying party the consumer already pins — never a supplied
    /// answer to a question the consumer asked.
    #[test]
    fn an_origin_outside_the_pinned_relying_party_is_refused() {
        let ca = key();
        let credential = Credential::generate();
        let request = Fingerprint::of(b"recovery request");
        let challenge = [7u8; 32];
        let mut evidence = evidence(
            &ca,
            &credential,
            CredentialState::Active,
            request,
            challenge,
        );
        evidence.webauthn_origin = "https://astra.example.evil".into();
        assert!(evidence
            .verify(
                &ca.public,
                &domain(),
                &gateway(),
                &request,
                &challenge,
                RELYING_PARTY,
                1,
                4,
                1_100,
            )
            .is_err());
    }

    /// Two of the three inputs to the challenge, moved one at a time. A
    /// derivation that dropped any of them would let one touch answer for
    /// a different request, a different nonce or a longer window.
    #[test]
    fn the_challenge_binds_the_request_the_nonce_and_the_deadline() {
        let base = ExpiredRecoveryApproval {
            request_fingerprint: Fingerprint::of(b"request"),
            astra_challenge: [1; 32],
            approved_at: 1_000,
            expires_at: 1_200,
            credential_id: b"credential-one".to_vec(),
            credential_fingerprint: Fingerprint::of(b"row"),
            assertion_fingerprint: Fingerprint::of(b"assertion"),
            webauthn_assertion: WebAuthnAssertion {
                authenticator_data: Vec::new(),
                client_data_json: Vec::new(),
                signature: Vec::new(),
            },
        };
        let reference = base.challenge();

        let mut moved = base.clone();
        moved.request_fingerprint = Fingerprint::of(b"other request");
        assert!(!moved.challenge().matches(&reference));

        let mut moved = base.clone();
        moved.astra_challenge = [2; 32];
        assert!(!moved.challenge().matches(&reference));

        let mut moved = base;
        moved.expires_at = 1_500;
        assert!(!moved.challenge().matches(&reference));
    }
}

fn approval(
    service: &Key,
    binding: &AstraCredentialBinding,
    request: &AstraCredentialApprovalRequest,
    assertion: WebAuthnAssertion,
) -> AstraRenewalApproval {
    AstraRenewalApproval {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: request.operation_id,
        request_fingerprint: request.request_fingerprint,
        approval_request_fingerprint: request.fingerprint(),
        credential_binding: binding.clone(),
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: assertion.fingerprint(),
        webauthn_assertion: assertion,
        approved_at: 1_050,
        expires_at: 1_240,
        astra_service_key_epoch: 7,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service.private)
    .expect("sign")
}

struct Fixture {
    ca: Key,
    service: Key,
    binding: AstraCredentialBinding,
    request: AstraCredentialApprovalRequest,
    approval: AstraRenewalApproval,
}

fn fixture() -> Fixture {
    let ca = key();
    let service = key();
    let credential = Credential::generate();
    let binding = binding(&ca, &credential, CredentialState::Active);
    let request = request(&service);
    let assertion = assertion(&credential, &request.challenge());
    let approval = approval(&service, &binding, &request, assertion);
    Fixture {
        ca,
        service,
        binding,
        request,
        approval,
    }
}

fn verify(fixture: &Fixture, approval: &AstraRenewalApproval) -> Result<(), CertificateError> {
    approval.verify(
        &fixture.request,
        &fixture.ca.public,
        &fixture.service.public,
        7,
        &domain(),
        1,
        4,
        1_100,
    )
}

#[test]
fn an_approval_bound_to_its_request_verifies_under_the_anchor_and_the_credential() {
    let fixture = fixture();
    fixture
        .request
        .verify(
            &fixture.service.public,
            7,
            &domain(),
            &gateway(),
            &client(),
            RELYING_PARTY,
            4,
            1_100,
        )
        .expect("request");
    verify(&fixture, &fixture.approval).expect("approval");
}

#[test]
fn astra_verifies_the_companion_evidence_before_adding_its_signature() {
    let fixture = fixture();
    let mut companion = fixture.approval.clone();
    companion.astra_signature = MlDsa87Signature::placeholder();

    companion
        .verify_operator_evidence(
            &fixture.request,
            &fixture.ca.public,
            7,
            &domain(),
            1,
            4,
            1_100,
        )
        .expect("the independent evidence is complete");
    assert!(matches!(
        verify(&fixture, &companion),
        Err(CertificateError::InvalidSignature)
    ));
    let countersigned = companion
        .sign(&fixture.service.private)
        .expect("countersign");
    verify(&fixture, &countersigned).expect("the completed approval verifies");
}

/// The refusal the amendment of 15 August 2026 exists for.
#[test]
fn an_approval_bound_to_another_request_hash_is_refused() {
    let fixture = fixture();
    let mut moved = fixture.approval.clone();
    moved.request_fingerprint = Fingerprint::of(b"another request");
    let moved = moved.sign(&fixture.service.private).expect("sign");
    assert!(matches!(
        verify(&fixture, &moved),
        Err(CertificateError::ApprovalMismatch("request fingerprint"))
    ));
}

/// A byte moved anywhere in the request moves the challenge, so the
/// assertion no longer answers it — even though Astra re-signed both.
#[test]
fn a_mutated_request_breaks_the_chain_that_the_assertion_answers() {
    let fixture = fixture();
    let mut altered = fixture.request.clone();
    altered.requested_generation = 6;
    let altered = altered.sign(&fixture.service.private).expect("sign");
    let mut approval = fixture.approval.clone();
    approval.request_fingerprint = altered.request_fingerprint;
    approval.approval_request_fingerprint = altered.fingerprint();
    let approval = approval.sign(&fixture.service.private).expect("sign");
    assert!(matches!(
        approval.verify(
            &altered,
            &fixture.ca.public,
            &fixture.service.public,
            7,
            &domain(),
            1,
            4,
            1_100
        ),
        Err(CertificateError::InvalidAssertion("challenge binding"))
    ));
}

#[test]
fn an_approval_by_a_credential_the_request_did_not_list_is_refused() {
    let fixture = fixture();
    let mut narrowed = fixture.request.clone();
    narrowed.allowed_credential_ids = vec![b"credential-two".to_vec()];
    let narrowed = narrowed.sign(&fixture.service.private).expect("sign");
    let mut approval = fixture.approval.clone();
    approval.request_fingerprint = narrowed.request_fingerprint;
    approval.approval_request_fingerprint = narrowed.fingerprint();
    let approval = approval.sign(&fixture.service.private).expect("sign");
    assert!(matches!(
        approval.verify(
            &narrowed,
            &fixture.ca.public,
            &fixture.service.public,
            7,
            &domain(),
            1,
            4,
            1_100
        ),
        Err(CertificateError::UnknownCredential)
    ));
}

/// Astra's own signature is not allowed to stand in for the anchor's.
#[test]
fn a_credential_binding_not_signed_by_ca_pq_is_refused() {
    let fixture = fixture();
    let impostor = key();
    let forged = fixture
        .binding
        .clone()
        .sign(&impostor.private)
        .expect("sign");
    let mut approval = fixture.approval.clone();
    approval.credential_fingerprint = forged.fingerprint();
    approval.credential_binding = forged;
    let approval = approval.sign(&fixture.service.private).expect("sign");
    assert!(matches!(
        verify(&fixture, &approval),
        Err(CertificateError::InvalidSignature)
    ));
}

#[test]
fn a_lost_or_revoked_credential_cannot_approve_a_renewal() {
    for (state, expected) in [
        (CredentialState::Lost, "lost"),
        (CredentialState::Revoked, "revoked"),
    ] {
        let ca = key();
        let service = key();
        let credential = Credential::generate();
        let binding = binding(&ca, &credential, state);
        let request = request(&service);
        let assertion = assertion(&credential, &request.challenge());
        let approval = approval(&service, &binding, &request, assertion);
        let outcome = approval.verify(
            &request,
            &ca.public,
            &service.public,
            7,
            &domain(),
            1,
            4,
            1_100,
        );
        match (state, outcome) {
            (CredentialState::Lost, Err(CertificateError::InvalidCredentialBinding("lost"))) => {}
            (CredentialState::Revoked, Err(CertificateError::Revoked)) => {}
            (_, other) => panic!("{expected} credential accepted: {other:?}"),
        }
    }
}

#[test]
fn a_credential_binding_at_a_rolled_back_registry_epoch_is_refused() {
    let fixture = fixture();
    assert!(matches!(
        fixture.binding.verify(
            &fixture.ca.public,
            &domain(),
            &gateway(),
            1,
            5, // the consumer has already seen epoch 5
        ),
        Err(CertificateError::GenerationRollback { .. })
    ));
}

/// `revoked` is terminal: a restored backup at a higher epoch does not
/// bring a token back.
#[test]
fn a_revocation_dominates_a_later_active_decision() {
    let ca = key();
    let credential = Credential::generate();
    let revoked = binding(&ca, &credential, CredentialState::Revoked);
    let mut restored = binding(&ca, &credential, CredentialState::Active);
    restored.credential_registry_epoch = 9;
    let restored = restored.sign(&ca.private).expect("sign");
    assert!(matches!(
        restored.supersedes(Some(&revoked)),
        Err(CertificateError::Revoked)
    ));
}

#[test]
fn a_registry_cannot_claim_an_epoch_its_signed_rows_do_not_carry() {
    let fixture = fixture();
    let mut registry = CredentialRegistry {
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway(),
        ca_epoch: 1,
        credential_registry_epoch: fixture.binding.credential_registry_epoch,
        bindings: vec![fixture.binding.clone()],
    };
    registry
        .verify(&fixture.ca.public, &domain(), &gateway(), 1, 4)
        .expect("one coherent snapshot");

    registry.credential_registry_epoch += 1;
    assert!(matches!(
        registry.verify(&fixture.ca.public, &domain(), &gateway(), 1, 4),
        Err(CertificateError::InvalidCredentialBinding(
            "mixed registry epochs"
        ))
    ));
}

#[test]
fn a_credential_counter_moves_exactly_with_its_decision_and_never_its_key() {
    let fixture = fixture();

    let mut changed_state = fixture.binding.clone();
    changed_state.state = CredentialState::Lost;
    changed_state.credential_registry_epoch += 1;
    let changed_state = changed_state.sign(&fixture.ca.private).expect("sign");
    assert!(matches!(
        changed_state.supersedes(Some(&fixture.binding)),
        Err(CertificateError::GenerationConflict { .. })
    ));

    let other_credential = Credential::generate();
    let mut changed_key = fixture.binding.clone();
    changed_key.credential_public_key = other_credential.cose_public_key();
    changed_key.credential_registry_epoch += 1;
    let changed_key = changed_key.sign(&fixture.ca.private).expect("sign");
    assert!(matches!(
        changed_key.supersedes(Some(&fixture.binding)),
        Err(CertificateError::InvalidCredentialBinding(
            "credential identity changed"
        ))
    ));
}

#[test]
fn an_approval_request_older_than_five_minutes_is_refused() {
    let service = key();
    let mut stretched = request(&service);
    stretched.expires_at = stretched.created_at + MAX_APPROVAL_LIFETIME_SECS + 1;
    let stretched = stretched.sign(&service.private).expect("sign");
    assert!(matches!(
        stretched.verify(
            &service.public,
            7,
            &domain(),
            &gateway(),
            &client(),
            RELYING_PARTY,
            4,
            1_100
        ),
        Err(CertificateError::InvalidLease)
    ));

    let expired = request(&service);
    assert!(matches!(
        expired.verify(
            &service.public,
            7,
            &domain(),
            &gateway(),
            &client(),
            RELYING_PARTY,
            4,
            1_240
        ),
        Err(CertificateError::StageExpired)
    ));
}

#[test]
fn an_approval_request_for_another_peer_relying_party_or_generation_is_refused() {
    let service = key();
    let request = request(&service);
    let checks: [(&str, Result<(), CertificateError>); 4] = [
        (
            "gateway",
            request.verify(
                &service.public,
                7,
                &domain(),
                &WireGuardKey::from_bytes([8; 32]),
                &client(),
                RELYING_PARTY,
                4,
                1_100,
            ),
        ),
        (
            "client",
            request.verify(
                &service.public,
                7,
                &domain(),
                &gateway(),
                &WireGuardKey::from_bytes([8; 32]),
                RELYING_PARTY,
                4,
                1_100,
            ),
        ),
        (
            "relying party",
            request.verify(
                &service.public,
                7,
                &domain(),
                &gateway(),
                &client(),
                "other.example",
                4,
                1_100,
            ),
        ),
        (
            "generation",
            request.verify(
                &service.public,
                7,
                &domain(),
                &gateway(),
                &client(),
                RELYING_PARTY,
                5,
                1_100,
            ),
        ),
    ];
    for (name, outcome) in checks {
        assert!(outcome.is_err(), "{name} mismatch accepted");
    }
}

#[test]
fn an_approval_outliving_its_request_is_refused() {
    let fixture = fixture();
    let mut stretched = fixture.approval.clone();
    stretched.expires_at = fixture.request.expires_at + 1;
    let stretched = stretched.sign(&fixture.service.private).expect("sign");
    assert!(matches!(
        verify(&fixture, &stretched),
        Err(CertificateError::InvalidLease)
    ));
}

#[test]
fn a_policy_fingerprint_is_zero_free_and_covers_every_ceiling() {
    let pin = policy().pin().expect("pin");
    for mutate in [
        (|policy: &mut AstraIssuancePolicy| policy.maximum_leaf_lifetime_secs += 1)
            as fn(&mut AstraIssuancePolicy),
        |policy| policy.maximum_stage_lease_secs += 1,
        |policy| policy.maximum_overlap_secs += 1,
        |policy| policy.expired_recovery_credentials = 1,
        |policy| policy.server_name = "other.example".into(),
        |policy| policy.gateway_wg_public_key = WireGuardKey::from_bytes([4; 32]),
    ] {
        let mut altered = policy();
        mutate(&mut altered);
        assert!(
            pin.assert_matches(&altered.fingerprint().expect("fingerprint"))
                .is_err(),
            "a changed ceiling produced the same pin"
        );
    }
    assert!(matches!(
        AstraPolicyPin::new(Fingerprint::from_bytes([0; 32])),
        Err(CertificateError::PolicyNotPinned)
    ));
}

#[test]
fn a_policy_outside_the_bounds_of_the_specification_has_no_fingerprint() {
    for mutate in [
        (|policy: &mut AstraIssuancePolicy| policy.maximum_stage_lease_secs = 86_401)
            as fn(&mut AstraIssuancePolicy),
        |policy| policy.maximum_overlap_secs = MAX_OVERLAP_SECS + 1,
        |policy| policy.expired_recovery_credentials = 3,
        |policy| policy.renewal_start_percent = 50,
        |policy| policy.scheduled_renewal_credentials = 1,
        |policy| policy.authority_mutation_credentials = 1,
        |policy| policy.maximum_leaf_lifetime_secs = 0,
    ] {
        let mut altered = policy();
        mutate(&mut altered);
        assert!(
            altered.fingerprint().is_err(),
            "out-of-bounds policy hashed"
        );
    }
}

/// §14.1: "délégation refusée quand `policy_fingerprint` diffère du pin
/// hors bande du profil, même sous une signature `CA-PQ` valide".
#[test]
fn a_delegation_carrying_another_policy_is_refused_under_a_valid_ca_pq_signature() {
    use crate::certificates::authority::AstraIssuerAuthorization;

    let ca = key();
    let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut widened = policy();
    widened.maximum_leaf_lifetime_secs = 10 * 365 * 86_400;
    let delegation = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway(),
        server_name: "gateway.example".into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer,
        tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
            "astra-issuer",
        ),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: widened.maximum_leaf_lifetime_secs,
        policy_fingerprint: widened.fingerprint().expect("fingerprint"),
        not_before: 1_000,
        not_after: 100_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("sign");

    // `CA-PQ` really did sign it.
    delegation
        .verify(
            &ca.public,
            &domain(),
            1,
            1,
            &gateway(),
            "gateway.example",
            2_000,
        )
        .expect("delegation");
    // And the pin still refuses it.
    let pin = policy().pin().expect("pin");
    assert!(matches!(
        pin.assert_authorizes(&delegation),
        Err(CertificateError::FingerprintMismatch(
            "Astra issuance policy"
        ))
    ));
}

/// The migration recognises exactly one legacy shape, and it is not the
/// current one: a fingerprint that collided would let the superseded
/// policy pass for the amended one.
#[test]
fn the_superseded_policy_is_not_the_current_policy() {
    let current = AstraIssuancePolicy::standard(domain(), gateway(), "gateway.example".into())
        .fingerprint()
        .expect("current");
    let superseded =
        superseded_per_request_policy_fingerprint(domain(), gateway(), "gateway.example")
            .expect("superseded");
    assert!(!current.matches(&superseded));
}

/// Signs a delegation naming `policy_fingerprint`, under `ca`.
fn delegation_naming(
    ca: &Key,
    policy_fingerprint: Fingerprint,
) -> crate::certificates::authority::AstraIssuerAuthorization {
    let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
    crate::certificates::authority::AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway(),
        server_name: "gateway.example".into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer,
        tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
            "astra-issuer",
        ),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 90 * 86_400,
        policy_fingerprint,
        not_before: 1_000,
        not_after: 100_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("sign")
}

/// The whole point of the migration: a domain pinned before the amendment
/// moves onto the current policy, and only on a delegation that names it.
#[test]
fn a_superseded_pin_adopts_the_current_policy_from_a_delegation_that_names_it() {
    let ca = key();
    let current = AstraIssuancePolicy::standard(domain(), gateway(), "gateway.example".into())
        .fingerprint()
        .expect("current");
    let superseded =
        superseded_per_request_policy_fingerprint(domain(), gateway(), "gateway.example")
            .expect("superseded");
    let pin = AstraPolicyPin::new(superseded).expect("pin");

    let adopted = pin
        .adopt_automatic_renewal_policy(
            domain(),
            gateway(),
            "gateway.example",
            &delegation_naming(&ca, current),
        )
        .expect("migration");
    let PolicyMigration::Adopted(moved) = adopted else {
        panic!("a superseded pin must move");
    };
    assert!(moved.fingerprint().matches(&current));
}

/// Running the migration twice must be a no-op rather than a second move,
/// so an interrupted operator can simply run it again.
#[test]
fn a_pin_already_on_the_current_policy_moves_nothing() {
    let ca = key();
    let current = AstraIssuancePolicy::standard(domain(), gateway(), "gateway.example".into())
        .fingerprint()
        .expect("current");
    let pin = AstraPolicyPin::new(current).expect("pin");
    assert_eq!(
        pin.adopt_automatic_renewal_policy(
            domain(),
            gateway(),
            "gateway.example",
            &delegation_naming(&ca, current),
        )
        .expect("migration"),
        PolicyMigration::AlreadyCurrent
    );
}

/// A `CA-PQ` signature says the document is genuine, never that its policy
/// is the one this domain is migrating to. A delegation naming a third
/// policy must leave the pin where it is.
#[test]
fn a_delegation_naming_a_third_policy_never_moves_a_superseded_pin() {
    let ca = key();
    let mut widened = AstraIssuancePolicy::standard(domain(), gateway(), "gateway.example".into());
    widened.maximum_leaf_lifetime_secs = 10 * 365 * 86_400;
    let superseded =
        superseded_per_request_policy_fingerprint(domain(), gateway(), "gateway.example")
            .expect("superseded");
    let pin = AstraPolicyPin::new(superseded).expect("pin");

    assert!(matches!(
        pin.adopt_automatic_renewal_policy(
            domain(),
            gateway(),
            "gateway.example",
            &delegation_naming(&ca, widened.fingerprint().expect("widened")),
        ),
        Err(CertificateError::FingerprintMismatch(_))
    ));
}

/// A pin this migration does not describe belongs to some other domain or
/// some other policy. Guessing at it is the silent broadening the
/// amendment forbids, so it is refused rather than overwritten.
#[test]
fn a_pin_that_is_neither_standard_is_left_alone() {
    let ca = key();
    let current = AstraIssuancePolicy::standard(domain(), gateway(), "gateway.example".into())
        .fingerprint()
        .expect("current");
    let pin = AstraPolicyPin::new(Fingerprint::of(b"some other domain")).expect("pin");

    assert!(matches!(
        pin.adopt_automatic_renewal_policy(
            domain(),
            gateway(),
            "gateway.example",
            &delegation_naming(&ca, current),
        ),
        Err(CertificateError::InvalidPolicy(_))
    ));
}

/// Approval values that cross a boundary, built from constant bytes only, and
/// the fingerprints they must keep.
///
/// The standard policy fingerprint is computed independently by Astra and by
/// Helios at bootstrap, shown to the operator, confirmed out of band and
/// carried by enrolment documents. The credential-binding fingerprint and the
/// approval request's WebAuthn challenge are what a security key and the
/// anchor sign over. Refactoring these types — splitting this module included
/// — must not move a byte of any of them, and no other test would notice: they
/// all compare two values computed by the same code. A change here is a
/// wire-format change and needs new domains, not new constants.
#[test]
fn the_approval_fingerprints_are_pinned() {
    let domain = TrustDomainId::new([1; 16]).expect("domain");
    let gateway = WireGuardKey::from_bytes([2; 32]);

    let policy = AstraIssuancePolicy::standard(domain, gateway, "gateway.example".into());
    let binding = AstraCredentialBinding {
        format_version: ISSUANCE_POLICY_FORMAT_VERSION,
        credential_id: vec![3; 16],
        credential_public_key: vec![4; 77],
        aaguid: [5; 16],
        trust_domain_id: domain,
        gateway_wg_public_key: gateway,
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 1_000,
        ca_pq_signature: MlDsa87Signature::new(vec![
            6;
            crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN
        ])
        .expect("signature"),
    };
    let request = AstraCredentialApprovalRequest {
        format_version: ISSUANCE_POLICY_FORMAT_VERSION,
        operation_id: Id16::new([7; 16]).expect("id"),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        trust_domain_id: domain,
        gateway_wg_public_key: gateway,
        client_wg_public_key: WireGuardKey::from_bytes([8; 32]),
        active_generation: 1,
        requested_generation: 2,
        credential_registry_epoch: 1,
        webauthn_rp_id: "astra.example".into(),
        webauthn_origin: "https://astra.example".into(),
        allowed_credential_ids: vec![vec![3; 16]],
        required_credentials: 1,
        created_at: 1_000,
        expires_at: 1_300,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::new(vec![
            9;
            crate::key_negotiation::ML_DSA_87_SIGNATURE_LEN
        ])
        .expect("signature"),
    };

    assert_eq!(
        [
            policy
                .fingerprint()
                .expect("the standard policy is valid")
                .to_hex(),
            binding.fingerprint().to_hex(),
            request.challenge().to_hex(),
            request.fingerprint().to_hex(),
        ],
        [
            "7c5b4fc1e3f62d2c6bbcbf5ae3676ce0d6c054be6fc84ceb933cfc3e888c9225",
            "e71513de77fdbb2214b795c41747d2771d172530f3999496acbe157db93517ca",
            "4b4927c7aeef9b37e4cbc3286d96e3c361e967153066012c0dcffd3ac5ce4151",
            "a267325005a3a02fc76559d4f4d31c039e11b4d9b24a508a779c5afc05a0e3f4",
        ]
    );
}
