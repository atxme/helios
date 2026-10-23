use super::*;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey,
};
use aether::key_negotiation::{
    encode_invitation_file, encode_request_file, verify_wireguard_proof, ProtectionMode,
    ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use base64::engine::general_purpose::STANDARD;

pub(crate) const NOW: u64 = 1_800_000_000;

pub(crate) struct Operator {
    pub(crate) ca_private: Zeroizing<Vec<u8>>,
    pub(crate) ca_public: MlDsa87PublicKey,
    pub(crate) proof_private: [u8; 32],
}

pub(crate) fn operator() -> Operator {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("ca");
    let proof = aether::wg::generate_keypair().expect("proof");
    Operator {
        ca_private,
        ca_public,
        proof_private: STANDARD
            .decode(proof.private_key.expose())
            .expect("base64")
            .try_into()
            .expect("32 bytes"),
    }
}

pub(crate) fn unsigned_invitation(operator: &Operator) -> EnrollmentInvitation {
    let secret = x25519_dalek::StaticSecret::from(operator.proof_private);
    EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([1; 16]).expect("id"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
        server_name: "vpn.example.net".into(),
        operator_ca_public_key: operator.ca_public.clone(),
        wireguard_proof_public_key: WireGuardKey::from_bytes(
            *x25519_dalek::PublicKey::from(&secret).as_bytes(),
        ),
        not_before_unix: NOW - 60,
        not_after_unix: NOW + 3_600,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission: false,
        operator_signature: MlDsa87Signature::placeholder(),
    }
}

pub(crate) fn invitation(operator: &Operator) -> EnrollmentInvitation {
    unsigned_invitation(operator)
        .sign(&operator.ca_private)
        .expect("signed")
}

pub(crate) fn fingerprint_of(operator: &Operator) -> String {
    operator.ca_public.authority_fingerprint().to_hex()
}

#[test]
fn a_wrong_confirmation_generates_nothing() {
    let operator = operator();
    let invitation = invitation(&operator);
    let other = self::operator();
    assert!(prepare_request(&invitation, &fingerprint_of(&other), "laptop-alice", NOW).is_err());

    let directory = tempfile::tempdir().expect("tempdir");
    let store = ProtectedIdentityStore::at(directory.path().join("identities"));
    assert!(begin_enrollment(
        &store,
        &invitation,
        &fingerprint_of(&other),
        "laptop-alice",
        NOW
    )
    .is_err());
    assert!(!directory.path().join("identities").exists());
}

#[test]
fn the_confirmation_tolerates_spaces_and_case() {
    let operator = operator();
    let invitation = invitation(&operator);
    let typed = format_fingerprint(&operator.ca_public.authority_fingerprint()).to_uppercase();
    assert!(typed.contains(' '));
    prepare_request(&invitation, &typed, "laptop-alice", NOW).expect("accepted");
}

#[test]
fn an_invitation_signed_by_another_key_than_its_ca_is_refused() {
    let operator = operator();
    let forger = self::operator();
    let forged = unsigned_invitation(&operator)
        .sign(&forger.ca_private)
        .expect("signed by another key");
    assert!(prepare_request(&forged, &fingerprint_of(&operator), "laptop-alice", NOW).is_err());
}

#[test]
fn an_expired_invitation_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    assert!(prepare_request(
        &invitation,
        &fingerprint_of(&operator),
        "laptop-alice",
        invitation.not_after_unix + 1
    )
    .is_err());
}

#[test]
fn a_prepared_request_verifies_and_proves_its_keys() {
    let operator = operator();
    let invitation = invitation(&operator);
    let pending =
        prepare_request(&invitation, &fingerprint_of(&operator), "laptop-alice", NOW).expect("ok");
    pending
        .request
        .verify(&invitation)
        .expect("request verifies");
    verify_wireguard_proof(&operator.proof_private, &invitation, &pending.request)
        .expect("WireGuard proof verifies");
    assert_eq!(
        aether::wg::public_from_private(pending.wg_private_key.expose()).expect("public"),
        pending.request.client_wg_public_key.to_base64()
    );
    assert_eq!(
        aether::certificates::encoding::derive_ml_dsa_87_public_key(&pending.ml_dsa_private_key)
            .expect("public"),
        pending.request.client_ml_dsa_87_public_key
    );
    assert_eq!(pending.request.requested_name, "laptop-alice");
}

#[test]
fn the_request_file_carries_no_private_material() {
    let operator = operator();
    let invitation = invitation(&operator);
    let pending =
        prepare_request(&invitation, &fingerprint_of(&operator), "laptop-alice", NOW).expect("ok");
    let text = encode_request_file(&pending.request);
    assert!(!text.contains(pending.wg_private_key.expose()));
    assert!(!text.contains(&STANDARD.encode(pending.tls_private_key_der.as_slice())));
    assert!(!text.contains(&STANDARD.encode(pending.ml_dsa_private_key.as_slice())));
}

#[test]
fn a_pending_record_round_trips_and_never_debugs_a_key() {
    let operator = operator();
    let invitation = invitation(&operator);
    let pending =
        prepare_request(&invitation, &fingerprint_of(&operator), "laptop-alice", NOW).expect("ok");
    let encoded = pending.encode().expect("encode");
    let decoded = PendingSecrets::decode(&encoded).expect("decode");
    assert_eq!(decoded.request, pending.request);
    assert_eq!(decoded.invitation, pending.invitation);
    assert_eq!(
        decoded.wg_private_key.expose(),
        pending.wg_private_key.expose()
    );
    assert_eq!(decoded.tls_private_key_der, pending.tls_private_key_der);
    assert_eq!(decoded.ml_dsa_private_key, pending.ml_dsa_private_key);

    let debug = format!("{pending:?}");
    assert!(!debug.contains(pending.wg_private_key.expose()));
    assert!(!debug.contains(&STANDARD.encode(pending.ml_dsa_private_key.as_slice())));
}

#[test]
fn preview_reads_a_bom_or_utf16_invitation() {
    let operator = operator();
    let invitation = invitation(&operator);
    let text = encode_invitation_file(&invitation);

    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(text.as_bytes());
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    for bytes in [text.as_bytes().to_vec(), bom, utf16] {
        let preview = preview_invitation(&bytes, NOW).expect("preview");
        assert_eq!(preview.server_name, "vpn.example.net");
        assert_eq!(preview.expires_at_unix, invitation.not_after_unix);
        assert_eq!(
            preview.ca_fingerprint,
            format_fingerprint(&operator.ca_public.authority_fingerprint())
        );
    }
    assert!(preview_invitation(b"{\"format\":\"orion-profile\"}", NOW).is_err());
}

#[cfg(not(windows))]
#[test]
fn the_request_is_not_produced_when_sealing_is_unavailable() {
    let operator = operator();
    let invitation = invitation(&operator);
    let directory = tempfile::tempdir().expect("tempdir");
    let store = ProtectedIdentityStore::at(directory.path().join("identities"));
    let error = begin_enrollment(
        &store,
        &invitation,
        &fingerprint_of(&operator),
        "laptop-alice",
        NOW,
    )
    .expect_err("no protected store on this platform");
    assert!(error
        .downcast_ref::<crate::IdentityStoreError>()
        .is_some_and(|e| matches!(e, crate::IdentityStoreError::UnsupportedPlatform)));
    assert!(pending_enrollments(&store).expect("list").is_empty());
}

#[cfg(windows)]
#[test]
fn a_pending_enrollment_survives_reopening_the_store_and_can_be_discarded() {
    let operator = operator();
    let invitation = invitation(&operator);
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("identities");
    let (pending, request_text) = begin_enrollment(
        &ProtectedIdentityStore::at(path.clone()),
        &invitation,
        &fingerprint_of(&operator),
        "laptop-alice",
        NOW,
    )
    .expect("begun");
    let request = aether::key_negotiation::decode_request_file(&request_text).expect("request");
    assert_eq!(request.request_id, pending.request_id);

    let reopened = ProtectedIdentityStore::at(path);
    let listed = pending_enrollments(&reopened).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].request_id, pending.request_id);
    let secrets = open_pending(&reopened, &pending.request_id).expect("open");
    assert_eq!(secrets.request, request);

    discard_enrollment(&reopened, &pending.request_id).expect("discard");
    assert!(pending_enrollments(&reopened).expect("list").is_empty());
}

// ─── Completion of a signed v5 document ─────────────────────────────────────

#[cfg(feature = "certificate-signing")]
mod completion {
    use super::*;
    use crate::profile_import::parse_profile_import;
    use crate::test_domain::{self, gateway_key, Domain, SERVER_NAME};
    use aether::certificates::encoding::DerCertificate;
    use aether::key_negotiation::{
        issue_pq_certificate, EnrollmentDocument, PqCertificate, PqCertificateRole,
        ENROLLMENT_DOCUMENT_FORMAT, ENROLLMENT_DOCUMENT_VERSION, PQ_CERTIFICATE_VERSION,
    };

    /// The profile is validated at import against the real clock, so the
    /// fixture's leaves are issued around it rather than around
    /// [`test_domain::NOW`].
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    pub(crate) struct Enrolled {
        pub(crate) domain: Domain,
        pub(crate) pending: PendingSecrets,
        pub(crate) document: EnrollmentDocument,
    }

    fn client_tls_leaf(domain: &Domain, csr: &DerCertificate) -> DerCertificate {
        let mut request =
            rcgen::CertificateSigningRequestParams::from_der(&csr.as_bytes().into()).expect("csr");
        request.params.not_before = test_domain::seconds_since_epoch(now() - 60);
        request.params.not_after = test_domain::seconds_since_epoch(now() + 365 * 86_400);
        request.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let issuer = rcgen::Issuer::from_ca_cert_der(domain.tls_ca.der(), &domain.tls_ca_key)
            .expect("issuer");
        DerCertificate::new(request.signed_by(&issuer).expect("leaf").der().to_vec()).expect("der")
    }

    fn client_pq_leaf(domain: &Domain, request: &EnrollmentRequest) -> PqCertificate {
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [5; 16],
                subject: request.requested_name.clone(),
                issuer: "helios-ca-pq".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: request.client_wg_public_key.to_base64(),
                ml_dsa_87_public_key: request.client_ml_dsa_87_public_key.to_base64(),
                not_before_unix: now() - 60,
                not_after_unix: now() + 365 * 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &domain.ca_pq_private,
        )
        .expect("client leaf")
    }

    pub(crate) fn profile_value(domain: &Domain) -> serde_json::Value {
        let mut settings = serde_json::to_value(test_domain::settings(domain)).expect("settings");
        settings.as_object_mut().expect("object").remove("identity");
        serde_json::json!({
            "name": "poste-windows",
            "type": "helios_key_negotiation",
            "endpoint": "gateway.example:51820",
            "peer_public_key": gateway_key().to_base64(),
            "address": "100.64.1.2/32",
            "key_negotiation": settings,
        })
    }

    pub(crate) fn sign(domain: &Domain, mut document: EnrollmentDocument) -> EnrollmentDocument {
        document.operator_signature = None;
        document.sign(&domain.ca_pq_private).expect("signed")
    }

    /// The test domain, its gateway leaf reissued around the real clock.
    fn current_domain() -> Domain {
        let mut domain = test_domain::domain();
        let mut gateway = domain.gateway_leaf.clone();
        gateway.not_before_unix = now() - 3_600;
        gateway.not_after_unix = now() + 10 * 86_400;
        gateway.ml_dsa_87_signature.clear();
        domain.gateway_leaf =
            issue_pq_certificate(gateway, &domain.ca_pq_private).expect("gateway leaf");
        domain
    }

    pub(crate) fn invitation_for(domain: &Domain) -> EnrollmentInvitation {
        let secret = x25519_dalek::StaticSecret::from(super::operator().proof_private);
        EnrollmentInvitation {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: Id16::new([3; 16]).expect("id"),
            gateway_wg_public_key: gateway_key(),
            gateway_certificate_fingerprint:
                aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                    .expect("fingerprint"),
            server_name: SERVER_NAME.into(),
            operator_ca_public_key: domain.ca_pq_public.clone(),
            wireguard_proof_public_key: WireGuardKey::from_bytes(
                *x25519_dalek::PublicKey::from(&secret).as_bytes(),
            ),
            not_before_unix: now() - 60,
            not_after_unix: now() + 3_600,
            minimum_mode: ProtectionMode::MlKem,
            allow_readmission: false,
            operator_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&domain.ca_pq_private)
        .expect("invitation")
    }

    /// The document the operator signs in answer to `request`.
    pub(crate) fn document_for(
        domain: &Domain,
        invitation: &EnrollmentInvitation,
        request: &EnrollmentRequest,
    ) -> EnrollmentDocument {
        let tls = client_tls_leaf(domain, &request.tls_csr);
        let pq = client_pq_leaf(domain, request);
        let serde_json::Value::Object(profile) = profile_value(domain) else {
            panic!("object");
        };
        sign(
            domain,
            EnrollmentDocument {
                format: ENROLLMENT_DOCUMENT_FORMAT.into(),
                format_version: ENROLLMENT_DOCUMENT_VERSION,
                invitation_id: invitation.invitation_id,
                request_id: request.request_id,
                request_fingerprint: request.fingerprint(),
                operator_ca_fingerprint: domain.ca_pq_public.authority_fingerprint(),
                issued_at_unix: now(),
                profile,
                client_tls_certificate: tls,
                client_pq_certificate: STANDARD.encode(serde_json::to_vec(&pq).expect("json")),
                operator_signature: None,
            },
        )
    }

    pub(crate) fn enrolled() -> Enrolled {
        let domain = current_domain();
        let invitation = invitation_for(&domain);
        let fingerprint = domain.ca_pq_public.authority_fingerprint().to_hex();
        let pending =
            prepare_request(&invitation, &fingerprint, "poste-windows", now()).expect("pending");
        let document = document_for(&domain, &invitation, &pending.request);
        Enrolled {
            domain,
            pending,
            document,
        }
    }

    fn profile_of(document: &EnrollmentDocument) -> crate::ClientProfile {
        parse_profile_import(&document.to_json().expect("json"), "poste.orion")
            .expect("parsed")
            .profile
    }

    fn matched(enrolled: &Enrolled, document: &EnrollmentDocument) -> Result<DocumentMatch> {
        match_document(
            Some(&enrolled.pending),
            document,
            profile_of(document),
            now(),
        )
    }

    /// Import then match, as Orion runs them: a refusal at either step keeps
    /// the document from being sealed.
    fn imported_and_matched(
        enrolled: &Enrolled,
        document: &EnrollmentDocument,
    ) -> Result<DocumentMatch> {
        let imported = parse_profile_import(&document.to_json()?, "poste.orion")?;
        match_document(Some(&enrolled.pending), document, imported.profile, now())
    }

    #[test]
    fn a_v5_document_parses_without_identity_or_private_key() {
        let enrolled = enrolled();
        let imported =
            parse_profile_import(&enrolled.document.to_json().expect("json"), "poste.orion")
                .expect("parsed");
        let enrollment = imported.enrollment.expect("a v5 document");
        assert_eq!(enrollment.request_id, enrolled.pending.request.request_id);
        assert!(imported.profile.private_key.is_empty());
        assert_eq!(
            imported.profile.key_negotiation.expect("block").identity,
            identity_name(&enrolled.pending.request.request_id)
        );
    }

    #[test]
    fn a_v5_profile_carrying_a_private_key_or_an_identity_is_refused() {
        let enrolled = enrolled();
        for (pointer, value) in [
            (
                "/private_key",
                serde_json::json!(WireGuardKey::from_bytes([9; 32]).to_base64()),
            ),
            ("/key_negotiation/identity", serde_json::json!("poste")),
            ("/key_negotiation_identity", serde_json::json!({})),
        ] {
            let mut profile = profile_value(&enrolled.domain);
            let (parent, field) = pointer.rsplit_once('/').expect("pointer");
            profile
                .pointer_mut(if parent.is_empty() { "" } else { parent })
                .and_then(serde_json::Value::as_object_mut)
                .expect("parent")
                .insert(field.into(), value);
            let serde_json::Value::Object(profile) = profile else {
                panic!("object");
            };
            let mut document = enrolled.document.clone();
            document.profile = profile;
            let document = sign(&enrolled.domain, document);
            assert!(
                parse_profile_import(&document.to_json().expect("json"), "poste.orion").is_err(),
                "{pointer} must be refused"
            );
        }
    }

    #[test]
    fn a_matching_document_yields_the_identity_and_the_wireguard_key() {
        let enrolled = enrolled();
        let DocumentMatch::Matched { profile, bundle } =
            matched(&enrolled, &enrolled.document).expect("matched")
        else {
            panic!("expected a match");
        };
        assert_eq!(
            profile.private_key.expose(),
            enrolled.pending.wg_private_key.expose()
        );
        let name = identity_name(&enrolled.pending.request.request_id);
        assert_eq!(bundle.identity, name);
        assert_eq!(profile.key_negotiation.expect("block").identity, name);
        assert_eq!(
            bundle.certificate_chain,
            vec![enrolled.document.client_tls_certificate.to_base64()]
        );
        assert_eq!(
            bundle.pq_certificate,
            enrolled.document.client_pq_certificate
        );
        bundle.validate().expect("a sealable bundle");
    }

    #[test]
    fn a_v5_document_without_pending_request_is_an_unmatched_draft() {
        let enrolled = enrolled();
        let outcome = match_document(
            None,
            &enrolled.document,
            profile_of(&enrolled.document),
            now(),
        )
        .expect("a draft, not an error");
        let DocumentMatch::Unmatched { profile, expected } = outcome else {
            panic!("expected no match");
        };
        assert!(profile.private_key.is_empty());
        assert!(
            expected.contains(&enrolled.pending.request.client_wg_public_key.to_base64()),
            "{expected}"
        );
    }

    #[test]
    fn a_v5_document_under_an_unpinned_ca_is_refused() {
        let enrolled = enrolled();
        let (other_private, other_public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("other");
        let mut document = enrolled.document.clone();
        document.operator_signature = None;
        document.operator_ca_fingerprint = other_public.authority_fingerprint();
        let document = document.sign(&other_private).expect("signed by another CA");
        assert!(matched(&enrolled, &document).is_err());
    }

    #[test]
    fn a_tampered_document_is_refused() {
        let enrolled = enrolled();
        let mut document = enrolled.document.clone();
        document
            .profile
            .insert("address".into(), serde_json::json!("100.64.1.99/32"));
        assert!(matched(&enrolled, &document).is_err());
    }

    #[test]
    fn a_document_for_another_request_is_refused() {
        let enrolled = enrolled();
        let mut document = enrolled.document.clone();
        document.request_fingerprint = Fingerprint::from_bytes([8; 32]);
        let document = sign(&enrolled.domain, document);
        assert!(matched(&enrolled, &document).is_err());
    }

    #[test]
    fn leaves_that_do_not_certify_the_local_keys_are_refused() {
        let enrolled = enrolled();
        let mut document = enrolled.document.clone();
        document.client_tls_certificate = enrolled.domain.active_client_tls.clone();
        let document = sign(&enrolled.domain, document);
        assert!(matched(&enrolled, &document).is_err());

        let mut document = enrolled.document.clone();
        document.client_pq_certificate =
            STANDARD.encode(serde_json::to_vec(&enrolled.domain.active_client_leaf).expect("json"));
        let document = sign(&enrolled.domain, document);
        assert!(matched(&enrolled, &document).is_err());
    }

    #[test]
    fn a_v5_document_naming_another_gateway_key_is_refused_before_sealing() {
        let enrolled = enrolled();
        // A coherent profile for another gateway under the same CA: it
        // imports, and only the invitation says it is not the one confirmed.
        let other_key = WireGuardKey::from_bytes([0x44; 32]);
        let mut gateway = enrolled.domain.gateway_leaf.clone();
        gateway.wireguard_public_key = other_key.to_base64();
        gateway.ml_dsa_87_signature.clear();
        let gateway = issue_pq_certificate(gateway, &enrolled.domain.ca_pq_private).expect("leaf");
        let mut document = enrolled.document.clone();
        document.profile.insert(
            "peer_public_key".into(),
            serde_json::json!(other_key.to_base64()),
        );
        document.profile["key_negotiation"]["gateway_pq_certificate"] =
            serde_json::json!(STANDARD.encode(serde_json::to_vec(&gateway).expect("json")));
        let document = sign(&enrolled.domain, document);
        let error = format!("{:#}", matched(&enrolled, &document).expect_err("refused"));
        assert!(error.contains(&gateway_key().to_base64()), "{error}");
        assert!(error.contains(&other_key.to_base64()), "{error}");
    }

    #[test]
    fn a_v5_document_naming_another_gateway_leaf_is_refused_before_sealing() {
        let enrolled = enrolled();
        let mut gateway = enrolled.domain.gateway_leaf.clone();
        gateway.serial = [6; 16];
        gateway.ml_dsa_87_signature.clear();
        let gateway = issue_pq_certificate(gateway, &enrolled.domain.ca_pq_private).expect("leaf");
        let mut document = enrolled.document.clone();
        document.profile["key_negotiation"]["gateway_pq_certificate"] =
            serde_json::json!(STANDARD.encode(serde_json::to_vec(&gateway).expect("json")));
        let document = sign(&enrolled.domain, document);
        assert!(matched(&enrolled, &document).is_err());
    }

    #[test]
    fn a_trust_block_naming_another_ca_is_refused() {
        let enrolled = enrolled();
        let (_, other) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("other");
        let mut document = enrolled.document.clone();
        document.profile["key_negotiation"]["trust"]["ca_pq_public_key"] =
            serde_json::json!(other.to_base64());
        let document = sign(&enrolled.domain, document);
        assert!(imported_and_matched(&enrolled, &document).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn completion_without_a_protected_store_leaves_an_unmatched_draft() {
        let enrolled = enrolled();
        let directory = tempfile::tempdir().expect("tempdir");
        let store = ProtectedIdentityStore::at(directory.path().join("identities"));
        let outcome = complete_enrollment(
            &store,
            &enrolled.document,
            profile_of(&enrolled.document),
            now(),
        )
        .expect("a draft");
        assert!(matches!(outcome, EnrollmentOutcome::Unmatched { .. }));
        assert!(!directory.path().join("identities").exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_signed_document_completes_the_pending_enrollment_it_answers() {
        let domain = current_domain();
        let invitation = invitation_for(&domain);
        let directory = tempfile::tempdir().expect("tempdir");
        let store = ProtectedIdentityStore::at(directory.path().join("identities"));
        let fingerprint = domain.ca_pq_public.authority_fingerprint().to_hex();
        let (pending, request_text) =
            begin_enrollment(&store, &invitation, &fingerprint, "poste-windows", now())
                .expect("begun");
        let request = aether::key_negotiation::decode_request_file(&request_text).expect("request");
        let document = document_for(&domain, &invitation, &request);

        let EnrollmentOutcome::Completed { profile } =
            complete_enrollment(&store, &document, profile_of(&document), now())
                .expect("completed")
        else {
            panic!("expected a completion");
        };
        assert!(!profile.private_key.is_empty());
        let name = identity_name(&pending.request_id);
        assert_eq!(profile.key_negotiation.expect("block").identity, name);
        assert_eq!(store.load(&name).expect("sealed").identity, name);
        assert!(pending_enrollments(&store).expect("list").is_empty());
    }
}
