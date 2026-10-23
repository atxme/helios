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

    discard_enrollment(&reopened, &pending.request_id).expect("discard");
    assert!(pending_enrollments(&reopened).expect("list").is_empty());
}
