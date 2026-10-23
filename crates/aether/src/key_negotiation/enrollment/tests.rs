use super::*;
use crate::certificates::encoding::{DerCertificate, Fingerprint, Id16, WireGuardKey};

const NOW: u64 = 10_000;

struct Operator {
    ca_private: zeroize::Zeroizing<Vec<u8>>,
    ca_public: MlDsa87PublicKey,
    proof_private: [u8; 32],
}

struct Client {
    wg_private: [u8; 32],
    ml_dsa_private: zeroize::Zeroizing<Vec<u8>>,
    request: EnrollmentRequest,
}

fn operator() -> Operator {
    let (ca_private, ca_public) = crate::ml_dsa::generate_keypair().expect("ca keys");
    let proof = crate::wg::generate_keypair().expect("proof keys");
    Operator {
        ca_private,
        ca_public: MlDsa87PublicKey::new(ca_public).expect("ca public"),
        proof_private: decode32(proof.private_key.expose()),
    }
}

fn decode32(value: &str) -> [u8; 32] {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(value)
        .expect("base64")
        .try_into()
        .expect("32 bytes")
}

fn public_of(private: &[u8; 32]) -> WireGuardKey {
    let secret = x25519_dalek::StaticSecret::from(*private);
    WireGuardKey::from_bytes(*x25519_dalek::PublicKey::from(&secret).as_bytes())
}

fn unsigned_invitation(operator: &Operator) -> EnrollmentInvitation {
    EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([1; 16]).expect("id"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
        server_name: "vpn.example.net".into(),
        operator_ca_public_key: operator.ca_public.clone(),
        wireguard_proof_public_key: public_of(&operator.proof_private),
        not_before_unix: NOW - 100,
        not_after_unix: NOW - 100 + MAX_INVITATION_LIFETIME_SECS,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission: false,
        operator_signature: MlDsa87Signature::placeholder(),
    }
}

fn invitation(operator: &Operator) -> EnrollmentInvitation {
    unsigned_invitation(operator)
        .sign(&operator.ca_private)
        .expect("signed invitation")
}

fn unsigned_request(invitation: &EnrollmentInvitation, name: &str) -> (Client, EnrollmentRequest) {
    let wg = crate::wg::generate_keypair().expect("wg keys");
    let wg_private = decode32(wg.private_key.expose());
    let (ml_dsa_private, ml_dsa_public) = crate::ml_dsa::generate_keypair().expect("ml-dsa");
    let csr = crate::certificates::x509::client_rotation_csr(name).expect("csr");
    let request = EnrollmentRequest {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: invitation.invitation_id,
        invitation_fingerprint: invitation.fingerprint(),
        request_id: Id16::new([9; 16]).expect("id"),
        timestamp_unix: NOW,
        requested_name: name.into(),
        client_wg_public_key: public_of(&wg_private),
        tls_csr: csr.csr,
        client_ml_dsa_87_public_key: MlDsa87PublicKey::new(ml_dsa_public).expect("public"),
        wireguard_proof: [0; 32],
        client_signature: MlDsa87Signature::placeholder(),
    };
    (
        Client {
            wg_private,
            ml_dsa_private,
            request: request.clone(),
        },
        request,
    )
}

fn request(invitation: &EnrollmentInvitation, name: &str) -> Client {
    let (mut client, mut request) = unsigned_request(invitation, name);
    request.wireguard_proof =
        wireguard_proof(&client.wg_private, invitation, &request).expect("proof");
    client.request = request
        .sign(&client.ml_dsa_private)
        .expect("signed request");
    client
}

#[test]
fn an_invitation_signs_and_verifies_under_its_ca() {
    let operator = operator();
    let invitation = invitation(&operator);
    invitation
        .verify(&operator.ca_public, NOW)
        .expect("verifies under its CA");
}

#[test]
fn an_invitation_verified_under_another_ca_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let other = self::operator();
    assert!(matches!(
        invitation.verify(&other.ca_public, NOW),
        Err(EnrollmentError::Signature)
    ));
}

#[test]
fn an_invitation_whose_embedded_ca_is_not_the_signer_is_refused() {
    let operator = operator();
    let other = self::operator();
    let mut forged = unsigned_invitation(&operator);
    forged.operator_ca_public_key = other.ca_public.clone();
    let forged = forged.sign(&operator.ca_private).expect("signed");
    assert!(matches!(
        forged.verify(&other.ca_public, NOW),
        Err(EnrollmentError::Signature)
    ));
}

#[test]
fn the_invitation_transcript_is_byte_exact() {
    let operator = operator();
    let mut invitation = unsigned_invitation(&operator);
    invitation.wireguard_proof_public_key = WireGuardKey::from_bytes([3; 32]);
    invitation.not_before_unix = 1_000;
    invitation.not_after_unix = 87_400;

    let mut expected = b"helios-key-negotiation-enrollment-invitation-v5".to_vec();
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&5u16.to_be_bytes());
    expected.extend_from_slice(&[1; 16]);
    expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&[4; 32]);
    expected.extend_from_slice(&15u32.to_be_bytes());
    expected.extend_from_slice(b"vpn.example.net");
    expected.extend_from_slice(&2592u32.to_be_bytes());
    expected.extend_from_slice(operator.ca_public.as_bytes());
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&1_000u64.to_be_bytes());
    expected.extend_from_slice(&87_400u64.to_be_bytes());
    expected.push(2);
    expected.push(0);

    assert_eq!(invitation.signed_bytes(), expected);
}

#[test]
fn the_fingerprint_covers_the_signature() {
    let operator = operator();
    let invitation = invitation(&operator);
    let mut input = invitation.signed_bytes();
    let signature = invitation.operator_signature.as_bytes();
    input.extend_from_slice(&u32::try_from(signature.len()).expect("len").to_be_bytes());
    input.extend_from_slice(signature);
    assert_eq!(invitation.fingerprint(), Fingerprint::of(&input));
}

#[test]
fn an_invitation_window_above_24_hours_is_refused() {
    let operator = operator();
    let mut invitation = unsigned_invitation(&operator);
    invitation.not_after_unix = invitation.not_before_unix + 86_401;
    assert!(matches!(
        invitation.validate(),
        Err(EnrollmentError::Window)
    ));
}

#[test]
fn an_empty_window_is_refused() {
    let operator = operator();
    let mut invitation = unsigned_invitation(&operator);
    invitation.not_after_unix = invitation.not_before_unix;
    assert!(matches!(
        invitation.validate(),
        Err(EnrollmentError::Window)
    ));
}

#[test]
fn an_expired_invitation_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    assert!(matches!(
        invitation.verify(&operator.ca_public, invitation.not_after_unix + 1),
        Err(EnrollmentError::Window)
    ));
}

#[test]
fn a_zero_invitation_id_is_refused() {
    let operator = operator();
    let text = encode_invitation_file(&invitation(&operator));
    let zeroed = text.replace(&"01".repeat(16), &"00".repeat(16));
    assert!(decode_invitation_file(&zeroed).is_err());
}

#[test]
fn an_invitation_below_ml_kem_is_refused() {
    let operator = operator();
    let mut invitation = unsigned_invitation(&operator);
    invitation.minimum_mode = ProtectionMode::StaticPsk;
    assert!(matches!(
        invitation.validate(),
        Err(EnrollmentError::Format(_))
    ));
}

#[test]
fn a_request_bound_to_its_invitation_verifies() {
    let operator = operator();
    let invitation = invitation(&operator);
    let client = request(&invitation, "laptop-alice");
    client
        .request
        .verify(&invitation)
        .expect("request verifies");
    verify_wireguard_proof(&operator.proof_private, &invitation, &client.request)
        .expect("proof verifies");
}

#[test]
fn a_request_naming_another_invitation_fingerprint_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let other = self::invitation(&operator);
    // Same fields, fresh hedged signature: a different fingerprint.
    assert_ne!(invitation.fingerprint(), other.fingerprint());
    let client = request(&other, "laptop-alice");
    assert!(matches!(
        client.request.verify(&invitation),
        Err(EnrollmentError::Binding(_))
    ));
}

#[test]
fn a_request_outside_the_invitation_window_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let (mut client, mut late) = unsigned_request(&invitation, "laptop-alice");
    late.timestamp_unix = invitation.not_after_unix + 1;
    late.wireguard_proof = wireguard_proof(&client.wg_private, &invitation, &late).expect("proof");
    client.request = late.sign(&client.ml_dsa_private).expect("signed");
    assert!(matches!(
        client.request.verify(&invitation),
        Err(EnrollmentError::Window)
    ));
}

#[test]
fn a_tampered_request_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let mut client = request(&invitation, "laptop-alice");
    client.request.timestamp_unix += 1;
    assert!(matches!(
        client.request.verify(&invitation),
        Err(EnrollmentError::Signature)
    ));
}

#[test]
fn a_non_nfc_or_long_name_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    for name in ["e\u{301}".to_owned(), "a".repeat(256), String::new()] {
        let (_, mut request) = unsigned_request(&invitation, "laptop");
        request.requested_name = name.clone();
        assert!(
            matches!(request.validate(), Err(EnrollmentError::Format(_))),
            "{name:?} must be refused"
        );
    }
    let (_, mut request) = unsigned_request(&invitation, "laptop");
    request.requested_name = "\u{e9}t\u{e9}".into();
    request.validate().expect("an NFC name is accepted");
}

#[test]
fn an_oversized_csr_is_refused() {
    assert!(DerCertificate::new(vec![0x30; MAX_ENROLLMENT_CSR_BYTES + 1]).is_err());
}

#[test]
fn a_csr_not_signed_by_its_key_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let (mut client, mut request) = unsigned_request(&invitation, "laptop-alice");
    let mut csr = request.tls_csr.as_bytes().to_vec();
    let last = csr.len() - 1;
    csr[last] ^= 0x01;
    request.tls_csr = DerCertificate::new(csr).expect("der");
    request.wireguard_proof =
        wireguard_proof(&client.wg_private, &invitation, &request).expect("proof");
    client.request = request.sign(&client.ml_dsa_private).expect("signed");
    assert!(matches!(
        client.request.verify(&invitation),
        Err(EnrollmentError::Csr)
    ));
}

#[test]
fn the_wireguard_proof_verifies_with_the_ephemeral_private_key() {
    let operator = operator();
    let invitation = invitation(&operator);
    let client = request(&invitation, "laptop-alice");
    verify_wireguard_proof(&operator.proof_private, &invitation, &client.request)
        .expect("proof verifies");
    let other = self::operator();
    assert!(matches!(
        verify_wireguard_proof(&other.proof_private, &invitation, &client.request),
        Err(EnrollmentError::Proof)
    ));
}

#[test]
fn a_proof_for_another_name_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let mut client = request(&invitation, "laptop-alice");
    client.request.requested_name = "laptop-mallory".into();
    assert!(matches!(
        verify_wireguard_proof(&operator.proof_private, &invitation, &client.request),
        Err(EnrollmentError::Proof)
    ));
}

#[test]
fn a_proof_from_a_key_that_is_not_the_requested_one_is_refused() {
    let operator = operator();
    let invitation = invitation(&operator);
    let (_, request) = unsigned_request(&invitation, "laptop-alice");
    let stranger = decode32(
        crate::wg::generate_keypair()
            .expect("wg")
            .private_key
            .expose(),
    );
    assert!(matches!(
        wireguard_proof(&stranger, &invitation, &request),
        Err(EnrollmentError::Binding(_))
    ));
}

#[test]
fn a_low_order_point_yields_zero_secret_and_is_refused() {
    let operator = operator();
    let mut invitation = unsigned_invitation(&operator);
    invitation.wireguard_proof_public_key = WireGuardKey::from_bytes([0; 32]);
    let (client, request) = unsigned_request(&invitation, "laptop-alice");
    assert!(matches!(
        wireguard_proof(&client.wg_private, &invitation, &request),
        Err(EnrollmentError::ZeroSharedSecret)
    ));
}

#[test]
fn invitation_and_request_files_round_trip_through_bom_and_unknown_fields() {
    let operator = operator();
    let invitation = invitation(&operator);
    let client = request(&invitation, "laptop-alice");

    let text = encode_invitation_file(&invitation);
    let decoded = decode_invitation_file(&format!("\u{feff}{text}")).expect("bom accepted");
    assert_eq!(decoded.fingerprint(), invitation.fingerprint());

    let text = encode_request_file(&client.request);
    let decoded = decode_request_file(&format!("\u{feff}{text}")).expect("bom accepted");
    assert_eq!(decoded.fingerprint(), client.request.fingerprint());

    let mut value: serde_json::Value =
        serde_json::from_str(&encode_invitation_file(&invitation)).expect("json");
    value["invitation"]["extra"] = serde_json::json!(true);
    assert!(decode_invitation_file(&value.to_string()).is_err());

    let mut value: serde_json::Value =
        serde_json::from_str(&encode_invitation_file(&invitation)).expect("json");
    value["format"] = serde_json::json!("helios-enrollment-request");
    assert!(decode_invitation_file(&value.to_string()).is_err());

    // A request file is not an invitation, even with a matching shape.
    assert!(decode_invitation_file(&encode_request_file(&client.request)).is_err());
}

#[test]
fn a_duplicated_member_is_refused() {
    let operator = operator();
    let text = encode_invitation_file(&invitation(&operator));
    let duplicated = text.replacen(
        "\"allow_readmission\":false",
        "\"allow_readmission\":false,\"allow_readmission\":true",
        1,
    );
    assert_ne!(duplicated, text, "the fixture must contain the member");
    assert!(decode_invitation_file(&duplicated).is_err());
}
