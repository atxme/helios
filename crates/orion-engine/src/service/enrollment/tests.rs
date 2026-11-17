use super::*;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, WireGuardKey,
};
use aether::key_negotiation::{
    decode_invitation_file, encode_invitation_file, EnrollmentInvitation, ProtectionMode,
    ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};

const EXPIRES_AT: u64 = 1_800_000_000;

pub(in crate::service) fn signed_invitation(expires_at: u64) -> EnrollmentInvitation {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("operator CA key pair");
    EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([1; 16]).expect("nonzero invitation ID"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        gateway_certificate_fingerprint: Fingerprint::from_bytes([3; 32]),
        server_name: "vpn.example.net".into(),
        operator_ca_public_key: ca_public,
        wireguard_proof_public_key: WireGuardKey::from_bytes([4; 32]),
        not_before_unix: expires_at - 3_600,
        not_after_unix: expires_at,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission: false,
        operator_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("signed invitation")
}

#[test]
fn preview_serializes_the_confirmation_fields_and_preserves_the_signed_invitation() {
    let invitation = signed_invitation(EXPIRES_AT);
    let invitation_text = encode_invitation_file(&invitation);
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(invitation_text.encode_utf16().flat_map(u16::to_le_bytes));

    let preview = invitation_preview_view(&utf16, EXPIRES_AT).expect("preview at expiration");
    let wire = serde_json::to_value(preview).expect("IPC view");
    let fingerprint = wire["ca_fingerprint"].as_str().expect("fingerprint string");
    assert_eq!(fingerprint.split(' ').count(), 16);
    assert!(fingerprint.split(' ').all(|group| group.len() == 4));
    assert_eq!(
        fingerprint.replace(' ', ""),
        invitation
            .operator_ca_public_key
            .authority_fingerprint()
            .to_hex()
    );
    assert_eq!(
        wire,
        serde_json::json!({
            "server_name": "vpn.example.net",
            "ca_fingerprint": fingerprint,
            "expires_at_unix": EXPIRES_AT,
            "invitation_token": invitation_text,
        })
    );

    let returned = decode_invitation_file(wire["invitation_token"].as_str().expect("token string"))
        .expect("token can be submitted for confirmation");
    assert_eq!(returned, invitation);
    returned
        .verify(&invitation.operator_ca_public_key, EXPIRES_AT)
        .expect("the original signature still verifies");
}

#[test]
fn preview_refuses_an_expired_invitation() {
    let invitation = encode_invitation_file(&signed_invitation(EXPIRES_AT));
    let error = invitation_preview_view(invitation.as_bytes(), EXPIRES_AT + 1)
        .expect_err("the invitation has expired");
    assert_eq!(
        error,
        "cette invitation a expiré : en demander une nouvelle à l'opérateur"
    );
}

#[test]
fn preview_refuses_an_invitation_with_an_invalid_lifetime() {
    let mut invitation = signed_invitation(EXPIRES_AT);
    invitation.not_before_unix = invitation.not_after_unix;
    let invitation = encode_invitation_file(&invitation);
    let error = invitation_preview_view(invitation.as_bytes(), EXPIRES_AT)
        .expect_err("an empty time window is invalid");
    assert_eq!(
        error,
        "invitation d'enrôlement illisible : outside the invitation window"
    );
}

#[test]
fn preview_reports_a_truncated_utf16_document() {
    let error =
        invitation_preview_view(&[0xff, 0xfe, b'{'], EXPIRES_AT).expect_err("truncated UTF-16");
    assert_eq!(
        error,
        "le profil est encodé en UTF-16 mais tronqué (nombre impair d'octets)"
    );
}

#[test]
fn request_id_allows_surrounding_whitespace() {
    let id = parse_request_id(" \tabababababababababababababababab\r\n").expect("pasted ID");
    assert_eq!(id.as_bytes(), &[0xab; 16]);
}

#[test]
fn request_id_refuses_noncanonical_or_reserved_values() {
    for input in [
        "",
        "ab",
        "abababababababababababababababab00",
        "abababababababab abababababababab",
        "abababababababababababababababaz",
        "ABABABABABABABABABABABABABABABAB",
        "00000000000000000000000000000000",
    ] {
        assert_eq!(
            parse_request_id(input).expect_err("invalid ID"),
            "identifiant de demande : 32 caractères hexadécimaux attendus",
            "input: {input:?}"
        );
    }
}
