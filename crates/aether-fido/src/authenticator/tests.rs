use super::*;

/// The platform hashes the PRF value before it reaches `hmac-secret`, and
/// the raw path must do the same. If this ever becomes the identity again,
/// a vault created on Windows stops opening over HID — with the same key,
/// and an error naming only the AEAD.
#[test]
fn the_prf_salt_is_the_platform_transformation_and_not_the_salt() {
    let salt = [0x5Au8; SALT_LEN];
    let derived = prf_salt(&salt);
    assert_ne!(derived, salt, "the value is hashed, not passed through");
    assert_eq!(derived, prf_salt(&salt), "and deterministically so");
    assert_ne!(
        derived,
        prf_salt(&[0x5Bu8; SALT_LEN]),
        "a different vault salt gives a different secret"
    );
}

/// The prefix is the specification's, byte for byte: `"WebAuthn PRF"` then
/// a `0x00`. A stray character here derives a secret nothing else agrees
/// with, and only a real key would ever notice.
#[test]
fn the_prf_prefix_is_the_one_the_specification_names() {
    assert_eq!(PRF_PREFIX, b"WebAuthn PRF\0");
    assert_eq!(PRF_PREFIX.len(), 13);
}

/// A canonical ES256 COSE key, in the shape CTAP2 emits: a five-entry map
/// of `kty`, `alg`, `crv`, `x` and `y`.
fn es256_cose_key() -> Vec<u8> {
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[0x11; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[0x22; 32]);
    key
}

fn authenticator_data(credential_id: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut data = vec![0x5A; 32];
    data.push(FLAG_ATTESTED_CREDENTIAL_DATA | 0x05);
    data.extend_from_slice(&7u32.to_be_bytes());
    data.extend_from_slice(&[0x3B; 16]);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&es256_cose_key());
    data.extend_from_slice(trailing);
    data
}

/// The three public values a credential binding needs come out of the
/// authenticator data, and out of nothing else.
#[test]
fn attested_credential_data_yields_the_key_the_binding_carries() {
    let credential_id = vec![0xC0, 0xDE, 0x01, 0x02];
    let attested = attested_credential(&authenticator_data(&credential_id, &[]))
        .expect("attested credential data");
    assert_eq!(attested.credential_id, credential_id);
    assert_eq!(attested.aaguid, [0x3B; 16]);
    assert_eq!(attested.credential_public_key, es256_cose_key());
}

/// Extension output follows the COSE key inside authenticator data. Taking
/// « everything after the credential identifier » would fold it into the
/// signed binding, and the key would then verify nothing.
#[test]
fn extension_output_after_the_cose_key_is_left_out_of_it() {
    let trailing = vec![
        0xa1, 0x6b, b'h', b'm', b'a', b'c', b'-', b'-', b'-', b'-', b'-', b'-', b'-', 0xf5,
    ];
    let attested = attested_credential(&authenticator_data(&[9; 32], &trailing))
        .expect("attested credential data");
    assert_eq!(attested.credential_public_key, es256_cose_key());
}

/// Without the AT flag there is no attested credential data at all, and
/// the refusal names that rather than failing somewhere inside a parse.
#[test]
fn authenticator_data_without_the_attested_flag_is_refused() {
    let mut data = authenticator_data(&[1; 16], &[]);
    data[32] &= !FLAG_ATTESTED_CREDENTIAL_DATA;
    assert!(matches!(
        attested_credential(&data),
        Err(AuthenticatorError::NoAttestedCredential(_))
    ));
}

/// The reader claims to understand one CBOR shape and refuses the rest.
/// A parser that guessed where a key ended would put the guess into a
/// document `CA-PQ` signs.
#[test]
fn a_cose_key_outside_the_shape_this_reader_claims_is_refused() {
    // An array where a map belongs.
    assert!(cose_key_length(&[0x85, 0x01]).is_err());
    // A text-string value: never part of the two shapes registered here.
    assert!(cose_key_length(&[0xa1, 0x01, 0x61, b'x']).is_err());
    // A byte string in label position.
    assert!(cose_key_length(&[0xa1, 0x41, 0x01, 0x02]).is_err());
    // An indefinite-length map.
    assert!(cose_key_length(&[0xbf, 0x01, 0x02, 0xff]).is_err());
    // A truncated coordinate.
    let mut truncated = es256_cose_key();
    truncated.truncate(truncated.len() - 1);
    assert!(cose_key_length(&truncated).is_err());
}
