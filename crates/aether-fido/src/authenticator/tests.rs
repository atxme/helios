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

fn authenticator_data_with_attested_tail(tail: &[u8]) -> Vec<u8> {
    let mut data = vec![0x5A; 32];
    data.push(FLAG_ATTESTED_CREDENTIAL_DATA);
    data.extend_from_slice(&[0; 4]);
    data.extend_from_slice(tail);
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

#[test]
fn attested_credential_rejects_each_truncated_field_and_empty_or_oversized_ids() {
    let truncated_aaguid = [0; 15];
    let truncated_length = [0; 16];
    let mut empty_id = vec![0; 16];
    empty_id.extend_from_slice(&0u16.to_be_bytes());
    let mut oversized_id = vec![0; 16];
    oversized_id.extend_from_slice(&((MAX_CREDENTIAL_ID_BYTES + 1) as u16).to_be_bytes());
    let mut truncated_id = vec![0; 16];
    truncated_id.extend_from_slice(&2u16.to_be_bytes());
    truncated_id.push(0x41);
    let mut missing_cose = vec![0; 16];
    missing_cose.extend_from_slice(&1u16.to_be_bytes());
    missing_cose.push(0x41);

    for (name, tail) in [
        ("AAGUID", truncated_aaguid.as_slice()),
        ("credential length", truncated_length.as_slice()),
        ("empty identifier", empty_id.as_slice()),
        ("oversized identifier", oversized_id.as_slice()),
        ("truncated identifier", truncated_id.as_slice()),
        ("missing COSE key", missing_cose.as_slice()),
    ] {
        assert!(
            matches!(
                attested_credential(&authenticator_data_with_attested_tail(tail)),
                Err(AuthenticatorError::NoAttestedCredential(_))
            ),
            "accepted truncated or out-of-bounds {name}"
        );
    }
}

#[test]
fn attested_credential_accepts_exact_identifier_limit_and_rejects_one_over() {
    let maximum = vec![0xA5; MAX_CREDENTIAL_ID_BYTES];
    let parsed = attested_credential(&authenticator_data(&maximum, &[]))
        .expect("identifier at the documented bound");
    assert_eq!(parsed.credential_id, maximum);

    let oversized = vec![0xA5; MAX_CREDENTIAL_ID_BYTES + 1];
    assert!(matches!(
        attested_credential(&authenticator_data(&oversized, &[])),
        Err(AuthenticatorError::NoAttestedCredential(_))
    ));
}

#[test]
fn cose_key_parser_accepts_supported_extended_integer_and_byte_string_heads() {
    for (key, expected_len) in [
        (vec![0xA1, 0x18, 0x01, 0x01], 4),
        (vec![0xA1, 0x19, 0x00, 0x01, 0x01], 5),
        (vec![0xA1, 0x1A, 0, 0, 0, 1, 0x01], 7),
        (vec![0xA1, 0x01, 0x59, 0x00, 0x01, 0xAB], 6),
        (vec![0xA1, 0x01, 0x5A, 0, 0, 0, 1, 0xAB], 8),
    ] {
        assert_eq!(
            cose_key_length(&key).expect("supported CBOR head"),
            expected_len
        );
    }
}

#[test]
fn cose_key_parser_enforces_its_exact_encoded_size_ceiling() {
    let map_with_scalar_pairs = |entries: u16| {
        let mut bytes = vec![0xB9];
        bytes.extend_from_slice(&entries.to_be_bytes());
        for _ in 0..entries {
            bytes.extend_from_slice(&[0x01, 0x01]);
        }
        bytes
    };

    let mut at_limit = vec![0xB9, 0x01, 0xFE, 0x01, 0x41, 0xAB];
    for _ in 1..510 {
        at_limit.extend_from_slice(&[0x01, 0x01]);
    }
    assert_eq!(at_limit.len(), MAX_CREDENTIAL_PUBLIC_KEY_BYTES);
    assert_eq!(
        cose_key_length(&at_limit).expect("key below the encoded-size ceiling"),
        at_limit.len()
    );

    let over_limit = map_with_scalar_pairs(511);
    assert!(over_limit.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES);
    assert!(matches!(
        cose_key_length(&over_limit),
        Err(AuthenticatorError::NoAttestedCredential(_))
    ));
}

#[test]
fn cose_key_parser_rejects_unsupported_head_widths_and_major_types() {
    for malformed in [
        &[0xA1, 0x01, 0x1B, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0xA1, 0x01, 0x5F, 0xFF][..],
        &[0xA1, 0x01, 0x61, b'x'][..],
        &[0xA1, 0x01, 0x41][..],
    ] {
        assert!(matches!(
            cose_key_length(malformed),
            Err(AuthenticatorError::NoAttestedCredential(_))
        ));
    }
}
