//! Deriving the negotiated PSK, and committing to a static one.

use super::*;

/// Output length of the derivation: one WireGuard `PresharedKey`.
///
/// HKDF's expand length is normally taken from the digest, which would give
/// SHA-512's 64 bytes. The PSK slot holds 32, so the length is stated here
/// rather than truncated at the call site.
struct PskLength;

impl hkdf::KeyType for PskLength {
    fn len(&self) -> usize {
        crate::pq::SHARED_SECRET_LEN
    }
}

/// Derives the WireGuard PSK, binding the whole negotiation context.
///
/// The salt carries the gateway challenge on top of v4's transaction and
/// nonces: a derived secret is tied to an authorization the gateway issued for
/// one connection. `info` carries the server name on top of both WireGuard
/// keys, so the same transcript replayed against a different gateway identity
/// cannot produce the same key.
pub fn derive_negotiated_psk(
    shared_secret: &SharedSecret,
    request: &KeyNegotiationRequest,
    response: &KeyNegotiationResponse,
) -> Result<Zeroizing<[u8; STATIC_PSK_LEN]>, KeyNegotiationError> {
    if request.mode != ProtectionMode::MlKem || response.selected_mode != ProtectionMode::MlKem {
        return Err(KeyNegotiationError::PskDerivationOutsideMlKem);
    }
    response.validate_for(request, &response.gateway_wg_public_key)?;

    let mut salt = Vec::with_capacity(SERVER_CHALLENGE_LEN + KEY_NEGOTIATION_NONCE_LEN * 3);
    salt.extend_from_slice(&request.server_challenge);
    salt.extend_from_slice(&request.transaction_id);
    salt.extend_from_slice(&request.client_nonce);
    salt.extend_from_slice(&response.gateway_nonce);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, &salt);
    let prk = salt.extract(shared_secret.as_slice());

    let name = request.server_name.as_bytes();
    let client = request.client_wg_public_key.as_bytes();
    let gateway = response.gateway_wg_public_key.as_bytes();
    let name_len = (name.len() as u16).to_be_bytes();
    let client_len = (client.len() as u16).to_be_bytes();
    let gateway_len = (gateway.len() as u16).to_be_bytes();
    let mode = [request.mode.security_level()];
    let version = request.protocol_version.to_be_bytes();
    let timestamp = request.timestamp_unix.to_be_bytes();
    // Every variable-length field is length-prefixed: no two field boundaries
    // can be shifted to produce the same concatenation.
    let info: [&[u8]; 10] = [
        KEY_NEGOTIATION_DOMAIN,
        &version,
        &mode,
        &timestamp,
        &name_len,
        name,
        &client_len,
        client,
        &gateway_len,
        gateway,
    ];
    // The output length is the PSK slot's, not the digest's: expanding to
    // SHA-512's 64 bytes and truncating would be the same secret, but it
    // would leave the caller to do the truncating.
    let okm = prk
        .expand(&info, PskLength)
        .map_err(|_| KeyNegotiationError::Kdf)?;
    let mut psk = Zeroizing::new([0u8; STATIC_PSK_LEN]);
    okm.fill(psk.as_mut_slice())
        .map_err(|_| KeyNegotiationError::Kdf)?;
    Ok(psk)
}

/// Decodes and checks a configured static PSK.
///
/// **Exactly 32 bytes** after decoding — the size of the slot it will occupy.
/// Anything else is refused when the configuration loads, not when a
/// negotiation runs: a gateway carrying a malformed PSK must not start.
///
/// What the code cannot check, the tooling must guarantee: the value must come
/// from the TRNG → seed/reseed → DRBG pipeline of the specification. A
/// passphrase is also 32 bytes once hashed, and no length check will ever say
/// otherwise. That is why no interface offers free-text entry for this field.
pub fn validate_static_psk(
    psk_base64: &str,
) -> Result<Zeroizing<[u8; STATIC_PSK_LEN]>, KeyNegotiationError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(psk_base64.trim())
            .map_err(|_| KeyNegotiationError::InvalidStaticPsk)?,
    );
    let bytes: [u8; STATIC_PSK_LEN] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| KeyNegotiationError::InvalidStaticPsk)?;
    Ok(Zeroizing::new(bytes))
}

/// Proves possession of a static PSK **for one transaction only**.
///
/// v4 sent `SHA-256(static_psk)`. The size and randomness now required rule
/// out an offline search, but that value is stable: an observer of the public
/// port could correlate two negotiations as using the same secret. An HMAC
/// keyed by the PSK over the transaction context is a different value every
/// time, and the gateway — which knows the PSK — recomputes and compares it in
/// constant time.
pub fn static_psk_commitment(
    psk_base64: &str,
    transaction_id: &[u8; KEY_NEGOTIATION_NONCE_LEN],
    client_nonce: &[u8; KEY_NEGOTIATION_NONCE_LEN],
    server_challenge: &[u8; SERVER_CHALLENGE_LEN],
    client_wg_public_key: &str,
    gateway_wg_public_key: &str,
) -> Result<String, KeyNegotiationError> {
    let psk = validate_static_psk(psk_base64)?;
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(STATIC_PSK_COMMITMENT_LABEL);
    message.extend_from_slice(transaction_id);
    message.extend_from_slice(client_nonce);
    message.extend_from_slice(server_challenge);
    append_bytes(&mut message, client_wg_public_key.as_bytes())?;
    append_bytes(&mut message, gateway_wg_public_key.as_bytes())?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, psk.as_slice());
    Ok(hex::encode(hmac::sign(&key, &message).as_ref()))
}

/// Constant-time comparison of two commitments.
///
/// Both are hex strings of the same length; a byte-wise early return would
/// leak how many leading nibbles an attacker guessed right.
pub fn commitments_match(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}
