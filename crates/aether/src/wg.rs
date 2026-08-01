//! Curve25519 keys of the WireGuard data plane.
//!
//! Three operations recur throughout the project: generating a key pair,
//! deriving a public key from a private one, and validating a received key.
//! They used to be rewritten in the gateway, the API, the client and the
//! campaign tool.
//!
//! They live here because a divergence between these copies does not
//! produce a readable error: it produces two peers that do not recognize
//! each other, with handshakes that fail silently on the WireGuard side.
//! The cost of a bug here is a long diagnostic, not a message.
//!
//! # Encoding
//!
//! Standard base64 with padding, like `wg genkey` and `wg pubkey` — this is
//! the form expected in `network.toml`, in Orion profiles and in
//! `wg-quick` files.
//!
//! # Clamping
//!
//! The private key is [clamped](curve25519_dalek::scalar::clamp_integer)
//! before being encoded, so that the displayed value is the one `wg genkey`
//! would have produced. WireGuard implementations clamp anyway at use time:
//! without this normalization, two different encodings would designate the
//! same identity, which makes any key comparison misleading.

use base64::Engine as _;

use crate::SecretString;

/// Length of a Curve25519 key, public or private.
pub const KEY_LEN: usize = 32;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Errors manipulating a WireGuard key.
#[derive(Debug, thiserror::Error)]
pub enum WgKeyError {
    #[error("key not decodable from base64: {0}")]
    Encoding(String),
    #[error("key of {0} bytes instead of {KEY_LEN} — this is not a Curve25519 key")]
    Length(usize),
    #[error("system CSPRNG unavailable")]
    Rng,
}

/// A WireGuard key pair, encoded in base64.
///
/// The private key is wrapped in [`SecretString`]: it cannot land in a log
/// through a derived `Debug`.
/// Deliberately not `Clone`: it carries a private key, and ADR-006 §5 puts the
/// rule on the type rather than on `Drop`. Duplicating one goes through
/// [`SecretString::duplicate`], which shows up in a diff.
#[derive(Debug)]
pub struct Keypair {
    pub private_key: SecretString,
    pub public_key: String,
}

/// Generates a fresh WireGuard key pair.
pub fn generate_keypair() -> Result<Keypair, WgKeyError> {
    let mut raw = [0u8; KEY_LEN];
    aws_lc_rs::rand::fill(&mut raw).map_err(|_| WgKeyError::Rng)?;
    let clamped = curve25519_dalek::scalar::clamp_integer(raw);
    let secret = x25519_dalek::StaticSecret::from(clamped);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(Keypair {
        private_key: SecretString::new(B64.encode(secret.to_bytes())),
        public_key: B64.encode(public.as_bytes()),
    })
}

/// Derives the public key corresponding to a base64 private key.
pub fn public_from_private(private_key_b64: &str) -> Result<String, WgKeyError> {
    let secret = x25519_dalek::StaticSecret::from(decode_key(private_key_b64)?);
    Ok(B64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// Checks that a string is indeed a 32-byte base64 Curve25519 key.
///
/// Call **before** writing anything: sealing or admitting an invalid key
/// costs more later, on a gateway that can no longer be reached.
pub fn validate_key(key_b64: &str) -> Result<(), WgKeyError> {
    decode_key(key_b64).map(|_| ())
}

fn decode_key(key_b64: &str) -> Result<[u8; KEY_LEN], WgKeyError> {
    let raw = B64
        .decode(key_b64.trim())
        .map_err(|e| WgKeyError::Encoding(e.to_string()))?;
    let len = raw.len();
    raw.try_into().map_err(|_| WgKeyError::Length(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X25519 test vector from RFC 7748 §6.1 (Alice's key). Better than a
    /// round-trip with our own code, which would only prove its internal
    /// consistency.
    const RFC7748_PRIVATE: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const RFC7748_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    fn hex_to_b64(hex_str: &str) -> String {
        B64.encode(hex::decode(hex_str).expect("valid hex"))
    }

    #[test]
    fn derivation_matches_the_rfc7748_vector() {
        let public = public_from_private(&hex_to_b64(RFC7748_PRIVATE)).expect("derivation");
        assert_eq!(public, hex_to_b64(RFC7748_PUBLIC));
    }

    #[test]
    fn the_generated_pair_is_consistent() {
        let pair = generate_keypair().expect("generation");
        let derived = public_from_private(pair.private_key.expose()).expect("derivation");
        assert_eq!(derived, pair.public_key);
    }

    /// Two calls must not yield the same identity: a collision would signal
    /// a frozen CSPRNG, hence interchangeable gateways.
    #[test]
    fn two_generations_differ() {
        let a = generate_keypair().expect("generation");
        let b = generate_keypair().expect("generation");
        assert_ne!(a.public_key, b.public_key);
    }

    /// The displayed private key must already be clamped: otherwise two
    /// distinct encodings designate the same identity and any comparison
    /// lies.
    #[test]
    fn the_generated_private_key_is_already_clamped() {
        let pair = generate_keypair().expect("generation");
        let raw = B64.decode(pair.private_key.expose()).expect("base64");
        let bytes: [u8; KEY_LEN] = raw.try_into().expect("32 bytes");
        assert_eq!(curve25519_dalek::scalar::clamp_integer(bytes), bytes);
    }

    #[test]
    fn the_pairs_debug_does_not_leak_the_private_key() {
        let pair = generate_keypair().expect("generation");
        let rendered = format!("{pair:?}");
        assert!(
            !rendered.contains(pair.private_key.expose()),
            "the private key leaked: {rendered}"
        );
    }

    #[test]
    fn validation_rejects_invalid_forms() {
        assert!(validate_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
        assert!(matches!(
            validate_key("pas-du-base64"),
            Err(WgKeyError::Encoding(_))
        ));
        assert!(matches!(validate_key("AAAA"), Err(WgKeyError::Length(3))));
        assert!(validate_key("").is_err());
    }

    /// Spaces around a key pasted from a terminal are common and must not
    /// turn a valid key into an incomprehensible refusal.
    #[test]
    fn surrounding_spaces_are_tolerated() {
        let pair = generate_keypair().expect("generation");
        let padded = format!("  {}\n", pair.private_key.expose());
        assert_eq!(
            public_from_private(&padded).expect("derivation"),
            pair.public_key
        );
    }
}
