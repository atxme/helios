//! WireGuard key escrow held by the operator, to survive a PCR change.
//!
//! # The problem
//!
//! A resealing generates a **new** TPM secret; the old one is unrecoverable by
//! construction. The vault encrypted with the old one becomes undecipherable,
//! and the WireGuard key is lost. Without a key, no tunnel — hence no API,
//! which lives behind the tunnel. The gateway becomes unreachable remotely.
//!
//! This does not happen on every OTA. Sealing covers PCR 0/4/7 — firmware,
//! boot chain, and Secure Boot. Replacing the `heliosd` binary touches none of
//! the three: unseal succeeds and the key survives. A new kernel/initrd,
//! bootloader, firmware update, or Secure Boot key change moves these PCRs.
//!
//! # The security boundary
//!
//! If the gateway could recover on its own after a PCR change, TPM protection
//! would be worthless: an attacker who replaces the kernel would obtain the
//! key through the same path. Recovery therefore requires an element held by
//! the operator. The gateway can seal to the operator's public key, but it
//! cannot open what it sealed because it never has the corresponding private
//! key.
//!
//! # The mechanism
//!
//! ```text
//! Under normal operation:
//! WireGuard key ──encrypted to the escrow public key──► wg-key.escrow
//!                        (only the operator can open it)
//!
//! After a PCR change:
//! 1. The operator opens wg-key.escrow offline with the private key.
//! 2. They place the recovered key in a recovery file delivered with the OTA.
//! 3. The gateway consumes the file, reseals the key under the new TPM secret,
//!    then erases the file.
//! ```
//!
//! No SSH is required: the key travels with the OTA, like the reseal ticket.
//!
//! # Bounded exposure
//!
//! The recovery file contains the key **in the clear** for the duration of one
//! boot. At that moment the gateway has no pre-existing secret to decrypt it
//! with — that is precisely what the resealing destroyed. The exposure is
//! bounded rather than eliminated:
//!
//! * the file is read only if the vault is genuinely undecipherable;
//! * it is erased immediately after use;
//! * it must be delivered with the same care as the OTA bundle itself.
//!
//! The HESC v1 blob uses an ephemeral X25519 key pair, HKDF-SHA256, and
//! AES-256-GCM. Fresh ephemeral material and a fresh nonce are generated for
//! every sealing through [`aether::random`].

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf;
use zeroize::Zeroizing;

/// Length of an X25519 public or private key.
pub const KEY_LEN: usize = 32;

const MAGIC: &[u8; 4] = b"HESC";
const VERSION: u8 = 1;
const AAD: &[u8] = b"helios-escrow-v1";
const KDF_INFO: &[u8] = b"helios-escrow-kdf-v1";
const HEADER_LEN: usize = 4 + 1 + KEY_LEN + NONCE_LEN;

/// Errors returned by the escrow format and cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("invalid escrow key: {0}")]
    BadKey(String),
    #[error("invalid escrow blob: {0}")]
    Format(String),
    #[error("cannot open the escrow (wrong private key or tampered blob)")]
    Undecipherable,
    #[error("secret generation (CSPRNG) failed: {0}")]
    Rng(String),
    #[error("serialization/deserialization: escrow encryption failed")]
    Encryption,
    #[error("serialization/deserialization: escrow derivation failed")]
    Derivation,
    #[error("serialization/deserialization: invalid escrow AEAD key")]
    InvalidAeadKey,
}

/// Result type for escrow operations.
pub type Result<T> = std::result::Result<T, EscrowError>;

/// Encrypts `plaintext` to the operator's escrow public key.
pub fn seal_to_operator(operator_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = x25519_dalek::PublicKey::from(to_array(operator_public_key)?);

    let mut ephemeral_bytes = Zeroizing::new([0u8; KEY_LEN]);
    aether::random::fill_secret(ephemeral_bytes.as_mut_slice()).map_err(|error| {
        EscrowError::Rng(format!("approved DRBG unavailable for escrow: {error}"))
    })?;
    let ephemeral_secret = x25519_dalek::StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let key = derive_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        recipient.as_bytes(),
    )?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aether::random::fill_secret(&mut nonce_bytes).map_err(|error| {
        EscrowError::Rng(format!("approved DRBG unavailable for nonce: {error}"))
    })?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(AAD),
        &mut in_out,
    )
    .map_err(|_| EscrowError::Encryption)?;

    let mut blob = Vec::with_capacity(HEADER_LEN + in_out.len());
    blob.extend_from_slice(MAGIC);
    blob.push(VERSION);
    blob.extend_from_slice(ephemeral_public.as_bytes());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Opens an escrow with the operator's private key.
///
/// The gateway never possesses this private key. The returned plaintext is
/// zeroizing so recovered key material is cleared when the value is dropped.
pub fn open_as_operator(operator_private_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN {
        return Err(EscrowError::Format("truncated blob".into()));
    }
    if &blob[..4] != MAGIC {
        return Err(EscrowError::Format("invalid magic".into()));
    }
    if blob[4] != VERSION {
        return Err(EscrowError::Format(format!(
            "unsupported version {}",
            blob[4]
        )));
    }

    let secret = x25519_dalek::StaticSecret::from(to_array(operator_private_key)?);
    let recipient_public = x25519_dalek::PublicKey::from(&secret);

    let mut ephemeral = [0u8; KEY_LEN];
    ephemeral.copy_from_slice(&blob[5..5 + KEY_LEN]);
    let ephemeral_public = x25519_dalek::PublicKey::from(ephemeral);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[5 + KEY_LEN..HEADER_LEN]);

    let shared = secret.diffie_hellman(&ephemeral_public);
    let key = derive_key(shared.as_bytes(), &ephemeral, recipient_public.as_bytes())?;

    let mut in_out = blob[HEADER_LEN..].to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD),
            &mut in_out,
        )
        .map_err(|_| EscrowError::Undecipherable)?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

fn derive_key(
    shared: &[u8],
    ephemeral_public: &[u8],
    recipient_public: &[u8],
) -> Result<LessSafeKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared);
    let info: [&[u8]; 3] = [KDF_INFO, ephemeral_public, recipient_public];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| EscrowError::Derivation)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    okm.fill(key_bytes.as_mut_slice())
        .map_err(|_| EscrowError::Derivation)?;

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_slice())
        .map_err(|_| EscrowError::InvalidAeadKey)?;
    Ok(LessSafeKey::new(unbound))
}

fn to_array(key: &[u8]) -> Result<[u8; KEY_LEN]> {
    key.try_into()
        .map_err(|_| EscrowError::BadKey(format!("{} bytes instead of {KEY_LEN}", key.len())))
}

/// Generates an operator escrow keypair. The private half stays off the gateway.
pub fn generate_operator_keypair() -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; KEY_LEN])> {
    let mut private = Zeroizing::new([0u8; KEY_LEN]);
    aether::random::fill_secret(private.as_mut_slice())
        .map_err(|error| EscrowError::Rng(format!("approved DRBG unavailable: {error}")))?;
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((private, *public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_round_trip() {
        let (private, public) = generate_operator_keypair().unwrap();
        let wg_key = b"cle-privee-wireguard-de-32-octet";

        let blob = seal_to_operator(&public, wg_key).unwrap();
        let out = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(out.as_slice(), wg_key);
    }

    #[test]
    /// The gateway seals but cannot reopen. A compromised gateway does not
    /// obtain the operator's private key through this mechanism.
    fn a_different_private_key_does_not_open_it() {
        let (_, public) = generate_operator_keypair().unwrap();
        let (other_private, _) = generate_operator_keypair().unwrap();

        let blob = seal_to_operator(&public, b"secret").unwrap();
        assert!(matches!(
            open_as_operator(other_private.as_slice(), &blob),
            Err(EscrowError::Undecipherable)
        ));
    }

    #[test]
    fn two_sealings_of_the_same_content_differ() {
        let (_, public) = generate_operator_keypair().unwrap();
        let a = seal_to_operator(&public, b"secret").unwrap();
        let b = seal_to_operator(&public, b"secret").unwrap();
        assert_ne!(
            a, b,
            "ephemeral pair and nonce must be fresh on each sealing"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_to_operator(&public, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    #[test]
    /// The ephemeral key enters the KDF, so the ciphertext is bound to the
    /// exact ephemeral/recipient pair.
    fn substituting_the_ephemeral_key_is_detected() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_to_operator(&public, b"secret").unwrap();
        blob[6] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    #[test]
    fn wrong_size_keys_are_rejected() {
        assert!(seal_to_operator(&[0u8; 10], b"x").is_err());
        let (_, public) = generate_operator_keypair().unwrap();
        let blob = seal_to_operator(&public, b"x").unwrap();
        assert!(open_as_operator(&[0u8; 10], &blob).is_err());
    }

    #[test]
    fn legacy_error_display_texts_are_preserved() {
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable for escrow: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable for escrow: detail"
        );
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable for nonce: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable for nonce: detail"
        );
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable: detail"
        );
        assert_eq!(
            EscrowError::Encryption.to_string(),
            "serialization/deserialization: escrow encryption failed"
        );
        assert_eq!(
            EscrowError::Derivation.to_string(),
            "serialization/deserialization: escrow derivation failed"
        );
        assert_eq!(
            EscrowError::InvalidAeadKey.to_string(),
            "serialization/deserialization: invalid escrow AEAD key"
        );
    }

    #[test]
    fn invalid_formats_are_rejected() {
        let (private, _) = generate_operator_keypair().unwrap();
        assert!(open_as_operator(private.as_slice(), b"court").is_err());

        let mut bad = vec![0u8; HEADER_LEN + 16];
        bad[..4].copy_from_slice(b"NOPE");
        assert!(open_as_operator(private.as_slice(), &bad).is_err());

        let mut bad_version = vec![0u8; HEADER_LEN + 16];
        bad_version[..4].copy_from_slice(MAGIC);
        bad_version[4] = 9;
        assert!(open_as_operator(private.as_slice(), &bad_version).is_err());
    }
}
