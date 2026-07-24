//! WireGuard key escrow, to survive a PCR change.
//!
//! # The problem
//!
//! A resealing generates a **new** TPM secret; the old one is unrecoverable
//! by construction. The vault encrypted with the old one becomes
//! undecryptable, and the WireGuard key is lost. Without a key, no tunnel —
//! hence no API, which lives behind the tunnel. The gateway becomes
//! unreachable remotely.
//!
//! Useful reminder: **this does not happen on every OTA.** Sealing covers
//! PCR 0/4/7 — firmware, boot chain, Secure Boot. Replacing the `heliosd`
//! binary touches none of the three: unseal succeeds and the key survives.
//! Only a new kernel/initrd, a new bootloader, a firmware update, or a
//! Secure Boot key change move these PCRs.
//!
//! # The constraint that dictates the solution
//!
//! If the gateway could recover **on its own** after a PCR change, the TPM
//! protection would be worthless: an attacker who replaces the kernel would
//! obtain the key through the same path. Recovery **must** require an
//! element held by the operator.
//!
//! # The mechanism
//!
//! ```text
//! ── Under normal operation ──────────────────────────────────────────────────
//! WireGuard key ──encrypted to the escrow public key──► wg-key.escrow
//!                        (only the operator can open it)
//!
//! ── After a PCR change ──────────────────────────────────────────────────────
//! 1. The operator opens wg-key.escrow offline (they hold the private key).
//! 2. They place the recovered key in a recovery file, delivered through the
//!    SAME channel as the reseal ticket (the OTA bundle).
//! 3. At boot, the gateway consumes this file, reseals the key under the
//!    new TPM secret, then **erases** the file.
//! ```
//!
//! No SSH is required: the key travels with the OTA, like the ticket.
//!
//! # The trade-off, stated plainly
//!
//! The recovery file contains the key **in the clear** for the duration of
//! one boot. This is unavoidable: at that moment the gateway has no
//! pre-existing secret to decrypt it with — that is precisely what the
//! resealing just destroyed. Exposure is therefore bounded rather than
//! eliminated:
//!
//! * the file is read **only** if the vault is genuinely undecryptable;
//! * it is erased immediately after use;
//! * it must be delivered with the same care as the OTA bundle itself.
//!
//! This is the same exposure as an SSH-based recovery, but automated and bounded.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf;
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::{Result, TpmError};

/// Magic bytes of the escrow blob.
const MAGIC: &[u8; 4] = b"HESC";
const VERSION: u8 = 1;
/// Separates escrow usage from any other encryption in the project.
const AAD: &[u8] = b"helios-escrow-v1";
/// KDF domain applied to the X25519 secret.
const KDF_INFO: &[u8] = b"helios-escrow-kdf-v1";

/// Length of an X25519 public/private key.
pub const KEY_LEN: usize = 32;
/// Header: magic + version + ephemeral public key + nonce.
const HEADER_LEN: usize = 4 + 1 + KEY_LEN + NONCE_LEN;

/// Errors specific to escrow.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("invalid escrow key: {0}")]
    BadKey(String),
    #[error("invalid escrow blob: {0}")]
    Format(String),
    #[error("cannot open the escrow (wrong private key or tampered blob)")]
    Undecipherable,
}

/// Encrypts `plaintext` to the operator's escrow public key.
///
/// "Sealed box" scheme: an ephemeral X25519 pair is drawn, the shared secret
/// goes through HKDF, and the result is encrypted with AES-256-GCM. The
/// ephemeral public key travels with the blob; its private half is
/// discarded immediately. **The gateway therefore cannot reopen what it
/// sealed** — this is intentional: only the operator can.
pub fn seal_to_operator(operator_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = to_array(operator_public_key)?;
    let recipient = x25519_dalek::PublicKey::from(recipient);

    // Ephemeral pair: discarded as soon as the secret is derived.
    let mut ephemeral_bytes = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(ephemeral_bytes.as_mut_slice())
        .map_err(|_| TpmError::Rng("CSPRNG unavailable for escrow".into()))?;
    let ephemeral_secret = x25519_dalek::StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let key = derive_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        recipient.as_bytes(),
    )?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| TpmError::Rng("CSPRNG unavailable for nonce".into()))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(AAD),
        &mut in_out,
    )
    .map_err(|_| TpmError::Serde("escrow encryption failed".into()))?;

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
/// Intended for **operator tooling** (outside the gateway) and tests: the
/// gateway does not hold this private key, by construction.
pub fn open_as_operator(operator_private_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN {
        return Err(EscrowError::Format("truncated blob".into()).into());
    }
    if &blob[..4] != MAGIC {
        return Err(EscrowError::Format("invalid magic".into()).into());
    }
    if blob[4] != VERSION {
        return Err(EscrowError::Format(format!("unsupported version {}", blob[4])).into());
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

/// Derives the AEAD key from the X25519 secret.
///
/// Both public keys enter the KDF: the ciphertext is thus bound to the
/// (ephemeral, recipient) pair and cannot be replayed toward another
/// recipient.
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
        .map_err(|_| TpmError::Serde("escrow derivation failed".into()))?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    okm.fill(key_bytes.as_mut_slice())
        .map_err(|_| TpmError::Serde("escrow derivation failed".into()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_slice())
        .map_err(|_| TpmError::Serde("invalid escrow AEAD key".into()))?;
    Ok(LessSafeKey::new(unbound))
}

fn to_array(key: &[u8]) -> Result<[u8; KEY_LEN]> {
    key.try_into().map_err(|_| {
        TpmError::Escrow(EscrowError::BadKey(format!(
            "{} bytes instead of {KEY_LEN}",
            key.len()
        )))
    })
}

/// Generates an escrow keypair. Operator tool: the private half stays off the gateway.
pub fn generate_operator_keypair() -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; KEY_LEN])> {
    let mut private = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(private.as_mut_slice())
        .map_err(|_| TpmError::Rng("CSPRNG unavailable".into()))?;
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

    /// The property that makes escrow worthwhile: the gateway seals but
    /// cannot reopen. A compromised gateway does not yield the key.
    #[test]
    fn a_different_private_key_does_not_open_it() {
        let (_, public) = generate_operator_keypair().unwrap();
        let (other_private, _) = generate_operator_keypair().unwrap();

        let blob = seal_to_operator(&public, b"secret").unwrap();
        assert!(matches!(
            open_as_operator(other_private.as_slice(), &blob),
            Err(TpmError::Escrow(EscrowError::Undecipherable))
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

    /// Tampering the ephemeral public key must also fail: it enters the
    /// KDF, so the ciphertext is bound to the key pair.
    #[test]
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

    /// The full end-to-end scenario: an OTA changes the kernel, the TPM
    /// secret is regenerated, the vault becomes unreadable — and the
    /// operator still recovers the gateway's identity through escrow.
    #[test]
    fn full_recovery_after_a_pcr_change() {
        use crate::keystore::SealedKeystore;
        use crate::secret::SecretKey;

        let dir = std::env::temp_dir().join(format!("helios-escrow-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SealedKeystore::new(dir.join("wg-key.sealed"));

        let wg_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();

        // ── Normal operation: the key is sealed, and escrowed ──
        let secret_before = SecretKey::from_bytes([1u8; 32]);
        store.store(&secret_before, wg_key).unwrap();
        let escrow_blob = seal_to_operator(&operator_public, wg_key).unwrap();
        assert_eq!(store.load(&secret_before).unwrap().as_slice(), wg_key);

        // ── OTA with a new kernel: PCR 4 moves, secret regenerated ──
        let secret_after = SecretKey::from_bytes([2u8; 32]);
        assert!(
            store.load(&secret_after).is_err(),
            "the vault must be unreadable with the new secret"
        );

        // ── Recovery: the operator opens the escrow offline ──
        let recovered = open_as_operator(operator_private.as_slice(), &escrow_blob).unwrap();
        assert_eq!(recovered.as_slice(), wg_key, "identity recovered");

        // ── The gateway reseals under the new secret ──
        store.store(&secret_after, &recovered).unwrap();
        assert_eq!(store.load(&secret_after).unwrap().as_slice(), wg_key);

        let _ = std::fs::remove_dir_all(&dir);
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
