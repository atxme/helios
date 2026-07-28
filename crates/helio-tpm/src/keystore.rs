//! Secrets vault encrypted by the secret sealed in the TPM.
//!
//! # Role
//!
//! The secret unsealed at boot is not just a gate: it **encrypts the
//! gateway's operational secrets**. Since the WireGuard switch, the secret
//! to protect is the gateway's **Curve25519 private key** — its actual
//! cryptographic identity, the one that authenticates every handshake.
//!
//! Without this vault, this key lives in the clear in `network.toml`: a
//! stolen disk is enough to impersonate the gateway. With it, decryption
//! requires a successful TPM unseal, hence an untampered boot chain
//! (PCR 0/4/7).
//!
//! # Chaining of protections
//!
//! ```text
//! PCR 0/4/7 unchanged ──► TPM unseals the secret ──► decrypts the WireGuard key
//!      (hardware)              (256 bits)               (AES-256-GCM)
//! ```
//!
//! Modifying the kernel or bootloader breaks the first link: the secret
//! stays locked, the WireGuard key stays encrypted. The guarantee is
//! hardware-based, not software-based — replacing the `heliosd` binary
//! yields nothing.
//!
//! # Warning: interaction with post-OTA resealing
//!
//! A resealing (`BootDecision::Resealed`) generates a **new** secret: the
//! old one is permanently lost, so **any content of this vault becomes
//! unrecoverable**. This is not an implementation flaw, it is the direct
//! consequence of the anti-rollback model. See
//! [`KeystoreError::Undecipherable`] and the note in `heliosd`: after an
//! OTA, the WireGuard key must be re-supplied by the operator.

use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::{secret::SecretKey, Result, TpmError};

/// File magic: distinguishes a vault from any other blob.
const MAGIC: &[u8; 4] = b"HKS1";
/// Format version. A vault of another version is rejected rather than
/// misinterpreted.
const VERSION: u8 = 1;
/// Authenticated data: binds the ciphertext to its usage. A vault cannot
/// be repurposed toward another context in the project.
const AAD: &[u8] = b"helios-keystore-v1";

/// Header: magic + version + nonce.
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;

/// Errors specific to the vault.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The content cannot be decrypted with this secret.
    ///
    /// Typical case: the secret changed (post-OTA resealing). The content
    /// is then **permanently lost** — re-provisioning is required.
    #[error(
        "vault undecryptable with the current secret — did a resealing occur? \
         The content is unrecoverable, the key must be re-supplied"
    )]
    Undecipherable,
    #[error("invalid vault format: {0}")]
    Format(String),
}

/// Encrypted vault backed by a file.
pub struct SealedKeystore {
    path: PathBuf,
}

impl SealedKeystore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Does the vault exist on disk?
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Encrypts `plaintext` with `secret` and persists the vault **atomically**.
    ///
    /// The write goes through a temp file then a `rename`: a power cut
    /// mid-write leaves the old vault intact rather than a truncated file —
    /// so the gateway can still restart.
    pub fn store(&self, secret: &SecretKey, plaintext: &[u8]) -> Result<()> {
        let key = aead_key(secret)?;

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
        .map_err(|_| TpmError::Serde("vault encryption failed".into()))?;

        let mut blob = Vec::with_capacity(HEADER_LEN + in_out.len());
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);

        self.write_atomic(&blob)
    }

    /// Decrypts the vault with `secret`.
    pub fn load(&self, secret: &SecretKey) -> Result<Zeroizing<Vec<u8>>> {
        let blob = std::fs::read(&self.path).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })?;

        if blob.len() < HEADER_LEN {
            return Err(KeystoreError::Format("truncated vault".into()).into());
        }
        if &blob[..4] != MAGIC {
            return Err(KeystoreError::Format("invalid magic".into()).into());
        }
        if blob[4] != VERSION {
            return Err(KeystoreError::Format(format!("unsupported version {}", blob[4])).into());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&blob[5..HEADER_LEN]);

        let key = aead_key(secret)?;
        let mut in_out = blob[HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(AAD),
                &mut in_out,
            )
            // A failure here means "wrong secret" or "tampered content".
            // Both deserve the same clean refusal: we do not guess.
            .map_err(|_| KeystoreError::Undecipherable)?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    /// Removes the vault. Used when its content has become unrecoverable.
    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TpmError::Io {
                path: self.path.display().to_string(),
                cause: e.to_string(),
            }),
        }
    }

    fn write_atomic(&self, blob: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| TpmError::Io {
                path: parent.display().to_string(),
                cause: e.to_string(),
            })?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, blob).map_err(|e| TpmError::Io {
            path: tmp.display().to_string(),
            cause: e.to_string(),
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })
    }
}

/// Builds the AEAD key from the unsealed secret.
fn aead_key(secret: &SecretKey) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
        .map_err(|_| TpmError::Serde("invalid AEAD key".into()))?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("helios-keystore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn secret(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 32])
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let ks = SealedKeystore::new(tmp_path("roundtrip"));
        let wg_key = b"une-cle-privee-wireguard-32-oct!";

        ks.store(&secret(1), wg_key).unwrap();
        assert!(ks.exists());

        let out = ks.load(&secret(1)).unwrap();
        assert_eq!(out.as_slice(), wg_key);
        ks.remove().unwrap();
    }

    /// The heart of the protection: without the right secret — hence
    /// without a successful TPM unseal — the content stays inaccessible.
    #[test]
    fn a_wrong_secret_does_not_decrypt() {
        let ks = SealedKeystore::new(tmp_path("wrongkey"));
        ks.store(&secret(1), b"secret").unwrap();

        let err = ks.load(&secret(2));
        assert!(
            matches!(err, Err(TpmError::Keystore(KeystoreError::Undecipherable))),
            "a different secret (e.g. after resealing) must fail cleanly"
        );
        ks.remove().unwrap();
    }

    /// AEAD must detect any tampering of the ciphertext, not just a wrong
    /// key: a modified disk must not produce a fake plaintext.
    #[test]
    fn tampering_is_detected() {
        let path = tmp_path("tamper");
        let ks = SealedKeystore::new(&path);
        ks.store(&secret(1), b"secret").unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(&path, &blob).unwrap();

        assert!(ks.load(&secret(1)).is_err(), "tampering must be detected");
        ks.remove().unwrap();
    }

    #[test]
    fn two_writes_of_the_same_content_differ() {
        let ks = SealedKeystore::new(tmp_path("nonce"));
        ks.store(&secret(1), b"secret").unwrap();
        let first = std::fs::read(ks.path()).unwrap();
        ks.store(&secret(1), b"secret").unwrap();
        let second = std::fs::read(ks.path()).unwrap();
        assert_ne!(first, second, "the nonce must be fresh on each write");
        ks.remove().unwrap();
    }

    #[test]
    fn invalid_formats_are_rejected() {
        let path = tmp_path("badformat");
        let ks = SealedKeystore::new(&path);

        std::fs::write(&path, b"xx").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "too short");

        std::fs::write(&path, b"NOPE\x01aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "wrong magic");

        std::fs::write(&path, b"HKS1\x09aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "unknown version");

        ks.remove().unwrap();
    }

    #[test]
    fn removal_is_idempotent() {
        let ks = SealedKeystore::new(tmp_path("gone"));
        ks.remove().unwrap();
        ks.remove().unwrap();
        assert!(!ks.exists());
    }
}
