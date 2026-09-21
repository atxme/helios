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

// Direct AEAD use is confined to reading the legacy `HKS1` container: the
// current format goes through `aether-vault`.
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use zeroize::Zeroizing;

use crate::{secret::SecretKey, Result, TpmError};

pub use aether_vault::Context;

/// Domain of the gateway's WireGuard identity (ADR-006 §2).
pub const DOMAIN_GATEWAY_WG_KEY: &str = "helios.gateway.wg-key";
/// Domain of the key-negotiation TLS and ML-DSA identity.
pub const DOMAIN_KEY_NEGOTIATION_IDENTITY: &str = "helios.key-negotiation.identity";

/// Magic of the **legacy** format, read-only.
const LEGACY_MAGIC: &[u8; 4] = b"HKS1";
/// Version of the legacy format.
const LEGACY_VERSION: u8 = 1;
/// Authenticated data of the legacy format.
const LEGACY_AAD: &[u8] = b"helios-keystore-v1";
/// Legacy header: magic + version + nonce.
const LEGACY_HEADER_LEN: usize = 4 + 1 + NONCE_LEN;

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
///
/// Carries its `domain` — the *use* it serves — while the `object_context`
/// given at each call names the *instance*. Both are authenticated: a vault of
/// one gateway is never openable as another's, even under an identical TPM
/// secret (ADR-006 §2).
pub struct SealedKeystore {
    path: PathBuf,
    domain: &'static str,
}

impl SealedKeystore {
    pub fn new(path: impl Into<PathBuf>, domain: &'static str) -> Self {
        Self {
            path: path.into(),
            domain,
        }
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
    pub fn store(&self, secret: &SecretKey, context: &Context, plaintext: &[u8]) -> Result<()> {
        let blob = aether_vault::seal(
            self.domain,
            context,
            &aether_vault::Unlock::Key(secret.as_bytes()),
            plaintext,
        )
        .map_err(|e| KeystoreError::Format(e.to_string()))?;
        self.write_atomic(&blob)
    }

    /// Decrypts the vault with `secret`.
    ///
    /// Reads both the current `HVLT` container and the legacy `HKS1` one. The
    /// compatibility is **not** politeness: a gateway updating in place holds
    /// its only WireGuard identity in that file, and refusing to read it would
    /// turn an update into a loss of identity with no recovery channel other
    /// than the escrow. The vault is rewritten in the new format on the next
    /// [`Self::store`], which the resealing path performs.
    pub fn load(&self, secret: &SecretKey, context: &Context) -> Result<Zeroizing<Vec<u8>>> {
        if self.is_legacy()? {
            return self.load_legacy_file(secret);
        }
        aether_vault::open_file(
            &self.path,
            self.domain,
            context,
            &aether_vault::Unlock::Key(secret.as_bytes()),
        )
        .map_err(translate)
    }

    /// Opens the vault and hands back the **authenticated** context alongside
    /// the plaintext.
    ///
    /// For the one flow where the expected context cannot be known beforehand:
    /// the gateway's own WireGuard public key is derived from the private key
    /// this very vault holds, so it cannot be supplied before opening. The
    /// caller derives it from the recovered secret and compares — which is
    /// sound because the context is covered by the AEAD, so a successful open
    /// already proves nobody rewrote it.
    ///
    /// A legacy `HKS1` vault has no context and yields an empty one.
    pub fn load_declared(&self, secret: &SecretKey) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        if self.is_legacy()? {
            return Ok((Vec::new(), self.load_legacy_file(secret)?));
        }
        let blob = self.read_bounded()?;
        let context = aether_vault::peek_context(&blob).map_err(translate)?;
        let plaintext = aether_vault::open(
            self.domain,
            &rebuild(&context),
            &aether_vault::Unlock::Key(secret.as_bytes()),
            &blob,
        )
        .map_err(translate)?;
        Ok((context, plaintext))
    }

    /// Peeks at the magic without reading the whole file.
    fn is_legacy(&self) -> Result<bool> {
        use std::io::Read as _;
        let mut head = [0u8; 4];
        let mut file = std::fs::File::open(&self.path).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })?;
        match file.read_exact(&mut head) {
            Ok(()) => Ok(&head == LEGACY_MAGIC),
            // Too short to be either format: let the parser produce the error.
            Err(_) => Ok(false),
        }
    }

    fn read_bounded(&self) -> Result<Vec<u8>> {
        use std::io::Read as _;
        let io = |e: std::io::Error| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        };
        let metadata = std::fs::metadata(&self.path).map_err(io)?;
        if metadata.len() > aether_vault::MAX_VAULT_BYTES as u64 {
            return Err(KeystoreError::Format("vault over the size bound".into()).into());
        }
        let mut blob = Vec::new();
        std::fs::File::open(&self.path)
            .map_err(io)?
            .take(aether_vault::MAX_VAULT_BYTES as u64 + 1)
            .read_to_end(&mut blob)
            .map_err(io)?;
        if blob.len() > aether_vault::MAX_VAULT_BYTES {
            return Err(KeystoreError::Format("vault over the size bound".into()).into());
        }
        Ok(blob)
    }

    fn load_legacy_file(&self, secret: &SecretKey) -> Result<Zeroizing<Vec<u8>>> {
        load_legacy(secret, &self.read_bounded()?)
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
            aether::private_file::create_private_dir(parent).map_err(|e| TpmError::Io {
                path: parent.display().to_string(),
                cause: e.to_string(),
            })?;
        }
        // Same defect as the two configuration writers had: a plain write left
        // the temporary file at the umask, and the `rename` carried that mode
        // onto the vault. Ciphertext rather than plaintext, so the exposure was
        // smaller — but a vault whose mode drifts is exactly what nobody
        // notices (ADR-006).
        aether::private_file::write_private_atomic(&self.path, blob).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })
    }
}

/// Maps a container error onto the vault's own vocabulary.
///
/// `Undecipherable` is kept distinct because the caller acts on it: it is the
/// signature of a resealing that lost the old secret, and the trigger for the
/// escrow recovery path.
fn translate(error: aether_vault::VaultError) -> TpmError {
    match error {
        aether_vault::VaultError::Undecipherable => KeystoreError::Undecipherable.into(),
        other => KeystoreError::Format(other.to_string()).into(),
    }
}

/// Hands a peeked context back to the AEAD, which is what authenticates it.
fn rebuild(context: &[u8]) -> Context {
    Context::from_encoded(context.to_vec())
}

/// Reads the legacy `HKS1` container.
///
/// Kept read-only and deliberately untouched: it exists to let an existing
/// gateway keep its identity across the update, not to be extended.
fn load_legacy(secret: &SecretKey, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < LEGACY_HEADER_LEN {
        return Err(KeystoreError::Format("truncated vault".into()).into());
    }
    if blob[4] != LEGACY_VERSION {
        return Err(KeystoreError::Format(format!("unsupported version {}", blob[4])).into());
    }
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[5..LEGACY_HEADER_LEN]);

    let key = aead_key(secret)?;
    // `Zeroizing` **before** the AEAD call, not after it. `open_in_place`
    // decrypts into the very buffer it is given: copying the plaintext into a
    // second `Vec` and dropping the first would leave the secret in a freed,
    // unwiped allocation — the pattern ADR-006 §5 forbids by name.
    let mut in_out = Zeroizing::new(blob[LEGACY_HEADER_LEN..].to_vec());
    let length = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(LEGACY_AAD),
            in_out.as_mut(),
        )
        .map_err(|_| KeystoreError::Undecipherable)?
        .len();
    // Truncating keeps the plaintext inside the same wiped allocation; the
    // tag bytes past `length` are already zeroed by the drop that follows.
    in_out.truncate(length);
    tracing::info!(
        "legacy HKS1 vault read — it will be rewritten in the HVLT format on the next store"
    );
    Ok(in_out)
}

/// Builds the AEAD key from the unsealed secret — **legacy path only**.
///
/// The current format derives it inside `aether-vault`; this remains for
/// reading an `HKS1` vault written before the migration.
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

    /// Object context of the gateway identity vault (ADR-006 §2).
    fn ctx() -> Context {
        Context::new().field("wg_public_key", b"cle-publique-de-test")
    }

    fn secret(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 32])
    }

    /// Writes a vault in the **legacy** `HKS1` format, exactly as a gateway
    /// installed before the migration holds it on disk.
    fn write_legacy_vault(path: &Path, secret: &SecretKey, plaintext: &[u8]) {
        use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes).unwrap();
        let key = aead_key(secret).unwrap();
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(LEGACY_AAD),
            &mut in_out,
        )
        .unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(LEGACY_MAGIC);
        blob.push(LEGACY_VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);
        std::fs::write(path, blob).unwrap();
    }

    /// A gateway updating in place must not lose its identity.
    ///
    /// The vault holds the gateway's **only** WireGuard private key. Refusing
    /// to read the old container would turn a routine update into a loss of
    /// identity whose sole recovery channel is the escrow — and the escrow is
    /// precisely what an operator discovers they never configured, on that day.
    #[test]
    fn a_legacy_hks1_vault_is_still_readable() {
        let path = tmp_path("legacy-read");
        let wg_key = b"une-cle-privee-wireguard-32-oct!";
        write_legacy_vault(&path, &secret(1), wg_key);

        let ks = SealedKeystore::new(&path, DOMAIN_GATEWAY_WG_KEY);
        let out = ks
            .load(&secret(1), &ctx())
            .expect("the legacy vault must stay readable");
        assert_eq!(out.as_slice(), wg_key);
        ks.remove().unwrap();
    }

    /// The legacy path must not become a way around authentication.
    #[test]
    fn a_legacy_vault_still_refuses_the_wrong_secret() {
        let path = tmp_path("legacy-wrong");
        write_legacy_vault(&path, &secret(1), b"secret");

        let ks = SealedKeystore::new(&path, DOMAIN_GATEWAY_WG_KEY);
        assert!(matches!(
            ks.load(&secret(2), &ctx()),
            Err(TpmError::Keystore(KeystoreError::Undecipherable))
        ));
        ks.remove().unwrap();
    }

    /// Reading an old vault then storing again must produce the **new**
    /// format: the migration has to actually happen, not stall forever on a
    /// compatibility path.
    #[test]
    fn storing_after_a_legacy_read_rewrites_in_the_new_format() {
        let path = tmp_path("legacy-upgrade");
        let wg_key = b"une-cle-privee-wireguard-32-oct!";
        write_legacy_vault(&path, &secret(1), wg_key);

        let ks = SealedKeystore::new(&path, DOMAIN_GATEWAY_WG_KEY);
        let recovered = ks.load(&secret(1), &ctx()).unwrap();
        ks.store(&secret(1), &ctx(), recovered.as_slice()).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.starts_with(LEGACY_MAGIC),
            "the vault stayed in the legacy format"
        );
        assert_eq!(ks.load(&secret(1), &ctx()).unwrap().as_slice(), wg_key);
        ks.remove().unwrap();
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let ks = SealedKeystore::new(tmp_path("roundtrip"), DOMAIN_GATEWAY_WG_KEY);
        let wg_key = b"une-cle-privee-wireguard-32-oct!";

        ks.store(&secret(1), &ctx(), wg_key).unwrap();
        assert!(ks.exists());

        let out = ks.load(&secret(1), &ctx()).unwrap();
        assert_eq!(out.as_slice(), wg_key);
        ks.remove().unwrap();
    }

    /// The heart of the protection: without the right secret — hence
    /// without a successful TPM unseal — the content stays inaccessible.
    #[test]
    fn a_wrong_secret_does_not_decrypt() {
        let ks = SealedKeystore::new(tmp_path("wrongkey"), DOMAIN_GATEWAY_WG_KEY);
        ks.store(&secret(1), &ctx(), b"secret").unwrap();

        let err = ks.load(&secret(2), &ctx());
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
        let ks = SealedKeystore::new(&path, DOMAIN_GATEWAY_WG_KEY);
        ks.store(&secret(1), &ctx(), b"secret").unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(&path, &blob).unwrap();

        assert!(
            ks.load(&secret(1), &ctx()).is_err(),
            "tampering must be detected"
        );
        ks.remove().unwrap();
    }

    #[test]
    fn two_writes_of_the_same_content_differ() {
        let ks = SealedKeystore::new(tmp_path("nonce"), DOMAIN_GATEWAY_WG_KEY);
        ks.store(&secret(1), &ctx(), b"secret").unwrap();
        let first = std::fs::read(ks.path()).unwrap();
        ks.store(&secret(1), &ctx(), b"secret").unwrap();
        let second = std::fs::read(ks.path()).unwrap();
        assert_ne!(first, second, "the nonce must be fresh on each write");
        ks.remove().unwrap();
    }

    #[test]
    fn invalid_formats_are_rejected() {
        let path = tmp_path("badformat");
        let ks = SealedKeystore::new(&path, DOMAIN_GATEWAY_WG_KEY);

        std::fs::write(&path, b"xx").unwrap();
        assert!(ks.load(&secret(1), &ctx()).is_err(), "too short");

        std::fs::write(&path, b"NOPE\x01aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1), &ctx()).is_err(), "wrong magic");

        std::fs::write(&path, b"HKS1\x09aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1), &ctx()).is_err(), "unknown version");

        ks.remove().unwrap();
    }

    #[test]
    fn removal_is_idempotent() {
        let ks = SealedKeystore::new(tmp_path("gone"), DOMAIN_GATEWAY_WG_KEY);
        ks.remove().unwrap();
        ks.remove().unwrap();
        assert!(!ks.exists());
    }
}
