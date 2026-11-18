//! Passphrase half of the `nomade` profile (ADR-006 §3).
//!
//! The manifest of a `nomade` profile opens only with two secrets: the
//! TPM-derived profile root key and a key derived here from the passphrase.
//! Either one alone is worth nothing, so a stolen disk with the TPM still
//! sealed, or a shoulder-surfed passphrase without the machine, both fail.
//!
//! The passphrase key lives in a [`LockedSecret`]: a fixed-capacity buffer
//! that is wiped on drop and, where the platform allows it, kept out of swap.
//! Failure to lock it is fatal for this profile: a copy the kernel may have
//! written to swap is not one the ADR accepts.

use aether::locked::{LockState, LockedSecret};
use aws_lc_rs::pbkdf2;
use zeroize::Zeroizing;

use super::{passphrase, VaultError};

/// Length of the random salt stored beside the profile manifest.
pub const SALT_LEN: usize = 16;

/// `info` of the nomad derivation: the domain label of the manifest key.
pub const NOMAD_INFO: &[u8] = b"orion/profile-nomade/v1";

/// Length of the derived passphrase key.
const KEY_LEN: usize = 32;

/// Refusal shown when the passphrase buffer cannot be locked in RAM.
const LOCK_REFUSED: &str =
    "verrouillage mémoire refusé : le profil nomade ne peut pas être déverrouillé";

/// The key derived from a passphrase, held in locked memory.
///
/// Not `Clone`, not `Serialize`, not `Display`: it must not be copied out of
/// its buffer or sent anywhere. [`PassphraseKey::with_exposed`] is the only
/// read access, so a platform wrapper can sit around it.
#[derive(Debug)]
pub struct PassphraseKey(LockedSecret);

impl PassphraseKey {
    /// Derives the key from a passphrase typed at connection or creation.
    ///
    /// The passphrase is normalised, not judged: see [`passphrase::normalise`].
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self, VaultError> {
        let mut secret = LockedSecret::with_capacity(KEY_LEN);
        if secret.lock_state() != LockState::Locked {
            return Err(VaultError::MemoryHygiene(LOCK_REFUSED));
        }

        let normalised = passphrase::normalise(passphrase);
        let iterations =
            std::num::NonZeroU32::new(aether_vault::PBKDF2_ITERATIONS).ok_or(VaultError::Derive)?;
        let mut derived = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            iterations,
            salt,
            normalised.as_bytes(),
            derived.as_mut(),
        );
        secret
            .set(derived.as_ref())
            .map_err(|_| VaultError::Derive)?;
        Ok(Self(secret))
    }

    /// Runs `f` on the key bytes. The only read access to the key.
    pub fn with_exposed<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        let bytes: &[u8; KEY_LEN] = self
            .0
            .expose()
            .try_into()
            .expect("a passphrase key is always KEY_LEN bytes");
        f(bytes)
    }
}

/// Draws a fresh salt for a new `nomade` profile.
pub fn new_salt() -> Result<[u8; SALT_LEN], VaultError> {
    let mut salt = [0u8; SALT_LEN];
    aether::random::fill_public(&mut salt).map_err(|_| VaultError::Rng)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProfile;
    use crate::vault::{
        open_manifest, seal_manifest, DeviceRootKey, ManifestKey, ProfileId, ProfileManifest,
        SecurityGeneration,
    };
    use zeroize::Zeroizing;

    const PASSPHRASE: &str = "cheval agrafe batterie correcte orion";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn root() -> DeviceRootKey {
        DeviceRootKey::from_unwrapped(Zeroizing::new([5u8; KEY_LEN]))
    }

    /// A real Curve25519 pair, so the post-open derivation check is exercised.
    fn keypair() -> (String, String) {
        let pair = aether::wg::generate_keypair().expect("keypair");
        (
            pair.private_key.expose().to_string(),
            pair.public_key.clone(),
        )
    }

    fn manifest_for(private_key: &str, gateway_public: &str) -> ProfileManifest {
        let profile = ClientProfile {
            name: "poste".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: private_key.into(),
            peer_public_key: gateway_public.into(),
            ..ClientProfile::default()
        };
        ProfileManifest::from_profile(&profile, SecurityGeneration(1))
    }

    #[test]
    fn the_passphrase_key_matches_its_reference_vector() {
        // hashlib.pbkdf2_hmac('sha512', b'cheval agrafe batterie correcte orion', bytes(range(16)), 600000, 32)
        let key = PassphraseKey::derive(PASSPHRASE, &core::array::from_fn(|i| i as u8)).unwrap();
        key.with_exposed(|bytes| {
            assert_eq!(
                hex(bytes),
                "040228c878145844af777e8ff6f99aa97d22ee190289607864e6785e2ac9d93b"
            )
        });
    }

    #[test]
    fn another_salt_gives_another_key() {
        // Salt bytes(range(1, 17)).
        let key =
            PassphraseKey::derive(PASSPHRASE, &core::array::from_fn(|i| i as u8 + 1)).unwrap();
        key.with_exposed(|bytes| {
            assert_eq!(
                hex(bytes),
                "fbef8869e778136c3d04a0a45dfc148d5ad21085e192faeeae1885817d529e12"
            )
        });
    }

    #[test]
    fn trailing_spaces_and_nfd_derive_the_same_key() {
        let salt = [7u8; SALT_LEN];
        let reference = PassphraseKey::derive("rivière calme montagne bleue vingt", &salt).unwrap();
        let typed =
            PassphraseKey::derive("  rivie\u{0300}re calme montagne bleue vingt  ", &salt).unwrap();
        let reference = reference.with_exposed(|bytes| *bytes);
        typed.with_exposed(|bytes| assert_eq!(bytes, &reference));
    }

    #[test]
    fn a_nomad_manifest_needs_both_the_root_and_the_passphrase() {
        let (private_key, public_key) = keypair();
        let (_, gateway_public) = keypair();
        let id = ProfileId::generate().unwrap();
        let manifest = manifest_for(&private_key, &gateway_public);
        let key = PassphraseKey::derive(PASSPHRASE, &[3u8; SALT_LEN]).unwrap();
        let other_key =
            PassphraseKey::derive("une autre passphrase assez longue", &[3u8; SALT_LEN]).unwrap();

        let blob = seal_manifest(
            &root(),
            id,
            &manifest,
            &public_key,
            ManifestKey::Nomad(&key),
        )
        .expect("seal");

        assert!(open_manifest(
            &root(),
            id,
            &public_key,
            &gateway_public,
            &blob,
            ManifestKey::Service
        )
        .is_err());

        let other_root = DeviceRootKey::from_unwrapped(Zeroizing::new([6u8; KEY_LEN]));
        assert!(open_manifest(
            &other_root,
            id,
            &public_key,
            &gateway_public,
            &blob,
            ManifestKey::Nomad(&key)
        )
        .is_err());

        assert!(matches!(
            open_manifest(
                &root(),
                id,
                &public_key,
                &gateway_public,
                &blob,
                ManifestKey::Nomad(&other_key)
            ),
            Err(VaultError::Container(_))
        ));

        let opened = open_manifest(
            &root(),
            id,
            &public_key,
            &gateway_public,
            &blob,
            ManifestKey::Nomad(&key),
        )
        .expect("open with root and passphrase");
        assert_eq!(opened.private_key.expose(), private_key);
        assert_eq!(opened.generation, SecurityGeneration(1));
    }

    #[test]
    fn fresh_salts_differ() {
        let first = new_salt().unwrap();
        let second = new_salt().unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; SALT_LEN]);
    }

    #[test]
    fn the_debug_output_names_no_byte() {
        let key = PassphraseKey::derive(PASSPHRASE, &[9u8; SALT_LEN]).unwrap();
        let rendered = format!("{key:?}");
        key.with_exposed(|bytes| assert!(!rendered.contains(&hex(bytes))));
    }
}
