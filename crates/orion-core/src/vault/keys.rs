//! Orion's key hierarchy ([ADR-006](../../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §3).
//!
//! ```text
//!                     CSPRNG
//!                       │
//!                       ▼
//!             device_root_key[32]
//!                       │
//!          enveloppe TPM obligatoire
//!        RSA-OAEP-SHA-256, clé non exportable
//!                       │
//!                       ▼
//!        DPAPI-utilisateur(blob_TPM + métadonnées)
//!
//! registre : HKDF(device_root_key, info = "orion/registry/v1")
//! profil   : profile_root_key = HKDF(device_root_key,
//!                                    salt = profile_id,
//!                                    info = "orion/profile-root/v1")
//! ```
//!
//! # A conjunction, never a list of recovery paths
//!
//! The wrapping layers are **and**, not **or**. This is the ambiguity the first
//! revision of the ADR left open and the amendment closed: **DPAPI does not
//! recover a lost TPM**. If the TPM is reset, replaced or invalidated by a
//! firmware update, the installation root is gone and profiles must be
//! re-enrolled. An alternative DPAPI envelope of the root key would have undone
//! the hardware binding, so it is forbidden — not merely absent.
//!
//! # Separation between profiles
//!
//! Deriving with a distinct `info` per use, and per-profile with `profile_id`
//! as salt, means knowing one profile's DEK yields nothing about the root, the
//! registry or another profile. Without that, a single compromised profile
//! would hand over the whole installation.

use aws_lc_rs::hkdf;
use zeroize::Zeroizing;

use super::{ProfileId, VaultError};

/// Length of every key in this hierarchy.
pub const KEY_LEN: usize = 32;

/// HKDF label of the registry key.
const REGISTRY_INFO: &[u8] = b"orion/registry/v1";
/// HKDF label of a profile root key.
const PROFILE_ROOT_INFO: &[u8] = b"orion/profile-root/v1";

/// Installation root, tirée une fois au CSPRNG.
///
/// Never `Clone`, never `Debug`, never serialized: ADR-006 §5 puts the rule on
/// the **type** before it puts it on `Drop`, because a copy already made cannot
/// be zeroized.
pub struct DeviceRootKey(Zeroizing<[u8; KEY_LEN]>);

impl DeviceRootKey {
    /// Draws a new installation root.
    pub fn generate() -> Result<Self, VaultError> {
        use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        SystemRandom::new()
            .fill(key.as_mut())
            .map_err(|_| VaultError::Rng)?;
        Ok(Self(key))
    }

    /// Rebuilds the root from bytes an unwrapping layer returned.
    pub fn from_unwrapped(key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(key)
    }

    /// Exposes the raw root so a wrapping layer can seal it.
    ///
    /// The only legitimate caller is the platform provider on its way to the
    /// TPM. Named explicitly so every use is a point to justify in review.
    pub fn expose_for_wrapping(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Key protecting the registry.
    pub fn registry_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        // Empty salt: the registry is unique per installation, so there is
        // nothing to separate it from. The `info` carries the separation.
        self.derive(&[], REGISTRY_INFO)
    }

    /// Root key of one profile, separated by its identifier.
    pub fn profile_root_key(
        &self,
        profile: ProfileId,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        self.derive(profile.as_bytes(), PROFILE_ROOT_INFO)
    }

    fn derive(&self, salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(self.0.as_ref());
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .map_err(|_| VaultError::Derive)?
            .fill(out.as_mut())
            .map_err(|_| VaultError::Derive)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> DeviceRootKey {
        DeviceRootKey::from_unwrapped(Zeroizing::new([3u8; KEY_LEN]))
    }

    #[test]
    fn derivation_is_deterministic() {
        let id = ProfileId::from_bytes([9u8; 16]);
        assert_eq!(
            root().profile_root_key(id).unwrap().as_ref(),
            root().profile_root_key(id).unwrap().as_ref()
        );
    }

    /// The property the whole hierarchy exists for: one compromised profile
    /// must not hand over another, nor the registry.
    #[test]
    fn every_use_gets_an_independent_key() {
        let root = root();
        let alice = root
            .profile_root_key(ProfileId::from_bytes([1u8; 16]))
            .unwrap();
        let bob = root
            .profile_root_key(ProfileId::from_bytes([2u8; 16]))
            .unwrap();
        let registry = root.registry_key().unwrap();

        assert_ne!(alice.as_ref(), bob.as_ref());
        assert_ne!(alice.as_ref(), registry.as_ref());
        assert_ne!(bob.as_ref(), registry.as_ref());
        // And none of them is the root itself.
        assert_ne!(alice.as_ref(), root.expose_for_wrapping());
        assert_ne!(registry.as_ref(), root.expose_for_wrapping());
    }

    #[test]
    fn two_installations_share_nothing() {
        let a = DeviceRootKey::generate().unwrap();
        let b = DeviceRootKey::generate().unwrap();
        let id = ProfileId::from_bytes([7u8; 16]);
        assert_ne!(
            a.profile_root_key(id).unwrap().as_ref(),
            b.profile_root_key(id).unwrap().as_ref()
        );
    }

    /// Pins the derivation against an **independent** HKDF implementation.
    ///
    /// A self-consistency test would pass just as well if the `info`, the hash
    /// or the salt changed — derive and re-derive would simply agree. These
    /// vectors come from RFC 5869 HKDF-SHA-256 computed outside this crate, so
    /// a silent change of any input fails here rather than turning every
    /// existing profile unreadable after an update.
    #[test]
    fn derivations_match_their_reference_vectors() {
        let hex = |value: &str| {
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
                .collect::<Vec<u8>>()
        };

        assert_eq!(
            root().registry_key().unwrap().as_ref(),
            hex("c52d0655de2f970e5b3a78c8e3b6aecfbc22b1d29a9c38e7d9881af0207baf7f").as_slice(),
            "the registry derivation changed — every existing installation would lose its registry"
        );
        assert_eq!(
            root()
                .profile_root_key(ProfileId::from_bytes([9u8; 16]))
                .unwrap()
                .as_ref(),
            hex("73eccd4875ac03f77fbba43e8df5f2dfb6ce420833663d685ba7f182f322069d").as_slice(),
            "the profile derivation changed — every existing profile would stop opening"
        );
    }
}
