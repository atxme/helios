//! Post-quantum key exchange (ML-KEM-1024, FIPS 203), shared by Helios and Orion.
//!
//! This module mounts nothing: it only produces a 32-byte shared secret through
//! one ML-KEM encapsulation. That secret feeds WireGuard's `PresharedKey` slot
//! (see ADR-001, §2). The KEM lives in `aether`, not in `helios-provisioning`,
//! because both ends use it: Orion encapsulates to Helios' public key, Helios
//! decapsulates. Placing it on the gateway side would force `orion-core` to
//! depend on a `helios-*` crate.
//!
//! The concrete backend is `aws-lc-rs` (AWS-LC) built **without** the `fips`
//! feature: statically linked, `cc`-based, no CMake/Go/Ninja/bindgen toolchain.
//! ML-KEM-1024 lives in the standard `kem` API, not behind FIPS. The `Kem` trait
//! keeps the backend swappable: enabling aws-lc-rs' `fips` feature later (FIPS
//! 140-3 validation) needs no change here.

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use zeroize::Zeroizing;

/// A 32-byte shared secret from an ML-KEM encapsulation, zeroized on drop.
///
/// This is the raw material for the WireGuard `PresharedKey`. ML-KEM-1024
/// outputs a uniform 32-byte secret whatever the parameter set — the secret
/// size does not grow with the security category, only the key and ciphertext
/// do.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// Length in bytes of an ML-KEM-1024 encapsulation (public) key.
pub const PUBLIC_KEY_LEN: usize = 1568;
/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const CIPHERTEXT_LEN: usize = 1568;
/// Length in bytes of the shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Errors from the post-quantum exchange.
#[derive(Debug, thiserror::Error)]
pub enum PqError {
    /// Public-key bytes of invalid length or shape.
    #[error("invalid ML-KEM public key")]
    BadPublicKey,
    /// Keypair generation failed in the backend.
    #[error("ML-KEM key generation failed")]
    KeyGen,
    /// Encapsulation failed in the backend.
    #[error("ML-KEM encapsulation failed")]
    Encapsulation,
    /// The ciphertext could not be decapsulated (corrupt, wrong key).
    #[error("ML-KEM decapsulation failed")]
    Decapsulation,
}

/// Post-quantum key exchange abstraction.
///
/// Two asymmetric roles: the **recipient** (Helios) generates a keypair and
/// publishes its public key; the **sender** (Orion) encapsulates to that key,
/// obtaining the secret plus a ciphertext to send back; the recipient
/// decapsulates the ciphertext and recovers the same secret.
pub trait Kem {
    /// Decapsulation (private) key, held by the recipient.
    type SecretKey;

    /// Generates a `(private key, encoded public key)` pair on the recipient side.
    fn generate() -> Result<(Self::SecretKey, Vec<u8>), PqError>;

    /// Encapsulates to `public_key` (sender). Returns `(ciphertext, secret)`.
    fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), PqError>;

    /// Decapsulates `ciphertext` with the private key (recipient) → same secret.
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, PqError>;
}

/// ML-KEM-1024 implementation backed by `aws-lc-rs` (AWS-LC).
///
/// Parameter set 1024 (NIST category 5) rather than 768 (category 3): the
/// secret it produces becomes a WireGuard PSK that outlives the session by
/// design — it is exactly what a "harvest now, decrypt later" adversary
/// stores. Paying 384 extra bytes of public key and 480 of ciphertext, once
/// per connection, is a poor reason to sit a category lower.
pub struct MlKem1024Kem;

/// Copies a backend secret slice into a zeroizing 32-byte array.
fn to_shared_secret(bytes: &[u8]) -> Result<SharedSecret, PqError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| PqError::Decapsulation)?;
    Ok(Zeroizing::new(arr))
}

impl Kem for MlKem1024Kem {
    type SecretKey = DecapsulationKey<aws_lc_rs::kem::AlgorithmId>;

    fn generate() -> Result<(Self::SecretKey, Vec<u8>), PqError> {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| PqError::KeyGen)?;
        let ek = dk.encapsulation_key().map_err(|_| PqError::KeyGen)?;
        let ek_bytes = ek.key_bytes().map_err(|_| PqError::KeyGen)?;
        Ok((dk, ek_bytes.as_ref().to_vec()))
    }

    fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), PqError> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(PqError::BadPublicKey);
        }
        let ek =
            EncapsulationKey::new(&ML_KEM_1024, public_key).map_err(|_| PqError::BadPublicKey)?;
        let (ciphertext, secret) = ek.encapsulate().map_err(|_| PqError::Encapsulation)?;
        let secret = to_shared_secret(secret.as_ref())?;
        Ok((ciphertext.as_ref().to_vec(), secret))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, PqError> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(PqError::Decapsulation);
        }
        let secret = secret_key
            .decapsulate(Ciphertext::from(ciphertext))
            .map_err(|_| PqError::Decapsulation)?;
        to_shared_secret(secret.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_yields_the_same_secret() {
        // Helios generates its keypair and publishes the public key.
        let (dk, ek_bytes) = MlKem1024Kem::generate().unwrap();
        assert_eq!(ek_bytes.len(), PUBLIC_KEY_LEN);

        // Orion encapsulates to Helios' public key.
        let (ct, secret_orion) = MlKem1024Kem::encapsulate(&ek_bytes).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);

        // Helios decapsulates → same secret on both ends.
        let secret_helios = MlKem1024Kem::decapsulate(&dk, &ct).unwrap();
        assert_eq!(*secret_orion, *secret_helios);
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let err = MlKem1024Kem::encapsulate(&[0u8; 10]);
        assert!(matches!(err, Err(PqError::BadPublicKey)));
    }

    #[test]
    fn malformed_ciphertext_is_rejected() {
        let (dk, _) = MlKem1024Kem::generate().unwrap();
        let err = MlKem1024Kem::decapsulate(&dk, &[0u8; 10]);
        assert!(matches!(err, Err(PqError::Decapsulation)));
    }

    #[test]
    fn two_encapsulations_yield_different_secrets() {
        // KEM property: each encapsulation draws fresh randomness.
        let (_, ek) = MlKem1024Kem::generate().unwrap();
        let (_, s1) = MlKem1024Kem::encapsulate(&ek).unwrap();
        let (_, s2) = MlKem1024Kem::encapsulate(&ek).unwrap();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn wrong_key_fails_to_recover_secret() {
        // A ciphertext for one key decapsulated with another must not match.
        let (_dk_a, ek_a) = MlKem1024Kem::generate().unwrap();
        let (dk_b, _ek_b) = MlKem1024Kem::generate().unwrap();
        let (ct, secret_sender) = MlKem1024Kem::encapsulate(&ek_a).unwrap();
        // ML-KEM decapsulation is implicit-rejection: it returns a secret, but a
        // different one. It must never equal the sender's secret.
        let secret_wrong = MlKem1024Kem::decapsulate(&dk_b, &ct).unwrap();
        assert_ne!(*secret_sender, *secret_wrong);
    }
}
