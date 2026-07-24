use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, TpmError};

/// 256-bit unlock secret unsealed by the TPM.
///
/// Wiped from memory on drop (`ZeroizeOnDrop`). Used to decrypt the
/// WireGuard secrets; never log it (`Debug` is masked).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Generates a random secret via the OS CSPRNG (provisioning / resealing).
    pub(crate) fn generate() -> Result<Self> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| TpmError::Rng(e.to_string()))?;
        Ok(Self(buf))
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes of the secret — used to feed decryption of the credentials.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(***)")
    }
}
