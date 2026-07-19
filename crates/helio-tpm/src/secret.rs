use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, TpmError};

/// Secret de déverrouillage 256 bits descellé par le TPM.
///
/// Effacé de la mémoire à la destruction (`ZeroizeOnDrop`). Sert à déchiffrer les
/// secrets WireGuard ; ne jamais le journaliser (le `Debug` est masqué).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Génère un secret aléatoire via le CSPRNG de l'OS (provisionnement / rescellement).
    pub(crate) fn generate() -> Result<Self> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| TpmError::Rng(e.to_string()))?;
        Ok(Self(buf))
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Octets bruts du secret — pour alimenter le déchiffrement des identifiants.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(***)")
    }
}
