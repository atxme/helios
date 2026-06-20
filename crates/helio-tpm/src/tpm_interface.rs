use crate::{secret::SecretKey, Result};

/// Blob scellé opaque, tel que stocké sur la partition de configuration.
#[derive(Debug, Clone)]
pub(crate) struct SealedBlob(pub Vec<u8>);

impl SealedBlob {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Primitives de scellement exposées par le TPM (réel ou simulé).
///
/// Les index/banque PCR sont portés par l'implémentation (depuis la config), pas
/// passés à `seal` : le scellement et le déscellement restent ainsi cohérents.
pub(crate) trait TpmSealer {
    /// Empreinte d'identité de l'état PCR courant (sert à lier le billet de rescellement).
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]>;
    /// Scelle `secret` contre la politique PCR courante ; renvoie le blob à persister.
    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob>;
    /// Tente de desceller le blob ; `UnsealPolicyFail` si les PCR ont changé.
    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey>;
}

// ───────────────────────── Backend simulé (WSL2 / dev) ─────────────────────────

/// TPM simulé : reproduit fidèlement la sémantique de liaison aux PCR sans matériel.
///
/// `seal` enregistre l'empreinte PCR courante dans le blob ; `unseal` ne rend le
/// secret que si l'empreinte courante est identique. Modifier `pcr_digest` entre
/// deux instances simule un changement de kernel/bootloader (OTA ou attaque).
///
/// **Non sécurisé** (le secret est en clair dans le blob) — réservé au dev/tests.
/// Compilé hors `feature tpm` (backend par défaut) et pour les tests.
#[cfg(any(not(feature = "tpm"), test))]
pub(crate) struct DryRunTpm {
    pcr_digest: [u8; 32],
}

#[cfg(any(not(feature = "tpm"), test))]
impl DryRunTpm {
    /// Construit depuis l'environnement : `HELIOS_TPM_FAKE_PCR` (hex 32 octets) ou zéros.
    pub(crate) fn from_env() -> Self {
        let pcr_digest = std::env::var("HELIOS_TPM_FAKE_PCR")
            .ok()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0u8; 32]);
        tracing::warn!(
            "TPM simulé (feature 'tpm' non compilée) — AUCUNE garantie matérielle. \
             Recompiler avec --features tpm sur la cible."
        );
        Self { pcr_digest }
    }

    #[cfg(test)]
    pub(crate) fn with_digest(pcr_digest: [u8; 32]) -> Self {
        Self { pcr_digest }
    }
}

#[cfg(any(not(feature = "tpm"), test))]
impl TpmSealer for DryRunTpm {
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.pcr_digest)
    }

    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob> {
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&self.pcr_digest);
        blob.extend_from_slice(secret.as_bytes());
        Ok(SealedBlob::from_bytes(blob))
    }

    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey> {
        let bytes = blob.as_bytes();
        if bytes.len() != 64 {
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        let bound = &bytes[..32];
        if bound != self.pcr_digest {
            // PCR courants différents de ceux du scellement → le TPM refuserait.
            return Err(crate::TpmError::UnsealPolicyFail);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[32..]);
        Ok(SecretKey::from_bytes(key))
    }
}

// ───────────────────────── Backend réel (cible, feature tpm) ─────────────────────────
//
// L'implémentation TPM2 réelle (scellement/déscellement durcis, sessions chiffrées)
// vit dans `tpm_real.rs` pour garder ce fichier lisible. Réexportée ici pour que
// `boot_controller` conserve le chemin `crate::tpm_interface::TpmDevice`.
#[cfg(feature = "tpm")]
pub(crate) use crate::tpm_real::TpmDevice;
