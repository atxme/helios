use std::sync::OnceLock;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{Result, TpmError};

/// Séparation de domaine : préfixe les octets signés pour éviter toute confusion
/// avec une autre signature de l'éditeur.
const TICKET_DOMAIN: &[u8] = b"helios-tpm-reseal-v1";

/// Graine de la clé de **développement** (la clé publique dérivée est utilisée si
/// `HELIOS_TPM_VENDOR_PUBKEY_HEX` n'est pas fourni au build). **AUCUNE sécurité** :
/// la clé privée correspondante est publique. Fournir la vraie clé en production.
#[cfg(any(test, debug_assertions))]
pub(crate) const DEV_VENDOR_SEED: [u8; 32] = *b"helios-dev-vendor-seed-000000001";

/// Clé publique Ed25519 de l'éditeur, résolue une fois.
///
/// Priorité à `HELIOS_TPM_VENDOR_PUBKEY_HEX` (injectée au build de production) ;
/// sinon, clé de développement dérivée de [`DEV_VENDOR_SEED`].
fn vendor_public_key() -> &'static VerifyingKey {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    KEY.get_or_init(|| {
        if let Some(hex_str) = option_env!("HELIOS_TPM_VENDOR_PUBKEY_HEX") {
            let bytes = hex::decode(hex_str).expect("HELIOS_TPM_VENDOR_PUBKEY_HEX : hex invalide");
            let arr: [u8; 32] = bytes
                .try_into()
                .expect("HELIOS_TPM_VENDOR_PUBKEY_HEX : 32 octets attendus");
            VerifyingKey::from_bytes(&arr).expect("clé publique Ed25519 invalide")
        } else {
            #[cfg(any(test, debug_assertions))]
            {
                tracing::warn!(
                    "clé éditeur de DÉVELOPPEMENT utilisée pour les billets TPM — \
                     fournir HELIOS_TPM_VENDOR_PUBKEY_HEX au build de production"
                );
                ed25519_dalek::SigningKey::from_bytes(&DEV_VENDOR_SEED).verifying_key()
            }
            #[cfg(not(any(test, debug_assertions)))]
            {
                panic!(
                    "HELIOS_TPM_VENDOR_PUBKEY_HEX doit être fournie au build release \
                     (pas de clé éditeur embarquée)"
                );
            }
        }
    })
}

/// Construit les octets canoniques signés par l'éditeur.
fn signing_bytes(version: u64, expected_pcr_digest: &Option<[u8; 32]>) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TICKET_DOMAIN.len() + 1 + 8 + 32);
    msg.extend_from_slice(TICKET_DOMAIN);
    msg.extend_from_slice(&version.to_le_bytes());
    match expected_pcr_digest {
        Some(d) => {
            msg.push(1);
            msg.extend_from_slice(d);
        }
        None => msg.push(0),
    }
    msg
}

/// Billet d'autorisation de rescellement, émis et signé par l'éditeur, livré avec l'OTA.
pub(crate) struct ResealTicket {
    /// Version monotone — strictement croissante (anti-rejeu/anti-rollback).
    pub version: u64,
    /// Durcissement optionnel : lie l'autorisation à un état PCR précis.
    /// Si présent, le rescellement n'est permis que si l'état courant correspond.
    pub expected_pcr_digest: Option<[u8; 32]>,
    /// Signature Ed25519 (64 octets) des octets canoniques.
    pub signature: [u8; 64],
}

/// Représentation disque (JSON inspectable) du billet.
#[derive(Serialize, Deserialize)]
struct TicketWire {
    version: u64,
    #[serde(default)]
    expected_pcr_digest: Option<String>,
    signature: String,
}

impl ResealTicket {
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self> {
        let wire: TicketWire =
            serde_json::from_slice(bytes).map_err(|e| TpmError::Serde(e.to_string()))?;
        let signature: [u8; 64] = hex::decode(&wire.signature)
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v).ok())
            .ok_or(TpmError::TicketInvalidSignature)?;
        let expected_pcr_digest = match wire.expected_pcr_digest {
            Some(h) => Some(
                hex::decode(&h)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    .ok_or_else(|| TpmError::Serde("expected_pcr_digest hex invalide".into()))?,
            ),
            None => None,
        };
        Ok(Self {
            version: wire.version,
            expected_pcr_digest,
            signature,
        })
    }

    /// Vérifie le billet : signature de l'éditeur, anti-rejeu, liaison PCR optionnelle.
    pub(crate) fn verify(&self, current_version: u64, current_pcr: &[u8; 32]) -> Result<()> {
        self.verify_with_key(vendor_public_key(), current_version, current_pcr)
    }

    /// Variante testable avec une clé arbitraire (l'API publique fige la clé éditeur).
    fn verify_with_key(
        &self,
        vk: &VerifyingKey,
        current_version: u64,
        current_pcr: &[u8; 32],
    ) -> Result<()> {
        let msg = signing_bytes(self.version, &self.expected_pcr_digest);
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| TpmError::TicketInvalidSignature)?;
        vk.verify_strict(&msg, &sig)
            .map_err(|_| TpmError::TicketInvalidSignature)?;

        if self.version <= current_version {
            return Err(TpmError::TicketRollback {
                ticket: self.version,
                current: current_version,
            });
        }
        if let Some(expected) = &self.expected_pcr_digest {
            if expected != current_pcr {
                return Err(TpmError::TicketPcrMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn sign_ticket(
        seed: &[u8; 32],
        version: u64,
        expected_pcr_digest: Option<[u8; 32]>,
    ) -> ResealTicket {
        let sk = SigningKey::from_bytes(seed);
        let msg = signing_bytes(version, &expected_pcr_digest);
        let sig = sk.sign(&msg);
        ResealTicket {
            version,
            expected_pcr_digest,
            signature: sig.to_bytes(),
        }
    }

    #[test]
    fn billet_valide_accepte() {
        let sk = SigningKey::from_bytes(&DEV_VENDOR_SEED);
        let t = sign_ticket(&DEV_VENDOR_SEED, 1, None);
        assert!(t.verify_with_key(&sk.verifying_key(), 0, &[0u8; 32]).is_ok());
    }

    #[test]
    fn signature_invalide_rejetee() {
        // Signé par une autre clé que celle de vérification.
        let other = [9u8; 32];
        let t = sign_ticket(&other, 1, None);
        let vk = SigningKey::from_bytes(&DEV_VENDOR_SEED).verifying_key();
        assert!(matches!(
            t.verify_with_key(&vk, 0, &[0u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn rollback_rejete() {
        let vk = SigningKey::from_bytes(&DEV_VENDOR_SEED).verifying_key();
        let t = sign_ticket(&DEV_VENDOR_SEED, 3, None);
        // version courante déjà 3 → rejet.
        assert!(matches!(
            t.verify_with_key(&vk, 3, &[0u8; 32]),
            Err(TpmError::TicketRollback { ticket: 3, current: 3 })
        ));
    }

    #[test]
    fn liaison_pcr_incoherente_rejetee() {
        let vk = SigningKey::from_bytes(&DEV_VENDOR_SEED).verifying_key();
        let t = sign_ticket(&DEV_VENDOR_SEED, 1, Some([1u8; 32]));
        assert!(matches!(
            t.verify_with_key(&vk, 0, &[2u8; 32]),
            Err(TpmError::TicketPcrMismatch)
        ));
        // état courant conforme → accepté.
        assert!(t.verify_with_key(&vk, 0, &[1u8; 32]).is_ok());
    }
}
