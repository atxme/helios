use std::sync::Once;

use aether::sig::{
    PublisherPublicKeys, SignedResealTicket, PUBLISHER_KEYS, USING_DEVELOPMENT_PUBLISHER_KEYS,
};

use crate::{Result, TpmError};

/// Billet v2 : enveloppe hybride Ed25519 + ML-DSA-65, sans compatibilité v1.
pub(crate) struct ResealTicket {
    envelope: SignedResealTicket,
}

impl ResealTicket {
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self> {
        let envelope = serde_json::from_slice(bytes).map_err(|e| TpmError::Serde(e.to_string()))?;
        Ok(Self { envelope })
    }

    pub(crate) const fn version(&self) -> u64 {
        self.envelope.payload.version
    }

    /// Vérifie l'hybride AND, l'époque signée, l'anti-rejeu puis la liaison PCR optionnelle.
    pub(crate) fn verify(&self, current_version: u64, current_pcr: &[u8; 32]) -> Result<()> {
        if USING_DEVELOPMENT_PUBLISHER_KEYS {
            static WARN_ONCE: Once = Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "trousseau éditeur de DÉVELOPPEMENT utilisé pour les billets TPM — \
                     fournir HELIOS_PUBLISHER_KEYRING_PATH au build de production"
                );
            });
        }
        self.verify_with_keyring(PUBLISHER_KEYS, current_version, current_pcr)
    }

    fn verify_with_keyring(
        &self,
        keyring: &[PublisherPublicKeys],
        current_version: u64,
        current_pcr: &[u8; 32],
    ) -> Result<()> {
        self.envelope
            .verify(keyring)
            .map_err(|_| TpmError::TicketInvalidSignature)?;

        let payload = &self.envelope.payload;
        if payload.version <= current_version {
            return Err(TpmError::TicketRollback {
                ticket: payload.version,
                current: current_version,
            });
        }
        if let Some(expected) = payload.expected_pcr_digest {
            if expected != *current_pcr {
                return Err(TpmError::TicketPcrMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aether::sig::{PublisherSigner, ResealPayload};

    use super::*;

    const ED_SEED: [u8; 32] = *b"helios-sign-ed25519-test-seed001";
    const ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-test-seed001";

    fn sign_ticket(
        version: u64,
        expected_pcr_digest: Option<[u8; 32]>,
    ) -> (ResealTicket, PublisherPublicKeys) {
        let signer = PublisherSigner::from_seed_material(7, &ED_SEED, &ML_SEED).unwrap();
        let public_keys = signer.public_keys();
        let envelope = signer
            .sign(ResealPayload {
                version,
                expected_pcr_digest,
            })
            .unwrap();
        (ResealTicket { envelope }, public_keys)
    }

    #[test]
    fn billet_hybride_valide_accepte() {
        let (ticket, keys) = sign_ticket(1, None);
        assert!(ticket.verify_with_keyring(&[keys], 0, &[0u8; 32]).is_ok());
    }

    #[test]
    fn signature_ed25519_invalide_rejetee() {
        let (mut ticket, keys) = sign_ticket(1, None);
        ticket.envelope.signatures[0].sig.push('A');
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 0, &[0u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn signature_ml_dsa_absente_rejetee() {
        let (mut ticket, keys) = sign_ticket(1, None);
        ticket
            .envelope
            .signatures
            .retain(|signature| signature.alg != "ml-dsa-65");
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 0, &[0u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn rollback_rejete() {
        let (ticket, keys) = sign_ticket(3, None);
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 3, &[0u8; 32]),
            Err(TpmError::TicketRollback {
                ticket: 3,
                current: 3
            })
        ));
    }

    #[test]
    fn liaison_pcr_optionnelle_et_incoherence_rejetee() {
        let (sans_pcr, keys) = sign_ticket(1, None);
        assert!(sans_pcr
            .verify_with_keyring(&[keys], 0, &[99u8; 32])
            .is_ok());

        let (avec_pcr, keys) = sign_ticket(1, Some([1u8; 32]));
        assert!(matches!(
            avec_pcr.verify_with_keyring(&[keys], 0, &[2u8; 32]),
            Err(TpmError::TicketPcrMismatch)
        ));
        assert!(avec_pcr.verify_with_keyring(&[keys], 0, &[1u8; 32]).is_ok());
    }

    #[test]
    fn ancien_format_v1_refuse_sans_fallback() {
        let old = br#"{"version":1,"expected_pcr_digest":null,"signature":"00"}"#;
        assert!(matches!(
            ResealTicket::from_json(old),
            Err(TpmError::Serde(_))
        ));
    }

    #[test]
    fn signature_est_verifiee_avant_anti_rollback_et_pcr() {
        let (mut ticket, keys) = sign_ticket(1, Some([1u8; 32]));
        ticket.envelope.signatures.clear();

        // Une enveloppe forgée ne doit pas servir d'oracle permettant de
        // distinguer compteur et PCR avant authentification de l'éditeur.
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 99, &[2u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn json_refuse_digest_pcr_malforme_et_champs_inconnus() {
        let malformed = br#"{"payload":{"version":1,"expected_pcr_digest":"abcd"},"key_epoch":1,"signatures":[]}"#;
        assert!(matches!(
            ResealTicket::from_json(malformed),
            Err(TpmError::Serde(_))
        ));

        let unknown = br#"{"payload":{"version":1,"expected_pcr_digest":null,"bypass":true},"key_epoch":1,"signatures":[]}"#;
        assert!(matches!(
            ResealTicket::from_json(unknown),
            Err(TpmError::Serde(_))
        ));
    }
}
