use std::sync::Once;

use aether::sig::{
    PublisherPublicKeys, SignedResealTicket, PUBLISHER_KEYS, USING_DEVELOPMENT_PUBLISHER_KEYS,
};

use crate::{Result, TpmError};

/// v2 ticket: hybrid Ed25519 + ML-DSA-65 envelope, no v1 compatibility.
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

    /// Verifies the hybrid AND, the signed epoch, anti-replay, then the optional PCR binding.
    pub(crate) fn verify(&self, current_version: u64, current_pcr: &[u8; 32]) -> Result<()> {
        if USING_DEVELOPMENT_PUBLISHER_KEYS {
            static WARN_ONCE: Once = Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "DEVELOPMENT publisher keyring used for TPM tickets — \
                     supply HELIOS_PUBLISHER_KEYRING_PATH for a production build"
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
    fn valid_hybrid_ticket_is_accepted() {
        let (ticket, keys) = sign_ticket(1, None);
        assert!(ticket.verify_with_keyring(&[keys], 0, &[0u8; 32]).is_ok());
    }

    #[test]
    fn invalid_ed25519_signature_is_rejected() {
        let (mut ticket, keys) = sign_ticket(1, None);
        ticket.envelope.signatures[0].sig.push('A');
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 0, &[0u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn missing_ml_dsa_signature_is_rejected() {
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
    fn rollback_is_rejected() {
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
    fn optional_pcr_binding_and_mismatch_is_rejected() {
        let (without_pcr, keys) = sign_ticket(1, None);
        assert!(without_pcr
            .verify_with_keyring(&[keys], 0, &[99u8; 32])
            .is_ok());

        let (with_pcr, keys) = sign_ticket(1, Some([1u8; 32]));
        assert!(matches!(
            with_pcr.verify_with_keyring(&[keys], 0, &[2u8; 32]),
            Err(TpmError::TicketPcrMismatch)
        ));
        assert!(with_pcr.verify_with_keyring(&[keys], 0, &[1u8; 32]).is_ok());
    }

    #[test]
    fn old_v1_format_refused_without_fallback() {
        let old = br#"{"version":1,"expected_pcr_digest":null,"signature":"00"}"#;
        assert!(matches!(
            ResealTicket::from_json(old),
            Err(TpmError::Serde(_))
        ));
    }

    #[test]
    fn signature_is_verified_before_anti_rollback_and_pcr() {
        let (mut ticket, keys) = sign_ticket(1, Some([1u8; 32]));
        ticket.envelope.signatures.clear();

        // A forged envelope must not act as an oracle allowing the counter
        // and PCR to be distinguished before publisher authentication.
        assert!(matches!(
            ticket.verify_with_keyring(&[keys], 99, &[2u8; 32]),
            Err(TpmError::TicketInvalidSignature)
        ));
    }

    #[test]
    fn json_rejects_malformed_pcr_digest_and_unknown_fields() {
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
