use crate::settings::TpmSettings;
use tracing::{error, info, warn};

use crate::{
    blob_store::BlobStore, provisioning, secret::SecretKey, tpm_interface::TpmSealer, Result,
    TpmError,
};

/// Issue de la séquence de déverrouillage au démarrage.
#[derive(Debug)]
pub enum BootDecision {
    /// Validation désactivée (`tpm.enabled = false`) — dev/WSL2, aucun secret.
    Disabled,
    /// Échec ignoré car `enforce = false` (DÉBOGAGE) — aucun secret.
    Bypassed,
    /// Déscellement nominal : intégrité confirmée, secret existant récupéré.
    Unsealed(SecretKey),
    /// Premier boot : secret provisionné (TOFU). À (re)chiffrer les identifiants.
    Provisioned(SecretKey),
    /// Rescellement post-OTA autorisé : nouveau secret. À (re)chiffrer les identifiants.
    Resealed(SecretKey),
}

impl BootDecision {
    /// Secret de déverrouillage si disponible (déchiffrement des identifiants IPsec).
    pub fn secret(&self) -> Option<&SecretKey> {
        match self {
            BootDecision::Unsealed(s)
            | BootDecision::Provisioned(s)
            | BootDecision::Resealed(s) => Some(s),
            BootDecision::Disabled | BootDecision::Bypassed => None,
        }
    }
}

/// Contrôleur de flux : point d'entrée unique de la validation d'intégrité.
///
/// À appeler **en premier** dans `heliosd::run()`, avant toute initialisation réseau.
pub struct BootController;

impl BootController {
    pub fn unlock(cfg: &TpmSettings) -> Result<BootDecision> {
        if !cfg.enabled {
            info!("scellement TPM désactivé (tpm.enabled = false) — démarrage sans vérification");
            return Ok(BootDecision::Disabled);
        }

        match Self::unlock_inner(cfg) {
            Ok(decision) => Ok(decision),
            Err(e) if !cfg.enforce => {
                warn!(
                    "échec TPM ignoré (enforce=false, RÉSERVÉ AU DÉBOGAGE — \
                     ne jamais utiliser en production) : {e}"
                );
                Ok(BootDecision::Bypassed)
            }
            Err(e) => {
                error!("VALIDATION D'INTÉGRITÉ ÉCHOUÉE — arrêt : {e}");
                Err(e)
            }
        }
    }

    fn unlock_inner(cfg: &TpmSettings) -> Result<BootDecision> {
        let mut tpm = open_tpm(cfg)?;
        let store = BlobStore::new(cfg);
        Self::run_flow(cfg, &mut tpm, &store)
    }

    /// Logique de décision, générique sur le backend TPM (testable avec `DryRunTpm`).
    fn run_flow<T: TpmSealer>(
        cfg: &TpmSettings,
        tpm: &mut T,
        store: &BlobStore<'_>,
    ) -> Result<BootDecision> {
        match store.load_blob()? {
            // Blob présent → tentative de déscellement (cas nominal).
            Some(blob) => match tpm.unseal(&blob) {
                Ok(secret) => {
                    info!("déscellement réussi — intégrité du démarrage confirmée");
                    Ok(BootDecision::Unsealed(secret))
                }
                Err(TpmError::UnsealPolicyFail) => {
                    // PCR modifiés : OTA légitime (billet) ou attaque (refus).
                    warn!("déscellement refusé (PCR modifiés) — recherche d'un billet de rescellement");
                    let secret = provisioning::reseal(tpm, store)?;
                    Ok(BootDecision::Resealed(secret))
                }
                Err(e) => Err(e),
            },
            // Pas de blob → provisionnement seulement si explicitement autorisé.
            None => {
                if cfg.allow_provisioning {
                    let secret = provisioning::provision(tpm, store)?;
                    Ok(BootDecision::Provisioned(secret))
                } else {
                    Err(TpmError::MissingBlobOnField)
                }
            }
        }
    }
}

/// Ouvre le backend TPM : réel sur la cible (`feature tpm`), simulé sinon.
fn open_tpm(cfg: &TpmSettings) -> Result<impl TpmSealer> {
    #[cfg(feature = "tpm")]
    {
        crate::tpm_interface::TpmDevice::new(cfg)
    }
    #[cfg(not(feature = "tpm"))]
    {
        let _ = cfg;
        Ok(crate::tpm_interface::DryRunTpm::from_env())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::reseal_ticket::DEV_VENDOR_SEED;
    use crate::tpm_interface::DryRunTpm;

    /// Construit une config TPM pointant vers un répertoire temporaire.
    fn test_cfg(dir: &std::path::Path, allow_provisioning: bool) -> TpmSettings {
        TpmSettings {
            enabled: true,
            enforce: true,
            allow_provisioning,
            device: "/dev/tpmrm0".into(),
            pcr_bank: "sha256".into(),
            pcr_selection: vec![0, 4, 7],
            sealed_blob_path: dir.join("sealed.key").to_string_lossy().into(),
            ticket_path: dir.join("ticket.json").to_string_lossy().into(),
            state_path: dir.join("state.json").to_string_lossy().into(),
        }
    }

    /// Écrit un billet signé par la clé de développement sur le disque.
    fn write_ticket(path: &std::path::Path, version: u64, expected_pcr_digest: Option<[u8; 32]>) {
        const DOMAIN: &[u8] = b"helios-tpm-reseal-v1";
        let sk = SigningKey::from_bytes(&DEV_VENDOR_SEED);
        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN);
        msg.extend_from_slice(&version.to_le_bytes());
        match &expected_pcr_digest {
            Some(d) => {
                msg.push(1);
                msg.extend_from_slice(d);
            }
            None => msg.push(0),
        }
        let sig = sk.sign(&msg);
        let json = serde_json::json!({
            "version": version,
            "expected_pcr_digest": expected_pcr_digest.map(hex::encode),
            "signature": hex::encode(sig.to_bytes()),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }

    #[test]
    fn provisionnement_puis_unseal_nominal() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        // Premier boot : pas de blob → provisionnement.
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        let d = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d, BootDecision::Provisioned(_)));

        // Boot suivant, mêmes PCR → déscellement nominal, même secret.
        let secret1 = d.secret().unwrap().as_bytes().to_vec();
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        let d2 = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d2, BootDecision::Unsealed(_)));
        assert_eq!(d2.secret().unwrap().as_bytes().to_vec(), secret1);
    }

    #[test]
    fn blob_absent_sur_le_terrain_rejete() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), false); // provisionnement interdit
        let store = BlobStore::new(&cfg);
        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::MissingBlobOnField)
        ));
    }

    #[test]
    fn pcr_modifies_sans_billet_rejete() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap(); // provision

        // Kernel modifié (PCR différents) sans billet → refus.
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::UnsealFailedNoTicket)
        ));
    }

    #[test]
    fn ota_avec_billet_valide_rescelle() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap(); // provision, version 0

        // OTA : nouveaux PCR + billet signé version 1.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        let d = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d, BootDecision::Resealed(_)));

        // Billet consommé ; boot suivant sur les mêmes nouveaux PCR → unseal nominal.
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        let d2 = BootController::run_flow(&cfg, &mut tpm, &store).unwrap();
        assert!(matches!(d2, BootDecision::Unsealed(_)));
    }

    #[test]
    fn billet_rejoue_rejete() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), true);
        let store = BlobStore::new(&cfg);

        let mut tpm = DryRunTpm::with_digest([1u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap();

        // Premier rescellement avec billet version 1 → état version 1.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([2u8; 32]);
        BootController::run_flow(&cfg, &mut tpm, &store).unwrap();

        // Rejeu du même billet version 1 sur de nouveaux PCR → anti-rollback.
        write_ticket(std::path::Path::new(&cfg.ticket_path), 1, None);
        let mut tpm = DryRunTpm::with_digest([3u8; 32]);
        assert!(matches!(
            BootController::run_flow(&cfg, &mut tpm, &store),
            Err(TpmError::TicketRollback { .. })
        ));
    }
}
