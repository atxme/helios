//! Clé privée WireGuard de la gateway : chargement scellé et mise à jour.
//!
//! # Pourquoi la clé ne vit plus dans `network.toml`
//!
//! `wg_private_key` est l'**identité cryptographique** de la gateway : c'est
//! elle qui authentifie chaque handshake WireGuard. En clair sur disque, un
//! disque volé suffit à usurper la gateway. Elle est donc déplacée dans un
//! coffre chiffré par le secret scellé dans le TPM ([`helio_tpm::keystore`]) :
//! la déchiffrer exige un déscellement réussi, donc une chaîne de démarrage
//! intacte (PCR 0/4/7).
//!
//! # ⚠️ Après une OTA, la clé est perdue — et c'est voulu
//!
//! Un rescellement post-OTA génère un **nouveau** secret ; l'ancien est
//! irrécupérable par construction (anti-rollback). Le coffre chiffré avec
//! l'ancien secret devient donc indéchiffrable : **la clé WireGuard doit être
//! re-fournie après chaque OTA**.
//!
//! Ce n'est pas un bug à contourner. Rendre la clé récupérable après un
//! changement de PCR reviendrait à la protéger par autre chose que le TPM,
//! c'est-à-dire à annuler la protection.
//!
//! Conséquence opérationnelle importante : sans clé, la gateway ne monte pas de
//! tunnel, donc **l'API n'est pas joignable** (elle vit derrière le tunnel). Le
//! ré-approvisionnement post-OTA passe donc par le canal d'administration hors
//! tunnel prévu par le pare-feu — SSH, autorisé même kill-switch engagé
//! (`allow_ssh_from`). La mise à jour *à distance* via l'API, elle, sert à la
//! **rotation** de clé en fonctionnement normal.

use std::path::PathBuf;

use aether::NetworkConfig;
use helio_tpm::{BootDecision, KeystoreError, SealedKeystore, TpmError};
use tracing::{info, warn};

/// Emplacement du coffre contenant la clé privée WireGuard.
const KEYSTORE_PATH: &str = "/var/lib/helios/wg-key.sealed";

/// Origine de la clé effectivement utilisée — sert à alerter l'opérateur.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Chargée depuis le coffre TPM. Cas nominal.
    Sealed,
    /// Lue en clair dans `network.toml`. **Dégradé** : à sceller au plus vite.
    PlaintextConfig,
    /// Aucune clé exploitable : la gateway ne peut pas monter son interface.
    Missing,
}

/// Clé résolue au démarrage.
pub struct ResolvedKey {
    /// Clé privée en base64, prête pour le plan de données. Vide si `Missing`.
    pub private_key: String,
    pub origin: KeyOrigin,
}

fn keystore() -> SealedKeystore {
    SealedKeystore::new(PathBuf::from(KEYSTORE_PATH))
}

/// Résout la clé privée WireGuard au démarrage.
///
/// Ordre de priorité :
/// 1. le coffre scellé (nominal) ;
/// 2. la clé en clair de `network.toml`, **avec avertissement** — et on la scelle
///    immédiatement pour que le passage au mode protégé soit automatique ;
/// 3. rien : la gateway démarre en fail-closed sans monter d'interface.
pub fn resolve(network: &NetworkConfig, boot: &BootDecision) -> ResolvedKey {
    let store = keystore();
    let secret = boot.secret();

    // 1. Coffre scellé.
    if store.exists() {
        match secret {
            None => {
                // TPM désactivé ou contourné : on ne peut pas ouvrir le coffre.
                warn!(
                    "coffre de clé présent mais aucun secret TPM disponible \
                     (tpm.enabled=false ou enforce=false) — clé inaccessible"
                );
            }
            Some(secret) => match store.load(secret) {
                Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                    Ok(key) => {
                        info!("clé WireGuard chargée depuis le coffre scellé TPM");
                        return ResolvedKey {
                            private_key: key.trim().to_string(),
                            origin: KeyOrigin::Sealed,
                        };
                    }
                    Err(_) => warn!("contenu du coffre illisible (encodage)"),
                },
                Err(TpmError::Keystore(KeystoreError::Undecipherable)) => {
                    // Cas le plus important à diagnostiquer correctement.
                    warn!(
                        "COFFRE INDÉCHIFFRABLE — un rescellement post-OTA a eu lieu. \
                         La clé WireGuard est définitivement perdue et doit être \
                         re-fournie par l'opérateur (SSH d'administration, puis \
                         POST /api/gateway/wireguard-key une fois le tunnel rétabli)."
                    );
                }
                Err(e) => warn!("lecture du coffre impossible : {e}"),
            },
        }
    }

    // 2. Repli sur la clé en clair de la config — mode dégradé.
    let plain = network.wg_private_key.trim();
    if !plain.is_empty() {
        warn!(
            "clé WireGuard lue EN CLAIR dans network.toml — un disque volé suffit \
             à usurper la gateway. Scellement automatique dans le coffre TPM…"
        );
        if let Some(secret) = secret {
            match store.store(secret, plain.as_bytes()) {
                Ok(()) => info!(
                    "clé scellée dans {KEYSTORE_PATH} — retirer `wg_private_key` de network.toml"
                ),
                Err(e) => warn!("scellement automatique impossible : {e}"),
            }
        } else {
            warn!("aucun secret TPM disponible : la clé reste en clair");
        }
        return ResolvedKey {
            private_key: plain.to_string(),
            origin: KeyOrigin::PlaintextConfig,
        };
    }

    // 3. Rien d'exploitable.
    ResolvedKey {
        private_key: String::new(),
        origin: KeyOrigin::Missing,
    }
}

/// Remplace la clé privée WireGuard et la scelle.
///
/// Appelé par l'API (`POST /api/gateway/wireguard-key`), donc **uniquement à
/// travers le tunnel** : le pare-feu restreint l'API à `admin_iface`.
///
/// Changer cette clé change l'identité de la gateway : **tous les clients
/// devront mettre à jour leur `peer_public_key`**. C'est une rotation, pas une
/// opération anodine — d'où la validation stricte en amont.
pub fn update_sealed(boot: &BootDecision, new_private_key: &str) -> Result<(), String> {
    let key = new_private_key.trim();
    validate_wg_key(key)?;

    let secret = boot
        .secret()
        .ok_or_else(|| "aucun secret TPM disponible : impossible de sceller".to_string())?;

    keystore()
        .store(secret, key.as_bytes())
        .map_err(|e| format!("scellement de la nouvelle clé impossible : {e}"))?;

    warn!(
        "clé privée WireGuard remplacée et rescellée — l'identité de la gateway a \
         changé, tous les clients doivent mettre à jour `peer_public_key`"
    );
    Ok(())
}

/// Valide qu'une chaîne est bien une clé Curve25519 base64 de 32 octets.
///
/// On refuse **avant** d'écrire : sceller une clé invalide rendrait la gateway
/// incapable de monter son interface, sans moyen de la joindre pour corriger.
pub fn validate_wg_key(key: &str) -> Result<(), String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| format!("clé non décodable en base64 : {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "clé de {} octets au lieu de 32 — ce n'est pas une clé Curve25519",
            raw.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn validation_de_la_cle() {
        assert!(validate_wg_key(VALID).is_ok());
        assert!(validate_wg_key("pas-du-base64").is_err());
        assert!(validate_wg_key("AAAA").is_err(), "longueur invalide");
        assert!(validate_wg_key("").is_err());
    }

    /// Sans coffre ni clé en config, la gateway doit le dire clairement plutôt
    /// que de démarrer avec une identité vide.
    #[test]
    fn absence_totale_de_cle_signalee() {
        let network = NetworkConfig::default();
        let resolved = resolve(&network, &BootDecision::Disabled);
        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert!(resolved.private_key.is_empty());
    }

    /// TPM désactivé + clé en clair : on fonctionne, mais en signalant le mode
    /// dégradé (le scellement automatique est impossible sans secret).
    #[test]
    fn cle_en_clair_utilisee_mais_signalee_degradee() {
        let network = NetworkConfig {
            wg_private_key: VALID.into(),
            ..NetworkConfig::default()
        };
        let resolved = resolve(&network, &BootDecision::Disabled);
        assert_eq!(resolved.origin, KeyOrigin::PlaintextConfig);
        assert_eq!(resolved.private_key, VALID);
    }

    /// Sans secret TPM, on refuse de sceller plutôt que d'échouer en silence.
    #[test]
    fn mise_a_jour_refusee_sans_secret_tpm() {
        assert!(update_sealed(&BootDecision::Disabled, VALID).is_err());
    }

    #[test]
    fn mise_a_jour_refuse_une_cle_invalide() {
        assert!(update_sealed(&BootDecision::Disabled, "pas-une-cle").is_err());
    }
}
