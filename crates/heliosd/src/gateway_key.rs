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
//! # Quelles mises à jour font perdre la clé — et lesquelles ne font rien
//!
//! Le scellement porte sur **PCR 0/4/7** : firmware, chaîne de démarrage,
//! Secure Boot. C'est ce qui décide, pas « il y a eu une OTA » :
//!
//! | Mise à jour | PCR | Clé |
//! |---|---|---|
//! | binaire `heliosd` seul (userspace) | inchangés | **survit** |
//! | kernel / initrd | PCR 4 | perdue |
//! | bootloader | PCR 4 | perdue |
//! | firmware UEFI | PCR 0 | perdue |
//! | clés Secure Boot | PCR 7 | perdue |
//!
//! PCR 4 mesure la chaîne de démarrage, pas les fichiers du rootfs : remplacer
//! `/usr/bin/heliosd` ne la déplace pas. Le cas « clé perdue » est donc plus
//! rare qu'il n'y paraît — il ne concerne que les OTA qui embarquent un noyau.
//!
//! # Reprise sans SSH : le séquestre
//!
//! Quand les PCR changent, le rescellement génère un **nouveau** secret et le
//! coffre devient indéchiffrable. Le [séquestre](helio_tpm::escrow) couvre ce
//! cas : une copie de la clé, chiffrée vers la clé publique de l'opérateur, est
//! écrite à chaque scellement. L'opérateur l'ouvre hors ligne, dépose la clé
//! dans un fichier de récupération livré **avec le bundle OTA** — même canal
//! que le billet de rescellement — et la gateway la rescelle au démarrage.
//!
//! Sans séquestre configuré (`escrow_public_key` absente), la clé est
//! définitivement perdue dans ce cas et la reprise redevient manuelle.

use std::path::PathBuf;

use aether::NetworkConfig;
use helio_tpm::{BootDecision, KeystoreError, SealedKeystore, TpmError};
use tracing::{info, warn};

/// Emplacement du coffre contenant la clé privée WireGuard.
const KEYSTORE_PATH: &str = "/var/lib/helios/wg-key.sealed";

/// Séquestre : copie de la clé chiffrée vers la clé publique de l'opérateur.
///
/// Réécrit à chaque scellement. L'opérateur le récupère et le conserve ; lui
/// seul peut l'ouvrir. La gateway, elle, en est incapable — c'est le principe.
const ESCROW_PATH: &str = "/var/lib/helios/wg-key.escrow";

/// Fichier de récupération, livré par l'opérateur avec le bundle OTA — même
/// canal que le billet de rescellement, donc **aucun SSH requis**.
///
/// Contient la clé privée WireGuard en base64. Consommé **une seule fois**, et
/// uniquement si le coffre est réellement indéchiffrable ; effacé aussitôt.
const RECOVERY_PATH: &str = "/var/lib/helios/wg-key.recovery";

/// Origine de la clé effectivement utilisée — sert à alerter l'opérateur.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Chargée depuis le coffre TPM. Cas nominal.
    Sealed,
    /// Lue en clair dans `network.toml`. **Dégradé** : à sceller au plus vite.
    PlaintextConfig,
    /// Restaurée depuis le séquestre après un changement de PCR.
    Recovered,
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

/// Écrit le séquestre de `private_key` vers la clé publique de l'opérateur.
///
/// Sans erreur fatale : un séquestre absent n'empêche pas la gateway de
/// fonctionner, il prive seulement d'un moyen de reprise. On le signale
/// bruyamment plutôt que d'échouer au démarrage.
fn write_escrow(network: &NetworkConfig, private_key: &str) {
    use base64::Engine as _;

    let Some(pubkey_b64) = network.escrow_public_key.as_deref().map(str::trim) else {
        warn!(
            "aucune clé publique de séquestre configurée (`escrow_public_key`) — \
             en cas de changement de PCR (kernel, bootloader, firmware), l'identité \
             de la gateway sera définitivement perdue"
        );
        return;
    };
    if pubkey_b64.is_empty() {
        return;
    }

    let pubkey = match base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
        Ok(k) => k,
        Err(e) => {
            warn!("clé publique de séquestre illisible ({e}) — séquestre non écrit");
            return;
        }
    };

    match helio_tpm::escrow::seal_to_operator(&pubkey, private_key.as_bytes()) {
        Ok(blob) => match write_atomic(ESCROW_PATH, &blob) {
            Ok(()) => info!(
                "séquestre de la clé WireGuard écrit dans {ESCROW_PATH} — \
                 le récupérer et le conserver hors de la gateway"
            ),
            Err(e) => warn!("écriture du séquestre impossible : {e}"),
        },
        Err(e) => warn!("scellement du séquestre impossible : {e}"),
    }
}

/// Tente une reprise depuis le fichier de récupération laissé par l'opérateur.
///
/// N'est appelée **que** lorsque le coffre est indéchiffrable : hors de ce cas,
/// un fichier de récupération traînant ne doit jamais pouvoir remplacer la clé
/// en vigueur — ce serait un vecteur de substitution d'identité.
fn try_recovery(secret: &helio_tpm::SecretKey) -> Option<String> {
    let path = PathBuf::from(RECOVERY_PATH);
    if !path.exists() {
        return None;
    }

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            warn!("fichier de récupération illisible : {e}");
            return None;
        }
    };
    let key = raw.trim().to_string();

    if let Err(e) = validate_wg_key(&key) {
        warn!("fichier de récupération invalide ({e}) — ignoré, non consommé");
        return None;
    }

    // Rescelle immédiatement sous le nouveau secret TPM.
    if let Err(e) = keystore().store(secret, key.as_bytes()) {
        warn!("rescellement de la clé récupérée impossible : {e}");
        return None;
    }

    // Puis efface : la clé ne doit pas rester en clair sur disque plus longtemps
    // que ce démarrage. L'échec de suppression est une anomalie à signaler fort.
    match std::fs::remove_file(&path) {
        Ok(()) => info!("fichier de récupération consommé et effacé"),
        Err(e) => warn!(
            "ÉCHEC DE L'EFFACEMENT de {RECOVERY_PATH} ({e}) — la clé privée reste \
             EN CLAIR sur disque, la supprimer manuellement sans délai"
        ),
    }

    warn!("identité WireGuard restaurée depuis le séquestre et rescellée");
    Some(key)
}

fn write_atomic(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)
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
                        let key = key.trim().to_string();
                        // Le séquestre suit la clé : si la configuration d'escrow
                        // vient d'être ajoutée, il est créé dès ce démarrage.
                        write_escrow(network, &key);
                        return ResolvedKey {
                            private_key: key,
                            origin: KeyOrigin::Sealed,
                        };
                    }
                    Err(_) => warn!("contenu du coffre illisible (encodage)"),
                },
                Err(TpmError::Keystore(KeystoreError::Undecipherable)) => {
                    // Les PCR ont bougé (kernel, bootloader ou firmware) : le
                    // secret a été régénéré et l'ancien coffre est perdu. C'est
                    // exactement le cas que le séquestre existe pour couvrir.
                    warn!(
                        "COFFRE INDÉCHIFFRABLE — les PCR ont changé (nouveau kernel, \
                         bootloader ou firmware) et le secret TPM a été régénéré. \
                         Recherche d'un fichier de récupération…"
                    );
                    if let Some(key) = try_recovery(secret) {
                        write_escrow(network, &key);
                        return ResolvedKey {
                            private_key: key,
                            origin: KeyOrigin::Recovered,
                        };
                    }
                    warn!(
                        "aucun fichier de récupération exploitable dans {RECOVERY_PATH}. \
                         Ouvrir le séquestre {ESCROW_PATH} avec la clé privée d'opérateur, \
                         déposer la clé retrouvée dans ce fichier (livré avec le bundle OTA, \
                         comme le billet de rescellement) et redémarrer."
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
                Ok(()) => {
                    info!(
                        "clé scellée dans {KEYSTORE_PATH} — retirer `wg_private_key` de network.toml"
                    );
                    write_escrow(network, plain);
                }
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
pub fn update_sealed(
    network: &NetworkConfig,
    boot: &BootDecision,
    new_private_key: &str,
) -> Result<(), String> {
    let key = new_private_key.trim();
    validate_wg_key(key)?;

    let secret = boot
        .secret()
        .ok_or_else(|| "aucun secret TPM disponible : impossible de sceller".to_string())?;

    keystore()
        .store(secret, key.as_bytes())
        .map_err(|e| format!("scellement de la nouvelle clé impossible : {e}"))?;

    // Le séquestre doit suivre la nouvelle clé : sinon une reprise post-OTA
    // restaurerait l'ancienne identité, que plus aucun client n'attend.
    write_escrow(network, key);

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
        assert!(update_sealed(&NetworkConfig::default(), &BootDecision::Disabled, VALID).is_err());
    }

    #[test]
    fn mise_a_jour_refuse_une_cle_invalide() {
        assert!(update_sealed(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            "pas-une-cle"
        )
        .is_err());
    }
}
