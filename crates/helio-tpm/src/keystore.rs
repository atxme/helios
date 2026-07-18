//! Coffre de secrets chiffré par le secret scellé dans le TPM.
//!
//! # Rôle
//!
//! Le secret descellé au boot n'est pas qu'une porte : il **chiffre les secrets
//! opérationnels de la gateway**. Depuis la bascule WireGuard, le secret à
//! protéger est la **clé privée Curve25519** de la gateway — son identité
//! cryptographique réelle, celle qui authentifie chaque handshake.
//!
//! Sans ce coffre, cette clé vit en clair dans `network.toml` : un disque volé
//! suffit à usurper la gateway. Avec, le déchiffrement exige un déscellement
//! TPM réussi, donc une chaîne de démarrage non altérée (PCR 0/4/7).
//!
//! # Chaînage des protections
//!
//! ```text
//! PCR 0/4/7 inchangés ──► TPM descelle le secret ──► déchiffre la clé WireGuard
//!      (matériel)              (256 bits)               (AES-256-GCM)
//! ```
//!
//! Modifier le kernel ou le bootloader casse le premier maillon : le secret
//! reste verrouillé, la clé WireGuard reste chiffrée. La garantie est
//! matérielle, pas logicielle — remplacer le binaire `heliosd` ne donne rien.
//!
//! # ⚠️ Interaction avec le rescellement post-OTA
//!
//! Un rescellement (`BootDecision::Resealed`) génère un **nouveau** secret :
//! l'ancien est définitivement perdu, donc **tout contenu de ce coffre devient
//! irrécupérable**. Ce n'est pas un défaut d'implémentation, c'est la
//! conséquence directe du modèle anti-rollback. Voir [`KeystoreError::Undecipherable`]
//! et la note dans `heliosd` : après une OTA, la clé WireGuard doit être
//! re-fournie par l'opérateur.

use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::{secret::SecretKey, Result, TpmError};

/// Magie de fichier : distingue un coffre d'un blob quelconque.
const MAGIC: &[u8; 4] = b"HKS1";
/// Version de format. Un coffre d'une autre version est refusé plutôt
/// qu'interprété de travers.
const VERSION: u8 = 1;
/// Données authentifiées : lient le chiffré à son usage. Un coffre ne peut pas
/// être détourné vers un autre contexte du projet.
const AAD: &[u8] = b"helios-keystore-v1";

/// En-tête : magie + version + nonce.
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;

/// Erreurs propres au coffre.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Le contenu ne peut pas être déchiffré avec ce secret.
    ///
    /// Cas typique : le secret a changé (rescellement post-OTA). Le contenu est
    /// alors **définitivement perdu** — il faut re-provisionner.
    #[error(
        "coffre indéchiffrable avec le secret courant — un rescellement a-t-il eu lieu ? \
         Le contenu est irrécupérable, la clé doit être re-fournie"
    )]
    Undecipherable,
    #[error("format de coffre invalide : {0}")]
    Format(String),
}

/// Coffre chiffré adossé à un fichier.
pub struct SealedKeystore {
    path: PathBuf,
}

impl SealedKeystore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Le coffre existe-t-il sur disque ?
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Chiffre `plaintext` avec `secret` et persiste le coffre **atomiquement**.
    ///
    /// L'écriture passe par un fichier temporaire puis un `rename` : une
    /// coupure de courant en cours d'écriture laisse l'ancien coffre intact
    /// plutôt qu'un fichier tronqué — donc une gateway qui redémarre encore.
    pub fn store(&self, secret: &SecretKey, plaintext: &[u8]) -> Result<()> {
        let key = aead_key(secret)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| TpmError::Rng("CSPRNG indisponible pour le nonce".into()))?;

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD),
            &mut in_out,
        )
        .map_err(|_| TpmError::Serde("chiffrement du coffre échoué".into()))?;

        let mut blob = Vec::with_capacity(HEADER_LEN + in_out.len());
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);

        self.write_atomic(&blob)
    }

    /// Déchiffre le coffre avec `secret`.
    pub fn load(&self, secret: &SecretKey) -> Result<Zeroizing<Vec<u8>>> {
        let blob = std::fs::read(&self.path).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })?;

        if blob.len() < HEADER_LEN {
            return Err(KeystoreError::Format("coffre tronqué".into()).into());
        }
        if &blob[..4] != MAGIC {
            return Err(KeystoreError::Format("magie invalide".into()).into());
        }
        if blob[4] != VERSION {
            return Err(KeystoreError::Format(format!("version {} non supportée", blob[4])).into());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&blob[5..HEADER_LEN]);

        let key = aead_key(secret)?;
        let mut in_out = blob[HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(AAD),
                &mut in_out,
            )
            // Un échec ici signifie « mauvais secret » ou « contenu altéré ».
            // Les deux méritent le même refus net : on ne devine pas.
            .map_err(|_| KeystoreError::Undecipherable)?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    /// Supprime le coffre. Utilisé quand son contenu est devenu irrécupérable.
    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TpmError::Io {
                path: self.path.display().to_string(),
                cause: e.to_string(),
            }),
        }
    }

    fn write_atomic(&self, blob: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| TpmError::Io {
                path: parent.display().to_string(),
                cause: e.to_string(),
            })?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, blob).map_err(|e| TpmError::Io {
            path: tmp.display().to_string(),
            cause: e.to_string(),
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| TpmError::Io {
            path: self.path.display().to_string(),
            cause: e.to_string(),
        })
    }
}

/// Construit la clé AEAD depuis le secret descellé.
fn aead_key(secret: &SecretKey) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
        .map_err(|_| TpmError::Serde("clé AEAD invalide".into()))?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("helios-keystore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn secret(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 32])
    }

    #[test]
    fn aller_retour_chiffre_dechiffre() {
        let ks = SealedKeystore::new(tmp_path("roundtrip"));
        let wg_key = b"une-cle-privee-wireguard-32-oct!";

        ks.store(&secret(1), wg_key).unwrap();
        assert!(ks.exists());

        let out = ks.load(&secret(1)).unwrap();
        assert_eq!(out.as_slice(), wg_key);
        ks.remove().unwrap();
    }

    /// Le cœur de la protection : sans le bon secret — donc sans déscellement
    /// TPM réussi — le contenu reste inaccessible.
    #[test]
    fn un_mauvais_secret_ne_dechiffre_pas() {
        let ks = SealedKeystore::new(tmp_path("wrongkey"));
        ks.store(&secret(1), b"secret").unwrap();

        let err = ks.load(&secret(2));
        assert!(
            matches!(err, Err(TpmError::Keystore(KeystoreError::Undecipherable))),
            "un secret différent (ex. après rescellement) doit échouer nettement"
        );
        ks.remove().unwrap();
    }

    /// L'AEAD doit détecter toute altération du chiffré, pas seulement une
    /// mauvaise clé : un disque modifié ne doit pas produire un faux plaintext.
    #[test]
    fn une_alteration_est_detectee() {
        let path = tmp_path("tamper");
        let ks = SealedKeystore::new(&path);
        ks.store(&secret(1), b"secret").unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(&path, &blob).unwrap();

        assert!(
            ks.load(&secret(1)).is_err(),
            "l'altération doit être détectée"
        );
        ks.remove().unwrap();
    }

    #[test]
    fn deux_ecritures_du_meme_contenu_different() {
        let ks = SealedKeystore::new(tmp_path("nonce"));
        ks.store(&secret(1), b"secret").unwrap();
        let first = std::fs::read(ks.path()).unwrap();
        ks.store(&secret(1), b"secret").unwrap();
        let second = std::fs::read(ks.path()).unwrap();
        assert_ne!(first, second, "le nonce doit être frais à chaque écriture");
        ks.remove().unwrap();
    }

    #[test]
    fn formats_invalides_refuses() {
        let path = tmp_path("badformat");
        let ks = SealedKeystore::new(&path);

        std::fs::write(&path, b"xx").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "trop court");

        std::fs::write(&path, b"NOPE\x01aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "mauvaise magie");

        std::fs::write(&path, b"HKS1\x09aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(ks.load(&secret(1)).is_err(), "version inconnue");

        ks.remove().unwrap();
    }

    #[test]
    fn suppression_idempotente() {
        let ks = SealedKeystore::new(tmp_path("gone"));
        ks.remove().unwrap();
        ks.remove().unwrap();
        assert!(!ks.exists());
    }
}
