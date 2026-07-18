//! Séquestre (escrow) de la clé WireGuard, pour survivre à un changement de PCR.
//!
//! # Le problème
//!
//! Un rescellement génère un **nouveau** secret TPM ; l'ancien est irrécupérable
//! par construction. Le coffre chiffré avec l'ancien devient indéchiffrable, et
//! la clé WireGuard est perdue. Sans clé, pas de tunnel — donc pas d'API, qui
//! vit derrière le tunnel. La gateway devient injoignable à distance.
//!
//! Rappel utile : **cela n'arrive pas à chaque OTA.** Le scellement porte sur
//! PCR 0/4/7 — firmware, chaîne de démarrage, Secure Boot. Remplacer le binaire
//! `heliosd` ne touche aucun des trois : l'unseal réussit et la clé survit.
//! Seuls un nouveau kernel/initrd, un nouveau bootloader, une mise à jour de
//! firmware ou un changement de clés Secure Boot déplacent ces PCR.
//!
//! # La contrainte qui dicte la solution
//!
//! Si la gateway savait se rétablir **seule** après un changement de PCR, la
//! protection TPM ne vaudrait plus rien : un attaquant qui remplace le kernel
//! obtiendrait la clé par le même chemin. La récupération **doit** exiger un
//! élément détenu par l'opérateur.
//!
//! # Le mécanisme
//!
//! ```text
//! ── En fonctionnement normal ────────────────────────────────────────────────
//! clé WireGuard ──chiffrée vers la clé publique d'escrow──► wg-key.escrow
//!                        (opérateur seul peut l'ouvrir)
//!
//! ── Après un changement de PCR ──────────────────────────────────────────────
//! 1. L'opérateur ouvre wg-key.escrow hors ligne (il détient la clé privée).
//! 2. Il place la clé retrouvée dans un fichier de récupération, livré par le
//!    MÊME canal que le billet de rescellement (le bundle OTA).
//! 3. Au démarrage, la gateway consomme ce fichier, rescelle la clé sous le
//!    nouveau secret TPM, puis **efface** le fichier.
//! ```
//!
//! Aucun SSH n'est requis : la clé voyage avec l'OTA, comme le billet.
//!
//! # Le compromis, énoncé franchement
//!
//! Le fichier de récupération contient la clé **en clair** le temps d'un
//! démarrage. C'est inévitable : la gateway n'a, à cet instant, aucun secret
//! préexistant avec lequel le déchiffrer — c'est précisément ce que le
//! rescellement vient de détruire. On borne donc l'exposition plutôt que de la
//! supprimer :
//!
//! * le fichier n'est lu **que** si le coffre est réellement indéchiffrable ;
//! * il est effacé immédiatement après usage ;
//! * il doit être livré avec le même soin que le bundle OTA lui-même.
//!
//! C'est la même exposition qu'une reprise par SSH, mais automatisée et bornée.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf;
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::{Result, TpmError};

/// Magie du blob d'escrow.
const MAGIC: &[u8; 4] = b"HESC";
const VERSION: u8 = 1;
/// Sépare l'usage escrow de tout autre chiffrement du projet.
const AAD: &[u8] = b"helios-escrow-v1";
/// Domaine du KDF appliqué au secret X25519.
const KDF_INFO: &[u8] = b"helios-escrow-kdf-v1";

/// Longueur d'une clé publique/privée X25519.
pub const KEY_LEN: usize = 32;
/// En-tête : magie + version + clé publique éphémère + nonce.
const HEADER_LEN: usize = 4 + 1 + KEY_LEN + NONCE_LEN;

/// Erreurs propres au séquestre.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("clé d'escrow invalide : {0}")]
    BadKey(String),
    #[error("blob d'escrow invalide : {0}")]
    Format(String),
    #[error("ouverture du séquestre impossible (mauvaise clé privée ou blob altéré)")]
    Undecipherable,
}

/// Chiffre `plaintext` vers la clé publique d'escrow de l'opérateur.
///
/// Schéma « sealed box » : une paire X25519 éphémère est tirée, le secret
/// partagé passe par HKDF, et le résultat chiffre en AES-256-GCM. La clé
/// publique éphémère voyage avec le blob ; sa moitié privée est jetée
/// immédiatement. **La gateway ne peut donc pas rouvrir ce qu'elle a scellé** —
/// c'est voulu : seul l'opérateur le peut.
pub fn seal_to_operator(operator_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = to_array(operator_public_key)?;
    let recipient = x25519_dalek::PublicKey::from(recipient);

    // Paire éphémère : jetée dès le secret dérivé.
    let mut ephemeral_bytes = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(ephemeral_bytes.as_mut_slice())
        .map_err(|_| TpmError::Rng("CSPRNG indisponible pour l'escrow".into()))?;
    let ephemeral_secret = x25519_dalek::StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let key = derive_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        recipient.as_bytes(),
    )?;

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
    .map_err(|_| TpmError::Serde("chiffrement du séquestre échoué".into()))?;

    let mut blob = Vec::with_capacity(HEADER_LEN + in_out.len());
    blob.extend_from_slice(MAGIC);
    blob.push(VERSION);
    blob.extend_from_slice(ephemeral_public.as_bytes());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Ouvre un séquestre avec la clé privée de l'opérateur.
///
/// Destiné à l'**outillage opérateur** (hors gateway) et aux tests : la gateway
/// ne détient pas cette clé privée, par construction.
pub fn open_as_operator(operator_private_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN {
        return Err(EscrowError::Format("blob tronqué".into()).into());
    }
    if &blob[..4] != MAGIC {
        return Err(EscrowError::Format("magie invalide".into()).into());
    }
    if blob[4] != VERSION {
        return Err(EscrowError::Format(format!("version {} non supportée", blob[4])).into());
    }

    let secret = x25519_dalek::StaticSecret::from(to_array(operator_private_key)?);
    let recipient_public = x25519_dalek::PublicKey::from(&secret);

    let mut ephemeral = [0u8; KEY_LEN];
    ephemeral.copy_from_slice(&blob[5..5 + KEY_LEN]);
    let ephemeral_public = x25519_dalek::PublicKey::from(ephemeral);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[5 + KEY_LEN..HEADER_LEN]);

    let shared = secret.diffie_hellman(&ephemeral_public);
    let key = derive_key(shared.as_bytes(), &ephemeral, recipient_public.as_bytes())?;

    let mut in_out = blob[HEADER_LEN..].to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD),
            &mut in_out,
        )
        .map_err(|_| EscrowError::Undecipherable)?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Dérive la clé AEAD du secret X25519.
///
/// Les deux clés publiques entrent dans le KDF : le chiffré est ainsi lié au
/// couple (éphémère, destinataire) et ne peut pas être rejoué vers un autre
/// destinataire.
fn derive_key(
    shared: &[u8],
    ephemeral_public: &[u8],
    recipient_public: &[u8],
) -> Result<LessSafeKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared);
    let info: [&[u8]; 3] = [KDF_INFO, ephemeral_public, recipient_public];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| TpmError::Serde("dérivation d'escrow échouée".into()))?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    okm.fill(key_bytes.as_mut_slice())
        .map_err(|_| TpmError::Serde("dérivation d'escrow échouée".into()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_slice())
        .map_err(|_| TpmError::Serde("clé AEAD d'escrow invalide".into()))?;
    Ok(LessSafeKey::new(unbound))
}

fn to_array(key: &[u8]) -> Result<[u8; KEY_LEN]> {
    key.try_into().map_err(|_| {
        TpmError::Escrow(EscrowError::BadKey(format!(
            "{} octets au lieu de {KEY_LEN}",
            key.len()
        )))
    })
}

/// Génère une paire d'escrow. Outil opérateur : la privée reste hors gateway.
pub fn generate_operator_keypair() -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; KEY_LEN])> {
    let mut private = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(private.as_mut_slice())
        .map_err(|_| TpmError::Rng("CSPRNG indisponible".into()))?;
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((private, *public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_operateur() {
        let (private, public) = generate_operator_keypair().unwrap();
        let wg_key = b"cle-privee-wireguard-de-32-octet";

        let blob = seal_to_operator(&public, wg_key).unwrap();
        let out = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(out.as_slice(), wg_key);
    }

    /// La propriété qui fait tout l'intérêt du séquestre : la gateway scelle
    /// mais ne peut pas rouvrir. Une gateway compromise ne rend pas la clé.
    #[test]
    fn une_autre_cle_privee_n_ouvre_pas() {
        let (_, public) = generate_operator_keypair().unwrap();
        let (autre_private, _) = generate_operator_keypair().unwrap();

        let blob = seal_to_operator(&public, b"secret").unwrap();
        assert!(matches!(
            open_as_operator(autre_private.as_slice(), &blob),
            Err(TpmError::Escrow(EscrowError::Undecipherable))
        ));
    }

    #[test]
    fn deux_scellements_du_meme_contenu_different() {
        let (_, public) = generate_operator_keypair().unwrap();
        let a = seal_to_operator(&public, b"secret").unwrap();
        let b = seal_to_operator(&public, b"secret").unwrap();
        assert_ne!(a, b, "paire éphémère et nonce frais à chaque scellement");
    }

    #[test]
    fn une_alteration_est_detectee() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_to_operator(&public, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    /// Altérer la clé publique éphémère doit aussi échouer : elle entre dans le
    /// KDF, donc le chiffré est lié au couple de clés.
    #[test]
    fn substitution_de_la_cle_ephemere_detectee() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_to_operator(&public, b"secret").unwrap();
        blob[6] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    #[test]
    fn cles_de_mauvaise_taille_refusees() {
        assert!(seal_to_operator(&[0u8; 10], b"x").is_err());
        let (_, public) = generate_operator_keypair().unwrap();
        let blob = seal_to_operator(&public, b"x").unwrap();
        assert!(open_as_operator(&[0u8; 10], &blob).is_err());
    }

    /// Le scénario complet, de bout en bout : une OTA change le kernel, le
    /// secret TPM est régénéré, le coffre devient illisible — et l'opérateur
    /// retrouve quand même l'identité de la gateway grâce au séquestre.
    #[test]
    fn reprise_complete_apres_changement_de_pcr() {
        use crate::keystore::SealedKeystore;
        use crate::secret::SecretKey;

        let dir = std::env::temp_dir().join(format!("helios-escrow-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SealedKeystore::new(dir.join("wg-key.sealed"));

        let wg_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();

        // ── Fonctionnement normal : la clé est scellée, et séquestrée ──
        let secret_avant = SecretKey::from_bytes([1u8; 32]);
        store.store(&secret_avant, wg_key).unwrap();
        let escrow_blob = seal_to_operator(&operator_public, wg_key).unwrap();
        assert_eq!(store.load(&secret_avant).unwrap().as_slice(), wg_key);

        // ── OTA avec nouveau kernel : PCR 4 bouge, secret régénéré ──
        let secret_apres = SecretKey::from_bytes([2u8; 32]);
        assert!(
            store.load(&secret_apres).is_err(),
            "le coffre doit être illisible avec le nouveau secret"
        );

        // ── Reprise : l'opérateur ouvre le séquestre hors ligne ──
        let recovered = open_as_operator(operator_private.as_slice(), &escrow_blob).unwrap();
        assert_eq!(recovered.as_slice(), wg_key, "identité retrouvée");

        // ── La gateway rescelle sous le nouveau secret ──
        store.store(&secret_apres, &recovered).unwrap();
        assert_eq!(store.load(&secret_apres).unwrap().as_slice(), wg_key);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn formats_invalides_refuses() {
        let (private, _) = generate_operator_keypair().unwrap();
        assert!(open_as_operator(private.as_slice(), b"court").is_err());

        let mut bad = vec![0u8; HEADER_LEN + 16];
        bad[..4].copy_from_slice(b"NOPE");
        assert!(open_as_operator(private.as_slice(), &bad).is_err());

        let mut bad_version = vec![0u8; HEADER_LEN + 16];
        bad_version[..4].copy_from_slice(MAGIC);
        bad_version[4] = 9;
        assert!(open_as_operator(private.as_slice(), &bad_version).is_err());
    }
}
