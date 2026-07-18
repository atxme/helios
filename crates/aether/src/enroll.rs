//! Protocole de provisioning : messages et dérivation du PSK post-quantique.
//!
//! Ce module est **partagé** par les deux bouts, comme [`crate::pq`] : la
//! gateway (`helios-provisioning`) et le client (`orion-core`) doivent parler le
//! même format et dériver **le même** PSK. Le placer d'un seul côté forcerait
//! l'autre à dépendre d'un crate qui ne le concerne pas.
//!
//! # Portée : provisioning, pas admission
//!
//! Ce protocole ne fait **pas** entrer un client inconnu. WireGuard est fondé
//! sur Noise_IK : le répondeur rejette un initiateur dont il ne connaît pas la
//! clé publique statique. Un client jamais déclaré ne peut donc pas monter le
//! tunnel — et ce protocole vit *à l'intérieur* du tunnel.
//!
//! L'enrôlement se scinde en deux :
//!
//! * **Admission** (premier contact) — nécessairement **hors bande** : un
//!   opérateur déclare la clé publique du client. Sa VIP en est dérivée
//!   déterministement (`helios-provisioning::ipam`).
//! * **Provisioning** (ce module) — dans le tunnel, automatisé : échange
//!   ML-KEM, dérivation du PSK, confirmation de la VIP, rotation.
//!
//! # Cinématique (ADR-001)
//!
//! ```text
//! 1. Tunnel WireGuard classique monté (Curve25519), état Connecting,
//!    kill-switch engagé — aucun trafic utilisateur.
//! 2. Canal de contrôle DANS le tunnel :
//!      client  -> ProvisionRequest  { clé publique ML-KEM éphémère, nonce }
//!      gateway -> ProvisionResponse { ciphertext ML-KEM, nonce, VIP }
//!    Les deux dérivent le même PSK.
//! 3. PSK installé des deux côtés -> le handshake suivant réussit -> Up.
//! ```
//!
//! C'est le **client** qui génère la paire ML-KEM et la **gateway** qui
//! encapsule : le secret est ainsi frais à chaque session et sa fraîcheur est
//! contrôlée par la gateway, pas par un client potentiellement compromis.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pq::SharedSecret;

/// Version du protocole. Un client et une gateway de versions différentes
/// doivent se refuser explicitement plutôt que de négocier à l'aveugle.
pub const PROTOCOL_VERSION: u16 = 1;

/// Séparateur de domaine du KDF. Changer cette valeur invalide tous les PSK
/// dérivés : elle fait partie du contrat cryptographique.
const PSK_DOMAIN: &[u8] = b"helios-provisioning-psk-v1";

/// Longueur des nonces de session, en octets.
pub const NONCE_LEN: usize = 16;

/// PSK WireGuard dérivé, 32 octets, effacé à la destruction.
pub type Psk = Zeroizing<[u8; 32]>;

/// Erreurs du protocole de provisioning.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    #[error("version de protocole incompatible : client {client}, gateway {gateway}")]
    VersionMismatch { client: u16, gateway: u16 },
    #[error("clé publique ML-KEM de longueur invalide : {0} au lieu de {expected}", expected = crate::pq::PUBLIC_KEY_LEN)]
    BadKemPublicKey(usize),
    #[error("ciphertext ML-KEM de longueur invalide : {0} au lieu de {expected}", expected = crate::pq::CIPHERTEXT_LEN)]
    BadKemCiphertext(usize),
    #[error("clé publique WireGuard du client absente ou vide")]
    MissingClientKey,
    #[error("pair inconnu : admission hors bande non effectuée")]
    UnknownPeer,
    #[error("dérivation du PSK impossible")]
    Kdf,
}

/// Demande de provisioning, émise par le client **dans** le tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub protocol_version: u16,
    /// Clé publique WireGuard du client (base64) — son identité, déjà connue de
    /// la gateway via l'admission hors bande.
    pub client_wg_public_key: String,
    /// Clé publique ML-KEM **éphémère**, générée pour cette session.
    pub kem_public_key: Vec<u8>,
    /// Aléa du client. Contribue au sel du KDF pour qu'aucun des deux bouts ne
    /// contrôle seul la dérivation.
    pub client_nonce: [u8; NONCE_LEN],
}

/// Réponse de la gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResponse {
    pub protocol_version: u16,
    /// Encapsulation ML-KEM vers la clé publique éphémère du client.
    pub kem_ciphertext: Vec<u8>,
    /// Aléa de la gateway.
    pub gateway_nonce: [u8; NONCE_LEN],
    /// VIP attribuée au client, en notation CIDR (ex. `100.64.1.2/32`).
    /// Dérivée de sa clé publique WireGuard, donc stable sans état disque.
    pub assigned_address: String,
    /// Clé publique WireGuard de la gateway (base64), pour que le client
    /// complète son profil sans configuration manuelle.
    pub gateway_wg_public_key: String,
    /// Durée de validité du PSK, en secondes. Passé ce délai, le client doit
    /// relancer un provisioning.
    pub psk_lifetime_secs: u32,
}

impl ProvisionRequest {
    /// Validation structurelle, avant toute opération cryptographique.
    pub fn validate(&self) -> Result<(), EnrollError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(EnrollError::VersionMismatch {
                client: self.protocol_version,
                gateway: PROTOCOL_VERSION,
            });
        }
        if self.client_wg_public_key.trim().is_empty() {
            return Err(EnrollError::MissingClientKey);
        }
        if self.kem_public_key.len() != crate::pq::PUBLIC_KEY_LEN {
            return Err(EnrollError::BadKemPublicKey(self.kem_public_key.len()));
        }
        Ok(())
    }
}

impl ProvisionResponse {
    pub fn validate(&self) -> Result<(), EnrollError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(EnrollError::VersionMismatch {
                client: PROTOCOL_VERSION,
                gateway: self.protocol_version,
            });
        }
        if self.kem_ciphertext.len() != crate::pq::CIPHERTEXT_LEN {
            return Err(EnrollError::BadKemCiphertext(self.kem_ciphertext.len()));
        }
        Ok(())
    }
}

/// Dérive le PSK WireGuard à partir du secret ML-KEM.
///
/// Le secret ML-KEM fait déjà 32 octets uniformes, exactement la taille du slot
/// PSK : on pourrait l'utiliser brut. On passe malgré tout par un HKDF pour
/// **lier** le PSK à son contexte :
///
/// * les deux nonces — le même secret ne peut pas être rejoué dans une autre
///   session, et aucun des deux bouts ne contrôle seul le sel ;
/// * les deux identités WireGuard — un PSK dérivé pour un couple
///   (client, gateway) ne vaut pas pour un autre ;
/// * un séparateur de domaine versionné — le secret ne peut pas être détourné
///   vers un autre usage cryptographique du projet.
///
/// L'ordre de concaténation est fixe (client puis gateway) : les deux bouts
/// **doivent** l'appliquer identiquement, sinon les PSK divergent et le
/// handshake échoue silencieusement.
pub fn derive_psk(
    kem_secret: &SharedSecret,
    client_nonce: &[u8; NONCE_LEN],
    gateway_nonce: &[u8; NONCE_LEN],
    client_wg_public_key: &str,
    gateway_wg_public_key: &str,
) -> Result<Psk, EnrollError> {
    use aws_lc_rs::hkdf;

    // Sel : contribution des deux bouts, ordre fixe.
    let mut salt_bytes = Vec::with_capacity(NONCE_LEN * 2);
    salt_bytes.extend_from_slice(client_nonce);
    salt_bytes.extend_from_slice(gateway_nonce);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(kem_secret.as_slice());

    // `info` : domaine + identités, longueurs préfixées pour qu'aucune
    // concaténation ambiguë ne puisse produire deux contextes identiques.
    let client_id = client_wg_public_key.as_bytes();
    let gateway_id = gateway_wg_public_key.as_bytes();
    let client_len = (client_id.len() as u16).to_be_bytes();
    let gateway_len = (gateway_id.len() as u16).to_be_bytes();
    let info: [&[u8]; 5] = [PSK_DOMAIN, &client_len, client_id, &gateway_len, gateway_id];

    // `HKDF_SHA256` comme `KeyType` produit exactement 32 octets.
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| EnrollError::Kdf)?;
    let mut psk = Zeroizing::new([0u8; 32]);
    okm.fill(psk.as_mut_slice()).map_err(|_| EnrollError::Kdf)?;
    Ok(psk)
}

/// Encode un PSK en base64, format attendu par WireGuard.
pub fn psk_to_base64(psk: &Psk) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(psk.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SharedSecret {
        Zeroizing::new([byte; 32])
    }

    fn psk_for(
        s: &SharedSecret,
        cn: [u8; NONCE_LEN],
        gn: [u8; NONCE_LEN],
        ck: &str,
        gk: &str,
    ) -> Psk {
        derive_psk(s, &cn, &gn, ck, gk).unwrap()
    }

    #[test]
    fn derivation_deterministe_pour_les_deux_bouts() {
        // Le client et la gateway calculent séparément : ils doivent converger.
        let a = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        assert_eq!(*a, *b);
    }

    #[test]
    fn le_psk_depend_de_chaque_nonce() {
        let base = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        // Changer le nonce du client suffit.
        assert_ne!(
            *base,
            *psk_for(&secret(7), [9; 16], [2; 16], "client", "gateway")
        );
        // Celui de la gateway aussi : aucun des deux ne contrôle seul le sel.
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [9; 16], "client", "gateway")
        );
    }

    #[test]
    fn le_psk_est_lie_aux_deux_identites() {
        let base = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [2; 16], "autre", "gateway")
        );
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [2; 16], "client", "autre")
        );
    }

    /// Sans préfixe de longueur, ("ab","c") et ("a","bc") donneraient le même
    /// `info` — deux contextes distincts partageraient un PSK.
    #[test]
    fn pas_de_collision_par_concatenation_ambigue() {
        let a = psk_for(&secret(7), [1; 16], [2; 16], "ab", "c");
        let b = psk_for(&secret(7), [1; 16], [2; 16], "a", "bc");
        assert_ne!(*a, *b);
    }

    #[test]
    fn un_secret_kem_different_donne_un_psk_different() {
        let a = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b = psk_for(&secret(8), [1; 16], [2; 16], "client", "gateway");
        assert_ne!(*a, *b);
    }

    #[test]
    fn psk_encode_en_base64_de_44_caracteres() {
        let psk = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b64 = psk_to_base64(&psk);
        // 32 octets -> 44 caractères base64, format attendu par WireGuard.
        assert_eq!(b64.len(), 44);
    }

    #[test]
    fn requete_valide_les_versions_et_longueurs() {
        let mut req = ProvisionRequest {
            protocol_version: PROTOCOL_VERSION,
            client_wg_public_key: "cGVlcg==".into(),
            kem_public_key: vec![0u8; crate::pq::PUBLIC_KEY_LEN],
            client_nonce: [0; NONCE_LEN],
        };
        assert!(req.validate().is_ok());

        req.protocol_version = 99;
        assert!(matches!(
            req.validate(),
            Err(EnrollError::VersionMismatch { .. })
        ));

        req.protocol_version = PROTOCOL_VERSION;
        req.kem_public_key = vec![0u8; 10];
        assert!(matches!(
            req.validate(),
            Err(EnrollError::BadKemPublicKey(10))
        ));

        req.kem_public_key = vec![0u8; crate::pq::PUBLIC_KEY_LEN];
        req.client_wg_public_key = "  ".into();
        assert_eq!(req.validate(), Err(EnrollError::MissingClientKey));
    }

    #[test]
    fn reponse_valide_la_longueur_du_ciphertext() {
        let mut resp = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: vec![0u8; crate::pq::CIPHERTEXT_LEN],
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: "Z3c=".into(),
            psk_lifetime_secs: 3600,
        };
        assert!(resp.validate().is_ok());

        resp.kem_ciphertext = vec![0u8; 5];
        assert!(matches!(
            resp.validate(),
            Err(EnrollError::BadKemCiphertext(5))
        ));
    }
}
