//! Clés Curve25519 du plan de données WireGuard.
//!
//! Trois opérations reviennent partout dans le projet : générer une paire,
//! dériver la clé publique d'une privée, et valider une clé reçue. Elles
//! étaient réécrites dans la gateway, l'API, le client et l'outil de campagne.
//!
//! Elles vivent ici parce qu'une divergence entre ces copies ne produit pas une
//! erreur lisible : elle produit deux pairs qui ne se reconnaissent pas, avec
//! des handshakes qui échouent en silence côté WireGuard. Le coût d'un bug y
//! est un diagnostic long, pas un message.
//!
//! # Encodage
//!
//! Base64 standard avec padding, comme `wg genkey` et `wg pubkey` — c'est la
//! forme attendue dans `network.toml`, dans les profils Orion et dans les
//! fichiers `wg-quick`.
//!
//! # Clamping
//!
//! La clé privée est [clampée](curve25519_dalek::scalar::clamp_integer) avant
//! d'être encodée, de sorte que la valeur affichée soit celle que `wg genkey`
//! aurait produite. Les implémentations WireGuard clampent de toute façon à
//! l'usage : sans cette normalisation, deux encodages différents désigneraient
//! la même identité, ce qui rend toute comparaison de clés trompeuse.

use base64::Engine as _;

use crate::SecretString;

/// Longueur d'une clé Curve25519, publique ou privée.
pub const KEY_LEN: usize = 32;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Erreurs de manipulation d'une clé WireGuard.
#[derive(Debug, thiserror::Error)]
pub enum WgKeyError {
    #[error("clé non décodable en base64 : {0}")]
    Encoding(String),
    #[error("clé de {0} octets au lieu de {KEY_LEN} — ce n'est pas une clé Curve25519")]
    Length(usize),
    #[error("CSPRNG système indisponible")]
    Rng,
}

/// Une paire de clés WireGuard, encodée en base64.
///
/// La privée est enveloppée dans [`SecretString`] : elle ne peut pas atterrir
/// dans un journal par un `Debug` dérivé.
#[derive(Debug, Clone)]
pub struct Keypair {
    pub private_key: SecretString,
    pub public_key: String,
}

/// Génère une paire de clés WireGuard neuve.
pub fn generate_keypair() -> Result<Keypair, WgKeyError> {
    let mut raw = [0u8; KEY_LEN];
    aws_lc_rs::rand::fill(&mut raw).map_err(|_| WgKeyError::Rng)?;
    let clamped = curve25519_dalek::scalar::clamp_integer(raw);
    let secret = x25519_dalek::StaticSecret::from(clamped);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(Keypair {
        private_key: SecretString::new(B64.encode(secret.to_bytes())),
        public_key: B64.encode(public.as_bytes()),
    })
}

/// Dérive la clé publique correspondant à une clé privée base64.
pub fn public_from_private(private_key_b64: &str) -> Result<String, WgKeyError> {
    let secret = x25519_dalek::StaticSecret::from(decode_key(private_key_b64)?);
    Ok(B64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// Vérifie qu'une chaîne est bien une clé Curve25519 base64 de 32 octets.
///
/// À appeler **avant** d'écrire quoi que ce soit : sceller ou admettre une clé
/// invalide se paie plus tard, sur une gateway qu'on ne peut plus joindre.
pub fn validate_key(key_b64: &str) -> Result<(), WgKeyError> {
    decode_key(key_b64).map(|_| ())
}

fn decode_key(key_b64: &str) -> Result<[u8; KEY_LEN], WgKeyError> {
    let raw = B64
        .decode(key_b64.trim())
        .map_err(|e| WgKeyError::Encoding(e.to_string()))?;
    let len = raw.len();
    raw.try_into().map_err(|_| WgKeyError::Length(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteur X25519 de la RFC 7748 §6.1 (clé d'Alice). Il vaut mieux qu'un
    /// aller-retour avec notre propre code, qui ne prouverait que sa cohérence
    /// interne.
    const RFC7748_PRIVATE: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const RFC7748_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    fn hex_to_b64(hex_str: &str) -> String {
        B64.encode(hex::decode(hex_str).expect("hex valide"))
    }

    #[test]
    fn derivation_conforme_au_vecteur_rfc7748() {
        let public = public_from_private(&hex_to_b64(RFC7748_PRIVATE)).expect("dérivation");
        assert_eq!(public, hex_to_b64(RFC7748_PUBLIC));
    }

    #[test]
    fn la_paire_generee_est_coherente() {
        let paire = generate_keypair().expect("génération");
        let derivee = public_from_private(paire.private_key.expose()).expect("dérivation");
        assert_eq!(derivee, paire.public_key);
    }

    /// Deux appels ne doivent pas rendre la même identité : une collision
    /// signalerait un CSPRNG figé, donc des gateways interchangeables.
    #[test]
    fn deux_generations_different() {
        let a = generate_keypair().expect("génération");
        let b = generate_keypair().expect("génération");
        assert_ne!(a.public_key, b.public_key);
    }

    /// La privée affichée doit être déjà clampée : sinon deux encodages
    /// distincts désignent la même identité et toute comparaison ment.
    #[test]
    fn la_privee_generee_est_deja_clampee() {
        let paire = generate_keypair().expect("génération");
        let brut = B64.decode(paire.private_key.expose()).expect("base64");
        let bytes: [u8; KEY_LEN] = brut.try_into().expect("32 octets");
        assert_eq!(curve25519_dalek::scalar::clamp_integer(bytes), bytes);
    }

    #[test]
    fn le_debug_de_la_paire_ne_fuite_pas_la_privee() {
        let paire = generate_keypair().expect("génération");
        let rendu = format!("{paire:?}");
        assert!(
            !rendu.contains(paire.private_key.expose()),
            "la clé privée a fuité : {rendu}"
        );
    }

    #[test]
    fn validation_refuse_les_formes_invalides() {
        assert!(validate_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
        assert!(matches!(
            validate_key("pas-du-base64"),
            Err(WgKeyError::Encoding(_))
        ));
        assert!(matches!(validate_key("AAAA"), Err(WgKeyError::Length(3))));
        assert!(validate_key("").is_err());
    }

    /// Les espaces autour d'une clé collée depuis un terminal sont fréquents et
    /// ne doivent pas transformer une clé valide en refus incompréhensible.
    #[test]
    fn les_espaces_autour_sont_tolerees() {
        let paire = generate_keypair().expect("génération");
        let entoure = format!("  {}\n", paire.private_key.expose());
        assert_eq!(
            public_from_private(&entoure).expect("dérivation"),
            paire.public_key
        );
    }
}
