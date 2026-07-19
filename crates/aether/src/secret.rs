//! Secret transporté entre composants internes, dont l'affichage ne fuit pas.
//!
//! Un `String` nu portant un PSK finit tôt ou tard dans un `Debug` dérivé, donc
//! dans un log. [`SecretString`] rend cette fuite impossible par construction :
//! son `Debug` n'imprime jamais la valeur, et il faut appeler [`SecretString::expose`]
//! — nommé pour être visible en revue — pour l'obtenir.
//!
//! Ce type ne remplace pas [`zeroize`] : il protège de l'affichage accidentel,
//! pas de la rémanence mémoire. Pour un secret dont la durée de vie doit être
//! bornée en mémoire, préférer `Zeroizing` (voir [`crate::enroll::Psk`]).

use std::fmt;

/// Une chaîne secrète (PSK base64, clé privée…) qui ne s'imprime jamais.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Donne accès à la valeur en clair. Le nom est délibérément explicite :
    /// chaque appel est un point à justifier en revue.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Le secret est-il vide ? Utile pour valider sans exposer.
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ni la valeur, ni sa longueur : une longueur renseigne déjà sur la
        // nature du secret.
        f.write_str("SecretString(***)")
    }
}

/// `Display` est volontairement **non implémenté** : un secret ne doit pas
/// pouvoir se retrouver dans un `format!` par inadvertance. Utiliser
/// [`SecretString::expose`].
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_debug_ne_revele_ni_la_valeur_ni_sa_longueur() {
        let secret = SecretString::new("psk-ultra-confidentiel-en-base64");
        let rendu = format!("{secret:?}");
        assert!(
            !rendu.contains("psk-ultra"),
            "le Debug a fuité le secret : {rendu}"
        );
        assert!(
            !rendu.contains("32"),
            "le Debug a fuité la longueur du secret : {rendu}"
        );
        assert_eq!(rendu, "SecretString(***)");
    }

    /// Le `Debug` d'une structure englobante ne doit pas fuiter non plus :
    /// c'est le cas d'usage réel (une commande dérivant `Debug`).
    #[test]
    fn le_debug_derive_d_une_structure_englobante_ne_fuite_pas() {
        // Les champs ne sont lus que par le `Debug` dérivé, ce que l'analyse de
        // code mort ne compte pas comme un usage.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Commande {
            pair: String,
            psk: SecretString,
        }
        let cmd = Commande {
            pair: "cle-publique".into(),
            psk: SecretString::new("secret-a-ne-pas-logger"),
        };
        let rendu = format!("{cmd:?}");
        assert!(
            rendu.contains("cle-publique"),
            "le reste doit rester lisible"
        );
        assert!(!rendu.contains("secret-a-ne-pas-logger"), "fuite : {rendu}");
    }

    #[test]
    fn expose_rend_bien_la_valeur() {
        assert_eq!(SecretString::new("valeur").expose(), "valeur");
    }

    #[test]
    fn vide_detecte_sans_exposer() {
        assert!(SecretString::new("   ").is_empty());
        assert!(!SecretString::new("x").is_empty());
    }
}
