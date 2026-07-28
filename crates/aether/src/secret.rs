//! Secret carried between internal components, whose display does not leak.
//!
//! A bare `String` carrying a PSK ends up sooner or later in a derived
//! `Debug`, hence in a log. [`SecretString`] makes this leak impossible by
//! construction: its `Debug` never prints the value, and one must call
//! [`SecretString::expose`] — named to stand out in review — to obtain it.
//!
//! This type does not replace [`zeroize`]: it protects against accidental
//! display, not memory remanence. For a secret whose in-memory lifetime must
//! be bounded, prefer `Zeroizing` (see [`crate::enroll::Psk`]).

use std::fmt;

/// A secret string (base64 PSK, private key…) that never prints itself.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Gives access to the value in the clear. The name is deliberately
    /// explicit: every call is a point to justify in review.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Is the secret empty? Useful for validating without exposing.
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the value nor its length: a length already reveals
        // something about the nature of the secret.
        f.write_str("SecretString(***)")
    }
}

/// `Display` is deliberately **not implemented**: a secret must not be able
/// to end up in a `format!` by accident. Use [`SecretString::expose`].
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_reveals_neither_the_value_nor_its_length() {
        let secret = SecretString::new("psk-ultra-confidentiel-en-base64");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("psk-ultra"),
            "Debug leaked the secret: {rendered}"
        );
        assert!(
            !rendered.contains("32"),
            "Debug leaked the secret's length: {rendered}"
        );
        assert_eq!(rendered, "SecretString(***)");
    }

    /// The `Debug` of an enclosing structure must not leak either: this is
    /// the real use case (a command deriving `Debug`).
    #[test]
    fn the_derived_debug_of_an_enclosing_structure_does_not_leak() {
        // The fields are only read by the derived `Debug`, which dead-code
        // analysis does not count as a use.
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
        let rendered = format!("{cmd:?}");
        assert!(
            rendered.contains("cle-publique"),
            "the rest must stay readable"
        );
        assert!(
            !rendered.contains("secret-a-ne-pas-logger"),
            "leak: {rendered}"
        );
    }

    #[test]
    fn expose_returns_the_value_correctly() {
        assert_eq!(SecretString::new("valeur").expose(), "valeur");
    }

    #[test]
    fn empty_is_detected_without_exposing() {
        assert!(SecretString::new("   ").is_empty());
        assert!(!SecretString::new("x").is_empty());
    }
}
