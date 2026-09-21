//! Secret carried between internal components, whose display does not leak
//! and whose memory does not survive it ([ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §5).
//!
//! A bare `String` carrying a PSK ends up sooner or later in a derived
//! `Debug`, hence in a log. [`SecretString`] makes this leak impossible by
//! construction: its `Debug` never prints the value, and one must call
//! [`SecretString::expose`] — named to stand out in review — to obtain it.
//!
//! # The rule is on the type before it is on `Drop`
//!
//! Zeroizing repairs nothing about a copy already made. ADR-006 §5 therefore
//! starts with what the type *allows*: no `Clone`, no `Serialize`, no
//! `Display`, no revealing `Debug`. A duplication that is genuinely needed goes
//! through [`SecretString::duplicate`], whose name makes it a point to justify
//! in review — exactly like `expose`.
//!
//! `Drop` comes second, and it does come: the buffer is wiped with the
//! `zeroize` crate, whose volatile writes and fences the compiler may not
//! elide. An ordinary `String` drop leaves the bytes in the freed allocation.
//!
//! # Comparison is constant-time
//!
//! `PartialEq` on a secret is a timing oracle: the default byte comparison
//! returns as soon as two bytes differ, which leaks how long a common prefix
//! is. Since these values are compared against attacker-supplied ones — a PSK
//! fingerprint, a pasted key — the implementation here compares every byte.
//!
//! # Deserializing yes, serializing never
//!
//! [`serde::Deserialize`] is implemented; `Serialize` is not, and the
//! asymmetry is the whole point. Deserializing *creates* a secret from bytes
//! the process already holds — it is the « raw serialized data → immediate
//! conversion to a runtime secret type » step ADR-006 §5 asks for, and doing
//! it any other way means parsing into a bare `String` first. Serializing
//! would *emit* one, which is what the ADR forbids: « aucune sérialisation
//! TOML/JSON ne reçoit un type contenant un secret ». A structure holding a
//! [`SecretString`] therefore reads back from a legacy file, and cannot be
//! written to one by accident.
//!
//! # What this does not do
//!
//! It does not lock the page in RAM. A `String` grows by reallocating, and the
//! old allocation is copied then freed **unwiped** by the allocator. For a
//! secret whose residency must be controlled, see [`crate::locked`].

use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::Zeroize as _;

/// A secret string (base64 PSK, private key…) that never prints itself.
///
/// Deliberately **not** `Clone`: see the module documentation.
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

    /// Makes a second copy of the secret.
    ///
    /// Named rather than derived, so that a duplication appears in a diff. Each
    /// copy is one more buffer to wipe and one more chance for one to be
    /// forgotten; the ones that remain should be the ones someone chose.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    /// Is the secret empty? Useful for validating without exposing.
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

/// An absent secret. Required by `#[serde(default)]` on the fields that carry
/// one, and it is the honest default: no key rather than a placeholder.
impl Default for SecretString {
    fn default() -> Self {
        Self(String::new())
    }
}

/// Reads a secret from a serialized document. See the module documentation
/// for why the mirror image — `Serialize` — is deliberately absent.
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Through `String` because that is what the TOML/JSON parser hands
        // back; it is moved into the secret, not copied, so this detour
        // leaves no second buffer behind.
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the value nor its length: a length already reveals
        // something about the nature of the secret.
        f.write_str("SecretString(***)")
    }
}

/// Constant-time equality.
///
/// The lengths are compared first and in the clear, which is not a leak worth
/// avoiding: the length of a base64 PSK is a public property of the protocol.
/// What must not leak is *where* two values start to differ.
impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        let ours = self.0.as_bytes();
        let theirs = other.0.as_bytes();
        if ours.len() != theirs.len() {
            return false;
        }
        ours.iter()
            .zip(theirs)
            .fold(0u8, |differences, (a, b)| differences | (a ^ b))
            == 0
    }
}

impl Eq for SecretString {}

/// `Display` is deliberately **not implemented**: a secret must not be able
/// to end up in a `format!` by accident. Use [`SecretString::expose`].
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Only ever *into* the secret. The dangerous direction — a secret turning
/// back into a `String` by inference — has no conversion at all: it goes
/// through [`SecretString::expose`], which a reviewer can grep for.
impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
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

    /// A legacy `network.toml` still carries a plaintext key, so reading one
    /// must land in the secret type rather than in a bare `String`.
    #[test]
    fn a_secret_is_read_back_from_a_serialized_document() {
        #[derive(Deserialize)]
        struct Document {
            #[serde(default)]
            wg_private_key: SecretString,
            #[serde(default)]
            preshared_key: Option<SecretString>,
        }

        let document: Document =
            toml::from_str("wg_private_key = \"cle-heritee\"\npreshared_key = \"psk\"\n")
                .expect("a legacy document must still parse");
        assert_eq!(document.wg_private_key.expose(), "cle-heritee");
        assert_eq!(
            document.preshared_key.as_ref().map(SecretString::expose),
            Some("psk")
        );

        let absent: Document = toml::from_str("").expect("an empty document is valid");
        assert!(absent.wg_private_key.is_empty());
        assert!(absent.preshared_key.is_none());
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

    #[test]
    fn duplicate_yields_an_equal_but_independent_secret() {
        let original = SecretString::new("valeur");
        let copy = original.duplicate();
        assert_eq!(original, copy);
        assert_eq!(copy.expose(), "valeur");
    }

    /// Comparison must not answer "how far did I get before differing".
    #[test]
    fn equality_holds_on_every_shape() {
        let reference = SecretString::new("abcdefgh");
        assert_eq!(reference, SecretString::new("abcdefgh"));
        // Same length, differs at the last byte: the case a short-circuiting
        // comparison would answer fastest.
        assert_ne!(reference, SecretString::new("abcdefgX"));
        // Same length, differs at the first byte.
        assert_ne!(reference, SecretString::new("Xbcdefgh"));
        assert_ne!(reference, SecretString::new("abcdefg"));
        assert_ne!(reference, SecretString::new("abcdefghi"));
        assert_eq!(SecretString::new(""), SecretString::new(""));
    }

    /// The buffer must be wiped, not merely dropped.
    ///
    /// Reading freed memory is undefined behaviour, so the check is made on a
    /// buffer we still own: `Drop` calls exactly this, and asserting the
    /// primitive is what makes the guarantee testable at all.
    #[test]
    fn the_buffer_is_wiped_rather_than_merely_freed() {
        let mut value = String::from("psk-ultra-confidentiel");
        let address = value.as_ptr();
        let length = value.len();
        value.zeroize();
        // SAFETY: the allocation is still owned by `value`; `zeroize` empties
        // the string but does not release its buffer.
        let bytes = unsafe { std::slice::from_raw_parts(address, length) };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "the buffer still holds the secret after zeroize"
        );
    }
}
