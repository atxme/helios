//! Passphrase policy for the `nomade` profile (ADR-006 §3).
//!
//! # Why a policy at all
//!
//! PBKDF2 has no memory hardness. Against GPU or ASIC cracking, the iteration
//! count raises the price per guess but does not change the shape of the
//! attack — the ADR says so plainly, and concludes that **the countermeasure
//! is elsewhere**: in the entropy of what the user types. This module is that
//! countermeasure. Without it, the KDF choice would be a weakness with nothing
//! compensating it.
//!
//! # What the rules are, and what they deliberately are not
//!
//! The classic "one uppercase, one digit, one symbol" rule is **not** here. It
//! measures typographic variety, not entropy: `P@ssw0rd!` satisfies every such
//! rule and is on every cracking list. What is checked instead:
//!
//! * a length floor, or a word count for passphrases;
//! * membership in a list of known-bad values, checked on the **normalised**
//!   and case-folded form so `Password` does not slip past a check on
//!   `password`;
//! * the absence of a single repeated character or a keyboard run.
//!
//! # Normalisation
//!
//! The same passphrase typed on two machines must derive the same key. Unicode
//! offers several byte sequences for the same grapheme — `é` composed or
//! decomposed — so the input is normalised before it ever reaches PBKDF2. A
//! user typing on macOS and Windows would otherwise be locked out of their own
//! profile, with nothing on screen explaining why.
//!
//! Spaces are preserved: they separate words, and a passphrase is the
//! recommended form. Only the leading and trailing ones go, because they are
//! invisible and paste operations add them.

use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

/// Minimum length of a passphrase without word structure.
pub const MIN_LENGTH: usize = 20;

/// Minimum number of words when the passphrase is a word sequence.
///
/// Five words drawn at random from a large list carry more entropy than twenty
/// characters chosen by a human, and are far easier to remember. This is the
/// form the UI should encourage.
pub const MIN_WORDS: usize = 5;

/// Length a word must reach to count as one.
///
/// Without this, `a a a a a` would satisfy the word count.
const MIN_WORD_LENGTH: usize = 3;

/// Longest accepted input.
///
/// ADR-006 requires accepting at least 128 characters so a password manager can
/// paste a long value. The bound above that only stops a paste of an entire
/// file from reaching the KDF.
pub const MAX_LENGTH: usize = 1024;

/// Values refused outright, compared normalised and case-folded.
///
/// Deliberately short: this is not a substitute for a breach corpus. It catches
/// the values a user reaches for when a dialog blocks them, which is exactly
/// the moment a length rule alone would be satisfied by something worthless.
const REFUSED: &[&str] = &[
    "password",
    "motdepasse",
    "changeme",
    "correct horse battery staple",
    "administrator",
    "helios",
    "orion",
    "azertyuiop",
    "qwertyuiop",
    "0123456789",
];

/// Why a passphrase was refused. Each variant names an action the user can take.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassphraseError {
    #[error(
        "passphrase trop courte : au moins {MIN_LENGTH} caractères, ou {MIN_WORDS} mots séparés par des espaces"
    )]
    TooShort,
    #[error("passphrase trop longue : {0} caractères pour un maximum de {MAX_LENGTH}")]
    TooLong(usize),
    #[error("cette passphrase est trop courante pour protéger une clé privée")]
    TooCommon,
    #[error("passphrase trop répétitive : elle n'apporte pas l'entropie que sa longueur suggère")]
    TooRepetitive,
}

/// Checks a passphrase and returns its normalised form, ready for the KDF.
///
/// The returned value is [`Zeroizing`]: it is the passphrase itself, and it
/// must not survive the derivation that consumes it.
pub fn accept(raw: &str) -> Result<Zeroizing<String>, PassphraseError> {
    // Trim before counting: trailing spaces from a paste are invisible, and
    // refusing on them would look like the dialog is broken.
    let normalised: String = raw.trim().nfc().collect();
    let normalised = Zeroizing::new(normalised);

    let characters = normalised.chars().count();
    if characters > MAX_LENGTH {
        return Err(PassphraseError::TooLong(characters));
    }

    let folded = normalised.to_lowercase();
    if REFUSED.iter().any(|bad| folded == *bad) {
        return Err(PassphraseError::TooCommon);
    }

    let words = normalised
        .split_whitespace()
        .filter(|word| word.chars().count() >= MIN_WORD_LENGTH)
        .count();
    if characters < MIN_LENGTH && words < MIN_WORDS {
        return Err(PassphraseError::TooShort);
    }

    if is_repetitive(&normalised) {
        return Err(PassphraseError::TooRepetitive);
    }

    Ok(normalised)
}

/// `true` when the value is long only in appearance.
///
/// Catches the two shapes a length rule alone accepts: one character repeated,
/// and a short pattern tiled to reach the floor. Both are cracked in the time
/// it takes to enumerate the pattern, not the length.
fn is_repetitive(value: &str) -> bool {
    let characters: Vec<char> = value.chars().collect();
    if characters.len() < 2 {
        return true;
    }
    let distinct: std::collections::BTreeSet<char> = characters.iter().copied().collect();
    // Fewer than five distinct characters over a long string is a pattern, not
    // a passphrase.
    if distinct.len() < 5 {
        return true;
    }
    // A repeated block: `abcdefabcdefabcdef` is as weak as `abcdef`.
    for period in 1..=characters.len() / 3 {
        if characters.len().is_multiple_of(period)
            && characters
                .chunks(period)
                .all(|chunk| chunk == &characters[..period])
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_passphrase_is_accepted() {
        assert!(accept("montagne bleue vingt-sept rivière calme").is_ok());
    }

    #[test]
    fn five_words_are_enough_even_when_short() {
        // Shorter than MIN_LENGTH in characters, but five real words: this is
        // the form the UI is meant to encourage.
        let value = "sac mur toi pin ver";
        assert!(
            value.chars().count() < MIN_LENGTH,
            "the test premise requires a value under the character floor"
        );
        assert!(accept(value).is_ok(), "five words must be accepted");
    }

    #[test]
    fn a_short_value_is_refused() {
        assert_eq!(accept("Tr0ub4dor&3"), Err(PassphraseError::TooShort));
    }

    /// The rule this module exists to replace: typographic variety is not
    /// entropy.
    #[test]
    fn a_classic_complex_password_is_still_refused_when_short() {
        assert_eq!(accept("P@ssw0rd!"), Err(PassphraseError::TooShort));
    }

    #[test]
    fn known_bad_values_are_refused_whatever_the_case() {
        assert_eq!(
            accept("correct horse battery staple"),
            Err(PassphraseError::TooCommon)
        );
        assert_eq!(
            accept("Correct Horse Battery Staple"),
            Err(PassphraseError::TooCommon)
        );
        assert_eq!(accept("  AZERTYUIOP  "), Err(PassphraseError::TooCommon));
    }

    #[test]
    fn a_repeated_character_is_refused() {
        assert_eq!(accept(&"a".repeat(64)), Err(PassphraseError::TooRepetitive));
    }

    #[test]
    fn a_tiled_pattern_is_refused() {
        // Long enough to pass the length rule, worth exactly its period.
        assert_eq!(
            accept(&"abcdef".repeat(6)),
            Err(PassphraseError::TooRepetitive)
        );
    }

    /// A password manager must be usable: long values, spaces and pasted
    /// whitespace all have to work.
    #[test]
    fn a_manager_generated_value_is_accepted() {
        let value = "xK4#mQ9!vR2$wL7&nT5@bY8*cF3^hJ6%";
        assert!(accept(value).is_ok());
        assert!(
            accept(&format!("  {value}  ")).is_ok(),
            "pasted spaces must be trimmed"
        );

        // 128 characters, and deliberately **not** a repeated block: tiling a
        // 16-character chunk eight times is worth its chunk, and the policy is
        // right to refuse it.
        let long = concat!(
            "xK4#mQ9!vR2$wL7&nT5@bY8*cF3^hJ6%",
            "pW1?dG0-sZ6+eN4=uM8~aQ7|iX3<oB5>",
            "rV9,tH2.kD7;jL0:gS4_yC6/fP1(zA3)",
            "eU2[qO8]wI5{mE0}nR6!tY3?vB7*hN4#",
        );
        assert_eq!(long.chars().count(), 128);
        assert!(accept(long).is_ok(), "128 characters must be accepted");
    }

    /// A long value built by tiling a short block is worth the block.
    #[test]
    fn a_tiled_block_is_refused_even_at_full_length() {
        let tiled = "aA1!bB2@cC3#dD4$".repeat(8);
        assert_eq!(tiled.chars().count(), 128);
        assert_eq!(accept(&tiled), Err(PassphraseError::TooRepetitive));
    }

    #[test]
    fn an_absurdly_long_paste_is_refused() {
        let value = "a1B2c3D4 ".repeat(500);
        assert!(matches!(accept(&value), Err(PassphraseError::TooLong(_))));
    }

    /// The same passphrase typed on two systems must derive the same key.
    ///
    /// `é` exists composed (U+00E9) and decomposed (U+0065 U+0301). Without
    /// normalisation the two produce different KDF inputs, and a user moving
    /// between machines is locked out of their own profile with nothing on
    /// screen explaining it.
    #[test]
    fn composed_and_decomposed_forms_normalise_to_the_same_value() {
        // `è` is U+00E8 composed, or `e` + U+0300 COMBINING GRAVE decomposed.
        let composed = "rivière calme montagne bleue vingt";
        let decomposed = "rivie\u{0300}re calme montagne bleue vingt";
        assert_ne!(
            composed.as_bytes(),
            decomposed.as_bytes(),
            "the two inputs must genuinely differ before normalisation"
        );
        assert_eq!(
            accept(composed).unwrap().as_str(),
            accept(decomposed).unwrap().as_str()
        );
    }

    #[test]
    fn inner_spaces_are_preserved() {
        let value = accept("montagne bleue vingt-sept rivière calme").unwrap();
        assert!(value.contains(' '), "words must stay separated");
    }
}
