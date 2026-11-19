//! Where the `nomade` passphrase comes from (ADR-006 §5).
//!
//! The engine never reads a passphrase itself: it asks a [`PassphraseSource`],
//! and the source answers with a buffer it owns. On Windows the source is the
//! native credential dialog ([`super::windows::prompt`]); everywhere else the
//! engine is given a source that refuses, so no path lets the passphrase reach
//! the WebView, JavaScript or a serialised message.
//!
//! The trait lives here rather than in the engine so that the native source,
//! which is Windows-only, sits next to the dialog it wraps and the rest of the
//! crate stays portable.

use zeroize::Zeroizing;

use super::VaultError;

/// Why the passphrase is being asked. The source may show it to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptPurpose {
    /// Opening a sealed `nomade` profile.
    Unlock,
    /// Proving the current passphrase before changing or leaving it.
    Current,
    /// A new passphrase, for a profile being sealed under one.
    New,
    /// The same new passphrase, typed again.
    Confirm,
    /// The previous new passphrase was refused; carries the reason to show.
    Retry(String),
}

/// A source of passphrases the engine asks for, one prompt at a time.
///
/// Called from a blocking thread: a native dialog waits for the user.
pub trait PassphraseSource: Send + Sync {
    /// Asks for the passphrase of `profile`, for `purpose`.
    ///
    /// Cancelling answers [`VaultError::PassphraseCancelled`]. A source that
    /// cannot offer a protected prompt answers [`VaultError::NoNativePrompt`].
    fn ask(&self, profile: &str, purpose: &PromptPurpose) -> Result<Zeroizing<String>, VaultError>;

    /// `true` only when the source is the platform's protected dialog. The
    /// posture reports `nomad_available` from it.
    fn is_native_dialog(&self) -> bool {
        false
    }
}

/// The source of a platform without a protected prompt: every request is
/// refused, and the refusal says why.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailablePassphraseSource;

impl PassphraseSource for UnavailablePassphraseSource {
    fn ask(
        &self,
        _profile: &str,
        _purpose: &PromptPurpose,
    ) -> Result<Zeroizing<String>, VaultError> {
        Err(VaultError::NoNativePrompt)
    }
}
