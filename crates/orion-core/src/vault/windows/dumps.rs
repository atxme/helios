//! Excluding secret pages from Windows Error Reporting (ADR-006 §5).
//!
//! # A defence in depth, and nothing more
//!
//! When a process faults, WER can collect a dump and send it to Microsoft or to
//! a corporate collector. A secret resident at that instant travels with it —
//! off the machine, past every protection this crate builds, into a store
//! nobody here controls. `WerRegisterExcludedMemoryBlock` marks a region so the
//! collector skips it.
//!
//! ADR-006 is explicit about the limit, and this module repeats it because the
//! name invites over-reading: the exclusion covers **WER reports only**. It is
//! not a boundary against a debugger, against injection, or against malware
//! running as the same account. A minidump taken by anything other than WER is
//! unaffected.
//!
//! # Failure is logged, and logged blind
//!
//! Registration can fail — too many regions, an unsupported build. The failure
//! is reported, never fatal. And the log carries **neither the address nor the
//! content**: an address is what an attacker reading logs would most like to
//! learn, and it is exactly what a naive `{:?}` on the region would print.

use crate::vault::VaultError;

/// Result of asking WER to skip a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exclusion {
    /// The region is registered; WER dumps will omit it.
    Registered,
    /// The platform refused. Secrets may appear in a WER report.
    Refused,
    /// No WER on this platform.
    Unsupported,
}

impl Exclusion {
    pub fn holds(self) -> bool {
        matches!(self, Self::Registered)
    }

    /// Sentence for the posture panel.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Registered => "Pages secrètes exclues des rapports d'erreur Windows.",
            Self::Refused => {
                "Exclusion des rapports d'erreur refusée : un vidage WER pourrait \
                 emporter un secret hors de la machine."
            }
            Self::Unsupported => "Pas de rapports d'erreur Windows sur cette plateforme.",
        }
    }
}

/// Asks WER to skip `region` in any dump it collects.
///
/// # Safety
///
/// `region` must stay alive, at the same address, until [`release`] is called
/// with the same slice. Registering a stack buffer that then moves would leave
/// WER excluding an address that holds something else entirely.
pub fn exclude(region: &[u8]) -> Exclusion {
    imp::exclude(region)
}

/// Withdraws an exclusion registered by [`exclude`].
pub fn release(region: &[u8]) {
    imp::release(region);
}

/// Refuses when the exclusion could not be established and the caller demands
/// it — the `nomade` profile, where ADR-006 makes memory hygiene fatal.
pub fn require(region: &[u8]) -> Result<(), VaultError> {
    match exclude(region) {
        Exclusion::Registered => Ok(()),
        other => Err(VaultError::MemoryHygiene(other.detail())),
    }
}

#[cfg(windows)]
mod imp {
    // Glob rather than a named list: this module only compiles on Windows,
    // so an item added to the parent and forgotten here fails on the target
    // and nowhere else. See the note in `tpm.rs`.
    use super::*;
    use windows_sys::Win32::System::ErrorReporting::{
        WerRegisterExcludedMemoryBlock, WerUnregisterExcludedMemoryBlock,
    };

    pub fn exclude(region: &[u8]) -> Exclusion {
        if region.is_empty() {
            return Exclusion::Registered;
        }
        // SAFETY: the pointer and length describe a live allocation owned by
        // the caller, who is required to keep it alive until `release`.
        let status =
            unsafe { WerRegisterExcludedMemoryBlock(region.as_ptr().cast(), region.len() as u32) };
        // The API returns an `HRESULT`: success is `S_OK`, and a negative
        // value is the failure. Testing `!= 0` would reject `S_FALSE`.
        if status >= 0 {
            Exclusion::Registered
        } else {
            // Deliberately no address and no size in the message: a log is read
            // by more people than the process it describes.
            tracing::warn!("exclusion WER refusée — un vidage pourrait emporter un secret");
            Exclusion::Refused
        }
    }

    pub fn release(region: &[u8]) {
        if region.is_empty() {
            return;
        }
        // SAFETY: same region as the matching `exclude`.
        unsafe { WerUnregisterExcludedMemoryBlock(region.as_ptr().cast()) };
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Exclusion;

    pub fn exclude(_region: &[u8]) -> Exclusion {
        Exclusion::Unsupported
    }

    pub fn release(_region: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_registered_exclusion_holds() {
        assert!(Exclusion::Registered.holds());
        assert!(!Exclusion::Refused.holds());
        assert!(
            !Exclusion::Unsupported.holds(),
            "an absent primitive must never be reported as a guarantee"
        );
    }

    #[test]
    fn every_outcome_has_a_sentence_for_the_panel() {
        for outcome in [
            Exclusion::Registered,
            Exclusion::Refused,
            Exclusion::Unsupported,
        ] {
            assert!(!outcome.detail().is_empty());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_exclusion_is_unsupported_and_required_fails() {
        let region = [0u8; 32];
        assert_eq!(exclude(&region), Exclusion::Unsupported);
        release(&region);
        assert!(matches!(
            require(&region),
            Err(VaultError::MemoryHygiene(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_empty_regions_without_calling_wer() {
        assert_eq!(exclude(&[]), Exclusion::Registered);
        assert!(require(&[]).is_ok());
        release(&[]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_wer_registration_reports_its_real_outcome() {
        let region = [0x5au8; 64];
        let outcome = exclude(&region);
        assert!(matches!(
            outcome,
            Exclusion::Registered | Exclusion::Refused
        ));
        if outcome == Exclusion::Registered {
            release(&region);
        }
    }
}
