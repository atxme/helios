//! Volume-encryption posture (ADR-006 §3).
//!
//! # Why Orion checks a property it does not own
//!
//! Application encryption does not cover the old SSD blocks a rewrite cannot
//! reach, nor every copy in the pagefile and the hibernation file. The ADR
//! therefore makes volume encryption a **prerequisite that is verified**, not a
//! recommendation in a guide: import, migration and auto-connect are refused
//! without it.
//!
//! # Indeterminate is a refusal, not a pass
//!
//! `Unknown` and "could not ask" collapse into the same outcome on purpose. A
//! posture we cannot establish is a posture we cannot promise, and the failure
//! mode of guessing "probably fine" is a user believing their disk is protected
//! when it is not.
//!
//! # Why WMI rather than `manage-bde`
//!
//! `manage-bde -status` prints **localised** text. Parsing it would make the
//! security posture depend on the display language of the machine — a French
//! Windows would silently stop matching. `Win32_EncryptableVolume` exposes
//! `ProtectionStatus` as an integer, which no translation changes.

use crate::vault::VaultError;

/// What the platform reports about the volume holding the profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeProtection {
    /// Protection on, key not exposed.
    Protected,
    /// Encryption off, or suspended with the key in the clear.
    Unprotected,
    /// The question could not be answered. Treated as a refusal.
    Indeterminate,
}

impl VolumeProtection {
    /// Whether Orion may import, migrate or auto-connect.
    ///
    /// Only [`Self::Protected`] allows it — the two other cases are the same
    /// decision reached from different information.
    pub fn allows_secrets(self) -> bool {
        matches!(self, Self::Protected)
    }

    /// Sentence shown in the posture panel.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Protected => {
                "Volume chiffré : les anciens blocs et le fichier d'hibernation \
                 sont couverts."
            }
            Self::Unprotected => {
                "Volume non chiffré. Le chiffrement applicatif ne couvre ni les \
                 anciens blocs SSD ni le fichier d'hibernation : activer BitLocker."
            }
            Self::Indeterminate => {
                "Posture de chiffrement du volume indéterminable — traitée \
                 comme absente : Orion ne peut pas promettre ce qu'il ne peut pas vérifier."
            }
        }
    }
}

/// `ProtectionStatus` values of `Win32_EncryptableVolume`.
#[cfg(windows)]
const PROTECTION_OFF: i32 = 0;
#[cfg(windows)]
const PROTECTION_ON: i32 = 1;

/// Reports the posture of the volume holding `path`.
pub fn protection_of(path: &std::path::Path) -> VolumeProtection {
    imp::protection_of(path)
}

/// Refuses unless the volume is protected.
pub fn require_protected(path: &std::path::Path) -> Result<(), VaultError> {
    let protection = protection_of(path);
    if protection.allows_secrets() {
        Ok(())
    } else {
        Err(VaultError::VolumeUnprotected(protection))
    }
}

#[cfg(windows)]
mod imp {
    use super::{VolumeProtection, PROTECTION_OFF, PROTECTION_ON};
    use std::path::Path;
    use windows::core::BSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::System::Wmi::{
        IWbemLocator, WbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
        WBEM_INFINITE,
    };

    /// The BitLocker namespace. Its class exposes `ProtectionStatus` as an
    /// integer, which is why this path is used rather than parsing the
    /// localised output of `manage-bde`.
    const NAMESPACE: &str = r"root\CIMV2\Security\MicrosoftVolumeEncryption";

    /// Drive letter of the volume holding `path`, as `C:`.
    ///
    /// The result is interpolated into a WQL string, so the shape is enforced
    /// here: exactly one ASCII letter and a colon. Nothing else can reach the
    /// query, which is what stops it from being widened.
    fn volume_of(path: &Path) -> Option<String> {
        let text = path.to_string_lossy();
        let mut characters = text.chars();
        let letter = characters.next()?;
        if characters.next()? != ':' || !letter.is_ascii_alphabetic() {
            return None;
        }
        Some(format!("{}:", letter.to_ascii_uppercase()))
    }

    /// Every failure funnels into `Indeterminate`: the caller treats it as a
    /// refusal, so distinguishing "COM refused" from "class absent" buys
    /// nothing — and a path that returned `Protected` on a technicality would
    /// cost everything.
    pub fn protection_of(path: &Path) -> VolumeProtection {
        let Some(volume) = volume_of(path) else {
            return VolumeProtection::Indeterminate;
        };
        unsafe { query(&volume).unwrap_or(VolumeProtection::Indeterminate) }
    }

    unsafe fn query(volume: &str) -> windows::core::Result<VolumeProtection> {
        // `S_FALSE` means this thread had already initialised COM: we must not
        // uninitialise what we did not start.
        let initialised = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let owns_com = initialised.is_ok();
        let result = unsafe { query_inner(volume) };
        if owns_com {
            unsafe { CoUninitialize() };
        }
        result
    }

    unsafe fn query_inner(volume: &str) -> windows::core::Result<VolumeProtection> {
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
        let services = unsafe {
            locator.ConnectServer(
                &BSTR::from(NAMESPACE),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
        }?;
        unsafe {
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
        }?;

        let text = format!(
            "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{volume}'"
        );
        let rows = unsafe {
            services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(text),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
        }?;

        let mut row = [None; 1];
        let mut returned = 0u32;
        unsafe { rows.Next(WBEM_INFINITE, &mut row, &mut returned) }.ok()?;
        let Some(object) = row[0].as_ref().filter(|_| returned > 0) else {
            // No `Win32_EncryptableVolume` for that letter: the machine cannot
            // answer, which is not the same as answering "off".
            return Ok(VolumeProtection::Indeterminate);
        };

        let mut value = VARIANT::default();
        unsafe {
            object.Get(
                &windows::core::HSTRING::from("ProtectionStatus"),
                0,
                &mut value,
                None,
                None,
            )
        }?;
        // `ProtectionStatus` is a `uint32` carried in `VT_I4`.
        let status = i32::try_from(&value).unwrap_or(-1);
        Ok(match status {
            PROTECTION_ON => VolumeProtection::Protected,
            PROTECTION_OFF => VolumeProtection::Unprotected,
            // `2` is "unknown", and anything else is a value this build does
            // not know: both are unanswered questions.
            _ => VolumeProtection::Indeterminate,
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use super::VolumeProtection;

    /// Off Windows there is no BitLocker to ask about.
    ///
    /// `Indeterminate` rather than `Unprotected`: dm-crypt may well be in use,
    /// and claiming otherwise would be a statement we have not verified. The
    /// caller refuses on both, so the safe behaviour is identical while the
    /// message stays truthful.
    pub fn protection_of(_path: &std::path::Path) -> VolumeProtection {
        VolumeProtection::Indeterminate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_protected_volume_allows_secrets() {
        assert!(VolumeProtection::Protected.allows_secrets());
        assert!(!VolumeProtection::Unprotected.allows_secrets());
        assert!(
            !VolumeProtection::Indeterminate.allows_secrets(),
            "an unanswered question must never be read as a yes"
        );
    }

    #[test]
    fn every_posture_has_a_sentence_for_the_panel() {
        for posture in [
            VolumeProtection::Protected,
            VolumeProtection::Unprotected,
            VolumeProtection::Indeterminate,
        ] {
            assert!(!posture.detail().is_empty());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_posture_is_indeterminate_and_refuses() {
        let path = std::path::Path::new("/var/lib/orion");
        assert_eq!(protection_of(path), VolumeProtection::Indeterminate);
        assert!(matches!(
            require_protected(path),
            Err(VaultError::VolumeUnprotected(
                VolumeProtection::Indeterminate
            ))
        ));
    }
}
