//! Non-exportable TPM key in the *Microsoft Platform Crypto Provider*
//! (ADR-006 §3, layer 1).
//!
//! # What this layer buys, precisely
//!
//! The private key lives **in the TPM** and never leaves it. Copying the sealed
//! files to another machine therefore makes them permanently unreadable — that
//! is the whole answer to threat T4, and the reason a software provider is
//! refused rather than accepted quietly.
//!
//! It does **not** make the installation root non-exportable. Orion asks the
//! TPM to unwrap, and the plaintext root comes back into this process. Code
//! running as the same account can observe it at that moment (T9). The TPM
//! bounds a compromise in time and space; it does not prevent one.
//!
//! # Four verifications, before anything is persisted
//!
//! ADR-006 §3 requires checking the provider, the non-exportability, the ACL
//! and the operation result **before** writing. The order matters: a key
//! created and then found wanting must not have left a file behind that a later
//! run would adopt. So the checks happen on the freshly finalised handle, and
//! the material is only written once they pass.
//!
//! OAEP-SHA-256 over RSA. The modulus is **preferred** at 3072 and **floored**
//! at 2048 — see [`MIN_RSA_BITS`] for why the hardware settled that argument.
//! Falling back is announced in the log; moving to the software provider never
//! happens, because that would keep the screen's promise while removing what
//! backs it.

use zeroize::Zeroizing;

use crate::vault::{keys::KEY_LEN, VaultError};

/// Name the key is persisted under, inside the provider's own store.
pub const KEY_NAME: &str = "Helios Orion device root v1";

/// Modulus asked for first.
///
/// Kept as the preference, not as a requirement — see [`MIN_RSA_BITS`].
pub const PREFERRED_RSA_BITS: u32 = 3072;

/// Smallest modulus accepted. Below it, refuse.
///
/// # Pourquoi 2048 et non 3072 (amendement du 2 août 2026)
///
/// La décision initiale posait 3072 en plancher et refusait tout TPM qui ne le
/// portait pas. Le matériel a tranché autrement : le *TPM 2.0 PC Client
/// Profile* n'impose que **RSA-2048**, et 3072 y est facultatif — donc absent
/// de la quasi-totalité des puces. `NCryptSetProperty(NCRYPT_LENGTH_PROPERTY)`
/// y répond `NTE_INVALID_PARAMETER` (0x80090027), la création échoue, et Orion
/// refuse alors de conserver le moindre secret. Un plancher que le matériel
/// courant ne franchit pas ne protège rien : il supprime la fonctionnalité.
///
/// Ce que cette clé garantit est la **non-exportabilité** — un coffre copié sur
/// une autre machine y reste illisible — et cette propriété ne dépend pas du
/// module. Elle enveloppe 32 octets ; contre RSA-2048, un adversaire a des
/// chemins bien moins coûteux que la factorisation.
///
/// [`PREFERRED_RSA_BITS`] reste demandé en premier et obtenu quand le TPM le
/// porte. Le repli est **annoncé**, jamais silencieux : c'est la différence que
/// l'ADR-006 exige entre dégrader et se taire.
pub const MIN_RSA_BITS: u32 = 2048;

/// Who the persisted key belongs to, as the platform reports it.
///
/// The fourth check of ADR-006 §3, and the one that was missing: provider,
/// non-exportability and modulus say the key is *good*, none of them says it is
/// **ours**. A key persisted under our name but owned by another principal
/// would still satisfy the other three while letting that principal use the
/// installation root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum KeyOwnership {
    /// The security descriptor's owner is the account running this process.
    CurrentUser,
    /// It is somebody else. Refused rather than used.
    AnotherPrincipal,
    /// The descriptor, the owner or the process token could not be read.
    ///
    /// Refused too: ADR-006 §3 states that a property which cannot be verified
    /// is not a guarantee, and this enum exists so that stays a decision rather
    /// than an omission.
    Unverifiable,
}

/// Checks the security properties independently of the Win32 property reader.
///
/// Keeping the decision pure lets every refusal branch run on every host,
/// while the Windows suite separately exercises the CNG calls that obtain the
/// values.
#[cfg(any(windows, test))]
fn validate_key_properties(
    hardware_backed: bool,
    export_allowed: bool,
    bits: u32,
    ownership: KeyOwnership,
) -> Result<(), VaultError> {
    if !hardware_backed {
        return Err(VaultError::Tpm(
            "the provider answered but the key is not hardware-backed".into(),
        ));
    }
    if export_allowed {
        return Err(VaultError::Tpm(
            "the key is exportable — the machine binding it exists for would not hold".into(),
        ));
    }
    if bits < MIN_RSA_BITS {
        return Err(VaultError::Tpm(format!(
            "modulus of {bits} bits below the {MIN_RSA_BITS} floor — refused rather than lowered"
        )));
    }
    match ownership {
        KeyOwnership::CurrentUser => Ok(()),
        KeyOwnership::AnotherPrincipal => Err(VaultError::Tpm(
            "the TPM key is owned by another principal — a key persisted under our name that we \
             do not own is refused, not adopted"
                .into(),
        )),
        KeyOwnership::Unverifiable => Err(VaultError::Tpm(
            "the TPM key's owner could not be read — an unverifiable ACL is not an ACL".into(),
        )),
    }
}

#[cfg(windows)]
pub use imp::{unwrap_root, wrap_root};

#[cfg(windows)]
mod imp {
    // Glob rather than a named list, deliberately. This module only compiles on
    // Windows, and the workstation that builds it is not the one that edits it:
    // an item added above and forgotten here fails on the target, minutes into a
    // build, with an error nobody on Linux ever sees — `PREFERRED_RSA_BITS` did
    // exactly that. The parent module is small, private and entirely dedicated
    // to this one, so the usual argument against a glob does not apply.
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_OAEP_FLAG,
        NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SILENT_FLAG,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorOwner, GetTokenInformation, TokenUser,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Frees an `NCRYPT_*` handle on every exit path, including a `?`.
    struct Handle(usize);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { NCryptFreeObject(self.0 as NCRYPT_HANDLE) };
            }
        }
    }

    /// Only the key **name** needs converting: every `NCRYPT_*` and
    /// `BCRYPT_*` property constant is already a `PCWSTR` in `windows-sys`.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn fail(step: &str, status: i32) -> VaultError {
        VaultError::Tpm(format!("{step} failed with NTSTATUS {status:#010x}"))
    }

    fn open_provider() -> Result<Handle, VaultError> {
        let mut provider = 0usize;
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        if status != 0 {
            // No platform provider at all: this machine has no usable TPM, and
            // that is a refusal, not a reason to fall back.
            return Err(VaultError::NoHardwareRoot);
        }
        Ok(Handle(provider))
    }

    fn read_u32(handle: usize, property: windows_sys::core::PCWSTR) -> Result<u32, VaultError> {
        let mut value = 0u32;
        let mut written = 0u32;
        let status = unsafe {
            NCryptGetProperty(
                handle as NCRYPT_HANDLE,
                property,
                (&raw mut value).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut written,
                0,
            )
        };
        if status != 0 {
            return Err(fail("reading a key property", status));
        }
        Ok(value)
    }

    /// The four checks ADR-006 §3 demands, on a handle we are about to trust.
    ///
    /// A property that cannot be **read** is as disqualifying as one with the
    /// wrong value: an unverifiable guarantee is not a guarantee, and assuming
    /// it would be exactly the silent downgrade the ADR forbids.
    fn verify(key: usize) -> Result<(), VaultError> {
        let implementation = read_u32(key, NCRYPT_IMPL_TYPE_PROPERTY)?;
        let export = read_u32(key, NCRYPT_EXPORT_POLICY_PROPERTY)?;
        let bits = read_u32(key, NCRYPT_LENGTH_PROPERTY)?;
        validate_key_properties(
            implementation & NCRYPT_IMPL_HARDWARE_FLAG != 0,
            export & NCRYPT_ALLOW_EXPORT_FLAG != 0,
            bits,
            ownership_of(key),
        )
    }

    /// SID of the account this process runs as, owned for the call's duration.
    ///
    /// The buffer is variable-length — a `SID` grows with its sub-authorities —
    /// so `GetTokenInformation` is called twice: once for the size, once for
    /// the value. The `PSID` inside points **into** the returned buffer, which
    /// is why the buffer is handed back with it rather than dropped.
    fn current_user_sid() -> Option<(Vec<u8>, PSID)> {
        struct Token(HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        let mut raw: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close;
        // `raw` is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return None;
        }
        let token = Token(raw);

        let mut needed = 0u32;
        // First call sizes the buffer; it is expected to fail with
        // ERROR_INSUFFICIENT_BUFFER, so only `needed` is trusted here.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return None;
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is exactly the size the call just asked for.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: on success the buffer starts with a `TOKEN_USER`, whose
        // `User.Sid` points inside that same buffer.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if sid.is_null() {
            return None;
        }
        Some((buffer, sid))
    }

    /// Reads the key's owner and compares it to the current account.
    ///
    /// Every failure collapses into [`KeyOwnership::Unverifiable`], which
    /// `validate_key_properties` refuses: distinguishing "no descriptor" from
    /// "unreadable token" would change the log and not the decision, and a
    /// branch that answered `CurrentUser` on a technicality would cost the
    /// whole check.
    fn ownership_of(key: usize) -> KeyOwnership {
        let mut needed = 0u32;
        // Sizing pass. The descriptor is variable-length like the SID above.
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                std::ptr::null_mut(),
                0,
                &mut needed,
                OWNER_SECURITY_INFORMATION,
            )
        };
        if status != 0 || needed == 0 {
            return KeyOwnership::Unverifiable;
        }
        let mut descriptor = vec![0u8; needed as usize];
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.as_mut_ptr(),
                needed,
                &mut needed,
                OWNER_SECURITY_INFORMATION,
            )
        };
        if status != 0 {
            return KeyOwnership::Unverifiable;
        }

        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0i32;
        // SAFETY: `descriptor` holds a self-relative security descriptor the
        // provider just wrote; `owner` points into it on success.
        let ok = unsafe {
            GetSecurityDescriptorOwner(
                descriptor.as_ptr() as PSECURITY_DESCRIPTOR,
                &mut owner,
                &mut defaulted,
            )
        };
        if ok == 0 || owner.is_null() {
            return KeyOwnership::Unverifiable;
        }

        let Some((_token_buffer, ours)) = current_user_sid() else {
            return KeyOwnership::Unverifiable;
        };
        // SAFETY: both SIDs are valid for the duration of this scope —
        // `owner` inside `descriptor`, `ours` inside `_token_buffer`.
        if unsafe { EqualSid(owner, ours) } != 0 {
            KeyOwnership::CurrentUser
        } else {
            KeyOwnership::AnotherPrincipal
        }
    }

    fn open_existing() -> Result<Option<(Handle, Handle)>, VaultError> {
        let provider = open_provider()?;
        let mut key = 0usize;
        let name = wide(KEY_NAME);
        let status =
            unsafe { NCryptOpenKey(provider.0, &mut key, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status != 0 {
            return Ok(None);
        }
        let key = Handle(key);
        verify(key.0)?;
        Ok(Some((provider, key)))
    }

    /// Creates the persisted key, at the largest modulus this TPM accepts.
    ///
    /// Tries [`PREFERRED_RSA_BITS`] then [`MIN_RSA_BITS`]. Most TPM 2.0 chips
    /// implement only the mandatory RSA-2048 and answer `NTE_INVALID_PARAMETER`
    /// to anything larger — refusing outright, as the first version did, made
    /// Orion unusable on ordinary hardware.
    ///
    /// The fallback is announced. A degradation nobody is told about is the one
    /// failure mode ADR-006 refuses everywhere else.
    fn create() -> Result<(Handle, Handle), VaultError> {
        let mut last = None;
        for bits in [PREFERRED_RSA_BITS, MIN_RSA_BITS] {
            match create_at(bits) {
                Ok(handles) => {
                    if bits < PREFERRED_RSA_BITS {
                        tracing::warn!(
                            bits,
                            preferred = PREFERRED_RSA_BITS,
                            "TPM sans RSA-{PREFERRED_RSA_BITS} : clé d'enveloppe créée en \
                             RSA-{bits}. La liaison matérielle et la non-exportabilité sont \
                             conservées ; c'est le module qui est plus court."
                        );
                    }
                    return Ok(handles);
                }
                // Only a refusal of the *size* is worth retrying smaller. A
                // provider that is absent, or a key we do not own, would fail
                // identically at every size — retrying would just hide it
                // behind a second, less precise error.
                Err(error) if retryable_at_a_smaller_modulus(&error) => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| VaultError::Tpm("no RSA modulus accepted by this TPM".into())))
    }

    /// `true` when the failure plausibly comes from the requested modulus.
    fn retryable_at_a_smaller_modulus(error: &VaultError) -> bool {
        matches!(error, VaultError::Tpm(message) if message.contains("modulus length")
            || message.contains("finalising"))
    }

    fn create_at(bits: u32) -> Result<(Handle, Handle), VaultError> {
        let provider = open_provider()?;
        let mut key = 0usize;
        let name = wide(KEY_NAME);
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                name.as_ptr(),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("creating the TPM key", status));
        }
        let key = Handle(key);

        // Length and export policy are set **before** finalisation: after it,
        // they are immutable, which is precisely the property we want.
        let status = unsafe {
            NCryptSetProperty(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_LENGTH_PROPERTY,
                (&raw const bits).cast(),
                std::mem::size_of::<u32>() as u32,
                0,
            )
        };
        if status != 0 {
            return Err(fail("setting the modulus length", status));
        }

        let no_export = 0u32;
        let status = unsafe {
            NCryptSetProperty(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                (&raw const no_export).cast(),
                std::mem::size_of::<u32>() as u32,
                0,
            )
        };
        if status != 0 {
            return Err(fail("forbidding export", status));
        }

        let status = unsafe { NCryptFinalizeKey(key.0, 0) };
        if status != 0 {
            return Err(fail("finalising the TPM key", status));
        }
        verify(key.0)?;
        Ok((provider, key))
    }

    fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        }
    }

    /// Wraps the installation root under the TPM key, creating it on first use.
    pub fn wrap_root(root: &[u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
        let (_provider, key) = match open_existing()? {
            Some(handles) => handles,
            None => create()?,
        };
        let padding = oaep();

        let mut needed = 0u32;
        let status = unsafe {
            NCryptEncrypt(
                key.0,
                root.as_ptr(),
                root.len() as u32,
                (&raw const padding).cast(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("sizing the TPM wrap", status));
        }
        let mut wrapped = vec![0u8; needed as usize];
        let mut written = 0u32;
        let status = unsafe {
            NCryptEncrypt(
                key.0,
                root.as_ptr(),
                root.len() as u32,
                (&raw const padding).cast(),
                wrapped.as_mut_ptr(),
                wrapped.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("wrapping under the TPM key", status));
        }
        wrapped.truncate(written as usize);
        Ok(wrapped)
    }

    /// Unwraps the installation root. Absence of the key is fatal: there is no
    /// second envelope to fall back on, by design.
    pub fn unwrap_root(wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let Some((_provider, key)) = open_existing()? else {
            return Err(VaultError::TpmKeyLost);
        };
        let padding = oaep();

        let mut needed = 0u32;
        let status = unsafe {
            NCryptDecrypt(
                key.0,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                (&raw const padding).cast(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(VaultError::TpmKeyLost);
        }
        let mut plaintext = Zeroizing::new(vec![0u8; needed as usize]);
        let mut written = 0u32;
        let status = unsafe {
            NCryptDecrypt(
                key.0,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                (&raw const padding).cast(),
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(VaultError::TpmKeyLost);
        }
        if written as usize != KEY_LEN {
            return Err(VaultError::Tpm(format!(
                "unwrapped {written} bytes where {KEY_LEN} were expected"
            )));
        }
        let mut root = Zeroizing::new([0u8; KEY_LEN]);
        root.copy_from_slice(&plaintext[..KEY_LEN]);
        Ok(root)
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;

    #[test]
    fn only_hardware_non_exportable_keys_at_the_rsa_floor_are_accepted() {
        let ours = KeyOwnership::CurrentUser;
        assert!(validate_key_properties(true, false, MIN_RSA_BITS, ours).is_ok());
        assert!(validate_key_properties(true, false, MIN_RSA_BITS + 1024, ours).is_ok());

        let software = validate_key_properties(false, false, MIN_RSA_BITS, ours).unwrap_err();
        assert!(
            matches!(software, VaultError::Tpm(message) if message.contains("not hardware-backed"))
        );

        let exportable = validate_key_properties(true, true, MIN_RSA_BITS, ours).unwrap_err();
        assert!(matches!(exportable, VaultError::Tpm(message) if message.contains("exportable")));

        let weak = validate_key_properties(true, false, MIN_RSA_BITS - 1, ours).unwrap_err();
        assert!(matches!(weak, VaultError::Tpm(message) if message.contains("below")));
    }

    /// The fourth check ADR-006 §3 demands, and the one that was absent.
    ///
    /// Provider, non-exportability and modulus establish that the key is
    /// *sound*; none of them establishes that it is **ours**. Both non-`ours`
    /// answers must refuse — including the unreadable one, because the ADR is
    /// explicit that a property which cannot be verified is not a guarantee.
    #[test]
    fn a_key_that_is_not_ours_is_refused_even_when_every_other_property_holds() {
        let sound = |ownership| validate_key_properties(true, false, MIN_RSA_BITS, ownership);

        assert!(sound(KeyOwnership::CurrentUser).is_ok());

        let foreign = sound(KeyOwnership::AnotherPrincipal).unwrap_err();
        assert!(
            matches!(foreign, VaultError::Tpm(ref message) if message.contains("another principal")),
            "obtenu : {foreign}"
        );

        let unknown = sound(KeyOwnership::Unverifiable).unwrap_err();
        assert!(
            matches!(unknown, VaultError::Tpm(ref message) if message.contains("could not be read")),
            "obtenu : {unknown}"
        );
    }
}

#[cfg(not(windows))]
pub fn wrap_root(_root: &[u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
    Err(VaultError::NoHardwareRoot)
}

#[cfg(not(windows))]
pub fn unwrap_root(_wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    Err(VaultError::NoHardwareRoot)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn without_a_platform_provider_both_directions_refuse() {
        assert!(matches!(
            wrap_root(&[0u8; KEY_LEN]),
            Err(VaultError::NoHardwareRoot)
        ));
        assert!(matches!(
            unwrap_root(b"wrapped"),
            Err(VaultError::NoHardwareRoot)
        ));
    }
}
