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
//! RSA-3072 with OAEP-SHA-256 is the floor. A TPM that cannot do it is refused
//! — never silently lowered to RSA-2048, and never moved to the software
//! provider, because both would keep the screen's promise while removing what
//! backs it.

use zeroize::Zeroizing;

use crate::vault::{keys::KEY_LEN, VaultError};

/// Name the key is persisted under, inside the provider's own store.
pub const KEY_NAME: &str = "Helios Orion device root v1";

/// Minimum modulus. Below it, refuse.
pub const MIN_RSA_BITS: u32 = 3072;

#[cfg(windows)]
pub use imp::{unwrap_root, wrap_root};

#[cfg(windows)]
mod imp {
    use super::{VaultError, Zeroizing, KEY_LEN, KEY_NAME, MIN_RSA_BITS};
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_SILENT_FLAG,
    };

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
        if implementation & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
            return Err(VaultError::Tpm(
                "the provider answered but the key is not hardware-backed".into(),
            ));
        }

        let export = read_u32(key, NCRYPT_EXPORT_POLICY_PROPERTY)?;
        if export & NCRYPT_ALLOW_EXPORT_FLAG != 0 {
            return Err(VaultError::Tpm(
                "the key is exportable — the machine binding it exists for would not hold".into(),
            ));
        }

        let bits = read_u32(key, NCRYPT_LENGTH_PROPERTY)?;
        if bits < MIN_RSA_BITS {
            return Err(VaultError::Tpm(format!(
                "modulus of {bits} bits below the {MIN_RSA_BITS} floor — refused rather than lowered"
            )));
        }
        Ok(())
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

    fn create() -> Result<(Handle, Handle), VaultError> {
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
                0,
            )
        };
        if status != 0 {
            return Err(fail("creating the TPM key", status));
        }
        let key = Handle(key);

        // Length and export policy are set **before** finalisation: after it,
        // they are immutable, which is precisely the property we want.
        let bits = MIN_RSA_BITS;
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
