//! DPAPI user-scope envelope (ADR-006 §3, layer 2).
//!
//! # What this layer is, and what it is not
//!
//! It is **defence in depth over the TPM**, never a recovery path. The ADR
//! closed that ambiguity explicitly: DPAPI protects the TPM blob and its public
//! metadata, and **never holds a second envelope of the installation root**.
//! Holding a domain's DPAPI backup keys therefore buys nothing without the TPM
//! itself.
//!
//! It binds access to the Windows account, which is what stops another local
//! user from reading the wrapped material. It does **not** stop code running as
//! that same account — see ADR-006's T9. Nothing here claims otherwise.
//!
//! The domain entropy plays the same role as in `identity_store`: another
//! Helios secret sealed by the same user cannot be opened through this path.

use zeroize::Zeroizing;

use crate::vault::VaultError;

/// Domain separation of this envelope. A blob sealed here cannot be opened by
/// another Helios code path, and vice versa.
#[cfg_attr(not(windows), allow(dead_code))]
const ENTROPY: &[u8] = b"helios-orion-device-root-v1";

#[cfg(windows)]
mod imp {
    use super::{VaultError, Zeroizing, ENTROPY};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// Wraps a `CRYPT_INTEGER_BLOB` the OS allocated, so every exit path frees it.
    struct OwnedBlob(CRYPT_INTEGER_BLOB);

    impl OwnedBlob {
        fn as_slice(&self) -> &[u8] {
            if self.0.pbData.is_null() {
                return &[];
            }
            // SAFETY: the API guarantees `pbData` holds `cbData` valid bytes on
            // success, and we only build this wrapper after a success.
            unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
        }
    }

    impl Drop for OwnedBlob {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // Zeroize before returning the memory: the plaintext root key
                // passes through this buffer on the unwrap path.
                unsafe {
                    std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }

    fn input(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr().cast_mut(),
        }
    }

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // `CRYPTPROTECT_UI_FORBIDDEN`: this runs in a service-like path and
        // must fail rather than raise a dialog nobody is there to answer.
        let ok = unsafe {
            CryptProtectData(
                &input(plaintext),
                std::ptr::null(),
                &input(ENTROPY),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(VaultError::Dpapi(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let owned = OwnedBlob(out);
        Ok(owned.as_slice().to_vec())
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input(ciphertext),
                std::ptr::null_mut(),
                &input(ENTROPY),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(VaultError::Dpapi(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let owned = OwnedBlob(out);
        Ok(Zeroizing::new(owned.as_slice().to_vec()))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{VaultError, Zeroizing};

    pub fn protect(_plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        Err(VaultError::NoHardwareRoot)
    }

    pub fn unprotect(_ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Err(VaultError::NoHardwareRoot)
    }
}

/// Seals `plaintext` to the current Windows account.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    imp::protect(plaintext)
}

/// Opens what [`protect`] sealed, on the same account and machine.
pub fn unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    imp::unprotect(ciphertext)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// Off Windows the refusal is the contract, not a stub.
    #[test]
    fn both_directions_refuse_without_dpapi() {
        assert!(matches!(protect(b"x"), Err(VaultError::NoHardwareRoot)));
        assert!(matches!(unprotect(b"x"), Err(VaultError::NoHardwareRoot)));
    }
}
