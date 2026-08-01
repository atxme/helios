//! Native passphrase dialog for the `nomade` profile (ADR-006 §3, §5).
//!
//! # Why not a field in the Orion window
//!
//! ADR-006 §5 is explicit: the passphrase must not cross the WebView2 DOM,
//! JavaScript, or a serialised Tauri message. Each of those makes copies this
//! process cannot wipe — a JavaScript `String` is immutable and garbage
//! collected, a serialised command allocates buffers inside the IPC layer, and
//! the DOM keeps input values alive for as long as the node exists. Zeroizing
//! at the Rust end would then wipe one copy out of four.
//!
//! `CredUIPromptForWindowsCredentials` runs the dialog **inside the OS**. The
//! secret arrives as one buffer this module owns, unpacks and wipes.
//!
//! # What it does not protect against
//!
//! A keylogger, a malicious accessibility client, or a debugger attached to
//! this process at the moment of entry. ADR-006 says so in the same breath as
//! it retains the `nomade` profile: the profile stops a stolen, powered-off
//! laptop, not an attacker already present when the user types.

use zeroize::Zeroizing;

use crate::vault::VaultError;

/// Caption and message the OS dialog shows.
const CAPTION: &str = "Orion — profil nomade";
const MESSAGE: &str =
    "Saisir la passphrase du profil. Elle n'est stockée nulle part : elle déverrouille les \
     secrets à chaque session.";

/// Asks the user for their passphrase, through the platform's protected dialog.
///
/// The returned value is **not** validated: [`crate::vault::passphrase::accept`]
/// does that, so the policy stays testable off Windows and the dialog stays a
/// transport.
pub fn ask() -> Result<Zeroizing<String>, VaultError> {
    imp::ask(CAPTION, MESSAGE)
}

#[cfg(windows)]
mod imp {
    use super::{VaultError, Zeroizing};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Credentials::{
        CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW,
        CredUnPackAuthenticationBufferW, CREDUIWIN_ENUMERATE_CURRENT_USER, CREDUIWIN_GENERIC,
        CREDUI_INFOW,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn ask(caption: &str, message: &str) -> Result<Zeroizing<String>, VaultError> {
        let caption = wide(caption);
        let message = wide(message);
        let info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: std::ptr::null_mut(),
            pszMessageText: message.as_ptr(),
            pszCaptionText: caption.as_ptr(),
            hbmBanner: std::ptr::null_mut(),
        };

        let mut package = 0u32;
        let mut buffer: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut buffer_len = 0u32;
        let mut save = 0i32;

        let status = unsafe {
            CredUIPromptForWindowsCredentialsW(
                &info,
                0,
                &mut package,
                std::ptr::null(),
                0,
                &mut buffer,
                &mut buffer_len,
                &mut save,
                CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(VaultError::PassphraseCancelled);
        }

        // From here the buffer holds the secret: every exit path must wipe and
        // free it, which is what this guard is for.
        struct Buffer(*mut core::ffi::c_void, u32);
        impl Drop for Buffer {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        std::ptr::write_bytes(self.0.cast::<u8>(), 0, self.1 as usize);
                        CoTaskMemFree(self.0);
                    }
                }
            }
        }
        let owned = Buffer(buffer, buffer_len);

        let mut password = vec![0u16; 512];
        let mut password_len = password.len() as u32;
        let mut user = vec![0u16; 256];
        let mut user_len = user.len() as u32;
        let mut domain = vec![0u16; 256];
        let mut domain_len = domain.len() as u32;

        let unpacked = unsafe {
            CredUnPackAuthenticationBufferW(
                0,
                owned.0,
                owned.1,
                user.as_mut_ptr(),
                &mut user_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                password.as_mut_ptr(),
                &mut password_len,
            )
        };
        if unpacked == 0 {
            password.iter_mut().for_each(|unit| *unit = 0);
            return Err(VaultError::PassphraseCancelled);
        }

        // `password_len` counts the terminating NUL.
        let length = (password_len as usize).saturating_sub(1);
        let secret = Zeroizing::new(String::from_utf16_lossy(&password[..length]));
        // The UTF-16 staging buffer is a second copy of the secret; wipe it
        // before it is dropped, since `Vec<u16>` does not.
        password.iter_mut().for_each(|unit| *unit = 0);
        Ok(secret)
    }

    /// Kept referenced so the import stays meaningful to a reader auditing the
    /// packing side of this API.
    #[allow(dead_code)]
    fn _packing_is_available() {
        let _ = CredPackAuthenticationBufferW;
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{VaultError, Zeroizing};

    pub fn ask(_caption: &str, _message: &str) -> Result<Zeroizing<String>, VaultError> {
        Err(VaultError::NoNativePrompt)
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// Off Windows there is no protected dialog, and a text fallback would put
    /// the passphrase exactly where §5 forbids it.
    #[test]
    fn without_a_native_dialog_the_prompt_refuses() {
        assert!(matches!(ask(), Err(VaultError::NoNativePrompt)));
    }
}
