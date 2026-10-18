//! A window for the platform dialog to belong to.
//!
//! # Why a program with no interface needs a window
//!
//! Windows attaches its WebAuthn prompt to an owner window. `astra-signer` had
//! one for free — a console program owns its console — and asking the system
//! for it was the whole of that decision. This helper has no console: it is
//! launched by Orion, below Orion's token, with nothing attached. The same
//! call returns null, Windows accepts null, and the prompt opens **unowned**.
//!
//! An unowned dialog is not a dialog that fails. It is one that may open
//! behind the window the operator is reading, on a screen whose only
//! instruction is «touchez la clé». The key never answers, the ceremony times
//! out, and nothing anywhere says why. That failure has no error message by
//! construction, which is exactly the kind this helper must not be able to
//! produce.
//!
//! So the helper creates one: a top-level window, one pixel, off the taskbar,
//! shown without stealing focus and destroyed when the ceremony ends. It draws
//! nothing and receives nothing. It exists to be an owner.
//!
//! # Limite connue
//!
//! *Target-only, et non exercé dans ce dépôt.* WSL2 n'a pas de chaîne MSVC,
//! donc ce fichier ne se compile nulle part ici — comme `deelevate.rs`, DPAPI
//! et le TPM. Il doit être essayé sous Windows avant qu'on s'y fie, et ce
//! qu'il faut essayer en premier n'est pas le chemin heureux : c'est le refus
//! quand la fenêtre ne se crée pas.

use aether_fido::authenticator::DialogOwner;

/// A window owned for the length of a ceremony.
///
/// Dropping it destroys the window. Held by the caller rather than leaked
/// because a helper that ran two ceremonies would otherwise accumulate one
/// window per gesture, and because the destruction has to happen on the thread
/// that created it.
pub struct OwnerWindow {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HWND,
    #[cfg(not(windows))]
    handle: isize,
}

impl OwnerWindow {
    /// Activates the private owner immediately before a platform prompt.
    ///
    /// Orion transfers its foreground right on the corresponding button
    /// press. Merely owning a window does not consume that grant: the helper
    /// must bring this window forward before the WebAuthn broker creates its
    /// modal dialog.
    pub fn prompt_owner(&self) -> anyhow::Result<DialogOwner> {
        #[cfg(windows)]
        {
            windows::activate(self.handle)?;
            Ok(DialogOwner::Window(self.handle as isize))
        }
        #[cfg(not(windows))]
        {
            let _ = self.handle;
            Ok(DialogOwner::Console)
        }
    }
}

/// Creates the window the prompts will belong to.
///
/// On anything but Windows there is no platform dialog to own — the only
/// transport is raw CTAP, whose gesture is on the token and shows nothing — so
/// this is honestly nothing at all rather than a stub pretending otherwise.
#[cfg(not(windows))]
pub fn create() -> anyhow::Result<OwnerWindow> {
    Ok(OwnerWindow { handle: 0 })
}

#[cfg(windows)]
pub use windows::create;

#[cfg(windows)]
mod windows {
    use super::OwnerWindow;
    use anyhow::{bail, Result};
    use windows_sys::core::PCWSTR;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    /// Class name of the owner window. Registered once per process.
    const CLASS: &[u16] = &[
        b'H' as u16,
        b'e' as u16,
        b'l' as u16,
        b'i' as u16,
        b'o' as u16,
        b's' as u16,
        b'A' as u16,
        b's' as u16,
        b't' as u16,
        b'r' as u16,
        b'a' as u16,
        b'O' as u16,
        b'w' as u16,
        b'n' as u16,
        b'e' as u16,
        b'r' as u16,
        0,
    ];

    /// The window is a parent and nothing else: everything is default.
    unsafe extern "system" fn procedure(
        window: HWND,
        message: u32,
        w: WPARAM,
        l: LPARAM,
    ) -> LRESULT {
        DefWindowProcW(window, message, w, l)
    }

    pub fn create() -> Result<OwnerWindow> {
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(procedure),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: CLASS.as_ptr(),
        };
        // A second registration of the same class fails, and that is not an
        // error here: a helper that ran two ceremonies registers once. Only the
        // window creation below decides.
        unsafe { RegisterClassW(&class) };

        let handle = unsafe {
            CreateWindowExW(
                // Off the taskbar and out of Alt-Tab: this window is a parent,
                // not a place anybody should be able to switch to.
                WS_EX_TOOLWINDOW,
                CLASS.as_ptr(),
                CLASS.as_ptr() as PCWSTR,
                WS_POPUP,
                0,
                0,
                1,
                1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };
        if handle.is_null() {
            bail!(
                "impossible de créer la fenêtre propriétaire de la boîte WebAuthn : sans elle \
                 la boîte s'ouvrirait derrière Orion, et l'opérateur attendrait une invite \
                 qu'il ne voit pas"
            );
        }
        // Shown without activation while the manifest is verified and read.
        // `prompt_owner` activates it only after the operator's confirmation
        // and Orion's just-in-time foreground transfer.
        unsafe { ShowWindow(handle, SW_SHOWNOACTIVATE) };
        Ok(OwnerWindow { handle })
    }

    pub fn activate(handle: HWND) -> Result<()> {
        // SAFETY: `handle` is the live window created by `create`. Orion has
        // just granted this process the foreground right for this gesture.
        if unsafe { SetForegroundWindow(handle) } == 0 && unsafe { GetForegroundWindow() } != handle
        {
            bail!(
                "Windows a refusé de placer la boîte WebAuthn au premier plan ; \
                 recommencer depuis la fenêtre Orion active"
            );
        }
        Ok(())
    }

    impl Drop for OwnerWindow {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { DestroyWindow(self.handle) };
            }
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// Off Windows the only transport is raw CTAP, which shows nothing: the
    /// owner is honestly the console, and no window is claimed.
    #[test]
    fn there_is_nothing_to_own_where_there_is_no_dialog() {
        let window = create().expect("no window is needed here");
        assert_eq!(
            window.prompt_owner().expect("no prompt window is needed"),
            DialogOwner::Console
        );
    }
}
