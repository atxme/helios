//! Session and power notifications, turned into [`LockEvent`]s.
//!
//! A message-only window on its own thread receives the notifications the
//! system sends a session: the session locks or logs off, the console or the
//! remote desktop disconnects, the machine suspends. The window procedure
//! only translates and sends; it never calls into the engine, which runs on
//! its runtime and reads the channel.
//!
//! [`translate`] is the whole decision and it is portable, so the codes are
//! tested under Linux. The Win32 calls are in `imp`, `cfg(windows)`.

use crate::service::LockEvent;

/// `WM_WTSSESSION_CHANGE`, sent to a window registered with
/// `WTSRegisterSessionNotification`.
const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
/// `WM_POWERBROADCAST`, sent to a window registered with
/// `RegisterSuspendResumeNotification`.
const WM_POWERBROADCAST: u32 = 0x0218;

const WTS_CONSOLE_DISCONNECT: usize = 2;
const WTS_REMOTE_DISCONNECT: usize = 4;
const WTS_SESSION_LOGOFF: usize = 6;
const WTS_SESSION_LOCK: usize = 7;
const PBT_APMSUSPEND: usize = 4;

/// The lock event a window message stands for, or `None` for any other
/// message. Unlock and resume are not events: they lock nothing.
pub fn translate(message: u32, wparam: usize) -> Option<LockEvent> {
    match message {
        WM_WTSSESSION_CHANGE => match wparam {
            WTS_SESSION_LOCK => Some(LockEvent::SessionLock),
            WTS_SESSION_LOGOFF => Some(LockEvent::SessionLogoff),
            WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => Some(LockEvent::SessionDisconnect),
            _ => None,
        },
        WM_POWERBROADCAST => match wparam {
            PBT_APMSUSPEND => Some(LockEvent::Suspend),
            _ => None,
        },
        _ => None,
    }
}

pub use imp::{start, LockWatch};

#[cfg(windows)]
mod imp {
    // Glob rather than a named list: this module only compiles on Windows, so
    // an item added to the parent and forgotten here fails on the target only.
    use super::*;
    use std::cell::RefCell;
    use std::sync::mpsc::{sync_channel, SyncSender};

    use tokio::sync::mpsc::UnboundedSender;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::{
        RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        PostThreadMessageW, RegisterClassW, TranslateMessage, UnregisterClassW,
        DEVICE_NOTIFY_WINDOW_HANDLE, HWND_MESSAGE, MSG, WM_QUIT, WNDCLASSW,
    };

    /// Window class of the watch. One watch per process.
    const CLASS_NAME: &str = "OrionLockWatch";

    thread_local! {
        /// Where the window procedure sends what it translates. Set on the
        /// watch's own thread, which is the only one that runs the procedure.
        static SENDER: RefCell<Option<UnboundedSender<LockEvent>>> = const { RefCell::new(None) };
    }

    /// Stops the watch when dropped: the thread leaves its message loop, then
    /// removes its registrations and its window.
    pub struct LockWatch {
        thread_id: u32,
    }

    impl Drop for LockWatch {
        fn drop(&mut self) {
            // SAFETY: posts a message to a thread id, with no pointer argument.
            // A thread that has already ended makes the post fail, which is fine.
            unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) };
        }
    }

    /// Starts the watch. Returns only once both registrations have succeeded:
    /// a failure is an error, and the caller keeps the lock watch off.
    pub fn start(sender: UnboundedSender<LockEvent>) -> Result<LockWatch, String> {
        let (ready, answer) = sync_channel(1);
        std::thread::Builder::new()
            .name("orion-lock-watch".into())
            .spawn(move || run(sender, ready))
            .map_err(|error| format!("lock watch thread: {error}"))?;
        match answer.recv() {
            Ok(Ok(thread_id)) => Ok(LockWatch { thread_id }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("lock watch thread ended before it was ready".to_string()),
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The watch's thread: registers, reports readiness, pumps messages, then
    /// unregisters everything it registered.
    fn run(sender: UnboundedSender<LockEvent>, ready: SyncSender<Result<u32, String>>) {
        let class = wide(CLASS_NAME);
        // SAFETY: a null name returns the handle of the executable's module.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let class_definition = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(window_procedure),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        // SAFETY: `class_definition` and the name it points to live until
        // `UnregisterClassW` below.
        if unsafe { RegisterClassW(&class_definition) } == 0 {
            let _ = ready.send(Err(last_error("RegisterClassW")));
            return;
        }

        // SAFETY: a message-only window, with no pointer argument but the class
        // name, which is alive for the call.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };
        if window.is_null() {
            let error = last_error("CreateWindowExW");
            unregister_class(&class, instance);
            let _ = ready.send(Err(error));
            return;
        }

        // SAFETY: the window was created above and is destroyed below.
        if unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) } == 0 {
            let error = last_error("WTSRegisterSessionNotification");
            destroy(window, &class, instance);
            let _ = ready.send(Err(error));
            return;
        }

        // SAFETY: the window handle is valid for the registration's lifetime.
        // The power notification is refused with a null handle.
        let power = unsafe {
            RegisterSuspendResumeNotification(window.cast(), DEVICE_NOTIFY_WINDOW_HANDLE)
        };
        if power == 0 {
            let error = last_error("RegisterSuspendResumeNotification");
            // SAFETY: the session registration above is still held.
            unsafe { WTSUnRegisterSessionNotification(window) };
            destroy(window, &class, instance);
            let _ = ready.send(Err(error));
            return;
        }

        // SAFETY: no pointer argument.
        let thread_id = unsafe { GetCurrentThreadId() };
        SENDER.with(|slot| *slot.borrow_mut() = Some(sender));
        let _ = ready.send(Ok(thread_id));

        let mut message = MSG::default();
        loop {
            // SAFETY: `message` is a valid out-parameter for the call.
            let status = unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) };
            // Zero is WM_QUIT, negative an error: either ends the watch.
            if status <= 0 {
                break;
            }
            // SAFETY: `message` was filled by GetMessageW.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        SENDER.with(|slot| slot.borrow_mut().take());
        // SAFETY: the handles registered above are released once each.
        unsafe {
            UnregisterSuspendResumeNotification(power);
            WTSUnRegisterSessionNotification(window);
        }
        destroy(window, &class, instance);
    }

    fn destroy(window: HWND, class: &[u16], instance: windows_sys::Win32::Foundation::HINSTANCE) {
        // SAFETY: `window` was created by this thread and is destroyed once.
        unsafe { DestroyWindow(window) };
        unregister_class(class, instance);
    }

    fn unregister_class(class: &[u16], instance: windows_sys::Win32::Foundation::HINSTANCE) {
        // SAFETY: `class` is the NUL-terminated name registered by `run`.
        unsafe { UnregisterClassW(class.as_ptr(), instance) };
    }

    fn last_error(call: &str) -> String {
        format!("{call} failed: {}", std::io::Error::last_os_error())
    }

    /// Translates the message and queues the event. Never calls the engine.
    unsafe extern "system" fn window_procedure(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if let Some(event) = translate(message, wparam) {
            SENDER.with(|slot| {
                if let Some(sender) = slot.borrow().as_ref() {
                    // Never blocks. A closed channel means the engine is
                    // stopping, and there is no one left to tell.
                    let _ = sender.send(event);
                }
            });
        }
        // SAFETY: forwarded unchanged to the system's default procedure.
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::LockEvent;
    use tokio::sync::mpsc::UnboundedSender;

    /// Never built off Windows: [`start`] refuses first.
    pub struct LockWatch(());

    /// Off Windows there is no session to watch, and the engine keeps its lock
    /// watch off, which refuses every passphrase unlock.
    pub fn start(_sender: UnboundedSender<LockEvent>) -> Result<LockWatch, String> {
        Err("the session and power watch exists only on Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_maps_each_notification() {
        assert_eq!(
            translate(WM_WTSSESSION_CHANGE, 7),
            Some(LockEvent::SessionLock)
        );
        assert_eq!(
            translate(WM_WTSSESSION_CHANGE, 6),
            Some(LockEvent::SessionLogoff)
        );
        assert_eq!(
            translate(WM_WTSSESSION_CHANGE, 2),
            Some(LockEvent::SessionDisconnect)
        );
        assert_eq!(
            translate(WM_WTSSESSION_CHANGE, 4),
            Some(LockEvent::SessionDisconnect)
        );
        assert_eq!(translate(WM_POWERBROADCAST, 4), Some(LockEvent::Suspend));
    }

    #[test]
    fn translate_ignores_unlock_resume_and_other_messages() {
        assert_eq!(translate(WM_WTSSESSION_CHANGE, 8), None);
        assert_eq!(translate(WM_POWERBROADCAST, 0x12), None);
        assert_eq!(translate(0, 7), None);
    }
}
