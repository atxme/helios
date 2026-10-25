//! Win32 half of the named pipe: server creation, process observation, SIDs.
//!
//! Everything here is `cfg(windows)` and was not compiled under WSL2 (no
//! MSVC): checked against the windows-sys 0.61 and tokio 1.53 sources. The
//! decisions live in the parent module, which is tested on Linux.

use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FILETIME, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{is_plain_sid, ObservedClient};

/// Longest image path Windows reports, in UTF-16 units, with its terminator.
const MAX_IMAGE_PATH: usize = 32_768;

/// Owns a Win32 handle and closes it on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from a Win32 call that opened it and is
            // closed exactly once, here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Creates the engine's pipe. Refused if the name is already taken, so a
/// program that squatted it first makes the engine stop instead of serving.
///
/// The DACL grants read and write to `client_sid` alone, and only the local
/// machine may connect.
pub fn create_server(name: &str, client_sid: &str) -> Result<NamedPipeServer, String> {
    if !is_plain_sid(client_sid) {
        return Err("SID de l'IHM invalide, tube refusé".into());
    }
    let sddl: Vec<u16> = format!("D:P(A;;GRGW;;;{client_sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call. On success
    // `descriptor` receives a LocalAlloc'd buffer, freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(format!(
            "descripteur de sécurité du tube refusé ({})",
            std::io::Error::last_os_error()
        ));
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .max_instances(1)
        .reject_remote_clients(true);
    // SAFETY: `attributes` and the descriptor it points at are alive for the
    // whole call; CreateNamedPipeW copies what it needs and keeps no pointer.
    let created = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    // SAFETY: `descriptor` came from the conversion above and is freed once,
    // after the pipe has been created or refused.
    unsafe { LocalFree(descriptor) };
    created.map_err(|error| format!("tube nommé refusé ({error})"))
}

/// Opens a process with the limited right to query it, or fails.
fn open_process(pid: u32) -> Result<OwnedHandle, String> {
    // SAFETY: OpenProcess takes no pointer; a null result is checked below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(format!(
            "processus {pid} inaccessible ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(OwnedHandle(raw))
}

/// Reads the PID, image path and creation time of a running process.
///
/// Fails rather than guessing: a zero creation time is refused, since it
/// could not be compared against the engine's own.
pub fn observe_process(pid: u32) -> Result<ObservedClient, String> {
    let process = open_process(pid)?;
    let mut buffer = vec![0u16; MAX_IMAGE_PATH];
    let mut length = MAX_IMAGE_PATH as u32;
    // SAFETY: `buffer` holds `length` UTF-16 units and the handle is open for
    // PROCESS_QUERY_LIMITED_INFORMATION.
    let named = unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut length,
        )
    };
    if named == 0 {
        return Err(format!(
            "chemin de l'image du processus {pid} illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let units = buffer
        .get(..length as usize)
        .ok_or_else(|| format!("chemin de l'image du processus {pid} illisible"))?;
    let image = PathBuf::from(OsString::from_wide(units));
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the four out-parameters are valid, writable FILETIME structs.
    let timed =
        unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) };
    if timed == 0 {
        return Err(format!(
            "date de création du processus {pid} illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let created_at = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if created_at == 0 {
        return Err(format!("date de création du processus {pid} nulle"));
    }
    Ok(ObservedClient {
        pid,
        image,
        created_at,
    })
}

/// Observes the process at the other end of a connected pipe.
pub fn observe_client(server: &NamedPipeServer) -> Result<ObservedClient, String> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to `server`, alive for the call; `pid` is a
    // valid u32 out-parameter.
    let found = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle(), &mut pid) };
    if found == 0 {
        return Err(format!(
            "PID du client du tube illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    observe_process(pid)
}

/// The PID of the process that created the pipe, as seen from a client.
///
/// The UI compares it with the engine's PID before sending anything, so a
/// third party that took the name first receives no token and no secret.
pub fn server_process_id(client: &NamedPipeClient) -> Result<u32, String> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to `client`, alive for the call; `pid` is a
    // valid u32 out-parameter.
    let found = unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) };
    if found == 0 {
        return Err(format!(
            "PID du serveur du tube illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(pid)
}

/// The user SID of a process's token, in string form (`S-1-5-…`).
pub fn process_user_sid(pid: u32) -> Result<String, String> {
    let process = open_process(pid)?;
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid handle; `raw` receives a token handle that
    // OwnedHandle closes.
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut raw) };
    if opened == 0 {
        return Err(format!(
            "jeton du processus {pid} illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    let token = OwnedHandle(raw);
    let mut needed = 0u32;
    // SAFETY: a null buffer of length 0 only asks for the size; the call fails
    // and writes the size into `needed`.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(format!("taille du jeton du processus {pid} inconnue"));
    }
    // Pointer-aligned storage: TOKEN_USER holds a pointer.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut returned = 0u32;
    // SAFETY: the buffer holds at least `needed` bytes and is aligned for
    // TOKEN_USER; `returned` is a valid out-parameter.
    let filled = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut returned,
        )
    };
    if filled == 0 {
        return Err(format!(
            "jeton du processus {pid} illisible ({})",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a successful TokenUser query writes one TOKEN_USER at the start
    // of `buffer`; its SID points into that same buffer, alive here.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if sid.is_null() {
        return Err(format!("SID du processus {pid} absent"));
    }
    let mut wide: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` points into `buffer`, alive for the call; on success `wide`
    // receives a LocalAlloc'd NUL-terminated string, freed below.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut wide) };
    if converted == 0 {
        return Err(format!(
            "SID du processus {pid} non convertible ({})",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `wide` is the NUL-terminated string the call just returned.
    let text = unsafe { copy_wide_string(wide) };
    // SAFETY: `wide` is freed exactly once, whether or not the copy succeeded.
    unsafe { LocalFree(wide.cast::<c_void>()) };
    text
}

/// Copies a NUL-terminated UTF-16 string into a `String`.
///
/// # Safety
///
/// `text` must point at a NUL-terminated UTF-16 string that stays valid for
/// the whole call.
unsafe fn copy_wide_string(text: *const u16) -> Result<String, String> {
    let mut length = 0usize;
    // SAFETY: the caller guarantees a terminator, so every unit before it is
    // readable.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the `length` units before the terminator are readable.
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    String::from_utf16(units).map_err(|_| "SID illisible".to_string())
}

/// Opens the engine's pipe as the UI.
pub fn connect_client(name: &str) -> Result<NamedPipeClient, String> {
    ClientOptions::new()
        .open(name)
        .map_err(|error| format!("connexion au tube impossible ({error})"))
}

#[cfg(test)]
mod tests {
    use super::super::{pipe_name, same_image};
    use super::*;

    fn unique_name() -> String {
        let nonce = aether::random::secret_bytes::<16>().expect("randomness available");
        pipe_name(std::process::id(), &nonce)
    }

    #[tokio::test]
    async fn a_second_server_on_the_same_name_is_refused() {
        let sid = process_user_sid(std::process::id()).expect("own SID readable");
        let name = unique_name();
        let _first = create_server(&name, &sid).expect("first server");
        assert!(create_server(&name, &sid).is_err());
    }

    #[test]
    fn this_process_is_observed_as_itself() {
        let observed = observe_process(std::process::id()).expect("own process observable");
        let current = std::env::current_exe().expect("current exe");
        assert!(same_image(&observed.image, &current));
        assert!(observed.created_at > 0);
    }

    #[tokio::test]
    async fn a_connected_client_is_this_process() {
        let sid = process_user_sid(std::process::id()).expect("own SID readable");
        let name = unique_name();
        let server = create_server(&name, &sid).expect("server");
        let client = connect_client(&name).expect("client");
        server.connect().await.expect("client connected");
        let observed = observe_client(&server).expect("client observed");
        assert_eq!(observed.pid, std::process::id());
        assert_eq!(
            server_process_id(&client).expect("server observed"),
            std::process::id()
        );
    }

    #[test]
    fn a_malformed_sid_is_refused() {
        assert!(create_server(&unique_name(), "S-1)(A;;GA;;;WD").is_err());
    }
}
