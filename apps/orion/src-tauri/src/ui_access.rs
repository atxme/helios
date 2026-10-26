//! Rights the UI grants the Administrators group on its own process and token,
//! before it launches the engine.
//!
//! When a standard user types another administrator's credentials at the UAC
//! prompt, the engine runs under that account. The default DACL of the UI's
//! process and token grants neither the Administrators group nor that account,
//! so the engine could not observe the UI. The UI grants the group what the
//! engine reads, and nothing else: waiting on the process and querying its
//! image and creation time, and reading the token's user. `SeDebugPrivilege`
//! already lets an administrator do as much.
//!
//! The entries are merged into the existing DACL, never put in its place. A
//! failed grant only keeps the narrower rights: it is logged and the launch
//! goes on. An engine of the same account does not need it, and one of another
//! account then stops with `OTHER_ACCOUNT_ELEVATION`.

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_KERNEL_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
    TOKEN_READ_CONTROL, TOKEN_WRITE_DAC,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

/// Well-known SID of the local Administrators group (`BA`).
#[cfg(any(windows, test))]
pub(crate) const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// What Administrators get on the UI's process, by value:
/// `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`.
#[cfg(any(windows, test))]
pub(crate) const UI_PROCESS_GRANT: u32 = 0x0010_0000 | 0x0000_1000;

/// What Administrators get on the UI's token, by value: `TOKEN_QUERY`.
#[cfg(any(windows, test))]
pub(crate) const UI_TOKEN_GRANT: u32 = 0x0000_0008;

// The masks by value above are the windows-sys rights they name.
#[cfg(windows)]
const _: () = assert!(UI_PROCESS_GRANT == PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
#[cfg(windows)]
const _: () = assert!(UI_TOKEN_GRANT == TOKEN_QUERY);

/// Grants Administrators [`UI_PROCESS_GRANT`] on this process and
/// [`UI_TOKEN_GRANT`] on its token. A failure is logged and changes nothing.
#[cfg(windows)]
pub(crate) fn let_administrators_observe_the_ui() {
    // SAFETY: GetCurrentProcess returns a pseudo-handle, never closed, with
    // every right on this process, WRITE_DAC included.
    let process = unsafe { GetCurrentProcess() };
    if let Err(error) = grant_administrators(process, UI_PROCESS_GRANT) {
        tracing::warn!(%error, "droits des administrateurs sur le processus de l'IHM non accordés");
    }
    if let Err(error) = grant_on_own_token() {
        tracing::warn!(%error, "droits des administrateurs sur le jeton de l'IHM non accordés");
    }
}

/// Opens this process's token to read and change its DACL, and grants
/// Administrators [`UI_TOKEN_GRANT`] on it.
#[cfg(windows)]
fn grant_on_own_token() -> Result<(), String> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle needs no closing; `raw` is a valid
    // out-parameter, owned below on success.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_READ_CONTROL | TOKEN_WRITE_DAC,
            &mut raw,
        )
    };
    if opened == 0 {
        return Err(format!(
            "jeton de l'IHM inaccessible ({})",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the handle was just opened, and is closed once, on drop.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    grant_administrators(token.as_raw_handle(), UI_TOKEN_GRANT)
}

/// Merges one entry granting `rights` to Administrators into the DACL of
/// `object`, a kernel object handle open for `READ_CONTROL | WRITE_DAC`.
///
/// The existing entries are kept. An object with no DACL is left alone:
/// merging into it would replace "everyone" with Administrators alone.
#[cfg(windows)]
fn grant_administrators(object: HANDLE, rights: u32) -> Result<(), String> {
    let administrators = LocalMemory::sid(ADMINISTRATORS_SID)?;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: every out-parameter is valid or null where the call allows it.
    // On success `descriptor` is LocalAlloc'd, and `dacl` points into it.
    let read = unsafe {
        GetSecurityInfo(
            object,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if read != ERROR_SUCCESS {
        return Err(format!("DACL illisible (erreur {read})"));
    }
    // Freed last: `dacl` lives inside it.
    let _descriptor = LocalMemory(descriptor);
    if dacl.is_null() {
        return Err("objet sans DACL : laissé tel quel".to_owned());
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: administrators.0.cast(),
        },
    };
    let mut merged: *mut ACL = std::ptr::null_mut();
    // SAFETY: `entry` and the SID it points at outlive the call; `dacl` is
    // the object's current list, read above; `merged` receives a LocalAlloc'd
    // list, freed below.
    let built = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut merged) };
    if built != ERROR_SUCCESS {
        return Err(format!("DACL fusionnée refusée (erreur {built})"));
    }
    let _merged = LocalMemory(merged.cast());
    // SAFETY: `merged` is a valid, non-null list alive for the call; only the
    // DACL is set, owner, group and SACL are left as they are.
    let set = unsafe {
        SetSecurityInfo(
            object,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            merged,
            std::ptr::null(),
        )
    };
    if set != ERROR_SUCCESS {
        return Err(format!("DACL non appliquée (erreur {set})"));
    }
    Ok(())
}

/// Memory a Win32 call allocated with LocalAlloc, freed once on drop.
#[cfg(windows)]
struct LocalMemory(*mut c_void);

#[cfg(windows)]
impl LocalMemory {
    /// The binary form of a string SID.
    fn sid(text: &str) -> Result<Self, String> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and alive for the call; on success
        // `sid` is LocalAlloc'd and owned by the returned value.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
            return Err(format!(
                "SID {text} illisible ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(sid))
    }
}

#[cfg(windows)]
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a LocalAlloc'ing call, freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrators_get_only_what_the_engine_reads() {
        assert_eq!(ADMINISTRATORS_SID, "S-1-5-32-544");
        // SYNCHRONIZE (0x0010_0000) and PROCESS_QUERY_LIMITED_INFORMATION (0x1000).
        assert_eq!(UI_PROCESS_GRANT, 0x0010_1000);
        // TOKEN_QUERY.
        assert_eq!(UI_TOKEN_GRANT, 0x0008);
    }

    #[test]
    fn no_right_that_changes_the_ui_is_granted() {
        // PROCESS_TERMINATE, CREATE_THREAD, SET_SESSIONID, VM_OPERATION,
        // VM_READ, VM_WRITE, DUP_HANDLE, CREATE_PROCESS, SET_QUOTA,
        // SET_INFORMATION, QUERY_INFORMATION, SUSPEND_RESUME.
        let process_rights = 0x0000_0FFF;
        // TOKEN_ASSIGN_PRIMARY, DUPLICATE, IMPERSONATE, QUERY_SOURCE,
        // ADJUST_PRIVILEGES, ADJUST_GROUPS, ADJUST_DEFAULT, ADJUST_SESSIONID.
        let token_rights = 0x0000_01F7;
        // DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, ACCESS_SYSTEM_SECURITY,
        // MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE,
        // GENERIC_READ.
        let standard_rights = 0x000F_0000 | 0x0100_0000 | 0x0200_0000 | 0xF000_0000;
        assert_eq!(UI_PROCESS_GRANT & (process_rights & !0x1000), 0);
        assert_eq!(UI_PROCESS_GRANT & standard_rights, 0);
        assert_eq!(UI_TOKEN_GRANT & token_rights, 0);
        assert_eq!(UI_TOKEN_GRANT & standard_rights, 0);
    }
}
