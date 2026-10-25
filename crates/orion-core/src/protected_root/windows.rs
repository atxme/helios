//! The Win32 calls of the protected root: the folders, created with an access
//! list only administrators and SYSTEM can use, read back before anything is
//! written under them.
//!
//! Each call is thin. The decision on what an access list admits is
//! [`admits_only_admins`], tested under Linux.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{addr_of, null_mut};

use windows_sys::core::{HRESULT, PWSTR};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

use super::{
    admits_only_admins, classify_ace, is_plain_sid, protected_root_for, Ace, EnginePaths,
    RootError, ACCESS_ALLOWED_TYPE, ACCESS_DENIED_TYPE,
};

/// Owner Administrators, protected DACL, full control for Administrators and
/// SYSTEM, both inherited by the objects under the folder.
const PROTECTED_SDDL: &str = "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

/// The machine-wide data folder, from the shell: never the environment.
pub fn program_data() -> Result<PathBuf, String> {
    let mut folder: PWSTR = null_mut();
    // SAFETY: the GUID is a constant, no token is given, and `folder` is a
    // valid out-pointer. On success it receives a CoTaskMem string.
    let status: HRESULT =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut folder) };
    let path = if status == 0 {
        // SAFETY: a successful call leaves a NUL-terminated string in `folder`.
        Ok(PathBuf::from(std::ffi::OsString::from_wide(unsafe {
            wide_units(folder)
        })))
    } else {
        Err(format!(
            "dossier ProgramData introuvable (HRESULT {status:#x})"
        ))
    };
    // SAFETY: `folder` is null or a CoTaskMem string, freed exactly once here,
    // after its last use.
    unsafe { CoTaskMemFree(folder.cast::<c_void>()) };
    path
}

/// Creates `path` with the protected access list, or accepts it when it is
/// already there, then reads it back.
///
/// Created or found, the folder is checked: a reparse point, a folder that is
/// not a folder, or an access list that admits anyone else is refused.
pub fn ensure_protected_dir(path: &Path) -> Result<(), RootError> {
    let sddl: Vec<u16> = PROTECTED_SDDL.encode_utf16().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `sddl` is NUL-terminated and alive for the call; `descriptor` is
    // a valid out-pointer, freed by `LocalBlock` below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(RootError::Unavailable(format!(
            "descripteur du dossier protégé illisible ({})",
            io::Error::last_os_error()
        )));
    }
    let _descriptor = LocalBlock(descriptor);

    let wide = wide_path(path);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated and alive; `attributes` and the
    // descriptor it names stay alive until the call returns.
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    if created == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(RootError::Unavailable(format!(
                "dossier protégé d'Orion impossible à créer ({error})"
            )));
        }
    }
    verify_protected_dir(path)
}

/// Reads `path` back and refuses it unless only administrators and SYSTEM can
/// use it.
fn verify_protected_dir(path: &Path) -> Result<(), RootError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        RootError::Unavailable(format!("dossier protégé d'Orion illisible ({error})"))
    })?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RootError::Refused);
    }
    let (owner, aces, protected) = read_dacl(path)?;
    if admits_only_admins(&owner, &aces, protected) {
        Ok(())
    } else {
        Err(RootError::Refused)
    }
}

/// The owner's SID in string form, the entries of the DACL, and whether the
/// DACL is protected from inheritance.
///
/// A null DACL admits everyone, so it is refused here.
fn read_dacl(path: &Path) -> Result<(String, Vec<Ace>, bool), RootError> {
    let wide = wide_path(path);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide` is NUL-terminated and alive; the out-pointer is valid. The
    // descriptor it returns owns the owner and the DACL, and is freed by
    // `LocalBlock` below, after the last use of both.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = LocalBlock(descriptor);
    if status != 0 {
        return Err(RootError::Unavailable(format!(
            "droits du dossier protégé illisibles (code {status})"
        )));
    }
    // SAFETY: `descriptor` is the one just read, alive until `_descriptor` drops.
    unsafe { access_of(descriptor) }
}

/// The owner's SID in string form, the entries of the DACL of `descriptor`,
/// and whether that DACL is protected from inheritance.
///
/// The one reader of access lists: the protected root and the machine TPM key
/// both pass their descriptor here, so an entry is parsed once. A null DACL
/// admits everyone, so it is refused.
///
/// # Safety
///
/// `descriptor` must be a self-relative security descriptor that stays alive
/// for the whole call.
pub(crate) unsafe fn access_of(
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(String, Vec<Ace>, bool), RootError> {
    let mut owner: PSID = null_mut();
    let mut owner_defaulted = 0i32;
    // SAFETY: the descriptor is valid per the contract; `owner` points into it.
    let has_owner =
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) };
    if has_owner == 0 || owner.is_null() {
        return Err(RootError::Unavailable(
            "propriétaire du dossier protégé illisible".to_string(),
        ));
    }
    let mut dacl_present = 0i32;
    let mut dacl: *mut ACL = null_mut();
    let mut dacl_defaulted = 0i32;
    // SAFETY: as above; `dacl` points into the descriptor when present.
    let has_dacl = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if has_dacl == 0 {
        return Err(RootError::Unavailable(
            "droits du dossier protégé illisibles".to_string(),
        ));
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(RootError::Refused);
    }

    let owner = sid_to_string(owner)?;
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is alive for the call; the out-parameters are valid.
    let read = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    if read == 0 {
        return Err(RootError::Unavailable(format!(
            "contrôle du dossier protégé illisible ({})",
            io::Error::last_os_error()
        )));
    }
    let protected = control & SE_DACL_PROTECTED != 0;

    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into the descriptor; `size` is a valid buffer of
    // the size passed for the AclSizeInformation class.
    let sized = unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if sized == 0 {
        return Err(RootError::Unavailable(format!(
            "entrées du dossier protégé illisibles ({})",
            io::Error::last_os_error()
        )));
    }

    let mut aces = Vec::with_capacity(size.AceCount as usize);
    for index in 0..size.AceCount {
        let mut entry: *mut c_void = null_mut();
        // SAFETY: `index` is below AceCount, so the entry exists; `entry` is a
        // valid out-pointer that points into the descriptor.
        if unsafe { GetAce(dacl, index, &mut entry) } == 0 {
            return Err(RootError::Unavailable(format!(
                "entrée du dossier protégé illisible ({})",
                io::Error::last_os_error()
            )));
        }
        aces.push(read_ace(entry)?);
    }
    Ok((owner, aces, protected))
}

/// One entry, read from its header. A type other than allow or deny is not
/// read further: its layout is unknown, and [`classify_ace`] refuses it.
fn read_ace(entry: *mut c_void) -> Result<Ace, RootError> {
    let header = entry.cast::<ACE_HEADER>();
    // SAFETY: `entry` came from GetAce, so it starts with an ACE_HEADER.
    let (ace_type, flags) = unsafe { ((*header).AceType, (*header).AceFlags) };
    let inherited = u32::from(flags) & INHERITED_ACE != 0;
    if ace_type != ACCESS_ALLOWED_TYPE && ace_type != ACCESS_DENIED_TYPE {
        return Ok(classify_ace(ace_type, 0, String::new(), inherited));
    }
    let allowed = entry.cast::<ACCESS_ALLOWED_ACE>();
    // SAFETY: an allow or deny entry has the ACCESS_ALLOWED_ACE layout: the
    // header, then the mask, then the SID starting at `SidStart`.
    let (mask, sid) = unsafe {
        (
            (*allowed).Mask,
            addr_of!((*allowed).SidStart).cast_mut().cast::<c_void>(),
        )
    };
    Ok(classify_ace(ace_type, mask, sid_to_string(sid)?, inherited))
}

/// A SID in string form, such as `S-1-5-32-544`.
fn sid_to_string(sid: PSID) -> Result<String, RootError> {
    let mut text: PWSTR = null_mut();
    // SAFETY: `sid` points to a SID that stays alive for the call, and `text`
    // is a valid out-pointer that receives a LocalAlloc string on success.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    let _text = LocalBlock(text.cast::<c_void>());
    if converted == 0 {
        return Err(RootError::Unavailable(format!(
            "SID illisible ({})",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful conversion leaves a NUL-terminated string in `text`,
    // which `_text` frees after this read.
    String::from_utf16(unsafe { wide_units(text) })
        .map_err(|_| RootError::Unavailable("SID illisible".to_string()))
}

impl EnginePaths {
    /// Creates, or checks, the protected root of the user `sid`, and returns
    /// the paths under it. The vault and the identities directories are
    /// created in it, and inherit its access list.
    pub fn establish_for(sid: &str) -> Result<Self, RootError> {
        if !is_plain_sid(sid) {
            return Err(RootError::Unavailable(
                "identifiant de compte invalide".to_string(),
            ));
        }
        let program_data = program_data().map_err(RootError::Unavailable)?;
        let helios = program_data.join("helios");
        ensure_protected_dir(&helios)?;
        ensure_protected_dir(&helios.join("orion"))?;
        let root = protected_root_for(&program_data, sid).map_err(RootError::Unavailable)?;
        ensure_protected_dir(&root)?;

        let paths = Self {
            user_sid: Some(sid.to_string()),
            ..Self::under(&root)
        };
        for directory in [&paths.vault, &paths.identities] {
            std::fs::create_dir_all(directory).map_err(|error| {
                RootError::Unavailable(format!("dossier d'Orion impossible à créer ({error})"))
            })?;
        }
        Ok(paths)
    }
}

/// A memory block from `LocalAlloc`, freed on drop.
pub(crate) struct LocalBlock(pub(crate) HLOCAL);

impl Drop for LocalBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the block came from a LocalAlloc-based Win32 call and is
            // freed exactly once, by its owner.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The path as a NUL-terminated UTF-16 buffer.
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// The units of a NUL-terminated wide string, without the terminator.
///
/// # Safety
///
/// `text` must point to a NUL-terminated UTF-16 string that stays valid for
/// the lifetime of the returned slice.
unsafe fn wide_units<'a>(text: *const u16) -> &'a [u16] {
    let mut length = 0;
    // SAFETY: the caller guarantees a NUL terminator, so every read below the
    // terminator is in bounds.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units from `text` are initialised, per the contract.
    unsafe { std::slice::from_raw_parts(text, length) }
}
