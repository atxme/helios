//! Where the engine keeps its files on this machine.
//!
//! The locations the client already uses, named once, and the protected root
//! that a Windows engine establishes for its user before it opens anything.
//! Off Windows nothing moves: [`EnginePaths::for_current_user`] returns the
//! paths the code reads and writes today.

#[cfg(any(windows, test))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::config::ClientConfig;
use crate::identity_store::ProtectedIdentityStore;
use crate::vault::ProfileStore;

/// Log file, beside the vault it describes. Same name as the shell's log.
pub const LOG_FILE: &str = "orion.log";

/// Reported when no protected location is established for this process.
pub const NOT_ESTABLISHED: &str = "emplacement protégé d'Orion non établi";

/// Reported when a protected root is set again with other paths.
#[cfg(any(windows, test))]
const ALREADY_ESTABLISHED: &str = "racine protégée déjà établie";

/// Reported when the protected root is reachable by a non-administrator.
pub const REFUSED_ROOT: &str =
    "Le dossier protégé d'Orion est accessible à un compte non administrateur : démarrage refusé.";

/// Reported when the install can be changed by a non-administrator.
pub const WRITABLE_INSTALL: &str =
    "Orion est installé dans un dossier modifiable sans droits administrateur : démarrage refusé.";

/// Why the protected root could not be established.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    /// The folder is reachable by an account that is not an administrator,
    /// or is a reparse point, or has no protected access list.
    Refused,
    /// The folder could not be created or read; the message is for the person.
    Unavailable(String),
    /// The folder of the executable, its parent, the executable or one of its
    /// DLLs can be changed by an account that is not an administrator.
    WritableInstall,
}

#[cfg(any(windows, test))]
impl std::fmt::Display for RootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused => formatter.write_str(REFUSED_ROOT),
            Self::Unavailable(message) => formatter.write_str(message),
            Self::WritableInstall => formatter.write_str(WRITABLE_INSTALL),
        }
    }
}

/// The well-known SID of the Administrators group.
#[cfg(any(windows, test))]
pub const ADMINISTRATORS: &str = "S-1-5-32-544";

/// The well-known SID of the local system account.
#[cfg(any(windows, test))]
pub const SYSTEM: &str = "S-1-5-18";

/// The well-known SID of the Windows module installer, which owns `Program Files`.
#[cfg(any(windows, test))]
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// The well-known SID of the creator-owner placeholder. Only an administrator
/// can create a child under a folder that grants it, so only one inherits it.
#[cfg(any(windows, test))]
pub const CREATOR_OWNER: &str = "S-1-3-0";

/// `FILE_ADD_FILE`: create a file in a folder.
#[cfg(any(windows, test))]
pub const FILE_ADD_FILE: u32 = 0x2;

/// `FILE_ADD_SUBDIRECTORY`: create a folder in a folder.
#[cfg(any(windows, test))]
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x4;

/// `FILE_DELETE_CHILD`: delete an entry of a folder, whatever its own rights.
#[cfg(any(windows, test))]
pub const FILE_DELETE_CHILD: u32 = 0x40;

/// `FILE_WRITE_DATA`: write the contents of a file.
#[cfg(any(windows, test))]
pub const FILE_WRITE_DATA: u32 = 0x2;

/// `FILE_APPEND_DATA`: append to a file.
#[cfg(any(windows, test))]
pub const FILE_APPEND_DATA: u32 = 0x4;

/// `FILE_WRITE_EA`: write the extended attributes of a file.
#[cfg(any(windows, test))]
pub const FILE_WRITE_EA: u32 = 0x10;

/// `FILE_WRITE_ATTRIBUTES`: write the attributes of a file.
#[cfg(any(windows, test))]
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x100;

/// `DELETE`: delete the object.
#[cfg(any(windows, test))]
pub const DELETE: u32 = 0x1_0000;

/// `WRITE_DAC`: replace the access list of the object.
#[cfg(any(windows, test))]
pub const WRITE_DAC: u32 = 0x4_0000;

/// `WRITE_OWNER`: take ownership of the object.
#[cfg(any(windows, test))]
pub const WRITE_OWNER: u32 = 0x8_0000;

/// `GENERIC_WRITE`: the generic write right.
#[cfg(any(windows, test))]
pub const GENERIC_WRITE: u32 = 0x4000_0000;

/// `GENERIC_ALL`: every right.
#[cfg(any(windows, test))]
pub const GENERIC_ALL: u32 = 0x1000_0000;

/// The rights that change a folder that holds the executable.
#[cfg(any(windows, test))]
pub const DIRECTORY_WRITE_MASK: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// The rights that change a file: the executable or one of its DLLs.
#[cfg(any(windows, test))]
pub const FILE_WRITE_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// The rights that let a holder rename or delete the folder of the executable
/// through its parent.
#[cfg(any(windows, test))]
pub const PARENT_WRITE_MASK: u32 = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// The root every engine file sits under, installed once for this process.
static INSTALLED: OnceLock<EnginePaths> = OnceLock::new();

/// Files and directories the engine uses on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePaths {
    /// Per-user configuration directory. The vault and the log are in it.
    pub root: PathBuf,
    /// Vault directory: device root, local settings, sealed profiles.
    pub vault: PathBuf,
    /// Configuration file. `ORION_CONFIG` may name another, in development
    /// builds only.
    pub config: PathBuf,
    /// Directory of the sealed key-negotiation identities.
    pub identities: PathBuf,
    /// Log file, truncated at each start.
    pub log: PathBuf,
    /// The interactive user this root belongs to, when it was established for
    /// one. It names the machine TPM key the engine uses. `None` where no root
    /// was established for a user, such as the paths of a test.
    pub user_sid: Option<String>,
    /// The UI process that started this engine, when the engine runs for one.
    /// Its token, which belongs to the user, is the one the cleanup of the
    /// legacy vault runs under. `None` everywhere but the engine's start-up.
    pub user_process: Option<u32>,
}

impl EnginePaths {
    /// The paths of the current user, as the client resolves them today.
    #[cfg(not(windows))]
    pub fn for_current_user() -> Result<Self, String> {
        let root = ProfileStore::default_dir().map_err(|error| error.to_string())?;
        let config = ClientConfig::path().map_err(|error| format!("{error:#}"))?;
        let identities = ProtectedIdentityStore::for_current_user()
            .map_err(|error| format!("{error:#}"))?
            .directory()
            .to_path_buf();
        Ok(Self {
            vault: root.clone(),
            log: root.join(LOG_FILE),
            root,
            config,
            identities,
            user_sid: None,
            user_process: None,
        })
    }

    /// The layout of the protected root `root`: every file under it.
    #[cfg(any(windows, test))]
    pub fn under(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            vault: root.join("vault"),
            config: root.join("profiles.toml"),
            identities: root.join("identities"),
            log: root.join(LOG_FILE),
            user_sid: None,
            user_process: None,
        }
    }
}

/// Makes `paths` the protected root of this process.
///
/// Installing the same paths again is harmless; other paths are refused,
/// because the engine's files would otherwise move under a running process.
#[cfg(any(windows, test))]
pub fn install(paths: EnginePaths) -> Result<(), String> {
    let established = INSTALLED.get_or_init(|| paths.clone());
    if *established == paths {
        Ok(())
    } else {
        Err(ALREADY_ESTABLISHED.to_string())
    }
}

/// The protected root of this process, once [`install`] has set it.
pub fn installed() -> Option<&'static EnginePaths> {
    INSTALLED.get()
}

/// The per-user directory of the UI's own log.
///
/// It is not protected: the UI runs unelevated and writes nothing secret
/// there.
pub fn user_dir() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("net", "helios", "orion")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .ok_or_else(|| "impossible de déterminer le répertoire de configuration".to_string())
}

/// The directories of the client on this platform, as they were before the
/// protected root existed.
///
/// Windows has none: a per-user path must never be taken for the vault, so
/// every resolver fails there until the root is installed.
pub(crate) fn platform_dirs() -> Result<directories::ProjectDirs, String> {
    #[cfg(windows)]
    {
        Err(NOT_ESTABLISHED.to_string())
    }
    #[cfg(not(windows))]
    {
        directories::ProjectDirs::from("net", "helios", "orion")
            .ok_or_else(|| NOT_ESTABLISHED.to_string())
    }
}

/// The path a resolver uses: the override if one applies, else the installed
/// root, else the platform default.
pub(crate) fn select(
    override_path: Option<PathBuf>,
    installed: Option<PathBuf>,
    platform_default: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    if let Some(path) = override_path.or(installed) {
        return Ok(path);
    }
    platform_default()
}

/// The value of `variable`, read only when `allow_overrides` holds.
///
/// Callers pass `cfg!(debug_assertions)`: a release build never lets the
/// environment move the engine's files.
pub(crate) fn path_override(variable: &str, allow_overrides: bool) -> Option<PathBuf> {
    if !allow_overrides {
        return None;
    }
    std::env::var_os(variable).map(PathBuf::from)
}

/// The per-user root of `sid` under `program_data`: `helios/orion/<sid>`.
///
/// The SID becomes a folder name, so anything that is not a plain SID (a
/// separator, a `..`, an SDDL bracket) is refused.
#[cfg(any(windows, test))]
pub fn protected_root_for(program_data: &Path, sid: &str) -> Result<PathBuf, String> {
    if !is_plain_sid(sid) {
        return Err("identifiant de compte invalide".to_string());
    }
    Ok(program_data.join("helios").join("orion").join(sid))
}

/// A SID in string form: `S-` then at least two non-empty runs of digits
/// separated by dashes, such as `S-1-5-18`. Nothing else is accepted.
///
/// It is written into an SDDL string and a folder name, so anything beyond
/// that shape (a bracket, a space, an empty segment, a trailing dash, a
/// lowercase `s`) is refused.
pub fn is_plain_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('-').collect();
    segments.len() >= 2
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()))
}

/// One entry of a discretionary access control list, reduced to what the
/// check reads.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub sid: String,
    pub allow: bool,
    pub mask: u32,
    pub inherited: bool,
}

/// `ACCESS_ALLOWED_ACE_TYPE`: an entry that grants access.
#[cfg(any(windows, test))]
const ACCESS_ALLOWED_TYPE: u8 = 0;

/// `ACCESS_DENIED_ACE_TYPE`: an entry that withholds access.
#[cfg(any(windows, test))]
const ACCESS_DENIED_TYPE: u8 = 1;

/// Reduces one raw entry to what [`admits_only_admins`] reads.
///
/// An entry of any other type (an object or audit entry) is read as an allow
/// entry with no SID, so it is refused: the check does not know what it grants.
#[cfg(any(windows, test))]
pub fn classify_ace(ace_type: u8, mask: u32, sid: String, inherited: bool) -> Ace {
    match ace_type {
        ACCESS_ALLOWED_TYPE => Ace {
            sid,
            allow: true,
            mask,
            inherited,
        },
        ACCESS_DENIED_TYPE => Ace {
            sid,
            allow: false,
            mask,
            inherited,
        },
        _ => Ace {
            sid: String::new(),
            allow: true,
            mask,
            inherited,
        },
    }
}

/// Whether a directory is reachable by administrators and SYSTEM alone.
///
/// The DACL must be protected (no inherited entry from a parent), its owner
/// must be administrators or SYSTEM, and every allow entry must name one of
/// them. Deny entries cannot widen access and do not count. The owner is
/// checked too: it may rewrite the DACL whatever the entries say.
#[cfg(any(windows, test))]
pub fn admits_only_admins(owner: &str, aces: &[Ace], protected: bool) -> bool {
    protected
        && (owner == ADMINISTRATORS || owner == SYSTEM)
        && aces
            .iter()
            .filter(|ace| ace.allow)
            .all(|ace| ace.sid == ADMINISTRATORS || ace.sid == SYSTEM)
}

/// Whether an account that is not an administrator can change an object with
/// one of the rights in `write_mask`.
///
/// The owner is a non-administrator unless it is trusted, and it may rewrite
/// the access list whatever the entries say. Otherwise an allow entry of an
/// untrusted SID counts when it grants a bit of `write_mask`. Deny entries
/// cannot widen access and do not count. An entry of unknown type has no SID
/// and no readable mask, so it counts: the check fails closed.
#[cfg(any(windows, test))]
pub fn grants_user_write(owner: &str, aces: &[Ace], write_mask: u32) -> bool {
    !is_trusted(owner)
        || aces.iter().any(|ace| {
            ace.allow
                && (ace.sid.is_empty() || (!is_trusted(&ace.sid) && ace.mask & write_mask != 0))
        })
}

/// Whether `sid` belongs to the trusted SIDs of an install.
#[cfg(any(windows, test))]
fn is_trusted(sid: &str) -> bool {
    [ADMINISTRATORS, SYSTEM, TRUSTED_INSTALLER, CREATOR_OWNER].contains(&sid)
}

#[cfg(windows)]
mod windows;

/// The DACL reader and the local-memory guard, shared with the machine TPM key.
#[cfg(windows)]
pub(crate) use windows::{access_of, LocalBlock};

/// The install check the UI and the engine both run before elevation.
#[cfg(windows)]
pub use windows::install_is_protected;

#[cfg(test)]
mod tests;
