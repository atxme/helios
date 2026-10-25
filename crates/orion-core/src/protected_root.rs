//! Where the engine keeps its files on this machine.
//!
//! The locations the client already uses, named once. Nothing here moves a
//! file: [`EnginePaths::for_current_user`] returns the paths the code reads and
//! writes today.

use std::path::PathBuf;

use crate::config::ClientConfig;
use crate::identity_store::ProtectedIdentityStore;
use crate::vault::ProfileStore;

/// Log file, beside the vault it describes. Same name as the shell's log.
pub const LOG_FILE: &str = "orion.log";

/// Files and directories the engine uses on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePaths {
    /// Per-user configuration directory. The vault and the log are in it.
    pub root: PathBuf,
    /// Vault directory: device root, local settings, sealed profiles.
    pub vault: PathBuf,
    /// Configuration file, or the path that `ORION_CONFIG` names.
    pub config: PathBuf,
    /// Directory of the sealed key-negotiation identities.
    pub identities: PathBuf,
    /// Log file, truncated at each start.
    pub log: PathBuf,
}

impl EnginePaths {
    /// The paths of the current user, as the client resolves them today.
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
        })
    }
}

#[cfg(test)]
mod tests;
