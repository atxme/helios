use std::{io::Write as _, path::Path};

use crate::settings::TpmSettings;
use serde::{Deserialize, Serialize};

use crate::{reseal_ticket::ResealTicket, tpm_interface::SealedBlob, Result, TpmError};

/// Minimal persistent state: anti-replay version counter for tickets.
///
/// On the hardened target, this counter should live in a locked NVRAM area
/// of the TPM; here it is stored next to the blob (sufficient for the
/// WSL2/dev model).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct TpmState {
    #[serde(default)]
    pub version: u64,
}

/// Access to the configuration partition: sealed blob, ticket, state.
pub(crate) struct BlobStore<'a> {
    cfg: &'a TpmSettings,
}

impl<'a> BlobStore<'a> {
    pub(crate) fn new(cfg: &'a TpmSettings) -> Self {
        Self { cfg }
    }

    // ── Sealed blob ──────────────────────────────────────────────────────────

    pub(crate) fn load_blob(&self) -> Result<Option<SealedBlob>> {
        match std::fs::read(&self.cfg.sealed_blob_path) {
            Ok(bytes) => Ok(Some(SealedBlob::from_bytes(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&self.cfg.sealed_blob_path, e)),
        }
    }

    pub(crate) fn store_blob(&self, blob: &SealedBlob) -> Result<()> {
        atomic_write(&self.cfg.sealed_blob_path, blob.as_bytes())
    }

    // ── Update window ────────────────────────────────────────────────────────

    pub(crate) fn load_window_marker(&self) -> Result<Option<SealedBlob>> {
        match std::fs::read(&self.cfg.update_window_marker_path) {
            Ok(bytes) => Ok(Some(SealedBlob::from_bytes(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&self.cfg.update_window_marker_path, e)),
        }
    }

    pub(crate) fn store_window_marker(&self, marker: &SealedBlob) -> Result<()> {
        atomic_write(&self.cfg.update_window_marker_path, marker.as_bytes())
    }

    /// Removes the non-secret window marker.
    ///
    /// Deleting the file is **not** what revokes the window — overwriting the
    /// NV payload is, and it must happen first.
    pub(crate) fn remove_window_marker(&self) -> Result<()> {
        let path = Path::new(&self.cfg.update_window_marker_path);
        match std::fs::remove_file(path) {
            Ok(()) => sync_parent(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&self.cfg.update_window_marker_path, e)),
        }
    }

    // ── Reseal ticket ────────────────────────────────────────────────────────

    pub(crate) fn load_ticket(&self) -> Result<Option<ResealTicket>> {
        match std::fs::read(&self.cfg.ticket_path) {
            Ok(bytes) => Ok(Some(ResealTicket::from_json(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&self.cfg.ticket_path, e)),
        }
    }

    /// Removes the ticket after use (anti-replay — a ticket is only usable once).
    pub(crate) fn consume_ticket(&self) -> Result<()> {
        match std::fs::remove_file(&self.cfg.ticket_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&self.cfg.ticket_path, e)),
        }
    }

    // ── State (version counter) ─────────────────────────────────────────────

    pub(crate) fn load_state(&self) -> Result<TpmState> {
        match std::fs::read(&self.cfg.state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| TpmError::Serde(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TpmState::default()),
            Err(e) => Err(io_err(&self.cfg.state_path, e)),
        }
    }

    pub(crate) fn store_state(&self, state: &TpmState) -> Result<()> {
        let json = serde_json::to_vec_pretty(state).map_err(|e| TpmError::Serde(e.to_string()))?;
        atomic_write(&self.cfg.state_path, &json)
    }
}

fn io_err(path: &str, e: std::io::Error) -> TpmError {
    TpmError::Io {
        path: path.to_string(),
        cause: e.to_string(),
    }
}

/// Atomic write: temp file + rename, so a power cut never leaves a
/// truncated blob/state (the next boot depends on it).
fn atomic_write(path: &str, bytes: &[u8]) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
        }
    }
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|error| TpmError::Rng(error.to_string()))?;
    let tmp = format!("{path}.tmp.{}", hex::encode(nonce));
    let outcome = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Every replacement gets restrictive permissions independently of
        // the caller's umask. The files are opaque, but their metadata and
        // ticket/state contents are still security-sensitive.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|e| io_err(&tmp, e))?;
        file.write_all(bytes).map_err(|e| io_err(&tmp, e))?;
        file.sync_all().map_err(|e| io_err(&tmp, e))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
        sync_parent(p)
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

/// Makes a rename or deletion durable before the TPM's irreversible state is
/// advanced. Atomicity alone is insufficient: without the directory fsync, a
/// power cut may preserve the NV revocation but lose the new filename.
fn sync_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| io_err(&parent.to_string_lossy(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_complete_content_without_leaving_a_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let path = path.to_string_lossy();

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();

        assert_eq!(std::fs::read(path.as_ref()).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_uses_private_file_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        atomic_write(&path.to_string_lossy(), b"opaque").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
