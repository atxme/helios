use std::path::Path;

use crate::settings::TpmSettings;
use serde::{Deserialize, Serialize};

use crate::{reseal_ticket::ResealTicket, tpm_interface::SealedBlob, Result, TpmError};

/// État persistant minimal : compteur de version anti-rejeu des billets.
///
/// Sur la cible durcie, ce compteur devrait résider dans une zone NVRAM verrouillée
/// du TPM ; ici il est stocké à côté du blob (suffisant pour le modèle WSL2/dev).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct TpmState {
    #[serde(default)]
    pub version: u64,
}

/// Accès à la partition de configuration : blob scellé, billet, état.
pub(crate) struct BlobStore<'a> {
    cfg: &'a TpmSettings,
}

impl<'a> BlobStore<'a> {
    pub(crate) fn new(cfg: &'a TpmSettings) -> Self {
        Self { cfg }
    }

    // ── Blob scellé ──────────────────────────────────────────────────────────

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

    // ── Billet de rescellement ───────────────────────────────────────────────

    pub(crate) fn load_ticket(&self) -> Result<Option<ResealTicket>> {
        match std::fs::read(&self.cfg.ticket_path) {
            Ok(bytes) => Ok(Some(ResealTicket::from_json(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&self.cfg.ticket_path, e)),
        }
    }

    /// Supprime le billet après usage (anti-rejeu — un billet ne sert qu'une fois).
    pub(crate) fn consume_ticket(&self) -> Result<()> {
        match std::fs::remove_file(&self.cfg.ticket_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&self.cfg.ticket_path, e)),
        }
    }

    // ── État (compteur de version) ───────────────────────────────────────────

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

/// Écriture atomique : fichier temporaire + rename, pour ne jamais laisser un
/// blob/état tronqué en cas de coupure (le démarrage suivant en dépend).
fn atomic_write(path: &str, bytes: &[u8]) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
        }
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| io_err(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    Ok(())
}
