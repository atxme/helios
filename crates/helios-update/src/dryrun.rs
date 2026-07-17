use async_trait::async_trait;
use aether::Result;
use tracing::info;

use crate::{InstallOutcome, Release, UpdateChannel};

/// Canal de mise à jour simulé : ne touche à rien, journalise les actions.
pub struct DryRunChannel {
    pub current: String,
    /// Release factice « disponible », pour exercer le flux de bout en bout.
    pub available: Option<Release>,
}

impl DryRunChannel {
    pub fn new(current: impl Into<String>) -> Self {
        Self {
            current: current.into(),
            available: None,
        }
    }
}

#[async_trait]
impl UpdateChannel for DryRunChannel {
    async fn current_version(&self) -> Result<String> {
        Ok(self.current.clone())
    }

    async fn check(&self) -> Result<Option<Release>> {
        Ok(self
            .available
            .clone()
            .filter(|r| r.version != self.current))
    }

    async fn install(&self, release: &Release) -> Result<InstallOutcome> {
        if release.version == self.current {
            return Ok(InstallOutcome::AlreadyUpToDate);
        }
        info!(
            "[dry-run] installation RAUC simulée de {} ({})",
            release.version, release.bundle
        );
        Ok(InstallOutcome::Installed {
            reboot_required: true,
        })
    }

    async fn confirm_boot(&self) -> Result<()> {
        info!("[dry-run] mark-good simulé");
        Ok(())
    }
}
