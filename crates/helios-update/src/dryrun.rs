use aether::Result;
use async_trait::async_trait;
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
        Ok(self.available.clone().filter(|r| r.version != self.current))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cycle_dry_run_couvre_absence_mise_a_jour_et_installation() {
        let mut channel = DryRunChannel::new("1.0.0");
        assert_eq!(channel.current_version().await.unwrap(), "1.0.0");
        assert_eq!(channel.check().await.unwrap(), None);

        channel.available = Some(Release {
            version: "1.1.0".into(),
            bundle: "https://updates.invalid/helios-1.1.0.raucb".into(),
        });
        let release = channel.check().await.unwrap().unwrap();
        assert_eq!(
            channel.install(&release).await.unwrap(),
            InstallOutcome::Installed {
                reboot_required: true
            }
        );
        channel.confirm_boot().await.unwrap();
    }

    #[tokio::test]
    async fn version_identique_n_est_jamais_reinstallee() {
        let mut channel = DryRunChannel::new("1.0.0");
        let same = Release {
            version: "1.0.0".into(),
            bundle: "local.raucb".into(),
        };
        channel.available = Some(same.clone());

        assert_eq!(channel.check().await.unwrap(), None);
        assert_eq!(
            channel.install(&same).await.unwrap(),
            InstallOutcome::AlreadyUpToDate
        );
    }
}
