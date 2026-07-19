//! Canal RAUC : pilote le binaire `rauc` via des appels de processus.
//!
//! Aucune dépendance C : on appelle `rauc` en ligne de commande. Le binaire est
//! présent sur la cible mais absent de WSL2 ; les méthodes échouent alors
//! proprement (utiliser [`crate::DryRunChannel`] en dev).

use std::path::PathBuf;

use aether::{HeliosError, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tracing::{info, warn};

use crate::{InstallOutcome, Release, UpdateChannel};

pub struct RaucChannel {
    /// Index local des releases (JSON contenant la dernière [`Release`]).
    /// À terme, remplacé par une source HTTPS signée.
    pub manifest_path: Option<PathBuf>,
    /// Version active (renseignée depuis l'image au build).
    pub current: String,
}

impl RaucChannel {
    pub fn new(current: impl Into<String>, manifest_path: Option<PathBuf>) -> Self {
        Self {
            manifest_path,
            current: current.into(),
        }
    }

    async fn rauc(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("rauc")
            .args(args)
            .output()
            .await
            .map_err(|e| HeliosError::Update(format!("exécution de `rauc {args:?}` : {e}")))?;
        if !output.status.success() {
            return Err(HeliosError::Update(format!(
                "`rauc {args:?}` a échoué : {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[async_trait]
impl UpdateChannel for RaucChannel {
    async fn current_version(&self) -> Result<String> {
        // TODO(cible) : parser `rauc status --output-format=json` pour lire le
        // slot booté. Pour l'instant on s'appuie sur la version embarquée.
        Ok(self.current.clone())
    }

    async fn check(&self) -> Result<Option<Release>> {
        let Some(path) = &self.manifest_path else {
            warn!("aucun index de mises à jour configuré");
            return Ok(None);
        };
        let raw = std::fs::read_to_string(path)
            .map_err(|e| HeliosError::Update(format!("lecture de l'index {path:?} : {e}")))?;
        let release: Release = serde_json::from_str(&raw)
            .map_err(|e| HeliosError::Update(format!("index invalide : {e}")))?;
        if release.version != self.current {
            Ok(Some(release))
        } else {
            Ok(None)
        }
    }

    async fn install(&self, release: &Release) -> Result<InstallOutcome> {
        if release.version == self.current {
            return Ok(InstallOutcome::AlreadyUpToDate);
        }
        info!(
            "installation RAUC de {} depuis {}",
            release.version, release.bundle
        );
        // `rauc install` écrit dans le slot inactif. La bascule a lieu au reboot.
        self.rauc(&["install", &release.bundle]).await?;
        Ok(InstallOutcome::Installed {
            reboot_required: true,
        })
    }

    async fn confirm_boot(&self) -> Result<()> {
        self.rauc(&["status", "mark-good"]).await?;
        info!("slot courant confirmé (mark-good)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn index_absent_invalide_identique_et_nouveau_sont_distingues() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("release.json");
        let channel = RaucChannel::new("1.0.0", Some(manifest.clone()));

        assert!(channel.check().await.is_err());
        std::fs::write(&manifest, b"pas du json").unwrap();
        assert!(channel.check().await.is_err());

        std::fs::write(&manifest, br#"{"version":"1.0.0","bundle":"same.raucb"}"#).unwrap();
        assert_eq!(channel.check().await.unwrap(), None);

        std::fs::write(&manifest, br#"{"version":"1.1.0","bundle":"next.raucb"}"#).unwrap();
        assert_eq!(
            channel.check().await.unwrap(),
            Some(Release {
                version: "1.1.0".into(),
                bundle: "next.raucb".into()
            })
        );
    }

    #[tokio::test]
    async fn version_identique_n_execute_pas_rauc() {
        let channel = RaucChannel::new("1.0.0", None);
        let release = Release {
            version: "1.0.0".into(),
            bundle: "inexistant.raucb".into(),
        };
        assert_eq!(
            channel.install(&release).await.unwrap(),
            InstallOutcome::AlreadyUpToDate
        );
    }
}
