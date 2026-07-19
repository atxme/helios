//! Canal RAUC : pilote le binaire `rauc` via des appels de processus.
//!
//! Aucune dépendance C : on appelle `rauc` en ligne de commande. Le binaire est
//! présent sur la cible mais absent de WSL2 ; les méthodes échouent alors
//! proprement (utiliser [`crate::DryRunChannel`] en dev).

use std::collections::HashMap;
use std::path::PathBuf;

use aether::{HeliosError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;
use tracing::{info, warn};

use crate::{InstallOutcome, Release, UpdateChannel};

/// Sortie de `rauc status --output-format=json`, réduite à ce qu'on consomme.
///
/// `slots` est un tableau d'objets à clé unique (`[{"rootfs.0": {…}}, …]`) et
/// non une map : c'est la forme émise par RAUC, on la suit telle quelle.
#[derive(Deserialize)]
struct RaucStatus {
    /// Nom du slot booté (`rootfs.0`, …). Absent sur certaines configurations.
    booted: Option<String>,
    #[serde(default)]
    slots: Vec<HashMap<String, RaucSlot>>,
}

#[derive(Deserialize)]
struct RaucSlot {
    /// `booted`, `inactive`, … Sert de repli si `booted` manque à la racine.
    state: Option<String>,
    slot_status: Option<RaucSlotStatus>,
}

#[derive(Deserialize)]
struct RaucSlotStatus {
    bundle: Option<RaucBundle>,
}

#[derive(Deserialize)]
struct RaucBundle {
    version: Option<String>,
}

/// Extrait la version du slot booté de la sortie JSON de `rauc status`.
///
/// Le slot booté est identifié par le champ racine `booted` ; à défaut, par le
/// premier slot dont l'`state` vaut `booted`. Une sortie sans slot booté
/// identifiable est une erreur : mieux vaut échouer que rapporter la version
/// d'un slot inactif.
fn parse_booted_version(raw: &str) -> Result<String> {
    let status: RaucStatus = serde_json::from_str(raw)
        .map_err(|e| HeliosError::Update(format!("sortie de `rauc status` illisible : {e}")))?;

    let entry = status
        .slots
        .iter()
        .flatten()
        .find(|(name, slot)| match &status.booted {
            Some(booted) => *name == booted,
            None => slot.state.as_deref() == Some("booted"),
        })
        .ok_or_else(|| HeliosError::Update("aucun slot booté dans `rauc status`".into()))?;

    let (name, slot) = entry;
    slot.slot_status
        .as_ref()
        .and_then(|s| s.bundle.as_ref())
        .and_then(|b| b.version.clone())
        .ok_or_else(|| HeliosError::Update(format!("slot booté `{name}` sans version de bundle")))
}

pub struct RaucChannel {
    /// Index local des releases (JSON contenant la dernière [`Release`]).
    /// À terme, remplacé par une source HTTPS signée.
    pub manifest_path: Option<PathBuf>,
    /// Version compilée dans l'image courante. Sert de référence à [`Self::check`]
    /// — c'est bien la version du binaire qui tourne, y compris après rollback,
    /// puisque le binaire provient du slot booté. [`RaucChannel::current_version`]
    /// la recoupe avec ce que RAUC rapporte.
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
    /// Version du slot booté telle que RAUC la connaît.
    ///
    /// C'est la source autoritaire : `current` n'est que la constante compilée
    /// dans l'image. Les deux doivent coïncider — l'image qui tourne est celle
    /// du slot booté. Une divergence signale un slot status corrompu ou une
    /// image substituée : on la journalise en `warn` et on renvoie la valeur de
    /// RAUC, qui décrit le système réel.
    async fn current_version(&self) -> Result<String> {
        let raw = self.rauc(&["status", "--output-format=json"]).await?;
        let booted = parse_booted_version(&raw)?;
        if booted != self.current {
            warn!(
                embarquee = %self.current,
                rauc = %booted,
                "divergence entre la version compilée et le slot booté RAUC"
            );
        }
        Ok(booted)
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

    /// Sortie réaliste de `rauc status --output-format=json` : deux slots, le
    /// booté désigné à la racine et portant un `state` cohérent.
    const STATUS_DEUX_SLOTS: &str = r#"{
        "compatible": "helios-gateway",
        "booted": "rootfs.1",
        "boot_primary": "rootfs.1",
        "slots": [
            {"rootfs.0": {
                "state": "inactive",
                "bootname": "A",
                "slot_status": {"bundle": {"version": "1.0.0"}}
            }},
            {"rootfs.1": {
                "state": "booted",
                "bootname": "B",
                "slot_status": {"bundle": {"version": "1.1.0"}}
            }}
        ]
    }"#;

    #[test]
    fn version_lue_sur_le_slot_boote_et_non_sur_l_inactif() {
        assert_eq!(parse_booted_version(STATUS_DEUX_SLOTS).unwrap(), "1.1.0");
    }

    #[test]
    fn slot_boote_identifie_par_son_state_quand_la_racine_ne_le_dit_pas() {
        let raw = r#"{
            "slots": [
                {"rootfs.0": {"state": "inactive",
                    "slot_status": {"bundle": {"version": "1.0.0"}}}},
                {"rootfs.1": {"state": "booted",
                    "slot_status": {"bundle": {"version": "1.1.0"}}}}
            ]
        }"#;
        assert_eq!(parse_booted_version(raw).unwrap(), "1.1.0");
    }

    #[test]
    fn sortie_illisible_ou_sans_slot_boote_est_une_erreur() {
        // Pas du JSON.
        assert!(parse_booted_version("pas du json").is_err());
        // Aucun slot booté : ne jamais rapporter la version d'un inactif.
        let aucun = r#"{"slots":[{"rootfs.0":{"state":"inactive",
            "slot_status":{"bundle":{"version":"1.0.0"}}}}]}"#;
        assert!(parse_booted_version(aucun).is_err());
        // Slot booté sans version exploitable.
        let sans_version = r#"{"booted":"rootfs.0","slots":[{"rootfs.0":{
            "state":"booted","slot_status":{}}}]}"#;
        assert!(parse_booted_version(sans_version).is_err());
        // `booted` désigne un slot absent du tableau.
        let orphelin = r#"{"booted":"rootfs.9","slots":[{"rootfs.0":{
            "state":"booted","slot_status":{"bundle":{"version":"1.0.0"}}}}]}"#;
        assert!(parse_booted_version(orphelin).is_err());
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
