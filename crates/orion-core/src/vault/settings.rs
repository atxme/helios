//! Réglages locaux du coffre ([ADR-006](../../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §3).
//!
//! # One flag, deliberately unpleasant to write
//!
//! `danger_allow_software_keystore` is the only escape from the hardware
//! requirement, and its name is part of the decision: it must be impossible to
//! enable by distraction and embarrassing to leave in place.
//!
//! It exists for ageing fleets with no usable TPM, and it is a **downgrade,
//! never a recovery**. Turning it on withdraws, in one stroke:
//!
//! * resistance to copying the installation to another machine;
//! * resistance to a hardware rollback;
//! * resistance to a domain administrator holding the DPAPI backup keys.
//!
//! # Why absence is a refusal, not a default
//!
//! A machine with no TPM and no flag does **not** silently fall back: Orion
//! refuses, exactly as `heliosd` refuses a missing kernel backend outside
//! `--dev`. The flag is what turns that refusal into an informed choice — and
//! the choice then has to be visible, at every start and in the posture panel,
//! for as long as it lasts.
//!
//! # Why a file rather than an environment variable
//!
//! A variable is set by whoever launches the process, which on Windows is a
//! shortcut nobody re-reads. A file sits in the profile directory, survives
//! reboots, and can be inspected by whoever audits the machine.

use serde::{Deserialize, Serialize};

/// File holding the settings, beside the vault it governs.
pub const SETTINGS_FILE: &str = "settings.toml";

/// Local settings of an Orion installation.
///
/// Every field defaults to the **safe** value, so a missing or truncated file
/// yields the strict behaviour rather than the permissive one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalSettings {
    /// Waives the hardware requirement. See the module documentation for what
    /// it costs.
    pub danger_allow_software_keystore: bool,

    /// Waives the volume-encryption prerequisite (ADR-006 §3).
    ///
    /// # Pourquoi cette échappatoire existe
    ///
    /// Le chiffrement applicatif n'atteint ni les anciens blocs SSD ni le
    /// fichier d'hibernation : sur un volume nu, sceller un profil **recopie**
    /// le secret ailleurs sur le même disque sans retirer ce qui s'y trouvait.
    /// D'où le refus.
    ///
    /// Mais un refus sans issue transforme un poste de développement sans
    /// BitLocker — le cas courant d'une machine de test — en Orion qui ne peut
    /// rien importer et ne l'explique qu'en journal. Le drapeau rend le choix
    /// possible, explicite et visible, exactement comme
    /// `danger_allow_software_keystore` le fait pour le TPM.
    ///
    /// Il ne rend pas le volume chiffré. Sous ce mode, T1 et T7 — disque volé,
    /// sauvegarde, pagefile, hibernation — ne sont plus couverts, et la posture
    /// continue de le dire à chaque démarrage.
    pub danger_allow_unencrypted_volume: bool,
}

impl LocalSettings {
    /// Reads the settings from `dir`, falling back to the strict defaults.
    ///
    /// An unreadable or malformed file yields the defaults **and** says so to
    /// the caller: silently applying the permissive value because a file could
    /// not be parsed is how a downgrade arrives without anyone choosing it.
    pub fn load(dir: &std::path::Path) -> (Self, Option<String>) {
        let path = dir.join(SETTINGS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(raw) => match toml::from_str::<Self>(&raw) {
                Ok(settings) => (settings, None),
                Err(cause) => (
                    Self::default(),
                    Some(format!(
                        "{} illisible ({cause}) — réglages stricts appliqués",
                        path.display()
                    )),
                ),
            },
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(cause) => (
                Self::default(),
                Some(format!(
                    "{} inaccessible ({cause}) — réglages stricts appliqués",
                    path.display()
                )),
            ),
        }
    }

    /// Persists the complete local choice atomically, beside the vault.
    ///
    /// The file can be created by the interface on first use; its absence is
    /// merely the strict default, not an installation error. A complete write
    /// preserves the other downgrade flag instead of replacing it with an
    /// implicit default.
    pub fn save(&self, dir: &std::path::Path) -> Result<(), super::VaultError> {
        aether::private_file::create_private_dir(dir).map_err(|cause| super::VaultError::Io {
            path: dir.to_path_buf(),
            cause: cause.to_string(),
        })?;
        let path = dir.join(SETTINGS_FILE);
        let encoded = toml::to_string(self)
            .map_err(|cause| super::VaultError::LocalSettings(cause.to_string()))?;
        aether::private_file::write_private_atomic(&path, encoded.as_bytes()).map_err(|cause| {
            super::VaultError::Io {
                path,
                cause: cause.to_string(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orion-settings-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    /// The safe value is what an absent file means.
    #[test]
    fn an_absent_file_yields_the_strict_defaults() {
        let dir = dir("absent");
        let (settings, complaint) = LocalSettings::load(&dir);
        assert!(!settings.danger_allow_software_keystore);
        assert!(complaint.is_none(), "an absent file is not an anomaly");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_flag_is_read_when_it_is_set() {
        let dir = dir("set");
        std::fs::write(
            dir.join(SETTINGS_FILE),
            "danger_allow_software_keystore = true\n",
        )
        .unwrap();
        let (settings, complaint) = LocalSettings::load(&dir);
        assert!(settings.danger_allow_software_keystore);
        assert!(complaint.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A malformed file must not enable anything. Applying the permissive
    /// value because a parse failed is how a downgrade arrives without anyone
    /// choosing it.
    #[test]
    fn a_malformed_file_falls_back_to_strict_and_complains() {
        let dir = dir("malformed");
        std::fs::write(dir.join(SETTINGS_FILE), "danger_allow_software_keystore = ").unwrap();
        let (settings, complaint) = LocalSettings::load(&dir);
        assert!(
            !settings.danger_allow_software_keystore,
            "a parse failure must never enable the downgrade"
        );
        assert!(complaint.is_some(), "the caller must be told to look");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unknown key is refused rather than ignored: a typo on the flag's own
    /// name would otherwise leave the operator believing it is on.
    #[test]
    fn an_unknown_key_is_refused() {
        let dir = dir("unknown");
        std::fs::write(
            dir.join(SETTINGS_FILE),
            "danger_allow_sofware_keystore = true\n",
        )
        .unwrap();
        let (settings, complaint) = LocalSettings::load(&dir);
        assert!(!settings.danger_allow_software_keystore);
        assert!(
            complaint.is_some(),
            "a misspelled flag must be reported, not silently ignored"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_explicit_false_stays_false() {
        let dir = dir("false");
        std::fs::write(
            dir.join(SETTINGS_FILE),
            "danger_allow_software_keystore = false\n",
        )
        .unwrap();
        assert!(!LocalSettings::load(&dir).0.danger_allow_software_keystore);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_creates_the_file_and_preserves_every_choice() {
        let dir = dir("save");
        let settings = LocalSettings {
            danger_allow_software_keystore: true,
            danger_allow_unencrypted_volume: true,
        };

        settings.save(&dir).unwrap();

        assert_eq!(LocalSettings::load(&dir).0, settings);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
