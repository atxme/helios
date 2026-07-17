//! Profil VPN du client : éditable dans l'IHM, persisté localement en TOML.
//!
//! Contrairement à `heliosd` (qui est la *gateway*), le client se connecte à une
//! gateway distante par son **endpoint IKE** (IP/FQDN). Le profil porte donc tout
//! ce qu'il faut pour initier un IKEv2 : endpoint, identités, credentials et la
//! proposition cryptographique (profil prédéfini de [`aether::profiles`] ou
//! proposition IKE/ESP saisie à la main).

use std::path::PathBuf;

use anyhow::{Context, Result};
use aether::profiles;
use serde::{Deserialize, Serialize};

/// Méthode d'authentification IKEv2 du client auprès de la gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Clé pré-partagée (PSK).
    Psk { secret: String },
    /// Certificat X.509 + clé privée (chemins locaux).
    Cert { cert_path: String, key_path: String },
    /// EAP (identifiant + mot de passe) — auth utilisateur, courant en road-warrior.
    Eap { username: String, password: String },
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig::Psk {
            secret: String::new(),
        }
    }
}

/// Un profil VPN complet, tel qu'édité par l'utilisateur dans l'IHM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// Nom convivial unique (clé de sélection dans la liste).
    pub name: String,
    /// Endpoint IKE de la gateway : IP ou FQDN. **Pas** une URL HTTP.
    pub gateway: String,
    /// Identité IKE locale (ex. `client@helios`).
    #[serde(default)]
    pub local_id: Option<String>,
    /// Identité IKE attendue de la gateway (ex. `gw@example.net`).
    #[serde(default)]
    pub remote_id: Option<String>,
    /// Mode d'authentification.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Identifiant d'un profil cryptographique prédéfini (`classic`, `hybrid`, …).
    /// Prioritaire sur `ike_proposal`/`esp_proposal` s'il est présent et connu.
    #[serde(default)]
    pub profile_id: Option<String>,
    /// Proposition IKE personnalisée (utilisée si `profile_id` absent/inconnu).
    #[serde(default)]
    pub ike_proposal: Option<String>,
    /// Proposition ESP personnalisée (utilisée si `profile_id` absent/inconnu).
    #[serde(default)]
    pub esp_proposal: Option<String>,
    /// URL interne de l'API heliosd, joignable **uniquement une fois le tunnel
    /// monté** (ex. `http://10.10.0.1:8080`). `None` = pas de télémétrie enrichie.
    #[serde(default)]
    pub heliosd_url: Option<String>,
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            name: "nouveau".to_string(),
            gateway: String::new(),
            local_id: None,
            remote_id: None,
            auth: AuthConfig::default(),
            profile_id: Some("hybrid".to_string()),
            ike_proposal: None,
            esp_proposal: None,
            heliosd_url: None,
        }
    }
}

impl ClientProfile {
    /// Résout les propositions IKE/ESP effectives : profil prédéfini en priorité,
    /// sinon les valeurs custom du profil. Réutilise [`aether::profiles`].
    pub fn resolved_proposals(&self) -> (String, String) {
        if let Some(id) = &self.profile_id {
            if let Some(p) = profiles::find(id) {
                return (p.ike_proposal.to_string(), p.esp_proposal.to_string());
            }
        }
        (
            self.ike_proposal.clone().unwrap_or_default(),
            self.esp_proposal.clone().unwrap_or_default(),
        )
    }

    /// La proposition effective embarque-t-elle un échange post-quantique
    /// (ML-KEM, RFC 9370) ? Sert à prévenir l'utilisateur quand la pile IKEv2
    /// native ne le supporte pas (Windows/macOS natifs).
    pub fn uses_post_quantum(&self) -> bool {
        self.resolved_proposals().0.contains("mlkem")
    }
}

/// Configuration persistée du client : ensemble de profils + sélection courante.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    #[serde(default)]
    pub profiles: Vec<ClientProfile>,
    /// Nom du profil actuellement sélectionné.
    #[serde(default)]
    pub selected: Option<String>,
}

impl ClientConfig {
    /// Chemin du fichier de config. Surchargé par `ORION_CONFIG` (tests/dev),
    /// sinon répertoire de config standard de l'OS (`directories`).
    pub fn path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("ORION_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dirs = directories::ProjectDirs::from("net", "helios", "orion")
            .context("impossible de déterminer le répertoire de config de l'OS")?;
        Ok(dirs.config_dir().join("profiles.toml"))
    }

    /// Charge la config depuis le disque. Renvoie une config vide si le fichier
    /// n'existe pas encore (premier lancement).
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(raw) => toml::from_str(&raw)
                .with_context(|| format!("config invalide: {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", path.display())),
        }
    }

    /// Persiste la config de façon atomique (écriture temporaire + rename),
    /// même schéma que [`aether::NetworkConfig::save`].
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(self).context("sérialisation TOML")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, raw.as_bytes())
            .with_context(|| format!("écriture de {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).context("rename atomique")?;
        Ok(())
    }

    /// Retourne le profil portant ce nom, le cas échéant.
    pub fn find(&self, name: &str) -> Option<&ClientProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Insère ou remplace un profil (clé = `name`).
    pub fn upsert(&mut self, profile: ClientProfile) {
        match self.profiles.iter_mut().find(|p| p.name == profile.name) {
            Some(slot) => *slot = profile,
            None => self.profiles.push(profile),
        }
    }

    /// Supprime le profil portant ce nom. Désélectionne si c'était le profil courant.
    pub fn remove(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.selected.as_deref() == Some(name) {
            self.selected = self.profiles.first().map(|p| p.name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profil_predefini_prioritaire_sur_custom() {
        let p = ClientProfile {
            profile_id: Some("classic".to_string()),
            ike_proposal: Some("ignoré".to_string()),
            ..ClientProfile::default()
        };
        let (ike, esp) = p.resolved_proposals();
        assert_eq!(ike, "aes256gcm16-prfsha256-ecp256");
        assert_eq!(esp, "aes256gcm16-ecp256");
    }

    #[test]
    fn proposition_custom_si_pas_de_profil() {
        let p = ClientProfile {
            profile_id: None,
            ike_proposal: Some("aes256gcm16-prfsha384-ecp384".to_string()),
            esp_proposal: Some("aes256gcm16-ecp384".to_string()),
            ..ClientProfile::default()
        };
        let (ike, esp) = p.resolved_proposals();
        assert_eq!(ike, "aes256gcm16-prfsha384-ecp384");
        assert_eq!(esp, "aes256gcm16-ecp384");
    }

    #[test]
    fn detection_post_quantique() {
        let hybrid = ClientProfile {
            profile_id: Some("hybrid".to_string()),
            ..ClientProfile::default()
        };
        assert!(hybrid.uses_post_quantum());
        let classic = ClientProfile {
            profile_id: Some("classic".to_string()),
            ..ClientProfile::default()
        };
        assert!(!classic.uses_post_quantum());
    }

    #[test]
    fn upsert_et_remove() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "a".into(),
            ..ClientProfile::default()
        });
        cfg.upsert(ClientProfile {
            name: "b".into(),
            ..ClientProfile::default()
        });
        cfg.selected = Some("b".into());
        assert_eq!(cfg.profiles.len(), 2);

        // upsert sur nom existant remplace, n'ajoute pas.
        cfg.upsert(ClientProfile {
            name: "a".into(),
            gateway: "203.0.113.1".into(),
            ..ClientProfile::default()
        });
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.find("a").unwrap().gateway, "203.0.113.1");

        cfg.remove("b");
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.selected.as_deref(), Some("a")); // re-sélection auto
    }

    #[test]
    fn roundtrip_disque() {
        let dir = std::env::temp_dir().join(format!("orion-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        std::env::set_var("ORION_CONFIG", &path);

        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "site-a".into(),
            gateway: "203.0.113.10".into(),
            local_id: Some("client@helios".into()),
            ..ClientProfile::default()
        });
        cfg.selected = Some("site-a".into());
        cfg.save().unwrap();

        let loaded = ClientConfig::load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.find("site-a").unwrap().gateway, "203.0.113.10");
        assert_eq!(loaded.selected.as_deref(), Some("site-a"));

        std::env::remove_var("ORION_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
