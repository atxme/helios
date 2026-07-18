//! Profil VPN du client : éditable dans l'IHM, persisté localement en TOML.
//!
//! Modèle **WireGuard** (ADR-001) : un pair est identifié par sa clé publique
//! Curve25519, joint par un endpoint UDP, et protégé en post-quantique par le
//! `preshared_key` dérivé de l'échange ML-KEM à l'enrôlement. Il n'y a ni CA, ni
//! EAP, ni proposition cryptographique à choisir — WireGuard n'a qu'une suite.
//!
//! Les champs `private_key` / `preshared_key` sont des **secrets** : le `Debug`
//! est masqué pour qu'ils ne fuient pas dans les logs.

use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// `AllowedIPs` par défaut : tout le trafic passe par le tunnel.
///
/// C'est ce `0.0.0.0/0` qui, combiné à l'invariante de cycle de vie de
/// l'adaptateur (voir [`crate::backend`]), fait que WireGuard **jette** les
/// paquets au lieu de les laisser fuir en clair quand la session est morte.
pub const DEFAULT_ALLOWED_IPS: &str = "0.0.0.0/0";

/// Keepalive imposé : sans trafic, WireGuard ne handshake pas et notre inférence
/// d'état conclurait à tort que le tunnel est tombé (ADR-001 §3).
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// Un profil VPN complet, tel qu'édité par l'utilisateur dans l'IHM.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// Nom convivial unique (clé de sélection dans la liste).
    pub name: String,
    /// Endpoint UDP de la gateway : `IP:port` ou `FQDN:port`. **Pas** une URL HTTP.
    pub endpoint: String,
    /// Clé privée Curve25519 du client (base64). **Secret.**
    #[serde(default)]
    pub private_key: String,
    /// Clé publique Curve25519 de la gateway (base64) — l'identité du pair.
    #[serde(default)]
    pub peer_public_key: String,
    /// PSK post-quantique dérivé de l'échange ML-KEM (base64). **Secret.**
    /// `None` = tunnel classique seul, pas encore upgradé (voir cinématique ADR).
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Adresse virtuelle assignée par la gateway (CGNAT, ex. `100.64.1.2/32`).
    /// Dérivée côté gateway par `helios-provisioning`, reçue à l'enrôlement.
    #[serde(default)]
    pub address: Option<String>,
    /// Trafic routé dans le tunnel. Défaut [`DEFAULT_ALLOWED_IPS`].
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    /// Keepalive en secondes. Défaut [`DEFAULT_KEEPALIVE_SECS`].
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
    /// URL interne de l'API heliosd, joignable **uniquement une fois le tunnel
    /// monté** (ex. `http://100.64.0.1:8080`). `None` = pas de télémétrie enrichie.
    #[serde(default)]
    pub heliosd_url: Option<String>,
}

fn default_allowed_ips() -> String {
    DEFAULT_ALLOWED_IPS.to_string()
}

fn default_keepalive() -> u16 {
    DEFAULT_KEEPALIVE_SECS
}

/// `Debug` masqué : ne jamais laisser fuir la clé privée ni le PSK dans les logs.
impl fmt::Debug for ClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientProfile")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("private_key", &"***")
            .field("peer_public_key", &self.peer_public_key)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "***"))
            .field("address", &self.address)
            .field("allowed_ips", &self.allowed_ips)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("heliosd_url", &self.heliosd_url)
            .finish()
    }
}

impl ClientProfile {
    /// Le profil est-il exploitable pour monter un tunnel ?
    ///
    /// Un profil incomplet ne doit pas être présenté comme connectable : on
    /// échoue **avant** de toucher au réseau plutôt que de monter un adaptateur
    /// qui ne handshakera jamais.
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            anyhow::bail!("l'endpoint de la gateway (IP/FQDN:port) est requis");
        }
        if self.private_key.trim().is_empty() {
            anyhow::bail!("la clé privée du client est requise (enrôlement non effectué ?)");
        }
        if self.peer_public_key.trim().is_empty() {
            anyhow::bail!("la clé publique de la gateway est requise");
        }
        Ok(())
    }

    /// Le tunnel est-il protégé en post-quantique (PSK ML-KEM installé) ?
    pub fn is_post_quantum(&self) -> bool {
        self.preshared_key
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty())
    }
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            name: "nouveau".to_string(),
            endpoint: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            address: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: DEFAULT_KEEPALIVE_SECS,
            heliosd_url: None,
        }
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
            Ok(raw) => {
                toml::from_str(&raw).with_context(|| format!("config invalide: {}", path.display()))
            }
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
            endpoint: "203.0.113.1:51820".into(),
            ..ClientProfile::default()
        });
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.find("a").unwrap().endpoint, "203.0.113.1:51820");

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
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            preshared_key: Some("cHNr".into()),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        });
        cfg.selected = Some("site-a".into());
        cfg.save().unwrap();

        let loaded = ClientConfig::load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        let p = loaded.find("site-a").unwrap();
        assert_eq!(p.endpoint, "203.0.113.10:51820");
        assert_eq!(p.address.as_deref(), Some("100.64.1.2/32"));
        // Les défauts WireGuard doivent survivre au round-trip.
        assert_eq!(p.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(p.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
        assert!(p.is_post_quantum());
        assert_eq!(loaded.selected.as_deref(), Some("site-a"));

        std::env::remove_var("ORION_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_masques_dans_le_debug() {
        let p = ClientProfile {
            private_key: "TRES_SECRET".into(),
            preshared_key: Some("PSK_SECRET".into()),
            ..ClientProfile::default()
        };
        let dump = format!("{p:?}");
        assert!(
            !dump.contains("TRES_SECRET"),
            "la clé privée fuit dans les logs"
        );
        assert!(!dump.contains("PSK_SECRET"), "le PSK fuit dans les logs");
    }
}
