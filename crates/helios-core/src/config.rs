use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};
use crate::policy::{FirewallPolicy, PolicyMode};

/// Configuration complète du daemon, chargée depuis `helios.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub vici: Vici,
    pub firewall: Firewall,
    #[serde(default)]
    pub api: Api,
    #[serde(default)]
    pub update: Update,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct General {
    /// Mode développement : aucune écriture réelle dans le kernel (Netlink/charon
    /// simulés). C'est le mode par défaut, adapté à WSL2.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vici {
    /// Socket Unix exposé par charon (strongSwan).
    #[serde(default = "default_vici_socket")]
    pub socket: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Firewall {
    pub wan_iface: String,
    #[serde(default)]
    pub lan_ifaces: Vec<String>,
    #[serde(default)]
    pub ike_peers: Vec<String>,
    #[serde(default)]
    pub mode: PolicyMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Update {
    #[serde(default)]
    pub enabled: bool,
    /// Intervalle entre deux vérifications de mise à jour (secondes).
    #[serde(default = "default_update_interval")]
    pub check_interval_secs: u64,
    /// Index des releases (chemin local ou, à terme, URL HTTPS).
    #[serde(default)]
    pub manifest: Option<String>,
}

/// Une connexion IPsec à négocier auprès de charon.
///
/// Les propositions cryptographiques sont volontairement explicites : c'est ici
/// qu'on impose l'échange de clés hybride post-quantique (ML-KEM + ECDHE).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Connection {
    pub name: String,
    pub remote_addr: String,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub remote_id: Option<String>,
    /// Proposition IKE, ex. `aes256gcm16-prfsha384-ecp384-ke1_mlkem768`.
    pub ike_proposal: String,
    /// Proposition ESP/CHILD_SA, ex. `aes256gcm16-ecp384`.
    pub esp_proposal: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| HeliosError::Config(format!("lecture de {}: {e}", path.display())))?;
        toml::from_str(&raw).map_err(|e| HeliosError::Config(e.to_string()))
    }

    /// Projette la configuration vers la politique de pare-feu déclarative.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        FirewallPolicy {
            wan_iface: self.firewall.wan_iface.clone(),
            lan_ifaces: self.firewall.lan_ifaces.clone(),
            ike_peers: self.firewall.ike_peers.clone(),
            mode: self.firewall.mode,
        }
    }
}

impl Default for General {
    fn default() -> Self {
        Self {
            dry_run: true,
            log_level: default_log_level(),
        }
    }
}

impl Default for Vici {
    fn default() -> Self {
        Self {
            socket: default_vici_socket(),
        }
    }
}

/// Configuration du serveur HTTP (interface web + API REST + WebSocket).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Api {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_bind")]
    pub bind: String,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_bind(),
        }
    }
}

impl Default for Update {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: default_update_interval(),
            manifest: None,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_vici_socket() -> String {
    "/var/run/charon.vici".to_string()
}
fn default_update_interval() -> u64 {
    3600
}
fn default_bind() -> String {
    "127.0.0.1:8080".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let toml = r#"
            [firewall]
            wan_iface = "eth0"
            lan_ifaces = ["eth1"]
            ike_peers = ["203.0.113.10"]
            mode = "fail-closed"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.general.dry_run, "dry_run doit être vrai par défaut");
        assert_eq!(cfg.vici.socket, "/var/run/charon.vici");
        let policy = cfg.firewall_policy();
        assert!(policy.is_fail_closed());
        assert_eq!(policy.wan_iface, "eth0");
    }
}
