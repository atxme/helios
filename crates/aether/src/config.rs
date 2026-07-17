use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};
use crate::policy::{FirewallPolicy, PolicyMode};

const NETWORK_CONFIG_PATH: &str = "/var/lib/helios/network.toml";

/// Port TCP de l'API REST/WS (hardcodé, invariant d'architecture).
pub const API_PORT: u16 = 8080;
/// Adresse d'écoute du serveur HTTP.
pub const API_BIND: &str = "127.0.0.1:8080";

/// Configuration réseau chargeable par l'opérateur via CLI ou interface graphique.
///
/// Persistée dans `/var/lib/helios/network.toml`. C'est le seul fichier de
/// configuration fourni par l'opérateur — tous les autres paramètres (TPM,
/// VICI, API, firewall mode) sont des constantes d'architecture.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub wan_iface: String,
    #[serde(default)]
    pub lan_ifaces: Vec<String>,
    /// CIDRs ou IPs autorisés en SSH d'administration, même kill-switch engagé.
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
    /// Interface réseau exclusive pour l'accès à l'administration (ex. `ipsec0`).
    #[serde(default)]
    pub admin_iface: Option<String>,
    /// CIDRs locaux bypassant le tunnel par défaut (split-tunneling statique).
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<String>,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

impl NetworkConfig {
    /// Charge la config réseau depuis `/var/lib/helios/network.toml`.
    /// Renvoie une config vide si le fichier n'existe pas encore.
    pub fn load() -> Result<Self> {
        match std::fs::read_to_string(NETWORK_CONFIG_PATH) {
            Ok(raw) => toml::from_str(&raw).map_err(|e| HeliosError::Config(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(HeliosError::Config(format!(
                "lecture de {NETWORK_CONFIG_PATH}: {e}"
            ))),
        }
    }

    /// Persiste la config réseau de façon atomique (rename).
    pub fn save(&self) -> Result<()> {
        let raw =
            toml::to_string_pretty(self).map_err(|e| HeliosError::Config(e.to_string()))?;
        let tmp = format!("{NETWORK_CONFIG_PATH}.tmp");
        if let Some(parent) = std::path::Path::new(NETWORK_CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HeliosError::Config(format!("création répertoire: {e}")))?;
        }
        std::fs::write(&tmp, raw.as_bytes())
            .map_err(|e| HeliosError::Config(format!("écriture: {e}")))?;
        std::fs::rename(&tmp, NETWORK_CONFIG_PATH)
            .map_err(|e| HeliosError::Config(format!("rename atomique: {e}")))?;
        Ok(())
    }

    /// IKE peers déduits des adresses distantes des connexions.
    pub fn wg_peers(&self) -> Vec<String> {
        self.connections.iter().map(|c| c.remote_addr.clone()).collect()
    }

    /// Projette la config réseau vers la politique de pare-feu déclarative.
    /// Mode toujours `fail-closed` — invariant de sécurité non configurable.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        let admin_port = self.admin_iface.as_ref().map(|_| API_PORT);
        FirewallPolicy {
            wan_iface: self.wan_iface.clone(),
            lan_ifaces: self.lan_ifaces.clone(),
            wg_peers: self.wg_peers(),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: self.allow_ssh_from.clone(),
            admin_port,
            admin_iface: self.admin_iface.clone(),
            split_tunnel_cidrs: self.split_tunnel_cidrs.clone(),
            mss_clamp: None,
            captive_portal_gateway: None,
        }
    }
}

/// Un pair WireGuard connu de la configuration réseau.
///
/// `remote_addr` est l'endpoint UDP du pair (IP joignable en clair sur le port
/// 51820), utilisé pour scoper la règle de pare-feu. Les pairs road-warrior
/// dynamiques (VIP dérivée, clé publique) sont gérés par `helios-provisioning`,
/// pas ici ; cette structure ne couvre que les pairs statiques déclarés.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub remote_addr: String,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub remote_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_vide_par_defaut() {
        let cfg = NetworkConfig::default();
        assert!(cfg.connections.is_empty());
        assert!(cfg.wan_iface.is_empty());
    }

    #[test]
    fn deserialise_config_minimale() {
        let toml = r#"
            wan_iface = "eth0"
            lan_ifaces = ["eth1"]

            [[connections]]
            name = "site-a"
            remote_addr = "203.0.113.10"
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.wan_iface, "eth0");
        assert_eq!(cfg.connections.len(), 1);
        assert_eq!(cfg.connections[0].remote_addr, "203.0.113.10");
        let policy = cfg.firewall_policy();
        assert!(policy.is_fail_closed());
        assert_eq!(policy.wg_peers, vec!["203.0.113.10"]);
    }
}
