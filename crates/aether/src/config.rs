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
    /// Interface réseau exclusive pour l'accès à l'administration.
    /// Doit être l'interface WireGuard (`wg_iface`) : l'API vit derrière le tunnel.
    #[serde(default)]
    pub admin_iface: Option<String>,
    /// CIDRs locaux bypassant le tunnel par défaut (split-tunneling statique).
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<String>,

    // ── Plan de données WireGuard (rôle serveur) ──────────────────────────────
    /// Nom de l'interface WireGuard créée par la gateway.
    #[serde(default = "default_wg_iface")]
    pub wg_iface: String,
    /// Clé privée Curve25519 de la gateway, en base64. **Secret.**
    /// Vide = la gateway ne peut pas monter son interface.
    #[serde(default)]
    pub wg_private_key: String,
    /// Adresse de la gateway dans le réseau du tunnel (CGNAT, ADR-001 §4).
    #[serde(default = "default_wg_address")]
    pub wg_address: String,
    /// Port UDP d'écoute.
    #[serde(default = "default_wg_port")]
    pub wg_listen_port: u16,
    /// Pairs autorisés. À terme alimentés par `helios-provisioning` à
    /// l'enrôlement ; déclarables à la main en attendant.
    #[serde(default)]
    pub peers: Vec<WgPeer>,

    /// Pairs statiques joignables en sortie (site-à-site). Vide en road-warrior.
    #[serde(default)]
    pub static_peer_addrs: Vec<String>,
}

fn default_wg_iface() -> String {
    "helios0".to_string()
}

/// `100.64.0.1/10` : première adresse de la plage CGNAT partagée (RFC 6598).
fn default_wg_address() -> String {
    "100.64.0.1/10".to_string()
}

fn default_wg_port() -> u16 {
    51820
}

/// Un client WireGuard autorisé sur la gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    /// Nom convivial (journalisation, IHM).
    pub name: String,
    /// Clé publique Curve25519 du client, en base64 — son identité.
    pub public_key: String,
    /// VIP assignée, en notation CIDR (ex. `100.64.1.2/32`).
    /// Dans WireGuard, `AllowedIPs` **est** la table de routage cryptographique.
    pub address: String,
    /// PSK post-quantique dérivé de l'échange ML-KEM, en base64. **Secret.**
    #[serde(default)]
    pub preshared_key: Option<String>,
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

    /// Pairs statiques joignables en sortie (site-à-site). Vide en road-warrior :
    /// les clients arrivent en entrée, sur `wg_listen_port`.
    pub fn wg_peers(&self) -> Vec<String> {
        self.static_peer_addrs.clone()
    }

    /// La gateway est-elle configurée pour monter son interface WireGuard ?
    pub fn wireguard_ready(&self) -> bool {
        !self.wg_private_key.trim().is_empty() && !self.wg_address.trim().is_empty()
    }

    /// Projette la config réseau vers la politique de pare-feu déclarative.
    /// Mode toujours `fail-closed` — invariant de sécurité non configurable.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        let admin_port = self.admin_iface.as_ref().map(|_| API_PORT);
        FirewallPolicy {
            wan_iface: self.wan_iface.clone(),
            lan_ifaces: self.lan_ifaces.clone(),
            wg_peers: self.wg_peers(),
            // Rôle serveur : on n'ouvre le port en entrée que si la gateway est
            // réellement en mesure de monter son interface. Sinon on laisserait
            // un port ouvert sans rien derrière.
            wg_listen_port: self.wireguard_ready().then_some(self.wg_listen_port),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_vide_par_defaut() {
        let cfg = NetworkConfig::default();
        assert!(cfg.peers.is_empty());
        assert!(cfg.wan_iface.is_empty());
        assert!(!cfg.wireguard_ready(), "sans clé privée, rien ne doit monter");
    }

    #[test]
    fn deserialise_config_gateway() {
        let toml = r#"
            wan_iface = "eth0"
            lan_ifaces = ["eth1"]
            admin_iface = "helios0"
            wg_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [[peers]]
            name = "poste-christophe"
            public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            address = "100.64.1.2/32"
        "#;
        let cfg: NetworkConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.wan_iface, "eth0");
        // Les défauts WireGuard s'appliquent sans être écrits.
        assert_eq!(cfg.wg_iface, "helios0");
        assert_eq!(cfg.wg_listen_port, 51820);
        assert_eq!(cfg.wg_address, "100.64.0.1/10");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].address, "100.64.1.2/32");
        assert!(cfg.wireguard_ready());

        let policy = cfg.firewall_policy();
        assert!(policy.is_fail_closed());
        // Rôle serveur : le port d'écoute doit être ouvert en entrée, sinon
        // aucun client ne peut handshaker.
        assert_eq!(policy.wg_listen_port, Some(51820));
        assert!(policy.wg_peers.is_empty(), "road-warrior : pas de pair sortant");
    }

    #[test]
    fn port_non_ouvert_si_la_gateway_n_est_pas_prete() {
        // Pas de clé privée → on n'ouvre pas un port sans rien derrière.
        let cfg = NetworkConfig {
            wan_iface: "eth0".into(),
            ..NetworkConfig::default()
        };
        assert_eq!(cfg.firewall_policy().wg_listen_port, None);
    }
}
