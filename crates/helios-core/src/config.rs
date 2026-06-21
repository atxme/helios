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
    pub tpm: TpmConfig,
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

/// Configuration du validateur d'intégrité de démarrage par scellement TPM.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TpmConfig {
    /// Active le scellement/déscellement au démarrage. false = bypass (WSL2 / dev).
    #[serde(default)]
    pub enabled: bool,
    /// Si true, un échec bloque le démarrage (fail-closed). Défaut : true.
    /// false = log seulement (DÉBOGAGE uniquement).
    #[serde(default = "default_true")]
    pub enforce: bool,
    /// Autorise le provisionnement TOFU si aucun blob scellé n'existe.
    /// **Doit rester false sur le terrain** : à n'activer qu'en usine, sinon un
    /// attaquant peut supprimer le blob pour forcer un faux « premier boot ».
    #[serde(default)]
    pub allow_provisioning: bool,
    /// Périphérique TPM exposé par le noyau.
    #[serde(default = "default_tpm_device")]
    pub device: String,
    /// Banque PCR (sha256 recommandé — sha1 refusé).
    #[serde(default = "default_pcr_bank")]
    pub pcr_bank: String,
    /// Index PCR liés au scellement (0=firmware, 4=bootloader, 7=Secure Boot).
    #[serde(default = "default_pcr_selection")]
    pub pcr_selection: Vec<u8>,
    /// Blob scellé (partition de configuration).
    #[serde(default = "default_sealed_blob_path")]
    pub sealed_blob_path: String,
    /// Billet de rescellement signé déposé par l'OTA.
    #[serde(default = "default_ticket_path")]
    pub ticket_path: String,
    /// État persistant (compteur de version anti-rejeu).
    #[serde(default = "default_state_path")]
    pub state_path: String,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce: true,
            allow_provisioning: false,
            device: default_tpm_device(),
            pcr_bank: default_pcr_bank(),
            pcr_selection: default_pcr_selection(),
            sealed_blob_path: default_sealed_blob_path(),
            ticket_path: default_ticket_path(),
            state_path: default_state_path(),
        }
    }
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
    /// CIDR ou IPs depuis lesquels le port 22 est autorisé, même kill-switch engagé.
    /// Vide par défaut (SSH bloqué).
    #[serde(default)]
    pub allow_ssh_from: Vec<String>,
    /// Interface réseau exclusive pour l'accès à l'interface d'administration
    /// (ex. `ipsec0`). Quand défini, le pare-feu bloque tout accès au port admin
    /// depuis n'importe quelle autre interface — y compris le loopback.
    /// Non défini = pas de restriction supplémentaire (mode dev / client).
    #[serde(default)]
    pub admin_iface: Option<String>,
    /// CIDRs locaux bypassant le tunnel par défaut (configurables statiquement).
    /// Complété dynamiquement par l'UI via `OrchestratorCmd::SetSplitTunnel`.
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<String>,
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
    /// Active MOBIKE (RFC 4555) pour les clients nomades (Wi-Fi ↔ 4G/5G).
    /// Sans MOBIKE, un changement d'IP force une renégociation IKE complète —
    /// coûteuse avec ML-KEM. Activé par défaut.
    #[serde(default = "default_true")]
    pub mobike: bool,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| HeliosError::Config(format!("lecture de {}: {e}", path.display())))?;
        toml::from_str(&raw).map_err(|e| HeliosError::Config(e.to_string()))
    }

    /// Projette la configuration vers la politique de pare-feu déclarative.
    ///
    /// Les champs dynamiques (`mss_clamp`, `captive_portal_gateway`) sont
    /// initialisés à `None` ; l'orchestrateur les met à jour au fil du temps.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        // Le port admin est déduit de `api.bind` (ex. "0.0.0.0:8080" → 8080).
        // Il n'est transmis à la politique que si `admin_iface` est défini —
        // sans iface cible, la règle de restriction n'a pas de sens.
        let admin_port = self.firewall.admin_iface.as_ref().and_then(|_| {
            self.api.bind.rsplit(':').next()?.parse::<u16>().ok()
        });

        FirewallPolicy {
            wan_iface: self.firewall.wan_iface.clone(),
            lan_ifaces: self.firewall.lan_ifaces.clone(),
            ike_peers: self.firewall.ike_peers.clone(),
            mode: self.firewall.mode,
            allow_ssh_from: self.firewall.allow_ssh_from.clone(),
            admin_port,
            admin_iface: self.firewall.admin_iface.clone(),
            split_tunnel_cidrs: self.firewall.split_tunnel_cidrs.clone(),
            mss_clamp: None,
            captive_portal_gateway: None,
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
fn default_tpm_device() -> String {
    "/dev/tpmrm0".to_string()
}
fn default_pcr_bank() -> String {
    "sha256".to_string()
}
fn default_pcr_selection() -> Vec<u8> {
    vec![0, 4, 7]
}
fn default_sealed_blob_path() -> String {
    "/var/lib/helios/sealed.key".to_string()
}
fn default_ticket_path() -> String {
    "/var/lib/helios/reseal-ticket.json".to_string()
}
fn default_state_path() -> String {
    "/var/lib/helios/tpm-state.json".to_string()
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
            # allow_ssh_from absent → défaut vide
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.general.dry_run, "dry_run doit être vrai par défaut");
        assert_eq!(cfg.vici.socket, "/var/run/charon.vici");
        let policy = cfg.firewall_policy();
        assert!(policy.is_fail_closed());
        assert_eq!(policy.wan_iface, "eth0");
    }
}
