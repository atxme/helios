use serde::{Deserialize, Serialize};

/// Comportement du pare-feu lorsque le tunnel n'est pas opérationnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    /// Kill-switch : on bloque tout (sauf IKE) tant que le tunnel n'est pas Up.
    #[default]
    FailClosed,
    /// Mode dégradé : on laisse passer en clair si le tunnel tombe (déconseillé).
    FailOpen,
}

/// Description de haut niveau de ce que le pare-feu doit imposer.
///
/// C'est l'entrée du moteur de rendu de règles ([`crate`] consommé par
/// `helios-firewall`). Elle est volontairement déclarative : on décrit l'intention,
/// pas la syntaxe nftables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// Interface vers Internet (ex. `eth0`, le contrôleur Realtek RTL8111HS).
    pub wan_iface: String,
    /// Interfaces côté LAN dont le trafic doit transiter par le tunnel.
    pub lan_ifaces: Vec<String>,
    /// Pairs (adresses IP) autorisés en clair pour la négociation IKE
    /// (UDP 500/4500) et le transport ESP.
    pub ike_peers: Vec<String>,
    /// Comportement hors tunnel.
    pub mode: PolicyMode,
    /// CIDR ou IPs autorisés sur le port 22 (SSH d'administration),
    /// même lorsque le kill-switch est engagé.
    pub allow_ssh_from: Vec<String>,
}

impl FirewallPolicy {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.mode, PolicyMode::FailClosed)
    }
}
