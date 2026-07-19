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
    /// Pairs (adresses IP) joignables en clair pour le transport WireGuard
    /// (UDP 51820). Seul trafic autorisé à **sortir** du WAN hors tunnel.
    /// Utile pour des pairs statiques (site-à-site) ; vide en pur road-warrior.
    pub wg_peers: Vec<String>,
    /// Port UDP sur lequel la gateway **écoute** les clients WireGuard.
    ///
    /// `Some(port)` ouvre ce port en **entrée** depuis n'importe quelle source :
    /// les road-warriors roament, leur IP est inconnue à l'avance. C'est la
    /// seule ouverture entrante du modèle fail-closed, et elle est indispensable
    /// — sans elle aucun client ne peut handshaker. `None` = pas de rôle serveur.
    pub wg_listen_port: Option<u16>,
    /// Comportement hors tunnel.
    pub mode: PolicyMode,
    /// CIDR ou IPs autorisés sur le port 22 (SSH d'administration),
    /// même lorsque le kill-switch est engagé.
    pub allow_ssh_from: Vec<String>,
    /// Port TCP de l'interface d'administration REST/WS.
    pub admin_port: Option<u16>,
    /// Interface réseau exclusive pour l'accès à l'administration (ex. `helios0`).
    pub admin_iface: Option<String>,
    /// CIDRs locaux bypassant le tunnel (split-tunneling dynamique).
    /// Vide = tout le trafic WAN passe par le tunnel (comportement par défaut).
    pub split_tunnel_cidrs: Vec<String>,
    /// MSS clamping post-PMTUD (octets). `None` = pas de clamping.
    /// Calculé automatiquement au lancement du tunnel.
    pub mss_clamp: Option<u16>,
    /// IP de la passerelle du portail captif.
    /// Renseigné lors de la détection ; HTTP/HTTPS vers cette IP sont autorisés.
    pub captive_portal_gateway: Option<String>,
}

impl FirewallPolicy {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.mode, PolicyMode::FailClosed)
    }
}
