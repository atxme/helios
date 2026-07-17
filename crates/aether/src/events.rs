use serde::Serialize;

use crate::config::NetworkConfig;
use crate::state::TunnelState;

/// Événements diffusés aux abonnés (WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeliosEvent {
    StateChanged { state: TunnelState },
    Log { level: String, message: String },
    /// Compteurs réseau lus depuis /proc/net/dev, émis toutes les secondes.
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
    /// Migration MOBIKE (RFC 4555) : l'adresse IP WAN a changé dynamiquement.
    AddressChanged { iface: String, old_ip: String, new_ip: String },
    /// Portail captif interceptant le trafic HTTP détecté sur le réseau courant.
    CaptivePortalDetected { gateway: String },
    /// MTU optimal déterminé par PMTUD — règle MSS clamping appliquée.
    MtuDiscovered { mtu: u16, mss: u16 },
    /// Liste des CIDRs en split-tunneling mise à jour.
    SplitTunnelChanged { cidrs: Vec<String> },
}

/// Commandes envoyées par l'interface web vers l'orchestrateur.
#[derive(Debug, Clone)]
pub enum OrchestratorCmd {
    Connect,
    /// Connexion avec un profil IKE spécifique (identifiant de `profiles::PROFILES`).
    ConnectWithProfile(String),
    /// Connexion avec des propositions IKE/ESP personnalisées (saisie manuelle).
    ConnectWithCustom { ike_proposal: String, esp_proposal: String },
    /// Applique un jeu de règles nftables brut (dry-run = log seulement).
    ApplyFirewallRules(String),
    Disconnect,
    /// L'utilisateur a accepté le portail captif dans son navigateur — relancer la connexion.
    AcknowledgeCaptivePortal,
    /// Met à jour la liste des CIDRs bypassant le tunnel (split-tunneling dynamique).
    SetSplitTunnel(Vec<String>),
    /// Applique une valeur de MSS clamping issue de la sonde PMTUD (usage interne).
    SetMssClamp(u16),
    /// Recharge la configuration réseau à chaud (sans redémarrer le daemon).
    LoadNetworkConfig(NetworkConfig),
}
