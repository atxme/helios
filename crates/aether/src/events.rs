use serde::Serialize;
use tokio::sync::oneshot;

use crate::config::NetworkConfig;
use crate::secret::SecretString;
use crate::state::TunnelState;

/// Événements diffusés aux abonnés (WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeliosEvent {
    StateChanged {
        state: TunnelState,
    },
    Log {
        level: String,
        message: String,
    },
    /// Compteurs réseau lus depuis /proc/net/dev, émis toutes les secondes.
    Telemetry {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_pps: u64,
        tx_pps: u64,
    },
    /// Portail captif interceptant le trafic HTTP détecté sur le réseau courant.
    CaptivePortalDetected {
        gateway: String,
    },
    /// MTU optimal déterminé par PMTUD — règle MSS clamping appliquée.
    MtuDiscovered {
        mtu: u16,
        mss: u16,
    },
    /// Liste des CIDRs en split-tunneling mise à jour.
    SplitTunnelChanged {
        cidrs: Vec<String>,
    },
}

/// Commandes envoyées par l'interface web vers l'orchestrateur.
#[derive(Debug, Clone)]
pub enum OrchestratorCmd {
    Connect,
    /// Remplace la clé privée WireGuard de la gateway et la scelle dans le TPM.
    ///
    /// Le secret de scellement ne quitte jamais `heliosd` : l'API ne fait que
    /// transmettre la nouvelle clé, l'orchestrateur seul sait la sceller.
    ///
    /// **Rotation d'identité** : après application, tous les clients doivent
    /// mettre à jour leur `peer_public_key`.
    UpdateGatewayKey(String),
    /// Applique un jeu de règles nftables brut (dry-run = log seulement).
    ApplyFirewallRules(String),
    Disconnect,
    /// L'utilisateur a accepté le portail captif dans son navigateur — relancer la connexion.
    AcknowledgeCaptivePortal,
    /// Met à jour la liste des CIDRs bypassant le tunnel (split-tunneling dynamique).
    SetSplitTunnel(Vec<String>),
    /// Applique une valeur de MSS clamping issue de la sonde PMTUD (usage interne).
    SetMssClamp(u16),
    /// État déduit du polling des handshakes WireGuard (**usage interne**).
    ///
    /// Émise par le sondeur, jamais par l'API — aucune route ne la construit.
    /// Elle existe parce que le sondeur ne détient ni le backend de pare-feu ni
    /// la politique : écrire l'état lui-même laisserait le ruleset figé sur
    /// l'état précédent. Passer par la boucle principale garantit qu'une
    /// promotion vers `Up` ou une retombée vers `Connecting` re-rende toujours
    /// le pare-feu.
    TunnelStateInferred(TunnelState),
    /// Recharge la configuration réseau à chaud (sans redémarrer le daemon).
    /// Boxée : `NetworkConfig` est bien plus grosse que les autres variantes.
    LoadNetworkConfig(Box<NetworkConfig>),
}

/// Demande d'installation d'un PSK post-quantique sur un pair du plan de
/// données, émise par l'endpoint de provisioning vers l'orchestrateur.
///
/// # Pourquoi un canal dédié plutôt qu'une variante d'[`OrchestratorCmd`]
///
/// Deux raisons, toutes deux structurelles :
///
/// * cette demande porte un **secret** et attend une **réponse**, là où
///   `OrchestratorCmd` est un flux d'ordres d'IHM sans retour — la doter d'un
///   `oneshot` lui ferait perdre `Clone` ;
/// * garder le PSK hors d'une énumération qui dérive `Debug` supprime toute
///   possibilité de fuite par journalisation. Le champ est de surcroît un
///   [`SecretString`], donc muet à l'affichage.
///
/// # Pourquoi une réponse est indispensable
///
/// WireGuard n'a qu'un seul slot PSK par pair : une valeur posée d'un seul côté
/// fait échouer **tous** les handshakes suivants. L'endpoint ne doit donc
/// annoncer le PSK au client qu'une fois la gateway certaine de l'avoir posé.
/// Sans cet acquittement, un échec côté plan de données laisserait le client
/// installer un PSK orphelin et tomber — sans canal de contrôle pour se
/// rattraper, puisque ce canal vit dans le tunnel qui vient de mourir.
#[derive(Debug)]
pub struct InstallPskRequest {
    /// Clé publique Curve25519 du pair concerné (base64) — son identité.
    pub public_key: String,
    /// VIP attribuée au pair, en notation CIDR (ex. `100.64.1.2/32`).
    pub address: String,
    /// PSK dérivé de l'échange ML-KEM, en base64. **Secret.**
    pub psk: SecretString,
    /// Acquittement : `Ok` seulement si le PSK est réellement posé sur le pair.
    pub reply: oneshot::Sender<Result<(), String>>,
}
