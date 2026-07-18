//! Plan de données WireGuard de la gateway Helios.
//!
//! La gateway est un **serveur** : elle écoute en UDP 51820 et les clients Orion
//! s'y connectent. Elle ne compose jamais vers un endpoint — les road-warriors
//! roament, leur adresse source est inconnue à l'avance. C'est la différence
//! structurante avec le backend d'Orion (`orion-core::backend::wireguard`), qui
//! lui compose vers un endpoint fixe.
//!
//! Deux backends, selon le patron déjà en place dans `helios-firewall` :
//! * [`DryRunBackend`] — en mémoire, testable partout (WSL2 compris) ;
//! * [`KernelBackend`] — réel, derrière la feature `wireguard`.
//!
//! Le crate fournit aussi [`PeerAddressTable`], qui branche la table de pairs
//! **vivante** sur l'IPAM de `helios-provisioning` : c'est elle qui sert de
//! source de vérité pour la résolution de collision de VIP, sans aucun état
//! persistant sur disque (ADR-001 §4).

use std::net::Ipv4Addr;
use std::time::SystemTime;

use async_trait::async_trait;

pub mod dryrun;
#[cfg(feature = "wireguard")]
pub mod kernel;

pub use dryrun::DryRunBackend;
#[cfg(feature = "wireguard")]
pub use kernel::KernelBackend;

/// Port d'écoute WireGuard de la gateway (invariant d'architecture).
pub const WG_LISTEN_PORT: u16 = 51820;

/// Erreurs du plan de données WireGuard.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("clé WireGuard invalide : {0}")]
    BadKey(String),
    #[error("adresse invalide : {0}")]
    BadAddress(String),
    #[error("interface {iface} : {source_msg}")]
    Interface { iface: String, source_msg: String },
    #[error("backend WireGuard indisponible : {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, WgError>;

/// Configuration de l'interface WireGuard de la gateway.
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Nom de l'interface (ex. `helios0`).
    pub name: String,
    /// Clé privée Curve25519 de la gateway, en base64. **Secret.**
    pub private_key: String,
    /// Port UDP d'écoute. La gateway écoute ; elle ne compose pas.
    pub listen_port: u16,
    /// Adresse de la gateway dans le réseau du tunnel (ex. `100.64.0.1/10`).
    pub address: String,
}

/// Un pair (client Orion) autorisé sur la gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Clé publique Curve25519 du client, en base64 — son identité.
    pub public_key: String,
    /// VIP assignée au client, en notation CIDR (ex. `100.64.1.2/32`).
    ///
    /// Dans WireGuard, `AllowedIPs` **est** la table de routage
    /// cryptographique : deux pairs ne peuvent pas revendiquer la même adresse.
    pub allowed_ips: String,
    /// PSK post-quantique dérivé de l'échange ML-KEM, en base64. **Secret.**
    pub preshared_key: Option<String>,
}

/// État observé d'un pair, lu depuis le plan de données.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// Clé publique brute (32 octets) — c'est aussi l'entrée de l'IPAM.
    pub public_key: Vec<u8>,
    /// VIP revendiquées par ce pair.
    pub allowed_ips: Vec<String>,
    /// Dernier handshake réussi. `None` = jamais.
    pub last_handshake: Option<SystemTime>,
    /// Endpoint courant du pair (il roame : cette valeur change).
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl PeerStatus {
    /// Clé publique en base64, pour l'affichage et l'API REST.
    pub fn public_key_b64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.public_key)
    }
}

/// Le plan de données WireGuard de la gateway.
#[async_trait]
pub trait WireguardBackend: Send + Sync {
    /// Monte l'interface et applique la configuration + les pairs initiaux.
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()>;

    /// Démonte l'interface.
    async fn down(&self) -> Result<()>;

    /// Aligne la liste des pairs autorisés sur `peers` (ajouts et retraits).
    /// Appelé après chaque enrôlement ou révocation.
    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()>;

    /// Lit l'état courant des pairs depuis le plan de données.
    async fn peers(&self) -> Result<Vec<PeerStatus>>;

    /// L'interface est-elle montée ?
    fn is_up(&self) -> bool;

    /// Identifiant lisible du backend (diagnostic / IHM).
    fn kind(&self) -> &'static str;
}

/// Vue de la table de pairs vivante, branchée sur l'IPAM.
///
/// C'est le chaînon qui rend l'attribution de VIP « sans état disque » réelle :
/// la source de vérité est le plan de données lui-même, reconstruit à mesure que
/// les clients se reconnectent (ADR-001 §4).
pub struct PeerAddressTable {
    /// `(VIP, clé publique brute)` pour chaque pair connu.
    entries: Vec<(Ipv4Addr, Vec<u8>)>,
}

impl PeerAddressTable {
    /// Construit la table depuis un instantané du plan de données.
    ///
    /// Les `allowed_ips` non-IPv4 ou malformées sont ignorées : elles ne peuvent
    /// pas entrer en collision avec une VIP CGNAT dérivée.
    pub fn from_peers(peers: &[PeerStatus]) -> Self {
        let mut entries = Vec::new();
        for peer in peers {
            for cidr in &peer.allowed_ips {
                let host = cidr.split('/').next().unwrap_or(cidr);
                if let Ok(addr) = host.parse::<Ipv4Addr>() {
                    entries.push((addr, peer.public_key.clone()));
                }
            }
        }
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl helios_provisioning::PeerTable for PeerAddressTable {
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|(a, owner)| *a == addr && owner.as_slice() != pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_provisioning::PeerTable;

    fn peer(pubkey: &[u8], vip: &str) -> PeerStatus {
        PeerStatus {
            public_key: pubkey.to_vec(),
            allowed_ips: vec![vip.to_string()],
            last_handshake: None,
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    #[test]
    fn table_detecte_la_collision_avec_un_autre_pair() {
        let table = PeerAddressTable::from_peers(&[peer(&[1u8; 32], "100.64.1.2/32")]);
        let vip: Ipv4Addr = "100.64.1.2".parse().unwrap();

        // Une autre clé revendiquant la même VIP = collision.
        assert!(table.is_taken_by_other(vip, &[2u8; 32]));
        // Le même pair ne collisionne jamais avec lui-même (reconnexion).
        assert!(!table.is_taken_by_other(vip, &[1u8; 32]));
    }

    #[test]
    fn adresse_libre_non_signalee() {
        let table = PeerAddressTable::from_peers(&[peer(&[1u8; 32], "100.64.1.2/32")]);
        let autre: Ipv4Addr = "100.64.9.9".parse().unwrap();
        assert!(!table.is_taken_by_other(autre, &[2u8; 32]));
    }

    #[test]
    fn allowed_ips_non_ipv4_ignorees() {
        let mut p = peer(&[1u8; 32], "100.64.1.2/32");
        p.allowed_ips.push("fd00::1/128".into());
        p.allowed_ips.push("n'importe quoi".into());
        let table = PeerAddressTable::from_peers(&[p]);
        // Seule l'entrée IPv4 valide est retenue.
        assert!(!table.is_empty());
        assert!(table.is_taken_by_other("100.64.1.2".parse().unwrap(), &[2u8; 32]));
    }

    #[test]
    fn cle_publique_en_base64() {
        let p = peer(&[0u8; 32], "100.64.0.2/32");
        assert_eq!(
            p.public_key_b64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }
}
