//! Backend WireGuard **noyau** de la gateway, via `defguard_wireguard_rs`.
//!
//! Derrière la feature `wireguard`. Il compile partout mais ne peut être
//! *exercé* que là où le module noyau `wireguard` existe — pas sur WSL2. Même
//! statut que la feature `netlink` de `helios-firewall`.
//!
//! # Mode serveur
//!
//! Contrairement au backend d'Orion, la gateway **n'appelle jamais
//! `set_endpoint`** sur ses pairs : les road-warriors roament et leur adresse
//! source est découverte au premier handshake. Configurer un endpoint fixe
//! empêcherait précisément le roaming.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};
use tracing::{info, warn};

use crate::{InterfaceConfig, PeerConfig, PeerStatus, Result, WgError, WireguardBackend};

pub struct KernelBackend {
    ifname: String,
    /// L'API `defguard` est synchrone et `create_interface` exige `&mut`.
    /// Le `Mutex` fournit l'accès mutable derrière le `&self` du trait ; aucun
    /// `await` n'est tenu pendant que le verrou est pris.
    api: Mutex<WGApi<Kernel>>,
    up: AtomicBool,
}

impl KernelBackend {
    pub fn new(ifname: &str) -> Result<Self> {
        let api = WGApi::<Kernel>::new(ifname.to_string())
            .map_err(|e| WgError::Unavailable(e.to_string()))?;
        Ok(Self {
            ifname: ifname.to_string(),
            api: Mutex::new(api),
            up: AtomicBool::new(false),
        })
    }

    fn iface_err(&self, e: impl std::fmt::Display) -> WgError {
        WgError::Interface {
            iface: self.ifname.clone(),
            source_msg: e.to_string(),
        }
    }

    /// Traduit un pair Helios en pair `defguard`. **Sans endpoint** : voir le
    /// doc-comment du module.
    fn build_peer(cfg: &PeerConfig) -> Result<Peer> {
        let key = Key::try_from(cfg.public_key.as_str())
            .map_err(|e| WgError::BadKey(format!("{} : {e}", cfg.public_key)))?;
        let mut peer = Peer::new(key);

        let allowed = IpAddrMask::from_str(&cfg.allowed_ips)
            .map_err(|e| WgError::BadAddress(format!("{} : {e}", cfg.allowed_ips)))?;
        peer.set_allowed_ips(vec![allowed]);

        if let Some(psk) = cfg
            .preshared_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
        {
            let psk = Key::try_from(psk)
                .map_err(|e| WgError::BadKey(format!("PSK post-quantique : {e}")))?;
            peer.preshared_key = Some(psk);
        }
        Ok(peer)
    }

    fn build_peers(peers: &[PeerConfig]) -> Result<Vec<Peer>> {
        peers.iter().map(Self::build_peer).collect()
    }
}

#[async_trait]
impl WireguardBackend for KernelBackend {
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()> {
        // Tout ce qui peut échouer sans effet de bord se fait d'abord.
        Key::try_from(config.private_key.as_str())
            .map_err(|e| WgError::BadKey(format!("clé privée de la gateway : {e}")))?;
        let address = IpAddrMask::from_str(&config.address)
            .map_err(|e| WgError::BadAddress(format!("{} : {e}", config.address)))?;
        let wg_peers = Self::build_peers(peers)?;

        let interface = InterfaceConfiguration {
            name: config.name.clone(),
            prvkey: config.private_key.clone(),
            addresses: vec![address],
            port: config.listen_port,
            peers: wg_peers,
            mtu: None,
            fwmark: None,
        };

        let mut api = self.api.lock().unwrap();
        api.create_interface().map_err(|e| self.iface_err(e))?;
        self.up.store(true, Ordering::SeqCst);

        api.configure_interface(&interface)
            .map_err(|e| self.iface_err(e))?;

        info!(
            "interface {} montée — écoute UDP {}, adresse {}, {} pair(s)",
            config.name,
            config.listen_port,
            config.address,
            peers.len()
        );
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        // `mut` requis sur Windows (`remove_interface(&mut self)`), superflu ailleurs.
        #[allow(unused_mut)]
        let mut api = self.api.lock().unwrap();
        let result = api.remove_interface();
        self.up.store(false, Ordering::SeqCst);
        result.map_err(|e| self.iface_err(e))?;
        info!("interface {} démontée", self.ifname);
        Ok(())
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()> {
        let wanted = Self::build_peers(peers)?;
        let api = self.api.lock().unwrap();

        let host = api.read_interface_data().map_err(|e| self.iface_err(e))?;

        // Retire les pairs qui ne sont plus autorisés (révocation).
        for existing in host.peers.keys() {
            if !wanted.iter().any(|p| &p.public_key == existing) {
                match api.remove_peer(existing) {
                    Ok(()) => info!("pair révoqué retiré de {}", self.ifname),
                    Err(e) => warn!("retrait d'un pair révoqué impossible : {e}"),
                }
            }
        }

        // Ajoute ou met à jour les pairs autorisés (`configure_peer` fait les deux).
        for peer in &wanted {
            api.configure_peer(peer).map_err(|e| self.iface_err(e))?;
        }

        info!(
            "{} pair(s) synchronisé(s) sur {}",
            wanted.len(),
            self.ifname
        );
        Ok(())
    }

    async fn peers(&self) -> Result<Vec<PeerStatus>> {
        let host = self
            .api
            .lock()
            .unwrap()
            .read_interface_data()
            .map_err(|e| self.iface_err(e))?;

        Ok(host
            .peers
            .into_values()
            .map(|p| PeerStatus {
                public_key: p.public_key.as_slice().to_vec(),
                allowed_ips: p.allowed_ips.iter().map(ToString::to_string).collect(),
                // WireGuard rapporte l'epoch tant qu'aucun handshake n'a eu lieu :
                // le traduire en `None` plutôt qu'en « il y a 55 ans ».
                last_handshake: p.last_handshake.filter(|t| *t != std::time::UNIX_EPOCH),
                endpoint: p.endpoint.map(|e| e.to_string()),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            })
            .collect())
    }

    fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }

    fn kind(&self) -> &'static str {
        "wireguard-kernel"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// Conversion pure : testable sans plan de données.
    #[test]
    fn pair_gateway_sans_endpoint() {
        let peer = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: "100.64.1.2/32".into(),
            preshared_key: None,
        })
        .unwrap();

        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.allowed_ips[0].to_string(), "100.64.1.2/32");
        assert!(
            peer.endpoint.is_none(),
            "la gateway ne fixe jamais d'endpoint : cela casserait le roaming"
        );
    }

    #[test]
    fn psk_post_quantique_transmis() {
        let peer = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: "100.64.1.2/32".into(),
            preshared_key: Some(KEY_B.into()),
        })
        .unwrap();
        assert!(peer.preshared_key.is_some());
    }

    #[test]
    fn cle_ou_vip_invalide_rejetee() {
        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: "pas-du-base64".into(),
            allowed_ips: "100.64.1.2/32".into(),
            preshared_key: None,
        })
        .is_err());

        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: "pas-une-adresse".into(),
            preshared_key: None,
        })
        .is_err());
    }
}
