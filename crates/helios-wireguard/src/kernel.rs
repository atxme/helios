//! Gateway's **kernel** WireGuard backend, via `defguard_wireguard_rs`.
//!
//! Behind the `wireguard` feature. It compiles everywhere but can only be
//! *exercised* where the `wireguard` kernel module exists — not on WSL2. Same
//! status as `helios-firewall`'s `netlink` feature.
//!
//! # Server mode
//!
//! Unlike Orion's backend, the gateway **never calls `set_endpoint`** on its
//! peers: road-warriors roam and their source address is discovered on the
//! first handshake. Configuring a fixed endpoint would precisely prevent
//! roaming.

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
    /// The `defguard` API is synchronous and `create_interface` requires
    /// `&mut`. The `Mutex` provides mutable access behind the trait's
    /// `&self`; no `await` is held while the lock is taken.
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

    /// Translates a Helios peer into a `defguard` peer. **Without an
    /// endpoint**: see the module's doc-comment.
    fn build_peer(cfg: &PeerConfig) -> Result<Peer> {
        let key = Key::try_from(cfg.public_key.as_str())
            .map_err(|e| WgError::BadKey(format!("{}: {e}", cfg.public_key)))?;
        let mut peer = Peer::new(key);

        let allowed = IpAddrMask::from_str(&cfg.allowed_ips)
            .map_err(|e| WgError::BadAddress(format!("{}: {e}", cfg.allowed_ips)))?;
        peer.set_allowed_ips(vec![allowed]);

        if let Some(psk) = cfg
            .preshared_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
        {
            let psk = Key::try_from(psk)
                .map_err(|e| WgError::BadKey(format!("post-quantum PSK: {e}")))?;
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
        // Everything that can fail without side effects is done first.
        Key::try_from(config.private_key.as_str())
            .map_err(|e| WgError::BadKey(format!("gateway private key: {e}")))?;
        let address = IpAddrMask::from_str(&config.address)
            .map_err(|e| WgError::BadAddress(format!("{}: {e}", config.address)))?;
        let wg_peers = Self::build_peers(peers)?;

        let interface = InterfaceConfiguration {
            name: config.name.clone(),
            prvkey: config.private_key.clone(),
            addresses: vec![address],
            port: config.listen_port,
            peers: wg_peers,
            mtu: config.mtu,
            fwmark: None,
        };

        let mut api = self.api.lock().unwrap();
        api.create_interface().map_err(|e| self.iface_err(e))?;
        self.up.store(true, Ordering::SeqCst);

        api.configure_interface(&interface)
            .map_err(|e| self.iface_err(e))?;

        info!(
            "interface {} up — UDP listener {}, address {}, {} peer(s)",
            config.name,
            config.listen_port,
            config.address,
            peers.len()
        );
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        // `mut` required on Windows (`remove_interface(&mut self)`), superfluous elsewhere.
        #[allow(unused_mut)]
        let mut api = self.api.lock().unwrap();
        let result = api.remove_interface();
        self.up.store(false, Ordering::SeqCst);
        result.map_err(|e| self.iface_err(e))?;
        info!("interface {} down", self.ifname);
        Ok(())
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()> {
        let wanted = Self::build_peers(peers)?;
        let api = self.api.lock().unwrap();

        let host = api.read_interface_data().map_err(|e| self.iface_err(e))?;

        // Removes peers that are no longer admitted (revocation).
        for existing in host.peers.keys() {
            if !wanted.iter().any(|p| &p.public_key == existing) {
                match api.remove_peer(existing) {
                    Ok(()) => info!("revoked peer removed from {}", self.ifname),
                    Err(e) => warn!("could not remove a revoked peer: {e}"),
                }
            }
        }

        // Adds or updates admitted peers (`configure_peer` does both).
        for peer in &wanted {
            api.configure_peer(peer).map_err(|e| self.iface_err(e))?;
        }

        info!("{} peer(s) synchronized on {}", wanted.len(), self.ifname);
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
                // WireGuard reports the epoch as long as no handshake has
                // occurred: translate it to `None` rather than "55 years ago".
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

    /// Pure conversion: testable without a data plane.
    #[test]
    fn gateway_peer_without_endpoint() {
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
            "the gateway never sets an endpoint: that would break roaming"
        );
    }

    #[test]
    fn post_quantum_psk_transmitted() {
        let peer = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: "100.64.1.2/32".into(),
            preshared_key: Some(KEY_B.into()),
        })
        .unwrap();
        assert!(peer.preshared_key.is_some());
    }

    #[test]
    fn invalid_key_or_vip_rejected() {
        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: "not-base64".into(),
            allowed_ips: "100.64.1.2/32".into(),
            preshared_key: None,
        })
        .is_err());

        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: "not-an-address".into(),
            preshared_key: None,
        })
        .is_err());
    }
}
