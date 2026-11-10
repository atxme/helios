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
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};
use tracing::info;

use crate::{InterfaceConfig, PeerConfig, PeerStatus, Result, WgError, WireguardBackend};

/// Removes every peer outside the requested set and reports any failed
/// revocation. Continue after an individual error so one failure does not
/// prevent the other stale peers from being removed; the caller must not
/// proceed as though synchronization succeeded.
fn remove_revoked_peers<K, E>(
    existing: impl IntoIterator<Item = K>,
    is_wanted: impl Fn(&K) -> bool,
    mut remove: impl FnMut(&K) -> std::result::Result<(), E>,
) -> std::result::Result<(), String>
where
    E: std::fmt::Display,
{
    let mut failures = Vec::new();
    for peer in existing {
        if !is_wanted(&peer) {
            if let Err(error) = remove(&peer) {
                failures.push(error.to_string());
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

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

    fn lock_api(&self) -> Result<MutexGuard<'_, WGApi<Kernel>>> {
        self.api.lock().map_err(|_| {
            self.iface_err(
                "WireGuard backend mutex poisoned; refusing further data-plane operations",
            )
        })
    }

    /// Translates a Helios peer into a `defguard` peer. **Without an
    /// endpoint**: see the module's doc-comment.
    fn build_peer(cfg: &PeerConfig) -> Result<Peer> {
        let key = Key::try_from(cfg.public_key.as_str())
            .map_err(|e| WgError::BadKey(format!("{}: {e}", cfg.public_key)))?;
        let mut peer = Peer::new(key);

        // An empty list used to be impossible to write — the field was one
        // string, and an empty one failed to parse. A peer with no
        // `AllowedIPs` is unreachable and claims nothing, which is a
        // configuration bug rather than a state worth installing.
        if cfg.allowed_ips.is_empty() {
            return Err(WgError::BadAddress(format!(
                "peer {} has no AllowedIPs",
                cfg.public_key
            )));
        }
        peer.set_allowed_ips(Self::parse_masks(&cfg.allowed_ips)?);

        if let Some(psk) = cfg
            .preshared_key
            .as_ref()
            .map(|psk| psk.as_str())
            .filter(|k| !k.trim().is_empty())
        {
            let psk = Key::try_from(psk)
                .map_err(|e| WgError::BadKey(format!("post-quantum PSK: {e}")))?;
            peer.preshared_key = Some(psk);
        }
        // The gateway sends its own keep-alives rather than trusting the
        // client's setting, which it cannot inspect. Without them an idle
        // tunnel produces no handshake, and both liveness thresholds — the
        // client's renegotiation and this side's slot reclamation — would
        // read an ancient timestamp on a peer that is perfectly fine.
        if cfg.persistent_keepalive_secs > 0 {
            peer.persistent_keepalive_interval = Some(cfg.persistent_keepalive_secs);
        }
        Ok(peer)
    }

    fn build_peers(peers: &[PeerConfig]) -> Result<Vec<Peer>> {
        peers.iter().map(Self::build_peer).collect()
    }

    /// Translates the interface and its peers into a `defguard`
    /// configuration, validating everything that can be refused without
    /// touching the kernel.
    ///
    /// Every address is passed on: `defguard` assigns them one by one, and
    /// one the kernel refuses fails the whole bring-up. Leaving an address
    /// out is a decision for the caller, which knows why it would.
    fn build_interface(
        config: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<InterfaceConfiguration> {
        Key::try_from(config.private_key.as_str())
            .map_err(|e| WgError::BadKey(format!("gateway private key: {e}")))?;
        if config.addresses.is_empty() {
            return Err(WgError::BadAddress("no gateway address".into()));
        }
        Ok(InterfaceConfiguration {
            name: config.name.clone(),
            // `defguard` owns its own copy of the key and gives no borrowing
            // form, so this duplication is the boundary's, not ours. It lives
            // as long as the returned value, which does not outlive `up`.
            prvkey: config.private_key.to_string(),
            addresses: Self::parse_masks(&config.addresses)?,
            port: config.listen_port,
            peers: Self::build_peers(peers)?,
            mtu: config.mtu,
            fwmark: None,
        })
    }

    /// Parses every CIDR of a list, refusing the whole list on the first
    /// invalid entry and naming it.
    fn parse_masks(values: &[String]) -> Result<Vec<IpAddrMask>> {
        values
            .iter()
            .map(|value| {
                IpAddrMask::from_str(value)
                    .map_err(|e| WgError::BadAddress(format!("{value}: {e}")))
            })
            .collect()
    }
}

#[async_trait]
impl WireguardBackend for KernelBackend {
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()> {
        // Everything that can fail without side effects is done first.
        let interface = Self::build_interface(config, peers)?;

        let mut api = self.lock_api()?;
        api.create_interface().map_err(|e| self.iface_err(e))?;
        self.up.store(true, Ordering::SeqCst);

        api.configure_interface(&interface)
            .map_err(|e| self.iface_err(e))?;

        info!(
            "interface {} up — UDP listener {}, address {}, {} peer(s)",
            config.name,
            config.listen_port,
            config.addresses.join(", "),
            peers.len()
        );
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        // `mut` required on Windows (`remove_interface(&mut self)`), superfluous elsewhere.
        #[allow(unused_mut)]
        let mut api = self.lock_api()?;
        let result = api.remove_interface();
        self.up.store(false, Ordering::SeqCst);
        result.map_err(|e| self.iface_err(e))?;
        info!("interface {} down", self.ifname);
        Ok(())
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()> {
        let wanted = Self::build_peers(peers)?;
        let api = self.lock_api()?;

        let host = api.read_interface_data().map_err(|e| self.iface_err(e))?;

        // Removes peers that are no longer admitted (revocation).
        remove_revoked_peers(
            host.peers.keys(),
            |existing| wanted.iter().any(|peer| &peer.public_key == *existing),
            |existing| api.remove_peer(existing),
        )
        .map_err(|error| self.iface_err(format!("could not remove revoked peer(s): {error}")))?;

        // Adds or updates admitted peers (`configure_peer` does both).
        for peer in &wanted {
            api.configure_peer(peer).map_err(|e| self.iface_err(e))?;
        }

        info!("{} peer(s) synchronized on {}", wanted.len(), self.ifname);
        Ok(())
    }

    async fn peers(&self) -> Result<Vec<PeerStatus>> {
        let host = self
            .lock_api()?
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
    use zeroize::Zeroizing;

    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[test]
    fn failed_revocation_is_reported_after_all_stale_peers_are_attempted() {
        let existing = ["admitted", "revoked-one", "revoked-two"];
        let mut attempted = Vec::new();

        let result = remove_revoked_peers(
            existing,
            |peer| *peer == "admitted",
            |peer| {
                attempted.push(*peer);
                if *peer == "revoked-one" {
                    Err("injected remove failure")
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(attempted, ["revoked-one", "revoked-two"]);
        assert!(matches!(result, Err(message) if message.contains("injected remove failure")));
    }

    #[test]
    fn successful_revocation_skips_peers_in_the_requested_set() {
        let existing = ["admitted", "revoked"];
        let mut removed = Vec::new();

        remove_revoked_peers(
            existing,
            |peer| *peer == "admitted",
            |peer| {
                removed.push(*peer);
                Ok::<_, &'static str>(())
            },
        )
        .expect("all revoked peers removed");

        assert_eq!(removed, ["revoked"]);
    }

    /// Pure conversion: testable without a data plane.
    #[test]
    fn gateway_peer_without_endpoint() {
        let peer = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            preshared_key: None,
            persistent_keepalive_secs: 25,
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
            allowed_ips: vec!["100.64.1.2/32".into()],
            preshared_key: Some(Zeroizing::new(KEY_B.into())),
            persistent_keepalive_secs: 25,
        })
        .unwrap();
        assert!(peer.preshared_key.is_some());
    }

    #[test]
    fn an_empty_psk_is_absent_and_an_invalid_psk_is_refused() {
        let without_psk = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            preshared_key: Some(Zeroizing::new("   ".into())),
            persistent_keepalive_secs: 25,
        })
        .unwrap();
        assert!(without_psk.preshared_key.is_none());

        assert!(matches!(
            KernelBackend::build_peer(&PeerConfig {
                public_key: KEY_B.into(),
                allowed_ips: vec!["100.64.1.2/32".into()],
                preshared_key: Some(Zeroizing::new("not-a-key".into())),
                persistent_keepalive_secs: 25,
            }),
            Err(WgError::BadKey(message)) if message.contains("post-quantum PSK")
        ));
    }

    #[test]
    fn peer_list_translation_is_all_or_nothing() {
        let peers = [
            PeerConfig {
                public_key: KEY_B.into(),
                allowed_ips: vec!["100.64.1.2/32".into()],
                preshared_key: None,
                persistent_keepalive_secs: 25,
            },
            PeerConfig {
                public_key: "invalid".into(),
                allowed_ips: vec!["100.64.1.3/32".into()],
                preshared_key: None,
                persistent_keepalive_secs: 25,
            },
        ];

        assert!(KernelBackend::build_peers(&peers).is_err());
        assert!(KernelBackend::build_peers(&peers[..1]).is_ok());
    }

    /// A dual-stack peer claims one host per family, and both reach the
    /// kernel: dropping the IPv6 one would have WireGuard throw that traffic
    /// away as if the peer had no IPv6 VIP.
    #[test]
    fn a_dual_stack_peer_carries_both_hosts() {
        let peer = KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: vec![
                "100.64.1.2/32".into(),
                "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128".into(),
            ],
            preshared_key: None,
            persistent_keepalive_secs: 25,
        })
        .unwrap();

        let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
        assert_eq!(
            allowed,
            ["100.64.1.2/32", "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128"]
        );
    }

    #[test]
    fn a_peer_without_allowed_ips_is_refused() {
        assert!(matches!(
            KernelBackend::build_peer(&PeerConfig {
                public_key: KEY_B.into(),
                allowed_ips: Vec::new(),
                preshared_key: None,
                persistent_keepalive_secs: 25,
            }),
            Err(WgError::BadAddress(_))
        ));
    }

    fn interface(addresses: &[&str]) -> InterfaceConfig {
        InterfaceConfig {
            name: "helios0".into(),
            private_key: Zeroizing::new(KEY_B.into()),
            listen_port: crate::WG_LISTEN_PORT,
            addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
            mtu: Some(1420),
        }
    }

    #[test]
    fn every_interface_address_reaches_defguard_in_order() {
        let built = KernelBackend::build_interface(
            &interface(&["100.64.0.1/10", "fd3c:91a2:7e04::1/64"]),
            &[],
        )
        .unwrap();

        let addresses: Vec<String> = built.addresses.iter().map(ToString::to_string).collect();
        assert_eq!(addresses, ["100.64.0.1/10", "fd3c:91a2:7e04::1/64"]);
        assert_eq!(built.mtu, Some(1420));
    }

    #[test]
    fn an_interface_without_address_or_with_a_bad_one_is_refused() {
        assert!(matches!(
            KernelBackend::build_interface(&interface(&[]), &[]),
            Err(WgError::BadAddress(_))
        ));
        assert!(matches!(
            KernelBackend::build_interface(&interface(&["100.64.0.1/10", "fd3c::1/999"]), &[]),
            Err(WgError::BadAddress(message)) if message.contains("fd3c::1/999")
        ));
    }

    #[test]
    fn invalid_key_or_vip_rejected() {
        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: "not-base64".into(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            preshared_key: None,
            persistent_keepalive_secs: 25,
        })
        .is_err());

        assert!(KernelBackend::build_peer(&PeerConfig {
            public_key: KEY_B.into(),
            allowed_ips: vec!["not-an-address".into()],
            preshared_key: None,
            persistent_keepalive_secs: 25,
        })
        .is_err());
    }
}
