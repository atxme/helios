//! Simulation backend: keeps the interface and peer state in memory.
//!
//! Default backend on WSL2/dev. It touches no data plane at all but
//! faithfully reproduces the observable semantics — interface up/down, peer
//! list, handshakes — so that the orchestrator, the IPAM and the API are
//! fully exercisable without a WireGuard kernel or privileges.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

use async_trait::async_trait;
use base64::Engine as _;
use tracing::info;

use crate::{InterfaceConfig, PeerConfig, PeerStatus, Result, WgError, WireguardBackend};

#[derive(Default)]
pub struct DryRunBackend {
    up: AtomicBool,
    iface: Mutex<Option<String>>,
    peers: Mutex<Vec<PeerConfig>>,
    /// If `true`, the simulated peers report a fresh handshake (useful for
    /// exercising state inference without a data plane).
    simulate_handshakes: bool,
    /// If `true`, [`WireguardBackend::sync_peers`] systematically fails.
    /// Used to exercise the orchestrator's recovery paths — notably the
    /// rollback of a PSK application that the data plane refused.
    fail_sync: bool,
}

impl DryRunBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Variant whose peers report a handshake at the present instant.
    pub fn with_handshakes() -> Self {
        Self {
            simulate_handshakes: true,
            ..Self::default()
        }
    }

    /// Variant whose `sync_peers` always fails: simulates a data plane that
    /// refuses a reconfiguration.
    pub fn failing_sync() -> Self {
        Self {
            fail_sync: true,
            ..Self::default()
        }
    }

    fn decode_key(b64: &str) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| WgError::BadKey(format!("`{b64}`: {e}")))
            .and_then(|k| {
                if k.len() == 32 {
                    Ok(k)
                } else {
                    Err(WgError::BadKey(format!("length {} instead of 32", k.len())))
                }
            })
    }
}

#[async_trait]
impl WireguardBackend for DryRunBackend {
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()> {
        // Validates like the real backend would: a config that passes in
        // dry-run must pass on the target.
        Self::decode_key(&config.private_key)?;
        if config.address.trim().is_empty() {
            return Err(WgError::BadAddress("empty gateway address".into()));
        }
        for p in peers {
            Self::decode_key(&p.public_key)?;
        }

        *self.iface.lock().unwrap() = Some(config.name.clone());
        *self.peers.lock().unwrap() = peers.to_vec();
        self.up.store(true, Ordering::SeqCst);

        info!(
            "[dry-run] interface {} up — UDP listener {}, address {}, {} peer(s)",
            config.name,
            config.listen_port,
            config.address,
            peers.len()
        );
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        let name = self.iface.lock().unwrap().take();
        self.peers.lock().unwrap().clear();
        self.up.store(false, Ordering::SeqCst);
        info!("[dry-run] interface {} down", name.unwrap_or_default());
        Ok(())
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()> {
        if self.fail_sync {
            return Err(WgError::Unavailable(
                "[dry-run] peer synchronization refused (simulated failure)".into(),
            ));
        }
        for p in peers {
            Self::decode_key(&p.public_key)?;
        }
        let mut slot = self.peers.lock().unwrap();
        let before = slot.len();
        *slot = peers.to_vec();
        info!("[dry-run] peers synchronized: {before} -> {}", peers.len());
        Ok(())
    }

    async fn peers(&self) -> Result<Vec<PeerStatus>> {
        let peers = self.peers.lock().unwrap();
        let now = self.simulate_handshakes.then(SystemTime::now);
        peers
            .iter()
            .map(|p| {
                Ok(PeerStatus {
                    public_key: Self::decode_key(&p.public_key)?,
                    allowed_ips: vec![p.allowed_ips.clone()],
                    last_handshake: now,
                    endpoint: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                })
            })
            .collect()
    }

    fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }

    fn kind(&self) -> &'static str {
        "dry-run"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn iface() -> InterfaceConfig {
        InterfaceConfig {
            name: "helios0".into(),
            private_key: KEY_A.into(),
            listen_port: crate::WG_LISTEN_PORT,
            address: "100.64.0.1/10".into(),
            mtu: None,
        }
    }

    fn peer(key: &str, vip: &str) -> PeerConfig {
        PeerConfig {
            public_key: key.into(),
            allowed_ips: vip.into(),
            preshared_key: None,
        }
    }

    #[tokio::test]
    async fn cycle_up_down() {
        let be = DryRunBackend::new();
        assert!(!be.is_up());

        be.up(&iface(), &[peer(KEY_B, "100.64.1.2/32")])
            .await
            .unwrap();
        assert!(be.is_up());
        assert_eq!(be.peers().await.unwrap().len(), 1);

        be.down().await.unwrap();
        assert!(!be.is_up());
        assert!(be.peers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sync_peers_replaces_the_list() {
        let be = DryRunBackend::new();
        be.up(&iface(), &[peer(KEY_B, "100.64.1.2/32")])
            .await
            .unwrap();

        be.sync_peers(&[]).await.unwrap();
        assert!(be.peers().await.unwrap().is_empty(), "revocation applied");
    }

    #[tokio::test]
    async fn invalid_key_rejected_from_dry_run() {
        let be = DryRunBackend::new();
        let mut cfg = iface();
        cfg.private_key = "not-base64".into();
        assert!(be.up(&cfg, &[]).await.is_err());
        assert!(!be.is_up(), "no interface up on invalid config");

        // A peer key that is too short is also rejected.
        let bad = peer("AAAA", "100.64.1.2/32");
        assert!(be.up(&iface(), &[bad]).await.is_err());
    }

    #[tokio::test]
    async fn snapshot_feeds_the_ipam() {
        use helios_provisioning::PeerTable;

        let be = DryRunBackend::with_handshakes();
        be.up(&iface(), &[peer(KEY_B, "100.64.1.2/32")])
            .await
            .unwrap();

        let snapshot = be.peers().await.unwrap();
        assert!(snapshot[0].last_handshake.is_some());

        let table = crate::PeerAddressTable::from_peers(&snapshot);
        let vip = "100.64.1.2".parse().unwrap();
        assert!(table.is_taken_by_other(vip, &[9u8; 32]));
    }
}
