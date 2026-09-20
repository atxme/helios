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
use zeroize::Zeroizing;

use crate::{InterfaceConfig, PeerConfig, PeerStatus, Result, WgError, WireguardBackend};

/// What the simulation keeps of an admitted peer.
///
/// Deliberately **not** a [`PeerConfig`]: that one carries the PSK, and
/// nothing here ever reads it back — [`WireguardBackend::peers`] reports
/// identity and VIP. Storing the whole structure kept every negotiated PSK
/// alive in this `Mutex` for as long as the process, on the one backend that
/// runs everywhere including a developer's machine (ADR-006 §5).
struct InstalledPeer {
    public_key: String,
    allowed_ips: String,
}

impl From<&PeerConfig> for InstalledPeer {
    fn from(peer: &PeerConfig) -> Self {
        Self {
            public_key: peer.public_key.clone(),
            allowed_ips: peer.allowed_ips.clone(),
        }
    }
}

#[derive(Default)]
pub struct DryRunBackend {
    up: AtomicBool,
    iface: Mutex<Option<String>>,
    peers: Mutex<Vec<InstalledPeer>>,
    /// If `true`, the simulated peers report a recent handshake (useful for
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

    /// Decodes a 32-byte base64 key, reporting the failure **without** the
    /// value.
    fn decode(b64: &str) -> std::result::Result<Vec<u8>, String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| e.to_string())?;
        if raw.len() == 32 {
            Ok(raw)
        } else {
            Err(format!("length {} instead of 32", raw.len()))
        }
    }

    /// Decodes a peer's **public** key. The failing value is part of the
    /// message: a public key is an identity, and naming it is what makes the
    /// error actionable for the operator.
    fn decode_public_key(b64: &str) -> Result<Vec<u8>> {
        Self::decode(b64).map_err(|e| WgError::BadKey(format!("`{b64}`: {e}")))
    }

    /// Validates the gateway's private key under the same rules, and names
    /// **nothing** on failure.
    ///
    /// The previous single helper put the offending value in the message, and
    /// `up` validates the private key through it: a mistyped key wrote the
    /// gateway's identity into an error that the orchestrator logs and
    /// broadcasts to the console (ADR-006 §5).
    fn check_private_key(b64: &str) -> Result<()> {
        // Wrap the decoded buffer before checking its length: malformed keys
        // still contain private material, and the generic public-key helper
        // would otherwise drop that allocation without wiping it on this
        // error path.
        let raw = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| WgError::BadKey(format!("gateway private key: {e}")))?,
        );
        if raw.len() == 32 {
            Ok(())
        } else {
            Err(WgError::BadKey(format!(
                "gateway private key: length {} instead of 32",
                raw.len()
            )))
        }
    }
}

#[async_trait]
impl WireguardBackend for DryRunBackend {
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()> {
        // Validates like the real backend would: a config that passes in
        // dry-run must pass on the target.
        Self::check_private_key(&config.private_key)?;
        if config.address.trim().is_empty() {
            return Err(WgError::BadAddress("empty gateway address".into()));
        }
        for p in peers {
            Self::decode_public_key(&p.public_key)?;
        }

        *self.iface.lock().unwrap() = Some(config.name.clone());
        *self.peers.lock().unwrap() = peers.iter().map(InstalledPeer::from).collect();
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
            Self::decode_public_key(&p.public_key)?;
        }
        let mut slot = self.peers.lock().unwrap();
        let before = slot.len();
        *slot = peers.iter().map(InstalledPeer::from).collect();
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
                    public_key: Self::decode_public_key(&p.public_key)?,
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
            private_key: Zeroizing::new(KEY_A.into()),
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
            persistent_keepalive_secs: 25,
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
        cfg.private_key = Zeroizing::new("not-base64".into());
        assert!(be.up(&cfg, &[]).await.is_err());
        assert!(!be.is_up(), "no interface up on invalid config");

        // A peer key that is too short is also rejected.
        let bad = peer("AAAA", "100.64.1.2/32");
        assert!(be.up(&iface(), &[bad]).await.is_err());
    }

    /// The refusal message must not carry the key it refused.
    ///
    /// `up` validates the gateway's private key on this path, and the
    /// orchestrator logs and broadcasts what it gets back: a message quoting
    /// the offending value puts the gateway's identity in the journal and in
    /// the console (ADR-006 §5).
    #[tokio::test]
    async fn a_refused_private_key_is_not_named_in_the_error() {
        const NEARLY: &str = "Q2VjaS1uLWVzdC1wYXMtdW5lLWNsZS12YWxpZGU=";

        let be = DryRunBackend::new();
        let mut cfg = iface();
        cfg.private_key = Zeroizing::new(NEARLY.into());

        let Err(error) = be.up(&cfg, &[]).await else {
            panic!("a 29-byte key must be refused");
        };
        let rendered = error.to_string();
        assert!(
            !rendered.contains(NEARLY),
            "the private key leaked into the error: {rendered}"
        );
        assert!(
            rendered.contains("gateway private key"),
            "the error must still say what was refused: {rendered}"
        );
    }

    /// A PSK handed to the backend must not survive in its state.
    ///
    /// The simulation is the backend that runs everywhere, including on a
    /// developer's machine; keeping the whole `PeerConfig` left every
    /// negotiated PSK resident for the life of the process.
    #[tokio::test]
    async fn the_simulation_keeps_no_psk_of_the_peers_it_installs() {
        const PSK: &str = "cHNrLXF1aS1uZS1kb2l0LXBhcy1yZXN0ZXItbGE=";

        let be = DryRunBackend::new();
        let mut admitted = peer(KEY_B, "100.64.1.2/32");
        admitted.preshared_key = Some(Zeroizing::new(PSK.into()));
        be.up(&iface(), &[admitted]).await.unwrap();

        let stored = be.peers.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].public_key, KEY_B);
        assert_eq!(stored[0].allowed_ips, "100.64.1.2/32");
        // What the backend kept is an `InstalledPeer`, which has no slot for
        // a PSK: the guarantee is the type's, and this test is what fails if
        // the stored shape ever goes back to `PeerConfig`.
    }
}
