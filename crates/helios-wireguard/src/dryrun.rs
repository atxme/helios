//! Backend de simulation : tient l'état de l'interface et des pairs en mémoire.
//!
//! Backend par défaut sur WSL2/dev. Il ne touche à aucun plan de données mais
//! reproduit fidèlement la sémantique observable — interface montée/démontée,
//! liste de pairs, handshakes — pour que l'orchestrateur, l'IPAM et l'API soient
//! pleinement exerçables sans noyau WireGuard ni privilèges.

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
    /// Si `true`, les pairs simulés rapportent un handshake frais (utile pour
    /// exercer l'inférence d'état sans plan de données).
    simulate_handshakes: bool,
    /// Si `true`, [`WireguardBackend::sync_peers`] échoue systématiquement.
    /// Sert à exercer les chemins de rattrapage de l'orchestrateur — notamment
    /// l'annulation d'une pose de PSK que le plan de données a refusée.
    fail_sync: bool,
}

impl DryRunBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Variante dont les pairs rapportent un handshake à l'instant présent.
    pub fn with_handshakes() -> Self {
        Self {
            simulate_handshakes: true,
            ..Self::default()
        }
    }

    /// Variante dont `sync_peers` échoue toujours : simule un plan de données
    /// qui refuse une reconfiguration.
    pub fn failing_sync() -> Self {
        Self {
            fail_sync: true,
            ..Self::default()
        }
    }

    fn decode_key(b64: &str) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| WgError::BadKey(format!("`{b64}` : {e}")))
            .and_then(|k| {
                if k.len() == 32 {
                    Ok(k)
                } else {
                    Err(WgError::BadKey(format!(
                        "longueur {} au lieu de 32",
                        k.len()
                    )))
                }
            })
    }
}

#[async_trait]
impl WireguardBackend for DryRunBackend {
    async fn up(&self, config: &InterfaceConfig, peers: &[PeerConfig]) -> Result<()> {
        // Valide comme le ferait le backend réel : une config qui passe en
        // dry-run doit passer sur la cible.
        Self::decode_key(&config.private_key)?;
        if config.address.trim().is_empty() {
            return Err(WgError::BadAddress("adresse de gateway vide".into()));
        }
        for p in peers {
            Self::decode_key(&p.public_key)?;
        }

        *self.iface.lock().unwrap() = Some(config.name.clone());
        *self.peers.lock().unwrap() = peers.to_vec();
        self.up.store(true, Ordering::SeqCst);

        info!(
            "[dry-run] interface {} montée — écoute UDP {}, adresse {}, {} pair(s)",
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
        info!("[dry-run] interface {} démontée", name.unwrap_or_default());
        Ok(())
    }

    async fn sync_peers(&self, peers: &[PeerConfig]) -> Result<()> {
        if self.fail_sync {
            return Err(WgError::Unavailable(
                "[dry-run] synchronisation des pairs refusée (panne simulée)".into(),
            ));
        }
        for p in peers {
            Self::decode_key(&p.public_key)?;
        }
        let mut slot = self.peers.lock().unwrap();
        let before = slot.len();
        *slot = peers.to_vec();
        info!("[dry-run] pairs synchronisés : {before} -> {}", peers.len());
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
    async fn sync_peers_remplace_la_liste() {
        let be = DryRunBackend::new();
        be.up(&iface(), &[peer(KEY_B, "100.64.1.2/32")])
            .await
            .unwrap();

        be.sync_peers(&[]).await.unwrap();
        assert!(be.peers().await.unwrap().is_empty(), "révocation appliquée");
    }

    #[tokio::test]
    async fn cle_invalide_refusee_des_le_dry_run() {
        let be = DryRunBackend::new();
        let mut cfg = iface();
        cfg.private_key = "pas-du-base64".into();
        assert!(be.up(&cfg, &[]).await.is_err());
        assert!(!be.is_up(), "aucune interface montée sur config invalide");

        // Une clé de pair trop courte est rejetée aussi.
        let bad = peer("AAAA", "100.64.1.2/32");
        assert!(be.up(&iface(), &[bad]).await.is_err());
    }

    #[tokio::test]
    async fn instantane_alimente_l_ipam() {
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
