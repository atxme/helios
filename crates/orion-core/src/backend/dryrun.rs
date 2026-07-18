//! Backend de simulation : monte un « faux » adaptateur WireGuard.
//!
//! C'est le backend par défaut sur WSL2/dev (aucune pile WireGuard requise). Il
//! modélise fidèlement le **cycle de vie de l'adaptateur** — la propriété de
//! sécurité d'Orion (ADR-001 §3 bis) — pour que l'invariante « jamais démonté
//! sur échec » soit réellement testable sans matériel ni privilèges.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use aether::TunnelState;
use async_trait::async_trait;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// Sentinelle : « aucun handshake » (impossible comme âge réel).
const NO_HANDSHAKE: u64 = u64::MAX;

/// Backend simulant la montée du tunnel et l'état de l'adaptateur.
pub struct DryRunBackend {
    /// Délai de handshake simulé (court en test).
    pub negotiate_delay: Duration,
    /// `true` = `up()` échoue après avoir monté l'adaptateur (test d'invariante).
    fail_after_adapter: bool,
    /// L'adaptateur est-il monté ? Modélise Wintun / l'interface WireGuard.
    adapter_up: AtomicBool,
    /// Âge simulé du dernier handshake, en secondes.
    handshake_age_secs: AtomicU64,
}

impl Default for DryRunBackend {
    fn default() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(700),
            fail_after_adapter: false,
            adapter_up: AtomicBool::new(false),
            handshake_age_secs: AtomicU64::new(NO_HANDSHAKE),
        }
    }
}

impl DryRunBackend {
    /// Variante qui monte l'adaptateur puis échoue au handshake — reproduit le
    /// scénario d'attaque « blocage de l'UDP 51820 » de l'ADR §3 bis.
    pub fn failing() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(10),
            fail_after_adapter: true,
            ..Self::default()
        }
    }

    /// Force l'âge du dernier handshake (pilotage des tests de polling).
    pub fn set_handshake_age(&self, age: Option<Duration>) {
        let v = age.map(|d| d.as_secs()).unwrap_or(NO_HANDSHAKE);
        self.handshake_age_secs.store(v, Ordering::SeqCst);
    }
}

#[async_trait]
impl VpnBackend for DryRunBackend {
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        profile.validate()?;

        // 1. L'adaptateur monte AVANT toute tentative réseau : dès cet instant,
        //    AllowedIPs = 0.0.0.0/0 capture le trafic et WireGuard le jette tant
        //    que la session n'est pas établie. Rien ne peut fuir en clair.
        self.adapter_up.store(true, Ordering::SeqCst);
        sink(ClientEvent::state(TunnelState::Connecting));
        sink(ClientEvent::log(
            "info",
            format!(
                "[dry-run] adaptateur monté ({}) — handshake vers {}",
                profile.allowed_ips, profile.endpoint
            ),
        ));

        tokio::time::sleep(self.negotiate_delay).await;

        // 2. Échec simulé : on renvoie une erreur SANS toucher à l'adaptateur.
        if self.fail_after_adapter {
            anyhow::bail!("[dry-run] handshake impossible (UDP 51820 bloqué ?)");
        }

        self.handshake_age_secs.store(0, Ordering::SeqCst);
        sink(ClientEvent::state(TunnelState::Up));
        let pq = if profile.is_post_quantum() {
            "PSK post-quantique installé"
        } else {
            "tunnel classique (PSK PQ absent)"
        };
        sink(ClientEvent::log("info", format!("[dry-run] tunnel établi — {pq}")));
        Ok(())
    }

    async fn down(&self, sink: &EventSink) -> anyhow::Result<()> {
        self.adapter_up.store(false, Ordering::SeqCst);
        self.handshake_age_secs.store(NO_HANDSHAKE, Ordering::SeqCst);
        sink(ClientEvent::log("info", "[dry-run] adaptateur démonté"));
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        match self.handshake_age_secs.load(Ordering::SeqCst) {
            NO_HANDSHAKE => None,
            secs => Some(Duration::from_secs(secs)),
        }
    }

    fn adapter_is_up(&self) -> bool {
        self.adapter_up.load(Ordering::SeqCst)
    }

    fn kind(&self) -> &'static str {
        "dry-run"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn collector() -> (EventSink, Arc<Mutex<Vec<ClientEvent>>>) {
        let log: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&log);
        let sink: EventSink = Arc::new(move |ev| l.lock().unwrap().push(ev));
        (sink, log)
    }

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "test".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            ..ClientProfile::default()
        }
    }

    fn states(log: &Arc<Mutex<Vec<ClientEvent>>>) -> Vec<TunnelState> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ClientEvent::StateChanged { state } => Some(*state),
                _ => None,
            })
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn simulation_atteint_up() {
        let backend = DryRunBackend {
            negotiate_delay: Duration::from_millis(10),
            ..DryRunBackend::default()
        };
        let (sink, log) = collector();
        backend.up(&profile(), &sink).await.unwrap();

        assert_eq!(states(&log), vec![TunnelState::Connecting, TunnelState::Up]);
        assert!(backend.adapter_is_up());
    }

    #[tokio::test]
    async fn down_revient_a_down_et_demonte() {
        let backend = DryRunBackend::default();
        let (sink, log) = collector();
        backend.up(&profile(), &sink).await.unwrap();
        backend.down(&sink).await.unwrap();

        assert_eq!(states(&log).last(), Some(&TunnelState::Down));
        assert!(!backend.adapter_is_up());
        assert!(backend.last_handshake_age().await.is_none());
    }

    /// Le backend lui-même ne doit pas démonter sur échec (ADR-001 §3 bis).
    #[tokio::test]
    async fn echec_laisse_l_adaptateur_monte() {
        let backend = DryRunBackend::failing();
        let (sink, _log) = collector();
        assert!(backend.up(&profile(), &sink).await.is_err());
        assert!(
            backend.adapter_is_up(),
            "l'adaptateur doit survivre à l'échec du handshake"
        );
    }

    #[tokio::test]
    async fn profil_invalide_echoue_sans_monter_l_adaptateur() {
        let backend = DryRunBackend::default();
        let (sink, _log) = collector();
        // Profil vide : pas de clés → refus avant tout effet de bord.
        assert!(backend.up(&ClientProfile::default(), &sink).await.is_err());
        assert!(!backend.adapter_is_up());
    }
}
