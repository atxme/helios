//! Backend de simulation : monte un « faux » tunnel avec timing réaliste.
//!
//! C'est le backend par défaut sur WSL2/dev (aucune pile IKEv2 requise). Il
//! reproduit la séquence d'états d'une vraie connexion afin que l'IHM et la
//! logique de télémétrie soient pleinement exerçables sans charon ni privilèges.

use std::time::Duration;

use async_trait::async_trait;
use aether::TunnelState;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// Backend simulant la montée du tunnel.
pub struct DryRunBackend {
    /// Délai de négociation IKE simulé (court en test).
    pub negotiate_delay: Duration,
}

impl Default for DryRunBackend {
    fn default() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(700),
        }
    }
}

#[async_trait]
impl VpnBackend for DryRunBackend {
    async fn connect(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::state(TunnelState::Connecting));
        sink(ClientEvent::log(
            "info",
            format!("[dry-run] handshake WireGuard vers {}", profile.gateway),
        ));
        tokio::time::sleep(self.negotiate_delay).await;
        sink(ClientEvent::state(TunnelState::Up));
        sink(ClientEvent::log(
            "info",
            "[dry-run] tunnel établi — PSK post-quantique installé".to_string(),
        ));
        Ok(())
    }

    async fn disconnect(&self, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::log("info", "[dry-run] fermeture du tunnel"));
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
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

    #[tokio::test(start_paused = true)]
    async fn simulation_atteint_up() {
        let backend = DryRunBackend {
            negotiate_delay: Duration::from_millis(10),
        };
        let (sink, log) = collector();
        backend
            .connect(&ClientProfile::default(), &sink)
            .await
            .unwrap();

        let states: Vec<TunnelState> = log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ClientEvent::StateChanged { state } => Some(*state),
                _ => None,
            })
            .collect();
        assert_eq!(states, vec![TunnelState::Connecting, TunnelState::Up]);
    }

    #[tokio::test]
    async fn disconnect_revient_a_down() {
        let backend = DryRunBackend::default();
        let (sink, log) = collector();
        backend.disconnect(&sink).await.unwrap();
        let last = log
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|e| match e {
                ClientEvent::StateChanged { state } => Some(*state),
                _ => None,
            });
        assert_eq!(last, Some(TunnelState::Down));
    }
}
