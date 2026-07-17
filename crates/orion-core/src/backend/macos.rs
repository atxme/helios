//! Backend macOS : IKEv2 natif via profil de configuration / `scutil` (cible).
//!
//! Compilé derrière la feature `native-macos`. Ébauche à compléter sur cible
//! réelle. **Limite connue** : la pile IKEv2 native de macOS ne supporte pas
//! l'échange hybride post-quantique RFC 9370 (ML-KEM) — voir le backend Windows.

use async_trait::async_trait;
use aether::TunnelState;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

pub struct MacosIkev2Backend;

impl MacosIkev2Backend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosIkev2Backend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VpnBackend for MacosIkev2Backend {
    async fn connect(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        if profile.uses_post_quantum() {
            anyhow::bail!(
                "la pile IKEv2 native macOS ne supporte pas l'échange post-quantique \
                 (profil ML-KEM) ; choisir le profil « classic » ou installer strongSwan"
            );
        }
        sink(ClientEvent::state(TunnelState::Connecting));
        // TODO(cible) : installer un profil de configuration (.mobileconfig) puis
        // `scutil --nc start <service>`. Mapper la sortie vers Up/Failed.
        anyhow::bail!("backend macOS non encore implémenté")
    }

    async fn disconnect(&self, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "native-macos"
    }
}
