//! Backend Windows : IKEv2 natif via `Add-VpnConnection` / `rasdial` (cible).
//!
//! Compilé derrière la feature `native-windows`. Ébauche à compléter sur cible
//! réelle. **Limite connue** : la pile IKEv2 native de Windows ne supporte pas
//! l'échange hybride post-quantique RFC 9370 (ML-KEM) — les profils PQ ne sont
//! pas négociables par ce backend (à signaler dans l'IHM).

use async_trait::async_trait;
use helios_core::TunnelState;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

pub struct WindowsIkev2Backend;

impl WindowsIkev2Backend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsIkev2Backend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VpnBackend for WindowsIkev2Backend {
    async fn connect(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        if profile.uses_post_quantum() {
            anyhow::bail!(
                "la pile IKEv2 native Windows ne supporte pas l'échange post-quantique \
                 (profil ML-KEM) ; choisir le profil « classic » ou installer strongSwan"
            );
        }
        sink(ClientEvent::state(TunnelState::Connecting));
        // TODO(cible) : Add-VpnConnection -ServerAddress <gateway> -TunnelType Ikev2,
        // puis rasdial <nom>. Mapper la sortie vers Up/Failed.
        anyhow::bail!("backend Windows non encore implémenté")
    }

    async fn disconnect(&self, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "native-windows"
    }
}
