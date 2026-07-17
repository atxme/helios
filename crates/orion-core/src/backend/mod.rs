//! Abstraction du backend IPsec et contrôleur de connexion.
//!
//! Le `VpnBackend` est la frontière entre la logique portable (état, IHM) et la
//! pile IKEv2 **native de l'OS** qui monte réellement le tunnel. Seul
//! [`dryrun::DryRunBackend`] est compilé par défaut — il simule la montée et se
//! teste sur WSL2. Les backends réels (strongSwan Linux, IKEv2 natif Win/macOS)
//! sont derrière des features et ne sont validables que sur la cible, exactement
//! comme la feature `netlink` côté heliosd.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use helios_core::TunnelState;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

pub mod dryrun;

#[cfg(feature = "linux-strongswan")]
pub mod linux;
#[cfg(feature = "native-macos")]
pub mod macos;
#[cfg(feature = "native-windows")]
pub mod windows;

/// Puits d'événements : le backend pousse ses transitions d'état et ses logs ici.
/// Le shell Tauri fournit une implémentation qui relaie vers le frontend.
pub type EventSink = Arc<dyn Fn(ClientEvent) + Send + Sync>;

/// Une pile IKEv2 capable de monter/démonter un tunnel vers une gateway.
#[async_trait]
pub trait VpnBackend: Send + Sync {
    /// Monte le tunnel vers `profile.gateway`. Le backend **doit** émettre ses
    /// transitions d'état via `sink` (`Connecting` puis `Up`, ou `Failed`).
    async fn connect(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Démonte le tunnel. Le backend émet la transition vers `Down`.
    async fn disconnect(&self, sink: &EventSink) -> anyhow::Result<()>;

    /// Identifiant lisible du backend (diagnostic / IHM).
    fn kind(&self) -> &'static str;
}

/// Sélectionne le backend selon les features compilées. Sans feature de pile
/// réelle, on retombe sur la simulation dry-run (cas WSL2/dev).
// Les `return` explicites sont nécessaires : chaque branche est gardée par `cfg`,
// et selon la combinaison de features une seule reste active. Clippy ne voit
// qu'une branche à la fois et la croit superflue.
#[allow(clippy::needless_return)]
pub fn default_backend() -> Arc<dyn VpnBackend> {
    #[cfg(feature = "linux-strongswan")]
    {
        return Arc::new(linux::StrongSwanBackend::new());
    }
    #[cfg(all(feature = "native-windows", not(feature = "linux-strongswan")))]
    {
        return Arc::new(windows::WindowsIkev2Backend::new());
    }
    #[cfg(all(
        feature = "native-macos",
        not(feature = "linux-strongswan"),
        not(feature = "native-windows")
    ))]
    {
        return Arc::new(macos::MacosIkev2Backend::new());
    }
    #[cfg(not(any(
        feature = "linux-strongswan",
        feature = "native-windows",
        feature = "native-macos"
    )))]
    {
        Arc::new(dryrun::DryRunBackend::default())
    }
}

/// Contrôleur de connexion : détient l'état courant du tunnel et orchestre le
/// backend. Source de vérité unique de [`TunnelState`] côté client.
pub struct VpnController {
    backend: Arc<dyn VpnBackend>,
    state: Arc<RwLock<TunnelState>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl VpnController {
    pub fn new(backend: Arc<dyn VpnBackend>) -> Self {
        Self {
            backend,
            state: Arc::new(RwLock::new(TunnelState::Down)),
            task: Mutex::new(None),
        }
    }

    /// État courant du tunnel.
    pub fn state(&self) -> TunnelState {
        *self.state.read().unwrap()
    }

    /// Backend actif (diagnostic).
    pub fn backend_kind(&self) -> &'static str {
        self.backend.kind()
    }

    /// Construit un puits qui synchronise l'état interne **avant** de relayer
    /// l'événement à `user_sink`. Garantit que `state()` reflète toujours la
    /// dernière transition vue par l'IHM.
    fn wrap_sink(&self, user_sink: EventSink) -> EventSink {
        let state = Arc::clone(&self.state);
        Arc::new(move |ev: ClientEvent| {
            if let ClientEvent::StateChanged { state: s } = &ev {
                *state.write().unwrap() = *s;
            }
            user_sink(ev);
        })
    }

    /// Lance la connexion en tâche de fond (n'attend pas la montée complète).
    /// Annule toute connexion précédente.
    pub async fn connect(&self, profile: ClientProfile, user_sink: EventSink) {
        self.abort_task().await;
        let sink = self.wrap_sink(user_sink);
        let backend = Arc::clone(&self.backend);
        let handle = tokio::spawn(async move {
            if let Err(e) = backend.connect(&profile, &sink).await {
                sink(ClientEvent::state(TunnelState::Failed));
                sink(ClientEvent::Error {
                    message: format!("échec de connexion: {e}"),
                });
            }
        });
        *self.task.lock().await = Some(handle);
    }

    /// Démonte le tunnel et annule la tâche de connexion en cours.
    pub async fn disconnect(&self, user_sink: EventSink) {
        self.abort_task().await;
        let sink = self.wrap_sink(user_sink);
        if let Err(e) = self.backend.disconnect(&sink).await {
            sink(ClientEvent::Error {
                message: format!("échec de déconnexion: {e}"),
            });
        }
        // Garantit le retour à Down même si le backend n'a rien émis.
        if self.state() != TunnelState::Down {
            sink(ClientEvent::state(TunnelState::Down));
        }
    }

    async fn abort_task(&self) {
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
    }
}
