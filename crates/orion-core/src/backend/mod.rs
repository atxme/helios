//! Abstraction du backend WireGuard et contrôleur de connexion.
//!
//! # L'invariante de cycle de vie de l'adaptateur — lire avant de modifier
//!
//! Orion est délibérément **fail-open** (CWE-636) : aucun pare-feu, aucun WFP
//! (ADR-001 §3 bis). Sa seule protection contre la fuite en clair est une
//! discipline de cycle de vie :
//!
//! > L'adaptateur (Wintun) porte `AllowedIPs = 0.0.0.0/0`. Il est monté à la
//! > connexion et **n'est JAMAIS démonté sur échec** — ni en `Connecting`, ni en
//! > `Failed`, ni après N tentatives. Il n'est retiré que sur **déconnexion
//! > explicite** de l'utilisateur ou fermeture de l'application.
//!
//! Tant que l'adaptateur tient, les paquets partent vers WireGuard qui les
//! **jette** si la session est morte : l'attaquant qui bloque l'UDP 51820
//! n'obtient qu'un déni de service. S'il tombe, la route par défaut retombe sur
//! l'interface physique et le trafic sort **en clair**.
//!
//! C'est pour cela que le trait sépare [`VpnBackend::up`] de
//! [`VpnBackend::down`] : `down` n'est appelé que depuis
//! [`VpnController::disconnect`], jamais sur un chemin d'erreur. Le test
//! `adaptateur_reste_monte_apres_echec` verrouille cette propriété.
//!
//! Seul [`dryrun::DryRunBackend`] est compilé par défaut (testable sur WSL2). Le
//! backend WireGuard réel (BoringTun + Wintun via `defguard_wireguard_rs`) est
//! target-only, comme la feature `netlink` côté heliosd.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use aether::TunnelState;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

pub mod dryrun;
#[cfg(feature = "wireguard")]
pub mod wireguard;

/// Au-delà de cet âge, le dernier handshake est considéré périmé et l'état
/// retombe de `Up` à `Connecting`.
///
/// 150 s laisse une marge sous `REJECT_AFTER_TIME` (180 s) : à 179 s on
/// flapperait au moindre jitter (ADR-001 §3).
pub const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// Puits d'événements : le backend pousse ses transitions d'état et ses logs ici.
/// Le shell Tauri fournit une implémentation qui relaie vers le frontend.
pub type EventSink = Arc<dyn Fn(ClientEvent) + Send + Sync>;

/// Une pile WireGuard capable de monter/démonter un tunnel vers une gateway.
#[async_trait]
pub trait VpnBackend: Send + Sync {
    /// Monte l'adaptateur (`AllowedIPs = 0.0.0.0/0`) et configure le pair.
    ///
    /// **Contrat** : en cas d'échec, l'implémentation ne doit **pas** démonter
    /// l'adaptateur si elle a réussi à le créer — laisser WireGuard jeter les
    /// paquets vaut mieux que de rendre la route physique au trafic en clair.
    /// Doit être idempotent : rappeler `up` sur un adaptateur déjà monté
    /// reconfigure le pair sans le recréer.
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Démonte l'adaptateur. **Appelé uniquement sur déconnexion explicite.**
    async fn down(&self, sink: &EventSink) -> anyhow::Result<()>;

    /// Âge du dernier handshake réussi, ou `None` si aucun.
    /// Source de l'inférence d'état (WireGuard est sans connexion).
    async fn last_handshake_age(&self) -> Option<Duration>;

    /// L'adaptateur est-il actuellement monté ? Sert à vérifier l'invariante.
    fn adapter_is_up(&self) -> bool;

    /// Identifiant lisible du backend (diagnostic / IHM).
    fn kind(&self) -> &'static str;
}

/// Sélectionne le backend selon les features compilées. Sans backend réel
/// compilé, on retombe sur la simulation dry-run (cas WSL2/dev).
///
/// Avec la feature `wireguard`, on tente le backend réel ; s'il ne peut même pas
/// s'initialiser (plan de données absent, droits insuffisants), on **échoue en
/// journalisant** plutôt que de retomber silencieusement sur la simulation : un
/// utilisateur qui croit son trafic chiffré alors qu'il ne l'est pas serait bien
/// pire qu'une erreur visible.
pub fn default_backend() -> anyhow::Result<Arc<dyn VpnBackend>> {
    #[cfg(feature = "wireguard")]
    {
        let backend = wireguard::WireGuardBackend::new()
            .map_err(|e| anyhow::anyhow!("backend WireGuard réel indisponible : {e}"))?;
        Ok(Arc::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    Ok(Arc::new(dryrun::DryRunBackend::default()))
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

    /// L'adaptateur est-il monté ? Permet à l'IHM de distinguer « tunnel en
    /// échec mais protégé » (adaptateur debout, WireGuard jette) de « exposé ».
    pub fn adapter_is_up(&self) -> bool {
        self.backend.adapter_is_up()
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
    ///
    /// **En cas d'échec, `down()` n'est délibérément PAS appelé** : l'adaptateur
    /// reste monté et WireGuard continue de jeter les paquets. Voir l'invariante
    /// en tête de module — supprimer cette propriété rouvrirait la fuite en clair.
    pub async fn connect(&self, profile: ClientProfile, user_sink: EventSink) {
        self.abort_task().await;
        let sink = self.wrap_sink(user_sink);
        let backend = Arc::clone(&self.backend);
        let handle = tokio::spawn(async move {
            if let Err(e) = backend.up(&profile, &sink).await {
                sink(ClientEvent::state(TunnelState::Failed));
                sink(ClientEvent::Error {
                    message: format!("échec de connexion: {e}"),
                });
                // Volontairement aucun `backend.down(...)` ici.
            }
        });
        *self.task.lock().await = Some(handle);
    }

    /// Démonte le tunnel — **seul chemin autorisé à retirer l'adaptateur**.
    pub async fn disconnect(&self, user_sink: EventSink) {
        self.abort_task().await;
        let sink = self.wrap_sink(user_sink);
        if let Err(e) = self.backend.down(&sink).await {
            sink(ClientEvent::Error {
                message: format!("échec de déconnexion: {e}"),
            });
        }
        // Garantit le retour à Down même si le backend n'a rien émis.
        if self.state() != TunnelState::Down {
            sink(ClientEvent::state(TunnelState::Down));
        }
    }

    /// Réévalue l'état à partir de l'âge du dernier handshake (WireGuard est
    /// sans connexion : `Up` s'infère, il ne se reçoit pas).
    ///
    /// Ne touche **jamais** à l'adaptateur : cette inférence pilote l'IHM et la
    /// télémétrie, pas la protection anti-fuite (ADR-001 §3).
    pub async fn poll_handshake(&self, user_sink: EventSink) {
        let fresh = matches!(
            self.backend.last_handshake_age().await,
            Some(age) if age < HANDSHAKE_STALE_AFTER
        );
        let current = self.state();
        let sink = self.wrap_sink(user_sink);

        match (current, fresh) {
            (TunnelState::Connecting, true) => {
                sink(ClientEvent::state(TunnelState::Up));
            }
            (TunnelState::Up, false) => {
                sink(ClientEvent::log(
                    "warn",
                    "handshake WireGuard périmé — tunnel non opérationnel \
                     (adaptateur maintenu, aucun trafic en clair)"
                        .to_string(),
                ));
                sink(ClientEvent::state(TunnelState::Connecting));
            }
            _ => {}
        }
    }

    async fn abort_task(&self) {
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::dryrun::DryRunBackend;

    fn sink() -> EventSink {
        Arc::new(|_| {})
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

    /// L'invariante de sécurité d'Orion (ADR-001 §3 bis). Si ce test tombe, la
    /// fuite en clair devient exploitable par simple blocage de l'UDP 51820.
    #[tokio::test]
    async fn adaptateur_reste_monte_apres_echec() {
        let backend = Arc::new(DryRunBackend::failing());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        // Laisse la tâche de connexion échouer.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            ctrl.state(),
            TunnelState::Failed,
            "l'échec doit être visible"
        );
        assert!(
            ctrl.adapter_is_up(),
            "INVARIANTE VIOLÉE : l'adaptateur a été démonté sur échec — \
             la route par défaut retombe sur l'interface physique et le trafic \
             sort en clair (ADR-001 §3 bis)"
        );
    }

    /// Seule la déconnexion explicite a le droit de retirer l'adaptateur.
    #[tokio::test]
    async fn seule_la_deconnexion_explicite_demonte() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ctrl.adapter_is_up());

        ctrl.disconnect(sink()).await;
        assert!(
            !ctrl.adapter_is_up(),
            "disconnect doit démonter l'adaptateur"
        );
        assert_eq!(ctrl.state(), TunnelState::Down);
    }

    #[tokio::test]
    async fn polling_infere_up_puis_retombe_si_perime() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Handshake frais → Up.
        backend.set_handshake_age(Some(Duration::from_secs(10)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Up);

        // Handshake périmé → retour Connecting, sans toucher à l'adaptateur.
        backend.set_handshake_age(Some(Duration::from_secs(200)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Connecting);
        assert!(ctrl.adapter_is_up(), "le polling ne doit jamais démonter");
    }

    #[test]
    fn profil_incomplet_rejete_avant_le_reseau() {
        let mut p = profile();
        p.private_key = String::new();
        assert!(p.validate().is_err());

        let mut p = profile();
        p.endpoint = String::new();
        assert!(p.validate().is_err());

        assert!(profile().validate().is_ok());
    }
}
