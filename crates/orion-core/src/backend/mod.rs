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

/// Délai maximal d'attente du premier handshake avant de tenter le
/// provisioning post-quantique.
///
/// Le canal de provisioning vit *dans* le tunnel : inutile de l'appeler avant
/// que le tunnel classique ne porte du trafic. Au-delà, on renonce pour cette
/// session — sans casser quoi que ce soit, le tunnel classique reste debout.
const PROVISION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Période de sondage du handshake pendant l'attente ci-dessus.
const PROVISION_POLL_INTERVAL: Duration = Duration::from_secs(1);

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

/// Attend qu'un handshake frais prouve que le tunnel classique porte du trafic.
///
/// Renvoie `false` si le délai expire : l'appelant doit alors renoncer au
/// provisioning sans rien casser.
async fn wait_for_handshake(backend: &Arc<dyn VpnBackend>) -> bool {
    let deadline = tokio::time::Instant::now() + PROVISION_HANDSHAKE_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if matches!(
            backend.last_handshake_age().await,
            Some(age) if age < HANDSHAKE_STALE_AFTER
        ) {
            return true;
        }
        tokio::time::sleep(PROVISION_POLL_INTERVAL).await;
    }
    false
}

/// Upgrade post-quantique : obtient le PSK auprès de la gateway et l'installe.
///
/// # Cinématique (ADR-001)
///
/// Ne tourne qu'**après** montage du tunnel classique, puisque le canal de
/// provisioning vit à l'intérieur de ce tunnel. Une fois le PSK dérivé des deux
/// côtés, il est posé sur le pair via un `up()` — documenté idempotent : il
/// reconfigure le pair sans recréer l'adaptateur, donc **sans jamais le
/// démonter**. L'invariante anti-fuite en tête de module reste intacte.
///
/// # Pourquoi l'échec n'est jamais fatal
///
/// Un provisioning raté laisse le tunnel classique opérationnel : on perd la
/// protection post-quantique, pas la connexion. Propager l'erreur ferait
/// basculer l'état en `Failed` pour un tunnel qui fonctionne — bien pire que de
/// journaliser.
///
/// # Ordre d'installation
///
/// La gateway pose le PSK **avant** de répondre (elle refuse la requête sinon).
/// Quand ce code s'exécute, le PSK est donc déjà en place côté gateway, et la
/// fenêtre où un seul des deux bouts le porte se referme en quelques
/// millisecondes — bien avant le handshake suivant (≤ 2 min), le seul moment
/// où un PSK unilatéral se verrait.
async fn upgrade_to_post_quantum(
    backend: &Arc<dyn VpnBackend>,
    profile: &ClientProfile,
    sink: &EventSink,
) {
    // Déjà protégé : un PSK statique déclaré à la main reste souverain.
    if profile.preshared_key.is_some() {
        return;
    }

    let Some(url) = profile.heliosd_url.clone() else {
        sink(ClientEvent::log(
            "info",
            "Pas d'URL Helios interne au profil : le tunnel reste classique \
             (Curve25519 seul, vulnérable au « récolter maintenant, déchiffrer plus tard »)"
                .to_string(),
        ));
        return;
    };

    if !wait_for_handshake(backend).await {
        sink(ClientEvent::log(
            "warn",
            "Aucun handshake dans le délai imparti : upgrade post-quantique \
             reporté à la prochaine connexion"
                .to_string(),
        ));
        return;
    }

    let outcome = match crate::provisioning::provision(profile, &url).await {
        Ok(outcome) => outcome,
        Err(e) => {
            sink(ClientEvent::log(
                "warn",
                format!("Upgrade post-quantique impossible : {e} — le tunnel reste classique"),
            ));
            return;
        }
    };

    // La VIP annoncée doit correspondre à celle du profil. On ne la corrige pas
    // en silence : l'adresse de l'adaptateur est déjà posée, et la changer sous
    // les pieds d'une session vivante ferait plus de dégâts que de bien.
    if let Some(declared) = profile.address.as_deref() {
        if declared != outcome.address {
            sink(ClientEvent::log(
                "warn",
                format!(
                    "La gateway attribue {} alors que le profil déclare {declared} — \
                     corriger le profil puis se reconnecter",
                    outcome.address
                ),
            ));
        }
    }

    let upgraded = ClientProfile {
        preshared_key: Some(outcome.preshared_key.clone()),
        ..profile.clone()
    };

    match backend.up(&upgraded, sink).await {
        Ok(()) => sink(ClientEvent::log(
            "info",
            format!(
                "PSK post-quantique installé (ML-KEM-768, valable {} s) — \
                 le prochain handshake sera protégé",
                outcome.lifetime.as_secs()
            ),
        )),
        // Le PSK est posé côté gateway mais pas ici : le prochain handshake
        // échouera. Le dire explicitement, c'est la seule façon pour
        // l'utilisateur de comprendre une coupure qui arrivera deux minutes
        // plus tard.
        Err(e) => sink(ClientEvent::log(
            "error",
            format!(
                "PSK obtenu mais non installé localement : {e}. La gateway l'a \
                 posé de son côté — se reconnecter pour resynchroniser."
            ),
        )),
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
                return;
            }
            // Tunnel classique debout : on tente l'upgrade post-quantique. Cette
            // étape est longue (attente d'un handshake) mais reste dans la tâche
            // de connexion, donc annulée proprement par `abort_task` sur
            // reconnexion ou déconnexion.
            upgrade_to_post_quantum(&backend, &profile, &sink).await;
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

    /// Un profil déjà porteur d'un PSK statique ne doit pas être renégocié :
    /// l'upgrade rend la main immédiatement, sans toucher au réseau.
    #[tokio::test]
    async fn psk_statique_deja_present_court_circuite_l_upgrade() {
        let backend: Arc<dyn VpnBackend> = Arc::new(DryRunBackend::default());
        let mut p = profile();
        p.preshared_key = Some("psk-declare-a-la-main".into());
        // `heliosd_url` renseignée : seule la présence du PSK doit arrêter.
        p.heliosd_url = Some("http://127.0.0.1:1".into());

        // Sans court-circuit, l'attente de handshake durerait 30 s.
        tokio::time::timeout(
            Duration::from_millis(200),
            upgrade_to_post_quantum(&backend, &p, &sink()),
        )
        .await
        .expect("un PSK déjà présent doit rendre la main sans attendre");
    }

    /// Sans URL interne, l'upgrade est impossible : il doit le dire et renoncer,
    /// pas attendre un handshake qui ne servira à rien.
    #[tokio::test]
    async fn absence_d_url_interne_renonce_en_le_signalant() {
        let backend: Arc<dyn VpnBackend> = Arc::new(DryRunBackend::default());
        let p = profile(); // `heliosd_url` vaut None par défaut.

        let journal = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Arc::clone(&journal);
        let sink: EventSink = Arc::new(move |ev| {
            if let ClientEvent::Log { message, .. } = ev {
                capture.lock().unwrap().push(message);
            }
        });

        tokio::time::timeout(
            Duration::from_millis(200),
            upgrade_to_post_quantum(&backend, &p, &sink),
        )
        .await
        .expect("sans URL, l'upgrade doit renoncer immédiatement");

        let journal = journal.lock().unwrap();
        assert!(
            journal.iter().any(|m| m.contains("tunnel reste classique")),
            "l'utilisateur doit être averti qu'il n'a pas la protection \
             post-quantique, sinon il la croit acquise : {journal:?}"
        );
    }

    /// L'invariante anti-fuite tient aussi pendant l'upgrade : quel que soit le
    /// sort du provisioning, l'adaptateur ne doit jamais être démonté.
    #[tokio::test]
    async fn l_upgrade_ne_demonte_jamais_l_adaptateur() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        let mut p = profile();
        // URL injoignable : le provisioning échouera à coup sûr.
        p.heliosd_url = Some("http://127.0.0.1:1".into());

        ctrl.connect(p, sink()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        backend.set_handshake_age(Some(Duration::from_secs(1)));
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            ctrl.adapter_is_up(),
            "INVARIANTE VIOLÉE : un provisioning raté a démonté l'adaptateur — \
             la route par défaut retombe sur l'interface physique (ADR-001 §3 bis)"
        );
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
