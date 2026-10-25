//! The tunnel's connection: mounting it, unmounting it, renewing its PSK, and
//! the background work a connection starts once it is up.
//!
//! The shell reaches these through the engine's session. Their bodies are the
//! ones that used to run beside the window; what they report goes out through
//! the session's events.

use std::sync::Arc;

use aether::TunnelState;
use orion_core::{backend::EventSink, ClientConfig, ClientEvent, ClientProfile};
use tokio::sync::Mutex;

use super::certificates::{spawn_automatic_certificate_renewal, spawn_trust_refresh};
use super::EngineService;
use crate::events::EventQueue;

/// Polling interval for the last WireGuard handshake.
///
/// WireGuard is connectionless: the `Up` state is inferred from handshake
/// freshness, it's never notified (ADR-001 §3). Without this loop, the UI
/// would stay stuck on the last known state.
///
/// Three seconds rather than ten: this loop is what turns a tunnel that has
/// stopped answering into a visible state change, and ten seconds of a
/// screen claiming a dead tunnel is alive is ten seconds too many. A
/// negotiated connection no longer waits on it to *reach* `Up` — the
/// negotiation announces it itself, having just observed the handshake — but it
/// is still what makes it leave that state, a lost session link included.
const HANDSHAKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

impl EngineService {
    /// Mounts the tunnel. The engine's `Connect` runs it, and so does the
    /// selection from the notification area, through the same command: the two
    /// must not differ by one step, since a connection started from a hidden
    /// window has no screen to report a discrepancy on.
    pub async fn start_connection(
        &self,
        events: &EventQueue,
        name: Option<String>,
    ) -> Result<(), String> {
        let profile = {
            let cfg = self.config.lock().await;
            match name {
                Some(n) => cfg.find(&n).map(ClientProfile::duplicate),
                None => cfg
                    .selected
                    .as_deref()
                    .and_then(|n| cfg.find(n))
                    .map(ClientProfile::duplicate),
            }
            .ok_or_else(|| "aucun profil sélectionné".to_string())?
        };

        // Validates the WireGuard profile (endpoint + keys) BEFORE any side effect.
        profile.validate().map_err(|e| e.to_string())?;

        // # Signalé, jamais bloqué (arbitrage du 2 août 2026)
        //
        // Un profil repris de `profiles.toml` a eu sa clé en clair sur le disque,
        // et le sceller ne rappelle pas les copies déjà parties en sauvegarde. La
        // décision initiale en faisait un **refus de connexion**, ce qui était une
        // erreur de périmètre : Orion constate l'historique d'un fichier, il ne
        // sait rien de la clé elle-même — elle peut n'avoir jamais quitté la
        // machine, ou être une clé de développement dont personne ne se soucie.
        // Décider à la place de l'utilisateur qu'elle est perdue, et lui interdire
        // son propre tunnel sur cette présomption, dépasse ce que le client a à
        // arbitrer. La rotation reste la bonne pratique ; elle n'est pas à lui
        // imposer.
        //
        // Ce qui reste : la posture le montre, le journal le dit, et l'écran
        // Profils propose la manœuvre en un clic.
        let rotation_required = self.store.rotation_required().unwrap_or_default();
        let presumed_exposed = rotation_required.contains(&profile.name);
        if presumed_exposed {
            tracing::warn!(
                profil = %profile.name,
                "connexion avec une clé reprise de profiles.toml, où elle était en clair : \
                 une rotation reste recommandée"
            );
        }

        // Sink combining relay to the frontend AND telemetry control: telemetry
        // only starts on transition to Up (web behind the tunnel).
        let base = events.sink();
        let telemetry = Arc::clone(&self.telemetry);
        let heliosd_url = profile.heliosd_url.clone();
        let negotiating = profile.negotiates();
        // The trust update of §8.1.1 lives inside the tunnel, so the moment it
        // becomes reachable is the moment it is worth asking. Captured here rather
        // than read later: by the time the tunnel is up, the configuration may
        // already describe a different profile.
        let trust_settings = profile.key_negotiation.clone();
        let trust_url = profile.heliosd_url.clone();
        // Once per connection. `Up` is re-emitted whenever the inference loop sees
        // a fresh handshake after a stall, and each of those is the same tunnel —
        // asking again on every one would poll the gateway for the life of the
        // session.
        let trust_asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let renewal_task = Arc::clone(&self.certificate_renewal_task);
        let renewal_controller = Arc::clone(&self.controller);
        let renewal_sessions = Arc::clone(&self.renewals);
        let negotiated_profile = profile.name.clone();
        let config = Arc::clone(&self.config);
        let store = Arc::clone(&self.store);
        let events = events.clone();
        let sink: EventSink = Arc::new(move |ev: ClientEvent| {
            // Mirror of the gateway rule: a committed negotiation raises this
            // profile's floor for good. Helios does the same on its side and
            // would refuse a weaker mode afterwards — a client that kept
            // offering one would only produce a failed connection the user
            // couldn't explain.
            if negotiating {
                if let ClientEvent::Protection { psk } = &ev {
                    raise_key_negotiation_floor(
                        Arc::clone(&config),
                        Arc::clone(&store),
                        negotiated_profile.clone(),
                        *psk,
                    );
                }
            }
            if let ClientEvent::StateChanged { state } = &ev {
                match state {
                    TunnelState::Up => {
                        if let Some(url) = heliosd_url.clone() {
                            telemetry.start(url, events.sink());
                        }
                        if let (Some(settings), Some(url), false) = (
                            trust_settings.clone(),
                            trust_url.clone(),
                            trust_asked.swap(true, std::sync::atomic::Ordering::SeqCst),
                        ) {
                            let refresh =
                                spawn_trust_refresh(settings.clone(), url.clone(), events.sink());
                            let renewal = spawn_automatic_certificate_renewal(
                                refresh,
                                Arc::clone(&renewal_controller),
                                Arc::clone(&renewal_sessions),
                                negotiated_profile.clone(),
                                settings,
                                url,
                                events.sink(),
                            );
                            if let Some(previous) = renewal_task
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .replace(renewal)
                            {
                                previous.abort();
                            }
                        }
                    }
                    TunnelState::Down | TunnelState::Failed => {
                        telemetry.stop();
                        if let Some(task) = renewal_task
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            task.abort();
                        }
                    }
                    _ => {}
                }
            }
            base(ev);
        });

        // Said in the event log the user is actually looking at, not only in the
        // file. A recommendation nobody reads is not a recommendation.
        if presumed_exposed {
            sink(ClientEvent::log(
                "warn",
                "clé reprise de profiles.toml, où elle était en clair : une rotation reste \
                 recommandée — onglet Profils, « Générer une nouvelle clé »."
                    .to_string(),
            ));
        }

        self.controller.connect(profile, sink.clone()).await;

        // State inference loop: WireGuard notifies nothing, we poll the age of
        // the last handshake. Never touches the adapter (ADR-001 §3 bis).
        //
        // `Down` ends it — but only once the connection has left that state. The
        // first tick of a `tokio` interval fires immediately, and reading `Down`
        // there is what a starting connection looks like, not a finished one: the
        // loop used to end on that very tick and infer nothing for the rest of the
        // session. A lost session link then kept the screen on «Connecté» while the
        // log announced the tunnel was over.
        let controller = Arc::clone(&self.controller);
        let poll = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HANDSHAKE_POLL_INTERVAL);
            let mut started = false;
            loop {
                ticker.tick().await;
                match controller.state() {
                    // Explicit disconnection: nothing left to infer.
                    TunnelState::Down if started => break,
                    TunnelState::Down => continue,
                    _ => started = true,
                }
                controller.poll_handshake(sink.clone()).await;
                controller.poll_renewal(sink.clone()).await;
            }
        });
        let previous = self
            .handshake_poll
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(poll);
        if let Some(previous) = previous {
            previous.abort();
        }

        Ok(())
    }

    /// Unmounts the tunnel. The engine's `Disconnect` runs it, and so does
    /// `teardown` when the session ends, with the event side discarded. One
    /// function for both, for the same reason as [`start_connection`]: two paths
    /// that differ by one step end up differing by more.
    pub async fn stop_connection(&self, sink: EventSink) -> Result<(), String> {
        self.telemetry.stop();
        // The inference stops before the state moves, not after: a poll that read
        // `Up` and lands once the tunnel is down would re-announce `Connecting`
        // behind the disconnection the user just asked for.
        let poll = self
            .handshake_poll
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(poll) = poll {
            poll.abort();
        }
        self.controller
            .disconnect(sink)
            .await
            .map_err(|error| error.to_string())
    }

    /// Renews the ML-KEM PSK now, through the tunnel (design 2026-10-09).
    ///
    /// Returns once the renewal is started: it runs in the background and reports
    /// its outcome on the event stream, like the scheduled one.
    pub async fn renew_psk(&self, events: &EventQueue) -> Result<(), String> {
        self.controller
            .renew_now(events.sink())
            .await
            .map_err(|error| error.to_string())
    }
}

/// Persists a floor raise announced by a committed negotiation.
///
/// Runs in a task because the sink is synchronous while the configuration is
/// behind an async lock. A failed write is logged and nothing else: the
/// session in progress stays valid, and the gateway keeps its own floor —
/// which is the one that actually refuses a downgrade.
///
/// # Why this goes through the vault and not through `ClientConfig::save`
///
/// It used to call `cfg.save()`, which writes `profiles.toml` — the **legacy
/// plaintext file** ADR-006 exists to retire, in the very directory the store
/// occupies. Every negotiated connection that raised a floor therefore rewrote
/// the client's private key and static PSK in the clear on disk, undoing the
/// whole lot; the next start then found the file, migrated it again, and
/// marked the profile as having lived in plaintext. Raising a floor is a
/// security event, and it must be recorded the way every other one is.
fn raise_key_negotiation_floor(
    config: Arc<Mutex<ClientConfig>>,
    store: Arc<orion_core::vault::ProfileStore>,
    name: String,
    observed: orion_core::PskKind,
) {
    use aether::key_negotiation::ProtectionMode;

    let reached = match observed {
        orion_core::PskKind::MlKem => ProtectionMode::MlKem,
        orion_core::PskKind::Static => ProtectionMode::StaticPsk,
        // Classic commits nothing to raise.
        orion_core::PskKind::None => return,
    };
    tokio::spawn(async move {
        let mut cfg = config.lock().await;
        let Some(profile) = cfg.profiles.iter_mut().find(|profile| profile.name == name) else {
            return;
        };
        let Some(settings) = profile.key_negotiation.as_mut() else {
            return;
        };
        if settings.minimum_mode.satisfies(reached) {
            return;
        }
        settings.minimum_mode = reached;
        // Cloned out of the guard so the sealed write does not hold the lock
        // across an I/O the UI is waiting behind.
        let raised = profile.duplicate();
        drop(cfg);
        if let Err(error) = store.save_profile(&raised) {
            tracing::warn!(%error, "unable to persist the raised key-negotiation floor");
        }
    });
}
