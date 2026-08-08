//! WireGuard backend abstraction and connection controller.
//!
//! # The adapter lifecycle invariant — read before modifying
//!
//! Orion is deliberately **fail-open** (CWE-636): no firewall, no WFP
//! (ADR-001 §3 bis). Its only protection against leaking in clear is a
//! lifecycle discipline:
//!
//! > The adapter (Wintun) carries `AllowedIPs = 0.0.0.0/0`. It is mounted on
//! > connection and **is NEVER unmounted on failure** — neither in `Connecting`,
//! > nor in `Failed`, nor after N attempts. It is removed only on **explicit
//! > disconnection** by the user or application shutdown.
//!
//! As long as the adapter holds, packets go out toward WireGuard, which
//! **drops** them if the session is dead: an attacker who blocks UDP 51820
//! only gets a denial of service. If it falls, the default route falls back to
//! the physical interface and traffic exits **in clear**.
//!
//! This is why the trait separates [`VpnBackend::up`] from
//! [`VpnBackend::down`]: `down` is only called from
//! [`VpnController::disconnect`], never on an error path. The test
//! `adapter_stays_mounted_after_failure` locks in this property.
//!
//! Only [`dryrun::DryRunBackend`] is compiled by default (testable on WSL2). The
//! real WireGuard backend (BoringTun + Wintun via `defguard_wireguard_rs`) is
//! target-only, just like the `netlink` feature on the heliosd side.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use aether::TunnelState;
use anyhow::Context as _;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::ClientProfile;
use crate::events::{ClientEvent, PskKind};

pub mod dryrun;
#[cfg(feature = "wireguard")]
pub mod wireguard;

/// Beyond this age, the last handshake is considered stale and the state
/// falls back from `Up` to `Connecting`.
///
/// 150 s leaves margin under `REJECT_AFTER_TIME` (180 s): at 179 s we would
/// flap at the slightest jitter (ADR-001 §3).
pub const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// Maximum wait time for the first handshake before attempting
/// post-quantum provisioning.
///
/// The provisioning channel lives *inside* the tunnel: no point calling it
/// before the classic tunnel carries traffic. Beyond that, we give up for
/// this session — without breaking anything, the classic tunnel stays up.
const PROVISION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Handshake polling period during the wait above.
const PROVISION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Handshake polling period while a negotiation waits to be confirmed.
///
/// Four times a second rather than once: here the poll is on the critical
/// path of the connection — the confirmation cannot be sent before a fresh
/// handshake is seen, so every tick spent waiting is a tick the user spends
/// looking at «connexion…». The read is a local query on the interface, and
/// the wait it shortens lasts a second or two.
const NEGOTIATION_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Event sink: the backend pushes its state transitions and logs here.
/// The Tauri shell provides an implementation that relays to the frontend.
pub type EventSink = Arc<dyn Fn(ClientEvent) + Send + Sync>;

/// A WireGuard stack capable of mounting/unmounting a tunnel to a gateway.
#[async_trait]
pub trait VpnBackend: Send + Sync {
    /// Mounts the adapter (`AllowedIPs = 0.0.0.0/0`) and configures the peer.
    ///
    /// **Contract**: on failure, the implementation must **not** unmount
    /// the adapter if it succeeded in creating it — letting WireGuard drop
    /// packets is better than giving back the physical route to clear traffic.
    /// Must be idempotent: calling `up` again on an already-mounted adapter
    /// reconfigures the peer without recreating it.
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Unmounts the adapter. **Called only on explicit disconnection.**
    async fn down(&self, sink: &EventSink) -> anyhow::Result<()>;

    /// Age of the last successful handshake, or `None` if none.
    /// Source of state inference (WireGuard is connectionless).
    async fn last_handshake_age(&self) -> Option<Duration>;

    /// Is the adapter currently mounted? Used to check the invariant.
    fn adapter_is_up(&self) -> bool;

    /// Human-readable backend identifier (diagnostics / UI).
    fn kind(&self) -> &'static str;
}

/// Selects the backend according to compiled features. Without a real backend
/// compiled in, falls back to dry-run simulation (WSL2/dev case).
///
/// With the `wireguard` feature, attempts the real backend; if it can't even
/// initialize (data plane absent, insufficient privileges), it **fails while
/// logging** rather than silently falling back to simulation: a user who
/// believes their traffic is encrypted when it isn't would be far worse than
/// a visible error.
pub fn default_backend() -> anyhow::Result<Arc<dyn VpnBackend>> {
    #[cfg(feature = "wireguard")]
    {
        let backend = wireguard::WireGuardBackend::new()
            .map_err(|e| anyhow::anyhow!("real WireGuard backend unavailable: {e}"))?;
        Ok(Arc::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    Ok(Arc::new(dryrun::DryRunBackend::default()))
}

/// Waits for a handshake recent enough to prove the classic tunnel carries
/// traffic.
///
/// Returns `false` if the timeout expires: the caller must then give up on
/// provisioning without breaking anything.
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

/// Post-quantum upgrade: obtains the PSK from the gateway and installs it.
///
/// # Timing (ADR-001)
///
/// Only runs **after** the classic tunnel is mounted, since the provisioning
/// channel lives inside that tunnel. Once the PSK is derived on both sides,
/// it is set on the peer via an `up()` call — documented as idempotent: it
/// reconfigures the peer without recreating the adapter, therefore **never
/// unmounting it**. The anti-leak invariant at the top of the module remains
/// intact.
///
/// # Why failure is never fatal
///
/// A failed provisioning leaves the classic tunnel operational: we lose
/// post-quantum protection, not the connection. Propagating the error would
/// flip the state to `Failed` for a tunnel that works — far worse than
/// logging.
///
/// # Installation order
///
/// The gateway sets the PSK **before** responding (it refuses the request
/// otherwise). By the time this code runs, the PSK is therefore already in
/// place on the gateway side, and the window where only one end carries it
/// closes within milliseconds — well before the next handshake (≤ 2 min), the
/// only moment a unilateral PSK would be noticeable.
async fn upgrade_to_post_quantum(
    backend: &Arc<dyn VpnBackend>,
    profile: &ClientProfile,
    sink: &EventSink,
) {
    // Already protected: a manually declared static PSK remains sovereign.
    // It's a PSK, not a PQC PSK: it protects, but it doesn't rotate and isn't
    // derived from any exchange. The UI must be able to name it differently.
    if profile.preshared_key.is_some() {
        sink(ClientEvent::protection(PskKind::Static));
        sink(ClientEvent::log(
            "info",
            "PSK statique au profil : la négociation ML-KEM est désactivée. \
             Le tunnel est protégé par un secret partagé hors bande, non renouvelé."
                .to_string(),
        ));
        return;
    }

    let Some(url) = profile.heliosd_url.clone() else {
        sink(ClientEvent::protection(PskKind::None));
        sink(ClientEvent::log(
            "info",
            "Pas d'URL Helios interne au profil : le tunnel reste classique, \
             Curve25519 seul, sans PSK ML-KEM"
                .to_string(),
        ));
        return;
    };

    if !wait_for_handshake(backend).await {
        sink(ClientEvent::protection(PskKind::None));
        sink(ClientEvent::log(
            "warn",
            "Aucun handshake WireGuard dans le délai imparti : PSK ML-KEM reporté à la \
             prochaine connexion — le tunnel reste classique"
                .to_string(),
        ));
        return;
    }

    let outcome = match crate::provisioning::provision(profile, &url).await {
        Ok(outcome) => outcome,
        Err(e) => {
            sink(ClientEvent::protection(PskKind::None));
            sink(ClientEvent::log(
                "warn",
                format!("Négociation du PSK ML-KEM impossible : {e} — le tunnel reste classique"),
            ));
            return;
        }
    };

    // The announced VIP must match the profile's. We don't silently correct
    // it: the adapter's address is already set, and changing it under a live
    // session's feet would do more harm than good.
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
        // Same rule as the pre-WireGuard negotiation: this PSK is the result
        // of an ML-KEM exchange, not a secret typed into the profile.
        preshared_key_is_negotiated: true,
        ..profile.clone()
    };

    match backend.up(&upgraded, sink).await {
        Ok(()) => {
            sink(ClientEvent::protection(PskKind::MlKem));
            sink(ClientEvent::log(
                "info",
                format!(
                    "PSK ML-KEM-1024 installé (valable {} s) — \
                     le prochain handshake WireGuard sera protégé",
                    outcome.lifetime.as_secs()
                ),
            ));
        }
        // The PSK is set on the gateway side but not here: the next handshake
        // will fail. Saying so explicitly is the only way for the user to
        // understand a disconnection that will happen two minutes later. And
        // above all: don't announce anything as protected. The local slot
        // is empty, this tunnel has no PSK.
        Err(e) => {
            sink(ClientEvent::protection(PskKind::None));
            sink(ClientEvent::log(
                "error",
                format!(
                    "PSK ML-KEM négocié mais non installé sur cette machine : {e}. La gateway \
                     l'a déjà installé de son côté — se reconnecter pour resynchroniser \
                     les deux slots."
                ),
            ));
        }
    }
}

/// Connection controller: holds the tunnel's current state and orchestrates
/// the backend. Single source of truth for [`TunnelState`] on the client side.
pub struct VpnController {
    backend: Arc<dyn VpnBackend>,
    state: Arc<RwLock<TunnelState>>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// Receipt for the PSK currently posed, if any.
    ///
    /// Held here rather than in the connection task because it must outlive
    /// it: the task ends once the tunnel is up, while the receipt is needed
    /// at disconnection, arbitrarily later.
    installed: Arc<Mutex<Option<InstalledNegotiation>>>,
    /// Has the liveness link of the current tunnel died on its own?
    ///
    /// The handshake age cannot express this. When the link closes, the
    /// gateway drops the negotiated PSK, but the WireGuard session already
    /// established keeps carrying traffic until its next rekey — so the last
    /// handshake stays fresh for up to two more minutes while the tunnel is
    /// already condemned. Inferring the state from freshness alone left the
    /// UI showing a healthy connection the client knew was over.
    link_lost: Arc<AtomicBool>,
    key_negotiation_identities: Option<Arc<dyn crate::key_negotiation::IdentityProvider>>,
}

/// The PSK currently posed for this tunnel, and which transaction posed it.
///
/// v4 kept a live QUIC link here and treated its closure as the end of the
/// tunnel. v5 keeps a receipt instead: the transaction identifier the gateway
/// recorded as the slot's owner, which is what a signed release must name to
/// be accepted. Nothing about the tunnel depends on a connection any more.
#[derive(Clone)]
struct InstalledNegotiation {
    transaction_id: [u8; 16],
    /// The profile that negotiated it — the release has to be signed with the
    /// same identity and aimed at the same gateway, and the profile in use
    /// may have changed by the time the user disconnects.
    profile: ClientProfile,
}

impl VpnController {
    pub fn new(backend: Arc<dyn VpnBackend>) -> Self {
        Self {
            backend,
            state: Arc::new(RwLock::new(TunnelState::Down)),
            task: Mutex::new(None),
            installed: Arc::new(Mutex::new(None)),
            link_lost: Arc::new(AtomicBool::new(false)),
            key_negotiation_identities: None,
        }
    }

    /// Supplies the protected client-certificate store used before WireGuard.
    pub fn with_key_negotiation_identities(
        mut self,
        identities: Arc<dyn crate::key_negotiation::IdentityProvider>,
    ) -> Self {
        self.key_negotiation_identities = Some(identities);
        self
    }

    /// Can this client actually negotiate a key before WireGuard?
    ///
    /// One condition, now that the negotiation is part of every build: the
    /// shell must have supplied a protected identity store. A profile
    /// carrying the block would otherwise fail at connection time, after the
    /// user has been promised a mode the client cannot honor.
    pub fn key_negotiation_ready(&self) -> bool {
        self.key_negotiation_identities.is_some()
    }

    /// Current tunnel state.
    pub fn state(&self) -> TunnelState {
        *self.state.read().unwrap()
    }

    /// Active backend (diagnostics).
    pub fn backend_kind(&self) -> &'static str {
        self.backend.kind()
    }

    /// Is the adapter mounted? Lets the UI distinguish "tunnel failed but
    /// protected" (adapter up, WireGuard drops) from "exposed".
    pub fn adapter_is_up(&self) -> bool {
        self.backend.adapter_is_up()
    }

    /// Builds a sink that synchronizes internal state **before** relaying
    /// the event to `user_sink`. Guarantees that `state()` always reflects
    /// the last transition seen by the UI.
    fn wrap_sink(&self, user_sink: EventSink) -> EventSink {
        let state = Arc::clone(&self.state);
        Arc::new(move |ev: ClientEvent| {
            if let ClientEvent::StateChanged { state: s } = &ev {
                *state.write().unwrap() = *s;
            }
            user_sink(ev);
        })
    }

    /// Launches the connection as a background task (doesn't wait for full
    /// mount). Cancels any previous connection.
    ///
    /// **On failure, `down()` is deliberately NOT called**: the adapter
    /// stays mounted and WireGuard keeps dropping packets. See the invariant
    /// at the top of the module — removing this property would reopen the
    /// clear-text leak.
    pub async fn connect(&self, profile: ClientProfile, user_sink: EventSink) {
        self.abort_task().await;
        // No link to hang up any more. A previous PSK is not released here:
        // the negotiation about to run replaces it atomically on both ends,
        // and releasing first would open a window in which the gateway holds
        // nothing for a peer that is about to reconnect.
        self.installed.lock().await.take();
        self.link_lost.store(false, Ordering::SeqCst);
        let sink = self.wrap_sink(user_sink);
        // Says a connection has begun, before anything long happens.
        //
        // A negotiated connection reaches its backend only *after* the ML-KEM
        // exchange — several seconds during which nothing was emitted at all.
        // The state therefore stayed on `Down` while a connection was under
        // way, and every consumer reading it concluded there was none: the
        // screen showed «Déconnecté», and the shell's inference loop, whose
        // stop condition is precisely that state, ended on its first tick and
        // never downgraded anything afterwards.
        //
        // Emitting it here rather than in the spawned task is deliberate: the
        // caller must be able to observe the transition as soon as `connect`
        // returns, without racing the task it just started.
        sink(ClientEvent::state(TunnelState::Connecting));
        let backend = Arc::clone(&self.backend);
        let identities = self.key_negotiation_identities.clone();
        let installed = Arc::clone(&self.installed);
        let link_lost = Arc::clone(&self.link_lost);
        let handle = tokio::spawn(async move {
            if profile.key_negotiation.is_some() {
                if let Err(error) = connect_with_key_negotiation(
                    &backend,
                    &profile,
                    &sink,
                    identities.as_deref(),
                    &installed,
                    &link_lost,
                )
                .await
                {
                    sink(ClientEvent::state(TunnelState::Failed));
                    sink(ClientEvent::Error {
                        message: format!("key negotiation failed: {error}"),
                    });
                }
                return;
            }

            if let Err(e) = backend.up(&profile, &sink).await {
                sink(ClientEvent::state(TunnelState::Failed));
                sink(ClientEvent::Error {
                    message: format!("échec de connexion: {e}"),
                });
                // Deliberately no `backend.down(...)` here.
                return;
            }
            // Classic tunnel up: attempt the post-quantum upgrade. This step
            // is long (waiting for a handshake) but stays within the
            // connection task, so it's cleanly cancelled by `abort_task` on
            // reconnection or disconnection.
            upgrade_to_post_quantum(&backend, &profile, &sink).await;
        });
        *self.task.lock().await = Some(handle);
    }

    /// Sends the signed release for a PSK this controller had installed.
    ///
    /// Goes out on the internal API **through the tunnel that is still up**,
    /// which is why this runs before `down()` and not after. Bounded to two
    /// seconds, and failures are reported and swallowed: the gateway's own
    /// reclamation — five minutes of handshake silence — is the backstop, and
    /// it exists precisely because this message cannot be guaranteed.
    async fn release_installed_psk(&self, installed: InstalledNegotiation, sink: &EventSink) {
        let Some(identities) = self.key_negotiation_identities.clone() else {
            return;
        };
        if installed.profile.key_negotiation.is_none() {
            return;
        }
        match crate::key_negotiation::release_for_profile(
            &installed.profile,
            identities.as_ref(),
            installed.transaction_id,
        )
        .await
        {
            // « Reçue », pas « libérée ». Le `204` dit que la gateway a lu la
            // commande, pas qu'un slot a changé : elle répond la même chose
            // quand la transaction nommée n'est plus propriétaire, et c'est
            // délibéré — distinguer les cas renseignerait le client sur l'état
            // d'un pair. Seul le journal de la gateway sait ce qui a été
            // retiré, et l'IHM ne doit pas affirmer davantage qu'elle ne sait.
            Ok(()) => sink(ClientEvent::log(
                "info",
                "demande de libération du PSK reçue par la gateway".to_string(),
            )),
            Err(error) => sink(ClientEvent::log(
                "warn",
                format!(
                    "libération du PSK demandée sans confirmation ({error:#}) — la gateway le \
                     retirera d'elle-même quand les handshakes cesseront"
                ),
            )),
        }
    }

    /// Unmounts the tunnel — **the only path allowed to remove the adapter**.
    pub async fn disconnect(&self, user_sink: EventSink) {
        self.abort_task().await;
        let installed = self.installed.lock().await.take();
        self.link_lost.store(false, Ordering::SeqCst);
        let sink = self.wrap_sink(user_sink);
        // Say it explicitly, before unmounting. This is the message that
        // replaces v4's closing link, and it is best-effort by construction:
        // a host being powered off sends nothing, and the gateway then falls
        // back on reclaiming the slot once handshakes go quiet. A failure
        // here must never stop a disconnection — refusing to disconnect
        // because a courtesy message did not land would be worse than the
        // courtesy.
        if let Some(installed) = installed {
            self.release_installed_psk(installed, &sink).await;
        }
        if let Err(e) = self.backend.down(&sink).await {
            sink(ClientEvent::Error {
                message: format!("échec de déconnexion: {e}"),
            });
        }
        // Guarantees a return to Down even if the backend emitted nothing.
        if self.state() != TunnelState::Down {
            sink(ClientEvent::state(TunnelState::Down));
        }
    }

    /// Re-evaluates state from the age of the last handshake (WireGuard is
    /// connectionless: `Up` is inferred, not received).
    ///
    /// **Never** touches the adapter: this inference drives the UI and
    /// telemetry, not the anti-leak protection (ADR-001 §3).
    ///
    /// # Why freshness is not the only input
    ///
    /// A closed session link is invisible to the handshake age: the gateway has
    /// already released the negotiated PSK, but the WireGuard session in place
    /// keeps its last handshake recent until the rekey that will fail, up to
    /// two minutes later. Freshness alone therefore kept answering `Up` for a
    /// tunnel whose end was already decided — the screen said connected while
    /// the log said the session was over. A closed link outranks freshness, and
    /// it also has to: without it, this poll would hoist the tunnel back to
    /// `Up` three seconds after the closure was announced.
    ///
    /// # Two outcomes, because the two situations differ
    ///
    /// A stale handshake is recoverable: WireGuard renegotiates on its own once
    /// the endpoint answers again, so the state falls back to `Connecting` and
    /// this poll keeps watching. A closed session link is not: the gateway
    /// released the PSK and only a new negotiation installs another one, so the
    /// state goes to `Down` — there is no tunnel left, and saying anything else
    /// would promise a recovery that cannot happen. Neither outcome unmounts the
    /// adapter; that stays the privilege of an explicit disconnection.
    pub async fn poll_handshake(&self, user_sink: EventSink) {
        let link_lost = self.link_lost.load(Ordering::SeqCst);
        let fresh = !link_lost
            && matches!(
                self.backend.last_handshake_age().await,
                Some(age) if age < HANDSHAKE_STALE_AFTER
            );
        let current = self.state();
        let sink = self.wrap_sink(user_sink);

        match (current, fresh) {
            (TunnelState::Connecting, true) => {
                sink(ClientEvent::state(TunnelState::Up));
            }
            // The closure has just been announced by the link watcher, with the
            // detail this transition cannot carry. Repeating it would only push
            // that explanation further up the log.
            (TunnelState::Up, false) if link_lost => {
                sink(ClientEvent::state(TunnelState::Down));
            }
            (TunnelState::Up, false) => {
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "aucun handshake WireGuard depuis {} s : le tunnel ne transporte plus \
                         de trafic. L'adaptateur reste monté et bloque les paquets.",
                        HANDSHAKE_STALE_AFTER.as_secs()
                    ),
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

/// Negotiations attempted before giving up.
///
/// Three, because the failure this exists for is a **lost message**, and a
/// lost message is not repeated by a fourth try if the first two retries did
/// not carry it.
const KEY_NEGOTIATION_ATTEMPTS: u32 = 3;

/// Pause between two negotiations.
///
/// Long enough for a transient loss to clear, short enough that the user does
/// not read the wait as a hang.
const KEY_NEGOTIATION_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Negotiates, mounts, and recovers from a desynchronised slot.
///
/// # The failure this guards against
///
/// The transaction is only committed once Helios receives the signed
/// confirmation. If that message — or the commit answering it — is lost, the
/// two ends disagree in the worst possible way: Helios restores the previous
/// slot while Orion keeps the PSK it just installed. Every WireGuard handshake
/// then fails, and nothing in either log says why, because **both sides did
/// exactly what they were supposed to do**.
///
/// Retrying resolves it, because a fresh negotiation installs a new PSK on
/// both ends at once. Without this loop the tunnel stayed dead until the user
/// happened to disconnect and reconnect by hand.
///
/// Preparation failures are **not** retried: nothing has been installed yet,
/// so there is nothing to resynchronise, and repeating a missing identity
/// three times would only delay an error the user needs now.
///
/// If every attempt fails, the adapter deliberately stays mounted with its
/// desynchronised PSK: WireGuard drops the packets, which is the anti-leak
/// invariant of this module. A dead tunnel is the correct outcome — a leaking
/// one would not be.
async fn connect_with_key_negotiation(
    backend: &Arc<dyn VpnBackend>,
    profile: &ClientProfile,
    sink: &EventSink,
    identities: Option<&dyn crate::key_negotiation::IdentityProvider>,
    installed: &Mutex<Option<InstalledNegotiation>>,
    link_lost: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let identities = identities
        .context("the Orion shell did not provide a protected key-negotiation identity store")?;

    let endpoint = profile
        .key_negotiation
        .as_ref()
        .map(|settings| settings.endpoint.clone())
        .unwrap_or_default();

    let mut last_error = None;
    for attempt in 1..=KEY_NEGOTIATION_ATTEMPTS {
        sink(ClientEvent::log(
            "info",
            format!("négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : ouverture vers {endpoint}"),
        ));
        // A failed preparation installed nothing — but it is retried all the
        // same. It used to abort the loop outright, so a transient failure on
        // the second attempt discarded the third: the log showed one warning
        // then a final error, and the retry the user was promised never
        // happened.
        let negotiated =
            match crate::key_negotiation::prepare_for_profile(profile, identities).await {
                Ok(negotiated) => negotiated,
                Err(error) => {
                    // Also to `tracing`, and not only to the UI: the event sink
                    // feeds a window the user has usually already closed, while
                    // the file is what gets pasted into a bug report. Without
                    // this line `orion.log` showed three dial attempts two
                    // seconds apart and not one word about why any of them
                    // failed — the retry looked like the whole story.
                    tracing::warn!(
                        attempt,
                        attempts = KEY_NEGOTIATION_ATTEMPTS,
                        %endpoint,
                        error = format!("{error:#}"),
                        "key negotiation: attempt failed, nothing installed on the data plane"
                    );
                    sink(ClientEvent::log(
                        "warn",
                        format!(
                            "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : échec — \
                         {error:#}. Aucun PSK installé sur le plan de données."
                        ),
                    ));
                    last_error = Some(error);
                    if attempt < KEY_NEGOTIATION_ATTEMPTS {
                        tokio::time::sleep(KEY_NEGOTIATION_RETRY_DELAY).await;
                    }
                    continue;
                }
            };
        let mode = negotiated.mode;
        sink(ClientEvent::log(
            "info",
            format!(
                "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : PSK négocié ({mode:?}) — \
                 installation puis attente d'un handshake WireGuard réussi avec ce PSK \
                 ({} s au plus)",
                negotiated.confirmation_timeout.as_secs()
            ),
        ));
        let confirmation_timeout = negotiated.confirmation_timeout;
        let prepared_at = tokio::time::Instant::now();
        let negotiated_profile = ClientProfile {
            preshared_key: negotiated
                .psk
                .as_ref()
                .map(|secret| secret.expose().to_string()),
            // Says where that PSK comes from. Without it, the copy
            // contradicted its own settings — a PSK plus a non-static mode —
            // and the `validate()` inside every `up()` refused the tunnel the
            // negotiation had just succeeded in preparing.
            preshared_key_is_negotiated: negotiated.psk.is_some(),
            ..profile.clone()
        };

        match commit_negotiated_slot(
            backend,
            &negotiated_profile,
            sink,
            negotiated,
            prepared_at,
            confirmation_timeout,
        )
        .await
        {
            Ok(transaction_id) => {
                // The receipt the gateway will require to accept a release.
                // It replaces any previous one: the slot has a single owner,
                // and a renegotiation is precisely a change of owner.
                //
                // Only `ml_kem` produces one. A `static_psk` negotiation
                // proves possession of a value both peers were configured
                // with; it leaves the gateway's slot in `configured_static`,
                // owned by nobody. Sending a release for it would ask the
                // gateway to delete an operator's configuration — which it
                // refuses — so recording a receipt here would only schedule a
                // round trip that announces the disconnection and changes
                // nothing (spec §12.2).
                *installed.lock().await = (mode == aether::key_negotiation::ProtectionMode::MlKem)
                    .then(|| InstalledNegotiation {
                        transaction_id,
                        profile: profile.clone(),
                    });
                link_lost.store(false, Ordering::SeqCst);
                let protection = match mode {
                    aether::key_negotiation::ProtectionMode::Classic => PskKind::None,
                    aether::key_negotiation::ProtectionMode::StaticPsk => PskKind::Static,
                    aether::key_negotiation::ProtectionMode::MlKem => PskKind::MlKem,
                };
                sink(ClientEvent::protection(protection));
                sink(ClientEvent::log(
                    "info",
                    format!(
                        "négociation confirmée ({mode:?}) — un handshake WireGuard a réussi \
                         avec le PSK négocié, tunnel établi"
                    ),
                ));
                // The commit's precondition was a handshake that succeeded
                // with this PSK, a second ago: the tunnel is up, and saying
                // so now spares the
                // user the ten seconds the state poller would have taken to
                // reach the same conclusion.
                sink(ClientEvent::state(TunnelState::Up));
                return Ok(());
            }
            Err(error) => {
                // `{error:#}` and not `{error}`: anyhow only prints the outermost
                // context by default, so the message read «confirming the
                // key-negotiation transaction» and dropped the cause — the one
                // thing worth reading.
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : non confirmée — \
                         {error:#}. La gateway a restauré son slot précédent."
                    ),
                ));
                last_error = Some(error);
                if attempt < KEY_NEGOTIATION_ATTEMPTS {
                    tokio::time::sleep(KEY_NEGOTIATION_RETRY_DELAY).await;
                }
            }
        }
    }

    let error = last_error
        .unwrap_or_else(|| anyhow::anyhow!("key negotiation failed without a reported cause"));
    // What the user is left with, said plainly: the client holds a PSK the
    // gateway does not. WireGuard will drop everything — which is the
    // anti-leak invariant working as intended, not a bug to hunt.
    sink(ClientEvent::log(
        "error",
        format!(
            "négociation abandonnée après {KEY_NEGOTIATION_ATTEMPTS} tentatives : {error:#}. \
             Le slot PSK reste posé côté client alors que la gateway a restauré le sien : \
             aucun handshake n'aboutira tant qu'une négociation n'a pas abouti. Se déconnecter \
             puis se reconnecter en repart proprement."
        ),
    ));
    Err(error)
}

/// Installs the negotiated slot and commits it, or reports why it could not.
///
/// Split out so the caller can tell a failure that left the slot
/// desynchronised — everything below — from one that touched nothing.
async fn commit_negotiated_slot(
    backend: &Arc<dyn VpnBackend>,
    negotiated_profile: &ClientProfile,
    sink: &EventSink,
    negotiated: crate::key_negotiation::NegotiatedKey,
    prepared_at: tokio::time::Instant,
    confirmation_timeout: Duration,
) -> anyhow::Result<[u8; 16]> {
    backend
        .up(negotiated_profile, sink)
        .await
        .context("installing the negotiated PSK on the data plane")?;
    if !wait_for_new_handshake(backend, prepared_at, confirmation_timeout).await {
        anyhow::bail!(
            "no WireGuard handshake succeeded with the negotiated PSK within {} s: the gateway \
             either did not receive the client's handshakes, or answered with a PSK that does \
             not match — check UDP {} reaches the gateway",
            confirmation_timeout.as_secs(),
            negotiated_profile
                .endpoint
                .rsplit_once(':')
                .map(|(_, port)| port)
                .unwrap_or("51820")
        );
    }
    sink(ClientEvent::log(
        "info",
        format!(
            "handshake WireGuard obtenu en {} s — envoi de la confirmation",
            prepared_at.elapsed().as_secs()
        ),
    ));
    let transaction_id = negotiated.transaction_id();
    negotiated.confirm().await?;
    Ok(transaction_id)
}

async fn wait_for_new_handshake(
    backend: &Arc<dyn VpnBackend>,
    prepared_at: tokio::time::Instant,
    confirmation_timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + confirmation_timeout;
    while tokio::time::Instant::now() < deadline {
        if matches!(
            backend.last_handshake_age().await,
            Some(age) if age <= prepared_at.elapsed()
        ) {
            return true;
        }
        tokio::time::sleep(NEGOTIATION_POLL_INTERVAL).await;
    }
    false
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

    /// A connection announces itself before it does anything long.
    ///
    /// The bug this guards against was silent on this side and fatal on the
    /// other: a negotiated connection reaches its backend only after the ML-KEM
    /// exchange, so the state stayed `Down` for seconds while the tunnel was
    /// being built. The shell's inference loop stops on that state — it ended
    /// on its first tick, and nothing downgraded the tunnel for the rest of the
    /// session. A lost session link then left the screen on «Connecté».
    #[tokio::test]
    async fn connecting_is_announced_before_the_backend_is_reached() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        let seen: Arc<std::sync::Mutex<Vec<TunnelState>>> = Arc::default();
        let recorder = Arc::clone(&seen);

        ctrl.connect(
            profile(),
            Arc::new(move |ev: ClientEvent| {
                if let ClientEvent::StateChanged { state } = ev {
                    recorder.lock().unwrap().push(state);
                }
            }),
        )
        .await;

        assert_eq!(
            seen.lock().unwrap().first().copied(),
            Some(TunnelState::Connecting),
            "the transition must be visible as soon as `connect` returns, without \
             waiting for the task it started"
        );
        assert_ne!(
            ctrl.state(),
            TunnelState::Down,
            "a connection under way may not read as no connection at all"
        );
    }

    /// Orion's security invariant (ADR-001 §3 bis). If this test breaks, the
    /// clear-text leak becomes exploitable by simply blocking UDP 51820.
    #[tokio::test]
    async fn adapter_stays_mounted_after_failure() {
        let backend = Arc::new(DryRunBackend::failing());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        // Let the connection task fail.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            ctrl.state(),
            TunnelState::Failed,
            "the failure must be visible"
        );
        assert!(
            ctrl.adapter_is_up(),
            "INVARIANT VIOLATED: the adapter was unmounted on failure — \
             the default route falls back to the physical interface and traffic \
             exits in clear (ADR-001 §3 bis)"
        );
    }

    /// Only explicit disconnection may remove the adapter.
    #[tokio::test]
    async fn only_explicit_disconnection_unmounts() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ctrl.adapter_is_up());

        ctrl.disconnect(sink()).await;
        assert!(!ctrl.adapter_is_up(), "disconnect must unmount the adapter");
        assert_eq!(ctrl.state(), TunnelState::Down);
    }

    #[tokio::test]
    async fn polling_infers_up_then_falls_back_if_stale() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fresh handshake → Up.
        backend.set_handshake_age(Some(Duration::from_secs(10)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Up);

        // Stale handshake → back to Connecting, without touching the adapter.
        backend.set_handshake_age(Some(Duration::from_secs(200)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Connecting);
        assert!(ctrl.adapter_is_up(), "polling must never unmount");
    }

    /// The bug this guards against: the session link closed, the log said so,
    /// and the screen kept showing a healthy connection.
    ///
    /// Nothing in the handshake age can express it. The gateway has released
    /// the negotiated PSK, but the WireGuard session already established keeps
    /// its last handshake recent until the rekey that will fail — so freshness
    /// answered `Up` for a tunnel whose end was already decided.
    ///
    /// `Down` rather than `Connecting`, and the difference is not cosmetic:
    /// nothing is being connected. Only a new negotiation installs a PSK the
    /// gateway also holds, so the screen states a tunnel that is over and offers
    /// to build another one.
    #[tokio::test]
    async fn a_lost_session_link_ends_the_up_state_despite_a_fresh_handshake() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        backend.set_handshake_age(Some(Duration::from_secs(10)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Up);

        // The gateway hung up. The handshake stays recent — that is the whole
        // difficulty.
        ctrl.link_lost.store(true, Ordering::SeqCst);
        ctrl.poll_handshake(sink()).await;
        assert_eq!(
            ctrl.state(),
            TunnelState::Down,
            "a closed link must leave the `Up` state: the session is over and the \
             screen may not keep claiming otherwise"
        );

        // And it must stay there. Freshness alone would hoist the tunnel back
        // up on the very next poll, three seconds later — the screen would
        // flicker between the two answers instead of settling on the true one.
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Down);
        assert!(
            ctrl.adapter_is_up(),
            "the inference must never unmount: only an explicit disconnection may"
        );
    }

    /// The verdict belongs to one session. A reconnection must be able to
    /// reach `Up` again, otherwise the first lost link would pin the client
    /// to `Connecting` for as long as the process lives.
    #[tokio::test]
    async fn reconnecting_clears_the_lost_link_verdict() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        ctrl.link_lost.store(true, Ordering::SeqCst);

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        backend.set_handshake_age(Some(Duration::from_secs(10)));
        ctrl.poll_handshake(sink()).await;
        assert_eq!(ctrl.state(), TunnelState::Up);
    }

    /// A profile already carrying a static PSK must not be renegotiated:
    /// the upgrade returns immediately, without touching the network.
    #[tokio::test]
    async fn static_psk_already_present_short_circuits_the_upgrade() {
        let backend: Arc<dyn VpnBackend> = Arc::new(DryRunBackend::default());
        let mut p = profile();
        p.preshared_key = Some("manually-declared-psk".into());
        // `heliosd_url` set: only the PSK's presence should stop it.
        p.heliosd_url = Some("http://127.0.0.1:1".into());

        // Without the short circuit, the handshake wait would take 30 s.
        tokio::time::timeout(
            Duration::from_millis(200),
            upgrade_to_post_quantum(&backend, &p, &sink()),
        )
        .await
        .expect("an already-present PSK must return immediately without waiting");
    }

    /// Without an internal URL, the upgrade is impossible: it must say so and
    /// give up, not wait for a handshake that would serve no purpose.
    #[tokio::test]
    async fn absence_of_internal_url_gives_up_while_reporting_it() {
        let backend: Arc<dyn VpnBackend> = Arc::new(DryRunBackend::default());
        let p = profile(); // `heliosd_url` defaults to None.

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
        .expect("without a URL, the upgrade must give up immediately");

        let journal = journal.lock().unwrap();
        assert!(
            journal.iter().any(|m| m.contains("tunnel reste classique")),
            "the user must be warned they don't have post-quantum protection, \
             otherwise they'd believe it's already in place: {journal:?}"
        );
    }

    /// Captures the PSK kind announced by an upgrade.
    async fn announced_protection(profile: &ClientProfile) -> Vec<PskKind> {
        let backend: Arc<dyn VpnBackend> = Arc::new(DryRunBackend::default());
        let vu = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Arc::clone(&vu);
        let sink: EventSink = Arc::new(move |ev| {
            if let ClientEvent::Protection { psk } = ev {
                capture.lock().unwrap().push(psk);
            }
        });

        tokio::time::timeout(
            Duration::from_millis(200),
            upgrade_to_post_quantum(&backend, profile, &sink),
        )
        .await
        .expect("both tested cases must return without waiting");

        let vu = vu.lock().unwrap();
        vu.clone()
    }

    /// A static PSK and a PQC PSK occupy the same WireGuard slot, but don't
    /// protect the same way: one never rotates. The UI can't tell them apart
    /// on its own — if the upgrade stayed silent, it would display
    /// "post-quantum" for a manually copied secret.
    #[tokio::test]
    async fn a_static_psk_announces_itself_as_static_not_pqc() {
        let mut p = profile();
        p.preshared_key = Some("manually-declared-psk".into());
        p.heliosd_url = Some("http://127.0.0.1:1".into());

        assert_eq!(announced_protection(&p).await, vec![PskKind::Static]);
    }

    /// Without an internal URL, no PSK will be set: it must be said, or the
    /// UI would stay stuck on its waiting display indefinitely.
    #[tokio::test]
    async fn a_tunnel_without_psk_announces_itself_as_lacking_one() {
        let p = profile(); // neither a static PSK nor `heliosd_url`.

        assert_eq!(announced_protection(&p).await, vec![PskKind::None]);
    }

    /// The anti-leak invariant also holds during the upgrade: whatever the
    /// fate of provisioning, the adapter must never be unmounted.
    #[tokio::test]
    async fn the_upgrade_never_unmounts_the_adapter() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        let mut p = profile();
        // Unreachable URL: provisioning will fail for sure.
        p.heliosd_url = Some("http://127.0.0.1:1".into());

        ctrl.connect(p, sink()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        backend.set_handshake_age(Some(Duration::from_secs(1)));
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            ctrl.adapter_is_up(),
            "INVARIANT VIOLATED: a failed provisioning unmounted the adapter — \
             the default route falls back to the physical interface (ADR-001 §3 bis)"
        );
    }

    #[test]
    fn incomplete_profile_rejected_before_the_network() {
        let mut p = profile();
        p.private_key = String::new();
        assert!(p.validate().is_err());

        let mut p = profile();
        p.endpoint = String::new();
        assert!(p.validate().is_err());

        assert!(profile().validate().is_ok());
    }
}
