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

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// Name of the profile the current tunnel was mounted for.
    ///
    /// Separate from `installed`, which only exists once a negotiation has
    /// committed: a classic tunnel has no receipt, and the shell still has to
    /// be able to ask "is this the profile that is up?". Set as soon as a
    /// connection starts, so a profile removed while its negotiation is still
    /// running is recognised too.
    mounted_profile: Arc<Mutex<Option<String>>>,
    /// Renegotiations already triggered by a stale handshake, since the last
    /// one that succeeded.
    ///
    /// Bounds the repair of spec §12.5. A gateway that is durably gone must
    /// not produce an aggressive negotiation loop, and the counter is reset by
    /// the only fact that proves the repair worked — a fresh handshake — never
    /// by having attempted one.
    stale_renegotiations: Arc<AtomicU32>,
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
            mounted_profile: Arc::new(Mutex::new(None)),
            stale_renegotiations: Arc::new(AtomicU32::new(0)),
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

    /// The profile this tunnel was mounted for, while it is mounted.
    ///
    /// The shell asks this before removing a profile: uninstalling the one
    /// that is up has to release its slot **through the tunnel that is still
    /// up** (spec §12.2), and afterwards there is no profile left to sign the
    /// release with. Answering `None` means no connection is in progress, not
    /// that the tunnel is down — the two differ during a negotiation.
    pub async fn mounted_profile(&self) -> Option<String> {
        self.mounted_profile.lock().await.clone()
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
        // No link to hang up any more. A receipt for this same Helios profile
        // stays valid until a replacement actually commits. Dropping it merely
        // because a renegotiation started lost the only signed handle able to
        // release the old slot when the new dial failed before preparation.
        // A different profile cannot use that receipt and must not inherit it.
        let mut installed = self.installed.lock().await;
        let keep_previous_receipt = profile.negotiates()
            && installed
                .as_ref()
                .is_some_and(|receipt| receipt.profile.name == profile.name);
        if !keep_previous_receipt {
            installed.take();
        }
        drop(installed);
        self.link_lost.store(false, Ordering::SeqCst);
        *self.mounted_profile.lock().await = Some(profile.name.clone());
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
            // The discriminant, not the presence of the block. A Helios
            // profile that lost its block is refused by `validate()` inside
            // the negotiation path; reading the block here would instead have
            // sent it down the classic path, mounting a tunnel with no
            // pre-WireGuard authentication and reporting nothing wrong.
            if profile.negotiates() {
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
        if !installed.profile.negotiates() {
            return;
        }
        match crate::key_negotiation::release_for_profile(
            &installed.profile,
            identities.as_ref(),
            installed.transaction_id,
        )
        .await
        {
            // "Received", not "released". A 204 only says that the gateway
            // read the command, not that a slot changed: it deliberately sends
            // the same response when the named transaction no longer owns the
            // slot. Only the gateway log knows whether anything was removed,
            // and the UI must not claim more than it knows.
            Ok(()) => sink(ClientEvent::log(
                "info",
                "PSK release request received by the gateway".to_string(),
            )),
            Err(error) => sink(ClientEvent::log(
                "warn",
                format!(
                    "PSK release requested without confirmation ({error:#}) — the gateway will \
                     remove it after handshakes stop"
                ),
            )),
        }
    }

    /// Unmounts the tunnel — **the only path allowed to remove the adapter**.
    pub async fn disconnect(&self, user_sink: EventSink) -> anyhow::Result<()> {
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
        if let Err(error) = self.backend.down(&sink).await {
            // The profile still names a mounted adapter. Keep that ownership
            // visible so a deletion retries the disconnection instead of
            // destroying the only local material able to clean it up.
            sink(ClientEvent::state(TunnelState::Failed));
            sink(ClientEvent::Error {
                message: format!("échec de déconnexion: {error}"),
            });
            return Err(error);
        }
        self.mounted_profile.lock().await.take();
        self.stale_renegotiations.store(0, Ordering::SeqCst);
        // Guarantees a return to Down even if the backend emitted nothing.
        if self.state() != TunnelState::Down {
            sink(ClientEvent::state(TunnelState::Down));
        }
        Ok(())
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
        if fresh {
            // The repair worked — or none was ever needed. Either way the
            // budget of §12.5 is restored by the handshake itself, never by
            // the mere fact of having attempted a renegotiation.
            self.stale_renegotiations.store(0, Ordering::SeqCst);
        }
        let current = self.state();
        let retained_receipt = self.installed.lock().await.is_some();
        let raw_sink = Arc::clone(&user_sink);
        let sink = self.wrap_sink(user_sink);

        match (current, fresh) {
            (TunnelState::Connecting, true) => {
                sink(ClientEvent::state(TunnelState::Up));
            }
            // A same-profile renegotiation may fail before replacing the old
            // slot. If that slot was merely unreachable and its handshake
            // returns, the retained receipt proves which negotiated tunnel is
            // carrying traffic; keeping `Failed` would contradict the data
            // plane and would also strand a releasable gateway slot.
            (TunnelState::Failed, true) if retained_receipt => {
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
                if self.renegotiate_on_stale_handshake(&sink, raw_sink).await {
                    // `connect` has already announced its own transition.
                    return;
                }
                sink(ClientEvent::state(TunnelState::Connecting));
            }
            _ => {}
        }
    }

    /// Repairs a negotiated tunnel whose gateway slot is gone (spec §12.5).
    ///
    /// # The failure this exists for
    ///
    /// A negotiated PSK is never persisted, so a `heliosd` restart empties
    /// every slot — and the 300-second reclamation empties one. The client
    /// keeps a PSK the gateway no longer has, keeps working on the transport
    /// keys already derived, then fails silently at its next rekey up to two
    /// minutes later. Nothing tells it: there is no control link any more, by
    /// design. Without this, the user sees a tunnel displayed as up that
    /// simply stops carrying traffic, two minutes after the cause.
    ///
    /// # Why only a negotiated slot
    ///
    /// A receipt exists only for `ml_kem`. A `static_psk` slot is the
    /// operator's configuration: it is read back from `network.toml` at every
    /// restart, so it is still there and a stale handshake means something
    /// else entirely — renegotiating would repair nothing and cost a round of
    /// ML-DSA-87. A classic tunnel has no slot at all, and WireGuard retries
    /// on its own.
    ///
    /// Returns whether a renegotiation was started, so the caller does not
    /// also announce a transition `connect` has just made.
    async fn renegotiate_on_stale_handshake(&self, sink: &EventSink, raw_sink: EventSink) -> bool {
        let Some(installed) = self.installed.lock().await.clone() else {
            return false;
        };
        let attempt = self.stale_renegotiations.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt > STALE_RENEGOTIATIONS_ALLOWED {
            sink(ClientEvent::log(
                "error",
                format!(
                    "{STALE_RENEGOTIATIONS_ALLOWED} renégociations n'ont pas ramené de \
                     handshake : la gateway est durablement injoignable. Se reconnecter \
                     quand elle répond de nouveau."
                ),
            ));
            sink(ClientEvent::state(TunnelState::Failed));
            return true;
        }
        sink(ClientEvent::log(
            "info",
            format!(
                "renégociation {attempt}/{STALE_RENEGOTIATIONS_ALLOWED} : le PSK négocié a \
                 disparu côté gateway — redémarrage ou récupération du slot. Cause : \
                 handshake vieilli, pas échec de négociation."
            ),
        ));
        self.connect(installed.profile, raw_sink).await;
        true
    }

    async fn abort_task(&self) {
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
    }
}

/// Renegotiations a stale handshake may trigger before the tunnel gives up.
///
/// Three, and the bound matters as much as the repair: a gateway that is
/// durably absent must not be met with a permanent negotiation loop. Each
/// attempt is itself the bounded loop of [`KEY_NEGOTIATION_ATTEMPTS`], so the
/// spacing the specification asks for is already there — and wider than the
/// two seconds it names, because §4.5 arms ten seconds of rest after a
/// rollback and a retry inside that window is rejected by construction.
const STALE_RENEGOTIATIONS_ALLOWED: u32 = 3;

/// Negotiations attempted before giving up.
///
/// Three, because the failure this exists for is a **lost message**, and a
/// lost message is not repeated by a fourth try if the first two retries did
/// not carry it.
const KEY_NEGOTIATION_ATTEMPTS: u32 = 3;

/// Pause between two negotiations.
///
/// The gateway arms ten seconds of rest after rolling back a candidate that
/// reached the data plane (v5, sections 4.5 and 11.3). Retrying sooner cannot
/// succeed: it is deliberately rejected, and used to consume Orion's two
/// remaining attempts in four seconds. One extra second keeps the client past
/// the boundary despite scheduling and transport jitter.
const KEY_NEGOTIATION_RETRY_DELAY: Duration = Duration::from_secs(11);

/// Errors that cannot be repaired by opening the same authenticated session
/// again.  In particular, a `BadSignature` means that the certificate the
/// gateway serves does not match the one pinned by the profile; retrying it
/// only keeps the UI in `Connexion…` while no state can change.
///
/// Transport timeouts, refused UDP packets and lost responses remain
/// retryable: those are the desynchronisation and transient-network cases the
/// bounded retry loop exists to recover from.
fn is_terminal_negotiation_error(error: &anyhow::Error) -> bool {
    let rendered = format!("{error:#}");
    rendered.contains("invalid peer certificate")
        || rendered.contains("BadSignature")
        || rendered.contains("invalid certificate")
        || rendered.contains("TLS configuration failed")
        || rendered.contains("invalid PKCS#8 private key")
        || rendered.contains("peer did not present a certificate")
}

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
/// Preparation failures with a deterministic local or certificate cause are
/// not retried: nothing has been installed yet, so there is nothing to
/// resynchronise, and repeating a missing identity three times would only
/// delay an error the user needs now. Network and response failures still use
/// the bounded retry loop below.
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
                    let terminal = is_terminal_negotiation_error(&error);
                    if terminal {
                        sink(ClientEvent::log(
                            "error",
                            "échec cryptographique définitif : aucune nouvelle tentative de \
                         négociation ne peut réparer l’identité présentée."
                                .to_string(),
                        ));
                        return Err(error);
                    }
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

    #[test]
    fn negotiation_retry_waits_out_the_gateway_rollback_rest() {
        assert!(
            KEY_NEGOTIATION_RETRY_DELAY > Duration::from_secs(10),
            "a retry inside the gateway's ten-second rest period is guaranteed to be rejected"
        );
    }

    #[test]
    fn certificate_signature_failure_is_terminal() {
        let error = anyhow::anyhow!(
            "performing key negotiation: QUIC connection failed: invalid peer certificate: BadSignature"
        );
        assert!(is_terminal_negotiation_error(&error));
    }

    #[test]
    fn network_timeout_remains_retryable() {
        let error = anyhow::anyhow!(
            "no answer from the key-negotiation service after 10 s — check its UDP port"
        );
        assert!(!is_terminal_negotiation_error(&error));
    }

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

    struct RefusingDownBackend;

    #[async_trait::async_trait]
    impl VpnBackend for RefusingDownBackend {
        async fn up(&self, _profile: &ClientProfile, _sink: &EventSink) -> anyhow::Result<()> {
            Ok(())
        }

        async fn down(&self, _sink: &EventSink) -> anyhow::Result<()> {
            anyhow::bail!("adapter is still mounted")
        }

        async fn last_handshake_age(&self) -> Option<Duration> {
            None
        }

        fn adapter_is_up(&self) -> bool {
            true
        }

        fn kind(&self) -> &'static str {
            "refusing-down"
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

    /// The shell has to be able to name the profile that is up.
    ///
    /// Uninstalling a profile whose tunnel is mounted must release the
    /// gateway's slot first (spec §12.2), and the release travels inside that
    /// tunnel signed by that profile. Both disappear at deletion, so the
    /// question "is this the one that is up?" has to be answerable **before**
    /// anything is removed — and it has to be answerable for a classic profile
    /// too, which owns no negotiation receipt at all.
    #[tokio::test]
    async fn the_mounted_profile_is_named_from_the_start_and_forgotten_at_disconnection() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        assert_eq!(ctrl.mounted_profile().await, None, "nothing is mounted yet");

        ctrl.connect(profile(), sink()).await;
        assert_eq!(
            ctrl.mounted_profile().await.as_deref(),
            Some("test"),
            "a connection under way already owns the profile — a negotiation              takes seconds, and a profile removed during it must be recognised"
        );

        ctrl.disconnect(sink()).await.unwrap();
        assert_eq!(
            ctrl.mounted_profile().await,
            None,
            "the tunnel is down: no profile is mounted any more"
        );
    }

    /// A failed unmount must leave the profile associated with its adapter.
    ///
    /// The shell uses this fact to refuse deleting the profile: destroying its
    /// identity while the adapter still exists would violate the normative
    /// "disconnect first, then remove" order.
    #[tokio::test]
    async fn a_failed_disconnection_keeps_the_mounted_profile_owned() {
        let ctrl = VpnController::new(Arc::new(RefusingDownBackend));
        *ctrl.mounted_profile.lock().await = Some("test".into());
        *ctrl.state.write().unwrap() = TunnelState::Up;

        assert!(ctrl.disconnect(sink()).await.is_err());
        assert_eq!(ctrl.mounted_profile().await.as_deref(), Some("test"));
        assert_eq!(ctrl.state(), TunnelState::Failed);
        assert!(ctrl.adapter_is_up());
    }

    /// A failed same-profile renegotiation must not erase the old receipt.
    ///
    /// Network loss can stale a handshake while the gateway still owns the
    /// previous slot. Until the replacement commits, that transaction remains
    /// the only value a signed release can name.
    #[tokio::test]
    async fn starting_a_same_profile_renegotiation_keeps_the_previous_receipt() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend);
        let mut helios = profile();
        helios.profile_type = Some(crate::config::ProfileKind::HeliosKeyNegotiation);
        helios.key_negotiation = Some(crate::config::KeyNegotiationSettings {
            mode: aether::key_negotiation::ProtectionMode::MlKem,
            minimum_mode: aether::key_negotiation::ProtectionMode::MlKem,
            endpoint: "203.0.113.10:51821".into(),
            server_name: "gateway.example".into(),
            gateway_ca_der: "Q0E=".into(),
            gateway_pq_certificate: "Q0VSVA==".into(),
            identity: "test".into(),
            trust: None,
        });
        *ctrl.installed.lock().await = Some(InstalledNegotiation {
            transaction_id: [9; 16],
            profile: helios.clone(),
        });

        // No identity provider: the spawned negotiation fails, but only after
        // `connect` has made its receipt-retention decision.
        ctrl.connect(helios, sink()).await;
        tokio::task::yield_now().await;

        assert_eq!(
            ctrl.installed
                .lock()
                .await
                .as_ref()
                .map(|receipt| receipt.transaction_id),
            Some([9; 16])
        );
    }

    #[tokio::test]
    async fn a_returning_old_handshake_recovers_a_failed_renegotiation() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        *ctrl.installed.lock().await = Some(InstalledNegotiation {
            transaction_id: [9; 16],
            profile: profile(),
        });
        *ctrl.state.write().unwrap() = TunnelState::Failed;
        backend.set_handshake_age(Some(Duration::from_secs(1)));

        ctrl.poll_handshake(sink()).await;

        assert_eq!(ctrl.state(), TunnelState::Up);
    }

    #[tokio::test]
    async fn connecting_another_profile_drops_an_unrelated_receipt() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend);
        *ctrl.installed.lock().await = Some(InstalledNegotiation {
            transaction_id: [9; 16],
            profile: profile(),
        });
        let mut other = profile();
        other.name = "other".into();

        ctrl.connect(other, sink()).await;

        assert!(ctrl.installed.lock().await.is_none());
    }

    /// Records every log line, so a test can assert on what the user reads.
    fn logging_sink() -> (EventSink, Arc<std::sync::Mutex<Vec<String>>>) {
        let lines: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let recorder = Arc::clone(&lines);
        (
            Arc::new(move |ev: ClientEvent| {
                if let ClientEvent::Log { message, .. } = ev {
                    recorder.lock().unwrap().push(message);
                }
            }),
            lines,
        )
    }

    /// Puts the controller in the exact state §12.5 is about: a tunnel that
    /// reads as up, holding a negotiated receipt, with no handshake in sight.
    async fn stalled_with_receipt(ctrl: &VpnController, backend: &Arc<DryRunBackend>) {
        *ctrl.installed.lock().await = Some(InstalledNegotiation {
            transaction_id: [7; 16],
            profile: profile(),
        });
        *ctrl.state.write().unwrap() = TunnelState::Up;
        backend.set_handshake_age(Some(Duration::from_secs(300)));
    }

    /// A gateway restart empties every negotiated slot, and says nothing.
    ///
    /// The client keeps a PSK the gateway no longer has, keeps working on the
    /// transport keys already derived, then fails at its next rekey up to two
    /// minutes later. Falling back to `Connecting` and waiting described that
    /// tunnel truthfully but repaired nothing: only a new negotiation installs
    /// another PSK.
    #[tokio::test]
    async fn a_stale_handshake_on_a_negotiated_tunnel_renegotiates_by_itself() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        stalled_with_receipt(&ctrl, &backend).await;
        let (sink, lines) = logging_sink();

        ctrl.poll_handshake(sink).await;

        assert_eq!(
            ctrl.stale_renegotiations.load(Ordering::SeqCst),
            1,
            "the repair must be counted, or its bound cannot hold"
        );
        let lines = lines.lock().unwrap();
        assert!(
            lines.iter().any(|line| line.contains("renégociation 1/3")),
            "the log must name the cause as a stale handshake, not a failed \
             negotiation: {lines:?}"
        );
    }

    /// A `static_psk` slot is the operator's configuration, not a negotiation.
    ///
    /// It is read back from `network.toml` at every restart, so it is still
    /// there — a stale handshake means something else, and renegotiating would
    /// repair nothing while costing a round of ML-DSA-87. No receipt, no
    /// repair: that is the whole test.
    #[tokio::test]
    async fn a_tunnel_without_a_receipt_only_falls_back() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        *ctrl.state.write().unwrap() = TunnelState::Up;
        backend.set_handshake_age(Some(Duration::from_secs(300)));

        ctrl.poll_handshake(sink()).await;

        assert_eq!(ctrl.state(), TunnelState::Connecting);
        assert_eq!(ctrl.stale_renegotiations.load(Ordering::SeqCst), 0);
    }

    /// A gateway that is durably gone must not be met with a permanent loop.
    #[tokio::test]
    async fn the_repair_gives_up_after_its_budget_instead_of_looping() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        stalled_with_receipt(&ctrl, &backend).await;
        ctrl.stale_renegotiations
            .store(STALE_RENEGOTIATIONS_ALLOWED, Ordering::SeqCst);
        let (sink, lines) = logging_sink();

        ctrl.poll_handshake(sink).await;

        assert_eq!(
            ctrl.state(),
            TunnelState::Failed,
            "past the budget the tunnel must say it is over, not keep trying"
        );
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("durablement injoignable")),
            "giving up must name why: {lines:?}"
        );
    }

    /// Only a handshake restores the budget — never having attempted a repair.
    #[tokio::test]
    async fn a_successful_handshake_restores_the_repair_budget() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());
        ctrl.stale_renegotiations.store(2, Ordering::SeqCst);
        *ctrl.state.write().unwrap() = TunnelState::Up;
        backend.set_handshake_age(Some(Duration::from_secs(5)));

        ctrl.poll_handshake(sink()).await;

        assert_eq!(ctrl.stale_renegotiations.load(Ordering::SeqCst), 0);
    }

    /// Only explicit disconnection may remove the adapter.
    #[tokio::test]
    async fn only_explicit_disconnection_unmounts() {
        let backend = Arc::new(DryRunBackend::default());
        let ctrl = VpnController::new(backend.clone());

        ctrl.connect(profile(), sink()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ctrl.adapter_is_up());

        ctrl.disconnect(sink()).await.unwrap();
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
