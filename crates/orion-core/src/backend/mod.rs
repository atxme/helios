//! WireGuard backend abstraction and connection controller.
//!
//! # The adapter lifecycle invariant — read before modifying
//!
//! Orion is deliberately **fail-open** (CWE-636): no firewall, no WFP
//! (ADR-001 §3 bis). Its only protection against leaking in clear is a
//! lifecycle discipline:
//!
//! > The adapter (Wintun) carries `AllowedIPs = 0.0.0.0/0, ::/0`. It is
//! > mounted on connection and **is NEVER unmounted on failure** — neither in
//! > `Connecting`, nor in `Failed`, nor after N attempts. It is removed only on
//! > **explicit disconnection** by the user or application shutdown.
//!
//! As long as the adapter holds, packets go out toward WireGuard, which
//! **drops** them if the session is dead: an attacker who blocks UDP 51820
//! only gets a denial of service. If it falls, the default route falls back to
//! the physical interface and traffic exits **in clear**.
//!
//! The drop covers what the adapter captures and nothing more. A profile
//! stored with `0.0.0.0/0` alone — the default before `::/0` joined it — sends
//! its IPv6 out of the physical interface even with the tunnel up; it is
//! flagged by [`ClientProfile::ipv6_uncaptured_full_tunnel`], never widened
//! behind the user's back.
//!
//! This is why the trait separates [`VpnBackend::up`] from
//! [`VpnBackend::down`]: `down` is only called from
//! [`VpnController::disconnect`], never on an error path. The test
//! `adapter_stays_mounted_after_failure` locks in this property.
//!
//! Only [`dryrun::DryRunBackend`] is compiled by default (testable on WSL2). The
//! real WireGuard backend (BoringTun + Wintun via `defguard_wireguard_rs`) is
//! target-only, just like the `netlink` feature on the heliosd side.

use std::net::SocketAddr;
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
    /// Mounts the adapter (the profile's `AllowedIPs`, by default
    /// `0.0.0.0/0, ::/0`) and configures the peer.
    ///
    /// **Contract**: on failure, the implementation must **not** unmount
    /// the adapter if it succeeded in creating it — letting WireGuard drop
    /// packets is better than giving back the physical route to clear traffic.
    /// Must be idempotent: calling `up` again on an already-mounted adapter
    /// reconfigures the peer without recreating it.
    ///
    /// A backend able to read back what the driver applied reports it as
    /// [`ClientEvent::Capture`] on every call. A capture narrower than the
    /// profile is reported, not returned as an error: the adapter stays
    /// mounted either way, so failing would not stop the leak, only drop
    /// what *is* captured (see `wireguard`'s module documentation).
    ///
    /// `profile.endpoint` is a **literal** `IP:port` here, chosen by
    /// [`VpnController`] from a single resolution; a backend refuses a name
    /// instead of resolving it a second time (`endpoint_resolution`).
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

    if let Some(warning) = stale_profile_address(profile.address.as_deref(), &outcome.address) {
        sink(ClientEvent::log("warn", warning));
    }

    let upgraded = ClientProfile {
        preshared_key: Some(outcome.preshared_key.expose().to_owned()),
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

/// What to tell the user when the profile's VIP is not the one the gateway
/// announced, or `None` when they agree.
///
/// The gateway announces the address persisted for this peer at admission —
/// the one its `AllowedIPs` carry — and no longer a re-derivation that could
/// disagree with it (`ADRESSAGE-IPV6.md` §3 bis.2). A difference therefore
/// means this profile is stale: it was emitted for another address, or
/// before the peer was readmitted. Its traffic leaves from an address the
/// gateway drops. The fix is a profile re-emitted by the operator, from the
/// gateway's own record; Orion neither edits the address by hand nor
/// rewrites the profile on its own, like for `AllowedIPs`: the adapter's
/// address is already set, and changing it under a live session's feet would
/// do more harm than good.
fn stale_profile_address(profile_address: Option<&str>, announced: &str) -> Option<String> {
    let declared = profile_address?;
    (declared != announced).then(|| {
        format!(
            "Profil périmé : la gateway a enregistré {announced} pour ce poste, le profil \
             déclare {declared}. La gateway rejette le trafic émis depuis {declared}. Demander \
             à l'opérateur un profil réémis (helios-ctl profile emit) puis le réimporter ; \
             Orion ne modifie pas le profil de lui-même."
        )
    })
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

            // The copy the data plane receives: the endpoint is a literal,
            // resolved once here. The profile itself keeps its name.
            let mounted = match classic_data_plane_profile(&profile, &sink).await {
                Ok(mounted) => mounted,
                Err(e) => {
                    sink(ClientEvent::state(TunnelState::Failed));
                    sink(ClientEvent::Error {
                        message: format!("échec de connexion: {e}"),
                    });
                    // Deliberately no `backend.down(...)` here either.
                    return;
                }
            };
            if let Err(e) = backend.up(&mounted, &sink).await {
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
            // reconnection or disconnection. It remounts from the same copy,
            // so the peer keeps the address it was given.
            upgrade_to_post_quantum(&backend, &mounted, &sink).await;
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
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<crate::certificate_renewal::RenewalError>(),
            Some(crate::certificate_renewal::RenewalError::ActivationPending { .. })
        )
    }) {
        return true;
    }
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
        let (negotiated, wireguard_endpoint) = match prepare_attempt(profile, identities).await {
            Ok(prepared) => prepared,
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
        // Which address answered, in which family, and what was passed over
        // on the way: a broken IPv6 path that IPv4 replaced is said here, as
        // a warning, never absorbed in silence.
        let (level, route) = negotiated.selection().describe();
        sink(ClientEvent::log(
            level,
            format!("négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : {route}"),
        ));
        sink(ClientEvent::log(
            "info",
            format!(
                "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : {}",
                wireguard_endpoint.describe(&profile.endpoint)
            ),
        ));
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
            // The literal chosen above, never the name: the data plane must
            // not resolve it a second time. Only this ephemeral copy carries
            // it; the receipt below keeps the profile as stored, so a
            // renegotiation resolves the name afresh.
            endpoint: wireguard_endpoint.address.to_string(),
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

/// The literal address the tunnel's peer is given, and how it was chosen.
///
/// `defguard_wireguard_rs` resolves a name on its own, synchronously, and
/// keeps the first answer: a second `getaddrinfo`, free to return the other
/// family than the one the negotiation just reached. Handing it a literal is
/// what makes the negotiation and the tunnel agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WireGuardEndpoint {
    address: SocketAddr,
    origin: EndpointOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointOrigin {
    /// The WireGuard endpoint names the negotiation's host: the address that
    /// negotiated, on the WireGuard port.
    Negotiated,
    /// No negotiation on that host — a classic profile, or a negotiation
    /// endpoint naming another host: the first candidate of the WireGuard
    /// host's own single resolution. WireGuard offers one peer endpoint, so
    /// there is nothing to race there.
    FirstCandidate,
}

impl WireGuardEndpoint {
    /// The log line naming the address and family, for the user.
    fn describe(&self, endpoint: &str) -> String {
        let origin = match self.origin {
            EndpointOrigin::Negotiated => "l'adresse qui a négocié",
            EndpointOrigin::FirstCandidate => "premier candidat de sa résolution",
        };
        format!(
            "endpoint WireGuard {endpoint} : {} {} ({origin})",
            crate::endpoint_resolution::family(&self.address),
            self.address
        )
    }
}

/// The copy of `profile` the data plane receives: identical, but for an
/// endpoint that is now the literal `address`.
///
/// A copy, never an edit: the stored profile keeps the name the operator
/// wrote, so the next connection resolves it again — the gateway may have
/// moved, or the network may have gained or lost a family.
fn with_wireguard_endpoint(profile: &ClientProfile, address: SocketAddr) -> ClientProfile {
    ClientProfile {
        endpoint: address.to_string(),
        ..profile.clone()
    }
}

/// Resolves the WireGuard endpoint once and keeps its first RFC 8305
/// candidate.
///
/// The error keeps the wording the backend used when it resolved the name
/// itself, so a profile pointing nowhere reads as it always did.
async fn resolve_wireguard_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    let candidates = crate::endpoint_resolution::resolve_candidates(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("endpoint `{endpoint}` invalide : {e:#}"))?;
    candidates.first().copied().ok_or_else(|| {
        anyhow::anyhow!("endpoint `{endpoint}` invalide : aucune adresse utilisable")
    })
}

/// A classic connection's data-plane copy: validated, then resolved once.
///
/// The validation is the one `up()` starts with, made **before** the
/// resolver is asked, so an incomplete profile is still refused before any
/// network activity. `up()` runs it again on the copy, unchanged.
async fn classic_data_plane_profile(
    profile: &ClientProfile,
    sink: &EventSink,
) -> anyhow::Result<ClientProfile> {
    profile.validate_for_data_plane()?;
    let target = WireGuardEndpoint {
        address: resolve_wireguard_endpoint(&profile.endpoint).await?,
        origin: EndpointOrigin::FirstCandidate,
    };
    sink(ClientEvent::log("info", target.describe(&profile.endpoint)));
    Ok(with_wireguard_endpoint(profile, target.address))
}

/// One negotiation attempt's preparation: each host resolved once, then the
/// negotiation, then the WireGuard endpoint that follows from both.
///
/// The WireGuard host is resolved **before** negotiating when it differs
/// from the negotiation host. A name that does not resolve is then refused
/// with nothing prepared on the gateway; resolving it afterwards would drop
/// a prepared transaction, and the gateway arms ten seconds of rest after
/// every such rollback.
async fn prepare_attempt(
    profile: &ClientProfile,
    identities: &dyn crate::key_negotiation::IdentityProvider,
) -> anyhow::Result<(crate::key_negotiation::NegotiatedKey, WireGuardEndpoint)> {
    enum Plan {
        FromNegotiation(u16),
        Resolved(SocketAddr),
    }
    let plan = match profile.key_negotiation.as_ref() {
        // Refused by the negotiation below with its own message, before
        // anything is resolved.
        None => None,
        Some(settings)
            if crate::endpoint_resolution::same_host(&profile.endpoint, &settings.endpoint) =>
        {
            let port = crate::endpoint_resolution::port_of(&profile.endpoint).ok_or_else(|| {
                anyhow::anyhow!(
                    "endpoint `{}` invalide : port UDP absent ou nul",
                    profile.endpoint
                )
            })?;
            Some(Plan::FromNegotiation(port))
        }
        // Two names are two hosts: each is resolved once, never merged.
        Some(_) => Some(Plan::Resolved(
            resolve_wireguard_endpoint(&profile.endpoint).await?,
        )),
    };
    let negotiated = crate::key_negotiation::prepare_for_profile(profile, identities).await?;
    let wireguard = match plan {
        Some(Plan::FromNegotiation(port)) => {
            // `set_port` rather than a new address: an IPv6 candidate keeps
            // its scope identifier.
            let mut address = negotiated.remote();
            address.set_port(port);
            WireGuardEndpoint {
                address,
                origin: EndpointOrigin::Negotiated,
            }
        }
        Some(Plan::Resolved(address)) => WireGuardEndpoint {
            address,
            origin: EndpointOrigin::FirstCandidate,
        },
        None => anyhow::bail!("profile has no key-negotiation settings"),
    };
    Ok((negotiated, wireguard))
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
mod tests;
