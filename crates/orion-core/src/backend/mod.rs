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

use std::sync::{Arc, RwLock};
use std::time::Duration;

use aether::TunnelState;
#[cfg(feature = "key-negotiation")]
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

/// Waits for a fresh handshake to prove the classic tunnel carries traffic.
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
            "Pas d'URL Helios interne au profil : le tunnel reste classique \
             (Curve25519 seul, vulnérable au « récolter maintenant, déchiffrer plus tard »)"
                .to_string(),
        ));
        return;
    };

    if !wait_for_handshake(backend).await {
        sink(ClientEvent::protection(PskKind::None));
        sink(ClientEvent::log(
            "warn",
            "Aucun handshake dans le délai imparti : PSK PQC reporté à la \
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
                format!("Négociation du PSK PQC impossible : {e} — le tunnel reste classique"),
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
        ..profile.clone()
    };

    match backend.up(&upgraded, sink).await {
        Ok(()) => {
            sink(ClientEvent::protection(PskKind::MlKem));
            sink(ClientEvent::log(
                "info",
                format!(
                    "PSK PQC installé (ML-KEM-768, valable {} s) — \
                     le prochain handshake sera protégé",
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
                    "PSK PQC obtenu mais non installé localement : {e}. La gateway \
                     l'a posé de son côté — se reconnecter pour resynchroniser."
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
    #[cfg(feature = "key-negotiation")]
    key_negotiation_identities: Option<Arc<dyn crate::key_negotiation::IdentityProvider>>,
}

impl VpnController {
    pub fn new(backend: Arc<dyn VpnBackend>) -> Self {
        Self {
            backend,
            state: Arc::new(RwLock::new(TunnelState::Down)),
            task: Mutex::new(None),
            #[cfg(feature = "key-negotiation")]
            key_negotiation_identities: None,
        }
    }

    /// Supplies the protected client-certificate store used before WireGuard.
    #[cfg(feature = "key-negotiation")]
    pub fn with_key_negotiation_identities(
        mut self,
        identities: Arc<dyn crate::key_negotiation::IdentityProvider>,
    ) -> Self {
        self.key_negotiation_identities = Some(identities);
        self
    }

    /// Can this build actually negotiate a key before WireGuard?
    ///
    /// Two conditions, and the UI must not confuse them: the binary must be
    /// compiled with the `key-negotiation` feature, and the shell must have
    /// supplied a protected identity store. A profile carrying the block
    /// would otherwise fail at connection time, after the user has been
    /// promised a mode the client cannot honor.
    pub fn key_negotiation_ready(&self) -> bool {
        #[cfg(feature = "key-negotiation")]
        {
            self.key_negotiation_identities.is_some()
        }
        #[cfg(not(feature = "key-negotiation"))]
        {
            false
        }
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
        let sink = self.wrap_sink(user_sink);
        let backend = Arc::clone(&self.backend);
        #[cfg(feature = "key-negotiation")]
        let identities = self.key_negotiation_identities.clone();
        let handle = tokio::spawn(async move {
            #[cfg(feature = "key-negotiation")]
            if profile.key_negotiation.is_some() {
                if let Err(error) =
                    connect_with_key_negotiation(&backend, &profile, &sink, identities.as_deref())
                        .await
                {
                    sink(ClientEvent::state(TunnelState::Failed));
                    sink(ClientEvent::Error {
                        message: format!("key negotiation failed: {error}"),
                    });
                }
                return;
            }
            #[cfg(not(feature = "key-negotiation"))]
            if profile.key_negotiation.is_some() {
                sink(ClientEvent::state(TunnelState::Failed));
                sink(ClientEvent::Error {
                    message: "this Orion binary was built without key-negotiation support"
                        .to_string(),
                });
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

    /// Unmounts the tunnel — **the only path allowed to remove the adapter**.
    pub async fn disconnect(&self, user_sink: EventSink) {
        self.abort_task().await;
        let sink = self.wrap_sink(user_sink);
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

#[cfg(feature = "key-negotiation")]
async fn connect_with_key_negotiation(
    backend: &Arc<dyn VpnBackend>,
    profile: &ClientProfile,
    sink: &EventSink,
    identities: Option<&dyn crate::key_negotiation::IdentityProvider>,
) -> anyhow::Result<()> {
    let identities = identities
        .context("the Orion shell did not provide a protected key-negotiation identity store")?;
    let negotiated = crate::key_negotiation::prepare_for_profile(profile, identities).await?;
    let mode = negotiated.mode;
    let confirmation_timeout = negotiated.confirmation_timeout;
    let prepared_at = tokio::time::Instant::now();
    let negotiated_profile = ClientProfile {
        preshared_key: negotiated
            .psk
            .as_ref()
            .map(|secret| secret.expose().to_string()),
        ..profile.clone()
    };

    backend.up(&negotiated_profile, sink).await?;
    if !wait_for_new_handshake(backend, prepared_at, confirmation_timeout).await {
        anyhow::bail!(
            "no fresh WireGuard handshake before the key-negotiation transaction expired"
        );
    }
    negotiated.confirm().await?;

    let protection = match mode {
        aether::key_negotiation::ProtectionMode::Classic => PskKind::None,
        aether::key_negotiation::ProtectionMode::StaticPsk => PskKind::Static,
        aether::key_negotiation::ProtectionMode::MlKem => PskKind::MlKem,
    };
    sink(ClientEvent::protection(protection));
    sink(ClientEvent::log(
        "info",
        format!("key negotiation committed after a fresh WireGuard handshake ({mode:?})"),
    ));
    Ok(())
}

#[cfg(feature = "key-negotiation")]
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
        tokio::time::sleep(PROVISION_POLL_INTERVAL).await;
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
