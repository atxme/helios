//! The connection controller: one tunnel's lifecycle, from the classic
//! data plane to the post-quantum upgrade, and who owns the data plane.

use super::*;

/// Maximum wait time for the first handshake before attempting
/// post-quantum provisioning.
///
/// The provisioning channel lives *inside* the tunnel: no point calling it
/// before the classic tunnel carries traffic. Beyond that, we give up for
/// this session — without breaking anything, the classic tunnel stays up.
const PROVISION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Handshake polling period during the wait above.
const PROVISION_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
pub(super) async fn upgrade_to_post_quantum(
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
    if let Some(warning) =
        stale_profile_address_v6(profile.address_v6.as_deref(), outcome.address_v6.as_deref())
    {
        sink(ClientEvent::log("warn", warning));
    }

    let upgraded = ClientProfile {
        preshared_key: Some(outcome.preshared_key.duplicate()),
        // Same rule as the pre-WireGuard negotiation: this PSK is the result
        // of an ML-KEM exchange, not a secret typed into the profile.
        preshared_key_is_negotiated: true,
        ..profile.duplicate()
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
pub(super) fn stale_profile_address(
    profile_address: Option<&str>,
    announced: &str,
) -> Option<String> {
    let declared = profile_address?;
    (declared != announced).then(|| {
        format!(
            "Profil périmé : la gateway a enregistré {announced} pour ce poste, le profil \
             déclare {declared}. La gateway rejette le trafic émis depuis {declared}. Demander \
             à l'opérateur un profil réémis (helios profile emit) puis le réimporter ; \
             Orion ne modifie pas le profil de lui-même."
        )
    })
}

/// The same question for the IPv6 VIP, which either side may lack.
///
/// The gateway announces `assigned_address_v6` from the same record as the
/// IPv4 VIP (`ADRESSAGE-IPV6.md` §7.1), and its absence means it holds none
/// for this peer — a gateway without IPv6, or one older than the field. All
/// three disagreements name a stale profile, in the same words as the IPv4
/// one, and none rewrites it:
///
/// - another address: the gateway drops the IPv6 traffic this profile emits;
/// - an address the gateway does not hold: the same, for the same reason;
/// - no address where the gateway holds one: nothing is dropped, the tunnel
///   simply stays IPv4-only until the profile is re-emitted (§8).
///
/// Addresses are compared as addresses: `FD3C::2/128` and `fd3c::2/128` are
/// one VIP, and calling that a divergence would send the user to the
/// operator for nothing.
pub(super) fn stale_profile_address_v6(
    profile_address: Option<&str>,
    announced: Option<&str>,
) -> Option<String> {
    let same = |declared: &str, announced: &str| match (
        aether::net::parse_vip_v6(declared.trim()),
        aether::net::parse_vip_v6(announced.trim()),
    ) {
        (Ok(declared), Ok(announced)) => declared == announced,
        _ => declared.trim() == announced.trim(),
    };
    let reissue = "Demander à l'opérateur un profil réémis (helios profile emit) puis le \
                   réimporter ; Orion ne modifie pas le profil de lui-même.";
    match (profile_address, announced) {
        (None, None) => None,
        (Some(declared), Some(announced)) if same(declared, announced) => None,
        (Some(declared), Some(announced)) => Some(format!(
            "Profil périmé : la gateway a enregistré {announced} pour ce poste, le profil \
             déclare {declared}. La gateway rejette le trafic IPv6 émis depuis {declared}. \
             {reissue}"
        )),
        (Some(declared), None) => Some(format!(
            "Profil périmé : la gateway n'a enregistré aucune adresse IPv6 pour ce poste, le \
             profil déclare {declared}. La gateway rejette le trafic IPv6 émis depuis \
             {declared}. {reissue}"
        )),
        (None, Some(announced)) => Some(format!(
            "Profil périmé : la gateway a enregistré {announced} pour ce poste, le profil ne \
             déclare aucune adresse IPv6 : le tunnel reste en IPv4 seule. {reissue}"
        )),
    }
}

/// Connection controller: holds the tunnel's current state and orchestrates
/// the backend. Single source of truth for [`TunnelState`] on the client side.
pub struct VpnController {
    backend: Arc<dyn VpnBackend>,
    pub(super) state: Arc<RwLock<TunnelState>>,
    pub(super) task: Mutex<Option<JoinHandle<()>>>,
    /// Receipt for the PSK currently posed, if any.
    ///
    /// Held here rather than in the connection task because it must outlive
    /// it: the task ends once the tunnel is up, while the receipt is needed
    /// at disconnection, arbitrarily later.
    pub(super) installed: Arc<Mutex<Option<InstalledNegotiation>>>,
    /// Has the liveness link of the current tunnel died on its own?
    ///
    /// The handshake age cannot express this. When the link closes, the
    /// gateway drops the negotiated PSK, but the WireGuard session already
    /// established keeps carrying traffic until its next rekey — so the last
    /// handshake stays fresh for up to two more minutes while the tunnel is
    /// already condemned. Inferring the state from freshness alone left the
    /// UI showing a healthy connection the client knew was over.
    pub(super) link_lost: Arc<AtomicBool>,
    /// Name of the profile the current tunnel was mounted for.
    ///
    /// Separate from `installed`, which only exists once a negotiation has
    /// committed: a classic tunnel has no receipt, and the shell still has to
    /// be able to ask "is this the profile that is up?". Set as soon as a
    /// connection starts, so a profile removed while its negotiation is still
    /// running is recognised too.
    pub(super) mounted_profile: Arc<Mutex<Option<String>>>,
    /// Renegotiations already triggered by a stale handshake, since the last
    /// one that succeeded.
    ///
    /// Bounds the repair of spec §12.5. A gateway that is durably gone must
    /// not produce an aggressive negotiation loop, and the counter is reset by
    /// the only fact that proves the repair worked — a fresh handshake — never
    /// by having attempted one.
    pub(super) stale_renegotiations: Arc<AtomicU32>,
    /// Is a PSK renewal in flight? At most one at a time.
    pub(super) renewing: Arc<AtomicBool>,
    /// The renewal in flight, so a connection or a disconnection can stop it.
    renewal_task: Mutex<Option<JoinHandle<()>>>,
    /// Bumped by every connection and disconnection: see [`DataPlaneOwner`].
    data_plane_epoch: Arc<AtomicU64>,
    key_negotiation_identities: Option<Arc<dyn crate::key_negotiation::IdentityProvider>>,
}

/// The PSK currently posed for this tunnel, and which transaction posed it.
///
/// v4 kept a live QUIC link here and treated its closure as the end of the
/// tunnel. v5 keeps a receipt instead: the transaction identifier the gateway
/// recorded as the slot's owner, which is what a signed release must name to
/// be accepted. Nothing about the tunnel depends on a connection any more.
pub(super) struct InstalledNegotiation {
    pub(super) transaction_id: [u8; 16],
    /// The profile that negotiated it — the release has to be signed with the
    /// same identity and aimed at the same gateway, and the profile in use
    /// may have changed by the time the user disconnects.
    pub(super) profile: ClientProfile,
    /// The copy the data plane received — literal endpoint, PSK in place.
    ///
    /// A renewal re-registers the peer from it with the new PSK, and puts it
    /// back as it was if the renewal does not commit.
    pub(super) data_plane: ClientProfile,
    pub(super) clock: renewal::RenewalClock,
    /// Renewals failed since this PSK was committed.
    pub(super) failures: u32,
    /// No automatic renewal before this instant (back-off).
    pub(super) next_attempt: Option<std::time::Instant>,
}

impl InstalledNegotiation {
    pub(super) fn new(
        transaction_id: [u8; 16],
        profile: ClientProfile,
        data_plane: ClientProfile,
        bytes: Option<u64>,
    ) -> Self {
        Self {
            transaction_id,
            profile,
            data_plane,
            clock: renewal::RenewalClock::start(
                std::time::Instant::now(),
                std::time::SystemTime::now(),
                bytes,
            ),
            failures: 0,
            next_attempt: None,
        }
    }

    pub(super) fn duplicate(&self) -> Self {
        Self {
            transaction_id: self.transaction_id,
            profile: self.profile.duplicate(),
            data_plane: self.data_plane.duplicate(),
            clock: self.clock.clone(),
            failures: self.failures,
            next_attempt: self.next_attempt,
        }
    }
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
            renewing: Arc::new(AtomicBool::new(false)),
            renewal_task: Mutex::new(None),
            data_plane_epoch: Arc::new(AtomicU64::new(0)),
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
        let Some(installed) = self
            .installed
            .lock()
            .await
            .as_ref()
            .map(InstalledNegotiation::duplicate)
        else {
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

    /// Renews the negotiated PSK through the tunnel once it is due.
    ///
    /// Called by the shell's state loop beside [`Self::poll_handshake`].
    /// Never touches the adapter beyond re-registering the peer.
    pub async fn poll_renewal(&self, user_sink: EventSink) {
        if self.state() != TunnelState::Up {
            return;
        }
        // Read before taking the receipt lock: the counters come from the
        // data plane, and the lock is not held across that call.
        let bytes = self.backend.transfer_bytes().await;
        let trigger = {
            let mut installed = self.installed.lock().await;
            let Some(receipt) = installed.as_mut() else {
                return;
            };
            if receipt
                .next_attempt
                .is_some_and(|at| std::time::Instant::now() < at)
            {
                return;
            }
            match receipt.clock.due(
                std::time::Instant::now(),
                std::time::SystemTime::now(),
                bytes,
            ) {
                Some(trigger) => trigger,
                None => return,
            }
        };
        self.start_renewal(trigger, user_sink).await;
    }

    /// Renews now, at the user's request (and for the V1 measurement).
    pub async fn renew_now(&self, user_sink: EventSink) -> anyhow::Result<()> {
        if self.state() != TunnelState::Up || self.installed.lock().await.is_none() {
            anyhow::bail!("aucun tunnel ML-KEM monté : rien à renouveler");
        }
        if self.key_negotiation_identities.is_none() {
            anyhow::bail!("aucun magasin d'identités protégé : renouvellement impossible");
        }
        // Said, not swallowed: a click during the wait for the renewed
        // handshake otherwise reads as "requested" and does nothing.
        if !self
            .start_renewal(renewal::RenewalTrigger::Manual, user_sink)
            .await
        {
            anyhow::bail!(
                "un renouvellement est déjà en cours : attendre son issue, qui est annoncée                  dans le journal"
            );
        }
        Ok(())
    }

    /// Starts a renewal unless one is in flight; says whether it started.
    async fn start_renewal(&self, trigger: renewal::RenewalTrigger, user_sink: EventSink) -> bool {
        if self.renewing.swap(true, Ordering::SeqCst) {
            return false;
        }
        let flag = ClearOnDrop(Arc::clone(&self.renewing));
        let Some(identities) = self.key_negotiation_identities.clone() else {
            return false;
        };
        let backend = Arc::clone(&self.backend);
        let installed = Arc::clone(&self.installed);
        let sink = self.wrap_sink(user_sink);
        let owner = DataPlaneOwner::claim(&self.data_plane_epoch);
        let handle = tokio::spawn(async move {
            let _flag = flag;
            run_renewal(
                &backend,
                identities.as_ref(),
                &installed,
                trigger,
                &sink,
                owner,
            )
            .await;
        });
        *self.renewal_task.lock().await = Some(handle);
        true
    }

    /// Stops the connection task and any renewal in flight, and takes the data
    /// plane over: whatever either of them was about to do to the peer, the
    /// caller — a connection or a disconnection — now decides instead.
    async fn abort_task(&self) {
        self.data_plane_epoch.fetch_add(1, Ordering::SeqCst);
        if let Some(handle) = self.renewal_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
    }
}

/// Which connection currently owns the data plane.
///
/// [`VpnController::abort_task`] bumps the epoch on every connection and
/// disconnection. A renewal records the value it started under and touches
/// the peer only while it still holds.
#[derive(Clone)]
pub(super) struct DataPlaneOwner {
    epoch: Arc<AtomicU64>,
    held: u64,
}

impl DataPlaneOwner {
    pub(super) fn claim(epoch: &Arc<AtomicU64>) -> Self {
        Self {
            epoch: Arc::clone(epoch),
            held: epoch.load(Ordering::SeqCst),
        }
    }

    pub(super) fn still_held(&self) -> bool {
        self.epoch.load(Ordering::SeqCst) == self.held
    }
}

/// Clears the in-flight flag however the renewal task ends.
struct ClearOnDrop(Arc<AtomicBool>);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
