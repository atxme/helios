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
fn a_committed_recovery_waiting_for_activation_is_not_retried() {
    let error = anyhow::Error::new(
        crate::certificate_renewal::RenewalError::ActivationPending {
            generation: 5,
            activation_at: "12 septembre 2026 à 14:00:00 CEST".into(),
        },
    )
    .context("promoting a due key-negotiation identity before connecting");
    assert!(is_terminal_negotiation_error(&error));
}

#[test]
fn network_timeout_remains_retryable() {
    let error = anyhow::anyhow!(
        "no answer from the key-negotiation service after 10 s — check its UDP port"
    );
    assert!(!is_terminal_negotiation_error(&error));
}

/// §9 criterion 11, client side: the gateway now announces the address it
/// persisted, which is the one a profile emitted from its record carries —
/// so a connection made with that profile reports no divergence.
#[test]
fn a_profile_carrying_the_persisted_address_raises_no_warning() {
    assert_eq!(
        stale_profile_address(Some("100.64.1.2/32"), "100.64.1.2/32"),
        None
    );
    assert_eq!(stale_profile_address(None, "100.64.1.2/32"), None);
}

/// A divergence names both addresses, calls the profile stale and asks for a
/// re-emitted one, without telling the user to type the announced address in.
#[test]
fn a_profile_with_another_address_is_reported_stale() {
    let warning = stale_profile_address(Some("100.98.165.218/32"), "100.124.38.30/32")
        .expect("a divergence is reported");
    assert!(warning.contains("100.98.165.218/32"), "{warning}");
    assert!(warning.contains("100.124.38.30/32"), "{warning}");
    assert!(warning.contains("périmé"), "{warning}");
    assert!(warning.contains("réémis"), "{warning}");
    assert!(!warning.contains("corriger le profil"), "{warning}");
}

/// Agreement in either shape raises nothing: both without IPv6 — every
/// profile of a gateway without it (§8) — or the same VIP in two spellings.
#[test]
fn a_profile_agreeing_on_the_ipv6_address_raises_no_warning() {
    assert_eq!(stale_profile_address_v6(None, None), None);
    assert_eq!(
        stale_profile_address_v6(Some("fd3c:91a2:7e04::2/128"), Some("fd3c:91a2:7e04::2/128")),
        None
    );
    assert_eq!(
        stale_profile_address_v6(
            Some("FD3C:91A2:7E04:0::2/128"),
            Some("fd3c:91a2:7e04::2/128")
        ),
        None
    );
}

/// Each IPv6 divergence names the stale profile in the IPv4 message's words
/// and asks for a re-emitted one; none tells the user to edit it.
#[test]
fn a_profile_with_another_ipv6_address_is_reported_stale() {
    for (declared, announced, names) in [
        (
            Some("fd3c:91a2:7e04::2/128"),
            Some("fd3c:91a2:7e04::9/128"),
            vec!["fd3c:91a2:7e04::2/128", "fd3c:91a2:7e04::9/128", "rejette"],
        ),
        (
            Some("fd3c:91a2:7e04::2/128"),
            None,
            vec!["fd3c:91a2:7e04::2/128", "aucune adresse IPv6", "rejette"],
        ),
        (
            None,
            Some("fd3c:91a2:7e04::9/128"),
            vec!["fd3c:91a2:7e04::9/128", "IPv4 seule"],
        ),
    ] {
        let warning = stale_profile_address_v6(declared, announced)
            .unwrap_or_else(|| panic!("{declared:?} / {announced:?} must be reported"));
        assert!(warning.starts_with("Profil périmé"), "{warning}");
        assert!(warning.contains("réémis"), "{warning}");
        assert!(warning.contains("ne modifie pas le profil"), "{warning}");
        for name in names {
            assert!(warning.contains(name), "{name}: {warning}");
        }
    }
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

    async fn rekey_peer(&self, _profile: &ClientProfile, _sink: &EventSink) -> anyhow::Result<()> {
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        None
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
    *ctrl.installed.lock().await = Some(InstalledNegotiation::new(
        [9; 16],
        helios.duplicate(),
        helios.duplicate(),
        None,
    ));

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
    *ctrl.installed.lock().await = Some(InstalledNegotiation::new(
        [9; 16],
        profile(),
        profile(),
        None,
    ));
    *ctrl.state.write().unwrap() = TunnelState::Failed;
    backend.set_handshake_age(Some(Duration::from_secs(1)));

    ctrl.poll_handshake(sink()).await;

    assert_eq!(ctrl.state(), TunnelState::Up);
}

#[tokio::test]
async fn connecting_another_profile_drops_an_unrelated_receipt() {
    let backend = Arc::new(DryRunBackend::default());
    let ctrl = VpnController::new(backend);
    *ctrl.installed.lock().await = Some(InstalledNegotiation::new(
        [9; 16],
        profile(),
        profile(),
        None,
    ));
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
    *ctrl.installed.lock().await = Some(InstalledNegotiation::new(
        [7; 16],
        profile(),
        profile(),
        None,
    ));
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
    p.private_key = aether::SecretString::default();
    assert!(p.validate().is_err());

    let mut p = profile();
    p.endpoint = String::new();
    assert!(p.validate().is_err());

    assert!(profile().validate().is_ok());
}

/// Records the endpoint of every profile `up()` receives.
#[derive(Default)]
struct EndpointRecorder {
    endpoints: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl VpnBackend for EndpointRecorder {
    async fn up(&self, profile: &ClientProfile, _sink: &EventSink) -> anyhow::Result<()> {
        self.endpoints
            .lock()
            .unwrap()
            .push(profile.endpoint.clone());
        Ok(())
    }

    async fn down(&self, _sink: &EventSink) -> anyhow::Result<()> {
        Ok(())
    }

    async fn rekey_peer(&self, _profile: &ClientProfile, _sink: &EventSink) -> anyhow::Result<()> {
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        None
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        None
    }

    fn adapter_is_up(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "endpoint-recorder"
    }
}

/// Lets the connection task run to its end: classic, no URL, no PSK.
async fn connect_classic(profile: ClientProfile) -> (Arc<EndpointRecorder>, Vec<String>) {
    let backend = Arc::new(EndpointRecorder::default());
    let ctrl = VpnController::new(backend.clone());
    let (sink, lines) = logging_sink();
    ctrl.connect(profile, sink).await;
    if let Some(task) = ctrl.task.lock().await.take() {
        task.await.unwrap();
    }
    let lines = lines.lock().unwrap().clone();
    (backend, lines)
}

/// A literal endpoint reaches the data plane as written, in both families.
#[tokio::test]
async fn a_literal_endpoint_is_mounted_as_written() {
    for literal in ["[2001:db8::1]:51820", "203.0.113.10:51820"] {
        let mut p = profile();
        p.endpoint = literal.into();
        let (backend, _) = connect_classic(p).await;
        assert_eq!(
            *backend.endpoints.lock().unwrap(),
            vec![literal.to_string()]
        );
    }
}

/// A name is resolved once by the controller, and the backend receives the
/// literal it chose — never the name, which would be resolved a second time.
/// `localhost` resolves from the hosts file: no network involved.
#[tokio::test]
async fn a_hostname_endpoint_is_mounted_as_the_literal_it_resolved_to() {
    let mut p = profile();
    p.endpoint = "localhost:51820".into();
    let stored = p.duplicate();
    let (backend, lines) = connect_classic(p).await;

    let mounted = backend.endpoints.lock().unwrap().clone();
    assert_eq!(mounted.len(), 1, "{mounted:?}");
    let literal: SocketAddr = mounted[0]
        .parse()
        .unwrap_or_else(|_| panic!("{} is not a literal", mounted[0]));
    assert!(literal.ip().is_loopback(), "{literal}");
    assert_eq!(literal.port(), 51820);
    assert_eq!(stored.endpoint, "localhost:51820");
    let named = format!(
        "endpoint WireGuard localhost:51820 : {} {literal} (premier candidat de sa résolution)",
        crate::endpoint_resolution::family(&literal)
    );
    assert!(lines.contains(&named), "{lines:?}");
}

/// A name that cannot be resolved fails the connection explicitly, naming
/// the endpoint, and the backend is never reached.
#[tokio::test]
async fn an_unresolvable_endpoint_fails_explicitly_before_the_backend() {
    let backend = Arc::new(EndpointRecorder::default());
    let ctrl = VpnController::new(backend.clone());
    let errors: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let recorder = Arc::clone(&errors);
    let mut p = profile();
    // No port: refused by the resolver itself, without a DNS query.
    p.endpoint = "not-an-endpoint".into();
    ctrl.connect(
        p,
        Arc::new(move |ev: ClientEvent| {
            if let ClientEvent::Error { message } = ev {
                recorder.lock().unwrap().push(message);
            }
        }),
    )
    .await;
    if let Some(task) = ctrl.task.lock().await.take() {
        task.await.unwrap();
    }

    assert_eq!(ctrl.state(), TunnelState::Failed);
    let errors = errors.lock().unwrap().clone();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with("échec de connexion: endpoint `not-an-endpoint` invalide"),
        "{errors:?}"
    );
    assert!(backend.endpoints.lock().unwrap().is_empty());
}

/// The data-plane copy differs from the stored profile by its endpoint and
/// nothing else, and the stored profile is left as written.
#[test]
fn the_data_plane_copy_only_replaces_the_endpoint() {
    let mut stored = profile();
    stored.endpoint = "gateway.example:51820".into();
    stored.heliosd_url = Some("http://100.64.0.1:8080".into());
    let copy = with_wireguard_endpoint(&stored, "[2001:db8::1]:51820".parse().unwrap());

    assert_eq!(copy.endpoint, "[2001:db8::1]:51820");
    assert_eq!(stored.endpoint, "gateway.example:51820");
    assert_eq!(
        format!(
            "{:?}",
            ClientProfile {
                endpoint: stored.endpoint.clone(),
                ..copy
            }
        ),
        format!("{stored:?}")
    );
}

#[test]
fn the_wireguard_endpoint_log_names_the_family_and_its_origin() {
    let negotiated = WireGuardEndpoint {
        address: "203.0.113.10:51820".parse().unwrap(),
        origin: EndpointOrigin::Negotiated,
    };
    assert_eq!(
        negotiated.describe("gateway.example:51820"),
        "endpoint WireGuard gateway.example:51820 : IPv4 203.0.113.10:51820 \
         (l'adresse qui a négocié)"
    );
    let resolved = WireGuardEndpoint {
        address: "[2001:db8::1]:51820".parse().unwrap(),
        origin: EndpointOrigin::FirstCandidate,
    };
    assert_eq!(
        resolved.describe("gateway.example:51820"),
        "endpoint WireGuard gateway.example:51820 : IPv6 [2001:db8::1]:51820 \
         (premier candidat de sa résolution)"
    );
}

// ---- In-tunnel PSK renewal ----------------------------------------------------

use crate::backend::renewal::RenewalTrigger;

const NEW_PSK: &str = "bmV3cHNrbmV3cHNrbmV3cHNrbmV3cHNrbmV3cHNrMTI=";
const OLD_PSK: &str = "b2xkcHNrb2xkcHNrb2xkcHNrb2xkcHNrb2xkcHNrMTI=";

fn secret(value: &str) -> Option<aether::SecretString> {
    Some(aether::SecretString::new(value))
}

struct FakePending {
    psk: aether::SecretString,
    confirm: Result<(), String>,
    hang: bool,
}

#[async_trait::async_trait]
impl PendingRenewal for FakePending {
    fn psk(&self) -> Option<&aether::SecretString> {
        Some(&self.psk)
    }
    fn transaction_id(&self) -> [u8; 16] {
        [9; 16]
    }
    fn confirmation_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    async fn confirm(self: Box<Self>) -> anyhow::Result<()> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.confirm.map_err(|e| anyhow::anyhow!(e))
    }
}

fn pending(confirm: Result<(), String>) -> Box<dyn PendingRenewal> {
    Box::new(FakePending {
        psk: aether::SecretString::new(NEW_PSK),
        confirm,
        hang: false,
    })
}

async fn mounted() -> (
    Arc<DryRunBackend>,
    Arc<dyn VpnBackend>,
    InstalledNegotiation,
) {
    let mut instant = DryRunBackend::default();
    instant.negotiate_delay = Duration::ZERO;
    let dry = Arc::new(instant);
    let backend: Arc<dyn VpnBackend> = dry.clone();
    let data_plane = ClientProfile {
        preshared_key: secret(OLD_PSK),
        ..profile()
    };
    backend.up(&data_plane, &sink()).await.unwrap();
    let receipt = InstalledNegotiation::new([7; 16], profile(), data_plane, Some(0));
    (dry, backend, receipt)
}

#[tokio::test]
async fn a_confirmed_renewal_installs_the_new_psk_and_a_new_receipt() {
    let (dry, backend, current) = mounted().await;
    let renewed = renew_slot(&backend, &current, pending(Ok(())), &sink())
        .await
        .unwrap();
    assert_eq!(renewed.transaction_id, [9; 16]);
    assert_eq!(dry.rekeyed_psks(), vec![secret(NEW_PSK)]);
    assert_eq!(renewed.data_plane.preshared_key, secret(NEW_PSK));
    assert!(renewed.data_plane.preshared_key_is_negotiated);
}

#[tokio::test]
async fn a_renewal_restarts_the_volume_count_from_the_re_registered_peer() {
    let (dry, backend, current) = mounted().await;
    dry.set_transfer_bytes(Some(70 * 1024 * 1024 * 1024));
    let mut renewed = renew_slot(&backend, &current, pending(Ok(())), &sink())
        .await
        .unwrap();
    // `rekey_peer` restarted the client counters at zero; 80 GiB from there.
    let now = std::time::Instant::now();
    let wall = std::time::SystemTime::now();
    assert_eq!(
        renewed.clock.due(now, wall, Some(79 * 1024 * 1024 * 1024)),
        None
    );
    assert_eq!(
        renewed.clock.due(now, wall, Some(80 * 1024 * 1024 * 1024)),
        Some(RenewalTrigger::Volume)
    );
}

#[tokio::test]
async fn a_failed_confirmation_puts_the_previous_psk_back() {
    let (dry, backend, current) = mounted().await;
    assert!(
        renew_slot(&backend, &current, pending(Err("lost".into())), &sink())
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        dry.rekeyed_psks(),
        vec![secret(NEW_PSK), secret(OLD_PSK)],
        "the rollback re-registers the peer with the PSK it had"
    );
}

#[tokio::test]
async fn a_cancelled_renewal_still_puts_the_previous_psk_back() {
    let (dry, backend, current) = mounted().await;
    let task = tokio::spawn(async move {
        let hanging = Box::new(FakePending {
            psk: aether::SecretString::new(NEW_PSK),
            confirm: Ok(()),
            hang: true,
        });
        renew_slot(&backend, &current, hanging, &sink()).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(dry.rekeyed_psks().last(), Some(&secret(OLD_PSK)));
}

#[tokio::test]
async fn a_renewal_outcome_never_overwrites_a_newer_receipt() {
    let (_dry, _backend, current) = mounted().await;
    let newer = InstalledNegotiation::new([8; 16], profile(), current.data_plane.duplicate(), None);
    let mut slot = Some(newer);
    let renewed =
        InstalledNegotiation::new([9; 16], profile(), current.data_plane.duplicate(), None);
    settle_renewal(&mut slot, [7; 16], Ok(renewed), &sink());
    assert_eq!(
        slot.unwrap().transaction_id,
        [8; 16],
        "a reconnection owns the slot now"
    );
}

#[tokio::test]
async fn a_failed_renewal_schedules_the_next_attempt() {
    let (_dry, _backend, current) = mounted().await;
    let mut slot = Some(current);
    settle_renewal(&mut slot, [7; 16], Err(anyhow::anyhow!("refused")), &sink());
    let receipt = slot.unwrap();
    assert_eq!(receipt.failures, 1);
    assert!(receipt
        .next_attempt
        .is_some_and(|at| at > std::time::Instant::now()));
}

#[tokio::test]
async fn nothing_is_renewed_before_the_threshold_or_without_a_tunnel() {
    let (dry, _backend, receipt) = mounted().await;
    let ctrl = VpnController::new(dry.clone());
    *ctrl.installed.lock().await = Some(receipt);
    ctrl.poll_renewal(sink()).await; // state is Down
    *ctrl.state.write().unwrap() = TunnelState::Up;
    ctrl.poll_renewal(sink()).await; // fresh receipt
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(dry.rekeyed_psks().is_empty());
    assert!(!ctrl.renewing.load(Ordering::SeqCst));

    *ctrl.state.write().unwrap() = TunnelState::Down;
    assert!(
        ctrl.renew_now(sink()).await.is_err(),
        "no tunnel up: nothing to renew"
    );
}
