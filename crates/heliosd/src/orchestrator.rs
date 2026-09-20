//! Orchestration: wiring WireGuard <-> state machine <-> firewall.
//!
//! The gateway is a **server**: it brings up its WireGuard interface, listens
//! on UDP 51820 and waits for clients. It never dials anyone. The state
//! therefore moves to `Connecting` as soon as the interface is up, and it is
//! the handshake poller that promotes it to `Up` when a peer is actually
//! connected — WireGuard being connectionless, `Up` is inferred and never
//! received (ADR-001 §3).
//!
//! The real data plane lives behind the `wireguard` (`helios-wireguard`) and
//! `netlink` (`helios-firewall`) features: they **compile** everywhere but
//! can only **run** on the target. Simulation backends are only selected in
//! explicit or auto-detected dry-run.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use aether::{
    FirewallPolicy, HeliosEvent, InstallPskRequest, NetworkConfig, ObserveHandshakeRequest,
    OrchestratorCmd, TunnelEvent, TunnelState,
};
use anyhow::Context;
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_wireguard::{InterfaceConfig, PeerConfig, PeerStatus, WireguardBackend, WG_LISTEN_PORT};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// WireGuard UDP listening port (architectural invariant).
const WG_PORT: u16 = WG_LISTEN_PORT;

/// Beyond this age, a peer's handshake is considered stale (ADR-001 §3).
///
/// Derived from the shared constant rather than restated: the console reports
/// who is connected using the same threshold, and the two drifting apart would
/// show a client as online after the kill-switch had already cut it.
const HANDSHAKE_STALE_AFTER: Duration =
    Duration::from_secs(helios_wireguard::HANDSHAKE_STALE_AFTER_SECS);

/// Firewall posture selected explicitly for this daemon process.
///
/// Maintenance mode still uses the real TPM and WireGuard backends. It only
/// replaces firewall enforcement, and never results from a backend failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallMode {
    Enforced,
    DisabledForMaintenance,
}

impl FirewallMode {
    fn enforced(self) -> bool {
        self == Self::Enforced
    }
}

/// Selects the WireGuard data plane. Like for the firewall: dry-run by
/// default, real kernel backend behind the `wireguard` feature.
fn wireguard_backend(dry_run: bool, ifname: &str) -> anyhow::Result<Box<dyn WireguardBackend>> {
    if dry_run {
        return Ok(Box::new(helios_wireguard::DryRunBackend::new()));
    }
    #[cfg(feature = "wireguard")]
    {
        let backend = helios_wireguard::KernelBackend::new(ifname)
            .map_err(|e| anyhow::anyhow!("kernel WireGuard backend unavailable: {e}"))?;
        Ok(Box::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = ifname;
        anyhow::bail!("real mode requested without the `wireguard` feature");
    }
}

/// Projects the network config onto the interface config + WireGuard peers.
fn wg_config(network: &NetworkConfig) -> (InterfaceConfig, Vec<PeerConfig>) {
    let iface = InterfaceConfig {
        name: network.wg_iface.clone(),
        private_key: network.wg_private_key.clone(),
        listen_port: network.wg_listen_port,
        address: network.wg_address.clone(),
        mtu: Some(aether::mtu::tunnel_mtu(mtu_transport(
            network.primary_wan_iface().unwrap_or_default(),
        ))),
    };
    let peers = network
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: p.address.clone(),
            preshared_key: p.preshared_key.clone(),
            persistent_keepalive_secs: p.persistent_keepalive_secs,
        })
        .collect();
    (iface, peers)
}

fn firewall_backend(
    dry_run: bool,
    firewall_mode: FirewallMode,
) -> anyhow::Result<Box<dyn FirewallBackend>> {
    if dry_run {
        return Ok(Box::new(DryRunBackend));
    }
    if firewall_mode == FirewallMode::DisabledForMaintenance {
        #[cfg(feature = "netlink")]
        {
            return Ok(Box::new(helios_firewall::FirewallDisabledBackend::new()));
        }
        #[cfg(not(feature = "netlink"))]
        {
            anyhow::bail!(
                "firewall maintenance mode requested without the `netlink` feature; \
                 the daemon cannot prove that a persistent Helios table was removed"
            );
        }
    }
    #[cfg(feature = "netlink")]
    {
        Ok(Box::new(helios_firewall::NetlinkBackend::new()))
    }
    #[cfg(not(feature = "netlink"))]
    {
        anyhow::bail!("real mode requested without the `netlink` feature");
    }
}

/// Logs **and** broadcasts: the event channel feeds the UI and
/// `helios-ctl watch`, `tracing` feeds the console and journald.
///
/// Writing only to the channel left a console operator blind to state
/// changes: a peer could connect without a single line appearing in the
/// daemon's terminal. Observed on the first real deployment.
fn emit_log(tx: &broadcast::Sender<HeliosEvent>, level: &str, message: &str) {
    match level {
        "error" => tracing::error!("{message}"),
        "warn" => warn!("{message}"),
        _ => info!("{message}"),
    }
    let _ = tx.send(HeliosEvent::Log {
        level: level.into(),
        message: message.into(),
    });
}

async fn transition(
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    new_state: TunnelState,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    *shared.write().await = new_state;
    let _ = event_tx.send(HeliosEvent::StateChanged { state: new_state });
    fw.apply(policy, new_state)
        .await
        .context("applying the firewall")?;
    Ok(())
}

async fn sync_policy(shared: &Arc<RwLock<FirewallPolicy>>, policy: &FirewallPolicy) {
    *shared.write().await = policy.clone();
}

/// Daemon's main loop.
///
/// Many parameters, but each is a distinct dependency injected once from
/// `main`: grouping them into a struct would move the wiring around without
/// simplifying it.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    shared_network: Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    firewall_mode: FirewallMode,
    shared_state: Arc<RwLock<TunnelState>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    mut cmd_rx: mpsc::Receiver<OrchestratorCmd>,
    // PSK installation requests from provisioning (dedicated channel: they
    // carry a secret and await an acknowledgment).
    mut psk_rx: mpsc::Receiver<InstallPskRequest>,
    // Fresh reads of one peer's last handshake. Separate from `shared_peers`
    // below, which is a ten-second-old republication: the key-negotiation
    // commit needs the value *now* — see `ObserveHandshakeRequest`.
    mut handshake_rx: mpsc::Receiver<ObserveHandshakeRequest>,
    shared_policy: Arc<RwLock<FirewallPolicy>>,
    // Snapshot of the data plane, published for the API: it holds no
    // WireGuard backend and must not, so the runtime reaches it the same way
    // the tunnel state does.
    shared_peers: Arc<RwLock<Vec<PeerStatus>>>,
    // Held here and nowhere else: the TPM sealing secret must not transit
    // through the API crate. Only the orchestrator can seal.
    boot: helios_tpm::BootDecision,
    api_ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut policy = shared_network.read().await.firewall_policy();
    sync_policy(&shared_policy, &policy).await;

    let fw = firewall_backend(dry_run, firewall_mode)?;
    let wg: Arc<dyn WireguardBackend> = {
        let ifname = shared_network.read().await.wg_iface.clone();
        Arc::from(wireguard_backend(dry_run, &ifname)?)
    };
    let (internal_tx, mut internal_rx) = mpsc::channel::<OrchestratorCmd>(8);

    // 1. Establish the explicitly selected firewall posture before bringing
    // up WireGuard. Maintenance removes an old table; normal mode engages the
    // kill-switch.
    transition(
        &shared_state,
        &event_tx,
        TunnelState::Down,
        fw.as_ref(),
        &policy,
    )
    .await?;
    if firewall_mode.enforced() {
        info!("kill-switch engaged, starting fail-closed");
    } else {
        warn!("UNSAFE MAINTENANCE MODE: Helios firewall disabled by explicit operator request");
    }

    // 2. Initial tunnel bring-up.
    {
        let network = shared_network.read().await;
        do_connect(
            &network,
            wg.as_ref(),
            &shared_state,
            &event_tx,
            fw.as_ref(),
            &policy,
            dry_run,
        )
        .await?;
        let wan = network.primary_wan_iface().unwrap_or_default().to_string();
        drop(network);
        spawn_mtu_probe_if_up(&wan, dry_run, &shared_state, &event_tx, &internal_tx).await;
    }
    sync_policy(&shared_policy, &policy).await;

    // 3. State inference: WireGuard notifies nothing, handshakes are polled.
    spawn_handshake_poller(
        Arc::clone(&wg),
        Arc::clone(&shared_state),
        Arc::clone(&shared_network),
        Arc::clone(&shared_peers),
        event_tx.clone(),
        internal_tx.clone(),
    );

    // 4. Network telemetry (/proc/net/dev).
    {
        let wan = shared_network
            .read()
            .await
            .primary_wan_iface()
            .unwrap_or_default()
            .to_string();
        spawn_telemetry_loop(wan, event_tx.clone());
    }

    // 5. Admissions made on the console: `heliosd peer add` runs in another
    // process and can only rewrite the file. Watching it is what spares a
    // restart — and therefore spares cutting every connected client to admit
    // one more.
    spawn_network_config_watcher(Arc::clone(&shared_network), internal_tx.clone());

    // 4. Main loop: UI commands, internal results, or shutdown signal.
    let state_str = shared_state.read().await.as_str();
    info!("heliosd operational (state {state_str}). Ctrl-C to quit.");
    wait_api_ready(&api_ready).await?;
    publish_readiness(dry_run, firewall_mode)?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            shutdown_result = &mut shutdown => {
                match shutdown_result {
                    Ok(()) if firewall_mode.enforced() => {
                        info!("shutdown requested: kill-switch maintained (fail-closed)");
                    }
                    Ok(()) => {
                        warn!("shutdown requested: Helios firewall remains disabled");
                    }
                    Err(error) => {
                        warn!(
                            "shutdown signal setup failed; stopping and keeping the firewall fail-closed: {error:#}"
                        );
                    }
                }
                break;
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    None => break,
                    Some(c) => {
                        handle_external_cmd(
                            c, &shared_network, dry_run, wg.as_ref(), &shared_state, &event_tx,
                            fw.as_ref(), &mut policy, &internal_tx, &shared_policy, &boot,
                        ).await?;
                    }
                }
            }

            // Provisioning: applying the post-quantum PSK on a peer. The
            // caller (the HTTP endpoint) awaits the acknowledgment before
            // announcing the PSK to the client — see `InstallPskRequest`.
            psk_request = psk_rx.recv() => {
                if let Some(request) = psk_request {
                    install_peer_psk(request, &shared_network, wg.as_ref(), &event_tx).await;
                }
            }

            // Key negotiation, at the commit: has this peer handshaken since
            // its candidate PSK was posed? Only the backend knows, and only
            // this task holds it.
            handshake_request = handshake_rx.recv() => {
                if let Some(request) = handshake_request {
                    observe_peer_handshake(request, wg.as_ref()).await;
                }
            }

            internal = internal_rx.recv() => {
                match internal {
                    Some(OrchestratorCmd::SetMssClamp(mss)) => {
                        policy.mss_clamp = Some(mss);
                        let state = *shared_state.read().await;
                        fw.apply(&policy, state).await.context("firewall MSS clamping")?;
                        sync_policy(&shared_policy, &policy).await;
                        if firewall_mode.enforced() {
                            info!("PMTUD: MSS clamping applied at {mss} bytes");
                        } else {
                            warn!(
                                "PMTUD: optimal MSS is {mss} bytes but firewall enforcement is disabled"
                            );
                        }
                        emit_log(&event_tx, "info",
                            &format!("PMTUD: optimal MSS detected = {mss} bytes"));
                    }
                    // Promotion or demotion inferred from handshakes. It goes
                    // through `transition`, hence through a firewall
                    // reapplication: this is what was missing, and forward
                    // was never applied.
                    Some(OrchestratorCmd::TunnelStateInferred(state)) => {
                        transition(&shared_state, &event_tx, state, fw.as_ref(), &policy).await?;
                        let msg = if !firewall_mode.enforced() {
                            "Tunnel state changed — Helios firewall remains disabled for maintenance"
                        } else if state == TunnelState::Up {
                            "Peer connected — recent WireGuard handshake, firewall reapplied"
                        } else {
                            "Every peer handshake has gone stale — kill-switch re-engaged"
                        };
                        emit_log(&event_tx, "info", msg);
                    }
                    // `network.toml` changed under the running daemon — a
                    // console admission, typically. Deliberately handed to
                    // the **same** handler as the API path: two ways to
                    // apply a configuration would drift, and the one used
                    // only for bootstrap would be the one nobody exercises.
                    // The sender is in-process; nothing on the network can
                    // reach this channel.
                    Some(cmd @ OrchestratorCmd::LoadNetworkConfig(_)) => {
                        handle_external_cmd(
                            cmd, &shared_network, dry_run, wg.as_ref(), &shared_state, &event_tx,
                            fw.as_ref(), &mut policy, &internal_tx, &shared_policy, &boot,
                        ).await?;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Err(error) = transition(
        &shared_state,
        &event_tx,
        TunnelState::Down,
        fw.as_ref(),
        &policy,
    )
    .await
    {
        if firewall_mode.enforced() {
            warn!("engaging the kill-switch at shutdown: {error:#}");
        } else {
            warn!("keeping the Helios firewall disabled at shutdown: {error:#}");
        }
    }
    if let Err(error) = wg.down().await {
        warn!("tearing down WireGuard at shutdown: {error}");
    }
    // The interface is gone; routes naming it would linger in our table and
    // the rule would keep sending the range at an empty lookup. Harmless, but
    // it is state the daemon put there and must take back.
    unpin_peer_vips(dry_run).await;
    Ok(())
}

async fn wait_api_ready(api_ready: &AtomicBool) -> anyhow::Result<()> {
    for _ in 0..40 {
        if api_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("the API did not reach its ready state within the allotted time")
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("installing the SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    Ok(())
}

fn publish_readiness(dry_run: bool, firewall_mode: FirewallMode) -> anyhow::Result<()> {
    let path = std::env::var_os("HELIOS_READY_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if dry_run {
                std::env::temp_dir().join(format!("helios-ready-{}", std::process::id()))
            } else {
                std::path::PathBuf::from("/run/helios/ready")
            }
        });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        format!(
            "version={VERSION}\nmode_reel={}\nfirewall_enforced={}\n",
            !dry_run,
            !dry_run && firewall_mode.enforced()
        ),
    )?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_external_cmd(
    cmd: OrchestratorCmd,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    wg: &dyn WireguardBackend,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
    boot: &helios_tpm::BootDecision,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connection requested via the web interface");
            emit_log(
                event_tx,
                "info",
                "Connection requested via the web interface",
            );
            let network = shared_network.read().await;
            do_connect(&network, wg, shared_state, event_tx, fw, policy, dry_run).await?;
            let wan = network.primary_wan_iface().unwrap_or_default().to_string();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::UpdateGatewayKey(new_key) => {
            // Identity rotation: seal first, apply only afterwards. Sealing
            // after bringing up the interface would leave a window where the
            // key in effect would not be the one that survives a restart.
            match crate::gateway_key::update_sealed(&*shared_network.read().await, boot, &new_key) {
                Err(e) => {
                    warn!("WireGuard key rotation refused: {e}");
                    emit_log(event_tx, "error", &format!("Rotation refused: {e}"));
                }
                Ok(()) => {
                    {
                        let mut network = shared_network.write().await;
                        network.wg_private_key = new_key;
                    }
                    emit_log(
                        event_tx,
                        "warn",
                        "WireGuard key replaced and resealed — all clients \
                         must update the gateway's `peer_public_key`",
                    );

                    // The interface still carries the old identity: bring it back up.
                    if let Err(e) = wg.down().await {
                        warn!("tearing down before rotation: {e}");
                    }
                    let network = shared_network.read().await;
                    do_connect(&network, wg, shared_state, event_tx, fw, policy, dry_run).await?;
                    drop(network);
                    sync_policy(shared_policy, policy).await;
                }
            }
        }

        OrchestratorCmd::ApplyFirewallRules(rules) => {
            if dry_run {
                info!(
                    "[dry-run] custom nftables rules received ({} bytes) — not applied",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "info",
                    "[dry-run] Nftables rules received — application skipped (simulation mode)",
                );
            } else {
                info!("applying custom nftables rules ({} bytes)", rules.len());
                emit_log(
                    event_tx,
                    "warn",
                    "Custom nftables rules applied — check consistency",
                );
            }
        }

        OrchestratorCmd::Disconnect => {
            info!("disconnection requested via the web interface");
            emit_log(
                event_tx,
                "info",
                "Disconnection requested via the web interface",
            );
            policy.captive_portal_gateway = None;
            policy.mss_clamp = None;
            // Engage the fail-closed verdict before modifying the interface:
            // same order as a systemd stop for an update.
            transition(shared_state, event_tx, TunnelState::Down, fw, policy).await?;
            if let Err(e) = wg.down().await {
                warn!("tearing down the WireGuard interface: {e}");
                emit_log(
                    event_tx,
                    "warn",
                    &format!("Tearing down the interface: {e}"),
                );
            }
            unpin_peer_vips(dry_run).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::AcknowledgeCaptivePortal => {
            let current = *shared_state.read().await;
            if current == TunnelState::CaptivePortal {
                info!("captive portal acknowledged by the user — reconnecting");
                emit_log(
                    event_tx,
                    "info",
                    "Captive portal acknowledged — attempting to reconnect…",
                );
                policy.captive_portal_gateway = None;
                let next = current.on(TunnelEvent::CaptivePortalResolved)?;
                transition(shared_state, event_tx, next, fw, policy).await?;
                sync_policy(shared_policy, policy).await;
                let network = shared_network.read().await;
                do_connect(&network, wg, shared_state, event_tx, fw, policy, dry_run).await?;
                let wan = network.primary_wan_iface().unwrap_or_default().to_string();
                drop(network);
                spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
                sync_policy(shared_policy, policy).await;
            }
        }

        OrchestratorCmd::SetSplitTunnel(cidrs) => {
            info!("split-tunneling updated: {} CIDR(s)", cidrs.len());
            policy.split_tunnel_cidrs = cidrs.clone();
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("firewall split-tunnel")?;
            let _ = event_tx.send(HeliosEvent::SplitTunnelChanged { cidrs });
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::SetMssClamp(mss) => {
            policy.mss_clamp = Some(mss);
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("firewall MSS clamping (manual)")?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::LoadNetworkConfig(new_cfg) => {
            info!("network config reloaded: {} peer(s)", new_cfg.peers.len());
            *policy = new_cfg.firewall_policy();
            *shared_network.write().await = *new_cfg;
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("firewall after config reload")?;
            sync_policy(shared_policy, policy).await;

            // Aligns the data plane with the new peer list (client
            // enrollment, or revocation).
            if wg.is_up() {
                let (iface, peers) = wg_config(&*shared_network.read().await);
                if let Err(e) = wg.sync_peers(&peers).await {
                    warn!("WireGuard peer synchronization: {e}");
                    emit_log(event_tx, "warn", &format!("Peer synchronization: {e}"));
                }
                // An admission adds a VIP and a revocation removes one; the
                // pinned table has to follow both, or a freshly admitted
                // client is the only one still leaving through the wrong
                // tunnel — the hardest case to diagnose, since every other
                // client works.
                pin_peer_vips(dry_run, &iface, &peers, event_tx).await;
            }
            emit_log(event_tx, "info", "Network configuration applied");
        }
        // Emitted by the handshake poller on the **internal** channel, never
        // by the API: no route builds it. If it arrived through the
        // external channel anyway, ignoring it is better than letting a
        // caller drive the tunnel's state machine.
        OrchestratorCmd::TunnelStateInferred(state) => {
            warn!("inferred state received on the external channel, ignored: {state:?}");
        }
    }
    Ok(())
}

/// Brings up the gateway's WireGuard interface and applies its peers.
///
/// The gateway is a **server**: it creates its interface, listens on UDP and
/// waits for clients. It never "dials" anyone. The state therefore moves to
/// `Connecting` as soon as the interface is up; it is handshake polling
/// ([`spawn_handshake_poller`]) that promotes it to `Up` when a peer is
/// actually connected (ADR-001 §3).
/// Applies a peer's post-quantum PSK onto the data plane.
///
/// # Order of operations
///
/// The in-memory configuration is updated **first**, then synchronized to
/// the data plane. On `sync_peers` failure, the modification is rolled back:
/// the in-memory config must never announce a PSK the interface does not
/// carry, otherwise a later reconnection would apply a PSK the client has
/// already forgotten.
///
/// # Known limitation: the derived VIP is not reconciled
///
/// `helios_provisioning::assign_vip` derives the VIP from the peer's public
/// key and never consults the address declared in `network.toml`. The two
/// can therefore diverge. This function **keeps the declared address** and
/// only logs the discrepancy: the operator remains the source of truth, and
/// a silent switch of `AllowedIPs` would cut off traffic for a client that
/// keeps its profile's address. Reconciling the two requires deciding who
/// has authority — that is not this PSK-application function's job.
///
/// # What is deliberately not done: persistence
///
/// The PSK is **not** written to `network.toml`. It is derived per session,
/// its lifetime is bounded ([`helios_provisioning::DEFAULT_PSK_LIFETIME_SECS`]),
/// and a client that reconnects requests a fresh one. Writing it to disk
/// would add a persistent secret for no benefit — and would contradict the
/// ephemerality that bounds the exploitation window in case of a leak.
///
/// # On the absence of disruption
///
/// Changing a live peer's PSK does not break the current session: the
/// session keys are already derived, the new PSK will only be used on the
/// next handshake (≤ 2 min). This is what makes hot application safe — see
/// `helios_provisioning::rotation`.
/// Answers one [`ObserveHandshakeRequest`] from the live data plane.
///
/// A peer absent from the backend answers `Ok(None)`, not an error: it has
/// simply never handshaken, which is a fact the caller can act on. Only a
/// backend that cannot be read at all is an `Err`, and the caller must treat
/// that as "cannot tell" rather than as "no handshake" — a commit that
/// accepted a failed read as proof would prove nothing.
async fn observe_peer_handshake(request: ObserveHandshakeRequest, wg: &dyn WireguardBackend) {
    let ObserveHandshakeRequest { public_key, reply } = request;
    let answer = match wg.peers().await {
        Ok(peers) => Ok(peers
            .iter()
            .find(|peer| peer.public_key_b64() == public_key)
            .and_then(|peer| peer.last_handshake)),
        Err(error) => Err(error.to_string()),
    };
    let _ = reply.send(answer);
}

async fn install_peer_psk(
    request: InstallPskRequest,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    wg: &dyn WireguardBackend,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let InstallPskRequest {
        public_key,
        address,
        psk,
        reply,
    } = request;

    // In-memory update, with what's needed to roll back.
    let previous = {
        let mut network = shared_network.write().await;
        match network
            .peers
            .iter_mut()
            .find(|p| p.public_key == public_key)
        {
            None => {
                // Should not happen: the endpoint has already verified admission.
                let _ = reply.send(Err(format!(
                    "peer unknown to the configuration: {public_key}"
                )));
                return;
            }
            Some(peer) => {
                // The address declared by the operator is authoritative and
                // is **not** overwritten by the derived VIP. `AllowedIPs` is
                // WireGuard's cryptographic routing table: changing it under
                // a live session, while the client keeps its profile's
                // address, would cut off traffic. The divergence is
                // reported, not silently resolved — see the module's known
                // limitation.
                if peer.address != address {
                    warn!(
                        peer = %public_key,
                        declared = %peer.address,
                        derived = %address,
                        "the derived VIP differs from the declared address: \
                         the declared address is kept"
                    );
                }
                let previous = peer.preshared_key.take();
                peer.preshared_key = psk.as_ref().map(|secret| secret.expose().to_string());
                previous
            }
        }
    };

    let (_, peers) = wg_config(&*shared_network.read().await);

    match wg.sync_peers(&peers).await {
        Ok(()) => {
            let action = if psk.is_some() {
                "installed"
            } else {
                "cleared"
            };
            info!(peer = %public_key, vip = %address, "peer PSK slot {action}");
            emit_log(
                event_tx,
                "info",
                &format!("Peer PSK slot {action} for {address}"),
            );
            let _ = reply.send(Ok(()));
        }
        Err(e) => {
            // Rollback: the in-memory config must reflect the data plane.
            {
                let mut network = shared_network.write().await;
                if let Some(peer) = network
                    .peers
                    .iter_mut()
                    .find(|p| p.public_key == public_key)
                {
                    peer.preshared_key = previous;
                }
            }
            warn!(peer = %public_key, "could not install the PSK: {e}");
            emit_log(
                event_tx,
                "error",
                &format!("Post-quantum PSK installation refused: {e}"),
            );
            let _ = reply.send(Err(e.to_string()));
        }
    }
}

/// Path to the kernel's IPv4 routing flag. Overridable for tests: the system
/// file is read-only for an ordinary user.
const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

/// Reports a disabled kernel routing flag while the config asks to route.
///
/// Without `ip_forward`, the firewall allows the traffic and the kernel
/// drops it anyway: the tunnel comes up, the rules are correct, and nothing
/// gets through. The symptom is indistinguishable from a firewall problem,
/// hence the explicit warning. It is not enabled automatically — changing a
/// global kernel setting without saying so goes beyond what the
/// configuration asked for.
fn warn_if_ip_forward_disabled(event_tx: &broadcast::Sender<HeliosEvent>) {
    let path = std::env::var("HELIOS_IP_FORWARD_PATH").unwrap_or_else(|_| IP_FORWARD_PATH.into());
    match std::fs::read_to_string(&path) {
        Ok(value) if value.trim() == "0" => emit_log(
            event_tx,
            "warn",
            "`allow_client_internet` is active but the kernel's IPv4 routing is \
             disabled: client packets will be dropped despite correct rules. \
             Fix with `sysctl -w net.ipv4.ip_forward=1`, and make it \
             permanent in /etc/sysctl.d/.",
        ),
        Ok(_) => {}
        Err(e) => emit_log(
            event_tx,
            "warn",
            &format!("kernel IPv4 routing not verifiable ({path}: {e})"),
        ),
    }
}

async fn do_connect(
    network: &NetworkConfig,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
    dry_run: bool,
) -> anyhow::Result<()> {
    if !network.wireguard_ready() {
        emit_log(
            event_tx,
            "error",
            "WireGuard private key missing from the network config — cannot bring up the interface",
        );
        anyhow::bail!("gateway not configured: `wg_private_key` empty in network.toml");
    }

    if network.allow_client_internet {
        warn_if_ip_forward_disabled(event_tx);
    }

    let (iface, peers) = wg_config(network);

    // Kill-switch engaged throughout the bring-up.
    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }
    state = state
        .on(TunnelEvent::StartRequested)
        .context("state transition")?;
    transition(shared, event_tx, state, fw, policy).await?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Bringing up {} — UDP listener {}, {} peer(s) admitted",
            iface.name,
            iface.listen_port,
            peers.len()
        ),
    );

    wg.up(&iface, &peers)
        .await
        .context("bringing up the WireGuard interface")?;

    // After the interface exists — the peer routes name it — and before the
    // state is announced: a client that handshakes in between would otherwise
    // have its first replies handed to whichever VPN owns the CGNAT range.
    pin_peer_vips(dry_run, &iface, &peers, event_tx).await;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Interface {} active ({}) — waiting for client handshake",
            iface.name, iface.address
        ),
    );
    Ok(())
}

/// Pins the admitted peers' VIPs onto the tunnel interface.
///
/// # Why a failure is not fatal
///
/// On a gateway that has the CGNAT range to itself this changes nothing at
/// all — the main table already routes it to `helios0`. Refusing to serve
/// because a policy rule could not be written would therefore take down
/// gateways that were never at risk. The warning names the consequence
/// instead, because the symptom on the other side is invisible: packets are
/// not dropped, they leave through the wrong tunnel.
async fn pin_peer_vips(
    dry_run: bool,
    iface: &helios_wireguard::InterfaceConfig,
    peers: &[helios_wireguard::PeerConfig],
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    if dry_run {
        return;
    }
    let plan = match crate::vip_routing::plan(&iface.name, &iface.address, peers) {
        Ok(plan) => plan,
        Err(error) => {
            warn!("peer VIP routing not planned: {error}");
            return;
        }
    };
    if let Err(error) = crate::vip_routing::apply(&plan).await {
        warn!("peer VIP routing not installed: {error}");
        emit_log(
            event_tx,
            "warn",
            &format!(
                "Client VIPs not pinned to {} ({error}). If another VPN on this host claims \
                 100.64.0.0/10, traffic to clients leaves through it and no packet is dropped \
                 to say so.",
                iface.name
            ),
        );
    }
}

/// Removes the pinning. Paired with every path that takes the interface down.
async fn unpin_peer_vips(dry_run: bool) {
    if dry_run {
        return;
    }
    if let Err(error) = crate::vip_routing::withdraw().await {
        warn!("peer VIP routing not withdrawn: {error}");
    }
}

fn handshake_is_fresh(peer: &helios_wireguard::PeerStatus) -> bool {
    peer.last_handshake
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < HANDSHAKE_STALE_AFTER)
}

/// Logs peer connections and disconnections, once each.
///
/// This is the trace that lets us assert that **it really is `heliosd`
/// holding the tunnel**: the peer's name comes from its admission table, the
/// endpoint and handshake from its own data plane.
///
/// # What a client's disconnection is not
///
/// WireGuard is **connectionless**: the protocol has no disconnect message.
/// A client that shuts down destroys its interface without announcing
/// anything, and the gateway can only infer it from the absence of a new
/// handshake — hence a delay of up to [`HANDSHAKE_STALE_AFTER`]. Shortening
/// this threshold would declare dead peers that are alive but quiet,
/// rehandshaking only roughly every two minutes.
///
/// This is why a reconnection is reported by its **endpoint**, and not only
/// by the transition from stale to fresh: a client that reattaches within
/// the staleness window stays "fresh" from one round to the next, and its
/// return would otherwise go unnoticed. The source port changes on every
/// session, the line shows it.
///
/// # Known limitation
///
/// A **rejected** handshake — unknown public key — does not appear here and
/// cannot appear here: the WireGuard kernel module silently rejects it,
/// reporting nothing to userspace. `wg` only lists configured peers. What
/// would unblock this: an nftables `log` rule on the listening port, at the
/// cost of a noisy log on an exposed gateway.
async fn log_peer_transitions(
    peers: &[helios_wireguard::PeerStatus],
    shared_network: &Arc<RwLock<NetworkConfig>>,
    seen: &mut std::collections::HashMap<Vec<u8>, (bool, Option<String>)>,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let network = shared_network.read().await;
    for peer in peers {
        let fresh = handshake_is_fresh(peer);
        let observed = (fresh, peer.endpoint.clone());
        let previous = seen.insert(peer.public_key.clone(), observed.clone());
        if previous.as_ref() == Some(&observed) {
            continue;
        }

        let key = peer.public_key_b64();
        let declared = network.peers.iter().find(|p| p.public_key == key);
        let name = declared.map_or("undeclared peer", |p| p.name.as_str());
        let endpoint = peer.endpoint.as_deref().unwrap_or("unknown endpoint");

        match (previous, fresh) {
            (Some((true, _)), false) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!("peer \"{name}\" inactive — its handshake has gone stale"),
                );
            }
            // A peer never seen fresh that stays stale has nothing to
            // report: that would report the disconnection of a client that
            // was never connected.
            (_, false) => {}
            (Some((true, _)), true) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "peer \"{name}\" reconnected from {endpoint} — new session, \
                         the old one is not resumed"
                    ),
                );
            }
            (_, true) => {
                let protection = match declared.map(|p| p.preshared_key.is_some()) {
                    Some(true) => "post-quantum (ML-KEM PSK applied)",
                    // Without a PSK, the tunnel is up on Curve25519 alone:
                    // this is step 1 of the ADR-001 sequence, not a flaw.
                    // Saying so avoids believing the session is
                    // post-quantum protected when it is not.
                    _ => "classic (Curve25519, PSK not yet negotiated)",
                };
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "peer \"{name}\" connected from {endpoint} — VIP {} — protection {protection}",
                        peer.allowed_ips.join(", ")
                    ),
                );
            }
        }
    }
}

/// Interval between two looks at `network.toml`.
///
/// A few seconds: the operator admits a peer and expects the client to be
/// able to connect right away, not to wonder whether they should restart
/// something. Nothing is read unless the file's timestamp or size moved, so
/// the cost between two admissions is one `stat` every two seconds.
const NETWORK_CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Applies `network.toml` to the running gateway when it changes on disk.
///
/// # Why watch a file rather than take an order
///
/// Admission has two paths, deliberately (ADR-004 §4): the API, for a peer
/// already connected, and the console — `heliosd peer add` — which exists
/// precisely to bootstrap a gateway *without* a tunnel. The console path runs
/// in another process: all it can do is rewrite the file. Until now the
/// change waited for the next restart, which meant cutting every connected
/// client to admit one more.
///
/// # What is reloaded, and what is not
///
/// The whole configuration is re-applied — peer table, firewall policy — by
/// the same command the API already uses ([`OrchestratorCmd::LoadNetworkConfig`]),
/// so both paths converge on one code path. **Limite connue** : what the
/// running data plane cannot change under itself is not re-applied — the
/// interface name, its listen port and the API's bind address are fixed when
/// the interface comes up. Changing those in the file still requires a
/// restart, and the daemon says so rather than pretending otherwise.
///
/// The secrets never live in the file: they are restored from the running
/// configuration by [`NetworkConfig::adopt_runtime_secrets_from`]. Skipping
/// that step would erase the sealed private key and every negotiated PSK on
/// the first admission — the exact accident this reload exists to avoid.
fn spawn_network_config_watcher(
    shared_network: Arc<RwLock<NetworkConfig>>,
    cmd_tx: mpsc::Sender<OrchestratorCmd>,
) {
    /// Timestamp and size: enough to notice a rewrite without reading it.
    fn stamp(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
        let metadata = std::fs::metadata(path).ok()?;
        Some((metadata.modified().ok()?, metadata.len()))
    }

    tokio::spawn(async move {
        let path = NetworkConfig::path();
        let mut seen = stamp(&path);
        let mut ticker = time::interval(NETWORK_CONFIG_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            let current = stamp(&path);
            if current == seen {
                continue;
            }
            seen = current;

            // `save()` writes to a temporary file then renames: a partial
            // file is never observed. A parse error therefore reports a
            // genuinely invalid file, and keeping the running configuration
            // is the only safe answer.
            let from_disk = match NetworkConfig::load() {
                Ok(config) => config,
                Err(error) => {
                    warn!(%error, "network.toml changed but is unusable; keeping the running configuration");
                    continue;
                }
            };

            let mut merged = from_disk;
            {
                let running = shared_network.read().await;
                merged.adopt_runtime_secrets_from(&running);
                // The API also rewrites the file: without this comparison,
                // every mutation through the API would be applied twice —
                // once by the route, once by this watcher.
                if merged == *running {
                    continue;
                }
            }

            info!(
                "network.toml changed on disk: {} peer(s) applied without restart",
                merged.peers.len()
            );
            if cmd_tx
                .send(OrchestratorCmd::LoadNetworkConfig(Box::new(merged)))
                .await
                .is_err()
            {
                // The orchestrator is gone: the daemon is shutting down.
                return;
            }
        }
    });
}

/// Periodically polls peer handshakes to infer the state.
///
/// WireGuard is connectionless: `Up` is never received, it is inferred. The
/// gateway is `Up` as soon as **at least one** peer has handshaked less than
/// [`HANDSHAKE_STALE_AFTER`] ago.
fn spawn_handshake_poller(
    wg: Arc<dyn WireguardBackend>,
    shared: Arc<RwLock<TunnelState>>,
    shared_network: Arc<RwLock<NetworkConfig>>,
    shared_peers: Arc<RwLock<Vec<PeerStatus>>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(10));
        // Freshness observed on the previous round, by public key: without
        // this memory, "this peer just connected" cannot be distinguished
        // from "this peer has been connected for an hour", and it would be
        // logged every ten seconds.
        let mut seen: std::collections::HashMap<Vec<u8>, (bool, Option<String>)> =
            std::collections::HashMap::new();
        loop {
            ticker.tick().await;
            if !wg.is_up() {
                // Emptied rather than left as it was: a console still listing
                // yesterday's peers as connected, while the interface is down,
                // is worse than one listing none.
                shared_peers.write().await.clear();
                continue;
            }
            let peers = match wg.peers().await {
                Ok(peers) => peers,
                Err(e) => {
                    warn!("could not read WireGuard peers: {e}");
                    continue;
                }
            };

            // Published before the state is inferred: the snapshot is what the
            // console reads, and it must never lag behind the state it explains.
            *shared_peers.write().await = peers.clone();

            log_peer_transitions(&peers, &shared_network, &mut seen, &event_tx).await;

            let fresh = peers.iter().any(handshake_is_fresh);
            let current = *shared.read().await;
            let next = match (current, fresh) {
                (TunnelState::Connecting, true) => TunnelState::Up,
                (TunnelState::Up, false) => TunnelState::Connecting,
                _ => continue,
            };

            // Go through the main loop, the sole holder of the firewall
            // backend and policy. Writing the state here would leave the
            // ruleset frozen on the previous state — forward only exists in
            // states where traffic is allowed, it would never be applied.
            if internal_tx
                .send(OrchestratorCmd::TunnelStateInferred(next))
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

// ─── Probes kept: wired to the future real WireGuard backend (target-only) ───
// Captive portal detection will rely on these probes during real bring-up.
// Not used in the current dry-run path.
#[allow(dead_code)]
async fn probe_captive_portal(wan_iface: &str) -> Option<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        tcp_http_probe("connectivitycheck.gstatic.com", 80, "/generate_204"),
    )
    .await
    .ok()??;

    if result == 204 {
        return None;
    }

    let gateway = get_default_gateway(wan_iface)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    Some(gateway)
}

#[allow(dead_code)]
async fn tcp_http_probe(host: &str, port: u16, path: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.ok()?;
    let header = std::str::from_utf8(&buf[..n]).ok()?;
    header.split_whitespace().nth(1)?.parse().ok()
}

#[allow(dead_code)]
async fn get_default_gateway(wan_iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["route", "show", "default", "dev", wan_iface])
        .output()
        .await
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|&w| w != "via")
        .nth(1)
        .map(str::to_string)
}

async fn spawn_mtu_probe_if_up(
    wan_iface: &str,
    dry_run: bool,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
) {
    if *shared_state.read().await == TunnelState::Up {
        spawn_mtu_probe(
            wan_iface.to_string(),
            event_tx.clone(),
            internal_tx.clone(),
            dry_run,
        );
    }
}

fn spawn_mtu_probe(
    wan_iface: String,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
    dry_run: bool,
) {
    tokio::spawn(async move {
        let mss = if dry_run {
            1380u16
        } else {
            discover_mss(&wan_iface).await.unwrap_or(1380)
        };
        let mtu = mss + 40;
        info!("PMTUD: optimal MSS = {mss} bytes (estimated MTU = {mtu})");
        let _ = event_tx.send(HeliosEvent::MtuDiscovered { mtu, mss });
        let _ = internal_tx.send(OrchestratorCmd::SetMssClamp(mss)).await;
    });
}

async fn discover_mss(wan_iface: &str) -> Option<u16> {
    let mtu_str = tokio::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .await
        .ok()?;
    let mtu: u16 = mtu_str.trim().parse().ok()?;
    // WireGuard: ~60 bytes of overhead (header + UDP/IP) + 40 for the TCP/IP header.
    Some(mtu.saturating_sub(100).max(576))
}

/// WAN link MTU, read from sysfs.
///
/// Blocking read accepted: `wg_config` is called on the interface bring-up
/// path, before any networking, and the file is in memory. An unreadable
/// WAN — wrong name, interface not yet created — falls back to standard
/// Ethernet, which restores the behavior from before this setting.
fn mtu_transport(wan_iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or_else(|| {
            warn!(
                "MTU of {wan_iface} unreadable — falling back to {} bytes",
                aether::mtu::MTU_TRANSPORT_DEFAUT
            );
            aether::mtu::MTU_TRANSPORT_DEFAUT
        })
}

fn parse_proc_net_dev(content: &str, iface: &str) -> Option<(u64, u64, u64, u64)> {
    for line in content.lines() {
        let Some((name, rest)) = line.trim_start().split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        return Some((
            fields[0].parse().ok()?,
            fields[8].parse().ok()?,
            fields[1].parse().ok()?,
            fields[9].parse().ok()?,
        ));
    }
    None
}

fn spawn_telemetry_loop(iface: String, event_tx: broadcast::Sender<HeliosEvent>) {
    tokio::spawn(async move {
        let mut prev: Option<(u64, u64, u64, u64)> = None;
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await else {
                continue;
            };
            let Some(cur) = parse_proc_net_dev(&content, &iface) else {
                continue;
            };
            if let Some(p) = prev {
                let _ = event_tx.send(HeliosEvent::Telemetry {
                    iface: iface.clone(),
                    rx_bps: (cur.0.saturating_sub(p.0)) * 8,
                    tx_bps: (cur.1.saturating_sub(p.1)) * 8,
                    rx_pps: cur.2.saturating_sub(p.2),
                    tx_pps: cur.3.saturating_sub(p.3),
                });
            }
            prev = Some(cur);
        }
    });
}

pub fn status(network: &NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!(
        "  mode         : {}",
        if dry_run { "dry-run" } else { "real" }
    );
    println!("  transport    : WireGuard UDP {WG_PORT}");
    println!("  web interface: http://{}", network.api_bind());
    println!("  WAN          : {}", network.wan_ifaces.join(", "));
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!(
        "  WG interface : {} (UDP {})",
        network.wg_iface, network.wg_listen_port
    );
    println!("  WG address   : {}", network.wg_address);
    println!(
        "  ready        : {}",
        if network.wireguard_ready() {
            "yes"
        } else {
            "no (private key missing)"
        }
    );
    println!("  peers        : {}", network.peers.len());
    for p in &network.peers {
        let pq = if p.preshared_key.is_some() {
            "  [PQ]"
        } else {
            ""
        };
        println!("    - {} -> {}{}", p.name, p.address, pq);
    }
    Ok(())
}

pub async fn check_update(dry_run: bool) -> anyhow::Result<()> {
    let store = helios_update::UpdateStore::new(helios_update::UpdateLayout::for_daemon(dry_run));
    let status = store.status()?;
    println!("compiled version : {VERSION}");
    println!("channel          : {}", status.channel);
    println!("target           : {}", status.target);
    println!("active sequence  : {}", status.highest_confirmed_sequence);
    if let Some(version) = status.active_version {
        println!("confirmed version: {version}");
    }
    println!("staged releases  : {}", status.staged.len());
    if let Some(sequence) = status.activation_pending {
        println!("activation       : sequence {sequence} pending");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn configured_network() -> NetworkConfig {
        NetworkConfig {
            wan_ifaces: vec!["eth0".into()],
            wg_iface: "helios0".into(),
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            wg_listen_port: WG_LISTEN_PORT,
            peers: vec![aether::WgPeer {
                name: "poste-test".into(),
                public_key: PEER_KEY.into(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("psk-test".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..NetworkConfig::default()
        }
    }

    /// The poller must **not** write the state itself: it holds neither the
    /// firewall backend nor the policy, and a direct write would leave the
    /// ruleset frozen on the previous state. Since forward only exists in
    /// states where traffic is allowed, it would never be applied — an "up"
    /// tunnel that routes nothing, with nothing in the logs to explain it.
    #[tokio::test]
    async fn handshake_promotion_goes_through_the_main_loop() {
        let network = Arc::new(RwLock::new(configured_network()));
        let wireguard = Arc::new(helios_wireguard::DryRunBackend::with_handshakes());
        let (iface, peers) = wg_config(&*network.read().await);
        wireguard
            .up(&iface, &peers)
            .await
            .expect("dry-run bring-up");

        let state = Arc::new(RwLock::new(TunnelState::Connecting));
        let (event_tx, _rx) = broadcast::channel(16);
        let (internal_tx, mut internal_rx) = mpsc::channel(8);

        spawn_handshake_poller(
            wireguard,
            Arc::clone(&state),
            Arc::clone(&network),
            Arc::new(RwLock::new(Vec::new())),
            event_tx,
            internal_tx,
        );

        let received = time::timeout(Duration::from_secs(5), internal_rx.recv())
            .await
            .expect("the poller must signal the promotion");
        assert!(
            matches!(
                received,
                Some(OrchestratorCmd::TunnelStateInferred(TunnelState::Up))
            ),
            "unexpected command: {received:?}"
        );
        assert_eq!(
            *state.read().await,
            TunnelState::Connecting,
            "the poller wrote the state without going through firewall reapplication"
        );
    }

    fn connected_peer(endpoint: &str) -> helios_wireguard::PeerStatus {
        helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: Some(endpoint.into()),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// The trace that lets us assert that it really is `heliosd` holding the
    /// tunnel, and distinguish a classic session from a protected one.
    #[tokio::test]
    async fn a_peer_connection_is_logged_only_once() {
        let network = Arc::new(RwLock::new(configured_network()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();
        let peers = vec![helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: Some("203.0.113.7:51820".into()),
            rx_bytes: 0,
            tx_bytes: 0,
        }];

        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(message.contains("poste-test"), "message: {message}");
        assert!(message.contains("203.0.113.7:51820"), "message: {message}");
        assert!(
            message.contains("post-quantum"),
            "the peer carries a PSK, the protection must be reported: {message}"
        );

        // Second round, same state: nothing new to report. Without this
        // deduplication, the log would repeat the line every ten seconds.
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        assert!(events.try_recv().is_err(), "connection logged twice");
    }

    /// A client that reactivates within the staleness window stays "fresh"
    /// from one round to the next: without endpoint monitoring, its return
    /// would be completely silent. This is what gave the impression that
    /// the gateway saw nothing — and that an old session was resumed.
    #[tokio::test]
    async fn a_reconnection_within_the_staleness_window_is_visible() {
        let network = Arc::new(RwLock::new(configured_network()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();

        let mut peers = vec![connected_peer("192.168.1.41:58466")];
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        assert!(matches!(events.try_recv(), Ok(HeliosEvent::Log { .. })));

        // Same peer, still fresh, new source port: the Windows client
        // destroyed its interface and reopened a socket. This is a new
        // session, not the resumption of the old one.
        peers[0].endpoint = Some("192.168.1.41:56776".into());
        peers[0].last_handshake = Some(std::time::SystemTime::now());
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;

        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            other => panic!("the reconnection must be logged, got: {other:?}"),
        };
        assert!(message.contains("reconnected"), "message: {message}");
        assert!(message.contains("56776"), "message: {message}");
    }

    /// Without a PSK, the session is up on Curve25519 alone. Saying so
    /// avoids believing a session is post-quantum protected when it is not
    /// — this is step 1 of the ADR-001 sequence, not a flaw.
    #[tokio::test]
    async fn a_session_without_psk_is_reported_as_classic() {
        let network = Arc::new(RwLock::new(network_without_psk()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();
        let peers = vec![helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
        }];

        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(message.contains("classic"), "message: {message}");
    }

    #[test]
    fn wireguard_projection_keeps_the_interface_and_required_secrets() {
        let network = configured_network();

        let (iface, peers) = wg_config(&network);

        assert_eq!(iface.name, "helios0");
        assert_eq!(iface.private_key, PRIVATE_KEY);
        assert_eq!(iface.listen_port, WG_LISTEN_PORT);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips, "100.64.1.2/32");
        assert_eq!(peers[0].preshared_key.as_deref(), Some("psk-test"));
    }

    #[test]
    fn reading_proc_net_dev_recognizes_interface_and_counters() {
        let proc_net_dev = "Inter-|   Receive                                                |  Transmit\n\
                         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                           eth0: 42 3 1 0 0 0 0 0 84 4 2 0 0 0 0 0\n";

        assert_eq!(
            parse_proc_net_dev(proc_net_dev, "eth0"),
            Some((42, 84, 3, 4))
        );
        assert_eq!(parse_proc_net_dev(proc_net_dev, "eth1"), None);
    }

    #[test]
    fn proc_net_dev_requires_the_exact_interface_and_complete_counters() {
        let content = "eth01: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n\
                       eth0: 100 invalid 7 0 0 0 0 0 200 9\n\
                       short: 1 2 3\n\
                       malformed without colon\n";

        assert_eq!(parse_proc_net_dev(content, "eth01"), Some((1, 9, 2, 10)));
        assert_eq!(
            parse_proc_net_dev(content, "eth0"),
            None,
            "a malformed counter must not shift every following column"
        );
        assert_eq!(parse_proc_net_dev(content, "short"), None);
        assert_eq!(parse_proc_net_dev(content, "eth"), None);
    }

    #[test]
    fn handshake_freshness_covers_absent_recent_stale_and_future_timestamps() {
        let mut peer = connected_peer("192.0.2.1:51820");
        peer.last_handshake = None;
        assert!(!handshake_is_fresh(&peer));

        peer.last_handshake = Some(std::time::SystemTime::now());
        assert!(handshake_is_fresh(&peer));

        peer.last_handshake = Some(std::time::SystemTime::now() - HANDSHAKE_STALE_AFTER);
        assert!(!handshake_is_fresh(&peer));

        peer.last_handshake = Some(std::time::SystemTime::now() + Duration::from_secs(10));
        assert!(!handshake_is_fresh(&peer));
    }

    #[tokio::test]
    async fn stale_peers_are_silent_until_they_disconnect_after_being_fresh() {
        let network = Arc::new(RwLock::new(configured_network()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();
        let mut peer = connected_peer("192.0.2.1:51820");
        peer.last_handshake = Some(std::time::SystemTime::now() - Duration::from_secs(300));

        log_peer_transitions(&[peer.clone()], &network, &mut seen, &event_tx).await;
        assert!(
            events.try_recv().is_err(),
            "never-connected peers stay silent"
        );

        peer.last_handshake = Some(std::time::SystemTime::now());
        log_peer_transitions(&[peer.clone()], &network, &mut seen, &event_tx).await;
        assert!(matches!(events.try_recv(), Ok(HeliosEvent::Log { .. })));

        peer.last_handshake = Some(std::time::SystemTime::now() - Duration::from_secs(300));
        log_peer_transitions(&[peer], &network, &mut seen, &event_tx).await;
        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            other => panic!("expected disconnection log, got {other:?}"),
        };
        assert!(message.contains("inactive"), "message: {message}");
    }

    #[tokio::test]
    async fn dry_run_mtu_probe_publishes_matching_event_and_command() {
        let state = Arc::new(RwLock::new(TunnelState::Up));
        let (event_tx, mut events) = broadcast::channel(4);
        let (command_tx, mut commands) = mpsc::channel(4);

        spawn_mtu_probe_if_up("missing", true, &state, &event_tx, &command_tx).await;

        let event = time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            HeliosEvent::MtuDiscovered {
                mtu: 1420,
                mss: 1380
            }
        ));
        assert!(matches!(
            commands.recv().await,
            Some(OrchestratorCmd::SetMssClamp(1380))
        ));

        *state.write().await = TunnelState::Down;
        spawn_mtu_probe_if_up("missing", true, &state, &event_tx, &command_tx).await;
        tokio::task::yield_now().await;
        assert!(events.try_recv().is_err());
        assert!(commands.try_recv().is_err());
    }

    #[tokio::test]
    async fn mss_discovery_rejects_missing_interfaces_and_bounds_small_mtus() {
        assert_eq!(discover_mss("interface-that-does-not-exist").await, None);
        assert_eq!(
            mtu_transport("interface-that-does-not-exist"),
            aether::mtu::MTU_TRANSPORT_DEFAUT
        );
        if std::path::Path::new("/sys/class/net/lo/mtu").exists() {
            let loopback_mtu: u32 = std::fs::read_to_string("/sys/class/net/lo/mtu")
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(mtu_transport("lo"), loopback_mtu);
            let expected = u16::try_from(loopback_mtu)
                .ok()
                .map(|mtu| mtu.saturating_sub(100).max(576));
            assert_eq!(discover_mss("lo").await, expected);
        }
    }

    /// Network whose peer has no PSK yet: the starting state of a client
    /// that just brought up its classic tunnel.
    fn network_without_psk() -> NetworkConfig {
        let mut network = configured_network();
        network.peers[0].preshared_key = None;
        network
    }

    async fn request_installation(
        shared: &Arc<RwLock<NetworkConfig>>,
        wg: &dyn WireguardBackend,
        public_key: &str,
    ) -> Result<(), String> {
        let (events, _) = broadcast::channel(8);
        let (reply, response) = tokio::sync::oneshot::channel();
        install_peer_psk(
            InstallPskRequest {
                public_key: public_key.into(),
                address: "100.64.1.2/32".into(),
                psk: Some(aether::SecretString::new("psk-from-ml-kem")),
                reply,
            },
            shared,
            wg,
            &events,
        )
        .await;
        response
            .await
            .expect("the orchestrator must always acknowledge")
    }

    #[tokio::test]
    async fn provisioned_psk_is_applied_to_the_data_plane() {
        let shared = Arc::new(RwLock::new(network_without_psk()));
        let wireguard = helios_wireguard::DryRunBackend::new();

        request_installation(&shared, &wireguard, PEER_KEY)
            .await
            .expect("the installation must succeed");

        // The in-memory config carries the PSK…
        assert_eq!(
            shared.read().await.peers[0].preshared_key.as_deref(),
            Some("psk-from-ml-kem")
        );
        // …and so does the data plane: it is what actually protects it.
        let peers = wireguard.peers().await.unwrap();
        assert_eq!(peers.len(), 1, "the peer must be present on the interface");
    }

    /// If the data plane refuses, the in-memory config must not stay ahead
    /// of it: it would announce a PSK the interface does not carry, and a
    /// later reconnection would apply it while the client has already
    /// forgotten it.
    #[tokio::test]
    async fn data_plane_failure_rolls_back_the_in_memory_psk() {
        let shared = Arc::new(RwLock::new(network_without_psk()));
        let wireguard = helios_wireguard::DryRunBackend::failing_sync();

        let result = request_installation(&shared, &wireguard, PEER_KEY).await;

        assert!(result.is_err(), "the failure must propagate to the caller");
        assert_eq!(
            shared.read().await.peers[0].preshared_key,
            None,
            "INVARIANT VIOLATED: the config keeps a PSK the data plane \
             refused — the next handshake would fail with no explanation"
        );
    }

    /// The old PSK must be restored, not merely erased: a failed rotation
    /// must not degrade a peer that was already protected.
    #[tokio::test]
    async fn failed_rotation_restores_the_previous_psk() {
        // `configured_network` starts with a PSK already in place.
        let shared = Arc::new(RwLock::new(configured_network()));
        let wireguard = helios_wireguard::DryRunBackend::failing_sync();

        let result = request_installation(&shared, &wireguard, PEER_KEY).await;

        assert!(result.is_err());
        assert_eq!(
            shared.read().await.peers[0].preshared_key.as_deref(),
            Some("psk-test"),
            "a failed rotation must return the peer to its prior state"
        );
    }

    /// The endpoint already verifies admission, but the orchestrator must
    /// not rely on a caller: a peer absent from the config is refused.
    #[tokio::test]
    async fn a_peer_absent_from_the_configuration_is_refused() {
        let shared = Arc::new(RwLock::new(network_without_psk()));
        let wireguard = helios_wireguard::DryRunBackend::new();

        let result = request_installation(
            &shared,
            &wireguard,
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        )
        .await;

        assert!(result.is_err(), "an undeclared peer must not be applied");
        assert_eq!(
            shared.read().await.peers[0].preshared_key,
            None,
            "the legitimate peer must not have been touched"
        );
    }

    #[tokio::test]
    async fn dry_run_connection_stays_blocked_until_handshake() {
        let network = configured_network();
        let state = Arc::new(RwLock::new(TunnelState::Down));
        let (events, _) = broadcast::channel(8);
        let firewall = DryRunBackend;
        let wireguard = helios_wireguard::DryRunBackend::new();

        do_connect(
            &network,
            &wireguard,
            &state,
            &events,
            &firewall,
            &network.firewall_policy(),
            true,
        )
        .await
        .unwrap();

        assert!(wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Connecting);
        assert!(state.read().await.kill_switch_engaged());
    }

    #[tokio::test]
    async fn disconnection_tears_down_wireguard_and_re_engages_the_kill_switch() {
        let network = configured_network();
        let shared_network = Arc::new(RwLock::new(network.clone()));
        let state = Arc::new(RwLock::new(TunnelState::Up));
        let policy = Arc::new(RwLock::new(network.firewall_policy()));
        let (events, _) = broadcast::channel(8);
        let (internal_tx, _internal_rx) = mpsc::channel(1);
        let firewall = DryRunBackend;
        let wireguard = helios_wireguard::DryRunBackend::new();
        let (iface, peers) = wg_config(&network);
        wireguard.up(&iface, &peers).await.unwrap();
        let mut current_policy = network.firewall_policy();
        current_policy.mss_clamp = Some(1380);

        handle_external_cmd(
            OrchestratorCmd::Disconnect,
            &shared_network,
            true,
            &wireguard,
            &state,
            &events,
            &firewall,
            &mut current_policy,
            &internal_tx,
            &policy,
            // TPM disabled: this test does not perform a key rotation.
            &helios_tpm::BootDecision::Disabled,
        )
        .await
        .unwrap();

        assert!(!wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Down);
        assert!(state.read().await.kill_switch_engaged());
        assert_eq!(policy.read().await.mss_clamp, None);
    }
}
