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
    net::{Ipv6TunnelStatus, Ipv6Unavailable, TunnelPrefixV6},
    FirewallPolicy, HeliosEvent, InstallPskRequest, NetworkConfig, ObserveHandshakeRequest,
    OrchestratorCmd, TunnelEvent, TunnelState,
};
use anyhow::Context;
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_wireguard::{
    InterfaceConfig, PeerConfig, PeerStatus, WgError, WireguardBackend, WG_LISTEN_PORT,
};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

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

mod commands;
mod data_plane;
mod observation;
mod probes;
mod reload;
mod telemetry;

// What `run`, the sibling modules and the tests name of each other, through
// `use super::*`.
use self::{commands::*, data_plane::*, observation::*, probes::*, reload::*, telemetry::*};

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
    // What the last bring-up did with IPv6, published for the API like the
    // snapshot above. Every later projection of the peers also reads it, so a
    // PSK installation or a reload never puts back an IPv6 `/128` the
    // interface does not carry.
    shared_ipv6: Arc<RwLock<Ipv6TunnelStatus>>,
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
            &shared_ipv6,
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
    let mut unsupported_mss_clamp_reported = false;

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
                            &shared_ipv6,
                        ).await?;
                    }
                }
            }

            // Provisioning: applying the post-quantum PSK on a peer. The
            // caller (the HTTP endpoint) awaits the acknowledgment before
            // announcing the PSK to the client — see `InstallPskRequest`.
            psk_request = psk_rx.recv() => {
                if let Some(request) = psk_request {
                    install_peer_psk(
                        request, &shared_network, wg.as_ref(), &shared_ipv6, &event_tx,
                    ).await;
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
                        let state = *shared_state.read().await;
                        if apply_mss_clamp(fw.as_ref(), &mut policy, state, mss)
                            .await
                            .context("firewall MSS clamping")?
                        {
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
                        } else if !unsupported_mss_clamp_reported {
                            warn!(
                                "PMTUD: optimal MSS is {mss} bytes but the firewall backend does not support MSS clamping; policy unchanged"
                            );
                            emit_log(
                                &event_tx,
                                "warn",
                                &format!(
                                    "PMTUD: optimal MSS detected = {mss} bytes; firewall backend does not support clamping"
                                ),
                            );
                            unsupported_mss_clamp_reported = true;
                        }
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
                            &shared_ipv6,
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
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for Ctrl-C")?;
            }
            signal = terminate.recv() => {
                anyhow::ensure!(signal.is_some(), "SIGTERM handler closed unexpectedly");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for Ctrl-C")?;
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

pub fn status(network: &NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!(
        "  mode         : {}",
        if dry_run { "dry-run" } else { "real" }
    );
    println!("  transport    : WireGuard UDP {WG_PORT}");
    // Printed rather than propagated: a diagnostic command must still print
    // the rest, and the reason is what `run` would stop on.
    match network.api_bind() {
        Ok(bind) => println!("  web interface: http://{bind}"),
        Err(error) => println!("  web interface: none ({error})"),
    }
    println!("  WAN          : {}", network.wan_ifaces.join(", "));
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!(
        "  WG interface : {} (UDP {})",
        network.wg_iface, network.wg_listen_port
    );
    println!("  WG address   : {}", network.wg_address);
    println!(
        "  IPv6 tunnel  : {}",
        describe_ipv6(
            network,
            ipv6_installability(network, tunnel_mtu(network), &ipv6_conf_dir())
        )
    );
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

/// The IPv6 line of `heliosd status`.
///
/// This command runs beside the daemon, not in it: it applies the same
/// pre-checks the bring-up applies (`ipv6_installability`), on this host, now.
/// A refusal only the kernel could voice at bring-up is the running daemon's
/// to report — `GET /api/status` and `helios-ctl status` carry it.
fn describe_ipv6(network: &NetworkConfig, decided: Ipv6TunnelStatus) -> String {
    let Some(prefix) = network.wg_address_v6 else {
        return "not configured".into();
    };
    match decided {
        Ipv6TunnelStatus::Unavailable(reason) => {
            format!("{prefix} — unavailable, the gateway starts IPv4-only (degraded): {reason}")
        }
        Ipv6TunnelStatus::Installed | Ipv6TunnelStatus::NotConfigured => {
            format!("{prefix} (installable on this host)")
        }
    }
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
mod tests;
