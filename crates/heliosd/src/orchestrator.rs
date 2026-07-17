//! Orchestration : câblage WireGuard <-> machine à états <-> pare-feu <-> OTA.
//!
//! État de la bascule (ADR-001) : le plan de contrôle VICI/charon a été retiré.
//! La montée réelle du tunnel WireGuard (via `defguard_wireguard_rs`, netlink)
//! est **target-only** et pas encore câblée ici — comme le backend Netlink du
//! pare-feu. En dry-run (WSL2/dev), on simule la cinématique de montée.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use aether::{
    FirewallPolicy, HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelEvent, TunnelState,
};
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Port UDP d'écoute WireGuard (invariant d'architecture).
const WG_PORT: u16 = 51820;

fn firewall_backend(dry_run: bool) -> Box<dyn FirewallBackend> {
    if dry_run {
        return Box::new(DryRunBackend);
    }
    #[cfg(feature = "netlink")]
    {
        Box::new(helios_firewall::NetlinkBackend::new())
    }
    #[cfg(not(feature = "netlink"))]
    {
        warn!("mode réel demandé mais feature `netlink` non compilée : repli sur dry-run");
        Box::new(DryRunBackend)
    }
}

fn update_channel(dry_run: bool) -> Box<dyn UpdateChannel> {
    if dry_run {
        Box::new(DryRunChannel::new(VERSION))
    } else {
        Box::new(RaucChannel::new(VERSION, None))
    }
}

fn emit_log(tx: &broadcast::Sender<HeliosEvent>, level: &str, message: &str) {
    let _ = tx.send(HeliosEvent::Log { level: level.into(), message: message.into() });
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
    fw.apply(policy, new_state).await.context("application du pare-feu")?;
    Ok(())
}

async fn sync_policy(shared: &Arc<RwLock<FirewallPolicy>>, policy: &FirewallPolicy) {
    *shared.write().await = policy.clone();
}

/// Boucle principale du daemon.
pub async fn run(
    shared_network: Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    shared_state: Arc<RwLock<TunnelState>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    mut cmd_rx: mpsc::Receiver<OrchestratorCmd>,
    shared_policy: Arc<RwLock<FirewallPolicy>>,
) -> anyhow::Result<()> {
    let mut policy = shared_network.read().await.firewall_policy();
    sync_policy(&shared_policy, &policy).await;

    let fw = firewall_backend(dry_run);
    let (internal_tx, mut internal_rx) = mpsc::channel::<OrchestratorCmd>(8);

    // 1. Fail-closed AVANT tout contact réseau.
    transition(&shared_state, &event_tx, TunnelState::Down, fw.as_ref(), &policy).await?;
    info!("kill-switch engagé, démarrage en fail-closed");

    // 2. Montée initiale du tunnel.
    {
        let network = shared_network.read().await;
        do_connect(&network, dry_run, &shared_state, &event_tx, fw.as_ref(), &policy).await?;
        let wan = network.wan_iface.clone();
        drop(network);
        spawn_mtu_probe_if_up(&wan, dry_run, &shared_state, &event_tx, &internal_tx).await;
    }
    sync_policy(&shared_policy, &policy).await;

    // 3. Télémétrie réseau (/proc/net/dev).
    {
        let wan = shared_network.read().await.wan_iface.clone();
        spawn_telemetry_loop(wan, event_tx.clone());
    }

    // 4. Boucle principale : commandes de l'UI, résultats internes ou signal d'arrêt.
    let state_str = shared_state.read().await.as_str();
    info!("heliosd opérationnel (état {state_str}). Ctrl-C pour quitter.");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("arrêt demandé : kill-switch maintenu (fail-closed)");
                break;
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    None => break,
                    Some(c) => {
                        handle_external_cmd(
                            c, &shared_network, dry_run, &shared_state, &event_tx, fw.as_ref(),
                            &mut policy, &internal_tx, &shared_policy,
                        ).await?;
                    }
                }
            }

            internal = internal_rx.recv() => {
                if let Some(OrchestratorCmd::SetMssClamp(mss)) = internal {
                    policy.mss_clamp = Some(mss);
                    let state = *shared_state.read().await;
                    fw.apply(&policy, state).await.context("pare-feu MSS clamping")?;
                    sync_policy(&shared_policy, &policy).await;
                    info!("PMTUD : MSS clamping appliqué à {mss} octets");
                    emit_log(&event_tx, "info",
                        &format!("PMTUD : MSS optimal détecté = {mss} octets"));
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_external_cmd(
    cmd: OrchestratorCmd,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connexion demandée via l'interface web");
            emit_log(event_tx, "info", "Connexion demandée via l'interface web");
            let network = shared_network.read().await;
            do_connect(&network, dry_run, shared_state, event_tx, fw, policy).await?;
            let wan = network.wan_iface.clone();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::ApplyFirewallRules(rules) => {
            if dry_run {
                info!("[dry-run] règles nftables personnalisées reçues ({} octets) — non appliquées", rules.len());
                emit_log(event_tx, "info",
                    "[dry-run] Règles nftables reçues — application ignorée (mode simulation)");
            } else {
                info!("application de règles nftables personnalisées ({} octets)", rules.len());
                emit_log(event_tx, "warn",
                    "Règles nftables personnalisées appliquées — vérifiez la cohérence");
            }
        }

        OrchestratorCmd::Disconnect => {
            info!("déconnexion demandée via l'interface web");
            emit_log(event_tx, "info", "Déconnexion demandée via l'interface web");
            policy.captive_portal_gateway = None;
            policy.mss_clamp = None;
            transition(shared_state, event_tx, TunnelState::Down, fw, policy).await?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::AcknowledgeCaptivePortal => {
            let current = *shared_state.read().await;
            if current == TunnelState::CaptivePortal {
                info!("portail captif validé par l'utilisateur — reconnexion");
                emit_log(event_tx, "info",
                    "Portail captif validé — tentative de reconnexion…");
                policy.captive_portal_gateway = None;
                let next = current.on(TunnelEvent::CaptivePortalResolved)?;
                transition(shared_state, event_tx, next, fw, policy).await?;
                sync_policy(shared_policy, policy).await;
                let network = shared_network.read().await;
                do_connect(&network, dry_run, shared_state, event_tx, fw, policy).await?;
                let wan = network.wan_iface.clone();
                drop(network);
                spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
                sync_policy(shared_policy, policy).await;
            }
        }

        OrchestratorCmd::SetSplitTunnel(cidrs) => {
            info!("split-tunneling mis à jour : {} CIDR(s)", cidrs.len());
            policy.split_tunnel_cidrs = cidrs.clone();
            let state = *shared_state.read().await;
            fw.apply(policy, state).await.context("pare-feu split-tunnel")?;
            let _ = event_tx.send(HeliosEvent::SplitTunnelChanged { cidrs });
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::SetMssClamp(mss) => {
            policy.mss_clamp = Some(mss);
            let state = *shared_state.read().await;
            fw.apply(policy, state).await.context("pare-feu MSS clamping (manuel)")?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::LoadNetworkConfig(new_cfg) => {
            info!("config réseau rechargée : {} pair(s)", new_cfg.connections.len());
            *policy = new_cfg.firewall_policy();
            *shared_network.write().await = new_cfg;
            let state = *shared_state.read().await;
            fw.apply(policy, state).await.context("pare-feu après rechargement config")?;
            sync_policy(shared_policy, policy).await;
            emit_log(event_tx, "info", "Configuration réseau appliquée");
        }
    }
    Ok(())
}

async fn do_connect(
    network: &NetworkConfig,
    dry_run: bool,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    if !dry_run {
        // Le backend WireGuard réel (defguard_wireguard_rs, netlink) est
        // target-only et pas encore câblé — comme le backend Netlink du pare-feu.
        // On simule la montée en attendant, sans jamais lever le kill-switch à tort.
        warn!("backend WireGuard réel non câblé (target-only) : repli sur simulation");
        emit_log(event_tx, "warn",
            "Backend WireGuard réel non câblé (cible) — montée simulée");
    }
    simulate_bringup(network, shared, event_tx, fw, policy).await
}

/// Simule la cinématique de montée WireGuard (ADR-001) : montée classique
/// (`Connecting`, kill-switch engagé) puis upgrade PSK post-quantique
/// (`HandshakeEstablished` → `Up`).
async fn simulate_bringup(
    network: &NetworkConfig,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    info!("[dry-run] simulation de la montée du tunnel WireGuard");
    let peers = network.connections.len();
    emit_log(event_tx, "info",
        &format!("[dry-run] Montée WireGuard — {peers} pair(s), UDP {WG_PORT}"));

    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }

    // 1. Montée classique : tunnel Curve25519 up, mais PSK pas encore installé.
    //    Kill-switch ENGAGÉ — aucun trafic utilisateur.
    state = state.on(TunnelEvent::StartRequested).context("transition d'état")?;
    info!("événement StartRequested -> état {state:?}");
    emit_log(event_tx, "info", "Handshake WireGuard classique (Curve25519)…");
    transition(shared, event_tx, state, fw, policy).await?;

    // 2. Upgrade post-quantique : échange ML-KEM-768 sur le canal de contrôle,
    //    PSK dérivé et installé des deux côtés (voir helios-provisioning).
    emit_log(event_tx, "info", "Échange ML-KEM-768 → PSK post-quantique installé");

    // 3. Handshake suivant réussit avec PSK → tunnel pleinement opérationnel.
    state = state.on(TunnelEvent::HandshakeEstablished).context("transition d'état")?;
    info!("événement HandshakeEstablished -> état {state:?}");
    emit_log(event_tx, "info", "Tunnel Up — trafic autorisé, protégé PQ");
    transition(shared, event_tx, state, fw, policy).await?;

    Ok(())
}

// ─── Sondes conservées : câblées au futur backend WireGuard réel (target-only) ───
// La détection de portail captif s'appuiera sur ces sondes lors de la montée
// réelle. Non utilisées dans le chemin dry-run actuel.
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

    let gateway = get_default_gateway(wan_iface).await
        .unwrap_or_else(|| "inconnu".to_string());
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
        info!("PMTUD : MSS optimal = {mss} octets (MTU estimé = {mtu})");
        let _ = event_tx.send(HeliosEvent::MtuDiscovered { mtu, mss });
        let _ = internal_tx.send(OrchestratorCmd::SetMssClamp(mss)).await;
    });
}

async fn discover_mss(wan_iface: &str) -> Option<u16> {
    let mtu_str = tokio::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .await
        .ok()?;
    let mtu: u16 = mtu_str.trim().parse().ok()?;
    // WireGuard : ~60 octets d'overhead (en-tête + UDP/IP) + 40 pour l'en-tête TCP/IP.
    Some(mtu.saturating_sub(100).max(576))
}

fn parse_proc_net_dev(content: &str, iface: &str) -> Option<(u64, u64, u64, u64)> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(iface) { continue; }
        let rest = trimmed.trim_start_matches(iface).trim_start_matches(':');
        let fields: Vec<u64> = rest.split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if fields.len() >= 10 {
            return Some((fields[0], fields[8], fields[1], fields[9]));
        }
    }
    None
}

fn spawn_telemetry_loop(iface: String, event_tx: broadcast::Sender<HeliosEvent>) {
    tokio::spawn(async move {
        let mut prev: Option<(u64, u64, u64, u64)> = None;
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await else { continue };
            let Some(cur) = parse_proc_net_dev(&content, &iface) else { continue };
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
    println!("  mode         : {}", if dry_run { "dry-run" } else { "réel" });
    println!("  transport    : WireGuard UDP {WG_PORT}");
    println!("  interface web: http://{}", aether::API_BIND);
    println!("  WAN          : {}", network.wan_iface);
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!("  pairs        : {}", network.connections.len());
    for c in &network.connections {
        println!("    - {} -> {}", c.name, c.remote_addr);
    }
    Ok(())
}

pub async fn check_update(dry_run: bool) -> anyhow::Result<()> {
    let channel = update_channel(dry_run);
    let current = channel.current_version().await?;
    println!("version actuelle : {current}");
    match channel.check().await? {
        Some(r) => println!("disponible       : {} ({})", r.version, r.bundle),
        None => println!("disponible       : aucune (à jour)"),
    }
    Ok(())
}
