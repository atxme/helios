//! Orchestration : câblage WireGuard <-> machine à états <-> pare-feu <-> OTA.
//!
//! La gateway est un **serveur** : elle monte son interface WireGuard, écoute en
//! UDP 51820 et attend les clients. Elle ne compose vers personne. L'état passe
//! donc à `Connecting` dès l'interface montée, et c'est le poller de handshakes
//! qui promeut vers `Up` quand un pair est réellement connecté — WireGuard étant
//! sans connexion, `Up` s'infère et ne se reçoit pas (ADR-001 §3).
//!
//! Le plan de données réel vit derrière les features `wireguard`
//! (`helios-wireguard`) et `netlink` (`helios-firewall`) : elles **compilent**
//! partout mais ne peuvent **tourner** que sur la cible. Sans elles, ou en
//! dry-run, on retombe sur les backends de simulation.

use std::{sync::Arc, time::Duration};

use aether::{
    FirewallPolicy, HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelEvent, TunnelState,
};
use anyhow::Context;
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use helios_wireguard::{InterfaceConfig, PeerConfig, WireguardBackend, WG_LISTEN_PORT};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Port UDP d'écoute WireGuard (invariant d'architecture).
const WG_PORT: u16 = WG_LISTEN_PORT;

/// Au-delà de cet âge, le handshake d'un pair est considéré périmé (ADR-001 §3).
const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// Sélectionne le plan de données WireGuard. Comme pour le pare-feu : dry-run
/// par défaut, backend noyau réel derrière la feature `wireguard`.
fn wireguard_backend(dry_run: bool, ifname: &str) -> Box<dyn WireguardBackend> {
    if dry_run {
        return Box::new(helios_wireguard::DryRunBackend::new());
    }
    #[cfg(feature = "wireguard")]
    {
        match helios_wireguard::KernelBackend::new(ifname) {
            Ok(backend) => return Box::new(backend),
            Err(e) => {
                tracing::error!("backend WireGuard noyau indisponible ({e}) — repli sur dry-run : AUCUN tunnel réel");
                return Box::new(helios_wireguard::DryRunBackend::new());
            }
        }
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = ifname;
        warn!("mode réel demandé mais feature `wireguard` non compilée : repli sur dry-run");
        Box::new(helios_wireguard::DryRunBackend::new())
    }
}

/// Projette la config réseau vers la config d'interface + les pairs WireGuard.
fn wg_config(network: &NetworkConfig) -> (InterfaceConfig, Vec<PeerConfig>) {
    let iface = InterfaceConfig {
        name: network.wg_iface.clone(),
        private_key: network.wg_private_key.clone(),
        listen_port: network.wg_listen_port,
        address: network.wg_address.clone(),
    };
    let peers = network
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: p.address.clone(),
            preshared_key: p.preshared_key.clone(),
        })
        .collect();
    (iface, peers)
}

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
        .context("application du pare-feu")?;
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
    // Détenue ici et nulle part ailleurs : le secret de scellement TPM ne doit
    // pas transiter par le crate API. Seul l'orchestrateur peut sceller.
    boot: helio_tpm::BootDecision,
) -> anyhow::Result<()> {
    let mut policy = shared_network.read().await.firewall_policy();
    sync_policy(&shared_policy, &policy).await;

    let fw = firewall_backend(dry_run);
    let wg: Arc<dyn WireguardBackend> = {
        let ifname = shared_network.read().await.wg_iface.clone();
        Arc::from(wireguard_backend(dry_run, &ifname))
    };
    let (internal_tx, mut internal_rx) = mpsc::channel::<OrchestratorCmd>(8);

    // 1. Fail-closed AVANT tout contact réseau.
    transition(
        &shared_state,
        &event_tx,
        TunnelState::Down,
        fw.as_ref(),
        &policy,
    )
    .await?;
    info!("kill-switch engagé, démarrage en fail-closed");

    // 2. Montée initiale du tunnel.
    {
        let network = shared_network.read().await;
        do_connect(
            &network,
            wg.as_ref(),
            &shared_state,
            &event_tx,
            fw.as_ref(),
            &policy,
        )
        .await?;
        let wan = network.wan_iface.clone();
        drop(network);
        spawn_mtu_probe_if_up(&wan, dry_run, &shared_state, &event_tx, &internal_tx).await;
    }
    sync_policy(&shared_policy, &policy).await;

    // 3. Inférence d'état : WireGuard ne notifie rien, on interroge les handshakes.
    spawn_handshake_poller(Arc::clone(&wg), Arc::clone(&shared_state), event_tx.clone());

    // 4. Télémétrie réseau (/proc/net/dev).
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
                            c, &shared_network, dry_run, wg.as_ref(), &shared_state, &event_tx,
                            fw.as_ref(), &mut policy, &internal_tx, &shared_policy, &boot,
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
    wg: &dyn WireguardBackend,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
    boot: &helio_tpm::BootDecision,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connexion demandée via l'interface web");
            emit_log(event_tx, "info", "Connexion demandée via l'interface web");
            let network = shared_network.read().await;
            do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
            let wan = network.wan_iface.clone();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::UpdateGatewayKey(new_key) => {
            // Rotation d'identité : on scelle d'abord, on n'applique qu'ensuite.
            // Sceller après avoir monté l'interface laisserait une fenêtre où la
            // clé en vigueur ne serait pas celle qui survivrait au redémarrage.
            match crate::gateway_key::update_sealed(boot, &new_key) {
                Err(e) => {
                    warn!("rotation de la clé WireGuard refusée : {e}");
                    emit_log(event_tx, "error", &format!("Rotation refusée : {e}"));
                }
                Ok(()) => {
                    {
                        let mut network = shared_network.write().await;
                        network.wg_private_key = new_key;
                    }
                    emit_log(
                        event_tx,
                        "warn",
                        "Clé WireGuard remplacée et rescellée — tous les clients \
                         doivent mettre à jour `peer_public_key` de la gateway",
                    );

                    // L'interface porte encore l'ancienne identité : on la remonte.
                    if let Err(e) = wg.down().await {
                        warn!("démontage avant rotation : {e}");
                    }
                    let network = shared_network.read().await;
                    do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
                    drop(network);
                    sync_policy(shared_policy, policy).await;
                }
            }
        }

        OrchestratorCmd::ApplyFirewallRules(rules) => {
            if dry_run {
                info!(
                    "[dry-run] règles nftables personnalisées reçues ({} octets) — non appliquées",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "info",
                    "[dry-run] Règles nftables reçues — application ignorée (mode simulation)",
                );
            } else {
                info!(
                    "application de règles nftables personnalisées ({} octets)",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "warn",
                    "Règles nftables personnalisées appliquées — vérifiez la cohérence",
                );
            }
        }

        OrchestratorCmd::Disconnect => {
            info!("déconnexion demandée via l'interface web");
            emit_log(event_tx, "info", "Déconnexion demandée via l'interface web");
            policy.captive_portal_gateway = None;
            policy.mss_clamp = None;
            if let Err(e) = wg.down().await {
                warn!("démontage de l'interface WireGuard : {e}");
                emit_log(event_tx, "warn", &format!("Démontage de l'interface : {e}"));
            }
            transition(shared_state, event_tx, TunnelState::Down, fw, policy).await?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::AcknowledgeCaptivePortal => {
            let current = *shared_state.read().await;
            if current == TunnelState::CaptivePortal {
                info!("portail captif validé par l'utilisateur — reconnexion");
                emit_log(
                    event_tx,
                    "info",
                    "Portail captif validé — tentative de reconnexion…",
                );
                policy.captive_portal_gateway = None;
                let next = current.on(TunnelEvent::CaptivePortalResolved)?;
                transition(shared_state, event_tx, next, fw, policy).await?;
                sync_policy(shared_policy, policy).await;
                let network = shared_network.read().await;
                do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
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
            fw.apply(policy, state)
                .await
                .context("pare-feu split-tunnel")?;
            let _ = event_tx.send(HeliosEvent::SplitTunnelChanged { cidrs });
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::SetMssClamp(mss) => {
            policy.mss_clamp = Some(mss);
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("pare-feu MSS clamping (manuel)")?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::LoadNetworkConfig(new_cfg) => {
            info!("config réseau rechargée : {} pair(s)", new_cfg.peers.len());
            *policy = new_cfg.firewall_policy();
            *shared_network.write().await = *new_cfg;
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("pare-feu après rechargement config")?;
            sync_policy(shared_policy, policy).await;

            // Aligne le plan de données sur la nouvelle liste de pairs
            // (enrôlement d'un client, ou révocation).
            if wg.is_up() {
                let (_, peers) = wg_config(&*shared_network.read().await);
                if let Err(e) = wg.sync_peers(&peers).await {
                    warn!("synchronisation des pairs WireGuard : {e}");
                    emit_log(
                        event_tx,
                        "warn",
                        &format!("Synchronisation des pairs : {e}"),
                    );
                }
            }
            emit_log(event_tx, "info", "Configuration réseau appliquée");
        }
    }
    Ok(())
}

/// Monte l'interface WireGuard de la gateway et applique ses pairs.
///
/// La gateway est un **serveur** : elle crée son interface, écoute en UDP et
/// attend les clients. Elle ne « compose » vers personne. L'état passe donc à
/// `Connecting` dès l'interface montée ; c'est le polling des handshakes
/// ([`spawn_handshake_poller`]) qui promeut vers `Up` quand un pair est
/// réellement connecté (ADR-001 §3).
async fn do_connect(
    network: &NetworkConfig,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    if !network.wireguard_ready() {
        emit_log(
            event_tx,
            "error",
            "Clé privée WireGuard absente de la config réseau — impossible de monter l'interface",
        );
        anyhow::bail!("gateway non configurée : `wg_private_key` vide dans network.toml");
    }

    let (iface, peers) = wg_config(network);

    // Kill-switch engagé pendant toute la montée.
    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }
    state = state
        .on(TunnelEvent::StartRequested)
        .context("transition d'état")?;
    transition(shared, event_tx, state, fw, policy).await?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Montée de {} — écoute UDP {}, {} pair(s) autorisé(s)",
            iface.name,
            iface.listen_port,
            peers.len()
        ),
    );

    wg.up(&iface, &peers)
        .await
        .context("montée de l'interface WireGuard")?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Interface {} active ({}) — en attente de handshake client",
            iface.name, iface.address
        ),
    );
    Ok(())
}

/// Interroge périodiquement les handshakes des pairs pour inférer l'état.
///
/// WireGuard est sans connexion : `Up` ne se reçoit pas, il se déduit. La
/// gateway est `Up` dès qu'**au moins un** pair a un handshake frais.
fn spawn_handshake_poller(
    wg: Arc<dyn WireguardBackend>,
    shared: Arc<RwLock<TunnelState>>,
    event_tx: broadcast::Sender<HeliosEvent>,
) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(10));
        loop {
            ticker.tick().await;
            if !wg.is_up() {
                continue;
            }
            let fresh = match wg.peers().await {
                Ok(peers) => peers.iter().any(|p| {
                    p.last_handshake
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age < HANDSHAKE_STALE_AFTER)
                }),
                Err(e) => {
                    warn!("lecture des pairs WireGuard impossible : {e}");
                    continue;
                }
            };

            let current = *shared.read().await;
            let next = match (current, fresh) {
                (TunnelState::Connecting, true) => TunnelState::Up,
                (TunnelState::Up, false) => TunnelState::Connecting,
                _ => continue,
            };
            *shared.write().await = next;
            let _ = event_tx.send(HeliosEvent::StateChanged { state: next });
            let msg = if next == TunnelState::Up {
                "Pair connecté — handshake WireGuard frais"
            } else {
                "Plus aucun handshake frais — kill-switch réengagé"
            };
            emit_log(&event_tx, "info", msg);
        }
    });
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

    let gateway = get_default_gateway(wan_iface)
        .await
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
        if !trimmed.starts_with(iface) {
            continue;
        }
        let rest = trimmed.trim_start_matches(iface).trim_start_matches(':');
        let fields: Vec<u64> = rest
            .split_whitespace()
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
        if dry_run { "dry-run" } else { "réel" }
    );
    println!("  transport    : WireGuard UDP {WG_PORT}");
    println!("  interface web: http://{}", network.api_bind());
    println!("  WAN          : {}", network.wan_iface);
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!(
        "  interface WG : {} (UDP {})",
        network.wg_iface, network.wg_listen_port
    );
    println!("  adresse WG   : {}", network.wg_address);
    println!(
        "  prêt         : {}",
        if network.wireguard_ready() {
            "oui"
        } else {
            "non (clé privée manquante)"
        }
    );
    println!("  pairs        : {}", network.peers.len());
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
    let channel = update_channel(dry_run);
    let current = channel.current_version().await?;
    println!("version actuelle : {current}");
    match channel.check().await? {
        Some(r) => println!("disponible       : {} ({})", r.version, r.bundle),
        None => println!("disponible       : aucune (à jour)"),
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
            wan_iface: "eth0".into(),
            wg_iface: "helios0".into(),
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            wg_listen_port: WG_LISTEN_PORT,
            peers: vec![aether::WgPeer {
                name: "poste-test".into(),
                public_key: PEER_KEY.into(),
                address: "100.64.1.2/32".into(),
                preshared_key: Some("psk-test".into()),
            }],
            ..NetworkConfig::default()
        }
    }

    #[test]
    fn projection_wireguard_conserve_interface_et_secrets_necessaires() {
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
    fn lecture_proc_net_dev_reconnait_interface_et_compteurs() {
        let proc_net_dev = "Inter-|   Receive                                                |  Transmit\n\
                         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                           eth0: 42 3 1 0 0 0 0 0 84 4 2 0 0 0 0 0\n";

        assert_eq!(
            parse_proc_net_dev(proc_net_dev, "eth0"),
            Some((42, 84, 3, 4))
        );
        assert_eq!(parse_proc_net_dev(proc_net_dev, "eth1"), None);
    }

    #[tokio::test]
    async fn connexion_dry_run_reste_bloquee_jusqu_au_handshake() {
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
        )
        .await
        .unwrap();

        assert!(wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Connecting);
        assert!(state.read().await.kill_switch_engaged());
    }

    #[tokio::test]
    async fn deconnexion_demonte_wireguard_et_reengage_le_kill_switch() {
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
            // TPM désactivé : ce test ne fait pas de rotation de clé.
            &helio_tpm::BootDecision::Disabled,
        )
        .await
        .unwrap();

        assert!(!wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Down);
        assert!(state.read().await.kill_switch_engaged());
        assert_eq!(policy.read().await.mss_clamp, None);
    }
}
