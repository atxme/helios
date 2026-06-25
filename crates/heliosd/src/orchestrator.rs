//! Orchestration : câblage VICI <-> machine à états <-> pare-feu <-> OTA.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use helios_core::{
    profiles, Connection, FirewallPolicy, HeliosEvent, NetworkConfig, OrchestratorCmd,
    TunnelEvent, TunnelState,
};
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use helios_vici::{Message, ViciClient, ViciEventStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{error, info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const VICI_SOCKET: &str = "/var/run/charon.vici";

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

fn default_proposals() -> (String, String) {
    let p = profiles::find("hybrid").expect("profil hybride manquant");
    (p.ike_proposal.to_string(), p.esp_proposal.to_string())
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
    effective_proposals: Arc<RwLock<Option<(String, String)>>>,
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
        let proposals = effective_proposals.read().await.clone()
            .unwrap_or_else(default_proposals);
        do_connect(&network, dry_run, &proposals, &shared_state, &event_tx, fw.as_ref(), &mut policy).await?;
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
                            &mut policy, &effective_proposals, &internal_tx, &shared_policy,
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
    effective_proposals: &Arc<RwLock<Option<(String, String)>>>,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connexion demandée via l'interface web");
            emit_log(event_tx, "info", "Connexion demandée via l'interface web");
            let network = shared_network.read().await;
            let proposals = effective_proposals.read().await.clone()
                .unwrap_or_else(default_proposals);
            do_connect(&network, dry_run, &proposals, shared_state, event_tx, fw, policy).await?;
            let wan = network.wan_iface.clone();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::ConnectWithProfile(profile_id) => {
            match profiles::find(&profile_id) {
                Some(p) => {
                    info!("connexion avec profil `{}` ({})", p.id, p.name);
                    emit_log(event_tx, "info",
                        &format!("Connexion avec profil {} — {}", p.name, p.ike_proposal));
                    let proposals = (p.ike_proposal.to_string(), p.esp_proposal.to_string());
                    *effective_proposals.write().await = Some(proposals.clone());
                    let network = shared_network.read().await;
                    do_connect(&network, dry_run, &proposals, shared_state, event_tx, fw, policy).await?;
                    let wan = network.wan_iface.clone();
                    drop(network);
                    spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
                    sync_policy(shared_policy, policy).await;
                }
                None => {
                    error!("profil IKE inconnu : `{profile_id}`");
                    emit_log(event_tx, "error",
                        &format!("Profil IKE inconnu : `{profile_id}`"));
                }
            }
        }

        OrchestratorCmd::ConnectWithCustom { ike_proposal, esp_proposal } => {
            info!("connexion avec propositions personnalisées : IKE={ike_proposal}");
            emit_log(event_tx, "info",
                &format!("Connexion personnalisée — IKE : {ike_proposal}"));
            let proposals = (ike_proposal, esp_proposal);
            *effective_proposals.write().await = Some(proposals.clone());
            let network = shared_network.read().await;
            do_connect(&network, dry_run, &proposals, shared_state, event_tx, fw, policy).await?;
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
            *effective_proposals.write().await = None;
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
                let proposals = effective_proposals.read().await.clone()
                    .unwrap_or_else(default_proposals);
                do_connect(&network, dry_run, &proposals, shared_state, event_tx, fw, policy).await?;
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
            info!("config réseau rechargée : {} connexion(s)", new_cfg.connections.len());
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
    proposals: &(String, String),
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
) -> anyhow::Result<()> {
    if dry_run {
        simulate_bringup(shared, event_tx, fw, policy).await
    } else {
        bring_up_real(network, proposals, shared, event_tx, fw, policy).await
    }
}

async fn simulate_bringup(
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    info!("[dry-run] simulation de la montée du tunnel");
    emit_log(event_tx, "info", "[dry-run] Démarrage de la simulation IKEv2 + ML-KEM-768");
    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }
    for event in [TunnelEvent::StartRequested, TunnelEvent::IkeEstablished, TunnelEvent::ChildUp] {
        state = state.on(event).context("transition d'état")?;
        info!("événement {event:?} -> état {state:?}");
        let msg = match event {
            TunnelEvent::StartRequested  => "Négociation IKEv2 initiée…",
            TunnelEvent::IkeEstablished  => "IKE_SA établi — échange ML-KEM-768 + ECDHE terminé",
            TunnelEvent::ChildUp         => "CHILD_SA actif — trafic chiffré ESP autorisé",
            _ => "",
        };
        if !msg.is_empty() { emit_log(event_tx, "info", msg); }
        transition(shared, event_tx, state, fw, policy).await?;
    }
    Ok(())
}

async fn bring_up_real(
    network: &NetworkConfig,
    proposals: &(String, String),
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
) -> anyhow::Result<()> {
    let mut client = ViciClient::connect(VICI_SOCKET)
        .await
        .with_context(|| format!("connexion VICI sur {VICI_SOCKET}"))?;
    info!("connecté à charon via {VICI_SOCKET}");

    let mut state = TunnelState::Down;
    for conn in &network.connections {
        emit_log(event_tx, "info", &format!("Connexion `{}` — négociation IKEv2…", conn.name));
        state = state.on(TunnelEvent::StartRequested)?;
        transition(shared, event_tx, state, fw, policy).await?;

        load_connection(&mut client, conn, &proposals.0, &proposals.1).await?;
        match initiate(&mut client, conn).await {
            Ok(()) => {
                state = state.on(TunnelEvent::ChildUp)?;
                info!("connexion `{}` établie", conn.name);
                emit_log(event_tx, "info",
                    &format!("CHILD_SA `{}` actif — trafic chiffré ESP", conn.name));
                spawn_mobike_monitor(
                    VICI_SOCKET.to_string(),
                    network.wan_iface.clone(),
                    conn.name.clone(),
                    event_tx.clone(),
                );
            }
            Err(e) => {
                error!("échec de `{}` : {e}", conn.name);
                emit_log(event_tx, "error",
                    &format!("Échec de `{}` : {e}", conn.name));

                if let Some(gateway) = probe_captive_portal(&policy.wan_iface).await {
                    info!("portail captif détecté via sonde HTTP (passerelle : {gateway})");
                    emit_log(event_tx, "warn",
                        &format!("Portail captif détecté — passerelle : {gateway}"));
                    state = state.on(TunnelEvent::CaptivePortalDetected)?;
                    policy.captive_portal_gateway = Some(gateway.clone());
                    transition(shared, event_tx, state, fw, policy).await?;
                    let _ = event_tx.send(HeliosEvent::CaptivePortalDetected { gateway });
                    return Ok(());
                }

                state = state.on(TunnelEvent::Error)?;
            }
        }
        transition(shared, event_tx, state, fw, policy).await?;
    }
    Ok(())
}

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

async fn tcp_http_probe(host: &str, port: u16, path: &str) -> Option<u16> {
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.ok()?;
    let header = std::str::from_utf8(&buf[..n]).ok()?;
    header.split_whitespace().nth(1)?.parse().ok()
}

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
            1300u16
        } else {
            discover_mss(&wan_iface).await.unwrap_or(1300)
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
    Some(mtu.saturating_sub(102).max(576))
}

async fn load_connection(
    client: &mut ViciClient,
    conn: &Connection,
    ike_proposal: &str,
    esp_proposal: &str,
) -> anyhow::Result<()> {
    let child = Message::new()
        .list("esp_proposals", &[esp_proposal])
        .kv("start_action", "trap");

    let mut body = Message::new()
        .list("remote_addrs", &[conn.remote_addr.as_str()])
        .list("proposals", &[ike_proposal])
        .kv("version", "2")
        .kv("mobike", "yes");
    if let Some(id) = &conn.local_id {
        body = body.section("local", Message::new().kv("id", id));
    }
    if let Some(id) = &conn.remote_id {
        body = body.section("remote", Message::new().kv("id", id));
    }
    body = body.section("children", Message::new().section(&conn.name, child));

    let reply = client.request("load-conn", Message::new().section(&conn.name, body)).await?;
    if reply.get_str("success") == Some("no") {
        anyhow::bail!(
            "load-conn `{}` refusé : {}",
            conn.name,
            reply.get_str("errmsg").unwrap_or("raison inconnue")
        );
    }
    Ok(())
}

async fn initiate(client: &mut ViciClient, conn: &Connection) -> anyhow::Result<()> {
    let payload = Message::new().kv("child", &conn.name).kv("timeout", "-1");
    let reply = client.request("initiate", payload).await?;
    if reply.get_str("success") == Some("no") {
        anyhow::bail!(
            "initiate `{}` échoué : {}",
            conn.name,
            reply.get_str("errmsg").unwrap_or("raison inconnue")
        );
    }
    Ok(())
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

/// Constantes Netlink (linux/rtnetlink.h) — groupe multicast adresses IPv4.
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTM_NEWADDR: u16 = 20;
const NL_AF_INET: u8 = 2;
const IFA_ADDRESS: u16 = 1;

fn spawn_mobike_monitor(
    vici_socket: String,
    wan_iface: String,
    conn_name: String,
    event_tx: broadcast::Sender<HeliosEvent>,
) {
    {
        let socket = vici_socket.clone();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            match ViciEventStream::connect(&socket).await {
                Err(e) => warn!("MOBIKE : connexion VICI événements impossible : {e}"),
                Ok(mut stream) => {
                    for ev in ["ike-updown", "child-updown"] {
                        if let Err(e) = stream.subscribe(ev).await {
                            warn!("MOBIKE : abonnement `{ev}` impossible : {e}");
                            return;
                        }
                    }
                    info!("MOBIKE : abonné aux événements VICI ike-updown + child-updown");
                    loop {
                        match stream.next_event().await {
                            Ok((name, msg)) => {
                                let local = msg.get_str("local-host").unwrap_or("?");
                                let remote = msg.get_str("remote-host").unwrap_or("?");
                                info!("VICI `{name}` : local={local} distant={remote}");
                                emit_log(&tx, "info",
                                    &format!("VICI {name} : {local} ↔ {remote}"));
                            }
                            Err(e) => {
                                warn!("MOBIKE : perte du flux d'événements VICI : {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        if let Err(e) = netlink_addr_watcher(vici_socket, wan_iface, conn_name, event_tx).await {
            warn!("MOBIKE : surveillance Netlink terminée : {e}");
        }
    });
}

async fn netlink_addr_watcher(
    vici_socket: String,
    wan_iface: String,
    conn_name: String,
    event_tx: broadcast::Sender<HeliosEvent>,
) -> anyhow::Result<()> {
    use netlink_sys::{AsyncSocket, AsyncSocketExt, TokioSocket, SocketAddr as NlSocketAddr, protocols};

    let if_index = read_if_index(&wan_iface).await
        .with_context(|| format!("index introuvable pour {wan_iface} dans sysfs"))?;

    let mut sock = TokioSocket::new(protocols::NETLINK_ROUTE)
        .context("ouverture socket Netlink ROUTE")?;
    sock.socket_mut()
        .bind(&NlSocketAddr::new(0, RTMGRP_IPV4_IFADDR))
        .context("bind RTMGRP_IPV4_IFADDR")?;

    let mut current_ip = seed_wan_ip(&wan_iface).await;
    info!(
        "MOBIKE : listener Netlink RTM_NEWADDR actif sur {} (index={}, ip={})",
        wan_iface,
        if_index,
        current_ip.as_deref().unwrap_or("?"),
    );

    loop {
        let (buf, _): (Vec<u8>, _) = sock.recv_from_full().await.context("recv Netlink")?;
        let mut offset = 0usize;
        while offset + 16 <= buf.len() {
            let nlmsg_len =
                u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let nlmsg_type =
                u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());

            if nlmsg_type == RTM_NEWADDR && offset + 24 <= buf.len() {
                let ifa_family = buf[offset + 16];
                let ifa_index =
                    u32::from_ne_bytes(buf[offset + 20..offset + 24].try_into().unwrap());

                if ifa_family == NL_AF_INET && ifa_index == if_index {
                    let end = (offset + nlmsg_len).min(buf.len());
                    if let Some(new_ip) = parse_ifa_address(&buf[offset + 24..end]) {
                        match &current_ip {
                            Some(prev) if *prev != new_ip => {
                                info!("MOBIKE : {wan_iface} {prev} → {new_ip}");
                                emit_log(&event_tx, "info",
                                    &format!("MOBIKE : migration {prev} → {new_ip} sur {wan_iface}"));
                                let _ = event_tx.send(HeliosEvent::AddressChanged {
                                    iface: wan_iface.clone(),
                                    old_ip: prev.clone(),
                                    new_ip: new_ip.clone(),
                                });
                                trigger_mobike_update(&vici_socket, &conn_name).await;
                                current_ip = Some(new_ip);
                            }
                            None => current_ip = Some(new_ip),
                            _ => {}
                        }
                    }
                }
            }

            let aligned = (nlmsg_len + 3) & !3;
            if aligned == 0 { break; }
            offset += aligned;
        }
    }
}

fn parse_ifa_address(data: &[u8]) -> Option<String> {
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let rta_len = u16::from_ne_bytes(data[off..off + 2].try_into().ok()?) as usize;
        let rta_type = u16::from_ne_bytes(data[off + 2..off + 4].try_into().ok()?);
        if rta_type == IFA_ADDRESS && rta_len == 8 && off + 8 <= data.len() {
            return Some(format!(
                "{}.{}.{}.{}",
                data[off + 4], data[off + 5], data[off + 6], data[off + 7]
            ));
        }
        let aligned = (rta_len + 3) & !3;
        if aligned < 4 { break; }
        off += aligned;
    }
    None
}

async fn read_if_index(iface: &str) -> Option<u32> {
    tokio::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

async fn seed_wan_ip(iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["-brief", "addr", "show", "dev", iface])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip(2)
        .find(|s| s.contains('.') && s.contains('/'))
        .and_then(|cidr| cidr.split('/').next())
        .map(str::to_string)
}

async fn trigger_mobike_update(vici_socket: &str, conn_name: &str) {
    match ViciClient::connect(vici_socket).await {
        Err(e) => warn!("MOBIKE : connexion VICI impossible pour mise à jour : {e}"),
        Ok(mut client) => {
            let payload = Message::new().kv("ike", conn_name);
            match client.request("mobike", payload).await {
                Err(e) => warn!("MOBIKE : commande mobike échouée : {e}"),
                Ok(reply) => {
                    if reply.get_str("success") == Some("no") {
                        warn!("MOBIKE : mise à jour rejetée par charon : {}",
                            reply.get_str("errmsg").unwrap_or("raison inconnue"));
                    } else {
                        info!("MOBIKE : adresse mise à jour dans charon pour `{conn_name}`");
                    }
                }
            }
        }
    }
}

pub fn status(network: &NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!("  mode         : {}", if dry_run { "dry-run" } else { "réel" });
    println!("  socket VICI  : {VICI_SOCKET}");
    println!("  interface web: http://{}", helios_core::API_BIND);
    println!("  WAN          : {}", network.wan_iface);
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!("  connexions   : {}", network.connections.len());
    let (ike, _) = default_proposals();
    for c in &network.connections {
        println!("    - {} -> {} [{}]", c.name, c.remote_addr, ike);
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
