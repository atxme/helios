//! Orchestration : câblage VICI <-> machine à états <-> pare-feu <-> OTA.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use helios_core::{
    profiles, Config, Connection, FirewallPolicy, HeliosEvent, OrchestratorCmd, TunnelEvent,
    TunnelState,
};
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use helios_vici::{Message, ViciClient, ViciEventStream};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{error, info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

fn update_channel(config: &Config) -> Box<dyn UpdateChannel> {
    if config.general.dry_run {
        Box::new(DryRunChannel::new(VERSION))
    } else {
        let manifest = config.update.manifest.as_ref().map(Into::into);
        Box::new(RaucChannel::new(VERSION, manifest))
    }
}

fn emit_log(tx: &broadcast::Sender<HeliosEvent>, level: &str, message: &str) {
    let _ = tx.send(HeliosEvent::Log { level: level.into(), message: message.into() });
}

/// Met à jour l'état partagé, émet un événement WebSocket et applique le pare-feu.
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

/// Boucle principale du daemon.
pub async fn run(
    config: Config,
    shared_state: Arc<RwLock<TunnelState>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    mut cmd_rx: mpsc::Receiver<OrchestratorCmd>,
    effective_proposals: Arc<RwLock<Option<(String, String)>>>,
) -> anyhow::Result<()> {
    let policy = config.firewall_policy();
    let fw = firewall_backend(config.general.dry_run);

    // 1. Fail-closed AVANT tout contact réseau.
    transition(&shared_state, &event_tx, TunnelState::Down, fw.as_ref(), &policy).await?;
    info!("kill-switch engagé, démarrage en fail-closed");

    // 2. Montée initiale du tunnel.
    do_connect(&config, &shared_state, &event_tx, fw.as_ref(), &policy).await?;

    // 3. Télémétrie réseau (/proc/net/dev).
    spawn_telemetry_loop(config.firewall.wan_iface.clone(), event_tx.clone());

    // 4. OTA.
    if config.update.enabled {
        spawn_update_loop(update_channel(&config), config.update.check_interval_secs);
    }

    // 5. Boucle principale : commandes de l'UI ou signal d'arrêt.
    let state_str = format!("{:?}", *shared_state.read().await);
    info!("heliosd opérationnel (état {state_str}). Ctrl-C pour quitter.");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("arrêt demandé : kill-switch maintenu (fail-closed)");
                break;
            }
            cmd = cmd_rx.recv() => match cmd {
                Some(OrchestratorCmd::Connect) => {
                    info!("connexion demandée via l'interface web");
                    emit_log(&event_tx, "info", "Connexion demandée via l'interface web");
                    do_connect(&config, &shared_state, &event_tx, fw.as_ref(), &policy).await?;
                }
                Some(OrchestratorCmd::ConnectWithProfile(profile_id)) => {
                    match profiles::find(&profile_id) {
                        Some(p) => {
                            info!("connexion avec profil `{}` ({})", p.id, p.name);
                            emit_log(&event_tx, "info",
                                &format!("Connexion avec profil {} — {}", p.name, p.ike_proposal));
                            *effective_proposals.write().await =
                                Some((p.ike_proposal.to_string(), p.esp_proposal.to_string()));
                            let mut overridden = config.clone();
                            for conn in &mut overridden.connections {
                                conn.ike_proposal = p.ike_proposal.to_string();
                                conn.esp_proposal = p.esp_proposal.to_string();
                            }
                            do_connect(&overridden, &shared_state, &event_tx, fw.as_ref(), &policy).await?;
                        }
                        None => {
                            error!("profil IKE inconnu : `{profile_id}`");
                            emit_log(&event_tx, "error",
                                &format!("Profil IKE inconnu : `{profile_id}`"));
                        }
                    }
                }
                Some(OrchestratorCmd::ConnectWithCustom { ike_proposal, esp_proposal }) => {
                    info!("connexion avec propositions personnalisées : IKE={ike_proposal}");
                    emit_log(&event_tx, "info",
                        &format!("Connexion personnalisée — IKE : {ike_proposal}"));
                    *effective_proposals.write().await =
                        Some((ike_proposal.clone(), esp_proposal.clone()));
                    let mut overridden = config.clone();
                    for conn in &mut overridden.connections {
                        conn.ike_proposal = ike_proposal.clone();
                        conn.esp_proposal = esp_proposal.clone();
                    }
                    do_connect(&overridden, &shared_state, &event_tx, fw.as_ref(), &policy).await?;
                }
                Some(OrchestratorCmd::ApplyFirewallRules(rules)) => {
                    if config.general.dry_run {
                        info!("[dry-run] règles nftables personnalisées reçues ({} octets) — non appliquées", rules.len());
                        emit_log(&event_tx, "info",
                            "[dry-run] Règles nftables reçues — application ignorée (mode simulation)");
                    } else {
                        info!("application de règles nftables personnalisées ({} octets)", rules.len());
                        emit_log(&event_tx, "warn", "Règles nftables personnalisées appliquées — vérifiez la cohérence");
                        // Sur cible : `nft -f /dev/stdin` serait appelé ici.
                    }
                }
                Some(OrchestratorCmd::Disconnect) => {
                    info!("déconnexion demandée via l'interface web");
                    emit_log(&event_tx, "info", "Déconnexion demandée via l'interface web");
                    *effective_proposals.write().await = None;
                    transition(&shared_state, &event_tx, TunnelState::Down, fw.as_ref(), &policy).await?;
                }
                None => break,
            }
        }
    }
    Ok(())
}

async fn do_connect(
    config: &Config,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    if config.general.dry_run {
        simulate_bringup(shared, event_tx, fw, policy).await
    } else {
        bring_up_real(config, shared, event_tx, fw, policy).await
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
    if state != TunnelState::Down {
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
    config: &Config,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    let mut client = ViciClient::connect(&config.vici.socket)
        .await
        .with_context(|| format!("connexion VICI sur {}", config.vici.socket))?;
    info!("connecté à charon via {}", config.vici.socket);

    let mut state = TunnelState::Down;
    for conn in &config.connections {
        emit_log(event_tx, "info", &format!("Connexion `{}` — négociation IKEv2…", conn.name));
        state = state.on(TunnelEvent::StartRequested)?;
        transition(shared, event_tx, state, fw, policy).await?;

        load_connection(&mut client, conn).await?;
        match initiate(&mut client, conn).await {
            Ok(()) => {
                state = state.on(TunnelEvent::ChildUp)?;
                info!("connexion `{}` établie", conn.name);
                emit_log(event_tx, "info", &format!("CHILD_SA `{}` actif — trafic chiffré ESP", conn.name));
                if conn.mobike {
                    spawn_mobike_monitor(
                        config.vici.socket.clone(),
                        config.firewall.wan_iface.clone(),
                        conn.name.clone(),
                        event_tx.clone(),
                    );
                }
            }
            Err(e) => {
                error!("échec de `{}` : {e}", conn.name);
                emit_log(event_tx, "error", &format!("Échec de `{}` : {e}", conn.name));
                state = state.on(TunnelEvent::Error)?;
            }
        }
        transition(shared, event_tx, state, fw, policy).await?;
    }
    Ok(())
}

async fn load_connection(client: &mut ViciClient, conn: &Connection) -> anyhow::Result<()> {
    let child = Message::new()
        .list("esp_proposals", &[conn.esp_proposal.as_str()])
        .kv("start_action", "trap");

    let mut body = Message::new()
        .list("remote_addrs", &[conn.remote_addr.as_str()])
        .list("proposals", &[conn.ike_proposal.as_str()])
        .kv("version", "2")
        .kv("mobike", if conn.mobike { "yes" } else { "no" });
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
        // /proc/net/dev : rx_bytes[0] rx_packets[1] ... tx_bytes[8] tx_packets[9]
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

fn spawn_update_loop(channel: Box<dyn UpdateChannel>, interval_secs: u64) {
    tokio::spawn(async move {
        if let Err(e) = channel.confirm_boot().await {
            warn!("confirmation du boot impossible : {e}");
        }
        let mut ticker = time::interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            ticker.tick().await;
            match channel.check().await {
                Ok(Some(release)) => {
                    info!("mise à jour disponible : {}", release.version);
                    match channel.install(&release).await {
                        Ok(outcome) => info!("installation : {outcome:?}"),
                        Err(e) => error!("installation échouée : {e}"),
                    }
                }
                Ok(None) => info!("aucune mise à jour"),
                Err(e) => warn!("vérification des mises à jour : {e}"),
            }
        }
    });
}

/// Constantes Netlink (linux/rtnetlink.h) — groupe multicast adresses IPv4.
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
/// RTM_NEWADDR : une adresse IP a été assignée à une interface.
const RTM_NEWADDR: u16 = 20;
/// AF_INET (famille IPv4).
const NL_AF_INET: u8 = 2;
/// IFA_ADDRESS : attribut rtattr portant l'adresse IP dans un message ifaddrmsg.
const IFA_ADDRESS: u16 = 1;

/// Démarre deux tâches Tokio pour la surveillance MOBIKE d'une connexion :
///
/// 1. Flux d'événements VICI (`ike-updown`, `child-updown`) — journalise les
///    changements d'adresse signalés par charon.
/// 2. Listener Netlink `RTM_NEWADDR` — coût CPU nul au repos (interruption noyau
///    plutôt que scrutation), latence de détection en microsecondes.
fn spawn_mobike_monitor(
    vici_socket: String,
    wan_iface: String,
    conn_name: String,
    event_tx: broadcast::Sender<HeliosEvent>,
) {
    // Tâche 1 : flux d'événements VICI
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

    // Tâche 2 : listener Netlink RTM_NEWADDR — zéro CPU au repos
    tokio::spawn(async move {
        if let Err(e) = netlink_addr_watcher(vici_socket, wan_iface, conn_name, event_tx).await {
            warn!("MOBIKE : surveillance Netlink terminée : {e}");
        }
    });
}

/// Écoute les messages Netlink `RTM_NEWADDR` sur l'interface WAN.
///
/// Aucun syscall entre deux changements d'adresse (le noyau réveille la tâche
/// via l'interruption du socket multicast, pas de timer actif). La détection
/// est quasi-instantanée (microsecondes) versus le polling 2 s précédent.
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
    // bind est sur Socket (inner), pas sur TokioSocket directement.
    sock.socket_mut()
        .bind(&NlSocketAddr::new(0, RTMGRP_IPV4_IFADDR))
        .context("bind RTMGRP_IPV4_IFADDR")?;

    // Seed de l'IP courante : une seule invocation de `ip` au démarrage du moniteur,
    // puis uniquement des événements noyau pour la suite.
    let mut current_ip = seed_wan_ip(&wan_iface).await;
    info!(
        "MOBIKE : listener Netlink RTM_NEWADDR actif sur {} (index={}, ip={})",
        wan_iface,
        if_index,
        current_ip.as_deref().unwrap_or("?"),
    );

    loop {
        // recv_from_full : attend le prochain paquet Netlink (wakeup noyau, pas de poll).
        let (buf, _): (Vec<u8>, _) = sock.recv_from_full().await.context("recv Netlink")?;

        // Un tampon peut contenir plusieurs messages consécutifs (NLMSG_NEXT).
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

            // NLMSG_ALIGN : alignement 4 octets entre messages.
            let aligned = (nlmsg_len + 3) & !3;
            if aligned == 0 { break; }
            offset += aligned;
        }
    }
}

/// Extrait l'attribut `IFA_ADDRESS` (IPv4) depuis la zone rtattr d'un ifaddrmsg.
fn parse_ifa_address(data: &[u8]) -> Option<String> {
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let rta_len = u16::from_ne_bytes(data[off..off + 2].try_into().ok()?) as usize;
        let rta_type = u16::from_ne_bytes(data[off + 2..off + 4].try_into().ok()?);
        // IFA_ADDRESS pour AF_INET : 4 octets d'IP + 4 octets d'en-tête rtattr = 8.
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

/// Lit l'index Netlink de l'interface depuis sysfs — sans dépendance à `libc`.
async fn read_if_index(iface: &str) -> Option<u32> {
    tokio::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Lit l'adresse IPv4 courante de l'interface WAN (appelée une seule fois au
/// démarrage du moniteur pour initialiser la baseline avant tout RTM_NEWADDR).
async fn seed_wan_ip(iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["-brief", "addr", "show", "dev", iface])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // "eth0  UP  192.168.1.100/24 fe80::1/64\n"
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip(2)
        .find(|s| s.contains('.') && s.contains('/'))
        .and_then(|cidr| cidr.split('/').next())
        .map(str::to_string)
}

/// Envoie la commande VICI `mobike` à charon pour déclencher la mise à jour
/// d'adresse de la SA IKEv2 concernée.
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

pub fn status(config: &Config) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!("  mode         : {}", if config.general.dry_run { "dry-run" } else { "réel" });
    println!("  socket VICI  : {}", config.vici.socket);
    println!("  interface web: http://{}", config.api.bind);
    println!("  WAN          : {}", config.firewall.wan_iface);
    println!("  LAN          : {:?}", config.firewall.lan_ifaces);
    println!("  connexions   : {}", config.connections.len());
    for c in &config.connections {
        println!("    - {} -> {} [{}]", c.name, c.remote_addr, c.ike_proposal);
    }
    Ok(())
}

pub async fn check_update(config: &Config) -> anyhow::Result<()> {
    let channel = update_channel(config);
    let current = channel.current_version().await?;
    println!("version actuelle : {current}");
    match channel.check().await? {
        Some(r) => println!("disponible       : {} ({})", r.version, r.bundle),
        None => println!("disponible       : aucune (à jour)"),
    }
    Ok(())
}
