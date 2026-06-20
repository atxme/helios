//! Orchestration : câblage VICI <-> machine à états <-> pare-feu <-> OTA.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use helios_core::{
    Config, Connection, FirewallPolicy, HeliosEvent, OrchestratorCmd, TunnelEvent, TunnelState,
};
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use helios_vici::{Message, ViciClient};
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
                Some(OrchestratorCmd::Disconnect) => {
                    info!("déconnexion demandée via l'interface web");
                    emit_log(&event_tx, "info", "Déconnexion demandée via l'interface web");
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
        .kv("version", "2");
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
