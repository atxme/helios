//! Orchestration : câblage VICI <-> machine à états <-> pare-feu <-> OTA.

use std::time::Duration;

use anyhow::Context;
use helios_core::{Config, Connection, TunnelEvent, TunnelState};
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_update::{DryRunChannel, RaucChannel, UpdateChannel};
use helios_vici::{Message, ViciClient};
use tokio::time;
use tracing::{error, info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Choisit le backend pare-feu selon le mode et les features compilées.
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

/// Choisit le canal de mise à jour selon le mode.
fn update_channel(config: &Config) -> Box<dyn UpdateChannel> {
    if config.general.dry_run {
        Box::new(DryRunChannel::new(VERSION))
    } else {
        let manifest = config.update.manifest.as_ref().map(Into::into);
        Box::new(RaucChannel::new(VERSION, manifest))
    }
}

/// Boucle principale du daemon.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let policy = config.firewall_policy();
    let fw = firewall_backend(config.general.dry_run);

    // 1. Fail-closed AVANT tout contact réseau : on verrouille d'abord.
    fw.engage_kill_switch(&policy)
        .await
        .context("engagement initial du kill-switch")?;
    let mut state = TunnelState::Down;
    info!("kill-switch engagé, état initial : {state:?}");

    // 2. Montée du tunnel.
    if config.general.dry_run {
        state = simulate_bringup(fw.as_ref(), &policy, state).await?;
    } else {
        state = bring_up_real(&config, fw.as_ref(), state).await?;
    }

    // 3. Vérification périodique des mises à jour.
    if config.update.enabled {
        spawn_update_loop(update_channel(&config), config.update.check_interval_secs);
    }

    // 4. Attente d'un signal d'arrêt. On NE désactive PAS le kill-switch en
    //    sortant : rester fail-closed est plus sûr qu'ouvrir le trafic.
    info!("heliosd opérationnel (état {state:?}). Ctrl-C pour quitter.");
    tokio::signal::ctrl_c().await.ok();
    info!("arrêt demandé : le kill-switch reste engagé (fail-closed)");
    Ok(())
}

/// Simule un cycle de vie complet sur WSL2 pour exercer la chaîne d'orchestration.
async fn simulate_bringup(
    fw: &dyn FirewallBackend,
    policy: &helios_core::FirewallPolicy,
    mut state: TunnelState,
) -> anyhow::Result<TunnelState> {
    info!("[dry-run] simulation de la montée du tunnel");
    for event in [
        TunnelEvent::StartRequested,
        TunnelEvent::IkeEstablished,
        TunnelEvent::ChildUp,
    ] {
        state = state.on(event).context("transition d'état")?;
        info!("événement {event:?} -> état {state:?}");
        fw.apply(policy, state).await.context("application pare-feu")?;
    }
    Ok(state)
}

/// Montée réelle via charon (VICI). Exécutée sur la machine dédiée.
async fn bring_up_real(
    config: &Config,
    fw: &dyn FirewallBackend,
    mut state: TunnelState,
) -> anyhow::Result<TunnelState> {
    let mut client = ViciClient::connect(&config.vici.socket)
        .await
        .with_context(|| format!("connexion VICI sur {}", config.vici.socket))?;
    info!("connecté à charon via {}", config.vici.socket);

    for conn in &config.connections {
        state = state.on(TunnelEvent::StartRequested)?;
        load_connection(&mut client, conn).await?;
        match initiate(&mut client, conn).await {
            Ok(()) => {
                state = state.on(TunnelEvent::ChildUp)?;
                info!("connexion `{}` établie", conn.name);
            }
            Err(e) => {
                error!("échec de `{}` : {e}", conn.name);
                state = state.on(TunnelEvent::Error)?;
            }
        }
        fw.apply(&config.firewall_policy(), state).await?;
    }
    Ok(state)
}

/// Construit et envoie un `load-conn` pour une connexion.
///
/// La proposition IKE porte l'échange hybride post-quantique
/// (ex. `..._ke1_mlkem768`) ; charon poussera les SA correspondantes dans XFRM.
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

    let payload = Message::new().section(&conn.name, body);
    let reply = client.request("load-conn", payload).await?;
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
    let payload = Message::new()
        .kv("child", &conn.name)
        .kv("timeout", "-1");
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

fn spawn_update_loop(channel: Box<dyn UpdateChannel>, interval_secs: u64) {
    tokio::spawn(async move {
        // Confirme le boot courant pour empêcher un rollback RAUC intempestif.
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

/// Sous-commande `status`.
pub fn status(config: &Config) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!("  mode         : {}", if config.general.dry_run { "dry-run" } else { "réel" });
    println!("  socket VICI  : {}", config.vici.socket);
    println!("  WAN          : {}", config.firewall.wan_iface);
    println!("  LAN          : {:?}", config.firewall.lan_ifaces);
    println!("  mode firewall: {:?}", config.firewall.mode);
    println!("  connexions   : {}", config.connections.len());
    for c in &config.connections {
        println!("    - {} -> {} [{}]", c.name, c.remote_addr, c.ike_proposal);
    }
    Ok(())
}

/// Sous-commande `check-update`.
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
