//! `helios-ctl` — outil de développement et de contrôle de heliosd.
//!
//! ```sh
//! cargo run -p heliosd -- run --dev          # daemon en mode dev
//! cargo run -p helios-ctl -- status
//! cargo run -p helios-ctl -- watch
//! cargo run -p helios-ctl -- network show
//! cargo run -p helios-ctl -- network load config/network.toml
//! ```

use std::{path::PathBuf, time::{Duration, Instant}};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use aether::NetworkConfig;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "helios-ctl",
    about = "Outil de test et de contrôle de heliosd",
    after_help = "\
EXEMPLES:
  cargo run -p helios-ctl -- status
  cargo run -p helios-ctl -- watch
  cargo run -p helios-ctl -- network show
  cargo run -p helios-ctl -- network load config/network.toml
  cargo run -p helios-ctl -- scenario nominal
  cargo run -p helios-ctl -- --url http://192.168.1.1:8080 status"
)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080", env = "HELIOS_URL")]
    url: String,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Affiche l'état courant du daemon.
    Status,
    /// Connecte le tunnel VPN.
    Connect,
    /// Déconnecte le tunnel (kill-switch engagé).
    Disconnect,
    /// Flux d'événements temps réel via WebSocket. Ctrl-C pour quitter.
    Watch,
    /// Gestion de la configuration réseau.
    Network {
        #[command(subcommand)]
        command: NetworkCmd,
    },
    /// Exécute un scénario de test prédéfini.
    Scenario {
        #[arg(default_value = "nominal")]
        name: String,
    },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Affiche la configuration réseau courante.
    Show,
    /// Charge une configuration réseau depuis un fichier TOML.
    Load {
        /// Chemin vers le fichier TOML de config réseau.
        file: PathBuf,
    },
}

// ─── Types API ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Status {
    state: String,
    version: String,
    wan_iface: String,
    lan_ifaces: Vec<String>,
    wg_peers: Vec<String>,
    connections: Vec<ConnSummary>,
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct ConnSummary {
    name: String,
    remote_addr: String,
}

#[derive(Debug, Deserialize)]
struct CmdResp {
    ok: bool,
    error: Option<String>,
}

// ─── Affichage ────────────────────────────────────────────────────────────────

fn colored_state(s: &str) -> String {
    match s {
        "up"         => format!("\x1b[32m{s}\x1b[0m"),
        "rekeying"   => format!("\x1b[33m{s}\x1b[0m"),
        "connecting" => format!("\x1b[33m{s}\x1b[0m"),
        "failed"     => format!("\x1b[31m{s}\x1b[0m"),
        _            => format!("\x1b[90m{s}\x1b[0m"),
    }
}

fn state_dot(s: &str) -> &'static str {
    match s {
        "up"         => "\x1b[32m●\x1b[0m",
        "rekeying"   => "\x1b[33m●\x1b[0m",
        "connecting" => "\x1b[33m●\x1b[0m",
        "failed"     => "\x1b[31m●\x1b[0m",
        _            => "\x1b[90m●\x1b[0m",
    }
}

fn ok()   -> &'static str { "\x1b[32m✓\x1b[0m" }
fn fail() -> &'static str { "\x1b[31m✗\x1b[0m" }

fn hh_mm_ss() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("\x1b[2m{:02}:{:02}:{:02}\x1b[0m", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

async fn api_status(client: &Client, base: &str) -> Result<Status> {
    client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .context("connexion refusée — heliosd tourne-t-il ? (cargo run -p heliosd -- run --dev)")?
        .json::<Status>()
        .await
        .context("réponse JSON inattendue")
}

async fn api_post(client: &Client, base: &str, path: &str) -> Result<CmdResp> {
    client
        .post(format!("{base}{path}"))
        .send()
        .await
        .context("connexion refusée")?
        .json::<CmdResp>()
        .await
        .context("réponse JSON inattendue")
}

fn ws_url(base: &str) -> String {
    base.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
}

// ─── Commandes ────────────────────────────────────────────────────────────────

async fn cmd_status(client: &Client, base: &str) -> Result<()> {
    let s = api_status(client, base).await?;
    let dry = if s.dry_run { "  \x1b[35m[dry-run]\x1b[0m" } else { "" };
    println!();
    println!("  \x1b[1mheliosd v{}\x1b[0m{}", s.version, dry);
    println!();
    println!("  {}  {}", state_dot(&s.state), colored_state(&s.state));
    println!();
    println!("  {:<14} {}", "WAN",       s.wan_iface);
    println!("  {:<14} {}", "LAN",       s.lan_ifaces.join(", "));
    println!("  {:<14} {}", "Pairs WG", s.wg_peers.join(", "));
    for c in &s.connections {
        println!("  {:<14} {} → {}", c.name, c.name, c.remote_addr);
    }
    println!();
    Ok(())
}

async fn cmd_connect(client: &Client, base: &str) -> Result<()> {
    let r = api_post(client, base, "/api/tunnel/start").await?;
    if r.ok {
        println!("{} commande de connexion envoyée", ok());
    } else {
        println!("{} refusé : {}", fail(), r.error.as_deref().unwrap_or("?"));
    }
    Ok(())
}

async fn cmd_disconnect(client: &Client, base: &str) -> Result<()> {
    let r = api_post(client, base, "/api/tunnel/stop").await?;
    if r.ok {
        println!("{} déconnexion envoyée — kill-switch engagé", ok());
    } else {
        println!("{} refusé : {}", fail(), r.error.as_deref().unwrap_or("?"));
    }
    Ok(())
}

async fn cmd_watch(base: &str) -> Result<()> {
    let url = ws_url(base);
    println!("\x1b[2m↳ {url}\x1b[0m");
    let (mut stream, _) = connect_async(&url)
        .await
        .context("impossible de se connecter — heliosd tourne-t-il ?")?;
    println!("\x1b[2m↳ connecté — Ctrl-C pour quitter\x1b[0m\n");

    while let Some(msg) = stream.next().await {
        if let Ok(Message::Text(text)) = msg {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            print_ws_event(&hh_mm_ss(), &v);
        }
    }
    Ok(())
}

async fn cmd_network_show(client: &Client, base: &str) -> Result<()> {
    let cfg: NetworkConfig = client
        .get(format!("{base}/api/network"))
        .send()
        .await
        .context("connexion refusée")?
        .json()
        .await
        .context("réponse JSON inattendue")?;

    println!();
    println!("  \x1b[1mConfig réseau\x1b[0m");
    println!();
    println!("  {:<16} {}", "WAN", if cfg.wan_iface.is_empty() { "(non défini)" } else { &cfg.wan_iface });
    println!("  {:<16} {}", "LAN", if cfg.lan_ifaces.is_empty() { "(aucune)".to_string() } else { cfg.lan_ifaces.join(", ") });
    if !cfg.allow_ssh_from.is_empty() {
        println!("  {:<16} {}", "SSH autorisé de", cfg.allow_ssh_from.join(", "));
    }
    if let Some(ref iface) = cfg.admin_iface {
        println!("  {:<16} {}", "Iface admin", iface);
    }
    println!("  {:<16} {} (UDP {})", "Interface WG", cfg.wg_iface, cfg.wg_listen_port);
    println!("  {:<16} {}", "Adresse WG", cfg.wg_address);
    println!("  {:<16} {}", "Pairs", cfg.peers.len());
    for p in &cfg.peers {
        let pq = if p.preshared_key.is_some() { "  [PQ]" } else { "" };
        println!("    - {} → {}{}", p.name, p.address, pq);
    }
    println!();
    Ok(())
}

async fn cmd_network_load(client: &Client, base: &str, file: &PathBuf) -> Result<()> {
    let raw = tokio::fs::read_to_string(file)
        .await
        .with_context(|| format!("impossible de lire {}", file.display()))?;

    let config: NetworkConfig = toml::from_str(&raw)
        .with_context(|| format!("TOML invalide dans {}", file.display()))?;

    let body = serde_json::to_string(&config)?;
    let resp: CmdResp = client
        .post(format!("{base}/api/network"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("connexion refusée")?
        .json()
        .await
        .context("réponse JSON inattendue")?;

    if resp.ok {
        println!("{} config réseau chargée ({} pair(s))",
            ok(), config.peers.len());
    } else {
        println!("{} refusé : {}", fail(), resp.error.as_deref().unwrap_or("?"));
    }
    Ok(())
}

fn print_ws_event(ts: &str, v: &Value) {
    match v["type"].as_str().unwrap_or("?") {
        "state_changed" => {
            let state = v["state"].as_str().unwrap_or("?");
            println!("{}  {}  {}", ts, state_dot(state), colored_state(state));
        }
        "log" => {
            let level = v["level"].as_str().unwrap_or("info");
            let msg   = v["message"].as_str().unwrap_or("");
            let lc = match level {
                "error" => format!("\x1b[31m{level}\x1b[0m"),
                "warn"  => format!("\x1b[33m{level}\x1b[0m"),
                _       => format!("\x1b[90m{level}\x1b[0m"),
            };
            println!("{}  [{}]  {}", ts, lc, msg);
        }
        other => println!("{}  {}  {}", ts, other, v),
    }
}

// ─── Scénarios ────────────────────────────────────────────────────────────────

async fn wait_state(client: &Client, base: &str, target: &str, timeout_secs: u64) -> Result<Duration> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    loop {
        let elapsed = start.elapsed();
        if elapsed > timeout {
            anyhow::bail!("timeout : état '{target}' non atteint en {timeout_secs}s");
        }
        if api_status(client, base).await?.state == target {
            return Ok(elapsed);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

async fn scenario_nominal(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    println!("\n\x1b[1mScénario nominal\x1b[0m");
    println!("────────────────");

    let s = api_status(client, base).await?;
    println!("  1/4  état initial              {} ({})", ok(), colored_state(&s.state));

    api_post(client, base, "/api/tunnel/start").await?;
    println!("  2/4  connexion…                {} commande envoyée", ok());
    let t = wait_state(client, base, "up", 5).await?;
    println!("       tunnel Up                 {} en {:.0}ms", ok(), t.as_millis());

    println!("  3/4  pause 2s…");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("       {}  ok", ok());

    api_post(client, base, "/api/tunnel/stop").await?;
    println!("  4/4  déconnexion…              {} commande envoyée", ok());
    let t = wait_state(client, base, "down", 5).await?;
    println!("       kill-switch               {} en {:.0}ms", ok(), t.as_millis());

    println!("\n  {} nominal terminé en \x1b[1m{:.2}s\x1b[0m\n", ok(), t0.elapsed().as_secs_f32());
    Ok(())
}

async fn scenario_flap(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    let cycles = 5u32;
    println!("\n\x1b[1mScénario flap\x1b[0m (×{cycles})");
    println!("─────────────");

    let mut up_times   = Vec::new();
    let mut down_times = Vec::new();

    for i in 1..=cycles {
        api_post(client, base, "/api/tunnel/start").await?;
        let tu = wait_state(client, base, "up", 5).await?;
        up_times.push(tu.as_millis());

        api_post(client, base, "/api/tunnel/stop").await?;
        let td = wait_state(client, base, "down", 5).await?;
        down_times.push(td.as_millis());

        println!("  cycle {i}/{cycles}  up={:>4}ms  down={:>4}ms  {}", tu.as_millis(), td.as_millis(), ok());
    }

    let avg_up   = up_times.iter().sum::<u128>() / up_times.len() as u128;
    let avg_down = down_times.iter().sum::<u128>() / down_times.len() as u128;
    let max_up   = up_times.iter().max().copied().unwrap_or(0);
    let max_down = down_times.iter().max().copied().unwrap_or(0);

    println!();
    println!("  moyenne  up={avg_up}ms  down={avg_down}ms");
    println!("  max      up={max_up}ms  down={max_down}ms");
    println!("\n  {} flap terminé en \x1b[1m{:.2}s\x1b[0m\n", ok(), t0.elapsed().as_secs_f32());
    Ok(())
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();
    let base = cli.url.trim_end_matches('/');

    match cli.command {
        Cmd::Status       => cmd_status(&client, base).await,
        Cmd::Connect      => cmd_connect(&client, base).await,
        Cmd::Disconnect   => cmd_disconnect(&client, base).await,
        Cmd::Watch        => cmd_watch(base).await,
        Cmd::Network { command } => match command {
            NetworkCmd::Show          => cmd_network_show(&client, base).await,
            NetworkCmd::Load { file } => cmd_network_load(&client, base, &file).await,
        },
        Cmd::Scenario { name } => match name.as_str() {
            "nominal" => scenario_nominal(&client, base).await,
            "flap"    => scenario_flap(&client, base).await,
            other     => anyhow::bail!(
                "scénario inconnu '{other}'. Disponibles : nominal, flap"
            ),
        },
    }
}
