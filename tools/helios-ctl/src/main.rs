//! `helios-ctl` — development and control tool for heliosd.
//!
//! ```sh
//! cargo run -p heliosd -- run --dev          # daemon in dev mode
//! cargo run -p helios-ctl -- status
//! cargo run -p helios-ctl -- watch
//! cargo run -p helios-ctl -- network show
//! cargo run -p helios-ctl -- network load config/network.toml
//! ```

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use aether::NetworkConfig;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};

mod api;
mod campaign;
mod enroll;
mod escrow;
mod files;
mod key_nego;
mod peer;
mod profile;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "helios-ctl",
    about = "Test and control tool for heliosd",
    after_help = "\
EXAMPLES:
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
    /// Shows the daemon's current state.
    Status,
    /// Connects the VPN tunnel.
    Connect,
    /// Disconnects the tunnel (kill switch engaged).
    Disconnect,
    /// Real-time event stream over WebSocket. Ctrl-C to quit.
    Watch,
    /// Network configuration management.
    Network {
        #[command(subcommand)]
        command: NetworkCmd,
    },
    /// Client admission on the gateway (ADR-004 §4).
    Peer {
        #[command(subcommand)]
        command: PeerCmd,
    },
    /// Orion client profiles (ADR-004 §6).
    Profile {
        #[command(subcommand)]
        command: ProfileCmd,
    },
    /// Enrolls a client in one go: keys, certificates, admission, profile.
    ///
    /// The gateway supplies everything it knows — its WireGuard identity, its
    /// negotiation certificates and the port they answer on — so the only
    /// things to state are the client's name and the public endpoint. The
    /// resulting file carries the client's private keys: it is born at 0600
    /// and must be destroyed once Orion has imported it.
    Enroll {
        /// Profile name, also used as the peer name on the gateway.
        #[arg(long)]
        name: String,
        /// Gateway's public UDP endpoint (`IP:port` or `FQDN:port`).
        #[arg(long)]
        endpoint: String,
        /// Directory of the operator client CA (`key-nego init-client-ca`).
        #[arg(long, default_value = "./orion-client-ca")]
        client_ca_dir: PathBuf,
        /// Client public key, when the client already holds its own pair.
        #[arg(long)]
        public_key: Option<String>,
        /// Fichier contenant la clé privée WireGuard du client, quand
        /// l'appelant a généré la paire lui-même. Un fichier, pas un
        /// argument : `ps` expose l'argv de tout processus.
        #[arg(long)]
        private_key_file: Option<PathBuf>,
        /// Répertoire d'une identité déjà émise par `key-nego issue-client`.
        /// Obligatoire quand l'admission a eu lieu séparément : la gateway
        /// connaît les empreintes de CES certificats-là.
        #[arg(long)]
        client_pki_dir: Option<PathBuf>,
        /// Negotiation mode, which also becomes the peer's floor.
        #[arg(long, value_enum, default_value = "ml-kem")]
        mode: key_nego::Mode,
        /// Negotiation endpoint. Defaults to the tunnel host with the port
        /// the gateway publishes.
        #[arg(long)]
        negotiation_endpoint: Option<String>,
        /// Name of the protected store entry. Defaults to `orion-<name>`.
        #[arg(long)]
        identity: Option<String>,
        /// Admit the peer as a control-plane administrator.
        #[arg(long)]
        admin: bool,
        /// Revoke a peer of the same name before admitting this identity.
        #[arg(long)]
        replace: bool,
        /// Output file.
        #[arg(long)]
        output: PathBuf,

        // ── Enrôlement hors API ──────────────────────────────────────────
        // L'API vit derrière le tunnel : l'atteindre suppose déjà une
        // connexion. Pour le PREMIER enrôlement, ces trois options prennent
        // le relais — l'opérateur a déjà une session SSH, qui suffit à lire
        // deux certificats publics et à admettre le pair en console.
        /// `key-negotiation-cert.der` de la gateway, récupéré par SSH.
        #[arg(long, requires = "gateway_pq_certificate", requires = "address")]
        gateway_certificate: Option<PathBuf>,
        /// `key-negotiation-pq-cert.json` de la gateway, récupéré par SSH.
        #[arg(long, requires = "gateway_certificate")]
        gateway_pq_certificate: Option<PathBuf>,
        /// VIP affichée par `heliosd peer add`, qui a fait l'admission.
        #[arg(long)]
        address: Option<String>,
        /// URL de l'API interne, pour la seule télémétrie.
        #[arg(long)]
        heliosd_url: Option<String>,
    },
    /// Escrow of the gateway identity — **operator workstation**.
    ///
    /// These commands are offline: they do not use `--url`. The escrow
    /// private key must never be located on the gateway it rescues.
    Escrow {
        #[command(subcommand)]
        command: EscrowCmd,
    },
    /// Offline PKI and authenticated key-negotiation diagnostics.
    KeyNego {
        #[command(subcommand)]
        command: key_nego::KeyNegoCmd,
    },
    /// Runs a predefined test scenario.
    Scenario {
        #[arg(default_value = "nominal")]
        name: String,
    },
    /// End-to-end campaign for post-quantum provisioning.
    ///
    /// The same binary serves both dry-run and target: only the data-plane
    /// scenarios require `--wg-iface` and a real kernel.
    Campaign {
        /// Client WireGuard private key (base64). The matching peer must be
        /// **admitted** on the gateway: admission stays out of band.
        #[arg(long, env = "HELIOS_CAMPAIGN_CLIENT_KEY")]
        client_key: Option<String>,
        /// Gateway WireGuard public key (base64).
        #[arg(long, env = "HELIOS_CAMPAIGN_GATEWAY_KEY")]
        gateway_key: Option<String>,
        /// WireGuard interface to inspect (e.g. `helios0`). Enables the
        /// data-plane scenarios — **target only**.
        #[arg(long)]
        wg_iface: Option<String>,
        /// Runs only one category of scenarios.
        #[arg(long, value_enum)]
        only: Option<campaign::Category>,
        /// Number of passes (endurance campaign beyond 1).
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        /// Generates a key pair to declare, then exits.
        #[arg(long)]
        generate_keys: bool,
    },
}

#[derive(Subcommand)]
enum PeerCmd {
    /// Lists admitted peers.
    List,
    /// Admits a client and assigns its VIP.
    Add {
        /// Friendly name, unique on the gateway.
        #[arg(long)]
        name: String,
        /// Client's Curve25519 public key, base64.
        #[arg(long)]
        public_key: String,
        /// Allows this peer to mutate the control plane and updates.
        #[arg(long)]
        admin: bool,
        /// SHA-256 fingerprint of the client's key-negotiation certificate.
        #[arg(long)]
        key_negotiation_certificate_sha256: Option<String>,
        /// SHA-256 fingerprint of the client's ML-DSA-65 certificate.
        #[arg(long)]
        key_negotiation_pq_certificate_sha256: Option<String>,
        /// Refuses every future network negotiation below this mode.
        #[arg(long, value_enum)]
        minimum_mode: Option<key_nego::Mode>,
    },
    /// Removes a peer from admission.
    Revoke {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Relit un document avec le parseur d'Orion, sans rien installer.
    ///
    /// Diagnostic : quand un import échoue, cette commande dit si le document
    /// est en cause ou si le problème est ailleurs — sans avoir à lancer
    /// Orion, ni à ouvrir un fichier qui contient des secrets.
    Check {
        /// Document à relire (`.orionprofile`, `.json` ou `.conf`).
        path: PathBuf,
    },
    /// Emits a client profile readable by Orion's import.
    Emit {
        /// Profile name, also used as the peer name on the gateway.
        #[arg(long)]
        name: String,
        /// Gateway's public UDP endpoint (`IP:port` or `FQDN:port`).
        #[arg(long)]
        endpoint: String,
        /// Client public key, received out of band. **Recommended mode**:
        /// the client's secret never travels.
        #[arg(long)]
        public_key: Option<String>,
        /// The operator generates the pair and delivers a complete profile.
        /// The only path where a client private key exists outside the
        /// client workstation.
        #[arg(long)]
        with_private_key: bool,
        /// Admits the peer as a control-plane administrator.
        #[arg(long)]
        admin: bool,
        /// Output file. Absent: standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum EscrowCmd {
    /// Generates the operator's escrow key pair.
    Keygen {
        /// Directory to create. The private key stays there, offline.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Opens an escrow and writes the recovery file.
    Open {
        /// Escrow retrieved from the gateway (`wg-key.escrow`).
        #[arg(long)]
        escrow: PathBuf,
        /// Operator's escrow private key.
        #[arg(long)]
        private_key: PathBuf,
        /// Recovery file to produce.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Shows the current network configuration.
    Show,
    /// Loads a network configuration from a TOML file.
    Load {
        /// Path to the network config TOML file.
        file: PathBuf,
    },
}

// ─── API types ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Status {
    state: String,
    version: String,
    wan_iface: String,
    lan_ifaces: Vec<String>,
    wg_peers: Vec<String>,
    allow_ssh_from: Vec<String>,
    peers: Vec<PeerSummary>,
    wg_iface: String,
    wg_listen_port: Option<u16>,
    dry_run: bool,
    split_tunnel_cidrs: Vec<String>,
    mss_clamp: Option<u16>,
    captive_portal_gateway: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PeerSummary {
    name: String,
    public_key: String,
    address: String,
    post_quantum: bool,
}

use crate::api::{CmdResp, NetworkConfigView};

// ─── Display ──────────────────────────────────────────────────────────────────

fn colored_state(s: &str) -> String {
    match s {
        "up" => format!("\x1b[32m{s}\x1b[0m"),
        "connecting" => format!("\x1b[33m{s}\x1b[0m"),
        "captive_portal" => format!("\x1b[33m{s}\x1b[0m"),
        "failed" => format!("\x1b[31m{s}\x1b[0m"),
        _ => format!("\x1b[90m{s}\x1b[0m"),
    }
}

fn state_dot(s: &str) -> &'static str {
    match s {
        "up" => "\x1b[32m●\x1b[0m",
        "connecting" => "\x1b[33m●\x1b[0m",
        "captive_portal" => "\x1b[33m●\x1b[0m",
        "failed" => "\x1b[31m●\x1b[0m",
        _ => "\x1b[90m●\x1b[0m",
    }
}

fn ok() -> &'static str {
    "\x1b[32m✓\x1b[0m"
}
fn fail() -> &'static str {
    "\x1b[31m✗\x1b[0m"
}

fn hh_mm_ss() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "\x1b[2m{:02}:{:02}:{:02}\x1b[0m",
        (s / 3600) % 24,
        (s / 60) % 60,
        s % 60
    )
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

async fn api_status(client: &Client, base: &str) -> Result<Status> {
    client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .context("connection refused — is heliosd running? (cargo run -p heliosd -- run --dev)")?
        .json::<Status>()
        .await
        .context("unexpected JSON response")
}

async fn api_post(client: &Client, base: &str, path: &str) -> Result<CmdResp> {
    client
        .post(format!("{base}{path}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("connection refused")?
        .json::<CmdResp>()
        .await
        .context("unexpected JSON response")
}

fn ws_url(base: &str) -> String {
    base.replace("http://", "ws://")
        .replace("https://", "wss://")
        + "/ws"
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async fn cmd_status(client: &Client, base: &str) -> Result<()> {
    let s = api_status(client, base).await?;
    let dry = if s.dry_run {
        "  \x1b[35m[dry-run]\x1b[0m"
    } else {
        ""
    };
    println!();
    println!("  \x1b[1mheliosd v{}\x1b[0m{}", s.version, dry);
    println!();
    println!("  {}  {}", state_dot(&s.state), colored_state(&s.state));
    println!();
    println!("  {:<14} {}", "WAN", s.wan_iface);
    println!("  {:<14} {}", "LAN", s.lan_ifaces.join(", "));
    println!(
        "  {:<14} {}{}",
        "WireGuard",
        s.wg_iface,
        s.wg_listen_port
            .map(|port| format!(" (UDP {port})"))
            .unwrap_or_else(|| " (port closed)".to_string())
    );
    for peer in &s.peers {
        let pq = if peer.post_quantum { " [PQ]" } else { "" };
        let key = peer.public_key.get(..8).unwrap_or(&peer.public_key);
        println!(
            "  {:<14} {} → {} ({key}…){pq}",
            "Peer", peer.name, peer.address
        );
    }
    if !s.wg_peers.is_empty() {
        println!("  {:<14} {}", "Site-to-site", s.wg_peers.join(", "));
    }
    if !s.allow_ssh_from.is_empty() {
        println!("  {:<14} {}", "SSH allowed", s.allow_ssh_from.join(", "));
    }
    if !s.split_tunnel_cidrs.is_empty() {
        println!(
            "  {:<14} {}",
            "Split tunnel",
            s.split_tunnel_cidrs.join(", ")
        );
    }
    if let Some(mss) = s.mss_clamp {
        println!("  {:<14} {}", "MSS clamp", mss);
    }
    if let Some(gateway) = &s.captive_portal_gateway {
        println!("  {:<14} {}", "Captive portal", gateway);
    }
    println!();
    Ok(())
}

async fn cmd_connect(client: &Client, base: &str) -> Result<()> {
    let r = api_post(client, base, "/api/tunnel/start").await?;
    if r.ok {
        println!("{} connect command sent", ok());
    } else {
        println!("{} refused: {}", fail(), r.error.as_deref().unwrap_or("?"));
    }
    Ok(())
}

async fn cmd_disconnect(client: &Client, base: &str) -> Result<()> {
    let r = api_post(client, base, "/api/tunnel/stop").await?;
    if r.ok {
        println!("{} disconnect sent — kill switch engaged", ok());
    } else {
        println!("{} refused: {}", fail(), r.error.as_deref().unwrap_or("?"));
    }
    Ok(())
}

async fn cmd_watch(base: &str) -> Result<()> {
    let url = ws_url(base);
    println!("\x1b[2m↳ {url}\x1b[0m");
    let (mut stream, _) = connect_async(&url)
        .await
        .context("could not connect — is heliosd running?")?;
    println!("\x1b[2m↳ connected — Ctrl-C to quit\x1b[0m\n");

    while let Some(msg) = stream.next().await {
        if let Ok(Message::Text(text)) = msg {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            print_ws_event(&hh_mm_ss(), &v);
        }
    }
    Ok(())
}

async fn cmd_network_show(client: &Client, base: &str) -> Result<()> {
    let cfg: NetworkConfigView = client
        .get(format!("{base}/api/network"))
        .send()
        .await
        .context("connection refused")?
        .json()
        .await
        .context("unexpected JSON response")?;

    println!();
    println!("  \x1b[1mNetwork config\x1b[0m");
    println!();
    println!(
        "  {:<16} {}",
        "WAN",
        if cfg.wan_iface.is_empty() {
            "(not set)"
        } else {
            &cfg.wan_iface
        }
    );
    println!(
        "  {:<16} {}",
        "LAN",
        if cfg.lan_ifaces.is_empty() {
            "(none)".to_string()
        } else {
            cfg.lan_ifaces.join(", ")
        }
    );
    if !cfg.allow_ssh_from.is_empty() {
        println!(
            "  {:<16} {}",
            "SSH allowed from",
            cfg.allow_ssh_from.join(", ")
        );
    }
    if let Some(ref iface) = cfg.admin_iface {
        println!("  {:<16} {}", "Admin iface", iface);
    }
    println!(
        "  {:<16} {} (UDP {})",
        "WG interface", cfg.wg_iface, cfg.wg_listen_port
    );
    println!(
        "  {:<16} {}",
        "Key negotiation",
        cfg.key_negotiation_port
            .map(|port| format!("UDP {port}"))
            .unwrap_or_else(|| "disabled".to_string())
    );
    println!(
        "  {:<16} {}",
        "Private key",
        if cfg.wg_private_key_configured {
            "configured (hidden)"
        } else {
            "absent"
        }
    );
    println!("  {:<16} {}", "WG address", cfg.wg_address);
    println!("  {:<16} {}", "Peers", cfg.peers.len());
    for p in &cfg.peers {
        let pq = if p.preshared_key_configured {
            "  [PQ]"
        } else {
            ""
        };
        println!("    - {} → {}{}", p.name, p.address, pq);
    }
    println!();
    Ok(())
}

async fn cmd_network_load(client: &Client, base: &str, file: &PathBuf) -> Result<()> {
    let raw = tokio::fs::read_to_string(file)
        .await
        .with_context(|| format!("could not read {}", file.display()))?;

    let config: NetworkConfig =
        toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", file.display()))?;

    let body = serde_json::to_string(&config)?;
    let resp: CmdResp = client
        .post(format!("{base}/api/network"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("connection refused")?
        .json()
        .await
        .context("unexpected JSON response")?;

    if resp.ok {
        println!(
            "{} network config loaded ({} peer(s))",
            ok(),
            config.peers.len()
        );
    } else {
        println!(
            "{} refused: {}",
            fail(),
            resp.error.as_deref().unwrap_or("?")
        );
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
            let msg = v["message"].as_str().unwrap_or("");
            let lc = match level {
                "error" => format!("\x1b[31m{level}\x1b[0m"),
                "warn" => format!("\x1b[33m{level}\x1b[0m"),
                _ => format!("\x1b[90m{level}\x1b[0m"),
            };
            println!("{}  [{}]  {}", ts, lc, msg);
        }
        other => println!("{}  {}  {}", ts, other, v),
    }
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

async fn wait_state(
    client: &Client,
    base: &str,
    target: &str,
    timeout_secs: u64,
) -> Result<Duration> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    loop {
        let elapsed = start.elapsed();
        if elapsed > timeout {
            anyhow::bail!("timeout: state '{target}' not reached within {timeout_secs}s");
        }
        if api_status(client, base).await?.state == target {
            return Ok(elapsed);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

async fn scenario_nominal(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    println!("\n\x1b[1mNominal scenario\x1b[0m");
    println!("────────────────");

    let s = api_status(client, base).await?;
    println!(
        "  1/4  initial state              {} ({})",
        ok(),
        colored_state(&s.state)
    );

    let response = api_post(client, base, "/api/tunnel/start").await?;
    ensure_command(response, "bringing up the interface")?;
    println!("  2/4  connecting…               {} command sent", ok());
    let target = if s.dry_run { "connecting" } else { "up" };
    let t = wait_state(client, base, target, 5).await?;
    println!(
        "       state {target:<10}          {} in {:.0}ms",
        ok(),
        t.as_millis()
    );

    println!("  3/4  2s pause…");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("       {}  ok", ok());

    let response = api_post(client, base, "/api/tunnel/stop").await?;
    ensure_command(response, "stopping the interface")?;
    println!("  4/4  disconnecting…            {} command sent", ok());
    let t = wait_state(client, base, "down", 5).await?;
    println!(
        "       kill switch               {} in {:.0}ms",
        ok(),
        t.as_millis()
    );

    println!(
        "\n  {} nominal completed in \x1b[1m{:.2}s\x1b[0m\n",
        ok(),
        t0.elapsed().as_secs_f32()
    );
    Ok(())
}

async fn scenario_flap(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    let cycles = 5u32;
    println!("\n\x1b[1mFlap scenario\x1b[0m (×{cycles})");
    println!("─────────────");

    let mut up_times = Vec::new();
    let mut down_times = Vec::new();
    let target = if api_status(client, base).await?.dry_run {
        "connecting"
    } else {
        "up"
    };

    for i in 1..=cycles {
        let response = api_post(client, base, "/api/tunnel/start").await?;
        ensure_command(response, "bringing up the interface")?;
        let tu = wait_state(client, base, target, 5).await?;
        up_times.push(tu.as_millis());

        let response = api_post(client, base, "/api/tunnel/stop").await?;
        ensure_command(response, "stopping the interface")?;
        let td = wait_state(client, base, "down", 5).await?;
        down_times.push(td.as_millis());

        println!(
            "  cycle {i}/{cycles}  up={:>4}ms  down={:>4}ms  {}",
            tu.as_millis(),
            td.as_millis(),
            ok()
        );
    }

    let avg_up = up_times.iter().sum::<u128>() / up_times.len() as u128;
    let avg_down = down_times.iter().sum::<u128>() / down_times.len() as u128;
    let max_up = up_times.iter().max().copied().unwrap_or(0);
    let max_down = down_times.iter().max().copied().unwrap_or(0);

    println!();
    println!("  average  up={avg_up}ms  down={avg_down}ms");
    println!("  max      up={max_up}ms  down={max_down}ms");
    println!(
        "\n  {} flap completed in \x1b[1m{:.2}s\x1b[0m\n",
        ok(),
        t0.elapsed().as_secs_f32()
    );
    Ok(())
}

fn ensure_command(response: CmdResp, action: &str) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    anyhow::bail!(
        "{action} refused: {}",
        response.error.as_deref().unwrap_or("unknown error")
    )
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();
    let base = cli.url.trim_end_matches('/');

    match cli.command {
        Cmd::Status => cmd_status(&client, base).await,
        Cmd::Connect => cmd_connect(&client, base).await,
        Cmd::Disconnect => cmd_disconnect(&client, base).await,
        Cmd::Watch => cmd_watch(base).await,
        Cmd::Network { command } => match command {
            NetworkCmd::Show => cmd_network_show(&client, base).await,
            NetworkCmd::Load { file } => cmd_network_load(&client, base, &file).await,
        },
        Cmd::Peer { command } => match command {
            PeerCmd::List => peer::cmd_list(&client, base).await,
            PeerCmd::Add {
                name,
                public_key,
                admin,
                key_negotiation_certificate_sha256,
                key_negotiation_pq_certificate_sha256,
                minimum_mode,
            } => {
                let minimum_mode = minimum_mode.map(Into::into).unwrap_or_else(|| {
                    if key_negotiation_pq_certificate_sha256.is_some() {
                        aether::key_negotiation::ProtectionMode::MlKem
                    } else {
                        aether::key_negotiation::ProtectionMode::Classic
                    }
                });
                peer::cmd_add(
                    &client,
                    base,
                    &name,
                    &public_key,
                    admin,
                    peer::KeyNegotiationAdmission {
                        tls_certificate_sha256: key_negotiation_certificate_sha256.as_deref(),
                        pq_certificate_sha256: key_negotiation_pq_certificate_sha256.as_deref(),
                        minimum_mode,
                    },
                )
                .await
            }
            PeerCmd::Revoke { name } => peer::cmd_revoke(&client, base, &name).await,
        },
        Cmd::Profile { command } => match command {
            ProfileCmd::Check { path } => profile::check(&path),
            ProfileCmd::Emit {
                name,
                endpoint,
                public_key,
                with_private_key,
                admin,
                output,
            } => {
                profile::emit(
                    &client,
                    base,
                    profile::EmitOptions {
                        name,
                        endpoint,
                        public_key,
                        with_private_key,
                        admin,
                        output,
                    },
                )
                .await
            }
        },
        Cmd::Enroll {
            name,
            endpoint,
            client_ca_dir,
            public_key,
            private_key_file,
            client_pki_dir,
            mode,
            negotiation_endpoint,
            identity,
            admin,
            replace,
            output,
            gateway_certificate,
            gateway_pq_certificate,
            address,
            heliosd_url,
        } => {
            // Checked before the gateway is contacted: a missing CA must not
            // be discovered after a peer has been admitted.
            enroll::check_client_ca(&client_ca_dir)?;
            let offline = match (gateway_certificate, gateway_pq_certificate, address) {
                (Some(gateway_certificate), Some(gateway_pq_certificate), Some(address)) => {
                    Some(enroll::OfflineInputs {
                        gateway_certificate,
                        gateway_pq_certificate,
                        address,
                        heliosd_url,
                    })
                }
                // `requires` in the parser already rules out partial
                // combinations; this arm is the online path.
                _ => None,
            };
            enroll::run(
                &client,
                base,
                enroll::EnrollOptions {
                    name,
                    endpoint,
                    client_ca_dir,
                    public_key,
                    private_key_file,
                    client_pki_dir,
                    mode: mode.into(),
                    negotiation_endpoint,
                    identity,
                    admin,
                    replace,
                    output,
                    offline,
                },
            )
            .await
        }
        Cmd::Escrow { command } => match command {
            EscrowCmd::Keygen { output_dir } => escrow::keygen(&output_dir),
            EscrowCmd::Open {
                escrow,
                private_key,
                output,
            } => escrow::open(&escrow, &private_key, &output),
        },
        Cmd::KeyNego { command } => key_nego::run(command).await,
        Cmd::Scenario { name } => match name.as_str() {
            "nominal" => scenario_nominal(&client, base).await,
            "flap" => scenario_flap(&client, base).await,
            other => anyhow::bail!("unknown scenario '{other}'. Available: nominal, flap"),
        },
        Cmd::Campaign {
            client_key,
            gateway_key,
            wg_iface,
            only,
            repeat,
            generate_keys,
        } => {
            if generate_keys {
                campaign::generate_keys();
                return Ok(());
            }
            campaign::run(
                &client,
                base,
                campaign::Options {
                    client_key,
                    gateway_key,
                    wg_iface,
                    only,
                    repeat,
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn current_wireguard_status_is_deserializable() {
        let raw = r#"{
            "state":"down","version":"0.1.0","wan_iface":"eth0",
            "lan_ifaces":["eth1"],"wg_peers":[],"allow_ssh_from":[],
            "peers":[{"name":"orion","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"100.64.1.2/32","post_quantum":false}],
            "wg_iface":"helios0","wg_listen_port":51820,"dry_run":true,
            "split_tunnel_cidrs":[],"mss_clamp":null,"captive_portal_gateway":null
        }"#;
        let status: Status = serde_json::from_str(raw).expect("valid status");
        assert_eq!(status.wg_iface, "helios0");
        assert_eq!(status.peers[0].name, "orion");
    }
}
