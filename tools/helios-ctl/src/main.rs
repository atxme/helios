//! `helios` — interactive and scripted gateway administration.
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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream};

mod api;
mod app_update;
mod campaign;
mod campaign_key_nego;
mod enroll;
mod escrow;
mod files;
mod firmware;
mod inspect;
mod interactive;
mod key_nego;
mod peer;
mod profile;
mod transport;
mod ui;
mod update;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "helios",
    about = "Helios gateway administration",
    after_help = "\
EXAMPLES:
  helios                                      # interactive terminal
  helios update --check                       # passive local plan
  helios firmware list                        # local firmware inventory
  cargo run -p helios-ctl -- status
  cargo run -p helios-ctl -- watch
  cargo run -p helios-ctl -- network show
  cargo run -p helios-ctl -- network load config/network.toml
  cargo run -p helios-ctl -- --url http://100.64.0.1:8080 app-update \
    --manifest heliosd.release.json --binary heliosd
  cargo run -p helios-ctl -- scenario nominal
  cargo run -p helios-ctl -- update                 # on the gateway
  cargo run -p helios-ctl -- --url http://192.168.1.1:8080 status"
)]
struct Cli {
    /// Gateway API over TCP. Without it, the gateway's local administration
    /// socket when present, else the in-tunnel API (http://100.64.0.1:8080).
    /// A dry-run daemon (`heliosd run --dev`) listens on http://127.0.0.1:8080.
    #[arg(long, env = "HELIOS_URL")]
    url: Option<String>,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Opens the interactive administration terminal.
    Shell,
    /// Firmware inventory, prepared updates and verified reboot/recovery through SSH.
    Firmware {
        #[command(subcommand)]
        command: firmware::FirmwareCmd,
    },
    /// Shows the daemon's current state.
    Status,
    /// Connects the VPN tunnel.
    Connect,
    /// Disconnects the tunnel (kill switch engaged).
    Disconnect,
    /// Real-time event stream over WebSocket. Ctrl-C to quit.
    Watch,
    /// One-pass health check: API, tunnel, TPM, firewall, certificates, release.
    Doctor,
    /// Machine health: uptime, load, memory, temperature and TPM posture.
    Health,
    /// nftables ruleset rendered for the current tunnel state.
    Firewall {
        /// The exact nftables text, for copying or diffing.
        #[arg(long)]
        raw: bool,
    },
    /// Trust domain and certificate lifecycle: CA, gateway identity, clients.
    Certificates,
    /// Publisher keys and algorithms an application update must carry.
    Trust,
    /// heliosd release state: active version, staged releases, pending activation.
    Release,
    /// Public key-negotiation material pinned by Orion profiles.
    Negotiation,
    /// heliosd journal on this machine (journalctl). Ctrl-C ends --follow.
    Logs {
        /// Number of most recent lines.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
        /// Also show the module each line comes from.
        #[arg(short, long)]
        verbose: bool,
    },
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
        /// Répertoire de la CA opérateur (`key-nego init-client-ca`).
        ///
        /// Défaut : l'emplacement fixe du compte, que `HELIOS_CLIENT_CA_DIR`
        /// déplace. Il ne dépend **pas** du répertoire courant — voir
        /// `key_nego::default_client_ca_dir`.
        #[arg(long)]
        client_ca_dir: Option<PathBuf>,
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
        /// Trafic capté par le tunnel : une ou plusieurs plages CIDR,
        /// séparées par des virgules.
        ///
        /// Absent = tunnel complet (`0.0.0.0/0`), qui reste le bon défaut.
        /// Le préciser ici plutôt que dans chaque poste évite qu'un parc
        /// finisse avec autant de tables de routage que d'utilisateurs.
        /// Ex. : `--allowed-ips "100.64.0.0/10, 192.168.1.0/24"`
        #[arg(long)]
        allowed_ips: Option<String>,
        /// Destination SSH à travers le tunnel, `utilisateur@hôte`.
        ///
        /// Active le bouton « Terminal SSH » d'Orion. La gateway doit poser
        /// `allow_ssh_over_tunnel`. Absent = aucun terminal proposé.
        #[arg(long)]
        ssh_target: Option<String>,
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
        /// Bloc de confiance §19, tel que `heliosd show-trust-enrolment` l'imprime.
        ///
        /// Sans lui le profil se connecte mais ne peut pas renouveler son
        /// certificat, et Orion le dit. Les valeurs ne sont pas devinables :
        /// ce sont les ancres du domaine et la génération de ce pair.
        #[arg(long, requires = "gateway_certificate")]
        trust_material: Option<PathBuf>,
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
    /// Transfers and activates a signed heliosd release through the admin API.
    AppUpdate {
        /// Signed `helios-binary-release-v1` JSON manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Exact heliosd ELF named by the manifest.
        #[arg(long)]
        binary: PathBuf,
        /// Stages and verifies the release without activating it.
        #[arg(long, conflicts_with = "yes")]
        stage_only: bool,
        /// Activates without an interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Upgrades this gateway's OS and reboots, keeping its identity (ADR-007).
    ///
    /// **Runs on the gateway.** Refreshes the package lists, reports which
    /// pending packages move which PCR, upgrades, then arms a TPM update
    /// window and reboots — which kills this command. Whether the window was
    /// consumed is in the journal at the next boot:
    /// `journalctl --namespace=helios -u heliosd -b | grep -i 'update window'`.
    /// PCR 0/7 changes are refused when sealing is enabled. `--check` is passive.
    Update {
        /// Skips the confirmation.
        #[arg(long)]
        yes: bool,
        /// Shows pending OS packages and firmware without changing the system.
        #[arg(long, conflicts_with = "yes")]
        check: bool,
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
        /// Orion profile of this workstation, for the key-negotiation
        /// scenarios. Its identity must be sealed here.
        ///
        /// **The campaign negotiates for real**: the peer's PSK is
        /// renegotiated then released, so an Orion connected with this same
        /// profile loses its tunnel.
        #[arg(long)]
        profile: Option<String>,
        /// Also runs the scenarios that have to wait — the liveness link
        /// holds a session silent for forty seconds to prove it survives.
        #[arg(long)]
        soak: bool,
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
        /// SHA-256 fingerprint of the client's ML-DSA-87 certificate.
        #[arg(long)]
        key_negotiation_pq_certificate_sha256: Option<String>,
        /// The client's TLS leaf, DER — the file `key-nego issue-client` wrote.
        ///
        /// A gateway holding a trust domain records the leaves themselves, not
        /// their digests, and refuses an admission without them: a peer with
        /// no registry row is a client that connects and can never renew.
        #[arg(long)]
        certificate: Option<PathBuf>,
        /// The client's ML-DSA-87 leaf, its JSON document.
        #[arg(long)]
        pq_certificate: Option<PathBuf>,
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
        /// Document à relire (`.orion`, `.json` ou `.conf`).
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
        /// Trafic capté par le tunnel : une ou plusieurs plages CIDR,
        /// séparées par des virgules.
        ///
        /// Absent = tunnel complet (`0.0.0.0/0`), qui reste le bon défaut.
        /// Le préciser ici plutôt que dans chaque poste évite qu'un parc
        /// finisse avec autant de tables de routage que d'utilisateurs.
        /// Ex. : `--allowed-ips "100.64.0.0/10, 192.168.1.0/24"`
        #[arg(long)]
        allowed_ips: Option<String>,
        /// Destination SSH à travers le tunnel, `utilisateur@hôte`.
        ///
        /// Active le bouton « Terminal SSH » d'Orion. La gateway doit poser
        /// `allow_ssh_over_tunnel`. Absent = aucun terminal proposé.
        #[arg(long)]
        ssh_target: Option<String>,
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
    /// Uplinks, in the gateway's order of preference: the API publishes the
    /// whole set, not a single interface.
    wan_ifaces: Vec<String>,
    lan_ifaces: Vec<String>,
    wg_peers: Vec<String>,
    allow_ssh_from: Vec<String>,
    #[serde(default)]
    admin_ifaces: Vec<String>,
    peers: Vec<PeerSummary>,
    wg_iface: String,
    wg_listen_port: Option<u16>,
    dry_run: bool,
    #[serde(default)]
    key_negotiation_port: Option<u16>,
    split_tunnel_cidrs: Vec<String>,
    mss_clamp: Option<u16>,
    captive_portal_gateway: Option<String>,
    /// Absent from older daemons: every observed handshake then counts.
    #[serde(default)]
    handshake_stale_after_seconds: Option<u64>,
}

impl Status {
    /// Peers whose last WireGuard handshake is still fresh, out of all
    /// admitted peers.
    fn online_peers(&self) -> (usize, usize) {
        let online = self
            .peers
            .iter()
            .filter(|peer| {
                peer.last_handshake_age_seconds.is_some_and(|age| {
                    self.handshake_stale_after_seconds
                        .is_none_or(|stale| age <= stale)
                })
            })
            .count();
        (online, self.peers.len())
    }
}

#[derive(Debug, Deserialize)]
struct PeerSummary {
    name: String,
    public_key: String,
    address: String,
    post_quantum: bool,
    #[serde(default)]
    last_handshake_age_seconds: Option<u64>,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    minimum_key_negotiation_mode: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
}

use crate::api::CmdResp;

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

async fn cmd_connect(client: &Client, base: &str) -> Result<()> {
    accepted(api_post(client, base, "/api/tunnel/start").await?)?;
    let ui = ui::Ui::detect();
    print!(
        "{}{}",
        ui.done("Tunnel start requested"),
        ui.note("Follow it with /status or /watch.")
    );
    Ok(())
}

async fn cmd_disconnect(client: &Client, base: &str) -> Result<()> {
    accepted(api_post(client, base, "/api/tunnel/stop").await?)?;
    let ui = ui::Ui::detect();
    print!(
        "{}{}",
        ui.done("Tunnel stop requested"),
        ui.note("The kill switch stays engaged: no traffic leaves outside the tunnel.")
    );
    Ok(())
}

/// A refusal is a failed command, not a success that prints a cross.
fn accepted(response: CmdResp) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    anyhow::bail!(
        "refused by the gateway: {}",
        response.error.as_deref().unwrap_or("no reason given")
    )
}

async fn cmd_watch(api: &transport::Api) -> Result<()> {
    let url = ws_url(&api.base);
    println!("\x1b[2m↳ {}\x1b[0m", api.describe());
    #[cfg(unix)]
    if let Some(socket) = &api.socket {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .with_context(|| format!("could not connect to {}", socket.display()))?;
        let (stream, _) = tokio_tungstenite::client_async(url.as_str(), stream)
            .await
            .context("WebSocket handshake over the local socket")?;
        return watch_events(stream).await;
    }
    let (stream, _) = connect_async(&url)
        .await
        .context("could not connect — is heliosd running?")?;
    watch_events(stream).await
}

async fn watch_events<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: WebSocketStream<S>,
) -> Result<()> {
    println!("\x1b[2m↳ connected — Ctrl-C to quit\x1b[0m\n");
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; return Ok(()); }
            message = stream.next() => {
                let Some(message) = message else { return Ok(()); };
                if let Ok(Message::Text(text)) = message {
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    print_ws_event(&hh_mm_ss(), &v);
                }
            }
        }
    }
}

async fn cmd_network_load(client: &Client, base: &str, file: &PathBuf) -> Result<()> {
    let raw = tokio::fs::read_to_string(file)
        .await
        .with_context(|| format!("could not read {}", file.display()))?;

    // Parsed once to fail here rather than on the gateway: an invalid file
    // must not travel.
    let config: NetworkConfig =
        toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", file.display()))?;

    // What travels is the operator's document, not a re-serialized
    // `NetworkConfig`. `NetworkConfig` deliberately has no `Serialize`: it
    // carries the gateway's private key and every peer PSK, and a derive
    // there would make any `to_string(&config)` emit them (ADR-006 §4/§5).
    // Sending the document keeps this command's behaviour exactly as it was —
    // a legacy file carrying a plaintext identity still reaches
    // `POST /api/network`, which is what installs it.
    let document: toml::Value =
        toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", file.display()))?;
    let body = serde_json::to_string(&document)?;
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

    accepted(resp)?;
    print!(
        "{}",
        ui::Ui::detect().done(&format!(
            "Network configuration loaded · {} peer(s)",
            config.peers.len()
        ))
    );
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

/// Checks and normalizes an operator-supplied `AllowedIPs` list.
///
/// Here rather than at render time, and that is the whole point: `render`
/// round-trips the document through Orion's own parser, so a malformed list
/// *would* be caught — but as "the emitted profile is not readable by Orion —
/// this is a tooling bug", which is a lie when the operator simply mistyped a
/// prefix. Worse, on `enroll` it would surface **after** the peer had been
/// admitted on the gateway, leaving an admission with no profile to go with it.
///
/// The normalized form is what gets written, so a document and the screen that
/// displays it never disagree on spelling.
/// Reads a file and encodes it base64, for the two certificates an admission
/// carries.
///
/// A path rather than a value on the command line: `ps` shows every process's
/// argv, and a certificate pasted there is one more place an operator can put
/// the wrong bytes without noticing.
fn read_base64(path: PathBuf) -> Result<String> {
    use base64::Engine as _;
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn check_allowed_ips(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    orion_core::profile_import::validate_allowed_ips(&value)
        .context("--allowed-ips")
        .context(
            "trafic capté invalide — une ou plusieurs plages CIDR séparées par des virgules, \
             par exemple \"100.64.0.0/10, 192.168.1.0/24\"",
        )?;
    Ok(Some(orion_core::profile_import::normalize_cidr_list(
        &value,
    )))
}

/// Checks an operator-supplied SSH destination, before anything is admitted.
///
/// Same placement argument as [`check_allowed_ips`], with more at stake: this
/// value ends up as an argument of a process Orion spawns. `orion-core` owns
/// the grammar — an allow-list of characters — and checking it here means a
/// typo is a refusal rather than a document that fails on the user's machine.
fn check_ssh_target(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_string();
    orion_core::profile_import::validate_ssh_target(&value).context("--ssh-target")?;
    Ok(Some(value))
}

// ─── main ─────────────────────────────────────────────────────────────────────

/// Same override as heliosd, for a non-default runtime directory.
fn admin_socket() -> std::path::PathBuf {
    std::env::var_os("HELIOS_ADMIN_SOCKET")
        .map(Into::into)
        .unwrap_or_else(|| aether::LOCAL_ADMIN_SOCKET.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Two rustls providers are compiled in — `ring` for the negotiation's QUIC
    // stack, AWS-LC for the private channel — so the process-level default is
    // ambiguous, and `hyper-rustls` builds `reqwest`'s TLS config without
    // naming one (`connector.rs:269`). Settled here, before the first client.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    let api = transport::Api::resolve(cli.url.as_deref(), &admin_socket())?;

    match cli.command {
        None | Some(Cmd::Shell) => interactive::run(api).await,
        Some(command) => execute_command(&api, command).await,
    }
}

async fn execute_command(api: &transport::Api, command: Cmd) -> Result<()> {
    let (client, base) = (&api.client, api.base.as_str());
    match command {
        Cmd::Shell => anyhow::bail!("open the shell at the command entry point"),
        Cmd::Firmware { command } => firmware::run(command),
        Cmd::Status => inspect::status(client, base).await,
        Cmd::Connect => cmd_connect(client, base).await,
        Cmd::Disconnect => cmd_disconnect(client, base).await,
        Cmd::Watch => cmd_watch(api).await,
        Cmd::Doctor => inspect::doctor(api).await,
        Cmd::Health => inspect::health(client, base).await,
        Cmd::Firewall { raw } => inspect::firewall(client, base, raw).await,
        Cmd::Certificates => inspect::certificates(client, base).await,
        Cmd::Trust => inspect::trust(client, base).await,
        Cmd::Release => inspect::release(client, base).await,
        Cmd::Negotiation => inspect::negotiation(client, base).await,
        Cmd::Logs {
            lines,
            follow,
            verbose,
        } => inspect::logs(lines, follow, verbose).await,
        Cmd::Network { command } => match command {
            NetworkCmd::Show => inspect::network(client, base).await,
            NetworkCmd::Load { file } => cmd_network_load(client, base, &file).await,
        },
        Cmd::Peer { command } => match command {
            PeerCmd::List => inspect::peers(client, base).await,
            PeerCmd::Add {
                name,
                public_key,
                admin,
                key_negotiation_certificate_sha256,
                key_negotiation_pq_certificate_sha256,
                certificate,
                pq_certificate,
                minimum_mode,
            } => {
                let certificate = certificate.map(read_base64).transpose()?;
                let pq_certificate = pq_certificate.map(read_base64).transpose()?;
                let minimum_mode = minimum_mode.map(Into::into).unwrap_or_else(|| {
                    if key_negotiation_pq_certificate_sha256.is_some() {
                        aether::key_negotiation::ProtectionMode::MlKem
                    } else {
                        aether::key_negotiation::ProtectionMode::Classic
                    }
                });
                peer::cmd_add(
                    client,
                    base,
                    &name,
                    &public_key,
                    admin,
                    peer::KeyNegotiationAdmission {
                        tls_certificate_sha256: key_negotiation_certificate_sha256.as_deref(),
                        pq_certificate_sha256: key_negotiation_pq_certificate_sha256.as_deref(),
                        tls_certificate: certificate.as_deref(),
                        pq_certificate: pq_certificate.as_deref(),
                        minimum_mode,
                    },
                )
                .await
            }
            PeerCmd::Revoke { name } => peer::cmd_revoke(client, base, &name).await,
        },
        Cmd::Profile { command } => match command {
            ProfileCmd::Check { path } => profile::check(&path),
            ProfileCmd::Emit {
                name,
                endpoint,
                public_key,
                with_private_key,
                admin,
                allowed_ips,
                ssh_target,
                output,
            } => {
                let allowed_ips = check_allowed_ips(allowed_ips)?;
                let ssh_target = check_ssh_target(ssh_target)?;
                let ssh_target = check_ssh_target(ssh_target)?;
                profile::emit(
                    client,
                    base,
                    profile::EmitOptions {
                        name,
                        endpoint,
                        public_key,
                        with_private_key,
                        admin,
                        allowed_ips,
                        ssh_target,
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
            allowed_ips,
            ssh_target,
            output,
            gateway_certificate,
            gateway_pq_certificate,
            address,
            heliosd_url,
            trust_material,
        } => {
            // Checked before the gateway is contacted: a missing CA must not
            // be discovered after a peer has been admitted.
            let client_ca_dir = client_ca_dir.unwrap_or_else(key_nego::default_client_ca_dir);
            enroll::check_client_ca(&client_ca_dir)?;
            let allowed_ips = check_allowed_ips(allowed_ips)?;
            let offline = match (gateway_certificate, gateway_pq_certificate, address) {
                (Some(gateway_certificate), Some(gateway_pq_certificate), Some(address)) => {
                    Some(enroll::OfflineInputs {
                        gateway_certificate,
                        gateway_pq_certificate,
                        address,
                        heliosd_url,
                        trust_material,
                    })
                }
                // `requires` in the parser already rules out partial
                // combinations; this arm is the online path.
                _ => None,
            };
            enroll::run(
                client,
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
                    allowed_ips,
                    ssh_target,
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
        Cmd::AppUpdate {
            manifest,
            binary,
            stage_only,
            yes,
        } => {
            app_update::run(
                client,
                base,
                app_update::Options {
                    manifest,
                    binary,
                    stage_only,
                    yes,
                },
            )
            .await
        }
        Cmd::Update { yes, check } => {
            if check {
                update::check()
            } else {
                update::run(yes)
            }
        }
        Cmd::Scenario { name } => match name.as_str() {
            "nominal" => scenario_nominal(client, base).await,
            "flap" => scenario_flap(client, base).await,
            other => anyhow::bail!("unknown scenario '{other}'. Available: nominal, flap"),
        },
        Cmd::Campaign {
            client_key,
            gateway_key,
            wg_iface,
            only,
            repeat,
            generate_keys,
            profile,
            soak,
        } => {
            if generate_keys {
                campaign::generate_keys();
                return Ok(());
            }
            campaign::run(
                client,
                base,
                campaign::Options {
                    client_key,
                    gateway_key,
                    wg_iface,
                    only,
                    repeat,
                    profile,
                    soak,
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests;
