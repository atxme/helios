//! Couche d'accès REST vers heliosd.
//!
//! `run()` tourne dans le runtime Tokio du thread principal et fait deux choses :
//! 1. Interroge `/api/status` toutes les secondes (poll) → envoie à l'UI via `mpsc`.
//! 2. Exécute les commandes reçues de l'UI via `ApiCommand`.

use std::sync::Arc;
use std::time::Duration;

use helios_core::TunnelState;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

// ─── Commandes de l'UI vers le worker ────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ApiCommand {
    Connect,
    Disconnect,
    SetUrl(String),
    /// L'utilisateur a cliqué « Connexion validée » dans le portail captif.
    AcknowledgeCaptivePortal,
    /// Mise à jour des CIDRs en split-tunneling. `vec![]` = désactiver.
    SetSplitTunnel(Vec<String>),
}

// ─── État transmis à l'UI ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AppStatus {
    pub tunnel:                 TunnelState,
    pub version:                String,
    pub peer:                   String,
    pub ike_proposal:           String,
    pub active_profile:         Option<String>,
    pub dry_run:                bool,
    pub reachable:              bool,
    pub rx_bps:                 u64,
    pub tx_bps:                 u64,
    /// IP de la passerelle du portail captif courant. `None` = pas de portail.
    pub captive_portal_gateway: Option<String>,
    /// MSS clamping actif (PMTUD). `None` = pas de clamping.
    pub mss_clamp:              Option<u16>,
    /// CIDRs actuellement en split-tunneling.
    pub split_tunnel_cidrs:     Vec<String>,
}

impl AppStatus {
    pub fn unreachable() -> Self {
        Self { reachable: false, ..Default::default() }
    }
}

// ─── Désérialisation REST ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct StatusResp {
    state: String,
    version: String,
    #[serde(default)]
    connections: Vec<ConnSummary>,
    dry_run: bool,
    active_profile: Option<String>,
    #[serde(default)]
    captive_portal_gateway: Option<String>,
    #[serde(default)]
    mss_clamp: Option<u16>,
    #[serde(default)]
    split_tunnel_cidrs: Vec<String>,
}

#[derive(Deserialize, Default, Clone)]
struct ConnSummary {
    remote_addr:  String,
    ike_proposal: String,
}

fn parse_state(s: &str) -> TunnelState {
    match s {
        "up"             => TunnelState::Up,
        "connecting"     => TunnelState::Connecting,
        "rekeying"       => TunnelState::Rekeying,
        "failed"         => TunnelState::Failed,
        "captive_portal" => TunnelState::CaptivePortal,
        _                => TunnelState::Down,
    }
}

// ─── Requêtes publiques ───────────────────────────────────────────────────────

pub async fn fetch_status(client: Client, base: String) -> anyhow::Result<AppStatus> {
    let resp: StatusResp = client
        .get(format!("{base}/api/status"))
        .timeout(Duration::from_secs(4))
        .send()
        .await?
        .json()
        .await?;

    let conn = resp.connections.first().cloned().unwrap_or_default();
    Ok(AppStatus {
        tunnel:                 parse_state(&resp.state),
        version:                resp.version,
        peer:                   conn.remote_addr,
        ike_proposal:           conn.ike_proposal,
        active_profile:         resp.active_profile,
        dry_run:                resp.dry_run,
        reachable:              true,
        rx_bps:                 0,
        tx_bps:                 0,
        captive_portal_gateway: resp.captive_portal_gateway,
        mss_clamp:              resp.mss_clamp,
        split_tunnel_cidrs:     resp.split_tunnel_cidrs,
    })
}

pub async fn post_cmd(client: Client, base: String, path: &str) -> anyhow::Result<()> {
    client
        .post(format!("{base}{path}"))
        .timeout(Duration::from_secs(4))
        .send()
        .await?;
    Ok(())
}

async fn post_split_tunnel(client: Client, base: String, cidrs: Vec<String>) -> anyhow::Result<()> {
    client
        .post(format!("{base}/api/split-tunnel"))
        .json(&serde_json::json!({ "cidrs": cidrs }))
        .timeout(Duration::from_secs(4))
        .send()
        .await?;
    Ok(())
}

// ─── Worker principal ─────────────────────────────────────────────────────────

/// Tâche Tokio : poll status + traitement des commandes UI.
pub async fn run(
    status_tx: std::sync::mpsc::Sender<AppStatus>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<ApiCommand>,
    initial_url: String,
) {
    let client = Client::builder()
        .build()
        .unwrap_or_else(|_| Client::new());

    let url: Arc<RwLock<String>> = Arc::new(RwLock::new(initial_url));

    // Tâche de polling : toutes les secondes.
    {
        let client = client.clone();
        let url    = Arc::clone(&url);
        let tx     = status_tx.clone();
        tokio::spawn(async move {
            loop {
                let base   = url.read().await.clone();
                let status = fetch_status(client.clone(), base).await
                    .unwrap_or_else(|_| AppStatus::unreachable());
                let _ = tx.send(status);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // Traitement des commandes émises par l'UI.
    while let Some(cmd) = cmd_rx.recv().await {
        let base = url.read().await.clone();
        match cmd {
            ApiCommand::Connect => {
                let _ = post_cmd(client.clone(), base, "/api/tunnel/start").await;
            }
            ApiCommand::Disconnect => {
                let _ = post_cmd(client.clone(), base, "/api/tunnel/stop").await;
            }
            ApiCommand::SetUrl(new_url) => {
                *url.write().await = new_url;
            }
            ApiCommand::AcknowledgeCaptivePortal => {
                let _ = post_cmd(client.clone(), base, "/api/captive-portal/release").await;
            }
            ApiCommand::SetSplitTunnel(cidrs) => {
                let _ = post_split_tunnel(client.clone(), base, cidrs).await;
            }
        }
    }
}
