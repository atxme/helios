//! `heliosd` — daemon orchestrateur du plan de contrôle.

mod orchestrator;

use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use helio_tpm::{BootController, BootDecision, TpmSettings};
use helios_api::AppState;
use aether::{HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelState, API_BIND};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "heliosd", version, about = "Orchestrateur VPN IPsec Helios")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lance le daemon (kill-switch + orchestration + interface web).
    Run {
        /// Mode développement : simule le tunnel sans charon, nftables ni modules
        /// IPsec. Activé automatiquement sur WSL2 si les modules ESP sont absents.
        #[arg(long)]
        dev: bool,
    },
    /// Affiche la configuration résolue et l'état du système.
    Status,
    /// Vérifie la disponibilité d'une mise à jour.
    CheckUpdate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let network = NetworkConfig::load()
        .context("chargement de la config réseau")?;

    match cli.command {
        Command::Run { dev } => {
            let dry_run = resolve_dry_run(dev);
            run(network, dry_run).await
        }
        Command::Status => {
            let dry_run = resolve_dry_run(false);
            orchestrator::status(&network, dry_run)
        }
        Command::CheckUpdate => {
            let dry_run = resolve_dry_run(false);
            orchestrator::check_update(dry_run).await
        }
    }
}

/// Détermine si on est sous WSL2 (noyau Microsoft).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Vérifie si les modules ESP (data-plane IPsec) sont disponibles.
fn ipsec_modules_present() -> bool {
    std::path::Path::new("/sys/module/esp4").exists()
}

/// Résout le mode dry-run : explicite (`--dev`) ou auto-détecté (WSL2 sans ESP).
fn resolve_dry_run(explicit_dev: bool) -> bool {
    if explicit_dev {
        info!("mode --dev activé : simulation sans charon ni nftables");
        return true;
    }
    if is_wsl2() && !ipsec_modules_present() {
        warn!(
            "WSL2 détecté sans modules ESP — bascule automatique en mode dev \
             (simulation sans crypto)"
        );
        return true;
    }
    false
}

async fn run(network: NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    // Validation d'intégrité TPM — AVANT tout réseau.
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm)
        .map_err(|e| anyhow::anyhow!("déscellement TPM échoué — arrêt : {e}"))?;
    match &boot {
        BootDecision::Disabled     => {}
        BootDecision::Bypassed     => warn!("intégrité TPM non vérifiée (enforce=false)"),
        BootDecision::Unsealed(_)  => info!("intégrité du démarrage confirmée (TPM)"),
        BootDecision::Provisioned(_) => warn!("premier boot : provisionnement TOFU effectué"),
        BootDecision::Resealed(_)  => warn!("rescellement post-OTA effectué (billet valide)"),
    }
    let _boot = boot;

    let (event_tx, _)  = broadcast::channel::<HeliosEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OrchestratorCmd>(32);
    let tunnel_state   = Arc::new(RwLock::new(TunnelState::Down));
    let effective_proposals: Arc<RwLock<Option<(String, String)>>> = Arc::new(RwLock::new(None));
    let shared_network = Arc::new(RwLock::new(network));
    let shared_policy  = Arc::new(RwLock::new(
        shared_network.read().await.firewall_policy()
    ));

    let state = AppState::new(
        Arc::clone(&shared_network),
        dry_run,
        Arc::clone(&tunnel_state),
        event_tx.clone(),
        cmd_tx,
        Arc::clone(&effective_proposals),
        Arc::clone(&shared_policy),
    );
    tokio::spawn(async move {
        if let Err(e) = helios_api::serve(state, API_BIND).await {
            tracing::error!("serveur API : {e:#}");
        }
    });

    orchestrator::run(
        shared_network,
        dry_run,
        tunnel_state,
        event_tx,
        cmd_rx,
        effective_proposals,
        shared_policy,
    ).await
}
