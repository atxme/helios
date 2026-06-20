//! `heliosd` — daemon orchestrateur du plan de contrôle.

mod orchestrator;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::{Parser, Subcommand};
use helios_api::AppState;
use helios_core::{Config, HeliosEvent, OrchestratorCmd, TunnelState};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "heliosd", version, about = "Orchestrateur VPN IPsec Helios")]
struct Cli {
    #[arg(long, default_value = "/etc/helios/helios.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lance le daemon (kill-switch + orchestration du tunnel + interface web).
    Run,
    /// Affiche la configuration résolue.
    Status,
    /// Vérifie la disponibilité d'une mise à jour.
    CheckUpdate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("chargement de {}", cli.config.display()))?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.general.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Command::Run => run(config).await,
        Command::Status => orchestrator::status(&config),
        Command::CheckUpdate => orchestrator::check_update(&config).await,
    }
}

async fn run(config: Config) -> anyhow::Result<()> {
    let (event_tx, _) = broadcast::channel::<HeliosEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OrchestratorCmd>(32);
    let tunnel_state = Arc::new(RwLock::new(TunnelState::Down));

    if config.api.enabled {
        let state = AppState::new(
            Arc::new(config.clone()),
            Arc::clone(&tunnel_state),
            event_tx.clone(),
            cmd_tx,
        );
        let bind = config.api.bind.clone();
        tokio::spawn(async move {
            if let Err(e) = helios_api::serve(state, &bind).await {
                tracing::error!("serveur API : {e:#}");
            }
        });
    }

    orchestrator::run(config, tunnel_state, event_tx, cmd_rx).await
}
