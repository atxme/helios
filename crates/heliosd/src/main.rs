//! `heliosd` — daemon orchestrateur du plan de contrôle.
//!
//! Il chapeaute strongSwan (négociation via VICI), impose le kill-switch
//! (nftables) selon l'état du tunnel, et gère les mises à jour OTA (RAUC).

mod orchestrator;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use helios_core::Config;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "heliosd", version, about = "Orchestrateur VPN IPsec Helios")]
struct Cli {
    /// Chemin du fichier de configuration.
    #[arg(long, default_value = "/etc/helios/helios.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lance le daemon (kill-switch + orchestration du tunnel).
    Run,
    /// Affiche l'état courant et la configuration résolue.
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
        Command::Run => orchestrator::run(config).await,
        Command::Status => orchestrator::status(&config),
        Command::CheckUpdate => orchestrator::check_update(&config).await,
    }
}
