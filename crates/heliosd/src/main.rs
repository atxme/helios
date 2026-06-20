//! `heliosd` — daemon orchestrateur du plan de contrôle.

mod orchestrator;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::{Parser, Subcommand};
use helios_api::AppState;
use helios_core::{Config, HeliosEvent, OrchestratorCmd, TunnelState};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};
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
    /// Lance le daemon (kill-switch + orchestration + interface web).
    Run {
        /// Mode développement : simule le tunnel sans charon, nftables ni modules
        /// IPsec. Identique à `general.dry_run = true` dans la config mais
        /// activable en ligne de commande. Activé automatiquement sur WSL2 si les
        /// modules ESP sont absents.
        #[arg(long)]
        dev: bool,
    },
    /// Affiche la configuration résolue.
    Status,
    /// Vérifie la disponibilité d'une mise à jour.
    CheckUpdate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = Config::load(&cli.config)
        .with_context(|| format!("chargement de {}", cli.config.display()))?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.general.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Command::Run { dev } => {
            apply_dev_mode(&mut config, dev);
            run(config).await
        }
        Command::Status => orchestrator::status(&config),
        Command::CheckUpdate => orchestrator::check_update(&config).await,
    }
}

/// Détermine si le processus tourne sous WSL2 (noyau Microsoft).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Vérifie si les modules ESP (data-plane IPsec) sont réellement disponibles.
fn ipsec_modules_present() -> bool {
    // Le module esp4 chargé expose ce répertoire.
    std::path::Path::new("/sys/module/esp4").exists()
}

/// Active le mode dev si demandé explicitement ou si l'environnement ne peut
/// pas supporter le mode réel (WSL2 sans modules ESP).
fn apply_dev_mode(config: &mut Config, explicit_dev: bool) {
    if explicit_dev {
        config.general.dry_run = true;
        info!("mode --dev activé : simulation du tunnel sans charon ni nftables");
        return;
    }

    // Auto-détection : on bascule en dev si on est sur WSL2 et que le config
    // demande le mode réel mais que les modules IPsec sont absents.
    if !config.general.dry_run && is_wsl2() && !ipsec_modules_present() {
        config.general.dry_run = true;
        warn!(
            "WSL2 détecté sans modules ESP — bascule automatique en mode dev \
             (simulation sans crypto)"
        );
        warn!(
            "Pour forcer le mode réel sur WSL2 : `modprobe esp4 esp6` ou \
             utilisez une machine dédiée"
        );
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
