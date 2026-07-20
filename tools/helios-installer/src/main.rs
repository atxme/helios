//! Helper privilégié, local et sans réseau, des mises à jour applicatives.

use std::{
    fs,
    path::Path,
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use helios_update::{clear_activation, prepare_switch, read_activation, SwitchGuard, UpdateLayout};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(
    name = "helios-installer",
    about = "Installe localement une release heliosd déjà signée et stagée"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Consomme `/var/lib/helios/updates/activate.json`.
    InstallPending,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::InstallPending => install_pending(),
    }
}

fn install_pending() -> Result<()> {
    let layout = UpdateLayout::for_daemon(false);
    let request = read_activation(&layout.activation_path).context("lecture de l’activation")?;
    wait_activation_delay(request.requested_at_unix, request.delay_seconds);

    let guard = prepare_switch(&layout, request.release_sequence)
        .context("préparation de la bascule atomique")?;
    let outcome = activate_and_check(&layout, &guard);
    match outcome {
        Ok(()) => {
            if let Err(error) = guard.confirm(&layout.state_path) {
                restore(&layout, &guard).context("rollback après échec de confirmation")?;
                clear_activation(&layout.activation_path)?;
                return Err(error).context("persistance de la séquence confirmée");
            }
            clear_activation(&layout.activation_path)?;
            println!(
                "heliosd {} séquence {} confirmé",
                guard.version, guard.sequence
            );
            Ok(())
        }
        Err(error) => {
            restore(&layout, &guard).context("rollback du binaire précédent")?;
            clear_activation(&layout.activation_path)?;
            Err(error)
        }
    }
}

fn activate_and_check(layout: &UpdateLayout, guard: &SwitchGuard) -> Result<()> {
    match fs::remove_file(&layout.ready_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).context("suppression de l’ancien marqueur de disponibilité")
        }
    }
    restart_service()?;
    wait_ready(
        &layout.ready_path,
        HEALTH_TIMEOUT,
        Some(&guard.version),
        true,
    )
}

fn restore(layout: &UpdateLayout, guard: &SwitchGuard) -> Result<()> {
    guard.rollback()?;
    match fs::remove_file(&layout.ready_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    restart_service()?;
    wait_ready(&layout.ready_path, HEALTH_TIMEOUT, None, true)
        .context("l’ancienne version n’a pas retrouvé son état disponible")
}

fn restart_service() -> Result<()> {
    let service = std::env::var("HELIOS_SERVICE_NAME").unwrap_or_else(|_| "heliosd.service".into());
    let status = Command::new("systemctl")
        .args(["restart", &service])
        .status()
        .with_context(|| format!("exécution de systemctl restart {service}"))?;
    if !status.success() {
        bail!("systemctl restart {service} a échoué avec {status}");
    }
    Ok(())
}

fn wait_ready(
    path: &Path,
    timeout: Duration,
    expected_version: Option<&str>,
    require_real: bool,
) -> Result<()> {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if let Ok(content) = fs::read_to_string(path) {
            if readiness_matches(&content, expected_version, require_real) {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "heliosd n’a pas publié dans {} la version et le mode attendus sous {} secondes",
        path.display(),
        timeout.as_secs()
    )
}

fn readiness_matches(content: &str, expected_version: Option<&str>, require_real: bool) -> bool {
    let version_ok = expected_version.is_none_or(|version| {
        content
            .lines()
            .any(|line| line == format!("version={version}"))
    });
    let mode_ok = !require_real || content.lines().any(|line| line == "mode_reel=true");
    version_ok && mode_ok
}

fn wait_activation_delay(requested_at: u64, delay: u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let activate_at = requested_at.saturating_add(delay);
    if activate_at > now {
        thread::sleep(Duration::from_secs(activate_at - now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disponibilite_exige_version_et_mode_reel() {
        assert!(readiness_matches(
            "version=1.2.0\nmode_reel=true\n",
            Some("1.2.0"),
            true
        ));
        assert!(!readiness_matches(
            "version=1.1.0\nmode_reel=true\n",
            Some("1.2.0"),
            true
        ));
        assert!(!readiness_matches(
            "version=1.2.0\nmode_reel=false\n",
            Some("1.2.0"),
            true
        ));
    }
}
