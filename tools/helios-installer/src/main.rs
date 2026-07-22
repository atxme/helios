//! Helper privilégié, local et sans réseau, des mises à jour applicatives.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use helios_update::{
    bundle::{self, BootstrapLayout},
    clear_activation, prepare_switch, read_activation, SwitchGuard, UpdateLayout,
};

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
    /// Installe un bundle signé sur une gateway (ADR-004).
    ///
    /// Premier déploiement comme réinstallation : le contenu est vérifié
    /// entièrement — signature hybride, empreinte de chaque fichier, absence de
    /// fichier surnuméraire — avant la moindre écriture.
    Bootstrap {
        /// Archive produite par `cargo xtask pack`.
        #[arg(long, conflicts_with = "dir")]
        archive: Option<PathBuf>,
        /// Répertoire de bundle déjà extrait.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::InstallPending => install_pending(),
        CommandKind::Bootstrap { archive, dir } => bootstrap(archive, dir),
    }
}

/// Installe un bundle signé, puis rend la main à l'opérateur.
///
/// La commande n'active aucun service et ne démarre rien : sur une gateway
/// neuve, l'identité WireGuard n'existe pas encore et le kill-switch couperait
/// l'accès. La séquence d'après appartient à l'opérateur, avec accès console.
fn bootstrap(archive: Option<PathBuf>, dir: Option<PathBuf>) -> Result<()> {
    let update = UpdateLayout::for_daemon(false);
    let layout = BootstrapLayout::system(update);

    let (root, extracted) = match (archive, dir) {
        (Some(archive), _) => {
            let root = extract(&archive)?;
            (root, true)
        }
        (None, Some(dir)) => (dir, false),
        (None, None) => bail!("indiquer --archive <fichier.tar.gz> ou --dir <répertoire>"),
    };

    let report = bundle::install(&root, &layout)
        .with_context(|| format!("installation du bundle {}", root.display()))?;

    if extracted {
        if let Some(parent) = root.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    let units_reloaded = reload_units();

    println!(
        "helios {} séquence {} installé (canal {})",
        report.version, report.release_sequence, report.channel
    );
    for path in &report.installed {
        println!("  {}", path.display());
    }
    if report.config_preserved {
        println!("  {} conservée telle quelle", layout.config_path.display());
    }
    if let Err(error) = units_reloaded {
        // Les fichiers sont posés et vérifiés : échouer ici annoncerait une
        // installation ratée alors qu'elle a réussi. On le dit fort, sans
        // masquer, parce que les unités restent à recharger.
        eprintln!(
            "\nATTENTION : les unités systemd n'ont pas été rechargées ({error:#}). \
             Exécuter `systemctl daemon-reload` avant d'activer les services."
        );
    }
    println!("\nSuite, avec accès console :");
    println!("  sudo heliosd provision-tpm     # premier déploiement seulement");
    println!("  sudo heliosd init-identity     # affiche la clé publique de la gateway");
    println!("  sudo heliosd peer add --name <nom> --public-key <clé> --admin");
    println!("  sudo systemctl enable --now heliosd helios-update.path");
    Ok(())
}

/// Extrait une archive dans un répertoire jetable et rend la racine du bundle.
fn extract(archive: &Path) -> Result<PathBuf> {
    if !archive.is_file() {
        bail!("{} introuvable", archive.display());
    }
    let workspace = std::env::temp_dir().join(format!("helios-bootstrap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&workspace);
    fs::create_dir_all(&workspace)
        .with_context(|| format!("création de {}", workspace.display()))?;

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&workspace)
        .status()
        .context("exécution de tar")?;
    if !status.success() {
        bail!("extraction de {} échouée ({status})", archive.display());
    }

    // L'archive contient un unique répertoire racine. Tout autre contenu est
    // une archive qui n'a pas été produite par `cargo xtask pack`, et dont on
    // ne devinera pas la disposition.
    let mut entries: Vec<PathBuf> = fs::read_dir(&workspace)
        .with_context(|| format!("lecture de {}", workspace.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    match entries.as_slice() {
        [only] if only.is_dir() => Ok(only.clone()),
        _ => bail!(
            "archive inattendue : un unique répertoire racine est attendu, {} entrée(s) trouvée(s)",
            entries.len()
        ),
    }
}

fn reload_units() -> Result<()> {
    let status = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .context("exécution de systemctl daemon-reload")?;
    if !status.success() {
        bail!("systemctl daemon-reload a échoué ({status})");
    }
    Ok(())
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
