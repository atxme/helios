//! Privileged, local, network-free helper for application updates.

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
    about = "Locally installs an already signed and staged heliosd release"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Consumes `/var/lib/helios/updates/activate.json`.
    InstallPending,
    /// Installs a signed bundle on a gateway (ADR-004).
    ///
    /// First deployment and reinstallation alike: the content is fully
    /// verified — hybrid signature, each file's fingerprint, absence of any
    /// extra file — before the slightest write.
    Bootstrap {
        /// Archive produced by `cargo xtask pack`.
        #[arg(long, conflicts_with = "dir")]
        archive: Option<PathBuf>,
        /// Already-extracted bundle directory.
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

/// Installs a signed bundle, then hands control back to the operator.
///
/// The command activates no service and starts nothing: on a fresh gateway,
/// the WireGuard identity does not exist yet and the kill switch would cut
/// off access. The next sequence belongs to the operator, with console
/// access.
fn bootstrap(archive: Option<PathBuf>, dir: Option<PathBuf>) -> Result<()> {
    let update = UpdateLayout::for_daemon(false);
    let layout = BootstrapLayout::system(update);

    let (root, extracted) = match (archive, dir) {
        (Some(archive), _) => {
            let root = extract(&archive)?;
            (root, true)
        }
        (None, Some(dir)) => (dir, false),
        (None, None) => bail!("provide --archive <file.tar.gz> or --dir <directory>"),
    };

    let report = bundle::install(&root, &layout)
        .with_context(|| format!("installing bundle {}", root.display()))?;

    if extracted {
        if let Some(parent) = root.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    let units_reloaded = reload_units();

    println!(
        "helios {} sequence {} installed (channel {})",
        report.version, report.release_sequence, report.channel
    );
    for path in &report.installed {
        println!("  {}", path.display());
    }
    if report.config_preserved {
        println!("  {} kept as is", layout.config_path.display());
    }
    for path in &report.removed {
        println!("  {} removed (replaced by helios)", path.display());
    }
    if let Err(error) = units_reloaded {
        // The files are laid down and verified: failing here would announce
        // a failed installation when it succeeded. We say so loudly, without
        // hiding it, because the units still need reloading.
        eprintln!(
            "\nWARNING: systemd units were not reloaded ({error:#}). \
             Run `systemctl daemon-reload` before activating the services."
        );
    }
    println!("\nNext, with console access:");
    println!("  sudo heliosd provision-tpm     # first deployment only");
    println!("  sudo heliosd init-identity     # shows the gateway's public key");
    println!("  sudo heliosd peer add --name <name> --public-key <key> --admin");
    println!("  sudo systemctl enable --now heliosd helios-update.path helios-update-window.timer");
    Ok(())
}

/// Extracts an archive into a disposable directory and returns the bundle root.
fn extract(archive: &Path) -> Result<PathBuf> {
    if !archive.is_file() {
        bail!("{} not found", archive.display());
    }
    let workspace = std::env::temp_dir().join(format!("helios-bootstrap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&workspace);
    fs::create_dir_all(&workspace).with_context(|| format!("creating {}", workspace.display()))?;

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&workspace)
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!("extraction of {} failed ({status})", archive.display());
    }

    // The archive contains a single root directory. Any other content is an
    // archive that was not produced by `cargo xtask pack`, and whose layout
    // will not be guessed.
    let mut entries: Vec<PathBuf> = fs::read_dir(&workspace)
        .with_context(|| format!("reading {}", workspace.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    match entries.as_slice() {
        [only] if only.is_dir() => Ok(only.clone()),
        _ => bail!(
            "unexpected archive: a single root directory is expected, {} entry(ies) found",
            entries.len()
        ),
    }
}

fn reload_units() -> Result<()> {
    let status = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .context("running systemctl daemon-reload")?;
    if !status.success() {
        bail!("systemctl daemon-reload failed ({status})");
    }
    Ok(())
}

/// Consumes one activation request, whatever the outcome.
///
/// The activation is cleared *before* the rollback is attempted, and that
/// order is the point. `helios-update.path` re-triggers this service on the
/// mere existence of the request file, so an activation left behind by a
/// rollback that could not run turns a single failed update into a gateway
/// that restarts every thirty seconds until someone notices. A request that
/// has already restarted the daemon has been consumed; retrying it on its own
/// is never the right answer.
fn install_pending() -> Result<()> {
    let layout = UpdateLayout::for_daemon(false);
    let request = read_activation(&layout.activation_path).context("reading activation")?;
    wait_activation_delay(request.requested_at_unix, request.delay_seconds);

    let guard =
        prepare_switch(&layout, request.release_sequence).context("preparing the atomic switch")?;
    let outcome = activate_and_check(&layout, &guard);
    match outcome {
        Ok(()) => {
            if let Err(error) = guard.confirm(&layout.state_path) {
                clear_activation(&layout.activation_path)?;
                restore(&layout, &guard).context("rollback after confirmation failure")?;
                return Err(error).context("persisting the confirmed sequence");
            }
            clear_activation(&layout.activation_path)?;
            println!(
                "heliosd {} sequence {} confirmed",
                guard.version, guard.sequence
            );
            Ok(())
        }
        Err(error) => {
            clear_activation(&layout.activation_path)?;
            restore(&layout, &guard)
                .with_context(|| format!("rollback of the previous binary after: {error:#}"))?;
            Err(error)
        }
    }
}

fn activate_and_check(layout: &UpdateLayout, guard: &SwitchGuard) -> Result<()> {
    match fs::remove_file(&layout.ready_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing the old readiness marker"),
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
        .context("the previous version did not return to a ready state")
}

fn restart_service() -> Result<()> {
    let service = std::env::var("HELIOS_SERVICE_NAME").unwrap_or_else(|_| "heliosd.service".into());
    let status = Command::new("systemctl")
        .args(["restart", &service])
        .status()
        .with_context(|| format!("running systemctl restart {service}"))?;
    if !status.success() {
        bail!("systemctl restart {service} failed with {status}");
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
        "heliosd did not publish the expected version and mode in {} within {} seconds",
        path.display(),
        timeout.as_secs()
    )
}

/// Reads the readiness marker written by `heliosd`.
///
/// `mode_reel` (real mode) is the wire literal `heliosd` writes to that
/// marker file; it is kept as-is here because it is a cross-component
/// protocol string, not a message — renaming it would require a matching
/// change in `heliosd`, which is out of scope for this file.
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

    fn test_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "helios-installer-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn readiness_requires_version_and_real_mode() {
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
        assert!(readiness_matches("anything", None, false));
        assert!(readiness_matches(
            "version=1.2.0\nmode_reel=false\n",
            Some("1.2.0"),
            false
        ));
        assert!(readiness_matches("mode_reel=true\n", None, true));
        assert!(!readiness_matches(
            "version=1.2.0-extra\nmode_reel=true",
            Some("1.2.0"),
            true
        ));
        assert!(readiness_matches(
            "version=1.2.0\nmode_reel=true\nfirewall_enforced=false\n",
            Some("1.2.0"),
            true
        ));
    }

    #[test]
    fn command_line_requires_one_bootstrap_source() {
        assert!(matches!(
            Cli::try_parse_from(["helios-installer", "install-pending"])
                .unwrap()
                .command,
            CommandKind::InstallPending
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "helios-installer",
                "bootstrap",
                "--archive",
                "release.tar.gz"
            ])
            .unwrap()
            .command,
            CommandKind::Bootstrap {
                archive: Some(_),
                dir: None
            }
        ));
        assert!(Cli::try_parse_from([
            "helios-installer",
            "bootstrap",
            "--archive",
            "release.tar.gz",
            "--dir",
            "release"
        ])
        .is_err());
        assert!(bootstrap(None, None)
            .unwrap_err()
            .to_string()
            .contains("provide"));
    }

    #[test]
    fn readiness_wait_returns_immediately_or_times_out() {
        let directory = test_directory("readiness");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("ready");
        fs::write(&marker, "version=2.0.0\nmode_reel=true\n").unwrap();

        wait_ready(&marker, Duration::from_millis(50), Some("2.0.0"), true).unwrap();
        assert!(wait_ready(&marker, Duration::ZERO, Some("different"), true)
            .unwrap_err()
            .to_string()
            .contains("did not publish"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn extraction_requires_an_archive_with_one_directory_root() {
        let directory = test_directory("archive");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(directory.join("payload/bundle")).unwrap();
        fs::write(directory.join("payload/bundle/manifest.json"), b"{}").unwrap();
        let valid = directory.join("valid.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&valid)
            .arg("-C")
            .arg(directory.join("payload"))
            .arg("bundle")
            .status()
            .unwrap();
        assert!(status.success());

        let root = extract(&valid).unwrap();
        assert!(root.join("manifest.json").is_file());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
        assert!(extract(&directory.join("absent.tar.gz")).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn past_activation_times_never_sleep() {
        let started = std::time::Instant::now();
        wait_activation_delay(0, 0);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
