//! `helios-ctl update` — upgrade the gateway's OS without losing its identity.
//!
//! # What it does
//!
//! Refreshes the package lists, shows what the upgrade would touch, upgrades,
//! then arms a TPM update window and reboots. That is the whole chain, in one
//! command, run **on the gateway** — `helios-ctl` ships in the gateway bundle
//! next to `heliosd`, and an operator upgrading the OS is already in a session
//! on that machine.
//!
//! # Why the TPM is questioned before `apt`, not after
//!
//! `apt upgrade` is the point of no return: once the kernel is replaced, the
//! PCRs move at the next reboot whether or not a window was ever armed, and an
//! unarmed reboot loses the vaults — every client re-enrolled. Arming needs a
//! **nominal** unseal, and that condition is knowable before anything is
//! written. So the command asks `tpm update-readiness` first and refuses the
//! upgrade outright when the answer is not yes; finding out at
//! `prepare-update` time, after the upgrade, would be finding out too late.
//!
//! The command ends by killing itself: `prepare-update --reboot` reboots, so
//! there is nothing to report afterwards and nothing to wait for. Whether the
//! window was consumed is written in the journal at the next boot, which is
//! where an operator looks anyway:
//!
//! ```text
//! journalctl --namespace=helios -u heliosd -b | grep -i 'update window'
//! ```
//!
//! Arming needs the TPM secret, so it is a local `sudo heliosd tpm`
//! subprocess. [ADR-007](../../../docs/adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md)
//! keeps it off the API deliberately: the API lives behind the very tunnel the
//! window exists to preserve, and a remotely triggerable window is a remotely
//! triggerable exposure.
//!
//! # Why it still classifies the pending packages
//!
//! Because the three cases lead to different operations, and the difference is
//! only visible before the reboot:
//!
//! - nothing in the boot chain — the PCRs will not move and no window is
//!   needed, though arming one costs nothing since a nominal unseal revokes it;
//! - kernel or bootloader (PCR 4) — exactly what the window covers;
//! - firmware or Secure Boot database (PCR 0/7) — **beyond** the window, which
//!   binds those two PCRs and will not open. That upgrade falls back to reseal
//!   ticket plus escrow, and learning it here beats learning it from a gateway
//!   that no longer starts.
//!
//! Initramfs regeneration — microcode, `linux-firmware` — is deliberately not
//! flagged: under GRUB the initrd is measured into PCR 8/9, which Helios does
//! not seal. Flagging it would raise an alarm for an upgrade that changes
//! nothing the sealing depends on.

use std::process::{Command, Output, Stdio};

use anyhow::{Context as _, Result};

/// Path of `heliosd` on an installed gateway.
///
/// Same value as `ExecStart` in `deploy/systemd/heliosd.service`, which is the
/// authority: the installer publishes releases under `/opt/helios` and points
/// `current` at the live one.
const INSTALLED_HELIOSD: &str = "/opt/helios/current/heliosd";

/// What an upgraded package does to the PCRs Helios seals against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootChainImpact {
    /// Nothing the sealing depends on.
    None,
    /// PCR 4 — kernel and boot chain. This is what the window covers.
    PcrFour,
    /// PCR 0 or 7 — firmware, Secure Boot database. Beyond the window.
    PcrZeroSeven,
}

/// Packages that move PCR 4: the kernel image and what loads it.
const PCR_FOUR_PREFIXES: &[&str] = &[
    "linux-image",
    "grub-efi",
    "grub-pc",
    "grub-common",
    "grub2-common",
    "shim-signed",
];

/// Packages that move PCR 0 or 7: firmware and the Secure Boot databases.
const PCR_ZERO_SEVEN_PREFIXES: &[&str] = &["fwupd", "secureboot-db"];

pub fn classify_package(name: &str) -> BootChainImpact {
    if PCR_ZERO_SEVEN_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return BootChainImpact::PcrZeroSeven;
    }
    if PCR_FOUR_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return BootChainImpact::PcrFour;
    }
    BootChainImpact::None
}

/// Extracts the packages `apt-get -s upgrade` would install.
///
/// Only `Inst` lines matter: `Conf` repeats the same package, and counting it
/// twice would report every kernel upgrade as two.
pub fn parse_simulated_upgrade(output: &str) -> Vec<(String, BootChainImpact)> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("Inst "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| (name.to_string(), classify_package(name)))
        .collect()
}

/// State of the update window as `heliosd tpm update-status` reports it.
#[derive(Debug, PartialEq, Eq)]
pub enum WindowState {
    Armed,
    None,
}

/// Whether a window could be armed, as `heliosd tpm update-readiness` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Nominal unseal: arming will work.
    Ready,
    /// Nothing is sealed to the PCRs — the upgrade has no secret to lose.
    SealingDisabled,
    /// The TPM answers, but this boot cannot arm a window.
    Unavailable,
}

pub fn parse_readiness(output: &str) -> Result<Readiness> {
    let mut verdicts = output.lines().filter_map(|line| match line.trim() {
        "ready" => Some(Readiness::Ready),
        "disabled" => Some(Readiness::SealingDisabled),
        "unavailable" => Some(Readiness::Unavailable),
        _ => None,
    });
    match (verdicts.next(), verdicts.next()) {
        (Some(state), None) => Ok(state),
        _ => anyhow::bail!(
            "unexpected `tpm update-readiness` output {:?} — does this heliosd carry \
             the update window?",
            output.trim()
        ),
    }
}

/// Reads the verdict out of `heliosd tpm update-status`.
///
/// The verdict is the one line that is exactly `armed` or `none`; anything else
/// is dropped. A `heliosd` older than this tool logs to stdout, and a status
/// probe on a gateway that never armed a window logs an ESAPI error for the
/// absent NV index — the verdict then arrives after several lines of journal.
/// A log line can never be mistaken for a verdict: the format always prefixes a
/// timestamp and a level.
///
/// Requiring **exactly one** verdict is what keeps this from guessing: no line
/// at all means another binary answered, and two would mean the output is not
/// what this tool thinks it is. Guessing `none` there would arm a second
/// window over an unfinished one.
pub fn parse_window_state(output: &str) -> Result<WindowState> {
    let mut verdicts = output.lines().filter_map(|line| match line.trim() {
        "armed" => Some(WindowState::Armed),
        "none" => Some(WindowState::None),
        _ => None,
    });
    match (verdicts.next(), verdicts.next()) {
        (Some(state), None) => Ok(state),
        _ => anyhow::bail!(
            "unexpected `tpm update-status` output {:?} — does this heliosd carry \
             the update window?",
            output.trim()
        ),
    }
}

// ─── The command ──────────────────────────────────────────────────────────────

pub fn run(yes: bool) -> Result<()> {
    let heliosd = locate_heliosd()?;

    // Refuse to stack a second window on an unfinished run: the operator would
    // otherwise never learn that a previous reboot never happened.
    if window_state(&heliosd)? == WindowState::Armed {
        anyhow::bail!(
            "a window is already armed — a previous run did not reboot. Reboot to \
             consume it, or `sudo {heliosd} tpm cancel-update`."
        );
    }

    // Everything below this line is irreversible in the way that matters: once
    // `apt upgrade` has replaced the kernel, the PCRs move at the next reboot
    // whether or not a window was ever armed. So the ability to arm one is
    // established *here*, while doing nothing is still an option — an
    // unreachable TPM or a non-nominal boot is a refusal, not a warning.
    let arm_window = match readiness(&heliosd).context(
        "checking whether an update window can be armed — refusing to upgrade without \
         that answer, since the vaults are what an unarmed reboot loses",
    )? {
        Readiness::Ready => true,
        Readiness::SealingDisabled => {
            println!(
                "TPM sealing is disabled on this gateway — the upgrade has no sealed \
                 secret to lose, so no window will be armed and no reboot ordered."
            );
            false
        }
        Readiness::Unavailable => anyhow::bail!(
            "this boot cannot arm an update window (see the reason logged just \
             above) — the reboot after an upgrade would lose the vaults and force \
             every client to be re-enrolled. Repair the TPM state first (reseal \
             ticket, escrow), or upgrade deliberately with `sudo apt upgrade` and \
             accept that cost."
        ),
    };

    println!("==> Refreshing package lists");
    sudo_apt(&["update"]).context("refreshing the package lists")?;

    let pending = pending_upgrades()?;
    println!();
    report_pending(&pending);

    if pending.is_empty() {
        println!("\nNothing to upgrade.");
        return Ok(());
    }
    if !yes && !confirm(arm_window)? {
        println!("aborted");
        return Ok(());
    }

    println!("\n==> Upgrading");
    sudo_apt(&["-y", "upgrade"]).context("upgrading the packages")?;

    if !arm_window {
        println!("\nUpgrade done. Reboot when it suits you: nothing is sealed to the PCRs.");
        return Ok(());
    }

    // Say what happens next *before* ordering it: this process is about to be
    // killed by the reboot it asks for, so anything printed afterwards may
    // never reach the terminal.
    println!("\n==> Arming the update window and rebooting");
    println!("    The connection will drop. Once the gateway is back:");
    println!("      journalctl --namespace=helios -u heliosd -b | grep -i 'update window'");
    println!();
    heliosd_tpm(&heliosd, &["prepare-update", "--reboot"]).context("arming the update window")?;

    // Reached only if the reboot did not happen.
    anyhow::bail!(
        "the window is armed but the machine did not reboot. Reboot it now — the \
         window expires on its own — or `sudo {heliosd} tpm cancel-update`."
    )
}

fn report_pending(pending: &[(String, BootChainImpact)]) {
    if pending.is_empty() {
        println!("Pending upgrades none");
        return;
    }
    let covered = names_with(pending, BootChainImpact::PcrFour);
    let beyond = names_with(pending, BootChainImpact::PcrZeroSeven);

    println!("Pending upgrades {} package(s)", pending.len());
    if !covered.is_empty() {
        println!(
            "  PCR 4   {} — covered by the update window",
            covered.join(", ")
        );
    }
    if !beyond.is_empty() {
        println!(
            "  PCR 0/7 {} — {} BEYOND the window: it binds those PCRs and will not \
             open. The gateway will fall back to the reseal ticket and lose its \
             vaults. Hold those packages unless the escrow is ready.",
            beyond.join(", "),
            crate::fail()
        );
    }
    if covered.is_empty() && beyond.is_empty() {
        println!("  nothing touches the boot chain — the PCRs will not move");
    }
}

fn names_with(pending: &[(String, BootChainImpact)], wanted: BootChainImpact) -> Vec<&str> {
    pending
        .iter()
        .filter(|(_, impact)| *impact == wanted)
        .map(|(name, _)| name.as_str())
        .collect()
}

fn confirm(arm_window: bool) -> Result<bool> {
    use std::io::{BufRead as _, Write as _};

    println!();
    if arm_window {
        println!("About to upgrade, arm a TPM update window carrying the current secret,");
        println!("and reboot immediately. While the window is open, someone with physical");
        println!("access who boots another signed OS can read the secret, undetectably");
        println!("(ADR-007). Rebooting at once is what keeps that short.");
    } else {
        println!("About to upgrade. No window will be armed and no reboot ordered.");
    }
    print!("Proceed? [y/N] ");
    std::io::stdout().flush().ok();

    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("reading the confirmation")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

// ─── Subprocesses ─────────────────────────────────────────────────────────────

/// Finds `heliosd`: the installed path first, then whatever `PATH` resolves.
///
/// The fallback is what makes the command usable on a development gateway
/// running from a build tree, without adding a flag nobody sets in production.
fn locate_heliosd() -> Result<String> {
    if std::path::Path::new(INSTALLED_HELIOSD).is_file() {
        return Ok(INSTALLED_HELIOSD.to_string());
    }
    let found = Command::new("sh")
        .args(["-c", "command -v heliosd"])
        .output()
        .context("looking for heliosd")?;
    let path = String::from_utf8_lossy(&found.stdout).trim().to_string();
    if found.status.success() && !path.is_empty() {
        return Ok(path);
    }
    anyhow::bail!(
        "heliosd not found at {INSTALLED_HELIOSD} nor on PATH — is this command \
         running on the gateway?"
    )
}

fn window_state(heliosd: &str) -> Result<WindowState> {
    let output =
        heliosd_tpm_output(heliosd, &["update-status"]).context("reading the window state")?;
    parse_window_state(&String::from_utf8_lossy(&output.stdout))
}

/// Asked only once no window is armed: the readiness probe unseals, and an
/// unseal consumes an armed window.
fn readiness(heliosd: &str) -> Result<Readiness> {
    let output = heliosd_tpm_output(heliosd, &["update-readiness"])?;
    parse_readiness(&String::from_utf8_lossy(&output.stdout))
}

fn pending_upgrades() -> Result<Vec<(String, BootChainImpact)>> {
    // `-s` simulates: it installs nothing and needs no privilege.
    let output = Command::new("apt-get")
        .args(["-s", "upgrade"])
        .output()
        .context("running apt-get -s upgrade — is this a Debian-family gateway?")?;
    anyhow::ensure!(
        output.status.success(),
        "apt-get -s upgrade failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(parse_simulated_upgrade(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Runs `apt-get` under `sudo`, non-interactively.
///
/// `DEBIAN_FRONTEND=noninteractive` keeps a package that would prompt over a
/// modified configuration file from hanging the upgrade with no terminal to
/// answer on; it keeps the existing file, which is the conservative choice for
/// a gateway whose configuration was edited on purpose.
fn sudo_apt(arguments: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .arg("DEBIAN_FRONTEND=noninteractive")
        .arg("apt-get")
        .args(arguments)
        .status()
        .context("running apt-get")?;
    anyhow::ensure!(
        status.success(),
        "apt-get {} failed ({status})",
        arguments.join(" ")
    );
    Ok(())
}

/// Runs `sudo <heliosd> tpm …` with the terminal attached.
///
/// Inheriting stdio is what lets `sudo` prompt for a password and what lets
/// `prepare-update` print its own progress; a captured invocation would leave
/// the operator staring at a silent terminal waiting for input.
fn heliosd_tpm(heliosd: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .arg(heliosd)
        .arg("tpm")
        .args(arguments)
        .status()
        .with_context(|| format!("running {heliosd} tpm {}", arguments.join(" ")))?;
    anyhow::ensure!(
        status.success(),
        "`{heliosd} tpm {}` failed ({status})",
        arguments.join(" ")
    );
    Ok(())
}

/// Same, capturing stdout for the one caller that parses it.
fn heliosd_tpm_output(heliosd: &str, arguments: &[&str]) -> Result<Output> {
    let output = Command::new("sudo")
        .arg(heliosd)
        .arg("tpm")
        .args(arguments)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running {heliosd} tpm {}", arguments.join(" ")))?;
    anyhow::ensure!(
        output.status.success(),
        "`{heliosd} tpm {}` failed ({})",
        arguments.join(" "),
        output.status
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kernel upgrade is the case the window exists for.
    #[test]
    fn the_kernel_and_the_boot_loader_are_pcr_four() {
        for package in [
            "linux-image-amd64",
            "linux-image-6.1.0-15-amd64",
            "grub-efi-amd64",
            "grub-efi-amd64-signed",
            "shim-signed",
        ] {
            assert_eq!(
                classify_package(package),
                BootChainImpact::PcrFour,
                "{package} must be reported as moving PCR 4"
            );
        }
    }

    /// Firmware and Secure Boot databases move the two PCRs the window itself
    /// is bound to, so it cannot cover them. Misclassifying them as PCR 4
    /// would send an operator into a reboot the window cannot survive.
    #[test]
    fn firmware_and_secure_boot_are_beyond_the_window() {
        for package in ["fwupd", "fwupd-signed", "secureboot-db"] {
            assert_eq!(
                classify_package(package),
                BootChainImpact::PcrZeroSeven,
                "{package} must be reported as beyond the window"
            );
        }
    }

    /// Initramfs contents land in PCR 8/9, which Helios does not seal.
    /// Reporting them would raise an alarm for an upgrade that changes nothing.
    #[test]
    fn ordinary_and_initramfs_packages_are_not_flagged() {
        for package in [
            "openssl",
            "nginx",
            "systemd",
            "intel-microcode",
            "amd64-microcode",
            "linux-firmware",
        ] {
            assert_eq!(
                classify_package(package),
                BootChainImpact::None,
                "{package} must not be flagged"
            );
        }
    }

    #[test]
    fn the_simulated_upgrade_lists_each_package_once() {
        let output = "\
Reading package lists...
Inst linux-image-amd64 [6.1.0-13] (6.1.0-15 Debian:12/stable [amd64])
Inst openssl [3.0.11-1] (3.0.14-1 Debian:12/stable [amd64])
Conf linux-image-amd64 (6.1.0-15 Debian:12/stable [amd64])
Conf openssl (3.0.14-1 Debian:12/stable [amd64])
";
        let parsed = parse_simulated_upgrade(output);
        assert_eq!(
            parsed,
            vec![
                ("linux-image-amd64".to_string(), BootChainImpact::PcrFour),
                ("openssl".to_string(), BootChainImpact::None),
            ]
        );
    }

    #[test]
    fn nothing_pending_parses_to_nothing() {
        assert!(parse_simulated_upgrade("Reading package lists...\n0 upgraded.\n").is_empty());
    }

    #[test]
    fn the_window_state_is_read_strictly() {
        assert_eq!(parse_window_state("armed\n").unwrap(), WindowState::Armed);
        assert_eq!(parse_window_state(" none \n").unwrap(), WindowState::None);
        // Anything else means another binary answered: refuse rather than
        // guess, since guessing "none" would arm a second window.
        assert!(parse_window_state("").is_err());
        assert!(parse_window_state("unknown subcommand").is_err());
        // Two verdicts are not a verdict either.
        assert!(parse_window_state("armed\nnone\n").is_err());
    }

    #[test]
    fn the_readiness_verdict_is_read_the_same_way() {
        assert_eq!(parse_readiness("ready\n").unwrap(), Readiness::Ready);
        assert_eq!(
            parse_readiness("disabled\n").unwrap(),
            Readiness::SealingDisabled
        );
        assert_eq!(
            parse_readiness("ERROR the boot is Bypassed\nunavailable\n").unwrap(),
            Readiness::Unavailable
        );
        // No verdict at all is a refusal, never an implicit "go ahead": an
        // upgrade started on a silent TPM is one that cannot arm a window.
        assert!(parse_readiness("").is_err());
        assert!(parse_readiness("error: unknown subcommand 'update-readiness'").is_err());
    }

    /// A `heliosd` that logs to stdout still answers: the probe of an absent NV
    /// index — a gateway with no window armed — puts an ESAPI error in front of
    /// the verdict, and reading it as "unknown binary" blocked every upgrade.
    #[test]
    fn the_verdict_survives_log_lines_on_stdout() {
        let output = "\
2026-08-04T07:29:11.618510Z ERROR tss_esapi::context::general_esys_tr: Error when getting ESYS handle from TPM handle: the handle is not correct for the use (associated with handle number 1)
2026-08-04T07:29:11.618520Z  INFO tss_esapi::context: Closing context.
2026-08-04T07:29:11.618523Z  INFO tss_esapi::context: Context closed.
none
";
        assert_eq!(parse_window_state(output).unwrap(), WindowState::None);
    }
}
