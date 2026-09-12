//! Host and process preconditions, settled before the first secret exists.
//!
//! Two guards, consulted by `main` and by the daemon before any key is loaded
//! or any backend is built: what this kernel actually offers (which decides
//! simulation), and whether this process can refuse to be dumped.

use tracing::{info, warn};

/// Determines whether we are under WSL2 (Microsoft kernel).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Checks whether the kernel WireGuard module is loaded.
fn wireguard_module_present() -> bool {
    std::path::Path::new("/sys/module/wireguard").exists()
}

/// Resolves dry-run mode: explicit (`--dev`) or auto-detected (WSL2 without WireGuard).
pub(crate) fn resolve_dry_run(explicit_dev: bool) -> bool {
    if explicit_dev {
        info!("--dev mode enabled: simulating WireGuard, nftables and TPM");
        return true;
    }
    if is_wsl2() && !wireguard_module_present() {
        warn!(
            "WSL2 detected without the WireGuard module — automatically switching \
             to dev mode (simulation without crypto)"
        );
        return true;
    }
    false
}

/// Makes the process non-dumpable, **before** the first key is loaded.
///
/// `LimitCORE=0` in the unit covers the service started by systemd; this covers
/// every other way `heliosd` is launched, and it also removes the ptrace
/// attachability that `PR_SET_DUMPABLE=1` grants to same-uid processes.
///
/// Fatal outside `--dev`: a daemon that cannot make itself non-dumpable would
/// hold the gateway identity in a process anyone of the same user can dump, and
/// that is not a warning-level fact (ADR-006 §6).
#[cfg(unix)]
pub(crate) fn forbid_core_dumps(dry_run: bool) -> anyhow::Result<()> {
    // SAFETY: `prctl` with PR_SET_DUMPABLE takes an int and touches only this
    // process's own attributes.
    let applied = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if applied != 0 {
        let cause = std::io::Error::last_os_error();
        if dry_run {
            warn!("PR_SET_DUMPABLE refused ({cause}) — tolerated in --dev only");
            return Ok(());
        }
        anyhow::bail!("PR_SET_DUMPABLE refused: {cause}");
    }
    // Reading it back rather than trusting the return code: the value is what
    // the kernel will actually honour on a crash.
    let effective = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    anyhow::ensure!(
        effective == 0,
        "PR_SET_DUMPABLE accepted but PR_GET_DUMPABLE reports {effective}"
    );
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn forbid_core_dumps(_dry_run: bool) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_development_mode_always_wins_auto_detection() {
        assert!(resolve_dry_run(true));
    }

    #[test]
    fn automatic_development_mode_matches_the_detected_kernel() {
        assert_eq!(
            resolve_dry_run(false),
            is_wsl2() && !wireguard_module_present()
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_is_made_non_dumpable_before_loading_secrets() {
        forbid_core_dumps(false).expect("this process must control its dumpability");
        // SAFETY: PR_GET_DUMPABLE has no pointer argument and only reads the
        // current test process attribute.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
    }
}
