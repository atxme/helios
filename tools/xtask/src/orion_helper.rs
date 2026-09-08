//! Staging of Orion's Astra operator sidecar, shared by `xtask` and Orion's
//! build script.
//!
//! `tauri.windows.conf.json` declares `binaries/helios-astra-helper` as an
//! `externalBin`. Tauri looks for that file under its **target-qualified**
//! name and refuses to build without it, so the helper must be compiled and
//! staged before `tauri_build` runs — for the installer as well as for a plain
//! `cargo build -p orion` on a Windows workstation.
//!
//! The build is spawned in a caller-chosen target directory. A build script
//! must never reuse the directory of the build that invoked it: the nested
//! Cargo would wait forever on a lock its own parent holds.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

/// Name shared by the crate, its binary and the sidecar Tauri looks for.
pub const HELPER: &str = "helios-astra-helper";

/// Directory `externalBin` resolves against, next to Orion's manifest.
pub fn sidecar_dir(root: &Path) -> PathBuf {
    root.join("apps")
        .join("orion")
        .join("src-tauri")
        .join("binaries")
}

/// The exact path Tauri requires for `target`.
pub fn sidecar_path(root: &Path, target: &str) -> PathBuf {
    sidecar_dir(root).join(format!("{HELPER}-{target}{}", exe_suffix(target)))
}

/// Builds the helper for `target` under `target_dir`, then stages it.
///
/// `release` follows the profile of the build being served: an installer ships
/// the release helper, and a development `cargo run` gets the debug one rather
/// than paying for an optimized build of the operator dependency graph.
pub fn prepare(root: &Path, target: &str, target_dir: &Path, release: bool) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(&cargo);
    command
        .current_dir(root)
        .args(["build", "-p", HELPER, "--target", target])
        .env("CARGO_TARGET_DIR", target_dir)
        // Cargo passes its build scripts the descriptors of a jobserver that
        // belongs to the running build. A nested Cargo inheriting them would
        // negotiate for tokens nobody is going to hand back.
        .env_remove("CARGO_MAKEFLAGS");
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .with_context(|| format!("running {cargo} build -p {HELPER}"))?;
    if !status.success() {
        bail!("building {HELPER} for {target} failed ({status})");
    }

    let profile = if release { "release" } else { "debug" };
    let produced = target_dir
        .join(target)
        .join(profile)
        .join(format!("{HELPER}{}", exe_suffix(target)));
    if !produced.is_file() {
        bail!("{HELPER} was not produced at {}", produced.display());
    }
    let destination = sidecar_path(root, target);
    let directory = sidecar_dir(root);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    std::fs::copy(&produced, &destination).with_context(|| {
        format!(
            "staging {HELPER} from {} to {}",
            produced.display(),
            destination.display()
        )
    })?;
    Ok(())
}

/// Suffix of the **target's** executables, not of the machine building them.
fn exe_suffix(target: &str) -> &'static str {
    if target.contains("windows") {
        ".exe"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The staged name is the one Tauri derives from the `externalBin` entry.
    #[test]
    fn sidecar_is_named_as_tauri_resolves_external_binaries() {
        let path = sidecar_path(Path::new("/helios"), "x86_64-pc-windows-msvc");
        assert!(path.ends_with("helios-astra-helper-x86_64-pc-windows-msvc.exe"));
        assert!(path
            .parent()
            .unwrap()
            .ends_with(Path::new("apps/orion/src-tauri/binaries")));
    }

    /// A Linux target has no `.exe`; the host's suffix is not the answer.
    #[test]
    fn sidecar_suffix_follows_the_target() {
        assert_eq!(exe_suffix("x86_64-unknown-linux-gnu"), "");
        assert_eq!(exe_suffix("aarch64-pc-windows-msvc"), ".exe");
    }
}
