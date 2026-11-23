//! Helios installation bundle factory.
//!
//! Until now, installing a gateway meant copying the repo onto it and
//! building it there: `scripts/setup-target.sh` installed `cargo` and `npm`
//! on the appliance. This tool replaces that (ADR-004) — the target now
//! receives only binaries and a signed manifest.
//!
//! # Three steps, and why they are separate
//!
//! ```sh
//! cargo xtask bundle                       # builds and assembles
//! helios-publisher bundle --dir …          # signs, on the publisher workstation
//! cargo xtask pack --dir …                 # archives
//! ```
//!
//! The signature step is interposed because it does not happen here: the
//! publisher's private keys must enter neither a CI nor a repository
//! (ADR-004 §7). `pack` refuses a directory without a manifest: an unsigned
//! bundle therefore cannot ship by accident.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use xtask::{archive, container, orion_deps, verify};

/// Features of the shipped gateway. A production bundle carries all of them:
/// a `heliosd` without `netlink` or `wireguard` would refuse to start on a
/// real target, and discovering that there costs a trip.
///
/// The key negotiation is no longer among them: like Orion, every heliosd
/// carries it. It used to be a flag on the grounds that it opens a second UDP
/// port — but the port only opens when `network.toml` declares
/// `key_negotiation_port`, so the flag decided nothing except whether the
/// setting would be silently inert. A gateway that accepts the configuration,
/// logs nothing, and fails every pinned client's first handshake is not a
/// gateway anyone can debug from the target.
const GATEWAY_FEATURES: &str = "netlink,wireguard,tpm,embed-ui";

/// How npm is spawned on this platform.
///
/// On Windows npm is a `.cmd` shim, and [`Command`] only appends `.exe` to a
/// program without an extension — it never consults `PATHEXT`, unlike a
/// shell. Spawning a plain `npm` there fails with «program not found», and
/// it fails *late*: after the toolchain, the WireGuardNT download and the
/// whole workspace build. Naming the shim is the entire fix.
#[cfg(windows)]
const NPM: &str = "npm.cmd";
#[cfg(not(windows))]
const NPM: &str = "npm";

/// Systemd units shipped with the gateway.
const SYSTEMD_UNITS: &[&str] = &[
    "heliosd.service",
    "helios-update.service",
    "helios-update.path",
    "helios-update-window.service",
    "helios-update-window.timer",
    "helios-log-prune.service",
    "helios-log-prune.timer",
];

/// Shipped binaries, and their role.
const BINARIES: &[&str] = &["heliosd", "helios-installer", "helios"];

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Helios installation bundle factory (build workstation, never the gateway)"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Downloads and verifies the WireGuardNT DLLs needed by the Orion bundle.
    OrionDeps,
    /// Builds the production heliosd binary for an API application update.
    App {
        /// Target triple. Default: the host.
        #[arg(long)]
        target: Option<String>,
        /// Does not rebuild the embedded frontend (local iteration).
        #[arg(long)]
        skip_frontend: bool,
        /// Builds on this host instead of in the pinned build container.
        #[arg(long)]
        native: bool,
    },
    /// Builds the binaries and assembles the bundle directory.
    Bundle {
        /// Target triple. Default: the host.
        #[arg(long)]
        target: Option<String>,
        /// Does not rebuild the embedded frontend (local iteration).
        #[arg(long)]
        skip_frontend: bool,
        /// Output directory. Default: `target/bundle/<name>`.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Builds on this host instead of in the pinned build container.
        #[arg(long)]
        native: bool,
    },
    /// Builds the Orion Windows installer (MSI) on this machine.
    ///
    /// Same features and same checks as the CI job, so a local build and a
    /// release build produce the same binary — the point being to find out
    /// here, in seconds, what would otherwise cost a CI round-trip.
    OrionMsi {
        /// Produce an **unsigned** installer, for testing only.
        ///
        /// Without it, an Authenticode certificate and an RFC 3161 timestamp
        /// server are required, and the build stops if either is missing.
        #[arg(long)]
        unsigned: bool,
        /// Also produce the NSIS installer.
        #[arg(long)]
        with_nsis: bool,
        /// Skip `npm ci` when `node_modules` is already installed.
        #[arg(long)]
        skip_npm_ci: bool,
    },
    /// Checks a signed bundle against the commit its manifest names.
    ///
    /// The signature must verify under `--keyring`. The commit is then rebuilt
    /// in the build container, and every file compared: the command fails
    /// unless the bundle and the rebuilt commit agree file for file.
    Verify {
        /// Bundle directory, or the `.tar.gz` archive made by `pack`.
        #[arg(long)]
        bundle: PathBuf,
        /// Public keyring the signature must verify under.
        #[arg(long)]
        keyring: PathBuf,
    },
    /// Archives a **signed** bundle.
    Pack {
        /// Directory produced by `bundle`, containing `manifest.json`.
        #[arg(long)]
        dir: PathBuf,
        /// Archive to produce. Default: `<dir>.tar.gz`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::OrionDeps => orion_deps(),
        Cmd::App {
            target,
            skip_frontend,
            native,
        } => app(target, skip_frontend, native),
        Cmd::Bundle {
            target,
            skip_frontend,
            output,
            native,
        } => bundle(target, skip_frontend, output, native),
        Cmd::OrionMsi {
            unsigned,
            with_nsis,
            skip_npm_ci,
        } => orion_msi(unsigned, with_nsis, skip_npm_ci),
        Cmd::Verify { bundle, keyring } => verify::run(&workspace_root()?, &bundle, &keyring),
        Cmd::Pack { dir, output } => pack(&dir, output),
    }
}

fn orion_deps() -> Result<()> {
    let root = workspace_root()?;
    orion_deps::prepare(&root)
}

fn app(target: Option<String>, skip_frontend: bool, native: bool) -> Result<()> {
    let root = workspace_root()?;
    let target = match target {
        Some(target) => target,
        None => host_target()?,
    };
    let binary = if native {
        build_gateway(&root, &target, skip_frontend)?
    } else {
        app_in_container(&root, &target, skip_frontend)?
    };
    println!("\n==> Application ready: {}", binary.display());
    Ok(())
}

/// Builds `heliosd` in the build container and copies it to where the native
/// build would have left it, the path `scripts/deploy-app.sh` reads.
fn app_in_container(root: &Path, target: &str, skip_frontend: bool) -> Result<PathBuf> {
    container_target(target)?;
    let skip = if skip_frontend {
        " --skip-frontend"
    } else {
        ""
    };
    let script = format!(
        "cargo run --locked --package xtask -- app --native --target {target}{skip} \
         && cp /helios/target/{target}/release/heliosd /helios/out/heliosd"
    );
    let out = container::build_in_container(
        root,
        &publisher_keyring()?,
        vec!["sh".into(), "-c".into(), script],
    )?;
    let binary = cargo_target_dir(root)
        .join(target)
        .join("release")
        .join("heliosd");
    let copied = container::copy_out(&out.join("heliosd"), &binary);
    let discarded = container::discard(&out);
    copied?;
    discarded?;
    Ok(binary)
}

/// Refuses a target the build container cannot produce.
fn container_target(target: &str) -> Result<()> {
    if target != container::CONTAINER_TARGET {
        bail!(
            "the build container only produces {}: build {target} on its own host with `--native`",
            container::CONTAINER_TARGET
        );
    }
    Ok(())
}

/// Features the Orion installer must carry.
///
/// Only `wireguard`, for the real data plane — without it Orion refuses to
/// start rather than simulate. The pre-WireGuard PQC exchange used to be a
/// second flag here; it is now compiled into every build, precisely because
/// omitting it produced a client that imported a negotiating profile and then
/// failed to connect — a slow way to discover a build flag.
const ORION_FEATURES: &str = "wireguard";

/// Builds the Orion MSI locally, with the checks that make it worth trusting.
///
/// Every prerequisite is verified **before** the compilation starts. A build
/// that runs for minutes and then stops on a missing environment variable is
/// the exact waste this command exists to remove.
fn orion_msi(unsigned: bool, with_nsis: bool, skip_npm_ci: bool) -> Result<()> {
    let root = workspace_root()?;
    let orion = root.join("apps").join("orion");

    // WiX has no cross-compiler: the MSI is produced by Windows tooling on
    // Windows. Saying so here beats letting the Tauri CLI report that `msi`
    // is not among its bundle targets.
    if !cfg!(windows) {
        bail!(
            "an MSI can only be built on Windows: WiX and the MSVC linker have no cross-target \
             equivalent. On this machine, `cargo build -p orion --features {ORION_FEATURES}` \
             checks that everything compiles; the installer itself is built on the Windows \
             workstation or by the `release` CI job."
        );
    }

    // Same anchor as the gateway bundle: a release build refuses the
    // development keyring, and finds out in `aether`'s build script — several
    // minutes in.
    let keyring = std::env::var("HELIOS_PUBLISHER_KEYRING_PATH").map_err(|_| {
        anyhow::anyhow!(
            "HELIOS_PUBLISHER_KEYRING_PATH must point to the publisher's public keyring: \
             a release build refuses the development anchor"
        )
    })?;
    if !Path::new(&keyring).is_file() {
        bail!("public keyring not found: {keyring}");
    }

    // Signing is required unless explicitly waived, and the waiver is loud:
    // the signing script itself announces every unsigned artifact.
    let signing_certificate_set = std::env::var("ORION_SIGNING_CERT_SHA1").is_ok();
    let timestamp_url_set = std::env::var("ORION_TIMESTAMP_URL").is_ok();
    validate_orion_signing(unsigned, signing_certificate_set, timestamp_url_set)?;
    if unsigned {
        println!("==> UNSIGNED build: this installer must not be distributed");
        std::env::set_var("ORION_UNSIGNED_FOR_OFFLINE_SIGNING", "1");
    }

    println!("==> WireGuardNT dependencies");
    orion_deps()?;

    // Tauri's `beforeBuildCommand` fetches those same dependencies, so that a
    // plain `npm run tauri build` also produces a complete installer. They are
    // in place by now, and letting the hook redo it would re-enter `cargo`
    // from inside this running process: on Windows, relinking `xtask.exe`
    // while it executes fails with `Access is denied (os error 5)` — minutes
    // in, after the download and the whole workspace build.
    std::env::set_var("ORION_DEPS_READY", "1");

    if skip_npm_ci && orion.join("node_modules").is_dir() {
        println!("==> npm: existing node_modules reused (--skip-npm-ci)");
    } else {
        println!("==> npm dependencies");
        run(&orion, NPM, &["ci"])?;
    }

    // `--bundles msi` alone, unless NSIS is asked for: `targets: "all"` would
    // also build it, doubling a wait this command is meant to shorten.
    let bundles = if with_nsis { "msi,nsis" } else { "msi" };
    println!("==> Orion installer ({ORION_FEATURES}, bundles: {bundles})");
    run(
        &orion,
        NPM,
        &[
            "run",
            "tauri",
            "--",
            "build",
            "--features",
            ORION_FEATURES,
            "--bundles",
            bundles,
        ],
    )?;

    report_installers(&root.join("target").join("release").join("bundle"))
}

fn validate_orion_signing(
    unsigned: bool,
    certificate_set: bool,
    timestamp_set: bool,
) -> Result<()> {
    if unsigned {
        return Ok(());
    }
    for (variable, is_set) in [
        ("ORION_SIGNING_CERT_SHA1", certificate_set),
        ("ORION_TIMESTAMP_URL", timestamp_set),
    ] {
        if !is_set {
            bail!(
                "{variable} is required to sign the installer. Set the Authenticode \
                 thumbprint and an RFC 3161 timestamp server, or pass --unsigned to \
                 produce a test installer that must not be distributed."
            );
        }
    }
    Ok(())
}

/// Lists what was produced, with a fingerprint for each artifact.
///
/// The fingerprint is what the operator compares after transferring the
/// installer; printing it here saves computing it by hand later.
fn report_installers(bundle_dir: &Path) -> Result<()> {
    let mut found = Vec::new();
    for kind in ["msi", "nsis"] {
        let directory = bundle_dir.join(kind);
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "msi" | "exe"))
            {
                found.push(path);
            }
        }
    }
    if found.is_empty() {
        bail!(
            "no installer found under {} — the Tauri build reported success but produced nothing",
            bundle_dir.display()
        );
    }

    println!();
    println!("==> Installer(s) produced");
    for path in found {
        let digest = helios_update::sha256_file(&path)
            .map_err(|e| anyhow::anyhow!("fingerprint of {}: {e}", path.display()))?;
        println!("    {}", path.display());
        println!("    sha256 {}", hex(&digest));
    }
    Ok(())
}

fn bundle(
    target: Option<String>,
    skip_frontend: bool,
    output: Option<PathBuf>,
    native: bool,
) -> Result<()> {
    let root = workspace_root()?;
    let target = match target {
        Some(target) => target,
        None => host_target()?,
    };
    let version = release_version(&root)?;
    let staging = bundle_staging_dir(&root, &version, &target, output);

    if native {
        assemble_natively(&root, &target, &staging, skip_frontend)?;
    } else {
        assemble_in_container(&root, &target, skip_frontend, &staging)?;
    }

    let files = helios_update::bundle::collect(&staging)
        .map_err(|e| anyhow::anyhow!("listing the bundle: {e}"))?;

    println!("\n==> Bundle assembled in {}", staging.display());
    for entry in &files {
        println!("  {:>10}  {}", entry.size, entry.path);
    }
    println!("\nSign on the publisher workstation, then archive:");
    println!(
        "  helios-publisher bundle --dir {} \\\n    --key-epoch <N> --release-sequence <N> \\\n    \
         --channel <testing|production> --version {version} \\\n    --git-commit $(git rev-parse \
         --short=16 HEAD) --target {target} \\\n    --ed25519-private-key <…> \
         --ml-dsa-65-private-key <…> --keyring {}",
        staging.display(),
        publisher_keyring()?.display()
    );
    println!("  cargo xtask pack --dir {}", staging.display());
    Ok(())
}

/// Builds the bundle's binaries on this host and assembles them in `staging`.
fn assemble_natively(root: &Path, target: &str, staging: &Path, skip_frontend: bool) -> Result<()> {
    let heliosd = build_gateway(root, target, skip_frontend)?;

    println!("==> helios-installer, helios");
    run(
        root,
        "cargo",
        &[
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "-p",
            "helios-installer",
            "-p",
            "helios",
        ],
    )?;

    if staging.exists() {
        std::fs::remove_dir_all(staging)
            .with_context(|| format!("cleaning {}", staging.display()))?;
    }
    std::fs::create_dir_all(staging.join("systemd"))
        .with_context(|| format!("creating {}", staging.display()))?;

    let built = cargo_target_dir(root).join(target).join("release");
    copy_executable(&heliosd, &staging.join("heliosd"))?;
    for binary in BINARIES
        .iter()
        .copied()
        .filter(|binary| *binary != "heliosd")
    {
        copy_executable(&built.join(binary), &staging.join(binary))?;
    }
    for unit in SYSTEMD_UNITS {
        copy_data(
            &root.join("deploy").join("systemd").join(unit),
            &staging.join("systemd").join(unit),
        )?;
    }
    copy_data(
        &root.join("config").join("network.toml"),
        &staging.join("network.toml.example"),
    )?;
    Ok(())
}

/// Runs the native assembly in the build container, then copies the bundle
/// it produced to `staging`.
fn assemble_in_container(
    root: &Path,
    target: &str,
    skip_frontend: bool,
    staging: &Path,
) -> Result<()> {
    container_target(target)?;
    let name = staging
        .file_name()
        .context("the bundle output has no directory name")?
        .to_string_lossy()
        .into_owned();

    let mut arguments = vec![
        "bundle".to_string(),
        "--native".into(),
        "--target".into(),
        target.into(),
        "--output".into(),
        format!("/helios/out/{name}"),
    ];
    if skip_frontend {
        arguments.push("--skip-frontend".into());
    }
    let out = container::build_in_container(
        root,
        &publisher_keyring()?,
        container::xtask_command(&arguments),
    )?;
    let copied = container::copy_out(&out.join(&name), staging);
    let discarded = container::discard(&out);
    copied?;
    discarded
}

/// Builds the exact daemon shape shipped to a real gateway.
///
/// Kept in one function because installation bundles and application updates
/// must never drift to different feature sets or embedded frontends.
fn build_gateway(root: &Path, target: &str, skip_frontend: bool) -> Result<PathBuf> {
    publisher_keyring()?;

    if skip_frontend {
        println!("==> Frontend: reused as is (--skip-frontend)");
    } else {
        println!("==> Embedded frontend");
        run(root, NPM, &["ci", "--prefix", "web"])?;
        run(root, NPM, &["run", "build", "--prefix", "web"])?;
    }

    println!("==> heliosd ({GATEWAY_FEATURES})");
    run(root, "cargo", &gateway_build_args(target))?;
    Ok(cargo_target_dir(root)
        .join(target)
        .join("release")
        .join("heliosd"))
}

fn bundle_staging_dir(
    root: &Path,
    version: &str,
    target: &str,
    output: Option<PathBuf>,
) -> PathBuf {
    output.unwrap_or_else(|| {
        root.join("target")
            .join("bundle")
            .join(format!("helios-{version}-{target}"))
    })
}

fn gateway_build_args(target: &str) -> [&str; 9] {
    [
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "-p",
        "heliosd",
        "--features",
        GATEWAY_FEATURES,
    ]
}

fn publisher_keyring() -> Result<PathBuf> {
    let keyring = std::env::var_os("HELIOS_PUBLISHER_KEYRING_PATH").ok_or_else(|| {
        anyhow::anyhow!(
            "HELIOS_PUBLISHER_KEYRING_PATH must point to the publisher's public keyring: \
             a gateway binary built without a trust anchor cannot verify any update"
        )
    })?;
    let keyring = PathBuf::from(keyring);
    if !keyring.is_file() {
        bail!("public keyring not found: {}", keyring.display());
    }
    Ok(keyring)
}

fn pack(dir: &Path, output: Option<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} is not a bundle directory", dir.display());
    }

    // An unsigned bundle must not be able to ship: without a manifest, the
    // target would have nothing to verify and the installation would happen
    // blindly.
    let manifest = helios_update::bundle::read_manifest(dir)
        .map_err(|e| anyhow::anyhow!("{e}\nSign the bundle before archiving it."))?;
    helios_update::bundle::verify_contents(dir, &manifest.payload)
        .map_err(|e| anyhow::anyhow!("content no longer matches the signed manifest: {e}"))?;

    // `canonicalize` before anything else: `tar` is launched from the parent
    // directory, and a relative path there would designate something other
    // than in the caller's current directory.
    let dir = dir
        .canonicalize()
        .with_context(|| format!("resolving {}", dir.display()))?;
    let archive = match output {
        Some(output) => output,
        None => archive_path(&dir)?,
    };
    let parent = dir
        .parent()
        .context("bundle directory has no parent")?
        .to_path_buf();
    let name = dir
        .file_name()
        .context("bundle directory has no name")?
        .to_string_lossy()
        .to_string();

    archive::create(&parent, &name, &archive, archive::entry_mtime())?;

    let digest = helios_update::sha256_file(&archive)
        .map_err(|e| anyhow::anyhow!("archive fingerprint: {e}"))?;
    println!("{} {}", hex(&digest), archive.display());
    println!(
        "\n  Bundle {} sequence {}, channel {}, {} file(s).",
        manifest.payload.version,
        manifest.payload.release_sequence,
        manifest.payload.channel,
        manifest.payload.files.len()
    );
    println!("  Publish this fingerprint with the archive: it is what the operator");
    println!("  compares before the very first `helios-installer bootstrap`.");
    Ok(())
}

/// Archive name for a bundle directory.
///
/// The extension is **appended**, never substituted: a bundle's name
/// contains dots (`helios-0.1.0-x86_64-…`), and replacing the extension
/// would truncate the version.
fn archive_path(dir: &Path) -> Result<PathBuf> {
    let name = dir
        .file_name()
        .context("bundle directory has no name")?
        .to_string_lossy()
        .to_string();
    Ok(dir.with_file_name(format!("{name}.tar.gz")))
}

fn copy_executable(from: &Path, to: &Path) -> Result<()> {
    copy_data(from, to)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("execute permissions on {}", to.display()))?;
    }
    Ok(())
}

fn copy_data(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    // Permissions are set explicitly: the source file's permissions depend
    // on the build machine's umask, and would end up in the signed
    // manifest — two identical builds would then produce different
    // manifests.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("permissions on {}", to.display()))?;
    }
    Ok(())
}

fn run(dir: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("running {program}"))?;
    if !status.success() {
        bail!("{program} {} failed ({status})", args.join(" "));
    }
    Ok(())
}

fn output_of(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!("{program} failed ({})", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Host triple, read from `rustc` rather than guessed.
fn host_target() -> Result<String> {
    let verbose = output_of("rustc", &["-vV"])?;
    verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_string())
        .context("`rustc -vV` did not report a host triple")
}

fn workspace_root() -> Result<PathBuf> {
    // `CARGO_MANIFEST_DIR` points at `tools/xtask`: the root is two levels
    // above. Deriving it avoids requiring the tool to be launched from a
    // specific directory.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("workspace root not found")
}

/// Where the Cargo builds this tool launches write their output.
///
/// `CARGO_TARGET_DIR` when set, the workspace's `target/` otherwise. The WSL
/// build scripts pin it to the single bounded cache, and reading binaries
/// from `target/` then would find nothing, or a stale build.
fn cargo_target_dir(root: &Path) -> PathBuf {
    cargo_target_dir_from(root, std::env::var_os("CARGO_TARGET_DIR"))
}

/// Resolves a configured target directory as Cargo does for the builds run
/// from `root`: a relative path is relative to that directory.
fn cargo_target_dir_from(root: &Path, configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(directory) if !directory.is_empty() => root.join(directory),
        _ => root.join("target"),
    }
}

/// The version the bundle is labeled with, read from the `heliosd` crate.
///
/// It must be the daemon's own version, which is the Helios product version.
/// The readiness marker `heliosd` writes after an update carries
/// `env!("CARGO_PKG_VERSION")` — its crate version. The installer compares
/// that marker to the manifest before confirming, so a bundle labeled with any
/// other number cannot be confirmed by the binary it ships: the health check
/// reads two different numbers for the same release, times out, and rolls back
/// a daemon that had in fact started.
fn release_version(root: &Path) -> Result<String> {
    let manifest = std::fs::read_to_string(root.join("crates").join("heliosd").join("Cargo.toml"))
        .context("reading crates/heliosd/Cargo.toml")?;
    manifest
        .lines()
        .take_while(|line| {
            let line = line.trim();
            !line.starts_with('[') || line == "[package]"
        })
        .find_map(|line| line.trim().strip_prefix("version = "))
        .map(|value| value.trim().trim_matches('"').to_string())
        .context("version missing from crates/heliosd/Cargo.toml [package]")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "helios-xtask-{label}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test directory {}: {error}", path.display()),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn executable_script(directory: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make script executable");
        path
    }

    #[test]
    fn the_version_is_the_daemon_s_own() {
        let root = workspace_root().expect("root");
        let version = release_version(&root).expect("version");
        assert!(
            version.split('.').count() == 3,
            "unexpected version: {version}"
        );

        // The label and the readiness marker must be the same number. The
        // marker is `heliosd`'s `CARGO_PKG_VERSION`, so reading anything but
        // that crate's `[package] version` re-opens the mismatch that makes
        // every update time out on its own health check.
        let daemon = std::fs::read_to_string(root.join("crates/heliosd/Cargo.toml"))
            .expect("heliosd manifest");
        let declared = daemon
            .lines()
            .take_while(|line| {
                let line = line.trim();
                !line.starts_with('[') || line == "[package]"
            })
            .find_map(|line| line.trim().strip_prefix("version = "))
            .map(|value| value.trim().trim_matches('"'))
            .expect("heliosd version");
        assert_eq!(version, declared);
    }

    /// The target is read from `rustc`, never from a constant: a bundle
    /// labeled for a triple that is not the binary's would be rejected at
    /// install time, after the transfer.
    #[test]
    fn the_host_triple_is_rustc_s() {
        let host = host_target().expect("host triple");
        assert!(host.contains('-'), "unexpected triple: {host}");
        assert_eq!(host, helios_update::BUILD_TARGET);
    }

    /// The bundle reads the binaries where Cargo wrote them. Before this,
    /// a build pinned to the shared WSL cache left `target/` empty and the
    /// bundle failed on a missing `heliosd`, after the whole release build.
    #[test]
    fn built_binaries_are_read_from_the_configured_target_directory() {
        let root = Path::new("/work/helios");
        assert_eq!(
            cargo_target_dir_from(root, None),
            Path::new("/work/helios/target")
        );
        assert_eq!(
            cargo_target_dir_from(root, Some("".into())),
            Path::new("/work/helios/target")
        );
        assert_eq!(
            cargo_target_dir_from(root, Some("/cache/helios-target".into())),
            Path::new("/cache/helios-target")
        );
        assert_eq!(
            cargo_target_dir_from(root, Some("build/out".into())),
            Path::new("/work/helios/build/out")
        );
    }

    #[test]
    fn gateway_build_plan_uses_release_target_and_production_features() {
        assert_eq!(
            gateway_build_args("x86_64-unknown-linux-gnu"),
            [
                "build",
                "--locked",
                "--release",
                "--target",
                "x86_64-unknown-linux-gnu",
                "-p",
                "heliosd",
                "--features",
                "netlink,wireguard,tpm,embed-ui",
            ]
        );
    }

    #[test]
    fn bundle_staging_plan_uses_versioned_default_or_explicit_output() {
        let root = Path::new("/work/helios");
        assert_eq!(
            bundle_staging_dir(root, "1.2.3", "x86_64-unknown-linux-gnu", None),
            Path::new("/work/helios/target/bundle/helios-1.2.3-x86_64-unknown-linux-gnu")
        );

        let output = PathBuf::from("/tmp/release-candidate");
        assert_eq!(
            bundle_staging_dir(
                root,
                "1.2.3",
                "x86_64-unknown-linux-gnu",
                Some(output.clone())
            ),
            output
        );
    }

    #[test]
    fn unsigned_msi_preflight_does_not_require_signing_configuration() {
        validate_orion_signing(true, false, false)
            .expect("explicit unsigned installer skips Authenticode requirements");
    }

    #[test]
    fn signed_msi_preflight_requires_the_authenticode_certificate() {
        let error = validate_orion_signing(false, false, true)
            .expect_err("signed installer requires certificate thumbprint");
        assert!(format!("{error:#}").contains("ORION_SIGNING_CERT_SHA1 is required"));
    }

    #[test]
    fn signed_msi_preflight_requires_the_timestamp_url() {
        let error = validate_orion_signing(false, true, false)
            .expect_err("signed installer requires an RFC 3161 timestamp URL");
        assert!(format!("{error:#}").contains("ORION_TIMESTAMP_URL is required"));
    }

    #[test]
    fn signed_msi_preflight_accepts_both_signing_requirements() {
        validate_orion_signing(false, true, true)
            .expect("certificate and timestamp URL allow a signed installer build");
    }

    #[test]
    fn cli_app_dispatch_preserves_target_and_frontend_flag() {
        let cli = Cli::try_parse_from([
            "xtask",
            "app",
            "--target",
            "aarch64-linux",
            "--skip-frontend",
        ])
        .expect("valid app command");
        assert!(matches!(
            cli.command,
            Cmd::App {
                target: Some(target),
                skip_frontend: true,
                native: false,
            } if target == "aarch64-linux"
        ));
    }

    #[test]
    fn cli_bundle_dispatch_preserves_explicit_output_path() {
        let cli = Cli::try_parse_from([
            "xtask",
            "bundle",
            "--target",
            "x86_64-linux",
            "--output",
            "/tmp/staging",
        ])
        .expect("valid bundle command");
        assert!(matches!(
            cli.command,
            Cmd::Bundle {
                target: Some(target),
                skip_frontend: false,
                output: Some(output),
                native: false,
            } if target == "x86_64-linux" && output == Path::new("/tmp/staging")
        ));
    }

    #[test]
    fn bundle_cli_accepts_native() {
        let cli = Cli::try_parse_from(["xtask", "bundle", "--native"]).expect("valid bundle");
        assert!(matches!(cli.command, Cmd::Bundle { native: true, .. }));

        let cli = Cli::try_parse_from(["xtask", "app", "--native"]).expect("valid app");
        assert!(matches!(cli.command, Cmd::App { native: true, .. }));
    }

    #[test]
    fn container_build_refuses_other_targets() {
        assert!(container_target(container::CONTAINER_TARGET).is_ok());
        let error = container_target("aarch64-unknown-linux-gnu")
            .expect_err("other targets are refused")
            .to_string();
        assert!(error.contains("--native"), "{error}");
    }

    #[test]
    fn cli_orion_msi_dispatch_preserves_unsigned_nsis_and_dependency_flags() {
        let cli = Cli::try_parse_from([
            "xtask",
            "orion-msi",
            "--unsigned",
            "--with-nsis",
            "--skip-npm-ci",
        ])
        .expect("valid Orion MSI command");
        assert!(matches!(
            cli.command,
            Cmd::OrionMsi {
                unsigned: true,
                with_nsis: true,
                skip_npm_ci: true,
            }
        ));
    }

    #[test]
    fn cli_pack_dispatch_requires_an_input_directory() {
        let error = match Cli::try_parse_from(["xtask", "pack"]) {
            Ok(_) => panic!("pack should reject a missing bundle directory"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--dir"));
    }

    /// A bundle's name contains the version, hence dots: substituting the
    /// extension instead of appending it produced `helios-0.1.tar.gz`.
    #[test]
    fn the_archive_name_keeps_the_full_version() {
        let archive = archive_path(Path::new(
            "/tmp/bundle/helios-0.1.0-x86_64-unknown-linux-gnu",
        ))
        .expect("archive name");
        assert_eq!(
            archive,
            Path::new("/tmp/bundle/helios-0.1.0-x86_64-unknown-linux-gnu.tar.gz")
        );
    }

    fn archive_fixture(directory: &TestDirectory) -> PathBuf {
        use helios_update::bundle;

        let root = directory.path().join("helios-1.2.3-test");
        std::fs::create_dir_all(root.join("systemd")).expect("create bundle directory");
        let binary = directory.path().join("test-binary");
        std::fs::write(&binary, b"test binary").expect("write binary fixture");
        copy_executable(&binary, &root.join("heliosd")).expect("stage binary");
        std::fs::write(root.join("systemd/heliosd.service"), b"[Unit]\n").expect("stage unit");
        // Pack checks the manifest inventory and preserves the envelope as
        // provided. The installer verifies the signatures against its keyring.
        let manifest = serde_json::json!({
            "payload": {
                "product": bundle::BUNDLE_PRODUCT,
                "channel": "testing",
                "release_sequence": 7,
                "version": "1.2.3",
                "git_commit": "abcdef0123456789",
                "target": helios_update::BUILD_TARGET,
                "minimum_installer_version": helios_update::INSTALLER_VERSION,
                "files": bundle::collect(&root).expect("inventory the fixture"),
            },
            "key_epoch": 1,
            "signatures": [
                { "alg": "ed25519", "sig": "dGVzdC1lZDI1NTE5" },
                { "alg": "ml-dsa-65", "sig": "dGVzdC1tbC1kc2EtNjU=" },
            ],
        });
        let mut document = serde_json::to_vec_pretty(&manifest).expect("encode manifest");
        document.push(b'\n');
        std::fs::write(root.join(bundle::BUNDLE_MANIFEST_FILE), document).expect("write manifest");
        root
    }

    #[cfg(unix)]
    #[test]
    fn pack_preserves_the_manifest_and_inventory_through_extraction() {
        use helios_update::bundle;

        let directory = TestDirectory::new("archive-roundtrip");
        let root = archive_fixture(&directory);
        let original =
            std::fs::read(root.join(bundle::BUNDLE_MANIFEST_FILE)).expect("original manifest");
        let expected = archive_path(&root).expect("default archive path");
        pack(&root, None).expect("archive the bundle");
        assert!(expected.is_file());

        let unpacked = directory.path().join("unpacked");
        std::fs::create_dir(&unpacked).expect("create an extraction directory");
        run(
            &unpacked,
            "tar",
            &["-xzf", expected.to_str().expect("archive path")],
        )
        .expect("extract the new archive");
        let extracted = unpacked.join(root.file_name().expect("bundle name"));
        let manifest = bundle::read_manifest(&extracted).expect("read archived manifest");
        assert_eq!(
            std::fs::read(extracted.join(bundle::BUNDLE_MANIFEST_FILE)).expect("archived manifest"),
            original
        );
        bundle::verify_contents(&extracted, &manifest.payload).expect("verify extracted contents");
        assert_eq!(
            std::fs::read(extracted.join("heliosd")).expect("extracted binary"),
            b"test binary"
        );
        assert_eq!(
            std::fs::read(extracted.join("systemd/heliosd.service")).expect("extracted unit"),
            b"[Unit]\n"
        );
        assert!(
            manifest
                .payload
                .entry("heliosd")
                .expect("manifest entry")
                .executable
        );
    }

    #[cfg(unix)]
    #[test]
    fn pack_uses_the_explicit_output_path() {
        let directory = TestDirectory::new("archive-output");
        let root = archive_fixture(&directory);
        let output = directory.path().join("exports");
        std::fs::create_dir(&output).expect("create archive output directory");
        let archive = output.join("custom archive.tar.gz");
        pack(&root, Some(archive.clone())).expect("archive to the requested location");

        let listing = output_of("tar", &["-tzf", archive.to_str().expect("archive path")])
            .expect("list the produced archive");
        let bundle = root
            .file_name()
            .expect("bundle name")
            .to_str()
            .expect("UTF-8 name");
        assert!(listing
            .lines()
            .any(|line| line == format!("{bundle}/manifest.json")));
        assert!(listing
            .lines()
            .any(|line| line == format!("{bundle}/heliosd")));
        assert!(!archive_path(&root).expect("default path").exists());
    }

    #[test]
    fn pack_refuses_changed_or_missing_files_and_unsigned_additions() {
        let directory = TestDirectory::new("archive-mismatch");
        let root = archive_fixture(&directory);
        let unit = root.join("systemd/heliosd.service");
        let output = directory.path().join("existing.tar.gz");
        std::fs::write(&output, b"prior archive").expect("preserve an existing destination");

        std::fs::write(&unit, b"[Bad]\n").expect("alter the signed unit");
        let changed = pack(&root, Some(output.clone())).expect_err("digest mismatch");
        assert!(format!("{changed:#}").contains("digest mismatch for systemd/heliosd.service"));

        std::fs::remove_file(&unit).expect("remove the signed unit");
        let missing = pack(&root, Some(output.clone())).expect_err("required unit missing");
        assert!(format!("{missing:#}")
            .contains("file missing from the bundle: systemd/heliosd.service"));

        std::fs::write(&unit, b"[Unit]\n").expect("restore the signed unit");
        std::fs::write(root.join("systemd/extra.service"), b"[Unit]\n").expect("add unsigned unit");
        let extra = pack(&root, Some(output.clone())).expect_err("unsigned addition");
        assert!(format!("{extra:#}")
            .contains("unsigned file present in the bundle: systemd/extra.service"));
        assert_eq!(
            std::fs::read(output).expect("prior archive"),
            b"prior archive"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pack_refuses_changed_executable_permissions_or_symbolic_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("archive-permissions");
        let root = archive_fixture(&directory);
        let binary = root.join("heliosd");
        let archive = archive_path(&root).expect("default archive path");

        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o644))
            .expect("remove signed executable permission");
        let mode = pack(&root, None).expect_err("executable permission is signed");
        assert!(format!("{mode:#}").contains("execute permission mismatch for heliosd"));

        std::fs::remove_file(&binary).expect("remove the regular file");
        symlink(directory.path().join("test-binary"), &binary)
            .expect("create a symbolic link to identical bytes");
        let link = pack(&root, None).expect_err("symlinks are forbidden in bundle contents");
        assert!(format!("{link:#}").contains("symbolic link"));
        assert!(!archive.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pack_reports_tar_failure_instead_of_claiming_a_fingerprint() {
        let directory = TestDirectory::new("archive-tar-error");
        let root = archive_fixture(&directory);
        let archive = directory.path().join("absent").join("bundle.tar.gz");

        let error = pack(&root, Some(archive.clone())).expect_err("unwritable output destination");
        let message = format!("{error:#}");
        assert!(message.contains("tar failed"), "{message}");
        assert!(message.contains("not written"), "{message}");
        assert!(!archive.exists());
        assert!(!archive_path(&root).expect("default archive path").exists());
    }

    #[test]
    fn pack_reports_an_unreadable_manifest_before_creating_an_archive() {
        use helios_update::bundle::BUNDLE_MANIFEST_FILE;

        let directory = TestDirectory::new("archive-invalid-manifest");
        let root = archive_fixture(&directory);
        std::fs::write(root.join(BUNDLE_MANIFEST_FILE), b"{not-json")
            .expect("replace the manifest with malformed JSON");

        let error = pack(&root, None).expect_err("malformed manifest cannot ship");
        let message = format!("{error:#}");
        assert!(message.contains("invalid bundle manifest"), "{message}");
        assert!(
            message.contains("Sign the bundle before archiving it"),
            "{message}"
        );
        assert!(!archive_path(&root).expect("default archive path").exists());
    }

    #[test]
    fn pack_refuses_unsigned_bundle_before_creating_an_archive() {
        let directory = TestDirectory::new("unsigned-bundle");
        let bundle = directory.path().join("helios-1.2.3-test");
        std::fs::create_dir(&bundle).expect("create unsigned bundle");
        std::fs::write(bundle.join("heliosd"), b"test binary").expect("write fixture");

        let error = pack(&bundle, None).expect_err("unsigned bundle cannot be archived");

        assert!(format!("{error:#}").contains("Sign the bundle before archiving it"));
        assert!(!archive_path(&bundle).expect("archive path").exists());
    }

    #[test]
    fn pack_rejects_non_directories_before_reading_a_manifest() {
        let directory = TestDirectory::new("not-a-bundle");
        let file = directory.path().join("bundle.txt");
        std::fs::write(&file, b"not a directory").expect("write file");

        let error = pack(&file, Some(directory.path().join("bundle.tar.gz")))
            .expect_err("a file is not a bundle directory");

        assert!(format!("{error:#}").contains("is not a bundle directory"));
        assert!(!directory.path().join("bundle.tar.gz").exists());
    }

    #[test]
    fn release_version_reads_only_the_package_table_and_reports_missing_version() {
        let directory = TestDirectory::new("release-version");
        let manifest_dir = directory.path().join("crates/heliosd");
        std::fs::create_dir_all(&manifest_dir).expect("create manifest parent");
        let manifest = manifest_dir.join("Cargo.toml");
        std::fs::write(
            &manifest,
            "[package]\nname = \"heliosd\"\nversion = \"1.2.3\"\n\
             [dependencies]\nversion = \"9.9.9\"\n",
        )
        .expect("write manifest");

        assert_eq!(
            release_version(directory.path()).expect("package version"),
            "1.2.3"
        );

        std::fs::write(
            &manifest,
            "[package]\nname = \"heliosd\"\n[dependencies]\nversion = \"9.9.9\"\n",
        )
        .expect("remove package version");
        let error = release_version(directory.path()).expect_err("missing package version");
        assert!(format!("{error:#}").contains("version missing"));
    }

    #[test]
    fn report_installers_ignores_unrelated_files_and_requires_an_installer() {
        let directory = TestDirectory::new("installer-report");
        let bundle = directory.path().join("bundle");
        std::fs::create_dir_all(bundle.join("msi")).expect("create MSI directory");
        std::fs::create_dir_all(bundle.join("nsis")).expect("create NSIS directory");
        std::fs::write(bundle.join("msi/readme.txt"), b"ignored").expect("write unrelated file");

        let empty_error = report_installers(&bundle).expect_err("no installer is an error");
        assert!(format!("{empty_error:#}").contains("no installer found"));

        std::fs::write(bundle.join("msi/orion.msi"), b"test MSI").expect("write MSI fixture");
        std::fs::write(bundle.join("nsis/orion.exe"), b"test NSIS").expect("write NSIS fixture");
        report_installers(&bundle).expect("both installer formats are reported");
    }

    #[test]
    fn report_installers_skips_missing_format_directories_and_rejects_unreadable_artifacts() {
        let directory = TestDirectory::new("installer-report-errors");
        let bundle = directory.path().join("bundle");
        std::fs::create_dir_all(bundle.join("msi")).expect("create MSI directory");

        // A missing NSIS directory is an optional format, not a report failure.
        std::fs::write(bundle.join("msi/notes.MSI.txt"), b"not an installer")
            .expect("write unrelated file");
        let error = report_installers(&bundle).expect_err("unreadable MSI artifact is an error");
        assert!(format!("{error:#}").contains("no installer found"));

        // A directory with an installer suffix reaches fingerprinting, where
        // the file reader must surface the malformed artifact with context.
        std::fs::create_dir(bundle.join("msi/broken.msi")).expect("create malformed MSI");
        let error = report_installers(&bundle).expect_err("directory cannot be fingerprinted");
        assert!(format!("{error:#}").contains("fingerprint of"));
    }

    #[cfg(unix)]
    #[test]
    fn file_copy_helpers_set_manifest_stable_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("copy-permissions");
        let source = directory.path().join("source");
        std::fs::write(&source, b"artifact bytes").expect("write source");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
            .expect("set source mode");
        let data_copy = directory.path().join("data-copy");
        let executable_copy = directory.path().join("executable-copy");

        copy_data(&source, &data_copy).expect("copy data");
        copy_executable(&source, &executable_copy).expect("copy executable");

        assert_eq!(
            std::fs::read(&data_copy).expect("data bytes"),
            b"artifact bytes"
        );
        assert_eq!(
            std::fs::read(&executable_copy).expect("executable bytes"),
            b"artifact bytes"
        );
        assert_eq!(
            std::fs::metadata(&data_copy)
                .expect("data metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&executable_copy)
                .expect("executable metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let missing = copy_data(&directory.path().join("missing"), &data_copy)
            .expect_err("missing source is reported");
        assert!(format!("{missing:#}").contains("copying"));
    }

    #[cfg(unix)]
    #[test]
    fn process_helpers_use_the_requested_directory_and_report_failures() {
        let directory = TestDirectory::new("process-helpers");
        let success = executable_script(
            directory.path(),
            "success",
            "printf '%s\\n' \"$@\" > args.txt",
        );
        run(
            directory.path(),
            success.to_str().expect("script path"),
            &["one", "two"],
        )
        .expect("successful subprocess");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("args.txt")).expect("captured args"),
            "one\ntwo\n"
        );

        let output = executable_script(directory.path(), "output", "printf 'controlled output\\n'");
        assert_eq!(
            output_of(output.to_str().expect("script path"), &[]).expect("captured output"),
            "controlled output\n"
        );

        let failure = executable_script(directory.path(), "failure", "exit 7");
        let error = run(
            directory.path(),
            failure.to_str().expect("script path"),
            &[],
        )
        .expect_err("non-zero subprocess is an error");
        assert!(format!("{error:#}").contains("failed (exit status: 7)"));

        let output_failure = executable_script(directory.path(), "output-failure", "exit 9");
        let error = output_of(output_failure.to_str().expect("script path"), &[])
            .expect_err("non-zero output command is an error");
        assert!(format!("{error:#}").contains("failed (exit status: 9)"));

        let missing = directory.path().join("does-not-exist");
        let error = run(
            directory.path(),
            missing.to_str().expect("missing path"),
            &[],
        )
        .expect_err("missing command cannot run");
        assert!(format!("{error:#}").contains("running "));
        let error = output_of(missing.to_str().expect("missing path"), &[])
            .expect_err("missing output command cannot run");
        assert!(format!("{error:#}").contains("running "));
    }

    /// The bundle must carry everything a gateway needs. An omission would
    /// only show up at install time, on the target.
    #[test]
    fn the_shipped_content_is_complete() {
        assert!(BINARIES.contains(&"heliosd"));
        assert!(BINARIES.contains(&"helios-installer"));
        // Named rather than counted: a count says a unit was added, never
        // which one was dropped.
        for unit in [
            "heliosd.service",
            "helios-update.service",
            "helios-update.path",
            // Without the timer, a window armed for an upgrade that never
            // happened stays live until the next boot.
            "helios-update-window.service",
            "helios-update-window.timer",
            "helios-log-prune.service",
            "helios-log-prune.timer",
        ] {
            assert!(
                SYSTEMD_UNITS.contains(&unit),
                "unit {unit} missing from the bundle"
            );
        }
        for feature in ["netlink", "wireguard", "tpm", "embed-ui"] {
            assert!(
                GATEWAY_FEATURES.split(',').any(|f| f == feature),
                "feature {feature} missing from the production bundle"
            );
        }
        // And not the key negotiation: every heliosd carries it, exactly as
        // every Orion does. Making it a flag again would restore the failure
        // it was removed for — a `key_negotiation_port` accepted, inert, and
        // silent.
        assert!(
            !GATEWAY_FEATURES.contains("key-negotiation"),
            "key negotiation must not be a build flag: every heliosd carries it"
        );
    }

    /// The installer must carry what makes Orion usable.
    ///
    /// `wireguard`, because a client without it refuses to start rather than
    /// simulate. And **not** `key-negotiation`: the pre-WireGuard exchange is
    /// compiled into every build now. Re-introducing it as a flag would bring
    /// back the failure mode it was removed for — a binary that imports a
    /// pinned profile, looks perfectly healthy, and fails to connect for a
    /// reason no user can see.
    #[test]
    fn the_orion_installer_carries_the_features_that_matter() {
        assert!(
            ORION_FEATURES.split(',').any(|f| f == "wireguard"),
            "feature wireguard missing from the Orion installer"
        );
        assert!(
            !ORION_FEATURES.contains("key-negotiation"),
            "key negotiation must not be a build flag: every Orion carries it"
        );
    }

    /// The CI must build the installer through this tool.
    ///
    /// It used to spell the feature list out itself, and drifted: it shipped
    /// installers without `key-negotiation` long after the client needed it.
    /// Keeping a single source for the flags is what stops that from
    /// happening again.
    #[test]
    fn the_release_workflow_builds_orion_through_xtask() {
        let workflow = std::fs::read_to_string(
            workspace_root()
                .unwrap()
                .join(".github/workflows/release.yml"),
        )
        .expect("the release workflow must exist");

        assert!(
            workflow.contains("cargo xtask orion-msi"),
            "the release job must build the installer through `xtask orion-msi`"
        );
        assert!(
            workflow.contains("runs-on: [self-hosted, windows, x64, orion-signing]"),
            "the signing key must remain on the dedicated internal runner"
        );
        assert!(
            !workflow.contains("cargo xtask orion-msi --unsigned"),
            "the release must not publish an unsigned Orion installer"
        );
        for required in [
            "Get-AuthenticodeSignature",
            "TimeStamperCertificate",
            "ORION_SIGNING_CERT_SHA1",
        ] {
            assert!(
                workflow.contains(required),
                "the release must verify the signed and timestamped MSI: {required}"
            );
        }
        assert!(
            !workflow.contains("tauri build"),
            "the release job must not spell out its own Tauri invocation: the features would drift"
        );
    }

    #[test]
    fn the_windows_application_update_launcher_uses_the_canonical_tools() {
        let script =
            std::fs::read_to_string(workspace_root().unwrap().join("scripts/deploy-app.ps1"))
                .expect("the Windows application update launcher must exist");

        for required in ["helios", "app-update", "scripts/deploy-app.sh", "wsl.exe"] {
            assert!(
                script.contains(required),
                "the Windows launcher must invoke `{required}`"
            );
        }
        for duplicated_api in ["Invoke-RestMethod", "/api/update/chunk"] {
            assert!(
                !script.contains(duplicated_api),
                "the Windows launcher must not duplicate the update API through `{duplicated_api}`"
            );
        }
    }

    #[test]
    fn the_regression_workflow_checks_and_tests_orion_on_windows() {
        let workflow = std::fs::read_to_string(
            workspace_root()
                .unwrap()
                .join(".github/workflows/regression.yml"),
        )
        .expect("the regression workflow must exist");
        let windows_job = workflow
            .split("  orion-windows:")
            .nth(1)
            .expect("the Windows job must exist")
            .split("\n  audit:")
            .next()
            .unwrap();

        for required in [
            "runs-on: windows-2025",
            "Get-Command .\\scripts\\deploy-app.ps1 -Syntax",
            "needs.changes.outputs.windows",
            "cargo clippy --locked @packages --all-targets --all-features -- -D warnings",
            "cargo test --locked @packages --all-features",
        ] {
            assert!(
                windows_job.contains(required),
                "Windows security regression is missing `{required}`"
            );
        }

        // Full campaigns and coverage remain local: CI retains the native
        // checks without recompiling the workspace for instrumentation.
        for expensive in [
            "cargo llvm-cov",
            "run: bash scripts/regression.sh",
            "run: bash scripts/coverage.sh",
        ] {
            assert!(
                !workflow.contains(expensive),
                "the CI must keep full local campaigns out of its jobs: {expensive}"
            );
        }
    }

    /// The NSIS installer must install for the machine. A per-user install
    /// lands in a folder the user can rewrite, which the engine refuses to
    /// elevate from.
    #[test]
    fn the_nsis_bundle_installs_per_machine() {
        let path = workspace_root()
            .expect("root")
            .join("apps/orion/src-tauri/tauri.windows.conf.json");
        let text = std::fs::read_to_string(&path).expect("tauri.windows.conf.json is readable");
        let config: serde_json::Value =
            serde_json::from_str(&text).expect("tauri.windows.conf.json is JSON");
        assert_eq!(
            config["bundle"]["windows"]["nsis"]["installMode"],
            "perMachine"
        );
    }

    /// The units and the example configuration must exist in the repo: a
    /// dead reference would break the factory at the worst moment.
    #[test]
    fn the_bundle_s_source_files_exist() {
        let root = workspace_root().expect("root");
        for unit in SYSTEMD_UNITS {
            let path = root.join("deploy").join("systemd").join(unit);
            assert!(path.is_file(), "missing unit: {}", path.display());
        }
        assert!(root.join("config").join("network.toml").is_file());
    }

    #[test]
    fn the_update_window_timer_executes_the_bundled_daemon() {
        let root = workspace_root().expect("root");
        let unit =
            std::fs::read_to_string(root.join("deploy/systemd/helios-update-window.service"))
                .expect("update-window service");

        assert!(unit.contains("ExecStart=/opt/helios/current/heliosd tpm expire-window"));
        assert!(!unit.contains("/opt/helios/current/bin/heliosd"));
    }

    /// The readiness handshake between the installer and the daemon runs
    /// through `/run/helios`. Under `ProtectSystem=strict` a `ReadWritePaths`
    /// entry whose directory does not yet exist is dropped without a word, so
    /// the directory each unit needs is declared as its own runtime directory,
    /// preserved across the restart the installer performs.
    #[test]
    fn the_readiness_directory_survives_the_update_restart() {
        let root = workspace_root().expect("root");
        let installer = std::fs::read_to_string(root.join("deploy/systemd/helios-update.service"))
            .expect("update service");
        let daemon =
            std::fs::read_to_string(root.join("deploy/systemd/heliosd.service")).expect("daemon");

        for (unit, text) in [
            ("helios-update.service", &installer),
            ("heliosd.service", &daemon),
        ] {
            assert!(
                text.lines()
                    .any(|line| line.trim() == "RuntimeDirectory=helios"),
                "{unit} must declare RuntimeDirectory=helios"
            );
            assert!(
                text.lines()
                    .any(|line| line.trim() == "RuntimeDirectoryPreserve=yes"),
                "{unit} must preserve /run/helios across restarts"
            );
        }
        assert!(
            !installer
                .lines()
                .any(|line| line.starts_with("ReadWritePaths=") && line.contains("/run/helios")),
            "/run/helios must come from RuntimeDirectory, not from a ReadWritePaths entry              that is ignored when the directory is absent"
        );
    }

    #[test]
    fn firewall_maintenance_is_explicit_persistent_and_verified_on_target() {
        let root = workspace_root().expect("root");
        let deploy = std::fs::read_to_string(root.join("scripts/deploy.sh"))
            .expect("gateway deployment script");
        let bootstrap = std::fs::read_to_string(root.join("scripts/target-bootstrap.sh"))
            .expect("target bootstrap script");
        let unit = std::fs::read_to_string(root.join("deploy/systemd/heliosd.service"))
            .expect("daemon service");

        for required in ["--sans-firewall", "--avec-firewall", "ASTRA=0"] {
            assert!(
                deploy.contains(required),
                "deployment maintenance contract is missing `{required}`"
            );
        }
        for required in [
            "firewall-maintenance.conf",
            "run --unsafe-disable-firewall",
            "firewall_enforced=false",
            "nft list table inet helios",
        ] {
            assert!(
                bootstrap.contains(required),
                "target maintenance verification is missing `{required}`"
            );
        }
        assert!(
            !unit.contains("--unsafe-disable-firewall"),
            "maintenance must never become the signed service's default"
        );
    }

    #[test]
    fn wireguard_nt_is_pinned_and_stays_out_of_git() {
        assert!(orion_deps::WIREGUARD_NT_URL.starts_with("https://download.wireguard.com/"));
        assert_eq!(orion_deps::WIREGUARD_NT_SHA256.len(), 64);
        assert!(orion_deps::WIREGUARD_NT_SHA256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert!(orion_deps::WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/amd64/wireguard.dll",
            "binaries/wireguard-amd64.dll"
        )));
        assert!(orion_deps::WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/arm64/wireguard.dll",
            "binaries/wireguard-arm64.dll"
        )));
        assert!(workspace_root().unwrap().join(".gitignore").is_file());
        let ignore = std::fs::read_to_string(workspace_root().unwrap().join(".gitignore")).unwrap();
        assert!(
            ignore
                .lines()
                .any(|line| line.trim_end_matches('/') == "/resources-windows"),
            "the WireGuard-NT staging directory must stay ignored by git"
        );
    }
}
