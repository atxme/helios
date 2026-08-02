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
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

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
];

/// Shipped binaries, and their role.
const BINARIES: &[&str] = &["heliosd", "helios-installer", "helios-ctl"];

/// WireGuardNT binary version shipped with Orion.
const WIREGUARD_NT_VERSION: &str = "1.1";
/// Official archive, pinned: changing the version requires recomputing and
/// re-reading its content before updating this fingerprint.
const WIREGUARD_NT_URL: &str = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip";
const WIREGUARD_NT_SHA256: &str =
    "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace";
const MAX_WIREGUARD_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;

/// Output names are imposed by `defguard_wireguard_rs 0.11.0`, not by the
/// Orion bundler. Its Windows backend opens them relative to the current
/// directory under `resources-windows/binaries/`.
const WIREGUARD_FILES: &[(&str, &str)] = &[
    (
        "wireguard-nt/bin/amd64/wireguard.dll",
        "binaries/wireguard-amd64.dll",
    ),
    (
        "wireguard-nt/bin/arm64/wireguard.dll",
        "binaries/wireguard-arm64.dll",
    ),
    ("wireguard-nt/LICENSE.txt", "LICENSE-WireGuardNT.txt"),
];

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
        Cmd::Bundle {
            target,
            skip_frontend,
            output,
        } => bundle(target, skip_frontend, output),
        Cmd::OrionMsi {
            unsigned,
            with_nsis,
            skip_npm_ci,
        } => orion_msi(unsigned, with_nsis, skip_npm_ci),
        Cmd::Pack { dir, output } => pack(&dir, output),
    }
}

fn orion_deps() -> Result<()> {
    let root = workspace_root()?;
    let cache_dir = root.join("target").join("orion-deps");
    let archive = cache_dir.join(format!("wireguard-nt-{WIREGUARD_NT_VERSION}.zip"));
    let part = archive.with_extension("zip.part");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating {}", cache_dir.display()))?;

    let archive_is_valid = archive.is_file() && sha256_matches(&archive, WIREGUARD_NT_SHA256)?;
    if archive_is_valid {
        println!("==> WireGuardNT {WIREGUARD_NT_VERSION}: cached archive verified");
    } else {
        if archive.exists() {
            std::fs::remove_file(&archive)
                .with_context(|| format!("removing invalid archive {}", archive.display()))?;
        }
        if part.exists() {
            std::fs::remove_file(&part)
                .with_context(|| format!("removing incomplete download {}", part.display()))?;
        }
        println!("==> WireGuardNT {WIREGUARD_NT_VERSION}: official download");
        download_bounded(WIREGUARD_NT_URL, &part, MAX_WIREGUARD_ARCHIVE_BYTES)?;
        if !sha256_matches(&part, WIREGUARD_NT_SHA256)? {
            let actual = hex(&helios_update::sha256_file(&part)
                .map_err(|e| anyhow::anyhow!("fingerprint of {}: {e}", part.display()))?);
            std::fs::remove_file(&part).ok();
            bail!("WireGuardNT archive rejected: SHA-256 {actual}, expected {WIREGUARD_NT_SHA256}");
        }
        std::fs::rename(&part, &archive)
            .with_context(|| format!("validating {}", archive.display()))?;
    }

    let destination = root.join("resources-windows");
    extract_wireguard_files(&archive, &destination)?;
    println!(
        "==> Orion dependencies ready in {} (outside Git)",
        destination.display()
    );
    Ok(())
}

fn download_bounded(url: &str, destination: &Path, maximum: u64) -> Result<()> {
    let mut response = reqwest::blocking::Client::builder()
        .user_agent("Helios-xtask/orion-deps")
        .build()
        .context("creating the HTTPS client")?
        .get(url)
        .send()
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP response from {url}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum)
    {
        bail!("WireGuardNT archive too large (maximum {maximum} bytes)");
    }

    let mut file =
        File::create(destination).with_context(|| format!("creating {}", destination.display()))?;
    let copied = std::io::copy(&mut response.by_ref().take(maximum + 1), &mut file)
        .with_context(|| format!("writing {}", destination.display()))?;
    file.flush()
        .with_context(|| format!("finalizing {}", destination.display()))?;
    if copied > maximum {
        std::fs::remove_file(destination).ok();
        bail!("WireGuardNT archive too large (maximum {maximum} bytes)");
    }
    Ok(())
}

fn sha256_matches(path: &Path, expected: &str) -> Result<bool> {
    let digest = helios_update::sha256_file(path)
        .map_err(|e| anyhow::anyhow!("fingerprint of {}: {e}", path.display()))?;
    Ok(hex(&digest) == expected)
}

fn extract_wireguard_files(archive: &Path, destination: &Path) -> Result<()> {
    let file = File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(file)
        .with_context(|| format!("reading archive {}", archive.display()))?;

    for (source, relative_destination) in WIREGUARD_FILES {
        let mut entry = zip
            .by_name(source)
            .with_context(|| format!("entry {source} missing from the WireGuardNT archive"))?;
        if entry.is_dir() {
            bail!("unexpected WireGuardNT entry: {source} is a directory");
        }
        let output = destination.join(relative_destination);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let temporary = output.with_extension("part");
        let mut target = File::create(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        std::io::copy(&mut entry, &mut target).with_context(|| format!("extracting {source}"))?;
        target
            .flush()
            .with_context(|| format!("finalizing {}", temporary.display()))?;
        // `rename` does not replace an existing destination on Windows. The
        // command is replayed before each bundle: removing only this
        // generated file guarantees the new extraction wins.
        if output.exists() {
            std::fs::remove_file(&output)
                .with_context(|| format!("replacing {}", output.display()))?;
        }
        std::fs::rename(&temporary, &output)
            .with_context(|| format!("validating {}", output.display()))?;
        println!("  {}", output.display());
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
    if unsigned {
        println!("==> UNSIGNED build: this installer must not be distributed");
        std::env::set_var("ORION_UNSIGNED_FOR_OFFLINE_SIGNING", "1");
    } else {
        for variable in ["ORION_SIGNING_CERT_SHA1", "ORION_TIMESTAMP_URL"] {
            if std::env::var(variable).is_err() {
                bail!(
                    "{variable} is required to sign the installer. Set the Authenticode \
                     thumbprint and an RFC 3161 timestamp server, or pass --unsigned to \
                     produce a test installer that must not be distributed."
                );
            }
        }
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

fn bundle(target: Option<String>, skip_frontend: bool, output: Option<PathBuf>) -> Result<()> {
    let root = workspace_root()?;
    let target = match target {
        Some(target) => target,
        None => host_target()?,
    };
    let version = workspace_version(&root)?;

    // The publisher's public keyring is required by `heliosd`'s release
    // build. Checking it here avoids waiting several minutes of compilation
    // to learn it was missing.
    let keyring = std::env::var("HELIOS_PUBLISHER_KEYRING_PATH").map_err(|_| {
        anyhow::anyhow!(
            "HELIOS_PUBLISHER_KEYRING_PATH must point to the publisher's public keyring: \
             a bundle built without a trust anchor cannot verify any update"
        )
    })?;
    if !Path::new(&keyring).is_file() {
        bail!("public keyring not found: {keyring}");
    }

    if skip_frontend {
        println!("==> Frontend: reused as is (--skip-frontend)");
    } else {
        println!("==> Embedded frontend");
        run(&root, NPM, &["ci", "--prefix", "web"])?;
        run(&root, NPM, &["run", "build", "--prefix", "web"])?;
    }

    println!("==> heliosd ({GATEWAY_FEATURES})");
    run(
        &root,
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            &target,
            "-p",
            "heliosd",
            "--features",
            GATEWAY_FEATURES,
        ],
    )?;

    println!("==> helios-installer, helios-ctl");
    run(
        &root,
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            &target,
            "-p",
            "helios-installer",
            "-p",
            "helios-ctl",
        ],
    )?;

    let name = format!("helios-{version}-{target}");
    let staging = output.unwrap_or_else(|| root.join("target").join("bundle").join(&name));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("cleaning {}", staging.display()))?;
    }
    std::fs::create_dir_all(staging.join("systemd"))
        .with_context(|| format!("creating {}", staging.display()))?;

    let built = root.join("target").join(&target).join("release");
    for binary in BINARIES {
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
         --ml-dsa-65-private-key <…> --keyring {keyring}",
        staging.display()
    );
    println!("  cargo xtask pack --dir {}", staging.display());
    Ok(())
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

    run(
        &parent,
        "tar",
        &["-czf", &archive.to_string_lossy(), "--", &name],
    )?;

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

fn workspace_version(root: &Path) -> Result<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("reading the workspace Cargo.toml")?;
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace.package]")
        .find_map(|line| line.trim().strip_prefix("version = "))
        .map(|value| value.trim().trim_matches('"').to_string())
        .context("version missing from [workspace.package]")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_comes_from_the_workspace() {
        let root = workspace_root().expect("root");
        let version = workspace_version(&root).expect("version");
        assert!(
            version.split('.').count() == 3,
            "unexpected version: {version}"
        );
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

    /// The bundle must carry everything a gateway needs. An omission would
    /// only show up at install time, on the target.
    #[test]
    fn the_shipped_content_is_complete() {
        assert!(BINARIES.contains(&"heliosd"));
        assert!(BINARIES.contains(&"helios-installer"));
        assert_eq!(SYSTEMD_UNITS.len(), 3);
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
            !workflow.contains("tauri build"),
            "the release job must not spell out its own Tauri invocation: the features would drift"
        );
    }

    #[test]
    fn the_regression_workflow_executes_and_measures_orion_on_windows() {
        let workflow = std::fs::read_to_string(
            workspace_root()
                .unwrap()
                .join(".github/workflows/regression.yml"),
        )
        .expect("the regression workflow must exist");

        for required in [
            "orion-windows:",
            "runs-on: windows-2025",
            "cargo clippy -p orion-core -p orion --all-targets --all-features",
            "cargo llvm-cov --package orion-core --package orion --all-features",
            "coverage-orion-windows",
        ] {
            assert!(
                workflow.contains(required),
                "Windows security regression is missing `{required}`"
            );
        }
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
    fn wireguard_nt_is_pinned_and_stays_out_of_git() {
        assert!(WIREGUARD_NT_URL.starts_with("https://download.wireguard.com/"));
        assert_eq!(WIREGUARD_NT_SHA256.len(), 64);
        assert!(WIREGUARD_NT_SHA256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert!(WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/amd64/wireguard.dll",
            "binaries/wireguard-amd64.dll"
        )));
        assert!(WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/arm64/wireguard.dll",
            "binaries/wireguard-arm64.dll"
        )));
        assert!(workspace_root().unwrap().join(".gitignore").is_file());
        let ignore = std::fs::read_to_string(workspace_root().unwrap().join(".gitignore")).unwrap();
        assert!(ignore.lines().any(|line| line == "/resources-windows"));
    }
}
