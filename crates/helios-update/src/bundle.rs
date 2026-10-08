//! Installation bundle: what is delivered to a fresh gateway.
//!
//! A bundle is a directory — carried as an archive — containing the
//! binaries, the systemd units and an example configuration, plus a
//! [signed manifest](aether::sig::BundlePayload) that **exhaustively**
//! enumerates its contents along with their digests.
//!
//! # What this module guarantees, and what it does not
//!
//! It guarantees that an installed bundle matches byte for byte what the
//! publisher signed: no modified file, no added file, no missing file. This
//! is stronger than the applicative update verification (ADR-003), which
//! only covers the `heliosd` binary — a bundle also carries the systemd
//! unit, which decides the daemon's command line.
//!
//! It does **not** guarantee the authenticity of the program that runs this
//! verification on the very first deployment: at that point,
//! `helios-installer` itself comes from the bundle. The trust root of that
//! first step is the channel through which the operator copied the archive,
//! and the digest they compared. Subsequent installations, on the other
//! hand, are verified by an installer that is already installed and
//! verified. What would unblock the first step: a system package signed by
//! a distribution, out of scope here.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use aether::{
    sig::{BundleEntry, BundlePayload, SignedBundle, PUBLISHER_KEYS},
    Result,
};

use crate::{sha256_file, update_error, INSTALLER_VERSION, MAX_BINARY_SIZE};

/// Name of the signed manifest, at the bundle's root.
pub const BUNDLE_MANIFEST_FILE: &str = "manifest.json";

/// Maximum number of files in a bundle.
///
/// Bounds the memory and verification time of a hostile archive: the real
/// bundle has fewer than a dozen.
pub const MAX_BUNDLE_FILES: usize = 256;

/// Maximum tree depth, for the same reason.
pub const MAX_BUNDLE_DEPTH: usize = 4;

/// Expected product in a gateway bundle's manifest.
pub const BUNDLE_PRODUCT: &str = "helios";

/// Enumerates the contents of a bundle directory, sorted by path.
///
/// The manifest itself is excluded: it cannot contain its own digest.
pub fn collect(root: &Path) -> Result<Vec<BundleEntry>> {
    let mut entries = BTreeMap::new();
    walk(root, root, 0, &mut entries)?;
    if entries.len() > MAX_BUNDLE_FILES {
        return Err(update_error(format!(
            "bundle of {} files, maximum {MAX_BUNDLE_FILES}",
            entries.len()
        )));
    }
    Ok(entries.into_values().collect())
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    entries: &mut BTreeMap<String, BundleEntry>,
) -> Result<()> {
    if depth > MAX_BUNDLE_DEPTH {
        return Err(update_error(format!(
            "bundle tree too deep under {}",
            dir.display()
        )));
    }
    let listing =
        fs::read_dir(dir).map_err(|e| update_error(format!("reading {}: {e}", dir.display())))?;
    for item in listing {
        let item = item.map_err(|e| update_error(format!("iterating {}: {e}", dir.display())))?;
        let path = item.path();
        // `symlink_metadata`: a symbolic link is not followed. Following it
        // would let a file outside the bundle's root enter the bundle, whose
        // signed digest would say nothing about what would actually be
        // installed.
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| update_error(format!("reading {}: {e}", path.display())))?;
        if metadata.is_dir() {
            walk(root, &path, depth + 1, entries)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(update_error(format!(
                "{} is neither a file nor a directory — a bundle contains no symbolic \
                 link or special file",
                path.display()
            )));
        }
        let relative = relative_path(root, &path)?;
        if relative == BUNDLE_MANIFEST_FILE {
            continue;
        }
        if metadata.len() > MAX_BINARY_SIZE {
            return Err(update_error(format!(
                "{relative}: {} bytes, maximum {MAX_BINARY_SIZE}",
                metadata.len()
            )));
        }
        entries.insert(
            relative.clone(),
            BundleEntry {
                path: relative,
                size: metadata.len(),
                sha256: sha256_file(&path)?,
                executable: is_executable(&metadata),
            },
        );
        if entries.len() > MAX_BUNDLE_FILES {
            return Err(update_error(format!(
                "bundle of more than {MAX_BUNDLE_FILES} files"
            )));
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| update_error(format!("{} outside the bundle", path.display())))?;
    let mut segments = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| {
                        update_error(format!("non-UTF-8 file name: {}", path.display()))
                    })?
                    .to_string(),
            ),
            _ => {
                return Err(update_error(format!(
                    "unexpected bundle path: {}",
                    path.display()
                )))
            }
        }
    }
    Ok(segments.join("/"))
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

/// Outside Unix, the executable bit does not exist: the manifest then
/// carries the value intended by the producer, never a value guessed from
/// the filesystem. A gateway bundle is built under Linux anyway.
#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

/// Absolute path of a bundle entry, validated against directory escape.
pub fn entry_path(root: &Path, entry: &BundleEntry) -> PathBuf {
    root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR))
}

/// Reads the signed manifest at a bundle's root.
pub fn read_manifest(root: &Path) -> Result<SignedBundle> {
    let path = root.join(BUNDLE_MANIFEST_FILE);
    let raw = fs::read(&path).map_err(|e| {
        update_error(format!(
            "manifest missing or unreadable ({}): {e} — an unsigned bundle does not install",
            path.display()
        ))
    })?;
    serde_json::from_slice(&raw).map_err(|e| update_error(format!("invalid bundle manifest: {e}")))
}

/// Verifies the manifest's signatures and metadata.
pub fn verify_manifest(manifest: &SignedBundle, channel: &str, target: &str) -> Result<()> {
    verify_manifest_with_keyring(manifest, channel, target, PUBLISHER_KEYS)
}

fn verify_manifest_with_keyring(
    manifest: &SignedBundle,
    channel: &str,
    target: &str,
    keyring: &[aether::sig::PublisherPublicKeys],
) -> Result<()> {
    manifest
        .verify(keyring)
        .map_err(|e| update_error(format!("bundle signature rejected: {e}")))?;
    let payload = &manifest.payload;
    if payload.product != BUNDLE_PRODUCT {
        return Err(update_error(format!(
            "manifest does not target {BUNDLE_PRODUCT} but {}",
            payload.product
        )));
    }
    if payload.channel != channel {
        return Err(update_error(format!(
            "channel {} refused, {channel} expected",
            payload.channel
        )));
    }
    if payload.target != target {
        return Err(update_error(format!(
            "target {} refused, {target} expected",
            payload.target
        )));
    }
    if payload.release_sequence == 0
        || payload.version.trim().is_empty()
        || payload.git_commit.trim().is_empty()
    {
        return Err(update_error("incomplete bundle metadata"));
    }
    if payload.minimum_installer_version > INSTALLER_VERSION {
        return Err(update_error(format!(
            "installer v{} required, v{INSTALLER_VERSION} present",
            payload.minimum_installer_version
        )));
    }
    payload
        .validate()
        .map_err(|e| update_error(format!("bundle content rejected: {e}")))?;
    Ok(())
}

/// Verifies that the directory's contents match the manifest **exactly**.
///
/// Equality is strict in both directions: an extra file is a refusal, not a
/// tolerance. Without this symmetry, an archive could slip an unsigned file
/// alongside signed ones — a script, one more systemd unit — and the
/// installation would apply it under a guarantee that does not cover it.
pub fn verify_contents(root: &Path, payload: &BundlePayload) -> Result<()> {
    payload
        .validate()
        .map_err(|e| update_error(format!("bundle content rejected: {e}")))?;
    let actual = collect(root)?;
    if actual == payload.files {
        return Ok(());
    }

    for entry in &payload.files {
        match actual.iter().find(|candidate| candidate.path == entry.path) {
            None => {
                return Err(update_error(format!(
                    "file missing from the bundle: {}",
                    entry.path
                )))
            }
            Some(candidate) if candidate.sha256 != entry.sha256 => {
                return Err(update_error(format!(
                    "digest mismatch for {} — content altered",
                    entry.path
                )))
            }
            Some(candidate) if candidate.size != entry.size => {
                return Err(update_error(format!("size mismatch for {}", entry.path)))
            }
            Some(candidate) if candidate.executable != entry.executable => {
                return Err(update_error(format!(
                    "execute permission mismatch for {}",
                    entry.path
                )))
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = actual
        .iter()
        .find(|candidate| payload.entry(&candidate.path).is_none())
    {
        return Err(update_error(format!(
            "unsigned file present in the bundle: {}",
            extra.path
        )));
    }
    Err(update_error("bundle content does not match the manifest"))
}

/// System destinations of an installed bundle.
///
/// Each path can be overridden by an environment variable, like
/// [`crate::UpdateLayout`]: this is what makes the complete installation
/// verifiable on a development machine, without root privileges and without
/// touching the system. The production service, on the other hand, defines
/// none of them.
#[derive(Debug, Clone)]
pub struct BootstrapLayout {
    pub update: crate::UpdateLayout,
    /// Privileged update helper (`helios-installer`).
    pub libexec_dir: PathBuf,
    /// Operational tools (`helios`).
    pub bin_dir: PathBuf,
    /// Systemd units.
    pub systemd_dir: PathBuf,
    /// Network configuration, **never overwritten** if it already exists.
    pub config_path: PathBuf,
}

impl BootstrapLayout {
    pub fn system(update: crate::UpdateLayout) -> Self {
        Self {
            update,
            libexec_dir: env_path("HELIOS_LIBEXEC_DIR", "/usr/libexec"),
            bin_dir: env_path("HELIOS_BIN_DIR", "/usr/local/bin"),
            systemd_dir: env_path("HELIOS_SYSTEMD_DIR", "/etc/systemd/system"),
            config_path: env_path("HELIOS_NETWORK_CONFIG", "/var/lib/helios/network.toml"),
        }
    }
}

fn env_path(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// What an installation actually did, for the report to the operator.
#[derive(Debug)]
pub struct InstallReport {
    pub version: String,
    pub release_sequence: u64,
    pub channel: String,
    pub installed: Vec<PathBuf>,
    /// The configuration already existed and was not touched.
    pub config_preserved: bool,
    /// Files of earlier releases this installation retired.
    pub removed: Vec<PathBuf>,
}

/// The operator tool's former name. Installing `helios` removes it, so a
/// gateway never keeps two commands with diverging behaviour.
const LEGACY_TOOL: &str = "helios-ctl";

/// Destination of a bundle file.
enum Destination {
    /// The daemon: versioned under `install_root/<sequence>` and pointed to
    /// by `current`, like an applicative update.
    Daemon,
    /// An ordinary file, replaced if it exists.
    Replace(PathBuf, u32),
    /// The configuration: applied only if it is absent.
    ConfigIfAbsent(PathBuf, u32),
}

/// Where each declared file goes. An unknown path is a refusal.
///
/// Ignoring an unrecognized file would amount to silently installing a
/// bundle partially: the operator would believe they deployed what they
/// signed.
fn destination(path: &str, layout: &BootstrapLayout) -> Result<Destination> {
    match path {
        "heliosd" => Ok(Destination::Daemon),
        "helios-installer" => Ok(Destination::Replace(
            layout.libexec_dir.join("helios-installer"),
            0o755,
        )),
        "helios" => Ok(Destination::Replace(layout.bin_dir.join("helios"), 0o755)),
        "network.toml.example" => Ok(Destination::ConfigIfAbsent(
            layout.config_path.clone(),
            0o600,
        )),
        other => match other.strip_prefix("systemd/") {
            Some(unit) if !unit.contains('/') => {
                Ok(Destination::Replace(layout.systemd_dir.join(unit), 0o644))
            }
            _ => Err(update_error(format!(
                "file {other} has no known destination — this bundle was produced by a \
                 different version of the installer"
            ))),
        },
    }
}

/// Installs a **verified** bundle from an extracted directory.
///
/// Order matters: everything is verified before anything is written. An
/// installation that failed halfway through would leave a gateway with a
/// daemon of one version and a systemd unit of another.
pub fn install(root: &Path, layout: &BootstrapLayout) -> Result<InstallReport> {
    install_with_keyring(root, layout, PUBLISHER_KEYS)
}

fn install_with_keyring(
    root: &Path,
    layout: &BootstrapLayout,
    keyring: &[aether::sig::PublisherPublicKeys],
) -> Result<InstallReport> {
    let manifest = read_manifest(root)?;
    verify_manifest_with_keyring(
        &manifest,
        &layout.update.channel,
        &layout.update.target,
        keyring,
    )?;
    verify_contents(root, &manifest.payload)?;

    let payload = &manifest.payload;
    let state = crate::read_state(&layout.update.state_path)?;
    crate::reject_rollback(payload.release_sequence, &state)?;

    // Destinations are resolved before the first write: a bundle carrying an
    // unknown file must be refused entirely, not partially applied.
    let mut plan = Vec::with_capacity(payload.files.len());
    for entry in &payload.files {
        plan.push((entry, destination(&entry.path, layout)?));
    }
    if !payload.files.iter().any(|entry| entry.path == "heliosd") {
        return Err(update_error("bundle without heliosd"));
    }

    let mut installed = Vec::new();
    let mut config_preserved = false;
    let release_dir = layout
        .update
        .install_root
        .join(payload.release_sequence.to_string());

    for (entry, destination) in plan {
        let source = entry_path(root, entry);
        match destination {
            Destination::Daemon => {
                fs::create_dir_all(&release_dir)?;
                let target = release_dir.join("heliosd");
                replace_file(&source, &target, 0o755)?;
                installed.push(target);
            }
            Destination::Replace(target, mode) => {
                replace_file(&source, &target, mode)?;
                installed.push(target);
            }
            Destination::ConfigIfAbsent(target, mode) => {
                if target.exists() {
                    config_preserved = true;
                } else {
                    replace_file(&source, &target, mode)?;
                    installed.push(target);
                }
            }
        }
    }

    let mut removed = Vec::new();
    if payload.files.iter().any(|entry| entry.path == "helios") {
        let legacy = layout.bin_dir.join(LEGACY_TOOL);
        match fs::remove_file(&legacy) {
            Ok(()) => removed.push(legacy),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(update_error(format!(
                    "removing the legacy {}: {error}",
                    legacy.display()
                )))
            }
        }
    }

    crate::switch_link(&layout.update.current_link, &release_dir)?;
    crate::write_json_atomic(
        &layout.update.state_path,
        &crate::UpdateState {
            highest_confirmed_sequence: payload.release_sequence,
            active_version: Some(payload.version.clone()),
        },
    )?;

    Ok(InstallReport {
        version: payload.version.clone(),
        release_sequence: payload.release_sequence,
        channel: payload.channel.clone(),
        installed,
        config_preserved,
        removed,
    })
}

/// Writes a fresh copy then puts it in place via `rename`.
///
/// Directly replacing an executable in use would fail or corrupt the live
/// process; `rename` on the same filesystem is atomic and leaves the old
/// inode to the processes that opened it.
fn replace_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("helios-installing");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = fs::read(source)?;
    crate::write_new_synced(&temporary, &bytes, mode)?;
    fs::rename(&temporary, destination)?;
    if let Some(parent) = destination.parent() {
        crate::sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-bundle-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    fn write_file(root: &Path, relative: &str, content: &[u8]) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn payload(files: Vec<BundleEntry>) -> BundlePayload {
        BundlePayload {
            product: BUNDLE_PRODUCT.into(),
            channel: "testing".into(),
            release_sequence: 1,
            version: "0.1.0".into(),
            git_commit: "abcdef0123456789".into(),
            target: crate::BUILD_TARGET.into(),
            minimum_installer_version: INSTALLER_VERSION,
            files,
        }
    }

    #[test]
    fn enumeration_is_sorted_and_ignores_the_manifest() {
        let dir = temp_dir("collect");
        write_file(&dir, "heliosd", b"binary");
        write_file(&dir, "systemd/heliosd.service", b"unit");
        write_file(&dir, BUNDLE_MANIFEST_FILE, b"{}");

        let entries = collect(&dir).expect("enumeration");
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["heliosd", "systemd/heliosd.service"]);
        assert_eq!(entries[0].size, 6);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn matching_content_is_accepted() {
        let dir = temp_dir("matching");
        write_file(&dir, "heliosd", b"binary");
        let payload = payload(collect(&dir).unwrap());
        assert!(verify_contents(&dir, &payload).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_altered_file_is_rejected() {
        let dir = temp_dir("altered");
        write_file(&dir, "heliosd", b"binary");
        let payload = payload(collect(&dir).unwrap());
        write_file(&dir, "heliosd", b"binaryX");

        let error = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(error.contains("heliosd"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The point that distinguishes this verification from a simple digest
    /// check: an extra file is a refusal.
    #[test]
    fn an_extra_file_is_rejected() {
        let dir = temp_dir("extra");
        write_file(&dir, "heliosd", b"binary");
        let payload = payload(collect(&dir).unwrap());
        write_file(&dir, "systemd/pirate.service", b"unsigned unit");

        let error = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(error.contains("pirate"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_rejected() {
        let dir = temp_dir("missing");
        write_file(&dir, "heliosd", b"binary");
        write_file(&dir, "helios", b"tool");
        let payload = payload(collect(&dir).unwrap());
        fs::remove_file(dir.join("helios")).unwrap();

        let error = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(error.contains("helios"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_executable_bit_is_part_of_what_is_verified() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        write_file(&dir, "heliosd", b"binary");
        fs::set_permissions(dir.join("heliosd"), fs::Permissions::from_mode(0o755)).unwrap();
        let payload = payload(collect(&dir).unwrap());
        assert!(payload.files[0].executable);

        fs::set_permissions(dir.join("heliosd"), fs::Permissions::from_mode(0o644)).unwrap();
        let error = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(error.contains("execute"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A symbolic link would let a file outside the bundle's root enter the
    /// bundle: the signed digest would then say nothing about what is
    /// actually installed.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_rejected() {
        let dir = temp_dir("symlink");
        write_file(&dir, "heliosd", b"binary");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("secret")).unwrap();

        let error = collect(&dir).unwrap_err().to_string();
        assert!(error.contains("symbolic link"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_manifest_is_an_explicit_refusal() {
        let dir = temp_dir("no-manifest");
        write_file(&dir, "heliosd", b"binary");
        let error = read_manifest(&dir).unwrap_err().to_string();
        assert!(error.contains("unsigned"), "message: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    // ─── End-to-end installation ────────────────────────────────────────────

    use aether::sig::{PublisherPublicKeys, PublisherSigner};

    /// Complete bundle, as `cargo xtask bundle` assembles it.
    fn full_bundle(root: &Path) {
        write_file(root, "heliosd", b"the-daemon");
        write_file(root, "helios-installer", b"the-installer");
        write_file(root, "helios", b"the-tool");
        write_file(root, "systemd/heliosd.service", b"[Unit]");
        write_file(root, "systemd/helios-update.service", b"[Unit]");
        write_file(root, "systemd/helios-update.path", b"[Path]");
        write_file(root, "systemd/helios-log-prune.service", b"[Unit]");
        write_file(root, "systemd/helios-log-prune.timer", b"[Unit]");
        write_file(root, "network.toml.example", b"wan_iface = \"eth0\"");
    }

    fn sign_bundle(root: &Path, sequence: u64) -> PublisherPublicKeys {
        let signer = PublisherSigner::from_seed_material(1, &[3; 32], &[4; 32]).unwrap();
        let mut payload = payload(collect(root).unwrap());
        payload.release_sequence = sequence;
        payload.version = format!("0.{sequence}.0");
        let manifest = signer.sign(payload).unwrap();
        fs::write(
            root.join(BUNDLE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        signer.public_keys()
    }

    /// Destinations redirected to a throwaway directory: the complete
    /// installation becomes verifiable without root privileges and without
    /// touching the system.
    fn bootstrap_layout(target: &Path) -> BootstrapLayout {
        let mut update = crate::UpdateLayout::system("testing");
        update.staging_root = target.join("var/lib/helios/updates");
        update.state_path = update.staging_root.join("state.json");
        update.activation_path = update.staging_root.join("activate.json");
        update.install_root = target.join("opt/helios/releases");
        update.current_link = target.join("opt/helios/current");
        update.target = crate::BUILD_TARGET.to_string();
        BootstrapLayout {
            update,
            libexec_dir: target.join("usr/libexec"),
            bin_dir: target.join("usr/local/bin"),
            systemd_dir: target.join("etc/systemd/system"),
            config_path: target.join("var/lib/helios/network.toml"),
        }
    }

    #[test]
    fn installation_applies_the_whole_bundle_and_switches_the_link() {
        let source = temp_dir("install-source");
        let target = temp_dir("install-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 7);
        let layout = bootstrap_layout(&target);

        let report = install_with_keyring(&source, &layout, &[keys]).expect("installation");

        assert_eq!(report.release_sequence, 7);
        assert!(!report.config_preserved);
        assert_eq!(
            fs::read(target.join("opt/helios/releases/7/heliosd")).unwrap(),
            b"the-daemon"
        );
        assert_eq!(
            fs::read(target.join("usr/libexec/helios-installer")).unwrap(),
            b"the-installer"
        );
        assert_eq!(
            fs::read(target.join("usr/local/bin/helios")).unwrap(),
            b"the-tool"
        );
        assert!(target.join("etc/systemd/system/heliosd.service").is_file());
        assert!(target
            .join("etc/systemd/system/helios-update.path")
            .is_file());
        assert!(target
            .join("etc/systemd/system/helios-log-prune.timer")
            .is_file());
        assert!(target.join("var/lib/helios/network.toml").is_file());
        assert_eq!(
            fs::read_link(target.join("opt/helios/current")).unwrap(),
            target.join("opt/helios/releases/7")
        );

        // The anti-rollback state must reflect what was just applied,
        // otherwise an older applicative update would be accepted afterwards.
        let state: crate::UpdateState =
            serde_json::from_slice(&fs::read(&layout.update.state_path).unwrap()).unwrap();
        assert_eq!(state.highest_confirmed_sequence, 7);
        assert_eq!(state.active_version.as_deref(), Some("0.7.0"));

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    /// The operator tool is `helios` now: installing it retires the old
    /// `helios-ctl` binary, so the gateway is left with a single command.
    #[test]
    fn installing_the_tool_retires_the_legacy_binary() {
        let source = temp_dir("retire-source");
        let target = temp_dir("retire-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 9);
        let layout = bootstrap_layout(&target);
        fs::create_dir_all(&layout.bin_dir).unwrap();
        fs::write(layout.bin_dir.join("helios-ctl"), b"old tool").unwrap();

        let report = install_with_keyring(&source, &layout, &[keys]).expect("installation");

        assert!(!layout.bin_dir.join("helios-ctl").exists());
        assert_eq!(report.removed, vec![layout.bin_dir.join("helios-ctl")]);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn a_bundle_still_carrying_the_legacy_tool_is_refused() {
        let layout = bootstrap_layout(Path::new("/nonexistent"));
        let error = destination("helios-ctl", &layout).err().expect("refused");
        assert!(error.to_string().contains("helios-ctl"), "{error}");
    }

    /// Reinstalling an already-applied sequence would bring back a version
    /// that ADR-003's anti-rollback otherwise refuses: both paths must obey
    /// the same counter.
    #[test]
    fn an_already_confirmed_sequence_is_rejected() {
        let source = temp_dir("rollback-source");
        let target = temp_dir("rollback-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 5);
        let layout = bootstrap_layout(&target);
        install_with_keyring(&source, &layout, &[keys]).expect("first installation");

        let old = temp_dir("rollback-old");
        full_bundle(&old);
        let keys = sign_bundle(&old, 4);
        let error = install_with_keyring(&old, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(error.contains("sequence 4 refused"), "message: {error}");

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
        let _ = fs::remove_dir_all(&old);
    }

    /// The configuration carries the network identity and the admitted
    /// peers: overwriting it on every update would cut off the fleet.
    #[test]
    fn an_existing_configuration_is_never_overwritten() {
        let source = temp_dir("config-source");
        let target = temp_dir("config-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 3);
        let layout = bootstrap_layout(&target);
        fs::create_dir_all(layout.config_path.parent().unwrap()).unwrap();
        fs::write(&layout.config_path, b"wan_iface = \"already-configured\"").unwrap();

        let report = install_with_keyring(&source, &layout, &[keys]).expect("installation");

        assert!(report.config_preserved);
        assert_eq!(
            fs::read(&layout.config_path).unwrap(),
            b"wan_iface = \"already-configured\""
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    /// Nothing must be written until everything is verified: an installation
    /// done halfway would leave a daemon and a systemd unit of different
    /// versions.
    #[test]
    fn an_altered_bundle_installs_nothing() {
        let source = temp_dir("altered-source");
        let target = temp_dir("altered-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 9);
        write_file(&source, "heliosd", b"the-daemon-replaced");
        let layout = bootstrap_layout(&target);

        assert!(install_with_keyring(&source, &layout, &[keys]).is_err());
        assert!(
            !target.join("opt/helios").exists() && !target.join("etc").exists(),
            "a rejected installation must not have applied anything"
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    /// A signed file whose destination the installer does not know must fail
    /// the whole bundle, not be ignored.
    #[test]
    fn a_file_without_a_known_destination_rejects_the_whole_bundle() {
        let source = temp_dir("unknown-source");
        let target = temp_dir("unknown-target");
        full_bundle(&source);
        write_file(&source, "cron.d/helios", b"* * * * * root /bin/true");
        let keys = sign_bundle(&source, 2);
        let layout = bootstrap_layout(&target);

        let error = install_with_keyring(&source, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(error.contains("destination"), "message: {error}");
        assert!(!target.join("opt/helios").exists());
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn a_bundle_from_another_channel_is_rejected() {
        let source = temp_dir("channel-source");
        let target = temp_dir("channel-target");
        full_bundle(&source);
        let keys = sign_bundle(&source, 1);
        let mut layout = bootstrap_layout(&target);
        layout.update.channel = "production".into();

        let error = install_with_keyring(&source, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("channel testing refused"),
            "message: {error}"
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    /// A signature valid for a different era than the one compiled into the
    /// binary must authorize nothing.
    #[test]
    fn a_bundle_signed_by_another_key_is_rejected() {
        let source = temp_dir("key-source");
        let target = temp_dir("key-target");
        full_bundle(&source);
        sign_bundle(&source, 6);
        let other = PublisherSigner::from_seed_material(1, &[9; 32], &[8; 32])
            .unwrap()
            .public_keys();
        let layout = bootstrap_layout(&target);

        let error = install_with_keyring(&source, &layout, &[other])
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature"), "message: {error}");
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }
}
