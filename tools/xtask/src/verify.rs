//! `cargo xtask verify`: checks a published bundle against the commit it names.
//!
//! The signature of the bundle must verify under the given keyring. The commit
//! named by the signed manifest is then rebuilt in the pinned container, and
//! every file of the rebuilt bundle is compared with the bundle handed over:
//! same paths, same digests, same sizes, same execute bits (spec F15 §5.7).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
};

use aether::sig::BundleEntry;
use anyhow::{anyhow, bail, Context, Result};
use helios_update::bundle;

use crate::container;

/// Suffix of a commit name built from uncommitted changes.
const DIRTY_SUFFIX: &str = "-dirty";

/// Name of the bundle directory the container writes for a verification.
const REBUILT_NAME: &str = "rebuilt";

/// A file on which a rebuilt commit and a bundle disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Difference {
    /// Produced by the rebuilt commit, absent from the bundle.
    Missing(String),
    /// Present in the bundle, not produced by the rebuilt commit.
    Extra(String),
    /// Present on both sides, with another digest, size or execute bit.
    Changed {
        path: String,
        expected: BundleEntry,
        actual: BundleEntry,
    },
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(path) => write!(f, "missing from the bundle: {path}"),
            Self::Extra(path) => write!(f, "not produced by the commit: {path}"),
            Self::Changed {
                path,
                expected,
                actual,
            } => write!(
                f,
                "changed: {path}\n    rebuilt  sha256 {}, {} bytes, executable {}\n    bundle   sha256 {}, {} bytes, executable {}",
                digest(&expected.sha256),
                expected.size,
                expected.executable,
                digest(&actual.sha256),
                actual.size,
                actual.executable
            ),
        }
    }
}

fn digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The differences between the files a commit produces (`expected`) and the
/// files of a bundle (`actual`), sorted by path. Empty when they agree.
pub fn compare(expected: &[BundleEntry], actual: &[BundleEntry]) -> Vec<Difference> {
    let expected: BTreeMap<&str, &BundleEntry> = expected
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let actual: BTreeMap<&str, &BundleEntry> = actual
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let paths: BTreeSet<&str> = expected.keys().chain(actual.keys()).copied().collect();
    paths
        .into_iter()
        .filter_map(|path| match (expected.get(path), actual.get(path)) {
            (Some(_), None) => Some(Difference::Missing(path.to_string())),
            (None, Some(_)) => Some(Difference::Extra(path.to_string())),
            (Some(expected), Some(actual)) if expected != actual => Some(Difference::Changed {
                path: path.to_string(),
                expected: (**expected).clone(),
                actual: (**actual).clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Full hash of the commit that `git_commit` names in `repository`.
///
/// A commit built from uncommitted changes cannot be rebuilt from the
/// repository, and is refused. An unknown commit is most often a commit that
/// was never fetched here.
pub fn resolve_commit(repository: &Path, git_commit: &str) -> Result<String> {
    if git_commit.ends_with(DIRTY_SUFFIX) {
        bail!(
            "{git_commit} was built from uncommitted changes, which cannot be rebuilt from the repository"
        );
    }
    if git_commit.is_empty() || !git_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("the bundle names {git_commit:?}, which is not a commit hash");
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify"])
        .arg(format!("{git_commit}^{{commit}}"))
        .output()
        .context("running git rev-parse")?;
    if !output.status.success() {
        bail!(
            "commit {git_commit} is unknown in {}: run `git fetch` to get it, then verify again",
            repository.display()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Verifies the bundle at `bundle_path` (a directory, or a `.tar.gz` archive)
/// against `keyring`, and returns every difference with the rebuilt commit.
///
/// `rebuild` receives the repository and the full commit hash, and returns the
/// files of the bundle that commit produces. Everything that can be refused
/// without building is refused before `rebuild` is called.
pub fn verify_bundle(
    bundle_path: &Path,
    keyring: &Path,
    repository: &Path,
    rebuild: impl FnOnce(&Path, &str) -> Result<Vec<BundleEntry>>,
) -> Result<Vec<Difference>> {
    let scratch = Scratch::new("bundle")?;
    let dir = if bundle_path.is_dir() {
        bundle_path.to_path_buf()
    } else if bundle_path.is_file() {
        extract(bundle_path, scratch.path())?
    } else {
        bail!(
            "{} is neither a bundle directory nor an archive",
            bundle_path.display()
        );
    };

    let manifest = bundle::read_manifest(&dir)
        .with_context(|| format!("reading the bundle in {}", dir.display()))?;
    let keyring_bytes =
        fs::read(keyring).with_context(|| format!("reading {}", keyring.display()))?;
    let keys = bundle::parse_publisher_keyring(&keyring_bytes)
        .with_context(|| format!("invalid public keyring {}", keyring.display()))?;
    bundle::verify_signature_with_keyring(&manifest, &keys).context("verifying the bundle")?;

    let payload = &manifest.payload;
    if payload.target != container::CONTAINER_TARGET {
        bail!(
            "bundle target {} cannot be rebuilt: the build container only builds {}",
            payload.target,
            container::CONTAINER_TARGET
        );
    }
    let commit = resolve_commit(repository, &payload.git_commit)?;
    let rebuilt = rebuild(repository, &commit)?;

    let on_disk = bundle::collect(&dir).context("listing the bundle's files")?;
    let mut differences = compare(&rebuilt, &payload.files);
    differences.extend(compare(&rebuilt, &on_disk));
    Ok(differences)
}

/// Extracts a bundle archive into `scratch` and returns the bundle directory.
///
/// The listing is checked first: a link in the archive could make a later
/// member land outside `scratch`, before any signature is checked. Only
/// regular files and directories are accepted.
fn extract(archive: &Path, scratch: &Path) -> Result<PathBuf> {
    let archive =
        std::path::absolute(archive).with_context(|| format!("resolving {}", archive.display()))?;
    let listing = Command::new("tar")
        .arg("-tvzf")
        .arg(&archive)
        .output()
        .context("listing the archive with tar")?;
    if !listing.status.success() {
        bail!(
            "tar could not list {} ({})",
            archive.display(),
            listing.status
        );
    }
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        if !line.starts_with('-') && !line.starts_with('d') {
            bail!("the archive holds an entry that is not a file or a directory: {line}");
        }
    }

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(scratch)
        .status()
        .context("extracting the archive with tar")?;
    if !status.success() {
        bail!("tar could not extract {} ({status})", archive.display());
    }
    if scratch.join(bundle::BUNDLE_MANIFEST_FILE).is_file() {
        return Ok(scratch.to_path_buf());
    }
    let mut directories = fs::read_dir(scratch)
        .with_context(|| format!("reading {}", scratch.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir());
    match (directories.next(), directories.next()) {
        (Some(dir), None) => Ok(dir),
        _ => bail!(
            "{} does not hold exactly one bundle directory",
            archive.display()
        ),
    }
}

/// Rebuilds `commit` in the pinned build container, and returns the entries of
/// the bundle it produces. The container's output is removed afterwards.
fn rebuild_in_container(
    repository: &Path,
    keyring: &Path,
    commit: &str,
) -> Result<Vec<BundleEntry>> {
    let checkout = Checkout::add(repository, commit)?;
    let output = format!("/helios/out/{REBUILT_NAME}");
    let arguments: Vec<String> = [
        "bundle",
        "--native",
        "--target",
        container::CONTAINER_TARGET,
        "--output",
        &output,
    ]
    .iter()
    .map(|argument| argument.to_string())
    .collect();
    let out = container::build_in_container(
        &checkout.path,
        keyring,
        container::xtask_command(&arguments),
    )?;
    let entries = bundle::collect(&out.join(REBUILT_NAME))
        .map_err(|e| anyhow!("listing the rebuilt bundle: {e}"));
    let discarded = container::discard(&out);
    let entries = entries?;
    discarded?;
    Ok(entries)
}

/// `cargo xtask verify`: prints every difference, and fails unless there is none.
pub fn run(repository: &Path, bundle_path: &Path, keyring: &Path) -> Result<()> {
    let differences = verify_bundle(bundle_path, keyring, repository, |repository, commit| {
        rebuild_in_container(repository, keyring, commit)
    })?;
    if differences.is_empty() {
        println!("==> The bundle matches the commit it names, file for file");
        return Ok(());
    }
    for difference in &differences {
        println!("{difference}");
    }
    bail!(
        "{} file(s) differ from the rebuilt commit",
        differences.len()
    )
}

/// A detached worktree of the repository at one commit, removed on drop.
struct Checkout {
    repository: PathBuf,
    path: PathBuf,
}

impl Checkout {
    fn add(repository: &Path, commit: &str) -> Result<Self> {
        let path = unique_path("checkout");
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["worktree", "add", "--detach"])
            .arg(&path)
            .arg(commit)
            .output()
            .context("running git worktree add")?;
        if !output.status.success() {
            bail!(
                "git worktree add failed for {commit}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(Self {
            repository: repository.to_path_buf(),
            path,
        })
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .output();
        let _ = fs::remove_dir_all(&self.path);
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["worktree", "prune"])
            .output();
    }
}

/// A path under the system temporary directory, unique to this process.
fn unique_path(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    std::env::temp_dir().join(format!(
        "helios-verify-{label}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A scratch directory removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Result<Self> {
        let path = unique_path(label);
        fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aether::sig::{BundlePayload, PublisherSigner};
    use helios_update::{
        bundle::{self, BUNDLE_MANIFEST_FILE, BUNDLE_PRODUCT},
        INSTALLER_VERSION,
    };

    use super::*;
    use crate::container::CONTAINER_TARGET;

    fn entry(path: &str, sha256: u8, executable: bool) -> BundleEntry {
        BundleEntry {
            path: path.to_string(),
            size: 10,
            sha256: [sha256; 32],
            executable,
        }
    }

    fn refuse_build(_: &Path, _: &str) -> Result<Vec<BundleEntry>> {
        panic!("the bundle must be refused before any build")
    }

    /// A complete bundle signed for `target` and `git_commit`, written in
    /// `root`. Returns the path of the keyring that verifies it, written next
    /// to `root`.
    fn signed_bundle(root: &Path, target: &str, git_commit: &str) -> PathBuf {
        for (path, content) in [
            ("heliosd", "the-daemon"),
            ("helios-installer", "the-installer"),
            ("helios", "the-tool"),
            ("systemd/heliosd.service", "[Unit]"),
            ("network.toml.example", "wan_iface = \"eth0\""),
        ] {
            let file = root.join(path);
            fs::create_dir_all(file.parent().expect("parent")).expect("directory");
            fs::write(file, content).expect("bundle file");
        }
        let payload = BundlePayload {
            product: BUNDLE_PRODUCT.into(),
            channel: "testing".into(),
            release_sequence: 1,
            version: "1.0.0".into(),
            git_commit: git_commit.into(),
            target: target.into(),
            minimum_installer_version: INSTALLER_VERSION,
            files: bundle::collect(root).expect("listing"),
        };
        let signer = PublisherSigner::from_seed_material(1, &[3; 32], &[4; 32]).expect("signer");
        let manifest = signer.sign(payload).expect("signature");
        fs::write(
            root.join(BUNDLE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).expect("json"),
        )
        .expect("manifest");

        let keyring = root
            .parent()
            .expect("parent")
            .join("publisher-keyring.json");
        let keys = signer.public_keys();
        fs::write(
            &keyring,
            bundle::encode_publisher_keyring(&[keys]).expect("keyring"),
        )
        .expect("keyring file");
        keyring
    }

    /// A git repository holding one commit. Returns its full hash.
    fn repository_with_commit(root: &Path) -> String {
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(root)
                .args([
                    "-c",
                    "user.name=test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(args)
                .output()
                .expect("git");
            assert!(output.status.success(), "git {args:?} failed");
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "fixture"]);
        git(&["rev-parse", "HEAD"])
    }

    #[test]
    fn identical_lists_have_no_difference() {
        let list = [entry("a", 1, false), entry("b", 2, true)];
        assert!(compare(&list, &list).is_empty());
    }

    #[test]
    fn differences_are_named() {
        let expected = [
            entry("a", 1, false),
            entry("b", 2, false),
            entry("c", 3, false),
            entry("d", 4, false),
        ];
        let actual = [
            entry("a", 1, false),
            entry("c", 9, false),
            entry("d", 4, true),
            entry("e", 5, false),
        ];

        assert_eq!(
            compare(&expected, &actual),
            vec![
                Difference::Missing("b".into()),
                Difference::Changed {
                    path: "c".into(),
                    expected: entry("c", 3, false),
                    actual: entry("c", 9, false),
                },
                Difference::Changed {
                    path: "d".into(),
                    expected: entry("d", 4, false),
                    actual: entry("d", 4, true),
                },
                Difference::Extra("e".into()),
            ]
        );
    }

    #[test]
    fn dirty_commit_is_refused() {
        let error = resolve_commit(Path::new("."), "0123456789abcdef-dirty")
            .unwrap_err()
            .to_string();
        assert!(error.contains("dirty"), "message: {error}");
    }

    #[test]
    fn unknown_commit_names_git_fetch() {
        let scratch = Scratch::new("unknown-commit").expect("scratch");
        Command::new("git")
            .arg("-C")
            .arg(scratch.path())
            .args(["init", "-q"])
            .status()
            .expect("git init");

        let error = resolve_commit(scratch.path(), "0123456789abcdef")
            .unwrap_err()
            .to_string();
        assert!(error.contains("git fetch"), "message: {error}");
    }

    #[test]
    fn foreign_target_is_refused() {
        let scratch = Scratch::new("foreign-target").expect("scratch");
        let bundle_dir = scratch.path().join("bundle");
        fs::create_dir(&bundle_dir).expect("bundle directory");
        let keyring = signed_bundle(&bundle_dir, "aarch64-unknown-linux-gnu", "0123456789abcdef");

        let error = verify_bundle(&bundle_dir, &keyring, scratch.path(), refuse_build)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target"), "message: {error}");
    }

    #[test]
    fn unsigned_bundle_is_refused_before_building() {
        let scratch = Scratch::new("unsigned").expect("scratch");
        fs::write(scratch.path().join("heliosd"), b"the-daemon").expect("file");
        let keyring = scratch.path().join("keyring.json");
        fs::write(&keyring, b"[]").expect("keyring");

        let error =
            verify_bundle(scratch.path(), &keyring, scratch.path(), refuse_build).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("manifest"), "message: {message}");
    }

    #[test]
    fn verify_accepts_an_archive_and_a_directory() {
        let scratch = Scratch::new("archive-and-directory").expect("scratch");
        let repository = scratch.path().join("repository");
        fs::create_dir(&repository).expect("repository directory");
        let commit = repository_with_commit(&repository);
        let parent = scratch.path().join("bundles");
        let bundle_dir = parent.join("helios-test");
        fs::create_dir_all(&bundle_dir).expect("bundle directory");
        let keyring = signed_bundle(&bundle_dir, CONTAINER_TARGET, &commit[..16]);
        let archive = scratch.path().join("helios-test.tar.gz");
        crate::archive::create(&parent, "helios-test", &archive, 0).expect("archive");

        // A faithful rebuild: it produces exactly the files of the bundle.
        let rebuilt = bundle::collect(&bundle_dir).expect("listing");
        let seen = std::cell::RefCell::new(Vec::new());
        let from_directory = verify_bundle(&bundle_dir, &keyring, &repository, |_, commit| {
            seen.borrow_mut().push(commit.to_string());
            Ok(rebuilt.clone())
        })
        .expect("directory");
        let from_archive = verify_bundle(&archive, &keyring, &repository, |_, commit| {
            seen.borrow_mut().push(commit.to_string());
            Ok(rebuilt.clone())
        })
        .expect("archive");

        assert!(from_directory.is_empty(), "{from_directory:?}");
        assert_eq!(from_directory, from_archive);
        assert_eq!(*seen.borrow(), [commit.clone(), commit]);
    }

    #[cfg(unix)]
    #[test]
    fn an_archive_holding_a_link_is_refused_before_extraction() {
        let scratch = Scratch::new("archive-link").expect("scratch");
        let parent = scratch.path().join("bundles");
        let bundle_dir = parent.join("helios-test");
        fs::create_dir_all(&bundle_dir).expect("bundle directory");
        std::os::unix::fs::symlink("/etc", bundle_dir.join("escape")).expect("symlink");
        let archive = scratch.path().join("helios-test.tar.gz");
        crate::archive::create(&parent, "helios-test", &archive, 0).expect("archive");
        let keyring = scratch.path().join("keyring.json");
        fs::write(&keyring, b"[]").expect("keyring");

        let error = verify_bundle(&archive, &keyring, scratch.path(), refuse_build)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not a file or a directory"),
            "message: {error}"
        );
    }
}
