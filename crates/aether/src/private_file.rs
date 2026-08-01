//! Atomic writes of files that must never be world-readable.
//!
//! Two properties, and they only hold together:
//!
//! * **atomicity** — write to a temporary file then `rename`, so a reader never
//!   sees a half-written configuration and a crash never truncates the previous
//!   one;
//! * **restrictive permissions from creation** — 0600 on the temporary file,
//!   *before* a single byte is written. A `chmod` applied afterwards leaves a
//!   window during which the content is readable by anyone, and that window is
//!   exactly when the secret is on disk.
//!
//! # The defect this fixes
//!
//! Both configuration writers used a plain `std::fs::write` on the temporary
//! file, whose mode therefore came from the process umask — 0644 for a daemon
//! running as root with the usual umask 022. The `rename` then carried that
//! mode onto the final file, **silently undoing** the `chmod 600` that
//! `scripts/target-bootstrap.sh` had applied at install time. The gateway's
//! `network.toml` went world-readable at its first peer admission.
//!
//! It was not exploitable — the parent directory is 0700 and the persisted
//! content is redacted of every secret — but defence in depth is not supposed
//! to fall off on its own. See [ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md).
//!
//! # Limite connue : Windows
//!
//! The mode is a Unix notion. On Windows the file inherits the ACL of its
//! parent directory, which for `%APPDATA%` is already restricted to the user —
//! and that is precisely the protection ADR-006 judges insufficient. The answer
//! there is not a permission bit, it is encrypting the content, which is the
//! object of the vault lot. Nothing is faked here in the meantime.

use std::{fs, io::Write, path::Path};

/// Creates a directory meant to hold secrets, 0700 from creation.
///
/// Idempotent: an existing directory is left alone rather than widened, because
/// an operator may legitimately have tightened it further.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

/// Writes `bytes` to `path` atomically, private from creation.
///
/// `path` must be a file path whose parent directory already exists. The
/// temporary file is created next to it — on the same filesystem, which is what
/// makes the `rename` atomic.
///
/// # Why the temporary name is unique
///
/// A fixed `.tmp` name is shared by every writer of that path. Two concurrent
/// saves would then interleave into the same file and publish a mixture, and a
/// leftover from an interrupted write would have to be deleted first — a
/// delete-then-create window a local attacker can step into. A random suffix
/// with `create_new` removes both: each writer owns its temporary, and creation
/// fails rather than adopting a file it did not make.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // A symlink at the destination would send the `rename` — and the 0600 — to
    // a target we never inspected. `symlink_metadata` does not follow it.
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is a symbolic link — refusing to write", path.display()),
            ));
        }
    }

    let tmp = unique_temporary(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;

    // From here every exit path must remove the temporary: leaving one behind
    // would litter the directory with private files nobody reads.
    let written = (|| {
        file.write_all(bytes)?;
        // Durability before visibility: a `rename` that lands before the data
        // does would publish an empty configuration on power loss.
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    // The rename itself is a directory operation: without this, a power loss
    // can leave the directory entry pointing at neither name.
    sync_parent(path)
}

/// Builds a temporary path nobody else is using.
///
/// The randomness comes from the OS CSPRNG rather than a counter or a PID: two
/// processes started in the same second must not collide, and a predictable
/// name is exactly what lets someone else create the file first.
fn unique_temporary(path: &Path) -> std::io::Result<std::path::PathBuf> {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

    let mut suffix = [0u8; 8];
    SystemRandom::new().fill(&mut suffix).map_err(|_| {
        std::io::Error::other("system CSPRNG unavailable for the temporary file name")
    })?;
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no name"))?;
    let mut temporary = name.to_os_string();
    temporary.push(format!(".{suffix}.tmp"));
    Ok(path.with_file_name(temporary))
}

/// `fsync` on the directory holding `path`, so the rename itself is durable.
#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::File::open(parent)?.sync_all()
}

/// Directories are not opened for `fsync` on Windows; `rename` durability there
/// is the filesystem's business, not ours.
#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aether-private-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    #[test]
    fn the_content_survives_the_rename() {
        let dir = temp_dir("content");
        let path = dir.join("config.toml");
        write_private_atomic(&path, b"first").expect("first write");
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        // Unlike an exclusive creation, a configuration is rewritten: the
        // second write must replace the first rather than be refused.
        write_private_atomic(&path, b"second").expect("second write");
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_configuration_is_born_unreadable_by_others() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("mode");
        let path = dir.join("config.toml");
        write_private_atomic(&path, b"secret").expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtained: {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_rewrite_does_not_widen_the_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("rewrite");
        let path = dir.join("config.toml");
        write_private_atomic(&path, b"first").expect("first write");
        // This is the regression that motivated the module: the SECOND write
        // is the one that used to hand the file back to the umask.
        write_private_atomic(&path, b"second").expect("second write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtained after rewrite: {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A leftover temporary must not be adopted, whatever its mode.
    ///
    /// The unique name makes collision impossible in practice; this pins the
    /// property so that reverting to a fixed `.tmp` fails here rather than in
    /// production.
    #[cfg(unix)]
    #[test]
    fn a_leftover_temporary_is_never_adopted() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("leftover");
        let path = dir.join("config.toml");
        let stale = path.with_extension("toml.tmp");
        fs::write(&stale, b"stale").expect("stale temporary");
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).expect("widen");

        write_private_atomic(&path, b"fresh").expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtained: {mode:o}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Two writers must not share a temporary name, or they interleave into
    /// one file and publish a mixture of both.
    #[test]
    fn concurrent_writers_do_not_share_a_temporary() {
        let dir = temp_dir("concurrent");
        let path = dir.join("config.toml");
        let a = b"a".repeat(64 * 1024);
        let b = b"b".repeat(64 * 1024);

        std::thread::scope(|scope| {
            for payload in [&a, &b] {
                scope.spawn(|| {
                    for _ in 0..20 {
                        write_private_atomic(&path, payload).expect("write");
                    }
                });
            }
        });

        // Whoever won, the published file is one payload in full — never a
        // blend of the two.
        let published = fs::read(&path).expect("read");
        assert!(
            published == a || published == b,
            "published file is a mixture of two concurrent writes"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// No temporary may survive a successful write.
    #[test]
    fn no_temporary_is_left_behind() {
        let dir = temp_dir("cleanup");
        let path = dir.join("config.toml");
        write_private_atomic(&path, b"content").expect("write");

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporaries left behind: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A symlink at the destination would divert both the content and the
    /// 0600 to a target we never inspected.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_destination_is_refused() {
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere.toml");
        fs::write(&target, b"victim").expect("target");
        let path = dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");

        assert!(
            write_private_atomic(&path, b"payload").is_err(),
            "a symlinked destination must be refused"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "victim",
            "the symlink target was written through"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_private_directory_is_born_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("dir-mode");
        let nested = dir.join("secrets");
        create_private_dir(&nested).expect("create");
        let mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "mode obtained: {mode:o}");
        // Idempotent: a second call must not fail nor widen anything.
        create_private_dir(&nested).expect("second create");
        let _ = fs::remove_dir_all(&dir);
    }
}
