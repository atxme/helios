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

/// Writes `bytes` to `path` atomically, private from creation.
///
/// `path` must be a file path whose parent directory already exists. The
/// temporary file is created next to it — on the same filesystem, which is what
/// makes the `rename` atomic.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("toml.tmp");
    // A leftover temporary from an interrupted write would keep its old mode:
    // `mode()` only applies on creation. Removing it first is what guarantees
    // the 0600 below actually takes effect.
    let _ = fs::remove_file(&tmp);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    // Durability before visibility: a `rename` that lands before the data does
    // would publish an empty configuration on power loss.
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path)
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

    #[cfg(unix)]
    #[test]
    fn a_leftover_temporary_does_not_keep_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("leftover");
        let path = dir.join("config.toml");
        // Simulates an interrupted write that left a world-readable temporary
        // behind. `OpenOptions::mode` applies on creation only, so reusing that
        // file would carry the wide mode all the way to the final rename.
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, b"stale").expect("stale temporary");
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).expect("widen");

        write_private_atomic(&path, b"fresh").expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtained: {mode:o}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh");
        let _ = fs::remove_dir_all(&dir);
    }
}
