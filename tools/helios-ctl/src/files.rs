//! Writes of sensitive files: exclusive, and private when required.
//!
//! Two properties are worth centralizing:
//!
//! * **exclusive creation** — overwriting an existing secret is irreversible,
//!   and the only moment the operator can notice is when it is refused;
//! * **restrictive permissions from creation** — a `chmod` applied after the
//!   fact leaves a window during which the secret is readable by anyone.
//!
//! The same reasoning applies in `helios-publisher`, which keeps its own
//! copies for the same reason: the two tools share no dependency.

use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result};

/// Creates a directory meant to hold secrets (0700 on Unix).
pub fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .with_context(|| format!("creating private directory {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
            .with_context(|| format!("creating private directory {}", path.display()))
    }
}

/// Writes a new file, refusing to overwrite an existing one.
///
/// `secret` restricts permissions to 0600 from creation on Unix.
pub fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "exclusive creation of {} — does a file with this name already exist?",
            path.display()
        )
    })?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-ctl-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = temp_dir("write-new");
        let path = dir.join("secret");
        write_new(&path, b"first", true).expect("first write");
        assert!(
            write_new(&path, b"second", true).is_err(),
            "an existing secret must never be overwritten"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_is_born_unreadable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let path = dir.join("secret");
        write_new(&path, b"content", true).expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtained: {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
