//! Deterministic archive of a bundle directory (spec F15 §5.6).
//!
//! Every option that depends on the host is removed from the tar invocation,
//! and the gzip header carries neither name nor timestamp, so the same bundle
//! contents always produce the same bytes.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// GNU tar arguments for a deterministic archive of `name`, a directory
/// relative to the tar working directory. Compression is delegated to
/// `gzip -n`: no name and no timestamp in the gzip header.
pub fn tar_args(archive: &Path, name: &str, mtime: u64) -> Vec<OsString> {
    vec![
        "--use-compress-program=gzip -n".into(),
        "--sort=name".into(),
        "--owner=0".into(),
        "--group=0".into(),
        "--numeric-owner".into(),
        format!("--mtime=@{mtime}").into(),
        "--format=gnu".into(),
        "-cf".into(),
        archive.as_os_str().to_owned(),
        "--".into(),
        name.into(),
    ]
}

/// Writes the archive of `parent/name` to `archive`, with every entry dated
/// `mtime`.
///
/// `tar` runs from `parent`, so the archive path is made absolute first: a
/// relative one would otherwise resolve against `parent`.
pub fn create(parent: &Path, name: &str, archive: &Path, mtime: u64) -> Result<()> {
    let archive = std::path::absolute(archive)
        .with_context(|| format!("resolving archive path {}", archive.display()))?;
    let status = Command::new("tar")
        .args(tar_args(&archive, name, mtime))
        .current_dir(parent)
        .status()
        .context("running tar (GNU tar with gzip is required)")?;
    if !status.success() {
        bail!(
            "archive {} not written: tar failed ({status}); GNU tar and gzip are required",
            archive.display()
        );
    }
    Ok(())
}

/// Entry date of the archive: `SOURCE_DATE_EPOCH` when it is set to a number,
/// 0 otherwise.
pub fn entry_mtime() -> u64 {
    entry_mtime_from(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
}

/// Pure form of [`entry_mtime`], for the value of `SOURCE_DATE_EPOCH`.
pub fn entry_mtime_from(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "xtask-archive-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create test directory");
            Self(path)
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

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn tar_args_fix_order_owner_and_dates() {
        let args = strings(&tar_args(
            Path::new("/out/helios-1.2.3.tar.gz"),
            "helios-1.2.3",
            1_700_000_000,
        ));
        for expected in [
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mtime=@1700000000",
            "--format=gnu",
            "--use-compress-program=gzip -n",
        ] {
            assert!(
                args.iter().any(|arg| arg == expected),
                "{expected} in {args:?}"
            );
        }
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-cf", "/out/helios-1.2.3.tar.gz"]));
        let tail = &args[args.len() - 2..];
        assert_eq!(tail, ["--", "helios-1.2.3"]);
    }

    #[cfg(unix)]
    #[test]
    fn same_directory_gives_the_same_archive() {
        use helios_update::sha256_file;

        let directory = TestDirectory::new("same");
        let parent = directory.path().join("first");
        let bundle = parent.join("helios-1.2.3-test");
        std::fs::create_dir_all(bundle.join("systemd")).expect("bundle directory");
        std::fs::write(bundle.join("heliosd"), b"binary").expect("binary");
        std::fs::write(bundle.join("manifest.json"), b"{}\n").expect("manifest");
        std::fs::write(bundle.join("systemd/heliosd.service"), b"[Unit]\n").expect("unit");

        let first = directory.path().join("first.tar.gz");
        create(&parent, "helios-1.2.3-test", &first, 0).expect("first archive");

        // Another date on every file, and the same tree copied elsewhere.
        let day = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86_400 * 3);
        for file in [
            bundle.join("heliosd"),
            bundle.join("manifest.json"),
            bundle.join("systemd/heliosd.service"),
        ] {
            std::fs::File::options()
                .write(true)
                .open(&file)
                .expect("open for touch")
                .set_modified(day)
                .expect("touch");
        }
        let copied = directory.path().join("second");
        let copy = copied.join("helios-1.2.3-test");
        std::fs::create_dir_all(copy.join("systemd")).expect("copied directory");
        for relative in ["heliosd", "manifest.json", "systemd/heliosd.service"] {
            std::fs::copy(bundle.join(relative), copy.join(relative)).expect("copy file");
        }

        let second = directory.path().join("second.tar.gz");
        create(&copied, "helios-1.2.3-test", &second, 0).expect("second archive");

        assert_eq!(
            sha256_file(&first).expect("first digest"),
            sha256_file(&second).expect("second digest")
        );
    }

    #[test]
    fn entry_mtime_reads_source_date_epoch() {
        assert_eq!(entry_mtime_from(Some("1700000000")), 1_700_000_000);
        assert_eq!(entry_mtime_from(Some(" 42 ")), 42);
        assert_eq!(entry_mtime_from(None), 0);
        assert_eq!(entry_mtime_from(Some("yesterday")), 0);
    }
}
