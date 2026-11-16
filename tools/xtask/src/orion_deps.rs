//! WireGuardNT dependency preparation shared by `xtask` and Orion's build.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{bail, Context, Result};

/// WireGuardNT binary version shipped with Orion.
pub const WIREGUARD_NT_VERSION: &str = "1.1";
/// Official archive, pinned: changing the version requires recomputing and
/// re-reading its content before updating this fingerprint.
pub const WIREGUARD_NT_URL: &str =
    "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip";
pub const WIREGUARD_NT_SHA256: &str =
    "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace";
pub const MAX_WIREGUARD_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;

/// Output names are imposed by `defguard_wireguard_rs 0.12`, not by the
/// Orion bundler. Its Windows backend opens them relative to the current
/// directory under `resources-windows/binaries/`.
pub const WIREGUARD_FILES: &[(&str, &str)] = &[
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

/// Downloads, verifies and extracts the WireGuardNT resources below `root`.
pub fn prepare(root: &Path) -> Result<()> {
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

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "helios-xtask-orion-deps-{}-{}",
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

    fn archive(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).expect("create archive fixture");
        let mut zip = zip::ZipWriter::new(file);
        for (name, contents) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start archive entry");
            zip.write_all(contents).expect("write archive entry");
        }
        zip.finish().expect("finish archive fixture");
    }

    fn required_entries() -> [(&'static str, &'static [u8]); 3] {
        [
            (WIREGUARD_FILES[0].0, b"amd64 dll"),
            (WIREGUARD_FILES[1].0, b"arm64 dll"),
            (WIREGUARD_FILES[2].0, b"license"),
        ]
    }

    #[test]
    fn extraction_writes_all_required_files_to_their_runtime_names() {
        let directory = TestDirectory::new();
        let archive_path = directory.path().join("wireguard.zip");
        archive(&archive_path, &required_entries());
        let destination = directory.path().join("resources-windows");

        extract_wireguard_files(&archive_path, &destination).expect("extract required files");

        for (index, (_, output)) in WIREGUARD_FILES.iter().enumerate() {
            assert_eq!(
                std::fs::read(destination.join(output)).expect("read extracted file"),
                required_entries()[index].1
            );
            assert!(!destination.join(output).with_extension("part").exists());
        }
    }

    #[test]
    fn extraction_replaces_existing_outputs() {
        let directory = TestDirectory::new();
        let archive_path = directory.path().join("wireguard.zip");
        archive(&archive_path, &required_entries());
        let destination = directory.path().join("resources-windows");
        let existing = destination.join(WIREGUARD_FILES[0].1);
        std::fs::create_dir_all(existing.parent().expect("output parent"))
            .expect("create output parent");
        std::fs::write(&existing, b"stale dll").expect("write old output");

        extract_wireguard_files(&archive_path, &destination).expect("replace old files");

        assert_eq!(
            std::fs::read(existing).expect("read replaced file"),
            b"amd64 dll"
        );
    }

    #[test]
    fn extraction_rejects_invalid_zip_and_missing_required_entry() {
        let directory = TestDirectory::new();
        let invalid = directory.path().join("invalid.zip");
        std::fs::write(&invalid, b"not a zip").expect("write invalid archive");
        let error = extract_wireguard_files(&invalid, &directory.path().join("invalid-out"))
            .expect_err("invalid archive rejected");
        assert!(format!("{error:#}").contains("reading archive"));

        let missing = directory.path().join("missing.zip");
        archive(&missing, &required_entries()[..2]);
        let error = extract_wireguard_files(&missing, &directory.path().join("missing-out"))
            .expect_err("missing license rejected");
        assert!(format!("{error:#}").contains(WIREGUARD_FILES[2].0));
    }

    #[test]
    fn digest_helpers_use_lowercase_hex_and_reject_missing_files() {
        assert_eq!(hex(&[0x00, 0x0a, 0xff]), "000aff");
        let directory = TestDirectory::new();
        let file = directory.path().join("payload");
        std::fs::write(&file, b"payload").expect("write payload");
        assert!(sha256_matches(
            &file,
            "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
        )
        .expect("hash payload"));
        assert!(!sha256_matches(&file, &"0".repeat(64)).expect("compare wrong hash"));
        assert!(sha256_matches(&directory.path().join("missing"), &"0".repeat(64)).is_err());
    }
}
