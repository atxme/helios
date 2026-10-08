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
