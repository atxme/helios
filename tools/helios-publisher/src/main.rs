use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aether::sig::{
    BinaryReleasePayload, FirmwareRecoveryPayload, PublisherPublicKeys, PublisherSigner,
    ResealPayload, ED25519_PUBLIC_KEY_LEN, ML_DSA_65_PRIVATE_KEY_LEN, ML_DSA_65_PUBLIC_KEY_LEN,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "helios-publisher",
    about = "Off-gateway tool for the publisher's signed keys and artifacts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates a new Ed25519 + ML-DSA-65 epoch in a fresh directory.
    Keygen {
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Signs restoration of a prepared firmware backup, off the gateway.
    FirmwareRecovery {
        #[arg(long)]
        request: PathBuf,
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long)]
        ed25519_private_key: PathBuf,
        #[arg(long)]
        ml_dsa_65_private_key: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Signs a TPM v2 resealing ticket with both algorithms.
    ResealTicket {
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long, value_parser = positive_u64)]
        version: u64,
        #[arg(long, value_parser = parse_digest)]
        expected_pcr_digest: Option<[u8; 32]>,
        #[arg(long)]
        ed25519_private_key: PathBuf,
        #[arg(long)]
        ml_dsa_65_private_key: PathBuf,
        /// Public keyring that will be compiled into the target firmware.
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Signs the manifest of an already-built heliosd binary.
    BinaryRelease {
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long, value_parser = positive_u64)]
        release_sequence: u64,
        #[arg(long, value_parser = release_channel)]
        channel: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        git_commit: String,
        #[arg(long)]
        target: String,
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        ed25519_private_key: PathBuf,
        #[arg(long)]
        ml_dsa_65_private_key: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Signs the content of an already-assembled installation bundle.
    ///
    /// Writes `manifest.json` at the root of the directory. The manifest
    /// exhaustively enumerates the content: a file added or modified
    /// afterward makes the installation fail.
    Bundle {
        /// Directory assembled by `cargo xtask bundle`.
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long, value_parser = positive_u64)]
        release_sequence: u64,
        #[arg(long, value_parser = release_channel)]
        channel: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        git_commit: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        ed25519_private_key: PathBuf,
        #[arg(long)]
        ml_dsa_65_private_key: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyWire {
    key_epoch: u32,
    ed25519: String,
    #[serde(rename = "ml-dsa-65")]
    ml_dsa_65: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            key_epoch,
            output_dir,
        } => keygen(key_epoch, &output_dir),
        Command::FirmwareRecovery {
            request,
            key_epoch,
            ed25519_private_key,
            ml_dsa_65_private_key,
            keyring,
            output,
        } => {
            let payload: FirmwareRecoveryPayload = serde_json::from_slice(&fs::read(&request)?)
                .context("invalid firmware recovery request")?;
            payload.validate().map_err(anyhow::Error::msg)?;
            let signer = load_signer(
                key_epoch,
                &ed25519_private_key,
                &ml_dsa_65_private_key,
                &keyring,
            )?;
            let signed = signer.sign(payload)?;
            signed.verify(&load_keyring(&keyring)?)?;
            write_new(&output, &serde_json::to_vec_pretty(&signed)?, true)?;
            println!(
                "Firmware recovery authorization written to {}",
                output.display()
            );
            Ok(())
        }
        Command::ResealTicket {
            key_epoch,
            version,
            expected_pcr_digest,
            ed25519_private_key,
            ml_dsa_65_private_key,
            keyring,
            output,
        } => sign_reseal_ticket(
            key_epoch,
            version,
            expected_pcr_digest,
            &ed25519_private_key,
            &ml_dsa_65_private_key,
            &keyring,
            &output,
        ),
        Command::BinaryRelease {
            key_epoch,
            release_sequence,
            channel,
            version,
            git_commit,
            target,
            features,
            binary,
            ed25519_private_key,
            ml_dsa_65_private_key,
            keyring,
            output,
        } => sign_binary_release(
            key_epoch,
            release_sequence,
            channel,
            version,
            git_commit,
            target,
            features,
            &binary,
            &ed25519_private_key,
            &ml_dsa_65_private_key,
            &keyring,
            &output,
        ),
        Command::Bundle {
            dir,
            key_epoch,
            release_sequence,
            channel,
            version,
            git_commit,
            target,
            ed25519_private_key,
            ml_dsa_65_private_key,
            keyring,
        } => sign_bundle(
            &dir,
            key_epoch,
            release_sequence,
            channel,
            version,
            git_commit,
            target,
            &ed25519_private_key,
            &ml_dsa_65_private_key,
            &keyring,
        ),
    }
}

/// Signs the content of a bundle directory.
///
/// The `heliosd` binary is revalidated as an ELF for the declared target
/// before signing: signing a bundle whose executable does not match its
/// target would produce an authentic yet uninstallable artifact, discovered
/// only on the gateway.
#[allow(clippy::too_many_arguments)]
fn sign_bundle(
    dir: &Path,
    key_epoch: u32,
    release_sequence: u64,
    channel: String,
    version: String,
    git_commit: String,
    target: String,
    ed25519_path: &Path,
    ml_dsa_65_path: &Path,
    keyring_path: &Path,
) -> Result<()> {
    use helios_update::bundle;

    if version.trim().is_empty() || git_commit.trim().is_empty() || target.trim().is_empty() {
        bail!("version, commit, and target must be provided");
    }
    let signer = load_signer(key_epoch, ed25519_path, ml_dsa_65_path, keyring_path)?;

    let heliosd = dir.join("heliosd");
    if !heliosd.is_file() {
        bail!(
            "{} missing: a gateway bundle always contains the daemon",
            heliosd.display()
        );
    }
    helios_update::verify_elf(&heliosd, &target)
        .with_context(|| format!("ELF validation of {}", heliosd.display()))?;

    let files = bundle::collect(dir).context("listing the bundle's content")?;
    let payload = aether::sig::BundlePayload {
        product: bundle::BUNDLE_PRODUCT.to_string(),
        channel,
        release_sequence,
        version,
        git_commit,
        target,
        minimum_installer_version: helios_update::INSTALLER_VERSION,
        files,
    };
    payload
        .validate()
        .map_err(|e| anyhow::anyhow!("bundle content rejected: {e}"))?;

    let manifest = signer
        .sign(payload)
        .context("hybrid signature of the bundle manifest")?;
    let keyring = load_keyring(keyring_path)?;
    manifest
        .verify(&keyring)
        .context("self-verification of the produced manifest")?;

    let json = serde_json::to_vec_pretty(&manifest).context("serializing the manifest")?;
    let output = dir.join(bundle::BUNDLE_MANIFEST_FILE);
    write_new(&output, &json, false)?;

    println!(
        "bundle {} sequence {}, {} file(s), written to {}",
        manifest.payload.version,
        release_sequence,
        manifest.payload.files.len(),
        output.display()
    );
    for entry in &manifest.payload.files {
        println!("  {} {}", hex::encode(entry.sha256), entry.path);
    }
    Ok(())
}

fn keygen(key_epoch: u32, output_dir: &Path) -> Result<()> {
    create_private_dir(output_dir)?;
    let signer = PublisherSigner::generate(key_epoch).context("generating publisher keys")?;
    let (ed25519, ml_dsa_65) = signer
        .private_key_bytes()
        .context("serializing private keys")?;
    let public = signer.public_keys();

    write_new_secret(&output_dir.join("ed25519-private.pk8"), &ed25519)?;
    write_new_secret(&output_dir.join("ml-dsa-65-private.bin"), &ml_dsa_65)?;
    let keyring = vec![PublicKeyWire {
        key_epoch,
        ed25519: STANDARD.encode(public.ed25519),
        ml_dsa_65: STANDARD.encode(public.ml_dsa_65),
    }];
    let json = serde_json::to_vec_pretty(&keyring).context("serializing the keyring")?;
    write_new(&output_dir.join("publisher-keyring.json"), &json, false)?;

    println!(
        "epoch {key_epoch} generated in {}; keep both private files offline",
        output_dir.display()
    );
    println!(
        "build the firmware with HELIOS_PUBLISHER_KEYRING_PATH={}",
        output_dir.join("publisher-keyring.json").display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_reseal_ticket(
    key_epoch: u32,
    version: u64,
    expected_pcr_digest: Option<[u8; 32]>,
    ed25519_path: &Path,
    ml_dsa_65_path: &Path,
    keyring_path: &Path,
    output: &Path,
) -> Result<()> {
    let ed25519 =
        fs::read(ed25519_path).with_context(|| format!("reading {}", ed25519_path.display()))?;
    let ml_dsa_65 = fs::read(ml_dsa_65_path)
        .with_context(|| format!("reading {}", ml_dsa_65_path.display()))?;
    if ml_dsa_65.len() != ML_DSA_65_PRIVATE_KEY_LEN {
        bail!(
            "ML-DSA-65 private key: {} bytes instead of {}",
            ml_dsa_65.len(),
            ML_DSA_65_PRIVATE_KEY_LEN
        );
    }
    let signer = PublisherSigner::from_private_keys(key_epoch, &ed25519, &ml_dsa_65)
        .context("loading publisher private keys")?;
    let keyring = load_keyring(keyring_path)?;
    let expected_keys = keyring
        .iter()
        .find(|keys| keys.key_epoch == key_epoch)
        .with_context(|| format!("epoch {key_epoch} missing from the public keyring"))?;
    let actual_keys = signer.public_keys();
    if expected_keys.ed25519 != actual_keys.ed25519
        || expected_keys.ml_dsa_65 != actual_keys.ml_dsa_65
    {
        bail!("private keys do not match epoch {key_epoch} of the public keyring");
    }

    let ticket = signer
        .sign(ResealPayload {
            version,
            expected_pcr_digest,
        })
        .context("hybrid signature of the ticket")?;
    ticket
        .verify(&keyring)
        .context("self-verification of the produced ticket")?;
    let json = serde_json::to_vec_pretty(&ticket).context("serializing the ticket")?;
    write_new(output, &json, true)?;
    println!(
        "v2 ticket version {version}, epoch {key_epoch}, written to {}",
        output.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_binary_release(
    key_epoch: u32,
    release_sequence: u64,
    channel: String,
    version: String,
    git_commit: String,
    target: String,
    mut features: Vec<String>,
    binary: &Path,
    ed25519_path: &Path,
    ml_dsa_65_path: &Path,
    keyring_path: &Path,
    output: &Path,
) -> Result<()> {
    if version.trim().is_empty() || git_commit.trim().is_empty() || target.trim().is_empty() {
        bail!("version, commit, and target must be provided");
    }
    if features.iter().any(|feature| feature.trim().is_empty()) {
        bail!("an empty feature is not allowed");
    }
    features.sort();
    features.dedup();

    let signer = load_signer(key_epoch, ed25519_path, ml_dsa_65_path, keyring_path)?;
    let metadata = fs::metadata(binary)
        .with_context(|| format!("reading metadata of {}", binary.display()))?;
    // The bound is named in the message on purpose: the ordinary cause is
    // signing an unstripped debug build, where 80 % of the bytes are debug
    // information no shipped artifact carries. Without the figure, the reflex
    // is to raise the bound — which protects the update path, and is the one
    // thing that must not move.
    if metadata.len() == 0 || metadata.len() > helios_update::MAX_BINARY_SIZE {
        bail!(
            "binary size out of bounds: {} bytes for a maximum of {} — is this an unstripped \
             debug build?",
            metadata.len(),
            helios_update::MAX_BINARY_SIZE
        );
    }
    helios_update::verify_elf(binary, &target)
        .with_context(|| format!("ELF validation of {}", binary.display()))?;
    let sha256 = helios_update::sha256_file(binary)
        .with_context(|| format!("SHA-256 of {}", binary.display()))?;
    let manifest = signer
        .sign(BinaryReleasePayload {
            product: "heliosd".into(),
            channel,
            release_sequence,
            version,
            git_commit,
            target,
            features,
            binary_size: metadata.len(),
            sha256,
            minimum_installer_version: helios_update::INSTALLER_VERSION,
        })
        .context("hybrid signature of the binary manifest")?;
    let keyring = load_keyring(keyring_path)?;
    manifest
        .verify(&keyring)
        .context("self-verification of the produced manifest")?;
    let json = serde_json::to_vec_pretty(&manifest).context("serializing the manifest")?;
    write_new(output, &json, true)?;
    println!(
        "release {} sequence {}, SHA-256 {}, written to {}",
        manifest.payload.version,
        release_sequence,
        hex::encode(manifest.payload.sha256),
        output.display()
    );
    Ok(())
}

fn load_signer(
    key_epoch: u32,
    ed25519_path: &Path,
    ml_dsa_65_path: &Path,
    keyring_path: &Path,
) -> Result<PublisherSigner> {
    let ed25519 =
        fs::read(ed25519_path).with_context(|| format!("reading {}", ed25519_path.display()))?;
    let ml_dsa_65 = fs::read(ml_dsa_65_path)
        .with_context(|| format!("reading {}", ml_dsa_65_path.display()))?;
    if ml_dsa_65.len() != ML_DSA_65_PRIVATE_KEY_LEN {
        bail!(
            "ML-DSA-65 private key: {} bytes instead of {}",
            ml_dsa_65.len(),
            ML_DSA_65_PRIVATE_KEY_LEN
        );
    }
    let signer = PublisherSigner::from_private_keys(key_epoch, &ed25519, &ml_dsa_65)
        .context("loading publisher private keys")?;
    let keyring = load_keyring(keyring_path)?;
    let expected_keys = keyring
        .iter()
        .find(|keys| keys.key_epoch == key_epoch)
        .with_context(|| format!("epoch {key_epoch} missing from the public keyring"))?;
    let actual_keys = signer.public_keys();
    if expected_keys.ed25519 != actual_keys.ed25519
        || expected_keys.ml_dsa_65 != actual_keys.ml_dsa_65
    {
        bail!("private keys do not match epoch {key_epoch} of the public keyring");
    }
    Ok(signer)
}

fn load_keyring(path: &Path) -> Result<Vec<PublisherPublicKeys>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let wire: Vec<PublicKeyWire> =
        serde_json::from_slice(&bytes).context("invalid public keyring JSON")?;
    if wire.is_empty() {
        bail!("the public keyring is empty");
    }
    let mut epochs = HashSet::new();
    wire.into_iter()
        .map(|entry| {
            if !epochs.insert(entry.key_epoch) {
                bail!("epoch {} duplicated in the keyring", entry.key_epoch);
            }
            let ed25519 = decode_public_key::<ED25519_PUBLIC_KEY_LEN>(
                &entry.ed25519,
                "Ed25519",
                entry.key_epoch,
            )?;
            let ml_dsa_65 = decode_public_key::<ML_DSA_65_PUBLIC_KEY_LEN>(
                &entry.ml_dsa_65,
                "ML-DSA-65",
                entry.key_epoch,
            )?;
            Ok(PublisherPublicKeys {
                key_epoch: entry.key_epoch,
                ed25519,
                ml_dsa_65,
            })
        })
        .collect()
}

fn decode_public_key<const N: usize>(encoded: &str, name: &str, epoch: u32) -> Result<[u8; N]> {
    STANDARD
        .decode(encoded)
        .with_context(|| format!("invalid base64 {name} public key, epoch {epoch}"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "{name} public key of {} bytes instead of {N}, epoch {epoch}",
                bytes.len()
            )
        })
}

fn create_private_dir(path: &Path) -> Result<()> {
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

fn write_new_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    write_new(path, bytes, true)
}

fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("exclusive creation of {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

fn positive_u32(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|e| e.to_string())
        .and_then(|value| (value != 0).then_some(value).ok_or("must be > 0".into()))
}

fn positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|e| e.to_string())
        .and_then(|value| (value != 0).then_some(value).ok_or("must be > 0".into()))
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{} bytes instead of 32", bytes.len()))
}

fn release_channel(value: &str) -> Result<String, String> {
    match value {
        "testing" | "production" => Ok(value.to_string()),
        _ => Err("expected channel: testing or production".into()),
    }
}
