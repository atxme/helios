use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aether::sig::{
    BinaryReleasePayload, PublisherPublicKeys, PublisherSigner, ResealPayload,
    ED25519_PUBLIC_KEY_LEN, ML_DSA_65_PRIVATE_KEY_LEN, ML_DSA_65_PUBLIC_KEY_LEN,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "helios-publisher",
    about = "Outil hors gateway pour les clés et artefacts signés de l'éditeur"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Génère une nouvelle époque Ed25519 + ML-DSA-65 dans un répertoire neuf.
    Keygen {
        #[arg(long, value_parser = positive_u32)]
        key_epoch: u32,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Signe un billet de rescellement TPM v2 avec les deux algorithmes.
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
        /// Trousseau public qui sera compilé dans le firmware cible.
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Signe le manifeste d’un binaire heliosd déjà construit.
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
    /// Signe le contenu d’un bundle d’installation déjà assemblé.
    ///
    /// Écrit `manifest.json` à la racine du répertoire. Le manifeste énumère
    /// exhaustivement le contenu : un fichier ajouté ou modifié après coup fait
    /// échouer l’installation.
    Bundle {
        /// Répertoire assemblé par `cargo xtask bundle`.
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

/// Signe le contenu d’un répertoire de bundle.
///
/// Le binaire `heliosd` est revalidé comme ELF de la target déclarée avant
/// signature : signer un bundle dont l’exécutable ne correspond pas à sa cible
/// produirait un artefact authentique et pourtant ininstallable, découvert
/// seulement sur la gateway.
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
        bail!("version, commit et target doivent être renseignés");
    }
    let signer = load_signer(key_epoch, ed25519_path, ml_dsa_65_path, keyring_path)?;

    let heliosd = dir.join("heliosd");
    if !heliosd.is_file() {
        bail!(
            "{} absent : un bundle gateway contient toujours le daemon",
            heliosd.display()
        );
    }
    helios_update::verify_elf(&heliosd, &target)
        .with_context(|| format!("validation ELF de {}", heliosd.display()))?;

    let files = bundle::collect(dir).context("recensement du contenu du bundle")?;
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
        .map_err(|e| anyhow::anyhow!("contenu de bundle refusé : {e}"))?;

    let manifest = signer
        .sign(payload)
        .context("signature hybride du manifeste de bundle")?;
    let keyring = load_keyring(keyring_path)?;
    manifest
        .verify(&keyring)
        .context("auto-vérification du manifeste produit")?;

    let json = serde_json::to_vec_pretty(&manifest).context("sérialisation du manifeste")?;
    let output = dir.join(bundle::BUNDLE_MANIFEST_FILE);
    write_new(&output, &json, false)?;

    println!(
        "bundle {} séquence {}, {} fichier(s), écrit dans {}",
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
    let signer = PublisherSigner::generate(key_epoch).context("génération des clés éditeur")?;
    let (ed25519, ml_dsa_65) = signer
        .private_key_bytes()
        .context("sérialisation des clés privées")?;
    let public = signer.public_keys();

    write_new_secret(&output_dir.join("ed25519-private.pk8"), &ed25519)?;
    write_new_secret(&output_dir.join("ml-dsa-65-private.bin"), &ml_dsa_65)?;
    let keyring = vec![PublicKeyWire {
        key_epoch,
        ed25519: STANDARD.encode(public.ed25519),
        ml_dsa_65: STANDARD.encode(public.ml_dsa_65),
    }];
    let json = serde_json::to_vec_pretty(&keyring).context("sérialisation du trousseau")?;
    write_new(&output_dir.join("publisher-keyring.json"), &json, false)?;

    println!(
        "époque {key_epoch} générée dans {} ; conserver les deux fichiers privés hors ligne",
        output_dir.display()
    );
    println!(
        "compiler le firmware avec HELIOS_PUBLISHER_KEYRING_PATH={}",
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
        fs::read(ed25519_path).with_context(|| format!("lecture de {}", ed25519_path.display()))?;
    let ml_dsa_65 = fs::read(ml_dsa_65_path)
        .with_context(|| format!("lecture de {}", ml_dsa_65_path.display()))?;
    if ml_dsa_65.len() != ML_DSA_65_PRIVATE_KEY_LEN {
        bail!(
            "clé privée ML-DSA-65 : {} octets au lieu de {}",
            ml_dsa_65.len(),
            ML_DSA_65_PRIVATE_KEY_LEN
        );
    }
    let signer = PublisherSigner::from_private_keys(key_epoch, &ed25519, &ml_dsa_65)
        .context("chargement des clés privées éditeur")?;
    let keyring = load_keyring(keyring_path)?;
    let expected_keys = keyring
        .iter()
        .find(|keys| keys.key_epoch == key_epoch)
        .with_context(|| format!("époque {key_epoch} absente du trousseau public"))?;
    let actual_keys = signer.public_keys();
    if expected_keys.ed25519 != actual_keys.ed25519
        || expected_keys.ml_dsa_65 != actual_keys.ml_dsa_65
    {
        bail!("les clés privées ne correspondent pas à l'époque {key_epoch} du trousseau public");
    }

    let ticket = signer
        .sign(ResealPayload {
            version,
            expected_pcr_digest,
        })
        .context("signature hybride du billet")?;
    ticket
        .verify(&keyring)
        .context("auto-vérification du billet produit")?;
    let json = serde_json::to_vec_pretty(&ticket).context("sérialisation du billet")?;
    write_new(output, &json, true)?;
    println!(
        "billet v2 version {version}, époque {key_epoch}, écrit dans {}",
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
        bail!("version, commit et target doivent être renseignés");
    }
    if features.iter().any(|feature| feature.trim().is_empty()) {
        bail!("une feature vide est interdite");
    }
    features.sort();
    features.dedup();

    let signer = load_signer(key_epoch, ed25519_path, ml_dsa_65_path, keyring_path)?;
    let metadata = fs::metadata(binary)
        .with_context(|| format!("lecture des métadonnées de {}", binary.display()))?;
    if metadata.len() == 0 || metadata.len() > helios_update::MAX_BINARY_SIZE {
        bail!("taille du binaire hors limite : {} octets", metadata.len());
    }
    helios_update::verify_elf(binary, &target)
        .with_context(|| format!("validation ELF de {}", binary.display()))?;
    let sha256 = helios_update::sha256_file(binary)
        .with_context(|| format!("SHA-256 de {}", binary.display()))?;
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
        .context("signature hybride du manifeste binaire")?;
    let keyring = load_keyring(keyring_path)?;
    manifest
        .verify(&keyring)
        .context("auto-vérification du manifeste produit")?;
    let json = serde_json::to_vec_pretty(&manifest).context("sérialisation du manifeste")?;
    write_new(output, &json, true)?;
    println!(
        "release {} séquence {}, SHA-256 {}, écrite dans {}",
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
        fs::read(ed25519_path).with_context(|| format!("lecture de {}", ed25519_path.display()))?;
    let ml_dsa_65 = fs::read(ml_dsa_65_path)
        .with_context(|| format!("lecture de {}", ml_dsa_65_path.display()))?;
    if ml_dsa_65.len() != ML_DSA_65_PRIVATE_KEY_LEN {
        bail!(
            "clé privée ML-DSA-65 : {} octets au lieu de {}",
            ml_dsa_65.len(),
            ML_DSA_65_PRIVATE_KEY_LEN
        );
    }
    let signer = PublisherSigner::from_private_keys(key_epoch, &ed25519, &ml_dsa_65)
        .context("chargement des clés privées éditeur")?;
    let keyring = load_keyring(keyring_path)?;
    let expected_keys = keyring
        .iter()
        .find(|keys| keys.key_epoch == key_epoch)
        .with_context(|| format!("époque {key_epoch} absente du trousseau public"))?;
    let actual_keys = signer.public_keys();
    if expected_keys.ed25519 != actual_keys.ed25519
        || expected_keys.ml_dsa_65 != actual_keys.ml_dsa_65
    {
        bail!("les clés privées ne correspondent pas à l’époque {key_epoch} du trousseau public");
    }
    Ok(signer)
}

fn load_keyring(path: &Path) -> Result<Vec<PublisherPublicKeys>> {
    let bytes = fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    let wire: Vec<PublicKeyWire> =
        serde_json::from_slice(&bytes).context("trousseau public JSON invalide")?;
    if wire.is_empty() {
        bail!("le trousseau public est vide");
    }
    let mut epochs = HashSet::new();
    wire.into_iter()
        .map(|entry| {
            if !epochs.insert(entry.key_epoch) {
                bail!("époque {} dupliquée dans le trousseau", entry.key_epoch);
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
        .with_context(|| format!("clé publique {name} base64 invalide, époque {epoch}"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "clé publique {name} de {} octets au lieu de {N}, époque {epoch}",
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
            .with_context(|| format!("création du répertoire privé {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
            .with_context(|| format!("création du répertoire privé {}", path.display()))
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
        .with_context(|| format!("création exclusive de {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("écriture de {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("synchronisation de {}", path.display()))?;
    Ok(())
}

fn positive_u32(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|e| e.to_string())
        .and_then(|value| (value != 0).then_some(value).ok_or("doit être > 0".into()))
}

fn positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|e| e.to_string())
        .and_then(|value| (value != 0).then_some(value).ok_or("doit être > 0".into()))
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{} octets au lieu de 32", bytes.len()))
}

fn release_channel(value: &str) -> Result<String, String> {
    match value {
        "testing" | "production" => Ok(value.to_string()),
        _ => Err("canal attendu : testing ou production".into()),
    }
}
