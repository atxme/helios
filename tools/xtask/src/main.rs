//! Fabrique de bundles d'installation Helios.
//!
//! Jusqu'ici, installer une gateway voulait dire y copier le dépôt et l'y
//! compiler : `scripts/setup-target.sh` installait `cargo` et `npm` sur
//! l'appliance. C'est ce que cet outil remplace (ADR-004) — la cible ne reçoit
//! plus que des binaires et un manifeste signé.
//!
//! # Trois étapes, et pourquoi elles sont séparées
//!
//! ```sh
//! cargo xtask bundle                       # construit et assemble
//! helios-publisher bundle --dir …          # signe, sur le poste éditeur
//! cargo xtask pack --dir …                 # archive
//! ```
//!
//! La signature s'intercale parce qu'elle n'a pas lieu ici : les clés privées
//! de l'éditeur ne doivent entrer ni dans une CI, ni dans un dépôt (ADR-004
//! §7). `pack` refuse un répertoire sans manifeste : un bundle non signé ne
//! peut donc pas partir par distraction.

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

/// Features de la gateway livrée. Un bundle de production les porte toutes :
/// un `heliosd` sans `netlink` ni `wireguard` refuserait de démarrer sur une
/// vraie cible, et le découvrir là-bas coûte un déplacement.
const GATEWAY_FEATURES: &str = "netlink,wireguard,tpm,embed-ui";

/// Unités systemd livrées avec la gateway.
const SYSTEMD_UNITS: &[&str] = &[
    "heliosd.service",
    "helios-update.service",
    "helios-update.path",
];

/// Binaires livrés, et leur rôle.
const BINARIES: &[&str] = &["heliosd", "helios-installer", "helios-ctl"];

/// Version binaire de WireGuardNT livrée avec Orion.
const WIREGUARD_NT_VERSION: &str = "1.1";
/// Archive officielle, figée : changer la version exige de recalculer et de
/// relire son contenu avant de modifier cette empreinte.
const WIREGUARD_NT_URL: &str = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip";
const WIREGUARD_NT_SHA256: &str =
    "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace";
const MAX_WIREGUARD_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;

/// Les noms de sortie sont imposés par `defguard_wireguard_rs 0.11.0`, pas par
/// le bundler Orion. Son backend Windows les ouvre relativement au répertoire
/// courant sous `resources-windows/binaries/`.
const WIREGUARD_FILES: &[(&str, &str)] = &[
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

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Fabrique de bundles d'installation Helios (poste de build, jamais la gateway)"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Télécharge et vérifie les DLL WireGuardNT nécessaires au bundle Orion.
    OrionDeps,
    /// Construit les binaires et assemble le répertoire du bundle.
    Bundle {
        /// Triplet cible. Défaut : l'hôte.
        #[arg(long)]
        target: Option<String>,
        /// Ne reconstruit pas le frontend embarqué (itération locale).
        #[arg(long)]
        skip_frontend: bool,
        /// Répertoire de sortie. Défaut : `target/bundle/<nom>`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Archive un bundle **signé**.
    Pack {
        /// Répertoire produit par `bundle`, contenant `manifest.json`.
        #[arg(long)]
        dir: PathBuf,
        /// Archive à produire. Défaut : `<dir>.tar.gz`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::OrionDeps => orion_deps(),
        Cmd::Bundle {
            target,
            skip_frontend,
            output,
        } => bundle(target, skip_frontend, output),
        Cmd::Pack { dir, output } => pack(&dir, output),
    }
}

fn orion_deps() -> Result<()> {
    let root = workspace_root()?;
    let cache_dir = root.join("target").join("orion-deps");
    let archive = cache_dir.join(format!("wireguard-nt-{WIREGUARD_NT_VERSION}.zip"));
    let part = archive.with_extension("zip.part");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("création de {}", cache_dir.display()))?;

    let archive_is_valid = archive.is_file() && sha256_matches(&archive, WIREGUARD_NT_SHA256)?;
    if archive_is_valid {
        println!("==> WireGuardNT {WIREGUARD_NT_VERSION} : archive en cache vérifiée");
    } else {
        if archive.exists() {
            std::fs::remove_file(&archive).with_context(|| {
                format!("suppression de l'archive invalide {}", archive.display())
            })?;
        }
        if part.exists() {
            std::fs::remove_file(&part).with_context(|| {
                format!("suppression du téléchargement incomplet {}", part.display())
            })?;
        }
        println!("==> WireGuardNT {WIREGUARD_NT_VERSION} : téléchargement officiel");
        download_bounded(WIREGUARD_NT_URL, &part, MAX_WIREGUARD_ARCHIVE_BYTES)?;
        if !sha256_matches(&part, WIREGUARD_NT_SHA256)? {
            let actual = hex(&helios_update::sha256_file(&part)
                .map_err(|e| anyhow::anyhow!("empreinte de {} : {e}", part.display()))?);
            std::fs::remove_file(&part).ok();
            bail!("archive WireGuardNT refusée : SHA-256 {actual}, attendu {WIREGUARD_NT_SHA256}");
        }
        std::fs::rename(&part, &archive)
            .with_context(|| format!("validation de {}", archive.display()))?;
    }

    let destination = root.join("resources-windows");
    extract_wireguard_files(&archive, &destination)?;
    println!(
        "==> Dépendances Orion prêtes dans {} (hors Git)",
        destination.display()
    );
    Ok(())
}

fn download_bounded(url: &str, destination: &Path, maximum: u64) -> Result<()> {
    let mut response = reqwest::blocking::Client::builder()
        .user_agent("Helios-xtask/orion-deps")
        .build()
        .context("création du client HTTPS")?
        .get(url)
        .send()
        .with_context(|| format!("téléchargement de {url}"))?
        .error_for_status()
        .with_context(|| format!("réponse HTTP de {url}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum)
    {
        bail!("archive WireGuardNT trop volumineuse (maximum {maximum} octets)");
    }

    let mut file = File::create(destination)
        .with_context(|| format!("création de {}", destination.display()))?;
    let copied = std::io::copy(&mut response.by_ref().take(maximum + 1), &mut file)
        .with_context(|| format!("écriture de {}", destination.display()))?;
    file.flush()
        .with_context(|| format!("finalisation de {}", destination.display()))?;
    if copied > maximum {
        std::fs::remove_file(destination).ok();
        bail!("archive WireGuardNT trop volumineuse (maximum {maximum} octets)");
    }
    Ok(())
}

fn sha256_matches(path: &Path, expected: &str) -> Result<bool> {
    let digest = helios_update::sha256_file(path)
        .map_err(|e| anyhow::anyhow!("empreinte de {} : {e}", path.display()))?;
    Ok(hex(&digest) == expected)
}

fn extract_wireguard_files(archive: &Path, destination: &Path) -> Result<()> {
    let file =
        File::open(archive).with_context(|| format!("ouverture de {}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(file)
        .with_context(|| format!("lecture de l'archive {}", archive.display()))?;

    for (source, relative_destination) in WIREGUARD_FILES {
        let mut entry = zip
            .by_name(source)
            .with_context(|| format!("entrée {source} absente de l'archive WireGuardNT"))?;
        if entry.is_dir() {
            bail!("entrée WireGuardNT inattendue : {source} est un répertoire");
        }
        let output = destination.join(relative_destination);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let temporary = output.with_extension("part");
        let mut target = File::create(&temporary)
            .with_context(|| format!("création de {}", temporary.display()))?;
        std::io::copy(&mut entry, &mut target)
            .with_context(|| format!("extraction de {source}"))?;
        target
            .flush()
            .with_context(|| format!("finalisation de {}", temporary.display()))?;
        // `rename` ne remplace pas une destination existante sous Windows. La
        // commande est rejouée avant chaque bundle : retirer uniquement ce
        // fichier généré garantit que la nouvelle extraction l'emporte.
        if output.exists() {
            std::fs::remove_file(&output)
                .with_context(|| format!("remplacement de {}", output.display()))?;
        }
        std::fs::rename(&temporary, &output)
            .with_context(|| format!("validation de {}", output.display()))?;
        println!("  {}", output.display());
    }
    Ok(())
}

fn bundle(target: Option<String>, skip_frontend: bool, output: Option<PathBuf>) -> Result<()> {
    let root = workspace_root()?;
    let target = match target {
        Some(target) => target,
        None => host_target()?,
    };
    let version = workspace_version(&root)?;

    // Le trousseau public de l'éditeur est exigé par le build release de
    // `heliosd`. Le vérifier ici évite d'attendre plusieurs minutes de
    // compilation pour apprendre qu'il manquait.
    let keyring = std::env::var("HELIOS_PUBLISHER_KEYRING_PATH").map_err(|_| {
        anyhow::anyhow!(
            "HELIOS_PUBLISHER_KEYRING_PATH doit désigner le trousseau public de l'éditeur : \
             un bundle construit sans ancre de confiance ne peut vérifier aucune mise à jour"
        )
    })?;
    if !Path::new(&keyring).is_file() {
        bail!("trousseau public introuvable : {keyring}");
    }

    if skip_frontend {
        println!("==> Frontend : réutilisé tel quel (--skip-frontend)");
    } else {
        println!("==> Frontend embarqué");
        run(&root, "npm", &["ci", "--prefix", "web"])?;
        run(&root, "npm", &["run", "build", "--prefix", "web"])?;
    }

    println!("==> heliosd ({GATEWAY_FEATURES})");
    run(
        &root,
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            &target,
            "-p",
            "heliosd",
            "--features",
            GATEWAY_FEATURES,
        ],
    )?;

    println!("==> helios-installer, helios-ctl");
    run(
        &root,
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            &target,
            "-p",
            "helios-installer",
            "-p",
            "helios-ctl",
        ],
    )?;

    let name = format!("helios-{version}-{target}");
    let staging = output.unwrap_or_else(|| root.join("target").join("bundle").join(&name));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("nettoyage de {}", staging.display()))?;
    }
    std::fs::create_dir_all(staging.join("systemd"))
        .with_context(|| format!("création de {}", staging.display()))?;

    let built = root.join("target").join(&target).join("release");
    for binary in BINARIES {
        copy_executable(&built.join(binary), &staging.join(binary))?;
    }
    for unit in SYSTEMD_UNITS {
        copy_data(
            &root.join("deploy").join("systemd").join(unit),
            &staging.join("systemd").join(unit),
        )?;
    }
    copy_data(
        &root.join("config").join("network.toml"),
        &staging.join("network.toml.example"),
    )?;

    let files = helios_update::bundle::collect(&staging)
        .map_err(|e| anyhow::anyhow!("recensement du bundle : {e}"))?;

    println!("\n==> Bundle assemblé dans {}", staging.display());
    for entry in &files {
        println!("  {:>10}  {}", entry.size, entry.path);
    }
    println!("\nSigner sur le poste éditeur, puis archiver :");
    println!(
        "  helios-publisher bundle --dir {} \\\n    --key-epoch <N> --release-sequence <N> \\\n    \
         --channel <testing|production> --version {version} \\\n    --git-commit $(git rev-parse \
         --short=16 HEAD) --target {target} \\\n    --ed25519-private-key <…> \
         --ml-dsa-65-private-key <…> --keyring {keyring}",
        staging.display()
    );
    println!("  cargo xtask pack --dir {}", staging.display());
    Ok(())
}

fn pack(dir: &Path, output: Option<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} n'est pas un répertoire de bundle", dir.display());
    }

    // Un bundle non signé ne doit pas pouvoir partir : sans manifeste, la
    // cible n'aurait rien à vérifier et l'installation se ferait à l'aveugle.
    let manifest = helios_update::bundle::read_manifest(dir)
        .map_err(|e| anyhow::anyhow!("{e}\nSigner le bundle avant de l'archiver."))?;
    helios_update::bundle::verify_contents(dir, &manifest.payload)
        .map_err(|e| anyhow::anyhow!("le contenu ne correspond plus au manifeste signé : {e}"))?;

    // `canonicalize` avant tout : `tar` est lancé depuis le répertoire parent,
    // et un chemin relatif y désignerait autre chose que dans le répertoire
    // courant de l'appelant.
    let dir = dir
        .canonicalize()
        .with_context(|| format!("résolution de {}", dir.display()))?;
    let archive = match output {
        Some(output) => output,
        None => archive_path(&dir)?,
    };
    let parent = dir
        .parent()
        .context("répertoire de bundle sans parent")?
        .to_path_buf();
    let name = dir
        .file_name()
        .context("répertoire de bundle sans nom")?
        .to_string_lossy()
        .to_string();

    run(
        &parent,
        "tar",
        &["-czf", &archive.to_string_lossy(), "--", &name],
    )?;

    let digest = helios_update::sha256_file(&archive)
        .map_err(|e| anyhow::anyhow!("empreinte de l'archive : {e}"))?;
    println!("{} {}", hex(&digest), archive.display());
    println!(
        "\n  Bundle {} séquence {}, canal {}, {} fichier(s).",
        manifest.payload.version,
        manifest.payload.release_sequence,
        manifest.payload.channel,
        manifest.payload.files.len()
    );
    println!("  Publier cette empreinte avec l'archive : c'est elle que l'opérateur");
    println!("  compare avant le tout premier `helios-installer bootstrap`.");
    Ok(())
}

/// Nom de l'archive d'un répertoire de bundle.
///
/// L'extension est **ajoutée**, jamais substituée : le nom d'un bundle contient
/// des points (`helios-0.1.0-x86_64-…`), et remplacer l'extension en amputerait
/// la version.
fn archive_path(dir: &Path) -> Result<PathBuf> {
    let name = dir
        .file_name()
        .context("répertoire de bundle sans nom")?
        .to_string_lossy()
        .to_string();
    Ok(dir.with_file_name(format!("{name}.tar.gz")))
}

fn copy_executable(from: &Path, to: &Path) -> Result<()> {
    copy_data(from, to)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("droits d'exécution sur {}", to.display()))?;
    }
    Ok(())
}

fn copy_data(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to)
        .with_context(|| format!("copie de {} vers {}", from.display(), to.display()))?;
    // Les droits sont fixés explicitement : ceux du fichier source dépendent du
    // umask de la machine de build, et se retrouveraient dans le manifeste
    // signé — deux builds identiques produiraient alors des manifestes
    // différents.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("droits sur {}", to.display()))?;
    }
    Ok(())
}

fn run(dir: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("exécution de {program}"))?;
    if !status.success() {
        bail!("{program} {} a échoué ({status})", args.join(" "));
    }
    Ok(())
}

fn output_of(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("exécution de {program}"))?;
    if !output.status.success() {
        bail!("{program} a échoué ({})", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Triplet de l'hôte, lu de `rustc` plutôt que deviné.
fn host_target() -> Result<String> {
    let verbose = output_of("rustc", &["-vV"])?;
    verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_string())
        .context("`rustc -vV` n'a pas annoncé de triplet hôte")
}

fn workspace_root() -> Result<PathBuf> {
    // `CARGO_MANIFEST_DIR` pointe sur `tools/xtask` : la racine est deux
    // niveaux au-dessus. Le déduire évite d'exiger d'être lancé d'un
    // répertoire précis.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("racine du workspace introuvable")
}

fn workspace_version(root: &Path) -> Result<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("lecture du Cargo.toml du workspace")?;
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace.package]")
        .find_map(|line| line.trim().strip_prefix("version = "))
        .map(|value| value.trim().trim_matches('"').to_string())
        .context("version absente de [workspace.package]")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_version_vient_du_workspace() {
        let root = workspace_root().expect("racine");
        let version = workspace_version(&root).expect("version");
        assert!(
            version.split('.').count() == 3,
            "version inattendue : {version}"
        );
    }

    /// La cible se lit de `rustc`, jamais d'une constante : un bundle étiqueté
    /// pour un triplet qui n'est pas celui du binaire serait refusé à
    /// l'installation, après le transfert.
    #[test]
    fn le_triplet_hote_est_celui_de_rustc() {
        let host = host_target().expect("triplet hôte");
        assert!(host.contains('-'), "triplet inattendu : {host}");
        assert_eq!(host, helios_update::BUILD_TARGET);
    }

    /// Le nom d'un bundle contient la version, donc des points : substituer
    /// l'extension au lieu de l'ajouter produisait `helios-0.1.tar.gz`.
    #[test]
    fn le_nom_d_archive_conserve_la_version_complete() {
        let archive = archive_path(Path::new(
            "/tmp/bundle/helios-0.1.0-x86_64-unknown-linux-gnu",
        ))
        .expect("nom d'archive");
        assert_eq!(
            archive,
            Path::new("/tmp/bundle/helios-0.1.0-x86_64-unknown-linux-gnu.tar.gz")
        );
    }

    /// Le bundle doit porter tout ce dont une gateway a besoin. Une omission ne
    /// se verrait qu'à l'installation, sur la cible.
    #[test]
    fn le_contenu_livre_est_complet() {
        assert!(BINARIES.contains(&"heliosd"));
        assert!(BINARIES.contains(&"helios-installer"));
        assert_eq!(SYSTEMD_UNITS.len(), 3);
        for feature in ["netlink", "wireguard", "tpm", "embed-ui"] {
            assert!(
                GATEWAY_FEATURES.split(',').any(|f| f == feature),
                "feature {feature} absente du bundle de production"
            );
        }
    }

    /// Les unités et la configuration d'exemple doivent exister dans le dépôt :
    /// une référence morte casserait la fabrique au pire moment.
    #[test]
    fn les_fichiers_source_du_bundle_existent() {
        let root = workspace_root().expect("racine");
        for unit in SYSTEMD_UNITS {
            let path = root.join("deploy").join("systemd").join(unit);
            assert!(path.is_file(), "unité absente : {}", path.display());
        }
        assert!(root.join("config").join("network.toml").is_file());
    }

    #[test]
    fn wireguard_nt_est_epingle_et_sort_hors_git() {
        assert!(WIREGUARD_NT_URL.starts_with("https://download.wireguard.com/"));
        assert_eq!(WIREGUARD_NT_SHA256.len(), 64);
        assert!(WIREGUARD_NT_SHA256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert!(WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/amd64/wireguard.dll",
            "binaries/wireguard-amd64.dll"
        )));
        assert!(WIREGUARD_FILES.contains(&(
            "wireguard-nt/bin/arm64/wireguard.dll",
            "binaries/wireguard-arm64.dll"
        )));
        assert!(workspace_root().unwrap().join(".gitignore").is_file());
        let ignore = std::fs::read_to_string(workspace_root().unwrap().join(".gitignore")).unwrap();
        assert!(ignore.lines().any(|line| line == "/resources-windows"));
    }
}
