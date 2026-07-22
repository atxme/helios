//! Bundle d'installation : ce qu'on livre à une gateway neuve.
//!
//! Un bundle est un répertoire — transporté sous forme d'archive — contenant
//! les binaires, les unités systemd et un exemple de configuration, plus un
//! [manifeste signé](aether::sig::BundlePayload) qui énumère **exhaustivement**
//! son contenu avec les empreintes.
//!
//! # Ce que ce module garantit, et ce qu'il ne garantit pas
//!
//! Il garantit qu'un bundle installé correspond octet pour octet à ce que
//! l'éditeur a signé : ni fichier modifié, ni fichier ajouté, ni fichier
//! manquant. C'est plus fort que la vérification de la mise à jour applicative
//! (ADR-003), qui ne couvre que le binaire `heliosd` — un bundle porte aussi
//! l'unité systemd, qui décide de la ligne de commande du daemon.
//!
//! Il ne garantit **pas** l'authenticité du programme qui exécute cette
//! vérification lors du tout premier déploiement : à ce moment, `helios-installer`
//! vient lui-même du bundle. La racine de confiance du premier pas est le canal
//! par lequel l'opérateur a copié l'archive, et l'empreinte qu'il a comparée.
//! Les installations suivantes, elles, sont vérifiées par un installateur déjà
//! installé et vérifié. Ce qui débloquerait le premier pas : un paquet système
//! signé par une distribution, hors périmètre ici.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use aether::{
    sig::{BundleEntry, BundlePayload, SignedBundle, PUBLISHER_KEYS},
    Result,
};

use crate::{sha256_file, update_error, INSTALLER_VERSION, MAX_BINARY_SIZE};

/// Nom du manifeste signé, à la racine du bundle.
pub const BUNDLE_MANIFEST_FILE: &str = "manifest.json";

/// Nombre maximal de fichiers dans un bundle.
///
/// Borne la mémoire et le temps de vérification d'une archive hostile : le
/// bundle réel en compte moins d'une dizaine.
pub const MAX_BUNDLE_FILES: usize = 256;

/// Profondeur maximale de l'arborescence, pour la même raison.
pub const MAX_BUNDLE_DEPTH: usize = 4;

/// Produit attendu dans le manifeste d'un bundle gateway.
pub const BUNDLE_PRODUCT: &str = "helios";

/// Recense le contenu d'un répertoire de bundle, trié par chemin.
///
/// Le manifeste lui-même est exclu : il ne peut pas contenir sa propre
/// empreinte.
pub fn collect(root: &Path) -> Result<Vec<BundleEntry>> {
    let mut entries = BTreeMap::new();
    walk(root, root, 0, &mut entries)?;
    if entries.len() > MAX_BUNDLE_FILES {
        return Err(update_error(format!(
            "bundle de {} fichiers, maximum {MAX_BUNDLE_FILES}",
            entries.len()
        )));
    }
    Ok(entries.into_values().collect())
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    entries: &mut BTreeMap<String, BundleEntry>,
) -> Result<()> {
    if depth > MAX_BUNDLE_DEPTH {
        return Err(update_error(format!(
            "arborescence de bundle trop profonde sous {}",
            dir.display()
        )));
    }
    let listing = fs::read_dir(dir)
        .map_err(|e| update_error(format!("lecture de {} : {e}", dir.display())))?;
    for item in listing {
        let item =
            item.map_err(|e| update_error(format!("parcours de {} : {e}", dir.display())))?;
        let path = item.path();
        // `symlink_metadata` : un lien symbolique n'est pas suivi. Le suivre
        // ferait entrer dans le bundle un fichier extérieur à sa racine, dont
        // l'empreinte signée ne dirait rien de ce qui serait réellement
        // installé.
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| update_error(format!("lecture de {} : {e}", path.display())))?;
        if metadata.is_dir() {
            walk(root, &path, depth + 1, entries)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(update_error(format!(
                "{} n'est ni un fichier ni un répertoire — un bundle ne contient ni lien \
                 symbolique ni fichier spécial",
                path.display()
            )));
        }
        let relative = relative_path(root, &path)?;
        if relative == BUNDLE_MANIFEST_FILE {
            continue;
        }
        if metadata.len() > MAX_BINARY_SIZE {
            return Err(update_error(format!(
                "{relative} : {} octets, maximum {MAX_BINARY_SIZE}",
                metadata.len()
            )));
        }
        entries.insert(
            relative.clone(),
            BundleEntry {
                path: relative,
                size: metadata.len(),
                sha256: sha256_file(&path)?,
                executable: is_executable(&metadata),
            },
        );
        if entries.len() > MAX_BUNDLE_FILES {
            return Err(update_error(format!(
                "bundle de plus de {MAX_BUNDLE_FILES} fichiers"
            )));
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| update_error(format!("{} hors du bundle", path.display())))?;
    let mut segments = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| {
                        update_error(format!("nom de fichier non UTF-8 : {}", path.display()))
                    })?
                    .to_string(),
            ),
            _ => {
                return Err(update_error(format!(
                    "chemin de bundle inattendu : {}",
                    path.display()
                )))
            }
        }
    }
    Ok(segments.join("/"))
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

/// Hors Unix, le bit exécutable n'existe pas : le manifeste porte alors la
/// valeur voulue par le producteur, jamais une valeur devinée du système de
/// fichiers. Un bundle gateway se construit de toute façon sous Linux.
#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

/// Chemin absolu d'une entrée du bundle, validé contre l'évasion de répertoire.
pub fn entry_path(root: &Path, entry: &BundleEntry) -> PathBuf {
    root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR))
}

/// Lit le manifeste signé à la racine d'un bundle.
pub fn read_manifest(root: &Path) -> Result<SignedBundle> {
    let path = root.join(BUNDLE_MANIFEST_FILE);
    let raw = fs::read(&path).map_err(|e| {
        update_error(format!(
            "manifeste absent ou illisible ({}) : {e} — un bundle non signé ne s'installe pas",
            path.display()
        ))
    })?;
    serde_json::from_slice(&raw)
        .map_err(|e| update_error(format!("manifeste de bundle invalide : {e}")))
}

/// Vérifie les signatures et les métadonnées du manifeste.
pub fn verify_manifest(manifest: &SignedBundle, channel: &str, target: &str) -> Result<()> {
    verify_manifest_with_keyring(manifest, channel, target, PUBLISHER_KEYS)
}

fn verify_manifest_with_keyring(
    manifest: &SignedBundle,
    channel: &str,
    target: &str,
    keyring: &[aether::sig::PublisherPublicKeys],
) -> Result<()> {
    manifest
        .verify(keyring)
        .map_err(|e| update_error(format!("signature du bundle refusée : {e}")))?;
    let payload = &manifest.payload;
    if payload.product != BUNDLE_PRODUCT {
        return Err(update_error(format!(
            "le manifeste ne cible pas {BUNDLE_PRODUCT} mais {}",
            payload.product
        )));
    }
    if payload.channel != channel {
        return Err(update_error(format!(
            "canal {} refusé, {channel} attendu",
            payload.channel
        )));
    }
    if payload.target != target {
        return Err(update_error(format!(
            "target {} refusée, {target} attendue",
            payload.target
        )));
    }
    if payload.release_sequence == 0
        || payload.version.trim().is_empty()
        || payload.git_commit.trim().is_empty()
    {
        return Err(update_error("métadonnées de bundle incomplètes"));
    }
    if payload.minimum_installer_version > INSTALLER_VERSION {
        return Err(update_error(format!(
            "installer v{} requis, v{INSTALLER_VERSION} présent",
            payload.minimum_installer_version
        )));
    }
    payload
        .validate()
        .map_err(|e| update_error(format!("contenu de bundle refusé : {e}")))?;
    Ok(())
}

/// Vérifie que le contenu du répertoire correspond **exactement** au manifeste.
///
/// L'égalité est stricte dans les deux sens : un fichier surnuméraire est un
/// refus, pas une tolérance. Sans cette symétrie, une archive pourrait glisser
/// un fichier non signé à côté de ceux qui le sont — un script, une unité
/// systemd de plus — et l'installation le poserait sous une garantie qui ne le
/// couvre pas.
pub fn verify_contents(root: &Path, payload: &BundlePayload) -> Result<()> {
    payload
        .validate()
        .map_err(|e| update_error(format!("contenu de bundle refusé : {e}")))?;
    let actual = collect(root)?;
    if actual == payload.files {
        return Ok(());
    }

    for entry in &payload.files {
        match actual.iter().find(|candidate| candidate.path == entry.path) {
            None => {
                return Err(update_error(format!(
                    "fichier absent du bundle : {}",
                    entry.path
                )))
            }
            Some(candidate) if candidate.sha256 != entry.sha256 => {
                return Err(update_error(format!(
                    "empreinte différente pour {} — contenu altéré",
                    entry.path
                )))
            }
            Some(candidate) if candidate.size != entry.size => {
                return Err(update_error(format!(
                    "taille différente pour {}",
                    entry.path
                )))
            }
            Some(candidate) if candidate.executable != entry.executable => {
                return Err(update_error(format!(
                    "droit d'exécution différent pour {}",
                    entry.path
                )))
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = actual
        .iter()
        .find(|candidate| payload.entry(&candidate.path).is_none())
    {
        return Err(update_error(format!(
            "fichier non signé présent dans le bundle : {}",
            extra.path
        )));
    }
    Err(update_error("contenu du bundle non conforme au manifeste"))
}

/// Destinations système d'un bundle installé.
///
/// Chaque chemin est surchargeable par variable d'environnement, comme
/// [`crate::UpdateLayout`] : c'est ce qui rend l'installation complète
/// vérifiable sur une machine de développement, sans droits root et sans
/// toucher au système. Le service de production, lui, n'en définit aucune.
#[derive(Debug, Clone)]
pub struct BootstrapLayout {
    pub update: crate::UpdateLayout,
    /// Helper privilégié de mise à jour (`helios-installer`).
    pub libexec_dir: PathBuf,
    /// Outils d'exploitation (`helios-ctl`).
    pub bin_dir: PathBuf,
    /// Unités systemd.
    pub systemd_dir: PathBuf,
    /// Configuration réseau, **jamais écrasée** si elle existe déjà.
    pub config_path: PathBuf,
}

impl BootstrapLayout {
    pub fn system(update: crate::UpdateLayout) -> Self {
        Self {
            update,
            libexec_dir: env_path("HELIOS_LIBEXEC_DIR", "/usr/libexec"),
            bin_dir: env_path("HELIOS_BIN_DIR", "/usr/local/bin"),
            systemd_dir: env_path("HELIOS_SYSTEMD_DIR", "/etc/systemd/system"),
            config_path: env_path("HELIOS_NETWORK_CONFIG", "/var/lib/helios/network.toml"),
        }
    }
}

fn env_path(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// Ce qu'une installation a réellement fait, pour le rapport à l'opérateur.
#[derive(Debug)]
pub struct InstallReport {
    pub version: String,
    pub release_sequence: u64,
    pub channel: String,
    pub installed: Vec<PathBuf>,
    /// La configuration existait déjà et n'a pas été touchée.
    pub config_preserved: bool,
}

/// Destination d'un fichier du bundle.
enum Destination {
    /// Le daemon : versionné sous `install_root/<séquence>` et pointé par
    /// `current`, comme une mise à jour applicative.
    Daemon,
    /// Un fichier ordinaire, remplacé s'il existe.
    Replace(PathBuf, u32),
    /// La configuration : posée seulement si elle est absente.
    ConfigIfAbsent(PathBuf, u32),
}

/// Où va chaque fichier déclaré. Un chemin inconnu est un refus.
///
/// Ignorer un fichier non reconnu reviendrait à installer un bundle
/// partiellement, en silence : l'opérateur croirait avoir déployé ce qu'il a
/// signé.
fn destination(path: &str, layout: &BootstrapLayout) -> Result<Destination> {
    match path {
        "heliosd" => Ok(Destination::Daemon),
        "helios-installer" => Ok(Destination::Replace(
            layout.libexec_dir.join("helios-installer"),
            0o755,
        )),
        "helios-ctl" => Ok(Destination::Replace(
            layout.bin_dir.join("helios-ctl"),
            0o755,
        )),
        "network.toml.example" => Ok(Destination::ConfigIfAbsent(
            layout.config_path.clone(),
            0o600,
        )),
        other => match other.strip_prefix("systemd/") {
            Some(unit) if !unit.contains('/') => {
                Ok(Destination::Replace(layout.systemd_dir.join(unit), 0o644))
            }
            _ => Err(update_error(format!(
                "fichier {other} sans destination connue — ce bundle a été produit par une \
                 version différente de l'installateur"
            ))),
        },
    }
}

/// Installe un bundle **vérifié** depuis un répertoire extrait.
///
/// L'ordre compte : tout est vérifié avant que quoi que ce soit ne soit écrit.
/// Une installation qui échouerait à mi-parcours laisserait une gateway avec un
/// daemon d'une version et une unité systemd d'une autre.
pub fn install(root: &Path, layout: &BootstrapLayout) -> Result<InstallReport> {
    install_with_keyring(root, layout, PUBLISHER_KEYS)
}

fn install_with_keyring(
    root: &Path,
    layout: &BootstrapLayout,
    keyring: &[aether::sig::PublisherPublicKeys],
) -> Result<InstallReport> {
    let manifest = read_manifest(root)?;
    verify_manifest_with_keyring(
        &manifest,
        &layout.update.channel,
        &layout.update.target,
        keyring,
    )?;
    verify_contents(root, &manifest.payload)?;

    let payload = &manifest.payload;
    let state = crate::read_state(&layout.update.state_path)?;
    crate::reject_rollback(payload.release_sequence, &state)?;

    // Les destinations sont résolues avant la première écriture : un bundle
    // portant un fichier inconnu doit être refusé entier, pas à moitié posé.
    let mut plan = Vec::with_capacity(payload.files.len());
    for entry in &payload.files {
        plan.push((entry, destination(&entry.path, layout)?));
    }
    if !payload.files.iter().any(|entry| entry.path == "heliosd") {
        return Err(update_error("bundle sans heliosd"));
    }

    let mut installed = Vec::new();
    let mut config_preserved = false;
    let release_dir = layout
        .update
        .install_root
        .join(payload.release_sequence.to_string());

    for (entry, destination) in plan {
        let source = entry_path(root, entry);
        match destination {
            Destination::Daemon => {
                fs::create_dir_all(&release_dir)?;
                let target = release_dir.join("heliosd");
                replace_file(&source, &target, 0o755)?;
                installed.push(target);
            }
            Destination::Replace(target, mode) => {
                replace_file(&source, &target, mode)?;
                installed.push(target);
            }
            Destination::ConfigIfAbsent(target, mode) => {
                if target.exists() {
                    config_preserved = true;
                } else {
                    replace_file(&source, &target, mode)?;
                    installed.push(target);
                }
            }
        }
    }

    crate::switch_link(&layout.update.current_link, &release_dir)?;
    crate::write_json_atomic(
        &layout.update.state_path,
        &crate::UpdateState {
            highest_confirmed_sequence: payload.release_sequence,
            active_version: Some(payload.version.clone()),
        },
    )?;

    Ok(InstallReport {
        version: payload.version.clone(),
        release_sequence: payload.release_sequence,
        channel: payload.channel.clone(),
        installed,
        config_preserved,
    })
}

/// Écrit une copie neuve puis la met en place par `rename`.
///
/// Le remplacement direct d'un exécutable en cours d'utilisation échouerait ou
/// corromprait le processus vivant ; `rename` sur le même système de fichiers
/// est atomique et laisse l'ancien inode aux processus qui l'ont ouvert.
fn replace_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("helios-installing");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = fs::read(source)?;
    crate::write_new_synced(&temporary, &bytes, mode)?;
    fs::rename(&temporary, destination)?;
    if let Some(parent) = destination.parent() {
        crate::sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(nom: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-bundle-{nom}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("répertoire de test");
        dir
    }

    fn ecrire(root: &Path, relatif: &str, contenu: &[u8]) {
        let path = root.join(relatif);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contenu).unwrap();
    }

    fn payload(files: Vec<BundleEntry>) -> BundlePayload {
        BundlePayload {
            product: BUNDLE_PRODUCT.into(),
            channel: "testing".into(),
            release_sequence: 1,
            version: "0.1.0".into(),
            git_commit: "abcdef0123456789".into(),
            target: crate::BUILD_TARGET.into(),
            minimum_installer_version: INSTALLER_VERSION,
            files,
        }
    }

    #[test]
    fn le_recensement_est_trie_et_ignore_le_manifeste() {
        let dir = temp_dir("collect");
        ecrire(&dir, "heliosd", b"binaire");
        ecrire(&dir, "systemd/heliosd.service", b"unite");
        ecrire(&dir, BUNDLE_MANIFEST_FILE, b"{}");

        let entries = collect(&dir).expect("recensement");
        let chemins: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(chemins, ["heliosd", "systemd/heliosd.service"]);
        assert_eq!(entries[0].size, 7);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_contenu_conforme_est_accepte() {
        let dir = temp_dir("conforme");
        ecrire(&dir, "heliosd", b"binaire");
        let payload = payload(collect(&dir).unwrap());
        assert!(verify_contents(&dir, &payload).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_fichier_altere_est_refuse() {
        let dir = temp_dir("altere");
        ecrire(&dir, "heliosd", b"binaire");
        let payload = payload(collect(&dir).unwrap());
        ecrire(&dir, "heliosd", b"binaireX");

        let erreur = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(erreur.contains("heliosd"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Le point qui distingue cette vérification d'un simple contrôle
    /// d'empreintes : un fichier en plus est un refus.
    #[test]
    fn un_fichier_surnumeraire_est_refuse() {
        let dir = temp_dir("surnumeraire");
        ecrire(&dir, "heliosd", b"binaire");
        let payload = payload(collect(&dir).unwrap());
        ecrire(&dir, "systemd/pirate.service", b"unite non signee");

        let erreur = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(erreur.contains("pirate"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_fichier_manquant_est_refuse() {
        let dir = temp_dir("manquant");
        ecrire(&dir, "heliosd", b"binaire");
        ecrire(&dir, "helios-ctl", b"outil");
        let payload = payload(collect(&dir).unwrap());
        fs::remove_file(dir.join("helios-ctl")).unwrap();

        let erreur = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(erreur.contains("helios-ctl"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn le_bit_executable_fait_partie_de_ce_qui_est_verifie() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        ecrire(&dir, "heliosd", b"binaire");
        fs::set_permissions(dir.join("heliosd"), fs::Permissions::from_mode(0o755)).unwrap();
        let payload = payload(collect(&dir).unwrap());
        assert!(payload.files[0].executable);

        fs::set_permissions(dir.join("heliosd"), fs::Permissions::from_mode(0o644)).unwrap();
        let erreur = verify_contents(&dir, &payload).unwrap_err().to_string();
        assert!(erreur.contains("exécution"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Un lien symbolique ferait entrer dans le bundle un fichier extérieur à
    /// sa racine : l'empreinte signée ne dirait alors rien de ce qui est
    /// réellement installé.
    #[cfg(unix)]
    #[test]
    fn un_lien_symbolique_est_refuse() {
        let dir = temp_dir("lien");
        ecrire(&dir, "heliosd", b"binaire");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("secret")).unwrap();

        let erreur = collect(&dir).unwrap_err().to_string();
        assert!(erreur.contains("lien symbolique"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_manifeste_absent_est_un_refus_explicite() {
        let dir = temp_dir("sans-manifeste");
        ecrire(&dir, "heliosd", b"binaire");
        let erreur = read_manifest(&dir).unwrap_err().to_string();
        assert!(erreur.contains("non signé"), "message : {erreur}");
        let _ = fs::remove_dir_all(&dir);
    }

    // ─── Installation de bout en bout ────────────────────────────────────────

    use aether::sig::{PublisherPublicKeys, PublisherSigner};

    /// Bundle complet, tel que `cargo xtask bundle` l'assemble.
    fn bundle_complet(racine: &Path) {
        ecrire(racine, "heliosd", b"le-daemon");
        ecrire(racine, "helios-installer", b"l-installateur");
        ecrire(racine, "helios-ctl", b"l-outil");
        ecrire(racine, "systemd/heliosd.service", b"[Unit]");
        ecrire(racine, "systemd/helios-update.service", b"[Unit]");
        ecrire(racine, "systemd/helios-update.path", b"[Path]");
        ecrire(racine, "network.toml.example", b"wan_iface = \"eth0\"");
    }

    fn signer_bundle(racine: &Path, sequence: u64) -> PublisherPublicKeys {
        let signer = PublisherSigner::from_seed_material(1, &[3; 32], &[4; 32]).unwrap();
        let mut payload = payload(collect(racine).unwrap());
        payload.release_sequence = sequence;
        payload.version = format!("0.{sequence}.0");
        let manifest = signer.sign(payload).unwrap();
        fs::write(
            racine.join(BUNDLE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        signer.public_keys()
    }

    /// Destinations détournées vers un répertoire jetable : l'installation
    /// complète devient vérifiable sans droits root ni système à abîmer.
    fn bootstrap_layout(cible: &Path) -> BootstrapLayout {
        let mut update = crate::UpdateLayout::system("testing");
        update.staging_root = cible.join("var/lib/helios/updates");
        update.state_path = update.staging_root.join("state.json");
        update.activation_path = update.staging_root.join("activate.json");
        update.install_root = cible.join("opt/helios/releases");
        update.current_link = cible.join("opt/helios/current");
        update.target = crate::BUILD_TARGET.to_string();
        BootstrapLayout {
            update,
            libexec_dir: cible.join("usr/libexec"),
            bin_dir: cible.join("usr/local/bin"),
            systemd_dir: cible.join("etc/systemd/system"),
            config_path: cible.join("var/lib/helios/network.toml"),
        }
    }

    #[test]
    fn l_installation_pose_tout_le_bundle_et_bascule_le_lien() {
        let source = temp_dir("install-source");
        let cible = temp_dir("install-cible");
        bundle_complet(&source);
        let keys = signer_bundle(&source, 7);
        let layout = bootstrap_layout(&cible);

        let rapport = install_with_keyring(&source, &layout, &[keys]).expect("installation");

        assert_eq!(rapport.release_sequence, 7);
        assert!(!rapport.config_preserved);
        assert_eq!(
            fs::read(cible.join("opt/helios/releases/7/heliosd")).unwrap(),
            b"le-daemon"
        );
        assert_eq!(
            fs::read(cible.join("usr/libexec/helios-installer")).unwrap(),
            b"l-installateur"
        );
        assert_eq!(
            fs::read(cible.join("usr/local/bin/helios-ctl")).unwrap(),
            b"l-outil"
        );
        assert!(cible.join("etc/systemd/system/heliosd.service").is_file());
        assert!(cible
            .join("etc/systemd/system/helios-update.path")
            .is_file());
        assert!(cible.join("var/lib/helios/network.toml").is_file());
        assert_eq!(
            fs::read_link(cible.join("opt/helios/current")).unwrap(),
            cible.join("opt/helios/releases/7")
        );

        // L'état d'anti-rollback doit refléter ce qui vient d'être posé, sinon
        // une mise à jour applicative plus ancienne serait acceptée ensuite.
        let state: crate::UpdateState =
            serde_json::from_slice(&fs::read(&layout.update.state_path).unwrap()).unwrap();
        assert_eq!(state.highest_confirmed_sequence, 7);
        assert_eq!(state.active_version.as_deref(), Some("0.7.0"));

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }

    /// Réinstaller une séquence déjà posée ferait revenir une version que
    /// l'anti-rollback de l'ADR-003 refuse par ailleurs : les deux chemins
    /// doivent obéir au même compteur.
    #[test]
    fn une_sequence_deja_confirmee_est_refusee() {
        let source = temp_dir("rollback-source");
        let cible = temp_dir("rollback-cible");
        bundle_complet(&source);
        let keys = signer_bundle(&source, 5);
        let layout = bootstrap_layout(&cible);
        install_with_keyring(&source, &layout, &[keys]).expect("première installation");

        let ancien = temp_dir("rollback-ancien");
        bundle_complet(&ancien);
        let keys = signer_bundle(&ancien, 4);
        let erreur = install_with_keyring(&ancien, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(erreur.contains("séquence 4 refusée"), "message : {erreur}");

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
        let _ = fs::remove_dir_all(&ancien);
    }

    /// La configuration porte l'identité du réseau et les pairs admis :
    /// l'écraser à chaque mise à jour couperait le parc.
    #[test]
    fn une_configuration_existante_n_est_jamais_ecrasee() {
        let source = temp_dir("config-source");
        let cible = temp_dir("config-cible");
        bundle_complet(&source);
        let keys = signer_bundle(&source, 3);
        let layout = bootstrap_layout(&cible);
        fs::create_dir_all(layout.config_path.parent().unwrap()).unwrap();
        fs::write(&layout.config_path, b"wan_iface = \"deja-configure\"").unwrap();

        let rapport = install_with_keyring(&source, &layout, &[keys]).expect("installation");

        assert!(rapport.config_preserved);
        assert_eq!(
            fs::read(&layout.config_path).unwrap(),
            b"wan_iface = \"deja-configure\""
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }

    /// Rien ne doit être écrit tant que tout n'est pas vérifié : une
    /// installation à moitié faite laisserait un daemon et une unité systemd de
    /// versions différentes.
    #[test]
    fn un_bundle_altere_n_installe_rien() {
        let source = temp_dir("altere-source");
        let cible = temp_dir("altere-cible");
        bundle_complet(&source);
        let keys = signer_bundle(&source, 9);
        ecrire(&source, "heliosd", b"le-daemon-remplace");
        let layout = bootstrap_layout(&cible);

        assert!(install_with_keyring(&source, &layout, &[keys]).is_err());
        assert!(
            !cible.join("opt/helios").exists() && !cible.join("etc").exists(),
            "une installation refusée ne doit rien avoir posé"
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }

    /// Un fichier signé mais dont l'installateur ne connaît pas la destination
    /// doit faire échouer le bundle entier, pas être ignoré.
    #[test]
    fn un_fichier_sans_destination_connue_refuse_tout_le_bundle() {
        let source = temp_dir("inconnu-source");
        let cible = temp_dir("inconnu-cible");
        bundle_complet(&source);
        ecrire(&source, "cron.d/helios", b"* * * * * root /bin/true");
        let keys = signer_bundle(&source, 2);
        let layout = bootstrap_layout(&cible);

        let erreur = install_with_keyring(&source, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(erreur.contains("destination"), "message : {erreur}");
        assert!(!cible.join("opt/helios").exists());
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }

    #[test]
    fn un_bundle_d_un_autre_canal_est_refuse() {
        let source = temp_dir("canal-source");
        let cible = temp_dir("canal-cible");
        bundle_complet(&source);
        let keys = signer_bundle(&source, 1);
        let mut layout = bootstrap_layout(&cible);
        layout.update.channel = "production".into();

        let erreur = install_with_keyring(&source, &layout, &[keys])
            .unwrap_err()
            .to_string();
        assert!(
            erreur.contains("canal testing refusé"),
            "message : {erreur}"
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }

    /// Une signature valide d'une autre époque que celle compilée dans le
    /// binaire ne doit rien autoriser.
    #[test]
    fn un_bundle_signe_par_une_autre_cle_est_refuse() {
        let source = temp_dir("cle-source");
        let cible = temp_dir("cle-cible");
        bundle_complet(&source);
        signer_bundle(&source, 6);
        let autre = PublisherSigner::from_seed_material(1, &[9; 32], &[8; 32])
            .unwrap()
            .public_keys();
        let layout = bootstrap_layout(&cible);

        let erreur = install_with_keyring(&source, &layout, &[autre])
            .unwrap_err()
            .to_string();
        assert!(erreur.contains("signature"), "message : {erreur}");
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&cible);
    }
}
