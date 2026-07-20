//! Réception, vérification et installation atomique d’un binaire `heliosd`.
//!
//! Le daemon ne fait que déposer l’artefact sous `/var/lib/helios/updates`.
//! L’installation privilégiée est rejouée et revérifiée par
//! `helios-installer`, sans accès réseau.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aether::{
    sig::{PublisherPublicKeys, SignedBinaryRelease, PUBLISHER_KEYS},
    HeliosError, Result,
};
use aws_lc_rs::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};

pub const INSTALLER_VERSION: u32 = 1;
pub const BUILD_TARGET: &str = env!("HELIOS_BUILD_TARGET");
pub const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;
pub const MAX_CHUNK_SIZE: usize = 512 * 1024;

const MANIFEST_FILE: &str = "manifest.json";
const PART_FILE: &str = "heliosd.part";
const BINARY_FILE: &str = "heliosd";
const FINALIZED_FILE: &str = "finalized.json";

/// Paramètres locaux du canal et des chemins de mise à jour.
#[derive(Debug, Clone)]
pub struct UpdateLayout {
    pub staging_root: PathBuf,
    pub install_root: PathBuf,
    pub current_link: PathBuf,
    pub state_path: PathBuf,
    pub activation_path: PathBuf,
    pub ready_path: PathBuf,
    pub channel: String,
    pub target: String,
}

impl UpdateLayout {
    pub fn system(channel: impl Into<String>) -> Self {
        let staging_root = std::env::var_os("HELIOS_UPDATE_STAGING")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/helios/updates"));
        let install_root = std::env::var_os("HELIOS_INSTALL_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/helios/releases"));
        let current_link = std::env::var_os("HELIOS_CURRENT_LINK")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/helios/current"));
        let ready_path = std::env::var_os("HELIOS_READY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/helios/ready"));
        Self {
            state_path: staging_root.join("state.json"),
            activation_path: staging_root.join("activate.json"),
            staging_root,
            install_root,
            current_link,
            ready_path,
            channel: channel.into(),
            target: BUILD_TARGET.to_string(),
        }
    }

    pub fn for_daemon(dry_run: bool) -> Self {
        let channel = std::env::var("HELIOS_UPDATE_CHANNEL")
            .unwrap_or_else(|_| if dry_run { "testing" } else { "production" }.into());
        let mut layout = Self::system(channel);
        if dry_run && std::env::var_os("HELIOS_UPDATE_STAGING").is_none() {
            let root = std::env::temp_dir().join(format!("helios-updates-{}", std::process::id()));
            layout.staging_root = root.join("staging");
            layout.install_root = root.join("releases");
            layout.current_link = root.join("current");
            layout.state_path = layout.staging_root.join("state.json");
            layout.activation_path = layout.staging_root.join("activate.json");
            layout.ready_path = root.join("ready");
        }
        layout
    }

    pub fn staged_dir(&self, sequence: u64) -> PathBuf {
        self.staging_root.join(sequence.to_string())
    }
}

/// État persistant minimal nécessaire à l’anti-rollback.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateState {
    pub highest_confirmed_sequence: u64,
    pub active_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedRelease {
    pub release_sequence: u64,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub release_sequence: u64,
    pub requested_at_unix: u64,
    pub delay_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    pub highest_confirmed_sequence: u64,
    pub active_version: Option<String>,
    pub staged: Vec<FinalizedRelease>,
    pub activation_pending: Option<u64>,
    pub channel: String,
    pub target: String,
}

/// Store clonable partagé par les handlers HTTP.
#[derive(Clone)]
pub struct UpdateStore {
    layout: UpdateLayout,
    lock: Arc<Mutex<()>>,
    keyring: Arc<Vec<PublisherPublicKeys>>,
}

impl UpdateStore {
    pub fn new(layout: UpdateLayout) -> Self {
        Self {
            layout,
            lock: Arc::new(Mutex::new(())),
            keyring: Arc::new(PUBLISHER_KEYS.to_vec()),
        }
    }

    #[cfg(test)]
    fn with_keyring(layout: UpdateLayout, keyring: Vec<PublisherPublicKeys>) -> Self {
        Self {
            layout,
            lock: Arc::new(Mutex::new(())),
            keyring: Arc::new(keyring),
        }
    }

    pub fn layout(&self) -> &UpdateLayout {
        &self.layout
    }

    pub fn stage_manifest(&self, manifest: &SignedBinaryRelease) -> Result<FinalizedRelease> {
        let _guard = self.lock.lock().map_err(lock_error)?;
        verify_manifest_with_keyring(manifest, &self.layout, &self.keyring)?;
        let state = read_state(&self.layout.state_path)?;
        reject_rollback(manifest.payload.release_sequence, &state)?;

        let directory = self.layout.staged_dir(manifest.payload.release_sequence);
        fs::create_dir_all(&directory)?;
        let manifest_path = directory.join(MANIFEST_FILE);
        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|e| update_error(format!("sérialisation du manifeste : {e}")))?;
        write_new_synced(&manifest_path, &bytes, 0o600)?;
        write_new_synced(&directory.join(PART_FILE), &[], 0o600)?;
        sync_directory(&directory)?;
        Ok(summary(manifest))
    }

    pub fn append_chunk(&self, sequence: u64, offset: u64, data: &[u8]) -> Result<u64> {
        if data.is_empty() || data.len() > MAX_CHUNK_SIZE {
            return Err(update_error(format!(
                "fragment de {} octets hors limite 1..={MAX_CHUNK_SIZE}",
                data.len()
            )));
        }
        let _guard = self.lock.lock().map_err(lock_error)?;
        let directory = self.layout.staged_dir(sequence);
        let manifest = read_manifest(&directory)?;
        verify_manifest_with_keyring(&manifest, &self.layout, &self.keyring)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join(PART_FILE))?;
        let current = file.metadata()?.len();
        if current != offset {
            return Err(update_error(format!(
                "offset inattendu : reçu {offset}, attendu {current}"
            )));
        }
        let next = current.saturating_add(data.len() as u64);
        if next > manifest.payload.binary_size || next > MAX_BINARY_SIZE {
            return Err(update_error("le fragment dépasserait la taille signée"));
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.sync_data()?;
        Ok(next)
    }

    pub fn finalize(&self, sequence: u64) -> Result<FinalizedRelease> {
        let _guard = self.lock.lock().map_err(lock_error)?;
        let directory = self.layout.staged_dir(sequence);
        let manifest = read_manifest(&directory)?;
        verify_manifest_with_keyring(&manifest, &self.layout, &self.keyring)?;
        verify_binary(&directory.join(PART_FILE), &manifest)?;
        fs::rename(directory.join(PART_FILE), directory.join(BINARY_FILE))?;
        let finalized = summary(&manifest);
        let bytes = serde_json::to_vec_pretty(&finalized)
            .map_err(|e| update_error(format!("sérialisation de la finalisation : {e}")))?;
        write_new_synced(&directory.join(FINALIZED_FILE), &bytes, 0o600)?;
        sync_directory(&directory)?;
        Ok(finalized)
    }

    pub fn request_activation(&self, sequence: u64, confirmation: &str) -> Result<()> {
        let _guard = self.lock.lock().map_err(lock_error)?;
        if confirmation != format!("INSTALLER {sequence}") {
            return Err(update_error("confirmation d’activation incorrecte"));
        }
        let directory = self.layout.staged_dir(sequence);
        let _: FinalizedRelease = read_json(&directory.join(FINALIZED_FILE))?;
        let manifest = read_manifest(&directory)?;
        verify_manifest_with_keyring(&manifest, &self.layout, &self.keyring)?;
        verify_binary(&directory.join(BINARY_FILE), &manifest)?;
        reject_rollback(sequence, &read_state(&self.layout.state_path)?)?;
        let request = ActivationRequest {
            release_sequence: sequence,
            requested_at_unix: unix_now()?,
            // Laisse au serveur HTTP le temps d’envoyer son 202 avant que le
            // helper ne redémarre le daemon et son interface WireGuard.
            delay_seconds: 2,
        };
        let bytes = serde_json::to_vec_pretty(&request)
            .map_err(|e| update_error(format!("sérialisation de l’activation : {e}")))?;
        if self.layout.activation_path.exists() {
            return Err(update_error("une activation est déjà en attente"));
        }
        write_new_synced(&self.layout.activation_path, &bytes, 0o600)
    }

    pub fn status(&self) -> Result<UpdateStatus> {
        let _guard = self.lock.lock().map_err(lock_error)?;
        let state = read_state(&self.layout.state_path)?;
        let mut staged: Vec<FinalizedRelease> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.layout.staging_root) {
            for entry in entries.flatten() {
                let path = entry.path().join(FINALIZED_FILE);
                if let Ok(release) = read_json(&path) {
                    staged.push(release);
                }
            }
        }
        staged.sort_by_key(|release| release.release_sequence);
        let activation_pending = read_json::<ActivationRequest>(&self.layout.activation_path)
            .ok()
            .map(|request| request.release_sequence);
        Ok(UpdateStatus {
            highest_confirmed_sequence: state.highest_confirmed_sequence,
            active_version: state.active_version,
            staged,
            activation_pending,
            channel: self.layout.channel.clone(),
            target: self.layout.target.clone(),
        })
    }
}

pub fn verify_manifest(manifest: &SignedBinaryRelease, layout: &UpdateLayout) -> Result<()> {
    verify_manifest_with_keyring(manifest, layout, PUBLISHER_KEYS)
}

fn verify_manifest_with_keyring(
    manifest: &SignedBinaryRelease,
    layout: &UpdateLayout,
    keyring: &[PublisherPublicKeys],
) -> Result<()> {
    manifest
        .verify(keyring)
        .map_err(|e| update_error(format!("signature du manifeste refusée : {e}")))?;
    let payload = &manifest.payload;
    if payload.product != "heliosd" {
        return Err(update_error("le manifeste ne cible pas heliosd"));
    }
    if payload.channel != layout.channel {
        return Err(update_error(format!(
            "canal {} refusé, {} attendu",
            payload.channel, layout.channel
        )));
    }
    if payload.target != layout.target {
        return Err(update_error(format!(
            "target {} refusée, {} attendue",
            payload.target, layout.target
        )));
    }
    if payload.release_sequence == 0
        || payload.version.trim().is_empty()
        || payload.git_commit.trim().is_empty()
    {
        return Err(update_error("métadonnées de release incomplètes"));
    }
    if payload.binary_size == 0 || payload.binary_size > MAX_BINARY_SIZE {
        return Err(update_error("taille de binaire hors limite"));
    }
    if payload.minimum_installer_version > INSTALLER_VERSION {
        return Err(update_error(format!(
            "installer v{} requis, v{INSTALLER_VERSION} présent",
            payload.minimum_installer_version
        )));
    }
    if payload.features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(update_error(
            "les features doivent être triées, uniques et non vides",
        ));
    }
    if payload
        .features
        .iter()
        .any(|feature| feature.trim().is_empty())
    {
        return Err(update_error("feature vide dans le manifeste"));
    }
    Ok(())
}

pub fn verify_binary(path: &Path, manifest: &SignedBinaryRelease) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != manifest.payload.binary_size {
        return Err(update_error(format!(
            "taille du binaire : {} au lieu de {}",
            metadata.len(),
            manifest.payload.binary_size
        )));
    }
    let digest = sha256_file(path)?;
    if digest != manifest.payload.sha256 {
        return Err(update_error("SHA-256 du binaire incorrect"));
    }
    verify_elf(path, &manifest.payload.target)?;
    Ok(())
}

/// Refuse un artefact signé par erreur qui ne serait pas un ELF de
/// l’architecture annoncée. La signature reste le contrôle d’authenticité ; ce
/// précontrôle évite une indisponibilité causée par un mauvais fichier.
pub fn verify_elf(path: &Path, target: &str) -> Result<()> {
    let mut header = [0u8; 20];
    File::open(path)?.read_exact(&mut header).map_err(|error| {
        update_error(format!(
            "en-tête ELF incomplet dans {} : {error}",
            path.display()
        ))
    })?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 {
        return Err(update_error("le fichier n’est pas un ELF 64 bits"));
    }
    let machine = match header[5] {
        1 => u16::from_le_bytes([header[18], header[19]]),
        2 => u16::from_be_bytes([header[18], header[19]]),
        _ => return Err(update_error("endianness ELF inconnue")),
    };
    let expected = if target.starts_with("x86_64-") {
        62
    } else if target.starts_with("aarch64-") {
        183
    } else if target.starts_with("riscv64-") {
        243
    } else {
        return Err(update_error(format!(
            "architecture de target non prise en charge par l’installer : {target}"
        )));
    };
    if machine != expected {
        return Err(update_error(format!(
            "architecture ELF {machine} incohérente avec {target}"
        )));
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut context = DigestContext::new(&SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| update_error("SHA-256 de longueur inattendue"))
}

/// Installe les octets vérifiés et bascule atomiquement le lien `current`.
/// Le redémarrage et la décision de confirmer ou restaurer appartiennent au
/// binaire privilégié.
pub fn prepare_switch(layout: &UpdateLayout, sequence: u64) -> Result<SwitchGuard> {
    prepare_switch_with_keyring(layout, sequence, PUBLISHER_KEYS)
}

fn prepare_switch_with_keyring(
    layout: &UpdateLayout,
    sequence: u64,
    keyring: &[PublisherPublicKeys],
) -> Result<SwitchGuard> {
    let state = read_state(&layout.state_path)?;
    reject_rollback(sequence, &state)?;
    let staged = layout.staged_dir(sequence);
    let manifest = read_manifest(&staged)?;
    verify_manifest_with_keyring(&manifest, layout, keyring)?;
    verify_binary(&staged.join(BINARY_FILE), &manifest)?;

    let release_dir = layout.install_root.join(sequence.to_string());
    fs::create_dir_all(&release_dir)?;
    let binary_destination = release_dir.join(BINARY_FILE);
    if !binary_destination.exists() {
        let temporary = release_dir.join("heliosd.installing");
        copy_executable(&staged.join(BINARY_FILE), &temporary)?;
        // La source appartient au staging du daemon et peut changer pendant la
        // copie. Seule la copie root sous /opt est immuable pour le daemon :
        // elle doit donc correspondre au manifeste avant de devenir active.
        verify_binary(&temporary, &manifest)?;
        fs::rename(&temporary, &binary_destination)?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| update_error(format!("sérialisation du manifeste installé : {e}")))?;
        write_new_synced(&release_dir.join(MANIFEST_FILE), &manifest_bytes, 0o600)?;
        sync_directory(&release_dir)?;
    } else {
        verify_binary(&binary_destination, &manifest)?;
    }

    let previous = fs::read_link(&layout.current_link).ok();
    switch_link(&layout.current_link, &release_dir)?;
    Ok(SwitchGuard {
        sequence,
        version: manifest.payload.version,
        previous,
        current_link: layout.current_link.clone(),
    })
}

#[derive(Debug)]
pub struct SwitchGuard {
    pub sequence: u64,
    pub version: String,
    previous: Option<PathBuf>,
    current_link: PathBuf,
}

impl SwitchGuard {
    pub fn confirm(&self, state_path: &Path) -> Result<()> {
        let state = UpdateState {
            highest_confirmed_sequence: self.sequence,
            active_version: Some(self.version.clone()),
        };
        write_json_atomic(state_path, &state)
    }

    pub fn rollback(&self) -> Result<()> {
        let previous = self
            .previous
            .as_ref()
            .ok_or_else(|| update_error("aucune version précédente pour le rollback"))?;
        switch_link(&self.current_link, previous)
    }
}

pub fn read_activation(path: &Path) -> Result<ActivationRequest> {
    read_json(path)
}

pub fn clear_activation(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_manifest(directory: &Path) -> Result<SignedBinaryRelease> {
    read_json(&directory.join(MANIFEST_FILE))
}

fn read_state(path: &Path) -> Result<UpdateState> {
    match read_json(path) {
        Ok(state) => Ok(state),
        Err(HeliosError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(UpdateState::default())
        }
        Err(error) => Err(error),
    }
}

fn reject_rollback(sequence: u64, state: &UpdateState) -> Result<()> {
    if sequence <= state.highest_confirmed_sequence {
        return Err(update_error(format!(
            "séquence {sequence} refusée, la séquence {} est déjà confirmée",
            state.highest_confirmed_sequence
        )));
    }
    Ok(())
}

fn summary(manifest: &SignedBinaryRelease) -> FinalizedRelease {
    FinalizedRelease {
        release_sequence: manifest.payload.release_sequence,
        version: manifest.payload.version.clone(),
        sha256: hex::encode(manifest.payload.sha256),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| update_error(format!("JSON {} invalide : {e}", path.display())))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| update_error(format!("sérialisation JSON : {e}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| update_error("chemin d’état sans répertoire parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn write_new_synced(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn copy_executable(source: &Path, destination: &Path) -> Result<()> {
    let mut source = File::open(source)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut destination = options.open(destination)?;
    std::io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn switch_link(link: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;
    let parent = link
        .parent()
        .ok_or_else(|| update_error("lien current sans répertoire parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join("current.switching");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    symlink(target, &temporary)?;
    fs::rename(&temporary, link)?;
    sync_directory(parent)
}

#[cfg(not(unix))]
fn switch_link(_link: &Path, _target: &Path) -> Result<()> {
    Err(update_error(
        "l’installation atomique est disponible uniquement sur Unix",
    ))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| update_error(format!("horloge système antérieure à Unix : {e}")))
}

fn update_error(message: impl Into<String>) -> HeliosError {
    HeliosError::Update(message.into())
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> HeliosError {
    update_error(format!("verrou de mise à jour empoisonné : {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::sig::{BinaryReleasePayload, PublisherSigner};

    fn layout(root: &Path) -> UpdateLayout {
        UpdateLayout {
            staging_root: root.join("staging"),
            install_root: root.join("releases"),
            current_link: root.join("current"),
            state_path: root.join("staging/state.json"),
            activation_path: root.join("staging/activate.json"),
            ready_path: root.join("ready"),
            channel: "testing".into(),
            target: env!("HELIOS_BUILD_TARGET").into(),
        }
    }

    fn test_elf() -> Vec<u8> {
        let machine = if BUILD_TARGET.starts_with("x86_64-") {
            62
        } else if BUILD_TARGET.starts_with("aarch64-") {
            183
        } else {
            243
        };
        let mut binary = vec![0u8; 64];
        binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
        binary[18..20].copy_from_slice(&u16::to_le_bytes(machine));
        binary
    }

    fn signed(binary: &[u8], sequence: u64) -> (SignedBinaryRelease, PublisherPublicKeys) {
        let signer = PublisherSigner::from_seed_material(1, &[1; 32], &[2; 32]).unwrap();
        let digest = aws_lc_rs::digest::digest(&SHA256, binary);
        let keys = signer.public_keys();
        let manifest = signer
            .sign(BinaryReleasePayload {
                product: "heliosd".into(),
                channel: "testing".into(),
                release_sequence: sequence,
                version: format!("1.0.{sequence}"),
                git_commit: "0123456789abcdef".into(),
                target: env!("HELIOS_BUILD_TARGET").into(),
                features: vec!["embed-ui".into(), "netlink".into()],
                binary_size: binary.len() as u64,
                sha256: digest.as_ref().try_into().unwrap(),
                minimum_installer_version: 1,
            })
            .unwrap();
        (manifest, keys)
    }

    fn store_with_test_keys(root: &Path) -> (UpdateStore, SignedBinaryRelease, Vec<u8>) {
        let binary = test_elf();
        let (manifest, keys) = signed(&binary, 7);
        (
            UpdateStore::with_keyring(layout(root), vec![keys]),
            manifest,
            binary,
        )
    }

    #[test]
    fn staging_borne_et_verifie_chaque_octet() {
        let dir = tempfile::tempdir().unwrap();
        let (store, manifest, binary) = store_with_test_keys(dir.path());

        store.stage_manifest(&manifest).unwrap();
        let split = binary.len() / 2;
        let next = store.append_chunk(7, 0, &binary[..split]).unwrap();
        assert_eq!(next, split as u64);
        assert!(store.append_chunk(7, 0, &binary[split..]).is_err());
        store
            .append_chunk(7, split as u64, &binary[split..])
            .unwrap();
        let finalized = store.finalize(7).unwrap();
        assert_eq!(finalized.sha256, hex::encode(manifest.payload.sha256));
        assert!(store.request_activation(7, "INSTALLER 6").is_err());
        store.request_activation(7, "INSTALLER 7").unwrap();
        assert_eq!(store.status().unwrap().activation_pending, Some(7));
    }

    #[test]
    fn hash_altere_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heliosd");
        let expected = test_elf();
        let mut altered = expected.clone();
        altered[30] = 1;
        fs::write(&path, altered).unwrap();
        let (manifest, _) = signed(&expected, 1);
        assert!(verify_binary(&path, &manifest).is_err());
    }

    #[test]
    fn anti_rollback_strict() {
        let state = UpdateState {
            highest_confirmed_sequence: 4,
            active_version: Some("1.0.4".into()),
        };
        assert!(reject_rollback(4, &state).is_err());
        assert!(reject_rollback(3, &state).is_err());
        assert!(reject_rollback(5, &state).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn lien_courant_bascule_et_revient_atomiquement() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old");
        let new = dir.path().join("new");
        fs::create_dir_all(&old).unwrap();
        fs::create_dir_all(&new).unwrap();
        let link = dir.path().join("current");
        switch_link(&link, &old).unwrap();
        let previous = fs::read_link(&link).unwrap();
        switch_link(&link, &new).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), new);
        switch_link(&link, &previous).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), old);
    }

    #[cfg(unix)]
    #[test]
    fn installation_confirmee_persiste_l_anti_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout(dir.path());
        let binary = test_elf();
        let (manifest, keys) = signed(&binary, 8);
        let store = UpdateStore::with_keyring(layout.clone(), vec![keys]);
        store.stage_manifest(&manifest).unwrap();
        store.append_chunk(8, 0, &binary).unwrap();
        store.finalize(8).unwrap();

        let bootstrap = dir.path().join("bootstrap");
        fs::create_dir_all(&bootstrap).unwrap();
        switch_link(&layout.current_link, &bootstrap).unwrap();
        let guard = prepare_switch_with_keyring(&layout, 8, &[keys]).unwrap();
        assert_eq!(
            fs::read_link(&layout.current_link).unwrap(),
            layout.install_root.join("8")
        );
        guard.confirm(&layout.state_path).unwrap();
        assert_eq!(
            read_state(&layout.state_path)
                .unwrap()
                .highest_confirmed_sequence,
            8
        );
        assert!(reject_rollback(8, &read_state(&layout.state_path).unwrap()).is_err());
    }
}
