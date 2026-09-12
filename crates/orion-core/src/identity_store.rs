//! Protected storage of the client key-negotiation identity.
//!
//! The identity is what proves, to the gateway, that this machine is the peer
//! it admitted: an X.509 client certificate for mTLS and an ML-DSA-65
//! certificate that signs the protocol transcript. Both come with a private
//! key, and those two keys are the most sensitive secrets Orion holds after
//! the WireGuard private key — with one difference that decides the design:
//! they are **issued by the operator**, so they travel once, from the
//! operator workstation to this machine.
//!
//! That single transfer is the whole point of this module. The bundle is
//! imported once, sealed to the machine's user account, and the plaintext
//! file is meant to be destroyed. From then on the VPN profile only carries
//! the *name* of the entry — never the material.
//!
//! # Windows: DPAPI, and why not the Credential Manager
//!
//! Sealing goes through DPAPI (`CryptProtectData`), scoped to the current
//! user and bound to an application-specific entropy value, so a blob copied
//! to another account — or read by another program of the same user that does
//! not know the entropy — cannot be opened.
//!
//! The Credential Manager would have been the obvious store, and it is the
//! wrong one here: it caps a credential blob at 2560 bytes, while an ML-DSA-65
//! private key alone is 4032 bytes. The identity would not fit, and splitting
//! it across entries would just rebuild a worse container.
//!
//! # Known limitation: Windows only
//!
//! On every other platform, [`seal`] and [`unseal`] fail with
//! [`IdentityStoreError::UnsupportedPlatform`]. This is deliberate: writing
//! these keys to a plain file on disk would look like it worked while
//! offering none of the protection the screen promises, and Orion's real
//! target is Windows. Unblocking Linux means wiring the Secret Service API
//! (`libsecret`), and macOS the Keychain — each with its own unlock
//! semantics, which is why neither is faked here.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Domain separation for the DPAPI entropy.
///
/// It ties a sealed blob to this use: another Helios secret sealed by the
/// same user cannot be opened by this code path, and vice versa.
#[cfg(windows)]
const SEAL_ENTROPY: &[u8] = b"helios-orion-key-negotiation-identity-v1";

/// Sealed file suffix. The extension is deliberately not `.json`: what is on
/// disk is a ciphertext, and nothing should invite opening it as text.
const SEALED_SUFFIX: &str = ".identity";

/// Version of the plaintext record sealed by the platform backend.
const IDENTITY_RECORD_FORMAT_VERSION: u16 = 1;

/// Bound on a sealed identity, checked before decrypting.
///
/// A legitimate bundle is around 10 KB — two certificates and two private
/// keys. The limit exists so a corrupted or substituted file cannot make the
/// client allocate on someone else's terms.
const MAX_SEALED_BYTES: usize = 256 * 1024;

/// Client identity as the operator hands it over, before sealing.
///
/// Everything is base64: the document that carries it is JSON, and these are
/// DER and raw byte strings. The two private halves are **secrets** — `Debug`
/// is masked so an import failure cannot spill them into a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentityBundle {
    /// Entry name under which this identity is sealed. The VPN profile
    /// stores this name, and only this name.
    pub identity: String,
    /// Client leaf certificate first, then any intermediates (base64 DER).
    pub certificate_chain: Vec<String>,
    /// PKCS#8 client private key (base64 DER). **Secret.**
    pub private_key: String,
    /// ML-DSA-65 client certificate (base64 JSON).
    pub pq_certificate: String,
    /// Raw ML-DSA-65 private key (base64). **Secret.**
    pub pq_private_key: String,
}

/// Whether a retained identity may still be selected for service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviousIdentityPhase {
    NotYetAvailable,
    Available,
    Expired,
}

/// Public facts about the second protected slot. No certificate or key leaves
/// the store through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousIdentityStatus {
    pub available_from: u64,
    pub available_until: u64,
    pub phase: PreviousIdentityPhase,
    /// True only while the previous bundle is actually being served.
    pub selected: bool,
}

/// One read of the protected record, for inventory callers that need both the
/// served certificates and the bounded previous-slot status.
pub struct IdentitySnapshot {
    pub served: ClientIdentityBundle,
    pub previous: Option<PreviousIdentityStatus>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousIdentitySlot {
    bundle: ClientIdentityBundle,
    available_from: u64,
    available_until: u64,
}

/// Non-secret tombstone kept after the outgoing private keys are destroyed.
/// It lets the UI distinguish an expired window from a profile that never had
/// a previous identity without retaining any credential material.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredIdentityWindow {
    available_from: u64,
    available_until: u64,
}

/// Plaintext format inside DPAPI. Active and previous move in one sealed file,
/// so replacing the served bundle cannot lose the only rollback copy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedIdentityRecord {
    format_version: u16,
    current: ClientIdentityBundle,
    previous: Option<PreviousIdentitySlot>,
    #[serde(default)]
    retired_previous: Option<RetiredIdentityWindow>,
    serve_previous: bool,
}

impl ProtectedIdentityRecord {
    fn new(current: ClientIdentityBundle) -> Self {
        Self {
            format_version: IDENTITY_RECORD_FORMAT_VERSION,
            current,
            previous: None,
            retired_previous: None,
            serve_previous: false,
        }
    }

    fn validate(&self, identity: &str) -> Result<()> {
        if self.format_version != IDENTITY_RECORD_FORMAT_VERSION {
            anyhow::bail!(
                "version d'identité protégée non prise en charge : {}",
                self.format_version
            );
        }
        self.current.validate()?;
        if self.current.identity.trim() != identity.trim() {
            anyhow::bail!("l'identité protégée ne correspond pas au nom demandé");
        }
        match &self.previous {
            Some(previous) => {
                previous.bundle.validate()?;
                if previous.bundle.identity.trim() != identity.trim() {
                    anyhow::bail!("l'identité précédente ne correspond pas au nom demandé");
                }
                if previous.available_from >= previous.available_until {
                    anyhow::bail!("la fenêtre de retour à l'identité précédente est vide");
                }
            }
            None if self.serve_previous => {
                anyhow::bail!("le magasin sélectionne une identité précédente absente");
            }
            None => {}
        }
        if let Some(retired) = self.retired_previous {
            if self.previous.is_some() {
                anyhow::bail!("une identité précédente active et son tombstone coexistent");
            }
            if retired.available_from >= retired.available_until {
                anyhow::bail!("la fenêtre retirée de l'identité précédente est vide");
            }
        }
        Ok(())
    }

    fn previous_status(&self, now_unix: u64) -> Option<PreviousIdentityStatus> {
        let (available_from, available_until, selectable) = if let Some(previous) = &self.previous {
            (previous.available_from, previous.available_until, true)
        } else {
            let retired = self.retired_previous?;
            (retired.available_from, retired.available_until, false)
        };
        let phase = if selectable {
            if now_unix < available_from {
                PreviousIdentityPhase::NotYetAvailable
            } else if now_unix < available_until {
                PreviousIdentityPhase::Available
            } else {
                PreviousIdentityPhase::Expired
            }
        } else {
            PreviousIdentityPhase::Expired
        };
        Some(PreviousIdentityStatus {
            available_from,
            available_until,
            phase,
            selected: selectable
                && self.serve_previous
                && phase == PreviousIdentityPhase::Available,
        })
    }

    fn served_at(&self, now_unix: u64) -> &ClientIdentityBundle {
        match (&self.previous, self.previous_status(now_unix)) {
            (Some(previous), Some(status))
                if self.serve_previous && status.phase == PreviousIdentityPhase::Available =>
            {
                &previous.bundle
            }
            _ => &self.current,
        }
    }

    fn promote(
        &mut self,
        candidate: ClientIdentityBundle,
        available_from: u64,
        available_until: u64,
    ) -> Result<bool> {
        if available_from >= available_until {
            anyhow::bail!("la fenêtre de retour à l'identité précédente est vide");
        }
        if self.current == candidate {
            let same_window = self.previous.as_ref().is_some_and(|previous| {
                previous.available_from == available_from
                    && previous.available_until == available_until
            });
            if !same_window {
                anyhow::bail!("le candidat est déjà actif sans la fenêtre précédente attendue");
            }
            return Ok(false);
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| available_from < previous.available_until)
        {
            anyhow::bail!("une identité précédente non expirée occupe déjà le second slot");
        }
        let outgoing = std::mem::replace(&mut self.current, candidate);
        self.previous = Some(PreviousIdentitySlot {
            bundle: outgoing,
            available_from,
            available_until,
        });
        self.retired_previous = None;
        self.serve_previous = false;
        Ok(true)
    }

    fn select_previous(&mut self, now_unix: u64) -> Result<PreviousIdentityStatus> {
        let status = self
            .previous_status(now_unix)
            .ok_or_else(|| anyhow::anyhow!("aucune identité précédente n'est conservée"))?;
        if status.phase != PreviousIdentityPhase::Available {
            anyhow::bail!("l'identité précédente est hors de sa fenêtre de chevauchement");
        }
        self.serve_previous = true;
        Ok(PreviousIdentityStatus {
            selected: true,
            ..status
        })
    }

    fn retire_previous(&mut self, now_unix: u64) -> bool {
        let due = self
            .previous
            .as_ref()
            .is_some_and(|previous| now_unix >= previous.available_until);
        if due {
            self.retired_previous = self.previous.take().map(|previous| RetiredIdentityWindow {
                available_from: previous.available_from,
                available_until: previous.available_until,
            });
            self.serve_previous = false;
        }
        due
    }
}

impl std::fmt::Debug for ClientIdentityBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientIdentityBundle")
            .field("identity", &self.identity)
            .field("certificate_chain", &self.certificate_chain.len())
            .field("private_key", &"***")
            .field("pq_certificate", &self.pq_certificate.len())
            .field("pq_private_key", &"***")
            .finish()
    }
}

impl ClientIdentityBundle {
    /// Checks that the bundle is complete and decodable.
    ///
    /// Run **before** sealing: a bundle that only fails to decode at
    /// connection time would leave the user with a profile that looks
    /// imported and never connects.
    pub fn validate(&self) -> Result<()> {
        if self.identity.trim().is_empty() {
            anyhow::bail!("l'identité protégée doit porter un nom");
        }
        if self.certificate_chain.is_empty() {
            anyhow::bail!("la chaîne de certificats client est vide");
        }
        for certificate in &self.certificate_chain {
            decode(certificate, "certificat client")?;
        }
        decode(&self.private_key, "clé privée client")?;
        let pq_certificate = decode(&self.pq_certificate, "certificat PQ client")?;
        serde_json::from_slice::<serde_json::Value>(&pq_certificate)
            .context("le certificat PQ client n'est pas un document JSON")?;
        decode(&self.pq_private_key, "clé privée PQ client")?;
        Ok(())
    }
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .with_context(|| format!("{label} : encodage base64 illisible"))?;
    if bytes.is_empty() {
        anyhow::bail!("{label} : valeur vide");
    }
    Ok(bytes)
}

/// Failure modes of the protected store, kept distinct on purpose.
///
/// The user acts differently on each one: an absent identity means importing
/// the operator's bundle, a platform without a store means running Orion on
/// Windows, and a decryption failure means the blob belongs to another
/// account or another machine.
#[derive(Debug, thiserror::Error)]
pub enum IdentityStoreError {
    #[error(
        "aucune identité protégée nommée « {0} » sur ce poste — importer le fichier d'identité fourni par l'opérateur"
    )]
    NotFound(String),
    #[error(
        "le stockage protégé d'identité n'existe que sur Windows (DPAPI) ; sur cette plateforme, Orion refuse de conserver la clé privée du certificat en clair"
    )]
    UnsupportedPlatform,
    #[error("scellement de l'identité refusé par le système : {0}")]
    Seal(String),
    #[error(
        "l'identité protégée est illisible : elle a été scellée pour un autre compte ou une autre machine ({0})"
    )]
    Unseal(String),
}

/// Per-user protected store, backed by a sealed file.
///
/// The directory belongs to the user profile: DPAPI already binds the
/// ciphertext to the account, so the file location adds convenience, not
/// protection.
pub struct ProtectedIdentityStore {
    directory: PathBuf,
}

impl ProtectedIdentityStore {
    /// Store located in the OS's standard per-user data directory.
    ///
    /// `ORION_IDENTITY_DIR` overrides it, for tests and for an operator who
    /// wants to inspect what was written.
    pub fn for_current_user() -> Result<Self> {
        if let Ok(directory) = std::env::var("ORION_IDENTITY_DIR") {
            return Ok(Self::at(PathBuf::from(directory)));
        }
        let directories = directories::ProjectDirs::from("net", "helios", "orion")
            .context("impossible de déterminer le répertoire de données de l'OS")?;
        Ok(Self::at(directories.data_dir().join("identities")))
    }

    pub fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Path of a sealed identity.
    ///
    /// The name is reduced to ordinary characters, which at once removes
    /// separators, `..` and disguised extensions: an identity name comes from
    /// a document the operator wrote, and it must not be able to designate a
    /// file outside this directory.
    fn path_of(&self, identity: &str) -> Result<PathBuf> {
        let sanitized: String = identity
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .take(96)
            .collect();
        let sanitized = sanitized.trim_matches('.').to_string();
        if sanitized.is_empty() {
            anyhow::bail!("nom d'identité protégée inutilisable : « {identity} »");
        }
        Ok(self.directory.join(format!("{sanitized}{SEALED_SUFFIX}")))
    }

    /// Seals a bundle, replacing any identity of the same name.
    ///
    /// Replacement is the expected case — an identity is reissued when the
    /// certificate expires — and the write is atomic so a failure mid-way
    /// cannot leave a truncated blob where a valid one used to be.
    pub fn store(&self, bundle: &ClientIdentityBundle) -> Result<PathBuf> {
        bundle.validate()?;
        self.write_record(
            &bundle.identity,
            &ProtectedIdentityRecord::new(bundle.clone()),
        )
    }

    /// Opens a sealed identity.
    pub fn load(&self, identity: &str) -> Result<ClientIdentityBundle> {
        self.load_at(identity, unix_now()?)
    }

    /// Opens whichever bundle the local service selector names at this instant.
    pub fn load_at(&self, identity: &str, now_unix: u64) -> Result<ClientIdentityBundle> {
        Ok(self.snapshot_at(identity, now_unix)?.served)
    }

    /// Reads the served bundle and the bounded previous slot with one unseal.
    pub fn snapshot_at(&self, identity: &str, now_unix: u64) -> Result<IdentitySnapshot> {
        let record = self.read_record(identity)?;
        Ok(IdentitySnapshot {
            served: record.served_at(now_unix).clone(),
            previous: record.previous_status(now_unix),
        })
    }

    /// Replaces the served identity while retaining the outgoing one in the
    /// same sealed write for exactly the signed overlap window.
    pub(crate) fn promote_with_previous(
        &self,
        identity: &str,
        candidate: &ClientIdentityBundle,
        available_from: u64,
        available_until: u64,
    ) -> Result<bool> {
        let mut record = self.read_record(identity)?;
        let mut promoted = candidate.clone();
        promoted.identity = identity.trim().to_string();
        promoted.validate()?;
        if !record.promote(promoted, available_from, available_until)? {
            return Ok(false);
        }
        record.validate(identity)?;
        self.write_record(identity, &record)?;
        Ok(true)
    }

    /// Selects the outgoing bundle without changing either certificate state
    /// or generation counters.
    ///
    /// `validate` runs on the exact record that will be written. This lets the
    /// lifecycle compare both bundles with its authoritative active/next state
    /// before a restored or substituted file can move the service selector.
    pub(crate) fn select_previous<F>(
        &self,
        identity: &str,
        now_unix: u64,
        validate: F,
    ) -> Result<PreviousIdentityStatus>
    where
        F: FnOnce(&ClientIdentityBundle, &ClientIdentityBundle) -> Result<()>,
    {
        let mut record = self.read_record(identity)?;
        let previous = record
            .previous
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("aucune identité précédente n'est conservée"))?;
        validate(&record.current, &previous.bundle)?;
        let status = record.select_previous(now_unix)?;
        record.validate(identity)?;
        self.write_record(identity, &record)?;
        Ok(status)
    }

    /// Destroys an outgoing private identity once its overlap has ended.
    pub(crate) fn retire_previous(&self, identity: &str, now_unix: u64) -> Result<bool> {
        let mut record = self.read_record(identity)?;
        if !record.retire_previous(now_unix) {
            return Ok(false);
        }
        self.write_record(identity, &record)?;
        Ok(true)
    }

    fn read_record(&self, identity: &str) -> Result<ProtectedIdentityRecord> {
        let path = self.path_of(identity)?;
        let sealed =
            read_bounded(&path).map_err(|_| IdentityStoreError::NotFound(identity.to_string()))?;
        let plaintext = unseal(&sealed)?;
        let record = match serde_json::from_slice::<ProtectedIdentityRecord>(&plaintext) {
            Ok(record) => record,
            Err(record_error) => {
                // Compatibility with every identity sealed before the second
                // slot existed. A rewrite migrates it to the envelope; a read
                // never needs a destructive migration merely to connect.
                let bundle: ClientIdentityBundle = serde_json::from_slice(&plaintext).with_context(
                    || {
                        format!(
                            "l'identité descellée n'a ni le format courant ({record_error}) ni le format historique"
                        )
                    },
                )?;
                ProtectedIdentityRecord::new(bundle)
            }
        };
        record.validate(identity)?;
        Ok(record)
    }

    fn write_record(&self, identity: &str, record: &ProtectedIdentityRecord) -> Result<PathBuf> {
        record.validate(identity)?;
        let path = self.path_of(identity)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(record).context("encodage de l'identité avant scellement")?,
        );
        let sealed = seal(&plaintext)?;

        aether::private_file::create_private_dir(&self.directory)
            .with_context(|| format!("création de {}", self.directory.display()))?;
        aether::private_file::write_private_atomic(&path, &sealed)
            .with_context(|| format!("remplacement atomique de {}", path.display()))?;
        Ok(path)
    }

    /// Is an identity of this name already sealed on this machine?
    ///
    /// Answers without decrypting: the screen needs to know whether the
    /// import still has to happen, and that question must not depend on the
    /// user's session being able to unseal.
    pub fn contains(&self, identity: &str) -> bool {
        self.path_of(identity)
            .is_ok_and(|path| std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()))
    }
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("l'horloge système précède l'époque Unix")
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file =
        std::fs::File::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_SEALED_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("lecture de {}", path.display()))?;
    if bytes.len() > MAX_SEALED_BYTES {
        anyhow::bail!(
            "identité scellée anormalement volumineuse : {}",
            path.display()
        );
    }
    Ok(bytes)
}

// ─── Platform sealing ────────────────────────────────────────────────────────

/// Seals bytes for the current user.
#[cfg(windows)]
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: both blobs point at live slices for the duration of the call,
    // and the output blob is only read after a success return, then freed
    // exactly once.
    unsafe {
        let mut input = dpapi::DataBlob::over(plaintext);
        let mut entropy = dpapi::DataBlob::over(SEAL_ENTROPY);
        let mut output = dpapi::DataBlob::empty();
        let ok = dpapi::CryptProtectData(
            &mut input,
            std::ptr::null(),
            &mut entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dpapi::CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );
        if ok == 0 {
            return Err(IdentityStoreError::Seal(dpapi::last_error()).into());
        }
        Ok(output.take())
    }
}

/// Opens bytes sealed by [`seal`] on this machine, for this user.
#[cfg(windows)]
pub fn unseal(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // SAFETY: same contract as `seal`.
    unsafe {
        let mut input = dpapi::DataBlob::over(sealed);
        let mut entropy = dpapi::DataBlob::over(SEAL_ENTROPY);
        let mut output = dpapi::DataBlob::empty();
        let ok = dpapi::CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            &mut entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dpapi::CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );
        if ok == 0 {
            return Err(IdentityStoreError::Unseal(dpapi::last_error()).into());
        }
        Ok(Zeroizing::new(output.take()))
    }
}

#[cfg(not(windows))]
pub fn seal(_plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(IdentityStoreError::UnsupportedPlatform.into())
}

#[cfg(not(windows))]
pub fn unseal(_sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(IdentityStoreError::UnsupportedPlatform.into())
}

/// Minimal DPAPI bindings.
///
/// Declared here rather than pulled from `windows-sys`: three stable Win32
/// entry points do not justify a generated dependency, and the ABI of
/// `CryptProtectData` has not moved since Windows 2000. Keeping them local
/// also keeps the `unsafe` surface visible in one screen.
#[cfg(windows)]
mod dpapi {
    use std::ffi::c_void;

    /// Do not raise any UI: Orion may be running without an interactive
    /// desktop, and a blocked prompt would look like a hang.
    pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[repr(C)]
    pub struct DataBlob {
        pub cb_data: u32,
        pub pb_data: *mut u8,
    }

    impl DataBlob {
        /// Borrows a slice. The blob must not outlive it.
        pub fn over(bytes: &[u8]) -> Self {
            Self {
                cb_data: bytes.len() as u32,
                pb_data: bytes.as_ptr() as *mut u8,
            }
        }

        pub fn empty() -> Self {
            Self {
                cb_data: 0,
                pb_data: std::ptr::null_mut(),
            }
        }

        /// Copies the DPAPI-allocated buffer out and frees it.
        ///
        /// # Safety
        /// Only valid on a blob a successful DPAPI call has filled in.
        pub unsafe fn take(&mut self) -> Vec<u8> {
            if self.pb_data.is_null() {
                return Vec::new();
            }
            let bytes = std::slice::from_raw_parts(self.pb_data, self.cb_data as usize).to_vec();
            LocalFree(self.pb_data as *mut c_void);
            self.pb_data = std::ptr::null_mut();
            self.cb_data = 0;
            bytes
        }
    }

    pub fn last_error() -> String {
        // SAFETY: no arguments, no allocation, always callable.
        format!("code {}", unsafe { GetLastError() })
    }

    // Win32 names are imposed by the ABI: renaming them to snake_case would
    // simply fail to link.
    #[allow(non_snake_case)]
    #[link(name = "crypt32")]
    extern "system" {
        pub fn CryptProtectData(
            data_in: *mut DataBlob,
            description: *const u16,
            optional_entropy: *mut DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;

        pub fn CryptUnprotectData(
            data_in: *mut DataBlob,
            description: *mut *mut u16,
            optional_entropy: *mut DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[allow(non_snake_case)]
    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
        pub fn GetLastError() -> u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "orion-identity-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    fn bundle() -> ClientIdentityBundle {
        let encoder = base64::engine::general_purpose::STANDARD;
        ClientIdentityBundle {
            identity: "orion-portable".into(),
            certificate_chain: vec![encoder.encode([0x30, 0x82, 0x01, 0x00])],
            private_key: encoder.encode([0x30, 0x81, 0x87, 0x02]),
            pq_certificate: encoder.encode(br#"{"version":1}"#),
            pq_private_key: encoder.encode([7u8; 64]),
        }
    }

    /// A bundle that only failed at connection time would leave the user with
    /// a profile that looks imported and never connects.
    #[test]
    fn an_undecodable_bundle_is_refused_before_sealing() {
        for broken in [
            ClientIdentityBundle {
                identity: "  ".into(),
                ..bundle()
            },
            ClientIdentityBundle {
                certificate_chain: Vec::new(),
                ..bundle()
            },
            ClientIdentityBundle {
                certificate_chain: vec![String::new()],
                ..bundle()
            },
            ClientIdentityBundle {
                certificate_chain: vec!["not base64".into()],
                ..bundle()
            },
            ClientIdentityBundle {
                private_key: "pas du base64 !".into(),
                ..bundle()
            },
            ClientIdentityBundle {
                private_key: String::new(),
                ..bundle()
            },
            ClientIdentityBundle {
                pq_certificate: String::new(),
                ..bundle()
            },
            ClientIdentityBundle {
                pq_private_key: String::new(),
                ..bundle()
            },
            ClientIdentityBundle {
                pq_private_key: "not base64".into(),
                ..bundle()
            },
            // Decodable base64, but not the JSON document a PQ certificate is.
            ClientIdentityBundle {
                pq_certificate: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                ..bundle()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?} should be refused");
        }
        assert!(bundle().validate().is_ok());
    }

    #[test]
    fn debug_never_prints_private_material() {
        let bundle = bundle();
        let rendered = format!("{bundle:?}");

        assert!(rendered.contains("orion-portable"));
        assert!(rendered.contains("private_key: \"***\""));
        assert!(rendered.contains("pq_private_key: \"***\""));
        assert!(!rendered.contains(&bundle.private_key));
        assert!(!rendered.contains(&bundle.pq_private_key));
    }

    #[test]
    fn serialized_bundles_reject_unknown_fields() {
        let mut value = serde_json::to_value(bundle()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<ClientIdentityBundle>(value).is_err());
    }

    /// The identity name comes from an operator-written document: it must not
    /// be able to designate a file outside the store.
    #[test]
    fn an_identity_name_cannot_escape_the_store_directory() {
        let store = ProtectedIdentityStore::at(PathBuf::from("/var/lib/orion"));

        for hostile in ["../../etc/passwd", "..", "a/b", r"..\\windows"] {
            // Refusing outright is just as good as sanitizing: nothing is
            // written either way. What must never happen is a path that
            // leaves the store directory.
            if let Ok(path) = store.path_of(hostile) {
                assert_eq!(
                    path.parent(),
                    Some(Path::new("/var/lib/orion")),
                    "{hostile} escaped the store"
                );
                assert!(!path.to_string_lossy().contains(".."));
            }
        }
        assert_eq!(
            store.path_of("orion-portable").unwrap(),
            Path::new("/var/lib/orion/orion-portable.identity")
        );
        assert!(store.path_of("...").is_err());

        let long = "a".repeat(128);
        let path = store.path_of(&long).unwrap();
        assert_eq!(
            path.file_stem().unwrap().to_string_lossy().len(),
            96,
            "identity filenames are bounded"
        );
    }

    #[test]
    fn contains_only_accepts_a_regular_identity_file() {
        let directory = test_directory("contains");
        std::fs::create_dir_all(&directory).unwrap();
        let store = ProtectedIdentityStore::at(directory.clone());
        let path = store.path_of("portable").unwrap();

        assert!(!store.contains("portable"));
        std::fs::create_dir(&path).unwrap();
        assert!(
            !store.contains("portable"),
            "a directory is not a sealed identity"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, b"sealed").unwrap();
        assert!(store.contains("portable"));

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn bounded_reads_distinguish_the_limit_from_an_oversized_blob() {
        let directory = test_directory("bounded");
        std::fs::create_dir_all(&directory).unwrap();
        let exact = directory.join("exact.identity");
        let oversized = directory.join("oversized.identity");
        std::fs::write(&exact, vec![0x5a; MAX_SEALED_BYTES]).unwrap();
        std::fs::write(&oversized, vec![0x5a; MAX_SEALED_BYTES + 1]).unwrap();

        assert_eq!(read_bounded(&exact).unwrap().len(), MAX_SEALED_BYTES);
        let error = read_bounded(&oversized).expect_err("oversized identity must be refused");
        assert!(error.to_string().contains("anormalement volumineuse"));
        assert!(read_bounded(&directory.join("missing.identity")).is_err());

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn promotion_keeps_the_outgoing_bundle_until_the_overlap_ends() {
        let outgoing = bundle();
        let mut incoming = outgoing.clone();
        incoming.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
        let mut record = ProtectedIdentityRecord::new(outgoing.clone());

        assert!(record
            .promote(incoming.clone(), 2_000, 3_000)
            .expect("promoted"));
        assert_eq!(record.current, incoming);
        assert_eq!(
            record.previous.as_ref().map(|slot| &slot.bundle),
            Some(&outgoing)
        );
        assert_eq!(
            record.previous_status(2_000).map(|status| status.phase),
            Some(PreviousIdentityPhase::Available)
        );

        record
            .select_previous(2_100)
            .expect("selected during overlap");
        assert_eq!(record.served_at(2_100), &outgoing);
        assert_eq!(
            record.previous_status(2_100).map(|status| status.selected),
            Some(true)
        );

        assert_ne!(record.served_at(3_000), &outgoing);
        assert!(record.select_previous(3_000).is_err());
        assert!(record.retire_previous(3_000));
        assert!(record.previous.is_none());
        assert!(!record.serve_previous);
        let retired_record = serde_json::to_string(&record).expect("serialized tombstone");
        assert!(!retired_record.contains(&outgoing.pq_private_key));
        assert_eq!(
            record.previous_status(3_001).map(|status| status.phase),
            Some(PreviousIdentityPhase::Expired)
        );
    }

    #[test]
    fn replaying_promotion_preserves_an_explicit_service_rollback() {
        let outgoing = bundle();
        let mut incoming = outgoing.clone();
        incoming.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
        let mut record = ProtectedIdentityRecord::new(outgoing.clone());
        record
            .promote(incoming.clone(), 2_000, 3_000)
            .expect("promoted");
        record.select_previous(2_100).expect("selected");

        assert!(!record
            .promote(incoming, 2_000, 3_000)
            .expect("idempotent promotion"));
        assert_eq!(record.served_at(2_200), &outgoing);
    }

    #[test]
    fn a_second_previous_slot_is_refused_while_the_first_is_live() {
        let outgoing = bundle();
        let mut first = outgoing.clone();
        first.pq_private_key = base64::engine::general_purpose::STANDARD.encode([8u8; 64]);
        let mut second = outgoing.clone();
        second.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
        let mut record = ProtectedIdentityRecord::new(outgoing);
        record.promote(first, 2_000, 3_000).expect("first");

        assert!(record.promote(second, 2_500, 4_000).is_err());
    }

    #[test]
    fn loading_an_absent_identity_reports_its_name() {
        let store = ProtectedIdentityStore::at(test_directory("missing"));
        let error = store.load("workstation").expect_err("identity is absent");
        assert!(
            error.downcast_ref::<IdentityStoreError>().is_some_and(
                |error| matches!(error, IdentityStoreError::NotFound(name) if name == "workstation")
            ),
            "unexpected error: {error}"
        );
    }

    /// Exercises the actual Windows account boundary rather than the
    /// non-Windows refusal compiled on the Linux runner.
    #[cfg(windows)]
    #[test]
    fn dpapi_sealing_round_trips_and_hides_the_plaintext() {
        let plaintext = b"orion identity private material";
        let sealed = seal(plaintext).expect("DPAPI must seal for the current test account");

        assert_ne!(sealed, plaintext);
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|window| window == plaintext),
            "the DPAPI envelope must not contain the plaintext"
        );
        assert_eq!(unseal(&sealed).unwrap().as_slice(), plaintext);
    }

    /// Covers validation, DPAPI, the atomic replacement and decoding as one
    /// operation on the platform Orion actually ships for.
    #[cfg(windows)]
    #[test]
    fn protected_store_round_trips_and_replaces_an_identity() {
        let directory = test_directory("windows-round-trip");
        let store = ProtectedIdentityStore::at(directory.clone());
        let first = bundle();

        let path = store.store(&first).unwrap();
        let ciphertext = std::fs::read(&path).unwrap();
        assert!(!ciphertext
            .windows(first.private_key.len())
            .any(|window| { window == first.private_key.as_bytes() }));
        assert!(store.contains(&first.identity));
        let loaded = store.load(&first.identity).unwrap();
        assert_eq!(loaded.private_key, first.private_key);
        assert_eq!(loaded.pq_private_key, first.pq_private_key);

        let mut replacement = first;
        replacement.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
        store.store(&replacement).unwrap();
        assert_eq!(
            store.load(&replacement.identity).unwrap().pq_private_key,
            replacement.pq_private_key
        );
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));

        std::fs::remove_dir_all(directory).unwrap();
    }

    /// DPAPI authentication must turn a modified blob into an explicit
    /// decryption failure, never partially decoded identity material.
    #[cfg(windows)]
    #[test]
    fn a_tampered_identity_blob_is_refused() {
        let directory = test_directory("windows-tamper");
        let store = ProtectedIdentityStore::at(directory.clone());
        let identity = bundle();
        let path = store.store(&identity).unwrap();
        let mut sealed = std::fs::read(&path).unwrap();
        let last = sealed.last_mut().expect("DPAPI produced a non-empty blob");
        *last ^= 0x80;
        std::fs::write(&path, sealed).unwrap();

        let error = store
            .load(&identity.identity)
            .expect_err("modified DPAPI material must not open");
        assert!(
            error
                .downcast_ref::<IdentityStoreError>()
                .is_some_and(|error| matches!(error, IdentityStoreError::Unseal(_))),
            "unexpected error: {error}"
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    /// The refusal must be explicit rather than a silent plaintext fallback:
    /// a screen promising a protected store must not be served by a file
    /// anyone can read.
    #[cfg(not(windows))]
    #[test]
    fn sealing_fails_loudly_where_no_protected_store_exists() {
        let error = seal(b"secret").expect_err("no protected store outside Windows");
        assert!(
            error
                .downcast_ref::<IdentityStoreError>()
                .is_some_and(|e| matches!(e, IdentityStoreError::UnsupportedPlatform)),
            "unexpected error: {error}"
        );
        assert!(unseal(b"secret").is_err());
    }

    /// Storing must not write anything when the platform cannot seal: a
    /// plaintext bundle left behind would be worse than no import at all.
    #[cfg(not(windows))]
    #[test]
    fn a_refused_seal_leaves_no_file_behind() {
        let directory = test_directory("refused-seal");
        let store = ProtectedIdentityStore::at(directory.clone());

        assert!(store.store(&bundle()).is_err());
        assert!(!store.contains("orion-portable"));
        assert!(
            std::fs::read_dir(&directory).is_err(),
            "nothing must have been created"
        );
    }
}
