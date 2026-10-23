//! The operator's registry of enrollment invitations (spec §15.2).
//!
//! One file per invitation under `~/.helios/enrollment-invitations`, private
//! from creation. Each holds the public invitation, its state — `issued`,
//! `consumed`, `revoked`, `expired` — and, while it is `issued` and only then,
//! the private half of the X25519 key the WireGuard proof is made against.
//!
//! The property this exists for is **single use**: an invitation is marked
//! `consumed`, and that state reaches the disk, *before* anything is issued
//! for it. A failure afterwards needs a new invitation; nothing ever reopens
//! the old one, and the key that would let anyone verify a second proof
//! against it is gone with the same write.

use std::{
    fs,
    path::{Path, PathBuf},
};

use aether::certificates::encoding::{Fingerprint, Id16, WireGuardKey};
use aether::key_negotiation::{verify_wireguard_proof, EnrollmentInvitation, EnrollmentRequest};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Overrides [`InvitationRegistry::default_location`], for tests and for an
/// operator who keeps the registry beside a vault elsewhere.
pub const REGISTRY_ENV: &str = "HELIOS_ENROLLMENT_REGISTRY";

/// Largest record the registry reads back: an invitation is about 7 KiB.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Where an invitation stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum InvitationState {
    Issued,
    Consumed {
        request_fingerprint: Fingerprint,
        client_wg_public_key: WireGuardKey,
        consumed_at_unix: u64,
    },
    Revoked {
        at_unix: u64,
    },
    Expired {
        at_unix: u64,
    },
}

impl InvitationState {
    /// French label, for listings.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Issued => "émise",
            Self::Consumed { .. } => "consommée",
            Self::Revoked { .. } => "révoquée",
            Self::Expired { .. } => "expirée",
        }
    }
}

/// An invitation and its state. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRecord {
    pub invitation: EnrollmentInvitation,
    pub state: InvitationState,
}

/// What [`InvitationRegistry::consume`] hands back once the consumption is on
/// disk.
#[derive(Debug, Clone)]
pub struct ConsumedInvitation {
    pub invitation: EnrollmentInvitation,
    pub request_fingerprint: Fingerprint,
}

/// The on-disk record. The only type here that holds the proof key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    invitation: EnrollmentInvitation,
    state: InvitationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_private_key: Option<ProofKey>,
}

/// The X25519 private key of an invitation's WireGuard proof.
///
/// Serialized because the registry must hold it between `invite` and
/// `accept` (§15.2), and only into the registry's own `0600` file.
struct ProofKey(Zeroizing<[u8; 32]>);

impl Serialize for ProofKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(*self.0));
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for ProofKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| D::Error::custom("invalid proof key"))?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        if decoded.len() != key.len() {
            return Err(D::Error::custom("invalid proof key"));
        }
        key.copy_from_slice(&decoded);
        Ok(Self(key))
    }
}

/// The directory of invitation records.
#[derive(Debug, Clone)]
pub struct InvitationRegistry {
    directory: PathBuf,
}

impl InvitationRegistry {
    /// `$HELIOS_ENROLLMENT_REGISTRY`, else `~/.helios/enrollment-invitations`
    /// (`%APPDATA%\helios\enrollment-invitations` on Windows).
    pub fn default_location() -> Result<Self> {
        if let Some(directory) = std::env::var_os(REGISTRY_ENV) {
            return Ok(Self::at(PathBuf::from(directory)));
        }
        let base = if cfg!(windows) {
            std::env::var_os("APPDATA")
                .map(|base| PathBuf::from(base).join("helios"))
                .context("APPDATA n'est pas défini : impossible de situer le registre")?
        } else {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".helios"))
                .context("HOME n'est pas défini : impossible de situer le registre")?
        };
        Ok(Self::at(base.join("enrollment-invitations")))
    }

    pub fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn path_of(&self, id: &Id16) -> PathBuf {
        self.directory.join(format!("{}.json", id.to_hex()))
    }

    /// Records a freshly signed invitation with its proof key.
    ///
    /// Refuses an identifier already present: two invitations under one id
    /// would share one consumption.
    pub fn issue(
        &self,
        invitation: &EnrollmentInvitation,
        proof_private_key: Zeroizing<[u8; 32]>,
    ) -> Result<()> {
        aether::private_file::create_private_dir(&self.directory)
            .with_context(|| format!("création de {}", self.directory.display()))?;
        let path = self.path_of(&invitation.invitation_id);
        if fs::symlink_metadata(&path).is_ok() {
            bail!(
                "une invitation {} existe déjà dans le registre",
                invitation.invitation_id
            );
        }
        self.write(
            &invitation.invitation_id,
            &RecordFile {
                invitation: invitation.clone(),
                state: InvitationState::Issued,
                proof_private_key: Some(ProofKey(proof_private_key)),
            },
        )
    }

    /// Reads one record, without its secret.
    pub fn load(&self, id: &Id16) -> Result<InvitationRecord> {
        let record = self.read(id)?;
        Ok(InvitationRecord {
            invitation: record.invitation,
            state: record.state,
        })
    }

    /// Every record, after marking the lapsed ones `expired` — which destroys
    /// their proof key.
    pub fn list(&self, now_unix: u64) -> Result<Vec<InvitationRecord>> {
        let mut records = Vec::new();
        for id in self.ids()? {
            let mut record = self.read(&id)?;
            if record.state == InvitationState::Issued
                && now_unix > record.invitation.not_after_unix
            {
                record = self.expire(&id, record, now_unix)?;
            }
            records.push(InvitationRecord {
                invitation: record.invitation,
                state: record.state,
            });
        }
        records.sort_by_key(|record| record.invitation.not_before_unix);
        Ok(records)
    }

    /// Verifies a request and consumes its invitation, in the order of §15.2.
    ///
    /// Signed, aimed, alive and still `issued`; the request's self-signature
    /// and CSR; the WireGuard proof; then the readmission policy. Only then is
    /// the invitation written `consumed`, its proof key dropped, and the write
    /// synchronized. Returning `Ok` means that state is durable.
    pub fn consume(
        &self,
        id: &Id16,
        request: &EnrollmentRequest,
        now_unix: u64,
    ) -> Result<ConsumedInvitation> {
        let _lock = ConsumptionLock::take(self, id)?;
        let record = self.read(id)?;
        if record.state != InvitationState::Issued {
            bail!(
                "l'invitation {id} est {} : elle n'admet plus aucune demande",
                record.state.label()
            );
        }
        let invitation = record.invitation.clone();
        if now_unix > invitation.not_after_unix {
            self.expire(id, record, now_unix)?;
            bail!("l'invitation {id} a expiré : en émettre une nouvelle");
        }
        invitation
            .verify(&invitation.operator_ca_public_key, now_unix)
            .context("l'invitation enregistrée ne vérifie plus")?;
        request
            .verify(&invitation)
            .context("la demande ne correspond pas à cette invitation")?;
        let proof_key = record
            .proof_private_key
            .as_ref()
            .context("le registre ne détient plus la clé de preuve de cette invitation")?;
        verify_wireguard_proof(&proof_key.0, &invitation, request)
            .context("la preuve de possession WireGuard ne vérifie pas")?;
        if !invitation.allow_readmission && self.readmits(&request.client_wg_public_key)? {
            bail!(
                "la clé WireGuard {} a déjà été enrôlée : sa réadmission exige une invitation \
                 émise avec --allow-readmission",
                request.client_wg_public_key
            );
        }

        let request_fingerprint = request.fingerprint();
        self.write(
            id,
            &RecordFile {
                invitation: invitation.clone(),
                state: InvitationState::Consumed {
                    request_fingerprint,
                    client_wg_public_key: request.client_wg_public_key,
                    consumed_at_unix: now_unix,
                },
                proof_private_key: None,
            },
        )?;
        Ok(ConsumedInvitation {
            invitation,
            request_fingerprint,
        })
    }

    /// Revokes an invitation that has not been consumed.
    pub fn revoke(&self, id: &Id16, now_unix: u64) -> Result<()> {
        let _lock = ConsumptionLock::take(self, id)?;
        let record = self.read(id)?;
        if !matches!(record.state, InvitationState::Issued) {
            bail!(
                "l'invitation {id} est {} : il n'y a plus rien à révoquer",
                record.state.label()
            );
        }
        self.write(
            id,
            &RecordFile {
                invitation: record.invitation,
                state: InvitationState::Revoked { at_unix: now_unix },
                proof_private_key: None,
            },
        )
    }

    /// Whether some consumed invitation already enrolled this WireGuard key.
    pub fn readmits(&self, key: &WireGuardKey) -> Result<bool> {
        for id in self.ids()? {
            if let InvitationState::Consumed {
                client_wg_public_key,
                ..
            } = self.read(&id)?.state
            {
                if &client_wg_public_key == key {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn expire(&self, id: &Id16, record: RecordFile, now_unix: u64) -> Result<RecordFile> {
        let expired = RecordFile {
            invitation: record.invitation,
            state: InvitationState::Expired { at_unix: now_unix },
            proof_private_key: None,
        };
        self.write(id, &expired)?;
        Ok(expired)
    }

    fn ids(&self) -> Result<Vec<Id16>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("lecture de {}", self.directory.display()))
            }
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry =
                entry.with_context(|| format!("lecture de {}", self.directory.display()))?;
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if let Ok(id) = Id16::parse_hex(stem) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    fn read(&self, id: &Id16) -> Result<RecordFile> {
        let path = self.path_of(id);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("aucune invitation {id} dans le registre"))?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
            bail!("{} n'est pas une invitation du registre", path.display());
        }
        let bytes = Zeroizing::new(
            fs::read(&path).with_context(|| format!("lecture de {}", path.display()))?,
        );
        let record: RecordFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} n'est pas une invitation lisible", path.display()))?;
        if &record.invitation.invitation_id != id {
            bail!(
                "{} porte l'invitation {} : le registre a été altéré",
                path.display(),
                record.invitation.invitation_id
            );
        }
        if (record.state == InvitationState::Issued) != record.proof_private_key.is_some() {
            bail!(
                "{} : une invitation émise détient sa clé de preuve, et elle seule",
                path.display()
            );
        }
        Ok(record)
    }

    fn write(&self, id: &Id16, record: &RecordFile) -> Result<()> {
        let path = self.path_of(id);
        let bytes = Zeroizing::new(
            serde_json::to_vec_pretty(record).context("sérialisation de l'invitation")?,
        );
        aether::private_file::write_private_atomic(&path, &bytes)
            .with_context(|| format!("écriture de {}", path.display()))
    }
}

/// Serializes the decisions taken on one invitation across processes.
///
/// Two `accept` run at once on the same invitation would both read `issued`.
/// The lock is a file created exclusively; one left behind by a crash is
/// named in the refusal so the operator can remove it once nothing runs.
struct ConsumptionLock {
    path: PathBuf,
}

impl ConsumptionLock {
    fn take(registry: &InvitationRegistry, id: &Id16) -> Result<Self> {
        if fs::symlink_metadata(registry.path_of(id)).is_err() {
            bail!("aucune invitation {id} dans le registre");
        }
        let path = registry.directory.join(format!("{}.lock", id.to_hex()));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "l'invitation {id} est déjà en cours de traitement ({} existe ; le supprimer \
                     si aucune autre commande ne tourne)",
                    path.display()
                )
            })?;
        Ok(Self { path })
    }
}

impl Drop for ConsumptionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
