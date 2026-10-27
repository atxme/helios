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

use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, WireGuardKey};
use aether::key_negotiation::{
    verify_wireguard_proof, EnrollmentInvitation, EnrollmentRequest, PqCertificate,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Overrides [`InvitationRegistry::default_location`], for tests and for an
/// operator who keeps the registry beside a vault elsewhere.
pub const REGISTRY_ENV: &str = "HELIOS_ENROLLMENT_REGISTRY";

/// Largest record the registry reads back: an invitation is about 7 KiB.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Largest accepted-enrollment file read back: a request and two certificates.
const MAX_ACCEPTED_BYTES: u64 = 256 * 1024;

/// Where an invitation stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum InvitationState {
    Issued,
    Consumed {
        request_id: Id16,
        request_fingerprint: Fingerprint,
        client_wg_public_key: WireGuardKey,
        consumed_at_unix: u64,
        /// The leaves issued for this request, once they exist. A document is
        /// signed only around these.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issued: Option<IssuedLeafFingerprints>,
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

/// The two leaves an accepted request received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedLeafFingerprints {
    pub tls_certificate: Fingerprint,
    pub pq_certificate: Fingerprint,
}

/// An accepted request and the two leaves issued for it, kept so a gesture
/// interrupted after issuance resumes without issuing again. Public material
/// only: the request and public certificates carry no private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedEnrollment {
    pub request: EnrollmentRequest,
    pub tls_certificate: DerCertificate,
    pub pq_certificate: PqCertificate,
}

impl AcceptedEnrollment {
    fn fingerprints(&self) -> Result<IssuedLeafFingerprints> {
        Ok(IssuedLeafFingerprints {
            tls_certificate: self.tls_certificate.fingerprint(),
            pq_certificate: aether::certificates::gateway::pq_certificate_fingerprint(
                &self.pq_certificate,
            )?,
        })
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

impl RecordFile {
    /// Still `issued`, past its window.
    fn lapsed(&self, now_unix: u64) -> bool {
        self.state == InvitationState::Issued && now_unix > self.invitation.not_after_unix
    }
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
        self.purge_lapsed(now_unix)?;
        let mut records = Vec::new();
        for id in self.ids()? {
            let record = self.read(&id)?;
            records.push(InvitationRecord {
                invitation: record.invitation,
                state: record.state,
            });
        }
        records.sort_by_key(|record| record.invitation.not_before_unix);
        Ok(records)
    }

    /// Marks every lapsed `issued` invitation `expired`, destroying its proof
    /// key (§15.2).
    ///
    /// No process watches the registry between two commands, so each command
    /// that opens it calls this first: the key outlives its invitation only
    /// until the next one. Each record is rewritten under its consumption
    /// lock and re-read there. One another command holds is left to it: that
    /// command decides its state, and an `expired` written over its
    /// `consumed` would forget a key that was enrolled.
    pub fn purge_lapsed(&self, now_unix: u64) -> Result<()> {
        for id in self.ids()? {
            if !self.read(&id)?.lapsed(now_unix) {
                continue;
            }
            let Ok(_lock) = ConsumptionLock::take(self, &id) else {
                continue;
            };
            let record = self.read(&id)?;
            if record.lapsed(now_unix) {
                self.expire(&id, record, now_unix)?;
            }
        }
        Ok(())
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
        self.purge_lapsed(now_unix)?;
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
                    request_id: request.request_id,
                    request_fingerprint,
                    client_wg_public_key: request.client_wg_public_key,
                    consumed_at_unix: now_unix,
                    issued: None,
                },
                proof_private_key: None,
            },
        )?;
        Ok(ConsumedInvitation {
            invitation,
            request_fingerprint,
        })
    }

    /// Records the leaves issued for a consumed invitation. Once.
    pub fn record_issued(&self, id: &Id16, leaves: IssuedLeafFingerprints) -> Result<()> {
        let _lock = ConsumptionLock::take(self, id)?;
        let mut record = self.read(id)?;
        match &mut record.state {
            InvitationState::Consumed { issued, .. } if issued.is_none() => {
                *issued = Some(leaves);
            }
            InvitationState::Consumed { .. } => {
                bail!("des feuilles ont déjà été émises pour l'invitation {id}")
            }
            other => bail!(
                "l'invitation {id} est {} : aucune feuille ne peut lui être rattachée",
                other.label()
            ),
        }
        self.write(id, &record)
    }

    /// Revokes an invitation that has not been consumed.
    /// Keeps the accepted request and its leaves beside the invitation.
    ///
    /// Refused unless the invitation is `consumed` with `issued` equal to the
    /// fingerprints of these very leaves.
    pub fn store_accepted(&self, id: &Id16, accepted: &AcceptedEnrollment) -> Result<()> {
        let _lock = ConsumptionLock::take(self, id)?;
        self.check_accepted(id, accepted)?;
        let path = self.accepted_path_of(id);
        let bytes =
            serde_json::to_vec_pretty(accepted).context("sérialisation de la demande acceptée")?;
        aether::private_file::write_private_atomic(&path, &bytes)
            .with_context(|| format!("écriture de {}", path.display()))
    }

    /// The accepted request and leaves kept for this invitation, if any.
    ///
    /// A file that does not match the record is an error, never an offer.
    pub fn accepted(&self, id: &Id16) -> Result<Option<AcceptedEnrollment>> {
        let path = self.accepted_path_of(id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("lecture de {}", path.display()))
            }
        };
        if !metadata.is_file() || metadata.len() > MAX_ACCEPTED_BYTES {
            bail!(
                "{} n'est pas une demande acceptée du registre",
                path.display()
            );
        }
        let bytes = fs::read(&path).with_context(|| format!("lecture de {}", path.display()))?;
        let accepted: AcceptedEnrollment = serde_json::from_slice(&bytes).with_context(|| {
            format!("{} n'est pas une demande acceptée lisible", path.display())
        })?;
        self.check_accepted(id, &accepted)?;
        Ok(Some(accepted))
    }

    fn accepted_path_of(&self, id: &Id16) -> PathBuf {
        self.directory
            .join(format!("{}.accepted.json", id.to_hex()))
    }

    fn check_accepted(&self, id: &Id16, accepted: &AcceptedEnrollment) -> Result<()> {
        let record = self.read(id)?;
        let InvitationState::Consumed {
            request_fingerprint,
            issued,
            ..
        } = &record.state
        else {
            bail!(
                "l'invitation {id} est {} : aucune demande acceptée ne peut lui être rattachée",
                record.state.label()
            );
        };
        if accepted.request.invitation_id != *id
            || accepted.request.fingerprint() != *request_fingerprint
        {
            bail!("la demande acceptée ne correspond pas à l'invitation {id}");
        }
        if *issued != Some(accepted.fingerprints()?) {
            bail!("les feuilles de l'invitation {id} ne correspondent pas à l'enregistrement");
        }
        Ok(())
    }

    pub fn revoke(&self, id: &Id16, now_unix: u64) -> Result<()> {
        self.purge_lapsed(now_unix)?;
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
