//! The encrypted vault copy, and the credential document, replaced through the
//! tunnel (spec §5.9).
//!
//! Astra cannot open the vault, so what it checks is what it can read without a
//! key: that the bytes name this domain. A tunnel administrator can therefore
//! replace the backup, and cannot open the vault or sign anything; the previous
//! copy kept beside it and the door's log limit that risk, they do not remove
//! it.

use std::path::Path;

use aether::certificates::approval::CredentialRegistry;
use aether::certificates::encoding::{Fingerprint, TrustDomainId};
use astra_channel::MAX_OPERATOR_VAULT_COPY_BYTES;
use serde::{Deserialize, Serialize};

use super::{DoorOutcome, DoorRefusal};
use crate::service::{
    verify_credentials, AstraService, CREDENTIALS_FILE, PREVIOUS_VAULT_FILE, VAULT_FILE,
};

/// The encrypted vault as it crosses the door.
///
/// Its own type for one reason: [`super::DoorRequest`] derives `Debug`, and a
/// `Vec<u8>` prints every byte. The door logs the action name alone today, but
/// a vault that reaches a log by the next `{request:?}` somebody writes is a
/// leak the type system can prevent, so it prints its length and nothing else.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VaultBytes(Vec<u8>);

impl From<Vec<u8>> for VaultBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for VaultBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "VaultBytes({} bytes)", self.0.len())
    }
}

/// What a vault shows without a key: enough to tell whose it is.
#[derive(Deserialize)]
struct VaultHeader {
    format_version: u16,
    trust_domain_id: TrustDomainId,
}

impl AstraService {
    /// Replaces the vault copy and, when one is sent, the credential document.
    ///
    /// Every check runs before anything is written, so a refusal leaves both
    /// files and the memory as they were. Under the volume gate, and with the
    /// registry held, so that a rotation cannot start between the check that
    /// none is in flight and the write.
    pub(super) async fn copy_vault(
        &self,
        vault: VaultBytes,
        credentials: Option<Box<CredentialRegistry>>,
    ) -> Result<DoorOutcome, DoorRefusal> {
        let vault = vault.0;
        let _volume = self.volume_writes.lock().await;
        let registry = self.registry.lock().await;

        if vault.len() > MAX_OPERATOR_VAULT_COPY_BYTES {
            return Err(DoorRefusal::VaultCopyRefused);
        }
        let Ok(header) = serde_json::from_slice::<VaultHeader>(&vault) else {
            return Err(DoorRefusal::VaultCopyRefused);
        };
        if header.format_version == 0 || header.trust_domain_id != registry.state().trust_domain_id
        {
            return Err(DoorRefusal::VaultCopyRefused);
        }

        let adopted = match credentials {
            Some(document) => {
                if registry.state().ca_rotation.is_some() {
                    return Err(DoorRefusal::CredentialsDuringRotation);
                }
                if document.credential_registry_epoch < self.approval_credentials().epoch {
                    return Err(DoorRefusal::CredentialsRollback);
                }
                if let Err(error) = verify_credentials(&document, &registry) {
                    tracing::warn!(%error, "the credential document sent with a vault copy does not verify");
                    return Err(DoorRefusal::VaultCopyRefused);
                }
                let encoded = serde_json::to_vec_pretty(&document).map_err(|error| {
                    tracing::error!(%error, "could not encode the credential document");
                    DoorRefusal::NotRecorded
                })?;
                Some((document, encoded))
            }
            None => None,
        };

        // The previous copy first: a crash after it leaves the old vault and a
        // backup of it; a crash after the next write leaves the new vault and
        // the old one beside it.
        if let Some(held) = self.encrypted_vault() {
            write_file(&self.state_dir, PREVIOUS_VAULT_FILE, &held)?;
        }
        write_file(&self.state_dir, VAULT_FILE, &vault)?;
        if let Some((_, encoded)) = &adopted {
            write_file(&self.state_dir, CREDENTIALS_FILE, encoded)?;
        }

        let fingerprint = Fingerprint::of(&vault);
        *self
            .encrypted_vault
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::sync::Arc::new(vault));
        if let Some((document, _)) = adopted {
            *self
                .approval_credentials
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                std::sync::Arc::new(crate::service::ApprovalCredentials::from_document(document));
        }
        drop(registry);

        Ok(DoorOutcome::VaultCopied {
            fingerprint,
            credential_registry_epoch: self
                .approval_credentials()
                .registry
                .as_ref()
                .map(|document| document.credential_registry_epoch),
        })
    }
}

fn write_file(state_dir: &Path, name: &str, bytes: &[u8]) -> Result<(), DoorRefusal> {
    let path = state_dir.join(name);
    aether::private_file::write_private_atomic(&path, bytes).map_err(|error| {
        tracing::error!(%error, path = %path.display(), "could not write the vault copy files");
        DoorRefusal::NotRecorded
    })
}
