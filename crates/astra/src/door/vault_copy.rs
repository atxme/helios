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

use super::{DoorConnector, DoorOutcome, DoorRefusal};
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

/// What a vault shows without a key: enough to tell whose it is, and which
/// write it is. The revision is absent from a vault written before it existed,
/// which reads as zero.
#[derive(Deserialize)]
struct VaultHeader {
    format_version: u16,
    trust_domain_id: TrustDomainId,
    #[serde(default)]
    revision: u64,
}

/// The revision a copy names in its header, or zero when the header does not
/// read: an unreadable copy is one Astra holds nothing against.
pub(crate) fn revision_of(vault: &[u8]) -> u64 {
    serde_json::from_slice::<VaultHeader>(vault).map_or(0, |header| header.revision)
}

/// Whether two documents are the same JSON value, whatever their layout or key
/// order. Unreadable either way is a difference.
fn same_json_value(left: &[u8], right: &[u8]) -> bool {
    match (
        serde_json::from_slice::<serde_json::Value>(left),
        serde_json::from_slice::<serde_json::Value>(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

impl AstraService {
    /// Replaces the vault copy and, when one is sent, the credential document.
    ///
    /// A copy other than the one held is taken only when its revision is newer
    /// than the held one's, or when it is the same vault at the same revision
    /// in another layout. A held copy at zero, or unreadable, takes any. With
    /// `replace_newer`, the held copy is replaced whatever the revision, and
    /// the replacement is logged as forced.
    ///
    /// Every check runs before anything is written, so a refusal leaves both
    /// files and the memory as they were. Under the volume gate, and with the
    /// registry held, so that a rotation cannot start between the check that
    /// none is in flight and the write.
    pub(super) async fn copy_vault(
        &self,
        connector: &DoorConnector,
        vault: VaultBytes,
        credentials: Option<Box<CredentialRegistry>>,
        now_unix: u64,
        replace_newer: bool,
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

        let fingerprint = Fingerprint::of(&vault);
        let mut forced = false;
        let held = self.encrypted_vault();
        let unchanged = held
            .as_ref()
            .is_some_and(|held| Fingerprint::of(held) == fingerprint);
        // Only a different copy can be late or diverging: the identical one is
        // what a retry sends, and it passes whatever it names.
        if !unchanged {
            let held_revision = held.as_ref().map_or(0, |held| revision_of(held));
            let sent_revision = header.revision;
            // At the same revision the same vault may only be laid out
            // differently (pretty-printed by hand on the volume, compact from
            // Orion): that is not a fork, and the copy normalizes the layout.
            let same_content = sent_revision == held_revision
                && held
                    .as_ref()
                    .is_some_and(|held| same_json_value(held, &vault));
            if held_revision > 0 && sent_revision <= held_revision && !same_content {
                tracing::warn!(
                    connector = %connector,
                    %fingerprint,
                    held_revision,
                    sent_revision,
                    late = sent_revision < held_revision,
                    "vault copy behind or diverging from the one held"
                );
                if !replace_newer {
                    return Err(DoorRefusal::VaultCopyStale);
                }
                forced = true;
            }
        }
        // An operation signed the fingerprint of the vault it will download.
        // Replacing the vault under it turns that download into an error until
        // the operation expires, and blocks its family meanwhile. Registry
        // then signing: no path takes them the other way round.
        if !unchanged {
            if let Some(operation_id) = self
                .signing
                .lock()
                .await
                .awaiting_operator_with_vault(now_unix)
            {
                return Err(DoorRefusal::AlreadyOpen { operation_id });
            }
        }

        let adopted = match credentials {
            Some(document) => {
                // A promotion's document still pending is the next one to be
                // adopted: a copy now could outrank it and be overwritten by
                // it, or make its adoption fail, at the next start.
                if registry.state().ca_rotation.is_some()
                    || registry.state().promoted_credentials.is_some()
                {
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
        // the old one beside it. An identical copy, a retry after a lost
        // answer or the step that follows a rotation, writes neither: it would
        // overwrite the one previous copy with the vault it is replacing.
        if !unchanged {
            if let Some(held) = &held {
                write_file(&self.state_dir, PREVIOUS_VAULT_FILE, held)?;
            }
            write_file(&self.state_dir, VAULT_FILE, &vault)?;
        }
        if let Some((_, encoded)) = &adopted {
            write_file(&self.state_dir, CREDENTIALS_FILE, encoded)?;
        }

        if forced {
            tracing::warn!(
                connector = %connector,
                %fingerprint,
                forced = true,
                held_revision = held.as_ref().map_or(0, |held| revision_of(held)),
                sent_revision = header.revision,
                "vault copy replaced the one held, forced by the operator"
            );
        }
        if !unchanged {
            *self
                .encrypted_vault
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(std::sync::Arc::new(vault));
        }
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
