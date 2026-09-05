//! The rotation an operator has committed to but not yet finished.
//!
//! # The window this closes
//!
//! A `CA-TLS` rotation touches four things that do not move together: the
//! sealed vault, the transition file, the authority's record of the operation,
//! and the hand-off the later commands read. Before this file existed they
//! moved in that order with nothing between them, so a machine that lost power
//! after the vault write and before the deposit left an operator holding a
//! successor the domain had never heard of — and the ceremony could not simply
//! be run again, because `CA-PQ` would sign a *different* transition the second
//! time and the campaign approval was already spent.
//!
//! So the ceremony now writes down, atomically and before it tells anyone
//! anything, the exact bytes it intends to deposit. Everything after that point
//! is a replay of a decision already made rather than a new one.
//!
//! # What is in it, and what is not
//!
//! The signed objects, the operation they answer, and the window they open.
//! **No private key**: the successor is sealed in the vault, which is the only
//! thing on this machine built to hold one. What this file does carry that is
//! not public is the operation's result token — a bearer credential for one
//! deposit — so it is written with the same private permissions as the vault
//! beside it, and removed as soon as the deposit lands.
//!
//! # Why it is not the vault
//!
//! The vault is re-sealed by an authenticator touch. Recording «what still has
//! to be sent» must not require one: an operator resuming after a crash has
//! already been through the ceremony, and asking for the key again would be
//! asking them to approve a second decision to finish the first.

use std::path::{Path, PathBuf};

use aether::certificates::status::AstraSignerResult;
use aether::certificates::operator_ipc::AstraCaTlsManifest;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Name of the prepared-rotation file, beside the vault.
pub const PREPARED_FILE: &str = "astra-prepared.json";

/// Which ceremony left this behind.
///
/// One variant today. It is named rather than assumed so a second kind of
/// prepared rotation cannot be resumed by the command that handles this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedKind {
    /// A client `CA-TLS` rotation (spec §9.4).
    CaTls,
}

/// A decision that is signed and sealed, and not yet everywhere it belongs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRotation {
    pub kind: PreparedKind,
    /// The operation the deposit answers, 32 hex characters.
    pub operation_id: String,
    /// Bearer token for that one deposit.
    pub result_token: String,
    /// The exact result to deposit. Replaying identical bytes is idempotent;
    /// different bytes under the same identifier are a conflict Astra decides,
    /// which is why this is stored rather than rebuilt.
    pub result: AstraSignerResult,
    /// Where the transition file was written, for the operator to carry to the
    /// gateway.
    pub transition_path: String,
    /// The `CA-TLS` generation this rotation opens.
    pub next_ca_tls_epoch: u64,
    /// The incoming anchor, DER base64. Public.
    pub next_ca_tls_certificate: String,
    pub activation_at: u64,
    pub not_after: u64,
    /// Whether the authority has accepted the deposit.
    ///
    /// Until it has, the domain and this machine disagree about which anchors
    /// exist, and no other rotation may start.
    pub submitted: bool,
    pub prepared_at: u64,
    /// Public campaign details retained for a GUI that resumes the durable
    /// decision after the companion or Orion restarted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<AstraCaTlsManifest>,
}

/// Where the prepared rotation sits: beside the vault, whatever its path.
pub fn path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(PREPARED_FILE)
}

/// Reads the prepared rotation, or `None` when no ceremony is outstanding.
pub fn load(path: &Path) -> Result<Option<PreparedRotation>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let record = serde_json::from_slice(&bytes)
                .with_context(|| format!("lecture de la rotation préparée {}", path.display()))?;
            Ok(Some(record))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("lecture de {}", path.display())),
    }
}

/// Writes the prepared rotation, atomically and privately.
pub fn save(path: &Path, record: &PreparedRotation) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes =
        serde_json::to_vec_pretty(record).context("sérialisation de la rotation préparée")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

/// Removes the record once the rotation it describes is complete.
///
/// Absence is the resting state, so a file that is already gone is success:
/// two operators finishing the same window must not produce an error that
/// suggests one of them broke something.
pub fn clear(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("suppression de {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{Fingerprint, Id16};
    use aether::certificates::status::CampaignApproval;

    fn record() -> PreparedRotation {
        PreparedRotation {
            kind: PreparedKind::CaTls,
            operation_id: "0".repeat(32),
            result_token: "jeton".into(),
            result: AstraSignerResult {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                approval: Box::new(CampaignApproval {
                    campaign_id: Id16::new([3; 16]).expect("id"),
                    campaign_fingerprint: Fingerprint::of(b"campagne"),
                    required_credentials: 2,
                    approved_at: 9,
                    approvals: Vec::new(),
                }),
                objects: Vec::new(),
                credential_registry: None,
                issuer_authorization: None,
            },
            transition_path: "/tmp/transition.json".into(),
            next_ca_tls_epoch: 2,
            next_ca_tls_certificate: "REVS".into(),
            activation_at: 100,
            not_after: 200,
            submitted: false,
            prepared_at: 10,
            manifest: None,
        }
    }

    #[test]
    fn an_absent_record_is_no_record_rather_than_an_error() {
        let dir = tempfile::tempdir().expect("dir");
        let path = path_beside(&dir.path().join("authority-vault.json"));
        assert_eq!(load(&path).expect("load"), None);
        clear(&path).expect("clear");
    }

    #[test]
    fn what_is_written_is_what_comes_back() {
        let dir = tempfile::tempdir().expect("dir");
        let path = path_beside(&dir.path().join("authority-vault.json"));
        let record = record();
        save(&path, &record).expect("save");
        assert_eq!(load(&path).expect("load"), Some(record));
        clear(&path).expect("clear");
        assert_eq!(load(&path).expect("load"), None);
    }
}
