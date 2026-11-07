//! What the rotations screen shows, and the manual copy of the vault.
//!
//! # Display data only
//!
//! The WebView receives fingerprints, epochs, instants and states. It receives no
//! capability token, no key, nothing the vault seals, no PIN and no path: the
//! vault's own path is blanked here, since the location view already shows where
//! the vault is and a path the page was given is one it could send back.
//!
//! # A read leaves nothing behind
//!
//! The vault is looked at where [`location::VaultLocation::path_to_look_at`] says,
//! which creates no folder: a machine that never opened Astra must not grow one for
//! having shown a screen.
//!
//! # What this read is not
//!
//! The blocking `Tunnel` serves the ceremony threads. The reads of the gateway are
//! `orion_core::operator_rotations`, which keep to a tolerant subset of each answer.

use std::path::Path;

use anyhow::Context as _;
use astra_operator::operations::rotation as operation;
use astra_operator::overview::VaultOverview;
use astra_operator::rotation_journal::{self, JournalStage, RotationJournal, RotationKind};
use astra_operator::tunnel::VaultCopySent;
use astra_operator::{credentials, prepared};
use orion_core::operator_rotations::{
    GatewayDomainRead, OperatorAuthorityStatus, OperatorPendingOperation, Reach,
};
use serde::Serialize;

use aether::certificates::transport::OperatorVaultCopy;

/// A rotation signed and not yet at its end, as the page may be told of it.
///
/// Raised whether or not a session is live: an operator who leaves a failure screen
/// and never returns before `activation_at` has no other prompt, and the gateway
/// refuses the installation after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalView {
    /// `ca_pq` or `ca_tls`.
    pub kind: &'static str,
    /// `signed`, `accepted`, `applied` or `installed`.
    pub stage: &'static str,
    /// The install deadline: the gateway refuses the transition after it.
    pub activation_at: u64,
    pub not_after: u64,
    /// The incoming anchor, hexadecimal.
    pub next_fingerprint: String,
}

impl JournalView {
    fn of(journal: &RotationJournal) -> Self {
        Self {
            kind: match journal.kind {
                RotationKind::CaPq => "ca_pq",
                RotationKind::CaTls => "ca_tls",
            },
            stage: match journal.stage {
                JournalStage::Signed => "signed",
                JournalStage::Accepted => "accepted",
                JournalStage::Applied => "applied",
                JournalStage::Installed => "installed",
            },
            activation_at: journal.activation_at,
            not_after: journal.not_after,
            next_fingerprint: journal.next_anchor_fingerprint.to_hex(),
        }
    }
}

/// What this machine holds, read from the files beside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Local {
    pub vault: Option<VaultOverview>,
    /// Why the vault could not be read, when it could not.
    pub vault_error: Option<String>,
    pub journal: Option<JournalView>,
    /// Something calls for a resumption: a journal, a legacy CA-PQ file or an
    /// unadopted record. A thing that cannot be read counts, so it is not hidden.
    pub resumable: bool,
    pub ca_tls_close_due: bool,
}

/// Reads the vault and what rotations left beside it, without a key.
pub fn read_local(vault_path: &Result<std::path::PathBuf, String>, now: u64) -> Local {
    let path = match vault_path {
        Ok(path) => path,
        Err(error) => {
            return Local {
                vault_error: Some(error.clone()),
                ..Local::default()
            }
        }
    };
    let (vault, vault_error) = match astra_operator::overview::read(path) {
        Ok(overview) => (Some(overview), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let journal_path = rotation_journal::path_beside(path);
    let journal = rotation_journal::load(&journal_path)
        .ok()
        .flatten()
        .map(|journal| JournalView::of(&journal));
    Local {
        vault,
        vault_error,
        journal,
        resumable: rotation_journal::something_to_resume(path).unwrap_or(true),
        ca_tls_close_due: ca_tls_close_due(path, now),
    }
}

/// « Terminer » is due: a client TLS rotation went through a journal, the gateway
/// holds it, its overlap is over, and nothing is left to resume. The conditions of
/// `CaTlsFinish::begin`, read without opening anything.
fn ca_tls_close_due(vault_path: &Path, now: u64) -> bool {
    rotation_journal::ensure_none_in_flight(vault_path).is_ok()
        && matches!(
            prepared::load(&prepared::path_beside(vault_path)),
            Ok(Some(record)) if record.submitted && record.adopted && now >= record.not_after
        )
}

/// Everything the screen needs, in one answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationsOverview {
    pub tunnel: bool,
    pub pending: Reach<Vec<OperatorPendingOperation>>,
    pub authority: Reach<OperatorAuthorityStatus>,
    pub domain: Reach<GatewayDomainRead>,
    pub vault: Option<VaultOverview>,
    pub vault_error: Option<String>,
    pub local_vault_fingerprint: Option<String>,
    pub local_ca_epoch: Option<u64>,
    pub local_ca_tls_epoch: Option<u64>,
    /// A rotation signed and not finished, with its install deadline.
    pub journal: Option<JournalView>,
    /// Something to resume, journal or not (legacy file, unadopted record).
    pub resumable: bool,
    /// A CA-PQ overlap is in flight at Astra. Renewing the workstations, every
    /// launch of an approval and recovery wait for it; a CA TLS overlap gates none
    /// of them.
    pub ca_pq_overlap: bool,
    pub ca_tls_close_due: bool,
}

impl RotationsOverview {
    pub fn assemble(
        tunnel: bool,
        pending: Reach<Vec<OperatorPendingOperation>>,
        authority: Reach<OperatorAuthorityStatus>,
        domain: Reach<GatewayDomainRead>,
        local: Local,
    ) -> Self {
        let Local {
            mut vault,
            vault_error,
            journal,
            resumable,
            ca_tls_close_due,
        } = local;
        let ca_pq_overlap = authority
            .ok()
            .is_some_and(|status| status.next_ca_fingerprint.is_some());
        if let Some(vault) = vault.as_mut() {
            vault.vault_path = String::new();
        }
        Self {
            tunnel,
            pending,
            authority,
            domain,
            local_vault_fingerprint: vault
                .as_ref()
                .and_then(|vault| vault.vault_fingerprint.clone()),
            local_ca_epoch: vault
                .as_ref()
                .and_then(|vault| vault.domain.as_ref())
                .and_then(|domain| domain.ca_epoch),
            local_ca_tls_epoch: vault
                .as_ref()
                .and_then(|vault| vault.domain.as_ref())
                .and_then(|domain| domain.ca_tls_epoch),
            vault,
            vault_error,
            journal,
            resumable,
            ca_pq_overlap,
            ca_tls_close_due,
        }
    }
}

/// What the page is told of a manual send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VaultCopyOutcome {
    /// Astra holds it, and this is what it reads back.
    Copied {
        fingerprint: String,
        /// `None`: Astra serves no credential document. Not epoch 0.
        credential_registry_epoch: Option<u64>,
    },
    /// A live operation or a rotation holds the copy back. Nothing was written, the
    /// same copy passes later, and this is an answer rather than a failure.
    HeldBack,
}

impl VaultCopyOutcome {
    pub fn of(sent: VaultCopySent) -> Self {
        match sent {
            VaultCopySent::Copied(copied) => Self::Copied {
                fingerprint: copied.fingerprint.to_hex(),
                credential_registry_epoch: copied.credential_registry_epoch,
            },
            VaultCopySent::HeldBack => Self::HeldBack,
        }
    }
}

/// The copy a manual send carries.
///
/// The vault in its compact form, so that Astra's fingerprint of the bytes it
/// receives equals the vault's own and the copy does not read « Ancienne » beside
/// the vault it was taken from. The credential document goes with it unless a CA-PQ
/// overlap is in flight or a rotation is waiting to be resumed: in the first case
/// Astra adopts the new document itself at the promotion, and in the second the
/// resumption sends it with the copy.
pub fn copy_to_send(
    vault_path: &Path,
    authority: &OperatorAuthorityStatus,
    resumable: bool,
) -> anyhow::Result<OperatorVaultCopy> {
    let mut copy = operation::vault_copy(vault_path)?;
    if authority.next_ca_fingerprint.is_none() && !resumable {
        copy.credentials = credentials::load(&credentials::path_beside(vault_path))
            .context("lecture du document de credentials")?
            .map(Box::new);
    }
    Ok(copy)
}

/// Why a read that did not go through stops a send, in a few words.
pub fn unreached(reach: &Reach<OperatorAuthorityStatus>) -> Option<&'static str> {
    match reach {
        Reach::Ok(_) => None,
        Reach::NotAdmin => Some("ce poste n'est pas administrateur de la gateway"),
        Reach::AstraUnavailable => Some("Astra n'est pas joignable par la gateway"),
        Reach::Throttled => Some("la gateway est saturée : réessayer plus tard"),
        Reach::Unreachable => Some("la gateway ne répond pas"),
    }
}

/// The base64 of what a copy carries, for a test to compare with the vault.
#[cfg(test)]
pub fn vault_bytes_of(copy: &OperatorVaultCopy) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(&copy.vault_base64)
        .expect("base64")
}
