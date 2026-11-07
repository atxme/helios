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
    AuthorityStatusRead, GatewayDomainRead, PendingOperationRead, Reach,
};
use serde::Serialize;

use aether::certificates::transport::{
    OperatorOpenAction, OperatorOpenRequest, OperatorOpened, OperatorVaultCopy,
};
use astra_operator::operations::rotation::RotationRemote;

use crate::operator::{relay_names_peer, GatewayTarget};

const NOT_THE_DOMAINS_GATEWAY: &str =
    "la gateway connectée n'est pas celle que nomme le relais du domaine";

/// The window of a campaign this screen opens: the door's own ceiling.
const OPEN_WINDOW_SECS: u64 = 300;

/// Refuses a gateway that is not the one the domain's relay names, before any call.
fn ensure_domains_gateway(vault_path: &Path, target: &GatewayTarget) -> Result<(), String> {
    if relay_names_peer(vault_path, &target.peer_key)? {
        Ok(())
    } else {
        Err(NOT_THE_DOMAINS_GATEWAY.to_string())
    }
}

/// Opens a campaign for the two actions this screen runs outside a ceremony.
///
/// The CA rotations open on the ceremony thread, at « Approuver », and a revocation
/// names a peer no screen of this kind offers. A `403` comes back as the gateway's
/// refusal, unchanged: the door answers `AlreadyOpen` that way, so the caller reads
/// what is pending after any of them.
pub fn open_campaign_with(
    remote: &dyn RotationRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    action: OperatorOpenAction,
    reason: &str,
    requested_by: &str,
) -> Result<OperatorOpened, String> {
    if !matches!(
        action,
        OperatorOpenAction::FleetLeafs | OperatorOpenAction::IssuerDelegation
    ) {
        return Err(
            "cette action ne s'ouvre pas ici : les rotations de CA s'ouvrent à \
                    « Approuver », dans leur cérémonie"
                .to_string(),
        );
    }
    ensure_domains_gateway(vault_path, target)?;
    remote
        .open_campaign(&OperatorOpenRequest {
            action,
            reason: reason.to_string(),
            requested_by: requested_by.to_string(),
            window_secs: OPEN_WINDOW_SECS,
        })
        .map_err(|error| format!("{error:#}"))
}

/// The manual send. `authority` is read only once the gateway has been checked.
pub fn send_copy_with(
    remote: &dyn RotationRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    authority: impl FnOnce() -> Reach<AuthorityStatusRead>,
) -> Result<VaultCopyOutcome, String> {
    ensure_domains_gateway(vault_path, target)?;
    let authority = match authority() {
        Reach::Ok(authority) => authority,
        other => return Err(unreached(&other).unwrap_or_default()),
    };
    let resumable =
        rotation_journal::something_to_resume(vault_path).map_err(|error| format!("{error:#}"))?;
    let copy =
        copy_to_send(vault_path, &authority, resumable).map_err(|error| format!("{error:#}"))?;
    let carried_a_document = copy.credentials.is_some();
    let mut sent = remote
        .send_vault_copy(&copy)
        .map_err(|error| format!("{error:#}"))?;
    // A document held back by a promotion the status does not show holds the whole
    // copy back with it. The vault alone passes, and the document follows later.
    if carried_a_document && sent == VaultCopySent::HeldBack {
        let alone = OperatorVaultCopy {
            credentials: None,
            ..copy
        };
        sent = remote
            .send_vault_copy(&alone)
            .map_err(|error| format!("{error:#}"))?;
    }
    Ok(VaultCopyOutcome::of(sent))
}

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
    /// No deposit of Orion's own: signed offline, or adopted from the CA-PQ file. Only
    /// then is `astra-signer rotate-ca-pq` a recourse that cannot conflict with Orion.
    pub offline: bool,
}

impl JournalView {
    pub(crate) fn of(journal: &RotationJournal) -> Self {
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
            offline: journal.deposit.is_none(),
        }
    }
}

/// What this machine holds, read from the files beside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Local {
    pub vault: Option<VaultOverview>,
    /// Why the vault could not be read, as a fixed label: `illisible` for a vault
    /// that cannot be read, `emplacement` for a location that cannot be resolved.
    /// The detail names paths, so it goes to the log and never to the page.
    pub vault_error: Option<&'static str>,
    pub journal: Option<JournalView>,
    /// Something calls for a resumption: a journal, a legacy CA-PQ file or an
    /// unadopted record. A thing that cannot be read counts, so it is not hidden.
    pub resumable: bool,
    pub ca_tls_close_due: bool,
    /// When « Terminer » falls due: the `not_after` of a client TLS rotation the
    /// gateway holds, whether or not that instant has passed.
    pub ca_tls_close_at: Option<u64>,
    /// When the CA TLS in the relay beside the vault ends. A public certificate, read
    /// without opening the vault; `None` when the relay holds none.
    pub ca_tls_not_after: Option<u64>,
}

/// The journal and whether anything calls for a resumption, read from the files beside
/// the vault and nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalJournal {
    pub journal: Option<JournalView>,
    pub resumable: bool,
}

/// A location that cannot be resolved, or a file that cannot be read, is nothing to
/// show: this read raises a reminder for everyone, and the full overview is where an
/// unreadable thing is reported.
pub fn read_journal(vault_path: &Result<std::path::PathBuf, String>) -> LocalJournal {
    let Ok(path) = vault_path else {
        return LocalJournal::default();
    };
    LocalJournal {
        journal: rotation_journal::load(&rotation_journal::path_beside(path))
            .ok()
            .flatten()
            .map(|journal| JournalView::of(&journal)),
        resumable: rotation_journal::something_to_resume(path).unwrap_or(false),
    }
}

/// Reads the vault and what rotations left beside it, without a key.
pub fn read_local(vault_path: &Result<std::path::PathBuf, String>, now: u64) -> Local {
    let path = match vault_path {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(%error, "emplacement du coffre illisible");
            return Local {
                vault_error: Some("emplacement"),
                ..Local::default()
            };
        }
    };
    let (vault, vault_error) = match astra_operator::overview::read(path) {
        Ok(overview) => (Some(overview), None),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "coffre illisible");
            (None, Some("illisible"))
        }
    };
    let close_at = ca_tls_close_at(path);
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
        ca_tls_close_due: close_at.is_some_and(|at| now >= at),
        ca_tls_close_at: close_at,
        ca_tls_not_after: ca_tls_not_after(path),
    }
}

/// The expiry of the CA TLS the relay records. Nothing is opened: the relay and the
/// certificate in it are public.
fn ca_tls_not_after(vault_path: &Path) -> Option<u64> {
    let relay =
        astra_operator::handoff::load(&astra_operator::handoff::path_beside(vault_path)).ok()?;
    let der =
        aether::certificates::encoding::DerCertificate::parse(relay.ca_tls_certificate.as_deref()?)
            .ok()?;
    aether::certificates::x509::inspect(&der)
        .ok()
        .map(|facts| facts.not_after)
}

/// When « Terminer » falls due: a client TLS rotation went through a journal, the
/// gateway holds it, and nothing is left to resume. The conditions of
/// `CaTlsFinish::begin`, read without opening anything; its overlap may still run.
fn ca_tls_close_at(vault_path: &Path) -> Option<u64> {
    if rotation_journal::ensure_none_in_flight(vault_path).is_err() {
        return None;
    }
    match prepared::load(&prepared::path_beside(vault_path)) {
        Ok(Some(record)) if record.submitted && record.adopted => Some(record.not_after),
        _ => None,
    }
}

/// Everything the screen needs, in one answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationsOverview {
    pub tunnel: bool,
    pub pending: Reach<Vec<PendingOperationRead>>,
    pub authority: Reach<AuthorityStatusRead>,
    pub domain: Reach<GatewayDomainRead>,
    pub vault: Option<VaultOverview>,
    pub vault_error: Option<&'static str>,
    pub local_vault_fingerprint: Option<String>,
    pub local_ca_epoch: Option<u64>,
    pub local_ca_tls_epoch: Option<u64>,
    /// When the CA TLS recorded beside the vault ends.
    pub local_ca_tls_not_after: Option<u64>,
    /// A rotation signed and not finished, with its install deadline.
    pub journal: Option<JournalView>,
    /// Something to resume, journal or not (legacy file, unadopted record).
    pub resumable: bool,
    /// A CA-PQ overlap is in flight at Astra. Renewing the workstations, every
    /// launch of an approval and recovery wait for it; a CA TLS overlap gates none
    /// of them.
    ///
    /// `None` when the authority could not be read: that is not « no overlap », and
    /// a screen that read it as one would spend a touch the overlap then refuses.
    pub ca_pq_overlap: Option<bool>,
    pub ca_tls_close_due: bool,
    pub ca_tls_close_at: Option<u64>,
}

impl RotationsOverview {
    pub fn assemble(
        tunnel: bool,
        pending: Reach<Vec<PendingOperationRead>>,
        authority: Reach<AuthorityStatusRead>,
        domain: Reach<GatewayDomainRead>,
        local: Local,
    ) -> Self {
        let Local {
            mut vault,
            vault_error,
            journal,
            resumable,
            ca_tls_close_due,
            ca_tls_close_at,
            ca_tls_not_after,
        } = local;
        let ca_pq_overlap = authority
            .ok()
            .map(|status| status.next_ca_fingerprint.is_some());
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
            local_ca_tls_not_after: ca_tls_not_after,
            vault,
            vault_error,
            journal,
            resumable,
            ca_pq_overlap,
            ca_tls_close_due,
            ca_tls_close_at,
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
/// the vault it was taken from. The credential document goes with it only when it is
/// newer than the one Astra serves (or Astra serves none): Astra answers an
/// indistinct refusal to an older one, and a vault that would have passed alone must
/// not be refused for it. It is also left out during a CA-PQ overlap, where Astra
/// adopts the new document itself at the promotion, and while a rotation waits to be
/// resumed, whose resumption sends it with the copy.
pub fn copy_to_send(
    vault_path: &Path,
    authority: &AuthorityStatusRead,
    resumable: bool,
) -> anyhow::Result<OperatorVaultCopy> {
    let mut copy = operation::vault_copy(vault_path)?;
    if authority.next_ca_fingerprint.is_none() && !resumable {
        let document = credentials::load(&credentials::path_beside(vault_path))
            .context("lecture du document de credentials")?;
        copy.credentials = document
            .filter(|document| {
                authority
                    .credential_registry_epoch
                    .is_none_or(|served| document.credential_registry_epoch > served)
            })
            .map(Box::new);
    }
    Ok(copy)
}

/// Why a read that did not go through stops a send, in a few words.
pub fn unreached<T>(reach: &Reach<T>) -> Option<String> {
    match reach {
        Reach::Ok(_) => None,
        Reach::NotAdmin => Some("ce poste n'est pas administrateur de la gateway".into()),
        Reach::AstraUnavailable => Some("Astra n'est pas joignable par la gateway".into()),
        Reach::Throttled => Some("la gateway est saturée : réessayer plus tard".into()),
        Reach::Unreachable => Some("la gateway ne répond pas".into()),
        Reach::Refused(status) => Some(format!("la gateway a refusé la lecture ({status})")),
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

#[cfg(test)]
mod journal_tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orion-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// A shell that polls this for every user must not raise a reminder out of a
    /// location it cannot resolve.
    #[test]
    fn an_unresolved_location_shows_nothing() {
        assert_eq!(
            read_journal(&Err("introuvable".into())),
            LocalJournal::default()
        );
    }

    /// Looking leaves nothing behind: no journal, no folder, no file.
    #[test]
    fn a_vault_with_nothing_beside_it_shows_nothing_and_creates_nothing() {
        let dir = scratch("empty");
        let vault = dir.join("vault.json");
        assert_eq!(read_journal(&Ok(vault)), LocalJournal::default());
        assert_eq!(std::fs::read_dir(&dir).expect("dir").count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_a_rotation_left_calls_for_a_resumption() {
        let dir = scratch("left");
        let vault = dir.join("vault.json");
        std::fs::write(rotation_journal::path_beside(&vault), b"not a journal").expect("write");
        let read = read_journal(&Ok(vault));
        assert!(read.resumable);
        // Unreadable is not shown as a journal with invented dates.
        assert_eq!(read.journal, None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
