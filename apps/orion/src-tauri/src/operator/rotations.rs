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
use astra_operator::tunnel::{Tunnel, VaultCopySent};
use astra_operator::{credentials, prepared};
use orion_core::operator_rotations::{
    AuthorityStatusRead, GatewayDomainRead, PeerCertificatesRead, PendingOperationRead, Reach,
};
use serde::Serialize;

use aether::certificates::transport::{
    OperatorChainStep, OperatorOpenAction, OperatorOpenRequest, OperatorOpened, OperatorVaultCopy,
    TrustUpdateObject,
};
use astra_operator::operations::gateway_identity::{self, GatewayIdentityRemote, RenewalOptions};
use astra_operator::operations::rotation::RotationRemote;

use crate::operator::ceremony::page_sentence;
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

/// The chain's calls the tunnel answers, named so a test can stand in for it.
pub trait ChainRemote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> anyhow::Result<OperatorOpened>;
    fn chain_next(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep>;
    fn chain_reopen(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep>;
    fn chain_abandon(&self) -> anyhow::Result<()>;
}

impl ChainRemote for Tunnel {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> anyhow::Result<OperatorOpened> {
        Tunnel::open_campaign(self, request)
    }

    fn chain_next(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep> {
        Tunnel::chain_next(self, expected_step)
    }

    fn chain_reopen(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep> {
        Tunnel::chain_reopen(self, expected_step)
    }

    fn chain_abandon(&self) -> anyhow::Result<()> {
        Tunnel::chain_abandon(self)
    }
}

/// What a `chain next` answers: the campaign it opened for the next step, or that the plan is
/// finished. The campaign's delegation request, when it carries one, is public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChainStepOutcome {
    Opened(Box<OperatorOpened>),
    Finished,
}

/// Said when a reopen is asked of a plan that has finished: there is no step to reopen.
const CHAIN_FINISHED: &str = "le plan est fini : rien à rouvrir.";

/// Replaces the step Orion holds in memory. Never written, never logged: its delegation request
/// is public, but nothing gains from being on disk.
fn hold(held: &std::sync::Mutex<Option<OperatorOpened>>, step: Option<OperatorOpened>) {
    *held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = step;
}

/// Holds what a chain answer opened, or nothing when the plan is finished, and says which.
fn answered(
    step: OperatorChainStep,
    held: &std::sync::Mutex<Option<OperatorOpened>>,
) -> ChainStepOutcome {
    match step {
        OperatorChainStep::Opened(opened) => {
            hold(held, Some((*opened).clone()));
            ChainStepOutcome::Opened(opened)
        }
        OperatorChainStep::Finished => {
            hold(held, None);
            ChainStepOutcome::Finished
        }
    }
}

/// Opens the certificate chain: its first step's campaign, which the gateway's pair check and
/// the chain's own refusal guard. The campaign is held until the next step or the abandon.
pub fn chain_start_with(
    remote: &dyn ChainRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    reason: &str,
    requested_by: &str,
    held: &std::sync::Mutex<Option<OperatorOpened>>,
) -> Result<OperatorOpened, String> {
    ensure_domains_gateway(vault_path, target)?;
    let opened = remote
        .open_campaign(&OperatorOpenRequest {
            action: OperatorOpenAction::ChainOpen,
            reason: reason.to_string(),
            requested_by: requested_by.to_string(),
            window_secs: OPEN_WINDOW_SECS,
        })
        .map_err(|error| format!("{error:#}"))?;
    hold(held, Some(opened.clone()));
    Ok(opened)
}

/// Opens the chain's next step. `expected_step` is the step the caller read: Astra refuses a
/// plan that has moved on, and its sentence reaches the page as it is.
pub fn chain_next_with(
    remote: &dyn ChainRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    expected_step: usize,
    held: &std::sync::Mutex<Option<OperatorOpened>>,
) -> Result<ChainStepOutcome, String> {
    ensure_domains_gateway(vault_path, target)?;
    let step = remote
        .chain_next(Some(expected_step))
        .map_err(|error| format!("{error:#}"))?;
    Ok(answered(step, held))
}

/// Redeposits the chain's current step once its campaign has ended. The campaign it opens
/// replaces the one held.
pub fn chain_reopen_with(
    remote: &dyn ChainRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    expected_step: usize,
    held: &std::sync::Mutex<Option<OperatorOpened>>,
) -> Result<OperatorOpened, String> {
    ensure_domains_gateway(vault_path, target)?;
    let step = remote
        .chain_reopen(Some(expected_step))
        .map_err(|error| format!("{error:#}"))?;
    match answered(step, held) {
        ChainStepOutcome::Opened(opened) => Ok(*opened),
        ChainStepOutcome::Finished => Err(CHAIN_FINISHED.to_string()),
    }
}

/// Drops the chain's plan. What was approved keeps its effect; the held step goes with it.
pub fn chain_abandon_with(
    remote: &dyn ChainRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    held: &std::sync::Mutex<Option<OperatorOpened>>,
) -> Result<(), String> {
    ensure_domains_gateway(vault_path, target)?;
    remote
        .chain_abandon()
        .map_err(|error| format!("{error:#}"))?;
    hold(held, None);
    Ok(())
}

/// Whether a gateway renewal on `terms` would be opened now, read through `remote` before the
/// chain's step is taken: the checks the renewal makes before it opens a campaign, and no key.
/// A refusal is its sentence, a failed read Orion's fixed one.
pub fn check_renewal_with(
    remote: &dyn GatewayIdentityRemote,
    vault_path: &Path,
    target: &GatewayTarget,
    options: RenewalOptions,
    now: u64,
) -> Result<(), String> {
    ensure_domains_gateway(vault_path, target)?;
    gateway_identity::check_renewal(remote, vault_path, options, now)
        .map_err(|refusal| page_sentence(&refusal))
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
    let local_epoch = local_credentials_epoch(vault_path);
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
    Ok(VaultCopyOutcome::of(sent, local_epoch))
}

/// The epoch of the credential document beside the vault, read without verifying it:
/// a number to compare with the one Astra serves, never a reason to trust the file.
fn local_credentials_epoch(vault_path: &Path) -> Option<u64> {
    credentials::load(&credentials::path_beside(vault_path))
        .ok()
        .flatten()
        .map(|document| document.credential_registry_epoch)
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

/// The gateway's waiting record, as the screen may be told of it: which kind it is and how
/// far it went. Read from the record beside the vault, with no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayPendingView {
    /// `decision` (a renewal or a cancellation) or `revocation`.
    pub kind: &'static str,
    /// The gateway holds the waiting transition, or the replacement of a revocation.
    pub installed: bool,
    /// Astra relayed the transition. A revocation has no such step: always `false`.
    pub published: bool,
    /// The revocation reached the gateway.
    pub revocation_applied: bool,
    /// `renewal` or `abort` for a decision; absent for a revocation.
    pub decision_kind: Option<String>,
    /// The replacement is deposited and the revocation is not signed yet: nothing is revoked.
    pub revocation_to_sign: bool,
    /// Astra refused the decision's publication for good. The refusal's own text is kept in the
    /// record and never shown here. A revocation has no publication: always `false`.
    pub publication_refused: bool,
    /// The fingerprint, in hex, of the replacement transition a revocation carries. `None` for a
    /// decision, and for a revocation without replacement.
    pub replacement_fingerprint: Option<String>,
}

/// The gateway record waiting beside the vault, if one does. A revocation's record is the one
/// the resumption reads first. A record that cannot be read is nothing to show here: the
/// gateway ceremony that reads it says why.
pub fn gateway_pending_of(vault_path: &Path, now: u64) -> Option<GatewayPendingView> {
    use astra_operator::operations::{gateway_identity, gateway_revocation};

    match gateway_revocation::pending_revocation(vault_path, now) {
        Ok(Some(record)) => {
            return Some(GatewayPendingView {
                kind: "revocation",
                installed: record.replacement_installed,
                published: false,
                revocation_applied: record.revocation_applied,
                decision_kind: None,
                revocation_to_sign: record
                    .replacement
                    .as_ref()
                    .is_some_and(|replacement| replacement.deposited)
                    && record.revocation.is_none(),
                publication_refused: false,
                replacement_fingerprint: record
                    .replacement
                    .as_ref()
                    .and_then(transition_fingerprint_of),
            })
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "révocation gateway illisible");
            return None;
        }
    }
    match gateway_identity::pending(vault_path, now) {
        Ok(Some(decision)) => Some(GatewayPendingView {
            kind: "decision",
            installed: decision.installed,
            published: decision.published,
            revocation_applied: false,
            decision_kind: Some(
                match decision.kind {
                    gateway_identity::GatewayDecisionKind::Renewal => "renewal",
                    gateway_identity::GatewayDecisionKind::Abort => "abort",
                }
                .to_string(),
            ),
            revocation_to_sign: false,
            publication_refused: decision.publication_refused.is_some(),
            replacement_fingerprint: None,
        }),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "décision gateway illisible");
            None
        }
    }
}

/// The fingerprint, in hex, of the gateway transition a recorded decision carries. `None` when it
/// carries none, or when the transition cannot be fingerprinted: the failure goes to the log.
fn transition_fingerprint_of(
    decision: &astra_operator::operations::gateway_identity::SignedGatewayDecision,
) -> Option<String> {
    let Some(TrustUpdateObject::GatewayIdentityTransition(transition)) =
        decision.result.objects.first()
    else {
        return None;
    };
    match transition.fingerprint() {
        Ok(fingerprint) => Some(fingerprint.to_hex()),
        Err(error) => {
            tracing::warn!(error = %error, "transition gateway illisible");
            None
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
    /// The epoch of the credential document beside the vault. A key added, removed or
    /// marked puts it ahead of the one Astra serves until a copy carries it there.
    pub credential_registry_epoch: Option<u64>,
    /// When the outgoing CA-PQ the vault keeps ends, for « Terminer la rotation CA-PQ ».
    /// Read from the clear copy, without a key; `None` when no key is kept.
    pub retained_ca_pq_not_after: Option<u64>,
    /// The gateway's identity record waiting beside the vault, if one does.
    pub gateway_pending: Option<GatewayPendingView>,
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
        credential_registry_epoch: local_credentials_epoch(path),
        retained_ca_pq_not_after: retained_ca_pq_not_after(path),
        gateway_pending: gateway_pending_of(path, now),
    }
}

/// The end of the outgoing CA-PQ the vault keeps, read without a key: the clear copy of
/// it, which only « Terminer » removes.
fn retained_ca_pq_not_after(vault_path: &Path) -> Option<u64> {
    let vault = astra_operator::store::load(vault_path).ok()?;
    vault
        .retained_outgoing_ca_pq_public()
        .map(|(_, _, not_after)| not_after)
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

/// A workstation as the warning before « Remplacer la CA-PQ » names it: its name and
/// when its certificate ends. No key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkstationExpiry {
    pub name: String,
    pub not_after: u64,
}

/// The workstations the gateway has not revoked, as [`WorkstationExpiry`].
pub fn workstations_of(certificates: Reach<PeerCertificatesRead>) -> Reach<Vec<WorkstationExpiry>> {
    certificates.map(|read| {
        read.peers
            .into_iter()
            .filter(|peer| !peer.revoked)
            .map(|peer| WorkstationExpiry {
                name: peer.name,
                not_after: peer.not_after,
            })
            .collect()
    })
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
    /// The epoch of the credential document beside the vault, to compare with the one
    /// Astra serves: a key change leaves it ahead until a copy carries the document.
    pub local_credential_registry_epoch: Option<u64>,
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
    /// When « Terminer la rotation CA-PQ » falls due: the end of the outgoing CA-PQ the
    /// vault keeps. `None` when none is kept.
    pub retained_ca_pq_not_after: Option<u64>,
    /// The workstations not revoked, for the warning before « Remplacer la CA-PQ ».
    pub workstations: Reach<Vec<WorkstationExpiry>>,
    /// The gateway's identity record waiting beside the vault, if one does.
    pub gateway_pending: Option<GatewayPendingView>,
}

impl RotationsOverview {
    pub fn assemble(
        tunnel: bool,
        pending: Reach<Vec<PendingOperationRead>>,
        authority: Reach<AuthorityStatusRead>,
        domain: Reach<GatewayDomainRead>,
        certificates: Reach<PeerCertificatesRead>,
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
            credential_registry_epoch,
            retained_ca_pq_not_after,
            gateway_pending,
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
            local_credential_registry_epoch: credential_registry_epoch,
            vault,
            vault_error,
            journal,
            resumable,
            ca_pq_overlap,
            ca_tls_close_due,
            ca_tls_close_at,
            retained_ca_pq_not_after,
            workstations: workstations_of(certificates),
            gateway_pending,
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
        /// The document beside the vault is still ahead of the one Astra serves: an
        /// overlap, a rotation or a promotion held it back, and a later send carries it.
        /// Said, so that a key change that did not reach Astra is never silent.
        document_waits: bool,
    },
    /// A live operation or a rotation holds the copy back. Nothing was written, the
    /// same copy passes later, and this is an answer rather than a failure.
    HeldBack,
}

impl VaultCopyOutcome {
    /// `local_epoch` is the epoch of the document beside the vault, if there is one.
    pub fn of(sent: VaultCopySent, local_epoch: Option<u64>) -> Self {
        match sent {
            VaultCopySent::Copied(copied) => Self::Copied {
                fingerprint: copied.fingerprint.to_hex(),
                credential_registry_epoch: copied.credential_registry_epoch,
                document_waits: local_epoch.is_some_and(|local| {
                    copied
                        .credential_registry_epoch
                        .is_none_or(|served| served < local)
                }),
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
/// resumed: the document beside the vault is then the one that rotation replaces, and
/// its resumption sends the copy without any (spec §10.6). A later send carries the
/// document once neither holds it.
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

#[cfg(test)]
mod overview_tests {
    use super::*;
    use orion_core::operator_rotations::{PeerCertificateRead, PeerCertificatesRead};

    fn peer(name: &str, not_after: u64, revoked: bool) -> PeerCertificateRead {
        PeerCertificateRead {
            name: name.into(),
            wg_public_key: "a".repeat(44),
            not_before: 0,
            not_after,
            revoked,
            renewing: false,
        }
    }

    fn assembled(local: Local, certificates: Reach<PeerCertificatesRead>) -> RotationsOverview {
        RotationsOverview::assemble(
            true,
            Reach::Unreachable,
            Reach::Unreachable,
            Reach::Unreachable,
            certificates,
            local,
        )
    }

    /// The kept key's expiry reaches the page, and nothing of the key does.
    #[test]
    fn rotations_overview_carries_the_kept_expiry_and_no_key() {
        let local = Local {
            retained_ca_pq_not_after: Some(1_900_000_000),
            ..Local::default()
        };
        let shown = serde_json::to_value(assembled(local, Reach::Unreachable)).expect("json");
        assert_eq!(shown["retainedCaPqNotAfter"], 1_900_000_000);

        let kept_nothing =
            serde_json::to_value(assembled(Local::default(), Reach::Unreachable)).expect("json");
        assert!(kept_nothing["retainedCaPqNotAfter"].is_null());
    }

    /// Only the workstations not revoked reach the page, with their name and expiry.
    #[test]
    fn rotations_overview_lists_the_workstations_not_revoked() {
        let certificates = Reach::Ok(PeerCertificatesRead {
            now_unix: Some(1),
            peers: vec![peer("PORTABLE", 10, false), peer("ANCIEN", 5, true)],
        });
        let shown = serde_json::to_value(assembled(Local::default(), certificates)).expect("json");
        assert_eq!(shown["workstations"]["state"], "ok");
        assert_eq!(
            shown["workstations"]["value"],
            serde_json::json!([{ "name": "PORTABLE", "not_after": 10 }])
        );

        let unread =
            serde_json::to_value(assembled(Local::default(), Reach::Unreachable)).expect("json");
        assert_eq!(unread["workstations"]["state"], "unreachable");
    }
}

#[cfg(test)]
mod chain_tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use aether::certificates::encoding::{Fingerprint, Id16, WireGuardKey};
    use aether::certificates::status::CampaignScope;
    use aether::certificates::transport::{OperatorChainStep, OperatorOpenRequest};
    use astra_operator::operations::fixtures::gateway_key;
    use astra_operator::operations::gateway_identity::tests::Scenario;

    use super::*;

    /// A tunnel that answers the chain's calls from scripts, and records what it was asked.
    #[derive(Default)]
    struct Fake {
        opened: Option<OperatorOpened>,
        /// What `chain_next` and `chain_reopen` answer, in turn: a refusal is Astra's sentence.
        steps: RefCell<VecDeque<Result<OperatorChainStep, String>>>,
        requests: RefCell<Vec<OperatorOpenRequest>>,
        expected: RefCell<Vec<Option<usize>>>,
    }

    impl Fake {
        fn answering(opened: OperatorOpened) -> Self {
            Self {
                opened: Some(opened),
                ..Self::default()
            }
        }

        fn then(self, step: Result<OperatorChainStep, String>) -> Self {
            self.steps.borrow_mut().push_back(step);
            self
        }

        fn next_step(&self, expected: Option<usize>) -> anyhow::Result<OperatorChainStep> {
            self.expected.borrow_mut().push(expected);
            match self.steps.borrow_mut().pop_front() {
                Some(Ok(step)) => Ok(step),
                Some(Err(sentence)) => Err(anyhow::anyhow!("{sentence}")),
                None => panic!("no step scripted"),
            }
        }
    }

    impl ChainRemote for Fake {
        fn open_campaign(&self, request: &OperatorOpenRequest) -> anyhow::Result<OperatorOpened> {
            self.requests.borrow_mut().push(request.clone());
            self.opened
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no campaign scripted"))
        }

        fn chain_next(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep> {
            self.next_step(expected_step)
        }

        fn chain_reopen(&self, expected_step: Option<usize>) -> anyhow::Result<OperatorChainStep> {
            self.next_step(expected_step)
        }

        fn chain_abandon(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn opened(serial: u8) -> OperatorOpened {
        OperatorOpened {
            operation_id: Id16::new([serial; 16]).expect("id"),
            campaign_id: Id16::new([serial + 1; 16]).expect("id"),
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            scope: CampaignScope::IssuerDelegation,
            target_count: 1,
            required_credentials: 2,
            expires_at: 1_900_000_000,
            revocation_expiries: None,
            delegation_request: Some("demande publique".into()),
            gateway_certificate: None,
        }
    }

    /// A vault whose relay names the gateway of the returned target.
    fn domain_gateway() -> (Scenario, GatewayTarget) {
        let scenario = Scenario::new(false);
        let target = GatewayTarget {
            address: "http://127.0.0.1:1".into(),
            peer_key: gateway_key().to_base64(),
            own_key: None,
        };
        (scenario, target)
    }

    fn held_with(opened: Option<OperatorOpened>) -> Mutex<Option<OperatorOpened>> {
        Mutex::new(opened)
    }

    fn read(held: &Mutex<Option<OperatorOpened>>) -> Option<OperatorOpened> {
        held.lock().expect("lock").clone()
    }

    #[test]
    fn chain_start_keeps_the_opened_step() {
        let (scenario, target) = domain_gateway();
        let fake = Fake::answering(opened(3));
        let held = held_with(None);

        let started = chain_start_with(
            &fake,
            &scenario.domain.path,
            &target,
            "renouvellement",
            "poste",
            &held,
        )
        .expect("started");

        assert_eq!(started, opened(3));
        assert_eq!(read(&held), Some(opened(3)), "the step is held");
        let request = fake.requests.borrow()[0].clone();
        assert_eq!(request.action, OperatorOpenAction::ChainOpen);
        assert_eq!(request.reason, "renouvellement");
        assert_eq!(request.requested_by, "poste");
    }

    #[test]
    fn chain_next_finished_clears_the_held_step() {
        let (scenario, target) = domain_gateway();
        let fake = Fake::default().then(Ok(OperatorChainStep::Finished));
        let held = held_with(Some(opened(3)));

        let outcome =
            chain_next_with(&fake, &scenario.domain.path, &target, 2, &held).expect("next");

        assert_eq!(outcome, ChainStepOutcome::Finished);
        assert_eq!(read(&held), None, "a finished chain holds no step");
        assert_eq!(
            *fake.expected.borrow(),
            vec![Some(2)],
            "the expected step is sent"
        );
    }

    #[test]
    fn chain_reopen_replaces_the_held_step() {
        let (scenario, target) = domain_gateway();
        let fake = Fake::default().then(Ok(OperatorChainStep::Opened(Box::new(opened(5)))));
        let held = held_with(Some(opened(3)));

        let reopened =
            chain_reopen_with(&fake, &scenario.domain.path, &target, 1, &held).expect("reopen");

        assert_eq!(reopened, opened(5));
        assert_eq!(
            read(&held),
            Some(opened(5)),
            "the reopened step replaces the old one"
        );
        assert_eq!(*fake.expected.borrow(), vec![Some(1)]);
    }

    #[test]
    fn chain_abandon_clears_the_held_step() {
        let (scenario, target) = domain_gateway();
        let fake = Fake::default();
        let held = held_with(Some(opened(3)));

        chain_abandon_with(&fake, &scenario.domain.path, &target, &held).expect("abandon");

        assert_eq!(read(&held), None);
    }

    #[test]
    fn chain_next_refusal_is_astras_sentence() {
        let (scenario, target) = domain_gateway();
        let sentence = "l'étape n'a pas été ouverte : continuer le plan";
        let fake = Fake::default().then(Err(sentence.to_string()));
        let held = held_with(Some(opened(3)));

        let refused =
            chain_next_with(&fake, &scenario.domain.path, &target, 1, &held).expect_err("refused");

        assert_eq!(refused, sentence, "Astra's sentence, unchanged");
        assert_eq!(
            read(&held),
            Some(opened(3)),
            "a refused step keeps the held one"
        );
    }

    #[test]
    fn chain_refuses_a_gateway_the_relay_does_not_name() {
        let (scenario, mut target) = domain_gateway();
        target.peer_key = WireGuardKey::from_bytes([9; 32]).to_base64();
        let fake = Fake::answering(opened(3));
        let held = held_with(None);

        let refused = chain_start_with(&fake, &scenario.domain.path, &target, "r", "p", &held)
            .expect_err("another domain's gateway");

        assert_eq!(refused, NOT_THE_DOMAINS_GATEWAY);
        assert!(fake.requests.borrow().is_empty(), "no campaign is opened");
    }
}
