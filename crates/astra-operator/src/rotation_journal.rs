//! A rotation written down until the gateway has it (spec §5.4).
//!
//! # The rule this keeps
//!
//! The decision is recorded before it is announced, and the vault in place moves
//! only after Astra accepted it. Everything after the four touches is therefore
//! a replay of bytes that already exist, and resuming never needs a key: a stop
//! at any point leaves either a rotation nobody has heard of, which can be
//! dropped without harm, or one this file can carry to the gateway alone.
//!
//! # What is in it, and what is not
//!
//! The next vault, sealed like any vault, its credentials and relay, the signed
//! transition and the result to deposit. **No private key in the clear.** The
//! transition stays until the gateway confirms it: with no `--out` file, this is
//! its only copy, and past `activation_at` the vault cannot sign another. What
//! is not public is the result token, a bearer credential for one deposit, so
//! the file is as private as the vault beside it and `Debug` does not print it.
//!
//! # The older records
//!
//! `astra-signer` left two others, and an operator may hold one from an
//! interrupted rotation: its CA-PQ journal, written after its deposit with the
//! next vault still to apply, and the prepared CA-TLS record, written after the
//! vault moved. [`adopt_legacy`] turns either into this one. Neither may be
//! discarded when Astra knows nothing of it: the vault in place is the only copy
//! of the keys that record was signed with.

use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialRegistry;
use aether::certificates::authority::{CaTransition, ClientTlsCaTransition};
use aether::certificates::encoding::{
    Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::status::AstraSignerResult;
use aether::certificates::transport::{OperatorAuthorityStatus, TrustUpdateObject};
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::handoff::DomainHandoff;
use crate::vault::AuthorityVault;
use crate::{credentials, documents, handoff, prepared, store};

/// Name of the journal, beside the vault.
pub const ROTATION_JOURNAL_FILE: &str = "astra-rotation-journal.json";

/// The only journal format this build reads.
pub const ROTATION_JOURNAL_VERSION: u16 = 1;

/// Name of the CA-PQ journal `astra-signer` writes, beside the vault.
pub const LEGACY_CA_PQ_JOURNAL_FILE: &str = "ca-pq-rotation.pending.json";

/// The only format of that journal there has been.
pub const LEGACY_CA_PQ_JOURNAL_VERSION: u16 = 1;

/// Largest journal read, in bytes.
///
/// It holds a vault, which [`store`] bounds at 1 MiB, beside documents
/// [`documents`] bounds at as much. A journal written and then refused at the
/// read would strand its rotation, so this sits above what it can carry.
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;

/// How long a prepared record's campaign can have lived.
///
/// The record did not keep the expiry, and a campaign's window is at most this
/// (§7.6). Reading it as an upper bound costs one refused replay at worst, and
/// a refused deposit then reads the authority like a dead campaign.
const LEGACY_CAMPAIGN_WINDOW_SECS: u64 = 300;

/// Which anchor a rotation replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationKind {
    CaPq,
    CaTls,
}

/// How far a rotation has come. Each stage holds for everything before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalStage {
    /// Signed and written; Astra may not have heard of it.
    Signed,
    /// Astra holds it; the vault in place may not have moved yet.
    Accepted,
    /// The vault, the credentials and the relay are in place.
    Applied,
    /// The gateway holds the transition; only the vault copy remains.
    Installed,
}

/// The signed object the gateway has to install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationTransition {
    CaPq(Box<CaTransition>),
    CaTls(Box<ClientTlsCaTransition>),
}

impl RotationTransition {
    pub fn kind(&self) -> RotationKind {
        match self {
            Self::CaPq(_) => RotationKind::CaPq,
            Self::CaTls(_) => RotationKind::CaTls,
        }
    }

    /// The incoming anchor, as Astra and the gateway report it.
    pub fn next_anchor_fingerprint(&self) -> Fingerprint {
        match self {
            Self::CaPq(transition) => transition.next_ca_public_key.authority_fingerprint(),
            Self::CaTls(transition) => transition.next_client_tls_ca_certificate.fingerprint(),
        }
    }

    pub fn window(&self) -> TransitionWindow {
        match self {
            Self::CaPq(transition) => transition.window,
            Self::CaTls(transition) => transition.window,
        }
    }
}

/// What replaces the files beside the vault once Astra accepted.
///
/// `handoff.vault_fingerprint` must name `vault`: [`save`] refuses a relay that
/// describes another vault than the one it lands with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextLocal {
    pub vault: AuthorityVault,
    pub credentials: Option<CredentialRegistry>,
    pub handoff: DomainHandoff,
}

/// The deposit a rotation still owes, or has made.
///
/// Identical bytes under the same operation are the same deposit to Astra, which
/// is why this is stored rather than rebuilt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalDeposit {
    pub operation_id: Id16,
    /// Bearer token for that one deposit.
    pub result_token: String,
    pub result: AstraSignerResult,
}

/// Leaves the token out: it is the one field here that opens something.
impl std::fmt::Debug for JournalDeposit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JournalDeposit")
            .field("operation_id", &self.operation_id)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

/// A rotation between its signature and the gateway's confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationJournal {
    pub format_version: u16,
    pub kind: RotationKind,
    pub stage: JournalStage,
    /// `None` only for an adopted CA-PQ journal: written after its deposit, that
    /// format holds no token and no result, and Astra already has them.
    pub deposit: Option<JournalDeposit>,
    pub transition: RotationTransition,
    /// `None` once applied, or for an adopted record whose vault had already
    /// moved. That absence is what forbids discarding it.
    pub next: Option<NextLocal>,
    pub next_anchor_fingerprint: Fingerprint,
    pub campaign_expires_at: u64,
    pub activation_at: u64,
    pub not_after: u64,
    pub signed_at: u64,
}

impl RotationJournal {
    /// Refuses a journal that contradicts itself, on both sides of the disk.
    fn validate(&self) -> Result<()> {
        if self.format_version != ROTATION_JOURNAL_VERSION {
            bail!(
                "version de journal de rotation non supportée : {}",
                self.format_version
            );
        }
        let window = self.transition.window();
        if self.kind != self.transition.kind()
            || self.next_anchor_fingerprint != self.transition.next_anchor_fingerprint()
            || self.activation_at != window.activation_at
            || self.not_after != window.not_after
        {
            bail!("le journal de rotation ne décrit pas la transition qu'il porte");
        }
        if self.stage == JournalStage::Signed && self.deposit.is_none() {
            bail!("le journal de rotation n'a aucun dépôt à rejouer");
        }
        if matches!(self.stage, JournalStage::Applied | JournalStage::Installed)
            && self.next.is_some()
        {
            bail!("le journal de rotation porte encore un coffre après l'avoir appliqué");
        }
        if let Some(next) = &self.next {
            if next.handoff.vault_fingerprint != next.vault.fingerprint()?.to_hex()
                || next.handoff.ca_pq_public_key != next.vault.ca_pq_public_key
            {
                bail!("le relais du journal de rotation décrit un autre coffre");
            }
        }
        Ok(())
    }
}

/// Where the journal sits: beside the vault, whatever its path.
pub fn path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(ROTATION_JOURNAL_FILE)
}

/// Reads the journal, or `None` when no rotation is outstanding.
///
/// A file that cannot be read is an error and not an absence: read as absent,
/// it would let a second rotation open over the one it records.
pub fn load(path: &Path) -> Result<Option<RotationJournal>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("lecture de {}", path.display())),
    };
    if metadata.len() > MAX_JOURNAL_BYTES {
        bail!(
            "{} pèse {} octets : ce n'est pas un journal de rotation",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    let journal: RotationJournal = serde_json::from_slice(&bytes)
        .with_context(|| format!("lecture du journal de rotation {}", path.display()))?;
    journal
        .validate()
        .with_context(|| format!("lecture du journal de rotation {}", path.display()))?;
    Ok(Some(journal))
}

/// Writes the journal, atomically and privately.
///
/// On failure the previous state stays whole. This comes before any deposit, so
/// a full disk stops the rotation while nobody has heard of it.
pub fn save(path: &Path, journal: &RotationJournal) -> Result<()> {
    journal.validate()?;
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes =
        serde_json::to_vec_pretty(journal).context("sérialisation du journal de rotation")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

/// Removes the journal. Already gone is success: absence is the resting state.
pub fn clear(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("suppression de {}", path.display())),
    }
}

/// Refuses a new rotation over a journal in place.
///
/// By presence and not by [`load`]: a file too damaged to read still records a
/// rotation, and it is no reason to sign another.
pub fn ensure_none_in_flight(vault_path: &Path) -> Result<()> {
    let path = path_beside(vault_path);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => bail!(
            "une rotation est en cours ({}) : la mener à son terme dans Orion avant d'en ouvrir \
             une autre. Rien n'a été signé.",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("lecture de {}", path.display())),
    }
}

/// Puts the next vault, its credentials and its relay in place.
///
/// Every write is atomic and the journal keeps `next` until all have landed, so
/// any prefix of this sequence is replayed from the top. Refused at
/// [`JournalStage::Signed`]: a caller that learned from Astra that the rotation
/// was accepted records [`JournalStage::Accepted`] first. Past
/// [`JournalStage::Accepted`] it changes nothing, so as not to overwrite a vault
/// that has moved on since.
pub fn apply_local(vault_path: &Path, journal: &mut RotationJournal) -> Result<()> {
    match journal.stage {
        JournalStage::Signed => {
            bail!("Astra n'a pas accepté cette rotation : le coffre en place ne bouge pas");
        }
        JournalStage::Accepted => {}
        JournalStage::Applied | JournalStage::Installed => return Ok(()),
    }
    if let Some(next) = &journal.next {
        store::save(vault_path, &next.vault)?;
        if let Some(registry) = &next.credentials {
            credentials::save(&credentials::path_beside(vault_path), registry)?;
        }
        handoff::save(&handoff::path_beside(vault_path), &next.handoff)?;
    }
    let applied = RotationJournal {
        stage: JournalStage::Applied,
        next: None,
        ..journal.clone()
    };
    save(&path_beside(vault_path), &applied)?;
    *journal = applied;
    Ok(())
}

/// The CA-PQ journal `astra-signer` writes before replacing the four files of a
/// rotation, and resumes from.
///
/// Its format, which this module also reads: an operator may hold one whose
/// vault was never applied, and that vault cannot be signed again.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCaPqJournal {
    pub format_version: u16,
    pub output_path: PathBuf,
    pub current_ca_public_key: MlDsa87PublicKey,
    pub vault: AuthorityVault,
    pub bindings: CredentialRegistry,
    pub transition: CaTransition,
    pub handoff: DomainHandoff,
}

impl LegacyCaPqJournal {
    /// Checks every signature and that the three documents describe one vault.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != LEGACY_CA_PQ_JOURNAL_VERSION {
            bail!("version de journal de rotation CA-PQ non supportée");
        }
        let domain = TrustDomainId::parse_hex(&self.handoff.trust_domain_id)?;
        let gateway = WireGuardKey::parse(self.handoff.require(
            self.handoff.gateway_wg_public_key.as_ref(),
            "la clé publique de la gateway",
            "--gateway-wg-public-key",
        )?)?;
        self.transition.verify(
            &self.current_ca_public_key,
            &domain,
            self.transition.current_ca_epoch,
        )?;
        let next_ca = MlDsa87PublicKey::parse(self.vault.ca_pq_public_key.trim())?;
        if next_ca != self.transition.next_ca_public_key
            || self.handoff.ca_epoch != Some(self.transition.next_ca_epoch)
            || self.handoff.ca_pq_public_key != self.vault.ca_pq_public_key
            || self.handoff.vault_fingerprint != self.vault.fingerprint()?.to_hex()
        {
            bail!("le journal CA-PQ ne décrit pas un coffre, une transition et un relais uniques");
        }
        self.bindings.verify(
            &next_ca,
            &domain,
            &gateway,
            self.transition.next_ca_epoch,
            self.bindings.credential_registry_epoch,
        )?;
        Ok(())
    }

    /// Accepted with its vault still to apply: this format is written after the
    /// deposit, and it holds nothing to replay one with.
    fn adopted(self) -> Result<RotationJournal> {
        self.validate()?;
        let window = self.transition.window;
        Ok(RotationJournal {
            format_version: ROTATION_JOURNAL_VERSION,
            kind: RotationKind::CaPq,
            stage: JournalStage::Accepted,
            deposit: None,
            next_anchor_fingerprint: self.transition.next_ca_public_key.authority_fingerprint(),
            transition: RotationTransition::CaPq(Box::new(self.transition)),
            next: Some(NextLocal {
                vault: self.vault,
                credentials: Some(self.bindings),
                handoff: self.handoff,
            }),
            campaign_expires_at: window.not_before,
            activation_at: window.activation_at,
            not_after: window.not_after,
            signed_at: window.not_before,
        })
    }
}

/// Where `astra-signer` leaves its CA-PQ journal: beside the vault.
pub fn legacy_ca_pq_path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(LEGACY_CA_PQ_JOURNAL_FILE)
}

/// A prepared record, whose vault moved before its deposit: nothing to apply.
fn adopted_prepared(record: prepared::PreparedRotation) -> Result<RotationJournal> {
    let prepared::PreparedRotation {
        kind: prepared::PreparedKind::CaTls,
        operation_id,
        result_token,
        result,
        next_ca_tls_epoch,
        next_ca_tls_certificate,
        activation_at,
        not_after,
        submitted,
        prepared_at,
        ..
    } = record;
    let operation_id = Id16::parse_hex(&operation_id)
        .map_err(|error| anyhow::anyhow!("rotation préparée illisible : {error}"))?;
    let transition = result
        .objects
        .iter()
        .find_map(|object| match object {
            TrustUpdateObject::ClientTlsCaTransition(transition) => Some(transition.clone()),
            _ => None,
        })
        .context("la rotation préparée ne porte aucune transition CA-TLS")?;
    if transition.next_ca_tls_epoch != next_ca_tls_epoch
        || transition.next_client_tls_ca_certificate.to_base64() != next_ca_tls_certificate
    {
        bail!("la rotation préparée ne décrit pas la transition qu'elle porte");
    }
    Ok(RotationJournal {
        format_version: ROTATION_JOURNAL_VERSION,
        kind: RotationKind::CaTls,
        stage: if submitted {
            JournalStage::Accepted
        } else {
            JournalStage::Signed
        },
        deposit: Some(JournalDeposit {
            operation_id,
            result_token,
            result,
        }),
        next_anchor_fingerprint: transition.next_client_tls_ca_certificate.fingerprint(),
        transition: RotationTransition::CaTls(transition),
        next: None,
        campaign_expires_at: prepared_at.saturating_add(LEGACY_CAMPAIGN_WINDOW_SECS),
        activation_at,
        not_after,
        signed_at: prepared_at,
    })
}

/// Turns what `astra-signer` left behind into the journal, and returns the
/// journal to resume: the adopted one, or the one already in place.
///
/// The CA-PQ journal goes first, because its vault is the one not yet applied.
/// It is removed once carried over: everything in it now lives in the journal
/// but `output_path`, a file the gateway no longer needs since the transition
/// travels through the tunnel.
///
/// The prepared record **stays**: `promote-ca-tls` reads it until `not_after`,
/// and it is what names the incoming certificate on the relay at that moment.
/// Adopting it again once its journal has ended replays a few idempotent calls,
/// with no key. A journal already in place wins over it, so it waits its turn
/// rather than overwriting a rotation further along.
///
/// A CA-PQ journal and a journal in place naming different anchors are two
/// rotations this machine cannot reconcile: refused, with both files intact.
pub fn adopt_legacy(vault_path: &Path) -> Result<Option<RotationJournal>> {
    let journal_path = path_beside(vault_path);
    let in_place = load(&journal_path)?;

    let ca_pq_path = legacy_ca_pq_path_beside(vault_path);
    let legacy_ca_pq = match std::fs::metadata(&ca_pq_path) {
        Ok(_) => Some(documents::read::<LegacyCaPqJournal>(&ca_pq_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("lecture de {}", ca_pq_path.display()))
        }
    };
    if let Some(legacy) = legacy_ca_pq {
        let adopted = legacy.adopted()?;
        let journal = match in_place {
            None => {
                save(&journal_path, &adopted)?;
                adopted
            }
            // A stop between the two writes of an earlier adoption: the journal
            // may be further along, and the legacy file is what remains to go.
            Some(in_place) if in_place.next_anchor_fingerprint == adopted.next_anchor_fingerprint => {
                in_place
            }
            Some(in_place) => bail!(
                "{} et {} décrivent deux rotations différentes (vers {} et vers {}) : les concilier \
                 n'est pas à Orion. Rien n'a été modifié.",
                ca_pq_path.display(),
                journal_path.display(),
                adopted.next_anchor_fingerprint,
                in_place.next_anchor_fingerprint
            ),
        };
        std::fs::remove_file(&ca_pq_path)
            .with_context(|| format!("suppression de {}", ca_pq_path.display()))?;
        return Ok(Some(journal));
    }

    if in_place.is_some() {
        return Ok(in_place);
    }
    let Some(record) = prepared::load(&prepared::path_beside(vault_path))? else {
        return Ok(None);
    };
    let adopted = adopted_prepared(record)?;
    save(&journal_path, &adopted)?;
    Ok(Some(adopted))
}

/// What the caller has learned so far, and what [`next_step`] decides from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeFacts {
    pub now: u64,
    /// Astra answered the replayed deposit with a refusal, and not silence.
    pub deposit_refused: bool,
    /// Astra's status, once read. `None` means not read yet, and
    /// [`ResumeStep::ReadAuthority`] asks for it.
    pub authority: Option<OperatorAuthorityStatus>,
    /// `Tunnel::gateway_next_anchor` of the rotation's kind: the next anchor, or
    /// the current one when none is in flight. Read before asking about a
    /// rotation at [`JournalStage::Applied`]: a failed read is a failure to
    /// report, and `None` here means the gateway named no such anchor.
    pub gateway_next: Option<Fingerprint>,
}

/// What a resume does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeStep {
    /// Replay the identical deposit.
    Deposit,
    /// Read `operator/status`, and ask again.
    ReadAuthority,
    /// Record [`JournalStage::Accepted`] if need be, then [`apply_local`].
    ApplyLocal,
    /// Send the transition to the gateway, which answers `already_present` to a
    /// replay.
    Install,
    /// Send the vault copy. A failure does not undo the rotation.
    SendVaultCopy,
    /// The driver's own answer once the copy was attempted and the journal
    /// cleared. [`next_step`] never returns it: a journal in place is not done.
    Finished,
    /// Astra knows nothing of it and the vault in place never moved: clear the
    /// journal, and nothing is lost but the touches.
    Discard,
    /// The domain contradicts this journal. Nothing is cleared: it is not for
    /// this machine to choose.
    DomainConflict,
    /// `activation_at` passed with the transition not on the gateway. It refuses
    /// it from now on, and no repair exists (spec §5.4).
    InstallDeadlinePassed,
}

/// The table of spec §5.4.
pub fn next_step(journal: &RotationJournal, facts: &ResumeFacts) -> ResumeStep {
    match journal.stage {
        JournalStage::Signed => next_step_of_signed(journal, facts),
        JournalStage::Accepted => ResumeStep::ApplyLocal,
        JournalStage::Applied => {
            // Checked before the clock: past `activation_at` the gateway refuses
            // a first installation, but one it already holds is not lost.
            if facts.gateway_next == Some(journal.next_anchor_fingerprint) {
                ResumeStep::SendVaultCopy
            } else if facts.now >= journal.activation_at {
                ResumeStep::InstallDeadlinePassed
            } else {
                ResumeStep::Install
            }
        }
        JournalStage::Installed => ResumeStep::SendVaultCopy,
    }
}

fn next_step_of_signed(journal: &RotationJournal, facts: &ResumeFacts) -> ResumeStep {
    let campaign_lives = facts.now < journal.campaign_expires_at;
    if journal.deposit.is_some() && campaign_lives && !facts.deposit_refused {
        return ResumeStep::Deposit;
    }
    let Some(authority) = &facts.authority else {
        return ResumeStep::ReadAuthority;
    };
    let (current, next) = match journal.kind {
        RotationKind::CaPq => (
            Some(authority.ca_fingerprint),
            authority.next_ca_fingerprint,
        ),
        RotationKind::CaTls => (
            authority.ca_tls_fingerprint,
            authority.next_ca_tls_fingerprint,
        ),
    };
    let accepted = [current, next].contains(&Some(journal.next_anchor_fingerprint));
    if accepted {
        ResumeStep::ApplyLocal
    } else if next.is_some() || journal.next.is_none() {
        // With no `next`, the vault in place is already the rotated one, and
        // clearing the only record of that would hide what Astra does not know.
        ResumeStep::DomainConflict
    } else {
        ResumeStep::Discard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{DerCertificate, MlDsa87Signature, WireGuardKey};
    use aether::certificates::status::CampaignApproval;
    use aether::certificates::transport::OperatorAuthorityStatus;
    use aether::certificates::window::TransitionWindow;

    const NOW: u64 = 1_000;
    const EXPIRES: u64 = NOW + 300;
    const ACTIVATION: u64 = NOW + 7 * 86_400;
    const NOT_AFTER: u64 = ACTIVATION + 30 * 86_400;

    fn domain() -> TrustDomainId {
        TrustDomainId::new([3; 16]).expect("domain")
    }

    fn vault(seed: u8) -> AuthorityVault {
        AuthorityVault {
            format_version: 1,
            vault_id: [seed; 16],
            trust_domain_id: domain(),
            ca_pq_public_key: format!("clé publique {seed}"),
            rp_id: "astra.helios.test".into(),
            created_at: 1,
            salt: "sel".into(),
            slots: Vec::new(),
            sealed_payload: format!("corps scellé {seed}"),
        }
    }

    fn registry(epoch: u64) -> CredentialRegistry {
        CredentialRegistry {
            trust_domain_id: domain(),
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            ca_epoch: 2,
            credential_registry_epoch: epoch,
            bindings: Vec::new(),
        }
    }

    fn window() -> TransitionWindow {
        TransitionWindow {
            not_before: NOW,
            activation_at: ACTIVATION,
            not_after: NOT_AFTER,
        }
    }

    fn ca_tls_transition() -> ClientTlsCaTransition {
        ClientTlsCaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            current_ca_tls_epoch: 1,
            next_ca_tls_epoch: 2,
            active_client_tls_ca_fingerprint: Fingerprint::of(b"ancre sortante"),
            next_client_tls_ca_certificate: DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
                .expect("certificate"),
            window: window(),
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
    }

    fn deposit() -> JournalDeposit {
        JournalDeposit {
            operation_id: Id16::new([4; 16]).expect("id"),
            result_token: "jeton-de-depot".into(),
            result: AstraSignerResult {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                approval: Box::new(CampaignApproval {
                    campaign_id: Id16::new([5; 16]).expect("id"),
                    campaign_fingerprint: Fingerprint::of(b"campagne"),
                    required_credentials: 2,
                    approved_at: NOW,
                    approvals: Vec::new(),
                }),
                objects: Vec::new(),
                credential_registry: None,
                issuer_authorization: None,
            },
        }
    }

    fn next_local() -> NextLocal {
        let vault = vault(2);
        let handoff = DomainHandoff::of(&vault).expect("handoff");
        NextLocal {
            vault,
            credentials: Some(registry(7)),
            handoff,
        }
    }

    fn journal(stage: JournalStage) -> RotationJournal {
        let transition = ca_tls_transition();
        RotationJournal {
            format_version: ROTATION_JOURNAL_VERSION,
            kind: RotationKind::CaTls,
            stage,
            deposit: Some(deposit()),
            next_anchor_fingerprint: transition.next_client_tls_ca_certificate.fingerprint(),
            transition: RotationTransition::CaTls(Box::new(transition)),
            next: match stage {
                JournalStage::Signed | JournalStage::Accepted => Some(next_local()),
                JournalStage::Applied | JournalStage::Installed => None,
            },
            campaign_expires_at: EXPIRES,
            activation_at: ACTIVATION,
            not_after: NOT_AFTER,
            signed_at: NOW,
        }
    }

    fn ca_pq_journal(stage: JournalStage) -> RotationJournal {
        let (_, public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keys");
        let transition = CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: Fingerprint::of(b"ancre sortante"),
            next_ca_fingerprint: public.authority_fingerprint(),
            next_ca_public_key: public,
            window: window(),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        };
        RotationJournal {
            kind: RotationKind::CaPq,
            next_anchor_fingerprint: transition.next_ca_fingerprint,
            transition: RotationTransition::CaPq(Box::new(transition)),
            ..journal(stage)
        }
    }

    fn facts(now: u64) -> ResumeFacts {
        ResumeFacts {
            now,
            deposit_refused: false,
            authority: None,
            gateway_next: None,
        }
    }

    fn authority() -> OperatorAuthorityStatus {
        OperatorAuthorityStatus {
            ca_epoch: 1,
            ca_fingerprint: Fingerprint::of(b"ca en service"),
            next_ca_fingerprint: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: Some(Fingerprint::of(b"ca tls en service")),
            next_ca_tls_fingerprint: None,
            issuer: None,
            vault_copy_fingerprint: None,
            credential_registry_epoch: None,
        }
    }

    fn with_authority(now: u64, status: OperatorAuthorityStatus) -> ResumeFacts {
        ResumeFacts {
            authority: Some(status),
            ..facts(now)
        }
    }

    /// A directory holding the vault in place, and its neighbours.
    struct Place {
        _directory: tempfile::TempDir,
        vault_path: PathBuf,
        journal_path: PathBuf,
    }

    fn place() -> Place {
        let directory = tempfile::tempdir().expect("dir");
        let vault_path = directory.path().join("authority-vault.json");
        crate::store::save(&vault_path, &vault(1)).expect("vault");
        let journal_path = path_beside(&vault_path);
        Place {
            _directory: directory,
            vault_path,
            journal_path,
        }
    }

    // The table of §5.4.

    #[test]
    fn signed_with_a_live_campaign_replays_the_deposit() {
        let step = next_step(&journal(JournalStage::Signed), &facts(EXPIRES - 1));
        assert_eq!(step, ResumeStep::Deposit);
    }

    #[test]
    fn signed_refused_or_dead_reads_the_authority() {
        let signed = journal(JournalStage::Signed);
        assert_eq!(
            next_step(&signed, &facts(EXPIRES)),
            ResumeStep::ReadAuthority
        );
        let refused = ResumeFacts {
            deposit_refused: true,
            ..facts(NOW)
        };
        assert_eq!(next_step(&signed, &refused), ResumeStep::ReadAuthority);
    }

    #[test]
    fn dead_and_accepted_applies() {
        let signed = journal(JournalStage::Signed);
        let fingerprint = signed.next_anchor_fingerprint;
        // Accepted, its answer lost: still in flight on Astra.
        let in_flight = OperatorAuthorityStatus {
            next_ca_tls_fingerprint: Some(fingerprint),
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, in_flight)),
            ResumeStep::ApplyLocal
        );
        // Accepted so long ago that Astra has already promoted it.
        let promoted = OperatorAuthorityStatus {
            ca_tls_fingerprint: Some(fingerprint),
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, promoted)),
            ResumeStep::ApplyLocal
        );
    }

    /// The anchors compared are those of the rotation's own family: a CA-PQ
    /// rotation in flight says nothing about a client TLS one.
    #[test]
    fn dead_and_accepted_reads_the_fields_of_its_own_family() {
        let signed = ca_pq_journal(JournalStage::Signed);
        let fingerprint = signed.next_anchor_fingerprint;
        let in_flight = OperatorAuthorityStatus {
            next_ca_fingerprint: Some(fingerprint),
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, in_flight)),
            ResumeStep::ApplyLocal
        );
        let promoted = OperatorAuthorityStatus {
            ca_fingerprint: fingerprint,
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, promoted)),
            ResumeStep::ApplyLocal
        );
        let other_family = OperatorAuthorityStatus {
            next_ca_tls_fingerprint: Some(fingerprint),
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, other_family)),
            ResumeStep::Discard
        );
    }

    #[test]
    fn dead_and_nothing_in_flight_discards() {
        let signed = journal(JournalStage::Signed);
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, authority())),
            ResumeStep::Discard
        );
    }

    #[test]
    fn dead_and_another_rotation_in_flight_conflicts() {
        let signed = journal(JournalStage::Signed);
        let other = OperatorAuthorityStatus {
            next_ca_tls_fingerprint: Some(Fingerprint::of(b"une autre")),
            ..authority()
        };
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, other)),
            ResumeStep::DomainConflict
        );
    }

    /// A refused deposit reads the authority even inside the campaign's life,
    /// and a read in hand decides at once.
    #[test]
    fn a_refused_deposit_is_decided_by_the_authority_while_the_campaign_lives() {
        let signed = journal(JournalStage::Signed);
        let refused = ResumeFacts {
            deposit_refused: true,
            ..with_authority(NOW, authority())
        };
        assert_eq!(next_step(&signed, &refused), ResumeStep::Discard);
    }

    #[test]
    fn accepted_applies_whatever_the_clock_says() {
        let accepted = journal(JournalStage::Accepted);
        assert_eq!(next_step(&accepted, &facts(NOW)), ResumeStep::ApplyLocal);
        assert_eq!(
            next_step(&accepted, &facts(NOT_AFTER + 1)),
            ResumeStep::ApplyLocal
        );
    }

    #[test]
    fn applied_before_activation_installs() {
        let applied = journal(JournalStage::Applied);
        assert_eq!(
            next_step(&applied, &facts(ACTIVATION - 1)),
            ResumeStep::Install
        );
    }

    #[test]
    fn applied_past_activation_and_not_on_the_gateway_is_a_dead_end() {
        let applied = journal(JournalStage::Applied);
        assert_eq!(
            next_step(&applied, &facts(ACTIVATION)),
            ResumeStep::InstallDeadlinePassed
        );
        let other = ResumeFacts {
            gateway_next: Some(Fingerprint::of(b"une autre")),
            ..facts(NOT_AFTER)
        };
        assert_eq!(
            next_step(&applied, &other),
            ResumeStep::InstallDeadlinePassed
        );
    }

    /// `gateway_next` is the next anchor, or the current one when nothing is in
    /// flight: past `not_after` the rotation is promoted and still counts.
    #[test]
    fn applied_past_activation_but_present_on_the_gateway_moves_on() {
        let applied = journal(JournalStage::Applied);
        let present = ResumeFacts {
            gateway_next: Some(applied.next_anchor_fingerprint),
            ..facts(NOT_AFTER + 1)
        };
        assert_eq!(next_step(&applied, &present), ResumeStep::SendVaultCopy);
    }

    #[test]
    fn installed_sends_the_copy() {
        assert_eq!(
            next_step(&journal(JournalStage::Installed), &facts(NOT_AFTER + 1)),
            ResumeStep::SendVaultCopy
        );
    }

    // The file.

    #[test]
    fn what_is_written_is_what_comes_back() {
        let place = place();
        assert_eq!(load(&place.journal_path).expect("load"), None);
        for candidate in [
            journal(JournalStage::Signed),
            journal(JournalStage::Installed),
            ca_pq_journal(JournalStage::Accepted),
        ] {
            save(&place.journal_path, &candidate).expect("save");
            assert_eq!(load(&place.journal_path).expect("load"), Some(candidate));
        }
    }

    #[test]
    fn the_journal_sits_beside_the_vault() {
        assert_eq!(
            path_beside(Path::new("/coffre/authority-vault.json")),
            Path::new("/coffre").join(ROTATION_JOURNAL_FILE)
        );
        assert_eq!(ROTATION_JOURNAL_FILE, "astra-rotation-journal.json");
    }

    #[cfg(unix)]
    #[test]
    fn the_journal_is_private_like_the_vault() {
        use std::os::unix::fs::PermissionsExt as _;
        let place = place();
        save(&place.journal_path, &journal(JournalStage::Signed)).expect("save");
        let mode = std::fs::metadata(&place.journal_path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_journal_gone_after_the_rotation_ends_is_no_journal() {
        let place = place();
        save(&place.journal_path, &journal(JournalStage::Installed)).expect("save");
        clear(&place.journal_path).expect("clear");
        assert_eq!(load(&place.journal_path).expect("load"), None);
        // Absence is the resting state: clearing twice is not a fault.
        clear(&place.journal_path).expect("clear again");
    }

    /// A journal that cannot be read must stop everything: read as absent, it
    /// would let a second rotation open over the one it records.
    #[test]
    fn an_unreadable_journal_is_an_error_and_not_an_absence() {
        let place = place();
        std::fs::write(&place.journal_path, b"{\"format_version\":1,").expect("write");
        assert!(load(&place.journal_path).is_err());
    }

    #[test]
    fn a_journal_of_another_format_version_is_refused() {
        let place = place();
        let mut future = serde_json::to_value(journal(JournalStage::Signed)).expect("value");
        future["format_version"] = serde_json::json!(ROTATION_JOURNAL_VERSION + 1);
        std::fs::write(
            &place.journal_path,
            serde_json::to_vec(&future).expect("bytes"),
        )
        .expect("write");
        assert!(load(&place.journal_path).is_err());
    }

    #[test]
    fn a_journal_that_contradicts_itself_is_neither_written_nor_read() {
        let place = place();
        let contradictions = [
            RotationJournal {
                kind: RotationKind::CaPq,
                ..journal(JournalStage::Signed)
            },
            RotationJournal {
                next_anchor_fingerprint: Fingerprint::of(b"une autre"),
                ..journal(JournalStage::Signed)
            },
            RotationJournal {
                activation_at: ACTIVATION + 1,
                ..journal(JournalStage::Signed)
            },
            RotationJournal {
                not_after: NOT_AFTER + 1,
                ..journal(JournalStage::Signed)
            },
            // Nothing to replay, in the one stage that replays.
            RotationJournal {
                deposit: None,
                ..journal(JournalStage::Signed)
            },
            // A vault left to apply, past the stage that applies it.
            RotationJournal {
                next: Some(next_local()),
                ..journal(JournalStage::Applied)
            },
            // A relay describing another vault than the one it would land with.
            RotationJournal {
                next: Some(NextLocal {
                    vault: vault(8),
                    ..next_local()
                }),
                ..journal(JournalStage::Accepted)
            },
        ];
        for contradiction in contradictions {
            assert!(
                save(&place.journal_path, &contradiction).is_err(),
                "{contradiction:?}"
            );
            std::fs::write(
                &place.journal_path,
                serde_json::to_vec(&contradiction).expect("bytes"),
            )
            .expect("write");
            assert!(load(&place.journal_path).is_err(), "{contradiction:?}");
            std::fs::remove_file(&place.journal_path).expect("remove");
        }
    }

    #[test]
    fn the_deposit_token_never_reaches_a_log_through_debug() {
        let rendered = format!("{:?}", journal(JournalStage::Signed));
        assert!(!rendered.contains("jeton-de-depot"), "{rendered}");
    }

    /// Review Focus 3: a disk that refuses the journal leaves nothing behind
    /// and moves nothing, so the deposit that follows it never happens.
    #[cfg(unix)]
    #[test]
    fn a_failed_journal_write_leaves_no_journal_and_the_old_vault() {
        use std::os::unix::fs::PermissionsExt as _;
        let place = place();
        let directory = place.vault_path.parent().expect("parent").to_path_buf();
        let vault_before = std::fs::read(&place.vault_path).expect("vault");

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("read only");
        // Superuser writes through the mode, and proves nothing here.
        let probe = directory.join("sonde");
        if std::fs::write(&probe, b"x").is_ok() {
            std::fs::remove_file(&probe).expect("remove probe");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("restore");
            return;
        }

        let refused = save(&place.journal_path, &journal(JournalStage::Signed));
        let loaded = load(&place.journal_path);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore");

        assert!(refused.is_err());
        assert_eq!(loaded.expect("load"), None);
        assert_eq!(
            std::fs::read(&place.vault_path).expect("vault"),
            vault_before
        );
        let names: Vec<_> = std::fs::read_dir(&directory)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 1, "no partial file: {names:?}");
    }

    /// The same refusal over a journal already there keeps the state before it.
    #[cfg(unix)]
    #[test]
    fn a_failed_rewrite_keeps_the_previous_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let place = place();
        let directory = place.vault_path.parent().expect("parent").to_path_buf();
        let previous = journal(JournalStage::Signed);
        save(&place.journal_path, &previous).expect("save");

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("read only");
        let probe = directory.join("sonde");
        if std::fs::write(&probe, b"x").is_ok() {
            std::fs::remove_file(&probe).expect("remove probe");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("restore");
            return;
        }
        let refused = save(&place.journal_path, &journal(JournalStage::Accepted));
        let loaded = load(&place.journal_path);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore");

        assert!(refused.is_err());
        assert_eq!(loaded.expect("load"), Some(previous));
    }

    // Applying.

    fn assert_applied(place: &Place, applied: &RotationJournal) {
        let next = next_local();
        assert_eq!(applied.stage, JournalStage::Applied);
        assert_eq!(applied.next, None);
        assert_eq!(
            crate::store::load(&place.vault_path).expect("vault"),
            next.vault
        );
        assert_eq!(
            crate::credentials::load(&crate::credentials::path_beside(&place.vault_path))
                .expect("credentials"),
            next.credentials
        );
        assert_eq!(
            crate::handoff::load(&crate::handoff::path_beside(&place.vault_path)).expect("relay"),
            next.handoff
        );
        assert_eq!(
            load(&place.journal_path).expect("load").as_ref(),
            Some(applied),
            "the journal on disk no longer holds the vault"
        );
    }

    #[test]
    fn apply_local_is_replayable_after_a_stop_between_writes() {
        let next = next_local();
        // A stop after each prefix of the writes, and after all of them with
        // the journal still saying Accepted.
        for prefix in 0..=3 {
            let place = place();
            let mut accepted = journal(JournalStage::Accepted);
            save(&place.journal_path, &accepted).expect("save");
            if prefix >= 1 {
                crate::store::save(&place.vault_path, &next.vault).expect("vault");
            }
            if prefix >= 2 {
                crate::credentials::save(
                    &crate::credentials::path_beside(&place.vault_path),
                    next.credentials.as_ref().expect("credentials"),
                )
                .expect("credentials");
            }
            if prefix >= 3 {
                crate::handoff::save(
                    &crate::handoff::path_beside(&place.vault_path),
                    &next.handoff,
                )
                .expect("relay");
            }
            apply_local(&place.vault_path, &mut accepted).expect("apply");
            assert_applied(&place, &accepted);
        }
    }

    /// Once applied, replaying must not touch the vault a later gesture may
    /// have moved on.
    #[test]
    fn apply_local_after_it_landed_changes_nothing() {
        let place = place();
        let mut applied = journal(JournalStage::Accepted);
        save(&place.journal_path, &applied).expect("save");
        apply_local(&place.vault_path, &mut applied).expect("apply");
        let vault_after = std::fs::read(&place.vault_path).expect("vault");

        apply_local(&place.vault_path, &mut applied).expect("replay");
        assert_eq!(applied.stage, JournalStage::Applied);
        assert_eq!(
            std::fs::read(&place.vault_path).expect("vault"),
            vault_after
        );

        let mut installed = journal(JournalStage::Installed);
        apply_local(&place.vault_path, &mut installed).expect("replay past applied");
        assert_eq!(installed.stage, JournalStage::Installed);
    }

    /// §5.4: the vault in place moves only after Astra accepted.
    #[test]
    fn apply_local_refuses_what_astra_has_not_accepted() {
        let place = place();
        let before = std::fs::read(&place.vault_path).expect("vault");
        let mut signed = journal(JournalStage::Signed);
        assert!(apply_local(&place.vault_path, &mut signed).is_err());
        assert_eq!(signed, journal(JournalStage::Signed));
        assert_eq!(std::fs::read(&place.vault_path).expect("vault"), before);
    }

    /// A record whose vault already moved has nothing left to write.
    #[test]
    fn apply_local_without_a_next_only_moves_the_stage() {
        let place = place();
        let before = std::fs::read(&place.vault_path).expect("vault");
        let mut accepted = RotationJournal {
            next: None,
            ..journal(JournalStage::Accepted)
        };
        save(&place.journal_path, &accepted).expect("save");
        apply_local(&place.vault_path, &mut accepted).expect("apply");
        assert_eq!(accepted.stage, JournalStage::Applied);
        assert_eq!(std::fs::read(&place.vault_path).expect("vault"), before);
    }

    #[test]
    fn discard_leaves_the_vault_bytes_untouched() {
        let place = place();
        let before = std::fs::read(&place.vault_path).expect("vault");
        let signed = journal(JournalStage::Signed);
        save(&place.journal_path, &signed).expect("save");
        assert_eq!(
            next_step(&signed, &with_authority(EXPIRES, authority())),
            ResumeStep::Discard
        );

        clear(&place.journal_path).expect("clear");

        assert_eq!(load(&place.journal_path).expect("load"), None);
        assert_eq!(std::fs::read(&place.vault_path).expect("vault"), before);
    }

    // What refuses to open over it.

    #[test]
    fn a_journal_in_place_refuses_a_new_rotation() {
        let place = place();
        ensure_none_in_flight(&place.vault_path).expect("no journal yet");
        // Presence decides, so a damaged file refuses as well.
        std::fs::write(&place.journal_path, b"illisible").expect("write");
        assert!(ensure_none_in_flight(&place.vault_path).is_err());
    }

    // Adoption's refusals; the two formats themselves are in
    // `tests/rotation_journal_legacy.rs`, where a real ceremony writes them.

    #[test]
    fn nothing_to_adopt_is_no_journal() {
        let place = place();
        assert_eq!(adopt_legacy(&place.vault_path).expect("adopt"), None);
        assert_eq!(load(&place.journal_path).expect("load"), None);
    }

    /// A record that names nothing it can install stays where it is, unadopted.
    #[test]
    fn a_prepared_record_without_its_transition_is_refused() {
        let place = place();
        let deposit = deposit();
        let record = crate::prepared::PreparedRotation {
            kind: crate::prepared::PreparedKind::CaTls,
            operation_id: deposit.operation_id.to_hex(),
            result_token: deposit.result_token.clone(),
            result: deposit.result,
            transition_path: "/tmp/transition.json".into(),
            next_ca_tls_epoch: 2,
            next_ca_tls_certificate: "REVS".into(),
            activation_at: ACTIVATION,
            not_after: NOT_AFTER,
            submitted: false,
            prepared_at: NOW,
            manifest: None,
        };
        let prepared_path = crate::prepared::path_beside(&place.vault_path);
        crate::prepared::save(&prepared_path, &record).expect("save");

        assert!(adopt_legacy(&place.vault_path).is_err());
        assert_eq!(load(&place.journal_path).expect("load"), None);
        assert_eq!(
            crate::prepared::load(&prepared_path).expect("load"),
            Some(record)
        );
    }
}
