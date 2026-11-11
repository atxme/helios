//! Orion's side of an operator ceremony (ADR-008 §9.4, §8.5, §7.5).
//!
//! # What runs here, and what does not cross a boundary
//!
//! The ceremony runs in a thread of this process, see [`ceremony`]. The
//! authority vault, the key gesture and every signature are reached from that
//! thread and nowhere else in the WebView's reach. F11 de-elevates this
//! process, and the ceremony does not depend on its token: the vault and the
//! key are opened by the same code whatever level the process holds.
//!
//! # What crosses
//!
//! Only [`OperatorStatus`] outward, through a `watch` channel, and a [`Press`]
//! inward, through a `mpsc` channel. A status carries two states, a typed
//! manifest, the labels of the key-slots that answered. A press carries an
//! action, the revision it answers and the window it came from. No PIN, no
//! assertion, no vault byte crosses either way. The WebView therefore renders
//! progress it cannot influence, and the refusals stay where the secrets are.
//!
//! # Files
//!
//! A ceremony that produces a file — an invitation, a `CA-TLS` — deposits it
//! in its session, and the window fetches it once with
//! [`OperatorCeremony::artifacts`] and saves it. It never rides the status.
//!
//! # Why the WebView names so little
//!
//! An [`OperationLocator`] — a kind, and at most an operation identifier Orion
//! itself opened. The authority origin, the RP ID, the domain and the service
//! key come from the hand-off pinned beside the vault. A WebView that sends a
//! press therefore buys the ability to answer a ceremony the operator started;
//! it does not buy the ability to choose one.

mod ceremony;
pub mod invitations;
pub mod location;
pub mod peers;
pub mod rotations;

use std::path::PathBuf;
use std::time::Duration;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    GestureState, OperationKind, OperationLocator, OperatorAction, OperatorStatus, Refusal,
    RemoteState,
};
use aether_fido::authenticator::DialogOwner;
use astra_operator::operations::rotation::RotationTerms;
use ceremony::Press;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{watch, Mutex};

/// How long a step may take before Orion stops waiting for the next state.
///
/// The steps that hold on a human — finding a key, touching it — are not
/// bounded here: the ceremony publishes a state of its own the moment it starts
/// working on them. This bounds the fetching and the signing between two such
/// states.
const STEP_TIMEOUT: Duration = Duration::from_secs(90);

/// Said when the ceremony stopped answering within [`STEP_TIMEOUT`].
const NOT_ANSWERING: &str = "la cérémonie opérateur ne répond plus";
/// Said when the ceremony's thread ended before the step it was asked for.
const STOPPED: &str = "la cérémonie opérateur s'est arrêtée";

/// Longest name an invitation file may carry.
const MAX_INVITATION_NAME: usize = 64;

/// A gesture of the enrollment ceremonies (§15.2), as the WebView names it.
///
/// Typed and closed: the page chooses among these three and fills their
/// parameters, and every value is validated here before a ceremony opens. A
/// file the operator picked travels by its public content only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentGesture {
    /// Signs an invitation aimed at the connected gateway.
    Invite {
        /// 1 to 24: an invitation is a short window, not a standing right.
        #[serde(deserialize_with = "invitation_hours")]
        valid_for_hours: u8,
        allow_readmission: bool,
        /// Becomes `<name>.helios-invite`; see [`valid_invitation_name`].
        name: String,
        /// The contents of the gateway's leaf, read from a file the operator
        /// chose, when no gateway is connected to read it from.
        #[serde(default)]
        gateway_pq_certificate: Option<String>,
    },
    /// Verifies a request, consumes its invitation, then issues the leaves.
    Accept {
        request: String,
        /// 1 to 1825 days; a year when absent.
        #[serde(default = "default_validity_days", deserialize_with = "validity_days")]
        validity_days: u16,
        endpoint: String,
        #[serde(default)]
        allowed_ips: Option<String>,
        #[serde(default)]
        ssh_target: Option<String>,
    },
    /// Finishes an acceptance whose leaves were issued but not delivered.
    Resume {
        invitation_id: Id16,
        endpoint: String,
        #[serde(default)]
        allowed_ips: Option<String>,
        #[serde(default)]
        ssh_target: Option<String>,
    },
}

fn default_validity_days() -> u16 {
    365
}

fn invitation_hours<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let hours = u8::deserialize(deserializer)?;
    if (1..=24).contains(&hours) {
        Ok(hours)
    } else {
        Err(serde::de::Error::custom(
            "une invitation dure entre 1 et 24 heures",
        ))
    }
}

fn validity_days<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    let days = u16::deserialize(deserializer)?;
    if (1..=1825).contains(&days) {
        Ok(days)
    } else {
        Err(serde::de::Error::custom(
            "la validité des feuilles est de 1 à 1825 jours",
        ))
    }
}

/// `[A-Za-z0-9._-]{1,64}`: the name ends up in a file name the WebView will
/// save, so nothing that could walk out of a folder or hide is accepted.
fn valid_invitation_name(name: &str) -> bool {
    (1..=MAX_INVITATION_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl EnrollmentGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Invite { name, .. } if !valid_invitation_name(name) => Err(
                "le nom de l'invitation tient en 1 à 64 caractères parmi lettres, chiffres, \
                 « . », « _ » et « - »"
                    .to_string(),
            ),
            _ => Ok(()),
        }
    }

    fn operation(&self) -> aether::certificates::operator_session::OperationKind {
        use aether::certificates::operator_session::OperationKind;
        match self {
            Self::Invite { .. } => OperationKind::InviteEnrollment,
            Self::Accept { .. } | Self::Resume { .. } => OperationKind::AcceptEnrollment,
        }
    }
}

/// A gesture on the vault or the domain, as the WebView names it.
///
/// Typed and closed like [`EnrollmentGesture`]: one kind per gesture, every
/// value validated here before a ceremony opens. A key is named by its slot
/// identifier, never by a path or a secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultGesture {
    /// The first vault of a domain, with its two keys.
    CreateDomain {
        rp_id: String,
        authority_url: String,
        first_label: String,
        second_label: String,
    },
    /// A further key, registered with a key the vault already opens for.
    AddKey { label: String, role: KeyRole },
    /// A key withdrawn from the vault.
    RemoveKey { slot_id: String },
    /// A key signed lost, or active again.
    MarkKey { slot_id: String, lost: bool },
    /// The domain's `CA-TLS` and credential document, issued once.
    FinalizeDomain,
    /// A gateway's leaf at epoch 1, from its public request, then whatever the
    /// domain still lacks. Only the request's text travels: a path never
    /// crosses from the WebView.
    BootstrapGateway { request: String },
}

/// The role of a key, under the names the overview gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum KeyRole {
    #[serde(rename = "principale")]
    Primary,
    #[serde(rename = "recuperation")]
    Recovery,
}

impl KeyRole {
    fn slot_role(self) -> astra_operator::vault::SlotRole {
        match self {
            Self::Primary => astra_operator::vault::SlotRole::Primary,
            Self::Recovery => astra_operator::vault::SlotRole::Recovery,
        }
    }

    fn of(role: astra_operator::vault::SlotRole) -> Self {
        match role {
            astra_operator::vault::SlotRole::Primary => Self::Primary,
            astra_operator::vault::SlotRole::Recovery => Self::Recovery,
        }
    }

    /// The name a manifest carries.
    fn name(self) -> &'static str {
        match self {
            Self::Primary => "principale",
            Self::Recovery => "recuperation",
        }
    }
}

/// Longest RP ID: a DNS name.
const MAX_RP_ID_CHARS: usize = 253;
/// Longest authority origin.
const MAX_AUTHORITY_URL_CHARS: usize = 256;

/// A WebAuthn RP ID this domain can be created under: a lowercase DNS name of
/// at least two labels, never an address — a credential is bound to it for
/// good. A last label of digits only is refused too: a browser's URL parser
/// reads such a host as an IPv4 address (`1.2.3`, `astra.123`).
fn valid_rp_id(rp_id: &str) -> bool {
    (1..=MAX_RP_ID_CHARS).contains(&rp_id.len())
        && !rp_id
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()))
        && rp_id.contains('.')
        && rp_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && rp_id
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        && rp_id.parse::<std::net::IpAddr>().is_err()
}

/// An origin the relay will record: `https://host[:port]`, nothing after the
/// host but a trailing `/`. The rule is the relay's own, applied on arrival so
/// a value it would refuse after the press opens no ceremony.
fn valid_authority_url(url: &str) -> bool {
    url.chars().count() <= MAX_AUTHORITY_URL_CHARS
        && !url.chars().any(char::is_whitespace)
        && astra_operator::vault_gestures::authority_origin(url).is_ok()
}

/// A key label the vault accepts: not blank, `MAX_LABEL_CHARS` at most.
fn check_key_label(label: &str) -> Result<(), String> {
    if !label.trim().is_empty() && label.chars().count() <= astra_operator::vault::MAX_LABEL_CHARS {
        Ok(())
    } else {
        Err(format!(
            "le nom d'une clé tient en 1 à {} caractères",
            astra_operator::vault::MAX_LABEL_CHARS
        ))
    }
}

/// The slot identifier the overview prints: 32 lowercase hexadecimals.
fn parse_slot_id(slot_id: &str) -> Result<[u8; 16], String> {
    Id16::parse_hex(slot_id)
        .map(|id| *id.as_bytes())
        .map_err(|_| "l'identifiant de la clé tient en 32 caractères hexadécimaux".to_string())
}

impl VaultGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::CreateDomain {
                rp_id,
                authority_url,
                first_label,
                second_label,
            } => {
                if !valid_rp_id(rp_id) {
                    return Err(
                        "l'identifiant WebAuthn du domaine est un nom DNS en minuscules, d'au \
                         moins deux libellés, et jamais une adresse IP"
                            .to_string(),
                    );
                }
                if !valid_authority_url(authority_url) {
                    return Err(format!(
                        "l'origine de l'autorité est https://hôte[:port], sans chemin ni \
                         espace, de {MAX_AUTHORITY_URL_CHARS} caractères au plus"
                    ));
                }
                check_key_label(first_label)?;
                check_key_label(second_label)
            }
            Self::AddKey { label, .. } => check_key_label(label),
            Self::RemoveKey { slot_id } | Self::MarkKey { slot_id, .. } => {
                parse_slot_id(slot_id).map(|_| ())
            }
            Self::FinalizeDomain => Ok(()),
            Self::BootstrapGateway { request } => {
                if request.trim().is_empty()
                    || request.len() > astra_operator::bootstrap::MAX_BOOTSTRAP_REQUEST_BYTES
                {
                    return Err(
                        "la demande d'amorçage est vide ou trop grande (256 Kio au plus)"
                            .to_string(),
                    );
                }
                Ok(())
            }
        }
    }

    fn operation(&self) -> OperationKind {
        match self {
            Self::CreateDomain { .. } => OperationKind::CreateDomain,
            Self::AddKey { .. } => OperationKind::AddKey,
            Self::RemoveKey { .. } => OperationKind::RemoveKey,
            Self::MarkKey { .. } => OperationKind::MarkKey,
            Self::FinalizeDomain => OperationKind::FinalizeDomain,
            Self::BootstrapGateway { .. } => OperationKind::IssueGatewayBootstrap,
        }
    }
}

/// The delegation of Astra's issuer (§9.5), as the WebView names it.
///
/// Typed and closed like [`VaultGesture`]. Only the request's text travels,
/// never a path; in a campaign, with the operation the authority opened. The
/// origin the campaign is fetched from is the relay's, never the window's.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum IssuerGesture {
    /// The ordinary path: the campaign `operation_id` names approves the
    /// request, and the same key opens the vault.
    AuthorizeIssuer {
        operation_id: String,
        request: String,
    },
    /// The last resort, for a domain whose relay names no Astra origin: the
    /// authorization is handed over as a file.
    AuthorizeIssuerOffline { request: String },
}

impl IssuerGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        let request = match self {
            Self::AuthorizeIssuer { request, .. } | Self::AuthorizeIssuerOffline { request } => {
                request
            }
        };
        if request.trim().is_empty()
            || request.len() > astra_operator::operations::issuer::MAX_DELEGATION_REQUEST_BYTES
        {
            return Err(
                "la demande de délégation est vide ou trop grande (256 Kio au plus)".to_string(),
            );
        }
        self.operation_id().map(|_| ())
    }

    fn operation(&self) -> OperationKind {
        OperationKind::AuthorizeIssuer
    }

    /// The campaign's operation, `None` offline.
    fn operation_id(&self) -> Result<Option<Id16>, String> {
        match self {
            Self::AuthorizeIssuer { operation_id, .. } => {
                Id16::parse_hex(operation_id).map(Some).map_err(|_| {
                    "l'identifiant de l'opération tient en 32 caractères hexadécimaux".to_string()
                })
            }
            Self::AuthorizeIssuerOffline { .. } => Ok(None),
        }
    }

    /// The text of the delegation request.
    fn request(&self) -> &str {
        match self {
            Self::AuthorizeIssuer { request, .. } | Self::AuthorizeIssuerOffline { request } => {
                request
            }
        }
    }
}

/// A CA rotation gesture, as the WebView names it.
///
/// Closed, and it names no value: the dates and the reason come with the press that
/// approves, and everything else from the files beside the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case")]
pub enum RotationGesture {
    /// Replaces the domain anchor: two keys validated, then two approvals.
    ReplaceCaPq,
    /// Replaces the client TLS CA, in the same four touches.
    ReplaceCaTls,
    /// Ends a client TLS rotation past `not_after`, with one key.
    FinishCaTls,
    /// Ends a CA-PQ rotation: destroys the outgoing `CA-PQ` kept for the overlap, with one key.
    FinishCaPq,
    /// Carries a signed rotation as far as it goes, with no key.
    Resume,
}

impl RotationGesture {
    /// `Resume` names what it found once it has read the journal.
    fn operation(self) -> OperationKind {
        match self {
            Self::ReplaceCaPq | Self::FinishCaPq | Self::Resume => OperationKind::RotateAnchor,
            Self::ReplaceCaTls | Self::FinishCaTls => OperationKind::RotateClientTlsCa,
        }
    }
}

/// A revocation gesture, as the WebView names it.
///
/// Closed like the others: the workstation is named by its WireGuard key and by the
/// name the gateway admitted it under, and nothing else crosses. The Astra campaign,
/// the approvals and the signature come from the ceremony, never from the page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationGesture {
    /// Cuts the workstation at the gateway, then opens, approves, signs and deposits.
    Revoke {
        /// The workstation's WireGuard public key, base64.
        peer: String,
        /// The name the gateway admitted the workstation under.
        name: String,
        reason: astra_operator::operations::revocation::RevocationReasonChoice,
    },
    /// Already cut: deposits the decision on record for it, or opens a new one.
    Resume {
        peer: String,
        reason: astra_operator::operations::revocation::RevocationReasonChoice,
    },
}

/// The longest name a gateway admits a workstation under, in characters.
const MAX_PEER_NAME_CHARS: usize = 64;

impl RevocationGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        use aether::certificates::encoding::WireGuardKey;

        if WireGuardKey::parse(self.peer().trim()).is_err() {
            return Err("la clé du poste est une clé WireGuard en base64".to_string());
        }
        if let Self::Revoke { name, .. } = self {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > MAX_PEER_NAME_CHARS {
                return Err(format!(
                    "le nom du poste tient en 1 à {MAX_PEER_NAME_CHARS} caractères"
                ));
            }
        }
        Ok(())
    }

    /// The workstation's key, as the page named it.
    fn peer(&self) -> &str {
        match self {
            Self::Revoke { peer, .. } | Self::Resume { peer, .. } => peer,
        }
    }

    fn operation(&self) -> OperationKind {
        OperationKind::RevokeCertificate
    }
}

/// The longest term a gateway renewal may set, in days.
pub const MAX_GATEWAY_TERM_DAYS: u64 = 3_650;

/// The longest rollback a gateway may be asked for, in hours: the overlap is bounded by its end.
const MAX_ROLLBACK_HOURS: u64 = 168;

/// The longest reason a rollback carries, in characters.
const MAX_ROLLBACK_REASON_CHARS: usize = 200;

/// A gateway identity gesture, as the WebView names it (F14 lot 6b).
///
/// Closed like the others: the terms and the reason come with the gesture, and the
/// campaign, the approvals, the signatures and the requester's name come from the
/// ceremony, never from the page. `Discard` takes no key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayGesture {
    /// Renews the gateway's identity, with the terms chosen before any key is asked for.
    Renew {
        rotate_tls: bool,
        key_recovery: bool,
        #[serde(default = "gateway_prepare_days")]
        prepare_days: u64,
        #[serde(default = "gateway_overlap_days")]
        overlap_days: u64,
        #[serde(default = "gateway_validity_days")]
        validity_days: u64,
    },
    /// Cancels the transition the gateway holds staged, before its activation.
    Abort,
    /// Returns to the outgoing identity for `hours` at most, for the rest of the overlap.
    Rollback { hours: u64, reason: String },
    /// Revokes the gateway, with or without its emergency replacement.
    Revoke {
        reason: astra_operator::operations::revocation::RevocationReasonChoice,
        with_replacement: bool,
    },
    /// Carries what a gateway gesture left waiting, with no key.
    Resume,
    /// Drops the waiting record, when the gateway refused it for good.
    Discard,
}

fn gateway_prepare_days() -> u64 {
    7
}

fn gateway_overlap_days() -> u64 {
    7
}

fn gateway_validity_days() -> u64 {
    365
}

impl GatewayGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Renew {
                prepare_days,
                overlap_days,
                validity_days,
                ..
            } => {
                for days in [prepare_days, overlap_days, validity_days] {
                    if !(1..=MAX_GATEWAY_TERM_DAYS).contains(days) {
                        return Err(format!(
                            "les durées se comptent en jours, de 1 à {MAX_GATEWAY_TERM_DAYS}"
                        ));
                    }
                }
                Ok(())
            }
            Self::Rollback { hours, reason } => {
                if !(1..=MAX_ROLLBACK_HOURS).contains(hours) {
                    return Err(format!(
                        "le retour arrière dure de 1 à {MAX_ROLLBACK_HOURS} heures"
                    ));
                }
                let reason = reason.trim();
                if reason.is_empty() || reason.chars().count() > MAX_ROLLBACK_REASON_CHARS {
                    return Err(format!(
                        "le motif tient en 1 à {MAX_ROLLBACK_REASON_CHARS} caractères"
                    ));
                }
                Ok(())
            }
            Self::Abort | Self::Revoke { .. } | Self::Resume | Self::Discard => Ok(()),
        }
    }

    /// The operation a ceremony for this gesture reports. `Resume` reads the record it carries.
    fn operation(&self) -> OperationKind {
        match self {
            Self::Revoke { .. } => OperationKind::RevokeCertificate,
            Self::Renew { .. } | Self::Abort | Self::Rollback { .. } | Self::Discard => {
                OperationKind::GatewayIdentity
            }
            Self::Resume => OperationKind::GatewayIdentity,
        }
    }
}

/// Drops the gateway record waiting beside the vault. Takes no key; the callers have checked
/// that no ceremony is open.
pub(crate) fn discard_gateway_record(vault_path: &std::path::Path) -> Result<(), String> {
    ceremony::discard_waiting(vault_path)
}

/// Renames the key `slot_id` of the vault at `vault_path`. No key is asked
/// anything; the label is checked as a gesture's would be.
pub fn rename_key(vault_path: &std::path::Path, slot_id: &str, label: &str) -> Result<(), String> {
    let slot = parse_slot_id(slot_id)?;
    check_key_label(label)?;
    astra_operator::vault_gestures::rename_key(vault_path, &slot, label.trim())
        .map_err(|error| format!("{error:#}"))
}

/// What the creation form starts from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainDefaults {
    /// The host of the selected profile's endpoint, when it is a name the
    /// domain could be created under.
    pub rp_id: Option<String>,
}

/// The RP ID an endpoint suggests: its host, without the port, in lowercase,
/// and only when it is a name [`valid_rp_id`] accepts.
pub fn suggested_rp_id(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    // A bracketed host is an IPv6 address.
    if endpoint.starts_with('[') {
        return None;
    }
    let host = match endpoint.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        Some(_) => return None,
        None => endpoint,
    };
    let host = host.to_ascii_lowercase();
    valid_rp_id(&host).then_some(host)
}

/// A file the ceremony produced, for the WebView to save.
///
/// Public content only (an invitation, an issued leaf). It is kept out of the
/// status, which every poll carries, and fetched once by the screen that saves
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorArtifact {
    pub file_name: String,
    pub contents: String,
    pub encoding: ArtifactEncoding,
    /// The file's fingerprint, shown under its button for the operator to
    /// compare where the file is installed (the gateway's bootstrap leaf).
    /// Public, as the file is; absent for every other file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// How `contents` is to be written to disk.
///
/// The IPC contract stays textual; a file of raw bytes (a DER leaf, which
/// `heliosd peer add` reads as is) travels as base64 and is decoded by the
/// window before it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    /// Written as is.
    Text,
    /// Base64 of the bytes to write.
    Base64,
}

/// The files of one session, written by its ceremony and read by the window.
type Artifacts = std::sync::Arc<std::sync::Mutex<Vec<OperatorArtifact>>>;

/// The French sentence of the refusal a gateway ceremony ended on, for the page to show.
pub(crate) type Words = std::sync::Arc<std::sync::Mutex<Option<String>>>;

/// Keeps a produced file for the window.
///
/// A poisoned lock is recovered, not skipped: the list holds plain values, and
/// dropping here would lose an invitation already signed and recorded.
fn deposit(artifacts: &Artifacts, artifact: OperatorArtifact) {
    artifacts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(artifact);
}

/// The live ceremony, for as long as one is open.
struct Session {
    presses: std::sync::mpsc::Sender<Press>,
    status: watch::Receiver<OperatorStatus>,
    artifacts: Artifacts,
    /// The sentence of a gateway refusal, set before its failure is published. Read only
    /// by a gateway ceremony, which answers with it as an error.
    words: Option<Words>,
    /// Opened by a tunnel coming up, not by the operator. Only such a session is
    /// replaced by the next one without being dismissed: a finished screen the
    /// operator opened, and the files it produced, are theirs to leave.
    automatic: bool,
}

/// Whether the tunnel just came up, from the states the engine reports.
///
/// The engine says its state more than once, and a resumption is for the edge: each
/// report of `Up` after `Up` is the same tunnel-up. One look per edge is also what
/// keeps a rotation that stops at a dead end from being retried in a loop.
#[derive(Default)]
pub struct TunnelWatch(std::sync::atomic::AtomicBool);

impl TunnelWatch {
    /// Records the state just reported, and says whether it is the edge into `Up`.
    pub fn entered_up(&self, up: bool) -> bool {
        use std::sync::atomic::Ordering;
        let was_up = self.0.swap(up, Ordering::AcqRel);
        up && !was_up
    }

    /// [`Self::entered_up`], from an event of the engine: only a state change counts.
    pub fn entered_up_by(&self, event: &orion_core::ClientEvent) -> bool {
        match event {
            orion_core::ClientEvent::StateChanged { state } => {
                self.entered_up(*state == aether::TunnelState::Up)
            }
            _ => false,
        }
    }
}

/// The gateway a tunnel leads to: where it is, and whose it is.
///
/// The peer key is the connected profile's. Orion holds several profiles and one
/// vault, so a rotation is carried only to the gateway the domain's relay names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayTarget {
    pub address: String,
    pub peer_key: String,
    /// This workstation's own WireGuard public key, from the connected profile, when
    /// the profile is the one the tunnel leads by. A revocation refuses to cut it.
    pub own_key: Option<String>,
}

/// Whether the relay beside the vault names `peer_key` as the domain's gateway.
///
/// A resumption reads the status of whatever authority answers, and sends the sealed
/// vault to whatever gateway it reaches: another domain's must be neither.
pub(crate) fn relay_names_peer(
    vault_path: &std::path::Path,
    peer_key: &str,
) -> Result<bool, String> {
    use aether::certificates::encoding::WireGuardKey;

    let relay = astra_operator::handoff::load(&astra_operator::handoff::path_beside(vault_path))
        .map_err(|error| format!("{error:#}"))?;
    let named = relay
        .gateway_wg_public_key
        .as_deref()
        .and_then(|key| WireGuardKey::parse(key.trim()).ok());
    let connected = WireGuardKey::parse(peer_key.trim()).ok();
    Ok(named.is_some() && named == connected)
}

/// What the window reads of a session: its status, and whether a tunnel coming up opened
/// it rather than the operator.
///
/// A wrapper here and not a field of [`OperatorStatus`]: the session's origin is Orion's
/// own, and the type shared with Astra rejects unknown fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObservedStatus {
    #[serde(flatten)]
    pub status: OperatorStatus,
    pub automatic: bool,
}

/// The one ceremony Orion hosts at a time.
///
/// A second concurrent ceremony is refused rather than queued. Two of them
/// would open the vault twice against one domain, and — for the two that
/// consume an operation — each would spend an approval the other is still
/// counting on.
#[derive(Default)]
pub struct OperatorCeremony(Mutex<Option<Session>>);

impl OperatorCeremony {
    /// The last state the ceremony published, or `None` when none ran.
    ///
    /// `None` rather than a synthetic «idle» status: there is no session, so
    /// there is no revision, and inventing one would give the WebView a number
    /// it could send back.
    pub async fn status(&self) -> Option<OperatorStatus> {
        self.0
            .lock()
            .await
            .as_mut()
            .map(|session| session.status.borrow_and_update().clone())
    }

    /// [`Self::status`] with the origin of the session, for a view that did not open it.
    pub async fn observed(&self) -> Option<ObservedStatus> {
        self.0.lock().await.as_mut().map(|session| ObservedStatus {
            status: session.status.borrow_and_update().clone(),
            automatic: session.automatic,
        })
    }

    /// Starts the ceremony in its own thread, against the vault at
    /// `vault_path`, and returns the first state it publishes.
    pub async fn begin(
        &self,
        locator: OperationLocator,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        self.open(
            locator.kind,
            move |session_id, presses, publish, _artifacts| {
                ceremony::run(session_id, locator, presses, publish, &vault_path)
            },
        )
        .await
    }

    /// Starts an enrollment gesture the same way, under the same rule of one
    /// ceremony at a time.
    ///
    /// `gateway` is the control-plane address of the connected profile, read by
    /// the caller from the engine, or `None` when no tunnel is up.
    pub async fn begin_enrollment(
        &self,
        gesture: EnrollmentGesture,
        gateway: Option<String>,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = gesture.operation();
        self.open(kind, move |session_id, presses, publish, artifacts| {
            ceremony::run_enrollment(
                session_id,
                gesture,
                gateway,
                presses,
                publish,
                &mut |artifact| deposit(artifacts, artifact),
                &vault_path,
            )
        })
        .await
    }

    /// Starts a vault or domain gesture the same way, under the same rule of
    /// one ceremony at a time.
    pub async fn begin_vault(
        &self,
        gesture: VaultGesture,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = gesture.operation();
        self.open(kind, move |session_id, presses, publish, artifacts| {
            ceremony::run_vault(
                session_id,
                gesture,
                presses,
                publish,
                &mut |artifact| deposit(artifacts, artifact),
                &vault_path,
            )
        })
        .await
    }

    /// Starts the delegation of Astra's issuer the same way, under the same
    /// rule of one ceremony at a time.
    pub async fn begin_issuer(
        &self,
        gesture: IssuerGesture,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = gesture.operation();
        self.open(kind, move |session_id, presses, publish, artifacts| {
            ceremony::run_issuer(
                session_id,
                gesture,
                presses,
                publish,
                &mut |artifact| deposit(artifacts, artifact),
                &vault_path,
            )
        })
        .await
    }

    /// Starts a CA rotation gesture the same way, under the same rule of one
    /// ceremony at a time.
    ///
    /// `gateway` is the control-plane address of the connected profile, read by
    /// the caller from the engine, or `None` when no tunnel is up: every gesture
    /// here goes through it, and none reaches a key without one.
    pub async fn begin_rotation(
        &self,
        gesture: RotationGesture,
        gateway: Option<GatewayTarget>,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        self.open(
            gesture.operation(),
            move |session_id, presses, publish, _artifacts| {
                ceremony::run_rotation(session_id, gesture, gateway, presses, publish, &vault_path)
            },
        )
        .await
    }

    /// Starts a revocation gesture the same way, under the same rule of one ceremony at
    /// a time.
    ///
    /// `gateway` is the control-plane address of the connected profile, with its key and
    /// this workstation's, read by the caller: a revocation cuts the admission at that
    /// gateway, and refuses to cut the workstation the tunnel runs on.
    pub async fn begin_revocation(
        &self,
        gesture: RevocationGesture,
        gateway: Option<GatewayTarget>,
        vault_path: PathBuf,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = gesture.operation();
        self.open(kind, move |session_id, presses, publish, _artifacts| {
            ceremony::run_revocation(session_id, gesture, gateway, presses, publish, &vault_path)
        })
        .await
    }

    /// Starts a gateway identity gesture the same way, under the same rule of one ceremony at
    /// a time, and returns once it waits for a key, or has ended.
    ///
    /// A refusal before any key comes back as an error carrying its sentence, which is how the
    /// page shows what the gateway or Astra said. `gateway` is the connected profile's target,
    /// and `requested_by` the workstation's name, which a rollback's campaign names.
    pub async fn begin_gateway(
        &self,
        gesture: GatewayGesture,
        gateway: Option<GatewayTarget>,
        vault_path: PathBuf,
        requested_by: String,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = match &gesture {
            GatewayGesture::Resume => {
                let path = vault_path.clone();
                let waiting = tokio::task::spawn_blocking(move || {
                    astra_operator::operations::gateway_revocation::pending_revocation(
                        &path,
                        now_unix(),
                    )
                })
                .await
                .map_err(|error| format!("lecture de la révocation en attente : {error}"))?
                .map_err(|error| format!("{error:#}"))?;
                if waiting.is_some() {
                    OperationKind::RevokeCertificate
                } else {
                    OperationKind::GatewayIdentity
                }
            }
            other => other.operation(),
        };
        let words: Words = Default::default();
        let thread_words = words.clone();
        let mut status = self
            .open_as(
                kind,
                false,
                Some(words.clone()),
                move |session_id, presses, publish, _artifacts| {
                    ceremony::run_gateway(
                        session_id,
                        gesture,
                        gateway,
                        presses,
                        publish,
                        &vault_path,
                        &requested_by,
                        &thread_words,
                    )
                },
            )
            .await
            .map_err(|error| match error {
                Opening::Busy { .. } => BUSY.to_string(),
                Opening::Failed(message) => message,
            })?;
        // Waits while the gesture works on its own: what it needs from the operator is a key,
        // and what it ends on is a terminal state.
        while matches!(
            status.gesture,
            GestureState::Verifying | GestureState::Signing | GestureState::ProcessingKey { .. }
        ) {
            let mut held = self.0.lock().await;
            let Some(session) = held.as_mut() else {
                break;
            };
            status = awaited(&mut session.status).await?;
        }
        if status.gesture == GestureState::Failed {
            return Err(words
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .unwrap_or_else(|| GATEWAY_FAILED.to_string()));
        }
        Ok(status)
    }

    /// Answers the wait for a rotation's terms, which opens its campaign.
    ///
    /// `revision` names the status the operator approved on. A press with no dialog
    /// to own: the keys come after, each with a press of its own.
    pub async fn approve_rotation(
        &self,
        terms: RotationTerms,
        revision: u64,
    ) -> Result<OperatorStatus, String> {
        let mut held = self.0.lock().await;
        let session = held
            .as_mut()
            .ok_or_else(|| "aucune cérémonie opérateur n'est ouverte".to_string())?;

        let current = session.status.borrow_and_update().clone();
        if !awaits_terms(&current) || current.revision != revision {
            return Err(
                "cette étape n'accepte pas cette action : l'écran a changé depuis la pression"
                    .to_string(),
            );
        }

        session
            .presses
            .send(Press {
                action: OperatorAction::Continue,
                revision,
                owner: 0,
                terms: Some(terms),
            })
            .map_err(|_| STOPPED.to_string())?;
        awaited(&mut session.status).await
    }

    /// The files the current session produced, or none.
    pub async fn artifacts(&self) -> Vec<OperatorArtifact> {
        match self.0.lock().await.as_ref() {
            Some(session) => session
                .artifacts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            None => Vec::new(),
        }
    }

    /// Carries whatever a rotation left in flight, with no key, now that the tunnel
    /// is up.
    ///
    /// Nothing is started when no journal, no unadopted record and no CA-PQ file
    /// stands beside the vault, when the relay names another gateway than the
    /// tunnel's, or when the operator's own finished screen is still showing
    /// (dismissing it looks again). [`ResumeOutcome::Running`] says a ceremony was
    /// running: the caller may wait for [`Self::ended`] and look once more. The run
    /// asks no key; it ends by itself, so the next operator action waits for no longer
    /// than the resumption does. A stop leaves the journal for the next tunnel-up, or
    /// the button. Only a relay naming the tunnel's gateway lets it go, which is
    /// what keeps another domain's authority from reading as « nothing in flight ».
    pub async fn resume_on_tunnel_up(
        &self,
        target: GatewayTarget,
        vault_path: PathBuf,
    ) -> Result<ResumeOutcome, String> {
        // Blocking reads: two stats, a record's parse and the relay.
        let looked = {
            let (vault_path, peer_key) = (vault_path.clone(), target.peer_key.clone());
            tokio::task::spawn_blocking(move || {
                let pending = astra_operator::rotation_journal::something_to_resume(&vault_path)
                    .map_err(|error| format!("{error:#}"))?;
                if !pending {
                    return Ok(false);
                }
                relay_names_peer(&vault_path, &peer_key)
            })
            .await
            .map_err(|error| format!("lecture du coffre : {error}"))?
        }?;
        if !looked {
            return Ok(ResumeOutcome::Nothing);
        }
        let gesture = RotationGesture::Resume;
        let started = self
            .open_as(
                gesture.operation(),
                true,
                None,
                move |session_id, presses, publish, _artifacts| {
                    ceremony::run_rotation(
                        session_id,
                        gesture,
                        Some(target),
                        presses,
                        publish,
                        &vault_path,
                    )
                },
            )
            .await;
        match started {
            Ok(_) => Ok(ResumeOutcome::Started),
            Err(Opening::Busy { running: true }) => Ok(ResumeOutcome::Running),
            Err(Opening::Busy { running: false }) => Ok(ResumeOutcome::Nothing),
            Err(Opening::Failed(message)) => Err(message),
        }
    }

    /// Returns once the ceremony open now has ended, at once when none is running.
    ///
    /// Only for a resumption's own session, which ends by itself: a ceremony of the
    /// operator's can wait on them indefinitely, which is why [`ResumeOutcome::Running`]
    /// is reported for an automatic session alone.
    pub async fn ended(&self) {
        let mut status = match self.0.lock().await.as_ref() {
            Some(session) => session.status.clone(),
            None => return,
        };
        loop {
            if status.borrow().gesture.is_terminal() || status.changed().await.is_err() {
                return;
            }
        }
    }

    async fn open<F>(&self, kind: OperationKind, run: F) -> Result<OperatorStatus, String>
    where
        F: FnOnce(
                Id16,
                std::sync::mpsc::Receiver<Press>,
                &mut dyn FnMut(OperatorStatus),
                &Artifacts,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        self.open_as(kind, false, None, run)
            .await
            .map_err(|error| match error {
                Opening::Busy { .. } => BUSY.to_string(),
                Opening::Failed(message) => message,
            })
    }

    async fn open_as<F>(
        &self,
        kind: OperationKind,
        automatic: bool,
        words: Option<Words>,
        run: F,
    ) -> Result<OperatorStatus, Opening>
    where
        F: FnOnce(
                Id16,
                std::sync::mpsc::Receiver<Press>,
                &mut dyn FnMut(OperatorStatus),
                &Artifacts,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            // A resumption gives way to everything but its own finished session.
            if !current.gesture.is_terminal() || (automatic && !session.automatic) {
                return Err(Opening::Busy {
                    // Only a resumption's own run is worth waiting for.
                    running: !current.gesture.is_terminal() && session.automatic,
                });
            }
        }
        *held = None;

        let session_id = Id16::new(
            *aether::random::secret_bytes::<16>()
                .map_err(|error| format!("tirage de l'identifiant de session : {error}"))?,
        )
        .map_err(|error| format!("identifiant de session : {error}"))?;
        let (publisher, status) = watch::channel(OperatorStatus::new(
            session_id,
            0,
            kind,
            RemoteState::Local,
            GestureState::Verifying,
        ));
        let (presses, received) = std::sync::mpsc::channel();
        let artifacts = Artifacts::default();
        let produced = artifacts.clone();

        // Its own thread, with the stack the vault and the signatures need: the
        // default stack of a runtime worker does not hold their post-quantum
        // computations.
        std::thread::Builder::new()
            .name("orion-operator-ceremony".into())
            .stack_size(astra_operator::WORK_STACK_BYTES)
            .spawn(move || {
                let final_status = FinalStatus::new(publisher);
                let outcome = run(
                    session_id,
                    received,
                    &mut |state| final_status.publish(state),
                    &produced,
                );
                if let Err(message) = &outcome {
                    tracing::warn!(error = %message, "cérémonie opérateur interrompue");
                }
                outcome
            })
            .map_err(|error| format!("démarrage de la cérémonie opérateur : {error}"))?;

        // Held before its first state is awaited: a ceremony that is slow to
        // speak is still running, and a second `begin` must find it here and
        // refuse rather than open the vault a second time beside it.
        let session = held.insert(Session {
            presses,
            status,
            artifacts,
            words,
            automatic,
        });
        Ok(awaited(&mut session.status).await?)
    }

    /// Takes the next step of the open ceremony.
    ///
    /// `revision` names the status the operator was looking at. Both ends
    /// check it: this one because it is the surface that offered the button,
    /// the ceremony because it is the one that would act on it. `owner` is the
    /// window the press came from, and the dialog of a key belongs to it.
    pub async fn advance(
        &self,
        action: OperatorAction,
        revision: u64,
        owner: isize,
    ) -> Result<OperatorStatus, String> {
        let mut held = self.0.lock().await;
        let session = held
            .as_mut()
            .ok_or_else(|| "aucune cérémonie opérateur n'est ouverte".to_string())?;

        let current = session.status.borrow_and_update().clone();
        if !current.accepts(action, revision) {
            return Err(
                "cette étape n'accepte pas cette action : l'écran a changé depuis la pression"
                    .to_string(),
            );
        }

        session
            .presses
            .send(Press {
                action,
                revision,
                owner,
                terms: None,
            })
            .map_err(|_| STOPPED.to_string())?;
        let status = awaited(&mut session.status).await?;
        failure_words(&session.words, &status)?;
        Ok(status)
    }

    /// Forgets a completed session after its final state has been shown.
    /// A live session cannot be dismissed: dropping its press channel would
    /// look like cancellation even after the ceremony crossed the point where
    /// cancellation is honest.
    ///
    /// Says whether the screen was the operator's own: only that one may have kept a
    /// resumption out, and only then is a look worth making. Dismissing a resumption's
    /// own dead end must not start another.
    pub async fn dismiss(&self) -> Result<bool, String> {
        let mut held = self.0.lock().await;
        let mut operators = false;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !current.gesture.is_terminal() {
                return Err("la cérémonie opérateur est encore en cours".to_string());
            }
            operators = !session.automatic;
        }
        *held = None;
        Ok(operators)
    }
}

/// Said when a gateway ceremony failed without a sentence of its own.
const GATEWAY_FAILED: &str = "la gestion de l'identité de la gateway a échoué : rien n'a été \
                              signé ou rien n'a été changé sur la gateway";

/// The sentence of a failed gateway ceremony, when the ceremony wrote one.
fn failure_words(words: &Option<Words>, status: &OperatorStatus) -> Result<(), String> {
    if status.gesture != GestureState::Failed {
        return Ok(());
    }
    match words {
        Some(words) => match words
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            Some(sentence) => Err(sentence),
            None => Ok(()),
        },
        None => Ok(()),
    }
}

/// Said when a ceremony is already open and a second one is asked for.
///
/// Not « l'annuler » on its own: a resumption offers no Cancel, and a key dialog open
/// cannot be cancelled until it returns.
const BUSY: &str = "une cérémonie opérateur est déjà ouverte : attendre sa fin, ou l'annuler \
                    quand elle le permet, avant d'en ouvrir une autre";

/// Why a ceremony did not open.
enum Opening {
    /// `running` tells a resumption still going from a ceremony of the operator's or a
    /// finished screen left showing, neither of which is waited for.
    Busy {
        running: bool,
    },
    Failed(String),
}

impl From<String> for Opening {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// What a look at the rotation in flight came to.
#[derive(Debug)]
pub enum ResumeOutcome {
    /// Nothing to resume, or not for this gateway, or the screen is not free.
    Nothing,
    Started,
    /// A ceremony was running.
    Running,
}

impl ResumeOutcome {
    #[cfg(test)]
    pub fn is_started(&self) -> bool {
        matches!(self, Self::Started)
    }
}

/// Carries a rotation left in flight as soon as the tunnel is up (spec §5.4).
///
/// Called once per edge into `Up`, see [`TunnelWatch`], and once when the operator
/// dismisses a finished screen of their own that was in the way, or chooses or
/// resets the vault location.
pub async fn resume_on_tunnel_up(app: &tauri::AppHandle) {
    use tauri::Manager;

    let state = app.state::<crate::AppState>();
    resume_with(&state.operator, || async {
        // A read that creates nothing: this runs on machines that never opened Astra.
        (
            state.vault_location.path_to_look_at(),
            crate::commands::connected_target(&state).await,
        )
    })
    .await;
}

/// The look itself, on what `read` finds: the vault and the gateway, or why they
/// cannot be named, which is nothing to do.
///
/// Meeting a resumption still running, it waits for that one to end and looks once
/// more, reading again: the edge must not be lost, the profile may have changed
/// meanwhile, and nothing here loops. The second look does not wait in its turn. A
/// ceremony of the operator's is not waited for, dismissing its screen looks.
/// Nothing secret is logged.
pub async fn resume_with<R, Fut>(ceremony: &OperatorCeremony, read: R)
where
    R: Fn() -> Fut,
    Fut: std::future::Future<Output = (Result<PathBuf, String>, Result<GatewayTarget, String>)>,
{
    for waited in [false, true] {
        let (Ok(vault_path), Ok(target)) = read().await else {
            return;
        };
        match ceremony.resume_on_tunnel_up(target, vault_path).await {
            Ok(ResumeOutcome::Started) => {
                tracing::info!("reprise d'une rotation en cours au montage du tunnel");
                return;
            }
            Ok(ResumeOutcome::Nothing) => return,
            Ok(ResumeOutcome::Running) if !waited => {
                tracing::debug!("une reprise est en cours : la suivante attend sa fin");
                ceremony.ended().await;
            }
            Ok(ResumeOutcome::Running) => {
                tracing::debug!(
                    "une reprise est de nouveau en cours : laissée au prochain montage"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(error = %error, "reprise d'une rotation impossible à lancer");
                return;
            }
        }
    }
}

/// Whether a ceremony is waiting for a rotation's terms: its keys are validated and
/// nothing is open yet. No other ceremony rests in this pair of states.
fn awaits_terms(status: &OperatorStatus) -> bool {
    status.gesture == GestureState::Idle && status.remote == RemoteState::Local
}

/// Publishes the end of a ceremony that stopped without one.
///
/// Owned by the ceremony's thread, so whatever ends that thread — a return, a
/// refusal, a panic — runs this destructor. A ceremony that stops short of a
/// terminal state would otherwise leave the operator on its last hopeful
/// screen, waiting on a «signature en cours» nothing is performing.
struct FinalStatus {
    publisher: watch::Sender<OperatorStatus>,
}

impl FinalStatus {
    fn new(publisher: watch::Sender<OperatorStatus>) -> Self {
        Self { publisher }
    }

    fn publish(&self, status: OperatorStatus) {
        self.publisher.send_replace(status);
    }
}

impl Drop for FinalStatus {
    fn drop(&mut self) {
        let last = self.publisher.borrow().clone();
        if last.gesture.is_terminal() {
            return;
        }
        let mut failed = OperatorStatus::new(
            last.session_id,
            last.revision + 1,
            last.operation,
            last.remote,
            GestureState::Failed,
        );
        failed.operation_id = last.operation_id;
        failed.refusal = Some(Refusal::Internal);
        self.publisher.send_replace(failed);
    }
}

/// Waits for the next state the ceremony publishes.
async fn awaited(status: &mut watch::Receiver<OperatorStatus>) -> Result<OperatorStatus, String> {
    tokio::time::timeout(STEP_TIMEOUT, status.changed())
        .await
        .map_err(|_| NOT_ANSWERING.to_string())?
        .map_err(|_| STOPPED.to_string())?;
    Ok(status.borrow_and_update().clone())
}

/// The window the platform dialog belongs to, from the press that opened it.
///
/// Orion's own window: the press came from it, and it is the window the
/// operator is looking at. A press that carries no handle is refused rather
/// than opened unowned — an unowned dialog may appear behind the window the
/// operator is reading, with nothing to say why the key never answers.
#[cfg(windows)]
pub(crate) fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    if owner == 0 {
        return Err(
            "la fenêtre d'Orion est introuvable : la boîte de la clé n'aurait pas de propriétaire"
                .to_string(),
        );
    }
    Ok(DialogOwner::Window(owner))
}

/// Off Windows the only transport is raw CTAP, whose gesture is on the token
/// and shows no dialog: the console is the honest owner, and nothing is
/// claimed.
#[cfg(not(windows))]
pub(crate) fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    let _ = owner;
    Ok(DialogOwner::Console)
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::operator_session::{KeyPurpose, OperationKind};

    fn session() -> Id16 {
        Id16::new([4; 16]).expect("id")
    }

    /// The button is offered and refused from the same value, so a WebView
    /// that invented one gains nothing.
    #[tokio::test]
    async fn a_ceremony_that_never_started_accepts_nothing() {
        let ceremony = OperatorCeremony::default();
        assert!(ceremony.status().await.is_none());
        assert!(ceremony
            .advance(OperatorAction::Continue, 1, 0)
            .await
            .is_err());
    }

    /// The origin of a session reaches the window beside the status, without a field
    /// of the shared type, and the status keeps its own names.
    #[test]
    fn an_observed_status_carries_its_origin_beside_the_status() {
        let status = OperatorStatus::new(
            session(),
            4,
            OperationKind::RotateAnchor,
            RemoteState::Local,
            GestureState::Done,
        );
        for automatic in [true, false] {
            let value = serde_json::to_value(ObservedStatus {
                status: status.clone(),
                automatic,
            })
            .expect("serialises");
            assert_eq!(value["automatic"], automatic);
            assert_eq!(value["revision"], 4);
            assert_eq!(value["operation"], "rotate_anchor");
        }
    }

    /// A press on a screen the ceremony has already left must not be applied to
    /// whatever replaced it, and Orion refuses it before it reaches the wire.
    #[test]
    fn a_stale_revision_is_not_accepted() {
        let status = OperatorStatus::new(
            session(),
            9,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        );
        assert!(status.accepts(OperatorAction::Continue, 9));
        assert!(!status.accepts(OperatorAction::Continue, 8));
    }

    /// Once the signed objects have left, «Annuler» would promise something
    /// this side cannot deliver — and the surface must not offer it either.
    #[test]
    fn nothing_is_cancellable_past_the_deposit() {
        let status = OperatorStatus::new(
            session(),
            2,
            OperationKind::RecoverIdentity,
            RemoteState::Staged,
            GestureState::Idle,
        );
        assert!(!status.accepts(OperatorAction::Cancel, 2));
    }

    /// A ceremony that stops short of a terminal state must not leave the
    /// operator on its last hopeful screen: the guard says it failed, one
    /// revision on.
    #[test]
    fn a_ceremony_that_stops_short_is_reported_failed() {
        let (publisher, observed) = watch::channel(OperatorStatus::new(
            session(),
            3,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        ));
        drop(FinalStatus::new(publisher));
        let last = observed.borrow().clone();
        assert_eq!(last.gesture, GestureState::Failed);
        assert_eq!(last.refusal, Some(Refusal::Internal));
        assert_eq!(last.revision, 4);
    }

    /// A ceremony that ended on its own terms is left as it ended.
    #[test]
    fn a_finished_ceremony_is_left_as_it_ended() {
        let (publisher, observed) = watch::channel(OperatorStatus::new(
            session(),
            5,
            OperationKind::RecoverIdentity,
            RemoteState::Staged,
            GestureState::Done,
        ));
        drop(FinalStatus::new(publisher));
        let last = observed.borrow().clone();
        assert_eq!(last.gesture, GestureState::Done);
        assert_eq!(last.refusal, None);
        assert_eq!(last.revision, 5);
    }

    fn gesture(json: &str) -> Result<EnrollmentGesture, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The window is a day at most, and it is refused on arrival: a value out
    /// of range never reaches the ceremony.
    #[test]
    fn an_invitation_lasts_at_most_a_day() {
        let invite = |hours: u32| {
            gesture(&format!(
                r#"{{"gesture":"invite","valid_for_hours":{hours},"allow_readmission":false,"name":"laptop"}}"#
            ))
        };
        assert!(invite(24).is_ok());
        assert!(invite(1).is_ok());
        assert!(invite(25).is_err());
        assert!(invite(0).is_err());
        assert!(gesture(
            r#"{"gesture":"invite","valid_for_hours":2,"allow_readmission":false,"name":"a","extra":1}"#
        )
        .is_err());
    }

    /// The acceptance window is bounded the same way, with a year by default.
    #[test]
    fn an_acceptance_lasts_at_most_five_years() {
        let accept = |extra: &str| {
            gesture(&format!(
                r#"{{"gesture":"accept","request":"r","endpoint":"gw:51820"{extra}}}"#
            ))
        };
        match accept("") {
            Ok(EnrollmentGesture::Accept { validity_days, .. }) => assert_eq!(validity_days, 365),
            other => panic!("{other:?}"),
        }
        assert!(accept(r#","validity_days":1825"#).is_ok());
        assert!(accept(r#","validity_days":1826"#).is_err());
        assert!(accept(r#","validity_days":0"#).is_err());
    }

    /// The name becomes a file name: only the documented alphabet and length.
    #[tokio::test]
    async fn a_bad_invitation_name_is_refused() {
        let ceremony = OperatorCeremony::default();
        let too_long = "a".repeat(65);
        for name in ["", "a/b", "a b", "..\\x", "é", "a\n", too_long.as_str()] {
            let refused = ceremony
                .begin_enrollment(
                    EnrollmentGesture::Invite {
                        valid_for_hours: 2,
                        allow_readmission: false,
                        name: name.to_string(),
                        gateway_pq_certificate: None,
                    },
                    None,
                    PathBuf::from(location::VAULT_FILE_NAME),
                )
                .await;
            assert!(refused.is_err(), "{name:?}");
        }
        assert!(ceremony.status().await.is_none());
        for name in ["laptop", "a.b_c-D9", &"a".repeat(64)] {
            assert!(valid_invitation_name(name), "{name:?}");
        }
    }

    /// An artifact belongs to a session: without one there is nothing to hand.
    #[tokio::test]
    async fn artifacts_are_empty_without_a_session() {
        assert!(OperatorCeremony::default().artifacts().await.is_empty());
    }

    /// A thread that panicked holding the list must not cost the operator an
    /// invitation that is already signed and recorded.
    #[test]
    fn a_poisoned_artifact_list_still_keeps_the_invitation() {
        let artifacts = Artifacts::default();
        let poisoner = artifacts.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().expect("lock");
            panic!("poisoning on purpose");
        })
        .join();
        assert!(artifacts.is_poisoned());
        deposit(
            &artifacts,
            OperatorArtifact {
                file_name: "a.helios-invite".into(),
                contents: "x".into(),
                encoding: ArtifactEncoding::Text,
                fingerprint: None,
            },
        );
        let held = artifacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(held.len(), 1);
    }

    fn creation(rp_id: &str, authority_url: &str, label: &str) -> VaultGesture {
        VaultGesture::CreateDomain {
            rp_id: rp_id.into(),
            authority_url: authority_url.into(),
            first_label: label.into(),
            second_label: "secours".into(),
        }
    }

    /// Every value is checked on arrival: a gesture the vault would refuse
    /// after a press never opens a ceremony.
    #[tokio::test]
    async fn gestures_with_invalid_values_open_no_ceremony() {
        let url = "https://astra.example";
        for origin in [url, "https://astra.example/", "https://astra.example:8443"] {
            assert_eq!(
                creation("astra.example", origin, "quotidienne").validate(),
                Ok(()),
                "{origin}"
            );
        }
        let invalid = [
            creation("192.168.1.1", url, "quotidienne"),
            creation("Astra.Example", url, "quotidienne"),
            creation("astra", url, "quotidienne"),
            creation("1.2.3", url, "quotidienne"),
            creation("astra.123", url, "quotidienne"),
            creation("astra.example", "http://astra.example", "quotidienne"),
            creation(
                "astra.example",
                "https://astra.example/astra",
                "quotidienne",
            ),
            creation("astra.example", "https://astra.example?x=1", "quotidienne"),
            creation("astra.example", "https://astra.example#x", "quotidienne"),
            creation("astra.example", "https://user@astra.example", "quotidienne"),
            creation(
                "astra.example",
                "https://astra.example:99999",
                "quotidienne",
            ),
            creation("astra.example", url, " "),
            VaultGesture::AddKey {
                label: " ".into(),
                role: KeyRole::Primary,
            },
            VaultGesture::RemoveKey {
                slot_id: "xyz".into(),
            },
            VaultGesture::MarkKey {
                slot_id: "xyz".into(),
                lost: true,
            },
        ];
        let ceremony = OperatorCeremony::default();
        for gesture in invalid {
            assert!(gesture.validate().is_err(), "{gesture:?}");
            assert!(ceremony
                .begin_vault(gesture, PathBuf::from(location::VAULT_FILE_NAME))
                .await
                .is_err());
        }
        assert!(ceremony.status().await.is_none());
    }

    /// The roles travel under the names the overview gives them.
    #[test]
    fn a_key_role_reads_as_the_overview_writes_it() {
        let added: VaultGesture = serde_json::from_str(
            r#"{"gesture":"add_key","label":"secours","role":"recuperation"}"#,
        )
        .expect("an addition");
        assert_eq!(
            added,
            VaultGesture::AddKey {
                label: "secours".into(),
                role: KeyRole::Recovery,
            }
        );
        assert!(serde_json::from_str::<VaultGesture>(
            r#"{"gesture":"add_key","label":"secours","role":"recovery"}"#
        )
        .is_err());
    }

    /// The bootstrap carries the request's text and nothing else.
    #[test]
    fn a_bootstrap_gesture_carries_only_the_request_text() {
        let gesture: VaultGesture =
            serde_json::from_str(r#"{"gesture":"bootstrap_gateway","request":"{}"}"#)
                .expect("a bootstrap");
        assert_eq!(
            gesture,
            VaultGesture::BootstrapGateway {
                request: "{}".into()
            }
        );
        assert_eq!(gesture.operation(), OperationKind::IssueGatewayBootstrap);
        assert!(gesture.validate().is_ok());
        assert!(serde_json::from_str::<VaultGesture>(
            r#"{"gesture":"bootstrap_gateway","request":"{}","path":"/etc/passwd"}"#
        )
        .is_err());

        let largest = astra_operator::bootstrap::MAX_BOOTSTRAP_REQUEST_BYTES;
        for request in [String::new(), "  \n".into(), "x".repeat(largest + 1)] {
            let message = VaultGesture::BootstrapGateway { request }
                .validate()
                .expect_err("refused");
            assert_eq!(
                message,
                "la demande d'amorçage est vide ou trop grande (256 Kio au plus)"
            );
        }
        assert!(VaultGesture::BootstrapGateway {
            request: "x".repeat(largest)
        }
        .validate()
        .is_ok());
    }

    /// A delegation carries the request's text and, in a campaign, the
    /// operation the authority opened: never a path, never anything else.
    #[test]
    fn an_issuer_gesture_carries_only_the_request_text() {
        let operation = "0123456789abcdef0123456789abcdef";
        let gesture: IssuerGesture = serde_json::from_str(&format!(
            r#"{{"gesture":"authorize_issuer","operation_id":"{operation}","request":"{{}}"}}"#
        ))
        .expect("a campaign delegation");
        assert_eq!(
            gesture,
            IssuerGesture::AuthorizeIssuer {
                operation_id: operation.into(),
                request: "{}".into(),
            }
        );
        assert_eq!(gesture.operation(), OperationKind::AuthorizeIssuer);
        assert!(gesture.validate().is_ok());
        assert_eq!(
            gesture.operation_id(),
            Ok(Some(Id16::parse_hex(operation).expect("id")))
        );

        let offline: IssuerGesture =
            serde_json::from_str(r#"{"gesture":"authorize_issuer_offline","request":"{}"}"#)
                .expect("an offline delegation");
        assert_eq!(
            offline,
            IssuerGesture::AuthorizeIssuerOffline {
                request: "{}".into()
            }
        );
        assert_eq!(offline.operation(), OperationKind::AuthorizeIssuer);
        assert!(offline.validate().is_ok());
        assert_eq!(offline.operation_id(), Ok(None));

        for unknown in [
            r#"{"gesture":"authorize_issuer_offline","request":"{}","path":"/etc/passwd"}"#,
            r#"{"gesture":"authorize_issuer","operation_id":"0123456789abcdef0123456789abcdef","request":"{}","authority_url":"https://elsewhere"}"#,
            // An offline delegation names no operation.
            r#"{"gesture":"authorize_issuer_offline","operation_id":"0123456789abcdef0123456789abcdef","request":"{}"}"#,
        ] {
            assert!(
                serde_json::from_str::<IssuerGesture>(unknown).is_err(),
                "{unknown}"
            );
        }

        let largest = astra_operator::operations::issuer::MAX_DELEGATION_REQUEST_BYTES;
        for request in [String::new(), "  \n".into(), "x".repeat(largest + 1)] {
            for gesture in [
                IssuerGesture::AuthorizeIssuerOffline {
                    request: request.clone(),
                },
                IssuerGesture::AuthorizeIssuer {
                    operation_id: operation.into(),
                    request: request.clone(),
                },
            ] {
                assert_eq!(
                    gesture.validate().expect_err("refused"),
                    "la demande de délégation est vide ou trop grande (256 Kio au plus)"
                );
            }
        }
        assert!(IssuerGesture::AuthorizeIssuerOffline {
            request: "x".repeat(largest)
        }
        .validate()
        .is_ok());

        for operation_id in ["", "not-hex", "0123456789abcdef", &"g".repeat(32)] {
            let gesture = IssuerGesture::AuthorizeIssuer {
                operation_id: operation_id.into(),
                request: "{}".into(),
            };
            assert!(gesture.validate().is_err(), "{operation_id}");
            assert!(gesture.operation_id().is_err(), "{operation_id}");
        }
    }

    /// Only a name can be a WebAuthn RP ID: an address suggests nothing.
    #[test]
    fn the_rp_id_is_suggested_only_from_a_name() {
        assert_eq!(
            suggested_rp_id("gw.tail1234.ts.net:51820"),
            Some("gw.tail1234.ts.net".to_string())
        );
        assert_eq!(
            suggested_rp_id("GW.Example.NET:51820"),
            Some("gw.example.net".to_string())
        );
        assert_eq!(suggested_rp_id("10.0.0.1:51820"), None);
        assert_eq!(suggested_rp_id("[fd00::1]:51820"), None);
        assert_eq!(suggested_rp_id("gateway:51820"), None);
    }
}
