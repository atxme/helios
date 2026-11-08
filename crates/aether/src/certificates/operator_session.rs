//! The local session between the Orion window and the operator ceremony (protocol 2).
//!
//! # Why there is a session at all
//!
//! The platform WebAuthn API answers only inside the interactive user's
//! session, at medium integrity. Since F11 the Orion UI runs there, and only
//! the engine is elevated (to load WireGuard-NT), so the operator ceremony
//! lives in the UI process and never in the engine. This module is everything
//! the ceremony and the window are allowed to say to each other, and nothing
//! else crosses.
//!
//! # What changed from protocol 1, and why
//!
//! Protocol 1 described exactly one ceremony (`CA-TLS`) with one flat phase
//! enum and a pair of `can_*` booleans. Generalising it to every operator
//! ceremony broke each of those choices in turn:
//!
//! * **One phase could not describe two machines.** A recovery is held by two
//!   parties at once — Orion owns the client's private keys and signs the
//!   commit, the ceremony owns the vault and signs the grant (§11.3). «Awaiting
//!   key» and «staged at the gateway» are not two points on one line; they are
//!   two coordinates. [`RemoteState`] and [`GestureState`] are those.
//! * **`can_continue` duplicated the phase** and could disagree with it. What
//!   an operator may do is now derived once, in [`allowed_actions`], and every
//!   command is checked against it on arrival rather than trusted.
//! * **A free-text progress line cannot be a manifest.** §12.2 requires that
//!   what is signed is what was shown. A `Vec<(label, value)>` lets a field be
//!   omitted or reworded, and the receiver cannot tell. So the manifest is a
//!   closed enum of typed records ([`AstraManifest`]): the mandatory fields of
//!   an operation are its struct fields, and a variant that lost one would not
//!   compile. The **words** shown to the operator are chosen by Orion, from the
//!   variant — never carried as text by the ceremony or the network.
//! * **One frame ceiling fitted nothing.** 16 KiB was below what a campaign
//!   manifest or a recovery needs. Ceilings are per message type now.
//! * **A stale command could land.** Statuses carry a strictly increasing
//!   [`OperatorStatus::revision`], and `Continue`/`Cancel` name the revision
//!   they answer, so a click on a screen the ceremony has already left is
//!   refused instead of applied to whatever came next.
//!
//! # What the WebView may ask for
//!
//! An [`OperationLocator`] — a kind and, when the authority already opened
//! one, an operation id. Not a request, not a path, not a URL. Everything else
//! the ceremony resolves from the hand-off it pins itself, so a stolen session
//! token buys the ability to *watch* a ceremony the operator started, not to
//! choose one.

use serde::{Deserialize, Serialize};

use super::encoding::{Fingerprint, Id16, TrustDomainId, WireGuardKey};
use super::status::AstraRotationCampaign;

/// Protocol version carried by the first frame.
pub const PROTOCOL_VERSION: u16 = 2;

/// Frame ceilings, per message type.
///
/// One number could not serve three messages whose sizes differ by two orders
/// of magnitude: a hello is a token, a command is a locator, and a status may
/// carry a campaign manifest naming every target of a fleet rotation.
pub mod limits {
    /// A version, a session id and a token.
    pub const HELLO_BYTES: usize = 1024;
    /// A verb and a locator.
    pub const COMMAND_BYTES: usize = 4 * 1024;
    /// A manifest, the key labels that answered, and a typed refusal.
    pub const STATUS_BYTES: usize = 256 * 1024;

    // The ordering is the point of having three: a ceiling that let a hello be
    // as large as a status would put the unauthenticated frame back on the
    // same footing as the authenticated one.
    const _: () = assert!(HELLO_BYTES < COMMAND_BYTES);
    const _: () = assert!(COMMAND_BYTES < STATUS_BYTES);
}

/// First frame sent by the ceremony.
///
/// The session id is checked as well as the token: a token alone authenticates
/// *something* to this listener, while the pair says it belongs to the
/// session this Orion actually opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorHello {
    pub protocol_version: u16,
    pub session_id: Id16,
    pub token: String,
}

/// Which ceremony a session is for.
///
/// Closed, and named by what it does rather than by the command line it used
/// to be. `RenewCertificate` is deliberately absent: since the amendment of
/// §8.1.2 an ordinary renewal employs neither this ceremony, nor a FIDO
/// assertion, nor the vault, and offering it here would re-create the
/// per-request ceremony that amendment removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// §7.5: a client whose active leaf expired, readmitted under an operator
    /// credential.
    RecoverIdentity,
    /// §8.5: a fleet campaign the authority prepared and an operator approves.
    ApproveCampaign,
    /// §9.5: the delegation that lets Astra issue unattended.
    AuthorizeIssuer,
    /// §9.4: a new client `CA-TLS`, self-signed in the vault.
    RotateClientTlsCa,
    /// §0.6: the domain anchor itself.
    RotateAnchor,
    /// §10.2: a certificate withdrawn before its term.
    RevokeCertificate,
    /// A touch of the operator key that opens the vault and proves it is the
    /// one this workstation expects; nothing leaves the machine.
    VerifyKey,
    /// §15.2: an invitation a gateway admits, signed with the vault.
    InviteEnrollment,
    /// §15.2: the acceptance of an invitation, which issues the first leaves.
    AcceptEnrollment,
    /// The first vault of a domain, created with two operator keys.
    CreateDomain,
    /// A further operator key registered in the vault.
    AddKey,
    /// An operator key withdrawn from the vault.
    RemoveKey,
    /// An operator key marked lost, or found again.
    MarkKey,
    /// The domain's first gateway identity and certificates, issued once.
    FinalizeDomain,
    /// A gateway's first identity and leaves, issued from its bootstrap request.
    IssueGatewayBootstrap,
}

/// What the WebView is allowed to name.
///
/// Minimal on purpose. The ceremony resolves the authority origin, the RP ID,
/// the service key and the domain from its own pinned hand-off, and compares
/// them; taking them from here would mean the process holding the vault
/// learned where to send its signatures from the process that does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLocator {
    pub kind: OperationKind,
    /// The operation the authority already opened, when there is one.
    ///
    /// A recovery has one — Orion opened it and holds the identifier — and it
    /// is the only way to reach that operation: §7.5 is served without a
    /// tunnel, so the authority never enumerates recoveries, and this
    /// identifier is the whole of the caller's claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Id16>,
}

/// The only things Orion may ask of the ceremony.
///
/// The payloads are named structs rather than inline variant fields, and each
/// one denies what it does not declare: `deny_unknown_fields` has no effect on
/// the variants of a tagged enum, so an inline shape would have quietly
/// accepted any extra field the WebView cared to add. This is the direction
/// that must be closed — it is the one a compromised WebView speaks in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum OperatorCommand {
    /// Start the ceremony this session was opened for.
    Begin(BeginCommand),
    /// Take the next step of the status at `revision`.
    Continue(StepCommand),
    /// Abandon, if the status at `revision` still allows it.
    Cancel(StepCommand),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginCommand {
    pub locator: OperationLocator,
}

/// A command answering one rendered status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepCommand {
    pub revision: u64,
}

/// What an operator may do at one point of a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAction {
    Continue,
    Cancel,
}

/// Where the ceremony stands **at the authority**.
///
/// The half Orion cannot observe on its own: it is what the ceremony learned
/// from Astra and the gateway. Ordered as the exchange runs, and the order is
/// what [`RemoteState::is_past_no_return`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteState {
    /// Nothing has been asked of the authority yet.
    Local,
    /// The authority holds the request and is waiting for an operator.
    AwaitingOperator,
    /// The ceremony signed the objects; nothing has left this machine.
    Prepared,
    /// The signed objects reached the authority. **Past the point of no
    /// return**: they may already have been acted upon.
    Deposited,
    /// The gateway staged the candidate against the authorization.
    Staged,
    /// The staging is receipted and the grant has not been released yet.
    PendingGrant,
    /// The grant is out. The client may install and commit.
    Granted,
    /// Committed at both ends.
    Committed,
    /// Committed, and dormant until its window opens. A recovered generation
    /// activates at the end of its staging lease, which §7.2 places after the
    /// commit — so «rien ne se passe» is a state, and it is named.
    ActivationDeferred { activation_at: u64 },
    /// The authority declined.
    Refused,
}

impl RemoteState {
    /// Whether anything has left this machine that cannot be recalled.
    ///
    /// The question a «Annuler» button has to answer honestly. Before the
    /// deposit, abandoning costs nothing; after it, the objects are signed and
    /// in someone else's hands, and offering to cancel would be offering
    /// something this side cannot deliver.
    pub fn is_past_no_return(self) -> bool {
        !matches!(
            self,
            Self::Local | Self::AwaitingOperator | Self::Prepared | Self::Refused
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::ActivationDeferred { .. } | Self::Refused
        )
    }
}

/// What one key-slot is being asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Opening the authority vault.
    OpenVault,
    /// Approving the campaign currently shown.
    ApproveCampaign,
    /// The second, distinct credential a two-key ceremony requires.
    SecondApproval,
    /// Promoting an object already prepared.
    Promotion,
    /// A new key to register in the vault.
    RegisterKey,
    /// Proving a key opens the vault, before any campaign exists.
    ValidateKey,
}

/// Where the ceremony stands **on this machine**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GestureState {
    /// Verifying inputs. No key is asked for until this passes.
    Verifying,
    /// Nothing is being asked; the ceremony waits on the authority.
    Idle,
    /// A key must be touched. `index` is 1-based.
    AwaitingKey {
        index: u8,
        of: u8,
        purpose: KeyPurpose,
    },
    ProcessingKey {
        index: u8,
        of: u8,
    },
    /// The vault is open and the objects are being signed.
    Signing,
    Done,
    Cancelled,
    Failed,
}

impl GestureState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Cancelled | Self::Failed)
    }
}

/// What an operator may do, given both halves.
///
/// One function, one answer, and it is the only thing that decides: the
/// listener validates every arriving command against it, so a WebView that
/// invented a button gains nothing.
pub fn allowed_actions(remote: RemoteState, gesture: GestureState) -> Vec<OperatorAction> {
    if gesture.is_terminal() || remote.is_terminal() {
        return Vec::new();
    }
    let mut actions = Vec::new();
    if matches!(gesture, GestureState::AwaitingKey { .. })
        || matches!(
            (remote, gesture),
            (RemoteState::Prepared, GestureState::Idle)
        )
    {
        actions.push(OperatorAction::Continue);
    }
    if !remote.is_past_no_return() && !matches!(gesture, GestureState::Signing) {
        actions.push(OperatorAction::Cancel);
    }
    actions
}

/// Why a ceremony stopped.
///
/// A closed class rather than a sentence: the words an operator reads are
/// Orion's, in Orion's language, and a ceremony that could write them could also
/// write a reassuring one over a refusal that mattered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "refusal")]
pub enum Refusal {
    /// The vault is missing, unreadable, or not this domain's.
    VaultUnavailable,
    /// No authenticator, or the operator declined the gesture.
    KeyDeclined,
    /// Windows could not create or foreground the owner of its WebAuthn UI.
    ForegroundUnavailable,
    /// The key that answered is not enrolled in this domain.
    KeyNotEnrolled,
    /// A two-key ceremony was answered twice by the same credential.
    KeyRepeated,
    /// The operation's window closed before the gesture completed.
    WindowExpired,
    /// The authority declined; its own reason stays in its protected log.
    AuthorityRefused { status: u16 },
    /// What the authority offered does not match what this ceremony pins.
    HandoffMismatch,
    /// The answer did not describe the request that was sent.
    ManifestMismatch,
    /// The peer on the socket broke the protocol.
    ProtocolViolation,
    /// The operator abandoned before the point of no return.
    Cancelled,
    /// The gateway did not admit the invitation or could not be read. It
    /// carries no text: whatever the gateway said stays in its own log.
    GatewayUnavailable,
    /// The invitation a request names is not in this machine's registry.
    InvitationUnknown,
    /// The invitation was already consumed: the acceptance is resumed, not redone.
    InvitationConsumed,
    /// The invitation is past its window or no longer open.
    InvitationExpired,
    /// The domain relay carries no `CA-TLS`: its issuance must come first.
    CaTlsMissing,
    /// The gateway answered 401 or 403: this machine's peer lacks the `admin`
    /// flag.
    GatewayForbidden,
    /// The gateway refused the request with this HTTP status. It carries no
    /// text: whatever the gateway said stays in its own log.
    GatewayRefused { status: u16 },
    /// The leaves were issued and handed out, but could not be kept: the
    /// acceptance cannot be resumed.
    AcceptanceNotKept,
    /// The invitation was consumed with no accepted request kept here: it was
    /// accepted outside Orion, so its leaves are not on this machine to resume.
    AcceptedElsewhere,
    /// An invitation was asked for, but no PQ leaf of the gateway could be read:
    /// the connected gateway did not answer (or has no `heliosd_url`) and no
    /// leaf file was supplied.
    GatewayLeafUnavailable,
    /// The peer is admitted, but its document could not be built or signed:
    /// the acceptance is resumed, not redone.
    DocumentNotSigned,
    /// A vault already exists where a new one would be created.
    VaultExists,
    /// The place the vault would be kept cannot be reached or written.
    LocationUnavailable,
    /// The vault holds as many keys as it may.
    VaultFull,
    /// The change would leave fewer keys than the vault requires.
    MinimumKeys,
    /// The key that opened the vault is the key the gesture removes: a key
    /// cannot sign its own withdrawal.
    KeyBeingRemoved,
    /// The gateway has no identity to anchor the domain on.
    GatewayIdentityMissing,
    /// The domain is already complete: nothing is left to finalize.
    DomainComplete,
    /// The bootstrap request is malformed, or does not hold what it must.
    BootstrapRequestInvalid,
    /// The request comes from a gateway other than the one the domain names.
    OtherGateway,
    /// The domain moved between the manifest shown and the press: what would
    /// be signed is no longer what the operator saw. Nothing was signed.
    DomainChanged,
    /// The credential document revokes the key that answered, or marks it
    /// lost: it cannot approve.
    SignerRevoked,
    /// The file is not a delegation request that can be read: nothing was
    /// signed.
    DelegationRequestInvalid,
    /// The campaign does not name this delegation request: its epoch or one
    /// of its keys was substituted. Refused before any key.
    DelegationRequestMismatch,
    /// The domain's `CA-TLS` cannot back the delegation: it is not a
    /// certificate authority, or it does not cover the whole delegation
    /// window. Refused before any key.
    CaTlsUnusable,
    /// Astra knows nothing of a rotation whose campaign died, and the vault never
    /// moved. Its journal is gone: the rotation is started again.
    RotationExpired,
    /// The domain contradicts the rotation's journal, or Astra and the vault name
    /// different anchors before any campaign. Nothing moved and nothing was
    /// cleared: it is not for this machine to choose.
    DomainConflict,
    /// The transition did not reach the gateway before `activation_at`. The gateway
    /// refuses it from now on, and no repair exists.
    InstallDeadlinePassed,
    /// The gateway names no anchor of this kind: it predates the field, or it is
    /// current with no client TLS CA configured, and the two read the same. The
    /// rotation is kept and resumes from its journal.
    GatewayNamesNoAnchor,
    /// A rotation stands in the way, or is not at the step this gesture takes.
    RotationInFlight,
    /// The campaign of a signed rotation has just closed, and Astra naming nothing
    /// of it is not yet its last word: a deposit may still be committing. Nothing
    /// was cleared; a look from `until` on decides.
    CampaignClosing { until: u64 },
    /// The key that answered is not the one this step can take: outside the two
    /// validated, or one that has already approved.
    KeyNotValidated,
    /// The approval screen's terms are outside what a rotation accepts. Nothing was
    /// sent, and the screen stays.
    TermsRefused,
    /// No client TLS rotation is waiting to end.
    NothingToFinish,
    /// The client TLS overlap runs until `until`, on this machine's clock: the
    /// gateway still requires the outgoing generation. Nothing was modified.
    OverlapRunning { until: u64 },
    /// Anything the ceremony could not classify. Deliberately last and
    /// deliberately opaque: an unclassified failure must not become a channel
    /// for text.
    Internal,
}

/// The verified description of what is about to be signed.
///
/// Closed, and typed per operation. This is the object §12.2 is about: what an
/// operator approves is what these fields say, and a field that could be
/// dropped without the receiver noticing would make that promise unverifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum AstraManifest {
    Recovery(RecoveryManifest),
    Campaign(CampaignManifest),
    IssuerAuthorization(IssuerManifest),
    CaRotation(CaRotationManifest),
    Revocation(RevocationManifest),
    KeyCheck(KeyCheckManifest),
    Invitation(InvitationManifest),
    EnrollmentAcceptance(AcceptanceManifest),
    DomainCreation(DomainCreationManifest),
    KeyAddition(KeyAdditionManifest),
    KeyRemoval(KeyRemovalManifest),
    KeyMarking(KeyMarkingManifest),
    DomainFinalization(DomainFinalizationManifest),
    GatewayBootstrap(GatewayBootstrapManifest),
}

impl AstraManifest {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Recovery(_) => OperationKind::RecoverIdentity,
            Self::Campaign(_) => OperationKind::ApproveCampaign,
            Self::IssuerAuthorization(_) => OperationKind::AuthorizeIssuer,
            Self::CaRotation(manifest) => manifest.kind(),
            Self::Revocation(_) => OperationKind::RevokeCertificate,
            Self::KeyCheck(_) => OperationKind::VerifyKey,
            Self::Invitation(_) => OperationKind::InviteEnrollment,
            Self::EnrollmentAcceptance(_) => OperationKind::AcceptEnrollment,
            Self::DomainCreation(_) => OperationKind::CreateDomain,
            Self::KeyAddition(_) => OperationKind::AddKey,
            Self::KeyRemoval(_) => OperationKind::RemoveKey,
            Self::KeyMarking(_) => OperationKind::MarkKey,
            Self::DomainFinalization(_) => OperationKind::FinalizeDomain,
            Self::GatewayBootstrap(_) => OperationKind::IssueGatewayBootstrap,
        }
    }

    /// The domain a manifest names, so Orion can refuse one that belongs to
    /// another domain before showing a single field of it. The enrollment
    /// manifests name none — the vault and the invitation bind them — so they
    /// return `None` and the caller must not read that as a match.
    pub fn trust_domain_id(&self) -> Option<TrustDomainId> {
        match self {
            Self::Recovery(manifest) => Some(manifest.trust_domain_id),
            Self::Campaign(manifest) => Some(manifest.campaign.trust_domain_id),
            Self::IssuerAuthorization(manifest) => Some(manifest.trust_domain_id),
            Self::CaRotation(manifest) => Some(manifest.trust_domain_id),
            Self::Revocation(manifest) => Some(manifest.trust_domain_id),
            Self::KeyCheck(_)
            | Self::Invitation(_)
            | Self::EnrollmentAcceptance(_)
            | Self::DomainCreation(_)
            | Self::KeyAddition(_)
            | Self::KeyRemoval(_)
            | Self::KeyMarking(_)
            | Self::DomainFinalization(_)
            | Self::GatewayBootstrap(_) => None,
        }
    }
}

/// The key check: what the touch proves, and nothing it signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCheckManifest {
    /// The vault the key opened, so the operator sees which one answered.
    pub vault_fingerprint: Fingerprint,
}

/// The first vault of a domain: where it answers and what its two keys are called.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainCreationManifest {
    pub rp_id: String,
    pub authority_url: String,
    pub first_label: String,
    pub second_label: String,
}

/// A key added to the vault; `role` is `principale` or `recuperation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAdditionManifest {
    pub vault_fingerprint: Fingerprint,
    pub label: String,
    pub role: String,
}

/// A key removed from the vault; `role` is `principale` or `recuperation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRemovalManifest {
    pub vault_fingerprint: Fingerprint,
    pub slot_id: String,
    pub label: String,
    pub role: String,
}

/// A key marked lost (`lost`) or found again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMarkingManifest {
    pub vault_fingerprint: Fingerprint,
    pub slot_id: String,
    pub label: String,
    pub lost: bool,
}

/// The domain's first gateway identity and what is issued under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainFinalizationManifest {
    pub vault_fingerprint: Fingerprint,
    pub server_name: String,
    pub gateway_wg_public_key: WireGuardKey,
    pub issues_ca_tls: bool,
    pub ca_tls_days: u64,
    pub issues_credentials: bool,
}

/// A gateway's bootstrap request and what is issued from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBootstrapManifest {
    pub vault_fingerprint: Fingerprint,
    pub server_name: String,
    pub gateway_wg_public_key: WireGuardKey,
    pub request_fingerprint: Fingerprint,
    pub leaf_days: u64,
    pub issues_ca_tls: bool,
    pub ca_tls_days: u64,
    pub issues_credentials: bool,
}

/// §15.2, the invitation a gateway is asked to admit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationManifest {
    pub server_name: String,
    pub gateway_wg_public_key: WireGuardKey,
    pub not_after_unix: u64,
    /// Whether a peer already known to the gateway may be admitted again.
    pub allow_readmission: bool,
    pub ca_pq_fingerprint: Fingerprint,
}

/// §15.2, the acceptance that consumes an invitation and issues the first
/// leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceManifest {
    pub invitation_id: Id16,
    pub request_fingerprint: Fingerprint,
    pub requested_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub leaves_not_after_unix: u64,
    pub endpoint: String,
    /// The routes the document will carry, shown because they are signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<String>,
    /// The SSH target the document will carry, shown because it is signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_target: Option<String>,
}

/// §7.5, and the only ceremony held by two parties at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryManifest {
    pub trust_domain_id: TrustDomainId,
    pub peer_name: String,
    pub client_wg_public_key: String,
    pub expired_generation: u64,
    pub next_generation: u64,
    /// How long the identity has been dead. Shown because an operator asked to
    /// resurrect one is entitled to know whether it died an hour or a year
    /// ago.
    pub expired_since_secs: u64,
    pub request_fingerprint: Fingerprint,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub activation_at: u64,
    pub not_after: u64,
}

/// §8.5, the fleet campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignManifest {
    /// The complete canonical value whose fingerprint the credentials approve.
    /// Keeping the original type here prevents this display contract from
    /// silently omitting a target or reinterpreting a scope.
    pub campaign: Box<AstraRotationCampaign>,
    pub fingerprint: Fingerprint,
}

/// §9.5, the delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerManifest {
    pub trust_domain_id: TrustDomainId,
    pub issuer_epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// What the delegated issuer will be allowed to do, spelled out rather
    /// than summarised: this is the whole of what the signature widens.
    pub allowed_usages: Vec<String>,
    pub policy_fingerprint: Fingerprint,
    /// SHA-256 of the compact JSON re-encoding of the parsed
    /// `IssuerDelegationRequest` (fields in declaration order). Not the hash
    /// of the file as read: whitespace around the document does not move it,
    /// whitespace inside a value does. It identifies the request; the values
    /// that bind what is certified are the two key fingerprints below.
    pub request_fingerprint: Fingerprint,
    /// Longest leaf the delegated issuer may sign, already capped by the
    /// pinned policy: the value shown is the value signed.
    pub maximum_leaf_lifetime_secs: u64,
    /// The ML-DSA-87 key the delegation certifies.
    pub pq_public_key_fingerprint: Fingerprint,
    /// The `SubjectPublicKeyInfo` the request's PKCS#10 proves possession of.
    pub tls_public_key_info_fingerprint: Fingerprint,
    /// The campaign the key also approves, when there is one. Absent for the
    /// offline form, which nothing ties to the authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<CampaignManifest>,
}

/// Which CA a rotation moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffectedCa {
    /// The domain anchor.
    CaPq,
    /// The client TLS CA.
    CaTls,
}

/// §0.6 and §9.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaRotationManifest {
    pub trust_domain_id: TrustDomainId,
    pub affected_ca: AffectedCa,
    pub current_epoch: u64,
    pub next_epoch: u64,
    pub activation_at: u64,
    pub not_after: u64,
    pub outgoing_anchor_fingerprint: Fingerprint,
    /// Absent at the touch: the incoming anchor does not exist before the
    /// signature, which the approvals come before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_anchor_fingerprint: Option<Fingerprint>,
    /// The campaign the keys approve, when there is one. Absent for a rotation
    /// signed offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<CampaignManifest>,
}

impl CaRotationManifest {
    fn kind(&self) -> OperationKind {
        match self.affected_ca {
            AffectedCa::CaPq => OperationKind::RotateAnchor,
            AffectedCa::CaTls => OperationKind::RotateClientTlsCa,
        }
    }
}

/// §10.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationManifest {
    pub trust_domain_id: TrustDomainId,
    pub target: String,
    pub scope: String,
    pub reason: String,
    pub revocation_epoch: u64,
    pub effective_at: u64,
}

/// The label of a key-slot that answered.
///
/// The label an operator gave the slot at enrolment, and nothing else: no
/// credential id, no AAGUID, no attestation. It exists so a two-key ceremony
/// can say *which* two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlotLabel {
    pub slot: String,
    pub label: String,
}

/// Complete observable state of one session. Public metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorStatus {
    pub session_id: Id16,
    /// Strictly increasing within a session. A command names the revision it
    /// answers, so a click on a superseded screen is refused rather than
    /// applied to whatever replaced it.
    pub revision: u64,
    pub operation: OperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Id16>,
    pub remote: RemoteState,
    pub gesture: GestureState,
    /// Derived from the two states by [`allowed_actions`], carried so the
    /// WebView renders exactly what the listener will accept.
    pub allowed: Vec<OperatorAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<AstraManifest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<KeySlotLabel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    /// Why the last answer was turned down, on a status still asking for another: a
    /// key, or a rotation's terms. Distinct from [`Self::refusal`], which ends the
    /// ceremony: this ends nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_retry: Option<Refusal>,
    /// The labels of the keys that approved, in the order they did. A key is named by
    /// the label it validated under, so the screen can say which of its keys is done.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved: Vec<KeySlotLabel>,
    /// When a wait for the operator ends by itself, unix seconds. Only a rotation's key
    /// and terms steps set it: nothing the operator types renews it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_until: Option<u64>,
}

impl OperatorStatus {
    pub fn new(
        session_id: Id16,
        revision: u64,
        operation: OperationKind,
        remote: RemoteState,
        gesture: GestureState,
    ) -> Self {
        Self {
            session_id,
            revision,
            operation,
            operation_id: None,
            remote,
            gesture,
            allowed: allowed_actions(remote, gesture),
            manifest: None,
            keys: Vec::new(),
            refusal: None,
            key_retry: None,
            approved: Vec::new(),
            idle_until: None,
        }
    }

    /// Whether a command is one this status offers.
    ///
    /// Checked on arrival rather than assumed: `allowed` is what was rendered,
    /// and a command that does not appear in it either raced a newer status or
    /// was never offered.
    pub fn accepts(&self, action: OperatorAction, revision: u64) -> bool {
        revision == self.revision && self.allowed.contains(&action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

    fn session() -> Id16 {
        Id16::new([3; 16]).expect("id")
    }

    #[test]
    fn the_vault_gestures_have_their_kinds() {
        let fp = Fingerprint::of(b"vault");
        let cases = [
            (
                AstraManifest::DomainCreation(DomainCreationManifest {
                    rp_id: "astra.example".into(),
                    authority_url: "https://astra.example".into(),
                    first_label: "a".into(),
                    second_label: "b".into(),
                }),
                OperationKind::CreateDomain,
            ),
            (
                AstraManifest::KeyAddition(KeyAdditionManifest {
                    vault_fingerprint: fp,
                    label: "c".into(),
                    role: "recuperation".into(),
                }),
                OperationKind::AddKey,
            ),
            (
                AstraManifest::KeyRemoval(KeyRemovalManifest {
                    vault_fingerprint: fp,
                    slot_id: "00".repeat(16),
                    label: "c".into(),
                    role: "principale".into(),
                }),
                OperationKind::RemoveKey,
            ),
            (
                AstraManifest::KeyMarking(KeyMarkingManifest {
                    vault_fingerprint: fp,
                    slot_id: "00".repeat(16),
                    label: "c".into(),
                    lost: true,
                }),
                OperationKind::MarkKey,
            ),
        ];
        for (manifest, kind) in cases {
            assert_eq!(manifest.kind(), kind);
            assert_eq!(manifest.trust_domain_id(), None);
        }
    }

    #[test]
    fn the_new_refusals_and_purpose_are_spelled_for_the_window() {
        assert_eq!(
            serde_json::to_value(Refusal::KeyBeingRemoved).unwrap(),
            serde_json::json!({"refusal": "key_being_removed"})
        );
        assert_eq!(
            serde_json::to_value(Refusal::LocationUnavailable).unwrap(),
            serde_json::json!({"refusal": "location_unavailable"})
        );
        assert_eq!(
            serde_json::to_value(KeyPurpose::RegisterKey).unwrap(),
            serde_json::json!("register_key")
        );
        assert_eq!(
            serde_json::to_value(OperationKind::FinalizeDomain).unwrap(),
            serde_json::json!("finalize_domain")
        );
    }

    #[test]
    fn a_creation_manifest_with_an_extra_field_is_refused() {
        let text = r#"{"operation":"domain_creation","rp_id":"a.example","authority_url":"https://a.example","first_label":"a","second_label":"b","extra":1}"#;
        assert!(serde_json::from_str::<AstraManifest>(text).is_err());
    }

    /// Validating a key is a touch like any other: it can be taken or abandoned.
    #[test]
    fn a_key_validation_may_be_continued_and_abandoned() {
        let actions = allowed_actions(
            RemoteState::Local,
            GestureState::AwaitingKey {
                index: 1,
                of: 2,
                purpose: KeyPurpose::ValidateKey,
            },
        );
        assert_eq!(
            actions,
            vec![OperatorAction::Continue, OperatorAction::Cancel]
        );
        assert_eq!(
            serde_json::to_value(KeyPurpose::ValidateKey).expect("purpose"),
            serde_json::json!("validate_key")
        );
    }

    /// Both keys validated, nothing open yet. Approving takes its terms and has a
    /// command of its own, so a Continue offered here could only be refused.
    #[test]
    fn the_wait_for_the_terms_may_be_answered_and_abandoned() {
        assert_eq!(
            allowed_actions(RemoteState::Local, GestureState::Idle),
            vec![OperatorAction::Cancel]
        );
    }

    /// A retry is not an end: the status still offers the key, and says why the
    /// last one was turned down. Absent from the wire when there is none.
    #[test]
    fn a_key_retry_rides_a_status_that_stays_open() {
        let mut status = OperatorStatus::new(
            session(),
            4,
            OperationKind::RotateAnchor,
            RemoteState::Local,
            GestureState::AwaitingKey {
                index: 2,
                of: 2,
                purpose: KeyPurpose::ValidateKey,
            },
        );
        let bare = serde_json::to_value(&status).expect("status");
        assert!(bare.get("key_retry").is_none());
        assert_eq!(
            serde_json::from_value::<OperatorStatus>(bare)
                .expect("a status with no retry")
                .key_retry,
            None
        );

        status.key_retry = Some(Refusal::KeyRepeated);
        let encoded = serde_json::to_value(&status).expect("status");
        assert_eq!(
            encoded["key_retry"],
            serde_json::json!({ "refusal": "key_repeated" })
        );
        assert_eq!(
            serde_json::from_value::<OperatorStatus>(encoded).expect("round trip"),
            status
        );
        assert!(!status.gesture.is_terminal());
        assert!(status.accepts(OperatorAction::Continue, 4));
    }

    #[test]
    fn the_rotation_refusals_carry_no_text() {
        for (refusal, wire) in [
            (Refusal::RotationExpired, "rotation_expired"),
            (Refusal::DomainConflict, "domain_conflict"),
            (Refusal::InstallDeadlinePassed, "install_deadline_passed"),
            (Refusal::GatewayNamesNoAnchor, "gateway_names_no_anchor"),
            (Refusal::RotationInFlight, "rotation_in_flight"),
            (Refusal::KeyNotValidated, "key_not_validated"),
            (Refusal::TermsRefused, "terms_refused"),
            (Refusal::NothingToFinish, "nothing_to_finish"),
        ] {
            assert_eq!(
                serde_json::to_value(refusal).expect("refusal"),
                serde_json::json!({ "refusal": wire })
            );
        }
    }

    /// A date, and still no text: the screen words it.
    #[test]
    fn the_dated_rotation_refusals_carry_their_instant_only() {
        assert_eq!(
            serde_json::to_value(Refusal::CampaignClosing { until: 7 }).expect("refusal"),
            serde_json::json!({ "refusal": "campaign_closing", "until": 7 })
        );
        assert_eq!(
            serde_json::to_value(Refusal::OverlapRunning { until: 9 }).expect("refusal"),
            serde_json::json!({ "refusal": "overlap_running", "until": 9 })
        );
    }

    #[test]
    fn a_key_touch_may_be_continued_and_abandoned() {
        let actions = allowed_actions(
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 2,
                purpose: KeyPurpose::OpenVault,
            },
        );
        assert_eq!(
            actions,
            vec![OperatorAction::Continue, OperatorAction::Cancel]
        );
    }

    /// The property the button depends on: once the signed objects have left,
    /// «Annuler» would promise something this side cannot deliver.
    #[test]
    fn nothing_may_be_cancelled_past_the_deposit() {
        for remote in [
            RemoteState::Deposited,
            RemoteState::Staged,
            RemoteState::PendingGrant,
            RemoteState::Granted,
        ] {
            assert!(remote.is_past_no_return(), "{remote:?}");
            assert!(
                !allowed_actions(remote, GestureState::Idle).contains(&OperatorAction::Cancel),
                "{remote:?}"
            );
        }
        for remote in [
            RemoteState::Local,
            RemoteState::AwaitingOperator,
            RemoteState::Prepared,
        ] {
            assert!(!remote.is_past_no_return(), "{remote:?}");
        }
    }

    #[test]
    fn a_finished_ceremony_offers_nothing() {
        assert!(allowed_actions(RemoteState::Committed, GestureState::Done).is_empty());
        assert!(allowed_actions(RemoteState::Local, GestureState::Failed).is_empty());
        assert!(allowed_actions(RemoteState::Refused, GestureState::Idle).is_empty());
    }

    /// A deferred activation is finished, not stuck: the operator has nothing
    /// left to do and must not be offered a button that implies otherwise.
    #[test]
    fn a_deferred_activation_is_terminal() {
        let remote = RemoteState::ActivationDeferred {
            activation_at: 1_800,
        };
        assert!(remote.is_terminal());
        assert!(allowed_actions(remote, GestureState::Done).is_empty());
    }

    /// The whole reason revisions exist.
    #[test]
    fn a_command_answering_a_superseded_status_is_refused() {
        let status = OperatorStatus::new(
            session(),
            7,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        );
        assert!(status.accepts(OperatorAction::Continue, 7));
        assert!(!status.accepts(OperatorAction::Continue, 6));
        assert!(!status.accepts(OperatorAction::Continue, 8));
    }

    #[test]
    fn a_status_never_offers_what_the_states_do_not() {
        let status = OperatorStatus::new(
            session(),
            1,
            OperationKind::ApproveCampaign,
            RemoteState::Deposited,
            GestureState::Idle,
        );
        assert!(!status.accepts(OperatorAction::Cancel, 1));
    }

    /// Closed on the wire in both directions: an unknown verb, or a field
    /// nobody declared, is a protocol violation and not a default.
    #[test]
    fn the_wire_refuses_what_it_does_not_declare() {
        let command: OperatorCommand =
            serde_json::from_str(r#"{"command":"continue","revision":3}"#).expect("continue");
        assert_eq!(
            command,
            OperatorCommand::Continue(StepCommand { revision: 3 })
        );
        assert!(serde_json::from_str::<OperatorCommand>(r#"{"command":"run"}"#).is_err());
        assert!(serde_json::from_str::<OperatorCommand>(
            r#"{"command":"continue","revision":3,"extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<OperatorHello>(
            r#"{"protocol_version":2,"session_id":"03030303030303030303030303030303"}"#
        )
        .is_err());
    }

    #[test]
    fn a_foreground_refusal_has_a_stable_wire_name() {
        assert_eq!(
            serde_json::to_value(Refusal::ForegroundUnavailable).expect("refusal"),
            serde_json::json!({ "refusal": "foreground_unavailable" })
        );
    }

    /// The locator is the whole of what the WebView may name.
    #[test]
    fn a_locator_carries_a_kind_and_at_most_an_identifier() {
        let locator: OperationLocator =
            serde_json::from_str(r#"{"kind":"recover_identity"}"#).expect("locator");
        assert_eq!(locator.kind, OperationKind::RecoverIdentity);
        assert_eq!(locator.operation_id, None);
        assert!(serde_json::from_str::<OperationLocator>(
            r#"{"kind":"recover_identity","authority_url":"https://elsewhere.example"}"#
        )
        .is_err());
    }

    #[test]
    fn a_manifest_names_its_operation_and_its_domain() {
        let manifest = AstraManifest::CaRotation(CaRotationManifest {
            trust_domain_id: Id16::new([1; 16]).expect("domain"),
            affected_ca: AffectedCa::CaTls,
            current_epoch: 1,
            next_epoch: 2,
            activation_at: 10,
            not_after: 20,
            outgoing_anchor_fingerprint: Fingerprint::of(b"outgoing"),
            next_anchor_fingerprint: Some(Fingerprint::of(b"next")),
            campaign: None,
        });
        assert_eq!(manifest.kind(), OperationKind::RotateClientTlsCa);
        assert_eq!(
            manifest.trust_domain_id(),
            Some(Id16::new([1; 16]).expect("domain"))
        );
    }

    /// At the touch there is no incoming anchor to name. A manifest that does name
    /// one, written before these two fields were optional, still reads.
    #[test]
    fn a_rotation_manifest_may_name_no_incoming_anchor_and_no_campaign() {
        let manifest = CaRotationManifest {
            trust_domain_id: Id16::new([1; 16]).expect("domain"),
            affected_ca: AffectedCa::CaPq,
            current_epoch: 1,
            next_epoch: 2,
            activation_at: 10,
            not_after: 20,
            outgoing_anchor_fingerprint: Fingerprint::of(b"outgoing"),
            next_anchor_fingerprint: None,
            campaign: None,
        };
        let encoded = serde_json::to_value(&manifest).expect("encoding");
        assert!(encoded.get("next_anchor_fingerprint").is_none());
        assert!(encoded.get("campaign").is_none());
        assert_eq!(
            serde_json::from_value::<CaRotationManifest>(encoded).expect("decoding"),
            manifest
        );

        let named = CaRotationManifest {
            next_anchor_fingerprint: Some(Fingerprint::of(b"next")),
            ..manifest
        };
        let encoded = serde_json::to_value(&named).expect("encoding");
        assert_eq!(
            encoded["next_anchor_fingerprint"],
            serde_json::to_value(Fingerprint::of(b"next")).expect("fingerprint")
        );
        assert_eq!(
            serde_json::from_value::<CaRotationManifest>(encoded).expect("decoding"),
            named
        );
    }

    /// A campaign approval binds every exact target. The IPC manifest must
    /// carry that same canonical object rather than a lossy count or summary.
    #[test]
    fn a_campaign_manifest_keeps_every_signed_target() {
        let domain = Id16::new([1; 16]).expect("domain");
        let campaign = AstraRotationCampaign {
            format_version: crate::certificates::CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([2; 16]).expect("campaign"),
            trust_domain_id: domain,
            gateway_wg_public_key: WireGuardKey::from_bytes([3; 32]),
            server_name: "gateway.example".into(),
            created_at: 10,
            expires_at: 20,
            scope: CampaignScope::OrionProfile,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientTls,
                identity_key: WireGuardKey::from_bytes([4; 32]),
                epoch: 7,
                generation: 8,
                active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            }],
            reason: "rotation".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: 1,
        };
        let fingerprint = campaign.fingerprint();
        let manifest = AstraManifest::Campaign(CampaignManifest {
            campaign: Box::new(campaign.clone()),
            fingerprint,
        });

        assert_eq!(manifest.trust_domain_id(), Some(domain));
        let encoded = serde_json::to_value(&manifest).expect("manifest");
        assert_eq!(
            encoded["campaign"]["targets"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(encoded["fingerprint"], fingerprint.to_string());
        assert_eq!(
            encoded["campaign"]["targets"][0]["identity_key"],
            campaign.targets[0].identity_key.to_string()
        );
    }

    #[test]
    fn enrollment_kinds_round_trip() {
        for (kind, wire) in [
            (OperationKind::VerifyKey, "verify_key"),
            (OperationKind::InviteEnrollment, "invite_enrollment"),
            (OperationKind::AcceptEnrollment, "accept_enrollment"),
        ] {
            let encoded = serde_json::to_value(kind).expect("kind");
            assert_eq!(encoded, serde_json::json!(wire));
            assert_eq!(
                serde_json::from_value::<OperationKind>(encoded).expect("back"),
                kind
            );
        }
    }

    #[test]
    fn enrollment_manifests_name_their_kind() {
        let key_check = AstraManifest::KeyCheck(KeyCheckManifest {
            vault_fingerprint: Fingerprint::of(b"vault"),
        });
        assert_eq!(key_check.kind(), OperationKind::VerifyKey);
        let invitation = AstraManifest::Invitation(InvitationManifest {
            server_name: "gateway.example".into(),
            gateway_wg_public_key: WireGuardKey::from_bytes([5; 32]),
            not_after_unix: 100,
            allow_readmission: false,
            ca_pq_fingerprint: Fingerprint::of(b"ca-pq"),
        });
        assert_eq!(invitation.kind(), OperationKind::InviteEnrollment);
        let acceptance = AstraManifest::EnrollmentAcceptance(acceptance_manifest());
        assert_eq!(acceptance.kind(), OperationKind::AcceptEnrollment);
    }

    fn acceptance_manifest() -> AcceptanceManifest {
        AcceptanceManifest {
            invitation_id: Id16::new([6; 16]).expect("invitation"),
            request_fingerprint: Fingerprint::of(b"request"),
            requested_name: "laptop".into(),
            client_wg_public_key: WireGuardKey::from_bytes([7; 32]),
            leaves_not_after_unix: 200,
            endpoint: "gateway.example:51820".into(),
            allowed_ips: None,
            ssh_target: None,
        }
    }

    #[test]
    fn the_signed_routes_are_shown_when_present_and_absent_otherwise() {
        let bare = serde_json::to_value(acceptance_manifest()).expect("manifest");
        assert!(bare.get("allowed_ips").is_none());
        assert!(bare.get("ssh_target").is_none());
        // A manifest written before the fields existed still reads.
        let old = serde_json::from_value::<AcceptanceManifest>(bare).expect("old manifest");
        assert_eq!(old, acceptance_manifest());

        let mut routed = acceptance_manifest();
        routed.allowed_ips = Some("10.0.0.0/24".into());
        routed.ssh_target = Some("root@10.0.0.1".into());
        let encoded = serde_json::to_value(&routed).expect("manifest");
        assert_eq!(encoded["allowed_ips"], "10.0.0.0/24");
        assert_eq!(encoded["ssh_target"], "root@10.0.0.1");
        assert_eq!(
            serde_json::from_value::<AcceptanceManifest>(encoded).expect("round trip"),
            routed
        );
    }

    #[test]
    fn the_document_and_leaf_refusals_carry_no_text() {
        assert_eq!(
            serde_json::to_value(Refusal::GatewayLeafUnavailable).expect("refusal"),
            serde_json::json!({ "refusal": "gateway_leaf_unavailable" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::DocumentNotSigned).expect("refusal"),
            serde_json::json!({ "refusal": "document_not_signed" })
        );
    }

    #[test]
    fn a_manifest_with_an_unknown_field_is_refused() {
        let mut encoded = serde_json::to_value(acceptance_manifest()).expect("manifest");
        assert!(serde_json::from_value::<AcceptanceManifest>(encoded.clone()).is_ok());
        encoded["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AcceptanceManifest>(encoded).is_err());
    }

    #[test]
    fn gateway_unavailable_carries_no_text() {
        assert_eq!(
            serde_json::to_value(Refusal::GatewayUnavailable).expect("refusal"),
            serde_json::json!({ "refusal": "gateway_unavailable" })
        );
    }

    #[test]
    fn the_acceptance_refusals_carry_no_text() {
        for (refusal, expected) in [
            (
                Refusal::InvitationUnknown,
                serde_json::json!({ "refusal": "invitation_unknown" }),
            ),
            (
                Refusal::CaTlsMissing,
                serde_json::json!({ "refusal": "ca_tls_missing" }),
            ),
            (
                Refusal::GatewayForbidden,
                serde_json::json!({ "refusal": "gateway_forbidden" }),
            ),
            (
                Refusal::GatewayRefused { status: 409 },
                serde_json::json!({ "refusal": "gateway_refused", "status": 409 }),
            ),
            (
                Refusal::AcceptanceNotKept,
                serde_json::json!({ "refusal": "acceptance_not_kept" }),
            ),
            (
                Refusal::AcceptedElsewhere,
                serde_json::json!({ "refusal": "accepted_elsewhere" }),
            ),
        ] {
            assert_eq!(serde_json::to_value(refusal).expect("refusal"), expected);
        }
    }

    fn bootstrap_manifest() -> GatewayBootstrapManifest {
        GatewayBootstrapManifest {
            vault_fingerprint: Fingerprint::of(b"vault"),
            server_name: "gateway.example".into(),
            gateway_wg_public_key: WireGuardKey::from_bytes([8; 32]),
            request_fingerprint: Fingerprint::of(b"request"),
            leaf_days: 90,
            issues_ca_tls: true,
            ca_tls_days: 365,
            issues_credentials: true,
        }
    }

    #[test]
    fn the_bootstrap_manifest_has_its_kind() {
        let manifest = AstraManifest::GatewayBootstrap(bootstrap_manifest());
        assert_eq!(manifest.kind(), OperationKind::IssueGatewayBootstrap);
        assert_eq!(manifest.trust_domain_id(), None);
        assert_eq!(
            serde_json::to_value(OperationKind::IssueGatewayBootstrap).expect("kind"),
            serde_json::json!("issue_gateway_bootstrap")
        );
        let encoded = serde_json::to_value(&manifest).expect("manifest");
        assert_eq!(encoded["operation"], "gateway_bootstrap");
        assert_eq!(
            serde_json::from_value::<AstraManifest>(encoded).expect("round trip"),
            manifest
        );
    }

    #[test]
    fn the_bootstrap_refusals_spell_in_snake_case() {
        assert_eq!(
            serde_json::to_value(Refusal::BootstrapRequestInvalid).expect("refusal"),
            serde_json::json!({ "refusal": "bootstrap_request_invalid" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::OtherGateway).expect("refusal"),
            serde_json::json!({ "refusal": "other_gateway" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::DomainChanged).expect("refusal"),
            serde_json::json!({ "refusal": "domain_changed" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::SignerRevoked).expect("refusal"),
            serde_json::json!({ "refusal": "signer_revoked" })
        );
    }

    #[test]
    fn the_bootstrap_manifest_refuses_unknown_fields() {
        let mut encoded = serde_json::to_value(bootstrap_manifest()).expect("manifest");
        assert!(serde_json::from_value::<GatewayBootstrapManifest>(encoded.clone()).is_ok());
        encoded["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<GatewayBootstrapManifest>(encoded).is_err());
    }

    fn issuer_manifest() -> IssuerManifest {
        IssuerManifest {
            trust_domain_id: Id16::new([7; 16]).expect("domain"),
            issuer_epoch: 2,
            not_before: 10,
            not_after: 20,
            allowed_usages: vec!["client_leaf_renewal".into()],
            policy_fingerprint: Fingerprint::of(b"policy"),
            request_fingerprint: Fingerprint::of(b"request"),
            maximum_leaf_lifetime_secs: 90 * 86_400,
            pq_public_key_fingerprint: Fingerprint::of(b"pq"),
            tls_public_key_info_fingerprint: Fingerprint::of(b"spki"),
            campaign: None,
        }
    }

    #[test]
    fn the_delegation_refusals_spell_in_snake_case() {
        assert_eq!(
            serde_json::to_value(Refusal::DelegationRequestInvalid).expect("refusal"),
            serde_json::json!({ "refusal": "delegation_request_invalid" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::DelegationRequestMismatch).expect("refusal"),
            serde_json::json!({ "refusal": "delegation_request_mismatch" })
        );
        assert_eq!(
            serde_json::to_value(Refusal::CaTlsUnusable).expect("refusal"),
            serde_json::json!({ "refusal": "ca_tls_unusable" })
        );
    }

    #[test]
    fn an_issuer_manifest_without_campaign_omits_it() {
        let encoded = serde_json::to_value(issuer_manifest()).expect("manifest");
        assert!(encoded.get("campaign").is_none());
        let decoded: IssuerManifest = serde_json::from_value(encoded).expect("decoded");
        assert_eq!(decoded.campaign, None);
        assert_eq!(decoded, issuer_manifest());
    }

    #[test]
    fn an_issuer_manifest_refuses_unknown_fields() {
        let mut encoded = serde_json::to_value(issuer_manifest()).expect("manifest");
        encoded["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<IssuerManifest>(encoded).is_err());
    }

    #[test]
    fn the_issuer_manifest_has_its_kind() {
        assert_eq!(
            AstraManifest::IssuerAuthorization(issuer_manifest()).kind(),
            OperationKind::AuthorizeIssuer
        );
    }
}
