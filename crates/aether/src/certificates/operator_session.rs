//! The local session between Orion and the operator helper (protocol 2).
//!
//! # Why there is a session at all
//!
//! Orion runs elevated so WireGuard-NT will load; the platform WebAuthn API
//! answers only inside the interactive user's session, at medium integrity.
//! The two therefore cannot share a process, and the ceremony runs in a child
//! launched **below** Orion's token. This module is everything the two are
//! allowed to say to each other, and nothing else crosses.
//!
//! # What changed from protocol 1, and why
//!
//! Protocol 1 described exactly one ceremony (`CA-TLS`) with one flat phase
//! enum and a pair of `can_*` booleans. Generalising it to every operator
//! ceremony broke each of those choices in turn:
//!
//! * **One phase could not describe two machines.** A recovery is held by two
//!   parties at once — Orion owns the client's private keys and signs the
//!   commit, the helper owns the vault and signs the grant (§11.3). «Awaiting
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
//!   variant — never carried as text by the helper or the network.
//! * **One frame ceiling fitted nothing.** 16 KiB was below what a campaign
//!   manifest or a recovery needs. Ceilings are per message type now.
//! * **A stale command could land.** Statuses carry a strictly increasing
//!   [`OperatorStatus::revision`], and `Continue`/`Cancel` name the revision
//!   they answer, so a click on a screen the helper has already left is
//!   refused instead of applied to whatever came next.
//!
//! # What the WebView may ask for
//!
//! An [`OperationLocator`] — a kind and, when the authority already opened
//! one, an operation id. Not a request, not a path, not a URL. Everything else
//! the helper resolves from the hand-off it pins itself, so a stolen session
//! token buys the ability to *watch* a ceremony the operator started, not to
//! choose one.

use serde::{Deserialize, Serialize};

use super::encoding::{Fingerprint, Id16, TrustDomainId};
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

/// First frame sent by the helper.
///
/// The session id is checked as well as the token: a token alone authenticates
/// *something* to this listener, while the pair says it is the child of the
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
/// §8.1.2 an ordinary renewal employs neither this helper, nor a FIDO
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
}

/// What the WebView is allowed to name.
///
/// Minimal on purpose. The helper resolves the authority origin, the RP ID,
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

/// The only things Orion may ask of the helper.
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
/// The half Orion cannot observe on its own: it is what the helper learned
/// from Astra and the gateway. Ordered as the exchange runs, and the order is
/// what [`RemoteState::is_past_no_return`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteState {
    /// Nothing has been asked of the authority yet.
    Local,
    /// The authority holds the request and is waiting for an operator.
    AwaitingOperator,
    /// The helper signed the objects; nothing has left this machine.
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
/// Orion's, in Orion's language, and a helper that could write them could also
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
    /// What the authority offered does not match what this helper pins.
    HandoffMismatch,
    /// The answer did not describe the request that was sent.
    ManifestMismatch,
    /// The peer on the socket broke the protocol.
    ProtocolViolation,
    /// The operator abandoned before the point of no return.
    Cancelled,
    /// Anything the helper could not classify. Deliberately last and
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
}

impl AstraManifest {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Recovery(_) => OperationKind::RecoverIdentity,
            Self::Campaign(_) => OperationKind::ApproveCampaign,
            Self::IssuerAuthorization(_) => OperationKind::AuthorizeIssuer,
            Self::CaRotation(manifest) => manifest.kind(),
            Self::Revocation(_) => OperationKind::RevokeCertificate,
        }
    }

    /// The domain every manifest names, so Orion can refuse one that belongs
    /// to another domain before showing a single field of it.
    pub fn trust_domain_id(&self) -> TrustDomainId {
        match self {
            Self::Recovery(manifest) => manifest.trust_domain_id,
            Self::Campaign(manifest) => manifest.campaign.trust_domain_id,
            Self::IssuerAuthorization(manifest) => manifest.trust_domain_id,
            Self::CaRotation(manifest) => manifest.trust_domain_id,
            Self::Revocation(manifest) => manifest.trust_domain_id,
        }
    }
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
    pub request_fingerprint: Fingerprint,
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
    pub next_anchor_fingerprint: Fingerprint,
    pub target_count: usize,
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
    use crate::certificates::encoding::WireGuardKey;
    use crate::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

    fn session() -> Id16 {
        Id16::new([3; 16]).expect("id")
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
            next_anchor_fingerprint: Fingerprint::of(b"next"),
            target_count: 3,
        });
        assert_eq!(manifest.kind(), OperationKind::RotateClientTlsCa);
        assert_eq!(
            manifest.trust_domain_id(),
            Id16::new([1; 16]).expect("domain")
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

        assert_eq!(manifest.trust_domain_id(), domain);
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
}
