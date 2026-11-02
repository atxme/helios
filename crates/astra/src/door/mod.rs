//! Astra's single door: every operator opening goes through one function.
//!
//! # Astra holds the door, the rest are connectors
//!
//! Opening a campaign needs two powers only the service should hold: the
//! registry it owns in memory, from which the targets are resolved, and the
//! service key that signs the companion request. [`AstraService::door`] is the
//! one place both are used for an opening. The local console and the
//! administrator tunnel are connectors: they carry a typed request to it and
//! carry its answer back, and neither resolves, signs or deposits anything.
//!
//! # The connector is the transport's word, never the body's
//!
//! [`DoorConnector`] is not deserializable, on purpose: the console socket
//! reads the local user from the kernel, the tunnel route takes the identity
//! the gateway resolved, and a connector a request could name for itself would
//! be a policy the caller chooses. [`allowed`] decides what each connector may
//! reach, before anything else runs.
//!
//! # What the door bounds
//!
//! A motive and a requester the operator reads before the touch, a window of
//! one to five minutes, at least one target and at most 256, a vault for any
//! scope that makes a master key sign, and **one live operation per family**
//! ([`crate::signing::SigningOperationStore::live_conflict`]). The last keeps
//! a compromised administrator peer to one campaign per family, which expires
//! on its own and does nothing without a key.
//!
//! Every opening and every refusal is logged with the connector, the action
//! and the operation, when there is one. An opening is not a durable mutation
//! of the registry, so it does not advance the hash-chained audit.

mod open;
mod resolve;

#[cfg(test)]
mod tests;

use aether::certificates::encoding::Id16;
use aether::certificates::status::CampaignScope;
use aether::certificates::transport::{OperatorOpenAction, OperatorOpenRequest, OperatorOpened};
use astra_channel::OperatorIdentity;
use serde::{Deserialize, Serialize};

use crate::service::{AstraService, ServiceError};
use crate::signing::SigningError;

pub use open::MAX_OPENING_WINDOW_SECS;

/// Who carried a request to the door, as the transport established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorConnector {
    /// The local console, over the service's Unix socket; the user is the
    /// peer credential the kernel reports.
    Console { uid: u32 },
    /// An administrator peer, relayed by the gateway over the private
    /// channel; the identity is the one the gateway resolved from its source.
    Tunnel { operator: OperatorIdentity },
}

impl std::fmt::Display for DoorConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Console { uid } => write!(formatter, "console uid={uid}"),
            Self::Tunnel { operator } => write!(formatter, "tunnel {operator}"),
        }
    }
}

const DEFAULT_OPENING_WINDOW_SECS: u64 = MAX_OPENING_WINDOW_SECS;

fn default_opening_window_secs() -> u64 {
    DEFAULT_OPENING_WINDOW_SECS
}

/// What the operator reads before the touch, and how long they have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningText {
    pub reason: String,
    pub requested_by: String,
    /// Defaults to five minutes; the door refuses anything outside 1..=300.
    #[serde(default = "default_opening_window_secs")]
    pub window_secs: u64,
}

/// One action the door performs, closed and typed.
///
/// No variant carries a target: the door resolves every target itself, so a
/// caller can ask for an action and never for the set it applies to.
///
/// Serializable because it is the body of the local socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum DoorRequest {
    /// Every admitted, unrevoked peer's leaves (`fleet_leafs`).
    FleetLeafs { text: OpeningText },
    /// `CA-PQ`, and the client `CA-TLS` when the domain pins one.
    TrustAuthorities { text: OpeningText },
}

impl DoorRequest {
    /// The name the log records the action under.
    pub fn action(&self) -> &'static str {
        match self {
            Self::FleetLeafs { .. } => "fleet_leafs",
            Self::TrustAuthorities { .. } => "trust_authorities",
        }
    }
}

impl TryFrom<OperatorOpenRequest> for DoorRequest {
    type Error = DoorRefusal;

    /// The tunnel's wire request, as the door's own.
    ///
    /// A client revocation is refused by name until the door implements it:
    /// translating it to anything else would open a campaign the
    /// administrator did not ask for.
    fn try_from(request: OperatorOpenRequest) -> Result<Self, Self::Error> {
        let text = OpeningText {
            reason: request.reason,
            requested_by: request.requested_by,
            window_secs: request.window_secs,
        };
        match request.action {
            OperatorOpenAction::FleetLeafs => Ok(Self::FleetLeafs { text }),
            OperatorOpenAction::TrustAuthorities => Ok(Self::TrustAuthorities { text }),
            OperatorOpenAction::ClientRevocation { .. } => Err(DoorRefusal::NotAllowedHere),
        }
    }
}

/// What the door produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorOutcome {
    /// A campaign waiting for its operator.
    Opened(OperatorOpened),
}

/// Why the door refused, as a complete sentence for the local console.
///
/// The tunnel never sees these words: [`DoorRefusal::class`] folds them into
/// the coarse refusals of §8.5.4, and the detail goes to the log.
#[derive(Debug, thiserror::Error)]
pub enum DoorRefusal {
    #[error("cette action ne peut pas être demandée par ce connecteur : rien n'a été ouvert")]
    NotAllowedHere,
    #[error(
        "le motif et le demandeur sont ce que l'opérateur lit avant le toucher : ni l'un ni \
         l'autre ne peut être vide"
    )]
    TextMissing,
    #[error("la fenêtre d'une campagne doit être comprise entre 1 et {MAX_OPENING_WINDOW_SECS} s")]
    WindowOutOfRange,
    #[error(
        "une opération de la même famille attend déjà l'opérateur ({operation_id}) : elle figure \
         parmi les opérations en attente, et rien n'a été ouvert"
    )]
    AlreadyOpen { operation_id: Id16 },
    #[error(
        "cette campagne ne vise aucune cible : il n'y a rien à faire approuver par l'opérateur"
    )]
    NoTarget,
    #[error(
        "cette campagne vise plus de {} cibles, le plafond du §8.2",
        aether::certificates::status::MAX_CAMPAIGN_TARGETS
    )]
    TooManyTargets,
    #[error(
        "ce volume d'état ne contient aucun coffre chiffré : le compagnon n'aurait rien à ouvrir, \
         et CA-PQ ne signerait jamais"
    )]
    NoVault,
    #[error("le magasin des opérations refuse cette ouverture : {0}")]
    Store(SigningError),
    #[error(
        "erreur interne d'Astra : rien n'a été ouvert, le détail est dans le journal du service"
    )]
    Internal,
}

impl DoorRefusal {
    /// The coarse refusal the tunnel answers with (§8.5.4).
    ///
    /// A malformed text is the caller's own input and says nothing about the
    /// domain; a full store is a budget. Every decision about the domain —
    /// policy, uniqueness, targets, vault — is the same indistinct refusal.
    pub fn class(&self) -> ServiceError {
        match self {
            Self::TextMissing | Self::WindowOutOfRange => ServiceError::Protocol,
            Self::NotAllowedHere
            | Self::AlreadyOpen { .. }
            | Self::NoTarget
            | Self::TooManyTargets
            | Self::NoVault => ServiceError::Refused,
            Self::Store(SigningError::Full) => ServiceError::Throttled,
            Self::Store(_) | Self::Internal => ServiceError::Internal,
        }
    }

    /// The operation this refusal names, for the log.
    fn operation_id(&self) -> Option<Id16> {
        match self {
            Self::AlreadyOpen { operation_id } => Some(*operation_id),
            _ => None,
        }
    }
}

/// What each connector may reach: exactly the table of §5.2.
///
/// A datum, not a consequence: widening the tunnel to one more action is a
/// change of this match, and the match has no wildcard, so a new action
/// cannot be added without a decision for each connector.
pub fn allowed(connector: &DoorConnector, request: &DoorRequest) -> bool {
    let (console, tunnel) = match request {
        DoorRequest::FleetLeafs { .. } => (true, true),
        DoorRequest::TrustAuthorities { .. } => (true, true),
    };
    match connector {
        DoorConnector::Console { .. } => console,
        DoorConnector::Tunnel { .. } => tunnel,
    }
}

impl AstraService {
    /// Performs one operator action, if this connector may ask for it.
    ///
    /// The policy first, then the action. Nothing the caller sent decides a
    /// target, a key or a policy: those come from the state this service
    /// holds.
    pub async fn door(
        &self,
        connector: DoorConnector,
        request: DoorRequest,
        now_unix: u64,
    ) -> Result<DoorOutcome, DoorRefusal> {
        let action = request.action();
        let outcome = if allowed(&connector, &request) {
            self.perform(&connector, request, now_unix).await
        } else {
            Err(DoorRefusal::NotAllowedHere)
        };
        match &outcome {
            Ok(DoorOutcome::Opened(opened)) => tracing::info!(
                connector = %connector,
                action,
                operation = %opened.operation_id,
                campaign = %opened.campaign_id,
                targets = opened.target_count,
                "operator campaign opened through the door"
            ),
            Err(refusal) => tracing::warn!(
                connector = %connector,
                action,
                operation = refusal.operation_id().map(|id| id.to_string()),
                %refusal,
                "operator request refused at the door"
            ),
        }
        outcome
    }

    async fn perform(
        &self,
        connector: &DoorConnector,
        request: DoorRequest,
        now_unix: u64,
    ) -> Result<DoorOutcome, DoorRefusal> {
        match request {
            DoorRequest::FleetLeafs { text } => open::open_campaign(
                self,
                connector,
                CampaignScope::FleetLeafs,
                text,
                |state| Ok(resolve::fleet_leaf_rows(state)),
                now_unix,
            )
            .await
            .map(DoorOutcome::Opened),
            DoorRequest::TrustAuthorities { text } => open::open_campaign(
                self,
                connector,
                CampaignScope::TrustAuthorities,
                text,
                |state| Ok(resolve::trust_authority_rows(state)),
                now_unix,
            )
            .await
            .map(DoorOutcome::Opened),
        }
    }
}
