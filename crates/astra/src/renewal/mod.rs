//! The relayed ordinary renewal, from Astra's side — spec §7.2, §7.3, §8.1.2.
//!
//! # The order, and why every step of it is load-bearing
//!
//! ```text
//! Orion --WireGuard--> Helios --veth/mTLS--> Astra   open()
//!                                            Astra verifies the 80 % gate
//!                                            Astra issues the two leaves
//!                             <-- stage authorization on the veth --
//!                             -- signed receipt on the same link -->
//!                                            Astra releases the grant
//! Orion <-- grant, through Helios --
//! Orion -- commit --WireGuard--> Helios
//! ```
//!
//! Three properties are decided by that order alone:
//!
//! - **nothing is issued before the renewal window**. [`open`] refuses a
//!   request that is not yet due; after it, the signed request and the pinned
//!   delegated policy authorize only `active + 1`;
//! - **the authorization never touches Orion**. It is handed to the gateway on
//!   the veth and the receipt comes back on that same relationship (§8.3,
//!   amendment of 16 August 2026). The client is a client of the gateway's private API, not
//!   a courier between two authorities;
//! - **no grant before the receipt**. Astra cannot release the leaves it just
//!   signed until the gateway says, under its own served leaf, that the
//!   candidate is on its disk.
//!
//! # What a failure leaves behind
//!
//! Once the request is accepted, its exact fingerprint and the exact random
//! issuance bytes are persisted. A transport failure therefore leaves
//! `pending_grant`, not a second ceremony: polling the same `operation_id`
//! replays the same authorization. The gateway treats that stage idempotently
//! and its signed lease bounds any reservation that cannot be completed.
//!
//! # Scheduled and manual authorization
//!
//! An ordinary renewal is authorized automatically once its active leaf is
//! due. A manual campaign (§7.6) is approved once, for a set of targets,
//! **before** any of their requests exist. [`open`] looks the campaign up in
//! [`crate::signing::SigningOperationStore`], and if one covers this peer at
//! this exact state, the operation is born already approved and goes straight
//! to issuance.
//!
//! A campaign is also the one thing that legitimately overrides the 80 %
//! threshold: renewing ahead of it is what a manual action is *for*. It does
//! not override expiry — an ordinary rotation proves possession with a leaf no
//! validator accepts, and §7.5 is the only way back from there.

use std::sync::Arc;

use aether::certificates::transport::{ClientRenewalOperationView, ClientRenewalSignerRequest};
use aether::certificates::{
    approval::{
        AstraCampaignApprovalEvidence, AstraCredentialApprovalRequest, AstraRenewalApproval,
        AstraRenewalApprovalEvidence, MAX_APPROVAL_LIFETIME_SECS, PER_REQUEST_APPROVAL_CREDENTIALS,
    },
    capability::{CapabilityGrant, CapabilityRequirement, CapabilityScope},
    client::{ClientCertificateRotationRequest, IssuerKind},
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
    window::{TransitionWindow, MAX_OVERLAP_SECS, MAX_STAGE_LEASE_SECS},
    CERTIFICATE_FORMAT_VERSION,
};

use crate::operations::{Operation, OperationError};
use crate::planner::{urgency, RenewalUrgency};
use crate::registry::{PendingRotation, RegistryError};
use crate::service::AstraService;

/// Lease a staging authorization is given, in seconds.
///
/// One hour: comfortably inside the 24-hour ceiling of §7.2, and long enough
/// for a client to fetch its grant and commit even after a reboot. It is also
/// `activation_at`, because §7.2 requires `stage_expires_at <= activation_at`
/// and putting the two apart would only widen the span in which a candidate
/// exists and cannot be used.
pub const STAGE_LEASE_SECS: u64 = 3_600;

/// Life of a client leaf when the delegation allows at least that much.
///
/// Ninety days. The ceiling that actually applies is
/// `AstraIssuerAuthorization::maximum_leaf_lifetime_secs`, and the smaller of
/// the two wins — a delegation is an upper bound, never a target.
pub const DEFAULT_CLIENT_LEAF_LIFETIME_SECS: u64 = 90 * 24 * 3_600;

/// Life of a capability token, bounded by §8.2 and by the operation.
pub const CAPABILITY_TOKEN_LIFETIME_SECS: u64 = MAX_APPROVAL_LIFETIME_SECS;

/// Why a relayed renewal was refused.
///
/// Finer than what a client ever learns: the private link's caller is the
/// gateway, which holds the registry these reasons describe. The coarse class
/// is produced by [`RenewalError::refusal`].
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("the request names a peer other than the one the gateway resolved")]
    CallerMismatch,
    #[error("no admitted peer holds this identity")]
    UnknownPeer,
    #[error("this identity is revoked; no credential lifts that state")]
    Revoked,
    #[error(
        "this identity is not due for renewal: the ordinary window opens at 80 % of the leaf's \
         life (spec §4.3), and issuing before it would let a client renew on demand"
    )]
    NotDue,
    #[error(
        "this identity has expired: an ordinary renewal proves possession with a leaf that no \
         validator accepts, and the recovery path of §7.5 is the only way back"
    )]
    ExpiredIdentity,
    #[error(
        "automatic renewal is disabled until the current credential-free issuance policy has \
         been confirmed and delegated; an older policy pin cannot be broadened by a software \
         upgrade"
    )]
    AutomaticPolicyMigrationRequired,
    #[error("the request is refused: {0}")]
    Request(aether::certificates::CertificateError),
    #[error("the operator approval is refused: {0}")]
    Approval(aether::certificates::CertificateError),
    #[error("the capability token is refused: {0}")]
    Capability(aether::certificates::CertificateError),
    #[error(
        "this authority holds no credential document: no operator credential can approve a \
         renewal, so the ceremony has no allow-list to run against. Copy the one \
         `astra-signer bindings` emits."
    )]
    NoOperatorCredential,
    #[error("operation: {0}")]
    Operation(#[from] OperationError),
    #[error("registry: {0}")]
    Registry(#[from] RegistryError),
    #[error("delegated issuer: {0}")]
    Issuer(#[from] crate::issuer::IssuerError),
    #[error(
        "this authority has no delegated issuer: `AstraIssuerAuthorization` has to be signed by \
         the operator companion before any ordinary renewal can be issued"
    )]
    NoIssuer,
    #[error(
        "this authority has no private channel to its gateway: a staging authorization has \
         nowhere to go, and no receipt could come back"
    )]
    NoGatewayChannel,
    #[error("the gateway refused or could not be reached: {0}")]
    Gateway(String),
    #[error("the authority could not build this object: {0}")]
    Internal(aether::certificates::CertificateError),
}

impl RenewalError {
    /// The bounded class the gateway — and through it the client — learns.
    ///
    /// Everything that is not an authority-side failure collapses to
    /// `Rejected`: on this link the reason travels in the protected log, and a
    /// finer taxonomy relayed to a peer is an oracle on other peers' state.
    pub fn refusal(&self) -> aether::certificates::transport::TrustUpdateRefusal {
        use aether::certificates::transport::TrustUpdateRefusal as Refusal;
        match self {
            Self::Registry(RegistryError::Io(_) | RegistryError::Corrupt(_))
            | Self::Operation(OperationError::Persistence(_) | OperationError::Corrupt(_))
            | Self::Internal(_) => Refusal::Internal,
            Self::NoIssuer
            | Self::NoGatewayChannel
            | Self::Gateway(_)
            | Self::AutomaticPolicyMigrationRequired => Refusal::Unavailable,
            _ => Refusal::Rejected,
        }
    }
}

mod approval;
mod companion;
mod request;
mod stage;

pub use companion::{read, signer_request, signer_result};
pub use request::open;
pub(crate) use request::transcribe_peer;

// What the steps name of each other, through `use super::*`.
use self::{approval::*, stage::*};

/// This process's clock, read the same way everywhere else in the crate.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// A non-zero 16-byte identifier from the approved DRBG (spec §2.3.2).
pub(crate) fn fresh_id() -> Result<Id16, aether::certificates::CertificateError> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|_| aether::certificates::CertificateError::RandomnessUnavailable)?;
    Id16::new(bytes)
}

/// A certificate serial from the same door.
fn fresh_serial() -> Result<[u8; 16], aether::certificates::CertificateError> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|_| aether::certificates::CertificateError::RandomnessUnavailable)?;
    Ok(bytes)
}

/// The `issuer_kind` this module produces, restated so a change is visible.
///
/// Always [`IssuerKind::Astra`]: a `master` staging is signed by `CA-PQ`, which
/// this process does not hold.
pub const RELAYED_ISSUER_KIND: IssuerKind = IssuerKind::Astra;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod workflow_tests;

/// Astra's private listener: the four routes the gateway relays into.
///
/// It is the mirror of [`astra_channel::router`], and it carries the
/// same three properties. Everything outside
/// [`astra_channel::ASTRA_INTERNAL_PREFIX`] is refused by the router
/// rather than by convention; every body is bounded before it is
/// deserialized; and every refusal collapses to the coarse class of
/// [`RenewalError::refusal`], because the finer reason is an oracle on other
/// peers' state and belongs in the protected log.
///
/// The caller travels **in the body**, not in the TLS identity: on this link
/// the authenticated party is the gateway, and the peer it resolved from a
/// source VIP is what the authority has to be told. Astra compares that
/// resolution against the object's own copy and refuses a mismatch — so a
/// gateway relaying somebody else's request is refused, not believed.
pub mod router;
