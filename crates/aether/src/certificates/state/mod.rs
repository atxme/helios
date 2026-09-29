//! Bounded states and their transitions — spec §3.2, §3.3, §4.2 and §4.4.
//!
//! Everything here holds **at most two** of anything: two CA anchors, two
//! gateway leaves per family, two client generations, two Astra service keys.
//! That is not an optimisation. An open-ended list of acceptable fingerprints
//! is an open-ended list of things an attacker can try to get added, and a
//! verifier that loops over a list has no natural place to say "this one is
//! current".
//!
//! # Counters decide, clocks only schedule
//!
//! A generation is persisted before an identity is served. Once promoted, the
//! outgoing slot is gone, and a clock moved backwards finds nothing to
//! reactivate — the state has no memory of it. Conversely, no counter ever
//! moves because time passed: promotion happens at `not_after` because the
//! decision that scheduled it was persisted, not because the date arrived.
//!
//! # `revoked` dominates
//!
//! A revoked identity refuses staging, commit, promotion and rollback, and no
//! operator credential lifts it. Only a fresh admission creates a new
//! identity. This is the one state that wins every race in this module.
//!
//! # Two scopes, two counters, two effects
//!
//! A revocation names either the gateway or a client, and the two axes never
//! meet. [`TrustLedger`] holds the gateway counter, [`ClientCertificateState`]
//! its own, and [`TrustLedger::apply_due`] routes each decision to the state it
//! actually removes something from. Sharing one counter would let a gateway
//! revocation consume a client's, and then the client's own revocation would
//! be refused as a rollback — the decision would exist, be signed, be
//! verified, and change nothing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::key_negotiation::PqCertificate;

use super::{
    approval::{AstraCredentialBinding, AstraPolicyPin},
    authority::{
        AstraIssuerAuthorization, AstraServiceKeyTransition, CaTransition, ClientTlsCaTransition,
        EmergencyAstraServiceKeyReplacement, RotationReason,
    },
    client::{
        ClientCertificateGeneration, ClientCertificateRotationGrant,
        ClientCertificateStageAuthorization,
    },
    encoding::{
        CanonicalBytes, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId,
        WireGuardKey,
    },
    gateway::{
        pq_certificate_fingerprint, GatewayIdentityTransition, GatewayTransitionAbort,
        GatewayTransitionAbortTombstone,
    },
    revocation::{EmergencyCertificateRevocation, RevocationScope},
    status::{AstraCertificateStatus, CertificateServiceRollbackAuthorization},
    window::TransitionWindow,
    CertificateError,
};

const BASE_STATE_DOMAIN: &[u8] = b"helios-trust-base-state-v5";

/// What installing an object did, once it verified.
///
/// The distinction is the idempotency rule of spec §4.2: the same bytes at the
/// same generation change nothing and succeed; different bytes at the same
/// generation are a conflict, which the verifiers refuse before reaching here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The state moved.
    Installed,
    /// The state already held exactly this decision.
    AlreadyPresent,
}

mod astra;
mod client_identity;
mod gateway_identity;
mod ledger;
mod revocation_schedule;

pub use astra::{AstraIssuerState, AstraProfile, IssuerLifecycle};
pub use client_identity::{
    ClientCertificatePendingStage, ClientCertificateState, ClientTlsCaState, CommittedStage,
    PendingStageState,
};
pub use gateway_identity::{GatewayCertificateState, GatewayServiceRollback};
pub use ledger::{base_state_fingerprint, TrustLedger, TrustSnapshot};
pub use revocation_schedule::{
    RevocationTombstone, RevokedFamily, ScheduledRevocation, StatusOrdering,
    MAX_REVOCATION_TOMBSTONES, MAX_SCHEDULED_REVOCATIONS, MAX_TRACKED_STATUS_TARGETS,
};

#[cfg(test)]
mod tests;
