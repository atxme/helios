//! In-tunnel certificate lifecycle API.
//!
//! - `POST /api/key-negotiation/trust-update` lives **inside the WireGuard
//!   tunnel**, behind [`crate::auth::require_peer`]. It is how an Orion that
//!   still has a working tunnel learns about transitions (spec §8.1).
//! - the four `/api/key-negotiation/certificate-renewal/*` routes carry an
//!   ordinary renewal end to end (spec §8.1.2): the request, the polling of
//!   the operation, and the two exchanges the signing companion needs.
//! - `POST /api/key-negotiation/stage-commit` carries an ordinary client commit
//!   through that same tunnel.
//!
//! The `/internal/v1/certificates/*` surface belongs on a separate listener on
//! the private Astra–Helios veth. It is not mounted by this router. In
//! particular there is deliberately no in-tunnel `stage` route: Astra sends a
//! stage authorization directly to Helios over the veth and receives the
//! signed receipt there (spec §§7.2 and 8.1.2).
//!
//! # Why the gateway is not a reverse proxy
//!
//! Every renewal route accepts one type and one size, resolves the caller from
//! its source VIP, compares the body's identity against that resolution and
//! then relays a **canonical object** it built itself. Nothing the client
//! chooses — method, path, header, redirect — is forwarded (spec §8.1.2). A
//! generic proxy would make the peer's own bytes decide what the authority is
//! asked, which is the one thing the source-VIP proof is there to prevent.
//!
//! # Why the public route is not a fallback for the private one
//!
//! An ordinary renewal request and its final commit travel in the tunnel,
//! because that is what proves the peer: the source address resolves to exactly
//! one admitted `/32`, and no proxy header is ever consulted. Helios relays the
//! request to Astra; the stage authorization and receipt never transit through
//! Orion. Recovery without a tunnel reaches Astra publicly, then uses the same
//! private veth surface.
//!
//! # Why the errors are coarse
//!
//! `400`, `401`, `403`, `413`, `415`, `500` — nothing else, and none of them
//! describes the certificate state. The detailed reason goes to the gateway's
//! protected log. This is the same rule the public QUIC port follows with its
//! three codes: an error taxonomy on an authenticated-but-hostile caller is an
//! oracle on other peers' generations.

use aether::certificates::{
    encoding::DerCertificate,
    status::AstraCertificateStatus,
    transport::{
        AuthenticatedTrustUpdateRequest, TrustUpdateChunk, TrustUpdateTransactionManifest,
        MAX_STAGE_COMMIT_REQUEST_BYTES, MAX_TRUST_UPDATE_REQUEST_BYTES,
    },
};
use aether::key_negotiation::PqCertificate;
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

mod gateway_identity;
mod operator_relay;
mod renewal;
mod trust_update;
mod views;

pub use gateway_identity::*;
pub use operator_relay::*;
pub use renewal::*;
pub use trust_update::*;
pub use views::*;

pub use aether::certificates::client::StageCommitRequest;

/// Why a trust update was refused, defined in `aether`.
///
/// It lives there rather than here because Astra names it too — it maps its
/// distribution and renewal errors onto these four shapes — and `astra` must
/// not depend on this crate (`docs/architecture/CRATE-REORGANIZATION.md` §7).
/// Same reason [`aether::certificates::transport::ClientRenewalOperationView`]
/// is there.
pub use aether::certificates::transport::TrustUpdateRefusal;

#[cfg(test)]
mod tests;
