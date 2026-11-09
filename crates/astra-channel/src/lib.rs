//! The private Astra ↔ Helios lifecycle channel — spec §8.3, ADR-008 §2.
//!
//! Astra runs in its own container on the gateway. The two processes meet on a
//! veth pair with no default route and no forwarding, and the only thing that
//! crosses it is this API, on a listener of its own:
//!
//! ```text
//! POST /internal/v1/certificates/stage
//! POST /internal/v1/certificates/stage-commit
//! POST /internal/v1/certificates/revoke
//! GET  /internal/v1/certificates/state/<identity>
//! GET  /internal/v1/certificates/peers
//! ```
//!
//! # Why a second listener rather than a path on the administration API
//!
//! The administration API of `helios-api` admits peers, rewrites the
//! network configuration, drives the firewall and serves the console. None of
//! that is Astra's business, and a shared listener would make "Astra may not
//! call it" a matter of middleware ordering. Two listeners make it a matter of
//! which socket the packet arrived on — and the fallback below refuses every
//! path this one does not serve, so `/api/peers` on the veth is a `404` decided
//! by the router, not by convention.
//!
//! # Why both ends are configured here
//!
//! The server is Helios and the client is Astra, and they live in different
//! crates — but every bound this channel claims has to be declared **on both
//! sides**, exactly as the negotiation port's flow limits are. A refusal of
//! resumption only the server states leaves the client offering tickets to a
//! peer that will never grant one; a TLS-1.3 floor only the client states
//! leaves the server willing to negotiate 1.2 with anything else that dials
//! it. So the two configurations are built by two functions in one file,
//! against one set of constants, and the tests check the pair.
//!
//! # Why the transport is not the authorization
//!
//! mTLS here proves *which process* is talking, and the ephemeral `(EC)DHE`
//! exchange keeps a later theft of either service key from decrypting an old
//! capture. It authorizes nothing: every mutation carries its own ML-DSA-87
//! signature under `CA-PQ` or the delegated issuer, and the registry verifies
//! that signature after the transport has already been passed. Two independent
//! reasons, and this channel is deliberately the weaker of the two — it
//! protects a process boundary on a machine whose kernel both ends already
//! trust, and it is never presented as a defence against `root`.
//!
//! # Why identities are pinned rather than issued by a CA
//!
//! Each end pins the other's certificate **by its exact DER**, configured out
//! of band. Nothing about the peer is learned from the object it authenticates:
//! a certificate arriving on the wire is compared against the pinned bytes and
//! is never a source of trust for itself. No CA on this link also means no
//! second certificate a CA compromise could mint. The transport keys are
//! service identities (spec §8.3): rotating one changes two files and touches
//! neither `CA-PQ` nor any client.
//!
//! # Limites connues
//!
//! - `POST /internal/v1/campaigns/apply` of §8.3 is deliberately **not**
//!   routed: a campaign is applied under an operator approval that does not
//!   exist, and Astra's public `/v1/campaigns` already answers `501` for the
//!   same reason. It is refused by the fallback like any other unknown path
//!   rather than reserved by an empty handler.
//! - The gateway opens no client towards Astra. Spec §7.3 asks it to notify
//!   the authority after purging an uncommitted `pending_grant`; §8.3 defines
//!   no Astra-side route to notify, so the purge is logged and Astra observes
//!   it at its next `GET .../state/<identity>`. Naming that route is a
//!   specification change, not an implementation gap.
//! - HTTP/1.1 only. The channel carries a handful of objects per rotation, so
//!   multiplexing buys nothing, and one advertised ALPN is also what makes an
//!   accidental h2 client fail loudly instead of half-working.
//!
//! What none of this proves is that the veth exists, has no route and forwards
//! nothing: that is a kernel and container fact, and a WSL2 build shows none of
//! it. See [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md).

use std::net::SocketAddr;
use std::sync::Arc;

use aether::certificates::{
    client::ClientCertificateStageAuthorization,
    encoding::{DerCertificate, Fingerprint, Id16, WireGuardKey},
    revocation::EmergencyCertificateRevocation,
    state::ClientCertificateState,
    x509,
};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};

use aether::certificates::transport::TrustUpdateRefusal;

/// ALPN of the private channel.
///
/// One protocol, advertised by both ends. Not decoration: this host also runs
/// the administration API and whatever else the operator installed, and a
/// mismatched ALPN fails the handshake instead of delivering a lifecycle body
/// to a server that was never meant to read one.
pub const INTERNAL_ALPN: &[u8] = b"helios-astra-lifecycle/1";

/// Largest body read before deserialization, in both directions.
///
/// The same 64 KiB the public Astra endpoint uses (spec §8.2): a staging
/// authorization carries two certificates, and nothing on this link is larger.
pub const MAX_INTERNAL_BODY_BYTES: usize = 64 * 1024;

/// Path prefix this listener serves. Everything outside it is refused.
pub const INTERNAL_PREFIX: &str = "/internal/v1/certificates/";

pub const STAGE_PATH: &str = "/internal/v1/certificates/stage";
pub const STAGE_COMMIT_PATH: &str = "/internal/v1/certificates/stage-commit";
pub const REVOKE_PATH: &str = "/internal/v1/certificates/revoke";
const STATE_ROUTE: &str = "/internal/v1/certificates/state/{identity}";

/// Where the authority leaves a pre-signed transaction for one peer (§8.1.1).
///
/// The gateway signs nothing here and verifies no signature: it holds neither
/// `CA-PQ` nor the service key, and «la gateway n'appelle jamais une clé CA et
/// ne réalise aucune signature de CA à la demande». It queues what arrives and
/// hands it to the peer the manifest names; the peer verifies it under anchors
/// it already trusts. Without this route the in-tunnel `trust-update` has
/// nothing to distribute and answers `503` to a client it knows is behind —
/// the one refusal a client does not recover from.
pub const DISTRIBUTION_PATH: &str = "/internal/v1/certificates/distribution";

/// The served gateway leaf, read back by the authority.
///
/// **A route §8.3 does not list**, and added deliberately. Astra has to verify
/// a receipt under the leaf the gateway actually serves, and it does not issue
/// that leaf: without this it would need the certificate copied into its state
/// out of band — one more value to paste between two shells, which is exactly
/// the class of deployment error `deploy.sh` exists to remove. Nothing secret
/// crosses: the leaf is the public object every client already pins.
pub const GATEWAY_IDENTITY_PATH: &str = "/internal/v1/certificates/gateway-identity";
/// Every peer the gateway holds a certificate record for, admitted or cut.
///
/// Astra needs the whole set to know every admitted workstation, and a peer
/// whose admission was removed keeps its record: it must stay listed, or the
/// authority would lose track of a certificate that is still valid.
pub const PEERS_PATH: &str = "/internal/v1/certificates/peers";
/// Where the authority reports that a staged transition may no longer be
/// aborted (spec §6.3, §11.1 step 6).
pub const GATEWAY_PUBLISHED_PATH: &str = "/internal/v1/certificates/gateway-transition/published";

/// The name the client puts in SNI.
///
/// A constant, in a reserved TLD, because it is **not** how the server is
/// authenticated — the pinned DER is. Deriving it from the veth address would
/// tie the certificate to an address the deployment is free to change, for no
/// security gain.
pub const INTERNAL_SERVER_NAME: &str = "helios-lifecycle.internal";

mod authority_client;
mod authority_routes;
mod gateway_client;
mod gateway_routes;
mod transport;

// The whole surface, one glob per part: 54 items and eight re-exports from
// `aether` every consumer names at the crate root, and a list this long is
// where one would go missing.
pub use self::{
    authority_client::*, authority_routes::*, gateway_client::*, gateway_routes::*, transport::*,
};

#[cfg(test)]
mod tests;
