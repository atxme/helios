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
//! ```
//!
//! # Why a second listener rather than a path on the administration API
//!
//! The administration API of [`crate::router`] admits peers, rewrites the
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

use crate::certificates::{AstraStageHandler, TrustUpdateRefusal};

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
const STATE_ROUTE: &str = "/internal/v1/certificates/state/:identity";

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

/// What the private listener answers, and the only statuses it may produce.
///
/// Deliberately finer than the in-tunnel taxonomy, for a reason that does not
/// generalise: the caller here **is** the authority. It already holds the
/// registry these codes describe, so a precise refusal is an operational
/// message to a peer that knows more than the answer could tell it, not an
/// oracle on another peer's generations. Nothing on this enum reaches a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalRefusal {
    /// Unreadable body, wrong version, unparsable identity.
    Protocol,
    /// Well formed and refused: signature, generation, ownership, revocation.
    Rejected,
    /// Known identity, nothing to answer with.
    Unavailable,
    /// The gateway failed on its own side.
    Internal,
}

impl InternalRefusal {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Rejected => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<TrustUpdateRefusal> for InternalRefusal {
    fn from(refusal: TrustUpdateRefusal) -> Self {
        match refusal {
            TrustUpdateRefusal::Protocol => Self::Protocol,
            TrustUpdateRefusal::Rejected => Self::Rejected,
            TrustUpdateRefusal::Unavailable => Self::Unavailable,
            TrustUpdateRefusal::Internal => Self::Internal,
        }
    }
}

impl IntoResponse for InternalRefusal {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

/// What the gateway tells the authority about one peer's certificate state.
///
/// The whole answer, and nothing else: no WireGuard private key, no PSK, no
/// TPM secret, no unredacted view of `network.toml` (spec §8.3).
///
/// The **active PQ leaf** is here, and it is not a leak: it is a certificate,
/// public by construction, which this peer presents on every negotiation. It
/// is here because Astra did not issue the first one — an operator did, at
/// enrolment — and a renewal is checked against the public key of the
/// generation the domain holds, never against one the request supplied. Astra
/// therefore has to be able to learn it from the gateway rather than from the
/// client asking to be renewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificateStateView {
    /// Friendly name, as admission recorded it.
    pub name: String,
    /// Bounded active/next/pending state, exactly as persisted.
    pub state: ClientCertificateState,
    /// The leaf of the active generation, as the registry holds it.
    pub active_pq_certificate: aether::key_negotiation::PqCertificate,
}

/// The gateway side of the private channel, implemented by the daemon.
///
/// Staging comes from [`AstraStageHandler`], which already exists as the
/// reserved Astra-to-Helios contract; this trait adds the two other routes
/// rather than declaring a second staging entry point. A trait for the same
/// reason [`crate::certificates::TrustUpdateHandler`] is one: the API process
/// holds no registry lock and no WireGuard backend, so it hands an object to
/// whatever owns the serializer and learns back only a refusal class.
///
/// Note what is **not** a parameter: a caller identity. On this link the
/// authenticated party is Astra, not a peer, so the object's own
/// `client_wg_public_key` names the target — and the registry verifies the
/// ML-DSA-87 signature binding it before writing anything. That is the opposite
/// of the in-tunnel routes, where the source VIP is the proof and the body is
/// only ever compared against it.
#[async_trait]
pub trait AstraChannelHandler: AstraStageHandler {
    /// Applies a signed emergency revocation (spec §10).
    async fn revoke(
        &self,
        revocation: Box<EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal>;

    /// Reads back one peer's bounded state.
    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, TrustUpdateRefusal>;

    /// The gateway's own served leaf, so the authority can verify a receipt
    /// under the key that signed it rather than under a copy it was handed.
    async fn gateway_identity(&self) -> Result<GatewayIdentityView, TrustUpdateRefusal>;

    /// Records that a staged gateway transition has left the authority.
    ///
    /// Irreversible on purpose (spec §6.3): a client may already hold the
    /// decision, go offline and promote on its own at `not_after`. Cancelling
    /// on the gateway alone would then create two truths.
    async fn gateway_transition_published(
        &self,
        published: GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal>;

    /// Queues a pre-signed transaction for the peer its manifest names.
    async fn distribute(
        &self,
        distribution: Box<TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal>;

    /// Commits a recovery staging on behalf of a client that has no tunnel.
    ///
    /// The only commit this link accepts, and the implementation is what
    /// enforces that: the peer comes from the **signed** commit, never from
    /// the caller, and the stage must be one a `CA-PQ` recovery authorization
    /// created.
    async fn commit_recovery(
        &self,
        relayed: Box<RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal>;
}

/// A commit relayed on the private link, for a recovery only (spec §7.3).
///
/// # Why the authorization travels with the commit
///
/// This link is the one place a commit does **not** arrive from the client's
/// own tunnel, and it is legitimate for exactly one operation: the recovery of
/// an identity whose leaf has expired, where by definition no tunnel exists.
/// The gateway must therefore be able to tell a recovery from an ordinary
/// renewal, and «which kind of stage is this» is a fact about the *signed
/// authorization* — not about the caller, and not about anything the registry
/// keeps.
///
/// So the authorization comes along. The gateway compares its fingerprint to
/// the one the pending stage already recorded, which makes the copy provably
/// the exact document it verified at staging time, and then reads the reason
/// off it. Carrying a flag instead would be asking the relay what kind of
/// operation it is relaying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedStageCommit {
    pub authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    pub commit: Box<aether::certificates::client::ClientCertificateStageCommit>,
    pub grant: Box<aether::certificates::client::ClientCertificateRotationGrant>,
}

/// One signed transaction, addressed to one peer.
///
/// The peer is read off the manifest and never carried beside it: a second
/// copy of the address would be a second thing to compare, and the manifest's
/// own `client_wg_public_key` is the one the signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDistribution {
    pub manifest: aether::certificates::transport::TrustUpdateTransactionManifest,
    /// Every fragment, in index order. All of them at once, because a
    /// transaction is atomic for the receiver: a queue able to hold half of one
    /// would leave a client polling for a fragment that never arrives.
    pub chunks: Vec<aether::certificates::transport::TrustUpdateChunk>,
}

/// What the gateway publishes about the identity it currently serves.
///
/// Public by construction: this is the leaf every admitted client already pins.
/// No private key, no PSK, no TPM secret — the same rule the peer state follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayIdentityView {
    /// The active gateway PQ leaf, exactly as it is served.
    pub pq_certificate: aether::key_negotiation::PqCertificate,
    /// Its fingerprint, recomputed by the reader anyway — carried so a
    /// mismatch is caught as a disagreement rather than as a bad signature.
    pub pq_certificate_fingerprint: Fingerprint,
    /// The active gateway TLS leaf, by fingerprint.
    ///
    /// The certificate itself stays here: the authority needs to *name* the
    /// leaf in service — a campaign freezes the identity by its two
    /// fingerprints (spec §11.1 step 3) — never to re-serve it.
    pub tls_certificate_fingerprint: Fingerprint,
    /// Its signed expiry, read from the DER this gateway actually serves.
    ///
    /// §10.1 makes a revocation carry the exact `not_after` of each leaf it
    /// withdraws, and the authority holds neither leaf. Reading it here is the
    /// difference between a revocation that applies and one every recipient
    /// refuses — during the incident that motivated it. The PQ half needs no
    /// field of its own: its certificate travels whole.
    pub tls_certificate_not_after: u64,
    pub active_gateway_identity_epoch: u64,
    pub gateway_decision_epoch: u64,
}

/// One staged transition, named exactly (spec §6.3).
///
/// The document is named rather than «whatever is staged»: an operator may
/// have installed one transition by hand while the authority published
/// another, and publishing the wrong decision would make the gateway refuse
/// an abort it is entitled to — or accept one it is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTransitionPublished {
    pub gateway_identity_epoch: u64,
    pub transition_fingerprint: Fingerprint,
}

/// Builds the private router — the seven routes, and a refusal for the rest.
pub fn router(handler: Arc<dyn AstraChannelHandler>) -> Router {
    Router::new()
        .route(STAGE_PATH, post(stage))
        .route(STAGE_COMMIT_PATH, post(stage_commit))
        .route(REVOKE_PATH, post(revoke))
        .route(STATE_ROUTE, get(peer_state))
        .route(GATEWAY_IDENTITY_PATH, get(gateway_identity))
        .route(GATEWAY_PUBLISHED_PATH, post(gateway_transition_published))
        .route(DISTRIBUTION_PATH, post(distribute))
        .fallback(refuse_unknown_route)
        .layer(DefaultBodyLimit::max(MAX_INTERNAL_BODY_BYTES))
        .with_state(handler)
}

/// `POST /internal/v1/certificates/stage` (spec §7.2).
async fn stage(State(handler): State<Arc<dyn AstraChannelHandler>>, body: Bytes) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let authorization: ClientCertificateStageAuthorization = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable staging authorization");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.stage_from_astra(Box::new(authorization)).await {
        Ok(receipt) => (StatusCode::OK, Json(*receipt)).into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `POST /internal/v1/certificates/distribution` (spec §8.1.1).
async fn distribute(State(handler): State<Arc<dyn AstraChannelHandler>>, body: Bytes) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let distribution: TrustDistribution = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable trust distribution");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.distribute(Box::new(distribution)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `POST /internal/v1/certificates/stage-commit` (spec §7.3, §7.5).
///
/// The recovery commit, and nothing else. A client whose leaf has expired has
/// no tunnel to commit through, so the authority relays the commit it received
/// on its public origin. Every proof still belongs to the client: the commit
/// carries both its signatures, and the peer is read off the signed document
/// rather than off the caller.
async fn stage_commit(
    State(handler): State<Arc<dyn AstraChannelHandler>>,
    body: Bytes,
) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let relayed: RelayedStageCommit = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable relayed commit");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.commit_recovery(Box::new(relayed)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `POST /internal/v1/certificates/revoke` (spec §10).
async fn revoke(State(handler): State<Arc<dyn AstraChannelHandler>>, body: Bytes) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let revocation: EmergencyCertificateRevocation = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable revocation");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.revoke(Box::new(revocation)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `POST /internal/v1/certificates/gateway-transition/published` (spec §6.3).
async fn gateway_transition_published(
    State(handler): State<Arc<dyn AstraChannelHandler>>,
    body: Bytes,
) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let published: GatewayTransitionPublished = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable publication marker");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.gateway_transition_published(published).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `GET /internal/v1/certificates/state/<identity>`.
async fn peer_state(
    State(handler): State<Arc<dyn AstraChannelHandler>>,
    Path(identity): Path<String>,
) -> Response {
    let Ok(identity) = WireGuardKey::parse(&identity) else {
        return InternalRefusal::Protocol.into_response();
    };
    match handler.peer_state(&identity).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `GET /internal/v1/certificates/gateway-identity`.
async fn gateway_identity(State(handler): State<Arc<dyn AstraChannelHandler>>) -> Response {
    match handler.gateway_identity().await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// Everything the private listener does not serve.
///
/// The refusal is the point: the administration API, the WebSocket, the
/// embedded console and `/internal/v1/campaigns/apply` all land here. Naming
/// the path in the log turns "Astra probed something it should not" into a
/// readable line rather than a silent `404`.
async fn refuse_unknown_route(uri: Uri) -> StatusCode {
    tracing::warn!(
        path = %uri.path(),
        "private channel: route refused; this listener serves only {}*",
        INTERNAL_PREFIX
    );
    StatusCode::NOT_FOUND
}

/// A transport identity of the private channel: one certificate, one key.
///
/// Not sealed to the TPM, and deliberately so. It authenticates a process on a
/// link whose two ends the host kernel already owns, so sealing would buy
/// nothing against the attacker who matters — while making the lifecycle
/// listener refuse to start on a gateway whose TPM is unavailable, which is
/// exactly the state `heliosd init-trust-domain` was built to survive. The file
/// is `0600`; the authorization is the ML-DSA-87 signature on every object,
/// never this key.
pub struct ChannelIdentity {
    /// The end-entity certificate, DER. The peer pins these exact bytes.
    pub certificate_der: Vec<u8>,
    /// PKCS#8 private key, DER.
    pub private_key_der: Vec<u8>,
}

impl ChannelIdentity {
    fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate_der.clone())
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>, ChannelError> {
        PrivateKeyDer::try_from(self.private_key_der.clone())
            .map_err(|reason| ChannelError::Tls(reason.to_string()))
    }
}

/// What can go wrong on the private channel, on either side.
#[derive(Debug)]
pub enum ChannelError {
    /// The TLS layer refused to build, to connect or to handshake.
    Tls(String),
    /// The pinned peer certificate is not usable as one.
    Pin(String),
    Io(std::io::Error),
    /// The peer answered with a status this client does not accept.
    Status(StatusCode),
    /// The answer was not the object this route returns.
    Body(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(reason) => write!(formatter, "private channel TLS: {reason}"),
            Self::Pin(reason) => write!(formatter, "pinned peer certificate: {reason}"),
            Self::Io(error) => write!(formatter, "private channel input/output: {error}"),
            Self::Status(status) => write!(formatter, "private channel answered {status}"),
            Self::Body(reason) => write!(formatter, "private channel answer: {reason}"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<std::io::Error> for ChannelError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Which end of the handshake a pinned certificate is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedRole {
    /// Astra, dialling the gateway. Must carry `clientAuth`.
    Client,
    /// The gateway, answering. Must carry `serverAuth`.
    Server,
}

/// The only certificate this end will accept from the other.
///
/// A pin, not a chain: `intermediates` must be empty, the end-entity DER must
/// equal the configured bytes, the extended key usage must match the role, and
/// the certificate must be inside its validity window right now. There is no
/// path building because there is no path — and no CA a compromise could use to
/// mint a second acceptable certificate.
#[derive(Debug)]
struct PinnedPeer {
    pinned: Vec<u8>,
    role: PinnedRole,
    not_before: u64,
    not_after: u64,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedPeer {
    fn new(
        pinned: &DerCertificate,
        role: PinnedRole,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, ChannelError> {
        // Parsed once, at configuration time rather than per handshake: a pin
        // that is not a usable certificate is an install error, and finding
        // that out on the first rotation means finding it out at 3 a.m.
        let facts = x509::inspect(pinned).map_err(|error| ChannelError::Pin(error.to_string()))?;
        let usable = match role {
            PinnedRole::Client => facts.is_client_authentication_leaf,
            PinnedRole::Server => facts.is_server_authentication_leaf,
        };
        if !usable {
            return Err(ChannelError::Pin(format!(
                "the pinned certificate declares no extended key usage a {role:?} end can use"
            )));
        }
        if facts.declares_key_usage && !facts.can_digitally_sign {
            return Err(ChannelError::Pin(
                "the pinned certificate declares a key usage that forbids signing a handshake"
                    .into(),
            ));
        }
        Ok(Self {
            pinned: pinned.as_bytes().to_vec(),
            role,
            not_before: facts.not_before,
            not_after: facts.not_after,
            provider,
        })
    }

    /// The pin check itself.
    ///
    /// A plain comparison: the pinned bytes are a public certificate, and
    /// claiming a constant-time one here would be describing a secret that does
    /// not exist.
    fn accept(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            // A chain means the peer expects to be trusted through an issuer.
            // Nothing on this link has one, so the extra certificates could
            // only ever be an attempt to be verified some other way.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        if end_entity.as_ref() != self.pinned.as_slice() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Pinned bytes still expire. Refusing them is what forces the service
        // identity to be rotated instead of quietly outliving its window.
        let now = now.as_secs();
        if now < self.not_before {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now >= self.not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }
        Ok(())
    }

    /// Unreachable through a configuration built here — both ends offer TLS 1.3
    /// alone — and refused again anyway. This second refusal is what still
    /// stands if a future edit widens `protocol_versions`.
    fn refuse_tls12() -> rustls::Error {
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
    }

    fn verify_tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No hint: there is no issuer to name, and naming one would invite the
        // peer to build a chain this verifier refuses anyway.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        debug_assert_eq!(self.role, PinnedRole::Client);
        self.accept(end_entity, intermediates, now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(Self::refuse_tls12())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        debug_assert_eq!(self.role, PinnedRole::Server);
        // The name is not consulted, and that is the design: the pin is
        // stronger than any SAN check, and tying the certificate to a name
        // would tie it to a veth address the deployment may change.
        self.accept(end_entity, intermediates, now)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(Self::refuse_tls12())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes()
    }
}

/// Named rather than taken from the process default: a global installed by
/// whichever crate got there first is not a decision, and this channel states
/// its guarantees per configuration.
///
/// The TLS 1.2 suites are dropped from the provider itself, not left to
/// version negotiation. `rustls` is compiled with its `tls12` feature for the
/// public HTTPS client, so those suites exist in the binary; restricting the
/// protocol version makes them unreachable, while removing them makes them
/// absent. On a link that carries authority material the difference is worth
/// the two lines: an unreachable suite is one configuration mistake away from
/// being offered, and a suite that is not in the list cannot be.
/// Settles the process-level provider, once, for the crates that cannot name
/// one themselves.
///
/// Two providers are compiled in — `ring` for the negotiation's QUIC stack,
/// AWS-LC for this channel — so `rustls` refuses to pick a default and panics
/// instead of choosing. Everything in this workspace names its provider, but
/// `hyper-rustls` does not: it builds `reqwest`'s configuration through
/// `rustls::ClientConfig::builder()` (`connector.rs:269`), and that call is
/// the one that aborts. Calling this at start-up, before the first HTTP
/// client, replaces a runtime panic with a decision — and it is the same
/// engine the rest of the protocol already draws on.
///
/// Idempotent: a second call, or a provider installed earlier by someone else,
/// is not an error.
pub fn install_process_default_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    Arc::new(provider)
}

/// The gateway's side: serve, and accept only Astra.
///
/// TLS 1.3 alone — `builder_with_protocol_versions` is what removes 1.2, and
/// the pinned verifier refuses a 1.2 signature a second time. No resumption
/// ticket is ever issued and no early data is ever accepted, which is also what
/// removes `psk_ke`: rustls only offers a Diffie-Hellman-less PSK against a
/// ticket, and there are none. Every TLS 1.3 suite the AWS-LC provider carries
/// negotiates `(EC)DHE`.
pub fn server_config(
    identity: &ChannelIdentity,
    pinned_astra_certificate: &DerCertificate,
) -> Result<rustls::ServerConfig, ChannelError> {
    let provider = provider();
    let verifier = PinnedPeer::new(
        pinned_astra_certificate,
        PinnedRole::Client,
        provider.clone(),
    )?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ChannelError::Tls(error.to_string()))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|error| ChannelError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![INTERNAL_ALPN.to_vec()];
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    Ok(tls)
}

/// Astra's side of the same channel: dial, and accept only this gateway.
///
/// The mirror of [`server_config`], and every bound is restated because a bound
/// only one side declares bounds only that side.
pub fn client_config(
    identity: &ChannelIdentity,
    pinned_gateway_certificate: &DerCertificate,
) -> Result<rustls::ClientConfig, ChannelError> {
    let provider = provider();
    let verifier = PinnedPeer::new(
        pinned_gateway_certificate,
        PinnedRole::Server,
        provider.clone(),
    )?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ChannelError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|error| ChannelError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![INTERNAL_ALPN.to_vec()];
    // No ticket is kept, so none can be offered — and a `psk_ke` resumption the
    // gateway would never grant is never proposed either.
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    Ok(tls)
}

/// Serves the private router until the listener itself fails.
///
/// A refused handshake closes that one connection and is logged; it never takes
/// the listener down, and the listener going down never takes the gateway down.
/// A gateway without an authority is a gateway that works.
///
/// `prefix` is the only path space the router serves; it is named in the log so
/// the two directions of the veth are told apart at a glance.
pub async fn serve(
    bind: SocketAddr,
    config: rustls::ServerConfig,
    router: Router,
    prefix: &'static str,
) -> std::io::Result<()> {
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(INTERNAL_ALPN),
        "private lifecycle channel listening; it serves only {prefix}*"
    );
    loop {
        let (stream, source) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%source, %error, "private lifecycle channel: handshake refused");
                    return;
                }
            };
            let service = TowerToHyperService::new(router);
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%source, %error, "private lifecycle channel: connection ended");
            }
        });
    }
}

/// Astra's typed client for the routes above.
///
/// It opens one connection per call and closes it. Not thrift: a rotation is a
/// handful of requests an hour, a pooled connection would have to be
/// revalidated against a certificate that may have been rotated meanwhile, and
/// a fresh handshake is the cheapest way to know the pin still holds.
pub struct GatewayLifecycleClient {
    http: PinnedHttpClient,
}

impl GatewayLifecycleClient {
    pub fn new(address: SocketAddr, tls: rustls::ClientConfig) -> Self {
        Self {
            http: PinnedHttpClient::new(address, tls, INTERNAL_SERVER_NAME),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.http.address
    }

    /// Hands a staging authorization to the gateway and returns its receipt.
    pub async fn stage(
        &self,
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<aether::certificates::client::GatewayCertificateStageReceipt, ChannelError> {
        let body = serde_json::to_vec(authorization)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self
            .http
            .request("POST", STAGE_PATH, Some(body), None)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    /// Relays a recovery commit for a client that has no tunnel (spec §7.3).
    pub async fn commit_recovery(&self, relayed: &RelayedStageCommit) -> Result<(), ChannelError> {
        let body =
            serde_json::to_vec(relayed).map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", STAGE_COMMIT_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    /// Applies a signed revocation.
    pub async fn revoke(
        &self,
        revocation: &EmergencyCertificateRevocation,
    ) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(revocation)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", REVOKE_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    /// Reads back one peer's bounded state.
    pub async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, ChannelError> {
        // A WireGuard key is base64 and therefore contains `/`, `+` and `=`: it
        // goes into the path percent-encoded, or it silently becomes several
        // path segments and the route stops matching.
        let path = format!(
            "{INTERNAL_PREFIX}state/{}",
            percent_encode_segment(&identity.to_base64())
        );
        let answer = self.http.request("GET", &path, None, None).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    /// Reads the leaf the gateway serves, so a receipt can be verified under
    /// the key that actually signed it.
    /// Leaves a signed transaction for the peer the manifest names (§8.1.1).
    ///
    /// The gateway queues it and hands the fragments to that peer as it polls.
    /// Nothing crosses back: there is no receipt to sign here, because the
    /// gateway attests nothing about a transaction it did not author.
    pub async fn distribute(&self, distribution: &TrustDistribution) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(distribution)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", DISTRIBUTION_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    pub async fn gateway_identity(&self) -> Result<GatewayIdentityView, ChannelError> {
        let answer = self
            .http
            .request("GET", GATEWAY_IDENTITY_PATH, None, None)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    pub async fn gateway_transition_published(
        &self,
        published: &GatewayTransitionPublished,
    ) -> Result<(), ChannelError> {
        let body =
            serde_json::to_vec(published).map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", GATEWAY_PUBLISHED_PATH, Some(body), None)
            .await?;
        Ok(())
    }
}

/// One pinned mTLS connection, opened per call, on either direction of the
/// veth.
///
/// Both typed clients are built on this because both carry the same bounds: a
/// bounded response, a `Host` and SNI that match the pinned identity, and a
/// connection driver that outlives the request in flight. A second copy of
/// this plumbing is how one direction quietly stops bounding its answers.
struct PinnedHttpClient {
    address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    /// SNI and `Host`. Not how the peer is authenticated — the pinned DER is —
    /// but it must match the certificate the peer was built with.
    server_name: &'static str,
}

impl PinnedHttpClient {
    fn new(address: SocketAddr, tls: rustls::ClientConfig, server_name: &'static str) -> Self {
        Self {
            address,
            tls: Arc::new(tls),
            server_name,
        }
    }

    /// `bearer` carries a capability token when the route requires one. It is
    /// set on the header and nowhere else: never a query parameter, never a
    /// path segment, never a log line (spec §8.2).
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
    ) -> Result<Bytes, ChannelError> {
        self.request_bounded(method, path, body, bearer, MAX_INTERNAL_BODY_BYTES)
            .await
    }

    /// The same call under a caller-chosen answer ceiling.
    ///
    /// The operator surface needs the 128 KiB ceiling of §8.5, including for a
    /// large campaign description and its encrypted vault. The limit is still
    /// applied before the answer is read into memory, so an authority that has
    /// been taken over cannot make this process allocate without end.
    async fn request_bounded(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
        max_answer_bytes: usize,
    ) -> Result<Bytes, ChannelError> {
        use http_body_util::BodyExt as _;
        use hyper_util::rt::TokioIo;

        let stream = tokio::net::TcpStream::connect(self.address).await?;
        let name = ServerName::try_from(self.server_name)
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, stream)
            .await
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        // The connection future drives the socket: dropping it before the
        // answer arrives cancels a request that is already in flight.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, self.server_name)
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = builder
            .body(http_body_util::Full::new(Bytes::from(
                body.unwrap_or_default(),
            )))
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let status = response.status();
        // Bounded before it is read into memory, exactly as the server bounds
        // what it accepts: an authority that has been taken over must not be
        // able to make the process that trusts it allocate without end.
        let collected = http_body_util::Limited::new(response.into_body(), max_answer_bytes)
            .collect()
            .await
            .map_err(|error| ChannelError::Body(error.to_string()))?
            .to_bytes();
        drop(sender);
        driver.abort();
        if !status.is_success() {
            return Err(ChannelError::Status(status));
        }
        Ok(collected)
    }
}

/// Percent-encodes one path segment.
///
/// Written here rather than pulled in: a WireGuard key is base64, so the only
/// characters that ever need escaping are `+`, `/` and `=`, and a dependency
/// for three replacements would be supply-chain cost for nothing.
fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 8);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// The other direction: the gateway dials the authority (spec §8.1.2, §8.3).
// ---------------------------------------------------------------------------

/// Path prefix Astra's private listener serves. Everything outside it is
/// refused, exactly as on the gateway's own listener.
pub const ASTRA_INTERNAL_PREFIX: &str = "/internal/v1/client-rotation/";

pub const ROTATION_REQUEST_PATH: &str = "/internal/v1/client-rotation/request";
pub const ROTATION_OPERATION_ROUTE: &str = "/internal/v1/client-rotation/operations/:operation";
pub const ROTATION_SIGNER_REQUEST_ROUTE: &str =
    "/internal/v1/client-rotation/signer-requests/:operation";
pub const ROTATION_SIGNER_RESULT_ROUTE: &str =
    "/internal/v1/client-rotation/signer-results/:operation";

/// The second prefix Astra's private listener serves (spec §0.6).
///
/// Its own prefix rather than a fifth route under the rotation one: a renewal
/// is about a peer asking to be re-certified, a preparation is about a peer
/// being behind on the domain's trust. They share a link, not a subject, and
/// naming them together would make the refusal log unable to say which surface
/// was probed.
pub const ASTRA_TRUST_UPDATE_PREFIX: &str = "/internal/v1/trust-update/";

pub const TRUST_UPDATE_PREPARE_PATH: &str = "/internal/v1/trust-update/prepare";

/// The third prefix Astra's private listener serves (spec §8.5).
///
/// Its own prefix, like the two above and for the same reason: a renewal
/// belongs to one peer, a preparation to one peer's backlog, and an operator
/// campaign to no peer at all. Sharing a prefix would leave a refusal log
/// unable to say which of the three surfaces was probed — and would make it
/// look as though a client identifier and a campaign identifier were
/// interchangeable, which is exactly the confusion §8.5 forbids.
pub const ASTRA_OPERATOR_PREFIX: &str = "/internal/v1/operator/";

pub const OPERATOR_OPERATION_ROUTE: &str = "/internal/v1/operator/operations/:operation";
pub const OPERATOR_SIGNER_REQUEST_ROUTE: &str = "/internal/v1/operator/signer-requests/:operation";
pub const OPERATOR_VAULT_ROUTE: &str = "/internal/v1/operator/vaults/:fingerprint";
pub const OPERATOR_SIGNER_RESULT_ROUTE: &str = "/internal/v1/operator/signer-results/:operation";

/// Ceiling on every operator answer, including the encrypted vault.
///
/// 128 KiB, the §8.2 response ceiling — the public origin serves the same file
/// under the same bound, and Astra refuses to serve one that is larger. The
/// ordinary [`MAX_INTERNAL_BODY_BYTES`] stays what it is for every non-operator
/// call on this link.
pub const MAX_OPERATOR_ANSWER_BYTES: usize = 128 * 1024;

/// Largest canonical operator request accepted on either public surface.
///
/// Operator results may contain several ML-DSA-87-signed transition objects.
/// Their §8.5 ceiling is intentionally larger than the 32 KiB transaction
/// request used by the chunked trust-update protocol.
pub const MAX_OPERATOR_REQUEST_BYTES: usize = 64 * 1024;

/// Largest private body carrying an operator result.
///
/// The public route bounds the canonical result at 64 KiB. The private route
/// adds only the gateway-resolved, fixed-size operator identity and the JSON
/// field names around that result. Keeping a separate ceiling preserves the
/// public bound without making a valid boundary-sized result impossible to
/// relay.
pub const MAX_OPERATOR_RELAY_BODY_BYTES: usize = MAX_OPERATOR_REQUEST_BYTES + 256;

/// Administrator identity established from the request's WireGuard source.
///
/// A peer name is a mutable UI label; the WireGuard public key is the unique
/// identity from the admitted peer table. Development loopback has no such
/// key and is represented explicitly so it can never be confused with a real
/// peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorIdentity {
    WireGuard { public_key: WireGuardKey },
    DevLoopback,
}

impl std::fmt::Display for OperatorIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard { public_key } => write!(formatter, "wireguard:{public_key}"),
            Self::DevLoopback => formatter.write_str("dev-loopback"),
        }
    }
}

/// What the gateway relays for an operator campaign (spec §8.5).
///
/// The administrator identity the gateway resolved from the source VIP, and
/// nothing else. It is **not** an authorization: a campaign is authorized by the
/// WebAuthn assertion and by the `CA-PQ` signatures the objects carry, never
/// by who relayed it. It travels so Astra's structured log can name the
/// admitted administrator the ceremony came through — the same reason the
/// client relay carries its caller. It does not advance the registry's
/// hash-chained mutation audit.
///
/// No path, no method, no header of the caller's: this is the whole of what
/// crosses, and the route is chosen by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorCampaign {
    pub operator: OperatorIdentity,
}

/// What the companion deposits, relayed with its administrator (spec §8.5).
///
/// Only the result. Astra holds the campaign it answers, and a result verified
/// against a campaign the same message supplied would verify nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorSignerResult {
    pub operator: OperatorIdentity,
    pub result: Box<aether::certificates::status::AstraSignerResult>,
}

/// The two operator shapes both ends parse, defined once in `aether`.
pub use aether::certificates::transport::{
    OperatorSignerRequestResponse, SigningOperationState, SigningOperationView,
};

/// The name the gateway puts in SNI when it dials Astra.
///
/// A second constant rather than a reuse of [`INTERNAL_SERVER_NAME`]: the two
/// ends hold two different certificates, and one shared name would let a
/// mis-pinned pair look like a working one right up to the pin comparison.
pub const ASTRA_INTERNAL_SERVER_NAME: &str = "helios-authority.internal";

/// The three types both ends parse, defined once in `aether`.
///
/// Re-exported rather than moved out of sight: every gateway-side caller
/// already names them through this module, and the path is what says which
/// wire they belong to.
pub use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
};

/// What the gateway relays once it has resolved the caller from its VIP.
///
/// `caller_wg_public_key` is the gateway's own resolution, never a value the
/// client chose: Astra compares the request's copy against it and refuses a
/// mismatch. Relaying the request alone would make the authority trust a field
/// the client filled in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedRotationRequest {
    pub caller_wg_public_key: WireGuardKey,
    pub request: Box<aether::certificates::client::ClientCertificateRotationRequest>,
}

/// What the gateway relays when a peer is behind and its queue holds nothing
/// built for the state that peer signed (spec §0.6).
///
/// Three things, and deliberately not a fourth: the client's own authenticated
/// request, the gateway's resolution of who is asking, and the peer snapshot
/// the registry already holds. No method, no path, no header of the client's —
/// the gateway builds a canonical object and relays that, so a request the
/// authority acts on is never a request a client shaped.
///
/// The peer snapshot travels because the authority does not hold the gateway's
/// admission state: it is the same view `GET /internal/v1/certificates/state`
/// already publishes, and it is what lets the authority check the request's
/// signature against the generation the **domain** holds rather than one the
/// request supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedTrustUpdatePreparation {
    pub caller_wg_public_key: WireGuardKey,
    pub request: Box<aether::certificates::transport::AuthenticatedTrustUpdateRequest>,
    pub peer: Box<PeerCertificateStateView>,
}

/// What the authority answers a preparation with.
///
/// `None` is a legitimate answer and not an error: the gateway's comparison
/// and the authority's registry can disagree about what «behind» means — the
/// gateway compares its own counters, the authority holds the objects — and a
/// disagreement resolves as «nothing to distribute», never as a fabricated
/// transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTrustUpdate {
    pub transaction: Option<PreparedTrustUpdateTransaction>,
}

/// One manifest and every fragment of it, ready to be queued.
///
/// The whole set in one answer: the gateway's queue holds a complete
/// transaction or none, so streaming the fragments over several calls would
/// only create a half-queued state neither end could describe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTrustUpdateTransaction {
    pub manifest: aether::certificates::transport::TrustUpdateTransactionManifest,
    pub chunks: Vec<aether::certificates::transport::TrustUpdateChunk>,
}

/// A read of one operation, on behalf of one caller.
///
/// The caller travels with every read for the same reason it travels with the
/// request: on this link the authenticated party is the gateway, not the peer,
/// so the authority can only refuse a peer asking about somebody else's
/// operation if it is told which peer is asking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperationQuery {
    pub caller_wg_public_key: WireGuardKey,
}

/// What the companion posts back.
///
/// Only the approval. Astra holds the request it answers, and an approval
/// verified against a request the same message supplied would verify nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRenewalSignerResult {
    pub caller_wg_public_key: WireGuardKey,
    pub approval: Box<aether::certificates::approval::AstraRenewalApproval>,
}

/// The gateway's door to the authority's transaction producer (spec §0.6).
///
/// A trait rather than the concrete client, for the same reason
/// [`AstraChannelHandler`] is one: the certificate service owns a registry
/// lock and no transport, and giving it a `reqwest`-shaped dependency would
/// make every one of its tests need a listener. It is also what lets a gateway
/// deployed **without** an authority hold `None` and answer exactly as it does
/// today.
#[async_trait]
pub trait TrustUpdatePreparer: Send + Sync {
    /// Asks the authority for the transaction this peer is missing.
    async fn prepare(
        &self,
        relayed: &RelayedTrustUpdatePreparation,
    ) -> Result<PreparedTrustUpdate, TrustUpdateRefusal>;
}

/// The gateway's typed client for Astra's private routes.
///
/// One connection per call, like [`GatewayLifecycleClient`] and for the same
/// reason: a rotation is a handful of requests, and a fresh handshake is the
/// cheapest way to know the pin still holds.
pub struct AstraLifecycleClient {
    http: PinnedHttpClient,
}

impl AstraLifecycleClient {
    pub fn new(address: SocketAddr, tls: rustls::ClientConfig) -> Self {
        Self {
            http: PinnedHttpClient::new(address, tls, ASTRA_INTERNAL_SERVER_NAME),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.http.address
    }

    /// Relays one client's rotation request and returns the operation it
    /// opened — always `awaiting_operator`, never a certificate.
    pub async fn request_rotation(
        &self,
        relayed: &RelayedRotationRequest,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(ROTATION_REQUEST_PATH, relayed, None).await
    }

    /// Asks the authority to build the transaction this peer is missing.
    pub async fn prepare_trust_update(
        &self,
        relayed: &RelayedTrustUpdatePreparation,
    ) -> Result<PreparedTrustUpdate, ChannelError> {
        self.post(TRUST_UPDATE_PREPARE_PATH, relayed, None).await
    }

    /// Reads one operation on behalf of the peer that owns it.
    pub async fn operation(
        &self,
        operation: &Id16,
        query: &RelayedOperationQuery,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(&operation_path("operations", operation), query, None)
            .await
    }

    /// Fetches what the companion has to display and answer.
    pub async fn signer_request(
        &self,
        operation: &Id16,
        token: &str,
        query: &RelayedOperationQuery,
    ) -> Result<ClientRenewalSignerRequest, ChannelError> {
        self.post(
            &operation_path("signer-requests", operation),
            query,
            Some(token),
        )
        .await
    }

    /// Delivers the operator's assertion and returns the operation it produced.
    pub async fn signer_result(
        &self,
        operation: &Id16,
        token: &str,
        result: &ClientRenewalSignerResult,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(
            &operation_path("signer-results", operation),
            result,
            Some(token),
        )
        .await
    }

    // -- The operator ceremony, relayed from inside the tunnel (spec §8.5) --
    //
    // Four calls, one per surface the public origin exposes, and no fifth. The
    // administrator travels in the body on every one of them for the reason
    // the caller does on a renewal: on this link the authenticated party is
    // the gateway, and the authority has to be told who it resolved.

    /// Reads one campaign operation, on behalf of an administrator.
    pub async fn operator_operation(
        &self,
        operation: &Id16,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<SigningOperationView, ChannelError> {
        self.post_bounded(
            &operator_path("operations", &operation.to_string()),
            relayed,
            None,
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Fetches what the companion has to display before it asks for a touch.
    pub async fn operator_signer_request(
        &self,
        operation: &Id16,
        token: &str,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<OperatorSignerRequestResponse, ChannelError> {
        self.post_bounded(
            &operator_path("signer-requests", &operation.to_string()),
            relayed,
            Some(token),
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Downloads the encrypted vault this campaign names.
    ///
    /// Bytes rather than a decoded object: this process holds no key-slot
    /// secret, cannot read the file and has no business parsing it. The
    /// fingerprint is compared against the operation's **signed** request on
    /// the authority side, exactly as on the public origin.
    pub async fn operator_encrypted_vault(
        &self,
        fingerprint: &aether::certificates::encoding::Fingerprint,
        token: &str,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<Vec<u8>, ChannelError> {
        let body =
            serde_json::to_vec(relayed).map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self
            .http
            .request_bounded(
                "POST",
                &operator_path("vaults", &fingerprint.to_string()),
                Some(body),
                Some(token),
                MAX_OPERATOR_ANSWER_BYTES,
            )
            .await?;
        Ok(answer.to_vec())
    }

    /// Delivers the operator's assertion and returns the operation it produced.
    pub async fn operator_signer_result(
        &self,
        operation: &Id16,
        token: &str,
        relayed: &RelayedOperatorSignerResult,
    ) -> Result<SigningOperationView, ChannelError> {
        self.post_bounded(
            &operator_path("signer-results", &operation.to_string()),
            relayed,
            Some(token),
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    async fn post<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R, ChannelError> {
        let body =
            serde_json::to_vec(body).map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self.http.request("POST", path, Some(body), bearer).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    async fn post_bounded<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
        max_answer_bytes: usize,
    ) -> Result<R, ChannelError> {
        let body =
            serde_json::to_vec(body).map_err(|error| ChannelError::Body(error.to_string()))?;
        if body.len() > MAX_OPERATOR_RELAY_BODY_BYTES {
            return Err(ChannelError::Body(format!(
                "operator relay body is {} bytes, above the private route ceiling",
                body.len()
            )));
        }
        let answer = self
            .http
            .request_bounded("POST", path, Some(body), bearer, max_answer_bytes)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }
}

/// Builds one of Astra's operation paths.
///
/// The identifier is hexadecimal, so nothing in it can escape a path segment
/// today — and it goes through the same percent-encoder as a WireGuard key
/// anyway, because "this value happens to be safe" is how the next change of
/// encoding introduces a traversal.
/// Builds one of Astra's operator paths.
///
/// Its own builder rather than a parameter on [`operation_path`]: the two
/// prefixes address two stores, and a single function with a prefix argument
/// is one wrong argument away from relaying a campaign read onto a peer's
/// renewal. The identifier goes through the same percent-encoder.
fn operator_path(collection: &str, identifier: &str) -> String {
    format!(
        "{ASTRA_OPERATOR_PREFIX}{collection}/{}",
        percent_encode_segment(identifier)
    )
}

fn operation_path(collection: &str, operation: &Id16) -> String {
    format!(
        "{ASTRA_INTERNAL_PREFIX}{collection}/{}",
        percent_encode_segment(&operation.to_string())
    )
}

/// The `Authorization: Bearer` value of a capability token, or `None`.
///
/// One reader and one writer: the token never travels in a URL, a cookie or a
/// log (spec §8.2), and a second extraction site is how it ends up in one.
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::client::{
        ClientCertificateGeneration, GatewayCertificateStageReceipt,
    };
    use aether::certificates::encoding::Fingerprint;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// The two relayed surfaces address two prefixes, and never each other.
    ///
    /// This is where "an operator route reaches no peer's renewal operation"
    /// is actually decided (spec §8.5.2): the same 128-bit identifier under
    /// the operator prefix reaches the campaign store, and under the rotation
    /// prefix the renewal one. A single builder with a prefix argument would
    /// be one wrong argument away from crossing them.
    #[test]
    fn a_campaign_path_and_a_renewal_path_never_name_the_same_route() {
        let id = Id16::new([7; 16]).expect("identifier");
        let campaign = operator_path("operations", &id.to_string());
        let renewal = operation_path("operations", &id);

        assert!(campaign.starts_with(ASTRA_OPERATOR_PREFIX));
        assert!(renewal.starts_with(ASTRA_INTERNAL_PREFIX));
        assert_ne!(campaign, renewal);
        assert!(!campaign.starts_with(ASTRA_INTERNAL_PREFIX));
        assert!(!renewal.starts_with(ASTRA_OPERATOR_PREFIX));
        assert!(!ASTRA_OPERATOR_PREFIX.starts_with(ASTRA_TRUST_UPDATE_PREFIX));
    }

    /// A path segment a caller chose cannot escape its segment.
    ///
    /// The identifiers are hexadecimal today, so nothing in them needs
    /// escaping — which is exactly how the next change of encoding introduces
    /// a traversal. The encoder is what makes that impossible rather than
    /// improbable.
    #[test]
    fn an_operator_path_segment_cannot_escape_its_segment() {
        let path = operator_path("vaults", "../../internal/v1/client-rotation/request");
        assert!(
            path.starts_with(ASTRA_OPERATOR_PREFIX),
            "the prefix is not something a caller can leave"
        );
        let segment = path
            .strip_prefix(&format!("{ASTRA_OPERATOR_PREFIX}vaults/"))
            .expect("the collection is the gateway's, not the caller's");
        assert!(
            !segment.contains('/'),
            "an encoded segment holds no separator, so it stays one segment: {segment}"
        );
        assert!(!path.contains("client-rotation/request"));
    }

    /// The private result envelope has a fixed and explicitly reserved cost.
    ///
    /// The canonical result may consume the whole public 64 KiB allowance.
    /// Only a typed WireGuard key (or the smaller development marker) is added
    /// on the private hop, so the extra 256-byte allowance must cover every
    /// identity variant and the surrounding JSON field names.
    #[test]
    fn every_operator_identity_fits_the_reserved_relay_overhead() {
        for operator in [
            OperatorIdentity::WireGuard {
                public_key: WireGuardKey::from_bytes([7; 32]),
            },
            OperatorIdentity::DevLoopback,
        ] {
            let envelope = serde_json::json!({
                "operator": operator,
                "result": null,
            });
            let encoded = serde_json::to_vec(&envelope).expect("operator envelope");
            let overhead = encoded.len() - b"null".len();
            assert!(
                overhead <= MAX_OPERATOR_RELAY_BODY_BYTES - MAX_OPERATOR_REQUEST_BYTES,
                "operator envelope uses {overhead} bytes"
            );
        }
    }

    /// A disposable transport identity, built exactly as the two `init`
    /// commands build theirs.
    struct Disposable {
        identity: ChannelIdentity,
        certificate: DerCertificate,
    }

    fn disposable(name: &str, role: PinnedRole) -> Disposable {
        let (certificate_der, private_key_der) = self_signed(name, role, 30);
        Disposable {
            certificate: DerCertificate::new(certificate_der.clone()).expect("der"),
            identity: ChannelIdentity {
                certificate_der,
                private_key_der,
            },
        }
    }

    fn self_signed(name: &str, role: PinnedRole, days: i64) -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![match role {
            PinnedRole::Client => ExtendedKeyUsagePurpose::ClientAuth,
            PinnedRole::Server => ExtendedKeyUsagePurpose::ServerAuth,
        }];
        let now = time::OffsetDateTime::now_utc();
        if days >= 0 {
            params.not_before = now - time::Duration::minutes(5);
            params.not_after = now + time::Duration::days(days);
        } else {
            // Entirely in the past: a pin that has run out of window.
            params.not_before = now + time::Duration::days(days * 2);
            params.not_after = now + time::Duration::days(days);
        }
        let key_pair = KeyPair::generate().expect("keygen");
        let certificate = params.self_signed(&key_pair).expect("self-signed");
        (certificate.der().to_vec(), key_pair.serialize_der())
    }

    struct SpyHandler {
        seen: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl AstraStageHandler for SpyHandler {
        async fn stage_from_astra(
            &self,
            _authorization: Box<ClientCertificateStageAuthorization>,
        ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("stage");
            Err(TrustUpdateRefusal::Rejected)
        }
    }

    #[async_trait]
    impl AstraChannelHandler for SpyHandler {
        async fn revoke(
            &self,
            _revocation: Box<EmergencyCertificateRevocation>,
        ) -> Result<(), TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("revoke");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn gateway_transition_published(
            &self,
            _published: GatewayTransitionPublished,
        ) -> Result<(), TrustUpdateRefusal> {
            self.seen
                .lock()
                .unwrap()
                .push("gateway_transition_published");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn distribute(
            &self,
            _distribution: Box<TrustDistribution>,
        ) -> Result<(), TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("distribute");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn commit_recovery(
            &self,
            _relayed: Box<RelayedStageCommit>,
        ) -> Result<(), TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("commit_recovery");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn peer_state(
            &self,
            _identity: &WireGuardKey,
        ) -> Result<PeerCertificateStateView, TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("peer_state");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn gateway_identity(&self) -> Result<GatewayIdentityView, TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("gateway_identity");
            Err(TrustUpdateRefusal::Rejected)
        }
    }

    fn spy() -> Arc<SpyHandler> {
        Arc::new(SpyHandler {
            seen: Mutex::new(Vec::new()),
        })
    }

    async fn status_of(handler: Arc<SpyHandler>, method: &str, uri: &str) -> StatusCode {
        router(handler)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    /// The listener serves the lifecycle and nothing else. Everything the
    /// gateway exposes elsewhere — administration, WebSocket, console — is
    /// refused by the router, not by convention.
    #[tokio::test]
    async fn only_the_certificate_routes_exist() {
        for (method, uri) in [
            ("GET", "/api/status"),
            ("POST", "/api/peers"),
            ("POST", "/api/peers/revoke"),
            ("POST", "/api/network"),
            ("GET", "/api/network"),
            ("POST", "/api/tunnel/start"),
            ("POST", "/api/key-negotiation/release"),
            ("POST", "/api/key-negotiation/trust-update"),
            ("GET", "/ws"),
            ("GET", "/"),
            ("POST", "/internal/v1/campaigns/apply"),
            ("GET", "/internal/v1/certificates"),
            ("GET", "/internal/v1/certificates/state"),
        ] {
            let handler = spy();
            assert_eq!(
                status_of(Arc::clone(&handler), method, uri).await,
                StatusCode::NOT_FOUND,
                "{method} {uri} was served by the private listener"
            );
            assert!(
                handler.seen.lock().unwrap().is_empty(),
                "{method} {uri} reached a handler"
            );
        }
    }

    /// The three live routes reach their handler, and a body the API cannot
    /// read never does.
    #[tokio::test]
    async fn the_live_routes_reach_their_handler() {
        for path in [STAGE_PATH, REVOKE_PATH] {
            let handler = spy();
            assert_eq!(
                status_of(Arc::clone(&handler), "POST", path).await,
                StatusCode::BAD_REQUEST,
                "an empty object is not a lifecycle object"
            );
            assert!(
                handler.seen.lock().unwrap().is_empty(),
                "{path} handed an unreadable body to the registry"
            );
        }

        let handler = spy();
        let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment("AAAA"));
        assert_eq!(
            status_of(Arc::clone(&handler), "GET", &uri).await,
            StatusCode::BAD_REQUEST,
            "a malformed key never reaches the registry"
        );
        assert!(handler.seen.lock().unwrap().is_empty());

        let handler = spy();
        let key = WireGuardKey::from_bytes([7; 32]).to_base64();
        let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment(&key));
        assert_eq!(
            status_of(Arc::clone(&handler), "GET", &uri).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(handler.seen.lock().unwrap().as_slice(), ["peer_state"]);
    }

    /// A commit on this link carries a whole relayed document, and a body that
    /// is not one never reaches the registry: an empty POST is a protocol
    /// error, not an ordinary commit that happened to arrive here.
    #[tokio::test]
    async fn a_commit_without_its_authorization_never_reaches_the_registry() {
        let handler = spy();
        assert_eq!(
            status_of(Arc::clone(&handler), "POST", STAGE_COMMIT_PATH).await,
            StatusCode::BAD_REQUEST
        );
        assert!(
            handler.seen.lock().unwrap().is_empty(),
            "the handler decides which stagings are recoveries; it must not be asked about \
             something that is not even a commit"
        );
    }

    #[test]
    fn every_refusal_maps_to_one_bounded_status() {
        for (refusal, expected) in [
            (InternalRefusal::Protocol, StatusCode::BAD_REQUEST),
            (InternalRefusal::Rejected, StatusCode::FORBIDDEN),
            (
                InternalRefusal::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (InternalRefusal::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(refusal.status(), expected, "{refusal:?}");
        }
    }

    /// Both configurations state the same bounds. A bound only one side
    /// declares bounds only that side.
    #[test]
    fn both_ends_refuse_tls12_resumption_and_early_data() {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);

        let server = server_config(&gateway.identity, &astra.certificate).expect("server");
        assert_eq!(server.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
        assert_eq!(
            server.send_tls13_tickets, 0,
            "a ticket is what enables psk_ke"
        );
        assert_eq!(server.max_early_data_size, 0, "0-RTT is replayable");
        assert!(
            server
                .crypto_provider()
                .cipher_suites
                .iter()
                .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
            "the server kept a TLS 1.2 suite"
        );

        let client = client_config(&astra.identity, &gateway.certificate).expect("client");
        assert_eq!(client.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
        assert!(!client.enable_early_data, "0-RTT is replayable");
        assert!(
            client
                .crypto_provider()
                .cipher_suites
                .iter()
                .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
            "the client kept a TLS 1.2 suite"
        );
    }

    /// Runs one complete handshake between two in-memory connections.
    ///
    /// No socket: what is under test is the key schedule the two
    /// configurations agree on, and a listener would only add a port to it.
    fn handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> Vec<u8> {
        for _ in 0..16 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).expect("client writes");
            }
            if !to_server.is_empty() {
                server
                    .read_tls(&mut to_server.as_slice())
                    .expect("server reads");
                server.process_new_packets().expect("server processes");
            }

            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).expect("server writes");
            }
            if !to_client.is_empty() {
                client
                    .read_tls(&mut to_client.as_slice())
                    .expect("client reads");
                client.process_new_packets().expect("client processes");
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                let exported = client
                    .export_keying_material(vec![0u8; 32], b"helios veth session probe", None)
                    .expect("exporter");
                assert_eq!(
                    exported,
                    server
                        .export_keying_material(vec![0u8; 32], b"helios veth session probe", None)
                        .expect("exporter"),
                    "the two ends must agree on the session they just derived"
                );
                return exported;
            }
        }
        panic!("the handshake never completed");
    }

    /// Every reconnection derives its own session keys (spec §14.1).
    ///
    /// It follows from the bounds the configurations declare — no ticket, no
    /// resumption, no 0-RTT — but it is the property the specification names,
    /// and the one an operator cares about: a captured veth session gives
    /// nothing about the next one.
    #[test]
    fn each_veth_reconnection_derives_its_own_session_keys() {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);
        let server_config =
            Arc::new(server_config(&gateway.identity, &astra.certificate).expect("server"));
        let client_config =
            Arc::new(client_config(&astra.identity, &gateway.certificate).expect("client"));
        let name = rustls::pki_types::ServerName::try_from(INTERNAL_SERVER_NAME).expect("name");

        let mut keys = std::collections::BTreeSet::new();
        for _ in 0..3 {
            let mut client =
                rustls::ClientConnection::new(Arc::clone(&client_config), name.clone())
                    .expect("client connection");
            let mut server =
                rustls::ServerConnection::new(Arc::clone(&server_config)).expect("connection");
            keys.insert(handshake(&mut client, &mut server));
        }

        assert_eq!(
            keys.len(),
            3,
            "two reconnections landed on the same session keys"
        );
    }

    /// A pin has to be usable for the role it is pinned in, and it has to be
    /// alive. Both are checked when the configuration is built, so a bad
    /// install fails at startup rather than on the first rotation.
    #[test]
    fn a_pin_is_refused_when_it_is_the_wrong_role_or_expired() {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);

        // A `serverAuth` certificate pinned as the dialling identity can never
        // authenticate a client, and vice versa.
        assert!(
            matches!(
                server_config(&gateway.identity, &gateway.certificate),
                Err(ChannelError::Pin(_))
            ),
            "a serverAuth certificate was accepted as the pinned client"
        );
        assert!(
            matches!(
                client_config(&astra.identity, &astra.certificate),
                Err(ChannelError::Pin(_))
            ),
            "a clientAuth certificate was accepted as the pinned server"
        );

        // Well formed, right role, out of its window: refused at the handshake
        // rather than trusted for ever.
        let (stale_der, _) = self_signed("stale.internal", PinnedRole::Server, -1);
        let stale = DerCertificate::new(stale_der).expect("der");
        let verifier = PinnedPeer::new(&stale, PinnedRole::Server, provider()).expect("pin");
        let refusal = verifier.accept(
            &CertificateDer::from(stale.as_bytes().to_vec()),
            &[],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                ))
            ),
            "an expired pin was accepted: {refusal:?}"
        );
    }

    /// The pin is the identity. Another certificate — even a well-formed one
    /// with the same name and the right usage — is refused, and so is a chain
    /// that tries to be verified through an issuer.
    #[test]
    fn an_unpinned_identity_is_refused() {
        let astra = disposable("astra.internal", PinnedRole::Client);
        let impostor = disposable("astra.internal", PinnedRole::Client);
        let verifier =
            PinnedPeer::new(&astra.certificate, PinnedRole::Client, provider()).expect("pin");

        assert!(
            verifier
                .accept(
                    &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
                    &[],
                    UnixTime::now()
                )
                .is_ok(),
            "the pinned identity must be accepted"
        );

        let refusal = verifier.accept(
            &CertificateDer::from(impostor.certificate.as_bytes().to_vec()),
            &[],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                ))
            ),
            "a second certificate with the same name was accepted: {refusal:?}"
        );

        let refusal = verifier.accept(
            &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
            &[CertificateDer::from(
                impostor.certificate.as_bytes().to_vec(),
            )],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "a chain was accepted on a link that has no issuer: {refusal:?}"
        );
    }

    /// The TLS 1.2 refusal exists in the verifier as well as in the version
    /// list: the second one still stands if a future edit widens the first.
    #[test]
    fn a_tls12_signature_is_refused_by_the_verifier() {
        assert!(matches!(
            PinnedPeer::refuse_tls12(),
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
        ));
    }

    /// A WireGuard key is base64: unescaped, `/` splits it into path segments
    /// and the route silently stops matching.
    #[test]
    fn a_base64_identity_survives_the_path() {
        let key = WireGuardKey::from_bytes([255; 32]).to_base64();
        assert!(key.contains('/') || key.contains('+') || key.contains('='));
        let encoded = percent_encode_segment(&key);
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('='));
    }

    /// The view carries the bounded state and nothing else — no key, no PSK.
    #[test]
    fn the_state_view_serializes_no_secret() {
        let view = PeerCertificateStateView {
            name: "workstation".into(),
            state: ClientCertificateState::new(ClientCertificateGeneration {
                generation: 4,
                ca_tls_epoch: 1,
                tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
                tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
                pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
                not_before: 0,
                not_after: 1_000_000,
            }),
            active_pq_certificate: aether::key_negotiation::PqCertificate {
                version: 2,
                serial: [7; 16],
                subject: "workstation".into(),
                issuer: "operator".into(),
                role: aether::key_negotiation::PqCertificateRole::Client,
                wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
                ml_dsa_87_public_key: "cHVibGlj".into(),
                not_before_unix: 0,
                not_after_unix: 1_000_000,
                ml_dsa_87_signature: "c2lnbmF0dXJl".into(),
            },
        };
        let encoded = serde_json::to_string(&view)
            .expect("encode")
            .to_ascii_lowercase();
        for forbidden in ["private", "preshared", "psk", "secret", "sealed"] {
            assert!(
                !encoded.contains(forbidden),
                "the state view mentions « {forbidden} »: {encoded}"
            );
        }
    }
}
