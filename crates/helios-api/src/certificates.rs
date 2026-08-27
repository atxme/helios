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
    client::{ClientCertificateRotationGrant, ClientCertificateStageCommit},
    encoding::DerCertificate,
    status::AstraCertificateStatus,
    transport::{
        AuthenticatedTrustUpdateRequest, TrustUpdateChunk, TrustUpdateTransactionManifest,
        MAX_TRUST_UPDATE_REQUEST_BYTES,
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

/// What a trust-update answer carries (spec §8.1).
///
/// An answer with no chunk means "your trust is current" — the ordinary case,
/// and the reason a client can poll this cheaply. When a transaction is
/// needed, the manifest travels with the first chunk so a client never holds
/// fragments it cannot attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdateResponse {
    /// Signed freshness statement about the caller's own identity.
    pub status: Option<AstraCertificateStatus>,
    /// Present from the first fragment of a transaction onwards.
    pub manifest: Option<TrustUpdateTransactionManifest>,
    pub chunk: Option<TrustUpdateChunk>,
}

/// A commit and the grant that authorizes it (spec §7.3).
///
/// The two travel together because the gateway needs both: the signatures
/// prove who is committing, the grant proves the authority released anything
/// at all. A commit alone would let a client that holds its own two private
/// keys — which it always does, it generated them — activate a candidate the
/// authority never granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageCommitRequest {
    pub commit: ClientCertificateStageCommit,
    pub grant: ClientCertificateRotationGrant,
}

/// Why a trust update was refused, in the only shapes the API may report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustUpdateRefusal {
    /// Unusable message: malformed body, wrong version.
    Protocol,
    /// Authenticated transport, refused identity: another peer, another
    /// gateway, a certificate or signature that does not verify.
    Rejected,
    /// The caller is behind, and the gateway holds no signed object to bring
    /// it forward. Distinct from "you are current" on purpose: answering an
    /// empty update to a client that is provably out of date would tell it the
    /// opposite of the truth, and it would stop asking.
    Unavailable,
    /// The gateway failed on its own side.
    Internal,
}

/// What a client needs in order to renew its own identity (spec §19).
///
/// Everything here is public: anchors, epochs and URLs. It is what an Orion
/// profile has to carry so that `certificate_renewal` can seed a trust store
/// without asking the network for it — a seed fetched at renewal time would be
/// a seed an attacker chooses.
///
/// Read from the gateway's registry rather than typed by an operator: eleven
/// values copied by hand between two shells is eleven places to paste the
/// wrong one, and the failure surfaces months later at 80 % of a leaf's life.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEnrolmentView {
    pub trust_domain_id: String,
    pub ca_epoch: u64,
    pub ca_pq_public_key: String,
    pub ca_tls_epoch: u64,
    pub client_tls_ca_der: String,
    /// Generation the named peer's identity is at, right now.
    pub client_generation: u64,
    pub astra_authority_url: String,
    pub webauthn_rp_id: String,
    pub astra_policy_fingerprint: String,
    pub credential_registry_epoch: u64,
    pub astra_service_key_epoch: u64,
    pub astra_service_public_key: String,
}

/// The domain as an operator reads it — `GET /api/certificates`.
///
/// # Why the console gets its own read
///
/// Every other view of the registry answers a *client's* question, and is
/// therefore shaped by what that client may learn: the §19 enrolment block
/// covers one peer, and a trust update tells its caller about its own
/// identity and nothing else. An operator's question is the opposite one —
/// *what is the state of the whole domain* — and there is no client-facing
/// route that could answer it without becoming an oracle on other peers.
///
/// Everything here is public: anchors, epochs, fingerprints and expiry dates.
/// No private key, no PSK, no capability token, and no certificate body — a
/// console shows what an operator acts on, and nobody acts on a DER blob.
///
/// # Why one read and not one per peer
///
/// The peers are rendered next to the epochs they were issued under. Reading
/// them separately would let a screen pair a generation taken at one instant
/// with an anchor taken at another, and the pairs that never existed together
/// are exactly the ones an operator would investigate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateDomainView {
    pub trust_domain_id: String,
    pub server_name: String,
    /// Unix instant this snapshot was taken, on the gateway's clock.
    ///
    /// Sent rather than assumed: the browser's clock is the operator's, and a
    /// workstation minutes off would draw the renewal ladder at the wrong rung
    /// for every leaf on the screen.
    pub now_unix: u64,
    pub ca_epoch: u64,
    /// SHA-256 of the `CA-PQ` anchor's public key, lowercase hex.
    pub ca_pq_fingerprint: String,
    /// A successor anchor is installed and waiting for its activation.
    pub ca_transition_pending: bool,
    pub ca_activation_at: Option<u64>,
    pub client_tls_ca_epoch: u64,
    pub client_tls_ca_transition_pending: bool,
    pub gateway_identity_epoch: u64,
    pub gateway_tls_fingerprint: String,
    pub gateway_pq_fingerprint: String,
    pub gateway_transition_pending: bool,
    pub gateway_activation_at: Option<u64>,
    pub astra_authority_url: String,
    pub astra_service_key_epoch: u64,
    pub astra_policy_fingerprint: String,
    pub webauthn_rp_id: String,
    pub credential_registry_epoch: u64,
    /// Operator credentials the domain holds. Two is the floor a vault opens
    /// under, and an approval nobody can answer is what one leaves behind.
    pub credential_bindings: usize,
    /// The delegated issuer, absent until `astra issuer install` has run.
    pub issuer: Option<IssuerView>,
    pub peers: Vec<PeerCertificateView>,
}

/// The bounded delegation an ordinary renewal is issued under (spec §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerView {
    pub issuer_epoch: u64,
    pub lifecycle: aether::certificates::state::IssuerLifecycle,
    pub not_before: u64,
    pub not_after: u64,
    /// Whether it may sign **now** — which the lifecycle alone does not say:
    /// an `active` delegation past its `not_after` signs nothing.
    pub usable: bool,
}

/// One admitted peer's identity, as the registry holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificateView {
    pub name: String,
    pub wg_public_key: String,
    pub generation: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Where the active leaf sits on the 80 / 90 / 95 % ladder of spec §4.3.
    pub phase: aether::certificates::window::ValidityPhase,
    pub revoked: bool,
    /// A candidate generation under lease, and how far it has got.
    pub pending: Option<PendingStageView>,
    /// A committed successor waiting for its activation instant.
    pub next_generation: Option<u64>,
    pub activation_at: Option<u64>,
    /// Fragments of a signed transaction still queued for this peer.
    ///
    /// Non-zero means the peer is behind and has not finished collecting what
    /// would bring it forward — the one state where `trust-update` is doing
    /// something rather than answering "you are current".
    pub distribution_chunks_pending: u16,
}

/// A candidate generation between staging and commit (spec §3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStageView {
    pub generation: u64,
    pub state: aether::certificates::state::PendingStageState,
    pub stage_expires_at: u64,
}

/// What the console asks of a gateway renewal (spec §12.2, §11.1 steps 1-2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRenewalRequest {
    /// Replace the self-signed TLS leaf too. §6.1 makes each leaf optional.
    #[serde(default)]
    pub rotate_tls: bool,
    /// Discard the sealed candidate and draw a fresh key.
    #[serde(default)]
    pub new_key: bool,
    /// Build the request without a continuity signature (§5 recovery).
    #[serde(default)]
    pub key_recovery: bool,
}

/// The exported request, as the operator reads it before carrying it away.
///
/// No private half, and no certificate body: an operator acts on an epoch, an
/// identifier and a fingerprint, which are also the three values they will
/// compare at the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRenewalView {
    pub gateway_identity_epoch: u64,
    pub request_id: String,
    pub request_fingerprint: String,
    pub expires_at: u64,
    /// Fingerprint of the candidate TLS leaf, absent when TLS does not change.
    pub candidate_tls_fingerprint: Option<String>,
    /// `true` when a request already prepared for this epoch was returned
    /// unchanged. Re-running is a resumption, and the console says so rather
    /// than letting an operator believe they hold a second document.
    pub reused: bool,
    pub key_recovery: bool,
}

/// A staged or cancelled decision, as the console displays it back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayDecisionView {
    pub gateway_identity_epoch: u64,
    pub fingerprint: String,
    /// `true` when this exact document was already applied.
    pub already_present: bool,
    /// Set for an installation: the instant the identity switches.
    pub activation_at: Option<u64>,
    /// Set for an installation: the instant the outgoing leaf retires.
    pub not_after: Option<u64>,
}

/// The gateway's own identity, driven from the console (spec §12.2).
///
/// Separate from [`TrustUpdateHandler`] because it needs something that
/// handler never touches: the TPM unlock material. A gateway that reads its
/// registry can answer every question of the lifecycle screen; only one that
/// can open its own vault can prepare a key, and wiring the two together
/// would close the screen on a daemon that merely cannot seal.
#[async_trait]
pub trait GatewayIdentityHandler: Send + Sync {
    /// Generates and seals the next identity, and exports its request.
    async fn prepare_renewal(
        &self,
        request: GatewayRenewalRequest,
    ) -> Result<GatewayRenewalView, GatewayActionRefusal>;

    /// Stages a signed transition without changing the identity served.
    async fn install_transition(
        &self,
        transition: Box<aether::certificates::gateway::GatewayIdentityTransition>,
    ) -> Result<GatewayDecisionView, GatewayActionRefusal>;

    /// Cancels a staged, unpublished transition (spec §6.3).
    async fn abort_transition(
        &self,
        abort: Box<aether::certificates::gateway::GatewayTransitionAbort>,
    ) -> Result<GatewayDecisionView, GatewayActionRefusal>;
}

/// Why a gateway identity gesture was refused, in words the operator reads.
///
/// # Why this one carries its reason and the negotiation refusals do not
///
/// A public negotiation error must not describe admission or policy: the
/// caller is unauthenticated and a precise refusal is an oracle. This surface
/// is the admin console, behind the same authentication as changing the
/// firewall — and here the opposite failure is the real one. « refusé » with
/// no reason sends an operator to the daemon logs during a renewal, which is
/// the moment they can least afford it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayActionRefusal {
    pub message: String,
}

impl GatewayActionRefusal {
    pub fn new(message: impl std::fmt::Display) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl axum::response::IntoResponse for GatewayActionRefusal {
    fn into_response(self) -> Response {
        (StatusCode::CONFLICT, Json(self)).into_response()
    }
}

/// `POST /api/certificates/gateway-renewal`, on the admin surface.
pub async fn gateway_renewal(
    State(s): State<AppState>,
    Json(request): Json<GatewayRenewalRequest>,
) -> Response {
    let Some(handler) = s.gateway_identity.as_ref() else {
        return gateway_identity_absent();
    };
    match handler.prepare_renewal(request).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// `POST /api/certificates/gateway-transition`, on the admin surface.
pub async fn gateway_transition_install(
    State(s): State<AppState>,
    Json(transition): Json<aether::certificates::gateway::GatewayIdentityTransition>,
) -> Response {
    let Some(handler) = s.gateway_identity.as_ref() else {
        return gateway_identity_absent();
    };
    match handler.install_transition(Box::new(transition)).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// `POST /api/certificates/gateway-transition/abort`, on the admin surface.
pub async fn gateway_transition_abort(
    State(s): State<AppState>,
    Json(abort): Json<aether::certificates::gateway::GatewayTransitionAbort>,
) -> Response {
    let Some(handler) = s.gateway_identity.as_ref() else {
        return gateway_identity_absent();
    };
    match handler.abort_transition(Box::new(abort)).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// The same `404` as the rest of the lifecycle, and for the same reason: an
/// absent trust domain is a different fact from a refused action.
fn gateway_identity_absent() -> Response {
    (
        StatusCode::NOT_FOUND,
        "this gateway drives no identity of its own — run `heliosd init-trust-domain`",
    )
        .into_response()
}

/// `GET /api/certificates`, on the admin surface.
///
/// `404` when the gateway has no trust domain, for the same reason
/// [`trust_enrolment`] answers `404`: an empty registry and an absent one are
/// different facts, and a console handed an empty list would draw a domain
/// with no clients rather than a gateway that was never initialised.
pub async fn domain(State(s): State<AppState>) -> Response {
    let Some(handler) = s.trust_update.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this gateway has no trust domain — run `heliosd init-trust-domain`",
        )
            .into_response();
    };
    match handler.domain().await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/key-negotiation/trust-enrolment/:public_key`, on the admin
/// surface.
///
/// `404` and not an empty body, for the same reason `/api/key-negotiation`
/// answers `404`: a tool handed `null` would have to guess between "no trust
/// domain on this gateway", "this peer is not admitted" and "read failure",
/// and would emit a profile that cannot renew without saying so.
pub async fn trust_enrolment(
    State(s): State<AppState>,
    axum::extract::Path(public_key): axum::extract::Path<String>,
) -> Response {
    let Some(handler) = s.trust_update.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this gateway has no trust domain — run `heliosd init-trust-domain`",
        )
            .into_response();
    };
    match handler.trust_enrolment(public_key.trim()).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(TrustUpdateRefusal::Rejected) => (
            StatusCode::NOT_FOUND,
            "no such admitted peer in the certificate registry",
        )
            .into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// The gateway side of a trust update, implemented by the daemon.
///
/// A trait for the same reason the PSK release is one: the API process must
/// never hold the certificate registry's lock or a WireGuard backend. It hands
/// an authenticated request to whatever owns the serializer.
#[async_trait]
pub trait TrustUpdateHandler: Send + Sync {
    /// The public trust material a profile must carry for `peer` (spec §19).
    ///
    /// On the **admin** surface, not in the tunnel: it is read while a client
    /// is being enrolled, which is by definition before that client has a
    /// tunnel. Nothing here is secret, so no peer resolution guards it — what
    /// guards it is `admin_iface`, like every other operator read.
    async fn trust_enrolment(
        &self,
        peer_wg_public_key: &str,
    ) -> Result<TrustEnrolmentView, TrustUpdateRefusal>;

    /// The whole domain, for the operator console (`GET /api/certificates`).
    ///
    /// One reading of the registry under one lock, like [`Self::trust_enrolment`]
    /// and for the same reason: a screen that paired a peer's generation with
    /// an anchor epoch read a moment later would show a combination that never
    /// existed, and it is precisely those that get investigated.
    async fn domain(&self) -> Result<CertificateDomainView, TrustUpdateRefusal>;

    /// Records a freshly admitted peer's **first** generation (spec §13.1).
    ///
    /// Admission is where this belongs, and nowhere else: the registry needs
    /// the leaves themselves — it verifies signatures made by them rather than
    /// merely comparing digests — and admission is the only moment the gateway
    /// is handed them. A peer admitted without them is a peer with no trust
    /// block, therefore a profile that cannot renew, and the gap only shows up
    /// at 80 % of a leaf's life.
    ///
    /// Idempotent for an unchanged peer, so a re-run of an interrupted
    /// admission finishes it instead of refusing it.
    async fn admit_peer(
        &self,
        name: &str,
        peer_wg_public_key: &str,
        tls_certificate: DerCertificate,
        pq_certificate: Box<PqCertificate>,
    ) -> Result<(), TrustUpdateRefusal>;

    /// `caller_wg_public_key` is the identity `require_peer` resolved from the
    /// source address — the trusted one. The request's own copy is only ever
    /// compared against it.
    async fn trust_update(
        &self,
        caller_wg_public_key: &str,
        request: AuthenticatedTrustUpdateRequest,
    ) -> Result<TrustUpdateResponse, TrustUpdateRefusal>;

    /// Client's commit of a staged generation, arriving in the tunnel with
    /// the grant that authorizes it.
    async fn stage_commit(
        &self,
        caller_wg_public_key: &str,
        request: Box<StageCommitRequest>,
    ) -> Result<(), TrustUpdateRefusal>;
}

/// The gateway's half of the relayed client renewal (spec §8.1.2).
///
/// Four operations, one per in-tunnel route, and every one of them takes the
/// **resolved** caller as its first argument — the identity `require_peer`
/// derived from the source VIP. Nothing here takes an identity out of a body:
/// the body's copy is compared against this one further down, exactly as the
/// PSK release does.
///
/// A trait for the same reason [`TrustUpdateHandler`] is one: the API process
/// holds no registry lock and no client towards Astra. It hands an
/// authenticated, typed object to whatever owns both, and learns back one
/// refusal class.
#[async_trait]
pub trait ClientRenewalRelay: Send + Sync {
    /// Opens an operation for the caller's own rotation request.
    ///
    /// The answer is always an operation, never a certificate: at this point
    /// no operator has approved anything, so there is nothing to issue.
    async fn open(
        &self,
        caller_wg_public_key: &str,
        request: Box<aether::certificates::client::ClientCertificateRotationRequest>,
    ) -> Result<crate::internal::ClientRenewalOperationView, TrustUpdateRefusal>;

    /// Reads one operation the caller owns.
    async fn operation(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
    ) -> Result<crate::internal::ClientRenewalOperationView, TrustUpdateRefusal>;

    /// Fetches what the signing companion has to display and answer.
    async fn signer_request(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
    ) -> Result<crate::internal::ClientRenewalSignerRequest, TrustUpdateRefusal>;

    /// Delivers the operator's assertion and returns what it produced.
    async fn signer_result(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
        approval: Box<aether::certificates::approval::AstraRenewalApproval>,
    ) -> Result<crate::internal::ClientRenewalOperationView, TrustUpdateRefusal>;
}

/// Private Astra-to-Helios staging contract.
///
/// This trait deliberately has no route in the in-tunnel router. The future
/// veth listener owns its mTLS authentication and calls it only for an Astra
/// peer pinned by the local trust domain.
#[async_trait]
pub trait AstraStageHandler: Send + Sync {
    async fn stage_from_astra(
        &self,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<aether::certificates::client::GatewayCertificateStageReceipt>, TrustUpdateRefusal>;
}

/// Tombstone for the pre-amendment Orion-to-Helios staging route.
///
/// The global router serves the web application as its fallback, including for
/// unknown paths. Keeping this explicit `404` prevents a retired API call from
/// receiving an HTML `200` that a client could mistake for a protocol answer.
pub async fn retired_in_tunnel_stage() -> StatusCode {
    StatusCode::NOT_FOUND
}

impl TrustUpdateRefusal {
    fn status(self) -> StatusCode {
        StatusCode::from(self)
    }
}

impl From<TrustUpdateRefusal> for StatusCode {
    fn from(refusal: TrustUpdateRefusal) -> Self {
        match refusal {
            TrustUpdateRefusal::Protocol => StatusCode::BAD_REQUEST,
            TrustUpdateRefusal::Rejected => StatusCode::FORBIDDEN,
            TrustUpdateRefusal::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            TrustUpdateRefusal::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// `POST /api/key-negotiation/trust-update`, inside the tunnel.
pub async fn trust_update(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    body: Bytes,
) -> Response {
    let Some(caller_key) = caller.public_key.as_deref() else {
        // `require_peer` also admits the `--dev` loopback identity, which has
        // no WireGuard key. A trust update is about one peer's generations;
        // without a key there is no peer to answer for.
        tracing::warn!(
            source = %caller.source,
            "trust update refused: the caller is not tied to a WireGuard peer"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if body.len() > MAX_TRUST_UPDATE_REQUEST_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let request: AuthenticatedTrustUpdateRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(peer = %caller_key, %error, "trust update refused: unreadable body");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let Some(handler) = s.trust_update.as_ref() else {
        // An older gateway answers `404` on this route (spec §8.1) and Orion
        // keeps its current trust rather than falling back to anything. A
        // gateway that runs no lifecycle is in the same position.
        tracing::warn!(
            peer = %caller_key,
            "trust update ignored: this gateway runs no certificate lifecycle"
        );
        return StatusCode::NOT_FOUND.into_response();
    };
    match handler.trust_update(caller_key, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `POST /api/key-negotiation/stage-commit`, inside the tunnel (spec §7.3).
pub async fn stage_commit(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    body: Bytes,
) -> StatusCode {
    let Some(caller_key) = caller.public_key.as_deref() else {
        return StatusCode::UNAUTHORIZED;
    };
    if body.len() > MAX_TRUST_UPDATE_REQUEST_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let request: StageCommitRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(peer = %caller_key, %error, "commit refused: unreadable body");
            return StatusCode::BAD_REQUEST;
        }
    };
    let Some(handler) = s.trust_update.as_ref() else {
        return StatusCode::NOT_FOUND;
    };
    match handler.stage_commit(caller_key, Box::new(request)).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(refusal) => refusal.status(),
    }
}

/// The renewal routes' common preamble: a caller, and an operation identifier.
///
/// Written once because it is the property the whole surface rests on. Every
/// route resolves the peer **before** it deserializes anything cryptographic,
/// and a route that forgot to would be indistinguishable from one that did.
fn renewal_caller(caller: &crate::auth::Caller, route: &str) -> Option<String> {
    match caller.public_key.as_deref() {
        Some(key) => Some(key.to_string()),
        None => {
            // `require_peer` also admits the `--dev` loopback identity, which
            // has no WireGuard key. A renewal is about one peer's generations;
            // without a key there is no peer to renew for.
            tracing::warn!(
                source = %caller.source,
                route,
                "certificate renewal refused: the caller is not tied to a WireGuard peer"
            );
            None
        }
    }
}

/// Parses an operation identifier out of a path segment.
fn parse_operation_id(
    raw: &str,
) -> Result<aether::certificates::encoding::Id16, aether::certificates::CertificateError> {
    aether::certificates::encoding::Id16::parse_hex(raw)
}

/// `POST /api/key-negotiation/certificate-renewal/request` (spec §8.1.2).
///
/// Step 1 of the relayed flow. The gateway resolves the peer, hands the
/// canonical request to Astra and returns the `awaiting_operator` operation it
/// opened. It never returns a certificate, because at this point none exists.
pub async fn renewal_request(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    body: Bytes,
) -> Response {
    let Some(caller_key) = renewal_caller(&caller, "request") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if body.len() > MAX_TRUST_UPDATE_REQUEST_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let request: aether::certificates::client::ClientCertificateRotationRequest =
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(peer = %caller_key, %error, "renewal refused: unreadable request");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
    let Some(relay) = s.client_renewal.as_ref() else {
        return renewal_unavailable(&caller_key, "request");
    };
    match relay.open(&caller_key, Box::new(request)).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/key-negotiation/certificate-renewal/operations/<operation_id>`.
///
/// Steps 3 and 7: the client polls its own operation, and collects the grant
/// once the gateway's receipt has produced one. Another peer asking for this
/// identifier is refused — the operation is bound to the peer that opened it.
pub async fn renewal_operation(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
) -> Response {
    let Some(caller_key) = renewal_caller(&caller, "operation") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(relay) = s.client_renewal.as_ref() else {
        return renewal_unavailable(&caller_key, "operation");
    };
    match relay.operation(&caller_key, &operation).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/key-negotiation/certificate-renewal/signer-requests/<operation_id>`.
///
/// Step 4a: the companion reads what it must display before it asks for a
/// touch. It needs the capability token the operation handed the client, and
/// the token is bound to that operation, that manifest and that scope.
pub async fn renewal_signer_request(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(caller_key) = renewal_caller(&caller, "signer-request") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(token) = crate::internal::bearer_token(&headers) else {
        // Missing is refused exactly like wrong: the answer must not tell a
        // caller whether the operation it named exists.
        return StatusCode::FORBIDDEN.into_response();
    };
    let token = token.to_string();
    let Some(relay) = s.client_renewal.as_ref() else {
        return renewal_unavailable(&caller_key, "signer-request");
    };
    match relay.signer_request(&caller_key, &operation, &token).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `POST /api/key-negotiation/certificate-renewal/signer-results/<operation_id>`.
///
/// Step 4b and step 5: the companion delivers the assertion, and the answer is
/// the operation Astra reached with it — `pending_commit` with a grant when
/// the whole chain succeeded, `failed` when it did not.
pub async fn renewal_signer_result(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let Some(caller_key) = renewal_caller(&caller, "signer-result") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(token) = crate::internal::bearer_token(&headers) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let token = token.to_string();
    if body.len() > MAX_TRUST_UPDATE_REQUEST_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let approval: aether::certificates::approval::AstraRenewalApproval =
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(peer = %caller_key, %error, "renewal refused: unreadable approval");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
    let Some(relay) = s.client_renewal.as_ref() else {
        return renewal_unavailable(&caller_key, "signer-result");
    };
    match relay
        .signer_result(&caller_key, &operation, &token, Box::new(approval))
        .await
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// The answer of a gateway that has no authority to relay to.
///
/// `503` and not `404`: the route exists and the client is right to be using
/// it. What is missing is the private channel, and a client told "unknown
/// route" would conclude its gateway is too old and stop trying — the same
/// mistake as answering "you are up to date" to a client that is behind.
fn renewal_unavailable(caller_key: &str, route: &str) -> Response {
    tracing::warn!(
        peer = %caller_key,
        route,
        "certificate renewal unavailable: this gateway has no private channel to the authority, \
         so no renewal can be relayed and no grant can be delivered"
    );
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{
        Fingerprint, Id16, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::transport::TrustUpdateRequest;
    use aether::certificates::CERTIFICATE_PROTOCOL_VERSION;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    use aether::{NetworkConfig, TunnelState};
    use axum::body::to_bytes;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, mpsc, RwLock};

    const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    struct SpyHandler {
        answer: Result<TrustUpdateResponse, TrustUpdateRefusal>,
        seen: Mutex<Option<String>>,
    }

    #[async_trait]
    impl TrustUpdateHandler for SpyHandler {
        async fn trust_enrolment(
            &self,
            _peer_wg_public_key: &str,
        ) -> Result<TrustEnrolmentView, TrustUpdateRefusal> {
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn domain(&self) -> Result<CertificateDomainView, TrustUpdateRefusal> {
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn admit_peer(
            &self,
            _name: &str,
            _peer_wg_public_key: &str,
            _tls_certificate: DerCertificate,
            _pq_certificate: Box<PqCertificate>,
        ) -> Result<(), TrustUpdateRefusal> {
            Ok(())
        }

        async fn trust_update(
            &self,
            caller_wg_public_key: &str,
            _request: AuthenticatedTrustUpdateRequest,
        ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
            *self.seen.lock().unwrap() = Some(caller_wg_public_key.to_string());
            self.answer.clone()
        }

        async fn stage_commit(
            &self,
            _caller_wg_public_key: &str,
            _request: Box<StageCommitRequest>,
        ) -> Result<(), TrustUpdateRefusal> {
            Ok(())
        }
    }

    fn state_with(handler: Option<Arc<SpyHandler>>) -> AppState {
        let network = NetworkConfig::default();
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (psk_tx, _psk_rx) = mpsc::channel(8);
        let state = AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(TunnelState::Up)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        match handler {
            Some(handler) => state.with_trust_update(handler),
            None => state,
        }
    }

    fn caller(public_key: Option<&str>) -> crate::auth::Caller {
        crate::auth::Caller {
            source: "100.64.1.2".parse().unwrap(),
            name: "workstation".into(),
            public_key: public_key.map(str::to_string),
            admin: false,
            dev_loopback: false,
        }
    }

    /// A syntactically complete request. Its signature is never reached here:
    /// the API parses and forwards, and every refusal it produces on its own
    /// happens before any verification.
    fn body() -> Bytes {
        let request = AuthenticatedTrustUpdateRequest {
            request: TrustUpdateRequest {
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                request_id: Id16::new([1; 16]).unwrap(),
                trust_domain_id: TrustDomainId::new([2; 16]).unwrap(),
                gateway_wg_public_key: WireGuardKey::parse(GATEWAY_KEY).unwrap(),
                client_wg_public_key: WireGuardKey::parse(CLIENT_KEY).unwrap(),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                astra_service_key_epoch: 1,
                issuer_epoch: 1,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                client_identity_generation: 4,
                active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"a"),
                active_gateway_certificate_fingerprint: Fingerprint::of(b"b"),
                active_client_tls_certificate_fingerprint: Fingerprint::of(b"c"),
                active_client_pq_certificate_fingerprint: Fingerprint::of(b"d"),
                client_pq_certificate_fingerprint: Fingerprint::of(b"e"),
                base_state_fingerprint: Fingerprint::of(b"base state"),
            },
            certificate: PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: "orion".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: CLIENT_KEY.into(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            ml_dsa_87_signature: MlDsa87Signature::placeholder(),
        };
        Bytes::from(serde_json::to_vec(&request).unwrap())
    }

    fn spy(answer: Result<TrustUpdateResponse, TrustUpdateRefusal>) -> Arc<SpyHandler> {
        Arc::new(SpyHandler {
            answer,
            seen: Mutex::new(None),
        })
    }

    fn empty_response() -> TrustUpdateResponse {
        TrustUpdateResponse {
            status: None,
            manifest: None,
            chunk: None,
        }
    }

    /// The key the handler receives is the one the transport proved, never the
    /// one the body claims.
    #[tokio::test]
    async fn an_accepted_request_forwards_the_source_resolved_key() {
        let handler = spy(Ok(empty_response()));
        let response = trust_update(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(Some(CLIENT_KEY))),
            body(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(handler.seen.lock().unwrap().as_deref(), Some(CLIENT_KEY));
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let decoded: TrustUpdateResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.chunk.is_none(), "no chunk means trust is current");
    }

    #[tokio::test]
    async fn a_caller_without_a_wireguard_key_is_refused() {
        let handler = spy(Ok(empty_response()));
        let response = trust_update(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(None)),
            body(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(handler.seen.lock().unwrap().is_none());
    }

    /// A gateway with no lifecycle answers `404`, which is exactly what an
    /// older gateway answers — so Orion has one behaviour to implement.
    #[tokio::test]
    async fn a_gateway_without_the_lifecycle_answers_not_found() {
        let response = trust_update(
            State(state_with(None)),
            Extension(caller(Some(CLIENT_KEY))),
            body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn every_refusal_class_maps_to_one_bounded_status() {
        for (refusal, expected) in [
            (TrustUpdateRefusal::Protocol, StatusCode::BAD_REQUEST),
            (TrustUpdateRefusal::Rejected, StatusCode::FORBIDDEN),
            (
                TrustUpdateRefusal::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                TrustUpdateRefusal::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let response = trust_update(
                State(state_with(Some(spy(Err(refusal))))),
                Extension(caller(Some(CLIENT_KEY))),
                body(),
            )
            .await;
            assert_eq!(response.status(), expected, "{refusal:?}");
        }
    }

    #[tokio::test]
    async fn a_body_the_api_cannot_use_never_reaches_the_state_machine() {
        let handler = spy(Ok(empty_response()));
        let state = state_with(Some(Arc::clone(&handler)));

        assert_eq!(
            trust_update(
                State(state.clone()),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from_static(b"{"),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            trust_update(
                State(state),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from(vec![b'x'; MAX_TRUST_UPDATE_REQUEST_BYTES + 1]),
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(handler.seen.lock().unwrap().is_none());
    }
}
