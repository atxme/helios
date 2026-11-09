//! What the gateway serves Astra on the veth: the refusals, the contracts,
//! the handler traits and the router.

use super::*;

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
    /// The authority holds as many live operations as it accepts.
    Throttled,
    /// A live operation holds this back; it can pass later.
    Conflict,
    /// The gateway failed on its own side.
    Internal,
}

impl InternalRefusal {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Rejected => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::Conflict => StatusCode::CONFLICT,
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
            TrustUpdateRefusal::Throttled => Self::Throttled,
            TrustUpdateRefusal::Conflict => Self::Conflict,
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
    /// The operator admission anchor this gateway verifies client PQ leaves
    /// under, beside the domain's own authorities.
    ///
    /// A first-generation leaf is signed by it: enrolment happens offline,
    /// without the vault, so it cannot be signed by `CA-PQ`. Renewed leaves
    /// come from the domain anchor or its delegated issuer instead. An
    /// authority that verified a historical leaf under the domain half alone
    /// would refuse every identity that has never been renewed — which is
    /// precisely the population a §7.5 recovery is for.
    #[serde(default)]
    pub admission_pq_ca: Option<aether::certificates::encoding::MlDsa87PublicKey>,
}

/// Private Astra-to-Helios staging contract.
///
/// This trait deliberately has no route in the in-tunnel router. The veth
/// listener of this crate owns its mTLS authentication and calls it only for
/// an Astra peer pinned by the local trust domain.
#[async_trait]
pub trait AstraStageHandler: Send + Sync {
    async fn stage_from_astra(
        &self,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<aether::certificates::client::GatewayCertificateStageReceipt>, TrustUpdateRefusal>;
}

/// The gateway side of the private channel, implemented by the daemon.
///
/// Staging comes from [`AstraStageHandler`], the reserved Astra-to-Helios
/// contract above; this trait adds the two other routes rather than declaring
/// a second staging entry point. A trait for the same reason
/// `helios_api::certificates::TrustUpdateHandler` is one: the API process
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

    /// Lists every peer with a certificate record, admitted or cut.
    async fn peer_keys(&self) -> Result<Vec<WireGuardKey>, TrustUpdateRefusal>;

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

/// The peers the gateway holds certificate state for.
///
/// Keys only: the listing says which identities the gateway knows, and nothing
/// about any of them. The state of one peer is read on its own route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeysView {
    pub peers: Vec<WireGuardKey>,
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

/// Builds the private router — the eight routes, and a refusal for the rest.
pub fn router(handler: Arc<dyn AstraChannelHandler>) -> Router {
    Router::new()
        .route(STAGE_PATH, post(stage))
        .route(STAGE_COMMIT_PATH, post(stage_commit))
        .route(REVOKE_PATH, post(revoke))
        .route(STATE_ROUTE, get(peer_state))
        .route(PEERS_PATH, get(peer_keys))
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

/// `GET /internal/v1/certificates/peers`.
async fn peer_keys(State(handler): State<Arc<dyn AstraChannelHandler>>) -> Response {
    match handler.peer_keys().await {
        Ok(peers) => (StatusCode::OK, Json(PeerKeysView { peers })).into_response(),
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
