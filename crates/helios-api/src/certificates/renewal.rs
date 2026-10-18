//! An ordinary client renewal relayed end to end (spec §8.1.2): the request,
//! its operation, the client commit, and the retired in-tunnel stage.

use super::*;

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
    ) -> Result<astra_channel::ClientRenewalOperationView, TrustUpdateRefusal>;

    /// Reads one operation the caller owns.
    async fn operation(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
    ) -> Result<astra_channel::ClientRenewalOperationView, TrustUpdateRefusal>;

    /// Fetches what the signing companion has to display and answer.
    async fn signer_request(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
    ) -> Result<astra_channel::ClientRenewalSignerRequest, TrustUpdateRefusal>;

    /// Delivers the operator's assertion and returns what it produced.
    async fn signer_result(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
        approval: Box<aether::certificates::approval::AstraRenewalApproval>,
    ) -> Result<astra_channel::ClientRenewalOperationView, TrustUpdateRefusal>;
}

/// Tombstone for the pre-amendment Orion-to-Helios staging route.
///
/// The global router serves the web application as its fallback, including for
/// unknown paths. Keeping this explicit `404` prevents a retired API call from
/// receiving an HTML `200` that a client could mistake for a protocol answer.
pub async fn retired_in_tunnel_stage() -> StatusCode {
    StatusCode::NOT_FOUND
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
    if body.len() > MAX_STAGE_COMMIT_REQUEST_BYTES {
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
pub(super) fn parse_operation_id(
    raw: &str,
) -> Result<aether::certificates::encoding::Id16, aether::certificates::CertificateError> {
    aether::certificates::encoding::Id16::parse_hex(raw)
}

/// `POST /api/key-negotiation/certificate-renewal/request` (spec §8.1.2).
///
/// Step 1 of the relayed flow. The gateway resolves the peer, hands the
/// canonical request to Astra and returns the operation Astra advanced. A due
/// request normally already carries its grant; no operator ceremony sits
/// between these two services.
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

// ---------------------------------------------------------------------------
// The operator campaign inside the tunnel (spec §8.5).
// ---------------------------------------------------------------------------

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
