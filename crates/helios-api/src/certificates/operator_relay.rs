//! The operator's in-tunnel relay to Astra: campaigns, pending operations,
//! the signing companion's exchanges and the vault.

use super::*;

/// The gateway's half of the in-tunnel operator campaign (spec §8.5).
///
/// Four operations, one per surface Astra's public origin exposes, and no
/// fifth. Every one takes the **resolved** administrator as its first
/// argument — the identity `require_admin` derived from the source VIP.
///
/// # Why this is not [`ClientRenewalRelay`]
///
/// A renewal operation belongs to a peer, and the peer's resolved key is what
/// lets the authority refuse somebody else's operation. A campaign belongs to
/// no peer: its authority is the WebAuthn assertion and the `CA-PQ`
/// signatures its objects carry. Merging the two would put a campaign behind
/// `require_peer`, which is the whole distinction §8.5 draws.
///
/// The administrator is carried for Astra's structured service log, never as
/// a permission. Nothing in this trait accepts a path, a method or a header.
#[async_trait]
pub trait OperatorCampaignRelay: Send + Sync {
    /// Reads everything waiting for an operator.
    ///
    /// The list carries no capability token: tokens are minted for the caller
    /// about to act on the operation they named, and a list that carried them
    /// would hand every reader a credential for every operation on it.
    async fn pending(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<astra_channel::OperatorPendingList, TrustUpdateRefusal>;

    /// Reads one campaign operation.
    async fn operation(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal>;

    /// Fetches what the companion has to display before it asks for a touch.
    async fn signer_request(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
    ) -> Result<astra_channel::OperatorSignerRequestResponse, TrustUpdateRefusal>;

    /// Downloads the encrypted vault this campaign names, still encrypted.
    async fn encrypted_vault(
        &self,
        operator: &astra_channel::OperatorIdentity,
        fingerprint: &aether::certificates::encoding::Fingerprint,
        capability_token: &str,
    ) -> Result<Vec<u8>, TrustUpdateRefusal>;

    /// Delivers the operator's assertion and returns what it produced.
    async fn signer_result(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
        result: Box<aether::certificates::status::AstraSignerResult>,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal>;
}

/// The administrator behind an operator route, or nothing.
///
/// `require_admin` has already resolved and checked the caller; this checks it
/// again. Not superstition: it is what makes these handlers safe to call, and
/// what keeps a future remount on the wrong router from silently turning a
/// campaign relay into a peer-reachable one. The stable WireGuard key is a log
/// identity, never a permission.
fn operator_caller(
    caller: &crate::auth::Caller,
    route: &str,
) -> Result<astra_channel::OperatorIdentity, StatusCode> {
    if !caller.admin {
        tracing::warn!(
            pair = %caller.name,
            source = %caller.source,
            route,
            "operator campaign refused: the caller is not an administrator"
        );
        return Err(StatusCode::FORBIDDEN);
    }
    if caller.dev_loopback {
        return Ok(astra_channel::OperatorIdentity::DevLoopback);
    }
    if caller.local {
        // Known limitation (ADR-003, amendment of 3 October 2026): Astra
        // ties an operator campaign to a WireGuard operator identity, which
        // the local socket does not carry. Use the tunnel for these routes.
        tracing::warn!(
            pair = %caller.name,
            route,
            "operator campaign refused: the local socket carries no WireGuard identity"
        );
        return Err(StatusCode::FORBIDDEN);
    }
    let Some(public_key) = caller.public_key.as_deref() else {
        tracing::error!(
            pair = %caller.name,
            source = %caller.source,
            route,
            "operator campaign refused: authenticated peer has no WireGuard identity"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let public_key =
        aether::certificates::encoding::WireGuardKey::parse(public_key).map_err(|error| {
            tracing::error!(
                pair = %caller.name,
                source = %caller.source,
                route,
                %error,
                "operator campaign refused: authenticated peer has an invalid WireGuard identity"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(astra_channel::OperatorIdentity::WireGuard { public_key })
}

/// One coarse refusal for everything a caller could probe with.
///
/// Unknown administrator, unparseable identifier, unknown operation, expired
/// operation, missing or out-of-scope capability: all `403`, and told apart
/// only in the gateway log before relay, or Astra's structured service log
/// after relay. A finer status here would answer «that campaign exists» to
/// whoever asked.
fn operator_refused(
    operator: &astra_channel::OperatorIdentity,
    route: &str,
    reason: &str,
) -> Response {
    tracing::warn!(operator = %operator, route, reason, "operator campaign refused");
    StatusCode::FORBIDDEN.into_response()
}

/// The answer of a gateway with no authority behind it, and why it is `503`.
///
/// Not `404`: the route exists and the administrator is right to be using it.
/// This is the one refusal on these routes allowed to be specific, because it
/// says nothing about the domain — only that this deployment has no private
/// channel to dial.
fn operator_unavailable(operator: &astra_channel::OperatorIdentity, route: &str) -> Response {
    tracing::warn!(
        operator = %operator,
        route,
        "operator campaign unavailable: this gateway has no private channel to the authority"
    );
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

/// `GET /api/certificates/operator/operations/<operation_id>`.
pub async fn operator_operation(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
) -> Response {
    let operator = match operator_caller(&caller, "operation") {
        Ok(operator) => operator,
        Err(status) => return status.into_response(),
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return operator_refused(&operator, "operation", "unparseable operation identifier");
    };
    let Some(relay) = s.operator_campaign.as_ref() else {
        return operator_unavailable(&operator, "operation");
    };
    match relay.operation(&operator, &operation).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/certificates/operator/pending`.
///
/// On the **admin** surface, beside the other operator routes and for the same
/// reason: a campaign belongs to no peer, and letting any admitted peer
/// enumerate what the domain is about to sign is the distinction this
/// placement exists to draw.
pub async fn operator_pending(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
) -> Response {
    let operator = match operator_caller(&caller, "pending") {
        Ok(operator) => operator,
        Err(status) => return status.into_response(),
    };
    let Some(relay) = s.operator_campaign.as_ref() else {
        return operator_unavailable(&operator, "pending");
    };
    match relay.pending(&operator).await {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/certificates/operator/signer-requests/<operation_id>`.
pub async fn operator_signer_request(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let operator = match operator_caller(&caller, "signer-request") {
        Ok(operator) => operator,
        Err(status) => return status.into_response(),
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return operator_refused(
            &operator,
            "signer-request",
            "unparseable operation identifier",
        );
    };
    let Some(token) = astra_channel::bearer_token(&headers) else {
        return operator_refused(&operator, "signer-request", "no capability token");
    };
    let token = token.to_string();
    let Some(relay) = s.operator_campaign.as_ref() else {
        return operator_unavailable(&operator, "signer-request");
    };
    match relay.signer_request(&operator, &operation, &token).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/certificates/operator/vaults/<encrypted_vault_fingerprint>`.
///
/// Served as it is held: encrypted. This gateway holds no key-slot secret and
/// no PRF output, and the fingerprint is checked against the operation's
/// **signed** request by the authority, not here.
pub async fn operator_vault(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(fingerprint): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let operator = match operator_caller(&caller, "vault") {
        Ok(operator) => operator,
        Err(status) => return status.into_response(),
    };
    let Ok(fingerprint) = aether::certificates::encoding::Fingerprint::parse_hex(&fingerprint)
    else {
        return operator_refused(&operator, "vault", "unparseable vault fingerprint");
    };
    let Some(token) = astra_channel::bearer_token(&headers) else {
        return operator_refused(&operator, "vault", "no capability token");
    };
    let token = token.to_string();
    let Some(relay) = s.operator_campaign.as_ref() else {
        return operator_unavailable(&operator, "vault");
    };
    match relay.encrypted_vault(&operator, &fingerprint, &token).await {
        Ok(vault) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            vault,
        )
            .into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `POST /api/certificates/operator/signer-results/<operation_id>`.
pub async fn operator_signer_result(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    axum::extract::Path(operation): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let operator = match operator_caller(&caller, "signer-result") {
        Ok(operator) => operator,
        Err(status) => return status.into_response(),
    };
    let Ok(operation) = parse_operation_id(&operation) else {
        return operator_refused(
            &operator,
            "signer-result",
            "unparseable operation identifier",
        );
    };
    let Some(token) = astra_channel::bearer_token(&headers) else {
        return operator_refused(&operator, "signer-result", "no capability token");
    };
    let token = token.to_string();
    if body.len() > astra_channel::MAX_OPERATOR_REQUEST_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let result: aether::certificates::status::AstraSignerResult = match serde_json::from_slice(
        &body,
    ) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(operator = %operator, %error, "operator campaign refused: unreadable result");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let Some(relay) = s.operator_campaign.as_ref() else {
        return operator_unavailable(&operator, "signer-result");
    };
    match relay
        .signer_result(&operator, &operation, &token, Box::new(result))
        .await
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}
