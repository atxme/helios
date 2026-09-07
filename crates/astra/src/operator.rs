//! The operator ceremony, reached from inside the tunnel (spec §8.5).
//!
//! # Why this exists beside the public origin
//!
//! Until the amendment of 4 September 2026, a campaign could only be approved
//! through Astra's public HTTPS origin. On a deployment whose authority name is
//! not publicly resolvable — the expected case, since the WebAuthn RP ID is
//! fixed before bootstrap and cannot change without invalidating every
//! key-slot — that origin does not exist, and the four chain commands were
//! unreachable. `rotate-ca-tls` is one of them, which is what unblocks §9.4.
//!
//! So the rule becomes the one the ordinary renewal already follows: the
//! WireGuard channel is mandatory as soon as it exists. The public origin
//! serves an operator who genuinely has no tunnel, and the offline bundle
//! remains the last resort.
//!
//! # What this module is not
//!
//! It is not a second implementation. Every route here calls the same function
//! the public handler calls, so the two channels cannot drift into deciding
//! differently. What it does not carry is the §8.2 rate budget: that is charged
//! per real source address, and on a link whose only caller is the gateway it
//! would be one shared bucket every administrator queued behind.
//!
//! # What the authority is told, and what it is not
//!
//! The administrator identity the gateway resolved from its source VIP travels
//! in the body for the structured service log, rather than as a permission: a
//! campaign is authorized by the WebAuthn assertion and the `CA-PQ` signatures
//! its objects carry, never by who relayed it. No path, no method and no header
//! of the original caller's crosses this link.

use std::sync::Arc;

use aether::certificates::encoding::{Fingerprint, Id16};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use helios_api::internal::{
    OperatorIdentity, RelayedOperatorCampaign, RelayedOperatorSignerResult,
    MAX_OPERATOR_RELAY_BODY_BYTES, OPERATOR_OPERATION_ROUTE, OPERATOR_PENDING_ROUTE,
    OPERATOR_SIGNER_REQUEST_ROUTE, OPERATOR_SIGNER_RESULT_ROUTE, OPERATOR_VAULT_ROUTE,
};

use crate::service::{
    operator_encrypted_vault, operator_operation, operator_signer_request, operator_signer_result,
    AstraService, ServiceError,
};

/// The five private operator routes, for the listener of §8.3 to merge.
pub fn private_routes() -> Router<Arc<AstraService>> {
    Router::new()
        .route(OPERATOR_PENDING_ROUTE, post(pending))
        .route(OPERATOR_OPERATION_ROUTE, post(operation))
        .route(OPERATOR_SIGNER_REQUEST_ROUTE, post(signer_request))
        .route(OPERATOR_VAULT_ROUTE, post(vault))
        .route(
            OPERATOR_SIGNER_RESULT_ROUTE,
            post(signer_result).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
        )
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// One refusal, logged with the administrator it came through.
///
/// The class is what crosses back; the reason stays in Astra's structured
/// service log. The hash-chained registry audit records durable authority
/// decisions, not read-side probes that would churn its anti-fork witness.
fn refuse(operator: &OperatorIdentity, route: &str, error: ServiceError) -> Response {
    tracing::warn!(operator = %operator, route, %error, "private operator route refused");
    error.into_response()
}

/// The capability token, from the one header it may travel in (spec §8.2).
fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn operation_id(raw: &str) -> Result<Id16, ServiceError> {
    Id16::parse_hex(raw).map_err(|_| ServiceError::Refused)
}

/// Everything waiting for an operator, without a capability token in sight.
///
/// The list exists so a campaign can be *found*: an administrator opens one in
/// the tunnel, and until now the only way to reach it was an identifier
/// carried by hand from the terminal that printed it — the transcription this
/// whole surface exists to remove.
///
/// Recoveries are deliberately absent, and their absence is the access control
/// (§7.5): a recovery is served without a tunnel, its only claim is the
/// identifier the client holds, and enumerating them would replace that claim
/// with a list.
async fn pending(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let _ = &relayed.operator;
    let operations = service.signing.lock().await.pending(now_unix());
    (
        axum::http::StatusCode::OK,
        Json(helios_api::internal::OperatorPendingList { operations }),
    )
        .into_response()
}

async fn operation(
    State(service): State<Arc<AstraService>>,
    Path(raw): Path<String>,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let id = match operation_id(&raw) {
        Ok(id) => id,
        Err(error) => return refuse(&relayed.operator, "operation", error),
    };
    match operator_operation(&service, &id, now_unix()).await {
        Ok(view) => (axum::http::StatusCode::OK, Json(view)).into_response(),
        Err(error) => refuse(&relayed.operator, "operation", error),
    }
}

async fn signer_request(
    State(service): State<Arc<AstraService>>,
    Path(raw): Path<String>,
    headers: axum::http::HeaderMap,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let id = match operation_id(&raw) {
        Ok(id) => id,
        Err(error) => return refuse(&relayed.operator, "signer-request", error),
    };
    let Some(token) = bearer(&headers) else {
        return refuse(&relayed.operator, "signer-request", ServiceError::Protocol);
    };
    match operator_signer_request(&service, &id, token, now_unix()).await {
        Ok(view) => (axum::http::StatusCode::OK, Json(view)).into_response(),
        Err(error) => refuse(&relayed.operator, "signer-request", error),
    }
}

/// Served encrypted, because there is no other form this process holds.
async fn vault(
    State(service): State<Arc<AstraService>>,
    Path(raw): Path<String>,
    headers: axum::http::HeaderMap,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let Ok(requested) = Fingerprint::parse_hex(&raw) else {
        return refuse(&relayed.operator, "vault", ServiceError::Refused);
    };
    let Some(token) = bearer(&headers) else {
        return refuse(&relayed.operator, "vault", ServiceError::Protocol);
    };
    match operator_encrypted_vault(&service, &requested, token, now_unix()).await {
        Ok(vault) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            vault,
        )
            .into_response(),
        Err(error) => refuse(&relayed.operator, "vault", error),
    }
}

async fn signer_result(
    State(service): State<Arc<AstraService>>,
    Path(raw): Path<String>,
    headers: axum::http::HeaderMap,
    Json(relayed): Json<RelayedOperatorSignerResult>,
) -> Response {
    let id = match operation_id(&raw) {
        Ok(id) => id,
        Err(error) => return refuse(&relayed.operator, "signer-result", error),
    };
    let Some(token) = bearer(&headers) else {
        return refuse(&relayed.operator, "signer-result", ServiceError::Protocol);
    };
    match operator_signer_result(&service, &id, token, relayed.result, now_unix()).await {
        Ok(view) => {
            tracing::info!(
                operator = %relayed.operator,
                operation = %id,
                "private operator result accepted"
            );
            (axum::http::StatusCode::OK, Json(view)).into_response()
        }
        Err(error) => refuse(&relayed.operator, "signer-result", error),
    }
}
