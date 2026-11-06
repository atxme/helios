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
//! differently. The opening has no public counterpart — `/v1/campaigns` stays
//! refused — and calls the door the local console calls, for the same reason.
//! What it does not carry is the §8.2 rate budget: that is charged per real
//! source address, and on a link whose only caller is the gateway it would be
//! one shared bucket every administrator queued behind.
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
use astra_channel::{
    OperatorAuthorityStatus, OperatorIdentity, OperatorIssuerStatus, OperatorVaultCopied,
    RelayedOperatorCampaign, RelayedOperatorOpen, RelayedOperatorSignerResult,
    RelayedOperatorVaultCopy, MAX_OPERATOR_RELAY_BODY_BYTES,
    MAX_OPERATOR_VAULT_COPY_RELAY_BODY_BYTES, OPERATOR_OPEN_ROUTE, OPERATOR_OPERATION_ROUTE,
    OPERATOR_PENDING_ROUTE, OPERATOR_SIGNER_REQUEST_ROUTE, OPERATOR_SIGNER_RESULT_ROUTE,
    OPERATOR_STATUS_ROUTE, OPERATOR_VAULT_COPY_ROUTE, OPERATOR_VAULT_ROUTE,
};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, State},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};

use crate::door::{DoorConnector, DoorOutcome, DoorRefusal, DoorRequest};
use crate::service::{
    operator_encrypted_vault, operator_operation, operator_signer_request, operator_signer_result,
    AstraService, ServiceError,
};

/// The eight private operator routes, for the listener of §8.3 to merge.
pub fn private_routes() -> Router<Arc<AstraService>> {
    Router::new()
        .route(
            OPERATOR_OPEN_ROUTE,
            post(open).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
        )
        .route(OPERATOR_PENDING_ROUTE, post(pending))
        .route(OPERATOR_STATUS_ROUTE, post(status))
        .route(OPERATOR_OPERATION_ROUTE, post(operation))
        .route(OPERATOR_SIGNER_REQUEST_ROUTE, post(signer_request))
        .route(OPERATOR_VAULT_ROUTE, post(vault))
        .route(
            OPERATOR_VAULT_COPY_ROUTE,
            post(vault_copy).layer(DefaultBodyLimit::max(
                MAX_OPERATOR_VAULT_COPY_RELAY_BODY_BYTES,
            )),
        )
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
        Json(aether::certificates::transport::OperatorPendingList { operations }),
    )
        .into_response()
}

/// What this authority holds, for Orion to decide what is left to do (§5.9).
///
/// A read: no capability token, no volume lock, nothing minted. The service
/// values are read after the registry, in the order `adopt_recorded_issuer`
/// takes them, so the report is one snapshot; the accessors are synchronous
/// and copy their `Arc` out, so no guard crosses an `.await`.
async fn status(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let _ = &relayed.operator;
    let registry = service.registry.lock().await;
    let state = registry.state();
    // What Astra serves, from the document it holds: neither
    // `state.credential_registry_epoch`, which is only the floor the registry
    // was bootstrapped with, nor a number when no document is served.
    let credential_registry_epoch = service
        .approval_credentials()
        .registry
        .as_ref()
        .map(|document| document.credential_registry_epoch);
    let serving_epoch = service
        .issuer()
        .map(|issuer| issuer.authorization.issuer_epoch);
    let vault_copy_fingerprint = service
        .encrypted_vault()
        .map(|bytes| Fingerprint::of(&bytes));
    let report = OperatorAuthorityStatus {
        ca_epoch: state.ca_epoch,
        ca_fingerprint: state.ca_public_key.authority_fingerprint(),
        next_ca_fingerprint: state
            .ca_rotation
            .as_ref()
            .map(|rotation| rotation.next_ca_public_key.authority_fingerprint()),
        ca_tls_epoch: state.ca_tls_epoch,
        ca_tls_fingerprint: state.ca_tls_fingerprint,
        next_ca_tls_fingerprint: state
            .ca_tls_rotation
            .as_ref()
            .map(|rotation| rotation.next_ca_tls_fingerprint),
        issuer: state.issuer.as_ref().map(|issuer| OperatorIssuerStatus {
            recorded_epoch: issuer.issuer_epoch,
            serving_epoch,
            ca_epoch: issuer.authorization.ca_epoch,
            ca_tls_epoch: issuer.authorization.ca_tls_epoch,
            not_after: issuer.authorization.not_after,
        }),
        vault_copy_fingerprint,
        credential_registry_epoch,
    };
    drop(registry);
    (axum::http::StatusCode::OK, Json(report)).into_response()
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

/// The tunnel's connector to the door (lot 5a, §5.4).
///
/// It carries the request and the identity the gateway resolved, and decides
/// nothing: what the tunnel may open, and on which targets, is the door's.
/// The answer is the opening alone — the console's facts about it stay with
/// the console. A refusal crosses back as its class: the door has already
/// logged the full sentence with this connector, and the domain it describes
/// is not the caller's to read.
///
/// An unreadable body, a console action among them (the tunnel's request has
/// no such variant), is the same malformed request whatever was wrong with it.
async fn open(
    State(service): State<Arc<AstraService>>,
    relayed: Result<Json<RelayedOperatorOpen>, JsonRejection>,
) -> Response {
    let Json(relayed) = match relayed {
        Ok(relayed) => relayed,
        Err(rejection) => {
            tracing::warn!(
                route = "open",
                %rejection,
                "private operator route refused an unreadable opening"
            );
            return ServiceError::Protocol.into_response();
        }
    };
    let operator = relayed.operator;
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    // Detached from this handler: a dropped tunnel connection drops the
    // handler's future, and with it the volume gate, while the blocking key
    // write goes on. Spawned, the opening and its gate end together.
    let opening = tokio::spawn({
        let service = Arc::clone(&service);
        let connector = connector.clone();
        let request = relayed.request.into();
        async move { service.door(connector, request, now_unix()).await }
    })
    .await;
    let opening = match opening {
        Ok(opening) => opening,
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            return refuse(&operator, "open", ServiceError::Internal);
        }
    };
    match opening {
        Ok(DoorOutcome::Opened(opening)) => {
            (axum::http::StatusCode::OK, Json(opening.opened)).into_response()
        }
        // The delegation's public request replaces the file the console
        // writes: the tunnel has no `--out`, so it travels in the answer.
        Ok(DoorOutcome::IssuerRequested {
            request,
            opened: Some(opening),
        }) => {
            let mut opened = opening.opened;
            opened.delegation_request = Some(request);
            (axum::http::StatusCode::OK, Json(opened)).into_response()
        }
        Ok(_) => {
            tracing::error!(
                operator = %operator,
                "the door answered a tunnel opening with something other than a campaign"
            );
            refuse(&operator, "open", ServiceError::Internal)
        }
        Err(refusal) => refuse(&operator, "open", refusal.class()),
    }
}

/// Replaces the vault copy, and the credential document when one travels with
/// it, for an administrator relayed from the tunnel (§5.9).
///
/// The door decides and writes; this carries the request in and the
/// fingerprint back. Spawned like the opening, for the same reason: a dropped
/// connection must not release the volume gate while a file is being written.
/// What is logged is the operator and the fingerprint, never the content.
async fn vault_copy(
    State(service): State<Arc<AstraService>>,
    relayed: Result<Json<RelayedOperatorVaultCopy>, JsonRejection>,
) -> Response {
    use base64::Engine as _;

    let Json(relayed) = match relayed {
        Ok(relayed) => relayed,
        Err(rejection) => {
            // The status alone: serde's text quotes the string it choked on,
            // and that string is the vault.
            tracing::warn!(
                route = "vault-copy",
                status = %rejection.status(),
                "private operator route refused an unreadable vault copy"
            );
            // The one rejection with a meaning of its own: a body over the
            // bound, which the sender can tell apart from a malformed one.
            if rejection.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
                return rejection.status().into_response();
            }
            return ServiceError::Protocol.into_response();
        }
    };
    let operator = relayed.operator;
    let Ok(vault) =
        base64::engine::general_purpose::STANDARD.decode(relayed.copy.vault_base64.as_bytes())
    else {
        return refuse(&operator, "vault-copy", ServiceError::Protocol);
    };
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    let copy = tokio::spawn({
        let service = Arc::clone(&service);
        let request = DoorRequest::VaultCopy {
            vault: vault.into(),
            credentials: relayed.copy.credentials,
        };
        async move { service.door(connector, request, now_unix()).await }
    })
    .await;
    let copy = match copy {
        Ok(copy) => copy,
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            return refuse(&operator, "vault-copy", ServiceError::Internal);
        }
    };
    match copy {
        Ok(DoorOutcome::VaultCopied {
            fingerprint,
            credential_registry_epoch,
        }) => (
            axum::http::StatusCode::OK,
            Json(OperatorVaultCopied {
                fingerprint,
                credential_registry_epoch,
            }),
        )
            .into_response(),
        Ok(_) => {
            tracing::error!(
                operator = %operator,
                "the door answered a vault copy with something other than a copy"
            );
            refuse(&operator, "vault-copy", ServiceError::Internal)
        }
        // The two refusals a later attempt can pass, told apart from the
        // indistinct one because the sender retries them. This route answers
        // only an administrator, who already reads those operations in `pending`.
        Err(DoorRefusal::AlreadyOpen { .. } | DoorRefusal::CredentialsDuringRotation) => {
            refuse(&operator, "vault-copy", ServiceError::HeldBack)
        }
        Err(refusal) => refuse(&operator, "vault-copy", refusal.class()),
    }
}
