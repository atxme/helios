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
    OperatorAuthorityStatus, OperatorChainRefusal, OperatorChainStep, OperatorGatewayPublished,
    OperatorIdentity, OperatorIssuerStatus, OperatorVaultCopied, RelayedChainStep,
    RelayedOperatorCampaign, RelayedOperatorGatewayPublish, RelayedOperatorOpen,
    RelayedOperatorSignerResult, RelayedOperatorVaultCopy, MAX_OPERATOR_RELAY_BODY_BYTES,
    MAX_OPERATOR_VAULT_COPY_RELAY_BODY_BYTES, OPERATOR_CHAIN_ABANDON_ROUTE,
    OPERATOR_CHAIN_NEXT_ROUTE, OPERATOR_CHAIN_REOPEN_ROUTE, OPERATOR_GATEWAY_PUBLISH_ROUTE,
    OPERATOR_OPEN_ROUTE, OPERATOR_OPERATION_ROUTE, OPERATOR_PENDING_ROUTE,
    OPERATOR_SIGNER_REQUEST_ROUTE, OPERATOR_SIGNER_RESULT_ROUTE, OPERATOR_STATUS_ROUTE,
    OPERATOR_VAULT_COPY_ROUTE, OPERATOR_VAULT_ROUTE,
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

/// The twelve private operator routes, for the listener of §8.3 to merge.
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
        .route(
            OPERATOR_GATEWAY_PUBLISH_ROUTE,
            post(gateway_publish).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
        )
        .route(
            OPERATOR_CHAIN_NEXT_ROUTE,
            post(chain_next).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
        )
        .route(
            OPERATOR_CHAIN_REOPEN_ROUTE,
            post(chain_reopen).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
        )
        .route(
            OPERATOR_CHAIN_ABANDON_ROUTE,
            post(chain_abandon).layer(DefaultBodyLimit::max(MAX_OPERATOR_RELAY_BODY_BYTES)),
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
    let approval_credentials = service.approval_credentials();
    let credential_registry_epoch = approval_credentials
        .registry
        .as_ref()
        .map(|document| document.credential_registry_epoch);
    let revoked_peers = state
        .peers
        .values()
        .filter(|peer| peer.revoked)
        .map(|peer| peer.client_wg_public_key)
        .collect();
    let serving_epoch = service
        .issuer()
        .map(|issuer| issuer.authorization.issuer_epoch);
    let held_copy = service.encrypted_vault();
    let vault_copy_fingerprint = held_copy.as_ref().map(|bytes| Fingerprint::of(bytes));
    let vault_copy_revision = held_copy
        .as_ref()
        .map(|bytes| crate::door::revision_of(bytes));
    let chain = crate::door::chain_view(&service);
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
        vault_copy_revision,
        credential_registry_epoch,
        revoked_peers,
        served_credentials: approval_credentials.registry.clone(),
        chain,
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
        // A chain step is the campaign it opened, with the public request of
        // its delegation step when it has one. A step that opened nothing is
        // the refusal below: the tunnel's chain always opens one.
        Ok(DoorOutcome::ChainStep {
            opened: Some(opening),
            delegation_request,
            ..
        }) => {
            let mut opened = opening.opened;
            opened.delegation_request = delegation_request;
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
            replace_newer: relayed.copy.replace_newer,
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

/// Lets the signed gateway transition of one epoch leave the authority, for an
/// administrator relayed from the tunnel (F14 lot 6b).
///
/// The door marks it published and relays it, and it asks again on every call:
/// a publication of an epoch already marked answers again, and `relayed` says
/// whether the gateway confirmed this one. Spawned like the other door writes,
/// so a dropped connection cannot end the relay half way.
async fn gateway_publish(
    State(service): State<Arc<AstraService>>,
    relayed: Result<Json<RelayedOperatorGatewayPublish>, JsonRejection>,
) -> Response {
    let Json(relayed) = match relayed {
        Ok(relayed) => relayed,
        Err(rejection) => {
            tracing::warn!(
                route = "gateway-identity-publish",
                status = %rejection.status(),
                "private operator route refused an unreadable publication"
            );
            return ServiceError::Protocol.into_response();
        }
    };
    let operator = relayed.operator;
    let epoch = relayed.request.epoch;
    let transition_fingerprint = relayed.request.transition_fingerprint;
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    let publication = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .door(
                    connector,
                    DoorRequest::GatewayIdentityPublish {
                        epoch,
                        transition_fingerprint,
                    },
                    now_unix(),
                )
                .await
        }
    })
    .await;
    let publication = match publication {
        Ok(publication) => publication,
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            return refuse(
                &operator,
                "gateway-identity-publish",
                ServiceError::Internal,
            );
        }
    };
    match publication {
        Ok(DoorOutcome::Published {
            epoch, confirmed, ..
        }) => (
            axum::http::StatusCode::OK,
            Json(OperatorGatewayPublished {
                epoch,
                relayed: confirmed,
            }),
        )
            .into_response(),
        Ok(_) => {
            tracing::error!(
                operator = %operator,
                "the door answered a publication with something other than a publication"
            );
            refuse(
                &operator,
                "gateway-identity-publish",
                ServiceError::Internal,
            )
        }
        Err(refusal) => refuse(&operator, "gateway-identity-publish", refusal.class()),
    }
}

/// Opens the next step of the certificate chain, once the step in progress
/// has taken effect, for an administrator relayed from the tunnel (F14 lot 6b).
///
/// The door decides. A plan refusal (`ChainStepIncomplete` and the refusals
/// of `reopen`) is the one class whose sentence crosses back, in a `409`: it
/// names what the operator still has to do. Every other refusal is its class,
/// as everywhere on this surface.
async fn chain_next(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedChainStep>,
) -> Response {
    chain_step(service, relayed, "chain-next", |expected_step| {
        DoorRequest::ChainNext { expected_step }
    })
    .await
}

/// Redeposits the chain's current step once its campaign has ended, for an
/// administrator relayed from the tunnel (F14-g). Answers as `next` does.
async fn chain_reopen(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedChainStep>,
) -> Response {
    chain_step(service, relayed, "chain-reopen", |expected_step| {
        DoorRequest::ChainReopen { expected_step }
    })
    .await
}

/// The shared body of `next` and `reopen`: one door request, its step or its
/// refusal.
async fn chain_step(
    service: Arc<AstraService>,
    relayed: RelayedChainStep,
    route: &'static str,
    request: impl FnOnce(Option<usize>) -> DoorRequest + Send + 'static,
) -> Response {
    let operator = relayed.operator;
    let expected_step = relayed.expected_step;
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    // Detached, as the other door writes: a dropped connection must not end
    // the plan's update half way.
    let step = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .door(connector, request(expected_step), now_unix())
                .await
        }
    })
    .await;
    let step = match step {
        Ok(step) => step,
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            return refuse(&operator, route, ServiceError::Internal);
        }
    };
    match step {
        Ok(DoorOutcome::ChainStep {
            opened: Some(opening),
            delegation_request,
            ..
        }) => {
            let mut opened = opening.opened;
            opened.delegation_request = delegation_request;
            (
                axum::http::StatusCode::OK,
                Json(OperatorChainStep::Opened(Box::new(opened))),
            )
                .into_response()
        }
        Ok(DoorOutcome::ChainStep { opened: None, .. }) => (
            axum::http::StatusCode::OK,
            Json(OperatorChainStep::Finished),
        )
            .into_response(),
        Ok(_) => {
            tracing::error!(
                operator = %operator,
                route,
                "the door answered a chain step with something other than a step"
            );
            refuse(&operator, route, ServiceError::Internal)
        }
        Err(refusal) if is_plan_refusal(&refusal) => {
            tracing::warn!(
                operator = %operator,
                route,
                "private operator route refused a chain step"
            );
            (
                axum::http::StatusCode::CONFLICT,
                Json(OperatorChainRefusal {
                    message: refusal.to_string(),
                }),
            )
                .into_response()
        }
        Err(refusal) => refuse(&operator, route, refusal.class()),
    }
}

/// The refusals of a chain step whose sentence the operator reads: there is no
/// plan or it is finished, the step has not taken effect, has not been opened,
/// is still open, or the plan has moved on from the step the caller expected.
fn is_plan_refusal(refusal: &DoorRefusal) -> bool {
    matches!(
        refusal,
        DoorRefusal::NoChain
            | DoorRefusal::ChainFinished
            | DoorRefusal::ChainStepIncomplete(_)
            | DoorRefusal::ChainStepNotDeposited
            | DoorRefusal::ChainStepLanded
            | DoorRefusal::ChainStepStillOpen { .. }
            | DoorRefusal::ChainStepApproved { .. }
            | DoorRefusal::ChainStepMoved { .. }
    )
}

/// Drops the certificate chain's plan, for an administrator relayed from the
/// tunnel (F14 lot 6b). What was approved keeps its effect: the door says so.
async fn chain_abandon(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let operator = relayed.operator;
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    let abandoned = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .door(connector, DoorRequest::ChainAbandon {}, now_unix())
                .await
        }
    })
    .await;
    match abandoned {
        Ok(Ok(DoorOutcome::ChainAbandoned { .. })) => {
            axum::http::StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(_)) => {
            tracing::error!(
                operator = %operator,
                "the door answered an abandon with something other than an abandon"
            );
            refuse(&operator, "chain-abandon", ServiceError::Internal)
        }
        Ok(Err(refusal)) => refuse(&operator, "chain-abandon", refusal.class()),
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            refuse(&operator, "chain-abandon", ServiceError::Internal)
        }
    }
}

#[cfg(test)]
mod plan_refusal_tests {
    use super::*;

    /// The sentences of a plan that has none to give or none left cross as a refusal, like
    /// the five that precede them.
    #[test]
    fn no_chain_and_a_finished_chain_are_plan_refusals() {
        assert!(is_plan_refusal(&DoorRefusal::NoChain));
        assert!(is_plan_refusal(&DoorRefusal::ChainFinished));
        assert!(!is_plan_refusal(&DoorRefusal::NoVault));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::tests::{fixture, rewrite_registry};
    use crate::registry::CaPqRotation;
    use crate::service::ApprovalCredentials;
    use aether::certificates::approval::{
        AstraCredentialBinding, CredentialRegistry, CredentialState, MAX_CREDENTIAL_BINDINGS,
    };
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, Id16, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::status::{
        AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget, CertificateKind,
    };
    use aether::certificates::CERTIFICATE_FORMAT_VERSION;
    use astra_channel::{OperatorIdentity, MAX_OPERATOR_STATUS_BYTES};

    const DOMAIN: [u8; 16] = [1; 16];
    const GATEWAY: [u8; 32] = [1; 32];

    /// A well-formed COSE key. The status never verifies the document, so the
    /// key only has to be the shape a real one is.
    fn cose_key() -> Vec<u8> {
        let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        key.extend_from_slice(&[1; 32]);
        key.extend_from_slice(&[0x22, 0x58, 0x20]);
        key.extend_from_slice(&[2; 32]);
        key
    }

    /// A credential document of `bindings` rows, each signed under `ca_private`.
    fn document(ca_private: &[u8], registry_epoch: u64, bindings: u8) -> Box<CredentialRegistry> {
        let rows = (1..=bindings)
            .map(|index| {
                AstraCredentialBinding {
                    format_version: CERTIFICATE_FORMAT_VERSION,
                    credential_id: vec![index; 16],
                    credential_public_key: cose_key(),
                    aaguid: [0; 16],
                    trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
                    gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
                    state: CredentialState::Active,
                    credential_epoch: 1,
                    credential_registry_epoch: registry_epoch,
                    ca_epoch: 1,
                    created_at: 500,
                    ca_pq_signature: MlDsa87Signature::placeholder(),
                }
                .sign(ca_private)
                .expect("sign")
            })
            .collect();
        Box::new(CredentialRegistry {
            trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
            ca_epoch: 1,
            credential_registry_epoch: registry_epoch,
            bindings: rows,
        })
    }

    /// Serves `document` as the one Astra holds for approvals.
    fn serve(service: &AstraService, document: Box<CredentialRegistry>) {
        *service.approval_credentials.write().expect("credentials") =
            Arc::new(ApprovalCredentials::from_document(document));
    }

    /// The status as the tunnel relays it: the handler's own answer, read back
    /// under the bound the channel client applies to it.
    async fn answer(service: &Arc<AstraService>) -> Vec<u8> {
        let response = status(
            State(Arc::clone(service)),
            Json(RelayedOperatorCampaign {
                operator: OperatorIdentity::DevLoopback,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        axum::body::to_bytes(response.into_body(), MAX_OPERATOR_STATUS_BYTES)
            .await
            .expect("the answer stays within the operator bound")
            .to_vec()
    }

    fn signing_operation(
        campaign_seed: u8,
        operation_seed: u8,
        created_at: u64,
        expires_at: u64,
        scope: CampaignScope,
        reason: String,
    ) -> crate::signing::SigningOperation {
        let campaign =
            Box::new(AstraRotationCampaign {
                format_version: CERTIFICATE_FORMAT_VERSION,
                campaign_id: Id16::new([campaign_seed; 16]).expect("campaign ID"),
                trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
                server_name: "gateway.example".into(),
                created_at,
                expires_at,
                scope,
                targets: vec![CampaignTarget {
                    certificate_kind: CertificateKind::ClientPq,
                    identity_key: WireGuardKey::from_bytes([3; 32]),
                    epoch: 1,
                    generation: 4,
                    active_tls_certificate_fingerprint:
                        aether::certificates::encoding::Fingerprint::of(b"active TLS"),
                    active_pq_certificate_fingerprint:
                        aether::certificates::encoding::Fingerprint::of(b"active PQ"),
                }],
                reason,
                requested_by: "operator workstation".into(),
                policy_fingerprint: aether::certificates::encoding::Fingerprint::of(b"policy"),
                required_credentials: scope.required_credentials(),
            });
        let request = Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: Id16::new([operation_seed; 16]).expect("operation ID"),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: aether::certificates::encoding::Fingerprint::of(b"vault"),
            required_credentials: campaign.required_credentials,
            created_at,
            expires_at,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        });
        crate::signing::SigningOperation::new(campaign, request, created_at)
            .expect("valid operator operation")
    }

    async fn pending_answer(service: &Arc<AstraService>) -> Vec<u8> {
        let response = pending(
            State(Arc::clone(service)),
            Json(RelayedOperatorCampaign {
                operator: OperatorIdentity::DevLoopback,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        axum::body::to_bytes(response.into_body(), MAX_OPERATOR_STATUS_BYTES)
            .await
            .expect("pending list stays bounded")
            .to_vec()
    }

    #[tokio::test]
    async fn pending_lists_only_live_unapproved_campaigns_in_deadline_order() {
        let directory = tempfile::tempdir().expect("temp dir");
        let service = fixture(directory.path());
        serve(
            &service,
            Box::new(CredentialRegistry {
                trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
                ca_epoch: 1,
                credential_registry_epoch: 1,
                bindings: Vec::new(),
            }),
        );
        let now = now_unix();
        let later = signing_operation(
            11,
            21,
            now,
            now + 240,
            CampaignScope::FleetLeafs,
            "later deadline".into(),
        );
        let later_id = later.operation_id;
        let sooner = signing_operation(
            12,
            22,
            now,
            now + 120,
            CampaignScope::FleetLeafs,
            "sooner deadline".into(),
        );
        let sooner_id = sooner.operation_id;
        let mut approved = signing_operation(
            13,
            23,
            now,
            now + 180,
            CampaignScope::FleetLeafs,
            "already approved".into(),
        );
        approved.approve_without_ceremony();
        let expired = signing_operation(
            14,
            24,
            now.saturating_sub(400),
            now.saturating_sub(100),
            CampaignScope::FleetLeafs,
            "expired".into(),
        );
        {
            let mut store = service.signing.lock().await;
            store.open(later, now).expect("later operation");
            store.open(sooner, now).expect("sooner operation");
            store.open(approved, now).expect("approved operation");
            store
                .open(expired, now.saturating_sub(400))
                .expect("expired operation");
        }

        let body = pending_answer(&service).await;
        let list: aether::certificates::transport::OperatorPendingList =
            serde_json::from_slice(&body).expect("pending list");

        assert_eq!(list.operations.len(), 2);
        assert_eq!(list.operations[0].operation_id, sooner_id);
        assert_eq!(list.operations[0].reason, "sooner deadline");
        assert_eq!(list.operations[0].target_count, 1);
        assert_eq!(list.operations[0].required_credentials, 1);
        assert_eq!(list.operations[1].operation_id, later_id);
        assert!(!body
            .windows(b"capability".len())
            .any(|part| part == b"capability"));

        let relayed = || {
            Json(RelayedOperatorCampaign {
                operator: OperatorIdentity::DevLoopback,
            })
        };
        let operation_response = operation(
            State(Arc::clone(&service)),
            Path(sooner_id.to_string()),
            relayed(),
        )
        .await;
        assert_eq!(operation_response.status(), axum::http::StatusCode::OK);
        let operation_view: crate::signing::SigningOperationView = serde_json::from_slice(
            &axum::body::to_bytes(operation_response.into_body(), MAX_OPERATOR_STATUS_BYTES)
                .await
                .expect("operation view stays bounded"),
        )
        .expect("operation view");
        assert_eq!(operation_view.operation_id, sooner_id);
        assert_eq!(
            operation_view.state,
            crate::signing::SigningOperationState::AwaitingOperator
        );
        assert!(operation_view.signer_request_token.is_some());
        assert!(operation_view.vault_token.is_none());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!(
                "Bearer {}",
                operation_view
                    .signer_request_token
                    .as_deref()
                    .expect("token")
            )
            .parse()
            .expect("authorization header"),
        );
        let signer_response = signer_request(
            State(Arc::clone(&service)),
            Path(sooner_id.to_string()),
            headers,
            relayed(),
        )
        .await;
        assert_eq!(signer_response.status(), axum::http::StatusCode::OK);
        let signer: crate::service::SignerRequestResponse = serde_json::from_slice(
            &axum::body::to_bytes(signer_response.into_body(), MAX_OPERATOR_STATUS_BYTES)
                .await
                .expect("signer request stays bounded"),
        )
        .expect("signer request");
        assert_eq!(signer.signer_request.operation_id, sooner_id);
        assert_eq!(signer.campaign.reason, "sooner deadline");

        let unknown = operation(
            State(Arc::clone(&service)),
            Path("01010101010101010101010101010101".into()),
            relayed(),
        )
        .await;
        let malformed = operation(
            State(Arc::clone(&service)),
            Path("not-hex".into()),
            relayed(),
        )
        .await;
        assert_eq!(unknown.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(malformed.status(), unknown.status());
        let unknown_body = axum::body::to_bytes(unknown.into_body(), 1024)
            .await
            .expect("refusal body");
        let malformed_body = axum::body::to_bytes(malformed.into_body(), 1024)
            .await
            .expect("refusal body");
        assert_eq!(unknown_body, malformed_body);

        let mut invalid_headers = axum::http::HeaderMap::new();
        invalid_headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer invalid".parse().expect("authorization header"),
        );
        let refused_signer = signer_request(
            State(Arc::clone(&service)),
            Path(sooner_id.to_string()),
            invalid_headers,
            relayed(),
        )
        .await;
        assert_eq!(refused_signer.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pending_is_empty_when_only_an_expired_campaign_remains() {
        let directory = tempfile::tempdir().expect("temp dir");
        let service = fixture(directory.path());
        let now = now_unix();
        let expired = signing_operation(
            31,
            41,
            now.saturating_sub(400),
            now.saturating_sub(100),
            CampaignScope::FleetLeafs,
            "expired campaign".into(),
        );
        service
            .signing
            .lock()
            .await
            .open(expired, now.saturating_sub(400))
            .expect("expired operation can be retained until listing");

        let list: aether::certificates::transport::OperatorPendingList =
            serde_json::from_slice(&pending_answer(&service).await).expect("pending list");

        assert!(list.operations.is_empty());
    }

    #[tokio::test]
    async fn operation_view_capability_reads_only_the_named_encrypted_vault() {
        let directory = tempfile::tempdir().expect("temp dir");
        let service = fixture(directory.path());
        let now = now_unix();
        let held_vault = b"vault".to_vec();
        let fingerprint = Fingerprint::of(&held_vault);
        *service.encrypted_vault.write().expect("vault lock") = Some(Arc::new(held_vault.clone()));
        let stored_operation = signing_operation(
            51,
            61,
            now,
            now + 300,
            CampaignScope::IssuerDelegation,
            "renew delegated issuer".into(),
        );
        let operation_id = stored_operation.operation_id;
        service
            .signing
            .lock()
            .await
            .open(stored_operation, now)
            .expect("open operator operation");

        let relayed = || {
            Json(RelayedOperatorCampaign {
                operator: OperatorIdentity::DevLoopback,
            })
        };
        let operation_response = operation(
            State(Arc::clone(&service)),
            Path(operation_id.to_string()),
            relayed(),
        )
        .await;
        assert_eq!(operation_response.status(), axum::http::StatusCode::OK);
        let view: crate::signing::SigningOperationView = serde_json::from_slice(
            &axum::body::to_bytes(operation_response.into_body(), MAX_OPERATOR_STATUS_BYTES)
                .await
                .expect("operation view"),
        )
        .expect("view");
        let token = view.vault_token.expect("issuer scope opens the vault");
        assert!(view.signer_request_token.is_some());

        let mut authorized = axum::http::HeaderMap::new();
        authorized.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .expect("authorization header"),
        );
        let copied = vault(
            State(Arc::clone(&service)),
            Path(fingerprint.to_string()),
            authorized.clone(),
            relayed(),
        )
        .await;
        assert_eq!(copied.status(), axum::http::StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(copied.into_body(), MAX_OPERATOR_STATUS_BYTES)
                .await
                .expect("vault response"),
            held_vault
        );

        let wrong_fingerprint = vault(
            State(Arc::clone(&service)),
            Path(Fingerprint::of(b"another vault").to_string()),
            authorized.clone(),
            relayed(),
        )
        .await;
        assert_eq!(
            wrong_fingerprint.status(),
            axum::http::StatusCode::FORBIDDEN
        );
        let missing_token = vault(
            State(Arc::clone(&service)),
            Path(fingerprint.to_string()),
            axum::http::HeaderMap::new(),
            relayed(),
        )
        .await;
        assert_eq!(missing_token.status(), axum::http::StatusCode::BAD_REQUEST);
        let malformed_path = vault(
            State(Arc::clone(&service)),
            Path("not-a-fingerprint".into()),
            authorized,
            relayed(),
        )
        .await;
        assert_eq!(malformed_path.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_names_revoked_peers() {
        let directory = tempfile::tempdir().expect("temp dir");
        let service = fixture(directory.path());
        let laptop = WireGuardKey::from_bytes([3; 32]);
        service
            .registry
            .lock()
            .await
            .revoke(&laptop, 1, 1_000)
            .expect("revoked");

        let service = Arc::new(service);
        let report: OperatorAuthorityStatus =
            serde_json::from_slice(&answer(&service).await).expect("status");

        assert_eq!(report.revoked_peers, vec![laptop]);
    }

    /// The revision of the held copy travels in the status, and it is absent
    /// without a copy.
    #[tokio::test]
    async fn status_carries_the_revision_of_the_held_copy() {
        let directory = tempfile::tempdir().expect("temp dir");
        let service = fixture(directory.path());
        let domain = service.registry.lock().await.state().trust_domain_id;
        let held = serde_json::to_vec(&serde_json::json!({
            "format_version": 1,
            "trust_domain_id": domain,
            "revision": 3,
        }))
        .expect("vault");
        *service.encrypted_vault.write().expect("vault lock") = Some(Arc::new(held));
        let service = Arc::new(service);
        let report: OperatorAuthorityStatus =
            serde_json::from_slice(&answer(&service).await).expect("status");
        assert_eq!(report.vault_copy_revision, Some(3));

        *service.encrypted_vault.write().expect("vault lock") = None;
        let report: OperatorAuthorityStatus =
            serde_json::from_slice(&answer(&service).await).expect("status");
        assert_eq!(report.vault_copy_revision, None);
    }

    #[tokio::test]
    // The daemon test `the_overlap_keeps_serving_the_outgoing_document` owns the
    // invariant that the outgoing document stays in service. This one checks
    // only that the status reports what is held, while the rotation is pending.
    async fn status_reports_the_held_document_while_a_rotation_is_pending() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, next) = generate_ml_dsa_87_keypair().expect("next CA-PQ");
        let service = fixture(directory.path());
        rewrite_registry(&service, |state| {
            state.ca_rotation = Some(CaPqRotation {
                next_ca_epoch: 2,
                next_ca_public_key: next,
                activation_at: 1_000,
                retire_active_at: 5_000,
            });
        })
        .await;
        let outgoing = document(&ca_private, 1, 2);
        serve(&service, outgoing.clone());

        let service = Arc::new(service);
        let report: OperatorAuthorityStatus =
            serde_json::from_slice(&answer(&service).await).expect("status");

        assert!(report.next_ca_fingerprint.is_some());
        assert_eq!(report.credential_registry_epoch, Some(1));
        assert_eq!(report.served_credentials, Some(outgoing));
    }

    #[tokio::test]
    async fn status_fits_the_status_bound_at_the_binding_ceiling() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let service = fixture(directory.path());
        serve(
            &service,
            document(&ca_private, 1, MAX_CREDENTIAL_BINDINGS as u8),
        );
        // Both workstations of the fixture are revoked: the answer names them.
        {
            let mut registry = service.registry.lock().await;
            for seed in [2, 3] {
                registry
                    .revoke(&WireGuardKey::from_bytes([seed; 32]), 1, 1_000)
                    .expect("revoked");
            }
        }

        let service = Arc::new(service);
        let body = answer(&service).await;
        let report: OperatorAuthorityStatus = serde_json::from_slice(&body).expect("status");

        assert_eq!(
            report.served_credentials.expect("document").bindings.len(),
            MAX_CREDENTIAL_BINDINGS
        );
        assert_eq!(report.revoked_peers.len(), 2);
        assert!(
            body.len() <= MAX_OPERATOR_STATUS_BYTES,
            "the status took {} bytes, over the status bound",
            body.len()
        );
    }
}
