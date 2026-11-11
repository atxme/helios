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
    OperatorIdentity, OperatorIssuerStatus, OperatorVaultCopied, RelayedOperatorCampaign,
    RelayedOperatorGatewayPublish, RelayedOperatorOpen, RelayedOperatorSignerResult,
    RelayedOperatorVaultCopy, MAX_OPERATOR_RELAY_BODY_BYTES,
    MAX_OPERATOR_VAULT_COPY_RELAY_BODY_BYTES, OPERATOR_CHAIN_ABANDON_ROUTE,
    OPERATOR_CHAIN_NEXT_ROUTE, OPERATOR_GATEWAY_PUBLISH_ROUTE, OPERATOR_OPEN_ROUTE,
    OPERATOR_OPERATION_ROUTE, OPERATOR_PENDING_ROUTE, OPERATOR_SIGNER_REQUEST_ROUTE,
    OPERATOR_SIGNER_RESULT_ROUTE, OPERATOR_STATUS_ROUTE, OPERATOR_VAULT_COPY_ROUTE,
    OPERATOR_VAULT_ROUTE,
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

/// The eleven private operator routes, for the listener of §8.3 to merge.
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
    let vault_copy_fingerprint = service
        .encrypted_vault()
        .map(|bytes| Fingerprint::of(&bytes));
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
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    let publication = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .door(
                    connector,
                    DoorRequest::GatewayIdentityPublish { epoch },
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
/// The door decides. A step that has not taken effect yet is the one refusal
/// whose sentence crosses back, in a `409`: it names what the operator still has
/// to do. Every other refusal is its class, as everywhere on this surface.
async fn chain_next(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedOperatorCampaign>,
) -> Response {
    let operator = relayed.operator;
    let connector = DoorConnector::Tunnel {
        operator: operator.clone(),
    };
    // Detached, as the other door writes: a dropped connection must not end
    // the plan's update half way.
    let step = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .door(connector, DoorRequest::ChainNext {}, now_unix())
                .await
        }
    })
    .await;
    let step = match step {
        Ok(step) => step,
        Err(error) => {
            tracing::error!(operator = %operator, %error, "the door task did not finish");
            return refuse(&operator, "chain-next", ServiceError::Internal);
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
                "the door answered a chain step with something other than a step"
            );
            refuse(&operator, "chain-next", ServiceError::Internal)
        }
        Err(refusal @ DoorRefusal::ChainStepIncomplete(_)) => {
            tracing::warn!(
                operator = %operator,
                route = "chain-next",
                "private operator route refused a step that has not taken effect"
            );
            (
                axum::http::StatusCode::CONFLICT,
                Json(OperatorChainRefusal {
                    message: refusal.to_string(),
                }),
            )
                .into_response()
        }
        Err(refusal) => refuse(&operator, "chain-next", refusal.class()),
    }
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
mod tests {
    use super::*;
    use crate::door::tests::{fixture, rewrite_registry};
    use crate::registry::CaPqRotation;
    use crate::service::ApprovalCredentials;
    use aether::certificates::approval::{
        AstraCredentialBinding, CredentialRegistry, CredentialState, MAX_CREDENTIAL_BINDINGS,
    };
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, MlDsa87Signature, TrustDomainId, WireGuardKey,
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
