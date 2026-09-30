use std::sync::Arc;

use aether::certificates::encoding::Id16;
use astra_channel::{
    InternalRefusal, PreparedTrustUpdate, PreparedTrustUpdateTransaction, RelayedOperationQuery,
    RelayedRotationRequest, RelayedTrustUpdatePreparation, ASTRA_INTERNAL_PREFIX,
    ASTRA_TRUST_UPDATE_PREFIX, ROTATION_OPERATION_ROUTE, ROTATION_REQUEST_PATH,
    TRUST_UPDATE_PREPARE_PATH,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};

use super::{now_unix, RenewalError};
use crate::service::AstraService;

/// Largest ordinary body this listener reads.
///
/// A rotation request carries two certificate requests and three ML-DSA-87
/// signatures; sixty-four kilobytes is well above that and far below what
/// an allocation driven by a caller would be. A relayed preparation adds a
/// peer snapshot and one PQ leaf to a request already bounded by
/// [`aether::certificates::transport::MAX_TRUST_UPDATE_REQUEST_BYTES`],
/// which stays inside the same ceiling. The operator result route has its
/// own 64 KiB canonical body plus the fixed typed-identity envelope; its
/// route-local limit is defined in [`crate::operator`].
pub const MAX_PRIVATE_BODY_BYTES: usize = 64 * 1024;

/// Builds the private router.
pub fn router(service: Arc<AstraService>) -> Router {
    Router::new()
        .route(ROTATION_REQUEST_PATH, post(request))
        .route(ROTATION_OPERATION_ROUTE, post(operation))
        .route(TRUST_UPDATE_PREPARE_PATH, post(prepare_trust_update))
        // The third surface this listener serves (spec §8.5). Its routes
        // live in their own module for the reason they have their own
        // prefix: a campaign belongs to no peer, and a refusal log has to
        // be able to say which of the three surfaces was probed.
        .merge(crate::operator::private_routes())
        .fallback(refuse_unknown_route)
        .layer(DefaultBodyLimit::max(MAX_PRIVATE_BODY_BYTES))
        .with_state(service)
}

/// `POST /internal/v1/trust-update/prepare` (spec §0.6).
///
/// The answer carries a transaction or nothing, and «nothing» is not an
/// error: the gateway's comparison and this authority's registry answer
/// two different questions, and where they disagree the honest reply is
/// that there is nothing to hand over.
async fn prepare_trust_update(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedTrustUpdatePreparation>,
) -> Response {
    let now = now_unix();
    match crate::distribution::prepare(&service, &relayed, now).await {
        Ok(Some((manifest, chunks))) => (
            StatusCode::OK,
            Json(PreparedTrustUpdate {
                transaction: Some(PreparedTrustUpdateTransaction { manifest, chunks }),
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::OK,
            Json(PreparedTrustUpdate { transaction: None }),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(route = TRUST_UPDATE_PREPARE_PATH, %error, "preparation refused");
            InternalRefusal::from(error.refusal()).into_response()
        }
    }
}

/// One refusal, logged with its real reason and answered with its class.
fn refuse(route: &str, error: RenewalError) -> Response {
    tracing::warn!(route, %error, "private renewal route refused");
    InternalRefusal::from(error.refusal()).into_response()
}

fn operation_id(raw: &str) -> Result<Id16, InternalRefusal> {
    Id16::parse_hex(raw).map_err(|_| InternalRefusal::Protocol)
}

async fn request(
    State(service): State<Arc<AstraService>>,
    Json(relayed): Json<RelayedRotationRequest>,
) -> Response {
    match super::open(
        &service,
        &relayed.caller_wg_public_key,
        relayed.request,
        now_unix(),
    )
    .await
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => refuse("request", error),
    }
}

async fn operation(
    State(service): State<Arc<AstraService>>,
    Path(raw): Path<String>,
    Json(query): Json<RelayedOperationQuery>,
) -> Response {
    let id = match operation_id(&raw) {
        Ok(id) => id,
        Err(refusal) => return refusal.into_response(),
    };
    match super::read(&service, &query.caller_wg_public_key, &id, now_unix()).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => refuse("operation", error),
    }
}

/// Everything this listener does not serve.
///
/// Named in the log rather than silently `404`: the public endpoint, the
/// operator routes and the gateway's own lifecycle prefix all land here,
/// and "the gateway probed something it should not" is worth reading.
async fn refuse_unknown_route(uri: Uri) -> StatusCode {
    tracing::warn!(
        path = %uri.path(),
        "private renewal listener: route refused; it serves only \
         {ASTRA_INTERNAL_PREFIX}* and {ASTRA_TRUST_UPDATE_PREFIX}*"
    );
    StatusCode::NOT_FOUND
}
