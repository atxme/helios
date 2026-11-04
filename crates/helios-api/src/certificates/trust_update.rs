//! The in-tunnel trust update (spec §8.1) and the coarse status of its
//! refusals.

use super::*;

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

/// The one status each refusal class is served as.
///
/// An extension trait rather than an inherent `impl` or a `From`, because
/// [`TrustUpdateRefusal`] is defined in `aether`, which carries no HTTP: the
/// refusal is the shared contract, and the status code it becomes on this
/// listener is this crate's business.
pub(crate) trait TrustUpdateRefusalStatus {
    fn status(self) -> StatusCode;
}

impl TrustUpdateRefusalStatus for TrustUpdateRefusal {
    fn status(self) -> StatusCode {
        match self {
            TrustUpdateRefusal::Protocol => StatusCode::BAD_REQUEST,
            TrustUpdateRefusal::Rejected => StatusCode::FORBIDDEN,
            TrustUpdateRefusal::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            TrustUpdateRefusal::Throttled => StatusCode::TOO_MANY_REQUESTS,
            TrustUpdateRefusal::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// The field name a `deny_unknown_fields` refusal names, if that is what failed.
///
/// Serde reports a field this binary does not know exactly like a malformed
/// body, and the two call for opposite actions: one is a broken client, the
/// other a gateway due an upgrade. Only the field **name** is lifted out — the
/// rest of the error quotes the payload, which carries certificate material
/// that has no business in a log line.
pub(super) fn unknown_field(error: &serde_json::Error) -> Option<String> {
    let rendered = error.to_string();
    let rest = rendered.strip_prefix("unknown field `")?;
    let (field, _) = rest.split_once('`')?;
    // A name is an identifier here; anything else means the shape moved and
    // this heuristic no longer holds, so it declines rather than guessing.
    field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then(|| field.to_string())
        .filter(|field| !field.is_empty())
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
            match unknown_field(&error) {
                // `deny_unknown_fields` is what a client newer than this
                // gateway runs into: it sends a field added after this binary
                // was built, and serde reports it as a parse error like any
                // other. Said plainly, that is a version skew, and it is worth
                // naming — the raw serde dump reads as a malformed request, so
                // the one action that fixes it (upgrade the gateway) is the one
                // nobody takes. It silently cost eleven days of failed renewals
                // between 2026-08-21 and 2026-09-01.
                Some(field) => tracing::warn!(
                    peer = %caller_key,
                    unknown_field = %field,
                    "trust update refused: this client sent a field this gateway does not know. \
                     The client is NEWER than this gateway — upgrade heliosd. Renewals keep \
                     failing until then."
                ),
                None => {
                    tracing::warn!(peer = %caller_key, %error, "trust update refused: unreadable body")
                }
            }
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
