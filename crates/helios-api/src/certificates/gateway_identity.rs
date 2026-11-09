//! The gateway's own identity: renewal, the transition it installs, aborts or
//! rolls back, and the CA transition.

use super::*;

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

/// A service rollback, as the console displays it back (spec §4.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRollbackView {
    /// The staged generation whose overlap this selection lives in.
    pub gateway_identity_epoch: u64,
    /// The leaf now selected — always the outgoing one.
    pub selected_certificate_fingerprint: String,
    /// When the selection lapses on its own, at most the overlap's `not_after`.
    pub expires_at: u64,
    /// `true` when this exact authorization was already applied.
    pub already_present: bool,
}

/// A staged anchor rotation, as the console displays it back (spec §9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDecisionView {
    /// The generation in service. It does not move here.
    pub ca_epoch: u64,
    pub next_ca_epoch: u64,
    /// The incoming anchor, for the operator to compare with the companion.
    pub next_ca_fingerprint: String,
    /// From this instant both anchors verify.
    pub activation_at: u64,
    /// When the outgoing anchor is retired and the epoch finally moves.
    pub not_after: u64,
    /// `true` when this exact document was already applied.
    pub already_present: bool,
}

/// The lifecycle gestures the console drives on this daemon's own registry
/// (spec §12.2).
///
/// Separate from [`TrustUpdateHandler`] because one of them needs something
/// that handler never touches: the TPM unlock material. A gateway that reads
/// its registry can answer every question of the lifecycle screen; only one
/// that can open its own vault can prepare a key, and wiring the two together
/// would close the screen on a daemon that merely cannot seal.
///
/// The anchor rotation of §9.1 sits here rather than beside the trust updates
/// for the plainer reason: it is a write to the same registry, under the same
/// lock, and a second door onto that file is the failure this module exists to
/// avoid.
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

    /// Selects the outgoing leaf for the rest of the overlap (spec §4.4).
    async fn install_rollback(
        &self,
        authorization: Box<aether::certificates::status::CertificateServiceRollbackAuthorization>,
    ) -> Result<GatewayRollbackView, GatewayActionRefusal>;

    /// Stages a rotation of the domain anchor `CA-PQ` (spec §9.1).
    async fn install_ca_transition(
        &self,
        transition: Box<aether::certificates::authority::CaTransition>,
    ) -> Result<AnchorDecisionView, GatewayActionRefusal>;
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

/// `POST /api/certificates/gateway-transition/rollback`, on the admin surface.
pub async fn gateway_transition_rollback(
    State(s): State<AppState>,
    Json(authorization): Json<
        aether::certificates::status::CertificateServiceRollbackAuthorization,
    >,
) -> Response {
    let Some(handler) = s.gateway_identity.as_ref() else {
        return gateway_identity_absent();
    };
    match handler.install_rollback(Box::new(authorization)).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// `POST /api/certificates/ca-transition`, on the admin surface.
pub async fn ca_transition_install(
    State(s): State<AppState>,
    Json(transition): Json<aether::certificates::authority::CaTransition>,
) -> Response {
    let Some(handler) = s.gateway_identity.as_ref() else {
        return gateway_identity_absent();
    };
    match handler.install_ca_transition(Box::new(transition)).await {
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

#[cfg(test)]
#[path = "gateway_identity_tests.rs"]
mod tests;
