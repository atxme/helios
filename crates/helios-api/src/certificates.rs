//! In-tunnel certificate lifecycle API.
//!
//! - `POST /api/key-negotiation/trust-update` lives **inside the WireGuard
//!   tunnel**, behind [`crate::auth::require_peer`]. It is how an Orion that
//!   still has a working tunnel learns about transitions (spec §8.1).
//! - `POST /api/key-negotiation/stage-commit` carries an ordinary client commit
//!   through that same tunnel.
//!
//! The `/internal/v1/certificates/*` surface belongs on a separate listener on
//! the private Astra–Helios veth. It is not mounted by this router yet. In
//! particular there is deliberately no in-tunnel `stage` route: Astra sends a
//! stage authorization directly to Helios over the veth and receives the
//! signed receipt there (spec §§7.2 and 8.1.2).
//!
//! # Why the public route is not a fallback for the private one
//!
//! An ordinary renewal request and its final commit travel in the tunnel,
//! because that is what proves the peer: the source address resolves to exactly
//! one admitted `/32`, and no proxy header is ever consulted. Helios relays the
//! request to Astra; the stage authorization and receipt never transit through
//! Orion. Recovery without a tunnel reaches Astra publicly, then uses the same
//! private veth surface.
//!
//! # Why the errors are coarse
//!
//! `400`, `401`, `403`, `413`, `415`, `500` — nothing else, and none of them
//! describes the certificate state. The detailed reason goes to the gateway's
//! protected log. This is the same rule the public QUIC port follows with its
//! three codes: an error taxonomy on an authenticated-but-hostile caller is an
//! oracle on other peers' generations.

use aether::certificates::{
    client::{ClientCertificateRotationGrant, ClientCertificateStageCommit},
    status::AstraCertificateStatus,
    transport::{
        AuthenticatedTrustUpdateRequest, TrustUpdateChunk, TrustUpdateTransactionManifest,
        MAX_TRUST_UPDATE_REQUEST_BYTES,
    },
};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

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

/// A commit and the grant that authorizes it (spec §7.3).
///
/// The two travel together because the gateway needs both: the signatures
/// prove who is committing, the grant proves the authority released anything
/// at all. A commit alone would let a client that holds its own two private
/// keys — which it always does, it generated them — activate a candidate the
/// authority never granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageCommitRequest {
    pub commit: ClientCertificateStageCommit,
    pub grant: ClientCertificateRotationGrant,
}

/// Why a trust update was refused, in the only shapes the API may report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustUpdateRefusal {
    /// Unusable message: malformed body, wrong version.
    Protocol,
    /// Authenticated transport, refused identity: another peer, another
    /// gateway, a certificate or signature that does not verify.
    Rejected,
    /// The caller is behind, and the gateway holds no signed object to bring
    /// it forward. Distinct from "you are current" on purpose: answering an
    /// empty update to a client that is provably out of date would tell it the
    /// opposite of the truth, and it would stop asking.
    Unavailable,
    /// The gateway failed on its own side.
    Internal,
}

/// The gateway side of a trust update, implemented by the daemon.
///
/// A trait for the same reason the PSK release is one: the API process must
/// never hold the certificate registry's lock or a WireGuard backend. It hands
/// an authenticated request to whatever owns the serializer.
#[async_trait]
pub trait TrustUpdateHandler: Send + Sync {
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

/// Private Astra-to-Helios staging contract.
///
/// This trait deliberately has no route in the in-tunnel router. The future
/// veth listener owns its mTLS authentication and calls it only for an Astra
/// peer pinned by the local trust domain.
#[async_trait]
pub trait AstraStageHandler: Send + Sync {
    async fn stage_from_astra(
        &self,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<aether::certificates::client::GatewayCertificateStageReceipt>, TrustUpdateRefusal>;
}

/// Tombstone for the pre-amendment Orion-to-Helios staging route.
///
/// The global router serves the web application as its fallback, including for
/// unknown paths. Keeping this explicit `404` prevents a retired API call from
/// receiving an HTML `200` that a client could mistake for a protocol answer.
pub async fn retired_in_tunnel_stage() -> StatusCode {
    StatusCode::NOT_FOUND
}

impl TrustUpdateRefusal {
    fn status(self) -> StatusCode {
        match self {
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Rejected => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
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
            tracing::warn!(peer = %caller_key, %error, "trust update refused: unreadable body");
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

/// `POST /api/key-negotiation/stage-commit`, inside the tunnel (spec §7.3).
pub async fn stage_commit(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    body: Bytes,
) -> StatusCode {
    let Some(caller_key) = caller.public_key.as_deref() else {
        return StatusCode::UNAUTHORIZED;
    };
    if body.len() > MAX_TRUST_UPDATE_REQUEST_BYTES {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{
        Fingerprint, Id16, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::transport::TrustUpdateRequest;
    use aether::certificates::CERTIFICATE_PROTOCOL_VERSION;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    use aether::{NetworkConfig, TunnelState};
    use axum::body::to_bytes;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, mpsc, RwLock};

    const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    struct SpyHandler {
        answer: Result<TrustUpdateResponse, TrustUpdateRefusal>,
        seen: Mutex<Option<String>>,
    }

    #[async_trait]
    impl TrustUpdateHandler for SpyHandler {
        async fn trust_update(
            &self,
            caller_wg_public_key: &str,
            _request: AuthenticatedTrustUpdateRequest,
        ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
            *self.seen.lock().unwrap() = Some(caller_wg_public_key.to_string());
            self.answer.clone()
        }

        async fn stage_commit(
            &self,
            _caller_wg_public_key: &str,
            _request: Box<StageCommitRequest>,
        ) -> Result<(), TrustUpdateRefusal> {
            Ok(())
        }
    }

    fn state_with(handler: Option<Arc<SpyHandler>>) -> AppState {
        let network = NetworkConfig::default();
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (psk_tx, _psk_rx) = mpsc::channel(8);
        let state = AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(TunnelState::Up)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        match handler {
            Some(handler) => state.with_trust_update(handler),
            None => state,
        }
    }

    fn caller(public_key: Option<&str>) -> crate::auth::Caller {
        crate::auth::Caller {
            source: "100.64.1.2".parse().unwrap(),
            name: "workstation".into(),
            public_key: public_key.map(str::to_string),
            admin: false,
            dev_loopback: false,
        }
    }

    /// A syntactically complete request. Its signature is never reached here:
    /// the API parses and forwards, and every refusal it produces on its own
    /// happens before any verification.
    fn body() -> Bytes {
        let request = AuthenticatedTrustUpdateRequest {
            request: TrustUpdateRequest {
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                request_id: Id16::new([1; 16]).unwrap(),
                trust_domain_id: TrustDomainId::new([2; 16]).unwrap(),
                gateway_wg_public_key: WireGuardKey::parse(GATEWAY_KEY).unwrap(),
                client_wg_public_key: WireGuardKey::parse(CLIENT_KEY).unwrap(),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                astra_service_key_epoch: 1,
                issuer_epoch: 1,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                client_identity_generation: 4,
                active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"a"),
                active_gateway_certificate_fingerprint: Fingerprint::of(b"b"),
                active_client_tls_certificate_fingerprint: Fingerprint::of(b"c"),
                active_client_pq_certificate_fingerprint: Fingerprint::of(b"d"),
                client_pq_certificate_fingerprint: Fingerprint::of(b"e"),
            },
            certificate: PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: "orion".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: CLIENT_KEY.into(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            ml_dsa_87_signature: MlDsa87Signature::placeholder(),
        };
        Bytes::from(serde_json::to_vec(&request).unwrap())
    }

    fn spy(answer: Result<TrustUpdateResponse, TrustUpdateRefusal>) -> Arc<SpyHandler> {
        Arc::new(SpyHandler {
            answer,
            seen: Mutex::new(None),
        })
    }

    fn empty_response() -> TrustUpdateResponse {
        TrustUpdateResponse {
            status: None,
            manifest: None,
            chunk: None,
        }
    }

    /// The key the handler receives is the one the transport proved, never the
    /// one the body claims.
    #[tokio::test]
    async fn an_accepted_request_forwards_the_source_resolved_key() {
        let handler = spy(Ok(empty_response()));
        let response = trust_update(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(Some(CLIENT_KEY))),
            body(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(handler.seen.lock().unwrap().as_deref(), Some(CLIENT_KEY));
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let decoded: TrustUpdateResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.chunk.is_none(), "no chunk means trust is current");
    }

    #[tokio::test]
    async fn a_caller_without_a_wireguard_key_is_refused() {
        let handler = spy(Ok(empty_response()));
        let response = trust_update(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(None)),
            body(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(handler.seen.lock().unwrap().is_none());
    }

    /// A gateway with no lifecycle answers `404`, which is exactly what an
    /// older gateway answers — so Orion has one behaviour to implement.
    #[tokio::test]
    async fn a_gateway_without_the_lifecycle_answers_not_found() {
        let response = trust_update(
            State(state_with(None)),
            Extension(caller(Some(CLIENT_KEY))),
            body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn every_refusal_class_maps_to_one_bounded_status() {
        for (refusal, expected) in [
            (TrustUpdateRefusal::Protocol, StatusCode::BAD_REQUEST),
            (TrustUpdateRefusal::Rejected, StatusCode::FORBIDDEN),
            (
                TrustUpdateRefusal::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                TrustUpdateRefusal::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let response = trust_update(
                State(state_with(Some(spy(Err(refusal))))),
                Extension(caller(Some(CLIENT_KEY))),
                body(),
            )
            .await;
            assert_eq!(response.status(), expected, "{refusal:?}");
        }
    }

    #[tokio::test]
    async fn a_body_the_api_cannot_use_never_reaches_the_state_machine() {
        let handler = spy(Ok(empty_response()));
        let state = state_with(Some(Arc::clone(&handler)));

        assert_eq!(
            trust_update(
                State(state.clone()),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from_static(b"{"),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            trust_update(
                State(state),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from(vec![b'x'; MAX_TRUST_UPDATE_REQUEST_BYTES + 1]),
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(handler.seen.lock().unwrap().is_none());
    }
}
