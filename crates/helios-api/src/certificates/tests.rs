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

/// A version skew must be told apart from a malformed body.
///
/// The two read the same in a serde error and call for opposite actions:
/// upgrade the gateway, or distrust the client. Between 2026-08-21 and
/// 2026-09-01 a gateway older than its client refused every renewal while
/// logging only serde's raw dump, and the field it named was the one clue
/// that the daemon — not the request — was the stale half.
#[test]
fn an_unknown_field_is_named_and_a_malformed_body_is_not() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Known {
        #[allow(dead_code)]
        protocol_version: u16,
    }

    let skew =
        serde_json::from_str::<Known>(r#"{"protocol_version":5,"base_state_fingerprint":"abc"}"#)
            .expect_err("an unknown field must not deserialize");
    assert_eq!(
        unknown_field(&skew).as_deref(),
        Some("base_state_fingerprint"),
        "the field that dates the gateway has to reach the log line"
    );

    // Everything else stays on the generic path: calling a truncated body
    // a version skew would send the operator upgrading the wrong side.
    for malformed in [
        r#"{"protocol_version":"#,
        r#"{"protocol_version":"five"}"#,
        "[",
    ] {
        let error = serde_json::from_str::<Known>(malformed)
            .expect_err("malformed input must not deserialize");
        assert_eq!(
            unknown_field(&error),
            None,
            "`{malformed}` is malformed, not a newer client"
        );
    }
}
use tokio::sync::{broadcast, mpsc, RwLock};

const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

struct SpyHandler {
    answer: Result<TrustUpdateResponse, TrustUpdateRefusal>,
    seen: Mutex<Option<String>>,
}

#[async_trait]
impl TrustUpdateHandler for SpyHandler {
    async fn trust_enrolment(
        &self,
        _peer_wg_public_key: &str,
    ) -> Result<TrustEnrolmentView, TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn domain(&self) -> Result<CertificateDomainView, TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn admit_peer(
        &self,
        _name: &str,
        _peer_wg_public_key: &str,
        _tls_certificate: DerCertificate,
        _pq_certificate: Box<PqCertificate>,
    ) -> Result<(), TrustUpdateRefusal> {
        Ok(())
    }

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

// -- The in-tunnel operator campaign (spec §8.5) --

/// A relay that records who reached it, and answers what it was given.
struct SpyCampaign {
    answer: Result<astra_channel::SigningOperationView, TrustUpdateRefusal>,
    seen: Mutex<Option<astra_channel::OperatorIdentity>>,
}

impl SpyCampaign {
    fn granting() -> Arc<Self> {
        Arc::new(Self {
            answer: Ok(campaign_view()),
            seen: Mutex::new(None),
        })
    }

    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            answer: Err(TrustUpdateRefusal::Rejected),
            seen: Mutex::new(None),
        })
    }
}

#[async_trait]
impl OperatorCampaignRelay for SpyCampaign {
    async fn pending(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<astra_channel::OperatorPendingList, TrustUpdateRefusal> {
        *self.seen.lock().unwrap() = Some(operator.clone());
        Ok(astra_channel::OperatorPendingList {
            operations: Vec::new(),
        })
    }

    async fn operation(
        &self,
        operator: &astra_channel::OperatorIdentity,
        _operation: &Id16,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal> {
        *self.seen.lock().unwrap() = Some(operator.clone());
        self.answer.clone()
    }

    async fn signer_request(
        &self,
        operator: &astra_channel::OperatorIdentity,
        _operation: &Id16,
        _capability_token: &str,
    ) -> Result<astra_channel::OperatorSignerRequestResponse, TrustUpdateRefusal> {
        *self.seen.lock().unwrap() = Some(operator.clone());
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn encrypted_vault(
        &self,
        operator: &astra_channel::OperatorIdentity,
        _fingerprint: &Fingerprint,
        _capability_token: &str,
    ) -> Result<Vec<u8>, TrustUpdateRefusal> {
        *self.seen.lock().unwrap() = Some(operator.clone());
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn signer_result(
        &self,
        operator: &astra_channel::OperatorIdentity,
        _operation: &Id16,
        _capability_token: &str,
        _result: Box<aether::certificates::status::AstraSignerResult>,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal> {
        *self.seen.lock().unwrap() = Some(operator.clone());
        self.answer.clone()
    }
}

fn campaign_view() -> astra_channel::SigningOperationView {
    astra_channel::SigningOperationView {
        operation_id: Id16::new([7; 16]).unwrap(),
        state: astra_channel::SigningOperationState::AwaitingOperator,
        scope: aether::certificates::status::CampaignScope::TrustAuthorities,
        target_count: 1,
        required_credentials: 1,
        campaign_fingerprint: Fingerprint::of(b"campaign"),
        created_at: 0,
        expires_at: u64::MAX,
        signer_request_token: Some("read".into()),
        vault_token: None,
        signer_result_token: Some("submit".into()),
    }
}

fn operator_caller_at(admin: bool) -> crate::auth::Caller {
    crate::auth::Caller {
        source: "100.64.1.2".parse().unwrap(),
        name: "poste-operateur".into(),
        public_key: Some(CLIENT_KEY.into()),
        admin,
        dev_loopback: false,
    }
}

const OPERATION_HEX: &str = "07070707070707070707070707070707";

#[tokio::test]
async fn an_administrator_reaches_the_campaign_and_the_authority_is_told_who() {
    let relay = SpyCampaign::granting();
    let state = state_with(None).with_operator_campaign(Arc::clone(&relay) as Arc<_>);
    let response = operator_operation(
        State(state),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        relay.seen.lock().unwrap().as_ref(),
        Some(&astra_channel::OperatorIdentity::WireGuard {
            public_key: aether::certificates::encoding::WireGuardKey::parse(CLIENT_KEY).unwrap(),
        }),
        "Astra's service log receives the administrator's stable identity, not its mutable label"
    );
}

#[tokio::test]
async fn development_loopback_never_impersonates_a_wireguard_operator() {
    let relay = SpyCampaign::granting();
    let state = state_with(None).with_operator_campaign(Arc::clone(&relay) as Arc<_>);
    let response = operator_operation(
        State(state),
        Extension(crate::auth::Caller {
            source: "127.0.0.1".parse().unwrap(),
            name: "dev-loopback".into(),
            public_key: None,
            admin: true,
            dev_loopback: true,
        }),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        relay.seen.lock().unwrap().as_ref(),
        Some(&astra_channel::OperatorIdentity::DevLoopback)
    );
}

/// An admitted peer is not an operator.
///
/// `require_admin` refuses this first in the real router; the handler
/// refuses it again, which is what makes these functions safe to mount and
/// keeps a future remount from turning a campaign relay into a
/// peer-reachable one.
#[tokio::test]
async fn an_admitted_peer_that_is_not_an_administrator_never_reaches_the_authority() {
    let relay = SpyCampaign::granting();
    let state = state_with(None).with_operator_campaign(Arc::clone(&relay) as Arc<_>);
    let response = operator_operation(
        State(state),
        Extension(operator_caller_at(false)),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        relay.seen.lock().unwrap().is_none(),
        "identity is established before any read or relay, not after"
    );
}

/// Every probe answers the same, so none of them confirms anything.
#[tokio::test]
async fn an_unknown_a_malformed_and_an_expired_operation_are_told_apart_only_in_the_log() {
    let malformed = operator_operation(
        State(state_with(None).with_operator_campaign(SpyCampaign::granting() as Arc<_>)),
        Extension(operator_caller_at(true)),
        axum::extract::Path("pas-un-identifiant".into()),
    )
    .await;
    let refused = operator_operation(
        State(state_with(None).with_operator_campaign(SpyCampaign::refusing() as Arc<_>)),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    let not_admin = operator_operation(
        State(state_with(None).with_operator_campaign(SpyCampaign::granting() as Arc<_>)),
        Extension(operator_caller_at(false)),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::FORBIDDEN);
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(not_admin.status(), StatusCode::FORBIDDEN);
}

/// A capability token is not optional, and a missing one is not a hint.
#[tokio::test]
async fn the_capability_bound_reads_refuse_a_request_that_carries_no_token() {
    let state = state_with(None).with_operator_campaign(SpyCampaign::granting() as Arc<_>);
    let response = operator_signer_request(
        State(state),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        axum::http::HeaderMap::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// The two surfaces are two relays, and a campaign route reaches neither
/// store of the other.
///
/// A gateway wired for client renewals and not for campaigns answers that
/// campaigns are unavailable — it does not fall back onto the renewal
/// relay, where a peer's operation lives.
#[tokio::test]
async fn a_campaign_route_never_falls_back_onto_the_client_renewal_relay() {
    let state = state_with(None);
    assert!(
        state.operator_campaign.is_none(),
        "this test is about a gateway that has no campaign relay"
    );
    let response = operator_operation(
        State(state),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
            base_state_fingerprint: Fingerprint::of(b"base state"),
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
