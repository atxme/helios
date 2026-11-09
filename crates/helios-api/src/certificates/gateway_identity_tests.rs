use super::*;
use aether::{NetworkConfig, TunnelState, WgPeer};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{broadcast, mpsc, RwLock};
use tower::ServiceExt as _;

struct StubIdentity {
    refuse: bool,
    calls: AtomicUsize,
}

impl StubIdentity {
    fn new(refuse: bool) -> Arc<Self> {
        Arc::new(Self {
            refuse,
            calls: AtomicUsize::new(0),
        })
    }

    fn called(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn result<T>(&self, value: T) -> Result<T, GatewayActionRefusal> {
        if self.refuse {
            Err(GatewayActionRefusal::new("policy refusal"))
        } else {
            Ok(value)
        }
    }
}

#[async_trait]
impl GatewayIdentityHandler for StubIdentity {
    async fn prepare_renewal(
        &self,
        _request: GatewayRenewalRequest,
    ) -> Result<GatewayRenewalView, GatewayActionRefusal> {
        self.called();
        self.result(GatewayRenewalView {
            gateway_identity_epoch: 7,
            request_id: "request-7".into(),
            request_fingerprint: "11".repeat(32),
            expires_at: 1_700_000_000,
            candidate_tls_fingerprint: None,
            reused: false,
            key_recovery: false,
        })
    }

    async fn install_transition(
        &self,
        _transition: Box<aether::certificates::gateway::GatewayIdentityTransition>,
    ) -> Result<GatewayDecisionView, GatewayActionRefusal> {
        self.called();
        self.result(GatewayDecisionView {
            gateway_identity_epoch: 8,
            fingerprint: "22".repeat(32),
            already_present: false,
            activation_at: Some(1_700_000_100),
            not_after: Some(1_702_592_100),
        })
    }

    async fn abort_transition(
        &self,
        _abort: Box<aether::certificates::gateway::GatewayTransitionAbort>,
    ) -> Result<GatewayDecisionView, GatewayActionRefusal> {
        self.called();
        self.result(GatewayDecisionView {
            gateway_identity_epoch: 8,
            fingerprint: "33".repeat(32),
            already_present: false,
            activation_at: None,
            not_after: None,
        })
    }

    async fn install_rollback(
        &self,
        _authorization: Box<aether::certificates::status::CertificateServiceRollbackAuthorization>,
    ) -> Result<GatewayRollbackView, GatewayActionRefusal> {
        self.called();
        self.result(GatewayRollbackView {
            gateway_identity_epoch: 8,
            selected_certificate_fingerprint: "44".repeat(32),
            expires_at: 1_700_000_200,
            already_present: false,
        })
    }

    async fn install_ca_transition(
        &self,
        _transition: Box<aether::certificates::authority::CaTransition>,
    ) -> Result<AnchorDecisionView, GatewayActionRefusal> {
        self.called();
        self.result(AnchorDecisionView {
            ca_epoch: 3,
            next_ca_epoch: 4,
            next_ca_fingerprint: "55".repeat(32),
            activation_at: 1_700_000_300,
            not_after: 1_702_592_300,
            already_present: false,
        })
    }
}

fn app_state(handler: Option<Arc<StubIdentity>>, admin: bool) -> AppState {
    let network = NetworkConfig {
        peers: vec![WgPeer {
            name: "test-operator".into(),
            public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }],
        ..NetworkConfig::default()
    };
    let policy = network.firewall_policy();
    let (event_tx, _) = broadcast::channel(4);
    let (cmd_tx, _) = mpsc::channel(4);
    let (psk_tx, _) = mpsc::channel(4);
    let mut state = AppState::new(
        Arc::new(RwLock::new(network)),
        false,
        Arc::new(RwLock::new(TunnelState::Down)),
        event_tx,
        cmd_tx,
        psk_tx,
        Arc::new(RwLock::new(policy)),
    );
    if let Some(handler) = handler {
        state = state.with_gateway_identity(handler);
    }
    state
}

fn request(path: &str, body: serde_json::Value) -> Request<Body> {
    let body = serde_json::to_vec(&body).expect("serialize route fixture");
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("build request");
    let address: std::net::SocketAddr = "100.64.1.2:40123".parse().expect("test socket address");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(address));
    request
}

fn route_fixtures() -> Vec<(&'static str, serde_json::Value)> {
    use aether::certificates::{
        authority::CaTransition,
        encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
        gateway::{AbortReason, GatewayIdentityTransition, GatewayTransitionAbort},
        status::CertificateServiceRollbackAuthorization,
        window::TransitionWindow,
        CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
    };

    let domain = Id16::new([1; 16]).expect("domain id");
    let gateway = WireGuardKey::from_bytes([2; 32]);
    let fingerprint = |byte| Fingerprint::from_bytes([byte; 32]);
    let signature = MlDsa87Signature::placeholder();
    let window = TransitionWindow {
        not_before: 100,
        activation_at: 200,
        not_after: 300,
    };
    let transition = GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        ca_epoch: 1,
        gateway_identity_epoch: 2,
        gateway_wg_public_key: gateway,
        server_name: "gateway.example.test".into(),
        active_gateway_tls_certificate_fingerprint: fingerprint(3),
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: fingerprint(4),
        next_gateway_certificate: None,
        window,
        reason: aether::certificates::authority::RotationReason::Scheduled,
        ca_signature: signature.clone(),
    };
    let abort = GatewayTransitionAbort {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        ca_epoch: 1,
        gateway_wg_public_key: gateway,
        server_name: "gateway.example.test".into(),
        gateway_identity_epoch: 2,
        gateway_transition_fingerprint: fingerprint(5),
        aborted_at: 150,
        reason: AbortReason::OperatorCancelled,
        campaign_fingerprint: fingerprint(6),
        ca_signature: signature.clone(),
    };
    let rollback = CertificateServiceRollbackAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain,
        ca_epoch: 1,
        gateway_wg_public_key: gateway,
        server_name: "gateway.example.test".into(),
        transition_fingerprint: fingerprint(7),
        selected_certificate_fingerprint: fingerprint(8),
        campaign_fingerprint: fingerprint(9),
        expires_at: 250,
        ca_signature: signature.clone(),
    };
    let next_ca = MlDsa87PublicKey::new(vec![22; 2592]).expect("test CA public key");
    let ca_transition = CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain,
        current_ca_epoch: 1,
        next_ca_epoch: 2,
        current_ca_fingerprint: fingerprint(10),
        next_ca_public_key: next_ca,
        next_ca_fingerprint: fingerprint(11),
        window,
        current_ca_signature: signature.clone(),
        next_ca_signature: signature,
    };

    vec![
        (
            "/api/certificates/gateway-renewal",
            serde_json::json!({"rotate_tls": true, "new_key": false, "key_recovery": false}),
        ),
        (
            "/api/certificates/gateway-transition",
            serde_json::to_value(transition).expect("transition JSON"),
        ),
        (
            "/api/certificates/gateway-transition/abort",
            serde_json::to_value(abort).expect("abort JSON"),
        ),
        (
            "/api/certificates/gateway-transition/rollback",
            serde_json::to_value(rollback).expect("rollback JSON"),
        ),
        (
            "/api/certificates/ca-transition",
            serde_json::to_value(ca_transition).expect("CA transition JSON"),
        ),
    ]
}

async fn send(state: AppState, path: &str, body: serde_json::Value) -> axum::response::Response {
    crate::router(state)
        .oneshot(request(path, body))
        .await
        .expect("router response")
}

#[tokio::test]
async fn every_gateway_identity_route_reaches_the_admin_router_and_returns_handler_results() {
    for (path, body) in route_fixtures() {
        let handler = StubIdentity::new(false);
        let response = send(app_state(Some(Arc::clone(&handler)), true), path, body).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let payload = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("JSON response");
        match path {
            "/api/certificates/gateway-renewal" => {
                assert_eq!(json["gateway_identity_epoch"], 7);
                assert_eq!(json["request_id"], "request-7");
                assert_eq!(json["reused"], false);
            }
            "/api/certificates/gateway-transition" => {
                assert_eq!(json["fingerprint"], "22".repeat(32));
                assert_eq!(json["activation_at"], 1_700_000_100u64);
            }
            "/api/certificates/gateway-transition/abort" => {
                assert_eq!(json["fingerprint"], "33".repeat(32));
                assert!(json["activation_at"].is_null());
            }
            "/api/certificates/gateway-transition/rollback" => {
                assert_eq!(json["selected_certificate_fingerprint"], "44".repeat(32));
                assert_eq!(json["expires_at"], 1_700_000_200u64);
            }
            "/api/certificates/ca-transition" => {
                assert_eq!(json["ca_epoch"], 3);
                assert_eq!(json["next_ca_epoch"], 4);
                assert_eq!(json["next_ca_fingerprint"], "55".repeat(32));
            }
            _ => panic!("unexpected route {path}"),
        }
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1, "{path}");
    }
}

#[tokio::test]
async fn every_gateway_identity_route_preserves_refusal_and_absent_handler_semantics() {
    for (path, body) in route_fixtures() {
        let refusing = StubIdentity::new(true);
        let response = send(
            app_state(Some(Arc::clone(&refusing)), true),
            path,
            body.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{path}");
        let payload = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("refusal body");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("refusal JSON");
        assert_eq!(json["message"], "policy refusal", "{path}");
        assert_eq!(refusing.calls.load(Ordering::SeqCst), 1, "{path}");

        let response = send(app_state(None, true), path, body).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let payload = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("absent-handler body");
        assert!(
            String::from_utf8_lossy(&payload).contains("init-trust-domain"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn gateway_identity_routes_are_admin_only_in_the_real_router() {
    for (path, body) in route_fixtures() {
        let handler = StubIdentity::new(false);
        let response = send(app_state(Some(Arc::clone(&handler)), false), path, body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0, "{path}");
    }
}
