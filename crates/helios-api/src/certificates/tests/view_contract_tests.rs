use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

const DOMAIN_ROUTE: &str = "/api/certificates";
const ENROLMENT_ROUTE: &str = "/api/key-negotiation/trust-enrolment";
const NOW: u64 = 12_000;

struct Registry {
    refusal: Option<TrustUpdateRefusal>,
    looked_up: Mutex<Vec<String>>,
}

#[async_trait]
impl TrustUpdateHandler for Registry {
    async fn trust_enrolment(
        &self,
        peer_wg_public_key: &str,
    ) -> Result<TrustEnrolmentView, TrustUpdateRefusal> {
        self.looked_up
            .lock()
            .unwrap()
            .push(peer_wg_public_key.to_owned());
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        if peer_wg_public_key != CLIENT_KEY {
            return Err(TrustUpdateRefusal::Rejected);
        }
        Ok(enrolment_snapshot())
    }

    async fn domain(&self) -> Result<CertificateDomainView, TrustUpdateRefusal> {
        match self.refusal {
            Some(refusal) => Err(refusal),
            None => Ok(domain_snapshot()),
        }
    }

    async fn admit_peer(
        &self,
        _: &str,
        _: &str,
        _: DerCertificate,
        _: Box<PqCertificate>,
    ) -> Result<(), TrustUpdateRefusal> {
        panic!("read-only route invoked admission");
    }

    async fn trust_update(
        &self,
        _: &str,
        _: AuthenticatedTrustUpdateRequest,
    ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
        panic!("read-only route invoked a trust update");
    }

    async fn stage_commit(
        &self,
        _: &str,
        _: Box<StageCommitRequest>,
    ) -> Result<(), TrustUpdateRefusal> {
        panic!("read-only route invoked a commit");
    }
}

fn enrolment_snapshot() -> TrustEnrolmentView {
    TrustEnrolmentView {
        trust_domain_id: "01".repeat(16),
        ca_epoch: 3,
        ca_pq_public_key: "fixture-ca-pq-public-key".into(),
        ca_tls_epoch: 4,
        client_tls_ca_der: "fixture-client-ca-der".into(),
        client_generation: 8,
        active_gateway_identity_epoch: 5,
        gateway_decision_epoch: 6,
        astra_authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: "ab".repeat(32),
        credential_registry_epoch: 7,
        astra_credential_bindings: Vec::new(),
        astra_service_key_epoch: 9,
        astra_service_public_key: "fixture-astra-service-public-key".into(),
    }
}

fn domain_snapshot() -> CertificateDomainView {
    use aether::certificates::{state::PendingStageState, window::ValidityPhase};

    CertificateDomainView {
        trust_domain_id: "01".repeat(16),
        server_name: "gateway.example".into(),
        now_unix: NOW,
        ca_epoch: 3,
        ca_pq_fingerprint: "02".repeat(32),
        ca_transition_pending: true,
        ca_activation_at: Some(NOW + 60),
        ca_retire_active_at: Some(NOW + 120),
        next_ca_fingerprint: Some("03".repeat(32)),
        client_tls_ca_epoch: 4,
        client_tls_ca_fingerprint: "04".repeat(32),
        next_client_tls_ca_fingerprint: None,
        client_tls_ca_transition_pending: false,
        gateway_identity_epoch: 5,
        gateway_tls_fingerprint: "05".repeat(32),
        gateway_pq_fingerprint: "06".repeat(32),
        gateway_tls_not_after: Some(NOW + 1800),
        gateway_pq_not_after: Some(NOW + 1800),
        gateway_transition_pending: false,
        gateway_activation_at: None,
        gateway_retire_active_at: None,
        gateway_transition_published: false,
        gateway_rollback_expires_at: None,
        gateway_revoked: false,
        gateway_awaited_replacement: None,
        gateway_restart_due: None,
        astra_authority_url: "https://astra.example".into(),
        astra_service_key_epoch: 9,
        astra_policy_fingerprint: "ab".repeat(32),
        webauthn_rp_id: "astra.example".into(),
        credential_registry_epoch: 7,
        credential_bindings: 2,
        issuer: None,
        peers: vec![PeerCertificateView {
            name: "workstation".into(),
            wg_public_key: CLIENT_KEY.into(),
            generation: 8,
            not_before: NOW - 60,
            not_after: NOW + 600,
            phase: ValidityPhase::Valid,
            revoked: false,
            pending: Some(PendingStageView {
                generation: 9,
                state: PendingStageState::PendingCommit,
                stage_expires_at: NOW + 100,
            }),
            next_generation: None,
            activation_at: None,
            distribution_chunks_pending: 2,
        }],
    }
}

fn router_with_registry(refusal: Option<TrustUpdateRefusal>) -> (axum::Router, Arc<Registry>) {
    let handler = Arc::new(Registry {
        refusal,
        looked_up: Mutex::new(Vec::new()),
    });
    let router = crate::router(state_with(None).with_trust_update(handler.clone()));
    (router, handler)
}

async fn get(router: &axum::Router, path: &str) -> Response {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    router.clone().oneshot(request).await.unwrap()
}

async fn body(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn both_certificate_views_report_an_unconfigured_trust_domain() {
    let router = crate::router(state_with(None));
    for path in [
        DOMAIN_ROUTE.to_owned(),
        format!("{ENROLMENT_ROUTE}/{CLIENT_KEY}"),
    ] {
        let response = get(&router, &path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(String::from_utf8(body(response).await)
            .unwrap()
            .contains("init-trust-domain"));
    }
}

#[tokio::test]
async fn domain_read_serves_the_registry_snapshot_over_the_router() {
    let (router, handler) = router_with_registry(None);
    let response = get(&router, DOMAIN_ROUTE).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/json"
    );
    let actual: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(actual, serde_json::to_value(domain_snapshot()).unwrap());
    assert_eq!(actual["peers"][0]["pending"]["generation"], 9);
    assert!(handler.looked_up.lock().unwrap().is_empty());
}

#[tokio::test]
async fn enrolment_read_trims_the_requested_key_and_returns_its_public_generations() {
    let (router, handler) = router_with_registry(None);
    let response = get(&router, &format!("{ENROLMENT_ROUTE}/%20{CLIENT_KEY}%20")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let actual: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(actual, serde_json::to_value(enrolment_snapshot()).unwrap());
    assert_eq!(actual["client_generation"], 8);
    assert_eq!(actual["active_gateway_identity_epoch"], 5);
    assert_eq!(actual["gateway_decision_epoch"], 6);
    assert_eq!(*handler.looked_up.lock().unwrap(), [CLIENT_KEY]);
}

#[tokio::test]
async fn enrolment_read_distinguishes_an_unknown_peer_from_an_absent_domain() {
    let (router, handler) = router_with_registry(None);
    let response = get(&router, &format!("{ENROLMENT_ROUTE}/{GATEWAY_KEY}")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(String::from_utf8(body(response).await)
        .unwrap()
        .contains("no such admitted peer"));
    assert_eq!(*handler.looked_up.lock().unwrap(), [GATEWAY_KEY]);
}

#[tokio::test]
async fn both_certificate_views_keep_coarse_refusal_statuses() {
    for (refusal, expected) in [
        (
            TrustUpdateRefusal::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            TrustUpdateRefusal::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (TrustUpdateRefusal::Conflict, StatusCode::CONFLICT),
    ] {
        let (router, _) = router_with_registry(Some(refusal));
        for path in [
            DOMAIN_ROUTE.to_owned(),
            format!("{ENROLMENT_ROUTE}/{CLIENT_KEY}"),
        ] {
            let response = get(&router, &path).await;
            assert_eq!(response.status(), expected, "{path}");
            assert!(body(response).await.is_empty());
        }
    }
}
