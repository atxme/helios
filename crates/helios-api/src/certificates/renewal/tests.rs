use super::*;
use aether::certificates::{
    client::ClientCertificateRotationRequest,
    encoding::{
        DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey,
    },
    transport::{ClientRenewalOperationState, ClientRenewalOperationView},
    CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use axum::{body::to_bytes, extract::Path, Extension};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, RwLock};

const CALLER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const OPERATION_ID: &str = "07070707070707070707070707070707";

#[derive(Default)]
struct Calls {
    opened_by: Option<String>,
    opened: Option<ClientCertificateRotationRequest>,
    read_by: Option<String>,
    read_id: Option<Id16>,
}

struct SpyRenewal {
    answer: Result<ClientRenewalOperationView, TrustUpdateRefusal>,
    calls: Mutex<Calls>,
}

#[async_trait]
impl ClientRenewalRelay for SpyRenewal {
    async fn open(
        &self,
        caller_wg_public_key: &str,
        request: Box<ClientCertificateRotationRequest>,
    ) -> Result<ClientRenewalOperationView, TrustUpdateRefusal> {
        let mut calls = self.calls.lock().unwrap();
        calls.opened_by = Some(caller_wg_public_key.to_string());
        calls.opened = Some(*request);
        self.answer.clone()
    }

    async fn operation(
        &self,
        caller_wg_public_key: &str,
        operation: &Id16,
    ) -> Result<ClientRenewalOperationView, TrustUpdateRefusal> {
        let mut calls = self.calls.lock().unwrap();
        calls.read_by = Some(caller_wg_public_key.to_string());
        calls.read_id = Some(*operation);
        self.answer.clone()
    }

    async fn signer_request(
        &self,
        _: &str,
        _: &Id16,
        _: &str,
    ) -> Result<astra_channel::ClientRenewalSignerRequest, TrustUpdateRefusal> {
        unreachable!("this module has no signer-request handler")
    }

    async fn signer_result(
        &self,
        _: &str,
        _: &Id16,
        _: &str,
        _: Box<aether::certificates::approval::AstraRenewalApproval>,
    ) -> Result<ClientRenewalOperationView, TrustUpdateRefusal> {
        unreachable!("this module has no signer-result handler")
    }
}

fn state(relay: Option<Arc<SpyRenewal>>) -> AppState {
    let network = aether::NetworkConfig::default();
    let policy = network.firewall_policy();
    let (events, _) = broadcast::channel(4);
    let (commands, _) = mpsc::channel(4);
    let (psks, _) = mpsc::channel(4);
    let state = AppState::new(
        Arc::new(RwLock::new(network)),
        true,
        Arc::new(RwLock::new(aether::TunnelState::Up)),
        events,
        commands,
        psks,
        Arc::new(RwLock::new(policy)),
    );
    relay.map_or(state.clone(), |relay| state.with_client_renewal(relay))
}

fn caller(public_key: Option<&str>) -> crate::auth::Caller {
    crate::auth::Caller {
        source: "100.64.1.2".parse().unwrap(),
        name: "workstation".into(),
        public_key: public_key.map(str::to_owned),
        admin: false,
        dev_loopback: false,
        local: false,
    }
}

fn relay(answer: Result<ClientRenewalOperationView, TrustUpdateRefusal>) -> Arc<SpyRenewal> {
    Arc::new(SpyRenewal {
        answer,
        calls: Mutex::new(Calls::default()),
    })
}

fn view() -> ClientRenewalOperationView {
    ClientRenewalOperationView {
        operation_id: Id16::parse_hex(OPERATION_ID).unwrap(),
        state: ClientRenewalOperationState::AwaitingOperator,
        client_wg_public_key: WireGuardKey::parse(CALLER_KEY).unwrap(),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        operation_manifest_fingerprint: Fingerprint::of(b"approval manifest"),
        created_at: 10,
        expires_at: 20,
        signer_request_token: Some("request-capability".into()),
        signer_result_token: Some("result-capability".into()),
        grant: None,
    }
}

fn request() -> ClientCertificateRotationRequest {
    ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([1; 16]).unwrap(),
        trust_domain_id: Id16::new([2; 16]).unwrap(),
        gateway_wg_public_key: WireGuardKey::from_bytes([3; 32]),
        server_name: "gateway.example".into(),
        client_wg_public_key: WireGuardKey::parse(CALLER_KEY).unwrap(),
        active_generation: 4,
        requested_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        // The gateway route parses and relays a typed object; Astra verifies
        // the CSR and signatures. These bounded wrappers are enough for the
        // API boundary test and intentionally do not claim cryptographic proof.
        tls_csr: DerCertificate::new(vec![1]).unwrap(),
        new_ml_dsa_87_public_key: MlDsa87PublicKey::new(vec![22; 2592]).unwrap(),
        created_at: 10,
        expires_at: 20,
        active_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
}

fn body() -> Bytes {
    Bytes::from(serde_json::to_vec(&request()).unwrap())
}

#[tokio::test]
async fn renewal_request_requires_a_resolved_wireguard_identity_before_parsing() {
    let relay = relay(Ok(view()));
    let response = renewal_request(
        State(state(Some(Arc::clone(&relay)))),
        Extension(caller(None)),
        Bytes::from_static(b"not-json"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(relay.calls.lock().unwrap().opened.is_none());
}

#[tokio::test]
async fn renewal_request_rejects_oversized_and_malformed_bodies_before_relaying() {
    let relay = relay(Ok(view()));
    let state = State(state(Some(Arc::clone(&relay))));
    let oversized = renewal_request(
        state.clone(),
        Extension(caller(Some(CALLER_KEY))),
        Bytes::from(vec![b'x'; MAX_TRUST_UPDATE_REQUEST_BYTES + 1]),
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let malformed = renewal_request(
        state,
        Extension(caller(Some(CALLER_KEY))),
        Bytes::from_static(b"{"),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(relay.calls.lock().unwrap().opened.is_none());
}

#[tokio::test]
async fn renewal_request_relays_the_resolved_peer_and_returns_the_operation() {
    let expected = request();
    let relay = relay(Ok(view()));
    let response = renewal_request(
        State(state(Some(Arc::clone(&relay)))),
        Extension(caller(Some(CALLER_KEY))),
        body(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: ClientRenewalOperationView =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(returned.operation_id.to_hex(), OPERATION_ID);
    let calls = relay.calls.lock().unwrap();
    assert_eq!(calls.opened_by.as_deref(), Some(CALLER_KEY));
    assert_eq!(calls.opened.as_ref(), Some(&expected));
}

#[tokio::test]
async fn renewal_request_maps_authority_refusal_without_returning_details() {
    let relay = relay(Err(TrustUpdateRefusal::Rejected));
    let response = renewal_request(
        State(state(Some(Arc::clone(&relay)))),
        Extension(caller(Some(CALLER_KEY))),
        body(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(to_bytes(response.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        relay.calls.lock().unwrap().opened_by.as_deref(),
        Some(CALLER_KEY)
    );
}

#[tokio::test]
async fn renewal_request_and_operation_report_an_absent_relay_as_unavailable() {
    let state = State(state(None));
    let request_response =
        renewal_request(state.clone(), Extension(caller(Some(CALLER_KEY))), body()).await;
    let operation_response = renewal_operation(
        state,
        Extension(caller(Some(CALLER_KEY))),
        Path(OPERATION_ID.into()),
    )
    .await;
    assert_eq!(request_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(operation_response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn renewal_operation_rejects_bad_ids_before_relay_and_relays_valid_ids() {
    let relay = relay(Ok(view()));
    let state = State(state(Some(Arc::clone(&relay))));
    let malformed = renewal_operation(
        state.clone(),
        Extension(caller(Some(CALLER_KEY))),
        Path("not-an-id".into()),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(relay.calls.lock().unwrap().read_id.is_none());

    let response = renewal_operation(
        state,
        Extension(caller(Some(CALLER_KEY))),
        Path(OPERATION_ID.into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let calls = relay.calls.lock().unwrap();
    assert_eq!(calls.read_by.as_deref(), Some(CALLER_KEY));
    assert_eq!(calls.read_id.unwrap().to_hex(), OPERATION_ID);
}
