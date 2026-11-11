//! Contract tests for the operator relay, including pre-dispatch refusals.
use super::*;
use aether::certificates::status::{AstraSignerResult, CampaignApproval};
use axum::http::{header, HeaderMap, HeaderValue};

#[derive(Debug, PartialEq, Eq)]
struct Call {
    route: &'static str,
    operator: astra_channel::OperatorIdentity,
    id: String,
    token: String,
}

struct RecordingRelay {
    calls: Mutex<Vec<Call>>,
    refusal: Option<TrustUpdateRefusal>,
    deposited: Mutex<Option<AstraSignerResult>>,
    /// The sentence a chain step is refused with, when a test sets one.
    chain_reason: Mutex<Option<String>>,
}
impl RecordingRelay {
    fn new(refusal: Option<TrustUpdateRefusal>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            deposited: Mutex::new(None),
            refusal,
            chain_reason: Mutex::new(None),
        })
    }
    fn record(
        &self,
        route: &'static str,
        operator: &astra_channel::OperatorIdentity,
        id: String,
        token: &str,
    ) -> Result<(), TrustUpdateRefusal> {
        self.calls.lock().unwrap().push(Call {
            route,
            operator: operator.clone(),
            id,
            token: token.into(),
        });
        match &self.refusal {
            Some(error) => Err(*error),
            None => Ok(()),
        }
    }
}
#[async_trait]
impl OperatorCampaignRelay for RecordingRelay {
    async fn pending(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<astra_channel::OperatorPendingList, TrustUpdateRefusal> {
        self.record("pending", operator, String::new(), "")?;
        Ok(astra_channel::OperatorPendingList { operations: vec![] })
    }
    async fn status(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<astra_channel::OperatorAuthorityStatus, TrustUpdateRefusal> {
        self.record("status", operator, String::new(), "")?;
        Ok(authority_status())
    }
    async fn operation(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &Id16,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal> {
        self.record("operation", operator, operation.to_hex(), "")?;
        Ok(campaign_view())
    }
    async fn signer_request(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &Id16,
        token: &str,
    ) -> Result<astra_channel::OperatorSignerRequestResponse, TrustUpdateRefusal> {
        self.record("signer-request", operator, operation.to_hex(), token)?;
        Err(TrustUpdateRefusal::Rejected)
    }
    async fn encrypted_vault(
        &self,
        operator: &astra_channel::OperatorIdentity,
        fingerprint: &Fingerprint,
        token: &str,
    ) -> Result<Vec<u8>, TrustUpdateRefusal> {
        self.record("vault", operator, fingerprint.to_hex(), token)?;
        Ok(vec![0, 1, 0xfe, 0xff])
    }
    async fn signer_result(
        &self,
        operator: &astra_channel::OperatorIdentity,
        operation: &Id16,
        token: &str,
        result: Box<AstraSignerResult>,
    ) -> Result<astra_channel::SigningOperationView, TrustUpdateRefusal> {
        self.record("result", operator, operation.to_hex(), token)?;
        *self.deposited.lock().unwrap() = Some(*result);
        Ok(campaign_view())
    }
    async fn vault_copy(
        &self,
        operator: &astra_channel::OperatorIdentity,
        copy: astra_channel::OperatorVaultCopy,
    ) -> Result<astra_channel::OperatorVaultCopied, TrustUpdateRefusal> {
        self.record(
            "vault-copy",
            operator,
            format!("{}:{}", copy.vault_base64.len(), copy.credentials.is_some()),
            "",
        )?;
        Ok(astra_channel::OperatorVaultCopied {
            fingerprint: Fingerprint::of(b"recorded encrypted vault"),
            credential_registry_epoch: copy
                .credentials
                .map(|registry| registry.credential_registry_epoch),
        })
    }
    async fn publish_gateway_transition(
        &self,
        operator: &astra_channel::OperatorIdentity,
        request: astra_channel::OperatorGatewayPublish,
    ) -> Result<astra_channel::OperatorGatewayPublished, TrustUpdateRefusal> {
        self.record(
            "gateway-publish",
            operator,
            format!("{}:{}", request.epoch, request.transition_fingerprint),
            "",
        )?;
        Ok(astra_channel::OperatorGatewayPublished {
            epoch: request.epoch,
            relayed: true,
        })
    }
    async fn open(
        &self,
        operator: &astra_channel::OperatorIdentity,
        _: astra_channel::OperatorOpenRequest,
    ) -> Result<astra_channel::OperatorOpened, TrustUpdateRefusal> {
        self.record("open", operator, String::new(), "")?;
        Err(TrustUpdateRefusal::Rejected)
    }
    async fn chain_next(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<astra_channel::OperatorChainStep, ChainRefusal> {
        self.record("chain-next", operator, String::new(), "")
            .map_err(ChainRefusal::Class)?;
        match self.chain_reason.lock().unwrap().clone() {
            Some(reason) => Err(ChainRefusal::Reason(reason)),
            None => Ok(astra_channel::OperatorChainStep::Finished),
        }
    }
    async fn chain_abandon(
        &self,
        operator: &astra_channel::OperatorIdentity,
    ) -> Result<(), TrustUpdateRefusal> {
        self.record("chain-abandon", operator, String::new(), "")
    }
}

/// A chain step that has not taken effect is refused with its sentence in a
/// `409` body, and the relay is asked once; a finished chain answers `200`.
#[tokio::test]
async fn chain_next_carries_a_step_refusal_with_its_reason() {
    let relay = RecordingRelay::new(None);
    *relay.chain_reason.lock().unwrap() = Some("l'étape 1 n'a pas pris effet".into());
    let response =
        operator_chain_next(State(state(&relay)), Extension(operator_caller_at(true))).await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({ "message": "l'étape 1 n'a pas pris effet" })
    );
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "chain-next",
            operator: expected_operator(),
            id: String::new(),
            token: String::new(),
        }]
    );
}

#[tokio::test]
async fn chain_next_answers_its_outcome_and_abandon_answers_no_content() {
    let relay = RecordingRelay::new(None);
    let response =
        operator_chain_next(State(state(&relay)), Extension(operator_caller_at(true))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({ "outcome": "finished" })
    );

    let response =
        operator_chain_abandon(State(state(&relay)), Extension(operator_caller_at(true))).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// The publication is relayed once, with the epoch and no capability token,
/// and the answer is the epoch and the relay's confirmation.
#[tokio::test]
async fn gateway_publish_is_relayed_once_with_its_epoch() {
    let relay = RecordingRelay::new(None);
    let fingerprint = Fingerprint::of(b"the transition installed");
    let body = Bytes::from(format!(
        r#"{{"epoch":5,"transition_fingerprint":"{fingerprint}"}}"#
    ));
    let response = operator_gateway_publish(
        State(state(&relay)),
        Extension(operator_caller_at(true)),
        body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let published: astra_channel::OperatorGatewayPublished =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        published,
        astra_channel::OperatorGatewayPublished {
            epoch: 5,
            relayed: true,
        }
    );
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "gateway-publish",
            operator: expected_operator(),
            id: format!("5:{fingerprint}"),
            token: String::new(),
        }]
    );
}

#[tokio::test]
async fn status_relay_receives_resolved_operator_without_a_capability() {
    let relay = RecordingRelay::new(None);
    let response = operator_status(State(state(&relay)), Extension(operator_caller_at(true))).await;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let report: astra_channel::OperatorAuthorityStatus = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report, authority_status());
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "status",
            operator: expected_operator(),
            id: String::new(),
            token: String::new(),
        }]
    );
}

#[tokio::test]
async fn vault_copy_is_relayed_once_without_recording_its_encrypted_content() {
    let relay = RecordingRelay::new(None);
    let copy = astra_channel::OperatorVaultCopy {
        vault_base64: "Y2lwaGVydGV4dA==".into(),
        credentials: None,
    };
    let body = Bytes::from(serde_json::to_vec(&copy).unwrap());
    let response = operator_vault_copy(
        State(state(&relay)),
        Extension(operator_caller_at(true)),
        body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let copied: astra_channel::OperatorVaultCopied = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        copied.fingerprint,
        Fingerprint::of(b"recorded encrypted vault")
    );
    assert_eq!(copied.credential_registry_epoch, None);
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "vault-copy",
            operator: expected_operator(),
            id: format!("{}:false", "Y2lwaGVydGV4dA==".len()),
            token: String::new(),
        }]
    );
}
fn state(relay: &Arc<RecordingRelay>) -> AppState {
    state_with(None).with_operator_campaign(Arc::clone(relay) as Arc<_>)
}
fn token() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer test-capability"),
    );
    headers
}
fn expected_operator() -> astra_channel::OperatorIdentity {
    astra_channel::OperatorIdentity::WireGuard {
        public_key: WireGuardKey::parse(CLIENT_KEY).unwrap(),
    }
}
fn signer_result_body() -> Bytes {
    let result = AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(CampaignApproval {
            campaign_id: Id16::new([8; 16]).unwrap(),
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            required_credentials: 1,
            approved_at: 10,
            approvals: vec![],
        }),
        objects: vec![],
        credential_registry: None,
        issuer_authorization: None,
    };
    Bytes::from(serde_json::to_vec(&result).unwrap())
}

#[tokio::test]
async fn pending_relay_receives_the_resolved_operator_without_a_token() {
    let relay = RecordingRelay::new(None);
    let response =
        operator_pending(State(state(&relay)), Extension(operator_caller_at(true))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let list: astra_channel::OperatorPendingList = serde_json::from_slice(&bytes).unwrap();
    assert!(list.operations.is_empty());
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "pending",
            operator: expected_operator(),
            id: String::new(),
            token: String::new()
        }]
    );
}

#[tokio::test]
async fn local_missing_and_invalid_peer_identities_are_refused_before_dispatch() {
    for (local, key, status) in [
        (true, Some(CLIENT_KEY), StatusCode::FORBIDDEN),
        (false, None, StatusCode::INTERNAL_SERVER_ERROR),
        (false, Some("invalid"), StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let relay = RecordingRelay::new(None);
        let mut caller = operator_caller_at(true);
        caller.local = local;
        caller.public_key = key.map(str::to_owned);
        let response = operator_pending(State(state(&relay)), Extension(caller)).await;
        assert_eq!(response.status(), status);
        assert!(relay.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn malformed_identifiers_and_missing_capabilities_never_reach_the_relay() {
    let relay = RecordingRelay::new(None);
    let s = state(&relay);
    let signer = operator_signer_request(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path("bad".into()),
        token(),
    )
    .await;
    let vault = operator_vault(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path("bad".into()),
        token(),
    )
    .await;
    let signer_without = operator_signer_request(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        HeaderMap::new(),
    )
    .await;
    let vault_without = operator_vault(
        State(s),
        Extension(operator_caller_at(true)),
        axum::extract::Path(Fingerprint::of(b"vault").to_hex()),
        HeaderMap::new(),
    )
    .await;
    for response in [signer, vault, signer_without, vault_without] {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .is_empty());
    }
    assert!(relay.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn vault_response_is_binary_and_the_capability_is_only_relayed_to_its_call() {
    let relay = RecordingRelay::new(None);
    let fingerprint = Fingerprint::of(b"vault");
    let response = operator_vault(
        State(state(&relay)),
        Extension(operator_caller_at(true)),
        axum::extract::Path(fingerprint.to_hex()),
        token(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        &to_bytes(response.into_body(), 4096).await.unwrap()[..],
        &[0, 1, 0xfe, 0xff]
    );
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "vault",
            operator: expected_operator(),
            id: fingerprint.to_hex(),
            token: "test-capability".into()
        }]
    );
}

#[tokio::test]
async fn signer_request_relays_the_exact_identifier_and_capability() {
    let relay = RecordingRelay::new(None);
    let response = operator_signer_request(
        State(state(&relay)),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(to_bytes(response.into_body(), 4096)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "signer-request",
            operator: expected_operator(),
            id: OPERATION_HEX.into(),
            token: "test-capability".into()
        }]
    );
}

#[tokio::test]
async fn signer_result_forwards_typed_body_and_capability_and_returns_the_view() {
    let relay = RecordingRelay::new(None);
    let response = operator_signer_result(
        State(state(&relay)),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
        signer_result_body(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let view: astra_channel::SigningOperationView = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(view.operation_id, Id16::new([7; 16]).unwrap());
    let expected: AstraSignerResult = serde_json::from_slice(&signer_result_body()).unwrap();
    assert_eq!(relay.deposited.lock().unwrap().as_ref(), Some(&expected));
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "result",
            operator: expected_operator(),
            id: OPERATION_HEX.into(),
            token: "test-capability".into()
        }]
    );
}

#[tokio::test]
async fn signer_result_refuses_bad_input_before_dispatch() {
    let relay = RecordingRelay::new(None);
    let s = state(&relay);
    let bad_id = operator_signer_result(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path("bad".into()),
        token(),
        signer_result_body(),
    )
    .await;
    let no_token = operator_signer_result(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        HeaderMap::new(),
        signer_result_body(),
    )
    .await;
    let oversized = operator_signer_result(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
        Bytes::from(vec![b' '; astra_channel::MAX_OPERATOR_REQUEST_BYTES + 1]),
    )
    .await;
    let malformed = operator_signer_result(
        State(s),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
        Bytes::from_static(b"{"),
    )
    .await;
    assert_eq!(bad_id.status(), StatusCode::FORBIDDEN);
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN);
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(relay.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_relay_refusal_is_mapped_without_returning_details() {
    for (error, expected) in [
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
        let relay = RecordingRelay::new(Some(error));
        let response = operator_operation(
            State(state(&relay)),
            Extension(operator_caller_at(true)),
            axum::extract::Path(OPERATION_HEX.into()),
        )
        .await;
        assert_eq!(response.status(), expected);
        assert!(to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(relay.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn valid_protected_requests_without_a_relay_return_unavailable() {
    let s = state_with(None);
    let fingerprint = Fingerprint::of(b"vault").to_hex();
    let pending = operator_pending(State(s.clone()), Extension(operator_caller_at(true))).await;
    let signer = operator_signer_request(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
    )
    .await;
    let vault = operator_vault(
        State(s.clone()),
        Extension(operator_caller_at(true)),
        axum::extract::Path(fingerprint),
        token(),
    )
    .await;
    let result = operator_signer_result(
        State(s),
        Extension(operator_caller_at(true)),
        axum::extract::Path(OPERATION_HEX.into()),
        token(),
        signer_result_body(),
    )
    .await;
    for response in [pending, signer, vault, result] {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn real_router_only_relays_campaign_reads_for_the_admitted_admin() {
    use axum::extract::ConnectInfo;
    use tower::ServiceExt;
    let relay = RecordingRelay::new(None);
    let state = state(&relay);
    state.network.write().await.peers = vec![
        aether::WgPeer {
            name: "admin".into(),
            public_key: CLIENT_KEY.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: true,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        },
        aether::WgPeer {
            name: "peer".into(),
            public_key: GATEWAY_KEY.into(),
            address: "100.64.1.3/32".into(),
            address_v6: None,
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        },
    ];
    for (ip, expected) in [
        ("100.64.1.3:1234", StatusCode::FORBIDDEN),
        ("100.64.1.4:1234", StatusCode::UNAUTHORIZED),
        ("100.64.1.2:1234", StatusCode::OK),
    ] {
        let mut request = axum::http::Request::builder()
            .uri("/api/certificates/operator/pending")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(ip.parse::<std::net::SocketAddr>().unwrap()));
        let response = crate::router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected, "source {ip}");
    }
    assert_eq!(
        *relay.calls.lock().unwrap(),
        vec![Call {
            route: "pending",
            operator: expected_operator(),
            id: String::new(),
            token: String::new()
        }]
    );
}
