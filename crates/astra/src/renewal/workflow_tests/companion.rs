//! Recovery of persisted pre-amendment operations, never a new ceremony for
//! the ordinary automatic renewal. The software ES256 key proves protocol
//! verification only; it makes no claim about a physical authenticator.

use super::*;
use aether::certificates::{
    approval::{AstraCredentialBinding, CredentialRegistry, CredentialState},
    webauthn::WebAuthnAssertion,
};
use rcgen::{SigningKey, PKCS_ECDSA_P256_SHA256};

struct Legacy {
    fixture: Fixture,
    id: Id16,
    credential: KeyPair,
    binding: AstraCredentialBinding,
}

async fn legacy() -> Legacy {
    let mut fixture = fixture().await;
    let credential = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ES256 key");
    let point = credential.public_key_raw();
    assert_eq!(point.len(), 65, "uncompressed ES256 point");
    let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose.extend_from_slice(&point[1..33]);
    cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose.extend_from_slice(&point[33..65]);
    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: b"legacy-companion-credential".to_vec(),
        credential_public_key: cose,
        aaguid: [0; 16],
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: NOW - 10,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca_private)
    .expect("CA signed credential");
    let service = Arc::get_mut(&mut fixture.service).expect("unique fixture");
    service.approval_credentials =
        std::sync::RwLock::new(Arc::new(crate::service::ApprovalCredentials {
            ids: vec![binding.credential_id.clone()],
            epoch: 1,
            registry: Some(Box::new(CredentialRegistry {
                trust_domain_id: domain(),
                gateway_wg_public_key: gateway_key(),
                ca_epoch: 1,
                credential_registry_epoch: 1,
                bindings: vec![binding.clone()],
            })),
        }));
    transcribe_peer(&fixture.service, &client_key(), NOW)
        .await
        .expect("transcribe authenticated peer");
    let id = Id16::new([0x39; 16]).expect("operation ID");
    let approval_request = build_approval_request(
        &fixture.service,
        id,
        &fixture.request,
        &4,
        domain(),
        gateway_key(),
        "astra.example",
        1,
        1,
        NOW,
    )
    .expect("signed legacy approval request");
    let operation = Operation::awaiting_operator(
        id,
        client_key(),
        Box::new(fixture.request.clone()),
        Box::new(approval_request),
        NOW,
    );
    {
        let mut operations = fixture.service.operations.lock().await;
        operations.open(operation, NOW).expect("legacy operation");
        operations.persist().expect("durable legacy record");
    }
    fixture.reload().await;
    assert_eq!(
        fixture
            .service
            .operations
            .lock()
            .await
            .get(&id, &client_key(), NOW + 1)
            .expect("loadable legacy record")
            .state,
        ClientRenewalOperationState::AwaitingOperator,
    );
    Legacy {
        fixture,
        id,
        credential,
        binding,
    }
}

impl Legacy {
    async fn operation_bytes(&self, now: u64) -> Vec<u8> {
        let operations = self.fixture.service.operations.lock().await;
        serde_json::to_vec(
            operations
                .get(&self.id, &client_key(), now)
                .expect("operation"),
        )
        .expect("operation snapshot")
    }

    async fn view(&self, now: u64) -> ClientRenewalOperationView {
        let operations = self.fixture.service.operations.lock().await;
        mint_view(
            &self.fixture.service,
            operations
                .get(&self.id, &client_key(), now)
                .expect("operation"),
            now,
        )
        .await
        .expect("scoped capabilities")
    }

    async fn read_at(&self, now: u64) -> Result<ClientRenewalOperationView, RenewalError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            read(&self.fixture.service, &client_key(), &self.id, now),
        )
        .await
        .expect("bounded legacy read")
    }

    async fn fetch(
        &self,
        caller: &WireGuardKey,
        token: &str,
        now: u64,
    ) -> Result<ClientRenewalSignerRequest, RenewalError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            signer_request(&self.fixture.service, caller, &self.id, token, now),
        )
        .await
        .expect("bounded signer request")
    }

    async fn submit(
        &self,
        token: &str,
        approval: AstraRenewalApproval,
        now: u64,
    ) -> Result<ClientRenewalOperationView, RenewalError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            signer_result(
                &self.fixture.service,
                &client_key(),
                &self.id,
                token,
                Box::new(approval),
                now,
            ),
        )
        .await
        .expect("bounded signer result")
    }

    async fn approval(&self, now: u64) -> AstraRenewalApproval {
        let request = self
            .fixture
            .service
            .operations
            .lock()
            .await
            .get(&self.id, &client_key(), now)
            .expect("operation")
            .approval_request
            .clone();
        let mut authenticator_data = Fingerprint::of(b"astra.example").as_bytes().to_vec();
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://astra.example","crossOrigin":false}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.challenge().as_bytes()),
        ).into_bytes();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(Fingerprint::of(&client_data_json).as_bytes());
        let assertion = WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: self
                .credential
                .sign(&message)
                .expect("software ES256 assertion"),
        };
        let approval = AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: self.id,
            request_fingerprint: request.request_fingerprint,
            approval_request_fingerprint: request.fingerprint(),
            credential_binding: self.binding.clone(),
            credential_fingerprint: self.binding.fingerprint(),
            assertion_fingerprint: assertion.fingerprint(),
            webauthn_assertion: assertion,
            approved_at: now,
            expires_at: (now + 200).min(request.expires_at),
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        };
        approval
            .verify_operator_evidence(
                &request,
                &self.fixture.gateway.ca_public,
                1,
                &domain(),
                1,
                1,
                now,
            )
            .expect("real credential binding and assertion verify before submission");
        approval
    }
}

#[tokio::test]
async fn an_unwritten_legacy_challenge_is_not_published_or_skipped_on_retry() {
    let legacy = legacy().await;
    // This token remains live across the approval-request expiry; rejection
    // after refresh must therefore prove manifest binding, not just a timeout.
    let old_view = legacy.view(NOW + 250).await;
    let old_token = old_view.signer_request_token.expect("read capability");
    let before = legacy.operation_bytes(NOW + 301).await;
    let backup = obstruct_operations(&legacy.fixture);
    let journal = std::fs::read(&backup).expect("durable legacy journal");
    assert!(matches!(
        legacy.read_at(NOW + 301).await,
        Err(RenewalError::Operation(OperationError::Persistence(_))),
    ));
    assert!(
        legacy.operation_bytes(NOW + 301).await == before,
        "failed refresh must preserve the exact in-memory legacy record"
    );
    assert_eq!(std::fs::read(&backup).expect("unchanged journal"), journal);
    assert!(legacy.fixture.gateway.stages.lock().await.is_empty());
    let unchanged = legacy
        .fetch(&client_key(), &old_token, NOW + 301)
        .await
        .expect("failed refresh preserves the still-live old capability");
    assert_eq!(
        unchanged.approval_request.fingerprint(),
        old_view.operation_manifest_fingerprint
    );
    restore_operations(&legacy.fixture, &backup);
    let refreshed = legacy
        .read_at(NOW + 301)
        .await
        .expect("durable challenge retry");
    assert_eq!(
        refreshed.state,
        ClientRenewalOperationState::AwaitingOperator
    );
    assert_ne!(
        refreshed.operation_manifest_fingerprint,
        old_view.operation_manifest_fingerprint
    );
    assert!(matches!(
        legacy.fetch(&client_key(), &old_token, NOW + 301).await,
        Err(RenewalError::Capability(
            CertificateError::CapabilityScopeViolation(_)
        )),
    ));
    let token = refreshed.signer_request_token.expect("new read capability");
    let request = legacy
        .fetch(&client_key(), &token, NOW + 301)
        .await
        .expect("new manifest readable");
    request
        .approval_request
        .verify(
            &legacy.fixture.service.service_public_key,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            "astra.example",
            4,
            NOW + 301,
        )
        .expect("refreshed approval request signature and lifetime");
    assert_eq!(
        request.credential_registry.bindings,
        vec![legacy.binding.clone()]
    );
    let durable =
        crate::operations::OperationStore::load(&legacy.fixture.operations_path(), NOW + 302)
            .expect("refreshed challenge survives restart");
    assert_eq!(
        durable
            .get(&legacy.id, &client_key(), NOW + 302)
            .expect("durable operation")
            .approval_request,
        request.approval_request
    );
}

#[tokio::test]
async fn an_unwritten_legacy_approval_cannot_authorize_staging_on_retry() {
    let legacy = legacy().await;
    let view = legacy.view(NOW + 1).await;
    let token = view.signer_result_token.expect("submit capability");
    let approval = legacy.approval(NOW + 1).await;
    let rejected_status =
        astra_channel::ChannelError::Status(axum::http::StatusCode::FORBIDDEN).to_string();
    assert_eq!(legacy.fixture.gateway.stage_calls.load(Ordering::SeqCst), 0);
    let before = legacy.operation_bytes(NOW + 1).await;
    let backup = obstruct_operations(&legacy.fixture);
    let journal = std::fs::read(&backup).expect("durable awaiting record");
    assert!(matches!(
        legacy.submit(&token, approval.clone(), NOW + 1).await,
        Err(RenewalError::Operation(OperationError::Persistence(_))),
    ));
    assert!(
        legacy.operation_bytes(NOW + 1).await == before,
        "failed approval write must preserve the exact awaiting record"
    );
    assert_eq!(std::fs::read(&backup).expect("unchanged journal"), journal);
    assert!(legacy.fixture.gateway.stages.lock().await.is_empty());
    assert_eq!(legacy.fixture.gateway.stage_calls.load(Ordering::SeqCst), 0);
    assert!(legacy
        .fixture
        .service
        .registry
        .lock()
        .await
        .peer(&client_key())
        .expect("peer")
        .pending
        .is_none());
    restore_operations(&legacy.fixture, &backup);
    // The current policy rejects legacy per-request staging. Persisting an
    // old approval must never reopen that superseded authorization family.
    assert!(matches!(
        legacy.submit(&token, approval.clone(), NOW + 2).await,
        Err(RenewalError::Gateway(message)) if message == rejected_status,
    ));
    assert_eq!(legacy.fixture.gateway.stage_calls.load(Ordering::SeqCst), 1);
    let authorization = {
        let operations = legacy.fixture.service.operations.lock().await;
        let operation = operations
            .get(&legacy.id, &client_key(), NOW + 2)
            .expect("operation");
        assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
        assert!(operation.view(None, None).grant.is_none());
        let evidence = operation
            .approval_evidence()
            .expect("durable verified approval");
        assert_eq!(
            evidence.approval.webauthn_assertion,
            approval.webauthn_assertion
        );
        evidence
            .verify(
                &legacy.fixture.request.fingerprint(),
                &legacy.fixture.gateway.ca_public,
                &legacy.fixture.service.service_public_key,
                1,
                &domain(),
                &gateway_key(),
                &client_key(),
                "astra.example",
                4,
                1,
                1,
                NOW + 2,
            )
            .expect("countersigned evidence remains independently verifiable");
        operation
            .stage_authorization()
            .expect("attempted exact legacy stage")
            .clone()
    };
    assert!(legacy.fixture.gateway.stages.lock().await.is_empty());
    {
        let registry = legacy.fixture.service.registry.lock().await;
        let pending = registry
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("ungranted reservation retained after rejection");
        // The current implementation retains this exact ungranted reservation
        // until lease expiry. This test observes that behavior; it does not
        // claim rejection cleanup or authorize a production cleanup change.
        assert_eq!(pending.stage_id, authorization.stage_id);
        assert_eq!(pending.stage_expires_at, authorization.stage_expires_at);
        assert_eq!(pending.window, authorization.window);
        assert!(!pending.granted);
    }
    let durable =
        crate::operations::OperationStore::load(&legacy.fixture.operations_path(), NOW + 2)
            .expect("verified legacy approval survives restart");
    let restored = durable
        .get(&legacy.id, &client_key(), NOW + 2)
        .expect("durable operation");
    assert_eq!(restored.stage_authorization(), Some(&authorization));
    assert_eq!(restored.approved_with(), Some(approval.fingerprint()));
    assert_ne!(
        approval.fingerprint(),
        authorization.renewal_authorization_fingerprint,
        "submission identity includes the placeholder, stage binds the countersigned evidence"
    );
    assert!(restored
        .is_idempotent_submission(&approval.fingerprint())
        .expect("identical upload survives restart"));
    let mut conflicting = approval.clone();
    conflicting.approved_at -= 1;
    assert_eq!(
        restored.is_idempotent_submission(&conflicting.fingerprint()),
        Err(OperationError::ApprovalConflict)
    );

    // These are structural journal checks, not acceptance of unsigned protocol
    // objects. Neither the original upload digest nor an unrelated digest may
    // stand in for the exact countersigned evidence in a staged operation.
    let good_journal = std::fs::read(legacy.fixture.operations_path()).expect("valid journal");
    for wrong in [
        approval.fingerprint(),
        Fingerprint::of(b"unrelated legacy authorization"),
    ] {
        let mut corrupted: serde_json::Value =
            serde_json::from_slice(&good_journal).expect("journal JSON");
        corrupted["operations"][0]["stage_authorization"]["renewal_authorization_fingerprint"] =
            serde_json::to_value(wrong).expect("fingerprint JSON");
        aether::private_file::write_private_atomic(
            &legacy.fixture.operations_path(),
            &serde_json::to_vec(&corrupted).expect("corrupt structural binding"),
        )
        .expect("write structurally invalid journal");
        assert!(matches!(
            crate::operations::OperationStore::load(&legacy.fixture.operations_path(), NOW + 2),
            Err(OperationError::Corrupt("stage authorization binding"))
        ));
    }
    aether::private_file::write_private_atomic(&legacy.fixture.operations_path(), &good_journal)
        .expect("restore signed journal bytes");
    let durable =
        crate::operations::OperationStore::load(&legacy.fixture.operations_path(), NOW + 2)
            .expect("restored legacy journal");
    *legacy.fixture.service.operations.lock().await = durable;
    assert!(matches!(
        legacy.submit(&token, approval.clone(), NOW + 3).await,
        Err(RenewalError::Gateway(message)) if message == rejected_status
    ));
    assert_eq!(legacy.fixture.gateway.stage_calls.load(Ordering::SeqCst), 2);
    let operations = legacy.fixture.service.operations.lock().await;
    let operation = operations
        .get(&legacy.id, &client_key(), NOW + 3)
        .expect("operation");
    assert_eq!(operation.stage_authorization(), Some(&authorization));
    assert!(operation.view(None, None).grant.is_none());
    drop(operations);
    assert!(matches!(
        legacy.submit(&token, conflicting, NOW + 4).await,
        Err(RenewalError::Operation(OperationError::ApprovalConflict))
    ));
    assert_eq!(legacy.fixture.gateway.stage_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn legacy_companion_capabilities_reject_wrong_scope_owner_and_expiry() {
    let legacy = legacy().await;
    let view = legacy.view(NOW + 1).await;
    let read_token = view.signer_request_token.expect("read capability");
    let submit_token = view.signer_result_token.expect("submit capability");
    let before = legacy.operation_bytes(NOW + 1).await;
    let journal = std::fs::read(legacy.fixture.operations_path()).expect("durable record");
    assert!(matches!(
        legacy.fetch(&client_key(), &submit_token, NOW + 1).await,
        Err(RenewalError::Capability(
            CertificateError::CapabilityScopeViolation("scope")
        )),
    ));
    assert!(matches!(
        legacy
            .fetch(&WireGuardKey::from_bytes([0x38; 32]), &read_token, NOW + 1)
            .await,
        Err(RenewalError::Operation(OperationError::NotYours)),
    ));
    assert!(matches!(
        legacy.fetch(&client_key(), "forged-token", NOW + 1).await,
        Err(RenewalError::Capability(
            CertificateError::InvalidCapabilityToken
        )),
    ));
    assert!(matches!(
        legacy.fetch(&client_key(), &read_token, NOW + 301).await,
        Err(RenewalError::Capability(
            CertificateError::CapabilityTokenExpired
        )),
    ));
    let approval = legacy.approval(NOW + 1).await;
    assert!(matches!(
        legacy.submit(&read_token, approval.clone(), NOW + 1).await,
        Err(RenewalError::Capability(
            CertificateError::CapabilityScopeViolation("scope")
        )),
    ));
    assert!(matches!(
        legacy.submit(&submit_token, approval, NOW + 301).await,
        Err(RenewalError::Capability(
            CertificateError::CapabilityTokenExpired
        )),
    ));
    assert!(legacy.operation_bytes(NOW + 301).await == before);
    assert_eq!(
        std::fs::read(legacy.fixture.operations_path()).expect("unchanged record"),
        journal
    );
    assert!(legacy.fixture.gateway.stages.lock().await.is_empty());
    assert!(matches!(
        legacy.read_at(NOW + 7_200).await,
        Err(RenewalError::Operation(OperationError::Expired)),
    ));
}

#[tokio::test]
async fn invalid_or_expired_legacy_operator_evidence_does_not_consume_the_request() {
    let legacy = legacy().await;
    let view = legacy.view(NOW + 1).await;
    let token = view.signer_result_token.expect("submit capability");
    let before = legacy.operation_bytes(NOW + 1).await;
    let journal = std::fs::read(legacy.fixture.operations_path()).expect("durable record");
    let approval = legacy.approval(NOW + 1).await;
    let mut corrupt = approval.clone();
    corrupt.webauthn_assertion.signature[0] ^= 1;
    corrupt.assertion_fingerprint = corrupt.webauthn_assertion.fingerprint();
    assert!(matches!(
        legacy.submit(&token, corrupt, NOW + 1).await,
        Err(RenewalError::Approval(CertificateError::InvalidAssertion(
            "assertion signature"
        ))),
    ));
    let mut wrong_request = approval.clone();
    wrong_request.approval_request_fingerprint = Fingerprint::of(b"another signed manifest");
    assert!(matches!(
        legacy.submit(&token, wrong_request, NOW + 1).await,
        Err(RenewalError::Approval(CertificateError::ApprovalMismatch(
            "approval request fingerprint"
        ))),
    ));
    // A fresh capability isolates approval expiry from bearer-token expiry.
    let fresh = legacy.view(NOW + 201).await;
    assert!(matches!(
        legacy
            .submit(
                &fresh.signer_result_token.expect("fresh capability"),
                approval,
                NOW + 201
            )
            .await,
        Err(RenewalError::Approval(CertificateError::StageExpired)),
    ));
    assert!(legacy.operation_bytes(NOW + 201).await == before);
    assert_eq!(
        std::fs::read(legacy.fixture.operations_path()).expect("unchanged record"),
        journal
    );
    assert!(legacy.fixture.gateway.stages.lock().await.is_empty());
    let operations = legacy.fixture.service.operations.lock().await;
    let operation = operations
        .get(&legacy.id, &client_key(), NOW + 201)
        .expect("operation");
    assert_eq!(
        operation.state,
        ClientRenewalOperationState::AwaitingOperator
    );
    assert!(operation.approved_with().is_none());
    assert!(operation.approval_evidence().is_none());
}
