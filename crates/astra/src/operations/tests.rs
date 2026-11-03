use super::*;
use aether::certificates::{
    approval::{
        AstraCredentialBinding, AstraRenewalApproval, CredentialState, MAX_APPROVAL_LIFETIME_SECS,
    },
    encoding::{DerCertificate, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId},
    webauthn::WebAuthnAssertion,
    CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};

fn key(seed: u8) -> WireGuardKey {
    WireGuardKey::from_bytes([seed; 32])
}

fn request(client: WireGuardKey) -> Box<ClientCertificateRotationRequest> {
    let (_, public) = aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
    Box::new(ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([3; 16]).expect("id"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: key(9),
        server_name: "gateway.example".into(),
        client_wg_public_key: client,
        active_generation: 4,
        requested_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        tls_csr: DerCertificate::new(vec![7; 64]).expect("der"),
        new_ml_dsa_87_public_key: public,
        created_at: 1_000,
        expires_at: 5_000,
        active_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    })
}

fn approval_request(client: WireGuardKey) -> Box<AstraCredentialApprovalRequest> {
    Box::new(AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: Id16::new([2; 16]).expect("id"),
        request_fingerprint: Fingerprint::of(b"request"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: key(9),
        client_wg_public_key: client,
        active_generation: 4,
        requested_generation: 5,
        credential_registry_epoch: 1,
        webauthn_rp_id: "astra.example".into(),
        webauthn_origin: "https://astra.example".into(),
        allowed_credential_ids: vec![vec![1, 2, 3]],
        required_credentials: 1,
        created_at: 1_000,
        expires_at: 1_000 + MAX_APPROVAL_LIFETIME_SECS,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    })
}

fn operation(seed: u8, client: WireGuardKey) -> Operation {
    let operation_id = Id16::new([seed; 16]).expect("id");
    let request = request(client);
    let mut approval_request = approval_request(client);
    approval_request.operation_id = operation_id;
    approval_request.request_fingerprint = request.fingerprint();
    Operation::awaiting_operator(operation_id, client, request, approval_request, 1_000)
}

fn campaign_evidence(client: WireGuardKey, generation: u64) -> Box<AstraCampaignApprovalEvidence> {
    use aether::certificates::approval::CredentialRegistry;
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignApproval, CampaignScope, CampaignTarget, CertificateKind,
    };
    let campaign = AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new([7; 16]).expect("id"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: key(9),
        server_name: "gateway.example".into(),
        created_at: 1_000,
        expires_at: 1_300,
        scope: CampaignScope::FleetLeafs,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: client,
            epoch: 1,
            generation,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        }],
        reason: "rotation".into(),
        requested_by: "operator".into(),
        policy_fingerprint: Fingerprint::of(b"policy"),
        required_credentials: 1,
    };
    let approval = CampaignApproval {
        campaign_id: campaign.campaign_id,
        campaign_fingerprint: campaign.fingerprint(),
        required_credentials: 1,
        approved_at: 1_050,
        approvals: Vec::new(),
    };
    Box::new(AstraCampaignApprovalEvidence {
        campaign,
        approval,
        credential_registry: CredentialRegistry {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: key(9),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        },
        webauthn_origin: "https://astra.example".into(),
    })
}

fn evidence(operation: &Operation) -> Box<AstraRenewalApprovalEvidence> {
    let request = operation.approval_request.clone();
    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: vec![1, 2, 3],
        credential_public_key: vec![0xa5, 0x01],
        aaguid: [0; 16],
        trust_domain_id: request.trust_domain_id,
        gateway_wg_public_key: request.gateway_wg_public_key,
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 1_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    };
    let assertion = WebAuthnAssertion {
        authenticator_data: vec![1],
        client_data_json: vec![2],
        signature: vec![3],
    };
    Box::new(AstraRenewalApprovalEvidence {
        approval_request: (*request).clone(),
        approval: AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: request.operation_id,
            request_fingerprint: request.request_fingerprint,
            approval_request_fingerprint: request.fingerprint(),
            credential_fingerprint: binding.fingerprint(),
            credential_binding: binding,
            assertion_fingerprint: assertion.fingerprint(),
            webauthn_assertion: assertion,
            approved_at: 1_001,
            expires_at: 1_200,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        },
    })
}

fn receipt() -> Box<GatewayCertificateStageReceipt> {
    Box::new(GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        stage_id: Id16::new([8; 16]).expect("id"),
        stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        gateway_wg_public_key: key(9),
        client_wg_public_key: key(2),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
        persisted_at: 1_100,
        stage_expires_at: 4_000,
        active_gateway_identity_epoch: 3,
        gateway_decision_epoch: 3,
        gateway_certificate_fingerprint: Fingerprint::of(b"gateway leaf"),
        gateway_signature: MlDsa87Signature::placeholder(),
    })
}

fn grant() -> Box<ClientCertificateRotationGrant> {
    Box::new(ClientCertificateRotationGrant {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: aether::certificates::client::IssuerKind::Astra,
        issuer_epoch: 1,
        issuer_authorization_fingerprint: Fingerprint::of(b"delegation"),
        issuer_authorization: None,
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: receipt().fingerprint(),
        stage_receipt: *receipt(),
        gateway_wg_public_key: key(9),
        server_name: "gateway.example".into(),
        client_wg_public_key: key(2),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        next_tls_certificate: DerCertificate::new(vec![5; 64]).expect("der"),
        next_pq_certificate: aether::key_negotiation::PqCertificate {
            version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [4; 16],
            subject: "workstation".into(),
            issuer: "astra-delegated-issuer".into(),
            role: aether::key_negotiation::PqCertificateRole::Client,
            wireguard_public_key: key(2).to_base64(),
            ml_dsa_87_public_key: MlDsa87PublicKey::parse(
                &aether::certificates::encoding::generate_ml_dsa_87_keypair()
                    .expect("keygen")
                    .1
                    .to_base64(),
            )
            .expect("key")
            .to_base64(),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        },
        stage_expires_at: 4_000,
        window: aether::certificates::window::TransitionWindow::new(1_000, 2_000, 90_000)
            .expect("window"),
        reason: aether::certificates::authority::RotationReason::Scheduled,
        signature: MlDsa87Signature::placeholder(),
    })
}

/// The point of the amendment of 15 August 2026: the threshold prepares,
/// and nothing else moves without an operator.
#[test]
fn an_operation_is_born_awaiting_an_operator_and_carries_no_grant() {
    let operation = operation(1, key(2));
    assert_eq!(
        operation.state,
        ClientRenewalOperationState::AwaitingOperator
    );
    let view = operation.view(Some("read".into()), Some("submit".into()));
    assert!(view.grant.is_none());
    assert_eq!(view.signer_request_token.as_deref(), Some("read"));
    assert_eq!(view.signer_result_token.as_deref(), Some("submit"));
}

/// The current ordinary path spends no credential: the signed request is
/// persisted as its exact authorization and the operation can issue.
#[test]
fn a_due_operation_is_authorized_automatically_for_its_exact_request() {
    let mut operation = operation(1, key(2));
    let expected = operation.request_fingerprint;
    operation
        .authorize_automatic()
        .expect("automatic authorization");

    assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
    assert!(matches!(
        operation.approval(),
        Some(DelegatedApproval::Automatic(fingerprint)) if fingerprint.matches(&expected)
    ));
    let view = operation.view(Some("read".into()), Some("submit".into()));
    assert!(view.signer_request_token.is_none());
    assert!(view.signer_result_token.is_none());
}

#[test]
fn an_operation_survives_restart_but_an_expired_one_does_not() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("operations.json");
    let id = Id16::new([1; 16]).expect("id");
    let mut store = OperationStore::load(&path, 1_000).expect("new store");
    store.open(operation(1, key(2)), 1_000).expect("open");
    store.persist().expect("persist");

    let restarted = OperationStore::load(&path, 1_001).expect("restart");
    restarted.get(&id, &key(2), 1_001).expect("survives");

    let expired = OperationStore::load(&path, 5_000).expect("purges expired");
    assert!(expired.is_empty());
    assert!(matches!(
        expired.get(&id, &key(2), 5_000),
        Err(OperationError::Unknown)
    ));
}

#[test]
fn an_approved_operation_resumes_without_a_second_touch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("operations.json");
    let id = Id16::new([1; 16]).expect("id");
    let mut operation = operation(1, key(2));
    let approval = Fingerprint::of(b"an approval");
    let accepted_evidence = evidence(&operation);
    operation
        .consume_approval(approval, accepted_evidence)
        .expect("approval");

    let mut store = OperationStore::load(&path, 1_000).expect("new store");
    store.open(operation, 1_000).expect("open");
    store.persist().expect("persist");

    let restarted = OperationStore::load(&path, 1_001).expect("restart");
    let resumed = restarted.get(&id, &key(2), 1_001).expect("operation");
    assert_eq!(resumed.state, ClientRenewalOperationState::PendingGrant);
    assert_eq!(resumed.approved_with(), Some(approval));
    assert!(resumed.approval_evidence().is_some());
}

/// A grant before the receipt would be the authority releasing an identity
/// the gateway has not admitted.
#[test]
fn a_grant_before_the_receipt_is_refused() {
    let mut operation = operation(1, key(2));
    assert_eq!(
        operation.record_grant(grant()),
        Err(OperationError::ReceiptRequired)
    );
    assert_eq!(
        operation.state,
        ClientRenewalOperationState::AwaitingOperator
    );

    operation.record_receipt(receipt()).expect("receipt");
    operation.record_grant(grant()).expect("grant");
    assert_eq!(operation.state, ClientRenewalOperationState::PendingCommit);
    assert!(operation
        .view(Some("read".into()), Some("submit".into()))
        .grant
        .is_some());
}

/// Once the grant exists the companion has nothing left to do, so it is
/// handed no token to do it with.
#[test]
fn a_granted_operation_hands_out_no_capability_token() {
    let mut operation = operation(1, key(2));
    operation.record_receipt(receipt()).expect("receipt");
    operation.record_grant(grant()).expect("grant");
    let view = operation.view(Some("read".into()), Some("submit".into()));
    assert!(view.signer_request_token.is_none());
    assert!(view.signer_result_token.is_none());
}

/// A receipt is idempotent when identical and a conflict otherwise: the
/// same `stage_id` with other bytes describes another fact.
#[test]
fn a_second_receipt_is_idempotent_only_if_it_is_the_same_one() {
    let mut operation = operation(1, key(2));
    operation.record_receipt(receipt()).expect("receipt");
    operation.record_receipt(receipt()).expect("replay");

    let mut other = receipt();
    other.staged_generation = 6;
    assert_eq!(
        operation.record_receipt(other),
        Err(OperationError::ReceiptConflict)
    );
}

/// The challenge may be re-minted while an operator is still expected, and
/// never afterwards: a fresh challenge on an approved operation invites a
/// second approval of one renewal.
#[test]
fn the_challenge_is_re_minted_only_while_an_operator_is_expected() {
    let mut operation = operation(1, key(2));
    operation
        .refresh_approval_request(approval_request(key(2)))
        .expect("refresh");

    operation.record_receipt(receipt()).expect("receipt");
    operation.record_grant(grant()).expect("grant");
    assert_eq!(
        operation.refresh_approval_request(approval_request(key(2))),
        Err(OperationError::NotAwaitingOperator)
    );
}

/// An operation belongs to the peer that opened it, and to nobody else.
#[test]
fn another_peer_cannot_read_an_operation() {
    let mut store = OperationStore::new();
    store.open(operation(1, key(2)), 1_000).expect("open");
    let id = Id16::new([1; 16]).expect("id");

    store.get(&id, &key(2), 1_100).expect("its owner");
    assert_eq!(
        store.get(&id, &key(3), 1_100).map(|_| ()),
        Err(OperationError::NotYours)
    );
}

/// One in flight per peer, and expired debris blocks nothing.
#[test]
fn one_operation_per_peer_and_expired_ones_free_the_slot() {
    let mut store = OperationStore::new();
    store.open(operation(1, key(2)), 1_000).expect("open");
    assert_eq!(
        store.open(operation(4, key(2)), 1_100),
        Err(OperationError::AlreadyInFlight)
    );
    // Another peer is unaffected: the bound is per peer, not global.
    store.open(operation(5, key(3)), 1_100).expect("other peer");
    assert_eq!(store.len(), 2);
    store
        .get(&Id16::new([5; 16]).expect("id"), &key(3), 1_100)
        .expect("and it is readable while it lives");

    // Past the request's own deadline the slot is free again. Every
    // operation here expires with the same request, so the sweep at 5_000
    // takes both of the older ones and only the fresh one is left — which
    // is the property: debris blocks nothing, and it does not linger.
    store
        .open(operation(6, key(2)), 5_000)
        .expect("after expiry");
    assert_eq!(store.len(), 1, "the expired ones were swept");
}

/// An expired operation is refused rather than read: a client polling one
/// must learn it has to start again.
#[test]
fn an_expired_operation_is_refused_on_read() {
    let mut store = OperationStore::new();
    store.open(operation(1, key(2)), 1_000).expect("open");
    let id = Id16::new([1; 16]).expect("id");
    assert_eq!(
        store.get(&id, &key(2), 5_000).map(|_| ()),
        Err(OperationError::Expired)
    );
}

/// One approval opens one issuance. A second consumption — the same
/// assertion replayed, or another one — is refused.
#[test]
fn an_approval_is_spent_once() {
    let mut operation = operation(1, key(2));
    let approval = Fingerprint::of(b"an approval");
    let accepted_evidence = evidence(&operation);
    operation
        .consume_approval(approval, accepted_evidence)
        .expect("first");
    assert_eq!(operation.approved_with(), Some(approval));
    let replayed_evidence = evidence(&operation);
    assert_eq!(
        operation.consume_approval(approval, replayed_evidence),
        Err(OperationError::NotAwaitingOperator)
    );
    let conflicting_evidence = evidence(&operation);
    assert_eq!(
        operation.consume_approval(Fingerprint::of(b"another approval"), conflicting_evidence),
        Err(OperationError::NotAwaitingOperator)
    );

    // And past `awaiting_operator` no approval is accepted at all.
    operation.record_receipt(receipt()).expect("receipt");
    operation.record_grant(grant()).expect("grant");
    let late_evidence = evidence(&operation);
    assert_eq!(
        operation.consume_approval(Fingerprint::of(b"late"), late_evidence),
        Err(OperationError::NotAwaitingOperator)
    );
}

#[test]
fn an_accepted_submission_is_idempotent_only_for_identical_bytes() {
    let mut operation = operation(1, key(2));
    let submitted = Fingerprint::of(b"companion result");
    let accepted_evidence = evidence(&operation);
    operation
        .consume_approval(submitted, accepted_evidence)
        .expect("first submission");

    assert!(operation
        .is_idempotent_submission(&submitted)
        .expect("same result"));
    assert_eq!(
        operation.is_idempotent_submission(&Fingerprint::of(b"different result")),
        Err(OperationError::ApprovalConflict)
    );
}

/// A failed operation carries no grant and no token: polling it forever is
/// how a client never renews.
#[test]
fn a_failed_operation_carries_nothing() {
    let mut operation = operation(1, key(2));
    operation.record_receipt(receipt()).expect("receipt");
    operation.record_grant(grant()).expect("grant");
    operation.fail();
    let view = operation.view(Some("read".into()), Some("submit".into()));
    assert_eq!(view.state, ClientRenewalOperationState::Failed);
    assert!(view.grant.is_none());
    assert!(view.signer_request_token.is_none());
}

/// A campaign approved before this request existed: nobody is asked
/// anything, so the operation never rests in `awaiting_operator`.
#[test]
fn a_covering_campaign_opens_an_operation_that_asks_no_one() {
    let client = key(1);
    let mut operation = operation(2, client);
    let evidence = campaign_evidence(client, 4);
    operation
        .consume_campaign_approval(Fingerprint::of(b"campaign"), evidence)
        .expect("covered");

    assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
    assert!(matches!(
        operation.approval(),
        Some(DelegatedApproval::Campaign(_))
    ));
    // The reason travels with the family, all the way to the issuer.
    assert_eq!(
        operation.approval().expect("approval").reason(),
        aether::certificates::authority::RotationReason::ManualGlobal
    );
}

/// The lookup is not the last word: the campaign has to cover the request
/// this operation actually carries.
#[test]
fn a_campaign_describing_another_generation_authorizes_nothing_here() {
    let client = key(1);
    let mut operation = operation(2, client);
    // The request is generation 4 -> 5; this campaign was approved for 3.
    let evidence = campaign_evidence(client, 3);
    assert!(matches!(
        operation.consume_campaign_approval(Fingerprint::of(b"campaign"), evidence),
        Err(OperationError::Corrupt("campaign evidence binding"))
    ));
    assert_eq!(
        operation.state,
        ClientRenewalOperationState::AwaitingOperator
    );
}

/// One approval, one issuance — whichever family it came from.
#[test]
fn a_campaign_approval_is_spent_once() {
    let client = key(1);
    let mut operation = operation(2, client);
    operation
        .consume_campaign_approval(Fingerprint::of(b"campaign"), campaign_evidence(client, 4))
        .expect("covered");
    assert!(matches!(
        operation
            .consume_campaign_approval(Fingerprint::of(b"campaign"), campaign_evidence(client, 4)),
        Err(OperationError::NotAwaitingOperator)
    ));
    // And the ordinary ceremony cannot approve it a second time either.
    let ordinary = evidence(&operation);
    assert!(matches!(
        operation.consume_approval(Fingerprint::of(b"other"), ordinary),
        Err(OperationError::NotAwaitingOperator)
    ));
}

/// A record carrying both families leaves «which one authorized this» to
/// whoever reads it first. It is refused on reload, and read as nothing.
#[test]
fn a_record_carrying_two_approval_families_is_refused() {
    let client = key(1);
    let mut operation = operation(2, client);
    operation
        .consume_campaign_approval(Fingerprint::of(b"campaign"), campaign_evidence(client, 4))
        .expect("covered");
    // Only a corrupted journal can reach this shape; construct it here so
    // the refusal is exercised rather than assumed.
    operation.approval_evidence = Some(evidence(&operation));

    assert!(operation.approval().is_none());
    assert!(matches!(
        operation.validate_persisted(),
        Err(OperationError::Corrupt("two approval families"))
    ));
}

/// Structural journal fixtures do not claim certificate/signature validity.
fn staged_journal_record(operation: &Operation) -> Box<ClientCertificateStageAuthorization> {
    let template = *grant();
    Box::new(ClientCertificateStageAuthorization {
        format_version: template.format_version,
        protocol_version: template.protocol_version,
        trust_domain_id: template.trust_domain_id,
        ca_epoch: template.ca_epoch,
        ca_tls_epoch: template.ca_tls_epoch,
        issuer_kind: template.issuer_kind,
        issuer_epoch: template.issuer_epoch,
        issuer_authorization_fingerprint: template.issuer_authorization_fingerprint,
        issuer_authorization: template.issuer_authorization,
        stage_id: Id16::new([8; 16]).expect("stage ID"),
        request_fingerprint: operation.request_fingerprint,
        renewal_authorization_fingerprint: operation.approved_with().expect("authorized operation"),
        renewal_approval: None,
        campaign_approval: operation.campaign_evidence.clone(),
        gateway_wg_public_key: template.gateway_wg_public_key,
        server_name: template.server_name,
        client_wg_public_key: operation.client_wg_public_key,
        active_generation: template.active_generation,
        next_generation: template.next_generation,
        active_tls_certificate_fingerprint: template.active_tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: template.active_pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: template.next_tls_ca_certificate_fingerprint,
        next_tls_certificate: template.next_tls_certificate,
        next_pq_certificate: template.next_pq_certificate,
        issued_at: 1_100,
        stage_expires_at: template.stage_expires_at,
        window: template.window,
        reason: operation.approval().expect("authorization family").reason(),
        signature: template.signature,
    })
}

#[test]
fn automatic_and_campaign_journals_keep_their_exact_stage_binding_on_reload() {
    for manual_campaign in [false, true] {
        let mut operation = operation(1, key(2));
        if manual_campaign {
            let evidence = campaign_evidence(key(2), 4);
            let fingerprint = evidence.fingerprint().expect("campaign fingerprint");
            operation
                .consume_campaign_approval(fingerprint, evidence)
                .expect("campaign authorization");
        } else {
            operation
                .authorize_automatic()
                .expect("due automatic request");
        }
        operation
            .record_stage(staged_journal_record(&operation))
            .expect("stage recorded");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("operations.json");
        let id = operation.operation_id;
        let mut store = OperationStore::load(&path, 1_100).expect("empty journal");
        store.open(operation.clone(), 1_100).expect("open record");
        store.persist().expect("durable stage");
        let loaded = OperationStore::load(&path, 1_101).expect("valid stage reloads");
        assert_eq!(
            loaded
                .get(&id, &key(2), 1_101)
                .expect("record")
                .stage_authorization(),
            operation.stage_authorization()
        );
        // Neither a changed authorization nor a changed consumed decision may
        // be accepted in automatic/campaign records after the legacy fix.
        for change_stage in [false, true] {
            let mut corrupted = operation.clone();
            if change_stage {
                corrupted
                    .stage_authorization
                    .as_mut()
                    .expect("stage")
                    .renewal_authorization_fingerprint = Fingerprint::of(b"other decision");
            } else {
                corrupted.approved_with = Some(Fingerprint::of(b"other consumed decision"));
            }
            let mut bad = OperationStore::load(&path, 1_101).expect("valid journal");
            *bad.get_mut(&id, &key(2), 1_101).expect("record") = corrupted;
            bad.persist().expect("model corrupted journal");
            assert!(matches!(
                OperationStore::load(&path, 1_101),
                Err(OperationError::Corrupt("stage authorization binding"))
            ));
            store.persist().expect("restore valid journal");
        }
    }
}

#[test]
fn a_rejected_journal_update_keeps_the_original_identity_and_durable_state() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("operations.json");
    let operation = operation(1, key(2));
    let id = operation.operation_id;
    let mut store = OperationStore::load(&path, 1_100).expect("empty journal");
    store.open(operation, 1_100).expect("record");
    store.persist().expect("durable awaiting record");
    let bytes = std::fs::read(&path).expect("journal");
    let snapshot =
        serde_json::to_value(store.get(&id, &key(2), 1_100).expect("record")).expect("snapshot");
    assert!(matches!(
        store.update_persisted(&id, &key(2), 1_100, |candidate| {
            candidate.client_wg_public_key = key(3);
            Ok(())
        }),
        Err(OperationError::Corrupt("identity or request binding"))
    ));
    assert!(matches!(
        store.update_persisted(&id, &key(2), 1_100, |candidate| {
            candidate.authorize_automatic()?;
            Err(OperationError::ApprovalConflict)
        }),
        Err(OperationError::ApprovalConflict)
    ));
    assert!(matches!(
        store.update_persisted(&id, &key(2), 1_100, |candidate| {
            let replacement = Id16::new([3; 16]).expect("other operation ID");
            candidate.operation_id = replacement;
            candidate.approval_request.operation_id = replacement;
            Ok(())
        }),
        Err(OperationError::Corrupt("operation update changed identity"))
    ));
    assert!(matches!(
        store.update_persisted(&id, &key(2), 1_100, |candidate| {
            candidate.request.created_at -= 1;
            candidate.request_fingerprint = candidate.request.fingerprint();
            candidate.approval_request.request_fingerprint = candidate.request_fingerprint;
            Ok(())
        }),
        Err(OperationError::Corrupt("operation update changed identity"))
    ));
    assert_eq!(
        serde_json::to_value(store.get(&id, &key(2), 1_100).expect("record")).expect("snapshot"),
        snapshot
    );
    assert_eq!(std::fs::read(&path).expect("journal unchanged"), bytes);
    store
        .update_persisted(&id, &key(2), 1_100, Operation::authorize_automatic)
        .expect("valid candidate published");
    let loaded = OperationStore::load(&path, 1_101).expect("reload accepted update");
    let operation = loaded.get(&id, &key(2), 1_101).expect("record");
    assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
    assert_eq!(
        operation.approved_with(),
        Some(operation.request_fingerprint)
    );
}
