use super::*;
use aether::certificates::{
    client::{ClientCertificateStageAuthorization, GatewayCertificateStageReceipt},
    encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature, WireGuardKey},
    gateway::pq_certificate_fingerprint,
    transport::ExpiredRecoveryState,
    CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use std::cell::RefCell;

use crate::operations::fixtures::{
    domain, gateway_key, operation, trust_domain, Domain, EXPIRES, NOW, ORIGIN, SERVER_NAME,
};

fn recovery_domain() -> Domain {
    let domain = domain();
    domain.keys[0].allow_combined_opening.set(true);
    domain
}

fn pq_leaf(
    role: PqCertificateRole,
    identity: WireGuardKey,
    key: &MlDsa87PublicKey,
    validity: (u64, u64),
    issuer_key: &[u8],
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [4; 16],
            subject: "workstation".into(),
            issuer: "test-pq-issuer".into(),
            role,
            wireguard_public_key: identity.to_base64(),
            ml_dsa_87_public_key: key.to_base64(),
            not_before_unix: validity.0,
            not_after_unix: validity.1,
            ml_dsa_87_signature: String::new(),
        },
        issuer_key,
    )
    .expect("signed PQ leaf")
}

fn request(domain: &Domain) -> ExpiredCertificateRecoveryRequest {
    let (old_private, old_public) = generate_ml_dsa_87_keypair().expect("expired key");
    let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("candidate key");
    let client = WireGuardKey::from_bytes([0x33; 32]);
    let tls = aether::certificates::test_x509::client_material("workstation");
    ExpiredCertificateRecoveryRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: trust_domain(),
        astra_challenge: [0x77; 32],
        request_id: Id16::new([9; 16]).expect("request ID"),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client,
        expired_generation: 4,
        requested_generation: 5,
        expired_tls_certificate: tls.leaf,
        expired_pq_certificate: pq_leaf(
            PqCertificateRole::Client,
            client,
            &old_public,
            (NOW - 2 * DAY_SECS, NOW - DAY_SECS),
            &old_private,
        ),
        tls_csr: tls.csr,
        new_ml_dsa_87_public_key: next_public,
        credential_id: domain.keys[0].credential_id(),
        created_at: NOW,
        expires_at: EXPIRES,
        expired_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&old_private, &next_private)
    .expect("signed recovery request")
}

fn awaiting(request: &ExpiredCertificateRecoveryRequest) -> ExpiredRecoveryOperationView {
    ExpiredRecoveryOperationView {
        operation_id: operation(),
        state: ExpiredRecoveryState::AwaitingOperator,
        client_wg_public_key: request.client_wg_public_key,
        request_fingerprint: request.fingerprint(),
        created_at: request.created_at,
        expires_at: request.expires_at,
        request: Some(Box::new(request.clone())),
        receipt: None,
        gateway_pq_certificate: None,
        grant: None,
    }
}

fn verified(domain: &Domain, request: &ExpiredCertificateRecoveryRequest) -> Verified {
    begin_with_fetch(&domain.path, operation(), None, None, NOW, |client, id| {
        assert_eq!(client.base(), ORIGIN);
        assert_eq!(*id, operation());
        Ok(awaiting(request))
    })
    .expect("prepared recovery")
}

fn receipt(
    authorization: &ClientCertificateStageAuthorization,
    gateway_leaf: &PqCertificate,
    gateway_private: &[u8],
    staged_generation: u64,
) -> GatewayCertificateStageReceipt {
    GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: authorization.trust_domain_id,
        stage_id: authorization.stage_id,
        stage_authorization_fingerprint: authorization.fingerprint().expect("authorization digest"),
        request_fingerprint: authorization.request_fingerprint,
        renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        client_wg_public_key: authorization.client_wg_public_key,
        active_generation: authorization.active_generation,
        staged_generation,
        staged_tls_certificate_fingerprint: authorization.next_tls_certificate.fingerprint(),
        staged_pq_certificate_fingerprint: pq_certificate_fingerprint(
            &authorization.next_pq_certificate,
        )
        .expect("candidate fingerprint"),
        persisted_at: NOW,
        stage_expires_at: authorization.stage_expires_at,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: pq_certificate_fingerprint(gateway_leaf)
            .expect("gateway fingerprint"),
        gateway_signature: MlDsa87Signature::placeholder(),
    }
    .sign(gateway_private)
    .expect("signed gateway receipt")
}

#[test]
fn the_manifest_names_the_expired_generation_without_opening_the_vault() {
    let domain = recovery_domain();
    let request = request(&domain);
    let verified = verified(&domain, &request);
    let manifest = verified.manifest();
    assert_eq!(verified.operation(), operation());
    assert_eq!(manifest.peer_name, "workstation");
    assert_eq!(manifest.trust_domain_id, trust_domain());
    assert_eq!(
        manifest.client_wg_public_key,
        request.client_wg_public_key.to_base64()
    );
    assert_eq!(manifest.request_fingerprint, request.fingerprint());
    assert_eq!(
        (manifest.expired_generation, manifest.next_generation),
        (4, 5)
    );
    assert_eq!(manifest.expired_since_secs, DAY_SECS);
    assert_eq!(
        (manifest.activation_at, manifest.not_after),
        (NOW, NOW + DAY_SECS)
    );
    assert_eq!(domain.touches(), 0);
}

#[test]
fn a_conflicting_origin_and_a_missing_request_never_touch_the_key() {
    let domain = recovery_domain();
    let Err(error) = begin_with_fetch(
        &domain.path,
        operation(),
        Some("https://other.example.test"),
        None,
        NOW,
        |_, _| panic!("the offered origin must not be contacted"),
    ) else {
        panic!("an offered origin cannot replace the pin");
    };
    assert!(error.to_string().contains("épingle l'origine"));

    let mut view = awaiting(&request(&domain));
    view.request = None;
    let Err(error) = begin_with_fetch(&domain.path, operation(), None, None, NOW, |_, _| Ok(view))
    else {
        panic!("a view without the request cannot prepare a recovery");
    };
    assert!(error.to_string().contains("ne rend pas la demande"));
    assert_eq!(domain.touches(), 0);
}

#[test]
fn a_signed_gateway_receipt_releases_only_the_grant_bound_to_the_approved_request() {
    let domain = recovery_domain();
    let request = request(&domain);
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let gateway_leaf = pq_leaf(
        PqCertificateRole::Gateway,
        gateway_key(),
        &gateway_public,
        (NOW - 60, NOW + DAY_SECS),
        &gateway_private,
    );
    let ca = MlDsa87PublicKey::parse(&domain.relay().ca_pq_public_key).expect("CA-PQ");
    let events = RefCell::new(Vec::new());
    let expected_receipt = RefCell::new(None);
    verified(&domain, &request)
        .approve_with_transport(
            &domain.keys[0],
            "",
            &mut |state| events.borrow_mut().push(state),
            |origin, id, deposit| {
                assert_eq!(origin.base(), ORIGIN);
                assert_eq!(*id, operation());
                assert_eq!(*events.borrow(), [RemoteState::Prepared]);
                assert_eq!(domain.touches(), 1, "approval and opening are one gesture");
                let authorization = &deposit.authorization;
                assert_eq!(authorization.request_fingerprint, request.fingerprint());
                assert_eq!(
                    deposit.evidence.approval.request_fingerprint,
                    request.fingerprint()
                );
                assert_eq!(
                    authorization.renewal_authorization_fingerprint,
                    deposit.evidence.fingerprint().expect("evidence digest")
                );
                assert_eq!(authorization.stage_expires_at, request.expires_at);
                assert_eq!(authorization.window.activation_at, NOW);
                let receipt = receipt(
                    authorization,
                    &gateway_leaf,
                    &gateway_private,
                    request.requested_generation,
                );
                *expected_receipt.borrow_mut() = Some(receipt.fingerprint());
                Ok(ExpiredRecoveryOperationView {
                    state: ExpiredRecoveryState::Staged,
                    gateway_pq_certificate: Some(Box::new(gateway_leaf.clone())),
                    receipt: Some(Box::new(receipt)),
                    ..awaiting(&request)
                })
            },
            |origin, id, deposit| {
                assert_eq!(origin.base(), ORIGIN);
                assert_eq!(*id, operation());
                assert_eq!(
                    *events.borrow(),
                    [
                        RemoteState::Prepared,
                        RemoteState::Staged,
                        RemoteState::PendingGrant
                    ]
                );
                let grant = &deposit.grant;
                assert_eq!(grant.request_fingerprint, request.fingerprint());
                assert_eq!(
                    Some(grant.stage_receipt_fingerprint),
                    *expected_receipt.borrow()
                );
                assert_eq!(grant.next_generation, request.requested_generation);
                grant
                    .verify_signed_by(&ca)
                    .expect("grant signed by the pinned CA");
                Ok(ExpiredRecoveryOperationView {
                    state: ExpiredRecoveryState::Granted,
                    grant: Some(grant.clone()),
                    ..awaiting(&request)
                })
            },
        )
        .expect("recovery deposits the grant");
    assert_eq!(
        domain.touches(),
        2,
        "one approval, then one opening after staging"
    );
    assert_eq!(
        *events.borrow(),
        [
            RemoteState::Prepared,
            RemoteState::Staged,
            RemoteState::PendingGrant,
            RemoteState::Granted
        ],
    );
}

#[test]
fn an_incomplete_or_disagreeing_stage_response_never_deposits_a_grant() {
    let domain = recovery_domain();
    let request = request(&domain);
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let gateway_leaf = pq_leaf(
        PqCertificateRole::Gateway,
        gateway_key(),
        &gateway_public,
        (NOW - 60, NOW + DAY_SECS),
        &gateway_private,
    );
    for (has_receipt, has_leaf, same_gateway, generation, expected, pending_grant) in [
        (false, true, true, 5, "n'a pas rendu le reçu", false),
        (true, false, true, 5, "n'a pas rendu la feuille", false),
        (true, true, false, 5, "une autre gateway", false),
        (true, true, true, 6, "generation", true),
    ] {
        let mut events = Vec::new();
        let before = domain.touches();
        let error = verified(&domain, &request)
            .approve_with_transport(
                &domain.keys[0],
                "",
                &mut |state| events.push(state),
                |_, _, deposit| {
                    let mut leaf = gateway_leaf.clone();
                    if !same_gateway {
                        leaf.wireguard_public_key =
                            WireGuardKey::from_bytes([0x22; 32]).to_base64();
                    }
                    Ok(ExpiredRecoveryOperationView {
                        state: ExpiredRecoveryState::Staged,
                        receipt: has_receipt.then(|| {
                            Box::new(receipt(
                                &deposit.authorization,
                                &gateway_leaf,
                                &gateway_private,
                                generation,
                            ))
                        }),
                        gateway_pq_certificate: has_leaf.then_some(Box::new(leaf)),
                        ..awaiting(&request)
                    })
                },
                |_, _, _| panic!("an invalid stage cannot yield a grant"),
            )
            .expect_err("invalid staging response");
        assert!(error.to_string().contains(expected), "{error:#}");
        if pending_grant {
            assert_eq!(
                events,
                [
                    RemoteState::Prepared,
                    RemoteState::Staged,
                    RemoteState::PendingGrant
                ]
            );
            assert_eq!(domain.touches() - before, 2);
        } else {
            assert_eq!(events, [RemoteState::Prepared, RemoteState::Staged]);
            assert_eq!(domain.touches() - before, 1);
        }
    }
}

#[test]
fn a_declined_key_and_a_failed_authorization_deposit_stop_the_ceremony() {
    let domain = recovery_domain();
    let request = request(&domain);
    domain.keys[0].declines.set(true);
    assert!(verified(&domain, &request)
        .approve_with_transport(
            &domain.keys[0],
            "",
            &mut |_| panic!("declined key produces no progress"),
            |_, _, _| panic!("declined key authorizes nothing"),
            |_, _, _| panic!("declined key grants nothing"),
        )
        .is_err());
    domain.keys[0].declines.set(false);
    let mut events = Vec::new();
    let error = verified(&domain, &request)
        .approve_with_transport(
            &domain.keys[0],
            "",
            &mut |state| events.push(state),
            |_, _, _| bail!("fixture authorization deposit error"),
            |_, _, _| panic!("failed deposit cannot yield a grant"),
        )
        .expect_err("authority refused the authorization");
    assert_eq!(error.to_string(), "fixture authorization deposit error");
    assert_eq!(events, [RemoteState::Prepared]);
    assert_eq!(domain.touches(), 1);
}
