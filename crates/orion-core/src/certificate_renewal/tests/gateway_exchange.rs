//! The in-tunnel exchange of spec §8.1.2: the request this client signs, the
//! operation views it adopts or refuses, and the grant it verifies, stages and
//! commits.

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87PublicKey, WireGuardKey,
};
use aether::certificates::transport::{ClientRenewalOperationState, ClientRenewalOperationView};
use aether::certificates::CertificateError;
use zeroize::Zeroizing;

use super::fixtures::{grant, session, window};
use crate::certificate_renewal::{ActiveIdentity, RenewalError, RenewalSession, RenewalStep};
use crate::test_domain::*;

/// The request is built from the store and from nothing else, and both
/// proofs are made — which is exactly what the gateway will check.
#[test]
fn a_prepared_request_verifies_against_the_active_generation() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let session = session(&store, &domain);

    let active_public = MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
        .expect("active public key");
    session
        .request()
        .verify(
            &active_public,
            &domain_id(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(&domain),
            &client_key(),
            NOW,
        )
        .expect("the request the client signed is the one the gateway accepts");
    assert_eq!(session.request().requested_generation, 5);
}

/// Continuity is proved by the **active** key, not by the candidate's. A
/// request signed twice with the new key would carry two valid signatures
/// and still be a stranger's.
#[test]
fn a_request_signed_by_the_wrong_active_key_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mut session =
        RenewalSession::prepare(&store, SUBJECT, "http://100.64.0.1:8080", NOW).expect("prepare");
    let (stranger, _) = generate_ml_dsa_87_keypair().expect("stranger");
    session
        .sign(&ActiveIdentity {
            pq_private_key: stranger,
            tls_private_key_der: Zeroizing::new(vec![0; 32]),
        })
        .expect("sign");

    let active_public = MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
        .expect("active public key");
    assert!(session
        .request()
        .verify(
            &active_public,
            &domain_id(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(&domain),
            &client_key(),
            NOW,
        )
        .is_err());
}

/// The whole point of the CSR: the grant's leaf certifies the key this
/// machine generated, and the client refuses one that does not.
#[test]
fn a_verified_grant_stages_and_commits() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let session = session(&store, &domain);
    let grant = grant(&domain, &session, window());

    let state = store.state();
    grant
        .verify(
            &domain.ca_pq_public,
            &MlDsa87PublicKey::parse(&domain.gateway_leaf.ml_dsa_87_public_key)
                .expect("gateway key"),
            &aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                .expect("gateway fingerprint"),
            &state.trust_domain_id,
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            session.request(),
            &[&domain.tls_ca_der],
            Some(&state.astra.astra_policy_fingerprint),
            NOW,
        )
        .expect("the grant this client asked for");

    store
        .stage_verified_grant(&grant, NOW)
        .expect("candidate persisted");
    assert_eq!(
        store
            .state()
            .certificates
            .pending
            .as_ref()
            .expect("pending")
            .state,
        aether::certificates::state::PendingStageState::PendingCommit,
        "a client holds a candidate only once the grant exists"
    );

    store
        .commit_staged_candidate(
            &grant.stage_receipt.stage_id,
            &Fingerprint::of(b"commit"),
            NOW,
        )
        .expect("committed");
    let committed = store.state();
    assert!(committed.certificates.pending.is_none());
    assert_eq!(
        committed
            .certificates
            .next
            .as_ref()
            .expect("next")
            .generation,
        5
    );
    assert_eq!(
        committed.certificates.active.generation, 4,
        "still connects"
    );
}

/// A grant issued for somebody else's CSR is refused before anything is
/// written — the failure a signature check alone would not catch.
#[test]
fn a_grant_certifying_another_key_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mine = session(&store, &domain);
    let theirs = session(&store, &domain);
    let stranger = grant(&domain, &theirs, window());

    let state = store.state();
    let refusal = stranger
        .verify(
            &domain.ca_pq_public,
            &MlDsa87PublicKey::parse(&domain.gateway_leaf.ml_dsa_87_public_key)
                .expect("gateway key"),
            &aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                .expect("gateway fingerprint"),
            &state.trust_domain_id,
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            mine.request(),
            &[&domain.tls_ca_der],
            Some(&state.astra.astra_policy_fingerprint),
            NOW,
        )
        .expect_err("a grant for another CSR is not this client's");
    assert!(
        matches!(refusal, CertificateError::InvalidX509(_)),
        "expected the CSR binding to fail first, got {refusal:?}"
    );
}

/// The gateway names which operation it opened; a view about another
/// renewal, or another peer, is refused rather than adopted.
#[test]
fn an_operation_about_another_renewal_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mut session = session(&store, &domain);

    let mut view = ClientRenewalOperationView {
        operation_id: Id16::new([6; 16]).expect("id"),
        // `AwaitingOperator` is no longer a state a scheduled renewal
        // reaches; the authority issues as soon as the request is due.
        state: ClientRenewalOperationState::PendingGrant,
        client_wg_public_key: client_key(),
        request_fingerprint: session.request_fingerprint(),
        operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
        created_at: NOW,
        expires_at: NOW + 300,
        signer_request_token: None,
        signer_result_token: None,
        grant: None,
    };
    assert!(matches!(
        session.adopt(view.clone()).expect("ours"),
        RenewalStep::Issuing { .. }
    ));

    view.request_fingerprint = Fingerprint::of(b"somebody else's request");
    assert!(matches!(
        session.adopt(view.clone()),
        Err(RenewalError::OperationMismatch { .. })
    ));

    view.request_fingerprint = session.request_fingerprint();
    view.client_wg_public_key = WireGuardKey::from_bytes([3; 32]);
    assert!(matches!(
        session.adopt(view.clone()),
        Err(RenewalError::OperationMismatch { .. })
    ));

    view.client_wg_public_key = client_key();
    view.operation_id = Id16::new([7; 16]).expect("id");
    assert!(
        matches!(
            session.adopt(view),
            Err(RenewalError::OperationMismatch { .. })
        ),
        "an operation identifier does not change under a client's feet"
    );
}

/// A failed operation is terminal: the client opens a new one rather than
/// polling an identifier the authority no longer accepts.
#[test]
fn a_failed_operation_is_reported_as_such() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mut session = session(&store, &domain);
    let view = ClientRenewalOperationView {
        operation_id: Id16::new([6; 16]).expect("id"),
        state: ClientRenewalOperationState::Failed,
        client_wg_public_key: client_key(),
        request_fingerprint: session.request_fingerprint(),
        operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
        created_at: NOW,
        expires_at: NOW + 300,
        signer_request_token: None,
        signer_result_token: None,
        grant: None,
    };
    assert!(matches!(
        session.adopt(view),
        Err(RenewalError::OperationFailed)
    ));
}

/// An authority still asking for a credential is named as obsolete.
///
/// The amendment of 6 September 2026 removed the per-request approval from
/// the scheduled path, so `AwaitingOperator` can only come from an Astra
/// that has not been migrated. The client says which of the two ends is
/// behind rather than waiting on a ceremony that no longer exists.
#[test]
fn an_authority_still_awaiting_an_operator_is_reported_as_obsolete() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mut session = session(&store, &domain);
    let operation_id = Id16::new([6; 16]).expect("id");
    let adopted = session.adopt(ClientRenewalOperationView {
        operation_id,
        state: ClientRenewalOperationState::AwaitingOperator,
        client_wg_public_key: client_key(),
        request_fingerprint: session.request_fingerprint(),
        operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
        created_at: NOW,
        expires_at: NOW + 300,
        signer_request_token: None,
        signer_result_token: None,
        grant: None,
    });

    assert!(matches!(
        adopted,
        Err(RenewalError::ObsoleteOperatorApproval)
    ));
    // L'état reste en attente d'opérateur : le remède que nomme l'erreur est
    // de migrer l'autorité, pas d'approuver une demande à la main.
    assert_eq!(session.operation_id(), Some(operation_id));
}
