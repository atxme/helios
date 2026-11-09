//! The in-tunnel exchange of spec §8.1.2: the request this client signs, the
//! operation views it adopts or refuses, and the grant it verifies, stages and
//! commits.

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87PublicKey, WireGuardKey,
};
use aether::certificates::transport::{ClientRenewalOperationState, ClientRenewalOperationView};
use aether::certificates::CertificateError;
use zeroize::Zeroizing;

use super::fixtures::{
    active_identity, grant, json_http_response, read_http_request, scripted_peer, session, window,
};
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
    // The session stays on the operation: the remedy the error names is to
    // migrate the authority, not to approve a request by hand.
    assert_eq!(session.operation_id(), Some(operation_id));
}

fn operation_view(
    request_fingerprint: Fingerprint,
    operation_id: Id16,
) -> ClientRenewalOperationView {
    ClientRenewalOperationView {
        operation_id,
        state: ClientRenewalOperationState::PendingGrant,
        client_wg_public_key: client_key(),
        request_fingerprint,
        operation_manifest_fingerprint: Fingerprint::of(b"approval manifest"),
        created_at: NOW,
        expires_at: NOW + 300,
        signer_request_token: Some("read-capability".into()),
        signer_result_token: Some("submit-capability".into()),
        grant: None,
    }
}

/// Exercise the client adapter against a local HTTP peer: the signed request
/// goes only to the tunnel route, then a PendingGrant poll stays on that same
/// gateway and does not carry companion capabilities.
#[tokio::test]
async fn session_posts_a_signed_request_and_polls_pending_grant_on_the_tunnel_routes() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let operation_id = Id16::new([0x68; 16]).expect("operation ID");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session =
        RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare request");
    session
        .sign(&active_identity(&domain))
        .expect("sign request");
    let request_fingerprint = session.request_fingerprint();
    let view = operation_view(request_fingerprint, operation_id);
    let response = json_http_response("200 OK", &view);
    let second_response = json_http_response("200 OK", &view);
    let (mut requests, server) = scripted_peer(listener, vec![response, second_response]).await;

    let opened = session.open().await.expect("open through tunnel");
    assert_eq!(opened, RenewalStep::Issuing { operation_id });
    assert_eq!(session.operation_id(), Some(operation_id));
    let active_public = MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
        .expect("active public key");
    let post = requests.recv().await.expect("request POST");
    assert!(post
        .headers
        .starts_with("POST /api/key-negotiation/certificate-renewal/request"));
    let request: aether::certificates::client::ClientCertificateRotationRequest =
        serde_json::from_slice(&post.body).expect("rotation request JSON");
    request
        .verify(
            &active_public,
            &domain_id(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(&domain),
            &client_key(),
            NOW,
        )
        .expect("both active and candidate signatures verify");
    assert_eq!(request.fingerprint(), request_fingerprint);

    let advanced = session
        .advance(
            &mut store,
            &crate::ProtectedIdentityStore::at(directory.path().join("identities")),
            SUBJECT,
            &active_identity(&domain),
            NOW,
        )
        .await
        .expect("pending grant stays in issuing state");
    assert_eq!(advanced, RenewalStep::Issuing { operation_id });
    let poll = requests.recv().await.expect("operation poll request");
    assert!(poll.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    assert!(
        !poll.headers.to_ascii_lowercase().contains("authorization:"),
        "the operation poll does not use a companion token"
    );
    server.await.expect("scripted peer task");
}

/// A redirect must remain a coarse refusal; the client never follows a
/// gateway-selected host or falls back to a public Astra origin.
#[tokio::test]
async fn renewal_open_refuses_a_redirect_without_following_it() {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let base = format!("http://{address}");
    let redirect_location = format!("{base}/public-astra-fallback");
    let (observed_sender, observed_receiver) = tokio::sync::oneshot::channel();
    let (followed_sender, followed_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("first request");
        let request = read_http_request(&mut stream).await;
        let _ = observed_sender.send(request);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {redirect_location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write redirect");

        let followed = if let Ok(Ok((mut redirected, _))) =
            timeout(Duration::from_millis(250), listener.accept()).await
        {
            let _ = read_http_request(&mut redirected).await;
            redirected
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .expect("write redirect response");
            true
        } else {
            false
        };
        let _ = followed_sender.send(followed);
    });

    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session
        .sign(&active_identity(&domain))
        .expect("sign request");
    let error = session.open().await.expect_err("redirect is not followed");
    assert!(
        matches!(error, RenewalError::Refused { status: 302 }),
        "{error}"
    );
    let request = observed_receiver.await.expect("observed request");
    assert!(request
        .headers
        .starts_with("POST /api/key-negotiation/certificate-renewal/request"));
    assert!(!followed_receiver.await.expect("redirect observation"));
    server.await.expect("redirect server task");
}

/// An HTTP 200 is still refused when the gateway describes somebody else's
/// request; a well-formed response does not make an unrelated operation ours.
#[tokio::test]
async fn session_refuses_an_operation_view_for_another_request() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session
        .sign(&active_identity(&domain))
        .expect("sign request");

    let mut unrelated = operation_view(
        Fingerprint::of(b"another client's request"),
        Id16::new([0x71; 16]).expect("operation ID"),
    );
    unrelated.client_wg_public_key = client_key();
    let response = json_http_response("200 OK", &unrelated);
    let (mut requests, server) = scripted_peer(listener, vec![response]).await;

    let error = session
        .open()
        .await
        .expect_err("unrelated operation refused");
    assert!(matches!(error, RenewalError::OperationMismatch { .. }));
    assert_eq!(session.operation_id(), None);
    let request = requests.recv().await.expect("observed POST");
    assert!(request
        .headers
        .starts_with("POST /api/key-negotiation/certificate-renewal/request"));
    server.await.expect("scripted peer task");
}

/// HTTP refusals stay coarse, and a missing certificate authority is the one
/// status that receives its dedicated actionable error.
#[tokio::test]
async fn session_maps_gateway_refusals_without_decoding_their_bodies() {
    use tokio::net::TcpListener;

    for (status, expected) in [
        (403, RenewalError::Refused { status: 403 }),
        (503, RenewalError::AuthorityUnavailable),
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
        session
            .sign(&active_identity(&domain))
            .expect("sign request");
        let wire = format!(
            "HTTP/1.1 {status} Refused\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let (mut requests, server) = scripted_peer(listener, vec![wire]).await;

        let error = session.open().await.expect_err("gateway refusal");
        match expected {
            RenewalError::AuthorityUnavailable => {
                assert!(matches!(error, RenewalError::AuthorityUnavailable));
            }
            RenewalError::Refused {
                status: expected_status,
            } => {
                assert!(
                    matches!(error, RenewalError::Refused { status } if status == expected_status)
                );
            }
            other => panic!("unexpected expected error: {other:?}"),
        }
        let request = requests.recv().await.expect("observed POST");
        assert!(request
            .headers
            .starts_with("POST /api/key-negotiation/certificate-renewal/request"));
        server.await.expect("scripted peer task");
    }
}

/// A successful status with a prematurely closed JSON body is a transport
/// failure; it cannot be adopted as an operation or retried as a public call.
#[tokio::test]
async fn session_reports_a_truncated_operation_response_as_transport_failure() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session
        .sign(&active_identity(&domain))
        .expect("sign request");
    let wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{".to_vec();
    let (mut requests, server) = scripted_peer(listener, vec![wire]).await;

    let error = session.open().await.expect_err("truncated body refused");
    assert!(matches!(error, RenewalError::Transport(_)), "{error}");
    let request = requests.recv().await.expect("observed POST");
    assert!(request
        .headers
        .starts_with("POST /api/key-negotiation/certificate-renewal/request"));
    server.await.expect("scripted peer task");
}
