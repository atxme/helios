//! Commit-boundary regressions for the client's ordinary certificate renewal.
//!
//! Before any operating-system identity sealing is attempted, the client must
//! bind the gateway response to the opened operation, require a grant, and
//! verify that grant against the signed request and pinned trust state.

use aether::certificates::encoding::{Fingerprint, Id16};
use aether::certificates::transport::{ClientRenewalOperationState, ClientRenewalOperationView};

use super::fixtures::{
    active_identity, grant, json_http_response as json_response, scripted_peer, window,
};
use crate::certificate_renewal::{RenewalError, RenewalSession};
use crate::test_domain::*;
use crate::ProtectedIdentityStore;
use std::sync::{Arc, Mutex};

use crate::certificate_renewal::exchange::CandidateIdentityWriter;
use crate::identity_store::ClientIdentityBundle;

#[derive(Clone, Default)]
struct FakeIdentityWriter {
    identities: Arc<Mutex<Vec<String>>>,
    events: Option<Arc<Mutex<Vec<&'static str>>>>,
    fail: bool,
}

impl CandidateIdentityWriter for FakeIdentityWriter {
    fn persist_candidate(&self, bundle: &ClientIdentityBundle) -> anyhow::Result<()> {
        self.identities
            .lock()
            .expect("identity writer lock")
            .push(bundle.identity.clone());
        if let Some(events) = &self.events {
            events.lock().expect("event lock").push("writer_completed");
        }
        if self.fail {
            anyhow::bail!("injected candidate identity write failure");
        }
        Ok(())
    }
}

async fn ordered_commit_peer(
    listener: tokio::net::TcpListener,
    operation_response: Vec<u8>,
    commit_response: Vec<u8>,
    events: Arc<Mutex<Vec<&'static str>>>,
) -> tokio::task::JoinHandle<()> {
    use tokio::io::AsyncWriteExt as _;

    tokio::spawn(async move {
        let (mut operation_stream, _) = listener.accept().await.expect("operation GET");
        let operation = super::fixtures::read_http_request(&mut operation_stream).await;
        assert!(operation.headers.starts_with("GET /api/key-negotiation/"));
        operation_stream
            .write_all(&operation_response)
            .await
            .expect("operation response");

        let (mut commit_stream, _) = listener.accept().await.expect("stage commit POST");
        let commit = super::fixtures::read_http_request(&mut commit_stream).await;
        assert!(commit
            .headers
            .starts_with("POST /api/key-negotiation/certificate-renewal/stage-commit"));
        events
            .lock()
            .expect("event lock")
            .push("gateway_commit_received");
        commit_stream
            .write_all(&commit_response)
            .await
            .expect("commit response");
    })
}

fn pending_commit_view(
    session: &RenewalSession,
    operation_id: Id16,
    grant: Option<aether::certificates::client::ClientCertificateRotationGrant>,
) -> ClientRenewalOperationView {
    ClientRenewalOperationView {
        operation_id,
        state: ClientRenewalOperationState::PendingCommit,
        client_wg_public_key: client_key(),
        request_fingerprint: session.request_fingerprint(),
        operation_manifest_fingerprint: Fingerprint::of(b"commit manifest"),
        created_at: NOW,
        expires_at: NOW + 300,
        signer_request_token: None,
        signer_result_token: None,
        grant: grant.map(Box::new),
    }
}

/// A tampered grant must fail before either the candidate keys or the pending
/// state are persisted, even when the response has valid JSON and operation
/// identity fields.
#[tokio::test]
async fn an_invalid_grant_never_creates_a_candidate_or_pending_state() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x91; 16]).expect("operation ID");
    let mut invalid_grant = grant(&domain, &session, window());
    invalid_grant.next_generation += 1;
    let view = pending_commit_view(&session, operation_id, Some(invalid_grant));
    session.adopt(view.clone()).expect("operation is ours");
    let (mut requests, server) =
        scripted_peer(listener, vec![json_response("200 OK", &view)]).await;
    let identity_dir = directory.path().join("identities");
    let identities = ProtectedIdentityStore::at(identity_dir.clone());

    let error = session
        .advance(
            &mut store,
            &identities,
            SUBJECT,
            &active_identity(&domain),
            NOW,
        )
        .await
        .expect_err("tampered grant refused");
    assert!(matches!(error, RenewalError::Certificate(_)), "{error}");
    assert!(store.state().certificates.pending.is_none());
    assert!(
        !identity_dir.exists(),
        "grant verification failed before any sealed identity write"
    );
    let request = requests.recv().await.expect("operation GET");
    assert!(request.body.is_empty());
    assert!(request.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    server.await.expect("scripted peer task");
}

/// A PendingCommit response without its grant is not a usable transaction and
/// must fail before touching protected identity storage.
#[tokio::test]
async fn a_pending_commit_without_a_grant_is_refused_before_local_io() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x93; 16]).expect("operation ID");
    let view = pending_commit_view(&session, operation_id, None);
    session.adopt(view.clone()).expect("operation is ours");
    let (mut requests, server) =
        scripted_peer(listener, vec![json_response("200 OK", &view)]).await;
    let identities = ProtectedIdentityStore::at(directory.path().join("identities"));

    let error = session
        .advance(
            &mut store,
            &identities,
            SUBJECT,
            &active_identity(&domain),
            NOW,
        )
        .await
        .expect_err("grant missing");
    assert!(matches!(error, RenewalError::GrantMissing));
    assert!(store.state().certificates.pending.is_none());
    let request = requests.recv().await.expect("operation GET");
    assert!(request.body.is_empty());
    assert!(request.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    server.await.expect("scripted peer task");
}

/// The gateway cannot switch an already-open renewal to another operation,
/// even if the returned view otherwise carries a valid grant for this request.
#[tokio::test]
async fn advance_refuses_a_different_operation_id_before_processing_its_grant() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x94; 16]).expect("operation ID");
    let view = pending_commit_view(
        &session,
        Id16::new([0x95; 16]).expect("substituted operation ID"),
        Some(grant(&domain, &session, window())),
    );
    let mut accepted_view = view.clone();
    accepted_view.operation_id = operation_id;
    session
        .adopt(accepted_view)
        .expect("initial operation is ours");
    let (mut requests, server) =
        scripted_peer(listener, vec![json_response("200 OK", &view)]).await;
    let identities = ProtectedIdentityStore::at(directory.path().join("identities"));

    let error = session
        .advance(
            &mut store,
            &identities,
            SUBJECT,
            &active_identity(&domain),
            NOW,
        )
        .await
        .expect_err("substituted operation refused");
    assert!(matches!(error, RenewalError::OperationMismatch { .. }));
    assert_eq!(session.operation_id(), Some(operation_id));
    assert!(store.state().certificates.pending.is_none());
    let request = requests.recv().await.expect("operation GET");
    assert!(request.body.is_empty());
    assert!(request.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    server.await.expect("scripted peer task");
}

/// The candidate writer completes before the gateway receives the signed
/// commit; only its confirmation moves the trust state from pending to next.
#[tokio::test]
async fn a_verified_grant_persists_candidate_before_commit_and_commits_state_after_confirmation() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x96; 16]).expect("operation ID");
    let view = pending_commit_view(
        &session,
        operation_id,
        Some(grant(&domain, &session, window())),
    );
    session.adopt(view.clone()).expect("operation is ours");

    let events = Arc::new(Mutex::new(Vec::new()));
    let writer = FakeIdentityWriter {
        events: Some(events.clone()),
        ..FakeIdentityWriter::default()
    };
    let server = ordered_commit_peer(
        listener,
        json_response("200 OK", &view),
        json_response("200 OK", &serde_json::json!({})),
        events.clone(),
    )
    .await;

    let step = session
        .advance_with_identity_writer(&mut store, &writer, SUBJECT, &active_identity(&domain), NOW)
        .await
        .expect("verified renewal commits");

    assert_eq!(
        step,
        crate::certificate_renewal::RenewalStep::Committed { generation: 5 }
    );
    assert_eq!(
        *events.lock().expect("event lock"),
        vec!["writer_completed", "gateway_commit_received"],
        "the writer completes before the gateway sees the commit"
    );
    assert_eq!(
        *writer.identities.lock().expect("identity writer lock"),
        vec![format!("{SUBJECT}-next")]
    );
    assert!(store.state().certificates.pending.is_none());
    assert_eq!(
        store
            .state()
            .certificates
            .next
            .as_ref()
            .expect("committed next generation")
            .generation,
        5
    );
    let reopened = crate::certificates::TrustStore::load(&directory.path().join("trust.json"))
        .expect("trust store reads after commit")
        .expect("trust store was persisted");
    assert!(reopened.state().certificates.pending.is_none());
    assert_eq!(
        reopened
            .state()
            .certificates
            .next
            .as_ref()
            .expect("persisted next generation")
            .generation,
        5
    );
    server.await.expect("ordered commit peer");
}

/// A storage failure stops the transaction before the trust store stages the
/// grant and before a stage-commit request can be sent.
#[tokio::test]
async fn candidate_identity_write_failure_prevents_staging_and_remote_commit() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x97; 16]).expect("operation ID");
    let view = pending_commit_view(
        &session,
        operation_id,
        Some(grant(&domain, &session, window())),
    );
    session.adopt(view.clone()).expect("operation is ours");
    let (mut requests, server) =
        scripted_peer(listener, vec![json_response("200 OK", &view)]).await;
    let writer = FakeIdentityWriter {
        fail: true,
        ..FakeIdentityWriter::default()
    };

    let error = session
        .advance_with_identity_writer(&mut store, &writer, SUBJECT, &active_identity(&domain), NOW)
        .await
        .expect_err("candidate write failure is fatal");

    assert!(matches!(error, RenewalError::Identity(ref reason) if reason.contains("injected")));
    assert!(store.state().certificates.pending.is_none());
    assert!(store.state().certificates.next.is_none());
    assert_eq!(
        *writer.identities.lock().expect("identity writer lock"),
        vec![format!("{SUBJECT}-next")],
        "the attempted candidate is the one named by this grant"
    );
    let request = requests.recv().await.expect("operation GET");
    assert!(request.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    assert!(requests.try_recv().is_err(), "no stage-commit POST follows");
    server.await.expect("scripted operation peer");
}

/// Once the candidate is persisted and the grant staged, a remote refusal
/// leaves that exact PendingCommit state available for an idempotent retry.
#[tokio::test]
async fn remote_commit_refusal_keeps_verified_pending_state_without_promoting_next() {
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().expect("temp directory");
    let domain = domain();
    let mut store = store(directory.path(), &domain);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let mut session = RenewalSession::prepare(&store, SUBJECT, &base, NOW).expect("prepare");
    session.sign(&active_identity(&domain)).expect("sign");
    let operation_id = Id16::new([0x98; 16]).expect("operation ID");
    let view = pending_commit_view(
        &session,
        operation_id,
        Some(grant(&domain, &session, window())),
    );
    session.adopt(view.clone()).expect("operation is ours");
    let (mut requests, server) = scripted_peer(
        listener,
        vec![
            json_response("200 OK", &view),
            json_response("403 Forbidden", &serde_json::json!({})),
        ],
    )
    .await;
    let writer = FakeIdentityWriter::default();

    let error = session
        .advance_with_identity_writer(&mut store, &writer, SUBJECT, &active_identity(&domain), NOW)
        .await
        .expect_err("gateway refuses the commit");

    assert!(matches!(error, RenewalError::Refused { status: 403 }));
    let pending = store
        .state()
        .certificates
        .pending
        .as_ref()
        .expect("verified grant remains pending for retry");
    assert_eq!(
        pending.state,
        aether::certificates::state::PendingStageState::PendingCommit
    );
    assert!(store.state().certificates.next.is_none());
    assert_eq!(
        writer
            .identities
            .lock()
            .expect("identity writer lock")
            .len(),
        1
    );
    let operation = requests.recv().await.expect("operation GET");
    assert!(operation.headers.starts_with(&format!(
        "GET /api/key-negotiation/certificate-renewal/operations/{operation_id} "
    )));
    let commit = requests.recv().await.expect("stage commit POST");
    assert!(commit
        .headers
        .starts_with("POST /api/key-negotiation/certificate-renewal/stage-commit"));
    server.await.expect("scripted peer task");
}
