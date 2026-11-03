//! Cancellation of the real private QUIC connection future, including its
//! backend rollback and point-of-no-return boundaries.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use aether::key_negotiation::{
    authenticate_confirmation, authenticate_request, KEY_NEGOTIATION_NONCE_LEN,
};
use quinn::Endpoint;

use crate::{
    client_endpoint, negotiate, request_challenge, server_endpoint, TransportError,
    MAX_NEGOTIATIONS_PER_IDENTITY,
};

use super::{handle_connection, NegotiationHandler};
use crate::tests::fixtures::{
    simple_request, test_pki, Handler, TestPki, CLIENT_WG_KEY, GATEWAY_WG_KEY,
};

struct DirectConnection {
    server: Endpoint,
    client: Endpoint,
    address: SocketAddr,
    handler_task: tokio::task::JoinHandle<Result<(), TransportError>>,
}

fn direct_connection(pki: &TestPki, handler: Arc<Handler>) -> DirectConnection {
    let server = server_endpoint(
        "127.0.0.1:0".parse().expect("loopback address"),
        &pki.server,
        std::slice::from_ref(&pki.ca_der),
    )
    .expect("server endpoint");
    let address = server.local_addr().expect("bound address");
    let acceptor = server.clone();
    let client = client_endpoint(
        "127.0.0.1:0".parse().expect("loopback client address"),
        &pki.client,
        pki.ca_der.clone(),
    )
    .expect("client endpoint");
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("single-connection permit");
    let per_identity = Arc::new(Mutex::new(crate::rate_limit::RateLimiter::new(
        MAX_NEGOTIATIONS_PER_IDENTITY,
    )));
    let handler_task = tokio::spawn(async move {
        let incoming = acceptor.accept().await.expect("incoming connection");
        handle_connection(
            incoming,
            handler as Arc<dyn NegotiationHandler>,
            permit,
            per_identity,
        )
        .await
    });
    DirectConnection {
        server,
        client,
        address,
        handler_task,
    }
}

async fn wait_for(signal: &tokio::sync::Semaphore) {
    tokio::time::timeout(Duration::from_secs(5), signal.acquire())
        .await
        .expect("bounded lifecycle signal wait")
        .expect("signal semaphore stays open")
        .forget();
}

async fn prepared_session(
    connection: &DirectConnection,
    pki: &TestPki,
    transaction_id: [u8; 16],
) -> crate::ClientSession {
    let pending = request_challenge(
        &connection.client,
        connection.address,
        "localhost",
        GATEWAY_WG_KEY,
    )
    .await
    .expect("mTLS challenge from the handler task");
    let mut request = simple_request(transaction_id);
    request.server_challenge = pending.server_challenge();
    request.server_name = "localhost".into();
    let authenticated = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .expect("signed v5 request");
    let (_, session) = negotiate(&connection.client, pending, &authenticated)
        .await
        .expect("candidate response from the handler");
    session
}

#[tokio::test]
async fn aborting_the_connection_handler_while_waiting_for_confirmation_rolls_back() {
    let pki = test_pki();
    let handler = Arc::new(Handler::new(&pki));
    let connection = direct_connection(&pki, Arc::clone(&handler));
    let transaction_id = [0x31; KEY_NEGOTIATION_NONCE_LEN];
    let session = prepared_session(&connection, &pki, transaction_id).await;

    // The response proves `prepare` completed; the handler now owns its armed
    // rollback guard while it awaits confirmation from this connection.
    connection.handler_task.abort();
    let joined = connection
        .handler_task
        .await
        .expect_err("aborted connection task has a cancelled JoinError");
    assert!(joined.is_cancelled());
    drop(session);

    wait_for(&handler.rollback_started).await;
    wait_for(&handler.rollback_completed).await;
    assert!(!handler.confirmed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        handler
            .rollback_events
            .lock()
            .expect("rollback events")
            .as_slice(),
        &[(transaction_id, CLIENT_WG_KEY.to_string())],
        "the actual handler's Drop guard rolls back the exact prepared owner"
    );
    connection.client.close(0u32.into(), b"test complete");
    connection.server.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn aborting_the_handler_during_backend_rollback_retries_the_exact_owner() {
    let pki = test_pki();
    let handler = Arc::new(Handler::with_blocked_rollback(&pki));
    let connection = direct_connection(&pki, Arc::clone(&handler));
    let transaction_id = [0x32; KEY_NEGOTIATION_NONCE_LEN];
    let session = prepared_session(&connection, &pki, transaction_id).await;

    // Closing the client stream enters the real handler's normal rollback
    // path. Hold its backend await so the handler future can be aborted there.
    drop(session);
    connection
        .client
        .close(0u32.into(), b"test abort during rollback");
    wait_for(&handler.rollback_started).await;
    connection.handler_task.abort();
    let joined = connection
        .handler_task
        .await
        .expect_err("aborted rollback path has a cancelled JoinError");
    assert!(joined.is_cancelled());

    handler.rollback_gate.add_permits(1);
    wait_for(&handler.rollback_started).await;
    wait_for(&handler.rollback_completed).await;
    assert_eq!(
        handler
            .rollback_events
            .lock()
            .expect("rollback events")
            .as_slice(),
        &[
            (transaction_id, CLIENT_WG_KEY.to_string()),
            (transaction_id, CLIENT_WG_KEY.to_string()),
        ],
        "Drop retries the same rollback after the handler's rollback future is cancelled"
    );
    connection.client.close(0u32.into(), b"test complete");
    connection.server.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn aborting_inside_confirm_keeps_the_rollback_guard_armed() {
    let pki = test_pki();
    let handler = Arc::new(Handler::with_blocked_confirm(&pki));
    let connection = direct_connection(&pki, Arc::clone(&handler));
    let transaction_id = [0x34; KEY_NEGOTIATION_NONCE_LEN];
    let pending = request_challenge(
        &connection.client,
        connection.address,
        "localhost",
        GATEWAY_WG_KEY,
    )
    .await
    .expect("mTLS challenge");
    let challenge = pending.server_challenge();
    let mut request = simple_request(transaction_id);
    request.server_challenge = challenge;
    request.server_name = "localhost".into();
    let authenticated = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .expect("signed v5 request");
    let (_, session) = negotiate(&connection.client, pending, &authenticated)
        .await
        .expect("prepared candidate");
    let confirmation =
        authenticate_confirmation(challenge, transaction_id, &pki.client_pq_private_key)
            .expect("signed confirmation");
    let client_confirmation = tokio::spawn(async move { session.confirm(confirmation).await });

    wait_for(&handler.confirm_started).await;
    connection.handler_task.abort();
    let joined = connection
        .handler_task
        .await
        .expect_err("cancelled confirm future drops the actual handler");
    assert!(joined.is_cancelled());
    wait_for(&handler.rollback_started).await;
    wait_for(&handler.rollback_completed).await;
    assert!(
        handler.confirm_returned.available_permits() == 0,
        "the handler future was destroyed before confirm returned"
    );
    assert_eq!(
        handler
            .rollback_events
            .lock()
            .expect("rollback events")
            .as_slice(),
        &[(transaction_id, CLIENT_WG_KEY.to_string())],
        "the armed guard undoes the candidate if confirm is cancelled"
    );

    connection
        .client
        .close(0u32.into(), b"confirm task cancelled");
    connection
        .server
        .close(0u32.into(), b"confirm task cancelled");
    let _ = tokio::time::timeout(Duration::from_secs(5), client_confirmation)
        .await
        .expect("client session sees connection close");
}

#[tokio::test]
async fn a_lost_commit_delivery_finishes_the_handler_without_rollback() {
    let pki = test_pki();
    let handler = Arc::new(Handler::with_blocked_confirm(&pki));
    let connection = direct_connection(&pki, Arc::clone(&handler));
    // The confirmation binds to the challenge this connection actually got.
    let pending = request_challenge(
        &connection.client,
        connection.address,
        "localhost",
        GATEWAY_WG_KEY,
    )
    .await
    .expect("mTLS challenge");
    let challenge = pending.server_challenge();
    let transaction_id = [0x33; KEY_NEGOTIATION_NONCE_LEN];
    let mut request = simple_request(transaction_id);
    request.server_challenge = challenge;
    request.server_name = "localhost".into();
    let authenticated = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .expect("signed v5 request");
    let (_, session) = negotiate(&connection.client, pending, &authenticated)
        .await
        .expect("prepared candidate");
    let confirmation =
        authenticate_confirmation(challenge, transaction_id, &pki.client_pq_private_key)
            .expect("signed confirmation");
    let client_confirmation = tokio::spawn(async move { session.confirm(confirmation).await });

    wait_for(&handler.confirm_started).await;
    assert!(handler
        .rollback_events
        .lock()
        .expect("rollback events")
        .is_empty());
    // Close both transport endpoints while confirm is held, so successful
    // signing cannot be mistaken for successful commit delivery.
    connection
        .client
        .close(0u32.into(), b"commit delivery interrupted");
    connection
        .server
        .close(0u32.into(), b"commit delivery interrupted");
    handler.confirm_gate.add_permits(1);

    let handler_result = tokio::time::timeout(Duration::from_secs(5), connection.handler_task)
        .await
        .expect("owned connection handler finishes after endpoint closure")
        .expect("connection handler task itself did not panic");
    assert!(
        handler_result.is_err(),
        "the handler cannot deliver a commit on the closed connection"
    );
    wait_for(&handler.confirm_returned).await;
    let client_result = tokio::time::timeout(Duration::from_secs(5), client_confirmation)
        .await
        .expect("client confirmation observes the closed endpoint")
        .expect("client confirmation task completes");
    assert!(
        client_result.is_err(),
        "the client did not receive a commit"
    );
    assert!(handler.confirmed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(handler
        .rollback_events
        .lock()
        .expect("rollback events")
        .is_empty());
    assert_eq!(
        Arc::strong_count(&handler),
        1,
        "a completed connection must not leave a rollback task retaining its handler"
    );
}
