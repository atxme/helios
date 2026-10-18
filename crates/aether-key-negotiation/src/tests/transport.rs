use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use aether::key_negotiation::{
    authenticate_confirmation, authenticate_request, KEY_NEGOTIATION_NONCE_LEN,
    KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
};

use super::fixtures::{
    bench, independent_client_identity, simple_request, test_now, test_pki, Handler, CLIENT_WG_KEY,
    GATEWAY_WG_KEY,
};
use crate::framing::{read_frame, write_frame, ServerMessage};
use crate::{
    certificate_fingerprint_der, client_endpoint, negotiate, request_challenge, serve,
    server_endpoint, NegotiationHandler, PendingChallenge, PublicError, TransportError,
};

/// The mTLS boundary must accept a renewed client whose chain ends at the
/// domain CA, even though the server certificate and first-generation
/// clients still use the original CA.
///
/// Exercising a real Quinn handshake matters here: checking that two DER
/// blobs entered a `RootCertStore` would not prove rustls can build the
/// second chain presented by Orion.
#[tokio::test]
async fn every_configured_client_ca_can_authenticate_a_connection() {
    let pki = test_pki();
    let (domain_ca, renewed_client) = independent_client_identity("renewed-orion");
    let client_cas = vec![pki.ca_der.clone(), domain_ca];
    let server = server_endpoint("127.0.0.1:0".parse().unwrap(), &pki.server, &client_cas).unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut handler = Handler::new(&pki);
    handler.expected_fingerprint =
        certificate_fingerprint_der(&renewed_client.certificate_chain[0]);
    let handler = Arc::new(handler);
    let task = tokio::spawn(serve(
        server,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));
    let client = client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &renewed_client,
        pki.ca_der.clone(),
    )
    .unwrap();

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .expect("the domain CA is one of the configured client roots");
    drop(pending);

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// An unrelated client authority remains outside the trust boundary.
/// Adding the domain CA must be an explicit set extension, not a fallback
/// that accepts any readable chain.
#[tokio::test]
async fn an_unconfigured_client_ca_is_refused_by_mtls() {
    let pki = test_pki();
    let (_untrusted_ca, untrusted_client) = independent_client_identity("untrusted-orion");
    let server = server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &pki.server,
        std::slice::from_ref(&pki.ca_der),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut handler = Handler::new(&pki);
    handler.expected_fingerprint =
        certificate_fingerprint_der(&untrusted_client.certificate_chain[0]);
    let handler = Arc::new(handler);
    let task = tokio::spawn(serve(
        server,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));
    let client = client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &untrusted_client,
        pki.ca_der.clone(),
    )
    .unwrap();

    assert!(
        request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .is_err(),
        "a CA absent from the configured set must fail at the mTLS boundary"
    );

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// An empty trust set is a configuration error, not a server that starts
/// successfully while refusing every legitimate client.
#[test]
fn an_empty_client_ca_set_is_refused() {
    let pki = test_pki();
    assert!(matches!(
        server_endpoint("127.0.0.1:0".parse().unwrap(), &pki.server, &[]),
        Err(TransportError::InvalidCertificate)
    ));
}
/// The nominal v5 sequence is challenge, request, response, confirmation,
/// commit, then **closure**. The connection does not outlive the
/// transaction, and closing it does not remove any PSK.
#[tokio::test]
async fn a_negotiation_ends_with_a_commit_and_a_closed_connection() {
    let pki = test_pki();
    let (handler, task, client, server_addr) = bench(&pki);

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let challenge = pending.server_challenge();
    assert_ne!(
        challenge, [0u8; SERVER_CHALLENGE_LEN],
        "un challenge nul ne prouverait rien"
    );

    let mut request = simple_request([1; KEY_NEGOTIATION_NONCE_LEN]);
    request.server_challenge = challenge;
    request.server_name = "localhost".into();
    let authenticated_request = authenticate_request(
        request.clone(),
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .unwrap();
    let (response, session) = negotiate(&client, pending, &authenticated_request)
        .await
        .unwrap();
    response
        .response
        .validate_for(&request, GATEWAY_WG_KEY)
        .unwrap();

    let confirmation = authenticate_confirmation(
        challenge,
        request.transaction_id,
        &pki.client_pq_private_key,
    )
    .unwrap();
    let commit = session.confirm(confirmation).await.unwrap();
    commit
        .verify(&pki.gateway_pq_certificate.ml_dsa_87_public_key)
        .unwrap();
    assert_eq!(commit.server_challenge, challenge);

    tokio::time::timeout(Duration::from_secs(1), async {
        while !handler.confirmed.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let sources = handler.sources.lock().unwrap().clone();
    assert!(
        !sources.is_empty() && sources.iter().all(|source| source.is_loopback()),
        "the handler must receive the canonical source of the connection: {sources:?}"
    );

    // The key v5 property: the connection is over, and that says nothing
    // about the tunnel. In v4 the same closure released the slot; here it
    // must not trigger rollback, and this port can no longer remove a PSK.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !handler.rolled_back.load(Ordering::SeqCst),
        "closing the connection after commit must not undo anything"
    );

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// A terminal refusal must arrive as the public protocol error, not as a
/// transport reset. Dropping the send stream immediately after writing
/// this frame made Quinn discard it and Orion reported `connection lost`.
#[tokio::test]
async fn a_prepare_refusal_is_delivered_before_the_connection_closes() {
    let pki = test_pki();
    let (handler, task, client, server_addr) = bench(&pki);
    handler.reject_prepare.store(true, Ordering::SeqCst);

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let mut request = simple_request([9; KEY_NEGOTIATION_NONCE_LEN]);
    request.server_challenge = pending.server_challenge();
    request.server_name = "localhost".into();
    let authenticated_request = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .unwrap();

    match negotiate(&client, pending, &authenticated_request).await {
        Err(TransportError::Rejected(PublicError::Rejected)) => {}
        Err(error) => {
            panic!("the framed refusal must survive graceful connection teardown: {error}")
        }
        Ok(_) => panic!("a handler refusal must not produce a negotiated session"),
    }

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// Le challenge est à usage unique : le rejouer sur une seconde connexion
/// échoue, ce qui est exactement la propriété que la v4 n'avait pas.
#[tokio::test]
async fn a_challenge_cannot_be_replayed_on_another_connection() {
    let pki = test_pki();
    let (handler, task, client, server_addr) = bench(&pki);

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let stolen = pending.server_challenge();
    drop(pending);

    // Nouvelle connexion, donc nouveau challenge — mais on présente
    // l'ancien, entièrement signé.
    let second = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let mut request = simple_request([7; KEY_NEGOTIATION_NONCE_LEN]);
    request.server_challenge = stolen;
    request.server_name = "localhost".into();
    let replayed = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .unwrap();
    let outcome = negotiate(&client, second, &replayed).await.err();
    assert!(
        matches!(outcome, Some(TransportError::Protocol(_))),
        "une requête portant le challenge d'une autre connexion doit être refusée : {outcome:?}"
    );
    assert!(!handler.confirmed.load(Ordering::SeqCst));

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// Le client refuse une gateway qui annonce une autre identité, avant
/// d'avoir produit la moindre signature.
#[tokio::test]
async fn a_gateway_announcing_another_identity_is_refused_before_signing() {
    let pki = test_pki();
    let (_handler, task, client, server_addr) = bench(&pki);

    let outcome = request_challenge(&client, server_addr, "localhost", CLIENT_WG_KEY)
        .await
        .err();
    assert!(
        matches!(outcome, Some(TransportError::Protocol(_))),
        "l'identité annoncée doit être comparée au profil : {outcome:?}"
    );

    client.close(0u32.into(), b"test complete");
    task.abort();
}

/// `release` has left this port: the legacy tag no longer decodes.
///
/// Merely not sending it is insufficient. An outdated Orion and a migrated
/// gateway must fail explicitly rather than silently. Rejection happens in
/// the parser, before any handler, without revealing slot state.
#[tokio::test]
async fn the_legacy_quic_release_message_is_refused_as_a_protocol_error() {
    let pki = test_pki();
    let (handler, task, client, server_addr) = bench(&pki);

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let PendingChallenge {
        connection,
        mut send,
        mut recv,
        challenge,
    } = pending;

    // The message exactly as v5 carried it before August 8, 2026.
    let legacy = serde_json::json!({
        "type": "release",
        "release": {
            "release": {
                "protocol_version": KEY_NEGOTIATION_VERSION,
                "server_challenge": challenge.server_challenge,
                "installed_transaction_id": vec![4u8; KEY_NEGOTIATION_NONCE_LEN],
                "client_wg_public_key": CLIENT_WG_KEY,
                "gateway_wg_public_key": GATEWAY_WG_KEY,
                "timestamp_unix": test_now(),
            },
            "certificate": pki.client_pq_certificate,
            "ml_dsa_87_signature": "",
        },
    });
    write_frame(&mut send, &legacy).await.unwrap();
    let _ = send.finish();

    // The gateway closes without acknowledging anything: `released` no
    // longer exists.
    let answer = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame::<ServerMessage>(&mut recv),
    )
    .await
    .unwrap();
    assert!(
        answer.is_err(),
        "a removed tag must not produce an application response: {answer:?}"
    );
    assert!(!handler.rolled_back.load(Ordering::SeqCst));

    connection.close(0u32.into(), b"test complete");
    client.close(0u32.into(), b"test complete");
    task.abort();
}
