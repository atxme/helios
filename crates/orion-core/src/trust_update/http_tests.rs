use super::*;
use crate::test_domain::{client_key, domain, domain_id, gateway_key, Domain, NOW};
use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
use aether::certificates::revocation::{
    EmergencyCertificateRevocation, RevocationReason, RevocationScope,
};
use aether::certificates::transport::signing::{build_transaction, TransactionPlan};
use aether::certificates::transport::{
    TrustUpdateChunk, TrustUpdateObject, TrustUpdateTransactionManifest,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt as _;

type Replies = VecDeque<(u16, Vec<u8>)>;

async fn finish_server(mut server: tokio::task::JoinHandle<()>) {
    let result = tokio::time::timeout(Duration::from_secs(5), &mut server).await;
    server.abort();
    result
        .expect("server completed all expected requests")
        .expect("server assertions");
}

async fn server(
    replies: Replies,
    store_path: std::path::PathBuf,
    original: Vec<u8>,
) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        let mut replies = replies;
        while let Some((status, body)) = replies.pop_front() {
            let (mut stream, _) = listener.accept().await.expect("connection");
            let request = super::tests::read_request(&mut stream).await;
            recorded.lock().expect("requests").push(request);
            assert_eq!(
                std::fs::read(&store_path).expect("persisted state"),
                original,
                "no prefix of a transaction may be persisted"
            );
            let head = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.expect("headers");
            let _ = stream.write_all(&body).await;
        }
    });
    (format!("http://{address}"), seen, server)
}

fn transaction(
    store: &TrustStore,
    domain: &Domain,
    service_private: &[u8],
) -> (TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>) {
    let active = &store.state().certificates.active;
    let objects: Vec<_> = (1..=2)
        .map(|epoch| {
            TrustUpdateObject::CertificateRevocation(Box::new(
                EmergencyCertificateRevocation {
                    format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                    trust_domain_id: domain_id(),
                    ca_epoch: 1,
                    scope: RevocationScope::Client,
                    identity_key: client_key(),
                    server_name: None,
                    revocation_epoch: epoch,
                    revoked_tls_fingerprint: (epoch == 1)
                        .then_some(active.tls_certificate_fingerprint),
                    revoked_tls_not_after: (epoch == 1).then_some(active.not_after),
                    revoked_pq_fingerprint: (epoch == 2)
                        .then_some(active.pq_certificate_fingerprint),
                    revoked_pq_not_after: (epoch == 2).then_some(active.not_after),
                    effective_at: NOW + 3_600,
                    reason: RevocationReason::KeyCompromise,
                    replacement_transition_fingerprint: None,
                    ca_signature: MlDsa87Signature::placeholder(),
                }
                .sign(&domain.ca_pq_private)
                .expect("signed revocation"),
            ))
        })
        .collect();
    let budget = objects
        .iter()
        .map(|object| serde_json::to_vec(object).expect("encoding").len())
        .max()
        .expect("objects");
    let plan = TransactionPlan {
        transaction_id: Id16::new([7; 16]).expect("transaction id"),
        trust_domain_id: domain_id(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        base_state_fingerprint: store.base_state_fingerprint().expect("snapshot"),
        created_at: NOW - 1,
        expires_at: NOW + 300,
        minimum_activation_at: NOW + 3_600,
        authority_epoch: 1,
        authority_private_key: service_private,
    };
    let built = build_transaction(objects, &plan, budget).expect("transaction");
    assert_eq!(built.1.len(), 2, "two separately delivered fragments");
    built
}

fn reply(manifest: &TrustUpdateTransactionManifest, chunk: &TrustUpdateChunk) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"status": null, "manifest": manifest, "chunk": chunk}))
        .expect("response")
}

async fn run_with_watchdog(
    session: TrustUpdateSession,
    store: &mut TrustStore,
) -> Result<TrustUpdateOutcome, TrustUpdateError> {
    tokio::time::timeout(Duration::from_secs(10), session.run(store, NOW))
        .await
        .expect("trust update finishes within the independent test deadline")
}

fn session(store: &TrustStore, domain: &Domain, url: &str) -> TrustUpdateSession {
    TrustUpdateSession::prepare(
        store,
        url,
        domain.active_client_leaf.clone(),
        &domain.active_client_private,
    )
    .expect("session")
}

#[tokio::test]
async fn signed_http_transaction_is_applied_once_and_survives_reload() {
    let directory = tempfile::tempdir().expect("directory");
    let domain = domain();
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service key");
    let mut state = crate::test_domain::store(directory.path(), &domain)
        .state()
        .clone();
    state.astra.active_astra_service_public_key = service_public;
    let path = directory.path().join("trust.json");
    let mut store = TrustStore::new(path.clone(), state);
    store.save().expect("persist fixture");
    let original = std::fs::read(&path).expect("original");
    let (manifest, chunks) = transaction(&store, &domain, &service_private);
    let replies = chunks
        .iter()
        .map(|chunk| (200, reply(&manifest, chunk)))
        .collect();
    let (url, seen, server) = server(replies, path.clone(), original).await;
    let result = run_with_watchdog(session(&store, &domain, &url), &mut store).await;
    finish_server(server).await;
    assert_eq!(
        result.expect("whole transaction"),
        TrustUpdateOutcome::Applied { objects: 2 }
    );
    let requests = seen.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|line| line.starts_with("POST /api/key-negotiation/trust-update ")));
    drop(requests);
    assert_eq!(store.state().ledger.scheduled_revocations.len(), 2);
    let reloaded = TrustStore::load(&path).expect("load").expect("persisted");
    assert_eq!(reloaded.state(), store.state());
    assert!(
        store
            .verify_and_apply_transaction(&manifest, &chunks, NOW)
            .is_err(),
        "same base cannot be applied twice"
    );
}

#[tokio::test]
async fn losing_the_last_page_leaves_live_and_durable_state_intact() {
    let directory = tempfile::tempdir().expect("directory");
    let domain = domain();
    let (private, _) = generate_ml_dsa_87_keypair().expect("service key");
    let mut store = crate::test_domain::store(directory.path(), &domain);
    store.save().expect("persist fixture");
    let path = directory.path().join("trust.json");
    let before = store.state().clone();
    let original = std::fs::read(&path).expect("original");
    let (manifest, chunks) = transaction(&store, &domain, &private);
    let replies = VecDeque::from([(200, reply(&manifest, &chunks[0])), (503, Vec::new())]);
    let (url, seen, server) = server(replies, path.clone(), original.clone()).await;
    let result = run_with_watchdog(session(&store, &domain, &url), &mut store).await;
    finish_server(server).await;
    assert!(matches!(
        result,
        Err(TrustUpdateError::Status { status: 503 })
    ));
    assert_eq!(seen.lock().expect("requests").len(), 2);
    assert_eq!(store.state(), &before);
    assert_eq!(std::fs::read(path).expect("persisted"), original);
}

#[tokio::test]
async fn repeating_a_fragment_exhausts_the_poll_budget_without_writing() {
    let directory = tempfile::tempdir().expect("directory");
    let domain = domain();
    let (private, _) = generate_ml_dsa_87_keypair().expect("service key");
    let mut store = crate::test_domain::store(directory.path(), &domain);
    store.save().expect("persist fixture");
    let path = directory.path().join("trust.json");
    let original = std::fs::read(&path).expect("original");
    let before = store.state().clone();
    let (manifest, chunks) = transaction(&store, &domain, &private);
    let replies = (0..MAX_POLLS)
        .map(|_| (200, reply(&manifest, &chunks[0])))
        .collect();
    let (url, seen, server) = server(replies, path.clone(), original.clone()).await;
    let result = run_with_watchdog(session(&store, &domain, &url), &mut store).await;
    finish_server(server).await;
    assert!(matches!(result, Err(TrustUpdateError::NeverCompleted)));
    assert_eq!(seen.lock().expect("requests").len(), MAX_POLLS);
    assert_eq!(store.state(), &before);
    assert_eq!(std::fs::read(path).expect("persisted"), original);
}

#[tokio::test]
async fn the_actual_poll_accepts_bounded_json_and_rejects_unknown_or_oversize_answers() {
    let directory = tempfile::tempdir().expect("directory");
    let domain = domain();
    let mut store = crate::test_domain::store(directory.path(), &domain);
    store.save().expect("persist fixture");
    let path = directory.path().join("trust.json");
    let original = std::fs::read(&path).expect("original");
    let before = store.state().clone();
    let limit = MAX_TRUST_UPDATE_RESPONSE_BYTES;
    for (body, accepted) in [
        ([b"{}".as_slice(), &vec![b' '; limit - 3]].concat(), true),
        ([b"{}".as_slice(), &vec![b' '; limit - 2]].concat(), true),
        ([b"{}".as_slice(), &vec![b' '; limit - 1]].concat(), false),
        (b"{\"unexpected\":true}".to_vec(), false),
        (
            b"{\"status\":null,\"manifest\":null,\"chunk\":null}".to_vec(),
            true,
        ),
        (b"{\"status\":true}".to_vec(), false),
        (b"{".to_vec(), false),
    ] {
        let (url, _, server) = server(
            VecDeque::from([(200, body)]),
            path.clone(),
            original.clone(),
        )
        .await;
        let result = run_with_watchdog(session(&store, &domain, &url), &mut store).await;
        finish_server(server).await;
        if accepted {
            assert_eq!(result.expect("legal JSON"), TrustUpdateOutcome::UpToDate);
        } else {
            assert!(
                matches!(result, Err(TrustUpdateError::Malformed(_))),
                "{result:?}"
            );
        }
        assert_eq!(store.state(), &before);
        assert_eq!(std::fs::read(&path).expect("persisted"), original);
    }
}

#[tokio::test]
async fn a_redirect_is_reported_instead_of_followed() {
    let directory = tempfile::tempdir().expect("directory");
    let domain = domain();
    let mut store = crate::test_domain::store(directory.path(), &domain);
    let before = store.state().clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("connection");
        super::tests::read_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\n\r\n").await.expect("redirect");
    });
    let result = run_with_watchdog(
        session(&store, &domain, &format!("http://{address}")),
        &mut store,
    )
    .await;
    finish_server(server).await;
    assert!(matches!(
        result,
        Err(TrustUpdateError::Status { status: 307 })
    ));
    assert_eq!(store.state(), &before);
}

struct SignedFixture {
    directory: tempfile::TempDir,
    domain: Domain,
    service_private: Zeroizing<Vec<u8>>,
    store: TrustStore,
}

impl SignedFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let domain = domain();
        let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service key");
        let mut state = crate::test_domain::store(directory.path(), &domain)
            .state()
            .clone();
        state.astra.active_astra_service_public_key = service_public;
        let store = TrustStore::new(directory.path().join("trust.json"), state);
        store.save().expect("persist fixture");
        Self {
            directory,
            domain,
            service_private,
            store,
        }
    }

    fn transaction(&self) -> (TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>) {
        transaction(&self.store, &self.domain, &self.service_private)
    }

    async fn refuse(
        &mut self,
        manifest: &TrustUpdateTransactionManifest,
        chunks: &[TrustUpdateChunk],
    ) -> TrustUpdateError {
        let path = self.directory.path().join("trust.json");
        let before = self.store.state().clone();
        let original = std::fs::read(&path).expect("persisted state");
        let replies = chunks
            .iter()
            .map(|chunk| (200, reply(manifest, chunk)))
            .collect();
        let (url, seen, server) = server(replies, path.clone(), original.clone()).await;
        let result =
            run_with_watchdog(session(&self.store, &self.domain, &url), &mut self.store).await;
        finish_server(server).await;
        assert_eq!(seen.lock().expect("requests").len(), 2);
        assert_eq!(self.store.state(), &before);
        assert_eq!(std::fs::read(&path).expect("durable state"), original);
        assert_eq!(
            TrustStore::load(&path)
                .expect("reload")
                .expect("persisted store")
                .state(),
            &before,
        );
        result.expect_err("the complete transaction must be refused")
    }
}

fn reattribute(manifest: &TrustUpdateTransactionManifest, chunks: &mut [TrustUpdateChunk]) {
    for chunk in chunks {
        chunk.manifest_fingerprint = manifest.fingerprint();
    }
}

#[tokio::test]
async fn an_unpinned_manifest_signer_is_refused_after_the_final_fragment() {
    let mut fixture = SignedFixture::new();
    let (manifest, mut chunks) = fixture.transaction();
    let (untrusted_private, _) = generate_ml_dsa_87_keypair().expect("untrusted key");
    let manifest = manifest
        .sign(&untrusted_private)
        .expect("untrusted signature");
    reattribute(&manifest, &mut chunks);
    assert!(matches!(
        fixture.refuse(&manifest, &chunks).await,
        TrustUpdateError::Store(TrustError::Certificate(CertificateError::InvalidSignature))
    ));
}

#[tokio::test]
async fn an_authenticated_manifest_cannot_address_another_domain_or_peer() {
    use aether::certificates::encoding::{TrustDomainId, WireGuardKey};

    let mut fixture = SignedFixture::new();
    for target in 0..3 {
        let (mut manifest, mut chunks) = fixture.transaction();
        let expected = match target {
            0 => {
                manifest.trust_domain_id = TrustDomainId::new([99; 16]).expect("other domain");
                CertificateError::TrustDomainMismatch
            }
            1 => {
                manifest.gateway_wg_public_key = WireGuardKey::from_bytes([99; 32]);
                CertificateError::GatewayIdentityMismatch
            }
            _ => {
                manifest.client_wg_public_key = WireGuardKey::from_bytes([99; 32]);
                CertificateError::ClientIdentityMismatch
            }
        };
        let manifest = manifest
            .sign(&fixture.service_private)
            .expect("signed target");
        reattribute(&manifest, &mut chunks);
        let error = fixture.refuse(&manifest, &chunks).await;
        let TrustUpdateError::Store(TrustError::Certificate(actual)) = error else {
            panic!("expected a store certificate refusal: {error:?}");
        };
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn an_online_manifest_cannot_select_another_authority_or_epoch() {
    use aether::certificates::transport::ManifestAuthority;

    let mut fixture = SignedFixture::new();
    for ca_authority in [false, true] {
        let (mut manifest, mut chunks) = fixture.transaction();
        if ca_authority {
            manifest.manifest_authority_kind = ManifestAuthority::CaPq;
            manifest = manifest
                .sign(&fixture.domain.ca_pq_private)
                .expect("CA signature");
        } else {
            manifest.manifest_authority_epoch += 1;
            manifest = manifest
                .sign(&fixture.service_private)
                .expect("service signature");
        }
        reattribute(&manifest, &mut chunks);
        assert!(matches!(
            fixture.refuse(&manifest, &chunks).await,
            TrustUpdateError::Store(TrustError::Certificate(
                CertificateError::UnauthorizedIssuer
            ))
        ));
    }
}

#[tokio::test]
async fn a_complete_transaction_is_refused_at_expiry_or_earliest_activation() {
    let mut fixture = SignedFixture::new();
    for expired in [true, false] {
        let (mut manifest, mut chunks) = fixture.transaction();
        let expected = if expired {
            manifest.expires_at = NOW;
            CertificateError::InvalidLease
        } else {
            manifest.minimum_activation_at = NOW;
            CertificateError::InvalidTransaction("minimum activation reached")
        };
        let manifest = manifest
            .sign(&fixture.service_private)
            .expect("signed window");
        reattribute(&manifest, &mut chunks);
        let error = fixture.refuse(&manifest, &chunks).await;
        let TrustUpdateError::Store(TrustError::Certificate(actual)) = error else {
            panic!("expected a store certificate refusal: {error:?}");
        };
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn an_authentic_envelope_does_not_authorize_an_invalid_last_object() {
    let mut fixture = SignedFixture::new();
    let (mut manifest, mut chunks) = fixture.transaction();
    let TrustUpdateObject::CertificateRevocation(revocation) = &mut chunks[1].objects[0] else {
        panic!("the final fixture object is a revocation");
    };
    revocation.ca_signature = MlDsa87Signature::placeholder();
    // Authenticate the altered object as transport content. The first valid
    // revocation may be evaluated in a candidate, but the envelope never
    // replaces the last object's own CA authorization.
    manifest.objects[1].object_fingerprint = chunks[1].objects[0]
        .fingerprint()
        .expect("altered object fingerprint");
    let manifest = manifest
        .sign(&fixture.service_private)
        .expect("authentic envelope");
    reattribute(&manifest, &mut chunks);
    assert!(matches!(
        fixture.refuse(&manifest, &chunks).await,
        TrustUpdateError::Store(TrustError::Certificate(CertificateError::InvalidSignature))
    ));
}

#[tokio::test]
async fn substituting_the_last_object_is_refused_before_store_application() {
    let mut fixture = SignedFixture::new();
    let (manifest, mut chunks) = fixture.transaction();
    let TrustUpdateObject::CertificateRevocation(revocation) = &mut chunks[1].objects[0] else {
        panic!("the final fixture object is a revocation");
    };
    revocation.revocation_epoch += 1;
    assert!(matches!(
        fixture.refuse(&manifest, &chunks).await,
        TrustUpdateError::Certificate(CertificateError::FingerprintMismatch("transaction object"))
    ));
}

#[tokio::test]
async fn a_fresh_session_can_apply_the_whole_transaction_after_losing_the_last_page() {
    let mut fixture = SignedFixture::new();
    let (manifest, chunks) = fixture.transaction();
    let path = fixture.directory.path().join("trust.json");
    let original = std::fs::read(&path).expect("original");
    let before = fixture.store.state().clone();
    let replies = VecDeque::from([(200, reply(&manifest, &chunks[0])), (503, Vec::new())]);
    let (url, _, failed_server) = server(replies, path.clone(), original.clone()).await;
    assert!(matches!(
        run_with_watchdog(
            session(&fixture.store, &fixture.domain, &url),
            &mut fixture.store,
        )
        .await,
        Err(TrustUpdateError::Status { status: 503 })
    ));
    finish_server(failed_server).await;
    assert_eq!(fixture.store.state(), &before);
    assert_eq!(std::fs::read(&path).expect("after failure"), original);

    let mut reloaded = TrustStore::load(&path).expect("reload").expect("store");
    let replies = chunks
        .iter()
        .map(|chunk| (200, reply(&manifest, chunk)))
        .collect();
    let (url, seen, complete_server) = server(replies, path.clone(), original).await;
    assert_eq!(
        run_with_watchdog(session(&reloaded, &fixture.domain, &url), &mut reloaded)
            .await
            .expect("fresh session applies both fragments"),
        TrustUpdateOutcome::Applied { objects: 2 }
    );
    finish_server(complete_server).await;
    assert_eq!(seen.lock().expect("requests").len(), 2);
    assert_eq!(reloaded.state().ledger.scheduled_revocations.len(), 2);
    assert_eq!(
        TrustStore::load(&path)
            .expect("reload committed state")
            .expect("committed store")
            .state(),
        reloaded.state()
    );
}
