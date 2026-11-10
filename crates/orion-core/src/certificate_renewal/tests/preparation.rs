//! Local renewal preparation binds one new identity to the exact active
//! generation and refuses malformed keys or overflowing counters early.

use aether::certificates::encoding::MlDsa87PublicKey;
use aether::certificates::{
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

use crate::certificate_renewal::{
    ActiveIdentity, RenewalError, RenewalSession, REQUEST_LIFETIME_SECS,
};
use crate::certificates::TrustStore;
use crate::test_domain::*;

#[test]
fn preparation_binds_and_signs_the_request_from_the_trust_store() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let mut session = RenewalSession::prepare(&store, SUBJECT, "http://100.64.0.1:8080/", NOW)
        .expect("prepare request");

    let request = session.request();
    let state = store.state();
    assert_eq!(request.format_version, CERTIFICATE_FORMAT_VERSION);
    assert_eq!(request.protocol_version, CERTIFICATE_PROTOCOL_VERSION);
    assert_eq!(request.trust_domain_id, state.trust_domain_id);
    assert_eq!(
        request.gateway_wg_public_key,
        state.gateway.gateway_wg_public_key
    );
    assert_eq!(request.server_name, state.gateway.server_name);
    assert_eq!(request.client_wg_public_key, state.client_wg_public_key);
    assert_eq!(
        request.active_generation,
        state.certificates.active.generation
    );
    assert_eq!(request.requested_generation, request.active_generation + 1);
    assert_eq!(
        request.active_tls_certificate_fingerprint,
        state.certificates.active.tls_certificate_fingerprint
    );
    assert_eq!(
        request.active_pq_certificate_fingerprint,
        state.certificates.active.pq_certificate_fingerprint
    );
    assert_eq!(request.created_at, NOW);
    assert_eq!(request.expires_at, NOW + REQUEST_LIFETIME_SECS);
    assert_eq!(session.operation_id(), None);

    session
        .sign(&ActiveIdentity {
            pq_private_key: domain.active_client_private.clone(),
            tls_private_key_der: Zeroizing::new(vec![7; 64]),
        })
        .expect("sign active continuity and candidate possession");
    session
        .request()
        .verify(
            &MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
                .expect("active client key"),
            &domain_id(),
            &gateway_key(),
            SERVER_NAME,
            &active_generation(&domain),
            &client_key(),
            NOW,
        )
        .expect("both request proofs verify");
}

#[test]
fn preparation_refuses_generation_counter_overflow() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut state = store(directory.path(), &domain).state().clone();
    state.certificates.active.generation = u64::MAX;
    let store = TrustStore::new(directory.path().join("overflow.json"), state);

    assert!(matches!(
        RenewalSession::prepare(&store, SUBJECT, "http://100.64.0.1:8080", NOW),
        Err(RenewalError::Certificate(
            CertificateError::ArithmeticOverflow
        ))
    ));
}

#[test]
fn preparation_refuses_expiration_timestamp_overflow() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let store = store(directory.path(), &domain);
    let near_max = u64::MAX - REQUEST_LIFETIME_SECS + 1;

    assert!(matches!(
        RenewalSession::prepare(&store, SUBJECT, "http://100.64.0.1:8080", near_max),
        Err(RenewalError::Certificate(
            CertificateError::ArithmeticOverflow
        ))
    ));
}

#[test]
fn active_identity_refuses_an_unreadable_tls_private_key_without_echoing_it() {
    let domain = domain();
    let mut bundle = bundle(&domain);
    let malformed = "not-a-base64-tls-private-key";
    bundle.private_key = malformed.into();

    let error = ActiveIdentity::from_bundle(&bundle)
        .err()
        .expect("malformed TLS key");
    let RenewalError::Identity(message) = error else {
        panic!("expected an identity decoding error");
    };
    assert!(message.contains("clé privée TLS"));
    assert!(!message.contains(malformed));
}

#[test]
fn active_identity_refuses_an_unreadable_pq_private_key_without_echoing_it() {
    let domain = domain();
    let mut bundle = bundle(&domain);
    let malformed = "not-a-base64-pq-private-key";
    bundle.pq_private_key = malformed.into();

    let error = ActiveIdentity::from_bundle(&bundle)
        .err()
        .expect("malformed PQ key");
    let RenewalError::Identity(message) = error else {
        panic!("expected an identity decoding error");
    };
    assert!(message.contains("clé privée PQ cliente"));
    assert!(!message.contains(malformed));
}
