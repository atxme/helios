use super::*;
#[cfg(feature = "certificate-signing")]
use aether::certificates::encoding::DerCertificate;
#[cfg(feature = "certificate-signing")]
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

fn generation(index: u64) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: index,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(&[index as u8, 1]),
        pq_certificate_fingerprint: Fingerprint::of(&[index as u8, 2]),
        not_before: 0,
        not_after: 1_000_000,
    }
}

fn key(seed: u8) -> WireGuardKey {
    WireGuardKey::from_bytes([seed; 32])
}

/// Derived, not drawn: the same inputs always give the same instant, so a
/// restart never moves a renewal that was about to happen.
#[test]
fn the_renewal_instant_is_stable_across_restarts() {
    let generation = generation(4);
    let first = renewal_instant(&generation, &key(1)).expect("instant");
    let second = renewal_instant(&generation, &key(1)).expect("instant");
    assert_eq!(first, second);
}

/// And it is inside the window it belongs to — never before 80 %, never at
/// or after the expiry.
#[test]
fn the_renewal_instant_stays_inside_the_window() {
    let generation = generation(4);
    let validity = generation.validity().expect("validity");
    let renewal_at = validity.renewal_at().expect("renewal");
    for seed in 0..64u8 {
        let instant = renewal_instant(&generation, &key(seed)).expect("instant");
        assert!(instant >= renewal_at, "seed {seed}");
        assert!(instant < validity.not_after, "seed {seed}");
    }
}

/// Every client gets the full remaining 20 % as its retry margin.
#[test]
fn clients_renew_at_the_eighty_percent_threshold() {
    let generation = generation(4);
    let expected = generation
        .validity()
        .expect("validity")
        .renewal_at()
        .expect("renewal");
    for seed in 0..32u8 {
        assert_eq!(
            renewal_instant(&generation, &key(seed)).expect("instant"),
            expected
        );
    }
}

/// A generation with a different validity period gets its own threshold.
#[test]
fn a_new_generation_uses_its_own_validity_period() {
    let mut next = generation(5);
    next.not_before = 1_000_000;
    next.not_after = 2_000_000;
    assert_ne!(
        renewal_instant(&generation(4), &key(1)).expect("instant"),
        renewal_instant(&next, &key(1)).expect("instant")
    );
}

#[test]
fn a_renewal_is_due_only_from_its_own_instant() {
    let generation = generation(4);
    let instant = renewal_instant(&generation, &key(1)).expect("instant");
    assert!(!renewal_is_due(&generation, &key(1), instant - 1).expect("due"));
    assert!(renewal_is_due(&generation, &key(1), instant).expect("due"));
}

/// Astra sends a suggested window with every status. It may bring a
/// renewal **forward** — an incident campaign — and can never push one
/// back: a gateway able to delay renewals could manufacture the very
/// expiry the planner exists to prevent (spec §4.3, §14.1).
#[cfg(feature = "certificate-signing")]
#[test]
fn an_astra_window_never_delays_the_local_renewal_instant() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::status::{
        AstraCertificateStatus, CertificateKind, CertificateStatus,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (_, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = store.state().certificates.active.clone();
    let client = store.state().client_wg_public_key;
    let validity = active.validity().expect("validity");
    let local_renewal_at = validity.renewal_at().expect("renewal");
    let before = renewal_instant(&active, &client).expect("instant");

    // A status that would have this client wait until the last thousand
    // seconds of the leaf's life.
    let late = AstraCertificateStatus {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        certificate_fingerprint: active.pq_certificate_fingerprint,
        certificate_kind: CertificateKind::ClientPq,
        generation: active.generation,
        status: CertificateStatus::Active,
        suggested_window_start: validity.not_after - 1_000,
        suggested_window_end: validity.not_after + 10_000,
        produced_at: 1_000,
        next_update: 4_600,
        status_epoch: 1,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service_private)
    .expect("sign");

    store
        .apply(
            &[TrustUpdateObject::CertificateStatus(Box::new(late.clone()))],
            1_000,
        )
        .expect("a correctly signed status about a slot this store holds");

    // The status landed — and moved nothing but its own counter.
    assert_eq!(
        store
            .state()
            .ledger
            .last_status_for(&active.pq_certificate_fingerprint),
        Some((1, 1))
    );
    assert_eq!(
        renewal_instant(&store.state().certificates.active, &client).expect("instant"),
        before,
        "the local instant is derived from the certificate, never from a status"
    );
    assert!(
        renewal_is_due(&store.state().certificates.active, &client, before).expect("due"),
        "the client renews at its own instant, whatever Astra suggested"
    );
    assert_eq!(
        late.clamped_window(local_renewal_at, validity.not_after),
        (local_renewal_at, validity.not_after),
        "both bounds are clamped back to what this client computed"
    );
}

/// A signed gateway leaf: a PQ certificate's fingerprint covers its own
/// signature, so an unsigned placeholder has no fingerprint at all.
#[cfg(feature = "certificate-signing")]
fn gateway_leaf() -> PqCertificate {
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;
    use aether::key_negotiation::issue_pq_certificate;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: "gateway.example".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: key(9).to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("issue")
}

#[cfg(feature = "certificate-signing")]
fn store(
    path: PathBuf,
    anchor: aether::certificates::encoding::MlDsa87PublicKey,
    service: aether::certificates::encoding::MlDsa87PublicKey,
) -> TrustStore {
    TrustStore::new(
        path,
        TrustState {
            credential_registry: None,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            client_wg_public_key: key(2),
            gateway: GatewayCertificateState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: key(9),
                server_name: "gateway.example".into(),
                ca_epoch: 1,
                current_ca_public_key: anchor,
                next_ca_public_key: None,
                next_ca_transition_fingerprint: None,
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                next_gateway_identity_epoch: None,
                next_transition_fingerprint: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_leaf(),
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
                service_rollback: None,
                awaited_replacement: None,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 1,
                active_client_tls_ca_certificate: DerCertificate::new(vec![2; 64]).expect("der"),
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                    Fingerprint::of(b"policy"),
                )
                .expect("policy pin"),
                credential_registry_epoch: 1,
                credential_bindings: Default::default(),
                active_astra_service_public_key: service,
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 1,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer_epoch: 1,
            issuer: None,
            certificates: ClientCertificateState::new(generation(4)),
            staged_gateway_transition: None,
            ledger: TrustLedger::default(),
        },
    )
}

/// The immediately preceding complete shape is refused, not silently
/// accepted with an empty tombstone list.
///
/// Nothing that ships has ever written this file, so no such document can
/// exist today — but the failure mode is what matters if one ever does:
/// loud, and on the side of refusing to run.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_trust_store_from_an_earlier_shape_is_refused_rather_than_half_read() {
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;

    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("trust.json");
    let (_, anchor) = generate_ml_dsa_87_keypair().expect("anchor");
    let (_, service) = generate_ml_dsa_87_keypair().expect("service");
    let current = store(path.clone(), anchor, service);
    let mut previous = serde_json::to_value(current.state()).expect("serialize state");
    previous
        .get_mut("ledger")
        .and_then(serde_json::Value::as_object_mut)
        .expect("ledger object")
        .remove("revoked");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&previous).expect("encode previous shape"),
    )
    .expect("write previous shape");
    assert!(matches!(
        TrustStore::load(&path),
        Err(TrustError::Corrupt(_))
    ));
}

/// The anti-rollback counter is bound even when no delegation is
/// installed. Deriving it from `issuer` would leave it out of the
/// fingerprint in exactly the case where the store has no issuer — and a
/// transaction built before the counter advanced would still match.
#[cfg(feature = "certificate-signing")]
#[test]
fn the_issuer_counter_is_bound_even_with_no_delegation_installed() {
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;

    let directory = tempfile::tempdir().expect("temp dir");
    let (_, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    assert!(store.state().issuer.is_none());

    let before = store.base_state_fingerprint().expect("fingerprint");
    let mut moved = store.state().clone();
    moved.issuer_epoch += 1;
    let store = TrustStore::new(directory.path().join("trust.json"), moved);
    assert_ne!(
        before,
        store.base_state_fingerprint().expect("fingerprint"),
        "the counter moved, so the state a manifest was built against did too"
    );
}

/// The producer and the client meet: what `aether`'s builder emits — the
/// exact call Astra makes — is collected, verified and applied by the real
/// client, with nothing between them but the wire types.
///
/// This is the test the 503 existed for. Every half was covered on its own
/// long before either could talk to the other.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_transaction_built_by_the_authority_is_applied_by_the_client() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };
    use aether::certificates::transport::signing::{build_transaction, TransactionPlan};

    let directory = tempfile::tempdir().expect("temp");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = generation(4);

    let revocation = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: key(2),
        server_name: None,
        revocation_epoch: 1,
        revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
        revoked_tls_not_after: Some(active.not_after),
        revoked_pq_fingerprint: None,
        revoked_pq_not_after: None,
        effective_at: 9_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    // The token the client would have signed into its request, read off
    // the very store the transaction is about to be applied to.
    let base = store.base_state_fingerprint().expect("base state");
    let plan = TransactionPlan {
        transaction_id: Id16::new([5; 16]).expect("id"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: key(9),
        client_wg_public_key: key(2),
        base_state_fingerprint: base,
        created_at: 1_000,
        expires_at: 5_000,
        minimum_activation_at: 9_000,
        authority_epoch: 1,
        // The **service** key, not `CA-PQ`: §0.6 makes the online manifest
        // a coordination signature. The revocation inside it still carries
        // its own `CA-PQ` proof, which is what actually authorizes it.
        authority_private_key: &service_private,
    };
    let (manifest, chunks) = build_transaction(
        vec![TrustUpdateObject::CertificateRevocation(Box::new(
            revocation,
        ))],
        &plan,
        32 * 1024,
    )
    .expect("built");

    let applied = store
        .verify_and_apply_transaction(&manifest, &chunks, 1_100)
        .expect("the client applies what the authority built");
    assert_eq!(applied, 1);
    assert_eq!(store.state().ledger.scheduled_revocations.len(), 1);

    // And the store has moved, so the same transaction no longer applies:
    // the compare-and-swap token is the whole point.
    assert!(
        store
            .verify_and_apply_transaction(&manifest, &chunks, 1_100)
            .is_err(),
        "a transaction bound to a state the store has left was applied twice"
    );
}

/// A revocation dated for later is kept, not dropped: its epoch is already
/// consumed, so it would never be delivered again.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_future_revocation_is_held_and_applied_at_its_own_instant() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = generation(4);

    let revocation = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: key(2),
        server_name: None,
        revocation_epoch: 1,
        // Only the TLS half is named, and that is still a revocation: the
        // generation is indivisible.
        revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
        revoked_tls_not_after: Some(active.not_after),
        revoked_pq_fingerprint: None,
        revoked_pq_not_after: None,
        effective_at: 9_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(
                revocation,
            ))],
            1_000,
        )
        .expect("revocation accepted");

    assert!(
        !store.state().certificates.revoked,
        "a revocation dated for later is not in force yet"
    );
    assert_eq!(
        store.state().ledger.scheduled_revocations.len(),
        1,
        "and it is kept: its epoch has already been consumed"
    );
    assert_eq!(store.state().certificates.revocation_epoch, 1);

    store.refresh(8_999).expect("refresh");
    assert!(
        !store.state().certificates.revoked,
        "one second before its instant it is still not in force"
    );

    store.refresh(9_000).expect("refresh");
    assert!(
        store.state().certificates.revoked,
        "at its instant it takes effect, even though only the TLS half was named"
    );
    assert!(store.state().ledger.scheduled_revocations.is_empty());
}

/// A gateway revocation must remove the **gateway**, and it must spend the
/// gateway's counter. Reading it against the client's consumes a number
/// the client then needs, and revokes nothing at all.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_gateway_revocation_retires_the_gateway_and_not_the_client() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let served = store
        .state()
        .gateway
        .active_pq_fingerprint()
        .expect("fingerprint");

    let revocation = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Gateway,
        identity_key: key(9),
        server_name: Some("gateway.example".into()),
        revocation_epoch: 1,
        revoked_tls_fingerprint: None,
        revoked_tls_not_after: None,
        revoked_pq_fingerprint: Some(served),
        revoked_pq_not_after: Some(1_000_000),
        effective_at: 2_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(
                revocation.clone(),
            ))],
            1_000,
        )
        .expect("revocation accepted");

    assert_eq!(store.state().ledger.gateway_revocation_epoch, 1);
    assert_eq!(
        store.state().certificates.revocation_epoch,
        0,
        "a gateway decision must not spend the client's counter"
    );

    store.refresh(2_000).expect("refresh");
    assert!(
        store.state().gateway.revoked,
        "the compromised gateway is retired at its instant"
    );
    assert!(
        store
            .acceptable_gateway_fingerprints(2_000)
            .expect("fingerprints")
            .is_empty(),
        "and no leaf of it is acceptable any more"
    );
    assert!(
        !store.state().certificates.revoked,
        "the client identity is untouched: it was not the one revoked"
    );

    // The client's own counter is still at zero, so its first revocation
    // is still deliverable — which is exactly what a shared counter would
    // have destroyed.
    let client_revocation = EmergencyCertificateRevocation {
        scope: RevocationScope::Client,
        identity_key: key(2),
        server_name: None,
        revoked_pq_fingerprint: Some(generation(4).pq_certificate_fingerprint),
        effective_at: 2_500,
        ca_signature: MlDsa87Signature::placeholder(),
        ..revocation
    }
    .sign(&anchor_private)
    .expect("sign");
    store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(
                client_revocation,
            ))],
            2_100,
        )
        .expect("the client's own first revocation still verifies");
    store.refresh(2_500).expect("refresh");
    assert!(store.state().certificates.revoked);
}

/// Two revocations dated for different instants take effect in **clock**
/// order, not counter order. The later decision can therefore land first,
/// and writing its predecessor's number afterwards would make an epoch
/// that has already been consumed deliverable again.
#[cfg(feature = "certificate-signing")]
#[test]
fn applying_revocations_out_of_counter_order_never_moves_the_counter_back() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = generation(4);

    let revocation = |epoch: u64, effective_at: u64, fingerprint| {
        EmergencyCertificateRevocation {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            scope: RevocationScope::Client,
            identity_key: key(2),
            server_name: None,
            revocation_epoch: epoch,
            revoked_tls_fingerprint: None,
            revoked_tls_not_after: None,
            revoked_pq_fingerprint: Some(fingerprint),
            revoked_pq_not_after: Some(1_000_000),
            effective_at,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private)
        .expect("sign")
    };

    // Epoch 1 is dated for later than epoch 2, so 2 reaches its instant
    // first. Both are accepted in counter order, as they arrive.
    let later = revocation(1, 9_000, Fingerprint::of(b"a leaf this client never held"));
    let sooner = revocation(2, 2_000, active.pq_certificate_fingerprint);
    store
        .apply(
            &[
                TrustUpdateObject::CertificateRevocation(Box::new(later)),
                TrustUpdateObject::CertificateRevocation(Box::new(sooner)),
            ],
            1_000,
        )
        .expect("both accepted");
    assert_eq!(store.state().certificates.revocation_epoch, 2);

    store.refresh(2_000).expect("refresh");
    assert!(store.state().certificates.revoked);
    assert_eq!(store.state().certificates.revocation_epoch, 2);

    store.refresh(9_000).expect("refresh");
    assert_eq!(
        store.state().certificates.revocation_epoch,
        2,
        "applying the older decision must not make epoch 2 deliverable again"
    );
}

/// A revocation naming a leaf the client does not hold yet is remembered,
/// not merely consumed. Otherwise its epoch is spent, the object can never
/// be delivered again, and the next transition carrying that leaf installs
/// it as if nothing had happened.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_revoked_fingerprint_is_remembered_even_when_it_was_never_held() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let unseen = Fingerprint::of(b"a candidate still in flight");

    let revocation = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: key(2),
        server_name: None,
        revocation_epoch: 1,
        revoked_tls_fingerprint: None,
        revoked_tls_not_after: None,
        revoked_pq_fingerprint: Some(unseen),
        revoked_pq_not_after: Some(1_000_000),
        effective_at: 1_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(
                revocation,
            ))],
            1_000,
        )
        .expect("revocation accepted");

    assert!(
        !store.state().certificates.revoked,
        "it named nothing this client holds, so nothing was withdrawn"
    );
    assert!(
        store.state().ledger.is_revoked(&unseen),
        "but the decision is remembered: its epoch is already spent"
    );
    let tombstone = store
        .state()
        .ledger
        .revoked
        .iter()
        .find(|tombstone| tombstone.fingerprint.matches(&unseen))
        .expect("tombstone");
    assert_eq!(tombstone.revocation_epoch, 1);
    assert_eq!(
        tombstone.expires_at, 1_000_000,
        "the signed revocation supplies the expiry even for an unseen leaf"
    );
    assert!(tombstone.revocation_fingerprint.is_some());
}

/// A revocation naming another machine is refused before its counter is
/// spent: the object is signed, but it is not about this store.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_revocation_naming_another_identity_is_refused() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );

    let stranger = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: key(77),
        server_name: None,
        revocation_epoch: 1,
        revoked_tls_fingerprint: Some(generation(4).tls_certificate_fingerprint),
        revoked_tls_not_after: Some(generation(4).not_after),
        revoked_pq_fingerprint: None,
        revoked_pq_not_after: None,
        effective_at: 1_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    assert!(store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(stranger))],
            1_000
        )
        .is_err());
    assert_eq!(store.state().certificates.revocation_epoch, 0);
    assert!(!store.state().certificates.revoked);
}

/// A future revocation is checked against a leaf already held before its
/// epoch is consumed. Deferring this check to `effective_at` would persist
/// an impossible decision and make every later refresh fail.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_revocation_with_a_false_cryptographic_expiry_is_never_scheduled() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = generation(4);
    let revocation = EmergencyCertificateRevocation {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key: key(2),
        server_name: None,
        revocation_epoch: 1,
        revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
        revoked_tls_not_after: Some(active.not_after + 1),
        revoked_pq_fingerprint: None,
        revoked_pq_not_after: None,
        effective_at: 9_000,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private)
    .expect("sign");

    assert!(store
        .apply(
            &[TrustUpdateObject::CertificateRevocation(Box::new(
                revocation
            ))],
            1_000,
        )
        .is_err());
    assert_eq!(store.state().certificates.revocation_epoch, 0);
    assert!(store.state().ledger.scheduled_revocations.is_empty());
}

/// A status must name a slot this store actually holds, of the right
/// family and generation. Taking the expected fingerprint from the status
/// itself makes the binding tautological, and a correctly signed status
/// about another identity is then absorbed as if it were about this one.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_status_about_something_this_store_does_not_hold_is_refused() {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::status::{
        AstraCertificateStatus, CertificateKind, CertificateStatus,
    };

    let directory = tempfile::tempdir().expect("temp dir");
    let (_, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public,
        service_public,
    );
    let active = generation(4);

    let status = |fingerprint, kind, generation, status_epoch| {
        AstraCertificateStatus {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            certificate_fingerprint: fingerprint,
            certificate_kind: kind,
            generation,
            status: CertificateStatus::Active,
            suggested_window_start: 800_000,
            suggested_window_end: 1_000_000,
            produced_at: 1_000,
            next_update: 4_600,
            status_epoch,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&service_private)
        .expect("sign")
    };

    // Perfectly signed, and about a certificate this store never held.
    let stranger = status(
        Fingerprint::of(b"someone else's leaf"),
        CertificateKind::ClientPq,
        4,
        1,
    );
    assert!(store
        .apply(
            &[TrustUpdateObject::CertificateStatus(Box::new(stranger))],
            1_000
        )
        .is_err());

    // The right fingerprint under the wrong family is refused too: the
    // three fields together name a slot, and any one of them alone does
    // not.
    let mislabelled = status(
        active.pq_certificate_fingerprint,
        CertificateKind::GatewayPq,
        4,
        1,
    );
    assert!(store
        .apply(
            &[TrustUpdateObject::CertificateStatus(Box::new(mislabelled))],
            1_000
        )
        .is_err());

    // The genuine one lands, and moves the counter of that target only.
    let genuine = status(
        active.pq_certificate_fingerprint,
        CertificateKind::ClientPq,
        4,
        7,
    );
    store
        .apply(
            &[TrustUpdateObject::CertificateStatus(Box::new(genuine))],
            1_000,
        )
        .expect("a status about a slot this store holds");
    assert_eq!(
        store
            .state()
            .ledger
            .last_status_for(&active.pq_certificate_fingerprint),
        Some((1, 7))
    );
    // …and the TLS half of the same generation is a different target, so
    // it still starts at its own epoch instead of being held back behind
    // the counter of a certificate it has nothing to do with.
    let tls = status(
        active.tls_certificate_fingerprint,
        CertificateKind::ClientTls,
        4,
        1,
    );
    store
        .apply(
            &[TrustUpdateObject::CertificateStatus(Box::new(tls))],
            1_000,
        )
        .expect("counters are per target");
}

/// A transaction that fails anywhere leaves the live state untouched —
/// the property that keeps a mixed trust store from ever existing.
#[cfg(feature = "certificate-signing")]
#[test]
fn a_transaction_that_fails_leaves_the_live_state_untouched() {
    use aether::certificates::authority::CaTransition;
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::window::TransitionWindow;

    let directory = tempfile::tempdir().expect("temp dir");
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut store = store(
        directory.path().join("trust.json"),
        anchor_public.clone(),
        service_public,
    );
    let before = store.state().clone();

    let valid = CaTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        current_ca_epoch: 1,
        next_ca_epoch: 2,
        current_ca_fingerprint: anchor_public.authority_fingerprint(),
        next_ca_public_key: next_public.clone(),
        next_ca_fingerprint: next_public.authority_fingerprint(),
        window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
        current_ca_signature: MlDsa87Signature::placeholder(),
        next_ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&anchor_private, &next_private)
    .expect("sign");

    // A **different** second CA transition cannot install: the store
    // already holds a rotation in flight after the first one, and it never
    // holds three anchors. (An identical replay would be idempotent — that
    // is the rule of spec §4.2, and a different one is the conflict.)
    let (other_private, other_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let conflicting = CaTransition {
        next_ca_public_key: other_public.clone(),
        next_ca_fingerprint: other_public.authority_fingerprint(),
        current_ca_signature: MlDsa87Signature::placeholder(),
        next_ca_signature: MlDsa87Signature::placeholder(),
        ..valid.clone()
    }
    .sign(&anchor_private, &other_private)
    .expect("sign");
    let objects = vec![
        TrustUpdateObject::CaTransition(Box::new(valid)),
        TrustUpdateObject::CaTransition(Box::new(conflicting)),
    ];
    assert!(store.apply(&objects, 500).is_err());
    assert_eq!(
        store.state(),
        &before,
        "a failed transaction must not move the live state"
    );
    assert!(
        TrustStore::load(&directory.path().join("trust.json"))
            .expect("load")
            .is_none(),
        "and it must not have written anything at all"
    );
}
