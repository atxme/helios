pub(super) fn authorization(
    fixture: &Fixture,
    candidate_leaf: &PqCertificate,
    stage_id: u8,
    stage_expires_at: u64,
) -> ClientCertificateStageAuthorization {
    let authorization = ClientCertificateStageAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        stage_id: Id16::new([stage_id; 16]).expect("stage"),
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"operator approval"),
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(2),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .state
            .active
            .pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: fixture.tls.authority.fingerprint(),
        next_tls_certificate: fixture.tls.leaf.clone(),
        next_pq_certificate: candidate_leaf.clone(),
        issued_at: 1_000,
        stage_expires_at,
        window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
        reason: RotationReason::Scheduled,
        signature: MlDsa87Signature::placeholder(),
    };
    authorization.sign(&fixture.ca.private).expect("sign")
}

/// The grant the authority releases against a receipt, signed by `CA-PQ`
/// acting as the master issuer.
pub(super) fn grant_for(
    fixture: &Fixture,
    authorization: &ClientCertificateStageAuthorization,
    receipt: GatewayCertificateStageReceipt,
) -> ClientCertificateRotationGrant {
    ClientCertificateRotationGrant {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: authorization.trust_domain_id,
        ca_epoch: authorization.ca_epoch,
        ca_tls_epoch: authorization.ca_tls_epoch,
        issuer_kind: authorization.issuer_kind,
        issuer_epoch: authorization.issuer_epoch,
        issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
        issuer_authorization: authorization.issuer_authorization.clone(),
        request_fingerprint: authorization.request_fingerprint,
        renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
        renewal_approval: authorization.renewal_approval.clone(),
        campaign_approval: authorization.campaign_approval.clone(),
        stage_receipt_fingerprint: receipt.fingerprint(),
        stage_receipt: receipt,
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        server_name: authorization.server_name.clone(),
        client_wg_public_key: authorization.client_wg_public_key,
        active_generation: authorization.active_generation,
        next_generation: authorization.next_generation,
        active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
        next_tls_certificate: authorization.next_tls_certificate.clone(),
        next_pq_certificate: authorization.next_pq_certificate.clone(),
        stage_expires_at: authorization.stage_expires_at,
        window: authorization.window,
        reason: authorization.reason,
        signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca.private)
    .expect("sign grant")
}

/// The commit a client sends once it holds the grant.
pub(super) fn commit_for(
    authorization: &ClientCertificateStageAuthorization,
    grant: &ClientCertificateRotationGrant,
    active_private: &[u8],
    candidate_private: &[u8],
    committed_at: u64,
) -> ClientCertificateStageCommit {
    let candidate = authorization.candidate().expect("candidate");
    ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: authorization.trust_domain_id,
        stage_id: authorization.stage_id,
        grant_fingerprint: grant.fingerprint().expect("fingerprint"),
        stage_receipt_fingerprint: grant.stage_receipt_fingerprint,
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        client_wg_public_key: authorization.client_wg_public_key,
        active_generation: authorization.active_generation,
        staged_generation: candidate.generation,
        staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
        staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
        stage_expires_at: authorization.stage_expires_at,
        committed_at,
        active_pq_signature: MlDsa87Signature::placeholder(),
        staged_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(active_private, candidate_private)
    .expect("sign commit")
}

/// The receipt is produced only after the candidate is on disk: that
/// ordering is what stops an identity from existing before its admission.
#[test]
fn a_receipt_describes_a_candidate_that_is_already_persisted() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging");

    let reloaded = CertificateRegistry::load(&fixture.registry.path)
        .expect("load")
        .expect("registry on disk");
    let peer = reloaded.peer(&client_key(2)).expect("peer");
    assert_eq!(
        peer.state
            .pending
            .as_ref()
            .expect("pending")
            .candidate
            .generation,
        5
    );

    // And the receipt verifies under the gateway leaf it names.
    let receipt = receipt
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign");
    receipt
        .verify(
            &fixture.gateway_leaf_key.public,
            &fixture
                .registry
                .state
                .gateway
                .active_pq_fingerprint()
                .expect("fingerprint"),
            &authorization,
        )
        .expect("receipt verifies");
}

/// The last complete registry shape had no ledger. Accepting it with an
/// empty default would forget every local peer-removal tombstone.
#[test]
fn a_registry_from_the_previous_shape_is_refused() {
    let fixture = fixture();
    let path = fixture.registry.path.clone();
    let mut previous = serde_json::to_value(fixture.registry.state()).expect("serialize registry");
    previous
        .as_object_mut()
        .expect("registry object")
        .remove("ledger");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&previous).expect("encode previous shape"),
    )
    .expect("write previous shape");

    assert!(matches!(
        CertificateRegistry::load(&path),
        Err(RegistryError::Corrupt(_))
    ));
}

/// The caller is resolved from the transport; the body is only compared.
#[test]
fn a_staging_aimed_at_another_peer_is_refused() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

    assert!(matches!(
        fixture
            .registry
            .stage(&client_key(9), &authorization, 1_100),
        Err(RegistryError::PeerMismatch)
    ));
}

#[test]
fn a_commit_carrying_the_grant_promotes_the_candidate_to_next() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &authorization, receipt);
    let commit = commit_for(
        &authorization,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );

    assert_eq!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300)
            .expect("commit"),
        InstallOutcome::Installed
    );
    let peer = fixture.registry.peer(&client_key(2)).expect("peer");
    assert!(peer.state.pending.is_none());
    assert_eq!(peer.state.next.as_ref().expect("next").generation, 5);

    // A retry over a lossy link must be a no-op, not a refusal.
    assert_eq!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_400)
            .expect("replay"),
        InstallOutcome::AlreadyPresent
    );
}

/// A failed write must leave the registry describing what is on disk.
///
/// Mutating memory and saving afterwards produces the worst outcome
/// available here: the running gateway answers the client's retry with
/// success, and a restart then reloads a candidate that is still pending.
/// The transaction is closed on the client's side, so nothing asks again.
#[test]
fn a_commit_whose_write_fails_leaves_the_registry_on_what_is_on_disk() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &authorization, receipt);
    let commit = commit_for(
        &authorization,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );

    // Repoint the registry at a path no write can reach.
    let unwritable = fixture
        ._directory
        .path()
        .join("missing")
        .join("certificates.json");
    fixture.registry = CertificateRegistry::new(unwritable, fixture.registry.state().clone());

    assert!(matches!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300),
        Err(RegistryError::Io(_))
    ));
    let peer = fixture.registry.peer(&client_key(2)).expect("peer");
    assert!(
        peer.state.pending.is_some() && peer.state.next.is_none(),
        "the live state must still describe the candidate the disk holds"
    );

    // And the retry is the same refusal, not a success invented in memory.
    assert!(matches!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_400),
        Err(RegistryError::Io(_))
    ));
}

/// Idempotency is the same signed document. A second, differently-signed
/// commit naming the same stage is a conflict — answering it with success
/// would report someone else's decision as landed.
#[test]
fn a_second_differently_signed_commit_for_the_same_stage_is_a_conflict() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &authorization, receipt);
    let commit = commit_for(
        &authorization,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );
    fixture
        .registry
        .commit(&client_key(2), &commit, &grant, 1_300)
        .expect("commit");

    // Same stage, same candidate, a different signed document: only
    // `committed_at` moved.
    let other = commit_for(
        &authorization,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_250,
    );
    assert!(matches!(
        fixture
            .registry
            .commit(&client_key(2), &other, &grant, 1_400),
        Err(RegistryError::Certificate(
            CertificateError::GenerationConflict { .. }
        ))
    ));
}

/// A commit that arrives at the deadline loses the race against the purge,
/// deterministically — the clock is read once, by the caller.
#[test]
fn a_commit_arriving_at_the_lease_deadline_is_refused() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &authorization, receipt);
    let commit = commit_for(
        &authorization,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );

    assert!(fixture
        .registry
        .commit(&client_key(2), &commit, &grant, 5_000)
        .is_err());
    assert!(fixture
        .registry
        .peer(&client_key(2))
        .expect("peer")
        .state
        .next
        .is_none());
}

/// The point of the whole staging protocol: holding both private keys is
/// not enough. Without a grant the authority released, the candidate the
/// gateway persisted stays where it is.
#[test]
fn a_client_holding_both_keys_cannot_commit_without_a_grant() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");

    // A grant the client forged for itself: everything matches except the
    // authority that signed it.
    let impostor = keys();
    let forged = ClientCertificateRotationGrant {
        signature: MlDsa87Signature::placeholder(),
        ..grant_for(&fixture, &authorization, receipt.clone())
    }
    .sign(&impostor.private)
    .expect("sign");
    let commit = commit_for(
        &authorization,
        &forged,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );
    assert!(matches!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &forged, 1_300),
        Err(RegistryError::Certificate(
            CertificateError::InvalidSignature
        ))
    ));

    // And a commit naming a grant other than the one it carries is refused
    // before any state moves.
    let genuine = grant_for(&fixture, &authorization, receipt);
    let mismatched = ClientCertificateStageCommit {
        grant_fingerprint: Fingerprint::of(b"another grant"),
        ..commit_for(
            &authorization,
            &genuine,
            &fixture.active_client.private,
            &candidate.private,
            1_200,
        )
    };
    assert!(fixture
        .registry
        .commit(&client_key(2), &mismatched, &genuine, 1_300)
        .is_err());

    assert!(
        fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .state
            .next
            .is_none(),
        "no refusal may leave a committed slot behind"
    );
}

/// A commit that only proves the candidate key would let a leaked grant
/// install an identity its owner never asked for.
#[test]
fn a_commit_missing_the_active_signature_is_refused() {
    let mut fixture = fixture();
    let candidate = keys();
    let stranger = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &authorization, receipt);
    // Signed by a key that is not the peer's active one: continuity is
    // exactly what this signature is there to prove.
    let commit = commit_for(
        &authorization,
        &grant,
        &stranger.private,
        &candidate.private,
        1_200,
    );

    assert!(matches!(
        fixture
            .registry
            .commit(&client_key(2), &commit, &grant, 1_300),
        Err(RegistryError::Certificate(CertificateError::MissingProof(
            "active client"
        )))
    ));
}

/// An orphaned stage is purged at its lease and frees `active + 1` again.
#[test]
fn an_orphaned_stage_is_purged_and_the_generation_becomes_requestable_again() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let first = authorization(&fixture, &candidate_leaf, 5, 5_000);
    fixture
        .registry
        .stage(&client_key(2), &first, 1_100)
        .expect("staging");

    // A second stage while the first lives is refused outright.
    let second = authorization(&fixture, &candidate_leaf, 6, 5_000);
    assert!(fixture
        .registry
        .stage(&client_key(2), &second, 1_200)
        .is_err());

    let purged = fixture.registry.purge_expired(5_000).expect("purge");
    assert_eq!(purged.len(), 1);
    assert!(fixture
        .registry
        .peer(&client_key(2))
        .expect("peer")
        .state
        .pending
        .is_none());

    // The same generation is requestable again, under a new stage id.
    let retry = authorization(&fixture, &candidate_leaf, 7, 9_000);
    fixture
        .registry
        .stage(&client_key(2), &retry, 5_100)
        .expect("re-staging");
}

/// A certificate identifies exactly one peer, active or staged.
#[test]
fn a_fingerprint_already_bound_to_another_peer_is_refused() {
    let mut fixture = fixture();
    let candidate = keys();
    // A leaf legitimately bound to peer 2 — so the authorization itself
    // verifies — but already recorded against another admitted peer.
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    fixture
        .registry
        .admit(
            "laptop",
            &client_key(3),
            generation(1, b"other tls", &candidate_leaf),
            candidate_leaf.clone(),
        )
        .expect("admission");

    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    assert!(matches!(
        fixture
            .registry
            .stage(&client_key(2), &authorization, 1_100),
        Err(RegistryError::FingerprintTaken(name)) if name == "laptop"
    ));
    // And the refusal changed nothing.
    assert!(fixture
        .registry
        .peer(&client_key(2))
        .expect("peer")
        .state
        .pending
        .is_none());
}

/// Revocation dominates a staging that is already persisted.
#[test]
fn revocation_removes_a_staged_candidate_and_refuses_the_commit() {
    let mut fixture = fixture();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);
    fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging");

    fixture
        .registry
        .revoke(&client_key(2), 1, 1_000)
        .expect("revoke");
    let peer = fixture.registry.peer(&client_key(2)).expect("peer");
    assert!(peer.state.revoked);
    assert!(peer.state.pending.is_none());
    assert!(peer.staged_pq_certificate.is_none());

    // And nothing can be staged again for a revoked peer.
    assert!(matches!(
        fixture
            .registry
            .stage(&client_key(2), &authorization, 1_200),
        Err(RegistryError::Certificate(CertificateError::Revoked))
    ));
}
use super::*;
