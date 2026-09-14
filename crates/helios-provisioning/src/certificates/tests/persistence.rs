use super::*;

/// A domain has one history. Bootstrapping over an existing registry would
/// restart the epochs at 1 while every client holds higher ones — a
/// gateway that looks freshly installed and is refused by its whole park.
#[test]
fn a_second_bootstrap_never_lands_on_the_first() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("nested").join("certificates.json");
    let state = fixture().registry.state().clone();

    let registry =
        CertificateRegistry::bootstrap(path.clone(), state.clone()).expect("first bootstrap");
    assert_eq!(registry.state(), &state);
    assert!(matches!(
        CertificateRegistry::bootstrap(path, state),
        Err(RegistryError::AlreadyBootstrapped(_))
    ));
}

/// What `bootstrap` wrote is what `load` reads back: the registry is the
/// file, and a lossy round trip would only surface at the first staging.
#[test]
fn a_bootstrapped_registry_reloads_identically() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("certificates.json");
    let state = fixture().registry.state().clone();

    CertificateRegistry::bootstrap(path.clone(), state.clone()).expect("bootstrap");
    let reloaded = CertificateRegistry::load(&path)
        .expect("load")
        .expect("a bootstrapped domain is not an absent one");
    assert_eq!(reloaded.state(), &state);
}

/// The crash matrix of the client staging path (spec §14.1).
///
/// A gateway can die at any instant of a rotation. What comes back off
/// disk is one of exactly three states — no candidate, `pending_grant`, or
/// `next_committed` — and never a fourth: a peer is written by whole
/// states, so there is no moment at which a reload finds a half one.
#[test]
fn a_crash_at_any_step_reloads_one_of_the_three_staging_states() {
    let mut fixture = fixture();
    let path = fixture.registry.path.clone();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let authorization = authorization(&fixture, &candidate_leaf, 5, 5_000);

    let on_disk = |path: &std::path::Path| {
        let reloaded = CertificateRegistry::load(path)
            .expect("load")
            .expect("registry on disk");
        let peer = reloaded.peer(&client_key(2)).expect("peer").state.clone();
        (peer.pending, peer.next, peer.active.generation)
    };

    // Before the stage: no candidate, and the active generation alone.
    let (pending, next, active) = on_disk(&path);
    assert!(pending.is_none() && next.is_none());
    assert_eq!(active, 4);

    let receipt = fixture
        .registry
        .stage(&client_key(2), &authorization, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");

    // A crash here reloads `pending_grant`, and no `next`.
    let (pending, next, active) = on_disk(&path);
    let pending = pending.expect("pending_grant");
    assert_eq!(pending.state, PendingStageState::PendingGrant);
    assert_eq!(pending.candidate.generation, 5);
    assert!(next.is_none(), "a candidate is never both pending and next");
    assert_eq!(active, 4, "the active generation keeps serving throughout");

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

    // A crash after the commit reloads `next_committed`, and no pending.
    let (pending, next, active) = on_disk(&path);
    assert!(pending.is_none(), "the commit replaced the candidate");
    assert_eq!(next.expect("next_committed").generation, 5);
    assert_eq!(active, 4);
}

/// The third state of the matrix: a stage that never received its grant.
///
/// The purge is a write like any other, so a crash after it reloads a peer
/// with no candidate at all — not one whose lease has expired in memory
/// and survived on disk.
#[test]
fn a_crash_after_the_purge_reloads_a_peer_without_a_candidate() {
    let mut fixture = fixture();
    let path = fixture.registry.path.clone();
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
    assert_eq!(
        fixture.registry.purge_expired(5_000).expect("purge").len(),
        1
    );

    let reloaded = CertificateRegistry::load(&path)
        .expect("load")
        .expect("registry on disk");
    let peer = reloaded.peer(&client_key(2)).expect("peer");
    assert!(peer.state.pending.is_none());
    assert!(peer.state.next.is_none());
    assert!(peer.staged_pq_certificate.is_none());
    assert_eq!(peer.state.active.generation, 4);
}

/// Two leafs per family is an invariant of the **state**, not of the
/// process that was running when it was written (spec §14.1).
///
/// A registry recovered from disk therefore refuses a third generation
/// exactly as the one that staged the second did — a restart is not a way
/// to obtain a candidate beside an already committed `next`.
#[test]
fn a_reloaded_registry_still_refuses_a_third_generation() {
    let mut fixture = fixture();
    let path = fixture.registry.path.clone();
    let candidate = keys();
    let candidate_leaf = leaf(
        &fixture.ca,
        &candidate,
        PqCertificateRole::Client,
        &client_key(2),
        3,
    );
    let first = authorization(&fixture, &candidate_leaf, 5, 5_000);
    let receipt = fixture
        .registry
        .stage(&client_key(2), &first, 1_100)
        .expect("staging")
        .sign(&fixture.gateway_leaf_key.private)
        .expect("sign receipt");
    let grant = grant_for(&fixture, &first, receipt);
    let commit = commit_for(
        &first,
        &grant,
        &fixture.active_client.private,
        &candidate.private,
        1_200,
    );
    fixture
        .registry
        .commit(&client_key(2), &commit, &grant, 1_300)
        .expect("commit");

    let mut reloaded = CertificateRegistry::load(&path)
        .expect("load")
        .expect("registry on disk");
    let third = authorization(&fixture, &candidate_leaf, 6, 9_000);
    assert!(matches!(
        reloaded.stage(&client_key(2), &third, 1_400),
        Err(RegistryError::Certificate(
            CertificateError::StageAlreadyPresent
        ))
    ));
    let peer = reloaded.peer(&client_key(2)).expect("peer");
    assert!(peer.state.pending.is_none());
    assert_eq!(peer.state.next.as_ref().expect("next").generation, 5);
}

/// Registries written before the Astra policy pin was added keep their
/// generations and ledger, while the three deterministic Astra fields are
/// filled and persisted on the first read by a current daemon.
#[test]
fn a_legacy_registry_is_migrated_without_losing_peers() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("certificates.json");
    let fixture = fixture();
    let state = fixture.registry.state().clone();
    let old_peer = state.peers.clone();
    let old_ledger = state.ledger.clone();
    let expected_policy = AstraIssuancePolicy::standard(
        state.trust_domain_id,
        state.gateway.gateway_wg_public_key,
        state.gateway.server_name.clone(),
    )
    .pin()
    .expect("standard policy");

    let mut legacy = serde_json::to_value(&state).expect("encode state");
    let astra = legacy
        .get_mut("astra")
        .and_then(Value::as_object_mut)
        .expect("astra object");
    astra.remove("astra_policy_fingerprint");
    astra.remove("credential_registry_epoch");
    astra.remove("credential_bindings");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy).expect("encode legacy state"),
    )
    .expect("write legacy state");

    let migrated = CertificateRegistry::load(&path)
        .expect("migrate")
        .expect("registry");
    assert_eq!(migrated.state().peers, old_peer);
    assert_eq!(migrated.state().ledger, old_ledger);
    assert!(migrated
        .state()
        .astra
        .astra_policy_fingerprint
        .fingerprint()
        .matches(expected_policy.fingerprint()));
    assert_eq!(migrated.state().astra.credential_registry_epoch, 1);
    assert!(migrated.state().astra.credential_bindings.is_empty());

    // The migration is durable; a second load takes the normal path.
    let persisted: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("persisted JSON");
    let persisted_astra = persisted
        .get("astra")
        .and_then(Value::as_object)
        .expect("persisted Astra object");
    assert!(persisted_astra.contains_key("astra_policy_fingerprint"));
    assert!(persisted_astra.contains_key("credential_registry_epoch"));
    assert!(persisted_astra.contains_key("credential_bindings"));
    let reloaded = CertificateRegistry::load(&path)
        .expect("reload")
        .expect("registry");
    assert_eq!(reloaded.state(), migrated.state());
}
