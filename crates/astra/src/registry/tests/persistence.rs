use super::*;

/// A backup that ends on another head is a fork, not a resume.
#[test]
fn loading_a_forked_chain_is_refused() {
    let (registry, directory) = registry();
    let head = registry.audit_head();
    let path = directory.path().join("astra.json");

    AstraRegistry::load(&path, Some(&head)).expect("same head");
    assert!(matches!(
        AstraRegistry::load(&path, Some(&Fingerprint::of(b"another history"))),
        Err(RegistryError::Audit(AuditError::Forked))
    ));
}

/// A registry written before the policy pin and the credential epoch
/// existed still loads, and comes back describing the same domain.
///
/// Refusing it is what actually happened on a live gateway: `astra status`
/// failed, the deployment read that failure as "not bootstrapped", and the
/// bootstrap then refused to start a second history over the first. The
/// operator was left with an authority holding a service key, an audit
/// chain and a domain, and no command that could read any of them.
#[test]
fn a_registry_written_before_the_policy_pin_is_migrated_rather_than_refused() {
    let (registry, directory) = registry();
    registry.save().expect("save");
    let path = directory.path().join("astra.json");

    // Exactly the older shape: the two fields simply are not there.
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = document.as_object_mut().unwrap();
    object.remove("astra_policy_fingerprint");
    object.remove("credential_registry_epoch");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

    let loaded = AstraRegistry::load(&path, None).expect("the older registry loads");
    let state = loaded.state();
    assert_eq!(state.trust_domain_id, TrustDomainId::new([1; 16]).unwrap());
    assert_eq!(state.peers.len(), 1, "the peers survived the migration");
    // The lowest possible epoch: every consumer keeps the highest it has
    // seen, so starting higher would refuse the first genuine document.
    assert_eq!(state.credential_registry_epoch, 0);
    // Recomputed, never read: exactly what bootstrap would have written
    // for this identity.
    let expected = AstraIssuancePolicy::standard(
        state.trust_domain_id,
        state.gateway_wg_public_key,
        state.server_name.clone(),
    )
    .pin()
    .expect("pin");
    assert_eq!(&state.astra_policy_fingerprint, &expected);

    // Written back, so the migration happens once and the audit head is
    // the one the operator already holds.
    let reloaded = AstraRegistry::load(&path, Some(&registry.audit_head()))
        .expect("and the chain did not fork");
    assert_eq!(
        reloaded.state().astra_policy_fingerprint,
        state.astra_policy_fingerprint
    );
}

/// A registry that carries neither the pin nor the identity to recompute
/// it from is refused by name. It is not a registry.
#[test]
fn a_registry_with_nothing_to_recompute_the_pin_from_is_refused() {
    let (registry, directory) = registry();
    registry.save().expect("save");
    let path = directory.path().join("astra.json");

    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = document.as_object_mut().unwrap();
    object.remove("astra_policy_fingerprint");
    object.remove("server_name");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

    assert!(matches!(
        AstraRegistry::load(&path, None),
        Err(RegistryError::Corrupt(_))
    ));
}

/// A reader sees the migrated state and leaves the file exactly as it was.
///
/// The console's readers run while the service may hold the registry; one
/// that wrote back a migration would be a second writer behind it (spec §5.9).
/// Both reading paths keep the head check of the load they mirror.
#[test]
fn a_read_migrates_in_memory_and_leaves_the_file_untouched() {
    let (registry, directory) = registry();
    registry.save().expect("save");
    let path = directory.path().join("astra.json");
    let head = registry.audit_head();

    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = document.as_object_mut().unwrap();
    object.remove("astra_policy_fingerprint");
    object.remove("credential_registry_epoch");
    let aged = serde_json::to_vec(&document).unwrap();
    std::fs::write(&path, &aged).unwrap();

    let expected_pin = AstraIssuancePolicy::standard(
        registry.state().trust_domain_id,
        registry.state().gateway_wg_public_key,
        registry.state().server_name.clone(),
    )
    .pin()
    .expect("pin");
    for state in [
        AstraRegistry::read_state(&path, Some(&head)).expect("read"),
        AstraRegistry::read_state_allowing_unattended_tail(&path, Some(&head)).expect("read"),
    ] {
        assert_eq!(state.credential_registry_epoch, 0);
        assert_eq!(state.astra_policy_fingerprint, expected_pin);
        assert_eq!(state.audit.head(), head);
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        aged,
        "a read wrote the registry"
    );

    let forked = Fingerprint::of(b"another history");
    assert!(matches!(
        AstraRegistry::read_state(&path, Some(&forked)),
        Err(RegistryError::Audit(AuditError::Forked))
    ));
    assert!(matches!(
        AstraRegistry::read_state_allowing_unattended_tail(&path, Some(&forked)),
        Err(RegistryError::Audit(_))
    ));
}
/// A persisted per-peer lifecycle suffix is accepted on daemon restart, but
/// remains a fork for the strict restore path. Display reads never rewrite it.
#[test]
fn a_persisted_peer_lifecycle_suffix_is_accepted_only_by_the_restart_path() {
    let (mut registry, directory) = registry();
    let path = directory.path().join("astra.json");
    let witness = registry.audit_head();

    assert!(registry
        .reconcile_peer(served(5), 2_000)
        .expect("adopt generation"));
    let persisted = std::fs::read(&path).expect("read persisted suffix");

    assert!(matches!(
        AstraRegistry::load(&path, Some(&witness)),
        Err(RegistryError::Audit(AuditError::Forked))
    ));

    let restarted = AstraRegistry::load_allowing_unattended_tail(&path, Some(&witness))
        .expect("restart accepts per-peer lifecycle tail");
    assert_eq!(
        restarted
            .peer(&WireGuardKey::from_bytes([2; 32]))
            .expect("peer survived restart")
            .active
            .generation,
        5
    );

    let read = AstraRegistry::read_state_allowing_unattended_tail(&path, Some(&witness))
        .expect("display read accepts per-peer lifecycle tail");
    assert_eq!(read.peers, restarted.state().peers);
    assert_eq!(
        std::fs::read(&path).expect("read after display"),
        persisted,
        "display read must not rewrite the registry"
    );
}

/// A witnessed chain that grows through an authority decision is never
/// accepted by the restart or display path, even if it is otherwise valid.
#[test]
fn an_authority_decision_after_the_witness_blocks_restart_and_read() {
    let (mut registry, directory) = registry();
    let path = directory.path().join("astra.json");
    let witness = registry.audit_head();

    registry
        .record(AuditEvent::IssuerInstalled { issuer_epoch: 2 }, 2_000)
        .expect("persist authority decision");
    let persisted = std::fs::read(&path).expect("read persisted decision");

    assert!(matches!(
        AstraRegistry::load_allowing_unattended_tail(&path, Some(&witness)),
        Err(RegistryError::Audit(AuditError::WitnessOutdated { .. }))
    ));
    assert!(matches!(
        AstraRegistry::read_state_allowing_unattended_tail(&path, Some(&witness)),
        Err(RegistryError::Audit(AuditError::WitnessOutdated { .. }))
    ));
    assert_eq!(
        std::fs::read(&path).expect("read after rejected display"),
        persisted,
        "a rejected display read must not rewrite the registry"
    );
}
