use super::*;

/// The whole point of the method: the gateway promotes, this adopts, and
/// the chain says so with an event of its own.
#[test]
fn a_promoted_generation_is_adopted_and_recorded() {
    let (mut registry, _dir) = registry();
    assert!(registry.reconcile_peer(served(5), 2_000).expect("adopted"));
    let key = WireGuardKey::from_bytes([2; 32]);
    assert_eq!(registry.peer(&key).expect("peer").active.generation, 5);
    assert!(matches!(
        registry.state().audit.records.last().map(|r| &r.event),
        Some(AuditEvent::PeerGenerationAdopted { generation: 5, .. })
    ));
}

/// Idempotence is what makes the repair safe to replay after a crash.
#[test]
fn adopting_what_is_already_recorded_writes_nothing() {
    let (mut registry, _dir) = registry();
    let before = registry.state().audit.records.len();
    assert!(!registry.reconcile_peer(served(4), 2_000).expect("no-op"));
    assert_eq!(registry.state().audit.records.len(), before);
}

/// A stale or rolled-back gateway view must not rewrite this authority's
/// idea of who is current.
#[test]
fn a_generation_below_the_recorded_one_is_refused() {
    let (mut registry, _dir) = registry();
    assert!(matches!(
        registry.reconcile_peer(served(3), 2_000),
        Err(RegistryError::GenerationRegression {
            held: 4,
            offered: 3
        })
    ));
}

/// One number, two leaves, is two histories — and the fingerprint is what
/// tells them apart before either is believed.
#[test]
fn the_same_generation_under_another_leaf_is_refused() {
    let (mut registry, _dir) = registry();
    let mut divergent = served(4);
    divergent.active.pq_certificate_fingerprint = Fingerprint::of(b"another leaf");
    assert!(matches!(
        registry.reconcile_peer(divergent, 2_000),
        Err(RegistryError::GenerationDisagrees { generation: 4 })
    ));
}

/// A generation is the TLS/PQ pair and its validity metadata, not only the
/// PQ fingerprint. Accepting another TLS leaf under the same number would
/// reintroduce the mixed-generation pair the lifecycle is built to reject.
#[test]
fn the_same_generation_with_other_tls_state_is_refused() {
    let (mut registry, _dir) = registry();
    let mut divergent = served(4);
    divergent.active.tls_certificate_fingerprint = Fingerprint::of(b"another TLS leaf");
    assert!(matches!(
        registry.reconcile_peer(divergent, 2_000),
        Err(RegistryError::GenerationDisagrees { generation: 4 })
    ));
}

/// Revocation is owned by the signed authority decision and is terminal.
/// A stale gateway view must not lift it before the caller checks it.
#[test]
fn reconciliation_never_lifts_a_revocation() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry.revoke(&key, 1, 1_200).expect("revoked");

    assert!(matches!(
        registry.reconcile_peer(served(4), 2_000),
        Err(RegistryError::RevocationDisagrees)
    ));
    assert!(registry.peer(&key).expect("peer").revoked);
}

/// The gateway supplies the admission anchor at first sight, but it does
/// not get to replace that recovery root on a later lifecycle contact.
#[test]
fn reconciliation_never_replaces_a_pinned_admission_anchor() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    let (_, first) = generate_ml_dsa_87_keypair().expect("first anchor");
    let (_, second) = generate_ml_dsa_87_keypair().expect("second anchor");
    registry
        .state
        .peers
        .get_mut(&key.to_base64())
        .expect("peer")
        .admission_pq_ca = Some(first);
    let mut divergent = served(4);
    divergent.admission_pq_ca = Some(second);

    assert!(matches!(
        registry.reconcile_peer(divergent, 2_000),
        Err(RegistryError::AdmissionAnchorDisagrees)
    ));
}

/// The reason `admit` could not be reused: a grant may already be in a
/// client's hands, and a refresh that dropped it would withhold something
/// this authority has no right to withhold.
#[test]
fn a_rotation_still_ahead_of_the_served_generation_survives() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry
        .state
        .peers
        .get_mut(&key.to_base64())
        .expect("peer")
        .pending = Some(rotation(9, 50_000));

    registry.reconcile_peer(served(4), 2_000).ok();
    assert!(
        registry.peer(&key).expect("peer").pending.is_some(),
        "the candidate is generation 5 and the gateway still serves 4"
    );
}

/// And its other half: once the served generation has caught up with the
/// candidate, the stage has either landed or been overtaken, and there is
/// nothing left to grant.
#[test]
fn a_rotation_the_served_generation_reached_is_purged() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry
        .state
        .peers
        .get_mut(&key.to_base64())
        .expect("peer")
        .pending = Some(rotation(9, 50_000));

    assert!(registry.reconcile_peer(served(5), 2_000).expect("adopted"));
    assert!(registry.peer(&key).expect("peer").pending.is_none());
    assert!(registry
        .state()
        .audit
        .records
        .iter()
        .any(|record| matches!(record.event, AuditEvent::ClientStagePurged { .. })));
}

/// A peer nobody transcribed yet is the first-sight case, and it is still
/// an admission.
#[test]
fn an_unknown_peer_is_admitted_rather_than_refused() {
    let (mut registry, _dir) = registry();
    let mut fresh = served(1);
    fresh.client_wg_public_key = WireGuardKey::from_bytes([9; 32]);
    fresh.name = "laptop".into();
    assert!(registry.reconcile_peer(fresh, 2_000).expect("admitted"));
    assert!(registry.peer(&WireGuardKey::from_bytes([9; 32])).is_some());
}

/// A delegation is installed by epoch, and the epoch only ever rises.
/// Reinstalling one already used would let a withdrawn intermediate come
/// back under a signature that is still perfectly valid.
#[test]
fn a_delegation_may_not_walk_its_epoch_backwards() {
    use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
    use aether::certificates::encoding::{DerCertificate, MlDsa87Signature};
    use aether::certificates::state::{AstraIssuerState, IssuerLifecycle};

    let (mut registry, _dir) = registry();
    let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
    let delegation = |epoch: u64| AstraIssuerState {
        issuer_epoch: epoch,
        authorization: AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            server_name: "gateway.example".into(),
            issuer_epoch: epoch,
            pq_issuer_public_key: issuer_key.clone(),
            tls_intermediate_certificate: DerCertificate::new(vec![9; 64]).expect("der"),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 100_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        },
        state: IssuerLifecycle::Active,
    };

    registry
        .install_issuer(delegation(1), 1_000)
        .expect("first");
    // The same delegation again is a replay of §8.2, not a walk-back: a
    // companion whose response was lost redeposits the same bytes.
    registry
        .install_issuer(delegation(1), 1_100)
        .expect("an identical delegation is a no-op");
    // A *different* delegation at a spent epoch is the substitution this
    // refuses — it would bring back an intermediate that was withdrawn,
    // under a signature that still verifies.
    let mut substituted = delegation(1);
    substituted.authorization.tls_intermediate_certificate =
        DerCertificate::new(vec![7; 64]).expect("der");
    assert!(matches!(
        registry.install_issuer(substituted, 1_150),
        Err(RegistryError::IssuerEpochNotAdvancing {
            installed: 1,
            offered: 1
        })
    ));
    registry
        .install_issuer(delegation(2), 1_200)
        .expect("second");
    assert_eq!(
        registry
            .state()
            .issuer
            .as_ref()
            .expect("issuer")
            .issuer_epoch,
        2
    );
}

/// The peer table is a transcription of the gateway's admission, and the
/// lazy path re-runs it on every renewal. Re-transcribing an unchanged
/// peer must not append an audit record — a chain that grew on every
/// renewal would make its head useless as a restore witness.
#[test]
fn re_transcribing_an_unchanged_peer_appends_nothing() {
    let (mut registry, _dir) = registry();
    let head = registry.audit_head();
    let record = registry
        .peer(&WireGuardKey::from_bytes([2; 32]))
        .expect("peer")
        .clone();

    registry.admit(record, 2_000).expect("re-transcription");

    assert_eq!(registry.audit_head(), head);
}

#[test]
fn only_one_rotation_may_be_in_flight_per_peer() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry
        .open_rotation(&key, rotation(5, 5_000), 1_100)
        .expect("first rotation");
    assert!(matches!(
        registry.open_rotation(&key, rotation(6, 5_000), 1_200),
        Err(RegistryError::RotationInFlight)
    ));
}

/// Debris must not block the renewal it was supposed to perform.
#[test]
fn an_expired_rotation_does_not_block_the_next_one() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry
        .open_rotation(&key, rotation(5, 5_000), 1_100)
        .expect("first rotation");
    registry
        .open_rotation(&key, rotation(6, 12_000), 5_000)
        .expect("second rotation after the lease");
}

#[test]
fn revocation_dominates_a_rotation_in_flight() {
    let (mut registry, _dir) = registry();
    let key = WireGuardKey::from_bytes([2; 32]);
    registry
        .open_rotation(&key, rotation(5, 5_000), 1_100)
        .expect("rotation");
    registry.revoke(&key, 1, 1_200).expect("revocation");

    let peer = registry.peer(&key).expect("peer");
    assert!(peer.revoked);
    assert!(peer.pending.is_none());
    assert!(matches!(
        registry.open_rotation(&key, rotation(6, 9_000), 1_300),
        Err(RegistryError::Revoked)
    ));
}

#[test]
fn a_status_epoch_only_ever_increases() {
    let (mut registry, _dir) = registry();
    let target = Fingerprint::of(b"leaf");
    assert_eq!(registry.next_status_epoch(&target), 1);
    assert_eq!(registry.next_status_epoch(&target), 2);
    assert_eq!(registry.next_status_epoch(&Fingerprint::of(b"other")), 1);
}
