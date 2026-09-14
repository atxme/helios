use super::*;

/// The fingerprint mTLS proved resolves to the peer that owns it.
///
/// This is the lookup that replaces the pins of `network.toml`, which
/// describe only the generation a peer was admitted with and are never
/// updated afterwards.
#[test]
fn the_proved_tls_half_resolves_to_its_peer_and_its_own_pq_half() {
    let fixture = fixture();
    let expected = fixture
        .registry
        .peer(&client_key(2))
        .expect("admitted")
        .state
        .active
        .clone();

    let resolved = fixture
        .registry
        .state()
        .resolve_negotiation_identity(&expected.tls_certificate_fingerprint, 0)
        .expect("resolved");
    assert_eq!(resolved.wg_public_key, client_key(2).to_base64());
    assert_eq!(resolved.name, "workstation");
    assert_eq!(
        resolved.pq_certificate_fingerprint,
        expected.pq_certificate_fingerprint
    );

    // A fingerprint the domain never issued resolves to nobody — an
    // unknown caller must not become an anonymous one.
    assert!(fixture
        .registry
        .state()
        .resolve_negotiation_identity(&Fingerprint::of(b"never issued"), 0)
        .is_none());
}

/// An ordinary renewal is issued by the delegated issuer, not by the
/// anchor the first generation chained to.
///
/// A gateway offering only the anchor would refuse every leaf it has
/// itself just renewed, which is the whole reason this returns a set.
#[test]
fn the_issuer_set_carries_the_delegation_an_ordinary_renewal_uses() {
    let fixture = fixture();
    let anchor = fixture
        .registry
        .state()
        .gateway
        .current_ca_public_key
        .clone();
    assert_eq!(
        fixture.registry.state().client_leaf_issuers(0),
        vec![&anchor],
        "with no delegation installed there is exactly the anchor"
    );

    let issuer = keys();
    let mut state = fixture.registry.state().clone();
    state.issuer = Some(AstraIssuerState {
        issuer_epoch: 1,
        authorization: aether::certificates::authority::AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer.public.clone(),
            tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
            allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 1_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        },
        state: aether::certificates::state::IssuerLifecycle::Active,
    });
    let registry =
        CertificateRegistry::new(fixture._directory.path().join("with-issuer.json"), state);

    assert_eq!(
        registry.state().client_leaf_issuers(0),
        vec![&anchor, &issuer.public]
    );
    // Past its own expiry the delegation signs nothing, whatever its
    // lifecycle field says.
    assert_eq!(registry.state().client_leaf_issuers(1_000), vec![&anchor]);
}

pub(super) fn client_tls_ca_transition(
    fixture: &Fixture,
    current_epoch: u64,
    active: Fingerprint,
    window: TransitionWindow,
) -> aether::certificates::authority::ClientTlsCaTransition {
    use aether::certificates::authority::ClientTlsCaTransition;

    ClientTlsCaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        current_ca_tls_epoch: current_epoch,
        next_ca_tls_epoch: current_epoch + 1,
        active_client_tls_ca_fingerprint: active,
        next_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
            "successor",
        )
        .authority,
        window,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca.private)
    .expect("sign the rotation")
}

pub(super) fn gateway_delegation_naming(
    ca: &Keys,
    policy_fingerprint: Fingerprint,
) -> aether::certificates::authority::AstraIssuerAuthorization {
    let (_, issuer_public) =
        aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
    aether::certificates::authority::AstraIssuerAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: aether::certificates::test_x509::certificate_authority(
            "astra-issuer",
        ),
        allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 200_000,
        policy_fingerprint,
        not_before: 0,
        not_after: 1_000_000,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("sign delegation")
}

/// Pins this fixture's registry to the superseded policy, as a gateway
/// bootstrapped before the amendment of 6 September 2026 holds it.
fn pin_to_superseded(fixture: &mut Fixture) -> Fingerprint {
    let superseded = aether::certificates::approval::superseded_per_request_policy_fingerprint(
        domain(),
        gateway_key(),
        SERVER_NAME,
    )
    .expect("superseded");
    let mut candidate = fixture.registry.state().clone();
    candidate.astra.astra_policy_fingerprint =
        aether::certificates::approval::AstraPolicyPin::new(superseded).expect("pin");
    fixture.registry.persist(candidate).expect("pinned");
    superseded
}

/// The gateway pins the policy for itself, so it has to be carried across
/// by the same `CA-PQ`-signed evidence — and carrying it must move nothing
/// else, least of all the peers whose renewals depend on their generation.
#[test]
fn a_superseded_gateway_pin_adopts_the_current_policy_and_keeps_every_peer() {
    use aether::certificates::approval::PolicyMigration;

    let mut fixture = fixture();
    pin_to_superseded(&mut fixture);
    let peers_before = fixture.registry.state().peers.clone();
    let ledger_before = fixture.registry.state().ledger.clone();
    let current = aether::certificates::approval::AstraIssuancePolicy::standard(
        domain(),
        gateway_key(),
        SERVER_NAME.into(),
    )
    .fingerprint()
    .expect("current");

    let migration = fixture
        .registry
        .install_astra_issuer(&gateway_delegation_naming(&fixture.ca, current), 1_000)
        .expect("migration");

    assert!(matches!(migration, PolicyMigration::Adopted(_)));
    assert!(fixture
        .registry
        .state()
        .astra
        .astra_policy_fingerprint
        .fingerprint()
        .matches(&current));
    // Without this the negotiation port cannot authenticate a renewed
    // leaf, and the staging check would refuse every candidate Astra
    // issues under the delegation it just accepted.
    let issuer = fixture
        .registry
        .state()
        .issuer
        .as_ref()
        .expect("the delegation is recorded");
    assert_eq!(issuer.issuer_epoch, 1);
    assert!(fixture
        .registry
        .state()
        .client_leaf_issuers(1_000)
        .contains(&&issuer.authorization.pq_issuer_public_key));
    assert_eq!(fixture.registry.state().peers, peers_before);
    assert_eq!(fixture.registry.state().ledger, ledger_before);
}

/// A spent epoch carrying different bytes is a substitution, not the
/// replay of a delegation whose delivery was lost.
#[test]
fn a_delegation_that_does_not_advance_its_epoch_is_refused() {
    let mut fixture = fixture();
    pin_to_superseded(&mut fixture);
    let current = aether::certificates::approval::AstraIssuancePolicy::standard(
        domain(),
        gateway_key(),
        SERVER_NAME.into(),
    )
    .fingerprint()
    .expect("current");
    let installed = gateway_delegation_naming(&fixture.ca, current);
    fixture
        .registry
        .install_astra_issuer(&installed, 1_000)
        .expect("first install");

    // The same bytes again are a replay, and stay accepted.
    fixture
        .registry
        .install_astra_issuer(&installed, 1_000)
        .expect("replaying the same delegation is idempotent");

    // Different bytes at the same epoch are not.
    assert!(matches!(
        fixture
            .registry
            .install_astra_issuer(&gateway_delegation_naming(&fixture.ca, current), 1_000),
        Err(RegistryError::IssuerEpochNotAdvancing {
            installed: 1,
            offered: 1
        })
    ));
}

/// The evidence has to be this domain's. A delegation signed by another
/// anchor names the right policy and still moves nothing.
#[test]
fn a_delegation_from_another_anchor_never_moves_the_gateway_pin() {
    let mut fixture = fixture();
    let superseded = pin_to_superseded(&mut fixture);
    let current = aether::certificates::approval::AstraIssuancePolicy::standard(
        domain(),
        gateway_key(),
        SERVER_NAME.into(),
    )
    .fingerprint()
    .expect("current");
    let stranger = keys();

    assert!(fixture
        .registry
        .install_astra_issuer(&gateway_delegation_naming(&stranger, current), 1_000)
        .is_err());
    assert!(fixture
        .registry
        .state()
        .astra
        .astra_policy_fingerprint
        .fingerprint()
        .matches(&superseded));
}

/// The migration fixes the bootstrap metadata and nothing else: peer
/// identities, revocations and queued signed distributions survive the
/// same atomic write.
#[test]
fn the_legacy_admission_ca_bootstrap_is_repaired_without_reenrolling_peers() {
    let mut fixture = fixture();
    let admission_ca = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .clone();
    let admission_fingerprint = admission_ca.fingerprint();
    let peer_key = client_key(2).to_base64();
    let peer = fixture
        .registry
        .state
        .peers
        .get_mut(&peer_key)
        .expect("peer");
    peer.state.active.generation = 1;
    peer.state.active.ca_tls_epoch = 1;
    peer.state.active.tls_ca_certificate_fingerprint = admission_fingerprint;
    let (manifest, chunks) = distribution(&client_key(2), 2, 10_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), manifest, chunks, 0)
        .expect("queue a signed distribution");
    let peer = fixture.registry.state().peers.get(&peer_key).expect("peer");
    let peer_before = peer.clone();
    let ledger_before = fixture.registry.state().ledger.clone();
    let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
    let domain_fingerprint = domain_ca.fingerprint();

    assert_eq!(
        fixture
            .registry
            .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
            .expect("repair"),
        BootstrapRepairOutcome::Repaired
    );

    let state = fixture.registry.state();
    assert!(state
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint()
        .matches(&domain_fingerprint));
    let peer_after = state.peers.get(&peer_key).expect("peer preserved");
    assert_eq!(peer_after.name, peer_before.name);
    assert_eq!(
        peer_after.active_pq_certificate,
        peer_before.active_pq_certificate
    );
    assert_eq!(peer_after.distribution, peer_before.distribution);
    assert_eq!(state.ledger, ledger_before);
    assert!(peer_after
        .state
        .active
        .tls_ca_certificate_fingerprint
        .matches(&domain_fingerprint));

    let reloaded = CertificateRegistry::load(&fixture.registry.path)
        .expect("read repaired registry")
        .expect("registry present");
    assert_eq!(reloaded.state(), fixture.registry.state());
    assert_eq!(
        fixture
            .registry
            .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
            .expect("idempotent repair"),
        BootstrapRepairOutcome::AlreadyCorrect
    );
}

/// Once any peer has moved, rewriting its generation-one anchor would be
/// an unsigned rotation rather than a bootstrap correction.
#[test]
fn the_legacy_bootstrap_repair_refuses_a_peer_that_already_moved() {
    let mut fixture = fixture();
    let admission_ca = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .clone();
    fixture.registry.state.peers.values_mut().for_each(|peer| {
        peer.state.active.tls_ca_certificate_fingerprint = admission_ca.fingerprint();
    });
    let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
    let before = fixture.registry.state().clone();

    let error = fixture
        .registry
        .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
        .expect_err("generation four is not a bootstrap state");

    assert!(matches!(
        error,
        RegistryError::LegacyClientTlsCaRepair(
            "at least one peer has left its untouched first generation"
        )
    ));
    assert_eq!(fixture.registry.state(), &before);
}

#[test]
fn the_legacy_bootstrap_repair_refuses_a_foreign_active_anchor() {
    let mut fixture = fixture();
    let admission_ca = aether::certificates::test_x509::client_material("operator").authority;
    let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
    let before = fixture.registry.state().clone();

    let error = fixture
        .registry
        .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
        .expect_err("only the exact operator admission CA can be replaced");

    assert!(matches!(
        error,
        RegistryError::LegacyClientTlsCaRepair(
            "the active anchor is not the operator admission CA"
        )
    ));
    assert_eq!(fixture.registry.state(), &before);
}

#[test]
fn the_bootstrap_repair_is_a_no_op_after_a_signed_rotation_epoch() {
    let mut fixture = fixture();
    let admission_ca = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .clone();
    fixture.registry.state.client_tls_ca.ca_tls_epoch = 2;
    let domain_ca = aether::certificates::test_x509::client_material("domain").authority;
    let before = fixture.registry.state().clone();

    assert_eq!(
        fixture
            .registry
            .repair_legacy_client_tls_ca_bootstrap(&admission_ca, &domain_ca)
            .expect("a later signed epoch needs no bootstrap repair"),
        BootstrapRepairOutcome::LaterEpoch
    );
    assert_eq!(fixture.registry.state(), &before);
}

/// §9.4: both chains are acceptable during the overlap, and only then.
#[test]
fn a_client_tls_ca_rotation_is_accepted_from_its_activation() {
    let mut fixture = fixture();
    let active = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    let transition = client_tls_ca_transition(&fixture, 1, active, window());

    fixture
        .registry
        .install_client_tls_ca_transition(&transition, 1_500)
        .expect("install");

    let anchors = fixture.registry.state().client_tls_anchors(1_999);
    assert_eq!(
        anchors.len(),
        1,
        "before activation only the anchor in service"
    );
    assert_eq!(fixture.registry.state().client_tls_anchors(2_000).len(), 2);
}

/// At `not_after` the outgoing anchor is gone, on the same write that
/// promotes the peers: a sweep that moved one without the other would keep
/// accepting a chain the domain retired.
#[test]
fn the_outgoing_client_tls_anchor_retires_with_the_generations() {
    let mut fixture = fixture();
    let active = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    let transition = client_tls_ca_transition(&fixture, 1, active, window());
    fixture
        .registry
        .install_client_tls_ca_transition(&transition, 1_500)
        .expect("install");

    fixture.registry.promote_due(3_000).expect("promote");

    let state = fixture.registry.state();
    assert_eq!(state.client_tls_ca.ca_tls_epoch, 2);
    assert!(state.client_tls_ca.next_client_tls_ca_certificate.is_none());
    assert_eq!(fixture.registry.state().client_tls_anchors(3_000).len(), 1);
    assert!(
        !fixture
            .registry
            .state()
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint()
            .matches(&active),
        "the successor is the one in service"
    );
}

/// One rotation in flight at a time: a second would leave two successors
/// and no rule saying which the next handshake is verified under.
#[test]
fn a_second_client_tls_ca_rotation_is_refused_while_one_is_in_flight() {
    let mut fixture = fixture();
    let active = fixture
        .registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    fixture
        .registry
        .install_client_tls_ca_transition(
            &client_tls_ca_transition(&fixture, 1, active, window()),
            1_500,
        )
        .expect("install");

    assert!(fixture
        .registry
        .install_client_tls_ca_transition(
            &client_tls_ca_transition(&fixture, 1, active, window()),
            1_500,
        )
        .is_err());
}

#[test]
fn a_publication_names_the_document_it_lets_go() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    let fingerprint = transition.fingerprint().expect("fingerprint");

    // Another document at the same epoch: an operator may have installed
    // one transition by hand while the authority published another.
    let other = gateway_transition(&fixture, &keys(), 2, window());
    assert!(fixture
        .registry
        .publish_gateway_transition(2, &other.fingerprint().expect("fingerprint"))
        .is_err());
    // The right document at the wrong epoch is no better.
    assert!(fixture
        .registry
        .publish_gateway_transition(3, &fingerprint)
        .is_err());
    assert!(!fixture.registry.state().gateway.published);

    fixture
        .registry
        .publish_gateway_transition(2, &fingerprint)
        .expect("published");
    assert!(fixture.registry.state().gateway.published);
    // A retry of a relay the authority could not confirm is not a second
    // decision.
    fixture
        .registry
        .publish_gateway_transition(2, &fingerprint)
        .expect("idempotent");
}

#[test]
fn an_abort_is_refused_once_the_transition_has_been_published() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    // What §6.3 makes irreversible: past this marker a client may already
    // hold the decision, go offline and promote on its own at `not_after`.
    let mut published = fixture.registry.state().clone();
    published.gateway.published = true;
    let mut registry =
        CertificateRegistry::new(fixture._directory.path().join("published.json"), published);
    let abort = gateway_abort(&fixture, &transition, 1_600);

    let refusal = registry
        .abort_gateway_transition(&abort, &transition, 1_700)
        .expect_err("an abort after publication");

    assert!(matches!(refusal, RegistryError::Certificate(_)));
    assert_eq!(
        registry.state().gateway.next_gateway_identity_epoch,
        Some(2)
    );
}

#[test]
fn an_abort_is_refused_once_the_local_clock_reaches_activation() {
    let mut fixture = fixture();
    let next = keys();
    let transition = gateway_transition(&fixture, &next, 2, window());
    fixture
        .registry
        .install_gateway_transition(&transition, 1_500)
        .expect("install");
    // Backdated inside the document, read against a clock that has moved
    // past `activation_at`: the overlap has begun and cancelling it here
    // would leave two truths in the fleet.
    let abort = gateway_abort(&fixture, &transition, 1_600);

    let refusal = fixture
        .registry
        .abort_gateway_transition(&abort, &transition, 2_400)
        .expect_err("an abort during the overlap");

    assert!(matches!(refusal, RegistryError::Certificate(_)));
    assert_eq!(
        fixture.registry.state().gateway.next_gateway_identity_epoch,
        Some(2)
    );
}
