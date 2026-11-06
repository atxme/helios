use super::*;
use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, TrustDomainId,
};
use aether::certificates::state::{
    AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState,
};
use aether::certificates::transport::TrustUpdateRequest;
use aether::certificates::CERTIFICATE_PROTOCOL_VERSION;
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use helios_provisioning::certificates::{PeerCertificates, RegistryState};

fn key(seed: u8) -> WireGuardKey {
    WireGuardKey::from_bytes([seed; 32])
}

fn generation() -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
        not_before: 0,
        not_after: 1_000_000,
    }
}

/// A signed leaf: the fingerprint of a PQ certificate covers its
/// signature, so an unsigned placeholder has no fingerprint at all.
fn signed_leaf(role: PqCertificateRole, subject: &str, serial: u8) -> PqCertificate {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: subject.into(),
            issuer: "CA-PQ".into(),
            role,
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

fn gateway_leaf() -> PqCertificate {
    signed_leaf(PqCertificateRole::Gateway, "gateway.example", 1)
}

fn state() -> RegistryState {
    let (_, anchor) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
    RegistryState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
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
            active_gateway_identity_epoch: 3,
            gateway_decision_epoch: 3,
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
            ca_tls_epoch: 2,
            // A genuine anchor, not a stub: the enrolment block ships this
            // certificate to every client, and Orion parses it at import.
            // A placeholder here would let the block pass these tests and
            // be refused on the machine it was emitted for.
            active_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
                "workstation",
            )
            .authority,
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
            astra_service_key_epoch: 5,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer: None,
        peers: Default::default(),
        ledger: Default::default(),
    }
}

fn peer() -> PeerCertificates {
    PeerCertificates {
        name: "workstation".into(),
        state: ClientCertificateState::new(generation()),
        active_pq_certificate: signed_leaf(PqCertificateRole::Client, "workstation", 2),
        staged_pq_certificate: None,
        distribution: None,
    }
}

/// A relayed recovery commit whose shape is right and whose stage is not.
///
/// The signatures are placeholders on purpose: every assertion that uses
/// this refuses **before** any signature is read, and building real ones
/// would hide which check actually fired.
fn relayed_commit() -> ::astra_channel::RelayedStageCommit {
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::{
        ClientCertificateStageAuthorization, ClientCertificateStageCommit,
    };
    use aether::certificates::encoding::MlDsa87Signature;
    use aether::certificates::window::TransitionWindow;

    let stage_id = Id16::new([4; 16]).expect("id");
    let authorization = ClientCertificateStageAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        ca_tls_epoch: 2,
        issuer_kind: aether::certificates::client::IssuerKind::Master,
        issuer_epoch: 1,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        stage_id,
        request_fingerprint: Fingerprint::of(b"recovery request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: key(9),
        server_name: "gateway.example".into(),
        client_wg_public_key: key(2),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
        next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        next_tls_certificate: DerCertificate::new(vec![2; 64]).expect("der"),
        next_pq_certificate: signed_leaf(PqCertificateRole::Client, "workstation", 5),
        issued_at: 1_000,
        stage_expires_at: 4_000,
        window: TransitionWindow::new(1_000, 2_000, 9_000).expect("window"),
        reason: RotationReason::ExpiredRecovery,
        signature: MlDsa87Signature::placeholder(),
    };
    let commit = ClientCertificateStageCommit {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: authorization.trust_domain_id,
        stage_id,
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        client_wg_public_key: authorization.client_wg_public_key,
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
        stage_expires_at: 4_000,
        committed_at: 1_100,
        active_pq_signature: MlDsa87Signature::placeholder(),
        staged_pq_signature: MlDsa87Signature::placeholder(),
    };
    let grant = aether::certificates::client::ClientCertificateRotationGrant {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: authorization.trust_domain_id,
        ca_epoch: 1,
        ca_tls_epoch: 2,
        issuer_kind: authorization.issuer_kind,
        issuer_epoch: 1,
        issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
        issuer_authorization: None,
        request_fingerprint: authorization.request_fingerprint,
        renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        stage_receipt: aether::certificates::client::GatewayCertificateStageReceipt {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            stage_id,
            stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
            staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
            persisted_at: 1_050,
            stage_expires_at: 4_000,
            active_gateway_identity_epoch: 3,
            gateway_decision_epoch: 3,
            gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
            gateway_signature: MlDsa87Signature::placeholder(),
        },
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        server_name: authorization.server_name.clone(),
        client_wg_public_key: authorization.client_wg_public_key,
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
        next_tls_certificate: authorization.next_tls_certificate.clone(),
        next_pq_certificate: authorization.next_pq_certificate.clone(),
        stage_expires_at: 4_000,
        window: authorization.window,
        reason: authorization.reason,
        signature: MlDsa87Signature::placeholder(),
    };
    ::astra_channel::RelayedStageCommit {
        authorization: Box::new(authorization),
        commit: Box::new(commit),
        grant: Box::new(grant),
    }
}

/// A request that declares exactly what the gateway serves.
fn request(state: &RegistryState, peer: &PeerCertificates) -> TrustUpdateRequest {
    TrustUpdateRequest {
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([7; 16]).expect("id"),
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway.gateway_wg_public_key,
        client_wg_public_key: key(2),
        ca_epoch: state.gateway.ca_epoch,
        ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        issuer_epoch: 0,
        active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
        gateway_decision_epoch: state.gateway.gateway_decision_epoch,
        client_identity_generation: peer.state.active.generation,
        active_gateway_tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
        active_gateway_certificate_fingerprint: state
            .gateway
            .active_pq_fingerprint()
            .expect("fingerprint"),
        active_client_tls_certificate_fingerprint: peer.state.active.tls_certificate_fingerprint,
        active_client_pq_certificate_fingerprint: peer.state.active.pq_certificate_fingerprint,
        client_pq_certificate_fingerprint: Fingerprint::of(b"presented"),
        base_state_fingerprint: Fingerprint::of(b"base state"),
    }
}

/// A relayed request, whose signature this side never checks.
///
/// `prepare_from_authority` relays and does not verify: the gateway
/// already verified the request before deciding the caller was behind, and
/// the authority verifies it again under the peer snapshot it is handed.
/// A fixture that had to produce a real signature would be testing those
/// two, not this one.
fn authenticated_request(
    peer_key: &WireGuardKey,
) -> aether::certificates::transport::AuthenticatedTrustUpdateRequest {
    let mut state = state();
    state.peers.insert(peer_key.to_base64(), peer());
    let peer = state
        .peers
        .get(&peer_key.to_base64())
        .expect("peer")
        .clone();
    aether::certificates::transport::AuthenticatedTrustUpdateRequest {
        request: request(&state, &peer),
        certificate: peer.active_pq_certificate.clone(),
        ml_dsa_87_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
}

/// An authority that hands back exactly what it was built with.
///
/// The gateway is not supposed to inspect a prepared transaction — the
/// registry's own `stage_distribution` is the check — so the stub answers
/// unconditionally and the test asserts on what the queue then holds.
struct StubAuthority {
    prepared: ::astra_channel::PreparedTrustUpdate,
}

#[async_trait::async_trait]
impl ::astra_channel::TrustUpdatePreparer for StubAuthority {
    async fn prepare(
        &self,
        _relayed: &::astra_channel::RelayedTrustUpdatePreparation,
    ) -> Result<::astra_channel::PreparedTrustUpdate, TrustUpdateRefusal> {
        Ok(self.prepared.clone())
    }
}

/// A registry on a disposable path, and a signer that signs nothing.
///
/// `admit_peer` never reaches the signer — it records a generation the
/// operator issued — so a stub that refuses is enough, and it makes the
/// test say out loud that admission borrows no gateway key.
struct RefusingSigner;

impl StageReceiptSigner for RefusingSigner {
    fn sign_stage_receipt(
        &self,
        _receipt: GatewayCertificateStageReceipt,
    ) -> Result<GatewayCertificateStageReceipt, CertificateError> {
        Err(CertificateError::Signing)
    }

    fn served_pq_certificate(&self) -> PqCertificate {
        gateway_leaf()
    }
}

fn service(state: RegistryState) -> (CertificateService, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("tempdir");
    let registry =
        CertificateRegistry::bootstrap(directory.path().join("certificates.json"), state)
            .expect("registry");
    (
        CertificateService::new(Arc::new(Mutex::new(registry)), Arc::new(RefusingSigner)),
        directory,
    )
}

/// A client leaf issued to one exact WireGuard key, with a real signature.
fn client_leaf(wg_public_key: &WireGuardKey, not_after: u64) -> PqCertificate {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [3; 16],
            subject: "workstation".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: wg_public_key.to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
            not_before_unix: 100,
            not_after_unix: not_after,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("issue")
}

/// Admission is where a peer enters the registry, and it enters whole:
/// both leaves, the anchor they chain to, and the window in which they may
/// be presented. Without this row there is no trust block, therefore a
/// profile that connects and can never renew — and nothing says so until
/// 80 % of a leaf's life.
#[tokio::test]
async fn admission_records_the_first_generation_from_the_two_leaves() {
    let state = state();
    let anchor = state
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    let (service, _directory) = service(state);
    let peer_key = key(2);
    let material = aether::certificates::test_x509::client_material("workstation");
    let leaf = client_leaf(&peer_key, 500_000);

    service
        .admit_peer(
            "workstation",
            &peer_key.to_base64(),
            material.leaf.clone(),
            Box::new(leaf.clone()),
        )
        .await
        .expect("admission");

    let registry = service.registry.lock().await;
    let recorded = registry.peer(&peer_key).expect("peer recorded");
    assert_eq!(recorded.name, "workstation");
    assert_eq!(recorded.state.active.generation, 1);
    assert_eq!(
        recorded.state.active.tls_certificate_fingerprint,
        material.leaf.fingerprint()
    );
    assert_eq!(
        recorded.state.active.pq_certificate_fingerprint,
        aether::certificates::gateway::pq_certificate_fingerprint(&leaf).expect("fingerprint")
    );
    assert_eq!(
        recorded.state.active.tls_ca_certificate_fingerprint, anchor,
        "the generation names the anchor the registry actually holds"
    );
    // The narrower of the two windows: the PQ leaf expires first here, and
    // a generation is only presentable while both halves are.
    assert_eq!(recorded.state.active.not_after, 500_000);
}

/// An interrupted admission is re-run by the operator. The second attempt
/// has to finish it, not refuse it — otherwise the registry holds a row
/// they cannot get rid of and cannot complete.
#[tokio::test]
async fn re_admitting_an_unchanged_peer_is_a_no_op() {
    let (service, _directory) = service(state());
    let peer_key = key(2);
    let material = aether::certificates::test_x509::client_material("workstation");
    let leaf = client_leaf(&peer_key, 500_000);

    for _ in 0..2 {
        service
            .admit_peer(
                "workstation",
                &peer_key.to_base64(),
                material.leaf.clone(),
                Box::new(leaf.clone()),
            )
            .await
            .expect("admission");
    }

    assert_eq!(service.registry.lock().await.state().peers.len(), 1);
}

/// The PQ leaf names the WireGuard key it belongs to. Recording it against
/// another one assembles an identity the domain never issued — §3.3 refuses
/// exactly that pair at the other end, and it must not be creatable here.
#[tokio::test]
async fn a_leaf_naming_another_peer_is_refused() {
    let (service, _directory) = service(state());
    let material = aether::certificates::test_x509::client_material("workstation");
    let leaf = client_leaf(&key(2), 500_000);

    let refusal = service
        .admit_peer(
            "workstation",
            &key(3).to_base64(),
            material.leaf,
            Box::new(leaf),
        )
        .await
        .expect_err("a leaf naming another peer must be refused");
    assert!(matches!(refusal, TrustUpdateRefusal::Rejected));
}

/// `heliosd peer add` runs in another process and may not write the
/// registry — the daemon holds it in memory, and a second writer would be
/// overwritten at the next persist. So the console queues, and the daemon
/// records: this is that hand-off, end to end.
#[tokio::test]
async fn a_queued_console_admission_becomes_a_generation() {
    use base64::Engine as _;
    let (service, directory) = service(state());
    let registry_path = directory.path().join("certificates.json");
    let peer_key = key(2);
    let material = aether::certificates::test_x509::client_material("workstation");
    let leaf = client_leaf(&peer_key, 500_000);
    let encoder = base64::engine::general_purpose::STANDARD;

    let path = queue_admission(
        &registry_path,
        &QueuedAdmission {
            name: "workstation".into(),
            client_wg_public_key: peer_key.to_base64(),
            tls_certificate: encoder.encode(material.leaf.as_bytes()),
            pq_certificate: encoder.encode(serde_json::to_vec(&leaf).expect("json")),
        },
    )
    .expect("queued");

    let name = service
        .record_queued_admission(&path)
        .await
        .expect("recorded");

    assert_eq!(name, "workstation");
    let registry = service.registry.lock().await;
    assert_eq!(
        registry
            .peer(&peer_key)
            .expect("peer recorded")
            .state
            .active
            .generation,
        1
    );
}

/// The block a profile carries is exactly what the registry holds, and it
/// is readable by the consumer that will use it. Eleven values copied by
/// hand between two shells is eleven places to paste the wrong one, and
/// the failure surfaces months later at 80 % of a leaf's life.
#[test]
fn the_enrolment_block_is_the_registry_and_orion_accepts_it() {
    let state = state();
    let peer = peer();
    let view = enrolment_view(&state, &peer);

    assert_eq!(view.trust_domain_id, state.trust_domain_id.to_hex());
    assert_eq!(view.ca_epoch, state.gateway.ca_epoch);
    assert_eq!(
        view.ca_pq_public_key,
        state.gateway.current_ca_public_key.to_base64()
    );
    assert_eq!(view.ca_tls_epoch, state.client_tls_ca.ca_tls_epoch);
    assert_eq!(view.client_generation, peer.state.active.generation);
    assert_eq!(
        view.active_gateway_identity_epoch,
        state.gateway.active_gateway_identity_epoch
    );
    assert_eq!(
        view.gateway_decision_epoch,
        state.gateway.gateway_decision_epoch
    );
    assert_eq!(
        view.astra_service_public_key,
        state.astra.active_astra_service_public_key.to_base64()
    );

    // The consumer is the judge: a block this gateway serves and Orion
    // refuses is a profile that cannot renew, discovered on the client.
    let material: orion_core::TrustMaterial =
        serde_json::from_value(serde_json::to_value(&view).expect("encode"))
            .expect("Orion reads what the gateway serves");
    material
        .validate()
        .expect("Orion accepts what the gateway serves");
}

#[test]
fn a_caller_declaring_exactly_what_the_gateway_serves_is_current() {
    let state = state();
    let peer = peer();
    assert!(caller_is_current(&state, &peer, &request(&state, &peer)).expect("comparison"));
}

/// A client that has just been enrolled is **not** behind.
///
/// The comparison reads eleven values; the enrolment block is where a
/// fresh client learns the ones it cannot derive from its own
/// certificates. A value missing from the block is seeded as zero, which
/// no registry is ever at, and the caller is then behind on a counter that
/// no transition can advance — the gateway answers `503` to every poll for
/// the life of the profile. So the block is compared to the request here,
/// field by field, rather than each half being trusted on its own.
#[test]
fn a_caller_seeded_from_the_enrolment_block_is_current() {
    let state = state();
    let peer = peer();
    let view = enrolment_view(&state, &peer);

    // Exactly what `orion_core::certificate_renewal` seeds from the block
    // and then declares. The rest of the request is the local material:
    // the certificates the client holds, and its own base state.
    let mut request = request(&state, &peer);
    request.ca_epoch = view.ca_epoch;
    request.ca_tls_epoch = view.ca_tls_epoch;
    request.astra_service_key_epoch = view.astra_service_key_epoch;
    request.client_identity_generation = view.client_generation;
    request.active_gateway_identity_epoch = view.active_gateway_identity_epoch;
    request.gateway_decision_epoch = view.gateway_decision_epoch;

    assert!(
        caller_is_current(&state, &peer, &request).expect("comparison"),
        "a profile enrolled from this block must not be born behind"
    );
}

/// Every counter and every active fingerprint is compared. A gap in this
/// list answers "you are up to date" to a client that is not, and the
/// client stops asking — the one refusal with no recovery.
#[test]
fn a_caller_behind_on_any_single_value_is_not_current() {
    let state = state();
    let peer = peer();
    let stale = Fingerprint::of(b"an older certificate");

    /// One way of being behind, and the name it is reported under.
    type Mutation = (&'static str, fn(&mut TrustUpdateRequest, Fingerprint));

    let mutations: Vec<Mutation> = vec![
        ("ca_epoch", |request, _| request.ca_epoch -= 1),
        ("ca_tls_epoch", |request, _| request.ca_tls_epoch -= 1),
        ("astra_service_key_epoch", |request, _| {
            request.astra_service_key_epoch -= 1
        }),
        ("issuer_epoch", |request, _| request.issuer_epoch += 1),
        ("active_gateway_identity_epoch", |request, _| {
            request.active_gateway_identity_epoch -= 1
        }),
        ("gateway_decision_epoch", |request, _| {
            request.gateway_decision_epoch -= 1
        }),
        ("client_identity_generation", |request, _| {
            request.client_identity_generation -= 1
        }),
        ("gateway TLS leaf", |request, stale| {
            request.active_gateway_tls_certificate_fingerprint = stale
        }),
        ("gateway PQ leaf", |request, stale| {
            request.active_gateway_certificate_fingerprint = stale
        }),
        ("client TLS leaf", |request, stale| {
            request.active_client_tls_certificate_fingerprint = stale
        }),
        ("client PQ leaf", |request, stale| {
            request.active_client_pq_certificate_fingerprint = stale
        }),
    ];

    for (name, mutate) in mutations {
        let mut behind = request(&state, &peer);
        mutate(&mut behind, stale);
        assert!(
            !caller_is_current(&state, &peer, &behind).expect("comparison"),
            "a caller behind on {name} was reported as up to date"
        );
    }
}

/// The delegation counts too: a client that has never seen the installed
/// issuer cannot verify a leaf renewed under it.
#[test]
fn a_caller_that_has_not_seen_the_installed_issuer_is_not_current() {
    let mut state = state();
    let peer = peer();
    let current = request(&state, &peer);

    let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
    state.issuer = Some(aether::certificates::state::AstraIssuerState {
        issuer_epoch: 4,
        authorization: aether::certificates::authority::AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: 1,
            ca_tls_epoch: 2,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            server_name: state.gateway.server_name.clone(),
            issuer_epoch: 4,
            pq_issuer_public_key: issuer_key,
            tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
            allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 1_000_000,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        },
        state: aether::certificates::state::IssuerLifecycle::Active,
    });

    assert!(!caller_is_current(&state, &peer, &current).expect("comparison"));
}

/// A queued transaction, at a chosen position, for the count below.
fn distribution(
    cursor: u16,
    chunk_count: u16,
) -> helios_provisioning::certificates::PendingDistribution {
    use aether::certificates::transport::{
        ManifestAuthority, TrustUpdateChunk, TrustUpdateTransactionManifest,
    };

    let manifest = TrustUpdateTransactionManifest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        transaction_id: Id16::new([9; 16]).expect("id"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: key(9),
        client_wg_public_key: key(2),
        base_state_fingerprint: Fingerprint::of(b"base state"),
        created_at: 0,
        expires_at: 1_000,
        minimum_activation_at: 1_000,
        chunk_count,
        objects: Vec::new(),
        manifest_authority_kind: ManifestAuthority::AstraServiceKey,
        manifest_authority_epoch: 1,
        signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    };
    let manifest_fingerprint = manifest.fingerprint();
    helios_provisioning::certificates::PendingDistribution {
        manifest,
        chunks: (0..chunk_count)
            .map(|index| TrustUpdateChunk {
                manifest_fingerprint,
                chunk_index: index,
                chunk_count,
                first_object_index: index,
                objects: Vec::new(),
            })
            .collect(),
        cursor,
        last_request_id: None,
    }
}

/// The gateway asks the authority when its queue holds nothing, and queues
/// what comes back. This is the whole of the 503 fix on this side.
/// The private link carries the recovery of §7.5 and nothing else.
///
/// The refusal happens before the registry is even locked, and that is the
/// point: an ordinary renewal is committed by its client, inside its
/// tunnel, where the source address proves the peer. A veth that also
/// accepted one would be a second path to the same write, reachable by a
/// party that is not the client.
#[tokio::test]
async fn an_ordinary_renewal_is_never_committed_on_the_private_link() {
    use ::astra_channel::AstraChannelHandler;
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::IssuerKind;

    let mut state = state();
    state.peers.insert(key(2).to_base64(), peer());
    let (service, _directory) = service(state);

    let mut relayed = relayed_commit();
    relayed.authorization.issuer_kind = IssuerKind::Astra;
    assert!(
        service.commit_recovery(Box::new(relayed)).await.is_err(),
        "a delegated staging is not a recovery, whatever its reason says"
    );

    let mut relayed = relayed_commit();
    relayed.authorization.reason = RotationReason::Scheduled;
    assert!(
        service.commit_recovery(Box::new(relayed)).await.is_err(),
        "CA-PQ signing an ordinary renewal is still an ordinary renewal"
    );
}

/// A recovery whose authorization is not the one that opened the pending
/// stage is refused: the relay may carry a decision, never describe one.
#[tokio::test]
async fn a_recovery_commit_must_name_the_staging_the_registry_recorded() {
    use ::astra_channel::AstraChannelHandler;

    let mut state = state();
    state.peers.insert(key(2).to_base64(), peer());
    let (service, _directory) = service(state);
    // `peer()` holds no pending stage at all, so there is nothing this
    // authorization could be the one that opened.
    assert!(service
        .commit_recovery(Box::new(relayed_commit()))
        .await
        .is_err());
}

#[tokio::test]
async fn an_empty_queue_makes_the_gateway_ask_the_authority() {
    let mut state = state();
    state.peers.insert(key(2).to_base64(), peer());
    let (service, _directory) = service(state);
    let prepared = distribution(0, 1);
    let service = service.with_authority(Arc::new(StubAuthority {
        prepared: ::astra_channel::PreparedTrustUpdate {
            transaction: Some(::astra_channel::PreparedTrustUpdateTransaction {
                manifest: prepared.manifest.clone(),
                chunks: prepared.chunks.clone(),
            }),
        },
    }));

    let request = authenticated_request(&key(2));
    service
        .prepare_from_authority(&key(2), &request, 0)
        .await
        .expect("preparation");

    let mut registry = service.registry.lock().await;
    let served = registry
        .take_distribution_chunk(
            &key(2),
            &Id16::new([4; 16]).expect("request id"),
            &Fingerprint::of(b"base state"),
            0,
        )
        .expect("readable")
        .expect("the prepared transaction is queued");
    assert_eq!(served.0.fingerprint(), prepared.manifest.fingerprint());
}

/// A gateway with no authority behaves exactly as before: it asks nobody
/// and queues nothing. A domain without Astra is a supported shape.
#[tokio::test]
async fn a_gateway_without_an_authority_asks_no_one() {
    let mut state = state();
    state.peers.insert(key(2).to_base64(), peer());
    let (service, _directory) = service(state);

    let request = authenticated_request(&key(2));
    service
        .prepare_from_authority(&key(2), &request, 0)
        .await
        .expect("no authority is not a failure");

    let mut registry = service.registry.lock().await;
    assert!(registry
        .take_distribution_chunk(
            &key(2),
            &Id16::new([4; 16]).expect("request id"),
            &Fingerprint::of(b"base state"),
            0,
        )
        .expect("readable")
        .is_none());
}

/// The console draws the same rungs the protocol decides on.
///
/// A screen with its own arithmetic is a screen that eventually says
/// *valide* about a leaf the planner has already scheduled a renewal for —
/// and the operator believes the screen.
#[test]
fn the_domain_view_places_a_leaf_on_the_protocol_ladder() {
    use aether::certificates::window::ValidityPhase;

    let mut state = state();
    state.peers.insert(key(2).to_base64(), peer());

    // The fixture generation runs from 0 to 1 000 000, so the thresholds
    // of spec §4.3 fall on round numbers.
    let phase_at = |now: u64| domain_view(&state, now).peers[0].phase;
    assert_eq!(phase_at(0), ValidityPhase::Valid);
    assert_eq!(phase_at(799_999), ValidityPhase::Valid);
    assert_eq!(phase_at(800_000), ValidityPhase::RenewalDue);
    assert_eq!(phase_at(900_000), ValidityPhase::Warning);
    assert_eq!(phase_at(950_000), ValidityPhase::Critical);
    assert_eq!(phase_at(1_000_000), ValidityPhase::Expired);
}

/// The count is what is **left**, not what was queued.
///
/// A peer that has collected two of three fragments is still behind, and a
/// console showing the total would report the same number before and after
/// every poll — the one figure that says whether anything is moving.
#[test]
fn the_domain_view_counts_the_fragments_a_peer_has_not_collected() {
    let pending_after = |cursor: u16| {
        let mut state = state();
        let mut queued = peer();
        queued.distribution = Some(distribution(cursor, 3));
        state.peers.insert(key(2).to_base64(), queued);
        domain_view(&state, 0).peers[0].distribution_chunks_pending
    };

    assert_eq!(pending_after(1), 2);
    assert_eq!(pending_after(3), 0);
}

/// A resume compares these with its journal: without them a CA-TLS rotation has
/// no way to tell it is on the gateway, or already promoted.
#[test]
fn the_domain_view_names_both_client_tls_anchors() {
    let mut state = state();
    let active = state
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    let view = domain_view(&state, 0);
    assert_eq!(view.client_tls_ca_fingerprint, active.to_hex());
    assert_eq!(view.next_client_tls_ca_fingerprint, None);

    let next =
        aether::certificates::encoding::DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
            .expect("certificate");
    state.client_tls_ca.next_client_tls_ca_certificate = Some(next.clone());
    let view = domain_view(&state, 0);
    assert_eq!(
        view.next_client_tls_ca_fingerprint,
        Some(next.fingerprint().to_hex())
    );
}

/// The operator read carries no certificate body, and no key.
///
/// It is served on the admin surface, so nothing here is secret — but a
/// view that grew a DER blob or a public key would be a view somebody
/// later fed to a parser, and the registry's own copies are the ones that
/// must decide. Fingerprints and dates are what an operator acts on.
#[test]
fn the_domain_view_carries_no_certificate_body() {
    let mut state = state();
    let peer = peer();
    let leaf_key = peer.active_pq_certificate.ml_dsa_87_public_key.clone();
    state.peers.insert(key(2).to_base64(), peer);

    let json = serde_json::to_string(&domain_view(&state, 0)).expect("serialise");
    assert!(
        !json.contains(&leaf_key),
        "the peer's public key must not travel"
    );
    assert!(
        !json.contains(&state.gateway.current_ca_public_key.to_base64()),
        "the anchor travels as a fingerprint, not as a key"
    );
    assert!(
        !json.contains(&state.astra.active_astra_service_public_key.to_base64()),
        "the Astra service key travels in the §19 block, not in this one"
    );
    // What it does carry: the values a screen shows.
    assert!(json.contains("gateway.example"));
    assert!(json.contains("\"generation\":4"));
}

/// An `active` delegation past its `not_after` signs nothing.
///
/// The lifecycle field alone would let the console call it usable, and an
/// operator would look everywhere but at the clock when renewals stop.
#[test]
fn the_domain_view_reads_the_issuer_clock_and_not_only_its_lifecycle() {
    let mut state = state();
    let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
    state.issuer = Some(aether::certificates::state::AstraIssuerState {
        issuer_epoch: 4,
        authorization: aether::certificates::authority::AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: 1,
            ca_tls_epoch: 2,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            server_name: state.gateway.server_name.clone(),
            issuer_epoch: 4,
            pq_issuer_public_key: issuer_key,
            tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
            allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 1_000,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        },
        state: aether::certificates::state::IssuerLifecycle::Active,
    });

    let inside = domain_view(&state, 999).issuer.expect("issuer");
    assert!(inside.usable);
    let outside = domain_view(&state, 1_000).issuer.expect("issuer");
    assert_eq!(
        outside.lifecycle,
        aether::certificates::state::IssuerLifecycle::Active
    );
    assert!(!outside.usable, "expiry decides, not the lifecycle field");
}

/// A leaf signed by a chosen key, for one exact WireGuard identity.
fn leaf_from(
    issuer_private: &[u8],
    wg_public_key: &WireGuardKey,
    serial: u8,
) -> (
    PqCertificate,
    aether::certificates::encoding::MlDsa87PublicKey,
) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: "workstation".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: wg_public_key.to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: u64::MAX / 2,
            ml_dsa_87_signature: String::new(),
        },
        issuer_private,
    )
    .expect("issue");
    (certificate, subject_public)
}

/// The staging check must accept exactly what the negotiation port will.
///
/// An ordinary renewal is issued by the **delegated issuer**, not by the
/// operator CA the first generation chained to. A gateway offering only
/// the key on disk refuses to stage the one candidate the whole lifecycle
/// exists to produce — and it refuses it silently enough that the operator
/// looks at the authority rather than at the pinning.
#[test]
fn a_candidate_signed_by_the_delegated_issuer_is_presentable() {
    use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
    use aether::certificates::client::{ClientCertificateStageAuthorization, IssuerKind};
    use aether::certificates::encoding::MlDsa87Signature;
    use aether::certificates::window::TransitionWindow;

    let material = aether::certificates::test_x509::client_material("workstation");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
    let (candidate, _) = leaf_from(&issuer_private, &key(2), 7);
    // The key the negotiation port reads from disk. Deliberately unrelated
    // to the delegation: that is the whole situation being tested.
    let (_, on_disk_ca) = generate_ml_dsa_87_keypair().expect("keygen");

    let authorization = ClientCertificateStageAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        ca_tls_epoch: 2,
        issuer_kind: IssuerKind::Astra,
        issuer_epoch: 4,
        issuer_authorization_fingerprint: Fingerprint::of(b"delegation"),
        issuer_authorization: None,
        stage_id: Id16::new([5; 16]).expect("stage"),
        request_fingerprint: Fingerprint::of(b"request"),
        renewal_authorization_fingerprint: Fingerprint::of(b"approval"),
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: key(9),
        server_name: "gateway.example".into(),
        client_wg_public_key: key(2),
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
        next_tls_ca_certificate_fingerprint: material.authority.fingerprint(),
        next_tls_certificate: material.leaf.clone(),
        next_pq_certificate: candidate,
        issued_at: 1_000,
        stage_expires_at: 50_000,
        window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
        reason: aether::certificates::authority::RotationReason::Scheduled,
        signature: MlDsa87Signature::placeholder(),
    };

    // Without the delegation the gateway knows only the key on disk, and
    // refuses — which is the behaviour that used to be permanent.
    let mut state = state();
    // One authority for both halves: `client_material` mints a fresh CA
    // per call, and a leaf checked against a different one would fail on
    // the TLS half before the PQ half — the half under test — is reached.
    state.client_tls_ca.active_client_tls_ca_certificate = material.authority.clone();
    let refusal = assert_candidate_is_presentable(&state, on_disk_ca.as_bytes(), &authorization)
        .expect_err("no issuer offered can verify this leaf");
    assert!(
        refusal.contains("not verifiable by the negotiation port"),
        "{refusal}"
    );

    // Installed, it is accepted — and the negotiation port admits the same
    // set, so what is staged here is what will authenticate later.
    state.issuer = Some(aether::certificates::state::AstraIssuerState {
        issuer_epoch: 4,
        authorization: AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: 1,
            ca_tls_epoch: 2,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            server_name: state.gateway.server_name.clone(),
            issuer_epoch: 4,
            pq_issuer_public_key: issuer_public,
            tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: u64::MAX / 2,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        },
        state: aether::certificates::state::IssuerLifecycle::Active,
    });
    assert_candidate_is_presentable(&state, on_disk_ca.as_bytes(), &authorization)
        .expect("the delegated issuer is one the negotiation admits");
}

/// The operator CA is the authority a client's **first** leaf is issued
/// under: only a renewal moves it to the delegated issuer. A trust-update
/// route that asked the registry alone therefore refused every client that
/// had never renewed — on a fresh domain, all of them — with a bare `403`
/// and nothing naming the cause.
#[test]
fn the_issuer_set_admits_a_client_that_has_never_renewed() {
    let (_, operator_ca) = generate_ml_dsa_87_keypair().expect("operator CA");
    let state = state();

    let issuers = client_leaf_issuers(&state, &operator_ca, 1_000);

    assert_eq!(
        issuers.first().copied(),
        Some(&operator_ca),
        "the operator CA is asked first, as the negotiation port asks it"
    );
    assert!(
        issuers.contains(&&state.gateway.current_ca_public_key),
        "the anchor stays in the set: a leaf reissued under CA-PQ must keep working"
    );
}

/// Asked twice, offered once. The registry may already carry the same key
/// the gateway holds on disk, and a duplicated issuer would make every
/// refusal report one more failed attempt than actually happened.
#[test]
fn the_issuer_set_does_not_repeat_an_authority_it_already_holds() {
    let state = state();
    let operator_ca = state.gateway.current_ca_public_key.clone();

    let issuers = client_leaf_issuers(&state, &operator_ca, 1_000);

    assert_eq!(
        issuers
            .iter()
            .filter(|issuer| ***issuer == operator_ca)
            .count(),
        1
    );
}

/// A service whose anchor is a key the test holds, so it can sign a
/// transition the way the companion does.
fn service_with_known_anchor() -> (
    CertificateService,
    tempfile::TempDir,
    zeroize::Zeroizing<Vec<u8>>,
) {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    let mut state = state();
    state.gateway.current_ca_public_key = public;
    let (service, directory) = service(state);
    (service, directory, private)
}

/// A rotation of the client CA-TLS from epoch 2 (the fixture's) to 3,
/// activating after the real clock the handler reads.
fn client_tls_ca_transition(
    service: &CertificateService,
    signer: &[u8],
) -> aether::certificates::authority::ClientTlsCaTransition {
    use aether::certificates::window::TransitionWindow;

    let now = now_unix();
    let registry = service.registry.try_lock().expect("registry");
    let active = registry
        .state()
        .client_tls_ca
        .active_client_tls_ca_certificate
        .fingerprint();
    aether::certificates::authority::ClientTlsCaTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        current_ca_tls_epoch: 2,
        next_ca_tls_epoch: 3,
        active_client_tls_ca_fingerprint: active,
        next_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
            "successor",
        )
        .authority,
        window: TransitionWindow {
            not_before: now,
            activation_at: now + 600,
            not_after: now + 900,
        },
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(signer)
    .expect("sign")
}

/// The console route installs what the offline command installs, under the
/// daemon's own registry, and says what it staged.
#[tokio::test]
async fn client_tls_ca_install_stages_the_rotation_and_reads_it_back() {
    use helios_api::certificates::GatewayIdentityHandler;

    let (service, _directory, private) = service_with_known_anchor();
    let transition = client_tls_ca_transition(&service, &private);

    let view = service
        .install_client_tls_ca_transition(Box::new(transition.clone()))
        .await
        .expect("installed");

    assert_eq!(view.ca_tls_epoch, 2);
    assert_eq!(view.next_ca_tls_epoch, 3);
    assert_eq!(
        view.next_ca_tls_fingerprint,
        transition
            .next_client_tls_ca_certificate
            .fingerprint()
            .to_hex()
    );
    assert_eq!(view.activation_at, transition.window.activation_at);
    assert_eq!(view.not_after, transition.window.not_after);
    assert!(!view.already_present);
    let registry = service.registry.lock().await;
    assert!(registry
        .state()
        .client_tls_ca
        .next_client_tls_ca_certificate
        .is_some());
}

/// The gateway verifies, not the console: a transition signed by another key
/// is refused and the registry keeps its state.
#[tokio::test]
async fn client_tls_ca_install_refuses_a_transition_badly_signed() {
    use helios_api::certificates::GatewayIdentityHandler;

    let (service, _directory, _private) = service_with_known_anchor();
    let (stranger, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let transition = client_tls_ca_transition(&service, &stranger);
    let before = service.registry.lock().await.state().clone();

    let refusal = service
        .install_client_tls_ca_transition(Box::new(transition))
        .await;

    assert!(refusal.is_err());
    assert_eq!(
        service.registry.lock().await.state().client_tls_ca,
        before.client_tls_ca,
        "a refused transition leaves the registry unchanged"
    );
}

/// Carrying the same document twice must not consume a second epoch, and the
/// operator is told it was already there.
#[tokio::test]
async fn client_tls_ca_install_replay_answers_already_present() {
    use helios_api::certificates::GatewayIdentityHandler;

    let (service, _directory, private) = service_with_known_anchor();
    let transition = client_tls_ca_transition(&service, &private);

    let first = service
        .install_client_tls_ca_transition(Box::new(transition.clone()))
        .await
        .expect("first");
    let replay = service
        .install_client_tls_ca_transition(Box::new(transition))
        .await
        .expect("replay");

    assert!(!first.already_present);
    assert!(replay.already_present);
}
