use super::*;

pub(super) const SERVER_NAME: &str = "gateway.example";

pub(super) struct Keys {
    pub(super) private: Zeroizing<Vec<u8>>,
    pub(super) public: MlDsa87PublicKey,
}

pub(super) fn keys() -> Keys {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    Keys { private, public }
}

pub(super) fn domain() -> TrustDomainId {
    TrustDomainId::new([1; 16]).expect("domain")
}

pub(super) fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([1; 32])
}

pub(super) fn client_key(seed: u8) -> WireGuardKey {
    WireGuardKey::from_bytes([seed; 32])
}

pub(super) fn leaf(
    ca: &Keys,
    subject: &Keys,
    role: PqCertificateRole,
    wg: &WireGuardKey,
    serial: u8,
) -> PqCertificate {
    let certificate = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [serial; 16],
        subject: if role == PqCertificateRole::Gateway {
            SERVER_NAME.into()
        } else {
            "orion".into()
        },
        issuer: "CA-PQ".into(),
        role,
        wireguard_public_key: wg.to_base64(),
        ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
        not_before_unix: 0,
        not_after_unix: 1_000_000,
        ml_dsa_87_signature: String::new(),
    };
    issue_pq_certificate(certificate, &ca.private).expect("issue")
}

pub(super) fn generation(
    index: u64,
    tls: &[u8],
    pq: &PqCertificate,
) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: index,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(tls),
        pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(pq)
            .expect("fingerprint"),
        not_before: 0,
        not_after: 1_000_000,
    }
}

pub(super) struct Fixture {
    pub(super) tls: aether::certificates::test_x509::TlsMaterial,
    pub(super) registry: CertificateRegistry,
    pub(super) ca: Keys,
    pub(super) gateway_leaf_key: Keys,
    pub(super) active_client: Keys,
    pub(super) _directory: tempfile::TempDir,
}

pub(super) fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temp dir");
    let tls = aether::certificates::test_x509::client_material("workstation");
    let ca = keys();
    let gateway_leaf_key = keys();
    let astra_key = keys();
    let active_client = keys();

    let gateway_leaf = leaf(
        &ca,
        &gateway_leaf_key,
        PqCertificateRole::Gateway,
        &gateway_key(),
        1,
    );
    let client_leaf = leaf(
        &ca,
        &active_client,
        PqCertificateRole::Client,
        &client_key(2),
        2,
    );

    let state = RegistryState {
        trust_domain_id: domain(),
        gateway: GatewayCertificateState {
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            ca_epoch: 1,
            current_ca_public_key: ca.public.clone(),
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
            active_gateway_certificate: gateway_leaf,
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
            active_client_tls_ca_certificate: tls.authority.clone(),
            next_client_tls_ca_certificate: None,
            next_transition_fingerprint: None,
            activation_at: None,
            retire_active_at: None,
        },
        astra: AstraProfile {
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint:
                aether::certificates::approval::AstraIssuancePolicy::standard(
                    domain(),
                    gateway_key(),
                    SERVER_NAME.into(),
                )
                .pin()
                .expect("policy"),
            credential_registry_epoch: 1,
            credential_bindings: Default::default(),
            active_astra_service_public_key: astra_key.public.clone(),
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 1,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer: None,
        peers: BTreeMap::new(),
        ledger: TrustLedger::default(),
    };

    let mut registry = CertificateRegistry::new(directory.path().join("certificates.json"), state);
    registry
        .admit(
            "workstation",
            &client_key(2),
            generation(4, b"active tls", &client_leaf),
            client_leaf,
        )
        .expect("admission");

    Fixture {
        tls,
        registry,
        ca,
        gateway_leaf_key,
        active_client,
        _directory: directory,
    }
}
