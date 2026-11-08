use super::*;
use aether::certificates::{
    approval::{
        AstraCredentialBinding, AstraIssuancePolicy, AstraPolicyPin, CredentialRegistry,
        CredentialState, ExpiredRecoveryApproval,
    },
    capability::CapabilityTokens,
    encoding::{generate_ml_dsa_87_keypair, TrustDomainId},
    webauthn::WebAuthnAssertion,
};
use aether::certificates::{
    client::{ClientCertificateGeneration, ClientCertificateStageAuthorization},
    encoding::MlDsa87Signature,
    state::ClientCertificateState,
    transport::TrustUpdateRefusal,
    window::TransitionWindow,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SigningKey, PKCS_ECDSA_P256_SHA256,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Mutex;

struct RecoveryGateway {
    peer: aether::certificates::encoding::WireGuardKey,
    peer_view: Mutex<astra_channel::PeerCertificateStateView>,
    stage_calls: std::sync::atomic::AtomicUsize,
    commit_fingerprints: Mutex<Vec<Fingerprint>>,
    lose_first_reply: std::sync::atomic::AtomicBool,
    gateway_leaf: aether::key_negotiation::PqCertificate,
    expected_authorization: ClientCertificateStageAuthorization,
    stage_receipt: GatewayCertificateStageReceipt,
    ca_public: aether::certificates::encoding::MlDsa87PublicKey,
    gateway_public: aether::certificates::encoding::MlDsa87PublicKey,
    gateway_certificate_fingerprint: Fingerprint,
    tls_anchor: aether::certificates::encoding::DerCertificate,
    active_generation: ClientCertificateGeneration,
    old_client_public: aether::certificates::encoding::MlDsa87PublicKey,
    candidate_client_public: aether::certificates::encoding::MlDsa87PublicKey,
}

#[async_trait::async_trait]
impl astra_channel::AstraStageHandler for RecoveryGateway {
    async fn stage_from_astra(
        &self,
        authorization: Box<ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        self.stage_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !authorization
            .fingerprint()
            .map_err(|_| TrustUpdateRefusal::Rejected)?
            .matches(
                &self
                    .expected_authorization
                    .fingerprint()
                    .map_err(|_| TrustUpdateRefusal::Rejected)?,
            )
        {
            return Err(TrustUpdateRefusal::Rejected);
        }
        authorization
            .verify(
                &self.ca_public,
                &authorization.trust_domain_id,
                authorization.ca_epoch,
                authorization.ca_tls_epoch,
                &authorization.gateway_wg_public_key,
                &authorization.server_name,
                &authorization.client_wg_public_key,
                &self.active_generation,
                &[&self.tls_anchor],
                None,
                Some(authorization.stage_expires_at + 200),
                authorization.issued_at,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        let mut view = self.peer_view.lock().await;
        view.state
            .stage(
                &authorization,
                &aether::certificates::state::TrustLedger::default(),
                authorization.issued_at,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        Ok(Box::new(self.stage_receipt.clone()))
    }
}

#[async_trait::async_trait]
impl astra_channel::AstraChannelHandler for RecoveryGateway {
    async fn revoke(
        &self,
        _revocation: Box<aether::certificates::revocation::EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<astra_channel::PeerCertificateStateView, TrustUpdateRefusal> {
        if identity != &self.peer {
            return Err(TrustUpdateRefusal::Rejected);
        }
        Ok(self.peer_view.lock().await.clone())
    }

    async fn gateway_identity(
        &self,
    ) -> Result<astra_channel::GatewayIdentityView, TrustUpdateRefusal> {
        let fingerprint =
            aether::certificates::gateway::pq_certificate_fingerprint(&self.gateway_leaf)
                .map_err(|_| TrustUpdateRefusal::Rejected)?;
        Ok(astra_channel::GatewayIdentityView {
            pq_certificate: self.gateway_leaf.clone(),
            pq_certificate_fingerprint: fingerprint,
            tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
            tls_certificate_not_after: 100_000,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
        })
    }

    async fn gateway_transition_published(
        &self,
        _published: astra_channel::GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn distribute(
        &self,
        _distribution: Box<astra_channel::TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn commit_recovery(
        &self,
        relayed: Box<astra_channel::RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        let authorization = &relayed.authorization;
        let commit = &relayed.commit;
        let candidate = authorization
            .candidate()
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        let anchors = [&self.tls_anchor];
        authorization
            .verify(
                &self.ca_public,
                &authorization.trust_domain_id,
                authorization.ca_epoch,
                authorization.ca_tls_epoch,
                &authorization.gateway_wg_public_key,
                &authorization.server_name,
                &authorization.client_wg_public_key,
                &self.active_generation,
                &anchors,
                None,
                Some(authorization.stage_expires_at + 200),
                commit.committed_at,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        relayed
            .grant
            .verify_for_gateway(
                &self.ca_public,
                &self.gateway_public,
                &self.gateway_certificate_fingerprint,
                &authorization.trust_domain_id,
                authorization.ca_epoch,
                authorization.ca_tls_epoch,
                &authorization.gateway_wg_public_key,
                &authorization.server_name,
                &authorization.client_wg_public_key,
                authorization.active_generation,
                &candidate,
                &authorization.stage_id,
                &anchors,
                None,
                commit.committed_at,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        commit
            .verify(
                &self.old_client_public,
                &self.candidate_client_public,
                &authorization.trust_domain_id,
                &authorization.gateway_wg_public_key,
                &authorization.client_wg_public_key,
                &authorization.stage_id,
                &candidate,
                authorization.active_generation,
                authorization.stage_expires_at,
                commit.committed_at,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        let fingerprint = relayed.commit.fingerprint();
        let mut commits = self.commit_fingerprints.lock().await;
        if let Some(previous) = commits.first() {
            if !previous.matches(&fingerprint) {
                return Err(TrustUpdateRefusal::Rejected);
            }
        } else {
            let candidate = relayed
                .authorization
                .candidate()
                .map_err(|_| TrustUpdateRefusal::Rejected)?;
            let mut view = self.peer_view.lock().await;
            view.state = ClientCertificateState::new(candidate);
            view.active_pq_certificate = relayed.authorization.next_pq_certificate.clone();
            commits.push(fingerprint);
            if self
                .lose_first_reply
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                // Model the gateway applying the commit to its in-memory
                // state before its response is lost. The same signed commit
                // must be safe to send again.
                return Err(TrustUpdateRefusal::Unavailable);
            }
            return Ok(());
        }
        commits.push(fingerprint);
        Ok(())
    }
}

fn service() -> (
    Arc<AstraService>,
    tempfile::TempDir,
    zeroize::Zeroizing<Vec<u8>>,
) {
    let directory = tempfile::tempdir().expect("temporary Astra state directory");
    let domain = TrustDomainId::new([11; 16]).expect("domain");
    let gateway = WireGuardKey::from_bytes([12; 32]);
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service keypair");
    let policy = AstraIssuancePolicy::standard(domain, gateway, "astra.example".into())
        .fingerprint()
        .expect("policy fingerprint");
    let registry = crate::registry::AstraRegistry::new(
        directory.path().join("astra.json"),
        crate::registry::AstraState {
            trust_domain_id: domain,
            gateway_wg_public_key: gateway,
            server_name: "astra.example".into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: AstraPolicyPin::new(policy).expect("policy pin"),
            credential_registry_epoch: 1,
            ca_epoch: 1,
            ca_public_key: ca_public,
            ca_rotation: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: None,
            ca_tls_rotation: None,
            astra_service_key_epoch: 1,
            astra_service_public_key: service_public.clone(),
            issuer: None,
            transitions: Vec::new(),
            promoted_credentials: None,
            peers: BTreeMap::new(),
            status_epochs: BTreeMap::new(),
            audit: crate::audit::AuditChain::default(),
        },
    );
    let state_dir = directory.path().to_path_buf();
    let service = Arc::new(AstraService {
        registry: Mutex::new(registry),
        issuer: RwLock::new(None),
        challenges: Mutex::new(crate::registry::ChallengeStore::with_capacity(
            crate::service::MAX_LIVE_CHALLENGES,
        )),
        budgets: Mutex::new(crate::service::SourceBudget::default()),
        service_private_key: service_private,
        service_public_key: service_public,
        operations: Mutex::new(crate::operations::OperationStore::new()),
        capabilities: Mutex::new(CapabilityTokens::new().expect("capability key")),
        approval_credentials: RwLock::new(Arc::new(crate::service::ApprovalCredentials {
            ids: Vec::new(),
            epoch: 1,
            registry: None,
        })),
        signing: Mutex::new(crate::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault: RwLock::new(None),
        state_dir,
        gateway: None,
        volume_writes: crate::door::VolumeWrites::new(),
    });
    (service, directory, ca_private)
}

#[tokio::test]
async fn recovery_steps_reject_unknown_ids_without_creating_state() {
    let (service, _directory, _) = service();
    let id = Id16::new([77; 16]).expect("operation id");
    let (authorization, evidence) = authorization_documents();
    assert!(matches!(
        authorize(&service, &id, authorization, evidence, 1_000).await,
        Err(RecoveryError::Unknown)
    ));
    assert!(matches!(
        commit(&service, &id, Box::new(commit_document()), 1_000).await,
        Err(RecoveryError::Unknown)
    ));
    let client = WireGuardKey::from_bytes([23; 32]);
    assert!(matches!(
        reconcile(&service, &client, 5, 1_000).await,
        Err(RecoveryError::UnknownPeer)
    ));
    assert!(matches!(
        open(&service, request(23), 1_000).await,
        Err(RecoveryError::UnknownPeer)
    ));
    assert!(service.recoveries.lock().await.is_empty());
}

fn authorization_documents() -> (
    Box<ClientCertificateStageAuthorization>,
    Box<ExpiredRecoveryApprovalEvidence>,
) {
    use aether::certificates::{
        approval::{CredentialRegistry, ExpiredRecoveryApproval},
        encoding::DerCertificate,
        window::TransitionWindow,
        WebAuthnAssertion,
    };

    let request = request(23);
    let request_fingerprint = request.fingerprint();
    let domain = request.trust_domain_id;
    let gateway = request.gateway_wg_public_key;
    let client = request.client_wg_public_key;
    let challenge = request.astra_challenge;
    let stage_id = Id16::new([1; 16]).expect("stage");
    let authorization_fingerprint = Fingerprint::of(b"authorization");
    let evidence = Box::new(ExpiredRecoveryApprovalEvidence {
        approval: ExpiredRecoveryApproval {
            request_fingerprint,
            astra_challenge: challenge,
            approved_at: 900,
            expires_at: 1_200,
            credential_id: b"credential".to_vec(),
            credential_fingerprint: Fingerprint::of(b"credential fingerprint"),
            assertion_fingerprint: Fingerprint::of(b"assertion fingerprint"),
            webauthn_assertion: WebAuthnAssertion {
                authenticator_data: Vec::new(),
                client_data_json: Vec::new(),
                signature: Vec::new(),
            },
        },
        credential_registry: CredentialRegistry {
            trust_domain_id: domain,
            gateway_wg_public_key: gateway,
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        },
        webauthn_origin: "https://astra.example".into(),
    });
    let authorization = Box::new(ClientCertificateStageAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain,
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::of(b""),
        issuer_authorization: None,
        stage_id,
        request_fingerprint,
        renewal_authorization_fingerprint: authorization_fingerprint,
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: gateway,
        server_name: "gateway.example".into(),
        client_wg_public_key: client,
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
        next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        next_tls_certificate: DerCertificate::new(vec![1; 64]).expect("DER certificate"),
        next_pq_certificate: request.expired_pq_certificate.clone(),
        issued_at: 1_000,
        stage_expires_at: 2_000,
        window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
        reason: aether::certificates::authority::RotationReason::ExpiredRecovery,
        signature: MlDsa87Signature::placeholder(),
    });
    (authorization, evidence)
}

fn commit_document() -> ClientCertificateStageCommit {
    ClientCertificateStageCommit {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([11; 16]).expect("domain"),
        stage_id: Id16::new([1; 16]).expect("stage"),
        grant_fingerprint: Fingerprint::of(b"grant"),
        stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
        gateway_wg_public_key: WireGuardKey::from_bytes([12; 32]),
        client_wg_public_key: WireGuardKey::from_bytes([23; 32]),
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
        staged_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        stage_expires_at: 4_000,
        committed_at: 1_000,
        active_pq_signature: MlDsa87Signature::placeholder(),
        staged_pq_signature: MlDsa87Signature::placeholder(),
    }
}

fn signed_pq_leaf(
    ca_private: &[u8],
    subject: &str,
    issuer: &str,
    role: PqCertificateRole,
    wireguard: WireGuardKey,
    subject_public: &[u8],
    serial: u8,
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: subject.into(),
            issuer: issuer.into(),
            role,
            wireguard_public_key: wireguard.to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(subject_public),
            not_before_unix: 0,
            not_after_unix: if serial == 41 { 5_000 } else { 100_000 },
            ml_dsa_87_signature: String::new(),
        },
        ca_private,
    )
    .expect("signed PQ leaf")
}

fn generation(
    index: u64,
    pq_leaf: &PqCertificate,
    tls_anchor: &aether::certificates::encoding::DerCertificate,
    tls_leaf: &aether::certificates::encoding::DerCertificate,
) -> ClientCertificateGeneration {
    let tls_facts = aether::certificates::x509::inspect(tls_leaf).expect("TLS leaf facts");
    ClientCertificateGeneration {
        generation: index,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: tls_anchor.fingerprint(),
        tls_certificate_fingerprint: tls_leaf.fingerprint(),
        pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
            pq_leaf,
        )
        .expect("PQ leaf fingerprint"),
        not_before: tls_facts.not_before,
        not_after: tls_facts.not_after,
    }
}

fn recovery_evidence(
    ca_private: &[u8],
    domain: TrustDomainId,
    gateway: WireGuardKey,
    request_fingerprint: Fingerprint,
    challenge: [u8; 32],
    now: u64,
) -> Box<ExpiredRecoveryApprovalEvidence> {
    let credential = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ES256 credential");
    let point = credential.public_key_raw();
    assert_eq!(
        point.len(),
        65,
        "ES256 public key uses an uncompressed point"
    );
    let mut cose_key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose_key.extend_from_slice(&point[1..33]);
    cose_key.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose_key.extend_from_slice(&point[33..65]);
    let credential_id = b"recovery-credential".to_vec();
    let binding = AstraCredentialBinding {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id: credential_id.clone(),
        credential_public_key: cose_key,
        aaguid: [0; 16],
        trust_domain_id: domain,
        gateway_wg_public_key: gateway,
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: now,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("CA-signed FIDO binding");
    let mut approval = ExpiredRecoveryApproval {
        request_fingerprint,
        astra_challenge: challenge,
        approved_at: now,
        expires_at: now + 200,
        credential_id,
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: Fingerprint::from_bytes([0; 32]),
        webauthn_assertion: WebAuthnAssertion {
            authenticator_data: Vec::new(),
            client_data_json: Vec::new(),
            signature: Vec::new(),
        },
    };
    let assertion_challenge = approval.challenge();
    let mut authenticator_data = Fingerprint::of(b"astra.example").as_bytes().to_vec();
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&1u32.to_be_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://astra.example","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(assertion_challenge.as_bytes())
    )
    .into_bytes();
    let mut signed_message = authenticator_data.clone();
    signed_message.extend_from_slice(Fingerprint::of(&client_data_json).as_bytes());
    approval.webauthn_assertion = WebAuthnAssertion {
        authenticator_data,
        client_data_json,
        signature: credential
            .sign(&signed_message)
            .expect("software credential assertion"),
    };
    approval.assertion_fingerprint = approval.webauthn_assertion.fingerprint();
    Box::new(ExpiredRecoveryApprovalEvidence {
        approval,
        credential_registry: CredentialRegistry {
            trust_domain_id: domain,
            gateway_wg_public_key: gateway,
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: vec![binding],
        },
        webauthn_origin: "https://astra.example".into(),
    })
}

fn tls_material() -> (
    aether::certificates::encoding::DerCertificate,
    aether::certificates::encoding::DerCertificate,
    aether::certificates::encoding::DerCertificate,
    aether::certificates::encoding::DerCertificate,
) {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("TLS root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    root_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    root_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let root_key = KeyPair::generate().expect("TLS root key");
    let root_certificate = root_params
        .self_signed(&root_key)
        .expect("TLS root certificate");

    let issuer =
        Issuer::from_ca_cert_der(root_certificate.der(), &root_key).expect("TLS root issuer");

    let mut expired_leaf_params =
        CertificateParams::new(Vec::<String>::new()).expect("expired TLS leaf params");
    expired_leaf_params.is_ca = IsCa::NoCa;
    expired_leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    expired_leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    expired_leaf_params.not_before =
        time::OffsetDateTime::from_unix_timestamp(0).expect("expired TLS not-before");
    expired_leaf_params.not_after =
        time::OffsetDateTime::from_unix_timestamp(5_000).expect("expired TLS not-after");
    let expired_leaf_key = KeyPair::generate().expect("expired TLS leaf key");
    let expired_leaf_certificate = expired_leaf_params
        .signed_by(&expired_leaf_key, &issuer)
        .expect("expired TLS client leaf");

    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("TLS leaf params");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let leaf_key = KeyPair::generate().expect("TLS leaf key");
    let csr = leaf_params.serialize_request(&leaf_key).expect("TLS CSR");
    let leaf_certificate = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("TLS candidate leaf");
    (
        aether::certificates::encoding::DerCertificate::new(root_certificate.der().to_vec())
            .expect("TLS root DER"),
        aether::certificates::encoding::DerCertificate::new(
            expired_leaf_certificate.der().to_vec(),
        )
        .expect("expired TLS leaf DER"),
        aether::certificates::encoding::DerCertificate::new(leaf_certificate.der().to_vec())
            .expect("TLS candidate leaf DER"),
        aether::certificates::encoding::DerCertificate::new(csr.der().to_vec())
            .expect("TLS CSR DER"),
    )
}

fn granted_recovery(
    seed: u8,
    now: u64,
    ca_private: &[u8],
    gateway_private: &[u8],
    gateway_public: &[u8],
) -> (
    RecoveryOperation,
    ClientCertificateRotationGrant,
    ClientCertificateStageCommit,
    PqCertificate,
    aether::certificates::encoding::MlDsa87PublicKey,
    aether::certificates::encoding::MlDsa87PublicKey,
    aether::certificates::encoding::DerCertificate,
    ClientCertificateStageAuthorization,
    Box<ExpiredRecoveryApprovalEvidence>,
) {
    let client = WireGuardKey::from_bytes([seed; 32]);
    let (old_private, old_public) = generate_ml_dsa_87_keypair().expect("old client key");
    let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("candidate key");
    let (tls_anchor, expired_tls_leaf, tls_leaf, tls_csr) = tls_material();
    let tls_anchor_fingerprint = tls_anchor.fingerprint();
    let old_leaf = signed_pq_leaf(
        ca_private,
        "workstation",
        "CA-PQ",
        PqCertificateRole::Client,
        client,
        old_public.as_bytes(),
        41,
    );
    let next_leaf = signed_pq_leaf(
        ca_private,
        "workstation",
        "CA-PQ",
        PqCertificateRole::Client,
        client,
        new_public.as_bytes(),
        42,
    );
    let gateway_leaf = signed_pq_leaf(
        ca_private,
        "gateway",
        "CA-PQ",
        PqCertificateRole::Gateway,
        WireGuardKey::from_bytes([12; 32]),
        gateway_public,
        43,
    );
    let mut request = request(seed);
    request.trust_domain_id = TrustDomainId::new([11; 16]).expect("domain");
    request.gateway_wg_public_key = WireGuardKey::from_bytes([12; 32]);
    request.server_name = "astra.example".into();
    request.expired_tls_certificate = expired_tls_leaf.clone();
    request.expired_pq_certificate = old_leaf.clone();
    request.expired_generation = 4;
    request.requested_generation = 5;
    request.created_at = now;
    request.expires_at = now + RECOVERY_LIFETIME_SECS;
    request.new_ml_dsa_87_public_key = new_public.clone();
    request.tls_csr = tls_csr;
    request.astra_challenge = [seed.wrapping_add(2); 32];
    request = Box::new(
        request
            .sign(&old_private, &new_private)
            .expect("signed expired recovery request"),
    );
    let request_fingerprint = request.fingerprint();
    let evidence = recovery_evidence(
        ca_private,
        request.trust_domain_id,
        request.gateway_wg_public_key,
        request_fingerprint,
        request.astra_challenge,
        now,
    );
    let stage_id = Id16::new([seed.wrapping_add(1); 16]).expect("stage id");
    let gateway_certificate_fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&gateway_leaf)
            .expect("gateway fingerprint");
    let mut receipt = GatewayCertificateStageReceipt {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: request.trust_domain_id,
        stage_id,
        stage_authorization_fingerprint: Fingerprint::of(b"stage authorization"),
        request_fingerprint,
        renewal_authorization_fingerprint: evidence.fingerprint().expect("approval fingerprint"),
        gateway_wg_public_key: request.gateway_wg_public_key,
        client_wg_public_key: client,
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: tls_leaf.fingerprint(),
        staged_pq_certificate_fingerprint:
            aether::certificates::gateway::pq_certificate_fingerprint(&next_leaf)
                .expect("candidate fingerprint"),
        persisted_at: now,
        stage_expires_at: now + 100,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint,
        gateway_signature: MlDsa87Signature::placeholder(),
    };
    let authorization = ClientCertificateStageAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: request.trust_domain_id,
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        stage_id,
        request_fingerprint,
        renewal_authorization_fingerprint: evidence.fingerprint().expect("approval fingerprint"),
        renewal_approval: None,
        campaign_approval: None,
        gateway_wg_public_key: request.gateway_wg_public_key,
        server_name: request.server_name.clone(),
        client_wg_public_key: client,
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: generation(
            4,
            &old_leaf,
            &tls_anchor,
            &expired_tls_leaf,
        )
        .tls_certificate_fingerprint,
        active_pq_certificate_fingerprint:
            aether::certificates::gateway::pq_certificate_fingerprint(&old_leaf)
                .expect("old fingerprint"),
        next_tls_ca_certificate_fingerprint: tls_anchor_fingerprint,
        next_tls_certificate: tls_leaf,
        next_pq_certificate: next_leaf.clone(),
        issued_at: now,
        stage_expires_at: now + 100,
        window: TransitionWindow::new(now - 1, now, now + 10_000).expect("window"),
        reason: aether::certificates::authority::RotationReason::ExpiredRecovery,
        signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("signed recovery authorization");
    authorization
        .verify(
            &service_ca_public(ca_private),
            &request.trust_domain_id,
            1,
            1,
            &request.gateway_wg_public_key,
            &request.server_name,
            &client,
            &generation(4, &old_leaf, &tls_anchor, &expired_tls_leaf),
            &[&tls_anchor],
            None,
            Some(request.expires_at),
            now,
        )
        .expect("valid signed recovery stage authorization");
    receipt.stage_authorization_fingerprint = authorization
        .fingerprint()
        .expect("authorization fingerprint");
    let receipt = receipt.sign(gateway_private).expect("signed stage receipt");
    receipt
        .verify(
            &aether::certificates::encoding::MlDsa87PublicKey::new(gateway_public.to_vec())
                .expect("gateway public key"),
            &aether::certificates::gateway::pq_certificate_fingerprint(&gateway_leaf)
                .expect("gateway fingerprint"),
            &authorization,
        )
        .expect("receipt answers authorization");
    let receipt_fingerprint = receipt.fingerprint();
    let grant = ClientCertificateRotationGrant {
        format_version: authorization.format_version,
        protocol_version: authorization.protocol_version,
        trust_domain_id: authorization.trust_domain_id,
        ca_epoch: authorization.ca_epoch,
        ca_tls_epoch: authorization.ca_tls_epoch,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
        issuer_authorization: None,
        request_fingerprint,
        renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: receipt_fingerprint,
        stage_receipt: receipt,
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        server_name: authorization.server_name.clone(),
        client_wg_public_key: client,
        active_generation: 4,
        next_generation: 5,
        active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
        next_tls_certificate: authorization.next_tls_certificate.clone(),
        next_pq_certificate: next_leaf.clone(),
        stage_expires_at: authorization.stage_expires_at,
        window: authorization.window,
        reason: authorization.reason,
        signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("signed recovery grant");
    grant
        .verify_signed_by(&service_ca_public(ca_private))
        .expect("grant signature");
    grant
        .verify_for_recovery(
            &service_ca_public(ca_private),
            &aether::certificates::encoding::MlDsa87PublicKey::new(gateway_public.to_vec())
                .expect("gateway public key"),
            &gateway_certificate_fingerprint,
            &request.trust_domain_id,
            1,
            1,
            &request.gateway_wg_public_key,
            &request.server_name,
            &client,
            &request,
            &[&tls_anchor],
            None,
            now + 1,
        )
        .expect("valid recovery grant for the historical request");
    let commit = ClientCertificateStageCommit {
        format_version: authorization.format_version,
        protocol_version: authorization.protocol_version,
        trust_domain_id: authorization.trust_domain_id,
        stage_id,
        grant_fingerprint: grant.fingerprint().expect("grant fingerprint"),
        stage_receipt_fingerprint: receipt_fingerprint,
        gateway_wg_public_key: authorization.gateway_wg_public_key,
        client_wg_public_key: client,
        active_generation: 4,
        staged_generation: 5,
        staged_tls_certificate_fingerprint: authorization.next_tls_certificate.fingerprint(),
        staged_pq_certificate_fingerprint:
            aether::certificates::gateway::pq_certificate_fingerprint(&next_leaf)
                .expect("candidate fingerprint"),
        stage_expires_at: authorization.stage_expires_at,
        committed_at: now,
        active_pq_signature: MlDsa87Signature::placeholder(),
        staged_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&old_private, &new_private)
    .expect("signed two-key commit");
    let operation = RecoveryOperation {
        operation_id: Id16::new([seed; 16]).expect("operation id"),
        request,
        request_fingerprint,
        state: ExpiredRecoveryState::AwaitingOperator,
        created_at: now,
        expires_at: now + RECOVERY_LIFETIME_SECS,
        authorization: None,
        receipt: None,
        gateway_pq_certificate: Some(Box::new(gateway_leaf.clone())),
        grant: None,
        accepted_commit: None,
    };
    let _old_generation = generation(4, &old_leaf, &tls_anchor, &expired_tls_leaf);
    (
        operation,
        grant,
        commit,
        gateway_leaf,
        old_public,
        new_public,
        tls_anchor,
        authorization,
        evidence,
    )
}

fn service_ca_public(private_key: &[u8]) -> aether::certificates::encoding::MlDsa87PublicKey {
    aether::certificates::encoding::derive_ml_dsa_87_public_key(private_key).expect("CA public key")
}

async fn bounded_commit(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    stage_commit: ClientCertificateStageCommit,
    now: u64,
) -> Result<ExpiredRecoveryOperationView, RecoveryError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        commit(service, operation_id, Box::new(stage_commit), now),
    )
    .await
    .expect("loopback private-channel commit completes within ten seconds")
}

struct RecoveryGatewayMaterial {
    ca_public: aether::certificates::encoding::MlDsa87PublicKey,
    gateway_public: aether::certificates::encoding::MlDsa87PublicKey,
    gateway_leaf: PqCertificate,
    old_client_public: aether::certificates::encoding::MlDsa87PublicKey,
    candidate_client_public: aether::certificates::encoding::MlDsa87PublicKey,
    tls_anchor: aether::certificates::encoding::DerCertificate,
    authorization: ClientCertificateStageAuthorization,
    receipt: GatewayCertificateStageReceipt,
}

async fn install_recovery_gateway(
    service: &mut Arc<AstraService>,
    directory: &tempfile::TempDir,
    operation: &RecoveryOperation,
    material: RecoveryGatewayMaterial,
    revoked: bool,
    now: u64,
) -> (
    Arc<RecoveryGateway>,
    crate::renewal::test_support::ServerTask,
) {
    let RecoveryGatewayMaterial {
        ca_public,
        gateway_public,
        gateway_leaf,
        old_client_public,
        candidate_client_public,
        tls_anchor,
        authorization,
        receipt,
    } = material;
    let client = operation.request.client_wg_public_key;
    let old_leaf = operation.request.expired_pq_certificate.clone();
    let old_tls_leaf = operation.request.expired_tls_certificate.clone();
    let old_generation = generation(4, &old_leaf, &tls_anchor, &old_tls_leaf);
    let gateway_certificate_fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&gateway_leaf)
            .expect("gateway fingerprint");
    let handler = Arc::new(RecoveryGateway {
        peer: client,
        peer_view: Mutex::new(astra_channel::PeerCertificateStateView {
            name: "workstation".into(),
            state: ClientCertificateState::new(old_generation.clone()),
            active_pq_certificate: old_leaf.clone(),
            admission_pq_ca: None,
        }),
        stage_calls: std::sync::atomic::AtomicUsize::new(0),
        commit_fingerprints: Mutex::new(Vec::new()),
        lose_first_reply: std::sync::atomic::AtomicBool::new(true),
        gateway_leaf,
        ca_public,
        gateway_public,
        gateway_certificate_fingerprint,
        tls_anchor,
        active_generation: old_generation.clone(),
        old_client_public,
        candidate_client_public,
        expected_authorization: authorization,
        stage_receipt: receipt,
    });
    let (gateway, server_task) =
        crate::renewal::test_support::channel(directory.path(), handler.clone()).await;
    Arc::get_mut(service)
        .expect("unique service before test calls")
        .gateway = Some(gateway);
    {
        let mut registry = service.registry.lock().await;
        registry
            .admit(
                crate::registry::PeerRecord {
                    name: "workstation".into(),
                    client_wg_public_key: client,
                    active: old_generation,
                    active_pq_certificate: old_leaf,
                    pending: None,
                    revoked: false,
                    revocation_epoch: 0,
                    admission_pq_ca: None,
                },
                now,
            )
            .expect("record admitted identity");
        if revoked {
            registry
                .revoke(&client, 1, now)
                .expect("revoke admitted identity");
        }
    }
    if revoked {
        handler.peer_view.lock().await.state.revoke(1);
    }
    (handler, server_task)
}

#[tokio::test]
async fn a_commit_applied_before_a_lost_reply_is_replayed_and_reconciled() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let now = 10_000;
        let (mut service, directory, ca_private) = service();
        let (gateway_private, gateway_public) =
            generate_ml_dsa_87_keypair().expect("gateway signing key");
        let (
            operation,
            stage_grant,
            stage_commit,
            gateway_leaf,
            old_client_public,
            candidate_client_public,
            tls_anchor,
            stage_authorization,
            approval_evidence,
        ) = granted_recovery(
            31,
            now,
            &ca_private,
            &gateway_private,
            gateway_public.as_bytes(),
        );
        let client = operation.request.client_wg_public_key;
        let (handler, _server_task) = install_recovery_gateway(
            &mut service,
            &directory,
            &operation,
            RecoveryGatewayMaterial {
                ca_public: service_ca_public(&ca_private),
                gateway_public,
                gateway_leaf,
                old_client_public,
                candidate_client_public,
                tls_anchor,
                authorization: stage_authorization.clone(),
                receipt: stage_grant.stage_receipt.clone(),
            },
            false,
            now,
        )
        .await;
        assert!(service
            .challenges
            .lock()
            .await
            .issue(operation.request.astra_challenge, now));
        let opened = open(&service, operation.request.clone(), now)
            .await
            .expect("signed expired identity request opens recovery");
        assert_eq!(opened.state, ExpiredRecoveryState::AwaitingOperator);
        let operation_id = opened.operation_id;
        let (mut out_of_scope, invalid_evidence) = authorization_documents();
        out_of_scope.issuer_kind = IssuerKind::Astra;
        out_of_scope.reason = aether::certificates::authority::RotationReason::Scheduled;
        assert!(matches!(
            authorize(
                &service,
                &operation_id,
                out_of_scope,
                invalid_evidence,
                now + 1,
            )
            .await,
            Err(RecoveryError::Certificate(
                aether::certificates::CertificateError::IssuerScopeViolation(_)
            ))
        ));
        assert_eq!(
            service
                .recoveries
                .lock()
                .await
                .get(&operation_id, now + 1)
                .expect("unapproved recovery remains available")
                .state,
            ExpiredRecoveryState::AwaitingOperator
        );
        let audit_before_invalid_evidence =
            service.registry.lock().await.state().audit.records.clone();
        let mut wrong_origin = approval_evidence.clone();
        wrong_origin.webauthn_origin = "https://attacker.example".into();
        let mut wrong_domain = approval_evidence.clone();
        wrong_domain.credential_registry.trust_domain_id =
            TrustDomainId::new([0x77; 16]).expect("other trust domain");
        for invalid_evidence in [wrong_origin, wrong_domain] {
            assert!(matches!(
                authorize(
                    &service,
                    &operation_id,
                    Box::new(stage_authorization.clone()),
                    invalid_evidence,
                    now + 1,
                )
                .await,
                Err(RecoveryError::Certificate(_))
            ));
        }
        assert_eq!(
            service
                .recoveries
                .lock()
                .await
                .get(&operation_id, now + 1)
                .expect("invalid evidence leaves recovery awaiting the operator")
                .state,
            ExpiredRecoveryState::AwaitingOperator
        );
        assert_eq!(
            handler
                .stage_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "invalid approval evidence is refused before gateway staging"
        );
        assert_eq!(
            service.registry.lock().await.state().audit.records,
            audit_before_invalid_evidence,
            "invalid approval evidence does not append an approval audit event"
        );
        assert!(!directory
            .path()
            .join(crate::reconciliation::RECONCILIATION_FILE)
            .exists());
        let staged = authorize(
            &service,
            &operation_id,
            Box::new(stage_authorization),
            approval_evidence,
            now + 1,
        )
        .await
        .expect("valid operator assertion authorizes recovery staging");
        assert_eq!(staged.state, ExpiredRecoveryState::Staged);
        let audit_before_invalid_grant =
            service.registry.lock().await.state().audit.records.clone();
        let mut mismatched_grant = stage_grant.clone();
        mismatched_grant.stage_receipt_fingerprint = Fingerprint::of(b"different receipt");
        assert!(matches!(
            grant(&service, &operation_id, Box::new(mismatched_grant), now + 1).await,
            Err(RecoveryError::Certificate(
                aether::certificates::CertificateError::ApprovalMismatch(_)
            ))
        ));
        assert_eq!(
            service
                .recoveries
                .lock()
                .await
                .get(&operation_id, now + 1)
                .expect("failed grant leaves staged operation")
                .state,
            ExpiredRecoveryState::Staged
        );
        assert_eq!(
            service.registry.lock().await.state().audit.records,
            audit_before_invalid_grant,
            "mismatched grant does not append an approval audit event"
        );
        assert!(!directory
            .path()
            .join(crate::reconciliation::RECONCILIATION_FILE)
            .exists());
        let granted = grant(&service, &operation_id, Box::new(stage_grant), now)
            .await
            .expect("release signed grant after receipt");
        assert_eq!(granted.state, ExpiredRecoveryState::Granted);

        assert!(matches!(
            bounded_commit(&service, &operation_id, stage_commit.clone(), now + 1).await,
            Err(RecoveryError::Gateway(_))
        ));
        let pending = crate::reconciliation::load(directory.path()).expect("durable intent");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].peer, client);
        assert_eq!(pending[0].expected_generation, 5);
        assert_eq!(
            service
                .recoveries
                .lock()
                .await
                .get(&operation_id, now + 1)
                .unwrap()
                .state,
            ExpiredRecoveryState::Granted
        );

        let committed = bounded_commit(&service, &operation_id, stage_commit.clone(), now + 2)
            .await
            .expect("idempotent replay after lost gateway response");
        assert_eq!(committed.state, ExpiredRecoveryState::Committed);
        assert!(crate::reconciliation::load(directory.path())
            .expect("reconciliation completes")
            .is_empty());
        assert_eq!(
            service
                .registry
                .lock()
                .await
                .peer(&client)
                .expect("adopted peer")
                .active
                .generation,
            5
        );
        let commits = handler.commit_fingerprints.lock().await;
        assert_eq!(commits.len(), 2, "only the exact commit was replayed");
        assert!(commits[0].matches(&commits[1]));
        drop(commits);

        assert_eq!(
            bounded_commit(&service, &operation_id, stage_commit.clone(), now + 3)
                .await
                .expect("retry after Astra response loss returns the same committed operation")
                .state,
            ExpiredRecoveryState::Committed
        );

        let mut changed_time = stage_commit.clone();
        changed_time.committed_at += 1;
        assert!(matches!(
            bounded_commit(&service, &operation_id, changed_time, now + 4).await,
            Err(RecoveryError::WrongState)
        ));
        let mut changed_signature = stage_commit.clone();
        changed_signature.active_pq_signature = MlDsa87Signature::placeholder();
        assert!(matches!(
            bounded_commit(&service, &operation_id, changed_signature, now + 5).await,
            Err(RecoveryError::WrongState)
        ));
        assert!(matches!(
            bounded_commit(
                &service,
                &operation_id,
                stage_commit,
                now + RECOVERY_LIFETIME_SECS
            )
            .await,
            Err(RecoveryError::Expired)
        ));
        assert_eq!(
            handler.commit_fingerprints.lock().await.len(),
            2,
            "rejected replays do not reach the gateway"
        );
    })
    .await
    .expect("the complete recovery workflow finishes within fifteen seconds");
}

#[tokio::test]
async fn a_revoked_peer_cannot_open_expired_recovery() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let now = 12_000;
        let (mut service, directory, ca_private) = service();
        let (gateway_private, gateway_public) =
            generate_ml_dsa_87_keypair().expect("gateway signing key");
        let (
            operation,
            stage_grant,
            _stage_commit,
            gateway_leaf,
            old_client_public,
            candidate_client_public,
            tls_anchor,
            stage_authorization,
            _approval_evidence,
        ) = granted_recovery(
            32,
            now,
            &ca_private,
            &gateway_private,
            gateway_public.as_bytes(),
        );
        let client = operation.request.client_wg_public_key;
        let (handler, _server_task) = install_recovery_gateway(
            &mut service,
            &directory,
            &operation,
            RecoveryGatewayMaterial {
                ca_public: service_ca_public(&ca_private),
                gateway_public,
                gateway_leaf,
                old_client_public,
                candidate_client_public,
                tls_anchor,
                authorization: stage_authorization.clone(),
                receipt: stage_grant.stage_receipt.clone(),
            },
            true,
            now,
        )
        .await;
        let audit_before_open = service.registry.lock().await.state().audit.records.clone();
        assert!(service
            .challenges
            .lock()
            .await
            .issue(operation.request.astra_challenge, now));
        let open_result = open(&service, operation.request.clone(), now).await;
        assert!(
            matches!(open_result, Err(RecoveryError::Revoked)),
            "revoked recovery open returned {open_result:?}"
        );
        assert!(service.recoveries.lock().await.is_empty());
        assert_eq!(
            service.registry.lock().await.state().audit.records,
            audit_before_open,
            "a refused recovery does not append a recovery audit event"
        );
        assert!(handler.peer_view.lock().await.state.revoked);
        assert_eq!(
            handler
                .stage_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(!directory
            .path()
            .join(crate::reconciliation::RECONCILIATION_FILE)
            .exists());
        assert!(
            service
                .registry
                .lock()
                .await
                .peer(&client)
                .expect("revoked peer remains recorded")
                .revoked
        );
    })
    .await
    .expect("revoked-peer recovery workflow finishes within fifteen seconds");
}

#[tokio::test]
async fn recovery_commit_cannot_skip_the_operator_and_grant_steps() {
    let (service, directory, _) = service();
    let now = 2_000;
    let operation = operation(13, now);
    let id = operation.operation_id;
    service
        .recoveries
        .lock()
        .await
        .open(operation, now)
        .expect("open recovery");

    assert!(matches!(
        commit(&service, &id, Box::new(commit_document()), now + 1,).await,
        Err(RecoveryError::WrongState)
    ));
    let recoveries = service.recoveries.lock().await;
    let stored = recoveries.get(&id, now + 1).expect("stored operation");
    assert_eq!(stored.state, ExpiredRecoveryState::AwaitingOperator);
    assert!(stored.grant.is_none());
    assert!(!directory
        .path()
        .join(crate::reconciliation::RECONCILIATION_FILE)
        .exists());
}

#[tokio::test]
async fn expired_recovery_cannot_resume_at_a_later_step() {
    let (service, _directory, _) = service();
    let now = 3_000;
    let mut operation = operation(14, now);
    operation.expires_at = now + 1;
    let id = operation.operation_id;
    service
        .recoveries
        .lock()
        .await
        .open(operation, now)
        .expect("open recovery");

    assert!(matches!(
        commit(&service, &id, Box::new(commit_document()), now + 1,).await,
        Err(RecoveryError::Expired)
    ));
}
