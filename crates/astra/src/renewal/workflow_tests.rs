//! Renewal orchestration over a real pinned private channel, with public test keys.

mod companion;
mod concurrency;
mod router;

use super::*;
use aether::certificates::{
    approval::{AstraIssuancePolicy, AstraPolicyPin},
    authority::{AllowedUsage, AstraIssuerAuthorization},
    client::{
        ClientCertificateGeneration, ClientCertificateStageAuthorization,
        GatewayCertificateStageReceipt,
    },
    encoding::{generate_ml_dsa_87_keypair, DerCertificate, TrustDomainId},
    gateway::pq_certificate_fingerprint,
    state::{ClientCertificateState, TrustLedger},
    transport::{ClientRenewalOperationState, TrustUpdateRefusal},
    CertificateError, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use astra_channel::{
    AstraChannelHandler, AstraStageHandler, GatewayIdentityView, PeerCertificateStateView,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::sync::RwLock;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const NOW: u64 = 800_000;
const SERVER_NAME: &str = "gateway.example";
const LOSE_STAGE_REPLY: u8 = 1;
const WRONG_RECEIPT: u8 = 2;
const WRONG_SERVED_FINGERPRINT: u8 = 3;
const BLOCK_GRANT_JOURNAL: u8 = 4;

fn domain() -> TrustDomainId {
    TrustDomainId::new([0x71; 16]).expect("domain")
}
fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x72; 32])
}
fn client_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x73; 32])
}

fn pq_leaf(
    ca: &[u8],
    subject: &MlDsa87PublicKey,
    role: PqCertificateRole,
    identity: WireGuardKey,
    serial: u8,
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: if role == PqCertificateRole::Gateway {
                SERVER_NAME.into()
            } else {
                "workstation".into()
            },
            issuer: "CA-PQ".into(),
            role,
            wireguard_public_key: identity.to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        ca,
    )
    .expect("signed PQ leaf")
}

fn tls_material() -> (DerCertificate, Zeroizing<Vec<u8>>, DerCertificate) {
    let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.not_before = rcgen::date_time_ymd(1970, 1, 1);
    ca.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let key = KeyPair::generate().expect("TLS issuer key");
    let certificate = ca.self_signed(&key).expect("intermediate certificate");
    let mut leaf = CertificateParams::new(Vec::<String>::new()).expect("leaf parameters");
    leaf.is_ca = IsCa::NoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_key = KeyPair::generate().expect("candidate TLS key");
    let csr = leaf.serialize_request(&leaf_key).expect("candidate CSR");
    (
        DerCertificate::new(certificate.der().to_vec()).expect("intermediate DER"),
        Zeroizing::new(key.serialize_der()),
        DerCertificate::new(csr.der().to_vec()).expect("CSR DER"),
    )
}

/// The lifecycle state is a test double; its transport, signatures and state
/// transitions are the shipped implementations. No kernel integration is claimed.
struct Gateway {
    view: Mutex<PeerCertificateStateView>,
    ca_public: MlDsa87PublicKey,
    anchor: DerCertificate,
    policy: AstraPolicyPin,
    gateway_leaf: PqCertificate,
    gateway_private: Zeroizing<Vec<u8>>,
    stages: Mutex<Vec<ClientCertificateStageAuthorization>>,
    stage_calls: AtomicUsize,
    fault: AtomicU8,
    state_path: PathBuf,
    journal_path: PathBuf,
    stage_gate: Mutex<Option<Arc<TestGate>>>,
    identity_gate: Mutex<Option<Arc<TestGate>>>,
}

/// A deterministic test pause with counted permits for concurrent handlers.
/// The test can wait for entry even when a handler reaches the gate first.
struct TestGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl TestGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        })
    }

    async fn pause(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("test gate semaphore remains open")
            .forget();
    }

    async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("test gate semaphore remains open")
            .forget();
    }

    fn open(&self) {
        self.release.add_permits(1);
    }
}

impl Gateway {
    fn receipt(
        &self,
        authorization: &ClientCertificateStageAuthorization,
    ) -> GatewayCertificateStageReceipt {
        let candidate = authorization.candidate().expect("candidate");
        GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id: authorization.stage_id,
            stage_authorization_fingerprint: authorization
                .fingerprint()
                .expect("authorization fingerprint"),
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: authorization.active_generation,
            staged_generation: authorization.next_generation,
            staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
            persisted_at: NOW,
            stage_expires_at: authorization.stage_expires_at,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            gateway_certificate_fingerprint: pq_certificate_fingerprint(&self.gateway_leaf)
                .expect("gateway leaf fingerprint"),
            gateway_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.gateway_private)
        .expect("signed receipt")
    }
}

#[async_trait]
impl AstraStageHandler for Gateway {
    async fn stage_from_astra(
        &self,
        authorization: Box<ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        self.stage_calls.fetch_add(1, Ordering::SeqCst);
        let mut view = self.view.lock().await;
        authorization
            .verify(
                &self.ca_public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &view.state.active,
                &[&self.anchor],
                Some(&self.policy),
                None,
                NOW,
            )
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        view.state
            .stage(&authorization, &TrustLedger::default(), NOW)
            .map_err(|_| TrustUpdateRefusal::Rejected)?;
        aether::private_file::write_private_atomic(
            &self.state_path,
            &serde_json::to_vec(&view.state).expect("gateway state"),
        )
        .map_err(|_| TrustUpdateRefusal::Internal)?;
        drop(view);
        self.stages.lock().await.push((*authorization).clone());
        let gate = self.stage_gate.lock().await.clone();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        if self.fault.load(Ordering::SeqCst) == BLOCK_GRANT_JOURNAL {
            let backup = self
                .journal_path
                .with_file_name("operations-before-failure.json");
            std::fs::rename(&self.journal_path, backup).expect("preserve pre-grant journal");
            std::fs::create_dir(&self.journal_path).expect("obstruct grant publication");
        }
        if self.fault.load(Ordering::SeqCst) == LOSE_STAGE_REPLY {
            self.fault.store(0, Ordering::SeqCst);
            return Err(TrustUpdateRefusal::Unavailable);
        }
        let mut receipt = self.receipt(&authorization);
        if self.fault.load(Ordering::SeqCst) == WRONG_RECEIPT {
            receipt.staged_generation += 1;
            receipt = receipt
                .sign(&self.gateway_private)
                .expect("wrong but signed receipt");
        }
        Ok(Box::new(receipt))
    }
}

#[async_trait]
impl AstraChannelHandler for Gateway {
    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, TrustUpdateRefusal> {
        if *identity != client_key() {
            return Err(TrustUpdateRefusal::Rejected);
        }
        Ok(self.view.lock().await.clone())
    }
    async fn peer_keys(&self) -> Result<Vec<WireGuardKey>, TrustUpdateRefusal> {
        Ok(Vec::new())
    }

    async fn gateway_identity(&self) -> Result<GatewayIdentityView, TrustUpdateRefusal> {
        let gate = self.identity_gate.lock().await.clone();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        Ok(GatewayIdentityView {
            pq_certificate_fingerprint: if self.fault.load(Ordering::SeqCst)
                == WRONG_SERVED_FINGERPRINT
            {
                Fingerprint::of(b"different served identity")
            } else {
                pq_certificate_fingerprint(&self.gateway_leaf).expect("gateway fingerprint")
            },
            pq_certificate: self.gateway_leaf.clone(),
            tls_certificate_fingerprint: Fingerprint::of(b"gateway TLS"),
            tls_certificate_not_after: 1_000_000,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
        })
    }
    async fn revoke(
        &self,
        _: Box<aether::certificates::revocation::EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }
    async fn gateway_transition_published(
        &self,
        _: astra_channel::GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }
    async fn distribute(
        &self,
        _: Box<astra_channel::TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }
    async fn commit_recovery(
        &self,
        _: Box<astra_channel::RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }
}

struct Fixture {
    ca_private: Zeroizing<Vec<u8>>,
    /// The private half of the pinned TLS intermediate, kept so a later
    /// delegation can reuse the chain the gateway already trusts.
    intermediate_private: Zeroizing<Vec<u8>>,
    service: Arc<AstraService>,
    gateway: Arc<Gateway>,
    request: ClientCertificateRotationRequest,
    _listener: super::test_support::ServerTask,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn operations_path(&self) -> PathBuf {
        self.directory.path().join("operations.json")
    }
    fn registry_path(&self) -> PathBuf {
        self.directory.path().join("astra.json")
    }
    fn operation_id(&self) -> Id16 {
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.operations_path()).expect("operation journal"),
        )
        .expect("journal JSON");
        serde_json::from_value(value["operations"][0]["operation_id"].clone())
            .expect("operation ID")
    }
    async fn reload(&self) {
        *self.service.operations.lock().await =
            crate::operations::OperationStore::load(&self.operations_path(), NOW + 1)
                .expect("reload operation journal");
        *self.service.registry.lock().await =
            crate::registry::AstraRegistry::load(&self.registry_path(), None)
                .expect("reload registry");
        *self.service.capabilities.lock().await =
            aether::certificates::capability::CapabilityTokens::new()
                .expect("new process capabilities");
    }
    async fn open(&self, now: u64) -> Result<ClientRenewalOperationView, RenewalError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            open(
                &self.service,
                &client_key(),
                Box::new(self.request.clone()),
                now,
            ),
        )
        .await
        .expect("renewal call completed")
    }
    async fn read(&self, id: &Id16) -> Result<ClientRenewalOperationView, RenewalError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            read(&self.service, &client_key(), id, NOW + 1),
        )
        .await
        .expect("renewal poll completed")
    }
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("state directory");
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("master key");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer key");
    let (active_private, active_public) = generate_ml_dsa_87_keypair().expect("active key");
    let (candidate_private, candidate_public) =
        generate_ml_dsa_87_keypair().expect("candidate key");
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service key");
    let (anchor, intermediate_private, csr) = tls_material();
    let policy = AstraPolicyPin::new(
        AstraIssuancePolicy::standard(domain(), gateway_key(), SERVER_NAME.into())
            .fingerprint()
            .expect("policy"),
    )
    .expect("pin");
    let authorization = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: anchor.clone(),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 2_000_000,
        policy_fingerprint: *policy.fingerprint(),
        not_before: 0,
        not_after: 10_000_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("delegation");
    let active_leaf = pq_leaf(
        &ca_private,
        &active_public,
        PqCertificateRole::Client,
        client_key(),
        0x75,
    );
    let active = ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: anchor.fingerprint(),
        tls_certificate_fingerprint: Fingerprint::of(b"active TLS leaf"),
        pq_certificate_fingerprint: pq_certificate_fingerprint(&active_leaf)
            .expect("active fingerprint"),
        not_before: 0,
        not_after: 1_000_000,
    };
    let request = ClientCertificateRotationRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([0x76; 16]).expect("request ID"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: active.generation,
        requested_generation: active.generation + 1,
        active_tls_certificate_fingerprint: active.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
        tls_csr: csr,
        new_ml_dsa_87_public_key: candidate_public,
        created_at: NOW - 10,
        expires_at: NOW + 7_200,
        active_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&active_private, &candidate_private)
    .expect("signed client request");
    let gateway = Arc::new(Gateway {
        view: Mutex::new(PeerCertificateStateView {
            name: "workstation".into(),
            state: ClientCertificateState::new(active),
            active_pq_certificate: active_leaf,
            admission_pq_ca: None,
        }),
        ca_public: ca_public.clone(),
        anchor: anchor.clone(),
        policy,
        gateway_leaf: pq_leaf(
            &ca_private,
            &gateway_public,
            PqCertificateRole::Gateway,
            gateway_key(),
            0x77,
        ),
        gateway_private,
        stages: Mutex::new(Vec::new()),
        stage_calls: AtomicUsize::new(0),
        fault: AtomicU8::new(0),
        state_path: directory.path().join("gateway-state.json"),
        journal_path: directory.path().join("operations.json"),
        stage_gate: Mutex::new(None),
        identity_gate: Mutex::new(None),
    });
    let handler: Arc<dyn AstraChannelHandler> = gateway.clone();
    let (channel, listener) = super::test_support::channel(directory.path(), handler).await;
    let registry = crate::registry::AstraRegistry::new(
        directory.path().join("astra.json"),
        crate::registry::AstraState {
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: policy,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            ca_public_key: ca_public,
            ca_rotation: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: Some(anchor.fingerprint()),
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
    registry.save().expect("initial registry");
    let operations =
        crate::operations::OperationStore::load(&directory.path().join("operations.json"), NOW)
            .expect("initial operations");
    let service = Arc::new(AstraService {
        registry: Mutex::new(registry),
        issuer: RwLock::new(Some(Arc::new(crate::DelegatedIssuer::new(
            authorization,
            issuer_private,
            intermediate_private.clone(),
        )))),
        challenges: Mutex::new(crate::registry::ChallengeStore::with_capacity(4)),
        budgets: Mutex::new(crate::service::SourceBudget::default()),
        service_private_key: service_private,
        service_public_key: service_public,
        operations: Mutex::new(operations),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new().expect("capability key"),
        ),
        approval_credentials: RwLock::new(Arc::new(crate::service::ApprovalCredentials {
            ids: vec![vec![1]],
            epoch: 1,
            registry: None,
        })),
        signing: Mutex::new(crate::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(crate::recovery::RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault: RwLock::new(None),
        state_dir: directory.path().to_path_buf(),
        gateway: Some(channel),
        volume_writes: crate::door::VolumeWrites::new(),
    });
    Fixture {
        ca_private,
        intermediate_private,
        service,
        gateway,
        request,
        _listener: listener,
        directory,
    }
}

/// Seals fresh private halves for `epoch` under the fixture's state volume and
/// records a delegation naming them, as a campaign deposit does.
async fn record_delegation(fixture: &Fixture, epoch: u64) {
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer key");
    let authorization = AstraIssuerAuthorization {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        issuer_epoch: epoch,
        pq_issuer_public_key: issuer_public,
        tls_intermediate_certificate: fixture.gateway.anchor.clone(),
        allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 2_000_000,
        policy_fingerprint: *fixture.gateway.policy.fingerprint(),
        not_before: 0,
        not_after: 10_000_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&fixture.ca_private)
    .expect("delegation");
    let dir = fixture.directory.path();
    std::fs::write(
        crate::issuer::pq_key_path(dir, epoch),
        issuer_private.as_slice(),
    )
    .expect("pq key");
    std::fs::write(
        crate::issuer::tls_key_path(dir, epoch),
        fixture.intermediate_private.as_slice(),
    )
    .expect("tls key");
    crate::issuer::adopt(
        &mut *fixture.service.registry.lock().await,
        authorization,
        &crate::issuer::pq_key_path(dir, epoch),
        &crate::issuer::tls_key_path(dir, epoch),
        NOW,
    )
    .expect("delegation recorded");
}

#[tokio::test]
async fn a_campaign_delegation_issues_without_a_restart() {
    let fixture = fixture().await;
    assert_eq!(
        fixture
            .service
            .issuer()
            .expect("issuer")
            .authorization
            .issuer_epoch,
        1
    );
    record_delegation(&fixture, 2).await;
    let adopted = {
        let registry = fixture.service.registry.lock().await;
        fixture.service.adopt_recorded_issuer(&registry)
    };
    assert!(adopted);
    let view = fixture
        .open(NOW)
        .await
        .expect("issuance under the new epoch");
    assert_eq!(view.grant.as_ref().expect("grant").issuer_epoch, 2);
}

#[tokio::test]
async fn a_failed_adoption_keeps_the_issuer_in_service() {
    let fixture = fixture().await;
    record_delegation(&fixture, 2).await;
    let dir = fixture.directory.path();
    std::fs::remove_file(crate::issuer::pq_key_path(dir, 2)).expect("remove key");
    std::fs::remove_file(crate::issuer::tls_key_path(dir, 2)).expect("remove key");
    let adopted = {
        let registry = fixture.service.registry.lock().await;
        fixture.service.adopt_recorded_issuer(&registry)
    };
    assert!(!adopted);
    assert_eq!(
        fixture
            .service
            .issuer()
            .expect("still serving")
            .authorization
            .issuer_epoch,
        1
    );
    let view = fixture
        .open(NOW)
        .await
        .expect("issuance under the old epoch");
    assert_eq!(view.grant.as_ref().expect("grant").issuer_epoch, 1);
}

#[tokio::test]
async fn automatic_renewal_releases_a_verified_durable_grant_without_a_gesture() {
    let fixture = fixture().await;
    let view = fixture.open(NOW).await.expect("due renewal");
    assert_eq!(view.state, ClientRenewalOperationState::PendingCommit);
    let grant = view.grant.as_ref().expect("released grant");
    assert_eq!(grant.issuer_kind, IssuerKind::Astra);
    assert!(grant.renewal_approval.is_none());
    assert!(grant.campaign_approval.is_none());
    assert_eq!(grant.next_generation, 5);
    assert_eq!(grant.request_fingerprint, fixture.request.fingerprint());
    let gateway_public =
        MlDsa87PublicKey::parse(&fixture.gateway.gateway_leaf.ml_dsa_87_public_key)
            .expect("gateway public");
    grant
        .verify(
            &fixture.gateway.ca_public,
            &gateway_public,
            &pq_certificate_fingerprint(&fixture.gateway.gateway_leaf)
                .expect("gateway fingerprint"),
            &domain(),
            1,
            1,
            &gateway_key(),
            SERVER_NAME,
            &client_key(),
            &fixture.request,
            &[&fixture.gateway.anchor],
            Some(&fixture.gateway.policy),
            NOW,
        )
        .expect("client verification of released grant");
    assert!(fixture.gateway.state_path.is_file());
    assert_eq!(fixture.gateway.stages.lock().await.len(), 1);
    assert!(
        fixture
            .service
            .registry
            .lock()
            .await
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("rotation")
            .granted
    );
    fixture.reload().await;
    let replay = fixture
        .read(&view.operation_id)
        .await
        .expect("durable grant poll");
    assert_eq!(replay.grant, view.grant);
    assert_eq!(
        fixture.gateway.stages.lock().await.len(),
        1,
        "grant polling does not restage"
    );
    assert!(matches!(
        fixture.open(NOW + 1).await,
        Err(RenewalError::Operation(OperationError::AlreadyInFlight))
    ));
}

#[tokio::test]
async fn a_lost_stage_reply_replays_the_exact_durable_authorization_after_restart() {
    let fixture = fixture().await;
    fixture
        .gateway
        .fault
        .store(LOSE_STAGE_REPLY, Ordering::SeqCst);
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Gateway(_))
    ));
    let id = fixture.operation_id();
    let issued = fixture.gateway.stages.lock().await[0].clone();
    let pending = crate::operations::OperationStore::load(&fixture.operations_path(), NOW)
        .expect("durable pending");
    let operation = pending
        .get(&id, &client_key(), NOW)
        .expect("pending operation");
    assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
    assert_eq!(operation.stage_authorization(), Some(&issued));
    assert!(operation.receipt().is_none());
    assert!(operation.view(None, None).grant.is_none());
    assert!(
        !fixture
            .service
            .registry
            .lock()
            .await
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("rotation")
            .granted
    );
    fixture.reload().await;
    // Reload the gateway's persisted lifecycle state too, rather than letting
    // its in-memory reservation provide the idempotency this test proves.
    let durable_state: ClientCertificateState = serde_json::from_slice(
        &std::fs::read(&fixture.gateway.state_path).expect("persisted gateway stage"),
    )
    .expect("gateway state JSON");
    {
        let mut view = fixture.gateway.view.lock().await;
        view.state = ClientCertificateState::new(view.state.active.clone());
        assert!(view.state.pending.is_none());
        view.state = durable_state;
        assert_eq!(
            view.state
                .pending
                .as_ref()
                .expect("reloaded stage")
                .stage_id,
            issued.stage_id
        );
    }
    let completed = fixture.read(&id).await.expect("retry pending stage");
    assert_eq!(completed.state, ClientRenewalOperationState::PendingCommit);
    let stages = fixture.gateway.stages.lock().await;
    assert_eq!(stages.len(), 2);
    assert_eq!(
        stages[0], stages[1],
        "no reissuance or fresh random material on retry"
    );
    assert_eq!(
        completed
            .grant
            .as_ref()
            .expect("grant")
            .stage_receipt
            .stage_authorization_fingerprint,
        issued.fingerprint().expect("fingerprint")
    );
}

/// Persists precisely the journal side of a cut before the registry audit bit.
async fn released_before_registry(fixture: &Fixture) -> Id16 {
    fixture
        .gateway
        .fault
        .store(LOSE_STAGE_REPLY, Ordering::SeqCst);
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Gateway(_))
    ));
    let id = fixture.operation_id();
    let authorization = fixture.gateway.stages.lock().await[0].clone();
    let receipt = fixture.gateway.receipt(&authorization);
    let key = MlDsa87PublicKey::parse(&fixture.gateway.gateway_leaf.ml_dsa_87_public_key)
        .expect("gateway public");
    let grant = fixture
        .service
        .issuer()
        .expect("issuer")
        .release_grant(
            &authorization,
            &receipt,
            &key,
            &pq_certificate_fingerprint(&fixture.gateway.gateway_leaf)
                .expect("gateway fingerprint"),
        )
        .expect("grant");
    let mut operations = fixture.service.operations.lock().await;
    let operation = operations
        .get_mut(&id, &client_key(), NOW)
        .expect("operation");
    operation
        .record_receipt(Box::new(receipt))
        .expect("receipt");
    operation.record_grant(Box::new(grant)).expect("grant");
    operations
        .persist()
        .expect("publish journal before audit bit");
    id
}

#[tokio::test]
async fn a_released_grant_repairs_only_its_exact_registry_stage_after_restart() {
    let fixture = fixture().await;
    let id = released_before_registry(&fixture).await;
    assert!(
        !fixture
            .service
            .registry
            .lock()
            .await
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("rotation")
            .granted
    );
    fixture.reload().await;
    let view = fixture.read(&id).await.expect("repair publication cut");
    let grant = view.grant.expect("grant survives publication cut");
    assert_eq!(fixture.gateway.stages.lock().await.len(), 1);
    let registry = crate::registry::AstraRegistry::load(&fixture.registry_path(), None)
        .expect("durable registry");
    assert!(
        registry
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("rotation")
            .granted
    );
    assert_eq!(
        fixture
            .read(&id)
            .await
            .expect("idempotent repair")
            .grant
            .as_deref(),
        Some(grant.as_ref())
    );
}

#[tokio::test]
async fn publication_repair_refuses_a_different_stage_without_withdrawing_the_grant() {
    let fixture = fixture().await;
    let id = released_before_registry(&fixture).await;
    let journal_before = std::fs::read(fixture.operations_path()).expect("journal");
    {
        let mut registry = fixture.service.registry.lock().await;
        let mut state = registry.state().clone();
        state
            .peers
            .get_mut(&client_key().to_base64())
            .expect("peer")
            .pending
            .as_mut()
            .expect("rotation")
            .stage_id = Id16::new([0x7a; 16]).expect("other stage");
        *registry = crate::registry::AstraRegistry::new(fixture.registry_path(), state);
        registry.save().expect("simulate divergent registry");
    }
    assert!(matches!(
        fixture.read(&id).await,
        Err(RenewalError::Operation(OperationError::Corrupt(
            "grant and registry name different stages"
        )))
    ));
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("journal"),
        journal_before
    );
    let operations = crate::operations::OperationStore::load(&fixture.operations_path(), NOW + 1)
        .expect("grant journal remains valid");
    assert!(operations
        .get(&id, &client_key(), NOW + 1)
        .expect("operation")
        .view(None, None)
        .grant
        .is_some());
}

#[tokio::test]
async fn wrong_receipt_or_served_identity_never_releases_a_grant() {
    for fault in [WRONG_RECEIPT, WRONG_SERVED_FINGERPRINT] {
        let fixture = fixture().await;
        fixture.gateway.fault.store(fault, Ordering::SeqCst);
        let error = fixture
            .open(NOW)
            .await
            .expect_err("invalid gateway evidence refused");
        match fault {
            WRONG_RECEIPT => assert!(matches!(
                error,
                RenewalError::Issuer(crate::issuer::IssuerError::ReceiptMismatch)
            )),
            _ => assert!(
                matches!(error, RenewalError::Gateway(ref reason) if reason.contains("the gateway's leaf and the fingerprint"))
            ),
        }
        let id = fixture.operation_id();
        let operations = crate::operations::OperationStore::load(&fixture.operations_path(), NOW)
            .expect("pending journal");
        let operation = operations.get(&id, &client_key(), NOW).expect("operation");
        assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
        assert!(operation.view(None, None).grant.is_none());
        assert!(operation.receipt().is_none());
        fixture.gateway.fault.store(0, Ordering::SeqCst);
        assert_eq!(
            fixture
                .read(&id)
                .await
                .expect("corrected evidence retries")
                .state,
            ClientRenewalOperationState::PendingCommit
        );
    }
}

#[tokio::test]
async fn threshold_revocation_and_caller_checks_precede_issuance() {
    let fixture = fixture().await;
    assert!(matches!(
        fixture.open(NOW - 1).await,
        Err(RenewalError::NotDue)
    ));
    assert!(matches!(
        open(
            &fixture.service,
            &WireGuardKey::from_bytes([0x7b; 32]),
            Box::new(fixture.request.clone()),
            NOW
        )
        .await,
        Err(RenewalError::CallerMismatch)
    ));
    assert!(matches!(
        fixture.open(1_000_000).await,
        Err(RenewalError::ExpiredIdentity)
    ));
    assert!(fixture.gateway.stages.lock().await.is_empty());
    assert!(fixture.service.operations.lock().await.is_empty());

    fixture.gateway.view.lock().await.state.revoke(1);
    fixture
        .service
        .registry
        .lock()
        .await
        .revoke(&client_key(), 1, NOW)
        .expect("matching terminal revocation");
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Revoked)
    ));
    assert!(fixture.gateway.stages.lock().await.is_empty());
    assert!(fixture.service.operations.lock().await.is_empty());
}

#[tokio::test]
async fn a_revocation_while_pending_prevents_retry_from_issuing_a_grant() {
    let fixture = fixture().await;
    fixture
        .gateway
        .fault
        .store(LOSE_STAGE_REPLY, Ordering::SeqCst);
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Gateway(_))
    ));
    let id = fixture.operation_id();
    fixture
        .service
        .registry
        .lock()
        .await
        .revoke(&client_key(), 1, NOW + 1)
        .expect("revoke while pending");
    assert!(matches!(
        fixture.read(&id).await,
        Err(RenewalError::Revoked)
    ));
    assert_eq!(fixture.gateway.stages.lock().await.len(), 1);
    let journal = crate::operations::OperationStore::load(&fixture.operations_path(), NOW + 1)
        .expect("journal");
    assert!(journal
        .get(&id, &client_key(), NOW + 1)
        .expect("operation")
        .view(None, None)
        .grant
        .is_none());
}

#[tokio::test]
async fn invalid_request_and_unconfirmed_policy_leave_no_issued_operation() {
    let mut fixture = fixture().await;
    fixture.request.active_pq_signature = MlDsa87Signature::placeholder();
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Request(CertificateError::MissingProof(
            "active client"
        )))
    ));
    assert!(fixture.service.operations.lock().await.is_empty());
    assert!(fixture.gateway.stages.lock().await.is_empty());

    let fixture = self::fixture().await;
    {
        let mut registry = fixture.service.registry.lock().await;
        let mut state = registry.state().clone();
        state.astra_policy_fingerprint =
            AstraPolicyPin::new(Fingerprint::of(b"superseded policy")).expect("older policy pin");
        *registry = crate::registry::AstraRegistry::new(fixture.registry_path(), state);
        registry.save().expect("unconfirmed policy fixture");
    }
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::AutomaticPolicyMigrationRequired)
    ));
    assert!(fixture.service.operations.lock().await.is_empty());
    assert!(fixture.gateway.stages.lock().await.is_empty());
}

#[tokio::test]
async fn incoherent_peer_views_are_refused_before_they_enter_the_registry() {
    for wrong_identity in [false, true] {
        let fixture = fixture().await;
        {
            let mut view = fixture.gateway.view.lock().await;
            if wrong_identity {
                view.active_pq_certificate.wireguard_public_key =
                    WireGuardKey::from_bytes([0x7c; 32]).to_base64();
            } else {
                view.state.active.pq_certificate_fingerprint =
                    Fingerprint::of(b"not the served client leaf");
            }
        }
        assert!(matches!(
            fixture.open(NOW).await,
            Err(RenewalError::UnknownPeer)
        ));
        assert!(fixture
            .service
            .registry
            .lock()
            .await
            .peer(&client_key())
            .is_none());
        assert!(fixture.service.operations.lock().await.is_empty());
        assert!(fixture.gateway.stages.lock().await.is_empty());
    }
}

/// Bootstrapping the signed credential document remains a service precondition;
/// the automatic workflow above needs no operator gesture or credential proof.
#[tokio::test]
async fn an_unconfigured_approval_allow_list_is_refused_before_issuance() {
    let mut fixture = fixture().await;
    Arc::get_mut(&mut fixture.service)
        .expect("unique service fixture")
        .approval_credentials = RwLock::new(Arc::new(crate::service::ApprovalCredentials {
        ids: Vec::new(),
        epoch: 1,
        registry: None,
    }));
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Approval(CertificateError::UnknownCredential))
    ));
    assert!(fixture.service.operations.lock().await.is_empty());
    assert!(fixture.gateway.stages.lock().await.is_empty());
}

/// A directory at a file's final path makes rename fail on every platform,
/// unlike permissions that can be bypassed by a privileged test process.
fn obstruct_registry(fixture: &Fixture) -> PathBuf {
    let backup = fixture
        .directory
        .path()
        .join("registry-before-failure.json");
    std::fs::rename(fixture.registry_path(), &backup).expect("preserve registry");
    std::fs::create_dir(fixture.registry_path()).expect("obstruct atomic publication");
    backup
}

fn restore_registry(fixture: &Fixture, backup: &std::path::Path) {
    std::fs::remove_dir(fixture.registry_path()).expect("remove publication obstruction");
    std::fs::rename(backup, fixture.registry_path()).expect("restore original registry");
}

#[tokio::test]
async fn a_failed_registry_reservation_is_not_published_in_memory_or_skipped_on_retry() {
    let fixture = fixture().await;
    let view = transcribe_peer(&fixture.service, &client_key(), NOW)
        .await
        .expect("transcribe admitted peer");
    let mut candidate = view.state.active;
    candidate.generation += 1;
    candidate.tls_certificate_fingerprint = Fingerprint::of(b"next TLS");
    candidate.pq_certificate_fingerprint = Fingerprint::of(b"next PQ");
    let rotation = PendingRotation {
        stage_id: Id16::new([0x7d; 16]).expect("stage"),
        request_fingerprint: fixture.request.fingerprint(),
        candidate,
        window: TransitionWindow::new(NOW, NOW + STAGE_LEASE_SECS, 1_000_000).expect("window"),
        stage_expires_at: NOW + STAGE_LEASE_SECS,
        granted: false,
    };
    let before = fixture.service.registry.lock().await.state().clone();
    let backup = obstruct_registry(&fixture);
    let bytes_before = std::fs::read(&backup).expect("original registry");
    {
        let mut registry = fixture.service.registry.lock().await;
        assert!(matches!(
            registry.open_rotation(&client_key(), rotation.clone(), NOW),
            Err(RegistryError::Io(_))
        ));
        assert_eq!(
            registry.state(),
            &before,
            "a failed write must not publish a reservation or its audit event"
        );
    }
    assert_eq!(
        std::fs::read(&backup).expect("preserved registry"),
        bytes_before
    );
    restore_registry(&fixture, &backup);
    fixture
        .service
        .registry
        .lock()
        .await
        .open_rotation(&client_key(), rotation.clone(), NOW)
        .expect("retry reservation");
    let durable = crate::registry::AstraRegistry::load(&fixture.registry_path(), None)
        .expect("durable reservation");
    assert_eq!(
        durable.peer(&client_key()).expect("peer").pending.as_ref(),
        Some(&rotation)
    );
    assert_eq!(
        durable.state(),
        fixture.service.registry.lock().await.state()
    );
}

#[tokio::test]
async fn a_failed_grant_marker_is_retried_durably_without_withdrawing_the_grant() {
    let fixture = fixture().await;
    let id = released_before_registry(&fixture).await;
    let before = fixture.service.registry.lock().await.state().clone();
    let journal = std::fs::read(fixture.operations_path()).expect("released grant journal");
    let backup = obstruct_registry(&fixture);
    let bytes_before = std::fs::read(&backup).expect("original registry");
    {
        let mut registry = fixture.service.registry.lock().await;
        assert!(matches!(
            registry.mark_granted(&client_key(), NOW + 1),
            Err(RegistryError::Io(_))
        ));
        assert_eq!(
            registry.state(),
            &before,
            "a failed write must not publish the granted bit or its audit event"
        );
    }
    assert_eq!(
        std::fs::read(&backup).expect("preserved registry"),
        bytes_before
    );
    restore_registry(&fixture, &backup);
    assert_eq!(
        fixture
            .read(&id)
            .await
            .expect("retry grant publication")
            .state,
        ClientRenewalOperationState::PendingCommit
    );
    let durable = crate::registry::AstraRegistry::load(&fixture.registry_path(), None)
        .expect("durable grant marker");
    assert!(
        durable
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("rotation")
            .granted
    );
    assert_eq!(
        durable.state(),
        fixture.service.registry.lock().await.state()
    );
    assert_eq!(
        std::fs::read(fixture.operations_path()).expect("grant never withdrawn"),
        journal
    );
}

fn obstruct_operations(fixture: &Fixture) -> PathBuf {
    let backup = fixture
        .directory
        .path()
        .join("operations-before-failure.json");
    std::fs::rename(fixture.operations_path(), &backup).expect("preserve operation journal");
    std::fs::create_dir(fixture.operations_path()).expect("obstruct operation publication");
    backup
}

fn restore_operations(fixture: &Fixture, backup: &std::path::Path) {
    std::fs::remove_dir(fixture.operations_path()).expect("remove journal obstruction");
    std::fs::rename(backup, fixture.operations_path()).expect("restore original journal");
}

/// Exactly the state after accepting the request and before creating issuance
/// material. No serialized private fields are modified to create this cut.
async fn pending_before_issuance(fixture: &Fixture) -> Id16 {
    transcribe_peer(&fixture.service, &client_key(), NOW)
        .await
        .expect("transcribe admitted peer");
    let id = Id16::new([0x7e; 16]).expect("operation");
    let approval_request = build_approval_request(
        &fixture.service,
        id,
        &fixture.request,
        &4,
        domain(),
        gateway_key(),
        "astra.example",
        &fixture.service.approval_credentials(),
        1,
        NOW,
    )
    .expect("approval manifest");
    let mut operation = Operation::awaiting_operator(
        id,
        client_key(),
        Box::new(fixture.request.clone()),
        Box::new(approval_request),
        NOW,
    );
    operation
        .authorize_automatic()
        .expect("verified automatic request");
    let mut operations = fixture.service.operations.lock().await;
    operations.open(operation, NOW).expect("accepted operation");
    operations.persist().expect("durable accepted operation");
    id
}

#[tokio::test]
async fn an_unwritten_new_operation_does_not_block_the_same_request_on_retry() {
    let fixture = fixture().await;
    let backup = obstruct_operations(&fixture);
    let journal_before = std::fs::read(&backup).expect("empty durable journal");
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Operation(OperationError::Persistence(_)))
    ));
    assert!(
        fixture.service.operations.lock().await.is_empty(),
        "failed acceptance must not reserve the peer in memory"
    );
    assert!(fixture.gateway.stages.lock().await.is_empty());
    assert_eq!(
        std::fs::read(&backup).expect("durable journal unchanged"),
        journal_before
    );
    restore_operations(&fixture, &backup);
    assert_eq!(
        fixture
            .open(NOW)
            .await
            .expect("retry accepted and issued")
            .state,
        ClientRenewalOperationState::PendingCommit
    );
}

#[tokio::test]
async fn unwritten_issuance_is_not_reused_or_sent_to_the_gateway_on_retry() {
    let fixture = fixture().await;
    let id = pending_before_issuance(&fixture).await;
    let before = {
        let operations = fixture.service.operations.lock().await;
        serde_json::to_value(operations.get(&id, &client_key(), NOW).expect("operation"))
            .expect("operation snapshot")
    };
    let backup = obstruct_operations(&fixture);
    let journal_before = std::fs::read(&backup).expect("durable acceptance");
    assert!(matches!(
        fixture.read(&id).await,
        Err(RenewalError::Operation(OperationError::Persistence(_)))
    ));
    {
        let operations = fixture.service.operations.lock().await;
        let operation = operations.get(&id, &client_key(), NOW).expect("operation");
        assert_eq!(
            serde_json::to_value(operation).expect("operation snapshot"),
            before,
            "failed issuance persistence must leave no stage material published in memory"
        );
    }
    assert!(fixture.gateway.stages.lock().await.is_empty());
    assert!(fixture
        .service
        .registry
        .lock()
        .await
        .peer(&client_key())
        .expect("peer")
        .pending
        .is_none());
    assert_eq!(
        std::fs::read(&backup).expect("durable acceptance unchanged"),
        journal_before
    );
    restore_operations(&fixture, &backup);
    let view = fixture.read(&id).await.expect("retry durable issuance");
    assert_eq!(view.state, ClientRenewalOperationState::PendingCommit);
    let durable = crate::operations::OperationStore::load(&fixture.operations_path(), NOW + 1)
        .expect("durable grant");
    assert_eq!(
        durable
            .get(&id, &client_key(), NOW + 1)
            .expect("operation")
            .view(None, None)
            .grant,
        view.grant
    );
}

#[tokio::test]
async fn an_unwritten_grant_cannot_escape_on_the_next_poll() {
    let fixture = fixture().await;
    fixture
        .gateway
        .fault
        .store(BLOCK_GRANT_JOURNAL, Ordering::SeqCst);
    assert!(matches!(
        fixture.open(NOW).await,
        Err(RenewalError::Operation(OperationError::Persistence(_)))
    ));
    let backup = fixture
        .directory
        .path()
        .join("operations-before-failure.json");
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&backup).expect("durable pre-grant state"))
            .expect("journal JSON");
    let id: Id16 = serde_json::from_value(snapshot["operations"][0]["operation_id"].clone())
        .expect("operation ID");
    {
        let operations = fixture.service.operations.lock().await;
        let operation = operations.get(&id, &client_key(), NOW).expect("operation");
        assert_eq!(
            operation.state,
            ClientRenewalOperationState::PendingGrant,
            "an unwritten grant must not be published in memory"
        );
        assert!(operation.receipt().is_none());
        assert!(operation.view(None, None).grant.is_none());
        assert_eq!(
            serde_json::to_value(operation).expect("operation snapshot"),
            snapshot["operations"][0]
        );
    }
    assert!(
        !fixture
            .service
            .registry
            .lock()
            .await
            .peer(&client_key())
            .expect("peer")
            .pending
            .as_ref()
            .expect("reservation")
            .granted
    );
    fixture.gateway.fault.store(0, Ordering::SeqCst);
    restore_operations(&fixture, &backup);
    let view = fixture.read(&id).await.expect("retry grant publication");
    assert_eq!(view.state, ClientRenewalOperationState::PendingCommit);
    assert_eq!(
        fixture.gateway.stages.lock().await.len(),
        2,
        "retry must finish the pending issuance, not serve cached unwritten grant"
    );
    let durable = crate::operations::OperationStore::load(&fixture.operations_path(), NOW + 1)
        .expect("durable completed journal");
    assert_eq!(
        durable
            .get(&id, &client_key(), NOW + 1)
            .expect("durable operation")
            .view(None, None)
            .grant,
        view.grant
    );
}
