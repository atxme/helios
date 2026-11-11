//! The gateway identity operations, end to end through the operator tunnel (F14
//! lot 6b): a renewal, and a revocation with its emergency replacement.
//!
//! This file does not depend on `heliosd`. The gateway is aether's own state,
//! `GatewayCertificateState`, served behind Astra's gateway channel by
//! `AetherGateway`. The steps `astra-operator` drives through `heliosd` (the
//! installation of a signed transition) are applied to that state by the test,
//! as `heliosd` would apply them. Astra's steps are real: the operator opens
//! through the tunnel's route and the door's `Tunnel` connector, deposits go
//! through `operator_signer_result`, and the publication and revocation relays
//! reach `AetherGateway` over the gateway channel.
//!
//! Signing mirrors `astra-operator`'s `sign_gateway_transition` and
//! `sign_revocation`: the same fields, the same `.sign` calls, and the same
//! verification before the document is returned. `astra-operator` is not linked
//! here: its signing needs an opened vault and an authenticator, and its domain
//! fixture is a different trust domain from the one Astra's registry holds.

use aether::certificates::approval::{AstraCredentialBinding, CredentialRegistry};
use aether::certificates::authority::RotationReason;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::{pq_certificate_fingerprint, GatewayIdentityTransition};
use aether::certificates::revocation::{
    EmergencyCertificateRevocation, RevocationReason, RevocationScope,
};
use aether::certificates::state::{GatewayCertificateState, InstallOutcome, TrustLedger};
use aether::certificates::status::{AstraSignerResult, CampaignApproval, CampaignScope};
use aether::certificates::transport::{RevocationExpiries, TrustUpdateObject, TrustUpdateRefusal};
use aether::certificates::window::TransitionWindow;
use aether::certificates::{
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use astra_channel::{
    OperatorGatewayPublish, OperatorGatewayPublished, OperatorOpenAction, OperatorOpenRequest,
    RelayedOperatorGatewayPublish, RelayedOperatorOpen, OPERATOR_GATEWAY_PUBLISH_ROUTE,
    OPERATOR_OPEN_ROUTE,
};
use base64::Engine as _;
use zeroize::Zeroizing;

use super::tunnel::{
    approving_credential, assertion_for, listen, post_to, submit_token, PrivateListener,
};
use super::*;
use crate::service::ApprovalCredentials;

/// The gateway's name and key, as the fixture's `AstraState` holds them.
const GATEWAY_NAME: &str = "gateway.example";
const GATEWAY_KEY: [u8; 32] = [1; 32];
/// The decision the gateway is at, and the generation it serves.
const DECISION_EPOCH: u64 = 7;
const GENERATION: u64 = 3;
/// Valid far beyond every instant these tests use.
const LEAF_NOT_AFTER: u64 = 4_000_000_000;

/// The `CA-PQ` the gateway and Astra both hold. Its private half is kept by the
/// test, as the operator's vault would keep it.
struct Authority {
    private: Zeroizing<Vec<u8>>,
    public: MlDsa87PublicKey,
}

/// Aether's gateway, behind the channel Astra relays to. Its state is the one a
/// client of the gateway would read.
struct AetherGateway {
    state: std::sync::Mutex<GatewayCertificateState>,
}

impl AetherGateway {
    /// Runs `change` on the gateway state. No await runs while the lock is held.
    fn with<T>(&self, change: impl FnOnce(&mut GatewayCertificateState) -> T) -> T {
        change(&mut self.state.lock().expect("gateway state"))
    }
}

#[async_trait::async_trait]
impl astra_channel::AstraStageHandler for AetherGateway {
    async fn stage_from_astra(
        &self,
        _: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<aether::certificates::client::GatewayCertificateStageReceipt>, TrustUpdateRefusal>
    {
        Err(TrustUpdateRefusal::Rejected)
    }
}

#[async_trait::async_trait]
impl astra_channel::AstraChannelHandler for AetherGateway {
    /// Verifies the revocation as the gateway does, then withdraws the leaves it names.
    async fn revoke(
        &self,
        revocation: Box<EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.with(|state| {
            revocation
                .verify(
                    &state.current_ca_public_key,
                    &state.trust_domain_id,
                    state.ca_epoch,
                    state.gateway_decision_epoch,
                )
                .map_err(|_| TrustUpdateRefusal::Rejected)?;
            state
                .apply_revocation(
                    revocation.revoked_tls_fingerprint.as_ref(),
                    revocation.revoked_pq_fingerprint.as_ref(),
                    revocation.revocation_epoch,
                    revocation.replacement_transition_fingerprint.as_ref(),
                )
                .map(|_| ())
                .map_err(|_| TrustUpdateRefusal::Rejected)
        })
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

    /// Marks the staged transition published, when it is the one Astra names.
    async fn gateway_transition_published(
        &self,
        published: astra_channel::GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal> {
        self.with(|state| {
            let staged = state.next_gateway_identity_epoch
                == Some(published.gateway_identity_epoch)
                && state
                    .next_transition_fingerprint
                    .is_some_and(|staged| staged.matches(&published.transition_fingerprint));
            if !staged {
                return Err(TrustUpdateRefusal::Rejected);
            }
            state
                .mark_published()
                .map_err(|_| TrustUpdateRefusal::Rejected)
        })
    }

    async fn peer_keys(&self) -> Result<Vec<WireGuardKey>, TrustUpdateRefusal> {
        Ok(Vec::new())
    }

    async fn gateway_identity(
        &self,
    ) -> Result<astra_channel::GatewayIdentityView, TrustUpdateRefusal> {
        self.with(|state| {
            Ok(astra_channel::GatewayIdentityView {
                pq_certificate: state.active_gateway_certificate.clone(),
                pq_certificate_fingerprint: state
                    .active_pq_fingerprint()
                    .map_err(|_| TrustUpdateRefusal::Rejected)?,
                tls_certificate_fingerprint: state.active_tls_fingerprint(),
                tls_certificate_not_after: LEAF_NOT_AFTER,
                active_gateway_identity_epoch: state.active_gateway_identity_epoch,
                gateway_decision_epoch: state.gateway_decision_epoch,
            })
        })
    }

    async fn peer_state(
        &self,
        _: &WireGuardKey,
    ) -> Result<astra_channel::PeerCertificateStateView, TrustUpdateRefusal> {
        Err(TrustUpdateRefusal::Rejected)
    }
}

/// A channel from Astra to `gateway`, on loopback, as `gateway_channel` builds
/// one for the fake gateway.
async fn channel_to(dir: &Path, gateway: Arc<AetherGateway>) -> crate::gateway::GatewayChannel {
    let (astra_certificate, identity, gateway_certificate) = channel_identities(dir);
    let config = astra_channel::server_config(&identity, &astra_certificate).expect("server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let router = astra_channel::router(gateway);
    tokio::spawn(async move {
        let _ = astra_channel::serve(address, config, router, astra_channel::INTERNAL_PREFIX).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    crate::gateway::GatewayChannel::open(dir, address, &gateway_certificate).expect("channel opens")
}

fn gateway_wg() -> WireGuardKey {
    WireGuardKey::from_bytes(GATEWAY_KEY)
}

/// A gateway leaf under `authority`, for a fresh subject key, valid until
/// [`LEAF_NOT_AFTER`].
fn leaf(authority: &Authority, serial: u8) -> PqCertificate {
    leaf_valid(authority, serial, (0, LEAF_NOT_AFTER))
}

/// A gateway leaf under `authority` valid over `validity`.
fn leaf_valid(authority: &Authority, serial: u8, validity: (u64, u64)) -> PqCertificate {
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("subject key");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: GATEWAY_NAME.into(),
            issuer: "helios-ca-pq".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_wg().to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                .encode(subject_public.as_bytes()),
            not_before_unix: validity.0,
            not_after_unix: validity.1,
            ml_dsa_87_signature: String::new(),
        },
        &authority.private,
    )
    .expect("signed leaf")
}

/// A gateway TLS leaf with server usage, which `verify` parses when a
/// transition names it. Its validity covers the synthetic clock the tests run on.
fn gateway_tls_successor() -> DerCertificate {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    let mut params = CertificateParams::new(vec![GATEWAY_NAME.to_string()]).expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let key = KeyPair::generate().expect("key");
    let certificate = params.self_signed(&key).expect("self-signed");
    DerCertificate::new(certificate.der().to_vec()).expect("der")
}

/// Signs a gateway transition from `state`'s current identity, as
/// `sign_gateway_transition` does. `window` is `(not_before, activation_at, not_after)`.
fn sign_transition(
    authority: &Authority,
    state: &GatewayCertificateState,
    epoch: u64,
    reason: RotationReason,
    window: (u64, u64, u64),
    rotate_tls: bool,
    serial: u8,
) -> GatewayIdentityTransition {
    // As `astra-operator` issues it: from now for a year, and covering the whole
    // window, so that a leaf never expires inside its own overlap.
    let validity = (NOW, NOW + 365 * DAY);
    assert!(
        validity.0 <= window.0 && validity.1 >= window.2,
        "the leaf's validity must cover the transition window"
    );
    let next_tls = rotate_tls.then(gateway_tls_successor);
    let tls = state.active_tls_fingerprint();
    let pq = state.active_pq_fingerprint().expect("active leaf");
    let transition = GatewayIdentityTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: state.trust_domain_id,
        ca_epoch: state.ca_epoch,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        active_gateway_tls_certificate_fingerprint: tls,
        next_gateway_tls_certificate: next_tls,
        active_gateway_certificate_fingerprint: pq,
        next_gateway_certificate: Some(leaf_valid(authority, serial, validity)),
        window: TransitionWindow::new(window.0, window.1, window.2).expect("window"),
        reason,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&authority.private)
    .expect("signed transition");
    // Verified before it is returned, against the state the campaign froze.
    transition
        .verify(
            &authority.public,
            &state.trust_domain_id,
            state.ca_epoch,
            epoch - 1,
            &state.gateway_wg_public_key,
            &state.server_name,
            &tls,
            &pq,
        )
        .expect("verified under the anchor");
    transition
}

/// Signs the revocation of the gateway's served leaves, naming `replacement`, as
/// `sign_revocation` does for a gateway scope.
fn sign_revocation(
    authority: &Authority,
    state: &GatewayCertificateState,
    expiries: RevocationExpiries,
    replacement: Option<Fingerprint>,
) -> EmergencyCertificateRevocation {
    let revocation = EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: state.trust_domain_id,
        ca_epoch: state.ca_epoch,
        scope: RevocationScope::Gateway,
        identity_key: state.gateway_wg_public_key,
        server_name: Some(state.server_name.clone()),
        revocation_epoch: state.gateway_decision_epoch + 1,
        revoked_tls_fingerprint: Some(state.active_tls_fingerprint()),
        revoked_tls_not_after: expiries.tls_not_after,
        revoked_pq_fingerprint: Some(state.active_pq_fingerprint().expect("active leaf")),
        revoked_pq_not_after: expiries.pq_not_after,
        effective_at: NOW,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: replacement,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&authority.private)
    .expect("signed revocation");
    revocation
        .verify(
            &authority.public,
            &state.trust_domain_id,
            state.ca_epoch,
            state.gateway_decision_epoch,
        )
        .expect("verified under the anchor");
    revocation
}

/// The gateway, the channel, Astra and its private route, and one credential
/// that approves what the operator opens.
struct Fixture {
    service: Arc<AstraService>,
    gateway: Arc<AetherGateway>,
    authority: Authority,
    credential: (rcgen::KeyPair, AstraCredentialBinding),
    listener: PrivateListener,
}

async fn fixture(dir: &Path) -> Fixture {
    let (private, public) = generate_ml_dsa_87_keypair().expect("CA-PQ keypair");
    let authority = Authority { private, public };
    let state = GatewayCertificateState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: gateway_wg(),
        server_name: GATEWAY_NAME.into(),
        ca_epoch: 1,
        current_ca_public_key: authority.public.clone(),
        next_ca_public_key: None,
        next_ca_transition_fingerprint: None,
        ca_activation_at: None,
        ca_retire_active_at: None,
        active_gateway_identity_epoch: GENERATION,
        gateway_decision_epoch: DECISION_EPOCH,
        next_gateway_identity_epoch: None,
        next_transition_fingerprint: None,
        last_aborted_transition: None,
        active_gateway_tls_certificate: DerCertificate::new(b"gateway tls in service".to_vec())
            .expect("der"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate: leaf(&authority, 0x31),
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: false,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    };
    let gateway = Arc::new(AetherGateway {
        state: std::sync::Mutex::new(state),
    });
    let channel = channel_to(dir, Arc::clone(&gateway)).await;
    let (mut built, _) = build_service_with_ca(dir, None, Some(channel));
    // Astra serves the anchor the gateway holds, at its epoch.
    let credential = approving_credential(&authority.private, 1);
    built.approval_credentials = RwLock::new(Arc::new(ApprovalCredentials {
        ids: vec![credential.1.credential_id.clone()],
        epoch: 1,
        registry: Some(Box::new(CredentialRegistry {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: gateway_wg(),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: vec![credential.1.clone()],
        })),
    }));
    let service = Arc::new(built);
    let anchor = authority.public.clone();
    rewrite_registry(&service, |state| state.ca_public_key = anchor).await;
    let listener = listen(Arc::clone(&service)).await;
    Fixture {
        service,
        gateway,
        authority,
        credential,
        listener,
    }
}

fn administrator() -> OperatorIdentity {
    OperatorIdentity::WireGuard {
        public_key: tunnel_key(),
    }
}

impl Fixture {
    /// Opens `action` through the tunnel's route, as the companion does.
    async fn open(&self, action: OperatorOpenAction) -> OperatorOpened {
        let body = serde_json::to_vec(&RelayedOperatorOpen {
            operator: administrator(),
            request: OperatorOpenRequest {
                action,
                reason: "gateway identity".into(),
                requested_by: "alice".into(),
                window_secs: 300,
            },
        })
        .expect("relayed opening");
        let (status, answer) = post_to(&self.listener, OPERATOR_OPEN_ROUTE, &body).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
        serde_json::from_slice(&answer).expect("the tunnel's answer")
    }

    /// Deposits `object` against the campaign `opened` names, approved by the credential.
    async fn deposit(
        &self,
        opened: &OperatorOpened,
        object: TrustUpdateObject,
    ) -> Result<crate::signing::SigningOperationView, crate::service::ServiceError> {
        let campaign = campaign_of(&self.service, opened).await;
        let result = Box::new(AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: campaign.campaign_id,
                campaign_fingerprint: campaign.fingerprint(),
                required_credentials: campaign.required_credentials,
                approved_at: NOW,
                approvals: vec![assertion_for(
                    &self.credential.0,
                    &self.credential.1,
                    &campaign,
                )],
            }),
            objects: vec![object],
            credential_registry: None,
            issuer_authorization: None,
        });
        let token = submit_token(&self.service, &opened.operation_id).await;
        crate::service::operator_signer_result(
            &self.service,
            &opened.operation_id,
            &token,
            result,
            NOW,
        )
        .await
    }

    /// Signs a transition against the gateway's state as it is now.
    fn transition(
        &self,
        epoch: u64,
        reason: RotationReason,
        window: (u64, u64, u64),
        rotate_tls: bool,
        serial: u8,
    ) -> GatewayIdentityTransition {
        self.gateway.with(|state| {
            sign_transition(
                &self.authority,
                state,
                epoch,
                reason,
                window,
                rotate_tls,
                serial,
            )
        })
    }

    /// Installs `transition` on the gateway, as `heliosd` does for the operator.
    fn install(
        &self,
        transition: &GatewayIdentityTransition,
    ) -> Result<InstallOutcome, CertificateError> {
        self.gateway
            .with(|state| state.install_transition(transition, &TrustLedger::default(), NOW))
    }

    fn in_service(&self) -> Fingerprint {
        self.gateway
            .with(|state| state.active_pq_fingerprint())
            .expect("fingerprint")
    }
}

/// An activation after `NOW` and a window that outlives the test's instants.
const STAGED: (u64, u64, u64) = (NOW, NOW + 100, NOW + 10_000);
/// The cause the gateway names when an emergency replacement is refused outside a revocation.
const EMERGENCY_CAUSE: &str = "emergency_replacement belongs to a revoked identity";
const DAY: u64 = 86_400;

/// The window `astra-operator` signs for a replacement (`REPLACEMENT_TERMS`, seven
/// days of preparation and seven of overlap): it starts at `NOW`, activates a week
/// later and ends a week after that. The gateway installs an emergency replacement at
/// once, so these instants are inert.
const INERT: (u64, u64, u64) = (NOW, NOW + 7 * DAY, NOW + 14 * DAY);

fn relayed_publication(transition: &GatewayIdentityTransition) -> Vec<u8> {
    serde_json::to_vec(&RelayedOperatorGatewayPublish {
        operator: administrator(),
        request: OperatorGatewayPublish {
            epoch: transition.gateway_identity_epoch,
            transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        },
    })
    .expect("relayed publication")
}

/// A renewal: Astra accepts the signed transition, the gateway installs it, the
/// door marks it published and the gateway confirms, and the leaf switches at
/// `not_after`.
#[tokio::test]
async fn a_gateway_renewal_runs_through_the_tunnel() {
    let dir = tempfile::tempdir().expect("temp dir");
    let fixture = fixture(dir.path()).await;

    let opened = fixture.open(OperatorOpenAction::GatewayIdentity).await;
    assert_eq!(opened.scope, CampaignScope::GatewayIdentity);
    let served = opened
        .gateway_certificate
        .as_ref()
        .expect("the answer carries the leaf in service");
    assert_eq!(
        pq_certificate_fingerprint(served).expect("fingerprint"),
        fixture.in_service(),
    );

    let transition = fixture.transition(
        DECISION_EPOCH + 1,
        RotationReason::Scheduled,
        STAGED,
        false,
        0x32,
    );
    fixture
        .deposit(
            &opened,
            TrustUpdateObject::GatewayIdentityTransition(Box::new(transition.clone())),
        )
        .await
        .expect("the deposit is accepted");
    assert!(!published_on_disk(dir.path()));

    assert_eq!(
        fixture
            .install(&transition)
            .expect("the gateway installs it"),
        InstallOutcome::Installed,
    );

    let (status, body) = post_to(
        &fixture.listener,
        OPERATOR_GATEWAY_PUBLISH_ROUTE,
        &relayed_publication(&transition),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: OperatorGatewayPublished = serde_json::from_slice(&body).expect("the answer");
    assert_eq!(
        answer,
        OperatorGatewayPublished {
            epoch: DECISION_EPOCH + 1,
            relayed: true,
        }
    );
    assert!(published_on_disk(dir.path()), "the door marked it");
    assert!(
        fixture.gateway.with(|state| state.published),
        "the gateway confirmed it"
    );

    let successor = pq_certificate_fingerprint(
        transition
            .next_gateway_certificate
            .as_ref()
            .expect("a successor leaf"),
    )
    .expect("fingerprint");
    assert!(fixture
        .gateway
        .with(|state| state.promote_if_due(STAGED.2))
        .expect("promotes"));
    assert_eq!(fixture.in_service(), successor);
    assert_eq!(
        fixture
            .gateway
            .with(|state| state.active_gateway_identity_epoch),
        DECISION_EPOCH + 1,
    );
}

/// The replacement is deposited and refused alone by the gateway; the revocation
/// is accepted, and then the replacement it names installs.
#[tokio::test]
async fn a_gateway_revocation_with_replacement_lands_in_order() {
    let dir = tempfile::tempdir().expect("temp dir");
    let fixture = fixture(dir.path()).await;
    let epoch = DECISION_EPOCH + 1;

    let replacement_round = fixture.open(OperatorOpenAction::GatewayIdentity).await;
    let replacement = fixture.transition(
        epoch,
        RotationReason::EmergencyReplacement,
        INERT,
        true,
        0x33,
    );
    fixture
        .deposit(
            &replacement_round,
            TrustUpdateObject::GatewayIdentityTransition(Box::new(replacement.clone())),
        )
        .await
        .expect("the replacement is deposited");
    // A healthy gateway refuses the replacement on its own.
    assert!(matches!(
        fixture.install(&replacement),
        Err(CertificateError::IllegalStateTransition(cause)) if cause.contains(EMERGENCY_CAUSE)
    ));

    let revocation_round = fixture.open(OperatorOpenAction::GatewayRevocation).await;
    let expiries = revocation_round
        .revocation_expiries
        .expect("both leaves carry their expiry");
    let revocation = fixture.gateway.with(|state| {
        sign_revocation(
            &fixture.authority,
            state,
            expiries,
            Some(replacement.fingerprint().expect("fingerprint")),
        )
    });
    fixture
        .deposit(
            &revocation_round,
            TrustUpdateObject::CertificateRevocation(Box::new(revocation)),
        )
        .await
        .expect("the revocation is deposited and relayed");
    assert!(
        fixture.gateway.with(|state| state.revoked),
        "the gateway withdrew its leaves"
    );

    // Revoked, the gateway refuses a transition the revocation did not name.
    let other = fixture.transition(epoch, RotationReason::Scheduled, STAGED, false, 0x34);
    assert!(matches!(
        fixture.install(&other),
        Err(CertificateError::Revoked)
    ));

    assert_eq!(
        fixture
            .install(&replacement)
            .expect("the named replacement installs"),
        InstallOutcome::Installed,
    );
    let replaced = replacement
        .next_gateway_certificate
        .as_ref()
        .map(|certificate| pq_certificate_fingerprint(certificate).expect("fingerprint"))
        .expect("a successor leaf");
    assert_eq!(fixture.in_service(), replaced);
    assert!(fixture.gateway.with(|state| !state.revoked));
}

/// The gateway, healthy, refuses an emergency replacement that Astra holds: the
/// deposit lands, and the gateway's state does not move.
#[tokio::test]
async fn an_emergency_replacement_is_refused_by_a_healthy_gateway() {
    let dir = tempfile::tempdir().expect("temp dir");
    let fixture = fixture(dir.path()).await;
    let before = fixture.gateway.with(|state| state.clone());

    let opened = fixture.open(OperatorOpenAction::GatewayIdentity).await;
    let replacement = fixture.transition(
        DECISION_EPOCH + 1,
        RotationReason::EmergencyReplacement,
        INERT,
        true,
        0x35,
    );
    fixture
        .deposit(
            &opened,
            TrustUpdateObject::GatewayIdentityTransition(Box::new(replacement.clone())),
        )
        .await
        .expect("the deposit is accepted");

    assert!(matches!(
        fixture.install(&replacement),
        Err(CertificateError::IllegalStateTransition(cause)) if cause.contains(EMERGENCY_CAUSE)
    ));
    assert_eq!(fixture.gateway.with(|state| state.clone()), before);
}
