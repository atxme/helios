//! The gateway renewal sequence, against simulated keys and a simulated tunnel.
//!
//! The vault, the document, the campaign requests, the gateway's leaf and every
//! signature are the production code. Only the CTAP2 boundary and the tunnel are
//! simulated.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use aether::certificates::authority::RotationReason;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature,
};
use aether::certificates::gateway::{
    pq_certificate_fingerprint, GatewayBootstrapRequest, GatewayCertificateRequest,
    GatewayIdentityTransition,
};
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerResult, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorGatewayPublished, OperatorOpenRequest, OperatorOpened,
    SigningOperationState,
};
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::PqCertificate;
use zeroize::Zeroizing;

use super::*;
use crate::operations::fixtures::{
    domain, gateway_key, nothing_in_flight, operation, trust_domain, Domain, EXPIRES, NOW,
    SERVER_NAME,
};
use crate::origin::CampaignRequest;
use crate::tunnel::admin_refusal;
use crate::{gestures, store};

const DAY: u64 = 86_400;
const ACTIVE_TLS: &[u8] = b"la TLS de la gateway en service";

/// The gateway's key, and the leaf Astra signed for it, as the domain holds them.
struct InService {
    key: Zeroizing<Vec<u8>>,
    leaf: PqCertificate,
}

fn gateway_in_service(domain: &Domain) -> InService {
    let (key, public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let proof = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        ml_dsa_87_public_key: public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&key)
    .expect("proof");
    let vault = store::load(&domain.path).expect("vault");
    let opening = gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("opened");
    let anchor = MlDsa87PublicKey::parse(domain.relay().ca_pq_public_key.trim()).expect("anchor");
    let leaf = signing::issue_gateway_bootstrap_certificate(
        &vault,
        &opening,
        &anchor,
        &signing::GatewayBootstrapDecision {
            request: &proof,
            leaf_validity: (NOW, NOW + 30 * DAY),
            serial: [0x51; 16],
        },
    )
    .expect("leaf");
    domain.keys.iter().for_each(|key| key.touches.set(0));
    InService { key, leaf }
}

/// The request the gateway prepares: its next key, proved by that key, and continuity
/// from the leaf in service unless the gateway recovers a lost key.
fn prepared_request(
    new_key: &[u8],
    new_public: MlDsa87PublicKey,
    continuity: Option<&[u8]>,
) -> GatewayCertificateRequest {
    GatewayCertificateRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: trust_domain(),
        gateway_identity_epoch: 2,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        new_ml_dsa_87_public_key: new_public,
        request_id: Id16::new([0x52; 16]).expect("request id"),
        created_at: NOW,
        expires_at: NOW + 3_600,
        new_key_proof: MlDsa87Signature::placeholder(),
        current_key_authorization: None,
    }
    .sign(new_key, continuity)
    .expect("request signed")
}

/// A self-signed TLS leaf of the gateway: not a CA, serving TLS for its name.
fn gateway_tls_leaf() -> DerCertificate {
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).expect("params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("TLS key");
    let certificate = params.self_signed(&key).expect("TLS certificate");
    DerCertificate::new(certificate.der().to_vec()).expect("DER")
}

/// One renewal's inputs: the domain, the gateway in service, and what it prepares.
struct Scenario {
    domain: Domain,
    in_service: InService,
    key_recovery: bool,
    request: GatewayCertificateRequest,
    candidate: DerCertificate,
}

impl Scenario {
    fn new(key_recovery: bool) -> Self {
        let domain = domain();
        let in_service = gateway_in_service(&domain);
        let (new_key, new_public) = generate_ml_dsa_87_keypair().expect("next key");
        let continuity = (!key_recovery).then(|| in_service.key.as_slice());
        let request = prepared_request(&new_key, new_public, continuity);
        let candidate = gateway_tls_leaf();
        Self {
            domain,
            in_service,
            key_recovery,
            request,
            candidate,
        }
    }

    fn leaf(&self) -> Fingerprint {
        pq_certificate_fingerprint(&self.in_service.leaf).expect("fingerprint")
    }

    /// The campaign Astra freezes for the gateway's leaf `leaf`, one decision forward.
    fn campaign(&self, leaf: Fingerprint) -> AstraRotationCampaign {
        self.domain.campaign(
            CampaignScope::GatewayIdentity,
            vec![CampaignTarget {
                certificate_kind: CertificateKind::GatewayPq,
                identity_key: gateway_key(),
                epoch: 1,
                generation: 1,
                active_tls_certificate_fingerprint: Fingerprint::of(ACTIVE_TLS),
                active_pq_certificate_fingerprint: leaf,
            }],
            EXPIRES,
        )
    }
}

fn gateway_read() -> GatewayIdentityRead {
    GatewayIdentityRead {
        ca_pq_fingerprint: Fingerprint::of(b"ca-pq"),
        next_ca_fingerprint: None,
        client_tls_ca_fingerprint: None,
        next_client_tls_ca_fingerprint: None,
        ca_retire_active_at: None,
        gateway_identity_epoch: 1,
        gateway_tls_fingerprint: String::new(),
        gateway_pq_fingerprint: String::new(),
        gateway_tls_not_after: None,
        gateway_pq_not_after: None,
        gateway_transition_pending: false,
        gateway_transition_published: false,
        gateway_activation_at: None,
        gateway_retire_active_at: None,
        gateway_rollback_expires_at: None,
        gateway_restart_due: None,
    }
}

/// The tunnel, as a test scripts it. Each call is recorded by name.
struct Remote<'a> {
    domain: &'a Domain,
    campaign: AstraRotationCampaign,
    served: PqCertificate,
    request: GatewayCertificateRequest,
    candidate: Option<DerCertificate>,
    prepared: GatewayRenewalRead,
    gateway: GatewayIdentityRead,
    overlap: Option<u64>,
    open_refusal: Cell<Option<u16>>,
    /// Answers to the deposits, in order; once empty, Astra accepts. A number is a
    /// refusal or a lost answer with that status.
    submit_replies: RefCell<VecDeque<Result<SigningOperationState, u16>>>,
    /// Answers to the installations, in order; a number is a refusal with that status.
    install_replies: RefCell<VecDeque<u16>>,
    /// Answers to the publications, in order; once empty, the gateway relays.
    publish_replies: RefCell<VecDeque<Result<bool, u16>>>,
    calls: RefCell<Vec<&'static str>>,
    submitted: RefCell<Vec<AstraSignerResult>>,
    installed: RefCell<Vec<GatewayIdentityTransition>>,
}

impl<'a> Remote<'a> {
    fn new(scenario: &'a Scenario) -> Self {
        Self {
            domain: &scenario.domain,
            campaign: scenario.campaign(scenario.leaf()),
            served: scenario.in_service.leaf.clone(),
            request: scenario.request.clone(),
            candidate: None,
            prepared: GatewayRenewalRead {
                gateway_identity_epoch: 2,
                request_fingerprint: scenario.request.fingerprint().to_hex(),
                expires_at: NOW + 3_600,
                candidate_tls_fingerprint: None,
                reused: false,
                key_recovery: scenario.key_recovery,
            },
            gateway: gateway_read(),
            overlap: None,
            open_refusal: Cell::new(None),
            submit_replies: RefCell::default(),
            install_replies: RefCell::default(),
            publish_replies: RefCell::default(),
            calls: RefCell::default(),
            submitted: RefCell::default(),
            installed: RefCell::default(),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }

    fn called(&self, name: &'static str) -> bool {
        self.calls.borrow().contains(&name)
    }

    fn count(&self, name: &'static str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| **call == name)
            .count()
    }

    fn note(&self, name: &'static str) {
        self.calls.borrow_mut().push(name);
    }
}

impl GatewayIdentityRemote for Remote<'_> {
    fn open_campaign(&self, _request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        self.note("open_campaign");
        if let Some(status) = self.open_refusal.get() {
            return Err(admin_refusal(status, None));
        }
        Ok(OperatorOpened {
            operation_id: operation(),
            campaign_id: self.campaign.campaign_id,
            campaign_fingerprint: self.campaign.fingerprint(),
            scope: CampaignScope::GatewayIdentity,
            target_count: 1,
            required_credentials: 1,
            expires_at: EXPIRES,
            revocation_expiries: None,
            delegation_request: None,
            gateway_certificate: Some(self.served.clone()),
        })
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        self.note("fetch_campaign");
        assert_eq!(*operation_id, operation());
        Ok(self.domain.request(self.campaign.clone()))
    }

    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        self.note("submit_campaign");
        assert_eq!(*operation_id, operation());
        assert_eq!(result_token, "jeton-de-depot");
        self.submitted.borrow_mut().push(result.clone());
        match self.submit_replies.borrow_mut().pop_front() {
            None => Ok(SigningOperationState::Approved),
            Some(Ok(state)) => Ok(state),
            Some(Err(status)) => Err(admin_refusal(status, Some("motif de la gateway".into()))),
        }
    }

    fn prepare_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead> {
        self.note("prepare_renewal");
        assert!(
            !ask.new_key,
            "the renewal keeps the sealed key of the gateway"
        );
        Ok(self.prepared.clone())
    }

    fn renewal_request(&self) -> Result<GatewayCertificateRequest> {
        self.note("renewal_request");
        Ok(self.request.clone())
    }

    fn candidate_tls(&self) -> Result<Option<DerCertificate>> {
        self.note("candidate_tls");
        Ok(self.candidate.clone())
    }

    fn install(&self, transition: &GatewayIdentityTransition) -> Result<GatewayDecisionRead> {
        self.note("install");
        self.installed.borrow_mut().push(transition.clone());
        match self.install_replies.borrow_mut().pop_front() {
            Some(status) => Err(admin_refusal(status, Some("motif de la gateway".into()))),
            None => Ok(GatewayDecisionRead {
                gateway_identity_epoch: transition.gateway_identity_epoch,
                fingerprint: String::new(),
                already_present: false,
                activation_at: Some(transition.window.activation_at),
                not_after: Some(transition.window.not_after),
            }),
        }
    }

    fn publish(&self, epoch: u64) -> Result<OperatorGatewayPublished> {
        self.note("publish");
        match self.publish_replies.borrow_mut().pop_front() {
            None => Ok(OperatorGatewayPublished {
                epoch,
                relayed: true,
            }),
            Some(Ok(relayed)) => Ok(OperatorGatewayPublished { epoch, relayed }),
            Some(Err(status)) => Err(admin_refusal(status, None)),
        }
    }

    fn abort(&self, _abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead> {
        unreachable!("the abort is Task 5's, and no test of this task calls it")
    }

    fn rollback(
        &self,
        _authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead> {
        unreachable!("the rollback is Task 5's, and no test of this task calls it")
    }

    fn staged_transition(&self) -> Result<Option<GatewayIdentityTransition>> {
        self.note("staged_transition");
        Ok(None)
    }

    fn gateway(&self) -> Result<GatewayIdentityRead> {
        self.note("gateway");
        Ok(self.gateway.clone())
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        self.note("authority_status");
        Ok(nothing_in_flight(&self.domain.path))
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        self.note("overlap_not_after");
        Ok(self.overlap)
    }
}

fn options() -> RenewalOptions {
    RenewalOptions {
        rotate_tls: false,
        key_recovery: false,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 30,
    }
}

/// Opens the renewal, approves it with the first key, and records the decision.
fn signed_decision(
    remote: &dyn GatewayIdentityRemote,
    domain: &Domain,
    options: RenewalOptions,
) -> SignedGatewayDecision {
    let mut opened = open_renewal(remote, &domain.path, options, NOW).expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    opened.sign_and_record(&domain.path, NOW).expect("signed")
}

fn record_on_disk(domain: &Domain) -> bool {
    domain
        .path
        .parent()
        .expect("parent")
        .join(PENDING_FILE)
        .exists()
}

#[test]
fn renewal_runs_to_published() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let decision = signed_decision(&remote, domain, options());
    assert_eq!(
        pending(&domain.path, NOW).expect("read"),
        Some(decision.clone())
    );

    let carried = carry(&remote, &domain.path, decision, NOW).expect("carried");

    assert_eq!(
        carried,
        GatewayCarried::Published {
            activation_at: NOW + 7 * DAY,
            not_after: NOW + 14 * DAY,
        }
    );
    assert!(!record_on_disk(domain), "published clears the record");
    assert_eq!(
        domain.touches(),
        2,
        "the approval, then the opening of the same key"
    );
    assert_eq!(
        remote.calls(),
        [
            "gateway",
            "overlap_not_after",
            "prepare_renewal",
            "open_campaign",
            "fetch_campaign",
            "renewal_request",
            "candidate_tls",
            "fetch_campaign",
            "submit_campaign",
            "install",
            "publish",
        ]
    );
}

#[test]
fn renewal_refuses_a_leaf_the_campaign_did_not_freeze() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.campaign = scenario.campaign(Fingerprint::of(b"une autre feuille"));

    let refusal = open_renewal(&remote, &scenario.domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::LeafMismatch);
    assert_eq!(scenario.domain.touches(), 0, "no key is touched");
}

#[test]
fn renewal_refuses_during_a_ca_pq_overlap() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.overlap = Some(NOW + DAY);

    let refusal = open_renewal(&remote, &scenario.domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::CaPqOverlap);
    assert!(!remote.called("open_campaign"), "no campaign is opened");
    assert_eq!(scenario.domain.touches(), 0);
}

#[test]
fn renewal_refuses_while_a_transition_is_staged() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.gateway.gateway_transition_pending = true;

    let refusal = open_renewal(&remote, &scenario.domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::TransitionInFlight);
    assert!(!remote.called("open_campaign"), "no campaign is opened");
}

#[test]
fn renewal_refuses_a_request_other_than_the_one_announced() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.prepared.request_fingerprint = Fingerprint::of(b"une autre demande").to_hex();

    let refusal = open_renewal(&remote, &scenario.domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RequestMismatch);
    assert_eq!(scenario.domain.touches(), 0);
}

#[test]
fn key_recovery_signs_without_continuity() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let recovery = RenewalOptions {
        key_recovery: true,
        ..options()
    };

    let decision = signed_decision(&remote, domain, recovery);
    carry(&remote, &domain.path, decision, NOW).expect("carried");

    let installed = remote.installed.borrow();
    assert_eq!(installed[0].reason, RotationReason::KeyRecovery);
    assert!(
        installed[0].window.activation_at > NOW,
        "the switch waits for the prepared window"
    );
}

#[test]
fn a_continuity_signature_is_refused_on_key_recovery() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let recovery = RenewalOptions {
        key_recovery: true,
        ..options()
    };

    let refusal = open_renewal(&remote, &scenario.domain.path, recovery, NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RequestMismatch);
}

#[test]
fn rotate_tls_binds_the_candidate_der() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.candidate = Some(scenario.candidate.clone());
    remote.prepared.candidate_tls_fingerprint = Some(scenario.candidate.fingerprint().to_hex());
    let domain = &scenario.domain;
    let rotating = RenewalOptions {
        rotate_tls: true,
        ..options()
    };

    let decision = signed_decision(&remote, domain, rotating);
    carry(&remote, &domain.path, decision, NOW).expect("carried");

    let installed = remote.installed.borrow();
    assert_eq!(
        installed[0]
            .next_gateway_tls_certificate
            .as_ref()
            .map(DerCertificate::as_bytes),
        Some(scenario.candidate.as_bytes()),
        "the transition carries the DER that was read"
    );
}

#[test]
fn a_candidate_der_of_another_fingerprint_is_refused() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.candidate = Some(scenario.candidate.clone());
    remote.prepared.candidate_tls_fingerprint = Some(Fingerprint::of(b"autre TLS").to_hex());
    let rotating = RenewalOptions {
        rotate_tls: true,
        ..options()
    };

    let refusal = open_renewal(&remote, &scenario.domain.path, rotating, NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RequestMismatch);
    assert_eq!(scenario.domain.touches(), 0);
}

#[test]
fn resume_publishes_without_a_key() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.publish_replies.borrow_mut().push_back(Err(503));
    let decision = signed_decision(&remote, domain, options());
    let touches = domain.touches();

    let refusal =
        carry(&remote, &domain.path, decision, NOW).expect_err("the publication was not confirmed");
    assert_eq!(refusal, GatewayRefusal::Unreachable);

    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the decision waits");
    assert!(waiting.installed, "installed before publication");
    assert!(!waiting.published);
    carry(&remote, &domain.path, waiting, NOW).expect("published on resume");

    assert_eq!(
        remote.submitted.borrow().len(),
        1,
        "the deposit is not sent again"
    );
    assert_eq!(domain.touches(), touches, "the resume touches no key");
    assert!(!record_on_disk(domain));
}

#[test]
fn a_lost_deposit_answer_replays_the_same_bytes() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.submit_replies.borrow_mut().push_back(Err(503));
    let decision = signed_decision(&remote, domain, options());
    let touches = domain.touches();

    let refusal = carry(&remote, &domain.path, decision, NOW).expect_err("the answer was lost");
    assert_eq!(refusal, GatewayRefusal::Unreachable);
    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the decision stays recorded");
    assert!(!waiting.installed);

    carry(&remote, &domain.path, waiting, NOW).expect("replayed");

    let submitted = remote.submitted.borrow();
    assert_eq!(submitted.len(), 2);
    assert_eq!(submitted[0], submitted[1], "the same bytes are sent");
    assert_eq!(domain.touches(), touches, "the replay touches no key");
    assert!(!record_on_disk(domain));
}

#[test]
fn a_definitive_install_refusal_is_not_retried() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.install_replies.borrow_mut().push_back(409);
    let decision = signed_decision(&remote, domain, options());

    let refusal = carry(&remote, &domain.path, decision, NOW).expect_err("refused");

    assert_eq!(
        refusal,
        GatewayRefusal::GatewayRefused("la gateway a refusé (409) : motif de la gateway".into())
    );
    assert_eq!(remote.count("install"), 1, "the refusal is not retried");
    assert!(!remote.called("publish"));
    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the record stays");
    assert!(!waiting.installed);
}

#[test]
fn a_decision_waiting_refuses_a_new_opening() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let _decision = signed_decision(&remote, domain, options());

    let refusal = open_renewal(&remote, &domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::AlreadyOpen);
    assert_eq!(
        remote.count("open_campaign"),
        1,
        "no second campaign is opened"
    );
}

#[test]
fn an_unconfirmed_decision_of_an_expired_campaign_is_discarded() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let decision = signed_decision(&remote, domain, options());

    let refusal = carry(&remote, &domain.path, decision, EXPIRES).expect_err("refused");

    assert!(matches!(refusal, GatewayRefusal::Internal(_)));
    assert_eq!(pending(&domain.path, EXPIRES).expect("read"), None);
    assert!(!record_on_disk(domain));
}
