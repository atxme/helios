//! The gateway renewal sequence, against simulated keys and a simulated tunnel.
//!
//! The vault, the document, the campaign requests, the gateway's leaf and every
//! signature are the production code. Only the CTAP2 boundary and the tunnel are
//! simulated.

#![cfg_attr(not(test), allow(dead_code, unused_imports))]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use aether::certificates::authority::RotationReason;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature, WireGuardKey,
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
pub const ACTIVE_TLS: &[u8] = b"la TLS de la gateway en service";

/// The gateway's key, and the leaf Astra signed for it, as the domain holds them.
pub struct InService {
    pub key: Zeroizing<Vec<u8>>,
    pub leaf: PqCertificate,
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
pub fn gateway_tls_leaf() -> DerCertificate {
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).expect("params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("TLS key");
    let certificate = params.self_signed(&key).expect("TLS certificate");
    DerCertificate::new(certificate.der().to_vec()).expect("DER")
}

/// One renewal's inputs: the domain, the gateway in service, and what it prepares.
pub struct Scenario {
    pub domain: Domain,
    pub in_service: InService,
    pub key_recovery: bool,
    pub request: GatewayCertificateRequest,
    pub candidate: DerCertificate,
}

impl Scenario {
    pub fn new(key_recovery: bool) -> Self {
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

    pub fn leaf(&self) -> Fingerprint {
        pq_certificate_fingerprint(&self.in_service.leaf).expect("fingerprint")
    }

    /// The campaign Astra freezes for the gateway's leaf `leaf`, one decision forward.
    pub fn campaign(&self, leaf: Fingerprint) -> AstraRotationCampaign {
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

pub fn gateway_read() -> GatewayIdentityRead {
    GatewayIdentityRead {
        now_unix: None,
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
pub struct Remote<'a> {
    pub domain: &'a Domain,
    pub campaign: AstraRotationCampaign,
    pub served: PqCertificate,
    pub request: GatewayCertificateRequest,
    pub candidate: Option<DerCertificate>,
    pub prepared: GatewayRenewalRead,
    pub gateway: GatewayIdentityRead,
    pub overlap: Option<u64>,
    pub open_refusal: Cell<Option<u16>>,
    /// Answers to the deposits, in order; once empty, Astra accepts. A number is a
    /// refusal or a lost answer with that status.
    pub submit_replies: RefCell<VecDeque<Result<SigningOperationState, u16>>>,
    /// Answers to the installations, in order; a number is a refusal with that status.
    pub install_replies: RefCell<VecDeque<u16>>,
    /// Answers to the publications, in order; once empty, the gateway relays.
    pub publish_replies: RefCell<VecDeque<Result<bool, u16>>>,
    pub calls: RefCell<Vec<&'static str>>,
    /// What each publication named: the epoch and the transition's fingerprint.
    pub published: RefCell<Vec<(u64, Fingerprint)>>,
    pub submitted: RefCell<Vec<AstraSignerResult>>,
    pub installed: RefCell<Vec<GatewayIdentityTransition>>,
    /// The transition the gateway holds staged, if any.
    pub staged: Option<GatewayIdentityTransition>,
    /// Answers to the cancellations, in order; once empty, the gateway takes them.
    pub abort_replies: RefCell<VecDeque<u16>>,
    pub aborted: RefCell<Vec<GatewayTransitionAbort>>,
    /// Answers to the rollbacks, in order; a number is a refusal with that status.
    pub rollback_replies: RefCell<VecDeque<u16>>,
    pub rolled: RefCell<Vec<CertificateServiceRollbackAuthorization>>,
}

impl<'a> Remote<'a> {
    pub fn new(scenario: &'a Scenario) -> Self {
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
            published: RefCell::default(),
            submitted: RefCell::default(),
            installed: RefCell::default(),
            staged: None,
            abort_replies: RefCell::default(),
            aborted: RefCell::default(),
            rollback_replies: RefCell::default(),
            rolled: RefCell::default(),
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }

    pub fn called(&self, name: &'static str) -> bool {
        self.calls.borrow().contains(&name)
    }

    pub fn count(&self, name: &'static str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| **call == name)
            .count()
    }

    pub fn note(&self, name: &'static str) {
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

    fn publish(
        &self,
        epoch: u64,
        transition_fingerprint: Fingerprint,
    ) -> Result<OperatorGatewayPublished> {
        self.note("publish");
        self.published
            .borrow_mut()
            .push((epoch, transition_fingerprint));
        match self.publish_replies.borrow_mut().pop_front() {
            None => Ok(OperatorGatewayPublished {
                epoch,
                relayed: true,
            }),
            Some(Ok(relayed)) => Ok(OperatorGatewayPublished { epoch, relayed }),
            Some(Err(status)) => Err(admin_refusal(status, None)),
        }
    }

    fn abort(&self, abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead> {
        self.note("abort");
        self.aborted.borrow_mut().push(abort.clone());
        match self.abort_replies.borrow_mut().pop_front() {
            Some(status) => Err(admin_refusal(status, Some("motif de la gateway".into()))),
            None => Ok(GatewayDecisionRead {
                gateway_identity_epoch: abort.gateway_identity_epoch,
                fingerprint: String::new(),
                already_present: false,
                activation_at: None,
                not_after: None,
            }),
        }
    }

    fn rollback(
        &self,
        authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead> {
        self.note("rollback");
        self.rolled.borrow_mut().push(authorization.clone());
        if let Some(status) = self.rollback_replies.borrow_mut().pop_front() {
            return Err(admin_refusal(status, None));
        }
        Ok(GatewayRollbackRead {
            expires_at: authorization.expires_at,
        })
    }

    fn staged_transition(&self) -> Result<Option<GatewayIdentityTransition>> {
        self.note("staged_transition");
        Ok(self.staged.clone())
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

/// A request the gateway kept is the one that stays: asked again with other options, it is
/// refused before any campaign opens, with the cause and the request's expiry.
#[test]
fn a_reused_request_with_other_options_is_refused_before_any_campaign() {
    let scenario = Scenario::new(false);
    let cases = [
        // (kept TLS candidate, kept key recovery, asked rotate_tls, asked key_recovery, cause)
        (false, false, true, false, "la feuille TLS candidate"),
        (false, false, false, true, "la perte de clé"),
        (
            false,
            false,
            true,
            true,
            "la feuille TLS candidate et la perte de clé",
        ),
        (true, false, false, false, "la feuille TLS candidate"),
    ];
    for (kept_tls, kept_recovery, rotate_tls, key_recovery, cause) in cases {
        let mut remote = Remote::new(&scenario);
        remote.prepared.reused = true;
        remote.prepared.candidate_tls_fingerprint =
            kept_tls.then(|| Fingerprint::of(b"kept TLS").to_hex());
        remote.prepared.key_recovery = kept_recovery;
        let asked = RenewalOptions {
            rotate_tls,
            key_recovery,
            ..options()
        };

        let refusal = open_renewal(&remote, &scenario.domain.path, asked, NOW)
            .err()
            .expect("refused");

        assert_eq!(
            refusal,
            GatewayRefusal::PreparedRequestDiffers {
                cause,
                expires_at: remote.prepared.expires_at,
            }
        );
        let sentence = refusal.to_string();
        assert!(sentence.contains(cause), "{sentence}");
        assert!(
            sentence.contains(&utc_label(remote.prepared.expires_at)),
            "{sentence}"
        );
        assert!(sentence.ends_with("Rien n'a été signé."), "{sentence}");
        assert!(!remote.called("open_campaign"), "no campaign is opened");
        assert_eq!(scenario.domain.touches(), 0, "no key is touched");
    }
}

/// The same request, asked with the options it was prepared with, goes on.
#[test]
fn a_reused_request_with_the_same_options_is_not_refused() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.prepared.reused = true;

    assert!(open_renewal(&remote, &scenario.domain.path, options(), NOW).is_ok());
    assert!(remote.called("open_campaign"));
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

/// The publication names the transition that was installed, not only its epoch.
#[test]
fn the_publication_names_the_transition_it_installed() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let decision = signed_decision(&remote, domain, options());
    let transition = transition_of(&decision).expect("transition").clone();

    carry(&remote, &domain.path, decision, NOW).expect("carried");

    assert_eq!(
        *remote.published.borrow(),
        vec![(
            transition.gateway_identity_epoch,
            transition.fingerprint().expect("fingerprint"),
        )]
    );
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

#[test]
fn a_lost_install_answer_resumes_without_redepositing() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.install_replies.borrow_mut().push_back(503);
    let decision = signed_decision(&remote, domain, options());

    let refusal =
        carry(&remote, &domain.path, decision, NOW).expect_err("the install answer was lost");
    assert_eq!(refusal, GatewayRefusal::Unreachable);
    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the decision waits");
    assert!(waiting.deposited, "Astra holds the decision");
    assert!(!waiting.installed);

    carry(&remote, &domain.path, waiting, NOW).expect("published on resume");

    assert_eq!(remote.count("submit_campaign"), 1, "no second deposit");
    assert_eq!(
        remote.count("install"),
        2,
        "the installation is asked again"
    );
    assert!(!record_on_disk(domain));
}

#[test]
fn a_deposited_decision_survives_campaign_expiry() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.install_replies.borrow_mut().push_back(503);
    let decision = signed_decision(&remote, domain, options());
    carry(&remote, &domain.path, decision, NOW).expect_err("the install answer was lost");

    let waiting = pending(&domain.path, EXPIRES)
        .expect("read")
        .expect("a deposited decision outlives its campaign");
    carry(&remote, &domain.path, waiting, EXPIRES).expect("published without the campaign");

    assert_eq!(
        remote.count("submit_campaign"),
        1,
        "no deposit after expiry"
    );
    assert!(!record_on_disk(domain));
}

#[test]
fn a_definitive_publish_refusal_keeps_the_record() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.publish_replies.borrow_mut().push_back(Err(409));
    let decision = signed_decision(&remote, domain, options());

    let refusal = carry(&remote, &domain.path, decision, NOW).expect_err("refused");

    assert!(matches!(refusal, GatewayRefusal::GatewayRefused(_)));
    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the record stays");
    assert!(waiting.installed && !waiting.published);
}

#[test]
fn rotate_tls_without_a_candidate_is_refused() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let rotating = RenewalOptions {
        rotate_tls: true,
        ..options()
    };

    let refusal = open_renewal(&remote, &scenario.domain.path, rotating, NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RequestMismatch);
    assert_eq!(scenario.domain.touches(), 0, "no key is touched");
}

#[test]
fn a_candidate_without_rotate_tls_is_refused() {
    let scenario = Scenario::new(false);
    let mut remote = Remote::new(&scenario);
    remote.candidate = Some(scenario.candidate.clone());
    remote.prepared.candidate_tls_fingerprint = Some(scenario.candidate.fingerprint().to_hex());

    let refusal = open_renewal(&remote, &scenario.domain.path, options(), NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RequestMismatch);
    assert_eq!(scenario.domain.touches(), 0, "no key is touched");
}

/// The campaign a cancellation or a rollback is approved under: the transition's own epoch.
fn cancellation_campaign(scenario: &Scenario, epoch: u64) -> AstraRotationCampaign {
    scenario.domain.campaign(
        CampaignScope::GatewayIdentity,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayPq,
            identity_key: gateway_key(),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: Fingerprint::of(ACTIVE_TLS),
            active_pq_certificate_fingerprint: scenario.leaf(),
        }],
        EXPIRES,
    )
}

/// A transition the renewal signed and the gateway holds staged. The record is removed,
/// as it is once the gateway holds the transition: no deposit waits.
fn staged(scenario: &Scenario) -> GatewayIdentityTransition {
    let remote = Remote::new(scenario);
    let decision = signed_decision(&remote, &scenario.domain, options());
    std::fs::remove_file(record_path(&scenario.domain.path)).expect("record removed");
    scenario
        .domain
        .keys
        .iter()
        .for_each(|key| key.touches.set(0));
    transition_of(&decision).expect("transition").clone()
}

/// The tunnel with `transition` staged, and the gateway's clock at `clock`. `published`
/// says whether Astra has relayed it, which ends the cancellation.
fn remote_with<'a>(
    scenario: &'a Scenario,
    transition: &GatewayIdentityTransition,
    clock: Option<u64>,
    published: bool,
) -> Remote<'a> {
    let mut remote = Remote::new(scenario);
    remote.campaign = cancellation_campaign(scenario, transition.gateway_identity_epoch);
    remote.staged = Some(transition.clone());
    remote.gateway = GatewayIdentityRead {
        now_unix: clock,
        gateway_identity_epoch: transition.gateway_identity_epoch,
        gateway_transition_pending: true,
        gateway_transition_published: published,
        gateway_activation_at: Some(transition.window.activation_at),
        ..gateway_read()
    };
    remote
}

fn refusal<T>(result: Result<T, GatewayRefusal>) -> GatewayRefusal {
    match result {
        Ok(_) => panic!("a refusal was expected"),
        Err(error) => error,
    }
}

fn no_key_touched(domain: &Domain) -> bool {
    domain.keys.iter().all(|key| key.touches.get() == 0)
}

#[test]
fn abort_runs_before_activation() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let remote = remote_with(&scenario, &transition, Some(NOW), false);
    let domain = &scenario.domain;

    let mut opened = open_abort(&remote, &domain.path, NOW).expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let decision = opened.sign_and_record(&domain.path, NOW).expect("signed");
    carry_abort(&remote, &domain.path, decision, NOW).expect("carried");

    let aborted = remote.aborted.borrow();
    assert_eq!(aborted.len(), 1);
    assert!(matches!(aborted[0].reason, AbortReason::OperatorCancelled));
    assert_eq!(
        aborted[0].gateway_identity_epoch,
        transition.gateway_identity_epoch
    );
    assert!(!record_on_disk(domain));
}

#[test]
fn abort_refused_at_activation() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let activation = transition.window.activation_at;
    let remote = remote_with(&scenario, &transition, Some(activation), false);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(error, GatewayRefusal::AbortTooLate(activation));
    assert!(!remote.called("open_campaign"));
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn abort_refused_once_published() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let remote = remote_with(&scenario, &transition, Some(NOW), true);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(
        error,
        GatewayRefusal::AbortTooLate(transition.window.activation_at)
    );
    assert!(!remote.called("open_campaign"));
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn a_live_gateway_operation_blocks_the_abort_by_name() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    // A renewal decision still waits in the record, not installed on the gateway.
    let renewal = Remote::new(&scenario);
    signed_decision(&renewal, &scenario.domain, options());
    let remote = remote_with(&scenario, &transition, Some(NOW), false);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(error, GatewayRefusal::AlreadyOpen);
    assert!(error.to_string().contains("identité de la gateway"));
    assert!(!remote.called("open_campaign"));
}

/// A renewal installed on the gateway and not published is what the cancellation
/// cancels: the abort record supersedes it at the same path.
#[test]
fn an_abort_supersedes_the_renewal_installed_and_not_published() {
    let scenario = Scenario::new(false);
    let domain = &scenario.domain;
    let renewal = Remote::new(&scenario);
    renewal.publish_replies.borrow_mut().push_back(Err(503));
    let decision = signed_decision(&renewal, domain, options());
    let transition = transition_of(&decision).expect("transition").clone();
    carry(&renewal, &domain.path, decision, NOW).expect_err("the publication was not confirmed");
    let waiting = pending(&domain.path, NOW)
        .expect("read")
        .expect("the renewal waits");
    assert!(waiting.installed && !waiting.published);
    domain.keys.iter().for_each(|key| key.touches.set(0));
    let remote = remote_with(&scenario, &transition, Some(NOW), false);

    let mut opened = open_abort(&remote, &domain.path, NOW).expect("the renewal does not block");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");

    let recorded = pending(&domain.path, NOW)
        .expect("read")
        .expect("the abort waits");
    assert_eq!(recorded.kind, GatewayDecisionKind::Abort);
    assert_eq!(recorded, signed);
    carry_abort(&remote, &domain.path, recorded, NOW).expect("carried");
    assert!(!record_on_disk(domain));
}

/// Only the renewal of the epoch staged is superseded.
#[test]
fn an_abort_does_not_supersede_a_renewal_of_another_epoch() {
    let scenario = Scenario::new(false);
    let domain = &scenario.domain;
    let renewal = Remote::new(&scenario);
    renewal.publish_replies.borrow_mut().push_back(Err(503));
    let decision = signed_decision(&renewal, domain, options());
    let mut transition = transition_of(&decision).expect("transition").clone();
    carry(&renewal, &domain.path, decision, NOW).expect_err("not confirmed");
    transition.gateway_identity_epoch += 1;
    let remote = remote_with(&scenario, &transition, Some(NOW), false);

    let error = refusal(open_abort(&remote, &domain.path, NOW));

    assert_eq!(error, GatewayRefusal::AlreadyOpen);
    assert!(!remote.called("open_campaign"));
}

#[test]
fn the_abort_clock_is_the_gateways_and_the_workstations_without_it() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let activation = transition.window.activation_at;

    // The gateway says it is past activation, while this workstation is not.
    let ahead = remote_with(&scenario, &transition, Some(activation), false);
    assert_eq!(
        refusal(open_abort(&ahead, &scenario.domain.path, NOW)),
        GatewayRefusal::AbortTooLate(activation)
    );

    // An older gateway sends no clock: the workstation's instant decides.
    let silent = remote_with(&scenario, &transition, None, false);
    assert!(open_abort(&silent, &scenario.domain.path, NOW).is_ok());
    assert_eq!(
        refusal(open_abort(&silent, &scenario.domain.path, activation)),
        GatewayRefusal::AbortTooLate(activation)
    );
}

#[test]
fn a_refused_abort_keeps_the_record() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let remote = remote_with(&scenario, &transition, Some(NOW), false);
    let domain = &scenario.domain;
    remote.abort_replies.borrow_mut().push_back(409);

    let mut opened = open_abort(&remote, &domain.path, NOW).expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let decision = opened.sign_and_record(&domain.path, NOW).expect("signed");
    let error = carry_abort(&remote, &domain.path, decision, NOW).expect_err("refused");

    assert!(matches!(error, GatewayRefusal::GatewayRefused(_)));
    assert!(record_on_disk(domain));
}

#[test]
fn rollback_runs_inside_the_overlap() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let clock = NOW + 8 * DAY;
    let remote = remote_with(&scenario, &transition, Some(clock), true);
    let domain = &scenario.domain;

    let mut opened =
        open_rollback(&remote, &domain.path, 24, "Retour arrière", "poste", clock).expect("opened");
    opened.approve(&domain.keys[0], clock).expect("approved");
    let authorization = opened.sign(&domain.path, clock).expect("signed");
    let read = carry_rollback(&remote, authorization.clone()).expect("carried");

    assert!(!remote.called("open_campaign"));
    assert_eq!(remote.rolled.borrow().len(), 1);
    assert_eq!(authorization.expires_at, clock + DAY);
    assert_eq!(read.expires_at, authorization.expires_at);
}

#[test]
fn rollback_refused_before_activation_and_after_not_after() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let domain = &scenario.domain;

    let early = transition.window.activation_at - 1;
    let remote = remote_with(&scenario, &transition, Some(early), true);
    assert_eq!(
        refusal(open_rollback(&remote, &domain.path, 24, "r", "p", early)),
        GatewayRefusal::NoOverlap
    );

    let late = transition.window.not_after;
    let remote = remote_with(&scenario, &transition, Some(late), true);
    assert_eq!(
        refusal(open_rollback(&remote, &domain.path, 24, "r", "p", late)),
        GatewayRefusal::NoOverlap
    );
    assert!(no_key_touched(domain));
}

#[test]
fn rollback_hours_are_capped_by_not_after() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let clock = transition.window.not_after - DAY;
    let remote = remote_with(&scenario, &transition, Some(clock), true);
    let domain = &scenario.domain;

    let mut opened = open_rollback(&remote, &domain.path, 1_000, "r", "p", clock).expect("opened");
    opened.approve(&domain.keys[0], clock).expect("approved");
    let authorization = opened.sign(&domain.path, clock).expect("signed");

    assert_eq!(authorization.expires_at, transition.window.not_after);
}

/// The transition the gateway holds, moved to another gateway's key.
fn foreign(transition: &GatewayIdentityTransition) -> GatewayIdentityTransition {
    GatewayIdentityTransition {
        gateway_wg_public_key: WireGuardKey::from_bytes([0x22; 32]),
        ..transition.clone()
    }
}

#[test]
fn abort_refuses_a_transition_for_another_gateway() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let remote = remote_with(&scenario, &foreign(&transition), Some(NOW), false);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(error, GatewayRefusal::CampaignMismatch);
    assert!(!remote.called("open_campaign"));
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn rollback_refuses_a_transition_for_another_gateway() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let clock = NOW + 8 * DAY;
    let remote = remote_with(&scenario, &foreign(&transition), Some(clock), true);

    let error = refusal(open_rollback(
        &remote,
        &scenario.domain.path,
        24,
        "r",
        "p",
        clock,
    ));

    assert_eq!(error, GatewayRefusal::CampaignMismatch);
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn abort_with_nothing_staged_is_refused() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(error, GatewayRefusal::NothingToAbort);
    assert!(!remote.called("open_campaign"));
}

#[test]
fn rollback_of_an_unpublished_transition_is_refused() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let clock = NOW + 8 * DAY;
    let remote = remote_with(&scenario, &transition, Some(clock), false);

    let error = refusal(open_rollback(
        &remote,
        &scenario.domain.path,
        24,
        "r",
        "p",
        clock,
    ));

    assert_eq!(error, GatewayRefusal::NoOverlap);
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn abort_refuses_a_campaign_of_another_epoch() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let mut remote = remote_with(&scenario, &transition, Some(NOW), false);
    remote.campaign = cancellation_campaign(&scenario, transition.gateway_identity_epoch + 1);

    let error = refusal(open_abort(&remote, &scenario.domain.path, NOW));

    assert_eq!(error, GatewayRefusal::CampaignMismatch);
    assert!(no_key_touched(&scenario.domain));
}

#[test]
fn a_record_of_the_other_kind_is_refused_and_named() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let domain = &scenario.domain;

    // A renewal waits: the abort's resume refuses it, and the record stays.
    let renewal = Remote::new(&scenario);
    let decision = signed_decision(&renewal, domain, options());
    assert_eq!(
        pending_kind(&domain.path, NOW).expect("read"),
        Some(GatewayDecisionKind::Renewal)
    );
    let remote = remote_with(&scenario, &transition, Some(NOW), false);
    assert_eq!(
        carry_abort(&remote, &domain.path, decision, NOW),
        Err(GatewayRefusal::OtherKindPending)
    );
    assert!(record_on_disk(domain));

    // Now the cancellation waits: the renewal's resume refuses it.
    discard_pending(&domain.path).expect("discarded");
    let mut opened = open_abort(&remote, &domain.path, NOW).expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let abort = opened.sign_and_record(&domain.path, NOW).expect("signed");
    assert_eq!(
        pending_kind(&domain.path, NOW).expect("read"),
        Some(GatewayDecisionKind::Abort)
    );
    assert_eq!(
        carry(&renewal, &domain.path, abort, NOW),
        Err(GatewayRefusal::OtherKindPending)
    );
}

#[test]
fn a_discarded_record_no_longer_blocks_a_renewal() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.submit_replies.borrow_mut().push_back(Err(409));

    let decision = signed_decision(&remote, domain, options());
    assert!(matches!(
        carry(&remote, &domain.path, decision, NOW),
        Err(GatewayRefusal::GatewayRefused(_))
    ));
    assert!(matches!(
        open_renewal(&remote, &domain.path, options(), NOW),
        Err(GatewayRefusal::AlreadyOpen)
    ));

    discard_pending(&domain.path).expect("discarded");

    assert!(!record_on_disk(domain));
    assert!(open_renewal(&remote, &domain.path, options(), NOW).is_ok());
}

#[test]
fn an_unconfirmed_rollback_says_it_is_not_resumed() {
    let scenario = Scenario::new(false);
    let transition = staged(&scenario);
    let clock = NOW + 8 * DAY;
    let remote = remote_with(&scenario, &transition, Some(clock), true);
    remote.rollback_replies.borrow_mut().push_back(503);
    let domain = &scenario.domain;

    let mut opened = open_rollback(&remote, &domain.path, 24, "r", "p", clock).expect("opened");
    opened.approve(&domain.keys[0], clock).expect("approved");
    let authorization = opened.sign(&domain.path, clock).expect("signed");

    assert_eq!(
        carry_rollback(&remote, authorization),
        Err(GatewayRefusal::RollbackUnreachable)
    );
}

const PUBLISH_LEFT: &str = "la décision est installée sur la gateway mais pas encore publiée : la reprendre pour la publier. Rien n'a été jeté.";

#[test]
fn a_decision_installed_but_not_published_is_not_discarded() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    remote.publish_replies.borrow_mut().push_back(Err(409));
    let decision = signed_decision(&remote, &scenario.domain, options());
    carry(&remote, &scenario.domain.path, decision, NOW).expect_err("the publication is refused");

    let refusal = discard_pending(&scenario.domain.path).expect_err("refused");

    assert_eq!(refusal, GatewayRefusal::NotDiscardable(PUBLISH_LEFT.into()));
    assert!(record_on_disk(&scenario.domain), "the record is kept");
}

#[test]
fn a_decision_never_deposited_is_discarded() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    signed_decision(&remote, &scenario.domain, options());

    discard_pending(&scenario.domain.path).expect("discarded");

    assert!(!record_on_disk(&scenario.domain));
}

#[test]
fn a_decision_deposited_but_not_installed_is_discarded() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    remote.install_replies.borrow_mut().push_back(409);
    let decision = signed_decision(&remote, &scenario.domain, options());
    carry(&remote, &scenario.domain.path, decision, NOW).expect_err("the install is refused");

    discard_pending(&scenario.domain.path).expect("discarded");

    assert!(!record_on_disk(&scenario.domain));
}

#[test]
fn a_finished_decision_leaves_nothing_to_discard() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let decision = signed_decision(&remote, &scenario.domain, options());
    carry(&remote, &scenario.domain.path, decision, NOW).expect("published");

    discard_pending(&scenario.domain.path).expect("nothing to discard");

    assert!(!record_on_disk(&scenario.domain));
}
