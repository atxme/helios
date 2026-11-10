//! The gateway revocation, against simulated keys and a simulated tunnel.
//!
//! The vault, the campaigns, the signatures and the record are the production code.
//! Only the CTAP2 boundary and the tunnel are simulated.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use aether::certificates::approval::{CredentialRegistry, CredentialState};
use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16};
use aether::certificates::gateway::{
    GatewayCertificateRequest, GatewayIdentityTransition, GatewayTransitionAbort,
};
use aether::certificates::revocation::RevocationScope;
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerResult, CampaignScope, CampaignTarget, CertificateKind,
    CertificateServiceRollbackAuthorization,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorGatewayPublished, OperatorOpenAction, OperatorOpenRequest,
    OperatorOpened, RevocationExpiries, SigningOperationState, TrustUpdateObject,
};
use aether::key_negotiation::PqCertificate;
use anyhow::Result;

use super::*;
use crate::operations::fixtures::{
    gateway_key, nothing_in_flight, operation, Domain, EXPIRES, NOW, SERVER_NAME,
};
use crate::operations::gateway_identity::tests::{gateway_read, Scenario, ACTIVE_TLS};
use crate::operations::gateway_identity::{
    self, open_renewal, GatewayDecisionKind, GatewayIdentityRemote, RenewalOptions,
};
use crate::origin::CampaignRequest;
use crate::tunnel::{
    admin_refusal, GatewayDecisionRead, GatewayIdentityRead, GatewayRenewalRead,
    GatewayRollbackRead, RenewalAsk,
};
use crate::{gestures, handoff, signing, store};

const DAY: u64 = 86_400;
const TLS_NOT_AFTER: u64 = EXPIRES + DAY;
const PQ_NOT_AFTER: u64 = EXPIRES + 2 * DAY;
const REVOCATION_CAMPAIGN: [u8; 16] = [10; 16];

/// The gateway's leaves as the revocation names them, and the expiries Astra reports.
fn revocation_campaign(domain: &Domain, leaf: Fingerprint) -> AstraRotationCampaign {
    let mut campaign = domain.campaign(
        CampaignScope::EmergencyRevocation,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayPq,
            identity_key: gateway_key(),
            epoch: 1,
            generation: 1,
            active_tls_certificate_fingerprint: Fingerprint::of(ACTIVE_TLS),
            active_pq_certificate_fingerprint: leaf,
        }],
        EXPIRES,
    );
    campaign.campaign_id = Id16::new(REVOCATION_CAMPAIGN).expect("id");
    campaign
}

/// The tunnel, as a test scripts it. Each call is recorded by name.
struct Remote<'a> {
    domain: &'a Domain,
    served: PqCertificate,
    request: GatewayCertificateRequest,
    candidate: DerCertificate,
    prepared: GatewayRenewalRead,
    gateway: GatewayIdentityRead,
    /// The overlap the gateway reports, if one runs.
    overlap: Option<u64>,
    status: RefCell<OperatorAuthorityStatus>,
    identity: AstraRotationCampaign,
    revocation: AstraRotationCampaign,
    /// The campaign the last opening opened: what a fetch and a deposit name.
    current: RefCell<Option<AstraRotationCampaign>>,
    expiries: RefCell<Option<RevocationExpiries>>,
    /// A status that refuses every opening.
    open_refusal: Cell<Option<u16>>,
    /// Answers to the deposits, in order; once empty, Astra accepts. A number is a
    /// refusal with that status.
    submit_replies: RefCell<VecDeque<Result<SigningOperationState, u16>>>,
    /// Answers to the installations, in order; a number is a refusal with that status.
    install_replies: RefCell<VecDeque<u16>>,
    calls: RefCell<Vec<&'static str>>,
    /// The labels the openings carried, in order.
    reasons: RefCell<Vec<String>>,
    submitted: RefCell<Vec<AstraSignerResult>>,
    installed: RefCell<Vec<GatewayIdentityTransition>>,
}

impl<'a> Remote<'a> {
    fn new(scenario: &'a Scenario) -> Self {
        let leaf = scenario.leaf();
        Self {
            domain: &scenario.domain,
            served: scenario.in_service.leaf.clone(),
            request: scenario.request.clone(),
            candidate: scenario.candidate.clone(),
            prepared: GatewayRenewalRead {
                gateway_identity_epoch: 2,
                request_fingerprint: scenario.request.fingerprint().to_hex(),
                expires_at: NOW + 3_600,
                candidate_tls_fingerprint: Some(scenario.candidate.fingerprint().to_hex()),
                reused: false,
                key_recovery: true,
            },
            gateway: gateway_read(),
            overlap: None,
            status: RefCell::new(nothing_in_flight(&scenario.domain.path)),
            identity: scenario.campaign(leaf),
            revocation: revocation_campaign(&scenario.domain, leaf),
            current: RefCell::default(),
            expiries: RefCell::new(Some(RevocationExpiries {
                tls_not_after: Some(TLS_NOT_AFTER),
                pq_not_after: Some(PQ_NOT_AFTER),
            })),
            open_refusal: Cell::new(None),
            submit_replies: RefCell::default(),
            install_replies: RefCell::default(),
            calls: RefCell::default(),
            reasons: RefCell::default(),
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
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        self.reasons.borrow_mut().push(request.reason.clone());
        match &request.action {
            OperatorOpenAction::GatewayIdentity => {
                self.note("open_identity");
                if let Some(status) = self.open_refusal.get() {
                    return Err(admin_refusal(status, None));
                }
                *self.current.borrow_mut() = Some(self.identity.clone());
                Ok(OperatorOpened {
                    operation_id: operation(),
                    campaign_id: self.identity.campaign_id,
                    campaign_fingerprint: self.identity.fingerprint(),
                    scope: CampaignScope::GatewayIdentity,
                    target_count: 1,
                    required_credentials: 1,
                    expires_at: EXPIRES,
                    revocation_expiries: None,
                    delegation_request: None,
                    gateway_certificate: Some(self.served.clone()),
                })
            }
            OperatorOpenAction::GatewayRevocation => {
                self.note("open_revocation");
                if let Some(status) = self.open_refusal.get() {
                    return Err(admin_refusal(status, None));
                }
                *self.current.borrow_mut() = Some(self.revocation.clone());
                Ok(OperatorOpened {
                    operation_id: operation(),
                    campaign_id: self.revocation.campaign_id,
                    campaign_fingerprint: self.revocation.fingerprint(),
                    scope: CampaignScope::EmergencyRevocation,
                    target_count: 1,
                    required_credentials: 1,
                    expires_at: EXPIRES,
                    revocation_expiries: *self.expiries.borrow(),
                    delegation_request: None,
                    gateway_certificate: None,
                })
            }
            _ => unreachable!("the gateway revocation opens only its two campaigns"),
        }
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        self.note("fetch_campaign");
        assert_eq!(*operation_id, operation());
        let campaign = self
            .current
            .borrow()
            .clone()
            .expect("a campaign was opened");
        Ok(self.domain.request(campaign))
    }

    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        self.note("submit");
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
        assert!(!ask.new_key, "the replacement keeps the sealed key");
        Ok(self.prepared.clone())
    }

    fn renewal_request(&self) -> Result<GatewayCertificateRequest> {
        self.note("renewal_request");
        Ok(self.request.clone())
    }

    fn candidate_tls(&self) -> Result<Option<DerCertificate>> {
        self.note("candidate_tls");
        Ok(Some(self.candidate.clone()))
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
                activation_at: None,
                not_after: None,
            }),
        }
    }

    fn publish(&self, _epoch: u64) -> Result<OperatorGatewayPublished> {
        unreachable!("an emergency replacement is installed at once, never published")
    }

    fn abort(&self, _abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead> {
        unreachable!("the revocation does not cancel a transition")
    }

    fn rollback(
        &self,
        _authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead> {
        unreachable!("the revocation does not roll back")
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
        Ok(self.status.borrow().clone())
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        self.note("overlap_not_after");
        Ok(self.overlap)
    }
}

fn reset_touches(domain: &Domain) {
    domain.keys.iter().for_each(|key| key.touches.set(0));
}

/// The document Astra serves before the rotation: the second key marked lost, signed under the
/// anchor the vault held at that moment.
fn served_document(domain: &Domain) -> CredentialRegistry {
    let vault = store::load(&domain.path).expect("vault");
    let identity = handoff::identity_of(&domain.relay()).expect("identity");
    let opening = gestures::open_with_authorized_key(&domain.keys[2], &vault, "").expect("opened");
    signing::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        Some(&domain.registry()),
        &[(domain.keys[1].credential_id(), CredentialState::Lost)],
        NOW,
    )
    .expect("signed")
}

fn record_on_disk(domain: &Domain) -> bool {
    domain
        .path
        .parent()
        .expect("parent")
        .join(PENDING_FILE)
        .exists()
}

/// The replacement's first round: opened, approved by one key, signed and recorded.
fn sign_replacement(remote: &Remote, domain: &Domain) -> SignedGatewayRevocation {
    let mut opened = open_gateway_revocation(
        remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        true,
        NOW,
    )
    .expect("the replacement opens");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    opened
        .sign_and_record(&domain.path, NOW)
        .expect("the replacement is signed")
}

/// The revocation's round, under the second key.
fn sign_revocation(
    remote: &Remote,
    domain: &Domain,
    with_replacement: bool,
) -> SignedGatewayRevocation {
    let mut opened = open_gateway_revocation(
        remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        with_replacement,
        NOW,
    )
    .expect("the revocation opens");
    opened.approve(&domain.keys[1], NOW).expect("approved");
    opened
        .sign_and_record(&domain.path, NOW)
        .expect("the revocation is signed")
}

fn revocation_of(signed: &SignedGatewayRevocation) -> &SignedRevocation {
    signed
        .revocation
        .as_ref()
        .expect("the revocation is signed")
}

fn transition_of_record(signed: &SignedGatewayRevocation) -> &GatewayIdentityTransition {
    match signed
        .replacement
        .as_ref()
        .expect("the replacement is recorded")
        .result
        .objects
        .first()
    {
        Some(TrustUpdateObject::GatewayIdentityTransition(transition)) => transition,
        _ => panic!("the replacement is a transition"),
    }
}

#[test]
fn revocation_with_replacement_applies_revocation_then_transition() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;

    let replacement = sign_replacement(&remote, domain);
    assert!(
        replacement.revocation.is_none(),
        "the first round holds no revocation yet"
    );
    assert!(
        !replacement
            .replacement
            .as_ref()
            .expect("replacement")
            .deposited,
        "nothing is deposited before the record is written"
    );
    assert!(
        record_on_disk(domain),
        "the record is written before any deposit"
    );
    assert_eq!(remote.count("submit"), 0, "nothing is deposited yet");
    assert_eq!(domain.touches(), 2, "one key, approval then opening");

    let refusal = carry_revocation(&remote, &domain.path, replacement, NOW)
        .expect_err("the replacement alone does not carry");
    assert_eq!(refusal, GatewayRefusal::RevocationToSign);
    assert_eq!(remote.count("submit"), 1, "the replacement is deposited");
    assert!(
        !remote.called("install"),
        "nothing is installed before the revocation"
    );

    let signed = sign_revocation(&remote, domain, true);
    let revocation = revocation_of(&signed);
    let TrustUpdateObject::CertificateRevocation(object) = &revocation.result.objects[0] else {
        panic!("the second round signs a revocation");
    };
    assert_eq!(
        object.replacement_transition_fingerprint,
        Some(
            transition_of_record(&signed)
                .fingerprint()
                .expect("fingerprint")
        ),
        "the revocation names the transition as signed"
    );

    carry_revocation(&remote, &domain.path, signed, NOW).expect("carried");

    assert_eq!(
        remote.calls(),
        [
            // The replacement's round: the anchor, then the renewal's own reads.
            "overlap_not_after",
            "authority_status",
            "gateway",
            "overlap_not_after",
            "prepare_renewal",
            "open_identity",
            "fetch_campaign",
            "renewal_request",
            "candidate_tls",
            // Deposited before the revocation's campaign is opened.
            "fetch_campaign",
            "submit",
            // The revocation's round, then its deposit, then the installation.
            "overlap_not_after",
            "authority_status",
            "open_revocation",
            "fetch_campaign",
            "fetch_campaign",
            "submit",
            "install",
        ],
        "the replacement is deposited before the revocation's campaign opens, and the \
         revocation is deposited before the transition is installed"
    );
    assert_eq!(remote.installed.borrow().len(), 1);
    assert!(
        !record_on_disk(domain),
        "a finished gesture clears the record"
    );
    assert_eq!(domain.touches(), 4, "two keys, each approval then opening");
}

#[test]
fn revocation_without_replacement_names_no_transition() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;

    let signed = sign_revocation(&remote, domain, false);
    assert!(signed.replacement.is_none());
    carry_revocation(&remote, &domain.path, signed, NOW).expect("carried");

    assert!(
        !remote.called("prepare_renewal"),
        "no replacement is prepared"
    );
    assert!(!remote.called("install"), "no transition is installed");
    assert_eq!(
        remote.count("submit"),
        1,
        "only the revocation is deposited"
    );
    let TrustUpdateObject::CertificateRevocation(object) = &remote.submitted.borrow()[0].objects[0]
    else {
        panic!("the deposit is a revocation");
    };
    assert_eq!(object.replacement_transition_fingerprint, None);
    assert!(!record_on_disk(domain));
}

#[test]
fn resume_applies_the_replacement_after_the_revocation() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let replacement = sign_replacement(&remote, domain);
    carry_revocation(&remote, &domain.path, replacement, NOW)
        .expect_err("the revocation is still to sign");
    let signed = sign_revocation(&remote, domain, true);
    // The gateway refuses the installation once: the revocation is applied, the
    // replacement is not.
    remote.install_replies.borrow_mut().push_back(409);
    let refusal = carry_revocation(&remote, &domain.path, signed, NOW)
        .expect_err("the gateway refuses the installation");
    assert!(
        matches!(refusal, GatewayRefusal::GatewayRefused(_)),
        "{refusal:?}"
    );
    let kept = pending_revocation(&domain.path, NOW)
        .expect("read")
        .expect("the record waits");
    assert!(kept.revocation_applied, "the revocation was applied");
    assert!(!kept.replacement_installed);
    let touches = domain.touches();
    let submits = remote.count("submit");

    carry_revocation(&remote, &domain.path, kept, NOW).expect("resumed");

    assert_eq!(domain.touches(), touches, "the resume touches no key");
    assert_eq!(
        remote.count("submit"),
        submits,
        "the resume deposits nothing again"
    );
    assert_eq!(
        remote.installed.borrow().len(),
        2,
        "the transition is installed on resume"
    );
    assert!(!record_on_disk(domain));
}

#[test]
fn both_halves_are_revoked_with_the_campaign_expiries() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let replacement = sign_replacement(&remote, domain);
    carry_revocation(&remote, &domain.path, replacement, NOW).expect_err("to sign");
    let signed = sign_revocation(&remote, domain, true);

    let TrustUpdateObject::CertificateRevocation(object) =
        &revocation_of(&signed).result.objects[0]
    else {
        panic!("a revocation");
    };
    assert_eq!(object.scope, RevocationScope::Gateway);
    assert_eq!(object.server_name.as_deref(), Some(SERVER_NAME));
    assert_eq!(object.identity_key, gateway_key());
    assert_eq!(object.revocation_epoch, 2, "the gateway's epoch plus one");
    assert_eq!(
        object.revoked_tls_fingerprint,
        Some(Fingerprint::of(ACTIVE_TLS))
    );
    assert_eq!(object.revoked_tls_not_after, Some(TLS_NOT_AFTER));
    assert_eq!(
        object.revoked_pq_fingerprint,
        Some(scenario.leaf()),
        "the leaf in service is the one revoked"
    );
    assert_eq!(object.revoked_pq_not_after, Some(PQ_NOT_AFTER));
}

/// The replacement deposited, then the revocation accepted by Astra with its answer lost: the
/// record holds the revocation unapplied.
fn lost_revocation_answer(remote: &Remote<'_>, domain: &Domain) -> SignedGatewayRevocation {
    let replacement = sign_replacement(remote, domain);
    carry_revocation(remote, &domain.path, replacement, NOW)
        .expect_err("the revocation is to sign");
    let signed = sign_revocation(remote, domain, true);
    remote.submit_replies.borrow_mut().push_back(Err(500));
    carry_revocation(remote, &domain.path, signed, NOW).expect_err("the answer was lost");
    pending_revocation(&domain.path, NOW)
        .expect("read")
        .expect("the record waits")
}

fn record_bytes(domain: &Domain) -> Vec<u8> {
    std::fs::read(domain.path.parent().expect("parent").join(PENDING_FILE)).expect("record")
}

#[test]
fn an_accepted_revocation_whose_answer_was_lost_is_completed_by_the_replacement() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let kept = lost_revocation_answer(&remote, domain);
    assert!(!kept.revocation_applied, "the answer was lost");
    let rounds = remote.count("open_revocation");

    // The campaign has closed. The gateway accepts the replacement: it was revoked.
    let at_expiry = pending_revocation(&domain.path, EXPIRES)
        .expect("read")
        .expect("the record still waits");
    carry_revocation(&remote, &domain.path, at_expiry, EXPIRES).expect("completed");

    assert_eq!(
        remote.count("open_revocation"),
        rounds,
        "no new revocation round"
    );
    assert_eq!(
        remote.installed.borrow().len(),
        1,
        "the replacement is installed once"
    );
    assert!(!record_on_disk(domain));
}

#[test]
fn a_refused_probe_returns_to_sign_and_keeps_the_replacement() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    lost_revocation_answer(&remote, domain);
    // The gateway refuses the replacement: the revocation never applied.
    remote.install_replies.borrow_mut().push_back(409);
    let at_expiry = pending_revocation(&domain.path, EXPIRES)
        .expect("read")
        .expect("the record still waits");

    let refusal = carry_revocation(&remote, &domain.path, at_expiry, EXPIRES)
        .expect_err("the revocation is to sign again");

    assert_eq!(refusal, GatewayRefusal::RevocationToSign);
    let kept = pending_revocation(&domain.path, EXPIRES)
        .expect("read")
        .expect("the replacement waits");
    assert!(
        kept.revocation.is_none(),
        "the expired revocation is dropped"
    );
    assert!(kept.replacement.as_ref().expect("replacement").deposited);
    open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        true,
        NOW,
    )
    .expect("the revocation round opens again");
}

#[test]
fn an_unreachable_probe_keeps_the_record_unchanged() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    lost_revocation_answer(&remote, domain);
    remote.install_replies.borrow_mut().push_back(500);
    let before = record_bytes(domain);
    let at_expiry = pending_revocation(&domain.path, EXPIRES)
        .expect("read")
        .expect("the record still waits");
    let before_probe = record_bytes(domain);
    assert_eq!(before, before_probe);

    let refusal = carry_revocation(&remote, &domain.path, at_expiry, EXPIRES)
        .expect_err("the gateway did not answer");

    assert!(
        matches!(refusal, GatewayRefusal::Internal(_)),
        "{refusal:?}"
    );
    assert_eq!(record_bytes(domain), before, "nothing is dropped");
}

#[test]
fn the_replacement_round_carries_its_own_label() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    sign_replacement(&remote, &scenario.domain);
    assert_eq!(
        remote.reasons.borrow().as_slice(),
        ["Identité de remplacement de la gateway, avant sa révocation".to_string()],
    );
}

#[test]
fn an_overlap_end_already_past_names_no_date() {
    let scenario = Scenario::new(true);
    let mut remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    remote.overlap = Some(NOW - 1);

    let refusal = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        true,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, GatewayRefusal::ReplacementAwaitsOverlap);
    assert!(!remote.called("open_identity"), "no campaign is opened");
    assert_eq!(domain.touches(), 0);
}

#[test]
fn rollback_is_refused_while_a_revocation_waits() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    sign_revocation(&remote, domain, false);

    let refusal = gateway_identity::open_rollback(&remote, &domain.path, 1, "motif", "Orion", NOW)
        .err()
        .expect("refused");

    assert_eq!(refusal, GatewayRefusal::RevocationPending);
    assert!(!remote.called("gateway"), "the gateway is not read");
}

#[test]
fn a_missing_expiry_refuses_before_a_key() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    *remote.expiries.borrow_mut() = Some(RevocationExpiries {
        tls_not_after: Some(TLS_NOT_AFTER),
        pq_not_after: None,
    });

    let refusal = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Replaced,
        false,
        NOW,
    )
    .err()
    .expect("refused");

    assert!(
        matches!(refusal, GatewayRefusal::Internal(_)),
        "{refusal:?}"
    );
    assert_eq!(domain.touches(), 0, "no key is touched");
    assert!(!remote.called("submit"));
    assert!(!record_on_disk(domain));
}

#[test]
fn during_a_ca_pq_overlap_the_revocation_follows_the_5c_anchor() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    // Astra serves the document as it was before the rotation, under the outgoing anchor.
    let served = served_document(domain);
    promoted(domain);
    let (outgoing, outgoing_epoch, _) = store::load(&domain.path)
        .expect("vault")
        .retained_outgoing_ca_pq_public()
        .expect("the outgoing key is kept");
    {
        let mut status = remote.status.borrow_mut();
        status.ca_fingerprint = outgoing.authority_fingerprint();
        status.ca_epoch = outgoing_epoch;
        status.served_credentials = Some(Box::new(served));
    }
    reset_touches(domain);
    // The second key is lost in the served document: the first one approves.
    let mut opened = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        false,
        NOW,
    )
    .expect("opened under the outgoing anchor");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");

    let revocation = revocation_of(&signed);
    let TrustUpdateObject::CertificateRevocation(object) = &revocation.result.objects[0] else {
        panic!("a revocation");
    };
    assert_eq!(
        object.ca_epoch, outgoing_epoch,
        "signed under the outgoing epoch"
    );
    let trust_domain = handoff::identity_of(&domain.relay())
        .expect("identity")
        .trust_domain_id;
    object
        .verify(&outgoing, &trust_domain, outgoing_epoch, 1)
        .expect("verifies under the outgoing anchor, which the gateway holds as current");
}

#[test]
fn with_replacement_during_an_overlap_is_refused_before_any_key() {
    let scenario = Scenario::new(true);
    let mut remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    promoted(domain);
    let (_, _, end) = store::load(&domain.path)
        .expect("vault")
        .retained_outgoing_ca_pq_public()
        .expect("the outgoing key is kept");
    remote.overlap = Some(end);
    reset_touches(domain);

    let refusal = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        true,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, GatewayRefusal::ReplacementNotBefore(end));
    assert!(!remote.called("prepare_renewal"), "nothing is prepared");
    assert!(!remote.called("open_identity"), "no campaign is opened");
    assert_eq!(domain.touches(), 0);
    assert!(!record_on_disk(domain));
}

#[test]
fn a_revocation_naming_leaves_the_replacement_does_not_replace_is_refused() {
    let scenario = Scenario::new(true);
    let mut remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let replacement = sign_replacement(&remote, domain);
    carry_revocation(&remote, &domain.path, replacement, NOW).expect_err("to sign");
    remote.revocation = revocation_campaign(domain, Fingerprint::of(b"une autre feuille"));
    let touches = domain.touches();

    let refusal = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        true,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, GatewayRefusal::CampaignMismatch);
    assert_eq!(domain.touches(), touches, "no key is touched");
}

#[test]
fn a_recorded_replacement_is_deposited_once_and_replayed_without_a_key() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let replacement = sign_replacement(&remote, domain);
    let bytes = remote_bytes_of(&replacement);
    // The first answer is lost on the tunnel: the replacement is replayed.
    remote.submit_replies.borrow_mut().push_back(Err(500));
    let refusal =
        carry_revocation(&remote, &domain.path, replacement, NOW).expect_err("the answer was lost");
    assert!(
        matches!(refusal, GatewayRefusal::Internal(_)),
        "{refusal:?}"
    );
    let kept = pending_revocation(&domain.path, NOW)
        .expect("read")
        .expect("the record waits");
    assert!(!kept.replacement.as_ref().expect("replacement").deposited);
    let touches = domain.touches();

    let refusal = carry_revocation(&remote, &domain.path, kept, NOW)
        .expect_err("the revocation is still to sign");

    assert_eq!(refusal, GatewayRefusal::RevocationToSign);
    assert_eq!(domain.touches(), touches, "the replay touches no key");
    let submitted = remote.submitted.borrow();
    assert_eq!(submitted.len(), 2);
    assert_eq!(
        remote_bytes(&submitted[1]),
        bytes,
        "the same bytes are sent again"
    );
}

#[test]
fn an_expired_replacement_campaign_discards_the_record() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let replacement = sign_replacement(&remote, domain);

    let refusal = carry_revocation(&remote, &domain.path, replacement, EXPIRES)
        .expect_err("expired before the deposit");

    assert!(
        matches!(refusal, GatewayRefusal::Internal(_)),
        "{refusal:?}"
    );
    assert!(
        !record_on_disk(domain),
        "the expired replacement is discarded"
    );
    assert!(!remote.called("submit"), "nothing is deposited late");
}

#[test]
fn a_refused_revocation_keeps_the_record_until_it_is_discarded() {
    let scenario = Scenario::new(false);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;
    let signed = sign_revocation(&remote, domain, false);
    remote.submit_replies.borrow_mut().push_back(Err(409));

    let refusal =
        carry_revocation(&remote, &domain.path, signed, NOW).expect_err("refused for good");
    assert!(
        matches!(refusal, GatewayRefusal::GatewayRefused(_)),
        "{refusal:?}"
    );
    assert!(record_on_disk(domain), "the refused decision waits");
    let blocked = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        false,
        NOW,
    )
    .err()
    .expect("blocked");
    assert_eq!(blocked, GatewayRefusal::RevocationAlreadyOpen);

    discard_pending_revocation(&domain.path).expect("discarded");

    assert!(!record_on_disk(domain));
    open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        false,
        NOW,
    )
    .expect("a new revocation opens");
}

#[test]
fn a_pending_record_of_either_gesture_blocks_the_other() {
    let scenario = Scenario::new(true);
    let remote = Remote::new(&scenario);
    let domain = &scenario.domain;

    // A renewal decision waits: no revocation opens.
    let mut renewal = open_renewal(&remote, &domain.path, renewal_options(), NOW).expect("opened");
    renewal.approve(&domain.keys[0], NOW).expect("approved");
    let decision = renewal.sign_and_record(&domain.path, NOW).expect("signed");
    assert_eq!(decision.kind, GatewayDecisionKind::Renewal);
    let refusal = open_gateway_revocation(
        &remote,
        &domain.path,
        RevocationReasonChoice::Compromised,
        false,
        NOW,
    )
    .err()
    .expect("blocked");
    assert_eq!(refusal, GatewayRefusal::DecisionPending);
    gateway_identity::discard_pending(&domain.path).expect("discarded");

    // A revocation waits: no renewal opens, and no cancellation either.
    let replacement = sign_replacement(&remote, domain);
    assert!(replacement.replacement.is_some());
    let refusal = open_renewal(&remote, &domain.path, renewal_options(), NOW)
        .err()
        .expect("blocked");
    assert_eq!(refusal, GatewayRefusal::RevocationPending);
    let refusal = gateway_identity::open_abort(&remote, &domain.path, NOW)
        .err()
        .expect("blocked");
    assert_eq!(refusal, GatewayRefusal::RevocationPending);
}

fn renewal_options() -> RenewalOptions {
    RenewalOptions {
        rotate_tls: true,
        key_recovery: true,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 365,
    }
}

/// The public bytes of a signed result, as the deposit sends them.
fn remote_bytes(result: &AstraSignerResult) -> Vec<u8> {
    serde_json::to_vec(result).expect("serialized")
}

fn remote_bytes_of(signed: &SignedGatewayRevocation) -> Vec<u8> {
    remote_bytes(&signed.replacement.as_ref().expect("replacement").result)
}

/// The vault after a CA-PQ rotation: the outgoing key is kept until the overlap ends.
fn promoted(domain: &Domain) {
    let mut journal = domain.signed(crate::rotation_journal::RotationKind::CaPq);
    crate::rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");
    crate::rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");
    crate::rotation_journal::clear(&crate::rotation_journal::path_beside(&domain.path))
        .expect("cleared");
}
