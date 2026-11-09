//! The revocation sequence, against simulated keys and a simulated tunnel.
//!
//! The vault, the document, the campaign requests and every signature are the
//! production code. Only the CTAP2 boundary and the tunnel are simulated.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::PathBuf;

use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87PublicKey, WireGuardKey};
use aether::certificates::status::{
    AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorOpenRequest, OperatorOpened, RevocationExpiries,
    SigningOperationState, TrustUpdateObject,
};

use aether::certificates::status::AstraSignerResult;

use super::*;
use crate::operations::fixtures::{domain, nothing_in_flight, operation, Domain, EXPIRES, NOW};
use crate::origin::CampaignRequest;
use crate::rotation_journal::{self, RotationKind};
use crate::tunnel::admin_refusal;
use crate::{handoff, store};

const TLS_NOT_AFTER: u64 = EXPIRES + 86_400;
const PQ_NOT_AFTER: u64 = EXPIRES + 2 * 86_400;

fn peer() -> WireGuardKey {
    WireGuardKey::from_bytes([7; 32])
}

fn other_peer() -> WireGuardKey {
    WireGuardKey::from_bytes([8; 32])
}

/// The one row an emergency revocation of `key` carries, as the door resolves it.
fn revocation_campaign(domain: &Domain, key: WireGuardKey) -> AstraRotationCampaign {
    domain.campaign(
        CampaignScope::EmergencyRevocation,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientTls,
            identity_key: key,
            epoch: 0,
            generation: 0,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls leaf"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq leaf"),
        }],
        EXPIRES,
    )
}

/// The tunnel, as a test scripts it. Each call is recorded by name.
struct Remote {
    vault_path: PathBuf,
    calls: RefCell<Vec<&'static str>>,
    /// `None` makes the read fail.
    authority: RefCell<Option<OperatorAuthorityStatus>>,
    /// Campaign requests, in the order the calls read them.
    requests: RefCell<VecDeque<CampaignRequest>>,
    /// Answers to the deposits, in order; once empty, Astra accepts. A number is a
    /// refusal with that status.
    replies: RefCell<VecDeque<Result<SigningOperationState, u16>>>,
    submitted: RefCell<Vec<AstraSignerResult>>,
    /// Whether the record was on disk at the moment of a deposit.
    record_at_submit: Cell<Option<bool>>,
    open_refusal: Cell<Option<u16>>,
}

impl Remote {
    fn watching(domain: &Domain, campaigns: Vec<AstraRotationCampaign>) -> Self {
        Self {
            vault_path: domain.path.clone(),
            calls: RefCell::default(),
            authority: RefCell::new(Some(nothing_in_flight(&domain.path))),
            requests: RefCell::new(campaigns.into_iter().map(|c| domain.request(c)).collect()),
            replies: RefCell::default(),
            submitted: RefCell::default(),
            record_at_submit: Cell::new(None),
            open_refusal: Cell::new(None),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }

    fn called(&self, name: &'static str) -> bool {
        self.calls.borrow().contains(&name)
    }

    fn note(&self, name: &'static str) {
        self.calls.borrow_mut().push(name);
    }
}

impl RevocationRemote for Remote {
    fn open_campaign(&self, _request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        self.note("open_campaign");
        if let Some(status) = self.open_refusal.get() {
            return Err(admin_refusal(status, None));
        }
        Ok(OperatorOpened {
            operation_id: operation(),
            campaign_id: Id16::new([9; 16]).expect("id"),
            campaign_fingerprint: Fingerprint::of(b"campagne"),
            scope: CampaignScope::EmergencyRevocation,
            target_count: 1,
            required_credentials: 1,
            expires_at: EXPIRES,
            revocation_expiries: Some(RevocationExpiries {
                tls_not_after: Some(TLS_NOT_AFTER),
                pq_not_after: Some(PQ_NOT_AFTER),
            }),
            delegation_request: None,
        })
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        self.note("fetch_campaign");
        assert_eq!(*operation_id, operation());
        Ok(self
            .requests
            .borrow_mut()
            .pop_front()
            .expect("an armed campaign"))
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
        self.record_at_submit.set(Some(
            self.vault_path
                .parent()
                .expect("parent")
                .join(PENDING_FILE)
                .exists(),
        ));
        self.submitted.borrow_mut().push(result.clone());
        match self.replies.borrow_mut().pop_front() {
            None => Ok(SigningOperationState::Approved),
            Some(Ok(state)) => Ok(state),
            Some(Err(status)) => Err(admin_refusal(status, None)),
        }
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        self.note("authority_status");
        match &*self.authority.borrow() {
            Some(status) => Ok(status.clone()),
            None => Err(admin_refusal(503, None)),
        }
    }

    fn overlap_not_after(&self) -> Result<Option<u64>> {
        self.note("overlap_not_after");
        Ok(None)
    }
}

/// The `CA-PQ` rotation of the fixture, taken to its promotion: the vault now holds
/// the new anchor and the outgoing key, as after Astra accepted the rotation.
fn promoted(domain: &Domain) {
    let mut journal = domain.signed(RotationKind::CaPq);
    rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");
    rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");
    rotation_journal::clear(&rotation_journal::path_beside(&domain.path)).expect("cleared");
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
fn opens_and_offers_only_active_keys_of_the_chosen_document() {
    let domain = domain();
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, peer())]);

    let mut opened = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::StolenOrLost,
        NOW,
    )
    .expect("opened");

    assert_eq!(opened.required_credentials(), 1);
    assert_eq!(opened.subject_name(), peer().to_base64());
    let active: Vec<Vec<u8>> = domain
        .registry()
        .approvable()
        .iter()
        .map(|binding| binding.credential_id.clone())
        .collect();
    assert_eq!(active.len(), 3);
    assert_eq!(opened.offered(), active);
    assert_eq!(domain.touches(), 0, "opening touches no key");
    assert_eq!(
        remote.calls(),
        [
            "authority_status",
            "overlap_not_after",
            "open_campaign",
            "fetch_campaign"
        ]
    );
    // A key still answers, so the offer is not a dead end.
    opened.approve(&domain.keys[0], NOW).expect("approved");
}

#[test]
fn outgoing_anchor_uses_the_served_document() {
    let domain = domain();
    let served = domain.registry();
    promoted(&domain);
    let (outgoing, outgoing_epoch) = retained(&domain);
    let mut status = nothing_in_flight(&domain.path);
    status.ca_fingerprint = outgoing.authority_fingerprint();
    status.ca_epoch = outgoing_epoch;
    status.credential_registry_epoch = Some(served.credential_registry_epoch);
    status.served_credentials = Some(Box::new(served.clone()));
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, peer())]);
    *remote.authority.borrow_mut() = Some(status);

    let mut opened = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::Compromised,
        NOW,
    )
    .expect("the outgoing anchor is checked");
    let active: Vec<Vec<u8>> = served
        .approvable()
        .iter()
        .map(|binding| binding.credential_id.clone())
        .collect();
    assert_eq!(
        opened.offered(),
        active,
        "the served document decides the offer"
    );
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");

    let TrustUpdateObject::CertificateRevocation(revocation) = &signed.result.objects[0] else {
        panic!("the decision is a revocation");
    };
    assert_eq!(
        revocation.ca_epoch, outgoing_epoch,
        "signed under the outgoing epoch"
    );
    let trust_domain = handoff::identity_of(&domain.relay())
        .expect("identity")
        .trust_domain_id;
    revocation
        .verify(&outgoing, &trust_domain, outgoing_epoch, 0)
        .expect("verifies under the outgoing anchor");
}

#[test]
fn unverifiable_served_document_is_refused_before_any_touch() {
    let domain = domain();
    promoted(&domain);
    let (outgoing, outgoing_epoch) = retained(&domain);
    let mut status = nothing_in_flight(&domain.path);
    status.ca_fingerprint = outgoing.authority_fingerprint();
    status.ca_epoch = outgoing_epoch;
    // What Astra serves now is the document of the new anchor: it does not verify
    // under the one checked.
    status.served_credentials = Some(Box::new(domain.registry()));
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, peer())]);
    *remote.authority.borrow_mut() = Some(status);
    let touches = domain.touches();

    let refusal = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::Replaced,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, RevocationRefusal::CredentialsUnverified);
    assert!(!remote.called("open_campaign"), "no campaign is opened");
    assert_eq!(domain.touches(), touches, "no key is touched");
}

/// The outgoing `CA-PQ` the promoted vault keeps, and its epoch.
fn retained(domain: &Domain) -> (MlDsa87PublicKey, u64) {
    let (key, epoch, _) = store::load(&domain.path)
        .expect("vault")
        .retained_outgoing_ca_pq_public()
        .expect("the outgoing key is kept");
    (key, epoch)
}

#[test]
fn campaign_naming_another_key_is_refused() {
    let domain = domain();
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, other_peer())]);

    let refusal = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::NoLongerUsed,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, RevocationRefusal::CampaignMismatch);
    assert_eq!(domain.touches(), 0);
}

#[test]
fn signed_decision_is_recorded_before_deposit() {
    let domain = domain();
    let remote = Remote::watching(
        &domain,
        vec![
            revocation_campaign(&domain, peer()),
            revocation_campaign(&domain, peer()),
        ],
    );
    let mut opened = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::StolenOrLost,
        NOW,
    )
    .expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");

    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");

    assert_eq!(
        pending(&domain.path, NOW).expect("read"),
        Some(signed.clone())
    );
    assert_eq!(
        deposit(&remote, &domain.path, &signed).expect("deposited"),
        RevocationDeposit::Accepted
    );
    assert_eq!(
        remote.record_at_submit.get(),
        Some(true),
        "the record was on disk when the deposit left"
    );
    assert!(!record_on_disk(&domain), "accepted clears the record");
}

#[test]
fn lost_answer_redeposits_the_same_bytes_without_a_key() {
    let domain = domain();
    let remote = Remote::watching(
        &domain,
        vec![
            revocation_campaign(&domain, peer()),
            revocation_campaign(&domain, peer()),
            revocation_campaign(&domain, peer()),
        ],
    );
    remote.replies.borrow_mut().push_back(Err(503));
    let mut opened = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::Compromised,
        NOW,
    )
    .expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");
    let touches = domain.touches();
    let record_before =
        std::fs::read(domain.path.parent().expect("parent").join(PENDING_FILE)).expect("record");

    assert!(
        deposit(&remote, &domain.path, &signed).is_err(),
        "the answer was lost"
    );
    assert!(record_on_disk(&domain), "the decision stays recorded");
    assert_eq!(
        deposit(&remote, &domain.path, &signed).expect("replayed"),
        RevocationDeposit::Accepted
    );

    let submitted = remote.submitted.borrow();
    assert_eq!(submitted.len(), 2);
    assert_eq!(submitted[0], submitted[1], "the same bytes are sent");
    let record_after = std::fs::read(domain.path.parent().expect("parent").join(PENDING_FILE));
    assert!(record_after.is_err(), "accepted clears the record");
    assert_eq!(
        record_before,
        serde_json::to_vec_pretty(&signed)
            .map(|mut b| {
                b.push(b'\n');
                b
            })
            .expect("json")
    );
    assert_eq!(domain.touches(), touches, "the replay touches no key");
}

#[test]
fn expired_campaign_discards_the_record() {
    let domain = domain();
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, peer())]);
    let mut opened = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::Replaced,
        NOW,
    )
    .expect("opened");
    opened.approve(&domain.keys[0], NOW).expect("approved");
    let signed = opened.sign_and_record(&domain.path, NOW).expect("signed");
    assert_eq!(pending(&domain.path, NOW).expect("read"), Some(signed));

    assert_eq!(pending(&domain.path, EXPIRES).expect("read"), None);
    assert!(!record_on_disk(&domain), "the expired record is removed");
}

#[test]
fn already_revoked_is_named() {
    let domain = domain();
    let remote = Remote::watching(&domain, vec![revocation_campaign(&domain, peer())]);
    remote
        .authority
        .borrow_mut()
        .as_mut()
        .expect("status")
        .revoked_peers
        .push(peer());

    let refusal = open(
        &remote,
        &domain.path,
        &peer(),
        RevocationReasonChoice::StolenOrLost,
        NOW,
    )
    .err()
    .expect("refused");

    assert_eq!(refusal, RevocationRefusal::AlreadyRevoked);
    assert!(!remote.called("open_campaign"));
    assert_eq!(domain.touches(), 0);
}
