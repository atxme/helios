//! The rotation sequence, against simulated keys and a simulated remote.
//!
//! Only the CTAP2 boundary and the tunnel are simulated. The vault, both
//! rotations, every signature and the journal are the production code, and the
//! assertions are real ones: `CampaignApproval::verify` is what Astra runs, and a
//! key that returned canned bytes would prove none of this.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use aether::certificates::approval::{AstraIssuancePolicy, CredentialRegistry, CredentialState};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId,
    WireGuardKey,
};
use aether::certificates::operator_session::AffectedCa;
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::transport::OperatorOpenAction;
use aether::certificates::webauthn::WebAuthnAssertion;
use aether::certificates::{CertificateError, CERTIFICATE_FORMAT_VERSION};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use zeroize::Zeroizing;

use super::*;
use crate::authenticator::{
    Approval, ApprovedOpening, AuthenticatorError, CredentialSubject, Opened, Registration,
};
use crate::gestures::{self, NewAuthority, NewKey};
use crate::rotation_journal::{
    self, JournalStage, LegacyCaPqJournal, LEGACY_CA_PQ_JOURNAL_VERSION,
};
use crate::signing::{self, CampaignApprovalSession};
use crate::tunnel::admin_refusal;
use crate::vault::{SlotRole, SlotSecret};
use crate::vault_gestures::{add_key_with, create_first_key, finalize_with};
use crate::{credentials, documents, handoff, store};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = NOW + 300;
const RP_ID: &str = "astra.helios.test";
const ORIGIN: &str = "https://astra.helios.test";
const AUTHORITY_URL: &str = "https://astra.helios.test/";
const SERVER_NAME: &str = "gateway.helios.test";
const OPERATION: [u8; 16] = [0x0B; 16];

fn operation() -> Id16 {
    Id16::new(OPERATION).expect("operation")
}

/// One simulated security key, holding one credential.
///
/// `derive` answers `hmac-secret` in shape and `approve` signs a real assertion.
/// A key that ignores the allow-list stands for what Windows WebAuthn does: the
/// key present answers, whichever was asked for.
struct TestKey {
    serial: u8,
    registered: Cell<bool>,
    touches: Cell<u32>,
    ignores_allow_list: Cell<bool>,
    declines: Cell<bool>,
}

impl TestKey {
    fn new(serial: u8) -> Self {
        Self {
            serial,
            registered: Cell::new(false),
            touches: Cell::new(0),
            ignores_allow_list: Cell::new(false),
            declines: Cell::new(false),
        }
    }

    fn credential_id(&self) -> Vec<u8> {
        vec![self.serial; 64]
    }

    fn signing_key(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[self.serial ^ 0x5A; 32]).expect("seed")
    }

    /// What a token does with an allow-list, and the one thing `declines` stops.
    fn answer(&self, credentials: &[Vec<u8>]) -> Result<Vec<u8>, AuthenticatorError> {
        if self.declines.get() {
            return Err(AuthenticatorError::Device("geste annulé".into()));
        }
        let own = self.credential_id();
        if !self.registered.get() || !(self.ignores_allow_list.get() || credentials.contains(&own))
        {
            return Err(AuthenticatorError::UnknownCredential);
        }
        self.touches.set(self.touches.get() + 1);
        Ok(own)
    }
}

impl Authenticator for TestKey {
    fn register(
        &self,
        _rp_id: &str,
        _subject: &CredentialSubject,
        _exclude: &[Vec<u8>],
        _pin: &str,
    ) -> Result<Registration, AuthenticatorError> {
        self.registered.set(true);
        let mut cose = vec![0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        cose.extend_from_slice(self.signing_key().public_key().as_ref());
        Ok(Registration {
            credential_id: self.credential_id(),
            credential_public_key: cose,
            aaguid: [0; 16],
        })
    }

    fn derive(
        &self,
        _rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; 32],
        _pin: &str,
    ) -> Result<Opened, AuthenticatorError> {
        let credential_id = self.answer(credentials)?;
        let mut output = *salt;
        output.iter_mut().for_each(|byte| *byte ^= self.serial);
        Ok(Opened {
            credential_id,
            secret: SlotSecret::new(output.to_vec()),
        })
    }

    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        _pin: &str,
    ) -> Result<Approval, AuthenticatorError> {
        let credential_id = self.answer(credentials)?;
        let digest = |bytes: &[u8]| {
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
                .as_ref()
                .to_vec()
        };
        let mut authenticator_data = digest(rp_id.as_bytes());
        // User presence and user verification, then a sign count.
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&digest(client_data_json));
        Ok(Approval {
            credential_id,
            assertion: WebAuthnAssertion {
                authenticator_data,
                client_data_json: client_data_json.to_vec(),
                signature: self.signing_key().sign(&message).as_ref().to_vec(),
            },
        })
    }

    fn approve_and_derive(
        &self,
        _rp_id: &str,
        _credentials: &[Vec<u8>],
        _client_data_json: &[u8],
        _salt: &[u8; 32],
        _pin: &str,
    ) -> Result<ApprovedOpening, AuthenticatorError> {
        unreachable!("a rotation takes its two gestures apart")
    }
}

/// A finished domain with three enrolled keys and a pinned service key.
struct Domain {
    _directory: tempfile::TempDir,
    path: PathBuf,
    keys: [TestKey; 3],
    service_key: Zeroizing<Vec<u8>>,
}

fn trust_domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

fn domain() -> Domain {
    let directory = tempfile::tempdir().expect("dir");
    let path = directory.path().join("authority-vault.json");
    let keys = [TestKey::new(1), TestKey::new(2), TestKey::new(3)];
    let first = create_first_key(
        &path,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: trust_domain(),
            label: "Clé 1".into(),
            role: SlotRole::Primary,
        },
        AUTHORITY_URL,
        &keys[0],
        "",
        NOW,
    )
    .expect("the domain is created");
    for (key, label) in [(&keys[1], "Clé 2"), (&keys[2], "Clé 3")] {
        let request = NewKey {
            label: label.into(),
            role: SlotRole::Recovery,
        };
        add_key_with(&path, &first, key, &request, "", NOW).expect("key added");
    }
    let (service_key, service_public) = generate_ml_dsa_87_keypair().expect("service key");
    let relay_path = handoff::path_beside(&path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = Some(gateway_key().to_base64());
    relay.server_name = Some(SERVER_NAME.into());
    relay.astra_service_public_key = Some(service_public.to_base64());
    relay.astra_service_key_epoch = Some(1);
    handoff::save(&relay_path, &relay).expect("relay saved");
    finalize_with(&path, &first, NOW).expect("the domain is finished");
    keys.iter().for_each(|key| key.touches.set(0));
    Domain {
        _directory: directory,
        path,
        keys,
        service_key,
    }
}

impl Domain {
    fn relay(&self) -> handoff::DomainHandoff {
        handoff::load(&handoff::path_beside(&self.path)).expect("relay")
    }

    fn registry(&self) -> CredentialRegistry {
        credentials::load(&credentials::path_beside(&self.path))
            .expect("document")
            .expect("present")
    }

    fn touches(&self) -> u32 {
        self.keys.iter().map(|key| key.touches.get()).sum()
    }

    /// Every file of the directory, to tell that nothing was written.
    fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(self.path.parent().expect("parent"))
            .expect("listing")
            .map(|entry| {
                let path = entry.expect("entry").path();
                let bytes = std::fs::read(&path).expect("file");
                (path, bytes)
            })
            .collect()
    }

    fn journal_on_disk(&self) -> Option<RotationJournal> {
        rotation_journal::load(&rotation_journal::path_beside(&self.path)).expect("journal")
    }

    /// The campaign the door resolves for `trust_authorities`: one row per
    /// anchor, each naming what the domain holds now.
    fn authority_campaign(&self, expires_at: u64) -> AstraRotationCampaign {
        let relay = self.relay();
        let identity = handoff::identity_of(&relay).expect("identity");
        let anchor = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim())
            .expect("anchor")
            .authority_fingerprint();
        let client_tls = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
            .expect("certificate")
            .fingerprint();
        let row = |certificate_kind, epoch, fingerprint| CampaignTarget {
            certificate_kind,
            identity_key: gateway_key(),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: fingerprint,
            active_pq_certificate_fingerprint: fingerprint,
        };
        self.campaign(
            CampaignScope::TrustAuthorities,
            vec![
                row(CertificateKind::CaPq, identity.ca_epoch, anchor),
                row(CertificateKind::CaTls, identity.ca_tls_epoch, client_tls),
            ],
            expires_at,
        )
    }

    fn campaign(
        &self,
        scope: CampaignScope,
        targets: Vec<CampaignTarget>,
        expires_at: u64,
    ) -> AstraRotationCampaign {
        AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([9; 16]).expect("id"),
            trust_domain_id: trust_domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            created_at: NOW,
            expires_at,
            scope,
            targets,
            reason: "remplacement".into(),
            requested_by: "opératrice".into(),
            policy_fingerprint: AstraIssuancePolicy::standard(
                trust_domain(),
                gateway_key(),
                SERVER_NAME.into(),
            )
            .fingerprint()
            .expect("policy"),
            required_credentials: scope.required_credentials(),
        }
    }

    fn request(&self, campaign: AstraRotationCampaign) -> CampaignRequest {
        let signer_request = AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: operation(),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: self.relay().astra_authority_url.expect("origin"),
            encrypted_vault_fingerprint: Fingerprint::of(b"vault"),
            required_credentials: campaign.required_credentials,
            created_at: NOW,
            expires_at: campaign.expires_at,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.service_key)
        .expect("signed request");
        CampaignRequest {
            operation_id: operation(),
            signer_request: Box::new(signer_request),
            campaign: Box::new(campaign),
            webauthn_rp_id: RP_ID.into(),
            webauthn_origin: ORIGIN.into(),
            result_token: "jeton-de-depot".into(),
            vault_token: None,
        }
    }

    fn armed_remote(&self) -> Remote {
        let remote = Remote::watching(&self.path);
        remote.arm(self.request(self.authority_campaign(EXPIRES)));
        remote
    }

    fn validated(&self, indexes: &[usize]) -> ValidatedKeys {
        let mut keys = ValidatedKeys::new(&self.path).expect("keys");
        for index in indexes {
            keys.validate(&self.keys[*index]).expect("validated");
        }
        keys
    }

    fn opened(&self, kind: RotationKind, remote: &Remote) -> OpenedRotation {
        open(
            remote,
            &self.path,
            kind,
            self.validated(&[0, 1]),
            &terms(),
            NOW,
        )
        .expect("opened")
    }

    /// The four touches, and the journal they end in.
    fn signed(&self, kind: RotationKind) -> RotationJournal {
        let remote = self.armed_remote();
        let mut rotation = self.opened(kind, &remote);
        rotation.approve(&self.keys[0], NOW).expect("first");
        rotation.approve(&self.keys[1], NOW).expect("second");
        rotation.sign_and_journal(&self.path, NOW).expect("signed")
    }
}

fn terms() -> RotationTerms {
    RotationTerms {
        existing_operation: None,
        reason: "remplacement".into(),
        requested_by: "opératrice".into(),
        prepare_days: DEFAULT_PREPARE_DAYS,
        overlap_days: DEFAULT_OVERLAP_DAYS,
        validity_days: DEFAULT_CA_TLS_VALIDITY_DAYS,
    }
}

/// What Astra says of a domain in step with the vault at `vault_path`.
fn nothing_in_flight(vault_path: &Path) -> OperatorAuthorityStatus {
    let relay = handoff::load(&handoff::path_beside(vault_path)).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");
    let anchor = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim()).expect("anchor");
    let client_tls = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
        .expect("certificate");
    OperatorAuthorityStatus {
        ca_epoch: identity.ca_epoch,
        ca_fingerprint: anchor.authority_fingerprint(),
        next_ca_fingerprint: None,
        ca_tls_epoch: identity.ca_tls_epoch,
        ca_tls_fingerprint: Some(client_tls.fingerprint()),
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
    }
}

fn holding(vault_path: &Path, journal: &RotationJournal) -> OperatorAuthorityStatus {
    let next = Some(journal.next_anchor_fingerprint);
    match journal.kind {
        RotationKind::CaPq => OperatorAuthorityStatus {
            next_ca_fingerprint: next,
            ..nothing_in_flight(vault_path)
        },
        RotationKind::CaTls => OperatorAuthorityStatus {
            next_ca_tls_fingerprint: next,
            ..nothing_in_flight(vault_path)
        },
    }
}

/// The tunnel, as a test scripts it. Each call is recorded by name.
struct Remote {
    vault_path: PathBuf,
    calls: RefCell<Vec<&'static str>>,
    request: RefCell<Option<CampaignRequest>>,
    opened_with: RefCell<Option<OperatorOpenRequest>>,
    /// Answers to the deposits, in order; once empty, Astra accepts. A number is
    /// a refusal with that status.
    deposits: RefCell<VecDeque<Result<SigningOperationState, u16>>>,
    /// `None` makes the read fail.
    authority: RefCell<Option<OperatorAuthorityStatus>>,
    gateway_anchor: RefCell<Option<Fingerprint>>,
    gateway_read_fails: Cell<bool>,
    install_ignored: Cell<bool>,
    install_refused: Cell<Option<u16>>,
    /// Answers to the copies, in order; once empty, Astra takes it.
    copies: RefCell<VecDeque<Result<VaultCopySent, u16>>>,
    copies_sent: RefCell<Vec<OperatorVaultCopy>>,
    /// The vault in place at the moment of the install, to prove the order.
    vault_at_install: RefCell<Option<Fingerprint>>,
    /// Whether the journal was on disk at the moment of a deposit.
    journal_at_deposit: Cell<Option<bool>>,
}

impl Remote {
    fn watching(vault_path: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            calls: RefCell::default(),
            request: RefCell::default(),
            opened_with: RefCell::default(),
            deposits: RefCell::default(),
            authority: RefCell::new(Some(nothing_in_flight(vault_path))),
            gateway_anchor: RefCell::new(Some(Fingerprint::of(b"ancre sortante"))),
            gateway_read_fails: Cell::new(false),
            install_ignored: Cell::new(false),
            install_refused: Cell::new(None),
            copies: RefCell::default(),
            copies_sent: RefCell::default(),
            vault_at_install: RefCell::default(),
            journal_at_deposit: Cell::new(None),
        }
    }

    fn arm(&self, request: CampaignRequest) {
        *self.request.borrow_mut() = Some(request);
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

    fn install(&self, name: &'static str, anchor: Fingerprint) -> Result<()> {
        self.note(name);
        if let Some(status) = self.install_refused.get() {
            return Err(admin_refusal(status, None));
        }
        *self.vault_at_install.borrow_mut() = Some(
            store::load(&self.vault_path)
                .expect("vault")
                .fingerprint()
                .expect("fingerprint"),
        );
        if !self.install_ignored.get() {
            *self.gateway_anchor.borrow_mut() = Some(anchor);
        }
        Ok(())
    }
}

impl RotationRemote for Remote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        self.note("open_campaign");
        *self.opened_with.borrow_mut() = Some(request.clone());
        Ok(OperatorOpened {
            operation_id: operation(),
            campaign_id: Id16::new([9; 16]).expect("id"),
            campaign_fingerprint: Fingerprint::of(b"campagne"),
            scope: CampaignScope::TrustAuthorities,
            target_count: 2,
            required_credentials: 2,
            expires_at: EXPIRES,
            revocation_expiries: None,
            delegation_request: None,
        })
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        self.note("fetch_campaign");
        assert_eq!(*operation_id, operation());
        Ok(self.request.borrow_mut().take().expect("an armed campaign"))
    }

    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        _result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        self.note("submit_campaign");
        assert_eq!(*operation_id, operation());
        assert_eq!(result_token, "jeton-de-depot");
        self.journal_at_deposit.set(Some(
            rotation_journal::path_beside(&self.vault_path).exists(),
        ));
        match self.deposits.borrow_mut().pop_front() {
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

    fn send_vault_copy(&self, copy: &OperatorVaultCopy) -> Result<VaultCopySent> {
        self.note("send_vault_copy");
        self.copies_sent.borrow_mut().push(copy.clone());
        match self.copies.borrow_mut().pop_front() {
            None => Ok(VaultCopySent::Copied(
                aether::certificates::transport::OperatorVaultCopied {
                    fingerprint: Fingerprint::of(b"copie"),
                    credential_registry_epoch: None,
                },
            )),
            Some(Ok(sent)) => Ok(sent),
            Some(Err(status)) => Err(admin_refusal(status, None)),
        }
    }

    fn install_ca_transition(&self, transition: &CaTransition) -> Result<()> {
        self.install("install_ca_transition", transition.next_ca_fingerprint)
    }

    fn install_client_tls_ca_transition(&self, transition: &ClientTlsCaTransition) -> Result<()> {
        self.install(
            "install_client_tls_ca_transition",
            transition.next_client_tls_ca_certificate.fingerprint(),
        )
    }

    fn gateway_next_anchor(&self, _kind: RotationKind) -> Result<Option<Fingerprint>> {
        self.note("gateway_next_anchor");
        if self.gateway_read_fails.get() {
            return Err(admin_refusal(503, None));
        }
        Ok(*self.gateway_anchor.borrow())
    }
}

// Validating a key.

#[test]
fn same_key_twice_is_repeated_and_keeps_the_first() {
    let domain = domain();
    let mut keys = ValidatedKeys::new(&domain.path).expect("keys");
    assert_eq!(keys.validate(&domain.keys[0]), Ok("Clé 1".to_string()));
    assert_eq!(keys.validate(&domain.keys[0]), Err(KeyStep::Repeated));
    assert_eq!(keys.count(), 1);
    assert_eq!(keys.validate(&domain.keys[1]), Ok("Clé 2".to_string()));
    assert_eq!(keys.count(), 2);
}

#[test]
fn an_unknown_key_is_not_enrolled_and_can_retry() {
    let domain = domain();
    let stranger = TestKey::new(9);
    stranger.registered.set(true);
    let mut keys = ValidatedKeys::new(&domain.path).expect("keys");
    assert_eq!(keys.validate(&stranger), Err(KeyStep::NotEnrolled));
    assert_eq!(keys.count(), 0);
    assert_eq!(keys.validate(&domain.keys[0]), Ok("Clé 1".to_string()));
}

#[test]
fn a_declined_gesture_is_declined_and_can_retry() {
    let domain = domain();
    let mut keys = ValidatedKeys::new(&domain.path).expect("keys");
    domain.keys[0].declines.set(true);
    assert_eq!(keys.validate(&domain.keys[0]), Err(KeyStep::Declined));
    domain.keys[0].declines.set(false);
    assert_eq!(keys.validate(&domain.keys[0]), Ok("Clé 1".to_string()));
}

/// Two is what a rotation takes, and a third touch would be asked for nothing.
#[test]
fn a_third_validation_asks_for_no_touch() {
    let domain = domain();
    let mut keys = domain.validated(&[0, 1]);
    assert_eq!(keys.validate(&domain.keys[2]), Err(KeyStep::NotValidated));
    assert_eq!(domain.keys[2].touches.get(), 0);
    assert_eq!(keys.count(), 2);
}

#[test]
fn validating_opens_no_campaign() {
    let domain = domain();
    let remote = Remote::watching(&domain.path);
    let keys = domain.validated(&[0, 1]);
    assert_eq!(keys.count(), 2);
    assert_eq!(remote.calls(), Vec::<&str>::new());
}

// Opening.

#[test]
fn one_validated_key_opens_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let keys = domain.validated(&[0]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

#[test]
fn opening_asks_the_door_for_the_authority_family_and_a_short_window() {
    let domain = domain();
    let remote = domain.armed_remote();
    domain.opened(RotationKind::CaPq, &remote);
    let asked = remote.opened_with.borrow().clone().expect("opened");
    assert_eq!(asked.action, OperatorOpenAction::TrustAuthorities);
    assert_eq!(asked.reason, "remplacement");
    assert_eq!(asked.requested_by, "opératrice");
    assert_eq!(asked.window_secs, 300);
}

#[test]
fn an_existing_operation_is_read_and_not_opened_again() {
    let domain = domain();
    let remote = domain.armed_remote();
    let terms = RotationTerms {
        existing_operation: Some(operation()),
        ..terms()
    };
    let keys = domain.validated(&[0, 1]);
    open(
        &remote,
        &domain.path,
        RotationKind::CaTls,
        keys,
        &terms,
        NOW,
    )
    .expect("opened");
    assert!(remote.called("fetch_campaign"));
    assert!(!remote.called("open_campaign"));
}

#[test]
fn a_preparation_under_a_day_opens_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let short = RotationTerms {
        prepare_days: 0,
        ..terms()
    };
    let keys = domain.validated(&[0, 1]);
    let refused = open(&remote, &domain.path, RotationKind::CaPq, keys, &short, NOW);
    assert!(refused.is_err());
    assert!(!remote.called("open_campaign"));
}

/// `rotate_ca_tls` would refuse it too, after four touches on a campaign that
/// blocks its family for five minutes.
#[test]
fn a_validity_that_does_not_cover_the_window_opens_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let short = RotationTerms {
        validity_days: DEFAULT_PREPARE_DAYS + DEFAULT_OVERLAP_DAYS,
        ..terms()
    };
    let keys = domain.validated(&[0, 1]);
    let refused = open(
        &remote,
        &domain.path,
        RotationKind::CaTls,
        keys,
        &short,
        NOW,
    );
    assert!(refused.is_err());
    assert!(!remote.called("open_campaign"));
}

#[test]
fn a_campaign_naming_another_anchor_is_refused_before_a_key() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        let domain = domain();
        let remote = Remote::watching(&domain.path);
        let mut campaign = domain.authority_campaign(EXPIRES);
        campaign.targets.iter_mut().for_each(|target| {
            target.active_pq_certificate_fingerprint = Fingerprint::of(b"une autre ancre");
        });
        remote.arm(domain.request(campaign));
        let keys = domain.validated(&[0, 1]);
        let touches = domain.touches();
        let refused = open(&remote, &domain.path, kind, keys, &terms(), NOW);
        assert!(refused.is_err(), "{kind:?}");
        assert_eq!(domain.touches(), touches, "{kind:?}");
    }
}

#[test]
fn a_campaign_that_rotates_no_anchor_is_refused_before_a_key() {
    let domain = domain();
    let remote = Remote::watching(&domain.path);
    let targets = domain.authority_campaign(EXPIRES).targets;
    remote.arm(domain.request(domain.campaign(CampaignScope::FleetLeafs, targets, EXPIRES)));
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
}

#[test]
fn a_campaign_the_service_key_did_not_sign_is_refused() {
    let domain = domain();
    let remote = Remote::watching(&domain.path);
    let (other_key, _) = generate_ml_dsa_87_keypair().expect("keys");
    let mut request = domain.request(domain.authority_campaign(EXPIRES));
    request.signer_request = Box::new(
        request
            .signer_request
            .as_ref()
            .clone()
            .sign(&other_key)
            .expect("signed"),
    );
    remote.arm(request);
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
}

#[test]
fn a_rotation_is_refused_over_a_journal_in_place() {
    let domain = domain();
    let remote = domain.armed_remote();
    domain.signed(RotationKind::CaTls);
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

/// It would come back at the next look and name this rotation's outgoing anchor.
#[test]
fn a_rotation_is_refused_over_a_legacy_ca_pq_journal() {
    let domain = domain();
    let remote = domain.armed_remote();
    let legacy = rotation_journal::legacy_ca_pq_path_beside(&domain.path);
    std::fs::write(&legacy, b"{}").expect("written");
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

/// Adopted or not, the record stays until the promotion, and its window with it.
#[test]
fn a_rotation_is_refused_over_a_prepared_record() {
    let domain = domain();
    let remote = domain.armed_remote();
    let journal = domain.signed(RotationKind::CaTls);
    let certificate = match &journal.transition {
        crate::rotation_journal::RotationTransition::CaTls(transition) => {
            transition.next_client_tls_ca_certificate.to_base64()
        }
        crate::rotation_journal::RotationTransition::CaPq(_) => unreachable!(),
    };
    let deposit = journal.deposit.clone().expect("deposit");
    crate::prepared::save(
        &crate::prepared::path_beside(&domain.path),
        &crate::prepared::PreparedRotation {
            kind: crate::prepared::PreparedKind::CaTls,
            operation_id: deposit.operation_id.to_hex(),
            result_token: Some(deposit.result_token),
            result: deposit.result,
            transition_path: "/tmp/transition-ca-tls.json".into(),
            next_ca_tls_epoch: 2,
            next_ca_tls_certificate: certificate,
            activation_at: journal.activation_at,
            not_after: journal.not_after,
            submitted: true,
            prepared_at: NOW,
            adopted: true,
            manifest: None,
        },
    )
    .expect("record");
    rotation_journal::clear(&rotation_journal::path_beside(&domain.path)).expect("cleared");

    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaTls,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

/// It opens the vault and approves nothing: found out now, and not at the touch.
#[test]
fn a_validated_key_the_document_marks_lost_opens_nothing() {
    let domain = domain();
    let vault = store::load(&domain.path).expect("vault");
    let identity = handoff::identity_of(&domain.relay()).expect("identity");
    let opening = gestures::open_with_authorized_key(&domain.keys[2], &vault, "").expect("opened");
    let document = signing::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        Some(&domain.registry()),
        &[(domain.keys[1].credential_id(), CredentialState::Lost)],
        NOW,
    )
    .expect("signed");
    credentials::save(&credentials::path_beside(&domain.path), &document).expect("saved");

    let remote = domain.armed_remote();
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaPq,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

/// During an overlap of either kind, the vault and the domain no longer agree on
/// what a new signature would be checked under.
#[test]
fn a_rotation_is_refused_while_the_authority_has_one_in_flight() {
    let overlaps: [fn(&mut OperatorAuthorityStatus); 2] = [
        |status| status.next_ca_fingerprint = Some(Fingerprint::of(b"suivante")),
        |status| status.next_ca_tls_fingerprint = Some(Fingerprint::of(b"suivante")),
    ];
    for overlap in overlaps {
        for kind in [RotationKind::CaPq, RotationKind::CaTls] {
            let domain = domain();
            let remote = domain.armed_remote();
            let mut status = nothing_in_flight(&domain.path);
            overlap(&mut status);
            *remote.authority.borrow_mut() = Some(status);
            let keys = domain.validated(&[0, 1]);
            assert!(open(&remote, &domain.path, kind, keys, &terms(), NOW).is_err());
            assert!(!remote.called("open_campaign"));
        }
    }
}

/// The campaign would block its family for five minutes, and Astra's own word on
/// the anchors was there to read first. Each row moves one thing, so a comparison
/// that forgot it would let that row through.
#[test]
fn a_vault_out_of_step_with_astra_opens_no_campaign() {
    type Shift = fn(&mut OperatorAuthorityStatus);
    let both = [RotationKind::CaPq, RotationKind::CaTls];
    let client_tls = [RotationKind::CaTls];
    let rows: [(&str, &[RotationKind], Shift); 8] = [
        ("vault ahead on CA-PQ", &both, |status| {
            status.ca_epoch -= 1;
            status.ca_fingerprint = Fingerprint::of(b"une autre ancre");
        }),
        ("vault behind on CA-PQ", &both, |status| {
            status.ca_epoch += 1;
            status.ca_fingerprint = Fingerprint::of(b"une autre ancre");
        }),
        ("CA-PQ epoch alone", &both, |status| status.ca_epoch += 1),
        ("CA-PQ anchor alone", &both, |status| {
            status.ca_fingerprint = Fingerprint::of(b"une autre ancre");
        }),
        ("vault ahead on client TLS", &client_tls, |status| {
            status.ca_tls_epoch -= 1;
            status.ca_tls_fingerprint = Some(Fingerprint::of(b"une autre ancre"));
        }),
        ("vault behind on client TLS", &client_tls, |status| {
            status.ca_tls_epoch += 1;
            status.ca_tls_fingerprint = Some(Fingerprint::of(b"une autre ancre"));
        }),
        ("client TLS epoch alone", &client_tls, |status| {
            status.ca_tls_epoch += 1;
        }),
        ("client TLS anchor alone", &client_tls, |status| {
            status.ca_tls_fingerprint = Some(Fingerprint::of(b"une autre ancre"));
        }),
    ];
    for (label, kinds, shift) in rows {
        for kind in kinds {
            let domain = domain();
            let remote = domain.armed_remote();
            let mut status = nothing_in_flight(&domain.path);
            shift(&mut status);
            *remote.authority.borrow_mut() = Some(status);
            let keys = domain.validated(&[0, 1]);
            let refused = open(&remote, &domain.path, *kind, keys, &terms(), NOW);
            assert!(refused.is_err(), "{label}, {kind:?}");
            assert!(!remote.called("open_campaign"), "{label}, {kind:?}");
            assert!(!remote.called("fetch_campaign"), "{label}, {kind:?}");
        }
    }
}

/// A campaign already open is not read either: the disagreement is the same.
#[test]
fn a_vault_out_of_step_with_astra_does_not_read_an_open_campaign() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut status = nothing_in_flight(&domain.path);
    status.ca_epoch += 1;
    *remote.authority.borrow_mut() = Some(status);
    let keys = domain.validated(&[0, 1]);
    let terms = RotationTerms {
        existing_operation: Some(operation()),
        ..terms()
    };
    let refused = open(&remote, &domain.path, RotationKind::CaPq, keys, &terms, NOW);
    assert!(refused.is_err());
    assert!(!remote.called("fetch_campaign"));
}

/// Astra pins no client TLS CA yet: replacing one is refused, and the CA-PQ
/// rotation, which does not depend on it, still opens.
#[test]
fn an_authority_pinning_no_client_tls_ca_refuses_that_rotation_alone() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut status = nothing_in_flight(&domain.path);
    status.ca_tls_fingerprint = None;
    *remote.authority.borrow_mut() = Some(status);

    let keys = domain.validated(&[0, 1]);
    let refused = open(
        &remote,
        &domain.path,
        RotationKind::CaTls,
        keys,
        &terms(),
        NOW,
    );
    assert!(refused.is_err());
    assert!(!remote.called("open_campaign"));

    domain.opened(RotationKind::CaPq, &remote);
    assert!(remote.called("open_campaign"));
}

/// Astra forgets a window once it promotes at `not_after`, and the vault keeps it
/// until « Terminer »: only the vault can stop this one before the touches.
#[test]
fn a_vault_with_a_client_tls_window_still_open_opens_nothing() {
    let domain = domain();
    let mut vault = store::load(&domain.path).expect("vault");
    let relay = domain.relay();
    let identity = handoff::identity_of(&relay).expect("identity");
    let active = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
        .expect("certificate");
    let opening = gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("opened");
    signing::rotate_ca_tls(
        &mut vault,
        &opening,
        &identity,
        &active,
        TransitionWindow::new(NOW, NOW + 86_400, NOW + 2 * 86_400).expect("window"),
        (NOW, NOW + 3 * 86_400),
    )
    .expect("rotated");
    store::save(&domain.path, &vault).expect("saved");
    let mut relay = domain.relay();
    relay.adopt(&vault).expect("adopted");
    handoff::save(&handoff::path_beside(&domain.path), &relay).expect("saved");

    let remote = domain.armed_remote();
    let keys = domain.validated(&[0, 1]);
    assert!(open(
        &remote,
        &domain.path,
        RotationKind::CaTls,
        keys,
        &terms(),
        NOW
    )
    .is_err());
    assert!(!remote.called("open_campaign"));
}

/// What the touch does, stated before it: the authority replaced, the campaign it
/// approves, and the incoming anchor absent since it does not exist yet.
#[test]
fn the_manifest_states_what_the_touch_does() {
    for (kind, affected_ca) in [
        (RotationKind::CaPq, AffectedCa::CaPq),
        (RotationKind::CaTls, AffectedCa::CaTls),
    ] {
        let domain = domain();
        let relay = domain.relay();
        let identity = handoff::identity_of(&relay).expect("identity");
        let (current_epoch, outgoing) = match kind {
            RotationKind::CaPq => (
                identity.ca_epoch,
                MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim())
                    .expect("anchor")
                    .authority_fingerprint(),
            ),
            RotationKind::CaTls => (
                identity.ca_tls_epoch,
                DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
                    .expect("certificate")
                    .fingerprint(),
            ),
        };
        let remote = domain.armed_remote();
        let rotation = domain.opened(kind, &remote);
        assert_eq!(rotation.kind(), kind);
        let AstraManifest::CaRotation(manifest) = rotation.manifest() else {
            panic!("a rotation manifest, {kind:?}");
        };
        assert_eq!(manifest.trust_domain_id, trust_domain());
        assert_eq!(manifest.affected_ca, affected_ca);
        assert_eq!(manifest.current_epoch, current_epoch);
        assert_eq!(manifest.next_epoch, current_epoch + 1);
        assert_eq!(manifest.activation_at, rotation.window().activation_at);
        assert_eq!(manifest.not_after, rotation.window().not_after);
        assert_eq!(manifest.outgoing_anchor_fingerprint, outgoing);
        assert_eq!(manifest.next_anchor_fingerprint, None);

        // The touch signs the campaign's fingerprint, so what it binds is all here.
        let campaign = manifest.campaign.as_ref().expect("the campaign");
        assert_eq!(campaign.fingerprint, campaign.campaign.fingerprint());
        assert_eq!(campaign.campaign.targets.len(), 2, "{kind:?}");
        assert_eq!(campaign.campaign.scope, CampaignScope::TrustAuthorities);
    }
}

#[test]
fn the_window_shown_is_the_one_signed() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaTls, &remote);

    let window = rotation.window();
    assert_eq!(window.not_before, NOW);
    assert_eq!(window.activation_at, NOW + 7 * 86_400);
    assert_eq!(window.not_after, NOW + 37 * 86_400);

    rotation.approve(&domain.keys[0], NOW + 10).expect("first");
    rotation.approve(&domain.keys[1], NOW + 10).expect("second");
    let journal = rotation
        .sign_and_journal(&domain.path, NOW + 20)
        .expect("signed");
    assert_eq!(journal.transition.window(), window);
    assert_eq!(journal.campaign_expires_at, EXPIRES);
    assert_eq!(journal.signed_at, NOW + 20);
}

// Approving.

#[test]
fn only_validated_keys_are_offered_and_an_approved_one_no_more() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    let mut offered = rotation.offered();
    offered.sort();
    assert_eq!(
        offered,
        vec![
            domain.keys[0].credential_id(),
            domain.keys[1].credential_id()
        ]
    );
    rotation.approve(&domain.keys[1], NOW).expect("first");
    assert_eq!(rotation.offered(), vec![domain.keys[0].credential_id()]);
}

#[test]
fn approval_accepts_either_order() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        for order in [[0, 1], [1, 0]] {
            let domain = domain();
            let remote = domain.armed_remote();
            let document = domain.registry();
            let mut rotation = domain.opened(kind, &remote);
            for index in order {
                let label = rotation
                    .approve(&domain.keys[index], NOW)
                    .expect("approved");
                assert_eq!(label, format!("Clé {}", index + 1));
            }
            let journal = rotation
                .sign_and_journal(&domain.path, NOW)
                .expect("signed");

            let deposit = journal.deposit.as_ref().expect("deposit");
            let campaign = domain.authority_campaign(EXPIRES);
            deposit.result.validate(&campaign).expect("Astra's shape");
            deposit
                .result
                .approval
                .verify(&campaign, &document, RP_ID, ORIGIN, NOW)
                .expect("Astra's check, under the document it holds");
            let ids: Vec<_> = deposit
                .result
                .approval
                .approvals
                .iter()
                .map(|approval| approval.credential_id.clone())
                .collect();
            let expected: Vec<_> = order
                .iter()
                .map(|index| domain.keys[*index].credential_id())
                .collect();
            assert_eq!(ids, expected);
        }
    }
}

/// Review Focus 1, in both shapes: a token that honours the allow-list holds
/// nothing it may answer for, and one that does not is refused all the same.
#[test]
fn a_third_enrolled_key_is_not_validated_and_nothing_is_lost() {
    for ignores_allow_list in [false, true] {
        let domain = domain();
        let remote = domain.armed_remote();
        let mut rotation = domain.opened(RotationKind::CaPq, &remote);
        domain.keys[2].ignores_allow_list.set(ignores_allow_list);

        assert_eq!(
            rotation.approve(&domain.keys[2], NOW),
            Err(KeyStep::NotValidated)
        );
        assert_eq!(rotation.offered().len(), 2);

        rotation.approve(&domain.keys[0], NOW).expect("first");
        assert_eq!(
            rotation.approve(&domain.keys[2], NOW),
            Err(KeyStep::NotValidated)
        );
        rotation.approve(&domain.keys[1], NOW).expect("second");
        rotation
            .sign_and_journal(&domain.path, NOW)
            .expect("signed");
    }
}

#[test]
fn the_same_key_twice_at_approval_is_repeated() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    domain.keys[0].ignores_allow_list.set(true);
    assert_eq!(
        rotation.approve(&domain.keys[0], NOW),
        Err(KeyStep::Repeated)
    );
    rotation.approve(&domain.keys[1], NOW).expect("second");

    // Both answered: nothing is left to touch a key for.
    let touches = domain.touches();
    assert_eq!(
        rotation.approve(&domain.keys[2], NOW),
        Err(KeyStep::Repeated)
    );
    assert_eq!(domain.touches(), touches);
}

/// The key still plugged in after the first approval: the platform is only offered
/// the other one, so it answers as a stranger would, and the words must hold for both.
#[test]
fn the_key_that_already_approved_is_asked_to_make_way() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    let refused = rotation
        .approve(&domain.keys[0], NOW)
        .expect_err("offered the other");
    assert_eq!(refused, KeyStep::NotValidated);
    assert_eq!(refused.to_string(), "autre clé attendue");
    rotation.approve(&domain.keys[1], NOW).expect("second");
}

#[test]
fn a_declined_approval_loses_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    domain.keys[0].declines.set(true);
    assert_eq!(
        rotation.approve(&domain.keys[0], NOW),
        Err(KeyStep::Declined)
    );
    domain.keys[0].declines.set(false);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    rotation.approve(&domain.keys[1], NOW).expect("second");
}

#[test]
fn touch_count_for_a_ca_rotation_is_four() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        let domain = domain();
        domain.signed(kind);
        assert_eq!(domain.keys[0].touches.get(), 2, "{kind:?}");
        assert_eq!(domain.keys[1].touches.get(), 2, "{kind:?}");
        assert_eq!(domain.keys[2].touches.get(), 0, "{kind:?}");
    }
}

/// Review Focus 4.
#[test]
fn expiry_between_two_approvals_signs_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let vault_before = std::fs::read(&domain.path).expect("vault");
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    let touches = domain.touches();

    assert_eq!(
        rotation.approve(&domain.keys[1], EXPIRES),
        Err(KeyStep::Expired)
    );
    assert_eq!(domain.touches(), touches, "no touch for a dead campaign");

    let refused = rotation
        .sign_and_journal(&domain.path, EXPIRES)
        .expect_err("nothing signed");
    assert_eq!(refused.downcast_ref::<KeyStep>(), Some(&KeyStep::Expired));
    assert_eq!(domain.journal_on_disk(), None);
    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault_before);
}

/// A campaign that died has no use for what the keys released, and a caller that
/// holds on to the value must not hold on to the secrets with it.
#[test]
fn expiry_lets_go_of_the_openings_at_once() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    assert_eq!(rotation.keys.count(), 2);

    assert_eq!(
        rotation.approve(&domain.keys[1], EXPIRES),
        Err(KeyStep::Expired)
    );

    assert_eq!(rotation.keys.count(), 0);
    assert!(rotation.offered().is_empty());
    assert_eq!(
        rotation.approve(&domain.keys[1], EXPIRES),
        Err(KeyStep::Expired),
        "still expired, and no panic over the openings gone"
    );
    let refused = rotation
        .sign_and_journal(&domain.path, EXPIRES)
        .expect_err("nothing signed");
    assert_eq!(refused.downcast_ref::<KeyStep>(), Some(&KeyStep::Expired));
}

/// Both approvals in, the openings gone, and a clock that went back: the signature
/// has nothing to sign with, and says so rather than reaching for them.
#[test]
fn a_clock_moving_back_after_the_expiry_signs_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    rotation.approve(&domain.keys[1], NOW).expect("second");
    assert_eq!(
        rotation.approve(&domain.keys[2], EXPIRES),
        Err(KeyStep::Expired)
    );
    let touches = domain.touches();

    assert_eq!(
        rotation.approve(&domain.keys[0], NOW + 1),
        Err(KeyStep::Expired),
        "the same answer as the signature, whatever the clock says now"
    );
    assert_eq!(domain.touches(), touches);

    let refused = rotation
        .sign_and_journal(&domain.path, NOW + 1)
        .expect_err("nothing signed");

    assert_eq!(refused.downcast_ref::<KeyStep>(), Some(&KeyStep::Expired));
    assert_eq!(domain.journal_on_disk(), None);
}

#[test]
fn signing_with_one_approval_signs_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    assert!(rotation.sign_and_journal(&domain.path, NOW).is_err());
    assert_eq!(domain.journal_on_disk(), None);
}

// Signing.

#[test]
fn sign_and_journal_leaves_the_vault_file_untouched() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        let domain = domain();
        let before = domain.files();
        let journal = domain.signed(kind);

        let mut after = domain.files();
        after.remove(&rotation_journal::path_beside(&domain.path));
        assert_eq!(after, before, "{kind:?}");

        assert_eq!(journal.stage, JournalStage::Signed);
        assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));
        let next = journal.next.as_ref().expect("the next vault");
        assert_ne!(
            next.vault.fingerprint().expect("fingerprint"),
            store::load(&domain.path)
                .expect("vault")
                .fingerprint()
                .expect("fingerprint"),
            "{kind:?}"
        );
    }
}

#[test]
fn a_ca_pq_rotation_carries_its_document_and_moves_the_relay_epoch() {
    let domain = domain();
    let document = domain.registry();
    let relay = domain.relay();
    let journal = domain.signed(RotationKind::CaPq);
    let next = journal.next.as_ref().expect("next");

    let carried = next.credentials.as_ref().expect("document");
    assert_eq!(carried.ca_epoch, document.ca_epoch + 1);
    let deposit = journal.deposit.as_ref().expect("deposit");
    assert_eq!(deposit.result.credential_registry.as_deref(), Some(carried));

    assert_eq!(next.handoff.ca_epoch, Some(relay.ca_epoch.unwrap_or(1) + 1));
    assert_eq!(next.handoff.ca_pq_public_key, next.vault.ca_pq_public_key);
    assert_eq!(
        next.handoff.vault_fingerprint,
        next.vault.fingerprint().expect("fingerprint").to_hex()
    );
    assert_eq!(next.handoff.ca_tls_certificate, relay.ca_tls_certificate);
    assert_eq!(
        next.handoff.gateway_wg_public_key,
        relay.gateway_wg_public_key
    );
}

/// The relay's client TLS epoch and certificate move at the promotion, where the
/// gateway moves its own: only its description of the vault follows here.
#[test]
fn a_client_tls_rotation_leaves_the_document_and_the_relay_epochs() {
    let domain = domain();
    let relay = domain.relay();
    let journal = domain.signed(RotationKind::CaTls);
    let next = journal.next.as_ref().expect("next");

    assert_eq!(next.credentials, None);
    let deposit = journal.deposit.as_ref().expect("deposit");
    assert_eq!(deposit.result.credential_registry, None);

    assert_eq!(next.handoff.ca_epoch, relay.ca_epoch);
    assert_eq!(next.handoff.ca_tls_epoch, relay.ca_tls_epoch);
    assert_eq!(next.handoff.ca_tls_certificate, relay.ca_tls_certificate);
    assert_eq!(
        next.handoff.vault_fingerprint,
        next.vault.fingerprint().expect("fingerprint").to_hex()
    );
}

#[test]
fn a_vault_that_moved_since_the_validation_signs_nothing() {
    let domain = domain();
    let remote = domain.armed_remote();
    let mut rotation = domain.opened(RotationKind::CaPq, &remote);
    rotation.approve(&domain.keys[0], NOW).expect("first");
    rotation.approve(&domain.keys[1], NOW).expect("second");

    let mut moved = store::load(&domain.path).expect("vault");
    moved.created_at += 1;
    store::save(&domain.path, &moved).expect("saved");

    assert!(rotation.sign_and_journal(&domain.path, NOW).is_err());
    assert_eq!(domain.journal_on_disk(), None);
}

#[test]
fn the_journal_is_written_before_any_deposit() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    assert_eq!(remote.journal_at_deposit.get(), Some(true));
    assert_eq!(remote.calls()[0], "submit_campaign");
}

// Advancing.

#[test]
fn a_rotation_goes_from_its_signature_to_the_end_with_no_key() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        let domain = domain();
        let mut journal = domain.signed(kind);
        let touches = domain.touches();
        let next = journal.next.clone().expect("next");
        let remote = Remote::watching(&domain.path);

        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

        assert_eq!(step, ResumeStep::Finished);
        assert_eq!(domain.touches(), touches);
        assert_eq!(domain.journal_on_disk(), None);
        assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
        assert_eq!(domain.relay(), next.handoff);
    }
}

fn prepared_record_on_disk(domain: &Domain) -> Option<prepared::PreparedRotation> {
    prepared::load(&prepared::path_beside(&domain.path)).expect("record")
}

/// `Finished` removes the journal, and with it the only other copy of the incoming
/// certificate. The record keeps what « Terminer » needs, and no token.
#[test]
fn a_finished_client_tls_rotation_leaves_the_incoming_anchor_for_the_promotion() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let RotationTransition::CaTls(transition) = journal.transition.clone() else {
        panic!("a client TLS transition");
    };
    let deposit = journal.deposit.clone().expect("deposit");
    let remote = Remote::watching(&domain.path);

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
    assert_eq!(domain.journal_on_disk(), None);

    let record = prepared_record_on_disk(&domain).expect("the record");
    assert_eq!(
        record,
        prepared::PreparedRotation {
            kind: prepared::PreparedKind::CaTls,
            operation_id: deposit.operation_id.to_hex(),
            result_token: None,
            result: deposit.result,
            transition_path: String::new(),
            next_ca_tls_epoch: transition.next_ca_tls_epoch,
            next_ca_tls_certificate: transition.next_client_tls_ca_certificate.to_base64(),
            activation_at: journal.activation_at,
            not_after: journal.not_after,
            submitted: true,
            prepared_at: journal.signed_at,
            manifest: None,
            adopted: true,
        }
    );
    let bytes = std::fs::read(prepared::path_beside(&domain.path)).expect("bytes");
    let text = String::from_utf8(bytes).expect("text");
    assert!(!text.contains(&deposit.result_token));
    assert!(!text.contains("result_token"));

    // The promotion, as `promote-ca-tls` runs it: the record names what the vault
    // puts in service.
    let mut vault = store::load(&domain.path).expect("vault");
    let opening = gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("opened");
    let advanced =
        signing::advance_ca_tls(&mut vault, &opening, record.not_after).expect("promoted");
    let crate::vault::CaTlsAdvance::Rotated {
        certificate_fingerprint,
        ..
    } = advanced
    else {
        panic!("the window closes at not_after");
    };
    let named = DerCertificate::parse(&record.next_ca_tls_certificate).expect("certificate");
    assert_eq!(certificate_fingerprint, named.fingerprint().to_string());
}

/// Any prefix of `apply_local` is replayed from the top, and the record is part of
/// it: a stop before it writes it at the replay, and a stop after it writes the same.
#[test]
fn a_stop_inside_apply_local_replays_to_the_same_record() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let next = journal.next.clone().expect("next");
    rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");
    let accepted = journal.clone();
    let journal_path = rotation_journal::path_beside(&domain.path);

    // A write that fails where the record goes: the vault has moved, the journal
    // keeps `next`, and nothing says the rotation went past this.
    let record_path = prepared::path_beside(&domain.path);
    std::fs::create_dir(&record_path).expect("in the way");
    let remote = Remote::watching(&domain.path);
    advance(&remote, &domain.path, &mut journal, NOW).expect_err("stopped");
    assert_eq!(domain.journal_on_disk(), Some(accepted.clone()));
    assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
    assert!(!remote.called("install_client_tls_ca_transition"));
    std::fs::remove_dir(&record_path).expect("out of the way");

    let mut resumed = domain.journal_on_disk().expect("journal");
    let step = advance(&remote, &domain.path, &mut resumed, NOW).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
    let record = std::fs::read(&record_path).expect("the record");

    // A stop after the record and before the journal says `Applied`.
    rotation_journal::save(&journal_path, &accepted).expect("back to Accepted");
    let mut replayed = accepted;
    rotation_journal::apply_local(&domain.path, &mut replayed).expect("replayed");
    assert_eq!(std::fs::read(&record_path).expect("the record"), record);
}

/// `Discard` is only reached with the vault unmoved, and the record means the vault
/// moved.
#[test]
fn a_discarded_client_tls_rotation_leaves_no_record() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    remote.deposits.borrow_mut().push_back(Err(403));

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::Discard);
    assert_eq!(prepared_record_on_disk(&domain), None);
}

/// A journal that has ended stays ended: the record is for `promote-ca-tls`.
#[test]
fn the_record_of_a_finished_rotation_is_not_adopted_into_a_journal() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    let record = prepared_record_on_disk(&domain).expect("the record");

    assert_eq!(
        rotation_journal::adopt_legacy(&domain.path).expect("read"),
        None
    );

    assert_eq!(domain.journal_on_disk(), None);
    assert_eq!(prepared_record_on_disk(&domain), Some(record));
}

/// Until « Terminer », the window this record describes is still open.
#[test]
fn a_finished_client_tls_rotation_holds_the_next_one_until_the_promotion() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    let refused = open(
        &domain.armed_remote(),
        &domain.path,
        RotationKind::CaPq,
        domain.validated(&[0, 1]),
        &terms(),
        NOW,
    )
    .err()
    .expect("refused");
    assert!(format!("{refused:#}").contains("préparée"), "{refused:#}");
}

/// The record names a client TLS certificate, and a CA-PQ rotation has none.
#[test]
fn a_ca_pq_rotation_leaves_no_record() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::Finished);
    assert_eq!(prepared_record_on_disk(&domain), None);
}

#[test]
fn accepted_runs_apply_install_copy_in_that_order() {
    for (kind, install) in [
        (RotationKind::CaPq, "install_ca_transition"),
        (RotationKind::CaTls, "install_client_tls_ca_transition"),
    ] {
        let domain = domain();
        let mut journal = domain.signed(kind);
        rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");
        let next_vault = journal.next.as_ref().expect("next").vault.fingerprint();
        let remote = Remote::watching(&domain.path);

        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

        assert_eq!(step, ResumeStep::Finished);
        assert_eq!(
            remote.calls(),
            vec![
                "gateway_next_anchor",
                install,
                "gateway_next_anchor",
                "send_vault_copy"
            ]
        );
        assert_eq!(
            *remote.vault_at_install.borrow(),
            Some(next_vault.expect("fingerprint")),
            "the vault lands before the gateway hears of it"
        );
    }
}

/// Nothing believed about the install: what ends it is the gateway naming the
/// anchor, and a gateway that answers success and names another stops the loop.
#[test]
fn a_gateway_that_accepts_and_does_not_name_the_anchor_stops_with_the_journal() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    remote.install_ignored.set(true);

    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    assert!(!remote.called("send_vault_copy"));
    assert_eq!(
        domain.journal_on_disk().expect("kept").stage,
        JournalStage::Applied
    );
}

#[test]
fn a_refused_install_keeps_the_journal_and_a_second_look_finishes() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote.install_refused.set(Some(503));

    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    assert_eq!(journal.stage, JournalStage::Applied);
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));

    remote.install_refused.set(None);
    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
}

/// Refused at `Signed` only: the deposit is what got refused, and a read that
/// says Astra holds it after all means the answer was lost.
#[test]
fn a_refused_deposit_astra_turns_out_to_hold_continues() {
    for status in [403, 409] {
        let domain = domain();
        let mut journal = domain.signed(RotationKind::CaTls);
        let remote = Remote::watching(&domain.path);
        remote.deposits.borrow_mut().push_back(Err(status));
        *remote.authority.borrow_mut() = Some(holding(&domain.path, &journal));

        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
        assert_eq!(step, ResumeStep::Finished, "{status}");
    }
}

#[test]
fn refused_deposit_of_a_dead_campaign_not_accepted_discards() {
    for status in [403, 409] {
        let domain = domain();
        let before = std::fs::read(&domain.path).expect("vault");
        let mut journal = domain.signed(RotationKind::CaPq);
        let remote = Remote::watching(&domain.path);
        remote.deposits.borrow_mut().push_back(Err(status));

        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

        assert_eq!(step, ResumeStep::Discard, "{status}");
        assert_eq!(domain.journal_on_disk(), None);
        assert_eq!(std::fs::read(&domain.path).expect("vault"), before);
        assert!(!remote.called("install_ca_transition"));
        assert!(!remote.called("send_vault_copy"));
    }
}

/// Requirement of the journal: 429, 500 and 503 say the gateway or the authority
/// could not answer. They say nothing of the rotation, whatever the status read
/// would add, and a live rotation must not be discarded on them.
#[test]
fn a_transient_status_on_the_deposit_keeps_the_rotation() {
    for status in [429, 500, 502, 503] {
        let domain = domain();
        let mut journal = domain.signed(RotationKind::CaPq);
        let before = journal.clone();
        let remote = Remote::watching(&domain.path);
        remote.deposits.borrow_mut().push_back(Err(status));

        let refused =
            advance(&remote, &domain.path, &mut journal, NOW).expect_err("an error to report");

        assert!(refused
            .downcast_ref::<crate::tunnel::TunnelRefusal>()
            .is_some());
        assert_eq!(journal, before, "{status}");
        assert_eq!(domain.journal_on_disk().as_ref(), Some(&before), "{status}");
        assert!(!remote.called("authority_status"), "{status}");

        // The next look replays the same deposit.
        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
        assert_eq!(step, ResumeStep::Finished, "{status}");
    }
}

/// What Astra answers when its own write failed: a 500, and a status read showing
/// nothing in flight. That is not a refusal, so nothing here may read it as the end
/// of the rotation, and the journal holding the incoming key stays.
#[test]
fn a_500_with_nothing_held_keeps_the_rotation_and_the_replay_lands() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        let domain = domain();
        let mut journal = domain.signed(kind);
        let before = journal.clone();
        let next = journal.next.clone().expect("next");
        let vault = std::fs::read(&domain.path).expect("vault");
        let remote = Remote::watching(&domain.path);
        remote.deposits.borrow_mut().push_back(Err(500));

        advance(&remote, &domain.path, &mut journal, NOW).expect_err("an error to report");

        assert_eq!(domain.journal_on_disk().as_ref(), Some(&before), "{kind:?}");
        assert_eq!(before.stage, JournalStage::Signed);
        assert_eq!(
            std::fs::read(&domain.path).expect("vault"),
            vault,
            "{kind:?}"
        );
        assert_eq!(prepared_record_on_disk(&domain), None, "{kind:?}");

        let mut resumed = domain.journal_on_disk().expect("journal");
        let step = advance(&remote, &domain.path, &mut resumed, NOW).expect("advanced");

        assert_eq!(step, ResumeStep::Finished, "{kind:?}");
        assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
        let deposits = remote
            .calls()
            .iter()
            .filter(|call| **call == "submit_campaign")
            .count();
        assert_eq!(deposits, 2, "{kind:?}");
    }
}

#[test]
fn a_deposit_left_waiting_is_not_an_acceptance() {
    let domain = domain();
    let vault = std::fs::read(&domain.path).expect("vault");
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote
        .deposits
        .borrow_mut()
        .push_back(Ok(SigningOperationState::AwaitingOperator));

    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    assert_eq!(journal.stage, JournalStage::Signed);
    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault);
}

/// User decision of §2: a signed object never serves another campaign. Past the
/// window nothing is deposited at all, and the three answers are Astra's.
#[test]
fn a_dead_campaign_is_decided_by_the_authority_and_never_deposited() {
    let domain_held = domain();
    let mut journal = domain_held.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain_held.path);
    *remote.authority.borrow_mut() = Some(holding(&domain_held.path, &journal));
    let step = advance(&remote, &domain_held.path, &mut journal, EXPIRES).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
    assert!(!remote.called("submit_campaign"));

    let domain_gone = domain();
    let vault = std::fs::read(&domain_gone.path).expect("vault");
    let mut journal = domain_gone.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain_gone.path);
    let step = advance(&remote, &domain_gone.path, &mut journal, EXPIRES).expect("advanced");
    assert_eq!(step, ResumeStep::Discard);
    assert!(!remote.called("submit_campaign"));
    assert_eq!(domain_gone.journal_on_disk(), None);
    assert_eq!(std::fs::read(&domain_gone.path).expect("vault"), vault);

    let domain_other = domain();
    let mut journal = domain_other.signed(RotationKind::CaPq);
    let before = domain_other.files();
    let remote = Remote::watching(&domain_other.path);
    *remote.authority.borrow_mut() = Some(OperatorAuthorityStatus {
        next_ca_fingerprint: Some(Fingerprint::of(b"une autre")),
        ..nothing_in_flight(&domain_other.path)
    });
    let step = advance(&remote, &domain_other.path, &mut journal, EXPIRES).expect("advanced");
    assert_eq!(step, ResumeStep::DomainConflict);
    assert!(!remote.called("submit_campaign"));
    assert_eq!(
        domain_other.files(),
        before,
        "nothing cleared, nothing moved"
    );
}

#[test]
fn a_dead_campaign_with_the_status_read_failing_keeps_the_journal() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    *remote.authority.borrow_mut() = None;
    assert!(advance(&remote, &domain.path, &mut journal, EXPIRES).is_err());
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));
}

/// What `astra-signer` leaves behind, adopted: it holds no deposit and does not
/// say whether one went out.
fn adopted_legacy_journal(domain: &Domain) -> RotationJournal {
    let mut vault = store::load(&domain.path).expect("vault");
    let relay = domain.relay();
    let identity = handoff::identity_of(&relay).expect("identity");
    let current = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("anchor");
    let first = gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("first");
    let second = gestures::open_with_authorized_key(&domain.keys[1], &vault, "").expect("second");
    let rotated = signing::rotate_ca_pq(
        &mut vault,
        &[&first, &second],
        &identity,
        Some(&domain.registry()),
        TransitionWindow::new(NOW, NOW + 7 * 86_400, NOW + 37 * 86_400).expect("window"),
        NOW,
    )
    .expect("rotated");
    let mut next_handoff = relay;
    next_handoff.adopt(&vault).expect("adopted");
    next_handoff.ca_epoch = Some(identity.ca_epoch + 1);
    let legacy = LegacyCaPqJournal {
        format_version: LEGACY_CA_PQ_JOURNAL_VERSION,
        output_path: PathBuf::from("/tmp/transition-ca-pq.json"),
        current_ca_public_key: current,
        vault,
        bindings: rotated.bindings,
        transition: rotated.transition,
        handoff: next_handoff,
    };
    documents::write(
        &rotation_journal::legacy_ca_pq_path_beside(&domain.path),
        &legacy,
    )
    .expect("written");
    rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal")
}

/// The user's rule, and `next_step` is its only barrier: `apply_local` does not
/// check it. An adoption Astra does not hold moves no file and reaches nobody.
#[test]
fn an_unconfirmed_adoption_astra_does_not_hold_moves_nothing() {
    let domain = domain();
    let mut journal = adopted_legacy_journal(&domain);
    let before = domain.files();
    let held = journal.clone();
    let remote = Remote::watching(&domain.path);

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::DomainConflict);
    assert_eq!(remote.calls(), vec!["authority_status"]);
    assert_eq!(domain.files(), before, "no file written");
    assert_eq!(journal, held);
}

#[test]
fn an_unconfirmed_adoption_with_astra_silent_moves_nothing() {
    let domain = domain();
    let mut journal = adopted_legacy_journal(&domain);
    let before = domain.files();
    let remote = Remote::watching(&domain.path);
    *remote.authority.borrow_mut() = None;

    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    assert_eq!(remote.calls(), vec!["authority_status"]);
    assert_eq!(domain.files(), before);
}

#[test]
fn an_adoption_astra_holds_runs_to_the_end() {
    let domain = domain();
    let mut journal = adopted_legacy_journal(&domain);
    let next = journal.next.clone().expect("next");
    let remote = Remote::watching(&domain.path);
    *remote.authority.borrow_mut() = Some(holding(&domain.path, &journal));

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::Finished);
    assert!(!remote.called("submit_campaign"));
    assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
    assert_eq!(domain.journal_on_disk(), None);
}

/// A failed read is a failure to report: read as « nothing named » past
/// `activation_at`, it would be a false dead end.
#[test]
fn a_failed_gateway_read_is_an_error_and_not_a_deadline() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote.gateway_read_fails.set(true);
    let past_activation = journal.activation_at;

    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    assert!(!remote.called("install_ca_transition"));
    assert!(advance(&remote, &domain.path, &mut journal, past_activation).is_err());
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));
}

#[test]
fn past_activation_and_not_on_the_gateway_stops_with_the_journal() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote.install_refused.set(Some(503));
    assert!(advance(&remote, &domain.path, &mut journal, NOW).is_err());
    let past_activation = journal.activation_at;

    let step = advance(&remote, &domain.path, &mut journal, past_activation).expect("advanced");

    assert_eq!(step, ResumeStep::InstallDeadlinePassed);
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));
}

#[test]
fn a_gateway_naming_no_anchor_stops_without_error_and_keeps_the_journal() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    *remote.gateway_anchor.borrow_mut() = None;

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::GatewayOutdated);
    assert!(!remote.called("install_client_tls_ca_transition"));
    assert_eq!(journal.stage, JournalStage::Applied);
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));

    // Updated since, the same journal resumes.
    *remote.gateway_anchor.borrow_mut() = Some(Fingerprint::of(b"ancre sortante"));
    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
}

/// An up-to-date gateway with no client TLS CA configured reads the same as an
/// old one, so the label cannot give the update as the only cause.
#[test]
fn the_label_of_a_gateway_naming_no_anchor_gives_both_causes() {
    let label = stop_label(ResumeStep::GatewayOutdated).expect("a label");
    assert!(label.contains("CA TLS"), "{label}");
    assert!(label.contains("mise à jour"), "{label}");
    assert_ne!(
        Some(label),
        stop_label(ResumeStep::DomainConflict),
        "a label of its own"
    );
    assert_eq!(stop_label(ResumeStep::Finished), None);
    assert_eq!(
        stop_label(ResumeStep::Discard),
        Some("Rotation expirée. Recommencer")
    );
    assert_eq!(
        stop_label(ResumeStep::InstallDeadlinePassed),
        Some("Délai dépassé")
    );
}

#[test]
fn the_journal_is_gone_once_the_copy_was_attempted() {
    let answers: [Result<VaultCopySent, u16>; 3] = [
        Ok(VaultCopySent::Copied(
            aether::certificates::transport::OperatorVaultCopied {
                fingerprint: Fingerprint::of(b"copie"),
                credential_registry_epoch: None,
            },
        )),
        Err(413),
        Err(503),
    ];
    for answer in answers {
        let domain = domain();
        let mut journal = domain.signed(RotationKind::CaTls);
        let remote = Remote::watching(&domain.path);
        remote.copies.borrow_mut().push_back(answer);

        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

        assert_eq!(step, ResumeStep::Finished);
        assert!(remote.called("send_vault_copy"));
        assert_eq!(domain.journal_on_disk(), None);
    }
}

#[test]
fn a_failed_copy_does_not_undo_the_rotation() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let next = journal.next.clone().expect("next");
    let anchor = journal.next_anchor_fingerprint;
    let remote = Remote::watching(&domain.path);
    remote.copies.borrow_mut().push_back(Err(500));

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    assert_eq!(step, ResumeStep::Finished);
    assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
    assert_eq!(*remote.gateway_anchor.borrow(), Some(anchor));
}

/// Spec §5.9: a 409 writes nothing and the same copy passes later. It is an
/// ordinary answer, so the rotation stays on the journal rather than failing.
#[test]
fn a_copy_held_back_keeps_the_journal_and_is_retried_at_the_next_look() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote
        .copies
        .borrow_mut()
        .push_back(Ok(VaultCopySent::HeldBack));

    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("not a failure");

    assert_eq!(step, ResumeStep::SendVaultCopy);
    assert_eq!(journal.stage, JournalStage::Installed);
    assert_eq!(domain.journal_on_disk().as_ref(), Some(&journal));

    remote.calls.borrow_mut().clear();
    let step = advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");
    assert_eq!(step, ResumeStep::Finished);
    assert_eq!(remote.calls(), vec!["send_vault_copy"]);
    assert_eq!(domain.journal_on_disk(), None);
}

/// Spec §5.9: during a CA-PQ overlap Astra refuses a document in the copy. Its
/// document comes through the accepted object, and it adopts that at `not_after`.
#[test]
fn the_copy_of_a_rotation_carries_the_vault_alone() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let next = journal.next.clone().expect("next");
    let remote = Remote::watching(&domain.path);

    advance(&remote, &domain.path, &mut journal, NOW).expect("advanced");

    let sent = remote.copies_sent.borrow();
    let [copy] = sent.as_slice() else {
        panic!("one copy");
    };
    assert!(copy.credentials.is_none());
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&copy.vault_base64)
        .expect("base64");
    assert_eq!(
        Fingerprint::of(&bytes),
        next.vault.fingerprint().expect("fingerprint"),
        "what Astra reports is what the screen compares to the vault's own"
    );
}

/// A rotation that reached the gateway reads as installed, and a stop after
/// that resumes with the copy alone, even at a clock past the install deadline.
#[test]
fn a_gateway_already_holding_the_transition_goes_straight_to_the_copy() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    *remote.gateway_anchor.borrow_mut() = Some(journal.next_anchor_fingerprint);
    let past_activation = journal.activation_at;
    rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");

    let step = advance(&remote, &domain.path, &mut journal, past_activation).expect("advanced");

    assert_eq!(step, ResumeStep::Finished);
    assert_eq!(
        remote.calls(),
        vec!["gateway_next_anchor", "send_vault_copy"]
    );
}

// Renewing the fleet during a CA-PQ overlap (spec §5.9, the plan's Task 12 reads
// this result).

/// The approval Orion would produce under the rotated document, against the one
/// Astra still verifies with until `not_after`.
///
/// Refused by `CampaignApproval::verify`: an approval carries
/// `credential_fingerprint`, which is `AstraCredentialBinding::fingerprint`, and
/// that covers the row's `ca_epoch`, its registry epoch and its `CA-PQ` signature.
/// All three change when the document is re-signed under the new anchor, even
/// though the credential's public key does not. So the assertion verifies and the
/// row does not match.
#[test]
fn fleet_approval_under_the_rotated_document_is_refused_by_astra_during_overlap() {
    let domain = domain();
    let astra_document = domain.registry();
    let mut journal = domain.signed(RotationKind::CaPq);
    advance(
        &Remote::watching(&domain.path),
        &domain.path,
        &mut journal,
        NOW,
    )
    .expect("rotated");

    let orion_document = domain.registry();
    assert_eq!(orion_document.ca_epoch, astra_document.ca_epoch + 1);
    let relay = domain.relay();
    let identity = handoff::identity_of(&relay).expect("identity");
    let anchor = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim()).expect("anchor");

    let campaign = domain.campaign(
        CampaignScope::FleetLeafs,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: WireGuardKey::from_bytes([0x33; 32]),
            epoch: 1,
            generation: 1,
            active_tls_certificate_fingerprint: Fingerprint::of(b"feuille tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"feuille pq"),
        }],
        EXPIRES,
    );
    let mut session = CampaignApprovalSession::new(
        &campaign,
        &orion_document,
        &identity,
        &anchor,
        RP_ID,
        ORIGIN,
        NOW,
    )
    .expect("Orion opens the ceremony under the document it holds");
    let assertion = domain.keys[0]
        .approve(
            session.webauthn_rp_id(),
            &session.offered_credentials(),
            session.client_data_json(),
            "",
        )
        .expect("touched");
    session.accept(assertion, NOW).expect("verified by Orion");
    let approval = session.finish(NOW).expect("finished");

    approval
        .verify(&campaign, &orion_document, RP_ID, ORIGIN, NOW)
        .expect("valid under the rotated document");
    assert_eq!(
        approval.verify(&campaign, &astra_document, RP_ID, ORIGIN, NOW),
        Err(CertificateError::InvalidAssertion("credential binding"))
    );
}

// « Terminer ».

/// A client TLS rotation carried to its end, with its prepared record left beside
/// the vault, and the instant its overlap is over.
fn finished_client_tls(domain: &Domain) -> u64 {
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    assert_eq!(
        advance(&remote, &domain.path, &mut journal, NOW).expect("advanced"),
        ResumeStep::Finished
    );
    journal.not_after
}

fn refusal_of_finish(error: &anyhow::Error) -> &FinishRefusal {
    error.downcast_ref::<FinishRefusal>().expect("a refusal")
}

fn record_of(domain: &Domain) -> Option<prepared::PreparedRotation> {
    prepared::load(&prepared::path_beside(&domain.path)).expect("record")
}

/// What is in the vault's issuing slot, seen from the certificate it should match.
fn assert_issues_under(domain: &Domain, key: &TestKey, certificate: &str) {
    let vault = store::load(&domain.path).expect("vault");
    let opening = gestures::open_with_authorized_key(key, &vault, "").expect("opened");
    let certificate = DerCertificate::parse(certificate).expect("certificate");
    assert!(signing::issues_under(&vault, &opening, &certificate).expect("read"));
    assert_eq!(
        vault
            .ca_tls_window(&opening.credential_id, &opening.secret)
            .expect("window"),
        None
    );
}

/// The incoming certificate comes from the record the journal left, nothing
/// remains to be promoted, and the copy that follows is the vault that moved.
#[test]
fn finishing_moves_the_vault_and_the_relay_then_clears_the_record_and_sends_the_copy() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let record = record_of(&domain).expect("the record survives the journal");
    let relay_before = domain.relay();
    let touches = domain.touches();
    let remote = Remote::watching(&domain.path);

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
    assert_eq!(domain.touches(), touches, "nothing is asked before the key");
    let opening = finish.open(&domain.keys[1]).expect("one key");
    assert_eq!(domain.touches(), touches + 1);
    finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect("finished");

    assert_eq!(domain.touches(), touches + 1, "one key, one touch");
    let relay = domain.relay();
    assert_eq!(relay.ca_tls_epoch, Some(record.next_ca_tls_epoch));
    assert_eq!(
        relay.ca_tls_certificate.as_deref(),
        Some(record.next_ca_tls_certificate.as_str())
    );
    assert_ne!(relay.ca_tls_certificate, relay_before.ca_tls_certificate);
    let vault = store::load(&domain.path).expect("vault");
    assert_eq!(
        relay.vault_fingerprint,
        vault.fingerprint().expect("fingerprint").to_hex()
    );
    assert_eq!(record_of(&domain), None);
    assert_issues_under(&domain, &domain.keys[0], &record.next_ca_tls_certificate);

    assert_eq!(remote.calls(), vec!["send_vault_copy"]);
    let copies = remote.copies_sent.borrow();
    assert_eq!(
        copies[0].vault_base64,
        vault_copy(&domain.path).expect("copy").vault_base64
    );
    assert_eq!(copies[0].credentials, None);
}

/// What the touch does: the certificate going and the one coming, by fingerprint,
/// with no campaign, since this executes one already approved.
#[test]
fn the_finish_shows_the_two_anchors_before_the_key() {
    let domain = domain();
    let outgoing = DerCertificate::parse(domain.relay().ca_tls_certificate.as_ref().expect("cert"))
        .expect("certificate");
    let not_after = finished_client_tls(&domain);
    let record = record_of(&domain).expect("record");
    let incoming = DerCertificate::parse(&record.next_ca_tls_certificate).expect("certificate");

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");

    let AstraManifest::CaRotation(manifest) = finish.manifest() else {
        panic!("a rotation manifest")
    };
    assert_eq!(manifest.trust_domain_id, trust_domain());
    assert_eq!(manifest.affected_ca, AffectedCa::CaTls);
    assert_eq!(manifest.current_epoch, record.next_ca_tls_epoch - 1);
    assert_eq!(manifest.next_epoch, record.next_ca_tls_epoch);
    assert_eq!(manifest.activation_at, record.activation_at);
    assert_eq!(manifest.not_after, record.not_after);
    assert_eq!(manifest.outgoing_anchor_fingerprint, outgoing.fingerprint());
    assert_eq!(
        manifest.next_anchor_fingerprint,
        Some(incoming.fingerprint())
    );
    assert_eq!(manifest.campaign, None);
}

/// The vault was saved and the machine stopped before the relay: the vault reads
/// as idle while the record is still there. The command-line tool gives up at this
/// point. This one has what it takes to finish, and rewrites no vault.
#[test]
fn a_stop_between_the_vault_and_the_relay_is_finished_by_the_next_press() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let record = record_of(&domain).expect("record");
    let mut vault = store::load(&domain.path).expect("vault");
    let opening = gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("opened");
    assert!(matches!(
        signing::advance_ca_tls(&mut vault, &opening, not_after).expect("advanced"),
        crate::vault::CaTlsAdvance::Rotated { .. }
    ));
    store::save(&domain.path, &vault).expect("saved");
    let vault_bytes = std::fs::read(&domain.path).expect("vault");
    let remote = Remote::watching(&domain.path);

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("still to finish");
    let opening = finish.open(&domain.keys[0]).expect("one key");
    finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect("the relay is finished");

    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault_bytes);
    let relay = domain.relay();
    assert_eq!(relay.ca_tls_epoch, Some(record.next_ca_tls_epoch));
    assert_eq!(
        relay.ca_tls_certificate.as_deref(),
        Some(record.next_ca_tls_certificate.as_str())
    );
    assert_eq!(
        relay.vault_fingerprint,
        vault.fingerprint().expect("fingerprint").to_hex()
    );
    assert_eq!(record_of(&domain), None);
    assert!(remote.called("send_vault_copy"));
}

/// A stop after the relay, before the record is cleared: the same press, and the
/// relay is written the same.
#[test]
fn a_stop_between_the_relay_and_the_clearing_is_finished_by_the_next_press() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let record = record_of(&domain).expect("record");
    let remote = Remote::watching(&domain.path);
    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
    let opening = finish.open(&domain.keys[0]).expect("one key");
    finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect("finished");
    let relay = domain.relay();
    prepared::save(&prepared::path_beside(&domain.path), &record).expect("put back");

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("still to finish");
    let opening = finish.open(&domain.keys[0]).expect("one key");
    finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect("finished again");

    assert_eq!(domain.relay(), relay);
    assert_eq!(record_of(&domain), None);
}

/// A journal stuck past `not_after` has not reached the gateway: promoting would
/// destroy the outgoing key while the gateway never installed the successor.
#[test]
fn a_journal_stuck_on_the_gateway_is_never_promoted() {
    let elsewhere = Some(Fingerprint::of(b"ancre en service"));
    for (read, stop, late) in [
        (None, ResumeStep::GatewayOutdated, false),
        (elsewhere, ResumeStep::InstallDeadlinePassed, true),
    ] {
        let domain = domain();
        let mut journal = domain.signed(RotationKind::CaTls);
        let remote = Remote::watching(&domain.path);
        remote.install_refused.set(Some(503));
        advance(&remote, &domain.path, &mut journal, NOW).expect_err("not installed");
        assert_eq!(journal.stage, JournalStage::Applied);
        remote.install_refused.set(None);
        *remote.gateway_anchor.borrow_mut() = read;
        let at = if late { journal.activation_at } else { NOW };
        assert_eq!(
            advance(&remote, &domain.path, &mut journal, at).expect("stopped"),
            stop
        );
        let record = record_of(&domain).expect("the apply left its record");
        assert!(record.submitted && record.adopted);
        let files = domain.files();
        let touches = domain.touches();

        let refused = CaTlsFinish::begin(&domain.path, journal.not_after + 1)
            .err()
            .expect("refused");

        assert!(matches!(
            refusal_of_finish(&refused),
            FinishRefusal::InFlight
        ));
        assert_eq!(domain.touches(), touches, "{stop:?}");
        assert_eq!(domain.files(), files, "{stop:?}");
    }
}

/// A journal is written while the key is being touched: read again before anything
/// moves. So is a vault that changed in that time.
#[test]
fn what_moved_during_the_touch_stops_the_finish() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let remote = Remote::watching(&domain.path);

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
    let opening = finish.open(&domain.keys[0]).expect("one key");
    let journal_path = rotation_journal::path_beside(&domain.path);
    std::fs::write(&journal_path, b"{}").expect("a journal appears");
    let files = domain.files();
    let refused = finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect_err("refused");
    assert!(matches!(
        refusal_of_finish(&refused),
        FinishRefusal::InFlight
    ));
    assert_eq!(domain.files(), files);
    std::fs::remove_file(&journal_path).expect("gone");

    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
    let opening = finish.open(&domain.keys[0]).expect("one key");
    let mut moved = store::load(&domain.path).expect("vault");
    moved.created_at += 1;
    store::save(&domain.path, &moved).expect("saved");
    let files = domain.files();
    let refused = finish
        .finish(&remote, &domain.path, opening, not_after)
        .expect_err("refused");
    assert!(matches!(refusal_of_finish(&refused), FinishRefusal::Moved));
    assert_eq!(domain.files(), files);
    assert!(!remote.called("send_vault_copy"));
}

#[test]
fn nothing_to_finish_asks_no_key() {
    let domain = domain();
    let touches = domain.touches();
    let refused = CaTlsFinish::begin(&domain.path, NOW)
        .err()
        .expect("refused");
    assert!(matches!(
        refusal_of_finish(&refused),
        FinishRefusal::Nothing
    ));
    assert_eq!(domain.touches(), touches);
}

/// Too early, and said before the key: the overlap is what the gateway relies on.
#[test]
fn the_finish_waits_for_not_after_before_any_key() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let touches = domain.touches();
    let refused = CaTlsFinish::begin(&domain.path, not_after - 1)
        .err()
        .expect("refused");
    assert!(matches!(
        refusal_of_finish(&refused),
        FinishRefusal::NotYet { at } if *at == not_after
    ));
    assert_eq!(domain.touches(), touches);
}

/// A record `astra-signer` left, which no journal has carried to the gateway yet,
/// or one never deposited: the resumption comes first.
#[test]
fn a_record_no_journal_has_carried_is_resumed_before_it_is_finished() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let record = record_of(&domain).expect("record");
    let path = prepared::path_beside(&domain.path);
    for unfinished in [
        prepared::PreparedRotation {
            adopted: false,
            ..record.clone()
        },
        prepared::PreparedRotation {
            submitted: false,
            ..record.clone()
        },
    ] {
        prepared::save(&path, &unfinished).expect("saved");
        let refused = CaTlsFinish::begin(&domain.path, not_after)
            .err()
            .expect("refused");
        assert!(matches!(
            refusal_of_finish(&refused),
            FinishRefusal::InFlight
        ));
    }
}

/// The two files do not describe one vault: the certificate named is not the one
/// the vault holds, whether it has already advanced or not. Nothing moves.
#[test]
fn a_record_naming_another_certificate_moves_nothing() {
    for vault_advanced in [false, true] {
        let domain = domain();
        let not_after = finished_client_tls(&domain);
        let record = record_of(&domain).expect("record");
        if vault_advanced {
            let mut vault = store::load(&domain.path).expect("vault");
            let opening =
                gestures::open_with_authorized_key(&domain.keys[0], &vault, "").expect("opened");
            signing::advance_ca_tls(&mut vault, &opening, not_after).expect("advanced");
            store::save(&domain.path, &vault).expect("saved");
        }
        // A certificate of the domain, and not the incoming one.
        let another = domain.relay().ca_tls_certificate.expect("cert");
        prepared::save(
            &prepared::path_beside(&domain.path),
            &prepared::PreparedRotation {
                next_ca_tls_certificate: another,
                ..record
            },
        )
        .expect("saved");
        let files = domain.files();
        let remote = Remote::watching(&domain.path);

        let finish = CaTlsFinish::begin(&domain.path, not_after).expect("readable");
        let opening = finish.open(&domain.keys[0]).expect("one key");
        let refused = finish
            .finish(&remote, &domain.path, opening, not_after)
            .expect_err("refused");

        assert!(
            matches!(refusal_of_finish(&refused), FinishRefusal::Mismatch),
            "{vault_advanced}"
        );
        assert_eq!(domain.files(), files, "{vault_advanced}");
        assert_eq!(remote.calls(), Vec::<&str>::new());
    }
}

#[test]
fn a_key_outside_the_vault_is_turned_down_and_another_can_finish() {
    let domain = domain();
    let not_after = finished_client_tls(&domain);
    let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
    let stranger = TestKey::new(9);
    stranger.registered.set(true);
    assert!(matches!(finish.open(&stranger), Err(KeyStep::NotEnrolled)));
    domain.keys[0].declines.set(true);
    assert!(matches!(
        finish.open(&domain.keys[0]),
        Err(KeyStep::Declined)
    ));
    domain.keys[0].declines.set(false);
    let opening = finish.open(&domain.keys[0]).expect("one key");
    finish
        .finish(
            &Remote::watching(&domain.path),
            &domain.path,
            opening,
            not_after,
        )
        .expect("finished");
}

/// As after a rotation (§5.9): the copy lost or held back does not undo the vault,
/// and the prerequisite reads what Astra holds.
#[test]
fn a_copy_refused_or_held_back_does_not_undo_the_finish() {
    for answer in [Err(503), Ok(VaultCopySent::HeldBack)] {
        let domain = domain();
        let not_after = finished_client_tls(&domain);
        let remote = Remote::watching(&domain.path);
        remote.copies.borrow_mut().push_back(answer);

        let finish = CaTlsFinish::begin(&domain.path, not_after).expect("ready");
        let opening = finish.open(&domain.keys[0]).expect("one key");
        finish
            .finish(&remote, &domain.path, opening, not_after)
            .expect("finished");

        assert!(remote.called("send_vault_copy"));
        assert_eq!(record_of(&domain), None);
    }
}

// What Orion asks before any key.

#[test]
fn what_stands_in_the_way_is_readable_before_any_key() {
    let domain = domain();
    ensure_nothing_outstanding(&domain.path).expect("nothing outstanding");
    let keys = ValidatedKeys::new(&domain.path).expect("keys");
    keys.ensure_domain_readable(&domain.path, RotationKind::CaTls)
        .expect("readable");

    let mut relay = domain.relay();
    relay.ca_tls_certificate = None;
    handoff::save(&handoff::path_beside(&domain.path), &relay).expect("relay");
    assert!(keys
        .ensure_domain_readable(&domain.path, RotationKind::CaTls)
        .is_err());
    keys.ensure_domain_readable(&domain.path, RotationKind::CaPq)
        .expect("a CA-PQ rotation does not read it");
    assert_eq!(domain.touches(), 0);

    std::fs::write(rotation_journal::path_beside(&domain.path), b"{}").expect("journal");
    assert!(ensure_nothing_outstanding(&domain.path).is_err());
}

#[test]
fn terms_that_would_be_refused_are_read_before_they_cost_anything() {
    check_terms(RotationKind::CaTls, &terms(), NOW).expect("the defaults");
    let short = RotationTerms {
        prepare_days: 0,
        ..terms()
    };
    assert!(check_terms(RotationKind::CaPq, &short, NOW).is_err());
    let brief = RotationTerms {
        validity_days: DEFAULT_PREPARE_DAYS + DEFAULT_OVERLAP_DAYS,
        ..terms()
    };
    assert!(check_terms(RotationKind::CaTls, &brief, NOW).is_err());
    check_terms(RotationKind::CaPq, &brief, NOW).expect("no certificate to outlive");
}

#[test]
fn an_opened_rotation_says_which_operation_and_until_when() {
    let domain = domain();
    let remote = domain.armed_remote();
    let rotation = domain.opened(RotationKind::CaTls, &remote);
    assert_eq!(rotation.operation_id(), operation());
    assert_eq!(rotation.campaign_expires_at(), EXPIRES);
}

/// A gateway out of reach, told from one that answered.
#[test]
fn a_lost_connection_reads_apart_from_a_refusal() {
    let tunnel = crate::tunnel::Tunnel::new("http://127.0.0.1:1").expect("tunnel");
    let lost = tunnel.authority_status().expect_err("nothing listens");
    assert!(crate::tunnel::is_unreachable(&lost));
    assert!(!crate::tunnel::is_unreachable(&admin_refusal(503, None)));
    assert!(!crate::tunnel::is_unreachable(&anyhow::anyhow!("autre")));
}

// Resuming at a tunnel-up (spec §5.4, §5.5).

/// A journal stopped at each stage is carried to its end by `advance` alone: a
/// resumption asks no key.
#[test]
fn resume_after_a_stop_at_each_stage_asks_no_key() {
    for kind in [RotationKind::CaPq, RotationKind::CaTls] {
        for stage in [
            JournalStage::Signed,
            JournalStage::Accepted,
            JournalStage::Applied,
            JournalStage::Installed,
        ] {
            let domain = domain();
            let mut journal = domain.signed(kind);
            let next = journal.next.clone().expect("next");
            let held_back = Remote::watching(&domain.path);
            match stage {
                JournalStage::Signed => {}
                JournalStage::Accepted => {
                    rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted")
                }
                JournalStage::Applied => {
                    held_back.install_refused.set(Some(503));
                    advance(&held_back, &domain.path, &mut journal, NOW).expect_err("stopped");
                }
                JournalStage::Installed => {
                    held_back
                        .copies
                        .borrow_mut()
                        .push_back(Ok(VaultCopySent::HeldBack));
                    let step =
                        advance(&held_back, &domain.path, &mut journal, NOW).expect("stopped");
                    assert_eq!(step, ResumeStep::SendVaultCopy);
                }
            }
            assert_eq!(domain.journal_on_disk().expect("kept").stage, stage);
            let touches = domain.touches();
            let remote = Remote::watching(&domain.path);

            let step = advance(&remote, &domain.path, &mut journal, NOW).expect("resumed");

            assert_eq!(step, ResumeStep::Finished, "{kind:?} {stage:?}");
            assert_eq!(domain.touches(), touches);
            assert_eq!(domain.journal_on_disk(), None);
            assert_eq!(store::load(&domain.path).expect("vault"), next.vault);
        }
    }
}

/// Review focus 2: the tunnel drops after Astra accepted and before the gateway was
/// told. The next tunnel-up finishes alone, and a gateway that already names the
/// anchor is not sent the transition again.
#[test]
fn tunnel_cut_between_acceptance_and_install_resumes_alone() {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    rotation_journal::record_accepted(&domain.path, &mut journal).expect("accepted");
    let touches = domain.touches();

    let cut = Remote::watching(&domain.path);
    cut.gateway_read_fails.set(true);
    advance(&cut, &domain.path, &mut journal, NOW).expect_err("the tunnel is down");
    assert!(domain.journal_on_disk().is_some());
    assert!(!cut.called("install_ca_transition"));

    let back = Remote::watching(&domain.path);
    *back.gateway_anchor.borrow_mut() = Some(journal.next_anchor_fingerprint);
    let step = advance(&back, &domain.path, &mut journal, NOW).expect("resumed");

    assert_eq!(step, ResumeStep::Finished);
    assert!(!back.called("install_ca_transition"));
    assert_eq!(domain.journal_on_disk(), None);
    assert_eq!(domain.touches(), touches);
}

/// The three dead ends are retried at each tunnel-up with no key, and stop the same
/// way each time, with the journal and the files as they were.
#[test]
fn resume_dead_ends_fail_safely_and_repeatedly() {
    // The gateway names no anchor.
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaTls);
    let remote = Remote::watching(&domain.path);
    *remote.gateway_anchor.borrow_mut() = None;
    advance(&remote, &domain.path, &mut journal, NOW).expect("stopped");
    let (files, touches) = (domain.files(), domain.touches());
    for _ in 0..2 {
        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("stopped");
        assert_eq!(step, ResumeStep::GatewayOutdated);
        assert_eq!(domain.files(), files);
    }
    assert_eq!(domain.touches(), touches);

    // Past the activation, and still not installed.
    let domain = domain_with_install_refused();
    let (mut journal, remote) = domain.1;
    let activation = journal.activation_at;
    for _ in 0..2 {
        let step = advance(&remote, &domain.0.path, &mut journal, activation).expect("stopped");
        assert_eq!(step, ResumeStep::InstallDeadlinePassed);
        assert!(domain.0.journal_on_disk().is_some());
    }

    // An adoption Astra does not hold.
    let domain = self::domain();
    adopted_legacy_journal(&domain);
    let mut journal = domain.journal_on_disk().expect("adopted");
    let remote = Remote::watching(&domain.path);
    for _ in 0..2 {
        let step = advance(&remote, &domain.path, &mut journal, NOW).expect("stopped");
        assert_eq!(step, ResumeStep::DomainConflict);
        assert!(domain.journal_on_disk().is_some());
    }
}

fn domain_with_install_refused() -> (Domain, (RotationJournal, Remote)) {
    let domain = domain();
    let mut journal = domain.signed(RotationKind::CaPq);
    let remote = Remote::watching(&domain.path);
    remote.install_refused.set(Some(503));
    advance(&remote, &domain.path, &mut journal, NOW).expect_err("not installed");
    (domain, (journal, remote))
}

// What there is to resume.

#[test]
fn resume_trigger_counts_a_journal_an_unadopted_record_and_a_legacy_file() {
    let domain = domain();
    assert!(!rotation_journal::something_to_resume(&domain.path).expect("read"));

    domain.signed(RotationKind::CaPq);
    assert!(rotation_journal::something_to_resume(&domain.path).expect("read"));
    rotation_journal::clear(&rotation_journal::path_beside(&domain.path)).expect("cleared");
    assert!(!rotation_journal::something_to_resume(&domain.path).expect("read"));

    std::fs::write(
        rotation_journal::legacy_ca_pq_path_beside(&domain.path),
        b"{}",
    )
    .expect("legacy");
    assert!(rotation_journal::something_to_resume(&domain.path).expect("read"));
}

#[test]
fn resume_trigger_counts_an_unadopted_record_and_not_an_adopted_one() {
    let domain = domain();
    finished_client_tls(&domain);
    let record = record_of(&domain).expect("record");
    let path = prepared::path_beside(&domain.path);

    prepared::save(
        &path,
        &prepared::PreparedRotation {
            adopted: true,
            ..record.clone()
        },
    )
    .expect("saved");
    assert!(!rotation_journal::something_to_resume(&domain.path).expect("read"));

    prepared::save(
        &path,
        &prepared::PreparedRotation {
            adopted: false,
            ..record
        },
    )
    .expect("saved");
    assert!(rotation_journal::something_to_resume(&domain.path).expect("read"));
}

#[test]
fn resume_trigger_reads_a_record_it_cannot_parse_as_an_error() {
    let domain = domain();
    std::fs::write(prepared::path_beside(&domain.path), b"illisible").expect("written");
    assert!(rotation_journal::something_to_resume(&domain.path).is_err());
}
