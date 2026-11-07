//! The rotation gestures, against simulated keys, a simulated tunnel and a clock
//! the test moves.
//!
//! Only the CTAP2 boundary, the tunnel and the time are simulated. The vault, both
//! rotations, every signature and the journal are astra-operator's production code.
//! A script answers each status as it is published, the way the window does.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aether::certificates::approval::AstraIssuancePolicy;
use aether::certificates::authority::{CaTransition, ClientTlsCaTransition};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId, WireGuardKey,
};
use aether::certificates::operator_session::{
    AffectedCa, AstraManifest, GestureState, KeyPurpose, OperationKind, OperationLocator,
    OperatorAction, RemoteState,
};
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerRequest, AstraSignerResult, CampaignScope, CampaignTarget,
    CertificateKind,
};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorOpenRequest, OperatorOpened, OperatorVaultCopied,
    OperatorVaultCopy, SigningOperationState,
};
use aether::certificates::webauthn::WebAuthnAssertion;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether_fido::authenticator::{
    Approval, ApprovedOpening, AuthenticatorError, CredentialSubject, Opened, Registration,
};
use astra_operator::gestures::{NewAuthority, NewKey};
use astra_operator::operations::rotation::{
    RotationTerms, DEFAULT_CA_TLS_VALIDITY_DAYS, DEFAULT_OVERLAP_DAYS, DEFAULT_PREPARE_DAYS,
};
use astra_operator::origin::CampaignRequest;
use astra_operator::rotation_journal::{self, JournalStage, RotationJournal, RotationKind};
use astra_operator::tunnel::{admin_refusal, Tunnel, VaultCopySent};
use astra_operator::vault::{CaTlsAdvance, SlotRole, SlotSecret};
use astra_operator::vault_gestures::{add_key_with, create_first_key, finalize_with};
use astra_operator::{gestures, handoff, prepared, signing, store};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use zeroize::Zeroizing;

use super::*;
use crate::operator::{OperatorCeremony, RotationGesture};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = NOW + 300;
const RP_ID: &str = "astra.helios.test";
const ORIGIN: &str = "https://astra.helios.test";
const AUTHORITY_URL: &str = "https://astra.helios.test/";
const SERVER_NAME: &str = "gateway.helios.test";
const CEREMONY_THREAD: &str = "orion-operator-ceremony";

fn operation() -> Id16 {
    Id16::new([0x0B; 16]).expect("operation")
}

fn trust_domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

/// One simulated security key, holding one credential, and what it was asked.
struct TestKey {
    serial: u8,
    registered: AtomicBool,
    touches: AtomicU32,
    declines: AtomicBool,
    /// What it released, to look for in what the window receives.
    released: Mutex<Vec<Vec<u8>>>,
    /// Which thread each gesture came from.
    threads: Mutex<Vec<String>>,
}

impl TestKey {
    fn new(serial: u8) -> Self {
        Self {
            serial,
            registered: AtomicBool::new(false),
            touches: AtomicU32::new(0),
            declines: AtomicBool::new(false),
            released: Mutex::default(),
            threads: Mutex::default(),
        }
    }

    fn enrolled(serial: u8) -> Self {
        let key = Self::new(serial);
        key.registered.store(true, Ordering::SeqCst);
        key
    }

    fn credential_id(&self) -> Vec<u8> {
        vec![self.serial; 64]
    }

    fn signing_key(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[self.serial ^ 0x5A; 32]).expect("seed")
    }

    /// The key present answers whichever was asked for, as under Windows WebAuthn.
    fn answer(&self) -> Result<Vec<u8>, AuthenticatorError> {
        if self.declines.load(Ordering::SeqCst) {
            return Err(AuthenticatorError::Device("geste annulé".into()));
        }
        if !self.registered.load(Ordering::SeqCst) {
            return Err(AuthenticatorError::UnknownCredential);
        }
        self.touches.fetch_add(1, Ordering::SeqCst);
        let thread = std::thread::current().name().unwrap_or("").to_string();
        self.threads.lock().expect("lock").push(thread);
        Ok(self.credential_id())
    }
}

impl Authenticator for TestKey {
    fn needs_pin(&self) -> bool {
        false
    }

    fn register(
        &self,
        _rp_id: &str,
        _subject: &CredentialSubject,
        _exclude: &[Vec<u8>],
        _pin: &str,
    ) -> aether_fido::authenticator::Result<Registration> {
        self.registered.store(true, Ordering::SeqCst);
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
    ) -> aether_fido::authenticator::Result<Opened> {
        let credential_id = self.answer()?;
        if !credentials.contains(&credential_id) {
            return Err(AuthenticatorError::UnknownCredential);
        }
        let mut output = *salt;
        output.iter_mut().for_each(|byte| *byte ^= self.serial);
        self.released.lock().expect("lock").push(output.to_vec());
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
    ) -> aether_fido::authenticator::Result<Approval> {
        if !credentials.contains(&self.credential_id()) {
            return Err(AuthenticatorError::UnknownCredential);
        }
        let credential_id = self.answer()?;
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
    ) -> aether_fido::authenticator::Result<ApprovedOpening> {
        unreachable!("a rotation takes its two gestures apart")
    }
}

/// What the ceremony holds of a key for the length of a gesture.
struct Plugged(Arc<TestKey>);

impl Authenticator for Plugged {
    fn needs_pin(&self) -> bool {
        false
    }

    fn register(
        &self,
        rp_id: &str,
        subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        pin: &str,
    ) -> aether_fido::authenticator::Result<Registration> {
        self.0.register(rp_id, subject, exclude, pin)
    }

    fn derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; 32],
        pin: &str,
    ) -> aether_fido::authenticator::Result<Opened> {
        self.0.derive(rp_id, credentials, salt, pin)
    }

    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        pin: &str,
    ) -> aether_fido::authenticator::Result<Approval> {
        self.0.approve(rp_id, credentials, client_data_json, pin)
    }

    fn approve_and_derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> aether_fido::authenticator::Result<ApprovedOpening> {
        self.0
            .approve_and_derive(rp_id, credentials, client_data_json, salt, pin)
    }
}

/// The tunnel, as a test scripts it. Each call is recorded by name.
#[derive(Default)]
struct Remote {
    calls: Mutex<Vec<&'static str>>,
    request: Mutex<Option<CampaignRequest>>,
    open_refused: Mutex<Option<u16>>,
    /// Answers to the deposits, in order; once empty, Astra accepts.
    deposits: Mutex<VecDeque<u16>>,
    authority: Mutex<Option<OperatorAuthorityStatus>>,
    gateway_anchor: Mutex<Option<Fingerprint>>,
    install_refused: Mutex<Option<u16>>,
    copies: Mutex<VecDeque<VaultCopySent>>,
}

impl Remote {
    fn note(&self, name: &'static str) {
        self.calls.lock().expect("lock").push(name);
    }

    fn called(&self, name: &str) -> bool {
        self.calls.lock().expect("lock").contains(&name)
    }

    fn install(&self, name: &'static str, anchor: Fingerprint) -> anyhow::Result<()> {
        self.note(name);
        if let Some(status) = *self.install_refused.lock().expect("lock") {
            return Err(admin_refusal(status, None));
        }
        *self.gateway_anchor.lock().expect("lock") = Some(anchor);
        Ok(())
    }
}

impl RotationRemote for Remote {
    fn open_campaign(&self, _request: &OperatorOpenRequest) -> anyhow::Result<OperatorOpened> {
        self.note("open_campaign");
        if let Some(status) = *self.open_refused.lock().expect("lock") {
            return Err(admin_refusal(status, None));
        }
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

    fn fetch_campaign(&self, _operation_id: &Id16) -> anyhow::Result<CampaignRequest> {
        self.note("fetch_campaign");
        Ok(self
            .request
            .lock()
            .expect("lock")
            .take()
            .expect("an armed campaign"))
    }

    fn submit_campaign(
        &self,
        _operation_id: &Id16,
        _result_token: &str,
        _result: &AstraSignerResult,
    ) -> anyhow::Result<SigningOperationState> {
        self.note("submit_campaign");
        match self.deposits.lock().expect("lock").pop_front() {
            None => Ok(SigningOperationState::Approved),
            Some(status) => Err(admin_refusal(status, None)),
        }
    }

    fn authority_status(&self) -> anyhow::Result<OperatorAuthorityStatus> {
        self.note("authority_status");
        Ok(self
            .authority
            .lock()
            .expect("lock")
            .clone()
            .expect("an authority"))
    }

    fn send_vault_copy(&self, _copy: &OperatorVaultCopy) -> anyhow::Result<VaultCopySent> {
        self.note("send_vault_copy");
        Ok(self
            .copies
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or(VaultCopySent::Copied(OperatorVaultCopied {
                fingerprint: Fingerprint::of(b"copie"),
                credential_registry_epoch: None,
            })))
    }

    fn install_ca_transition(&self, transition: &CaTransition) -> anyhow::Result<()> {
        self.install("install_ca_transition", transition.next_ca_fingerprint)
    }

    fn install_client_tls_ca_transition(
        &self,
        transition: &ClientTlsCaTransition,
    ) -> anyhow::Result<()> {
        self.install(
            "install_client_tls_ca_transition",
            transition.next_client_tls_ca_certificate.fingerprint(),
        )
    }

    fn gateway_next_anchor(&self, _kind: RotationKind) -> anyhow::Result<Option<Fingerprint>> {
        self.note("gateway_next_anchor");
        Ok(*self.gateway_anchor.lock().expect("lock"))
    }
}

/// A finished domain with three enrolled keys, the tunnel and the clock.
struct Bench {
    _directory: TempDirectory,
    path: PathBuf,
    keys: Vec<Arc<TestKey>>,
    stranger: Arc<TestKey>,
    service_key: Zeroizing<Vec<u8>>,
    remote: Remote,
    clock: AtomicU64,
    /// Which key answers the next gesture; [`STRANGER`] for one outside the vault.
    plugged: AtomicUsize,
    /// The refusal the next connection fails with, if any.
    unreachable: Mutex<Option<Refusal>>,
    /// Where the clock jumps at the next connection, standing for a touch that
    /// took that long.
    touch_ends_at: AtomicU64,
}

const STRANGER: usize = usize::MAX;

struct TempDirectory(PathBuf);

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

fn bench() -> Arc<Bench> {
    let directory = std::env::temp_dir().join(format!(
        "orion-rotation-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("authority-vault.json");
    let keys: Vec<_> = (1..=3)
        .map(|serial| Arc::new(TestKey::new(serial)))
        .collect();
    let first = create_first_key(
        &path,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: trust_domain(),
            label: "Clé 1".into(),
            role: SlotRole::Primary,
        },
        AUTHORITY_URL,
        keys[0].as_ref(),
        "",
        NOW,
    )
    .expect("the domain is created");
    for (key, label) in [(&keys[1], "Clé 2"), (&keys[2], "Clé 3")] {
        let request = NewKey {
            label: label.to_string(),
            role: SlotRole::Recovery,
        };
        add_key_with(&path, &first, key.as_ref(), &request, "", NOW).expect("key added");
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
    for key in &keys {
        key.touches.store(0, Ordering::SeqCst);
        key.released.lock().expect("lock").clear();
        key.threads.lock().expect("lock").clear();
    }
    let bench = Bench {
        _directory: TempDirectory(directory),
        path,
        keys,
        stranger: Arc::new(TestKey::enrolled(9)),
        service_key,
        remote: Remote::default(),
        clock: AtomicU64::new(NOW),
        plugged: AtomicUsize::new(0),
        unreachable: Mutex::default(),
        touch_ends_at: AtomicU64::new(0),
    };
    bench.arm(EXPIRES);
    *bench.remote.authority.lock().expect("lock") = Some(bench.nothing_in_flight());
    *bench.remote.gateway_anchor.lock().expect("lock") = Some(Fingerprint::of(b"ancre sortante"));
    Arc::new(bench)
}

/// How one run ended, and what it published.
struct Ran {
    outcome: Result<(), String>,
    published: Vec<OperatorStatus>,
    /// Whether the run still held an opening when it returned.
    still_held: bool,
}

impl Ran {
    fn last(&self) -> &OperatorStatus {
        self.published.last().expect("a status")
    }

    fn refused(&self, refusal: Refusal) {
        let last = self.last();
        assert_eq!(last.gesture, GestureState::Failed);
        assert_eq!(last.refusal, Some(refusal));
        assert!(last.allowed.is_empty());
        assert!(self.outcome.is_err());
        assert!(!self.still_held, "a failure erases");
    }

    fn cancelled(&self) {
        let last = self.last();
        assert_eq!(last.gesture, GestureState::Cancelled);
        assert_eq!(last.refusal, Some(Refusal::Cancelled));
        assert!(last.allowed.is_empty());
        assert!(last.keys.is_empty());
        assert!(self.outcome.is_ok());
        assert!(!self.still_held, "an abandonment erases");
    }

    fn done(&self) {
        let last = self.last();
        assert_eq!(last.gesture, GestureState::Done, "{:?}", last.refusal);
        assert_eq!(last.refusal, None);
        assert!(self.outcome.is_ok());
        assert!(!self.still_held, "the end erases");
    }

    fn asked_no_key(&self) -> bool {
        self.published
            .iter()
            .all(|status| !matches!(status.gesture, GestureState::AwaitingKey { .. }))
    }

    fn purpose_asked(&self, purpose: KeyPurpose) -> bool {
        self.published.iter().any(|status| {
            matches!(status.gesture, GestureState::AwaitingKey { purpose: asked, .. } if asked == purpose)
        })
    }
}

/// What the window does next, seen from one status.
enum Answer {
    Nothing,
    Press(Press),
    Presses(Vec<Press>),
    /// The window is closed: every sender is gone.
    Close,
}

fn proceed(status: &OperatorStatus) -> Answer {
    Answer::Press(Press {
        action: OperatorAction::Continue,
        revision: status.revision,
        owner: 0,
        terms: None,
    })
}

fn cancel_it(status: &OperatorStatus) -> Answer {
    Answer::Press(Press {
        action: OperatorAction::Cancel,
        revision: status.revision,
        owner: 0,
        terms: None,
    })
}

fn approve_it(status: &OperatorStatus, terms: RotationTerms) -> Answer {
    Answer::Press(Press {
        action: OperatorAction::Continue,
        revision: status.revision,
        owner: 0,
        terms: Some(terms),
    })
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

fn awaits_validation(status: &OperatorStatus, index: u8) -> bool {
    matches!(
        status.gesture,
        GestureState::AwaitingKey { index: asked, of: 2, purpose: KeyPurpose::ValidateKey } if asked == index
    )
}

fn awaits_approval(status: &OperatorStatus, index: u8) -> bool {
    matches!(
        status.gesture,
        GestureState::AwaitingKey { index: asked, of: 2, purpose: KeyPurpose::ApproveCampaign } if asked == index
    )
}

fn awaits_terms(status: &OperatorStatus) -> bool {
    status.gesture == GestureState::Idle && status.remote == RemoteState::Local
}

impl Bench {
    fn plug(&self, key: usize) {
        self.plugged.store(key, Ordering::SeqCst);
    }

    fn set_clock(&self, now: u64) {
        self.clock.store(now, Ordering::SeqCst);
    }

    fn touches(&self) -> u32 {
        self.keys
            .iter()
            .map(|key| key.touches.load(Ordering::SeqCst))
            .sum()
    }

    fn relay(&self) -> handoff::DomainHandoff {
        handoff::load(&handoff::path_beside(&self.path)).expect("relay")
    }

    fn journal(&self) -> Option<RotationJournal> {
        rotation_journal::load(&rotation_journal::path_beside(&self.path)).expect("journal")
    }

    fn record(&self) -> Option<prepared::PreparedRotation> {
        prepared::load(&prepared::path_beside(&self.path)).expect("record")
    }

    fn vault_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("vault")
    }

    /// Astra's status for a domain in step with the vault in place.
    fn nothing_in_flight(&self) -> OperatorAuthorityStatus {
        let relay = self.relay();
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

    /// Readies the campaign the door resolves for `trust_authorities`.
    fn arm(&self, expires_at: u64) {
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
        let scope = CampaignScope::TrustAuthorities;
        let campaign = AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([9; 16]).expect("id"),
            trust_domain_id: trust_domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            created_at: NOW,
            expires_at,
            scope,
            targets: vec![
                row(CertificateKind::CaPq, identity.ca_epoch, anchor),
                row(CertificateKind::CaTls, identity.ca_tls_epoch, client_tls),
            ],
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
        };
        let signer_request = AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: operation(),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: relay.astra_authority_url.expect("origin"),
            encrypted_vault_fingerprint: Fingerprint::of(b"vault"),
            required_credentials: campaign.required_credentials,
            created_at: NOW,
            expires_at: campaign.expires_at,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.service_key)
        .expect("signed request");
        *self.remote.request.lock().expect("lock") = Some(CampaignRequest {
            operation_id: operation(),
            signer_request: Box::new(signer_request),
            campaign: Box::new(campaign),
            webauthn_rp_id: RP_ID.into(),
            webauthn_origin: ORIGIN.into(),
            result_token: "jeton-de-depot".into(),
            vault_token: None,
        });
    }

    /// One gesture, on this thread, with `script` answering every status.
    fn drive(
        &self,
        gesture: RotationGesture,
        script: impl FnMut(&OperatorStatus, &Bench) -> Answer,
    ) -> Ran {
        self.drive_against(&self.remote, gesture, script)
    }

    fn drive_against(
        &self,
        remote: &dyn RotationRemote,
        gesture: RotationGesture,
        mut script: impl FnMut(&OperatorStatus, &Bench) -> Answer,
    ) -> Ran {
        let (presses, received) = channel::<Press>();
        let mut sender: Option<Sender<Press>> = Some(presses);
        let mut published = Vec::new();
        let connect = |owner: isize| self.connect(owner);
        let now = || self.clock.load(Ordering::SeqCst);
        let reach = Reach {
            remote,
            connect: &connect,
            now: &now,
        };
        let mut publish = |status: OperatorStatus| {
            match script(&status, self) {
                Answer::Nothing => {}
                Answer::Press(press) => {
                    if let Some(sender) = &sender {
                        sender.send(press).expect("sent");
                    }
                }
                Answer::Presses(presses) => {
                    if let Some(sender) = &sender {
                        for press in presses {
                            sender.send(press).expect("sent");
                        }
                    }
                }
                Answer::Close => sender = None,
            }
            published.push(status);
        };
        let mut ceremony = Ceremony::new(
            Id16::new([6; 16]).expect("id"),
            OperationLocator {
                kind: gesture.operation(),
                operation_id: None,
            },
        );
        publish(ceremony.status());
        let mut run = RotationRun::new(&mut ceremony, &received, &mut publish, &self.path, &reach);
        let outcome = run.run(gesture);
        let still_held = !matches!(run.openings.held, Held::Nothing);
        drop(run);
        Ran {
            outcome,
            published,
            still_held,
        }
    }

    fn connect(&self, _owner: isize) -> Result<Box<dyn Authenticator>, (Refusal, String)> {
        let jump = self.touch_ends_at.swap(0, Ordering::SeqCst);
        if jump != 0 {
            self.set_clock(jump);
        }
        if let Some(refusal) = self.unreachable.lock().expect("lock").take() {
            return Err((refusal, "aucune clé".into()));
        }
        let key = match self.plugged.load(Ordering::SeqCst) {
            STRANGER => self.stranger.clone(),
            index => self.keys[index].clone(),
        };
        Ok(Box::new(Plugged(key)))
    }

    /// The window that says yes to everything, with the key the status asks for.
    /// The approvals come in the reverse order, as the spec wants of Windows.
    fn all_the_way(status: &OperatorStatus, bench: &Bench) -> Answer {
        match status.gesture {
            GestureState::AwaitingKey {
                index,
                purpose: KeyPurpose::ValidateKey,
                ..
            } => {
                bench.plug(usize::from(index - 1));
                proceed(status)
            }
            GestureState::AwaitingKey {
                index,
                purpose: KeyPurpose::ApproveCampaign,
                ..
            } => {
                bench.plug(usize::from(2 - index));
                proceed(status)
            }
            GestureState::AwaitingKey { .. } => {
                bench.plug(0);
                proceed(status)
            }
            GestureState::Idle if status.remote == RemoteState::Local => {
                approve_it(status, terms())
            }
            _ => Answer::Nothing,
        }
    }

    /// A client TLS rotation carried to its end, then the clock at its `not_after`.
    fn rotated_client_tls(&self) -> prepared::PreparedRotation {
        self.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way)
            .done();
        let record = self.record().expect("the record survives the journal");
        self.set_clock(record.not_after);
        self.remote.calls.lock().expect("lock").clear();
        record
    }
}

// The tunnel.

#[test]
fn without_a_tunnel_no_gesture_reaches_a_key() {
    let bench = bench();
    let before = bench.vault_bytes();
    for gesture in [
        RotationGesture::ReplaceCaPq,
        RotationGesture::ReplaceCaTls,
        RotationGesture::FinishCaTls,
        RotationGesture::Resume,
    ] {
        let (presses, received) = channel::<Press>();
        let mut published = Vec::new();
        let outcome = run_rotation(
            Id16::new([1; 16]).expect("id"),
            gesture,
            None,
            received,
            &mut |status| published.push(status),
            &bench.path,
        );
        drop(presses);
        outcome.expect_err("no tunnel");
        let last = published.last().expect("a status");
        assert_eq!(last.gesture, GestureState::Failed, "{gesture:?}");
        assert_eq!(
            last.refusal,
            Some(Refusal::GatewayUnavailable),
            "{gesture:?}"
        );
        assert!(published
            .iter()
            .all(|status| !matches!(status.gesture, GestureState::AwaitingKey { .. })));
    }
    assert_eq!(bench.touches(), 0);
    assert_eq!(bench.vault_bytes(), before);
}

// Validating.

#[test]
fn a_repeated_key_publishes_a_retry_not_a_refusal() {
    let bench = bench();
    let mut tried = false;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_validation(status, 1) {
            bench.plug(0);
            return proceed(status);
        }
        if awaits_validation(status, 2) {
            if !tried {
                tried = true;
                bench.plug(0);
                return proceed(status);
            }
            assert_eq!(status.key_retry, Some(Refusal::KeyRepeated));
            assert!(!status.gesture.is_terminal());
            assert_eq!(status.refusal, None);
            assert!(status.accepts(OperatorAction::Continue, status.revision));
            bench.plug(1);
            return proceed(status);
        }
        if awaits_terms(status) {
            assert_eq!(status.key_retry, None, "turned down, and then answered");
            let labels: Vec<_> = status.keys.iter().map(|key| key.label.as_str()).collect();
            assert_eq!(labels, ["Clé 1", "Clé 2"]);
            return cancel_it(status);
        }
        Answer::Nothing
    });
    ran.cancelled();
    assert!(tried);
}

#[test]
fn a_key_outside_the_vault_publishes_a_retry() {
    let bench = bench();
    let mut tried = false;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_validation(status, 1) {
            if !tried {
                tried = true;
                bench.plug(STRANGER);
                return proceed(status);
            }
            assert_eq!(status.key_retry, Some(Refusal::KeyNotEnrolled));
            assert!(status.keys.is_empty());
            return cancel_it(status);
        }
        Answer::Nothing
    });
    ran.cancelled();
}

/// No key plugged in, or a dialog that could not come up: nothing is lost by it.
#[test]
fn a_key_out_of_reach_publishes_a_retry() {
    for refusal in [Refusal::KeyDeclined, Refusal::ForegroundUnavailable] {
        let bench = bench();
        let mut tried = false;
        let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
            if awaits_validation(status, 1) {
                if !tried {
                    tried = true;
                    *bench.unreachable.lock().expect("lock") = Some(refusal);
                    return proceed(status);
                }
                assert_eq!(status.key_retry, Some(refusal));
                return cancel_it(status);
            }
            Answer::Nothing
        });
        ran.cancelled();
    }
}

/// This process has no way to ask for a PIN: no other key would change that.
#[test]
fn a_transport_wanting_a_pin_ends_the_ceremony() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_validation(status, 1) {
            *bench.unreachable.lock().expect("lock") = Some(Refusal::ProtocolViolation);
            return proceed(status);
        }
        Answer::Nothing
    });
    ran.refused(Refusal::ProtocolViolation);
}

// Time.

#[test]
fn idle_validation_past_the_bound_expires() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_validation(status, 1) {
            bench.plug(0);
            return proceed(status);
        }
        if awaits_validation(status, 2) {
            bench.set_clock(NOW + VALIDATION_IDLE_SECS);
        }
        Answer::Nothing
    });
    ran.refused(Refusal::WindowExpired);
    assert!(ran.last().keys.is_empty());
    assert!(!bench.remote.called("open_campaign"));
}

#[test]
fn idle_on_the_approval_screen_past_the_bound_expires() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_terms(status) {
            bench.set_clock(bench.clock.load(Ordering::SeqCst) + VALIDATION_IDLE_SECS);
            return Answer::Nothing;
        }
        Bench::all_the_way(status, bench)
    });
    ran.refused(Refusal::WindowExpired);
    assert!(!bench.remote.called("open_campaign"));
}

/// One second short of the bound nothing happens, and the wait ends by itself,
/// with no press, once the clock has moved past it.
#[test]
fn the_bound_is_reached_while_waiting_with_no_press() {
    let bench = bench();
    std::thread::scope(|scope| {
        let (reached, wait) = channel::<()>();
        let clock = &bench.clock;
        scope.spawn(move || {
            wait.recv().expect("the wait began");
            clock.store(NOW + VALIDATION_IDLE_SECS - 1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            clock.store(NOW + VALIDATION_IDLE_SECS, Ordering::SeqCst);
        });
        let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, _| {
            if awaits_validation(status, 1) {
                reached.send(()).expect("sent");
            }
            Answer::Nothing
        });
        ran.refused(Refusal::WindowExpired);
    });
}

/// A wall clock set back must not keep an opening alive, and one that jumps must
/// not outlast a machine that slept: either one ending the bound is enough.
#[test]
fn the_bound_holds_whichever_clock_passes_it() {
    let bound = Duration::from_secs(VALIDATION_IDLE_SECS);
    let fresh = Patience {
        since: NOW,
        started: Instant::now(),
        until: None,
    };
    assert!(!fresh.is_over(NOW));
    assert!(!fresh.is_over(NOW + VALIDATION_IDLE_SECS - 1));
    assert!(fresh.is_over(NOW + VALIDATION_IDLE_SECS));
    let Some(long_ago) = Instant::now().checked_sub(bound) else {
        return;
    };
    let set_back = Patience {
        since: NOW,
        started: long_ago,
        until: None,
    };
    assert!(set_back.is_over(NOW - 1));
    let short = Patience {
        since: NOW,
        started: Instant::now(),
        until: Some(NOW + 10),
    };
    assert!(!short.is_over(NOW + 9));
    assert!(short.is_over(NOW + 10));
}

/// A campaign that dies during the wait ends it, whatever the idle bound still allows.
#[test]
fn a_campaign_dying_during_the_wait_for_a_touch_expires() {
    let bench = bench();
    bench.arm(NOW + 100);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_approval(status, 2) {
            bench.set_clock(NOW + 100);
            return Answer::Nothing;
        }
        Bench::all_the_way(status, bench)
    });
    ran.refused(Refusal::WindowExpired);
    assert!(bench.journal().is_none());
}

/// `approve` says it first: the touch took longer than the campaign had to live.
#[test]
fn a_campaign_dead_at_the_touch_expires() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_approval(status, 1) {
            bench.touch_ends_at.store(EXPIRES, Ordering::SeqCst);
        }
        Bench::all_the_way(status, bench)
    });
    ran.refused(Refusal::WindowExpired);
    assert_eq!(bench.touches(), 2, "the two validations, and no approval");
    assert!(bench.journal().is_none());
}

/// The platform only offers the key not yet used, so the one still plugged in answers
/// that it is not among them, though it was validated: the words must hold for it.
#[test]
fn the_key_that_already_approved_asks_for_another() {
    let bench = bench();
    let mut tried = false;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_approval(status, 2) {
            if !tried {
                tried = true;
                assert_eq!(status.key_retry, None);
                bench.plug(1);
                return proceed(status);
            }
            assert_eq!(status.key_retry, Some(Refusal::KeyNotValidated));
            assert!(status.accepts(OperatorAction::Continue, status.revision));
            bench.plug(0);
            return proceed(status);
        }
        Bench::all_the_way(status, bench)
    });
    ran.done();
    assert!(tried);
}

// Abandoning.

/// Each stage a key or a press is waited on. Nothing was signed, and nothing moved.
fn stages() -> [fn(&OperatorStatus) -> bool; 5] {
    [
        |status| awaits_validation(status, 1),
        |status| awaits_validation(status, 2),
        awaits_terms,
        |status| awaits_approval(status, 1),
        |status| awaits_approval(status, 2),
    ]
}

#[test]
fn cancel_at_each_stage_is_terminal_and_clears_the_keys() {
    for (position, stage) in stages().into_iter().enumerate() {
        let bench = bench();
        let before = bench.vault_bytes();
        let ran = bench.drive(RotationGesture::ReplaceCaTls, |status, bench| {
            if stage(status) {
                return cancel_it(status);
            }
            Bench::all_the_way(status, bench)
        });
        ran.cancelled();
        assert_eq!(bench.vault_bytes(), before, "stage {position}");
        assert!(bench.journal().is_none(), "stage {position}");
    }
}

/// The window that held the ceremony was closed: the same as abandoning.
#[test]
fn a_dropped_ceremony_at_each_stage_erases() {
    for (position, stage) in stages().into_iter().enumerate() {
        let bench = bench();
        let before = bench.vault_bytes();
        let ran = bench.drive(RotationGesture::ReplaceCaTls, |status, bench| {
            if stage(status) {
                return Answer::Close;
            }
            Bench::all_the_way(status, bench)
        });
        ran.cancelled();
        assert_eq!(bench.vault_bytes(), before, "stage {position}");
    }
}

// A press that arrives while the thread is busy.

/// `allowed` offers Cancel during a key call, and nothing reads it until the call
/// returns. The next screen has a revision of its own, which would lose it.
#[test]
fn a_cancel_sent_during_a_key_call_is_honoured_when_it_returns() {
    for during in 0..4u32 {
        let bench = bench();
        let before = bench.vault_bytes();
        let mut seen = 0;
        let ran = bench.drive(RotationGesture::ReplaceCaTls, |status, bench| {
            if matches!(status.gesture, GestureState::ProcessingKey { .. }) {
                seen += 1;
                if seen == during + 1 {
                    assert!(status.allowed.contains(&OperatorAction::Cancel));
                    return cancel_it(status);
                }
                return Answer::Nothing;
            }
            Bench::all_the_way(status, bench)
        });
        ran.cancelled();
        assert_eq!(bench.touches(), during + 1, "that touch, and no other");
        let before_the_end = &ran.published[ran.published.len() - 2];
        assert!(
            matches!(before_the_end.gesture, GestureState::ProcessingKey { .. }),
            "no other screen at {during}: {:?}",
            before_the_end.gesture
        );
        assert!(bench.journal().is_none());
        assert_eq!(bench.vault_bytes(), before);
    }
}

#[test]
fn a_cancel_sent_during_the_opening_is_honoured_when_it_returns() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if status.gesture == GestureState::Verifying && status.keys.len() == 2 {
            assert!(status.allowed.contains(&OperatorAction::Cancel));
            return cancel_it(status);
        }
        Bench::all_the_way(status, bench)
    });
    ran.cancelled();
    assert!(bench.remote.called("open_campaign"));
    assert!(!ran.purpose_asked(KeyPurpose::ApproveCampaign));
    assert_eq!(bench.touches(), 2);
}

/// A key turned down, or none in reach: the operator has left, and no retry is due.
#[test]
fn a_cancel_sent_during_a_key_that_fails_is_honoured() {
    for reachable in [true, false] {
        let bench = bench();
        let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
            if awaits_validation(status, 1) {
                if status.key_retry.is_some() {
                    return cancel_it(status);
                }
                bench.plug(STRANGER);
                if !reachable {
                    *bench.unreachable.lock().expect("lock") = Some(Refusal::KeyDeclined);
                }
                return proceed(status);
            }
            if matches!(status.gesture, GestureState::ProcessingKey { .. }) {
                return cancel_it(status);
            }
            Answer::Nothing
        });
        ran.cancelled();
        assert!(ran
            .published
            .iter()
            .all(|status| status.key_retry.is_none()));
    }
}

#[test]
fn a_cancel_sent_during_the_touch_of_the_finish_moves_nothing() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let (vault, relay) = (bench.vault_bytes(), bench.relay());
    let ran = bench.drive(RotationGesture::FinishCaTls, |status, bench| {
        if matches!(status.gesture, GestureState::ProcessingKey { .. }) {
            return cancel_it(status);
        }
        Bench::all_the_way(status, bench)
    });
    ran.cancelled();
    assert!(ran
        .published
        .iter()
        .all(|status| status.gesture != GestureState::Signing));
    assert_eq!(bench.vault_bytes(), vault);
    assert_eq!(bench.relay(), relay);
    assert_eq!(bench.record(), Some(record));
}

/// Only the screen just left: an older revision was answering something else.
#[test]
fn a_cancel_naming_an_older_screen_stays_ignored() {
    let bench = bench();
    let mut sent = false;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if matches!(status.gesture, GestureState::ProcessingKey { .. }) && !sent {
            sent = true;
            return Answer::Press(Press {
                action: OperatorAction::Cancel,
                revision: status.revision - 1,
                owner: 0,
                terms: None,
            });
        }
        Bench::all_the_way(status, bench)
    });
    ran.done();
}

/// Nobody is shown to be there: a dialog closing by itself, or a key turned down, buys
/// no more time, with a key already holding an opening.
#[test]
fn a_dialog_that_timed_out_or_a_refused_key_does_not_restart_the_bound() {
    #[derive(Clone, Copy)]
    enum Late {
        KeyTimedOut,
        DialogTimedOut,
        KeyRefused,
    }
    for late in [Late::KeyTimedOut, Late::DialogTimedOut, Late::KeyRefused] {
        let bench = bench();
        let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
            if awaits_validation(status, 1) {
                bench.plug(0);
                return proceed(status);
            }
            if awaits_validation(status, 2) {
                if status.key_retry.is_some() {
                    // Too late, and it must not count: the bound passed before it.
                    return cancel_it(status);
                }
                bench.plug(1);
                bench
                    .touch_ends_at
                    .store(NOW + VALIDATION_IDLE_SECS, Ordering::SeqCst);
                match late {
                    Late::KeyTimedOut => bench.keys[1].declines.store(true, Ordering::SeqCst),
                    Late::DialogTimedOut => {
                        *bench.unreachable.lock().expect("lock") = Some(Refusal::KeyDeclined);
                    }
                    Late::KeyRefused => bench.plug(STRANGER),
                }
                return proceed(status);
            }
            Answer::Nothing
        });
        ran.refused(Refusal::WindowExpired);
        assert_eq!(bench.keys[1].touches.load(Ordering::SeqCst), 0);
    }
}

/// A touch that went through is the operator being there, however long it took: the
/// next key has the whole bound, and no more than that.
#[test]
fn a_late_successful_touch_leaves_the_full_bound_for_the_next_key() {
    const TOUCH_ENDS: u64 = NOW + 290;
    for (next_press_at, kept) in [
        (TOUCH_ENDS + VALIDATION_IDLE_SECS - 1, true),
        (TOUCH_ENDS + VALIDATION_IDLE_SECS, false),
    ] {
        let bench = bench();
        let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
            if awaits_validation(status, 1) {
                bench.plug(0);
                bench.touch_ends_at.store(TOUCH_ENDS, Ordering::SeqCst);
                return proceed(status);
            }
            if awaits_validation(status, 2) {
                bench.set_clock(next_press_at);
                bench.plug(1);
                return proceed(status);
            }
            if awaits_terms(status) {
                return cancel_it(status);
            }
            Answer::Nothing
        });
        if kept {
            ran.cancelled();
            assert_eq!(bench.touches(), 2);
        } else {
            ran.refused(Refusal::WindowExpired);
            assert_eq!(bench.touches(), 1);
        }
    }
}

/// A press is the operator being there: the bound counts from the last one.
#[test]
fn a_press_restarts_the_bound() {
    let bench = bench();
    let mut pressed = false;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if !awaits_validation(status, 1) {
            return Answer::Nothing;
        }
        if !pressed {
            pressed = true;
            bench.set_clock(NOW + VALIDATION_IDLE_SECS - 1);
            *bench.unreachable.lock().expect("lock") = Some(Refusal::KeyDeclined);
            return proceed(status);
        }
        bench.set_clock(NOW + 2 * VALIDATION_IDLE_SECS - 2);
        cancel_it(status)
    });
    ran.cancelled();
}

// Opening.

fn out_of_bounds() -> RotationTerms {
    RotationTerms {
        prepare_days: 0,
        ..terms()
    }
}

/// Refused terms sent nothing and took nothing: the screen stays, and so do both keys.
#[test]
fn refused_terms_keep_the_keys_and_a_corrected_answer_needs_no_further_touch() {
    let bench = bench();
    let mut refused = 0;
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_terms(status) {
            if status.key_retry.is_none() {
                return approve_it(status, out_of_bounds());
            }
            refused += 1;
            assert_eq!(status.key_retry, Some(Refusal::TermsRefused));
            assert_eq!(status.refusal, None);
            assert!(!status.gesture.is_terminal());
            assert_eq!(status.manifest, None);
            let labels: Vec<_> = status.keys.iter().map(|key| key.label.as_str()).collect();
            assert_eq!(labels, ["Clé 1", "Clé 2"]);
            assert_eq!(bench.touches(), 2);
            assert!(!bench.remote.called("authority_status"));
            assert!(!bench.remote.called("open_campaign"));
            if refused == 1 {
                return approve_it(status, out_of_bounds());
            }
            return approve_it(status, terms());
        }
        if awaits_approval(status, 1) {
            assert_eq!(status.key_retry, None, "answered");
            assert_eq!(bench.touches(), 2, "no further validation");
        }
        Bench::all_the_way(status, bench)
    });
    ran.done();
    assert_eq!(refused, 2);
    assert_eq!(bench.touches(), 4);
}

#[test]
fn refused_terms_wait_under_the_same_bound() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_terms(status) {
            if status.key_retry.is_none() {
                return approve_it(status, out_of_bounds());
            }
            bench.set_clock(bench.clock.load(Ordering::SeqCst) + VALIDATION_IDLE_SECS);
            return Answer::Nothing;
        }
        Bench::all_the_way(status, bench)
    });
    ran.refused(Refusal::WindowExpired);
    assert!(!bench.remote.called("open_campaign"));
}

/// `allowed` decides what the window draws, and only `approve_rotation` carries terms.
#[test]
fn the_approval_screen_offers_only_cancel_and_takes_only_terms() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if awaits_terms(status) {
            assert_eq!(status.allowed, [OperatorAction::Cancel]);
            let with = |terms, revision| Press {
                action: OperatorAction::Continue,
                revision,
                owner: 0,
                terms,
            };
            return Answer::Presses(vec![
                with(None, status.revision),
                with(Some(terms()), status.revision - 1),
                Press {
                    action: OperatorAction::Cancel,
                    revision: status.revision,
                    owner: 0,
                    terms: None,
                },
            ]);
        }
        Bench::all_the_way(status, bench)
    });
    ran.cancelled();
    assert!(!bench.remote.called("open_campaign"));
}

/// A full store and a refusal keep their status, for the screen to word.
#[test]
fn a_refused_opening_names_its_status() {
    for status_code in [429, 403, 503] {
        let bench = bench();
        *bench.remote.open_refused.lock().expect("lock") = Some(status_code);
        let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
        ran.refused(Refusal::AuthorityRefused {
            status: status_code,
        });
        assert!(ran.last().keys.is_empty());
        assert!(!ran.purpose_asked(KeyPurpose::ApproveCampaign));
    }
}

#[test]
fn a_campaign_that_does_not_verify_is_refused_before_an_approval() {
    let bench = bench();
    let mut request = bench
        .remote
        .request
        .lock()
        .expect("lock")
        .take()
        .expect("armed");
    request.campaign.targets[0].epoch += 1;
    *bench.remote.request.lock().expect("lock") = Some(request);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    ran.refused(Refusal::HandoffMismatch);
    assert!(!ran.purpose_asked(KeyPurpose::ApproveCampaign));
}

// What stands in the way, before any key.

#[test]
fn a_rotation_in_flight_is_refused_before_any_key() {
    for outstanding in [
        rotation_journal::path_beside(Path::new("x")),
        prepared::path_beside(Path::new("x")),
        rotation_journal::legacy_ca_pq_path_beside(Path::new("x")),
    ] {
        let bench = bench();
        let file = bench
            .path
            .parent()
            .expect("folder")
            .join(outstanding.file_name().expect("name"));
        std::fs::write(&file, b"{}").expect("written");
        let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
        ran.refused(Refusal::RotationInFlight);
        assert!(ran.asked_no_key(), "{outstanding:?}");
        assert_eq!(bench.touches(), 0);
    }
}

#[test]
fn a_missing_vault_is_refused_before_any_key() {
    let bench = bench();
    std::fs::remove_file(&bench.path).expect("removed");
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    ran.refused(Refusal::VaultUnavailable);
    assert!(ran.asked_no_key());
}

#[test]
fn a_relay_that_cannot_back_the_rotation_is_refused_before_any_key() {
    let bench = bench();
    let mut relay = bench.relay();
    relay.ca_tls_certificate = None;
    handoff::save(&handoff::path_beside(&bench.path), &relay).expect("relay");
    let ran = bench.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way);
    ran.refused(Refusal::HandoffMismatch);
    assert!(ran.asked_no_key());
}

// All the way.

#[test]
fn a_rotation_runs_from_its_validations_to_its_end() {
    for (gesture, kind, affected, operation_kind) in [
        (
            RotationGesture::ReplaceCaPq,
            "install_ca_transition",
            AffectedCa::CaPq,
            OperationKind::RotateAnchor,
        ),
        (
            RotationGesture::ReplaceCaTls,
            "install_client_tls_ca_transition",
            AffectedCa::CaTls,
            OperationKind::RotateClientTlsCa,
        ),
    ] {
        let bench = bench();
        let ran = bench.drive(gesture, Bench::all_the_way);
        ran.done();
        assert_eq!(bench.touches(), 4, "two validations, two approvals");
        assert!(bench.journal().is_none());
        assert!(bench.remote.called("submit_campaign"));
        assert!(bench.remote.called(kind));
        assert!(bench.remote.called("send_vault_copy"));

        let at = |test: &dyn Fn(&OperatorStatus) -> bool| {
            ran.published
                .iter()
                .position(test)
                .expect("the step is published")
        };
        let order = [
            at(&|status| awaits_validation(status, 1)),
            at(&|status| awaits_validation(status, 2)),
            at(&awaits_terms),
            at(&|status| awaits_approval(status, 1)),
            at(&|status| awaits_approval(status, 2)),
            at(&|status| status.gesture == GestureState::Signing),
            at(&|status| status.remote == RemoteState::Prepared),
            at(&|status| status.remote == RemoteState::Deposited),
        ];
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");

        // Nothing exists at the authority before the approval, and the touch is on
        // the campaign shown.
        let terms_screen = &ran.published[order[2]];
        assert_eq!(terms_screen.manifest, None);
        assert_eq!(terms_screen.remote, RemoteState::Local);
        let touch = &ran.published[order[3]];
        assert_eq!(touch.remote, RemoteState::AwaitingOperator);
        assert_eq!(touch.operation, operation_kind);
        assert_eq!(touch.operation_id, Some(operation()));
        let Some(AstraManifest::CaRotation(shown)) = &touch.manifest else {
            panic!("a rotation manifest at the touch");
        };
        assert_eq!(shown.affected_ca, affected);
        assert_eq!(shown.next_anchor_fingerprint, None);
        assert!(shown.campaign.is_some());

        // Named as soon as it exists, and nothing can be cancelled by then.
        let signed = &ran.published[order[6]];
        let Some(AstraManifest::CaRotation(named)) = &signed.manifest else {
            panic!("a rotation manifest once signed");
        };
        assert!(named.next_anchor_fingerprint.is_some());
        assert!(signed.allowed.is_empty(), "{:?}", signed.allowed);

        let last = ran.last();
        assert_eq!(last.remote, RemoteState::Deposited);
        let labels: Vec<_> = last.keys.iter().map(|key| key.label.as_str()).collect();
        assert_eq!(labels, ["Clé 1", "Clé 2"]);
    }
}

/// The incoming anchor is the one the journal names, the moment it is signed: the
/// deposit is refused here so that the journal stays to compare.
#[test]
fn the_incoming_anchor_is_shown_from_the_journal() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    let journal = bench.journal().expect("kept");
    let signed = ran
        .published
        .iter()
        .find(|status| status.remote == RemoteState::Prepared)
        .expect("published");
    let Some(AstraManifest::CaRotation(manifest)) = &signed.manifest else {
        panic!("a rotation manifest");
    };
    assert_eq!(
        manifest.next_anchor_fingerprint,
        Some(journal.next_anchor_fingerprint)
    );
}

// What stops a rotation, and what the journal keeps.

#[test]
fn a_dead_campaign_nothing_heard_of_expires_the_rotation() {
    let bench = bench();
    let before = bench.vault_bytes();
    bench.remote.deposits.lock().expect("lock").push_back(409);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    ran.refused(Refusal::RotationExpired);
    assert_eq!(ran.last().remote, RemoteState::Prepared);
    assert!(bench.journal().is_none());
    assert_eq!(bench.vault_bytes(), before);
}

#[test]
fn another_rotation_at_the_authority_conflicts_and_keeps_the_journal() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(409);
    let other = OperatorAuthorityStatus {
        next_ca_fingerprint: Some(Fingerprint::of(b"une autre")),
        ..bench.nothing_in_flight()
    };
    // Read by `open` first, which must find the domain quiet.
    let ran = bench.drive(RotationGesture::ReplaceCaPq, |status, bench| {
        if status.gesture == GestureState::Signing {
            *bench.remote.authority.lock().expect("lock") = Some(other.clone());
        }
        Bench::all_the_way(status, bench)
    });
    ran.refused(Refusal::DomainConflict);
    assert_eq!(bench.journal().expect("kept").stage, JournalStage::Signed);
}

/// An up-to-date gateway with no client TLS CA reads the same as an old one. The
/// refusal is its own, and the rotation is kept.
#[test]
fn a_gateway_naming_no_anchor_keeps_the_rotation() {
    let bench = bench();
    *bench.remote.gateway_anchor.lock().expect("lock") = None;
    let ran = bench.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way);
    ran.refused(Refusal::GatewayNamesNoAnchor);
    assert_eq!(ran.last().remote, RemoteState::Deposited);
    assert_eq!(bench.journal().expect("kept").stage, JournalStage::Applied);
}

#[test]
fn a_transition_past_its_deadline_is_a_dead_end() {
    let bench = bench();
    *bench.remote.install_refused.lock().expect("lock") = Some(503);
    bench
        .drive(RotationGesture::ReplaceCaPq, Bench::all_the_way)
        .refused(Refusal::GatewayRefused { status: 503 });
    let journal = bench.journal().expect("kept");
    assert_eq!(journal.stage, JournalStage::Applied);
    *bench.remote.install_refused.lock().expect("lock") = None;
    bench.set_clock(journal.activation_at);

    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);

    ran.refused(Refusal::InstallDeadlinePassed);
    assert!(ran.asked_no_key());
    assert!(bench.journal().is_some());
}

/// Not a failure: the rotation is on the gateway, and the same copy passes later.
#[test]
fn a_copy_held_back_is_a_rotation_done_with_its_journal_kept() {
    let bench = bench();
    bench
        .remote
        .copies
        .lock()
        .expect("lock")
        .push_back(VaultCopySent::HeldBack);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    ran.done();
    assert_eq!(ran.last().remote, RemoteState::Deposited);
    assert_eq!(
        bench.journal().expect("kept").stage,
        JournalStage::Installed
    );

    let resumed = bench.drive(RotationGesture::Resume, Bench::all_the_way);
    resumed.done();
    assert!(resumed.asked_no_key());
    assert!(bench.journal().is_none());
}

/// A full store: its status, and the deposit stays to replay.
#[test]
fn a_full_store_keeps_the_rotation_to_resume() {
    let bench = bench();
    let before = bench.vault_bytes();
    bench.remote.deposits.lock().expect("lock").push_back(429);
    let ran = bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    ran.refused(Refusal::AuthorityRefused { status: 429 });
    assert_eq!(ran.last().remote, RemoteState::Prepared);
    assert_eq!(bench.journal().expect("kept").stage, JournalStage::Signed);
    assert_eq!(bench.vault_bytes(), before);
}

/// Nothing answered: said as such, and not as a word from the authority.
#[test]
fn a_gateway_out_of_reach_keeps_the_rotation_to_resume() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    let tunnel = Tunnel::new("http://127.0.0.1:1").expect("tunnel");

    let ran = bench.drive_against(&tunnel, RotationGesture::Resume, Bench::all_the_way);

    ran.refused(Refusal::GatewayUnavailable);
    assert!(ran.asked_no_key());
    assert!(bench.journal().is_some());
}

// Resuming.

#[test]
fn no_journal_is_nothing_to_resume() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);
    ran.done();
    assert!(ran.asked_no_key());
    assert!(bench.remote.calls.lock().expect("lock").is_empty());
}

/// It says which CA, once the journal has told it, and asks for no key.
#[test]
fn resuming_names_what_it_found_and_asks_no_key() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way);
    let touches = bench.touches();
    assert_eq!(bench.journal().expect("kept").stage, JournalStage::Signed);

    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);

    ran.done();
    assert!(ran.asked_no_key());
    assert_eq!(bench.touches(), touches);
    assert_eq!(ran.last().operation, OperationKind::RotateClientTlsCa);
    assert!(bench.journal().is_none());
    assert!(ran.published.iter().all(|status| {
        status.gesture.is_terminal() || !status.allowed.contains(&OperatorAction::Continue)
    }));
}

#[test]
fn a_journal_it_cannot_read_stops_the_resumption() {
    let bench = bench();
    std::fs::write(rotation_journal::path_beside(&bench.path), b"illisible").expect("written");
    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);
    ran.refused(Refusal::VaultUnavailable);
    assert!(bench.remote.calls.lock().expect("lock").is_empty());
}

/// What `rotate-ca-pq` leaves, once adopted: nothing shows a deposit ever went out.
fn adopted_with_no_deposit(bench: &Bench) -> RotationJournal {
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    let journal = RotationJournal {
        stage: JournalStage::Accepted,
        deposit: None,
        ..bench.journal().expect("kept")
    };
    rotation_journal::save(&rotation_journal::path_beside(&bench.path), &journal).expect("journal");
    journal
}

#[test]
fn an_adoption_nothing_confirms_never_reads_as_deposited() {
    let bench = bench();
    adopted_with_no_deposit(&bench);

    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);

    ran.refused(Refusal::DomainConflict);
    assert!(ran
        .published
        .iter()
        .all(|status| status.remote != RemoteState::Deposited));
}

#[test]
fn an_adoption_reads_as_deposited_once_the_authority_confirms_it() {
    let bench = bench();
    let journal = adopted_with_no_deposit(&bench);
    *bench.remote.authority.lock().expect("lock") = Some(OperatorAuthorityStatus {
        next_ca_fingerprint: Some(journal.next_anchor_fingerprint),
        ..bench.nothing_in_flight()
    });

    let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);

    ran.done();
    assert_eq!(ran.published[1].remote, RemoteState::Prepared);
    assert_eq!(ran.last().remote, RemoteState::Deposited);
}

/// A record the CLI left: vault rotated, token kept, no journal, not adopted. Neither
/// gesture of the screen takes it until the resumption has.
#[test]
fn a_record_astra_signer_left_is_resumed_then_finished() {
    for submitted in [false, true] {
        let bench = bench();
        bench
            .drive(RotationGesture::ReplaceCaTls, Bench::all_the_way)
            .done();
        let carried = bench.record().expect("the record");
        let record_path = prepared::path_beside(&bench.path);
        prepared::save(
            &record_path,
            &prepared::PreparedRotation {
                result_token: Some("jeton-de-depot".into()),
                transition_path: "/tmp/transition-ca-tls.json".into(),
                submitted,
                adopted: false,
                ..carried.clone()
            },
        )
        .expect("record");
        *bench.remote.gateway_anchor.lock().expect("lock") =
            Some(Fingerprint::of(b"ancre sortante"));
        let touches = bench.touches();

        bench.set_clock(carried.not_after);
        let finish = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);
        finish.refused(Refusal::RotationInFlight);
        assert!(finish.asked_no_key());
        let replace = bench.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way);
        replace.refused(Refusal::RotationInFlight);
        assert!(replace.asked_no_key());

        bench.set_clock(NOW);
        let resume = bench.drive(RotationGesture::Resume, Bench::all_the_way);
        resume.done();
        assert!(resume.asked_no_key());
        assert_eq!(resume.last().operation, OperationKind::RotateClientTlsCa);
        assert!(bench.journal().is_none());
        let adopted = bench.record().expect("still there until the end");
        assert!(adopted.adopted && adopted.submitted);
        assert_eq!(bench.touches(), touches);

        bench.set_clock(carried.not_after);
        let finish = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);
        finish.done();
        assert_eq!(bench.touches(), touches + 1);
        assert_eq!(bench.record(), None);
        let relay = bench.relay();
        assert_eq!(relay.ca_tls_epoch, Some(carried.next_ca_tls_epoch));
        assert_eq!(
            relay.ca_tls_certificate.as_deref(),
            Some(carried.next_ca_tls_certificate.as_str())
        );
    }
}

// « Terminer ».

#[test]
fn finishing_takes_one_key_and_moves_the_relay() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let touches = bench.touches();

    let ran = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);

    ran.done();
    assert_eq!(bench.touches(), touches + 1);
    assert!(ran.purpose_asked(KeyPurpose::Promotion));
    assert_eq!(bench.record(), None);
    let relay = bench.relay();
    assert_eq!(relay.ca_tls_epoch, Some(record.next_ca_tls_epoch));
    assert_eq!(
        relay.ca_tls_certificate.as_deref(),
        Some(record.next_ca_tls_certificate.as_str())
    );
    assert!(bench.remote.called("send_vault_copy"));
    assert_eq!(ran.last().operation, OperationKind::RotateClientTlsCa);
    let asked = ran
        .published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("asked");
    let Some(AstraManifest::CaRotation(manifest)) = &asked.manifest else {
        panic!("what the touch does");
    };
    assert!(manifest.next_anchor_fingerprint.is_some());
}

/// The vault was saved, then a stop before the relay. `astra-signer` gives up here.
#[test]
fn finishing_after_a_stop_before_the_relay_finishes_the_relay() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let mut vault = store::load(&bench.path).expect("vault");
    let opening =
        gestures::open_with_authorized_key(bench.keys[0].as_ref(), &vault, "").expect("opened");
    assert!(matches!(
        signing::advance_ca_tls(&mut vault, &opening, record.not_after).expect("advanced"),
        CaTlsAdvance::Rotated { .. }
    ));
    store::save(&bench.path, &vault).expect("saved");
    let before = bench.vault_bytes();

    let ran = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);

    ran.done();
    assert_eq!(bench.vault_bytes(), before);
    assert_eq!(bench.record(), None);
    assert_eq!(bench.relay().ca_tls_epoch, Some(record.next_ca_tls_epoch));
}

#[test]
fn a_journal_in_flight_refuses_the_finish_before_any_key() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    std::fs::write(rotation_journal::path_beside(&bench.path), b"{}").expect("journal");
    let before = bench.vault_bytes();
    let touches = bench.touches();

    let ran = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);

    ran.refused(Refusal::RotationInFlight);
    assert!(ran.asked_no_key());
    assert_eq!(bench.touches(), touches);
    assert_eq!(bench.vault_bytes(), before);
    assert_eq!(bench.record(), Some(record));
}

#[test]
fn finishing_too_early_or_with_nothing_asks_no_key() {
    let bench = bench();
    let ran = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);
    ran.refused(Refusal::NothingToFinish);
    assert!(ran.asked_no_key());

    let record = bench.rotated_client_tls();
    bench.set_clock(record.not_after - 1);
    let ran = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);
    ran.refused(Refusal::RotationInFlight);
    assert!(ran.asked_no_key());
    assert_eq!(bench.record(), Some(record));
}

#[test]
fn a_key_outside_the_vault_is_a_retry_at_the_finish() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let mut tried = false;
    let ran = bench.drive(RotationGesture::FinishCaTls, |status, bench| {
        if matches!(status.gesture, GestureState::AwaitingKey { .. }) {
            if !tried {
                tried = true;
                bench.plug(STRANGER);
                return proceed(status);
            }
            assert_eq!(status.key_retry, Some(Refusal::KeyNotEnrolled));
            bench.plug(0);
            return proceed(status);
        }
        Answer::Nothing
    });
    ran.done();
    assert_eq!(bench.relay().ca_tls_epoch, Some(record.next_ca_tls_epoch));
}

#[test]
fn the_wait_at_the_finish_has_the_same_bound() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let ran = bench.drive(RotationGesture::FinishCaTls, |status, bench| {
        if matches!(status.gesture, GestureState::AwaitingKey { .. }) {
            bench.set_clock(record.not_after + VALIDATION_IDLE_SECS);
        }
        Answer::Nothing
    });
    ran.refused(Refusal::WindowExpired);
    assert_eq!(bench.record(), Some(record));
}

// What crosses to the window.

/// Every JSON key, at any depth, of what the window receives.
fn keys_of(value: &serde_json::Value, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                keys.push(key.clone());
                keys_of(inner, keys);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| keys_of(item, keys)),
        _ => {}
    }
}

#[test]
fn the_webview_status_carries_labels_only() {
    use base64::Engine as _;
    let bench = bench();
    let ran = bench.drive(RotationGesture::ReplaceCaTls, Bench::all_the_way);
    ran.done();
    let finished = bench.record().expect("the record survives the journal");
    bench.set_clock(finished.not_after);
    let finish = bench.drive(RotationGesture::FinishCaTls, Bench::all_the_way);
    finish.done();
    assert_eq!(finished.result_token, None);

    let released: Vec<Vec<u8>> = bench
        .keys
        .iter()
        .flat_map(|key| key.released.lock().expect("lock").clone())
        .collect();
    assert!(released.len() >= 3, "the openings the test looks for");
    let credentials: Vec<Vec<u8>> = bench.keys.iter().map(|key| key.credential_id()).collect();

    for status in ran.published.iter().chain(&finish.published) {
        let value = serde_json::to_value(status).expect("status");
        let mut keys = Vec::new();
        keys_of(&value, &mut keys);
        for key in &keys {
            let lowered = key.to_lowercase();
            for forbidden in ["secret", "pin", "token", "wrapped", "sealed", "opening"] {
                assert!(!lowered.contains(forbidden), "{key}");
            }
        }
        let text = value.to_string();
        assert!(!text.contains("jeton-de-depot"), "the deposit's token");
        for bytes in released.iter().chain(&credentials) {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let standard = base64::engine::general_purpose::STANDARD.encode(bytes);
            let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            let raw = serde_json::to_string(bytes).expect("array");
            for form in [hex, standard, url, raw] {
                assert!(!text.contains(&form), "an opening's bytes as {form}");
            }
        }
    }
}

/// `Opened` holds what unwraps the vault. These types are what keep it in the thread.
#[test]
fn what_the_touches_released_cannot_leave_this_thread() {
    macro_rules! lacks {
        ($type:ty, $($bound:tt)+) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $($bound)+> Ambiguous<u8> for T {}
            let _ = <$type as Ambiguous<_>>::check;
        }};
    }
    lacks!(Openings, Send);
    lacks!(Openings, Sync);
    lacks!(Held, Send);
    lacks!(Held, Sync);
    lacks!(ValidatedKeys, Send);
    lacks!(ValidatedKeys, Sync);
    lacks!(OpenedRotation, Send);
    lacks!(OpenedRotation, Sync);
    lacks!(Openings, std::fmt::Debug);
    lacks!(Openings, serde::Serialize);
    lacks!(ValidatedKeys, std::fmt::Debug);
    lacks!(ValidatedKeys, serde::Serialize);
    lacks!(OpenedRotation, std::fmt::Debug);
    lacks!(OpenedRotation, serde::Serialize);
}

// The surface.

/// Runs a gesture behind the same surface as the window, on the ceremony's thread.
async fn open_session(
    ceremony: &OperatorCeremony,
    bench: &Arc<Bench>,
    gesture: RotationGesture,
) -> OperatorStatus {
    let running = bench.clone();
    ceremony
        .open(
            gesture.operation(),
            move |session_id, presses, publish, _artifacts| {
                let connect = |owner: isize| running.connect(owner);
                let now = || running.clock.load(Ordering::SeqCst);
                let reach = Reach {
                    remote: &running.remote,
                    connect: &connect,
                    now: &now,
                };
                let mut state = Ceremony::new(
                    session_id,
                    OperationLocator {
                        kind: gesture.operation(),
                        operation_id: None,
                    },
                );
                publish(state.status());
                RotationRun::new(&mut state, &presses, publish, &running.path, &reach).run(gesture)
            },
        )
        .await
        .expect("opened")
}

/// Waits for the thread to reach a status, as the window polls for it.
async fn until(
    ceremony: &OperatorCeremony,
    reached: impl Fn(&OperatorStatus) -> bool,
) -> OperatorStatus {
    for _ in 0..3_000 {
        if let Some(status) = ceremony.status().await {
            if reached(&status) {
                return status;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never reached: {:?}", ceremony.status().await);
}

/// Up to the approval screen, with both keys validated.
async fn on_the_approval_screen(ceremony: &OperatorCeremony, bench: &Bench) -> OperatorStatus {
    for index in 1..=2u8 {
        let status = until(ceremony, |status| awaits_validation(status, index)).await;
        bench.plug(usize::from(index - 1));
        ceremony
            .advance(OperatorAction::Continue, status.revision, 0)
            .await
            .expect("pressed");
    }
    until(ceremony, awaits_terms).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_revision_is_refused() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;

    // Not the screen that takes terms.
    let validating = until(&ceremony, |status| awaits_validation(status, 1)).await;
    ceremony
        .approve_rotation(terms(), validating.revision)
        .await
        .expect_err("no terms are awaited");

    let screen = on_the_approval_screen(&ceremony, &bench).await;
    for revision in [screen.revision - 1, screen.revision + 1] {
        ceremony
            .approve_rotation(terms(), revision)
            .await
            .expect_err("another screen");
    }
    // A press with no terms has nothing to open a campaign with.
    ceremony
        .advance(OperatorAction::Continue, screen.revision, 0)
        .await
        .expect_err("no terms");
    assert!(!bench.remote.called("open_campaign"));
    let unchanged = ceremony.status().await.expect("status");
    assert_eq!(unchanged.revision, screen.revision);

    ceremony
        .approve_rotation(terms(), screen.revision)
        .await
        .expect("this screen");
    until(&ceremony, |status| awaits_approval(status, 1)).await;
    assert!(bench.remote.called("open_campaign"));

    let touch = ceremony.status().await.expect("status");
    ceremony
        .advance(OperatorAction::Cancel, touch.revision, 0)
        .await
        .expect("abandoned");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    assert_eq!(ended.refusal, Some(Refusal::Cancelled));
    ceremony.dismiss().await.expect("dismissed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrected_approval_opens_with_no_further_touch() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;
    let screen = on_the_approval_screen(&ceremony, &bench).await;

    let refused = ceremony
        .approve_rotation(out_of_bounds(), screen.revision)
        .await
        .expect("answered");
    assert_eq!(refused.key_retry, Some(Refusal::TermsRefused));
    assert!(awaits_terms(&refused));
    assert_eq!(refused.keys.len(), 2);
    assert!(refused.revision > screen.revision);
    assert!(!bench.remote.called("open_campaign"));

    ceremony
        .approve_rotation(terms(), screen.revision)
        .await
        .expect_err("that screen has been left");
    ceremony
        .approve_rotation(terms(), refused.revision)
        .await
        .expect("corrected");
    let touch = until(&ceremony, |status| awaits_approval(status, 1)).await;
    assert!(bench.remote.called("open_campaign"));
    assert_eq!(bench.touches(), 2);
    ceremony
        .advance(OperatorAction::Cancel, touch.revision, 0)
        .await
        .expect("abandoned");
    until(&ceremony, |status| status.gesture.is_terminal()).await;
}

/// The window never reaches an opening: every gesture of every key came from the
/// ceremony's own thread, and the window only ever had statuses.
#[tokio::test(flavor = "multi_thread")]
async fn the_keys_are_only_touched_on_the_ceremony_thread() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;

    let screen = on_the_approval_screen(&ceremony, &bench).await;
    ceremony
        .approve_rotation(terms(), screen.revision)
        .await
        .expect("approved");
    for (index, key) in [(1u8, 1usize), (2, 0)] {
        let status = until(&ceremony, |status| awaits_approval(status, index)).await;
        bench.plug(key);
        ceremony
            .advance(OperatorAction::Continue, status.revision, 0)
            .await
            .expect("pressed");
    }
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    assert_eq!(ended.gesture, GestureState::Done, "{:?}", ended.refusal);

    assert_eq!(bench.touches(), 4);
    for key in &bench.keys {
        for thread in key.threads.lock().expect("lock").iter() {
            assert_eq!(thread, CEREMONY_THREAD);
        }
    }
}

/// With no tunnel the surface says so, and one ceremony at a time holds as usual.
#[tokio::test(flavor = "multi_thread")]
async fn begin_rotation_without_a_tunnel_reports_the_refusal() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    ceremony
        .begin_rotation(RotationGesture::ReplaceCaTls, None, bench.path.clone())
        .await
        .expect("a session");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    assert_eq!(ended.refusal, Some(Refusal::GatewayUnavailable));
    assert_eq!(bench.touches(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_ceremony_waits_for_the_rotation() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;
    let waiting = until(&ceremony, |status| awaits_validation(status, 1)).await;
    ceremony
        .begin_rotation(RotationGesture::Resume, None, bench.path.clone())
        .await
        .expect_err("one at a time");
    ceremony
        .advance(OperatorAction::Cancel, waiting.revision, 0)
        .await
        .expect("abandoned");
    until(&ceremony, |status| status.gesture.is_terminal()).await;
}

#[test]
fn the_gestures_name_no_value() {
    for (text, gesture, operation_kind) in [
        (
            r#"{"gesture":"replace_ca_pq"}"#,
            RotationGesture::ReplaceCaPq,
            OperationKind::RotateAnchor,
        ),
        (
            r#"{"gesture":"replace_ca_tls"}"#,
            RotationGesture::ReplaceCaTls,
            OperationKind::RotateClientTlsCa,
        ),
        (
            r#"{"gesture":"finish_ca_tls"}"#,
            RotationGesture::FinishCaTls,
            OperationKind::RotateClientTlsCa,
        ),
        (
            r#"{"gesture":"resume"}"#,
            RotationGesture::Resume,
            OperationKind::RotateAnchor,
        ),
    ] {
        let read: RotationGesture = serde_json::from_str(text).expect("a gesture");
        assert_eq!(read, gesture);
        assert_eq!(read.operation(), operation_kind);
    }
    assert!(serde_json::from_str::<RotationGesture>(r#"{"gesture":"rotate"}"#).is_err());
}

/// The `run` entry for a locator has never been the way in.
#[test]
fn a_locator_does_not_open_a_rotation() {
    for kind in [
        OperationKind::RotateAnchor,
        OperationKind::RotateClientTlsCa,
    ] {
        let (presses, received) = channel::<Press>();
        drop(presses);
        let mut published = Vec::new();
        let outcome = crate::operator::ceremony::run(
            Id16::new([1; 16]).expect("id"),
            OperationLocator {
                kind,
                operation_id: None,
            },
            received,
            &mut |status| published.push(status),
            Path::new("absent"),
        );
        let error = outcome.expect_err("refused");
        assert!(error.contains("s'ouvre par son geste"), "{error}");
    }
}

// The resumption at a tunnel-up (spec §5.4, §5.5).

/// Nothing out of reach: the address no tunnel answers at.
const NO_ONE_ANSWERS: &str = "http://127.0.0.1:1";

/// The tunnel of the domain's own gateway, which no one answers at.
fn towards_gateway(bench: &Bench) -> crate::operator::GatewayTarget {
    let relay = bench.relay();
    crate::operator::GatewayTarget {
        address: NO_ONE_ANSWERS.into(),
        peer_key: relay.gateway_wg_public_key.expect("a gateway"),
    }
}

/// A tunnel to a gateway that is not the domain's.
fn towards_another_gateway() -> crate::operator::GatewayTarget {
    crate::operator::GatewayTarget {
        address: NO_ONE_ANSWERS.into(),
        peer_key: WireGuardKey::from_bytes([0x77; 32]).to_base64(),
    }
}

/// A journal any look would find: only its presence counts to the trigger.
fn leave_a_journal(bench: &Bench) {
    std::fs::write(rotation_journal::path_beside(&bench.path), b"{}").expect("journal");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_journal_means_no_ceremony() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    let started = ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked");
    assert!(!started.is_started());
    assert!(ceremony.status().await.is_none());
}

/// A rotation finished leaves its record, adopted, until the promotion: it must not
/// run a resumption at every tunnel-up.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_rotation_means_no_ceremony() {
    let bench = bench();
    bench
        .drive(RotationGesture::ReplaceCaTls, Bench::all_the_way)
        .done();
    assert!(bench.record().expect("record").adopted);
    assert!(bench.journal().is_none());
    let ceremony = OperatorCeremony::default();
    let started = ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked");
    assert!(!started.is_started());
    assert!(ceremony.status().await.is_none());
}

/// An astra-signer record has no keyless way forward but this.
#[tokio::test(flavor = "multi_thread")]
async fn an_unadopted_record_starts_a_resumption() {
    let bench = bench();
    bench
        .drive(RotationGesture::ReplaceCaTls, Bench::all_the_way)
        .done();
    let record = bench.record().expect("record");
    prepared::save(
        &prepared::path_beside(&bench.path),
        &prepared::PreparedRotation {
            result_token: Some("jeton-de-depot".into()),
            transition_path: "/tmp/transition-ca-tls.json".into(),
            submitted: false,
            adopted: false,
            ..record
        },
    )
    .expect("record");
    let ceremony = OperatorCeremony::default();
    let started = ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked");
    assert!(started.is_started());
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    assert_eq!(ended.refusal, Some(Refusal::GatewayUnavailable));
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_waits_for_a_running_ceremony() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;
    let waiting = until(&ceremony, |status| awaits_validation(status, 1)).await;
    leave_a_journal(&bench);

    let started = ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked");

    assert!(!started.is_started());
    assert_eq!(ceremony.status().await.expect("status"), waiting);
    ceremony
        .advance(OperatorAction::Cancel, waiting.revision, 0)
        .await
        .expect("abandoned");
    until(&ceremony, |status| status.gesture.is_terminal()).await;
}

/// The operator's finished screen is theirs: the resumption does not wipe it, nor its
/// files. Once dismissed, it goes ahead.
#[tokio::test(flavor = "multi_thread")]
async fn resume_leaves_an_operators_finished_screen_alone() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    ceremony
        .begin_rotation(RotationGesture::ReplaceCaTls, None, bench.path.clone())
        .await
        .expect("a session");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    leave_a_journal(&bench);

    let started = ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked");
    assert!(!started.is_started());
    assert_eq!(ceremony.status().await.expect("status"), ended);

    ceremony.dismiss().await.expect("dismissed");
    assert!(ceremony
        .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
        .await
        .expect("looked")
        .is_started());
}

/// A stopped rotation is retried at each tunnel-up (here against a tunnel nobody
/// answers): its own finished session gives way, with the journal and the vault as
/// they were and no key asked.
#[tokio::test(flavor = "multi_thread")]
async fn each_tunnel_up_retries_a_stopped_rotation_with_no_key() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    let (journal, vault, touches) = (
        bench.journal().expect("kept"),
        bench.vault_bytes(),
        bench.touches(),
    );
    let ceremony = OperatorCeremony::default();

    for _ in 0..2 {
        let outcome = ceremony
            .resume_on_tunnel_up(towards_gateway(&bench), bench.path.clone())
            .await
            .expect("looked");
        assert!(outcome.is_started());
        let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
        assert_eq!(ended.refusal, Some(Refusal::GatewayUnavailable));
        assert!(ended.keys.is_empty());
        assert_eq!(bench.journal().as_ref(), Some(&journal));
        assert_eq!(bench.vault_bytes(), vault);
        assert_eq!(bench.touches(), touches);
    }
}

/// The engine's events, as the glue reads them: only a state change into `Up`, once.
#[test]
fn only_a_state_change_into_up_triggers() {
    use aether::TunnelState;
    use orion_core::ClientEvent;

    let watch = crate::operator::TunnelWatch::default();
    let state = |state| ClientEvent::StateChanged { state };
    assert!(!watch.entered_up_by(&state(TunnelState::Down)));
    assert!(watch.entered_up_by(&state(TunnelState::Up)));
    assert!(!watch.entered_up_by(&state(TunnelState::Up)));
    assert!(!watch.entered_up_by(&state(TunnelState::Down)));
    assert!(watch.entered_up_by(&state(TunnelState::Up)));
}

/// The tunnel's up edge, once: a repeated report of the same state starts nothing.
#[test]
fn only_the_edge_into_up_triggers() {
    let watch = crate::operator::TunnelWatch::default();
    assert!(!watch.entered_up(false));
    assert!(watch.entered_up(true));
    assert!(!watch.entered_up(true));
    assert!(!watch.entered_up(false));
    assert!(watch.entered_up(true));
}

/// A copy held back is no failure: the journal stays, and the next look or the button
/// sends it again.
#[test]
fn a_copy_held_back_by_a_resumption_keeps_the_journal_and_is_not_a_failure() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    bench
        .remote
        .copies
        .lock()
        .expect("lock")
        .push_back(VaultCopySent::HeldBack);

    let held = bench.drive(RotationGesture::Resume, Bench::all_the_way);
    held.done();
    assert!(held.asked_no_key());
    assert_eq!(held.last().refusal, None);
    assert_eq!(
        bench.journal().expect("kept").stage,
        JournalStage::Installed
    );

    let next = bench.drive(RotationGesture::Resume, Bench::all_the_way);
    next.done();
    assert!(bench.journal().is_none());
}

// Another domain's gateway, and the edges that meet a busy screen.

/// Orion holds several profiles and one vault: a tunnel to a gateway the relay does
/// not name reads another authority, which would call a live journal « nothing in
/// flight » and have it discarded. Nothing starts, and no folder or screen appears.
#[tokio::test(flavor = "multi_thread")]
async fn a_resume_towards_another_domains_gateway_starts_nothing() {
    let bench = bench();
    leave_a_journal(&bench);
    let before = std::fs::read(rotation_journal::path_beside(&bench.path)).expect("journal");
    let ceremony = OperatorCeremony::default();

    let outcome = ceremony
        .resume_on_tunnel_up(towards_another_gateway(), bench.path.clone())
        .await
        .expect("looked");

    assert!(!outcome.is_started());
    assert!(ceremony.status().await.is_none());
    assert_eq!(
        std::fs::read(rotation_journal::path_beside(&bench.path)).expect("journal"),
        before
    );
}

/// The gesture of the button says so, before any call, and moves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_resume_gesture_is_refused_towards_another_domains_gateway() {
    let bench = bench();
    bench.remote.deposits.lock().expect("lock").push_back(503);
    bench.drive(RotationGesture::ReplaceCaPq, Bench::all_the_way);
    let (journal, vault) = (bench.journal().expect("kept"), bench.vault_bytes());
    let ceremony = OperatorCeremony::default();

    ceremony
        .begin_rotation(
            RotationGesture::Resume,
            Some(towards_another_gateway()),
            bench.path.clone(),
        )
        .await
        .expect("a session");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;

    assert_eq!(ended.refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(bench.journal().as_ref(), Some(&journal));
    assert_eq!(bench.vault_bytes(), vault);
}

/// The look the glue makes, on the bench's vault and the domain's own gateway.
async fn look(ceremony: &OperatorCeremony, bench: &Bench) {
    crate::operator::resume_with(ceremony, || async {
        (Ok(bench.path.clone()), Ok(towards_gateway(bench)))
    })
    .await;
}

/// A resumption of its own that runs until released, standing for one on a dying
/// tunnel.
async fn blocked_resumption(
    ceremony: &OperatorCeremony,
) -> (std::sync::mpsc::Sender<()>, OperatorStatus) {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let status = ceremony
        .open_as(
            RotationGesture::Resume.operation(),
            true,
            move |session_id, _presses, publish, _artifacts| {
                publish(OperatorStatus::new(
                    session_id,
                    1,
                    OperationKind::RotateAnchor,
                    RemoteState::Prepared,
                    GestureState::Signing,
                ));
                let _ = held.recv();
                Ok(())
            },
        )
        .await
        .ok()
        .expect("opened");
    (release, status)
}

/// A ceremony of the operator's can wait on them for as long as they like: an edge
/// that meets one returns at once, and dismissing their screen is what looks again.
#[tokio::test(flavor = "multi_thread")]
async fn an_edge_met_during_an_operators_ceremony_returns_at_once() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    open_session(&ceremony, &bench, RotationGesture::ReplaceCaPq).await;
    let waiting = until(&ceremony, |status| awaits_validation(status, 1)).await;
    leave_a_journal(&bench);

    tokio::time::timeout(Duration::from_secs(5), look(&ceremony, &bench))
        .await
        .expect("returns without waiting");

    assert_eq!(ceremony.status().await.expect("status"), waiting);
    ceremony
        .advance(OperatorAction::Cancel, waiting.revision, 0)
        .await
        .expect("abandoned");
    until(&ceremony, |status| status.gesture.is_terminal()).await;
}

/// An edge that meets a resumption still running is not lost: the look waits for that
/// one to end, reads the vault and the gateway again, and looks once more.
#[tokio::test(flavor = "multi_thread")]
async fn an_edge_met_during_a_resumption_waits_then_looks_once_more() {
    let bench = bench();
    leave_a_journal(&bench);
    let ceremony = Arc::new(OperatorCeremony::default());
    let (release, running) = blocked_resumption(&ceremony).await;
    let reads = Arc::new(AtomicUsize::new(0));

    let waiting = {
        let (ceremony, bench, reads) = (ceremony.clone(), bench.clone(), reads.clone());
        tokio::spawn(async move {
            crate::operator::resume_with(&ceremony, || async {
                reads.fetch_add(1, Ordering::SeqCst);
                (Ok(bench.path.clone()), Ok(towards_gateway(&bench)))
            })
            .await;
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "waits for the running resumption");
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    release.send(()).expect("released");
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the wait ends by itself")
        .expect("joined");

    assert_eq!(reads.load(Ordering::SeqCst), 2, "read again");
    let after = ceremony.status().await.expect("a session");
    assert_ne!(after.session_id, running.session_id, "looked once more");
    until(&ceremony, |status| status.gesture.is_terminal()).await;
}

/// The profile may have changed during the wait: the second look goes by what is read
/// then, and a gateway the relay does not name starts nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_look_after_the_wait_goes_by_the_target_read_then() {
    let bench = bench();
    leave_a_journal(&bench);
    let ceremony = Arc::new(OperatorCeremony::default());
    let (release, running) = blocked_resumption(&ceremony).await;
    let reads = Arc::new(AtomicUsize::new(0));

    let waiting = {
        let (ceremony, bench, reads) = (ceremony.clone(), bench.clone(), reads.clone());
        tokio::spawn(async move {
            crate::operator::resume_with(&ceremony, || async {
                let target = if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    towards_gateway(&bench)
                } else {
                    towards_another_gateway()
                };
                (Ok(bench.path.clone()), Ok(target))
            })
            .await;
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    release.send(()).expect("released");
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the wait ends by itself")
        .expect("joined");

    let after = ceremony.status().await.expect("a session");
    assert_eq!(after.session_id, running.session_id, "nothing started");
}

/// The second look does not wait in its turn: another resumption met then is left to
/// the next tunnel-up, and nothing loops.
#[tokio::test(flavor = "multi_thread")]
async fn the_second_look_does_not_wait_in_its_turn() {
    let bench = bench();
    leave_a_journal(&bench);
    let ceremony = Arc::new(OperatorCeremony::default());
    let (release, _) = blocked_resumption(&ceremony).await;
    let second: Arc<Mutex<Option<std::sync::mpsc::Sender<()>>>> = Arc::default();
    let reads = Arc::new(AtomicUsize::new(0));

    let waiting = {
        let (ceremony, bench, reads, second) = (
            ceremony.clone(),
            bench.clone(),
            reads.clone(),
            second.clone(),
        );
        tokio::spawn(async move {
            let again = ceremony.clone();
            crate::operator::resume_with(&ceremony, || async {
                if reads.fetch_add(1, Ordering::SeqCst) == 1 {
                    // Another edge's run begins before the second look.
                    let (release, _) = blocked_resumption(&again).await;
                    *second.lock().expect("lock") = Some(release);
                }
                (Ok(bench.path.clone()), Ok(towards_gateway(&bench)))
            })
            .await;
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    release.send(()).expect("released");
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("returns without waiting a second time")
        .expect("joined");

    assert_eq!(reads.load(Ordering::SeqCst), 2);
    second
        .lock()
        .expect("lock")
        .take()
        .expect("the second run")
        .send(())
        .expect("released");
}

/// The operator's own screen is what kept the look out: dismissing it looks again. A
/// resumption's own dead end, dismissed, brings nothing back.
#[tokio::test(flavor = "multi_thread")]
async fn only_dismissing_the_operators_screen_calls_for_a_look() {
    let bench = bench();
    let ceremony = OperatorCeremony::default();
    ceremony
        .begin_rotation(RotationGesture::ReplaceCaTls, None, bench.path.clone())
        .await
        .expect("a session");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;
    leave_a_journal(&bench);

    look(&ceremony, &bench).await;
    assert_eq!(ceremony.status().await.expect("status"), ended);

    assert!(ceremony.dismiss().await.expect("dismissed"), "theirs");
    look(&ceremony, &bench).await;
    let after = ceremony.status().await.expect("a session");
    assert_ne!(after.session_id, ended.session_id);
    until(&ceremony, |status| status.gesture.is_terminal()).await;

    assert!(
        !ceremony.dismiss().await.expect("dismissed"),
        "a resumption's dead end"
    );
}

/// A vault or a gateway that cannot be named is nothing to do.
#[tokio::test(flavor = "multi_thread")]
async fn a_look_without_a_vault_or_a_gateway_does_nothing() {
    let bench = bench();
    leave_a_journal(&bench);
    let ceremony = OperatorCeremony::default();
    crate::operator::resume_with(&ceremony, || async {
        (Err("aucun coffre".into()), Ok(towards_gateway(&bench)))
    })
    .await;
    crate::operator::resume_with(&ceremony, || async {
        (Ok(bench.path.clone()), Err("aucun tunnel".into()))
    })
    .await;
    assert!(ceremony.status().await.is_none());
}

/// « Terminer » sends the vault copy at its end: towards another domain's gateway it is
/// refused before any key, and nothing moves.
#[tokio::test(flavor = "multi_thread")]
async fn finishing_is_refused_towards_another_domains_gateway() {
    let bench = bench();
    let record = bench.rotated_client_tls();
    let (vault, touches) = (bench.vault_bytes(), bench.touches());
    let ceremony = OperatorCeremony::default();

    ceremony
        .begin_rotation(
            RotationGesture::FinishCaTls,
            Some(towards_another_gateway()),
            bench.path.clone(),
        )
        .await
        .expect("a session");
    let ended = until(&ceremony, |status| status.gesture.is_terminal()).await;

    assert_eq!(ended.refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(bench.record().as_ref(), Some(&record));
    assert_eq!(bench.vault_bytes(), vault);
    assert_eq!(bench.touches(), touches);
}

/// A real dead end, retried at each tunnel-up: past `activation_at` the transition is
/// not on the gateway, and every resumption stops the same way with the journal and
/// the vault as they were, no key asked.
#[test]
fn a_rotation_past_its_install_deadline_is_retried_and_stops_the_same_way() {
    let bench = bench();
    *bench.remote.install_refused.lock().expect("lock") = Some(503);
    bench
        .drive(RotationGesture::ReplaceCaPq, Bench::all_the_way)
        .refused(Refusal::GatewayRefused { status: 503 });
    let journal = bench.journal().expect("kept");
    *bench.remote.install_refused.lock().expect("lock") = None;
    bench.set_clock(journal.activation_at);
    let (vault, touches) = (bench.vault_bytes(), bench.touches());

    for _ in 0..2 {
        let ran = bench.drive(RotationGesture::Resume, Bench::all_the_way);
        ran.refused(Refusal::InstallDeadlinePassed);
        assert!(ran.asked_no_key());
        assert_eq!(bench.journal().as_ref(), Some(&journal));
        assert_eq!(bench.vault_bytes(), vault);
        assert_eq!(bench.touches(), touches);
    }
}
