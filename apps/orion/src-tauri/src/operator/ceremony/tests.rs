use super::*;
use crate::operator::{EnrollmentGesture, OperatorArtifact};
use aether::certificates::operator_session::{
    GestureState, KeyPurpose, OperationKind, OperatorAction, Refusal, RemoteState,
};
use astra_operator::enrollment::InvitationRegistry;

fn locator() -> OperationLocator {
    OperationLocator {
        kind: OperationKind::RecoverIdentity,
        operation_id: Id16::parse_hex("fdcc7341b0cf98f1672eab37508db464").ok(),
    }
}

/// The property a press depends on: no two statuses of one session ever share
/// a revision, and the counter never goes back.
#[test]
fn revisions_only_move_forward() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    let first = ceremony.status();
    let second = ceremony.status();
    assert_eq!(first.revision, 1);
    assert_eq!(second.revision, 2);
}

/// A refusal is terminal, and a terminal status offers nothing: an interface
/// that still rendered «Continuer» would be offering a button the ceremony
/// refuses.
#[test]
fn a_refused_ceremony_offers_no_action() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    ceremony.refuse(Refusal::KeyDeclined);
    let status = ceremony.status();
    assert_eq!(status.refusal, Some(Refusal::KeyDeclined));
    assert!(status.allowed.is_empty());
    assert!(!status.accepts(OperatorAction::Continue, status.revision));
}

/// A press answering a screen this session has already left must not be
/// applied to whatever replaced it: the stale one is skipped and the next
/// press, which answers the offered revision, is the one taken.
#[test]
fn a_press_on_a_stale_revision_is_ignored_and_the_right_one_is_taken() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    let offered = ceremony.status();

    let (presses, received) = std::sync::mpsc::channel();
    presses
        .send(Press {
            action: OperatorAction::Continue,
            revision: offered.revision + 5,
            owner: 0,
            terms: None,
        })
        .expect("sent");
    presses
        .send(Press {
            action: OperatorAction::Continue,
            revision: offered.revision,
            owner: 7,
            terms: None,
        })
        .expect("sent");

    let taken = awaited_action(&received, &offered).expect("a press is taken");
    assert_eq!(taken.action, OperatorAction::Continue);
    assert_eq!(taken.revision, offered.revision);
    assert_eq!(taken.owner, 7);
}

/// A sender dropped while the operator is being waited on is an abandonment,
/// not a refusal: the window that held the ceremony was closed.
#[test]
fn a_dropped_sender_while_waiting_is_an_abandonment() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    let offered = ceremony.status();
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    assert!(awaited_action(&received, &offered).is_none());
}

/// An abandonment is not a failure, and the interface must be able to tell
/// the operator's own choice from something that went wrong.
#[test]
fn a_cancellation_is_not_a_failure() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    ceremony.cancel();
    let status = ceremony.status();
    assert_eq!(status.gesture, GestureState::Cancelled);
    assert_eq!(status.refusal, Some(Refusal::Cancelled));
    assert!(status.allowed.is_empty());
}

/// The locator travels whole: an operation the authority opened is reached by
/// the identifier Orion holds, and a status that dropped it would leave an
/// operator unable to say which recovery they were looking at.
#[test]
fn a_status_names_the_operation_it_is_about() {
    let mut ceremony = Ceremony::new(Id16::new([1; 16]).expect("id"), locator());
    let status = ceremony.status();
    assert_eq!(status.operation, OperationKind::RecoverIdentity);
    assert_eq!(status.operation_id, locator().operation_id);
}

/// Off Windows the only transport is raw CTAP, which shows nothing: the dialog
/// belongs to the console, and no window is claimed.
#[cfg(not(windows))]
#[test]
fn off_windows_the_dialog_belongs_to_the_console() {
    use aether_fido::authenticator::DialogOwner;

    assert_eq!(dialog_owner(0), Ok(DialogOwner::Console));
}

/// A key check on a vault that is not there is refused with a typed reason,
/// not answered by the arm that says the ceremony is not carried here.
#[test]
fn verify_key_is_served() {
    let missing =
        std::env::temp_dir().join(format!("orion-verify-key-{}-absent", std::process::id()));
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut published = Vec::new();
    let outcome = run(
        Id16::new([1; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::VerifyKey,
            operation_id: None,
        },
        received,
        &mut |status| published.push(status),
        &missing,
    );
    let error = outcome.expect_err("an absent vault is refused");
    assert!(!error.contains("pas encore portée"), "{error}");
    let last = published.last().expect("a status was published");
    assert_eq!(last.refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(last.keys.is_empty());
}

/// Gestures that need an explicit payload cannot be started from a bare
/// locator. Keep every such operation on the same fail-closed dispatch path.
#[test]
fn payload_ceremonies_refuse_a_bare_locator() {
    let vault = std::env::temp_dir().join(format!(
        "orion-payload-ceremony-{}-absent",
        std::process::id()
    ));
    for operation in [
        OperationKind::CreateDomain,
        OperationKind::AddKey,
        OperationKind::RemoveKey,
        OperationKind::MarkKey,
        OperationKind::FinalizeDomain,
        OperationKind::IssueGatewayBootstrap,
        OperationKind::AuthorizeIssuer,
        OperationKind::RotateAnchor,
        OperationKind::RotateClientTlsCa,
        OperationKind::RevokeCertificate,
    ] {
        let (presses, received) = std::sync::mpsc::channel::<Press>();
        drop(presses);
        let mut published = Vec::new();
        let outcome = run(
            Id16::new([1; 16]).expect("id"),
            OperationLocator {
                kind: operation,
                operation_id: None,
            },
            received,
            &mut |status| published.push(status),
            &vault,
        );

        let error = outcome.expect_err("a bare locator cannot carry gesture terms");
        assert!(
            error.contains("s'ouvre par son geste"),
            "{operation:?}: {error}"
        );
        assert_eq!(published.len(), 2, "{operation:?}");
        let last = published.last().expect("terminal status");
        assert_eq!(last.operation, operation);
        assert_eq!(last.refusal, Some(Refusal::Internal));
        assert_eq!(last.gesture, GestureState::Failed);
        assert!(last.allowed.is_empty());
    }
}

/// A locator can name operations not handled by this process. It gets an
/// explicit terminal status instead of leaving the UI waiting forever.
#[test]
fn unsupported_locator_operation_is_refused_explicitly() {
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut published = Vec::new();
    let outcome = run(
        Id16::new([1; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::GatewayIdentity,
            operation_id: None,
        },
        received,
        &mut |status| published.push(status),
        std::path::Path::new("unused-vault.json"),
    );

    let error = outcome.expect_err("GatewayIdentity uses its dedicated gesture");
    assert!(error.contains("n'est pas encore portée"), "{error}");
    let last = published.last().expect("terminal status");
    assert_eq!(last.operation, OperationKind::GatewayIdentity);
    assert_eq!(last.refusal, Some(Refusal::Internal));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(last.allowed.is_empty());
}

/// A vault of this machine's making, the domain relay beside it naming one
/// gateway, and a registry directory of its own.
pub(super) struct Domain {
    directory: std::path::PathBuf,
    pub(super) vault_path: std::path::PathBuf,
    registry: InvitationRegistry,
    pub(super) ca_private_key: zeroize::Zeroizing<Vec<u8>>,
    ca_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    pub(super) gateway_key: String,
}

const SERVER_NAME: &str = "gateway.example";

impl Domain {
    pub(super) fn new(label: &str) -> Self {
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, TrustDomainId};
        use astra_operator::vault::{
            draw_salt, AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, SlotSecret,
        };

        let directory = std::env::temp_dir().join(format!(
            "orion-invite-{label}-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("directory");
        let (ca_private_key, ca_public_key) = generate_ml_dsa_87_keypair().expect("CA-PQ");
        let secrets = AuthoritySecrets {
            ca_pq_private_key: "not-used-before-a-touch".into(),
            ca_pq_public_key: ca_public_key.to_base64(),
            ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
            retained_ca_tls: None,
            retained_outgoing_ca_pq: None,
        };
        let vault = AuthorityVault::create(
            TrustDomainId::new([3; 16]).expect("domain"),
            "astra.example",
            draw_salt().expect("salt"),
            &secrets,
            SlotEnrolment {
                role: SlotRole::Primary,
                label: "quotidienne".into(),
                credential_id: vec![1; 64],
                credential_public_key: vec![0xa5, 1],
                aaguid: [1; 16],
                enrolled_at: 2_000,
            },
            &SlotSecret::new(vec![1; 32]),
            1_000,
        )
        .expect("vault");
        let vault_path = directory.join("astra").join("authority-vault.json");
        astra_operator::store::save(&vault_path, &vault).expect("save vault");
        let gateway_key = aether::wg::generate_keypair()
            .expect("gateway key")
            .public_key;
        let mut relay = astra_operator::handoff::DomainHandoff::of(&vault).expect("relay");
        relay.gateway_wg_public_key = Some(gateway_key.clone());
        relay.server_name = Some(SERVER_NAME.into());
        astra_operator::handoff::save(&astra_operator::handoff::path_beside(&vault_path), &relay)
            .expect("save relay");
        Self {
            registry: InvitationRegistry::at(directory.join("registry")),
            directory,
            vault_path,
            ca_private_key,
            ca_public_key,
            gateway_key,
        }
    }

    /// A gateway leaf issued by this domain's `CA-PQ`, for the given identity.
    fn leaf(&self, server_name: &str, wireguard_key: &str) -> String {
        use aether::certificates::encoding::generate_ml_dsa_87_keypair;
        use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

        let (_, subject) = generate_ml_dsa_87_keypair().expect("subject");
        let now = now_unix();
        let leaf = aether::key_negotiation::issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [9; 16],
                subject: server_name.into(),
                issuer: "helios-ca-pq".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: wireguard_key.into(),
                ml_dsa_87_public_key: subject.to_base64(),
                not_before_unix: now - 60,
                not_after_unix: now + 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &self.ca_private_key,
        )
        .expect("leaf");
        serde_json::to_string(&leaf).expect("json")
    }

    fn invite(
        &self,
        readmission: bool,
        leaf: Option<String>,
        presses: Receiver<Press>,
    ) -> (
        Result<(), String>,
        Vec<OperatorStatus>,
        Vec<OperatorArtifact>,
    ) {
        let mut published = Vec::new();
        let mut artifacts = Vec::new();
        let outcome = run_enrollment_with(
            Id16::new([2; 16]).expect("id"),
            EnrollmentGesture::Invite {
                valid_for_hours: 2,
                allow_readmission: readmission,
                name: "laptop".into(),
                gateway_pq_certificate: leaf,
            },
            None,
            presses,
            &mut |status| published.push(status),
            &mut |artifact| artifacts.push(artifact),
            &self.vault_path,
            &self.registry,
        );
        (outcome, published, artifacts)
    }

    fn registry_is_empty(&self) -> bool {
        std::fs::read_dir(self.registry.directory())
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true)
    }
}

impl Drop for Domain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// With no gateway to read and no sheet to read from, there is nothing to
/// pin: the invitation is refused before any key is asked for.
#[test]
fn an_invitation_needs_a_gateway_leaf() {
    let domain = Domain::new("no-leaf");
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.invite(false, None, received);
    outcome.expect_err("no leaf, no invitation");
    let last = published.last().expect("a status");
    assert_eq!(last.refusal, Some(Refusal::HandoffMismatch));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(published
        .iter()
        .all(|status| !matches!(status.gesture, GestureState::AwaitingKey { .. })));
    assert!(artifacts.is_empty());
    assert!(domain.registry_is_empty());
}

/// A connected gateway that cannot be read, with no leaf file, is its own
/// refusal: not « admit the peer by hand », for there is no peer yet.
#[test]
fn an_unreadable_gateway_without_a_leaf_file_names_the_missing_leaf() {
    let domain = Domain::new("unreadable-no-leaf");
    let refused = leaf_from(
        None,
        Some(Err("injoignable".to_string())),
        SERVER_NAME,
        &WireGuardKey::parse(&domain.gateway_key).expect("key"),
    )
    .expect_err("no leaf to pin");
    assert_eq!(refused.0, Refusal::GatewayLeafUnavailable);
}

/// A leaf this domain issued, but for another gateway, would pin the wrong
/// machine: refused before a key is asked for, and nothing is recorded.
#[test]
fn a_leaf_for_another_gateway_is_refused() {
    let domain = Domain::new("other-gateway");
    let other_key = aether::wg::generate_keypair().expect("key").public_key;
    for leaf in [
        domain.leaf("elsewhere.example", &domain.gateway_key),
        domain.leaf(SERVER_NAME, &other_key),
        "not a leaf".to_string(),
    ] {
        let (presses, received) = std::sync::mpsc::channel::<Press>();
        drop(presses);
        let (outcome, published, artifacts) = domain.invite(false, Some(leaf), received);
        outcome.expect_err("another gateway's leaf is refused");
        let last = published.last().expect("a status");
        assert_eq!(last.refusal, Some(Refusal::HandoffMismatch));
        assert!(published
            .iter()
            .all(|status| !matches!(status.gesture, GestureState::AwaitingKey { .. })));
        assert!(artifacts.is_empty());
        assert!(domain.registry_is_empty());
    }
}

/// An invitation that may readmit is signed under two distinct keys, and the
/// first screen says so before anything is touched.
#[test]
fn readmission_asks_for_two_distinct_keys() {
    let domain = Domain::new("two-keys");
    let leaf = domain.leaf(SERVER_NAME, &domain.gateway_key);
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.invite(true, Some(leaf), received);
    outcome.expect("an abandoned ceremony is not a failure");
    let offered = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked for");
    assert_eq!(
        offered.gesture,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::OpenVault
        }
    );
    match offered
        .manifest
        .as_ref()
        .expect("the manifest is shown first")
    {
        AstraManifest::Invitation(manifest) => {
            assert_eq!(manifest.server_name, SERVER_NAME);
            assert!(manifest.allow_readmission);
            assert_eq!(
                manifest.ca_pq_fingerprint,
                domain.ca_public_key.authority_fingerprint()
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
    assert!(artifacts.is_empty());
    assert!(domain.registry_is_empty());
}

/// The second key of a readmission is a second approval, not another opening.
#[test]
fn the_second_key_is_a_second_approval() {
    assert_eq!(invitation_key_purpose(1), KeyPurpose::OpenVault);
    assert_eq!(invitation_key_purpose(2), KeyPurpose::SecondApproval);
}

fn material(
    server_name: &str,
    key: &str,
    leaf: &str,
) -> orion_core::enrollment_draft::GatewayMaterial {
    orion_core::enrollment_draft::GatewayMaterial {
        server_name: server_name.into(),
        gateway_ca_der: String::new(),
        gateway_pq_certificate: leaf.into(),
        wireguard_public_key: key.into(),
        pq_certificate_sha256: String::new(),
        negotiation_port: None,
    }
}

/// A connected gateway that answers for another identity than the relay names
/// is refused, and the leaf the operator supplied is not a way around it.
#[test]
fn a_connected_gateway_for_another_identity_is_refused_without_fallback() {
    let domain = Domain::new("connected-other");
    let leaf = domain.leaf(SERVER_NAME, &domain.gateway_key);
    let key = WireGuardKey::parse(&domain.gateway_key).expect("key");
    let other_key = aether::wg::generate_keypair().expect("key").public_key;
    for answered in [
        material("elsewhere.example", &domain.gateway_key, &leaf),
        material(SERVER_NAME, &other_key, &leaf),
    ] {
        let refused = leaf_from(Some(&leaf), Some(Ok(answered)), SERVER_NAME, &key)
            .expect_err("another identity is refused");
        assert_eq!(refused.0, Refusal::HandoffMismatch);
    }
    let accepted = leaf_from(
        None,
        Some(Ok(material(SERVER_NAME, &domain.gateway_key, &leaf))),
        SERVER_NAME,
        &key,
    );
    assert!(accepted.is_ok());
}

/// An unreachable connected gateway falls back to the supplied leaf, which is
/// still verified under `CA-PQ` afterwards: a bad one is refused before a key.
#[test]
fn an_unreachable_gateway_falls_back_to_the_supplied_leaf_and_it_is_verified() {
    let domain = Domain::new("unreachable");
    // A port nothing listens on: the real client fails to connect.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        format!("http://127.0.0.1:{port}")
    };
    let run = |leaf: Option<String>| {
        let (presses, received) = std::sync::mpsc::channel::<Press>();
        drop(presses);
        let mut published = Vec::new();
        let outcome = run_enrollment_with(
            Id16::new([2; 16]).expect("id"),
            EnrollmentGesture::Invite {
                valid_for_hours: 2,
                allow_readmission: false,
                name: "laptop".into(),
                gateway_pq_certificate: leaf,
            },
            Some(closed.clone()),
            received,
            &mut |status| published.push(status),
            &mut |_| {},
            &domain.vault_path,
            &domain.registry,
        );
        (outcome, published)
    };

    let good = domain.leaf(SERVER_NAME, &domain.gateway_key);
    let (outcome, published) = run(Some(good));
    // Accepted as far as a key being asked for; the sender is dropped, so the
    // ceremony ends cancelled rather than failed.
    outcome.expect("the supplied leaf is used");
    assert!(published
        .iter()
        .any(|status| matches!(status.gesture, GestureState::AwaitingKey { .. })));

    let bad = domain.leaf("elsewhere.example", &domain.gateway_key);
    let (outcome, published) = run(Some(bad));
    outcome.expect_err("the fallback leaf is verified");
    assert_eq!(
        published.last().expect("status").refusal,
        Some(Refusal::HandoffMismatch)
    );

    let (outcome, published) = run(None);
    outcome.expect_err("nothing to fall back to");
    assert_eq!(
        published.last().expect("status").refusal,
        Some(Refusal::GatewayLeafUnavailable)
    );
    assert!(domain.registry_is_empty());
}

/// A signed invitation recorded in the domain's registry, and the device's
/// request for it, built from real keys.
struct Enrolment {
    invitation: aether::key_negotiation::EnrollmentInvitation,
    request: aether::key_negotiation::EnrollmentRequest,
}

impl Domain {
    /// Names a CA-TLS in the relay, as an accepted request needs one.
    pub(super) fn with_ca_tls(self) -> Self {
        let csr = aether::certificates::x509::client_rotation_csr("stand-in-ca-tls")
            .expect("csr")
            .csr;
        let vault = astra_operator::store::load(&self.vault_path).expect("vault");
        let mut relay = astra_operator::handoff::DomainHandoff::beside(&self.vault_path, &vault)
            .expect("relay");
        relay.ca_tls_certificate = Some(csr.to_base64());
        astra_operator::handoff::save(
            &astra_operator::handoff::path_beside(&self.vault_path),
            &relay,
        )
        .expect("save relay");
        self
    }

    /// An invitation this domain signed, recorded as issued, and the request a
    /// device makes for it. `recorded` is false for an invitation the registry
    /// has never seen.
    fn enrolment(&self, name: &str, recorded: bool) -> Enrolment {
        use aether::certificates::encoding::{Fingerprint, MlDsa87Signature, WireGuardKey};
        use aether::key_negotiation::{
            wireguard_proof, EnrollmentInvitation, EnrollmentRequest, ProtectionMode,
            ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION, MAX_INVITATION_LIFETIME_SECS,
        };

        let now = now_unix();
        let proof = aether::wg::generate_keypair().expect("proof keys");
        let proof_private = *WireGuardKey::parse(proof.private_key.expose())
            .expect("proof private")
            .as_bytes();
        let invitation = EnrollmentInvitation {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: Id16::new(aether::random::public_bytes().expect("random")).expect("id"),
            gateway_wg_public_key: WireGuardKey::parse(&self.gateway_key).expect("gateway"),
            gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
            server_name: SERVER_NAME.into(),
            operator_ca_public_key: self.ca_public_key.clone(),
            wireguard_proof_public_key: WireGuardKey::parse(&proof.public_key).expect("proof"),
            not_before_unix: now - 60,
            not_after_unix: now - 60 + MAX_INVITATION_LIFETIME_SECS,
            minimum_mode: ProtectionMode::MlKem,
            allow_readmission: false,
            operator_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private_key)
        .expect("signed invitation");
        if recorded {
            self.registry
                .issue(&invitation, zeroize::Zeroizing::new(proof_private))
                .expect("recorded");
        }

        let device = aether::wg::generate_keypair().expect("device keys");
        let device_private = *WireGuardKey::parse(device.private_key.expose())
            .expect("device private")
            .as_bytes();
        let (ml_dsa_private, ml_dsa_public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("ml-dsa");
        let mut request = EnrollmentRequest {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: invitation.invitation_id,
            invitation_fingerprint: invitation.fingerprint(),
            request_id: Id16::new(aether::random::public_bytes().expect("random")).expect("id"),
            timestamp_unix: now,
            requested_name: name.into(),
            client_wg_public_key: WireGuardKey::parse(&device.public_key).expect("device"),
            tls_csr: aether::certificates::x509::client_rotation_csr(name)
                .expect("csr")
                .csr,
            client_ml_dsa_87_public_key: ml_dsa_public,
            wireguard_proof: [0; 32],
            client_signature: MlDsa87Signature::placeholder(),
        };
        request.wireguard_proof =
            wireguard_proof(&device_private, &invitation, &request).expect("proof");
        let request = request.sign(&ml_dsa_private).expect("signed request");
        Enrolment {
            invitation,
            request,
        }
    }

    fn accept(
        &self,
        request: &aether::key_negotiation::EnrollmentRequest,
        gateway: Option<String>,
        presses: Receiver<Press>,
    ) -> (
        Result<(), String>,
        Vec<OperatorStatus>,
        Vec<OperatorArtifact>,
    ) {
        let mut published = Vec::new();
        let mut artifacts = Vec::new();
        let outcome = run_enrollment_with(
            Id16::new([2; 16]).expect("id"),
            EnrollmentGesture::Accept {
                request: aether::key_negotiation::encode_request_file(request),
                validity_days: 365,
                endpoint: "198.51.100.7:51820".into(),
                allowed_ips: None,
                ssh_target: None,
            },
            gateway,
            presses,
            &mut |status| published.push(status),
            &mut |artifact| artifacts.push(artifact),
            &self.vault_path,
            &self.registry,
        );
        (outcome, published, artifacts)
    }
}

pub(super) fn no_key_was_asked(published: &[OperatorStatus]) -> bool {
    published
        .iter()
        .all(|status| !matches!(status.gesture, GestureState::AwaitingKey { .. }))
}

/// An invitation the registry does not know is refused before any key is
/// asked for, and nothing is written.
#[test]
fn a_request_for_an_unknown_invitation_is_refused_before_the_key() {
    let domain = Domain::new("accept-unknown").with_ca_tls();
    let unknown = domain.enrolment("laptop", false);
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.accept(&unknown.request, None, received);
    outcome.expect_err("an unknown invitation is refused");
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(Refusal::InvitationUnknown));
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
    assert!(domain.registry_is_empty());
}

/// Acceptance rejects a missing delivery endpoint before decoding a request
/// or consulting the gateway, so no key prompt or registry mutation can follow.
#[test]
fn acceptance_rejects_a_blank_endpoint_before_gateway_io() {
    let domain = Domain::new("accept-blank-endpoint").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let request = aether::key_negotiation::encode_request_file(&enrolment.request);
    let accept = Accept {
        request: &request,
        validity_days: 365,
        endpoint: " \t ",
        allowed_ips: None,
        ssh_target: None,
        gateway: Some("http://must-not-be-read.invalid"),
    };

    let result = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        now_unix(),
        &|_| panic!("gateway must not be read for a blank endpoint"),
    );

    let (refusal, message) = result.err().expect("blank endpoint is refused");
    assert_eq!(refusal, Refusal::ManifestMismatch);
    assert!(message.contains("adresse publique"));
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// Malformed request contents are rejected as a handoff mismatch without
/// consuming the otherwise valid invitation.
#[test]
fn acceptance_rejects_an_undecodable_request_without_consuming_the_invitation() {
    let domain = Domain::new("accept-malformed-request").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let accept = Accept {
        request: "not an enrollment request",
        validity_days: 365,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: None,
    };

    let result = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        now_unix(),
        &|_| Err(orion_core::gateway_admin::GatewayAdminError::Unreachable),
    );

    let (refusal, message) = result.err().expect("malformed request is refused");
    assert_eq!(refusal, Refusal::HandoffMismatch);
    assert!(message.contains("demande d'enrôlement"));
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// Even a correctly signed request cannot turn an overflowing delivery
/// lifetime into a certificate window. The invitation remains available and
/// the gateway is not consulted after the arithmetic failure.
#[test]
fn acceptance_rejects_a_delivery_window_that_overflows_unix_time() {
    let domain = Domain::new("accept-validity-overflow").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let request = aether::key_negotiation::encode_request_file(&enrolment.request);
    let accept = Accept {
        request: &request,
        validity_days: u16::MAX,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: Some("https://gateway.invalid"),
    };

    let (refusal, message) = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        u64::MAX,
        &|_| panic!("gateway must not be read for an overflowing validity window"),
    )
    .err()
    .expect("an overflowing certificate window is refused");

    assert_eq!(refusal, Refusal::HandoffMismatch);
    assert!(message.contains("hors bornes"));
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// A temporary read failure from the connected gateway is handled after the
/// local request and invitation have been validated. It does not misidentify
/// the gateway or consume the invitation before an operator key is presented.
#[test]
fn acceptance_keeps_a_valid_request_when_gateway_material_cannot_be_read() {
    let domain = Domain::new("accept-gateway-read-error").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let accept = accept_of(&enrolment.request, Some("https://gateway.invalid"));

    let accepting = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        now_unix(),
        &|_| Err(orion_core::gateway_admin::GatewayAdminError::Unreachable),
    )
    .expect("a temporarily unavailable gateway does not block local acceptance");

    assert_eq!(accepting.request.request_id, enrolment.request.request_id);
    assert_eq!(accepting.pin.server_name, SERVER_NAME);
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// The registry state is checked before a key is requested, even if the
/// request itself remains valid and the ceremony is otherwise ready.
#[test]
fn acceptance_refuses_a_revoked_invitation_before_gateway_io() {
    let domain = Domain::new("accept-revoked").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    domain
        .registry
        .revoke(&enrolment.invitation.invitation_id, now_unix())
        .expect("issued invitation can be revoked");
    let request = aether::key_negotiation::encode_request_file(&enrolment.request);
    let accept = Accept {
        request: &request,
        validity_days: 365,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: None,
    };

    let (refusal, message) = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        now_unix(),
        &|_| panic!("gateway must not be read for a revoked invitation"),
    )
    .err()
    .expect("revoked invitation is refused");

    assert_eq!(refusal, Refusal::InvitationExpired);
    assert!(message.contains("révoquée"));
    assert!(matches!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Revoked { .. }
    ));
}

/// An issued record whose signed validity window has elapsed is refused even
/// when the registry has not yet purged or rewritten it.
#[test]
fn acceptance_refuses_an_issued_invitation_past_its_signed_expiry() {
    let domain = Domain::new("accept-expired-window").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let request = aether::key_negotiation::encode_request_file(&enrolment.request);
    let accept = Accept {
        request: &request,
        validity_days: 365,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: None,
    };

    let (refusal, message) = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        enrolment.invitation.not_after_unix + 1,
        &|_| panic!("gateway must not be read for an expired invitation"),
    )
    .err()
    .expect("expired invitation is refused");

    assert_eq!(refusal, Refusal::InvitationExpired);
    assert!(message.contains("expiré"));
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// Altering the requested identity in an initially signed request invalidates
/// its signature and cannot consume the associated invitation.
#[test]
fn acceptance_refuses_a_request_that_does_not_match_its_invitation() {
    let domain = Domain::new("accept-request-mismatch").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let mut request = enrolment.request;
    request.requested_name = "another-device".into();
    let request_file = aether::key_negotiation::encode_request_file(&request);
    let accept = Accept {
        request: &request_file,
        validity_days: 365,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: None,
    };

    let (refusal, message) = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept,
        now_unix(),
        &|_| panic!("gateway must not be read for an invalid request"),
    )
    .err()
    .expect("mismatched request is refused");

    assert_eq!(refusal, Refusal::HandoffMismatch);
    assert!(message.contains("ne correspond pas"));
    assert_eq!(
        domain
            .registry
            .load(&enrolment.invitation.invitation_id)
            .expect("invitation remains readable")
            .state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// A relay with no CA-TLS cannot issue a client leaf: refused before a key,
/// naming what is missing.
#[test]
fn a_relay_without_ca_tls_is_refused_before_the_key() {
    let domain = Domain::new("accept-no-ca-tls");
    let enrolment = domain.enrolment("laptop", true);
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, _) = domain.accept(&enrolment.request, None, received);
    let error = outcome.expect_err("no CA-TLS, no leaf");
    assert!(error.contains("CA-TLS"), "{error}");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::CaTlsMissing)
    );
    assert!(no_key_was_asked(&published));
    let record = domain
        .registry
        .load(&enrolment.invitation.invitation_id)
        .expect("record");
    assert_eq!(
        record.state,
        astra_operator::enrollment::InvitationState::Issued
    );
}

/// A consumed invitation is the resumption's business: the refusal says so and
/// no key is asked for.
#[test]
fn accepting_a_consumed_invitation_points_to_resume() {
    let domain = Domain::new("accept-consumed").with_ca_tls();
    // Accepted here, leaves kept: a resumption exists to point to.
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.accept(&enrolment.request, None, received);
    let error = outcome.expect_err("a consumed invitation is refused");
    assert_eq!(
        error,
        "Cette invitation est déjà consommée : la reprendre depuis la liste des invitations."
    );
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::InvitationConsumed)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
}

/// Consumed outside Orion, nothing is kept here: no « Reprendre » exists, so
/// the refusal must not send the operator to it.
#[test]
fn accepting_a_cli_accepted_invitation_is_refused_as_accepted_elsewhere() {
    let domain = Domain::new("accept-cli-consumed").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    domain
        .registry
        .consume(
            &enrolment.invitation.invitation_id,
            &enrolment.request,
            now_unix(),
        )
        .expect("consumed");
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.accept(&enrolment.request, None, received);
    outcome.expect_err("a consumed invitation is refused");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::AcceptedElsewhere)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
}

/// The operator can walk away at the key prompt: the manifest was shown, and
/// the invitation is still issued.
#[test]
fn cancelling_before_the_key_consumes_nothing() {
    let domain = Domain::new("accept-cancel").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, artifacts) = domain.accept(&enrolment.request, None, received);
    outcome.expect("a cancellation is not a failure");
    let offered = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked for");
    match offered.manifest.as_ref().expect("manifest shown first") {
        AstraManifest::EnrollmentAcceptance(manifest) => {
            assert_eq!(manifest.invitation_id, enrolment.invitation.invitation_id);
            assert_eq!(manifest.requested_name, "laptop");
            assert_eq!(
                manifest.request_fingerprint,
                enrolment.request.fingerprint()
            );
            assert_eq!(
                manifest.client_wg_public_key,
                enrolment.request.client_wg_public_key
            );
            assert_eq!(manifest.endpoint, "198.51.100.7:51820");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
    assert!(artifacts.is_empty());
    let id = enrolment.invitation.invitation_id;
    assert_eq!(
        domain.registry.load(&id).expect("record").state,
        astra_operator::enrollment::InvitationState::Issued
    );
    assert!(domain.registry.accepted(&id).expect("readable").is_none());
}

/// Leaves for a request, with the registry recording them as the invitation's
/// issuance: what `accept_request` leaves behind, minus the key.
fn issued_leaves(
    domain: &Domain,
    enrolment: &Enrolment,
) -> astra_operator::enrollment::AcceptedEnrollment {
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    let request = &enrolment.request;
    domain
        .registry
        .consume(&request.invitation_id, request, now_unix())
        .expect("consumed");
    let now = now_unix();
    let pq_certificate = aether::key_negotiation::issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [5; 16],
            subject: request.requested_name.clone(),
            issuer: "helios-ca-pq".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: request.client_wg_public_key.to_base64(),
            ml_dsa_87_public_key: request.client_ml_dsa_87_public_key.to_base64(),
            not_before_unix: now - 60,
            not_after_unix: now + 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &domain.ca_private_key,
    )
    .expect("pq leaf");
    // The CSR stands in for the TLS leaf: these tests do not parse it.
    let accepted = astra_operator::enrollment::AcceptedEnrollment {
        request: request.clone(),
        tls_certificate: request.tls_csr.clone(),
        pq_certificate,
    };
    domain
        .registry
        .record_issued(
            &request.invitation_id,
            astra_operator::enrollment::IssuedLeafFingerprints {
                tls_certificate: accepted.tls_certificate.fingerprint(),
                pq_certificate: aether::certificates::gateway::pq_certificate_fingerprint(
                    &accepted.pq_certificate,
                )
                .expect("fingerprint"),
            },
        )
        .expect("recorded");
    accepted
}

/// Runs the part of an acceptance that follows the issuance, on leaves given.
fn keep_and_admit_on(
    domain: &Domain,
    accepted: &astra_operator::enrollment::AcceptedEnrollment,
    gateway: Option<&str>,
) -> (
    Result<(), String>,
    Vec<OperatorStatus>,
    Vec<OperatorArtifact>,
) {
    let mut ceremony = Ceremony::new(
        Id16::new([2; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AcceptEnrollment,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let kept = keep_leaves(
        &mut ceremony,
        &mut |status| published.push(status),
        &mut |artifact| artifacts.push(artifact),
        &domain.registry,
        accepted,
    );
    let outcome = kept.and_then(|()| {
        admit_or_stop(
            &mut ceremony,
            &mut |status| published.push(status),
            &mut |artifact| artifacts.push(artifact),
            accepted,
            gateway,
            &pin_of(domain, accepted),
            &read_negotiation,
        )
    });
    (outcome, published, artifacts)
}

/// With the gateway out of reach the acceptance stops after the leaves: they
/// are kept for the resumption, handed over with the line that admits the
/// peer by hand, and the refusal is the gateway's.
#[test]
fn an_unreachable_gateway_stops_after_the_leaves() {
    let domain = Domain::new("accept-unreachable").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let accepted = issued_leaves(&domain, &enrolment);
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        )
    };
    for gateway in [Some(closed.as_str()), None] {
        let (outcome, published, artifacts) = keep_and_admit_on(&domain, &accepted, gateway);
        outcome.expect_err("the acceptance stops here");
        let last = published.last().expect("a status");
        assert_eq!(last.refusal, Some(Refusal::GatewayUnavailable));
        assert_eq!(last.gesture, GestureState::Failed);
        let stem = enrolment.request.request_id.to_hex();
        let names: Vec<&str> = artifacts.iter().map(|a| a.file_name.as_str()).collect();
        assert_eq!(
            names,
            [
                format!("{stem}-client-cert.der"),
                format!("{stem}-client-pq-cert.json"),
                "admission.txt".to_string()
            ]
        );
        assert_eq!(
            artifacts[0].encoding,
            crate::operator::ArtifactEncoding::Base64
        );
        assert_eq!(
            artifacts[1].encoding,
            crate::operator::ArtifactEncoding::Text
        );
        assert_eq!(
            artifacts[2].encoding,
            crate::operator::ArtifactEncoding::Text
        );
        // Decoded, the first artifact is the DER `heliosd peer add` reads raw.
        let decoded = DerCertificate::parse(&artifacts[0].contents).expect("base64 of a DER");
        assert_eq!(decoded.as_bytes(), accepted.tls_certificate.as_bytes());
        let leaf: aether::key_negotiation::PqCertificate =
            serde_json::from_str(&artifacts[1].contents).expect("the PQ leaf is JSON");
        assert_eq!(leaf, accepted.pq_certificate);
    }
    let id = enrolment.invitation.invitation_id;
    assert_eq!(
        domain.registry.accepted(&id).expect("readable"),
        Some(accepted)
    );
    assert!(domain
        .registry
        .directory()
        .join(format!("{}.accepted.json", id.to_hex()))
        .is_file());
}

/// The line to paste names the files the operator is handed, not paths of this
/// machine, and the device's own key.
#[test]
fn the_admission_line_names_the_written_leaves() {
    let domain = Domain::new("accept-line").with_ca_tls();
    let enrolment = domain.enrolment("laptop $(id)", true);
    let accepted = issued_leaves(&domain, &enrolment);
    let (_, _, artifacts) = keep_and_admit_on(&domain, &accepted, None);
    let stem = enrolment.request.request_id.to_hex();
    let line = artifacts
        .iter()
        .find(|artifact| artifact.file_name == "admission.txt")
        .expect("the line is handed over");
    assert_eq!(
        line.contents.lines().next().expect("the line"),
        astra_operator::admission::admission_command_line(
            "laptop $(id)",
            &enrolment.request.client_wg_public_key.to_base64(),
            &format!("{stem}-client-cert.der"),
            &format!("{stem}-client-pq-cert.json"),
        )
    );
    assert!(line.contents.contains("'laptop $(id)'"));
    assert!(line.contents.contains(&format!("{stem}-client-cert.der")));
    assert!(line
        .contents
        .contains(&format!("{stem}-client-pq-cert.json")));
}

/// The device names its file; the file name is not the device's to choose.
#[test]
fn the_document_is_named_after_a_safe_requested_name() {
    let id = Id16::new([7; 16]).expect("id");
    assert_eq!(
        document_file_name("laptop-alice", &id),
        "laptop-alice.orion"
    );
    for hostile in ["../escape", "a b", "", &"x".repeat(65)] {
        assert_eq!(
            document_file_name(hostile, &id),
            format!("{}.orion", id.to_hex())
        );
    }
}

fn pin_of(
    domain: &Domain,
    accepted: &astra_operator::enrollment::AcceptedEnrollment,
) -> GatewayPin {
    let record = domain
        .registry
        .load(&accepted.request.invitation_id)
        .expect("record");
    GatewayPin::of(&record.invitation)
}

fn answer(
    server_name: &str,
    key: &str,
) -> Result<
    orion_core::enrollment_draft::GatewayMaterial,
    orion_core::gateway_admin::GatewayAdminError,
> {
    Ok(material(server_name, key, ""))
}

/// The connected gateway is the one the invitation pins, or nothing is
/// consumed: a gateway for another identity is refused before the key.
#[test]
fn a_gateway_other_than_the_pinned_one_is_refused_before_the_key() {
    let domain = Domain::new("accept-pin").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let other_key = aether::wg::generate_keypair().expect("key").public_key;
    let gateway_key = domain.gateway_key.clone();
    for (name, key) in [
        (SERVER_NAME, other_key.as_str()),
        ("elsewhere.example", gateway_key.as_str()),
    ] {
        let refused = prepare_acceptance(
            &domain.vault_path,
            &domain.registry,
            &accept_of(&enrolment.request, Some("http://gateway.invalid")),
            now_unix(),
            &|_| answer(name, key),
        )
        .err()
        .expect("another identity is refused");
        assert_eq!(refused.0, Refusal::HandoffMismatch);
        assert_eq!(
            domain
                .registry
                .load(&enrolment.invitation.invitation_id)
                .expect("record")
                .state,
            astra_operator::enrollment::InvitationState::Issued
        );
    }
    let accepted = prepare_acceptance(
        &domain.vault_path,
        &domain.registry,
        &accept_of(&enrolment.request, Some("http://gateway.invalid")),
        now_unix(),
        &|_| answer(SERVER_NAME, &gateway_key),
    );
    assert!(accepted.is_ok());
}

/// A gateway that does not answer is not a reason to refuse: the acceptance
/// goes on to the key, and stops after the leaves.
#[test]
fn an_unreachable_gateway_still_reaches_the_key() {
    let domain = Domain::new("accept-pin-unreachable").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        )
    };
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let (outcome, published, _) = domain.accept(&enrolment.request, Some(closed), received);
    outcome.expect("abandoned at the key, not refused");
    assert!(!no_key_was_asked(&published));
}

/// At admission the gateway is compared to the pin again: a mismatch stops
/// after the leaves, with the line to admit the peer by hand, and admits nothing.
#[test]
fn a_gateway_that_changed_identity_is_not_admitted_to() {
    let domain = Domain::new("accept-readmit-pin").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let accepted = issued_leaves(&domain, &enrolment);
    let other_key = aether::wg::generate_keypair().expect("key").public_key;
    let mut ceremony = Ceremony::new(
        Id16::new([2; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AcceptEnrollment,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let outcome = admit_or_stop(
        &mut ceremony,
        &mut |status| published.push(status),
        &mut |artifact| artifacts.push(artifact),
        &accepted,
        Some("http://gateway.invalid"),
        &pin_of(&domain, &accepted),
        &|_| answer(SERVER_NAME, &other_key),
    );
    outcome.expect_err("refused");
    assert_eq!(
        published.last().expect("status").refusal,
        Some(Refusal::HandoffMismatch)
    );
    assert_eq!(artifacts.len(), 3);
}

/// Each way the gateway can say no is its own typed refusal.
#[test]
fn a_document_that_cannot_be_drafted_after_admission_is_not_signed() {
    let domain = Domain::new("draft-fails");
    let (_, accepted) = kept_acceptance(&domain, "laptop");
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        )
    };
    let pin = pin_of(&domain, &accepted);
    for gateway in [Some(closed.as_str()), None] {
        let delivery = Delivery {
            endpoint: "198.51.100.7:51820",
            allowed_ips: None,
            ssh_target: None,
            gateway,
        };
        let (refusal, message) =
            draft_delivery(&accepted, &delivery, &pin).expect_err("the gateway cannot be read");
        assert_eq!(refusal, Refusal::DocumentNotSigned);
        assert!(!message.contains("admission.txt"), "{message}");
    }
}

/// What is signed into the document is shown before the touch.
#[test]
fn the_acceptance_manifest_shows_the_signed_routes() {
    let domain = Domain::new("manifest-routes").with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let device = accepted.request.client_wg_public_key.to_base64();
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([2; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AcceptEnrollment,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let _ = resume(
        &mut ceremony,
        &received,
        &mut |status| published.push(status),
        &mut |_| {},
        &domain.vault_path,
        &domain.registry,
        Resume {
            invitation_id: id,
            delivery: Delivery {
                endpoint: "198.51.100.7:51820",
                allowed_ips: Some("10.0.0.0/24"),
                ssh_target: Some("root@10.0.0.1"),
                gateway: Some("http://gateway.invalid"),
            },
            export: None,
        },
        &|_| answer(SERVER_NAME, &domain.gateway_key),
        &|_| Ok(vec![device.clone()]),
    );
    let asked = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("the key is asked for");
    let Some(AstraManifest::EnrollmentAcceptance(manifest)) = &asked.manifest else {
        panic!("an acceptance manifest");
    };
    assert_eq!(manifest.allowed_ips.as_deref(), Some("10.0.0.0/24"));
    assert_eq!(manifest.ssh_target.as_deref(), Some("root@10.0.0.1"));
}

#[test]
fn the_gateway_errors_are_told_apart() {
    use orion_core::gateway_admin::GatewayAdminError as E;
    assert_eq!(gateway_refusal(&E::Forbidden), Refusal::GatewayForbidden);
    assert_eq!(
        gateway_refusal(&E::Refused {
            status: 409,
            reason: None
        }),
        Refusal::GatewayRefused { status: 409 }
    );
    assert_eq!(
        gateway_refusal(&E::Unreachable),
        Refusal::GatewayUnavailable
    );
    assert_eq!(
        gateway_refusal(&E::Invalid("x".into())),
        Refusal::GatewayUnavailable
    );
}

fn accept_of<'a>(
    request: &aether::key_negotiation::EnrollmentRequest,
    gateway: Option<&'a str>,
) -> Accept<'a> {
    // Leaked for the test's length: `Accept` borrows the request text.
    let text: &'static str =
        Box::leak(aether::key_negotiation::encode_request_file(request).into_boxed_str());
    Accept {
        request: text,
        validity_days: 365,
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway,
    }
}

/// What the registry holds for one invitation, byte for byte: the record's
/// state and the accepted file, which a resumption must leave as it found them.
fn registry_snapshot(domain: &Domain, id: &Id16) -> (String, Vec<u8>) {
    let state = format!("{:?}", domain.registry.load(id).expect("record").state);
    let accepted = std::fs::read(
        domain
            .registry
            .directory()
            .join(format!("{}.accepted.json", id.to_hex())),
    )
    .unwrap_or_default();
    (state, accepted)
}

/// An invitation consumed and accepted here: leaves issued and kept, as an
/// interrupted acceptance leaves them.
fn kept_acceptance(
    domain: &Domain,
    name: &str,
) -> (Enrolment, astra_operator::enrollment::AcceptedEnrollment) {
    let enrolment = domain.enrolment(name, true);
    let accepted = issued_leaves(domain, &enrolment);
    domain
        .registry
        .store_accepted(&enrolment.invitation.invitation_id, &accepted)
        .expect("kept");
    (enrolment, accepted)
}

fn resume_of<'a>(id: Id16, gateway: Option<&'a str>) -> Resume<'a> {
    Resume {
        invitation_id: id,
        delivery: Delivery {
            endpoint: "198.51.100.7:51820",
            allowed_ips: None,
            ssh_target: None,
            gateway,
        },
        export: None,
    }
}

fn run_resume(
    domain: &Domain,
    id: Id16,
    gateway: Option<&str>,
    read: GatewayReader<'_>,
    admitted: AdmittedReader<'_>,
) -> (
    Result<(), String>,
    Vec<OperatorStatus>,
    Vec<OperatorArtifact>,
) {
    run_resume_of(domain, resume_of(id, gateway), read, admitted)
}

fn run_resume_of(
    domain: &Domain,
    resume_with: Resume<'_>,
    read: GatewayReader<'_>,
    admitted: AdmittedReader<'_>,
) -> (
    Result<(), String>,
    Vec<OperatorStatus>,
    Vec<OperatorArtifact>,
) {
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([2; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AcceptEnrollment,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let outcome = resume(
        &mut ceremony,
        &received,
        &mut |status| published.push(status),
        &mut |artifact| artifacts.push(artifact),
        &domain.vault_path,
        &domain.registry,
        resume_with,
        read,
        admitted,
    );
    (outcome, published, artifacts)
}

fn nothing_admitted(_: &str) -> Result<Vec<String>, orion_core::gateway_admin::GatewayAdminError> {
    Ok(Vec::new())
}

/// A resumption finishes the delivery around the leaves already kept: it
/// issues nothing, writes nothing to the registry, and with no gateway it
/// stops before any key with the very files the acceptance would have handed
/// over. The vault of these tests holds no issuer key a resumption could use,
/// so a path that issued would not even compile a leaf: the registry state is
/// what proves it.
#[test]
fn a_resumed_enrollment_never_reissues_leaves() {
    let domain = Domain::new("resume-no-reissue").with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let before = registry_snapshot(&domain, &id);

    let gesture_run = {
        let (presses, received) = std::sync::mpsc::channel::<Press>();
        drop(presses);
        let mut published = Vec::new();
        let mut artifacts = Vec::new();
        let outcome = run_enrollment_with(
            Id16::new([2; 16]).expect("id"),
            EnrollmentGesture::Resume {
                invitation_id: id,
                endpoint: "198.51.100.7:51820".into(),
                allowed_ips: None,
                ssh_target: None,
                enrolment_export: None,
            },
            None,
            received,
            &mut |status| published.push(status),
            &mut |artifact| artifacts.push(artifact),
            &domain.vault_path,
            &domain.registry,
        );
        (outcome, published, artifacts)
    };
    let (outcome, published, artifacts) = gesture_run;
    let error = outcome.expect_err("no gateway: the resumption stops");
    assert!(!error.contains("pas encore porté"), "{error}");
    let last = published.last().expect("a status");
    assert_eq!(last.refusal, Some(Refusal::GatewayUnavailable));
    assert_eq!(last.gesture, GestureState::Failed);
    assert!(no_key_was_asked(&published));

    let stem = enrolment.request.request_id.to_hex();
    let names: Vec<&str> = artifacts.iter().map(|a| a.file_name.as_str()).collect();
    assert_eq!(
        names,
        [
            format!("{stem}-client-cert.der"),
            format!("{stem}-client-pq-cert.json"),
            "admission.txt".to_string()
        ]
    );
    // The leaves handed over are the kept ones, not new ones.
    let decoded = DerCertificate::parse(&artifacts[0].contents).expect("base64 of a DER");
    assert_eq!(decoded.as_bytes(), accepted.tls_certificate.as_bytes());

    assert_eq!(registry_snapshot(&domain, &id), before);
    assert!(
        domain
            .registry
            .consume(&id, &enrolment.request, now_unix())
            .is_err(),
        "the invitation stays consumed"
    );
}

/// An invitation the command line accepted has no accepted request here: the
/// resumption says so and asks for nothing.
#[test]
fn resuming_a_cli_acceptance_is_refused_with_a_reason() {
    let domain = Domain::new("resume-cli").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let id = enrolment.invitation.invitation_id;
    domain
        .registry
        .consume(&id, &enrolment.request, now_unix())
        .expect("consumed");
    let (outcome, published, artifacts) = run_resume(
        &domain,
        id,
        None,
        &|_| unreachable_gateway(),
        &nothing_admitted,
    );
    outcome.expect_err("nothing to resume");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::AcceptedElsewhere)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
}

fn unreachable_gateway() -> Result<
    orion_core::enrollment_draft::GatewayMaterial,
    orion_core::gateway_admin::GatewayAdminError,
> {
    Err(orion_core::gateway_admin::GatewayAdminError::Unreachable)
}

#[test]
fn resuming_an_unknown_or_unfinished_invitation_is_refused() {
    let domain = Domain::new("resume-unknown").with_ca_tls();
    let unknown = domain.enrolment("laptop", false);
    let (_, published, artifacts) = run_resume(
        &domain,
        unknown.invitation.invitation_id,
        None,
        &|_| unreachable_gateway(),
        &nothing_admitted,
    );
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::InvitationUnknown)
    );
    assert!(artifacts.is_empty());

    let issued = domain.enrolment("tablet", true);
    let (outcome, published, _) = run_resume(
        &domain,
        issued.invitation.invitation_id,
        None,
        &|_| unreachable_gateway(),
        &nothing_admitted,
    );
    outcome.expect_err("an issued invitation has nothing to resume");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::Internal)
    );
    assert!(no_key_was_asked(&published));
}

/// The pin is checked as in the acceptance, before any key.
#[test]
fn a_resumption_against_another_gateway_is_refused_before_the_key() {
    let domain = Domain::new("resume-pin").with_ca_tls();
    let (enrolment, _) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let other = aether::wg::generate_keypair().expect("keys").public_key;
    let before = registry_snapshot(&domain, &id);
    let (outcome, published, artifacts) = run_resume(
        &domain,
        id,
        Some("http://gateway.invalid"),
        &|_| answer(SERVER_NAME, &other),
        &nothing_admitted,
    );
    outcome.expect_err("refused");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::HandoffMismatch)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
    assert_eq!(registry_snapshot(&domain, &id), before);
}

/// A peer the gateway already lists is not admitted again: the resumption goes
/// straight to the key for the document. Declining there leaves everything as
/// it was.
#[test]
fn an_admitted_peer_goes_straight_to_the_document_key() {
    let domain = Domain::new("resume-admitted").with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let id = enrolment.invitation.invitation_id;
    let device = accepted.request.client_wg_public_key.to_base64();
    let before = registry_snapshot(&domain, &id);

    let (outcome, published, artifacts) = run_resume(
        &domain,
        id,
        Some("http://gateway.invalid"),
        &|_| answer(SERVER_NAME, &domain.gateway_key),
        &|_| Ok(vec![device.clone()]),
    );
    outcome.expect("an abandonment is not a failure");
    let asked = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("the key is asked for");
    assert!(matches!(
        asked.manifest,
        Some(AstraManifest::EnrollmentAcceptance(_))
    ));
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
    assert!(artifacts.is_empty());
    assert_eq!(registry_snapshot(&domain, &id), before);

    let resuming = prepare_resumption(
        &domain.vault_path,
        &domain.registry,
        &resume_of(id, Some("http://gateway.invalid")),
        &|_| answer(SERVER_NAME, &domain.gateway_key),
        &|_| Ok(vec![device.clone()]),
    )
    .map_err(|(refusal, _)| refusal)
    .expect("prepared");
    assert!(resuming.admitted);
    let resuming = prepare_resumption(
        &domain.vault_path,
        &domain.registry,
        &resume_of(id, Some("http://gateway.invalid")),
        &|_| answer(SERVER_NAME, &domain.gateway_key),
        &nothing_admitted,
    )
    .map_err(|(refusal, _)| refusal)
    .expect("prepared");
    assert!(!resuming.admitted);
}

#[test]
fn revoking_an_issued_invitation() {
    let domain = Domain::new("revoke-issued").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let id = enrolment.invitation.invitation_id;
    crate::operator::invitations::revoke(&domain.registry, &id, now_unix()).expect("revoked");
    assert_eq!(
        domain.registry.load(&id).expect("record").state.label(),
        "révoquée"
    );
    // Nothing is left to revoke twice, and a consumed invitation is not revocable.
    assert!(crate::operator::invitations::revoke(&domain.registry, &id, now_unix()).is_err());
}

/// The trust domain of the fixture vault, as a trust block names it.
const DOMAIN_ID_HEX: &str = "03030303030303030303030303030303";

/// The gateway's leaf for `server_name` under `key`, as an export carries it:
/// base64 of its JSON, and the fingerprint the export names it by.
fn leaf_fields(domain: &Domain, server_name: &str, key: &str) -> (String, String) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let json = domain.leaf(server_name, key);
    let leaf: aether::key_negotiation::PqCertificate =
        serde_json::from_str(&json).expect("the leaf is JSON");
    (
        STANDARD.encode(json.as_bytes()),
        leaf.fingerprint().expect("fingerprint"),
    )
}

/// The export `heliosd export-enrolment` writes for the fixture gateway and the
/// peer `device`: the gateway's leaf, and the trust block of the fixture domain.
fn export_of(domain: &Domain, device: &str) -> aether::key_negotiation::EnrollmentExport {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (leaf, fingerprint) = leaf_fields(domain, SERVER_NAME, &domain.gateway_key);
    let trust = orion_core::TrustMaterial {
        trust_domain_id: DOMAIN_ID_HEX.into(),
        ca_epoch: 1,
        ca_pq_public_key: domain.ca_public_key.to_base64(),
        ca_tls_epoch: 1,
        client_tls_ca_der: STANDARD.encode(
            aether::certificates::test_x509::certificate_authority("helios-client-ca-tls")
                .as_bytes(),
        ),
        client_generation: 1,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        astra_authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: "11".repeat(32),
        credential_registry_epoch: 1,
        astra_credential_bindings: Vec::new(),
        astra_service_key_epoch: 1,
        astra_service_public_key: domain.ca_public_key.to_base64(),
    };
    aether::key_negotiation::EnrollmentExport {
        server_name: SERVER_NAME.into(),
        gateway_ca_der: STANDARD.encode(
            aether::certificates::test_x509::certificate_authority("helios-gateway-ca").as_bytes(),
        ),
        gateway_pq_certificate: leaf,
        pq_certificate_sha256: fingerprint,
        wireguard_public_key: domain.gateway_key.clone(),
        negotiation_port: Some(51821),
        gateway_wg_address: "100.64.0.1/24".into(),
        peer_public_key: device.into(),
        address: "100.64.1.2/32".into(),
        address_v6: None,
        trust: serde_json::to_value(&trust).expect("the trust block"),
    }
}

/// The export text for `device`, with `edit` applied to it first.
fn export_text(
    domain: &Domain,
    device: &str,
    edit: impl FnOnce(&mut aether::key_negotiation::EnrollmentExport),
) -> String {
    let mut export = export_of(domain, device);
    edit(&mut export);
    aether::key_negotiation::encode_enrolment_export_file(&export)
}

/// A kept acceptance of `laptop`, and the device's key it was made for.
fn offline_fixture(label: &str) -> (Domain, Id16, String) {
    let domain = Domain::new(label).with_ca_tls();
    let (enrolment, accepted) = kept_acceptance(&domain, "laptop");
    let device = accepted.request.client_wg_public_key.to_base64();
    (domain, enrolment.invitation.invitation_id, device)
}

/// A resumption with no gateway connected, reading `export`.
fn resume_offline(id: Id16, export: &str) -> Resume<'_> {
    Resume {
        invitation_id: id,
        delivery: Delivery {
            endpoint: "198.51.100.7:51820",
            allowed_ips: None,
            ssh_target: None,
            gateway: None,
        },
        export: Some(export),
    }
}

/// Refuses `text` as an offline resumption: a HandoffMismatch, before any key,
/// with the registry and the artifacts untouched. Returns the message.
fn refused_offline(domain: &Domain, id: Id16, text: &str) -> String {
    let before = registry_snapshot(domain, &id);
    let (outcome, published, artifacts) = run_resume_of(
        domain,
        resume_offline(id, text),
        &|_| unreachable_gateway(),
        &nothing_admitted,
    );
    let error = outcome.expect_err("the export is refused");
    assert_eq!(
        published.last().expect("a status").refusal,
        Some(Refusal::HandoffMismatch)
    );
    assert!(no_key_was_asked(&published));
    assert!(artifacts.is_empty());
    assert_eq!(registry_snapshot(domain, &id), before);
    error
}

/// An export read with no gateway draws the same document as the gateway's own
/// material: both go through one builder, and the draft is what gets signed.
#[test]
fn resume_offline_signs_the_same_document_as_online() {
    let (domain, id, device) = offline_fixture("resume-offline-document");
    let accepted = domain
        .registry
        .accepted(&id)
        .expect("readable")
        .expect("kept");
    let pin = pin_of(&domain, &accepted);
    // One export, built once: each call draws fresh CA certificates.
    let export = export_of(&domain, &device);
    let text = aether::key_negotiation::encode_enrolment_export_file(&export);
    let resuming = prepare_resumption(
        &domain.vault_path,
        &domain.registry,
        &resume_offline(id, &text),
        &|_| unreachable_gateway(),
        &nothing_admitted,
    )
    .map_err(|(refusal, _)| refusal)
    .expect("prepared");
    assert!(resuming.admitted);
    assert!(resuming.gateway_error.is_none());
    let (material, admission) = resuming.offline.expect("the export is read");

    let delivery = Delivery {
        endpoint: "198.51.100.7:51820",
        allowed_ips: None,
        ssh_target: None,
        gateway: None,
    };
    let now = now_unix();
    let from_export = draft_from_material(&accepted, &delivery, &pin, material, admission, now)
        .expect("drafted from the export");

    // The gateway's own values, as the online route serves them: the same ones
    // the export was written from.
    let online_material = GatewayMaterial {
        server_name: export.server_name.clone(),
        gateway_ca_der: export.gateway_ca_der.clone(),
        gateway_pq_certificate: export.gateway_pq_certificate.clone(),
        wireguard_public_key: export.wireguard_public_key.clone(),
        pq_certificate_sha256: export.pq_certificate_sha256.clone(),
        negotiation_port: export.negotiation_port,
    };
    let online_admission = Admission {
        address: export.address.clone(),
        address_v6: None,
        heliosd_url: Some(format!("http://100.64.0.1:{}", aether::API_PORT)),
        trust: Some(serde_json::from_value(export.trust.clone()).expect("the trust block")),
    };
    let from_gateway = draft_from_material(
        &accepted,
        &delivery,
        &pin,
        online_material,
        online_admission,
        now,
    )
    .expect("drafted from the gateway");
    assert_eq!(
        from_export.to_json().expect("json"),
        from_gateway.to_json().expect("json")
    );
}

/// With a verified export and no gateway, the ceremony reaches the key, and
/// only then. A byte order mark, as Notepad saves it, is read like any other.
#[test]
fn resume_offline_asks_for_the_key_only_after_every_check() {
    let (domain, id, device) = offline_fixture("resume-offline-key");
    let text = format!("\u{feff}{}", export_text(&domain, &device, |_| {}));
    let before = registry_snapshot(&domain, &id);
    let (outcome, published, artifacts) = run_resume_of(
        &domain,
        resume_offline(id, &text),
        &|_| unreachable_gateway(),
        &nothing_admitted,
    );
    let asked = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("the key is asked for");
    assert!(matches!(
        asked.manifest,
        Some(AstraManifest::EnrollmentAcceptance(_))
    ));
    outcome.expect("an abandonment is not a failure");
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
    assert!(artifacts.is_empty());
    assert_eq!(registry_snapshot(&domain, &id), before);
}

/// An export taken on another gateway, or naming another one, is refused.
#[test]
fn resume_offline_refuses_an_export_of_another_gateway() {
    let (domain, id, device) = offline_fixture("resume-offline-gateway");
    let other = aether::wg::generate_keypair().expect("keys").public_key;
    for text in [
        export_text(&domain, &device, |export| {
            export.wireguard_public_key = other.clone();
        }),
        export_text(&domain, &device, |export| {
            export.server_name = "elsewhere.example".into();
        }),
    ] {
        refused_offline(&domain, id, &text);
    }
}

/// An export of the right gateway for another peer (the wrong key was
/// exported) is refused before any key, by name.
#[test]
fn resume_offline_refuses_an_export_of_another_peer() {
    let (domain, id, _) = offline_fixture("resume-offline-peer");
    let other = aether::wg::generate_keypair().expect("keys").public_key;
    let error = refused_offline(&domain, id, &export_text(&domain, &other, |_| {}));
    assert!(error.contains("un autre poste"), "{error}");
}

/// A trust block naming another domain, or another CA-PQ, is refused before
/// any key.
#[test]
fn resume_offline_refuses_an_export_of_another_domain() {
    let (domain, id, device) = offline_fixture("resume-offline-domain");
    let other_ca = aether::certificates::encoding::generate_ml_dsa_87_keypair()
        .expect("CA-PQ")
        .1
        .to_base64();
    for text in [
        export_text(&domain, &device, |export| {
            export.trust["trust_domain_id"] = "04".repeat(16).into();
        }),
        export_text(&domain, &device, |export| {
            export.trust["ca_pq_public_key"] = other_ca.clone().into();
        }),
    ] {
        let error = refused_offline(&domain, id, &text);
        assert!(error.contains("un autre domaine"), "{error}");
    }
}

/// The gateway's leaf is verified under the domain's CA-PQ, and its fingerprint
/// must be the one the export names: anything else is refused before any key.
#[test]
fn resume_offline_refuses_a_gateway_leaf_that_does_not_verify() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (domain, id, device) = offline_fixture("resume-offline-leaf");
    let (other_leaf, other_fingerprint) =
        leaf_fields(&domain, "elsewhere.example", &domain.gateway_key);
    for text in [
        export_text(&domain, &device, |export| {
            export.gateway_pq_certificate = other_leaf.clone();
            export.pq_certificate_sha256 = other_fingerprint.clone();
        }),
        export_text(&domain, &device, |export| {
            export.pq_certificate_sha256 = "00".repeat(32);
        }),
        export_text(&domain, &device, |export| {
            export.gateway_pq_certificate = STANDARD.encode("not a leaf");
        }),
    ] {
        refused_offline(&domain, id, &text);
    }
}

/// Whatever is not a `heliosd export-enrolment` export is refused with the
/// window's sentence, verbatim, before any key.
#[test]
fn resume_offline_refuses_an_unreadable_export() {
    let (domain, id, device) = offline_fixture("resume-offline-unreadable");
    let good = export_text(&domain, &device, |_| {});
    assert!(good.contains("helios-enrolment-export-v1"), "{good}");
    let foreign = good.replace("helios-enrolment-export-v1", "helios-enrolment-export-v0");
    for text in [
        String::new(),
        "{}".to_string(),
        "not an export".to_string(),
        foreign,
    ] {
        let error = refused_offline(&domain, id, &text);
        assert_eq!(
            error,
            "Ce fichier n'est pas un export d'enrôlement de `heliosd export-enrolment`."
        );
    }
}

/// With a tunnel up, the gateway is read and the export is ignored, even when
/// it is unreadable: the online path is unchanged.
#[test]
fn resume_online_ignores_the_export() {
    let (domain, id, device) = offline_fixture("resume-online-export");
    let reads = std::cell::Cell::new(0);
    let read = |_: &str| {
        reads.set(reads.get() + 1);
        answer(SERVER_NAME, &domain.gateway_key)
    };
    let admitted_device = device.clone();
    let (outcome, published, artifacts) = run_resume_of(
        &domain,
        Resume {
            invitation_id: id,
            delivery: Delivery {
                endpoint: "198.51.100.7:51820",
                allowed_ips: None,
                ssh_target: None,
                gateway: Some("http://gateway.invalid"),
            },
            export: Some("not an export"),
        },
        &read,
        &|_| Ok(vec![admitted_device.clone()]),
    );
    assert_eq!(reads.get(), 1, "the gateway is read");
    outcome.expect("an abandonment is not a failure");
    assert!(published
        .iter()
        .any(|status| matches!(status.gesture, GestureState::AwaitingKey { .. })));
    assert!(published
        .iter()
        .all(|status| status.refusal != Some(Refusal::HandoffMismatch)));
    assert!(artifacts.is_empty());
}

/// The line to hand over names the export command after the admission, and the
/// sentence that says what to do with its file.
#[test]
fn admission_artifact_names_the_export_command() {
    let domain = Domain::new("admission-export").with_ca_tls();
    let enrolment = domain.enrolment("laptop", true);
    let accepted = issued_leaves(&domain, &enrolment);
    let (_, _, artifacts) = keep_and_admit_on(&domain, &accepted, None);
    let text = artifacts
        .iter()
        .find(|artifact| artifact.file_name == "admission.txt")
        .expect("the line is handed over")
        .contents
        .clone();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(
        lines[1],
        format!(
            "heliosd export-enrolment --public-key {} > laptop.enrolment.json",
            enrolment.request.client_wg_public_key.to_base64()
        )
    );
    assert_eq!(
        lines[2],
        "Ajouter --admin à la première ligne pour le premier administrateur, puis « Reprendre » avec ce fichier."
    );
}
