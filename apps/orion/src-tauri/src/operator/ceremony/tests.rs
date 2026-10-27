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
        })
        .expect("sent");
    presses
        .send(Press {
            action: OperatorAction::Continue,
            revision: offered.revision,
            owner: 7,
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
    let outcome = run_with_vault(
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

/// A vault of this machine's making, the domain relay beside it naming one
/// gateway, and a registry directory of its own.
struct Domain {
    directory: std::path::PathBuf,
    vault_path: std::path::PathBuf,
    registry: InvitationRegistry,
    ca_private_key: zeroize::Zeroizing<Vec<u8>>,
    ca_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    gateway_key: String,
}

const SERVER_NAME: &str = "gateway.example";

impl Domain {
    fn new(label: &str) -> Self {
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
        Some(Refusal::GatewayUnavailable)
    );
    assert!(domain.registry_is_empty());
}
