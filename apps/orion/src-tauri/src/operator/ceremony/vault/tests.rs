//! The vault and domain gestures, up to the first key: every refusal they
//! can name before a press, and the manifests they show first.
//!
//! Each test drops its press sender, so a gesture that reaches a key prompt
//! ends there as an abandonment: the platform key cannot be faked here, and
//! the key sequences themselves are astra-operator's tests.

use super::*;
use crate::operator::ceremony::run;
use crate::operator::ceremony::tests::{no_key_was_asked, Domain};
use aether::certificates::operator_session::OperationKind;

/// Runs one vault gesture with the presses already abandoned.
fn run_vault_gesture(
    gesture: crate::operator::VaultGesture,
    vault_path: &Path,
) -> (
    Result<(), String>,
    Vec<OperatorStatus>,
    Vec<OperatorArtifact>,
) {
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let outcome = run_vault(
        Id16::new([5; 16]).expect("id"),
        gesture,
        received,
        &mut |status| published.push(status),
        &mut |artifact| artifacts.push(artifact),
        vault_path,
    );
    (outcome, published, artifacts)
}

fn creation() -> crate::operator::VaultGesture {
    crate::operator::VaultGesture::CreateDomain {
        rp_id: "astra.example".into(),
        // A trailing `/`, as an operator may type it.
        authority_url: "https://astra.example/".into(),
        first_label: "quotidienne".into(),
        second_label: "coffre-fort".into(),
    }
}

/// An empty folder of its own, removed when the test ends.
struct Folder(std::path::PathBuf);

impl Folder {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "orion-vault-{label}-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("folder");
        Self(path)
    }

    fn vault_path(&self) -> std::path::PathBuf {
        self.0.join(crate::operator::location::VAULT_FILE_NAME)
    }

    fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.0)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn refused_before_the_key(published: &[OperatorStatus], refusal: Refusal) {
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(refusal));
    assert!(no_key_was_asked(published));
    assert!(last.keys.is_empty());
}

fn first_slot_id(domain: &Domain) -> String {
    let vault = astra_operator::store::load(&domain.vault_path).expect("vault");
    Id16::new(vault.slots[0].slot_id).expect("slot").to_hex()
}

impl Domain {
    /// Forgets the gateway on the relay, as a relay written before the
    /// gateway was known holds it.
    fn without_gateway(self) -> Self {
        let relay_path = astra_operator::handoff::path_beside(&self.vault_path);
        let mut relay = astra_operator::handoff::load(&relay_path).expect("relay");
        relay.gateway_wg_public_key = None;
        relay.server_name = None;
        astra_operator::handoff::save(&relay_path, &relay).expect("save relay");
        self
    }

    /// The credential document of a finished domain: one active row per
    /// slot, signed by this domain's `CA-PQ` for the gateway the relay names.
    fn with_document(self) -> Self {
        use aether::certificates::approval::{
            AstraCredentialBinding, CredentialRegistry, CredentialState,
        };
        use aether::certificates::encoding::{MlDsa87Signature, WireGuardKey};

        let vault = astra_operator::store::load(&self.vault_path).expect("vault");
        let gateway = WireGuardKey::parse(&self.gateway_key).expect("gateway key");
        let bindings = vault
            .slots
            .iter()
            .map(|slot| {
                AstraCredentialBinding {
                    format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                    credential_id: slot.credential_id().expect("credential"),
                    credential_public_key: cose_es256_key(),
                    aaguid: [0; 16],
                    trust_domain_id: vault.trust_domain_id,
                    gateway_wg_public_key: gateway,
                    state: CredentialState::Active,
                    credential_epoch: 1,
                    credential_registry_epoch: 1,
                    ca_epoch: 1,
                    created_at: now_unix(),
                    ca_pq_signature: MlDsa87Signature::placeholder(),
                }
                .sign(&self.ca_private_key)
                .expect("signed under CA-PQ")
            })
            .collect();
        let document = CredentialRegistry {
            trust_domain_id: vault.trust_domain_id,
            gateway_wg_public_key: gateway,
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings,
        };
        astra_operator::credentials::save(
            &astra_operator::credentials::path_beside(&self.vault_path),
            &document,
        )
        .expect("save document");
        self
    }

    /// Fills the vault up to its ceiling with stand-in keys.
    fn full(self) -> Self {
        use astra_operator::vault::{SlotEnrolment, SlotRole, SlotSecret, MAX_SLOTS};

        let mut vault = astra_operator::store::load(&self.vault_path).expect("vault");
        let mut next = 2u8;
        while vault.slots.len() < MAX_SLOTS {
            vault
                .add_slot(
                    &[1; 64],
                    &SlotSecret::new(vec![1; 32]),
                    SlotEnrolment {
                        role: SlotRole::Recovery,
                        label: format!("clé {next}"),
                        credential_id: vec![next; 64],
                        credential_public_key: vec![0xa5, next],
                        aaguid: [next; 16],
                        enrolled_at: 2_000,
                    },
                    &SlotSecret::new(vec![next; 32]),
                )
                .expect("slot added");
            next += 1;
        }
        astra_operator::store::save(&self.vault_path, &vault).expect("save vault");
        self
    }
}

/// A COSE ES256 public key, as an authenticator publishes one: the
/// document's own verification parses it.
fn cose_es256_key() -> Vec<u8> {
    let mut key = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[3u8; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[5u8; 32]);
    key
}

/// A vault is never replaced: the creation stops before any key.
#[test]
fn a_creation_over_an_existing_vault_asks_for_no_key() {
    let domain = Domain::new("create-existing");
    let before = std::fs::read(&domain.vault_path).expect("vault bytes");
    let (outcome, published, _) = run_vault_gesture(creation(), &domain.vault_path);
    outcome.expect_err("an existing vault is refused");
    refused_before_the_key(&published, Refusal::VaultExists);
    assert_eq!(
        std::fs::read(&domain.vault_path).expect("vault bytes"),
        before
    );
}

/// A folder that is not there is a mistyped choice, not one to create.
#[test]
fn a_creation_in_a_missing_folder_asks_for_no_key() {
    let folder = Folder::new("create-missing");
    let missing = folder.0.join("absent").join("authority-vault.json");
    let (outcome, published, _) = run_vault_gesture(creation(), &missing);
    outcome.expect_err("a missing folder is refused");
    refused_before_the_key(&published, Refusal::LocationUnavailable);
    assert!(!folder.0.join("absent").exists());
}

/// The operator can walk away at the first key: nothing has been written.
#[test]
fn abandoning_before_the_first_key_creates_nothing() {
    let folder = Folder::new("create-abandon");
    let (outcome, published, artifacts) = run_vault_gesture(creation(), &folder.vault_path());
    outcome.expect("an abandonment is not a failure");
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Cancelled);
    assert!(last.keys.is_empty());
    assert!(artifacts.is_empty());
    assert!(folder.is_empty());
}

/// What the domain will answer as is shown before the first key registers.
#[test]
fn the_creation_manifest_shows_what_will_be_fixed() {
    let folder = Folder::new("create-manifest");
    let (_, published, _) = run_vault_gesture(creation(), &folder.vault_path());
    let offered = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked for");
    assert_eq!(
        offered.gesture,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::RegisterKey,
        }
    );
    assert_eq!(offered.operation, OperationKind::CreateDomain);
    match offered.manifest.as_ref().expect("manifest shown first") {
        AstraManifest::DomainCreation(manifest) => {
            assert_eq!(manifest.rp_id, "astra.example");
            assert_eq!(manifest.authority_url, "https://astra.example");
            assert_eq!(manifest.first_label, "quotidienne");
            assert_eq!(manifest.second_label, "coffre-fort");
        }
        other => panic!("{other:?}"),
    }
}

/// A vault at its ceiling takes no other key, and says so before a press.
#[test]
fn a_full_vault_refuses_an_addition_before_the_key() {
    let domain = Domain::new("add-full").full();
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::AddKey {
            label: "neuve".into(),
            role: crate::operator::KeyRole::Recovery,
        },
        &domain.vault_path,
    );
    outcome.expect_err("a full vault is refused");
    refused_before_the_key(&published, Refusal::VaultFull);
}

/// A document the next gesture could not re-sign is found before the press,
/// not after the new key registered.
#[test]
fn an_addition_whose_document_cannot_be_resigned_asks_for_no_key() {
    use aether::certificates::approval::CredentialRegistry;
    use aether::certificates::encoding::WireGuardKey;

    let domain = Domain::new("add-document");
    let vault = astra_operator::store::load(&domain.vault_path).expect("vault");
    astra_operator::credentials::save(
        &astra_operator::credentials::path_beside(&domain.vault_path),
        &CredentialRegistry {
            trust_domain_id: vault.trust_domain_id,
            gateway_wg_public_key: WireGuardKey::parse(&domain.gateway_key).expect("key"),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        },
    )
    .expect("save document");
    let domain = domain.without_gateway();
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::AddKey {
            label: "neuve".into(),
            role: crate::operator::KeyRole::Primary,
        },
        &domain.vault_path,
    );
    outcome.expect_err("the document cannot follow the vault");
    refused_before_the_key(&published, Refusal::GatewayIdentityMissing);
}

/// The vault keeps at least two keys: the removal is refused before a press.
#[test]
fn removing_down_to_one_key_is_refused_before_the_key() {
    let domain = Domain::new("remove-minimum");
    let slot_id = first_slot_id(&domain);
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::RemoveKey { slot_id },
        &domain.vault_path,
    );
    outcome.expect_err("the last keys are kept");
    refused_before_the_key(&published, Refusal::MinimumKeys);
}

/// A key's state lives in a document that names the gateway: without it,
/// there is nothing to sign.
#[test]
fn marking_without_the_gateway_is_refused_before_the_key() {
    let domain = Domain::new("mark-no-gateway").without_gateway();
    let slot_id = first_slot_id(&domain);
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::MarkKey {
            slot_id,
            lost: true,
        },
        &domain.vault_path,
    );
    outcome.expect_err("no gateway, no document");
    refused_before_the_key(&published, Refusal::GatewayIdentityMissing);
}

/// A rotation applies the vault it signed over the one in place: a key slot changed
/// meanwhile would be undone, a removed key regaining access. Refused before the key,
/// with the vault as it was.
#[test]
fn key_slot_gestures_are_refused_while_a_rotation_is_in_flight() {
    use crate::operator::{KeyRole, VaultGesture};

    let domain = Domain::new("rotation-in-flight");
    let slot_id = first_slot_id(&domain);
    std::fs::write(
        astra_operator::rotation_journal::path_beside(&domain.vault_path),
        b"illisible",
    )
    .expect("journal");
    let vault_bytes = std::fs::read(&domain.vault_path).expect("vault");

    for gesture in [
        VaultGesture::AddKey {
            label: "neuve".into(),
            role: KeyRole::Recovery,
        },
        VaultGesture::RemoveKey {
            slot_id: slot_id.clone(),
        },
        VaultGesture::MarkKey {
            slot_id: slot_id.clone(),
            lost: true,
        },
    ] {
        let (outcome, published, _) = run_vault_gesture(gesture, &domain.vault_path);
        outcome.expect_err("refused while a rotation is in flight");
        refused_before_the_key(&published, Refusal::RotationInFlight);
        assert_eq!(
            std::fs::read(&domain.vault_path).expect("vault"),
            vault_bytes
        );
    }
}

/// A domain carrying its CA-TLS and a document for every key has nothing
/// left to issue.
#[test]
fn a_finished_domain_has_nothing_to_finalize() {
    let domain = Domain::new("finalize-complete")
        .with_ca_tls()
        .with_document();
    let (outcome, published, artifacts) = run_vault_gesture(
        crate::operator::VaultGesture::FinalizeDomain,
        &domain.vault_path,
    );
    outcome.expect_err("nothing to finalize");
    refused_before_the_key(&published, Refusal::DomainComplete);
    assert!(artifacts.is_empty());
}

/// The vault gestures name their own ceremony: a locator naming one of them
/// is refused, not run.
#[test]
fn a_locator_does_not_open_a_vault_gesture() {
    let folder = Folder::new("locator");
    for kind in [
        OperationKind::CreateDomain,
        OperationKind::AddKey,
        OperationKind::RemoveKey,
        OperationKind::MarkKey,
        OperationKind::FinalizeDomain,
        OperationKind::IssueGatewayBootstrap,
    ] {
        let (presses, received) = std::sync::mpsc::channel::<Press>();
        drop(presses);
        let mut published = Vec::new();
        let outcome = run(
            Id16::new([1; 16]).expect("id"),
            OperationLocator {
                kind,
                operation_id: None,
            },
            received,
            &mut |status| published.push(status),
            &folder.vault_path(),
        );
        let error = outcome.expect_err("refused");
        assert!(!error.contains("pas encore portée"), "{kind:?}: {error}");
        refused_before_the_key(&published, Refusal::Internal);
    }
    assert!(folder.is_empty());
}

/// A slot the vault does not hold means the window showed another vault.
#[test]
fn an_unknown_slot_is_refused_before_the_key() {
    let domain = Domain::new("remove-unknown");
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::RemoveKey {
            slot_id: "0123456789abcdef0123456789abcdef".into(),
        },
        &domain.vault_path,
    );
    outcome.expect_err("an unknown slot is refused");
    refused_before_the_key(&published, Refusal::HandoffMismatch);
}

/// The addition names the key it will register, then asks first for a key
/// the vault already opens for.
#[test]
fn an_addition_shows_its_manifest_before_the_key() {
    let domain = Domain::new("add-manifest");
    let (outcome, published, _) = run_vault_gesture(
        crate::operator::VaultGesture::AddKey {
            label: " secours ".into(),
            role: crate::operator::KeyRole::Recovery,
        },
        &domain.vault_path,
    );
    outcome.expect("an abandonment is not a failure");
    let offered = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked for");
    assert_eq!(
        offered.gesture,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::OpenVault,
        }
    );
    match offered.manifest.as_ref().expect("manifest shown first") {
        AstraManifest::KeyAddition(manifest) => {
            assert_eq!(manifest.label, "secours");
            assert_eq!(manifest.role, "recuperation");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
}

/// A key that refused, or a platform call that failed, is `KeyDeclined`; a
/// failure after the key answered is not the key's, and is `Internal`.
#[test]
fn only_a_key_failure_reads_as_a_declined_key() {
    use astra_operator::gestures::GestureError;

    let declined = [
        anyhow::Error::from(GestureError::Authenticator(AuthenticatorError::NoPin)),
        anyhow::Error::from(AuthenticatorError::UnknownCredential).context("enregistrement"),
        anyhow::Error::from(GestureError::Authenticator(AuthenticatorError::Device(
            "délai".into(),
        )))
        .context("création du coffre"),
    ];
    for error in &declined {
        assert_eq!(refusal_of(error), Refusal::KeyDeclined, "{error:#}");
    }
    let internal = [
        anyhow::anyhow!("écriture du coffre impossible"),
        anyhow::Error::from(GestureError::Anchors("tirage".into())),
        anyhow::anyhow!("signature du document").context("ajout de la clé"),
    ];
    for error in &internal {
        assert_eq!(refusal_of(error), Refusal::Internal, "{error:#}");
    }
    assert_eq!(
        refusal_of(&anyhow::Error::from(SetupRefusal::KeyBeingRemoved).context("retrait")),
        Refusal::KeyBeingRemoved
    );
    assert_eq!(
        refusal_of(&anyhow::Error::from(SetupRefusal::UnknownSlot)),
        Refusal::HandoffMismatch
    );
}

/// A gateway's bootstrap request, signed by a key of its own, as the text the
/// window sends.
fn bootstrap_request(server_name: &str) -> (String, BootstrapPlan) {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
    use aether::certificates::gateway::GatewayBootstrapRequest;

    let (private_key, public_key) = generate_ml_dsa_87_keypair().expect("gateway key");
    let wireguard = aether::wg::generate_keypair().expect("wireguard key");
    let request = GatewayBootstrapRequest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: aether::certificates::encoding::WireGuardKey::parse(
            &wireguard.public_key,
        )
        .expect("key"),
        server_name: server_name.into(),
        ml_dsa_87_public_key: public_key,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&private_key)
    .expect("signed");
    let text = serde_json::to_string(&request).expect("request text");
    let plan = BootstrapPlan {
        request,
        records_identity: true,
        issues_ca_tls: true,
        issues_credentials: true,
    };
    (text, plan)
}

fn opening(credential: u8) -> Opened {
    Opened {
        credential_id: vec![credential; 64],
        secret: astra_operator::vault::SlotSecret::new(vec![credential; 32]),
    }
}

/// A request that does not parse, or does not verify, is refused before any
/// key, and nothing is written.
#[test]
fn a_wrong_request_is_refused_before_any_key() {
    let domain = Domain::new("bootstrap-wrong");
    let before = std::fs::read_dir(domain.vault_path.parent().expect("folder"))
        .expect("folder")
        .count();
    let (text, _) = bootstrap_request("gateway.example");
    let forged = text.replace("gateway.example", "gateway.other");
    for request in ["not a request".to_string(), forged] {
        let (outcome, published, artifacts) = run_vault_gesture(
            crate::operator::VaultGesture::BootstrapGateway { request },
            &domain.vault_path,
        );
        outcome.expect_err("a wrong request is refused");
        refused_before_the_key(&published, Refusal::BootstrapRequestInvalid);
        assert!(artifacts.is_empty());
    }
    let after = std::fs::read_dir(domain.vault_path.parent().expect("folder"))
        .expect("folder")
        .count();
    assert_eq!(before, after);
}

/// A key presented twice is one approval: refused at the second press, with
/// nothing signed nor written.
#[test]
fn the_second_key_must_be_another_credential() {
    let domain = Domain::new("bootstrap-repeated");
    let relay_path = astra_operator::handoff::path_beside(&domain.vault_path);
    let relay_before = std::fs::read(&relay_path).expect("relay");
    let (_, plan) = bootstrap_request("gateway.example");

    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([5; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::IssueGatewayBootstrap,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let mut publish = |status| published.push(status);
    let mut run = VaultRun {
        ceremony: &mut ceremony,
        presses: &received,
        publish: &mut publish,
        vault_path: &domain.vault_path,
    };
    run.answered(1, "quotidienne");
    run.answered(2, "secours");
    let outcome = run.issue_bootstrap(&plan, &opening(1), &opening(1), &mut |artifact| {
        artifacts.push(artifact)
    });

    outcome.expect_err("one key twice is refused");
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(Refusal::KeyRepeated));
    assert!(published
        .iter()
        .all(|status| status.gesture != GestureState::Signing));
    assert_eq!(last.keys.len(), 1);
    assert_eq!(last.keys[0].slot, "1");
    assert_eq!(last.keys[0].label, "quotidienne");
    assert!(artifacts.is_empty());
    assert_eq!(std::fs::read(&relay_path).expect("relay"), relay_before);
    assert!(!astra_operator::bootstrap::path_beside(&domain.vault_path).exists());
}

/// The leaf is handed over first, with its fingerprint, then the `CA-TLS`
/// when one was issued.
#[test]
fn the_bootstrap_deposits_the_leaf_and_the_ca_tls() {
    use astra_operator::vault_gestures::Finalized;

    let mut artifacts = Vec::new();
    let failed = deposit_bootstrapped(
        Bootstrapped {
            leaf_json: "{\"leaf\":true}".into(),
            leaf_fingerprint: "fp".into(),
            finalization: Finalization::Issued(Finalized {
                ca_tls_pem: Some("-----BEGIN CERTIFICATE-----".into()),
                credentials_epoch: Some(1),
            }),
        },
        &mut |artifact| artifacts.push(artifact),
    );
    assert_eq!(failed, None);
    let names: Vec<&str> = artifacts
        .iter()
        .map(|artifact| artifact.file_name.as_str())
        .collect();
    assert_eq!(names, ["gateway-bootstrap-certificate.json", "ca-tls.pem"]);
    assert_eq!(artifacts[0].contents, "{\"leaf\":true}");
    assert_eq!(artifacts[0].fingerprint.as_deref(), Some("fp"));
    assert_eq!(artifacts[1].fingerprint, None);
    assert!(artifacts
        .iter()
        .all(|artifact| artifact.encoding == ArtifactEncoding::Text));

    // A domain that already carried its CA-TLS deposits the leaf alone.
    let mut artifacts = Vec::new();
    let failed = deposit_bootstrapped(
        Bootstrapped {
            leaf_json: "{}".into(),
            leaf_fingerprint: "fp".into(),
            finalization: Finalization::NotNeeded,
        },
        &mut |artifact| artifacts.push(artifact),
    );
    assert_eq!(failed, None);
    assert_eq!(artifacts.len(), 1);
}

/// Only the bootstrap leaf carries a fingerprint to the window: every other
/// file is serialized as before, without the field.
#[test]
fn only_the_leaf_carries_a_fingerprint_to_the_window() {
    let leaf = OperatorArtifact {
        file_name: "gateway-bootstrap-certificate.json".into(),
        contents: "{}".into(),
        encoding: ArtifactEncoding::Text,
        fingerprint: Some("fp".into()),
    };
    let encoded = serde_json::to_value(&leaf).expect("leaf");
    assert_eq!(encoded["fingerprint"], "fp");
    let other = OperatorArtifact {
        fingerprint: None,
        file_name: "ca-tls.pem".into(),
        ..leaf
    };
    let encoded = serde_json::to_value(&other).expect("other");
    assert!(encoded.get("fingerprint").is_none());
}

/// A finalization that failed after the leaf still hands the leaf over, then
/// ends the ceremony as `Internal`: « Finaliser le domaine » resumes the rest.
#[test]
fn a_late_finalization_failure_still_hands_over_the_leaf() {
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([5; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::IssueGatewayBootstrap,
            operation_id: None,
        },
    );
    let vault_path = Path::new("unused-authority-vault.json");
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let mut publish = |status| published.push(status);
    let mut run = VaultRun {
        ceremony: &mut ceremony,
        presses: &received,
        publish: &mut publish,
        vault_path,
    };
    let outcome = run.conclude_bootstrap(
        Bootstrapped {
            leaf_json: "{\"leaf\":true}".into(),
            leaf_fingerprint: "fp".into(),
            finalization: Finalization::Failed("écriture du document".into()),
        },
        &mut |artifact| artifacts.push(artifact),
    );

    let message = outcome.expect_err("the domain is not finished");
    assert!(message.contains("écriture du document"));
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(Refusal::Internal));
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].file_name, "gateway-bootstrap-certificate.json");
    assert_eq!(artifacts[0].fingerprint.as_deref(), Some("fp"));
}

/// What the bootstrap adds to the checks a vault gesture names.
#[test]
fn refusals_of_the_bootstrap_are_named() {
    for (setup, window) in [
        (SetupRefusal::OtherGateway, Refusal::OtherGateway),
        (
            SetupRefusal::BootstrapRequestInvalid,
            Refusal::BootstrapRequestInvalid,
        ),
        (SetupRefusal::SignerRevoked, Refusal::SignerRevoked),
        (SetupRefusal::PlanChanged, Refusal::DomainChanged),
    ] {
        assert_eq!(refusal_of_setup(setup), window);
        assert_eq!(refusal_of(&anyhow::Error::from(setup)), window);
    }
}

/// The bootstrap names the gateway and what it will issue, then asks first
/// for a key the vault opens for.
#[test]
fn a_bootstrap_shows_its_manifest_before_the_key() {
    use astra_operator::bootstrap::{bootstrap_plan, BOOTSTRAP_LEAF_DAYS};

    let domain = Domain::new("bootstrap-manifest").full().without_gateway();
    let (text, _) = bootstrap_request("gateway.example");
    let plan = bootstrap_plan(&domain.vault_path, &text).expect("a plan");
    assert!(plan.records_identity);

    let (outcome, published, artifacts) = run_vault_gesture(
        crate::operator::VaultGesture::BootstrapGateway { request: text },
        &domain.vault_path,
    );
    outcome.expect("an abandonment is not a failure");
    assert!(artifacts.is_empty());
    let offered = published
        .iter()
        .find(|status| matches!(status.gesture, GestureState::AwaitingKey { .. }))
        .expect("a key is asked for");
    assert_eq!(
        offered.gesture,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::OpenVault,
        }
    );
    match offered.manifest.as_ref().expect("manifest shown first") {
        AstraManifest::GatewayBootstrap(manifest) => {
            assert_eq!(manifest.leaf_days, BOOTSTRAP_LEAF_DAYS);
            assert_eq!(manifest.ca_tls_days, gestures::CA_TLS_DAYS);
            assert_eq!(manifest.issues_ca_tls, plan.issues_ca_tls);
            assert_eq!(manifest.issues_credentials, plan.issues_credentials);
            assert_eq!(manifest.request_fingerprint, plan.request.fingerprint());
            assert_eq!(manifest.server_name, plan.request.server_name);
            assert_eq!(
                manifest.gateway_wg_public_key,
                plan.request.gateway_wg_public_key
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        published.last().expect("a status").gesture,
        GestureState::Cancelled
    );
}
