//! The delegation of Astra's issuer, offline form: every refusal it names
//! before a press, and what it hands over once the vault is open.
//!
//! The campaign form needs the origin to fetch its campaign from, and is not
//! run here: its verification, its one-key approval and its restricted
//! opening are astra-operator's tests. Each test that runs a ceremony drops
//! its press sender, so a gesture that reaches a key prompt ends there as an
//! abandonment: the ceremony connects the platform transport, which no test
//! can stand in for. The signature after the key is run on the opening the
//! key would have released, from a domain [`OneKey`] created.

use super::*;
use crate::operator::ceremony::run;
use crate::operator::ceremony::tests::{no_key_was_asked, Domain};
use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87PublicKey, TrustDomainId};
use aether::certificates::operator_session::OperationKind;
use aether_fido::authenticator::{
    Approval, ApprovedOpening, AuthenticatorError, CredentialSubject, Registration, SALT_LEN,
};
use astra_operator::gestures::NewAuthority;
use astra_operator::signing::IssuerDelegationRequest;
use astra_operator::vault::{SlotRole, SlotSecret};

/// Runs one delegation gesture with the presses already abandoned.
fn run_issuer_gesture(
    gesture: crate::operator::IssuerGesture,
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
    let outcome = run_issuer(
        Id16::new([6; 16]).expect("id"),
        gesture,
        received,
        &mut |status| published.push(status),
        &mut |artifact| artifacts.push(artifact),
        vault_path,
    );
    (outcome, published, artifacts)
}

fn offline(request: String) -> crate::operator::IssuerGesture {
    crate::operator::IssuerGesture::AuthorizeIssuerOffline { request }
}

fn refused_before_the_key(published: &[OperatorStatus], refusal: Refusal) {
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(refusal));
    assert!(no_key_was_asked(published));
    assert!(last.keys.is_empty());
}

/// What `astra issuer request` writes for the domain `trust_domain_id`:
/// fresh issuer keys, their public halves.
fn delegation_request(trust_domain_id: TrustDomainId) -> String {
    let (_, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer keypair");
    let csr = aether::certificates::x509::client_rotation_csr("astra delegated issuer 1")
        .expect("csr")
        .csr;
    serde_json::to_string_pretty(&IssuerDelegationRequest {
        trust_domain_id: trust_domain_id.to_hex(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public.to_base64(),
        tls_intermediate_csr: csr.to_base64(),
    })
    .expect("request")
}

/// The domain [`Domain::new`] creates.
fn stand_in_domain() -> TrustDomainId {
    TrustDomainId::new([3; 16]).expect("domain")
}

fn set_origin(vault_path: &Path, origin: Option<&str>) {
    let relay_path = astra_operator::handoff::path_beside(vault_path);
    let mut relay = astra_operator::handoff::load(&relay_path).expect("relay");
    relay.astra_authority_url = origin.map(str::to_string);
    astra_operator::handoff::save(&relay_path, &relay).expect("save relay");
}

/// A request that does not parse, or is no delegation request, is refused
/// before any key, and nothing is written.
#[test]
fn a_wrong_request_is_refused_before_any_key() {
    let domain = Domain::new("issuer-wrong").with_ca_tls();
    let folder = domain.vault_path.parent().expect("folder").to_path_buf();
    let before = std::fs::read_dir(&folder).expect("folder").count();
    let request = delegation_request(stand_in_domain());
    let truncated = request.replace("pq_issuer_public_key", "pq_key");
    for request in ["not a request".to_string(), "{}".to_string(), truncated] {
        let (outcome, published, artifacts) =
            run_issuer_gesture(offline(request), &domain.vault_path);
        outcome.expect_err("a wrong request is refused");
        refused_before_the_key(&published, Refusal::DelegationRequestInvalid);
        assert_eq!(
            published.last().expect("a status").operation,
            OperationKind::AuthorizeIssuer
        );
        assert!(artifacts.is_empty());
    }
    assert_eq!(std::fs::read_dir(&folder).expect("folder").count(), before);
}

/// A domain that has an origin delegates through a campaign: the file path
/// is refused before the key, whatever the window offered.
#[test]
fn an_offline_delegation_is_refused_when_the_relay_names_an_origin() {
    let domain = Domain::new("issuer-origin").with_ca_tls();
    set_origin(&domain.vault_path, Some("https://astra.example"));
    let (outcome, published, artifacts) = run_issuer_gesture(
        offline(delegation_request(stand_in_domain())),
        &domain.vault_path,
    );
    outcome.expect_err("an origin is recorded");
    refused_before_the_key(&published, Refusal::ManifestMismatch);
    assert!(artifacts.is_empty());
}

/// A domain without its `CA-TLS` has nothing to issue the intermediate
/// under.
#[test]
fn a_domain_without_ca_tls_is_refused_before_any_key() {
    let domain = Domain::new("issuer-no-ca-tls");
    let (outcome, published, _) = run_issuer_gesture(
        offline(delegation_request(stand_in_domain())),
        &domain.vault_path,
    );
    outcome.expect_err("no CA-TLS");
    refused_before_the_key(&published, Refusal::CaTlsMissing);
}

/// The delegation is a gesture: a locator naming it is refused, not run.
#[test]
fn a_locator_does_not_open_a_delegation() {
    let domain = Domain::new("issuer-locator").with_ca_tls();
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut published = Vec::new();
    let outcome = run(
        Id16::new([1; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AuthorizeIssuer,
            operation_id: Some(Id16::new([2; 16]).expect("id")),
        },
        received,
        &mut |status| published.push(status),
        &domain.vault_path,
    );
    let error = outcome.expect_err("refused");
    assert!(!error.contains("pas encore portée"), "{error}");
    refused_before_the_key(&published, Refusal::Internal);
}

/// A token of one credential, standing for the key the operator would touch:
/// it registers one credential and releases one fixed secret for it.
struct OneKey;

const CREDENTIAL: u8 = 7;

impl Authenticator for OneKey {
    fn register(
        &self,
        _rp_id: &str,
        _subject: &CredentialSubject,
        _exclude: &[Vec<u8>],
        _pin: &str,
    ) -> aether_fido::authenticator::Result<Registration> {
        Ok(Registration {
            credential_id: vec![CREDENTIAL; 64],
            credential_public_key: vec![0xa5, CREDENTIAL],
            aaguid: [0; 16],
        })
    }

    fn derive(
        &self,
        _rp_id: &str,
        _credentials: &[Vec<u8>],
        _salt: &[u8; SALT_LEN],
        _pin: &str,
    ) -> aether_fido::authenticator::Result<Opened> {
        Ok(opening())
    }

    fn approve(
        &self,
        _rp_id: &str,
        _credentials: &[Vec<u8>],
        _client_data_json: &[u8],
        _pin: &str,
    ) -> aether_fido::authenticator::Result<Approval> {
        Err(AuthenticatorError::UnknownCredential)
    }

    fn approve_and_derive(
        &self,
        _rp_id: &str,
        _credentials: &[Vec<u8>],
        _client_data_json: &[u8],
        _salt: &[u8; SALT_LEN],
        _pin: &str,
    ) -> aether_fido::authenticator::Result<ApprovedOpening> {
        Err(AuthenticatorError::UnknownCredential)
    }
}

/// What [`OneKey`] releases: the opening of the vault it created.
fn opening() -> Opened {
    Opened {
        credential_id: vec![CREDENTIAL; 64],
        secret: SlotSecret::new(vec![CREDENTIAL; 32]),
    }
}

/// A domain able to delegate, with no origin: real anchors drawn by the
/// production gesture, the gateway on the relay and a `CA-TLS` issued under
/// them. Removed when the test ends.
struct IssuingDomain {
    directory: std::path::PathBuf,
    vault_path: std::path::PathBuf,
}

impl IssuingDomain {
    fn new(label: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "orion-issuer-{label}-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("directory");
        let vault_path = directory.join("authority-vault.json");
        let now = now_unix();
        let opened = astra_operator::vault_gestures::create_first_key(
            &vault_path,
            &NewAuthority {
                rp_id: "astra.example".into(),
                trust_domain_id: stand_in_domain(),
                label: "quotidienne".into(),
                role: SlotRole::Primary,
            },
            "https://astra.example",
            &OneKey,
            "",
            now,
        )
        .expect("the domain is created");

        let relay_path = astra_operator::handoff::path_beside(&vault_path);
        let mut relay = astra_operator::handoff::load(&relay_path).expect("relay");
        relay.astra_authority_url = None;
        relay.gateway_wg_public_key =
            Some(aether::wg::generate_keypair().expect("gateway").public_key);
        relay.server_name = Some("gateway.example".into());
        let identity = astra_operator::handoff::identity_of(&relay).expect("identity");
        let vault = astra_operator::store::load(&vault_path).expect("vault");
        let ca_tls = astra_operator::signing::issue_ca_tls(
            &vault,
            &opened,
            &identity,
            now,
            now + 365 * 86_400,
        )
        .expect("CA-TLS");
        relay.ca_tls_epoch = Some(identity.ca_tls_epoch);
        relay.ca_tls_certificate = Some(ca_tls.to_base64());
        astra_operator::handoff::save(&relay_path, &relay).expect("save relay");
        Self {
            directory,
            vault_path,
        }
    }
}

impl Drop for IssuingDomain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Once the key opened the vault, the delegation is signed, handed over as
/// `issuer-authorization.json` and verifies under the relay's `CA-PQ`.
#[test]
fn an_offline_delegation_deposits_the_authorization() {
    let domain = IssuingDomain::new("deposit");
    let request = delegation_request(stand_in_domain());

    // Up to the key, through the ceremony itself.
    let (outcome, published, artifacts) =
        run_issuer_gesture(offline(request.clone()), &domain.vault_path);
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
            of: 1,
            purpose: KeyPurpose::OpenVault,
        }
    );
    let plan =
        astra_operator::operations::issuer::plan(&domain.vault_path, &request, None, now_unix())
            .expect("a plan");
    match offered.manifest.as_ref().expect("manifest shown first") {
        AstraManifest::IssuerAuthorization(manifest) => {
            assert_eq!(manifest.campaign, None);
            assert_eq!(manifest.issuer_epoch, 1);
            assert_eq!(
                manifest.pq_public_key_fingerprint,
                plan.manifest.pq_public_key_fingerprint
            );
            assert_eq!(
                manifest.request_fingerprint,
                plan.manifest.request_fingerprint
            );
        }
        other => panic!("{other:?}"),
    }

    // After the key, on the opening it would have released.
    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([6; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AuthorizeIssuer,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let mut publish = |status| published.push(status);
    let mut run = IssuerRun {
        ceremony: &mut ceremony,
        presses: &received,
        publish: &mut publish,
        vault_path: &domain.vault_path,
    };
    run.sign_offline(&plan, &opening(), &mut |artifact| artifacts.push(artifact))
        .expect("signed");

    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Done);
    assert_eq!(last.refusal, None);
    assert!(published
        .iter()
        .any(|status| status.gesture == GestureState::Signing));
    assert_eq!(artifacts.len(), 1);
    let artifact = &artifacts[0];
    assert_eq!(artifact.file_name, "issuer-authorization.json");
    assert_eq!(artifact.encoding, ArtifactEncoding::Text);
    assert_eq!(artifact.fingerprint, None);

    let authorization: aether::certificates::authority::AstraIssuerAuthorization =
        serde_json::from_str(&artifact.contents).expect("what `astra issuer install` reads");
    assert_eq!(authorization.issuer_epoch, plan.manifest.issuer_epoch);
    assert_eq!(authorization.not_before, plan.manifest.not_before);
    assert_eq!(authorization.not_after, plan.manifest.not_after);
    let relay =
        astra_operator::handoff::load(&astra_operator::handoff::path_beside(&domain.vault_path))
            .expect("relay");
    let identity = astra_operator::handoff::identity_of(&relay).expect("identity");
    authorization
        .verify(
            &MlDsa87PublicKey::parse(&relay.ca_pq_public_key).expect("anchor"),
            &identity.trust_domain_id,
            identity.ca_epoch,
            identity.ca_tls_epoch,
            &identity.gateway_wg_public_key,
            &identity.server_name,
            now_unix(),
        )
        .expect("the delegation verifies under the relay's CA-PQ");
}

/// A relay that gained an origin between the manifest and the key refuses
/// the signature, and nothing is handed over.
#[test]
fn an_origin_recorded_after_the_manifest_refuses_the_signature() {
    let domain = IssuingDomain::new("late-origin");
    let request = delegation_request(stand_in_domain());
    let plan =
        astra_operator::operations::issuer::plan(&domain.vault_path, &request, None, now_unix())
            .expect("a plan");
    set_origin(&domain.vault_path, Some("https://astra.example"));

    let (presses, received) = std::sync::mpsc::channel::<Press>();
    drop(presses);
    let mut ceremony = Ceremony::new(
        Id16::new([6; 16]).expect("id"),
        OperationLocator {
            kind: OperationKind::AuthorizeIssuer,
            operation_id: None,
        },
    );
    let mut published = Vec::new();
    let mut artifacts = Vec::new();
    let mut publish = |status| published.push(status);
    let mut run = IssuerRun {
        ceremony: &mut ceremony,
        presses: &received,
        publish: &mut publish,
        vault_path: &domain.vault_path,
    };
    run.sign_offline(&plan, &opening(), &mut |artifact| artifacts.push(artifact))
        .expect_err("refused");
    let last = published.last().expect("a status");
    assert_eq!(last.gesture, GestureState::Failed);
    assert_eq!(last.refusal, Some(Refusal::ManifestMismatch));
    assert!(artifacts.is_empty());
}

/// Each refusal of the delegation is named, wherever it surfaces: from the
/// plan, inside an error chain from the signature, from the campaign's
/// verification and from the gesture in the campaign.
#[test]
fn refusals_of_the_delegation_are_named() {
    let cases = [
        (
            IssuerRefusal::RequestInvalid,
            Refusal::DelegationRequestInvalid,
        ),
        (
            IssuerRefusal::RequestMismatch,
            Refusal::DelegationRequestMismatch,
        ),
        (IssuerRefusal::NotADelegation, Refusal::ManifestMismatch),
        (IssuerRefusal::OriginRecorded, Refusal::ManifestMismatch),
        (IssuerRefusal::CaTlsMissing, Refusal::CaTlsMissing),
        (IssuerRefusal::CaTlsUnusable, Refusal::CaTlsUnusable),
        (IssuerRefusal::PlanChanged, Refusal::DomainChanged),
        (
            IssuerRefusal::Vault("coffre illisible".into()),
            Refusal::VaultUnavailable,
        ),
    ];
    for (issuer, window) in &cases {
        assert_eq!(refusal_of_plan(issuer), *window, "{issuer:?}");
        let wrapped = anyhow::Error::from(issuer.clone()).context("signature de la délégation");
        assert_eq!(refusal_of_signature(&wrapped), *window, "{issuer:?}");
        assert_eq!(refusal_of_campaign(&wrapped), *window, "{issuer:?}");
        assert_eq!(refusal_of_gesture(&wrapped, false), *window, "{issuer:?}");
    }

    // The campaign could not be fetched or verified.
    assert_eq!(
        refusal_of_campaign(&anyhow::anyhow!("la campagne ne vérifie pas")),
        Refusal::HandoffMismatch
    );
    // A failure after the key answered that names no check.
    assert_eq!(
        refusal_of_signature(&anyhow::anyhow!("signature impossible")),
        Refusal::Internal
    );
    // In a campaign: the key, the approval or the restricted opening failed.
    for error in [
        anyhow::Error::from(AuthenticatorError::UnknownCredential),
        anyhow::Error::from(astra_operator::gestures::GestureError::Anchors(
            "la clé qui ouvre le coffre n'est pas celle qui vient d'approuver".into(),
        )),
    ] {
        assert_eq!(refusal_of_gesture(&error, false), Refusal::KeyDeclined);
    }
    // Past the approval and the signature, only the deposit remains.
    assert_eq!(
        refusal_of_gesture(&anyhow::anyhow!("dépôt de la délégation"), true),
        Refusal::AuthorityRefused { status: 0 }
    );
}
