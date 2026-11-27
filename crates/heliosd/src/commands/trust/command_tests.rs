use super::trust_domain_seeding_tests::{gateway_identity, initial_state, key};
use super::*;
use aether::certificates::{
    approval::{
        superseded_per_request_policy_fingerprint, AstraCredentialBinding, CredentialRegistry,
        CredentialState,
    },
    authority::{
        AllowedUsage, AstraIssuerAuthorization, CaTransition, ClientTlsCaTransition, RotationReason,
    },
    encoding::generate_ml_dsa_87_keypair,
    gateway::{AbortReason, GatewayIdentityTransition, GatewayTransitionAbort},
    test_x509::certificate_authority,
    AstraPolicyPin, DerCertificate, Fingerprint, MlDsa87Signature, TransitionWindow,
    CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use helios_provisioning::certificates::RegistryState;
use std::{fs, path::PathBuf, process::Command};
use tempfile::tempdir;

const SCENARIO: &str = "HELIOSD_OFFLINE_TRUST_TEST";
const REGISTRY: &str = "HELIOS_CERTIFICATE_REGISTRY";
const TRANSITION: &str = "HELIOS_GATEWAY_TRANSITION";
const REQUEST: &str = "HELIOS_GATEWAY_REQUEST";
const CANDIDATE_TLS: &str = "HELIOS_KEY_NEGO_NEXT_CERT";
const CANDIDATE_KEY: &str = "HELIOS_KEY_NEGO_NEXT_KEY";

/// Give each invocation its own production path overrides without mutating
/// the environment of other tests in the harness.
fn isolated(name: &str, test: impl FnOnce(&Path)) {
    if let Some(directory) = std::env::var_os(SCENARIO) {
        test(Path::new(&directory));
        return;
    }
    let directory = tempdir().expect("isolated command directory");
    let root = directory.path();
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            &format!("commands::trust::command_tests::{name}"),
            "--nocapture",
        ])
        .env(SCENARIO, root)
        .env(REGISTRY, root.join("registry.json"))
        .env(TRANSITION, root.join("staged.json"))
        .env(REQUEST, root.join("request.json"))
        .env(CANDIDATE_TLS, root.join("candidate.der"))
        .env(CANDIDATE_KEY, root.join("candidate.sealed"))
        .output()
        .expect("isolated command starts");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("running 1 test"),
        "isolated {name} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Fixture<'a> {
    root: &'a Path,
    ca_private: zeroize::Zeroizing<Vec<u8>>,
    state: RegistryState,
    now: u64,
}

impl<'a> Fixture<'a> {
    fn new(root: &'a Path) -> Self {
        let now = now_unix().expect("clock");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("authority key");
        let mut state = initial_state(gateway_identity(&key(9).to_base64()));
        state.gateway.current_ca_public_key = ca_public;
        let mut leaf = state.gateway.active_gateway_certificate.clone();
        leaf.not_before_unix = now - 3_600;
        leaf.not_after_unix = now + 86_400;
        state.gateway.active_gateway_certificate =
            aether::key_negotiation::issue_pq_certificate(leaf, &ca_private)
                .expect("issue the active gateway leaf under the registered authority");
        state.client_tls_ca.active_client_tls_ca_certificate =
            certificate_authority("current client CA");
        Self {
            root,
            ca_private,
            state,
            now,
        }
    }

    fn persist(&self) {
        CertificateRegistry::bootstrap(CertificateRegistry::path(), self.state.clone())
            .expect("persist the initial registry");
    }

    fn reload(&self) -> CertificateRegistry {
        CertificateRegistry::load(&self.root.join("registry.json"))
            .expect("read persisted registry")
            .expect("registry exists")
    }

    fn input(&self, document: &impl serde::Serialize) -> PathBuf {
        let path = self.root.join("operator-document.json");
        fs::write(
            &path,
            serde_json::to_vec(document).expect("encode document"),
        )
        .expect("write the operator document");
        path
    }

    fn window(&self) -> TransitionWindow {
        TransitionWindow::new(self.now - 60, self.now + 3_600, self.now + 7_200)
            .expect("valid transition window")
    }

    fn pq_rotation(&self) -> CaTransition {
        let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("successor key");
        CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: self
                .state
                .gateway
                .current_ca_public_key
                .authority_fingerprint(),
            next_ca_fingerprint: next_public.authority_fingerprint(),
            next_ca_public_key: next_public,
            window: self.window(),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private, &next_private)
        .expect("sign both halves of the PQ rotation")
    }

    fn tls_rotation(&self) -> ClientTlsCaTransition {
        ClientTlsCaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            ca_epoch: 1,
            current_ca_tls_epoch: 1,
            next_ca_tls_epoch: 2,
            active_client_tls_ca_fingerprint: self
                .state
                .client_tls_ca
                .active_client_tls_ca_certificate
                .fingerprint(),
            next_client_tls_ca_certificate: certificate_authority("successor client CA"),
            window: self.window(),
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private)
        .expect("sign the TLS rotation")
    }

    fn issuer(&self, policy_fingerprint: Fingerprint) -> AstraIssuerAuthorization {
        let (_, issuer) = generate_ml_dsa_87_keypair().expect("issuer key");
        AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: self.state.gateway.gateway_wg_public_key,
            server_name: self.state.gateway.server_name.clone(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer,
            tls_intermediate_certificate: certificate_authority("Astra intermediate"),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 3_600,
            policy_fingerprint,
            not_before: self.now - 60,
            not_after: self.now + 86_400,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private)
        .expect("sign the Astra authorization")
    }

    fn credentials(&self) -> CredentialRegistry {
        let bindings = [1, 2].map(|id| {
            AstraCredentialBinding {
                format_version: CERTIFICATE_FORMAT_VERSION,
                credential_id: vec![id],
                credential_public_key: cose_es256_key(),
                aaguid: [0; 16],
                trust_domain_id: self.state.trust_domain_id,
                gateway_wg_public_key: self.state.gateway.gateway_wg_public_key,
                state: CredentialState::Active,
                credential_epoch: 1,
                credential_registry_epoch: 1,
                ca_epoch: 1,
                created_at: self.now,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            }
            .sign(&self.ca_private)
            .expect("sign a credential binding")
        });

        CredentialRegistry {
            trust_domain_id: self.state.trust_domain_id,
            gateway_wg_public_key: self.state.gateway.gateway_wg_public_key,
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: bindings.into(),
        }
    }

    fn tls_gateway_transition(&self) -> GatewayIdentityTransition {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

        let gateway = &self.state.gateway;
        let mut params =
            CertificateParams::new(vec![gateway.server_name.clone()]).expect("TLS parameters");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let tls_leaf = params
            .self_signed(&KeyPair::generate().expect("TLS key"))
            .expect("TLS leaf");
        GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            ca_epoch: 1,
            gateway_identity_epoch: 2,
            gateway_wg_public_key: gateway.gateway_wg_public_key,
            server_name: gateway.server_name.clone(),
            active_gateway_tls_certificate_fingerprint: gateway.active_tls_fingerprint(),
            next_gateway_tls_certificate: Some(
                DerCertificate::new(tls_leaf.der().to_vec()).expect("DER"),
            ),
            active_gateway_certificate_fingerprint: gateway
                .active_pq_fingerprint()
                .expect("PQ fingerprint"),
            next_gateway_certificate: None,
            window: self.window(),
            reason: RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private)
        .expect("sign the gateway transition")
    }

    fn abort(&self, transition: &GatewayIdentityTransition) -> GatewayTransitionAbort {
        GatewayTransitionAbort {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.state.trust_domain_id,
            ca_epoch: 1,
            gateway_identity_epoch: transition.gateway_identity_epoch,
            gateway_wg_public_key: transition.gateway_wg_public_key,
            server_name: transition.server_name.clone(),
            gateway_transition_fingerprint: transition
                .fingerprint()
                .expect("transition fingerprint"),
            aborted_at: self.now,
            reason: AbortReason::OperatorCancelled,
            campaign_fingerprint: Fingerprint::of(b"operator campaign"),
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.ca_private)
        .expect("sign the abort")
    }
}

/// The CBOR header and labels for an ES256 P-256 public key, followed
/// by the uncompressed coordinates of the standard curve generator.
fn cose_es256_key() -> Vec<u8> {
    let generator_x = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    let generator_y = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&generator_x);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&generator_y);
    key
}

fn registry_bytes() -> Vec<u8> {
    fs::read(CertificateRegistry::path()).expect("read the registry bytes")
}

#[test]
fn pq_rotation_requires_both_signatures_then_stages_once() {
    isolated(
        "pq_rotation_requires_both_signatures_then_stages_once",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let transition = fixture.pq_rotation();
            let mut unsigned_successor = transition.clone();
            unsigned_successor.next_ca_signature = MlDsa87Signature::placeholder();

            let initial = registry_bytes();
            let error = install_ca_transition(&fixture.input(&unsigned_successor))
                .expect_err("the successor must prove its key");
            assert!(error.to_string().contains("installing the CA-PQ rotation"));
            assert_eq!(registry_bytes(), initial);

            let document = fixture.input(&transition);
            install_ca_transition(&document).expect("stage the dual-signed rotation");
            let staged = registry_bytes();
            let registry = fixture.reload();
            let gateway = &registry.state().gateway;
            assert_eq!(
                gateway.current_ca_public_key,
                fixture.state.gateway.current_ca_public_key
            );
            assert_eq!(gateway.ca_epoch, 1);
            assert_eq!(
                gateway.next_ca_public_key.as_ref(),
                Some(&transition.next_ca_public_key)
            );
            assert_eq!(
                gateway.ca_activation_at,
                Some(transition.window.activation_at)
            );
            assert_eq!(
                gateway.ca_retire_active_at,
                Some(transition.window.not_after)
            );

            install_ca_transition(&document).expect("repeat the same signed decision");
            assert_eq!(registry_bytes(), staged);
        },
    );
}

#[test]
fn client_tls_rotation_checks_the_served_anchor_and_keeps_it_until_activation() {
    isolated(
        "client_tls_rotation_checks_the_served_anchor_and_keeps_it_until_activation",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let transition = fixture.tls_rotation();
            let mut different_anchor = transition.clone();
            different_anchor.active_client_tls_ca_fingerprint = Fingerprint::of(b"another anchor");
            let different_anchor = different_anchor
                .sign(&fixture.ca_private)
                .expect("sign the wrong anchor");

            let initial = registry_bytes();
            let error = install_client_tls_ca(&fixture.input(&different_anchor))
                .expect_err("a correctly signed transition is bound to its original anchor");
            assert!(error
                .to_string()
                .contains("installing the client TLS CA rotation"));
            assert_eq!(registry_bytes(), initial);

            let document = fixture.input(&transition);
            install_client_tls_ca(&document).expect("stage the successor client CA");
            let staged = registry_bytes();
            let registry = fixture.reload();
            let tls_ca = &registry.state().client_tls_ca;
            assert_eq!(tls_ca.ca_tls_epoch, 1);
            assert_eq!(
                tls_ca.active_client_tls_ca_certificate,
                fixture.state.client_tls_ca.active_client_tls_ca_certificate
            );
            assert_eq!(
                tls_ca.next_client_tls_ca_certificate.as_ref(),
                Some(&transition.next_client_tls_ca_certificate)
            );
            assert_eq!(tls_ca.activation_at, Some(transition.window.activation_at));
            assert_eq!(tls_ca.retire_active_at, Some(transition.window.not_after));

            install_client_tls_ca(&document).expect("repeat the same signed rotation");
            assert_eq!(registry_bytes(), staged);
        },
    );
}

#[test]
fn issuer_install_migrates_the_legacy_policy_atomically_with_the_delegation() {
    isolated(
        "issuer_install_migrates_the_legacy_policy_atomically_with_the_delegation",
        |root| {
            let mut fixture = Fixture::new(root);
            let current = fixture.state.astra.astra_policy_fingerprint;
            let legacy = superseded_per_request_policy_fingerprint(
                fixture.state.trust_domain_id,
                fixture.state.gateway.gateway_wg_public_key,
                &fixture.state.gateway.server_name,
            )
            .expect("legacy policy fingerprint");
            fixture.state.astra.astra_policy_fingerprint =
                AstraPolicyPin::new(legacy).expect("legacy pin");
            fixture.persist();

            let initial = registry_bytes();
            let unrelated_pin = fixture.issuer(Fingerprint::of(b"unrecognized policy"));
            let error = install_astra_issuer(&fixture.input(&unrelated_pin))
                .expect_err("even a valid signature cannot adopt an unrecognized policy");
            assert!(error
                .to_string()
                .contains("adopting the current Astra issuance policy"));
            assert_eq!(registry_bytes(), initial);

            let issuer = fixture.issuer(*current.fingerprint());
            let document = fixture.input(&issuer);
            install_astra_issuer(&document).expect("authorize the delegation and current policy");
            let installed = registry_bytes();
            let registry = fixture.reload();
            assert_eq!(registry.state().astra.astra_policy_fingerprint, current);
            assert_eq!(
                registry
                    .state()
                    .issuer
                    .as_ref()
                    .expect("delegation")
                    .authorization,
                issuer
            );

            install_astra_issuer(&document).expect("reinstall the current delegation");
            assert_eq!(registry_bytes(), installed);
        },
    );
}

#[test]
fn credentials_are_adopted_together_and_one_invalid_row_preserves_the_registry() {
    isolated(
        "credentials_are_adopted_together_and_one_invalid_row_preserves_the_registry",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let credentials = fixture.credentials();
            let mut invalid = credentials.clone();
            invalid.bindings[1].ca_pq_signature = MlDsa87Signature::placeholder();

            let initial = registry_bytes();
            let error = install_astra_credentials(&fixture.input(&invalid))
                .expect_err("one invalid row invalidates the complete document");
            assert!(error
                .to_string()
                .contains("recording the Astra operator credentials"));
            assert_eq!(registry_bytes(), initial);

            let document = fixture.input(&credentials);
            install_astra_credentials(&document).expect("install both credentials");
            let installed = registry_bytes();
            let registry = fixture.reload();
            assert_eq!(registry.state().astra.credential_bindings.len(), 2);
            assert!(credentials.bindings.iter().all(|row| registry
                .state()
                .astra
                .credential_bindings
                .values()
                .any(|stored| stored == row)));

            install_astra_credentials(&document).expect("repeat the signed snapshot");
            assert_eq!(registry_bytes(), installed);
        },
    );
}

#[test]
fn a_gateway_transition_cannot_stage_until_its_candidate_is_held() {
    isolated(
        "a_gateway_transition_cannot_stage_until_its_candidate_is_held",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let transition = fixture.tls_gateway_transition();
            let document = fixture.input(&transition);

            let initial = registry_bytes();
            let error = install_gateway_transition(&document).expect_err("no local TLS candidate");
            assert!(error
                .to_string()
                .contains("no candidate TLS leaf was sealed here"));
            assert_eq!(registry_bytes(), initial);
            assert!(!root.join("staged.json").exists());

            let candidate = transition
                .next_gateway_tls_certificate
                .as_ref()
                .expect("candidate");
            fs::write(root.join("candidate.der"), candidate.as_bytes())
                .expect("retain the candidate");
            install_gateway_transition(&document).expect("stage the matching candidate");
            let staged = registry_bytes();
            let registry = fixture.reload();
            let gateway = &registry.state().gateway;
            assert_eq!(
                gateway.active_tls_fingerprint(),
                fixture.state.gateway.active_tls_fingerprint()
            );
            assert_eq!(
                gateway.active_pq_fingerprint().expect("active PQ"),
                fixture
                    .state
                    .gateway
                    .active_pq_fingerprint()
                    .expect("previous PQ")
            );
            assert_eq!(
                gateway.next_gateway_tls_certificate.as_ref(),
                Some(candidate)
            );
            assert_eq!(gateway.next_gateway_identity_epoch, Some(2));
            assert!(!gateway.published);
            assert_eq!(
                fs::read(root.join("staged.json")).expect("retained decision"),
                serde_json::to_vec_pretty(&transition).expect("transition JSON")
            );

            install_gateway_transition(&document).expect("replay the staged transition");
            assert_eq!(registry_bytes(), staged);
        },
    );
}

#[test]
fn a_signed_abort_consumes_the_epoch_and_removes_only_its_local_candidate() {
    isolated(
        "a_signed_abort_consumes_the_epoch_and_removes_only_its_local_candidate",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let transition = fixture.tls_gateway_transition();
            let candidate = transition
                .next_gateway_tls_certificate
                .as_ref()
                .expect("candidate");
            fs::write(root.join("candidate.der"), candidate.as_bytes())
                .expect("retain the candidate");
            install_gateway_transition(&fixture.input(&transition))
                .expect("stage the gateway identity");
            fs::write(root.join("candidate.sealed"), b"candidate sealed slot")
                .expect("candidate slot");
            fs::write(root.join("request.json"), b"pending candidate request")
                .expect("request slot");

            let abort = fixture.abort(&transition);
            let mut different_document = abort.clone();
            different_document.gateway_transition_fingerprint =
                Fingerprint::of(b"another transition");
            let different_document = different_document
                .sign(&fixture.ca_private)
                .expect("sign the wrong decision");
            let staged = registry_bytes();
            let error = abort_gateway_transition(&fixture.input(&different_document))
                .expect_err("an abort names the exact staged transition");
            assert!(error
                .to_string()
                .contains("cancelling the staged transition"));
            assert_eq!(registry_bytes(), staged);
            for file in [
                "staged.json",
                "candidate.der",
                "candidate.sealed",
                "request.json",
            ] {
                assert!(root.join(file).exists(), "{file} survives a refused abort");
            }

            let document = fixture.input(&abort);
            abort_gateway_transition(&document).expect("cancel the exact staged decision");
            let registry = fixture.reload();
            let gateway = &registry.state().gateway;
            assert_eq!(gateway.active_gateway_identity_epoch, 1);
            assert_eq!(
                gateway.active_tls_fingerprint(),
                fixture.state.gateway.active_tls_fingerprint()
            );
            assert_eq!(gateway.gateway_decision_epoch, 2);
            assert!(gateway.next_gateway_identity_epoch.is_none());
            assert_eq!(
                gateway
                    .last_aborted_transition
                    .as_ref()
                    .expect("tombstone")
                    .abort_fingerprint,
                abort.fingerprint()
            );
            for file in [
                "staged.json",
                "candidate.der",
                "candidate.sealed",
                "request.json",
            ] {
                assert!(
                    !root.join(file).exists(),
                    "{file} is removed with the accepted abort"
                );
            }
            assert!(document.is_file(), "the operator's input stays available");

            let aborted_registry = registry_bytes();
            let missing_document = abort_gateway_transition(&document)
                .expect_err("the command requires the retained signed transition");
            assert!(format!("{missing_document:#}").contains("no staged transition document"));
            assert_eq!(registry_bytes(), aborted_registry);

            let staged_document = root.join("staged.json");
            fs::write(
                &staged_document,
                serde_json::to_vec_pretty(&transition).expect("encode the signed transition"),
            )
            .expect("model a retained document after an already persisted abort");
            abort_gateway_transition(&document).expect("replay the accepted signed abort");
            let reopened = fixture.reload();
            assert_eq!(registry_bytes(), aborted_registry);
            assert_eq!(reopened.state().gateway.gateway_decision_epoch, 2);
            assert_eq!(
                reopened
                    .state()
                    .gateway
                    .last_aborted_transition
                    .as_ref()
                    .expect("durable abort tombstone")
                    .abort_fingerprint,
                abort.fingerprint()
            );
            assert!(!root.join("candidate.der").exists());
        },
    );
}

#[test]
fn client_tls_rotation_rejects_wrong_domain_epoch_and_sequence_without_mutation() {
    isolated(
        "client_tls_rotation_rejects_wrong_domain_epoch_and_sequence_without_mutation",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let valid = fixture.tls_rotation();
            let mut wrong_domain = valid.clone();
            wrong_domain.trust_domain_id =
                aether::certificates::encoding::TrustDomainId::new([0x44; 16])
                    .expect("different domain");
            wrong_domain = wrong_domain
                .sign(&fixture.ca_private)
                .expect("signed transition for another domain");

            let mut wrong_ca_epoch = valid.clone();
            wrong_ca_epoch.ca_epoch = 2;
            wrong_ca_epoch = wrong_ca_epoch
                .sign(&fixture.ca_private)
                .expect("signed transition for another PQ epoch");

            let mut skipped_tls_epoch = valid.clone();
            skipped_tls_epoch.next_ca_tls_epoch = 3;
            skipped_tls_epoch = skipped_tls_epoch
                .sign(&fixture.ca_private)
                .expect("signed transition with skipped TLS epoch");

            let initial = registry_bytes();
            for (label, transition, cause) in [
                (
                    "wrong trust domain",
                    wrong_domain,
                    "object belongs to another trust domain",
                ),
                (
                    "wrong CA epoch",
                    wrong_ca_epoch,
                    "issuer is not authorized for this operation",
                ),
                (
                    "skipped TLS epoch",
                    skipped_tls_epoch,
                    "generation 3 skips 2",
                ),
            ] {
                let error = install_client_tls_ca(&fixture.input(&transition))
                    .expect_err(&format!("{label} is rejected"));
                let message = format!("{error:#}");
                assert!(
                    message.contains("installing the client TLS CA rotation"),
                    "{message}"
                );
                assert!(message.contains(cause), "{label}: {message}");
                assert_eq!(registry_bytes(), initial, "{label} leaves state untouched");
            }
        },
    );
}

#[test]
fn issuer_install_rejects_wrong_domain_gateway_and_epoch_atomically() {
    isolated(
        "issuer_install_rejects_wrong_domain_gateway_and_epoch_atomically",
        |root| {
            let fixture = Fixture::new(root);
            fixture.persist();
            let valid = fixture.issuer(*fixture.state.astra.astra_policy_fingerprint.fingerprint());

            let mut wrong_domain = valid.clone();
            wrong_domain.trust_domain_id =
                aether::certificates::encoding::TrustDomainId::new([0x55; 16])
                    .expect("different domain");
            wrong_domain = wrong_domain
                .sign(&fixture.ca_private)
                .expect("signed authorization for another domain");

            let mut wrong_gateway = valid.clone();
            wrong_gateway.gateway_wg_public_key = key(7);
            wrong_gateway = wrong_gateway
                .sign(&fixture.ca_private)
                .expect("signed authorization for another gateway");

            let initial = registry_bytes();
            for (label, authorization, cause) in [
                (
                    "wrong trust domain",
                    wrong_domain,
                    "object belongs to another trust domain",
                ),
                (
                    "wrong gateway",
                    wrong_gateway,
                    "object names another gateway identity",
                ),
            ] {
                let error = install_astra_issuer(&fixture.input(&authorization))
                    .expect_err("issuer authorization must match the pinned gateway state");
                let message = format!("{error:#}");
                assert!(
                    message.contains("adopting the current Astra issuance policy"),
                    "{message}"
                );
                assert!(message.contains(cause), "{label}: {message}");
                assert_eq!(registry_bytes(), initial, "{label} leaves state untouched");
            }

            let mut epoch_two = valid.clone();
            epoch_two.issuer_epoch = 2;
            epoch_two = epoch_two
                .sign(&fixture.ca_private)
                .expect("sign the first installed issuer epoch");
            install_astra_issuer(&fixture.input(&epoch_two))
                .expect("first installed delegation may use epoch two");
            let installed = registry_bytes();
            let registry = fixture.reload();
            assert_eq!(
                registry
                    .state()
                    .issuer
                    .as_ref()
                    .map(|issuer| issuer.issuer_epoch),
                Some(2)
            );
            assert_eq!(
                registry.state().astra.astra_policy_fingerprint,
                fixture.state.astra.astra_policy_fingerprint,
                "adopting a delegation that names the current pin keeps it unchanged"
            );

            let error = install_astra_issuer(&fixture.input(&valid))
                .expect_err("a previously spent issuer epoch cannot be restored");
            let message = format!("{error:#}");
            assert!(
                message.contains(
                    "delegation at issuer epoch 1 does not advance past the installed epoch 2"
                ),
                "{message}"
            );
            assert_eq!(
                registry_bytes(),
                installed,
                "rollback leaves the installed issuer intact"
            );
        },
    );
}

#[test]
fn offline_install_refuses_missing_registry_and_reports_malformed_input() {
    isolated(
        "offline_install_refuses_missing_registry_and_reports_malformed_input",
        |root| {
            let document = root.join("invalid.json");
            fs::write(&document, b"not JSON").expect("write malformed document");
            let absent = install_ca_transition(&document).expect_err("no trust domain");
            assert!(format!("{absent:#}").contains("heliosd init-trust-domain"));
            assert!(!CertificateRegistry::path().exists());

            let fixture = Fixture::new(root);
            fixture.persist();
            let before = registry_bytes();
            let malformed = install_ca_transition(&document).expect_err("malformed rotation");
            let message = format!("{malformed:#}");
            assert!(message.contains("decoding the CA-PQ transition"));
            assert!(message.contains("invalid.json"));
            assert_eq!(registry_bytes(), before);
        },
    );
}
