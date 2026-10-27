#![cfg(not(target_os = "windows"))]

use super::*;

use crate::service::EnginePaths;
use aether::key_negotiation::ProtectionMode;
use orion_core::backend::dryrun::DryRunBackend;
use orion_core::{ClientProfile, ProfileKind};
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "orion-engine-certificates-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn paths_under(root: &Path) -> EnginePaths {
    EnginePaths {
        root: root.to_path_buf(),
        vault: root.join("vault"),
        config: root.join("config.toml"),
        identities: root.join("identities"),
        log: root.join("orion.log"),
        user_sid: None,
        user_process: None,
    }
}

fn service(scratch: &Scratch) -> Arc<EngineService> {
    EngineService::open(
        paths_under(&scratch.0),
        Arc::new(DryRunBackend::default()),
        None,
        "0.0.0-test",
    )
    .expect("service opens on scratch paths")
}

fn key_negotiation(identity: &str) -> orion_core::KeyNegotiationSettings {
    orion_core::KeyNegotiationSettings {
        mode: ProtectionMode::MlKem,
        minimum_mode: ProtectionMode::MlKem,
        endpoint: "gateway.example:51821".into(),
        server_name: "gateway.example".into(),
        gateway_ca_der: String::new(),
        gateway_pq_certificate: String::new(),
        identity: identity.into(),
        trust: None,
    }
}

fn profile(name: &str, kind: ProfileKind) -> ClientProfile {
    let mut profile = ClientProfile::default();
    profile.name = name.into();
    profile.profile_type = Some(kind);
    profile
}

fn prepared_renewal_store(path: PathBuf) -> orion_core::certificates::TrustStore {
    use aether::certificates::approval::AstraPolicyPin;
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, WireGuardKey};
    use aether::certificates::state::{
        AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState,
        TrustLedger,
    };
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    let (_authority_private, authority_public) =
        aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("authority key");
    let service_public = authority_public.clone();
    let domain = Id16::new([1; 16]).expect("domain id");
    let gateway_wg = WireGuardKey::from_bytes([2; 32]);
    let client_wg = WireGuardKey::from_bytes([3; 32]);
    let tls_ca = DerCertificate::new(vec![4; 64]).expect("TLS CA DER");
    let gateway_tls = DerCertificate::new(vec![5; 64]).expect("gateway TLS DER");
    let gateway_pq = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [6; 16],
        subject: "CN=gateway".into(),
        issuer: "CN=CA-PQ".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: gateway_wg.to_base64(),
        ml_dsa_87_public_key: authority_public.to_base64(),
        not_before_unix: 1,
        not_after_unix: u64::MAX,
        ml_dsa_87_signature: String::new(),
    };
    let active = ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: tls_ca.fingerprint(),
        tls_certificate_fingerprint: Fingerprint::of(b"active TLS leaf"),
        pq_certificate_fingerprint: Fingerprint::of(b"active PQ leaf"),
        not_before: 1,
        not_after: u64::MAX,
    };

    orion_core::certificates::TrustStore::new(
        path,
        orion_core::certificates::TrustState {
            credential_registry: None,
            trust_domain_id: domain,
            client_wg_public_key: client_wg,
            gateway: GatewayCertificateState {
                trust_domain_id: domain,
                gateway_wg_public_key: gateway_wg,
                server_name: "gateway.example".into(),
                ca_epoch: 1,
                current_ca_public_key: authority_public,
                next_ca_public_key: None,
                next_ca_transition_fingerprint: None,
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                next_gateway_identity_epoch: None,
                next_transition_fingerprint: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: gateway_tls,
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_pq,
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
                service_rollback: None,
                awaited_replacement: None,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 1,
                active_client_tls_ca_certificate: tls_ca,
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                    .expect("policy pin"),
                credential_registry_epoch: 1,
                credential_bindings: Default::default(),
                active_astra_service_public_key: service_public,
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 1,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer_epoch: 1,
            issuer: None,
            certificates: ClientCertificateState::new(active),
            staged_gateway_transition: None,
            ledger: TrustLedger::default(),
        },
    )
}

#[tokio::test]
async fn fleet_renewal_excludes_classic_profiles_and_keeps_each_refusal_with_its_profile() {
    let scratch = Scratch::new("fleet-refusals");
    let service = service(&scratch);
    {
        let mut config = service.config.lock().await;
        config
            .profiles
            .push(profile("classic", ProfileKind::Classic));
        config
            .profiles
            .push(profile("missing-block", ProfileKind::HeliosKeyNegotiation));
        let mut no_store = profile("no-protected-store", ProfileKind::HeliosKeyNegotiation);
        no_store.key_negotiation = Some(key_negotiation("sealed-identity"));
        config.profiles.push(no_store);
    }

    let outcome = service
        .run_certificate_action(
            String::new(),
            orion_core::CertificateAction::RenewEveryProfile,
        )
        .await
        .expect("fleet action returns per-profile outcomes");

    assert!(outcome.progress.is_empty());
    assert_eq!(outcome.refused.len(), 2);
    assert!(outcome.refused.contains_key("missing-block"));
    assert!(outcome.refused.contains_key("no-protected-store"));
    assert!(!outcome.refused.contains_key("classic"));
    assert_ne!(
        outcome.refused["missing-block"],
        outcome.refused["no-protected-store"],
        "the profile without negotiation and the profile blocked by the platform have different causes"
    );
    assert!(service.renewals.lock().await.is_empty());
    assert!(service.recoveries.lock().await.is_empty());
    assert_eq!(
        service.last_certificate_error("missing-block".into()).await,
        Some(outcome.refused["missing-block"].clone())
    );
    assert_eq!(
        service
            .last_certificate_error("no-protected-store".into())
            .await,
        Some(outcome.refused["no-protected-store"].clone())
    );
}

#[tokio::test]
async fn a_renewal_begin_failure_does_not_leave_a_partial_session_in_the_map() {
    let settings = key_negotiation("");
    let renewals = Arc::new(Mutex::new(std::collections::HashMap::new()));

    let error = drive_renewal_in_map(&renewals, "bureau", settings, "http://invalid".into())
        .await
        .expect_err("an unnamed protected identity cannot begin renewal");

    assert!(error.contains("aucune identité protégée"), "{error}");
    assert!(renewals.lock().await.is_empty());
}

#[tokio::test]
async fn failed_resume_keeps_the_existing_renewal_session_and_candidate_intact() {
    let scratch = Scratch::new("renewal-resume-retains-session");
    let service = service(&scratch);
    let original_settings = key_negotiation("original-sealed-identity");
    let store = prepared_renewal_store(scratch.0.join("trust.json"));
    store.save().expect("initial trust state persists");
    let persisted_before = std::fs::read(scratch.0.join("trust.json")).expect("trust bytes");
    let session = orion_core::certificate_renewal::RenewalSession::prepare(
        &store,
        "CN=orion-test",
        "http://127.0.0.1:1",
        1_800_000_000,
    )
    .expect("a candidate session is prepared locally");
    let request_fingerprint = session.request_fingerprint();
    let candidate_public_key = session.request().new_ml_dsa_87_public_key.to_base64();
    let active_state_before = store.state().clone();
    service.renewals.lock().await.insert(
        "bureau".to_string(),
        InFlightRenewal {
            session,
            store,
            settings: original_settings.clone(),
            approval: None,
        },
    );

    let result = drive_renewal_in_map(
        &service.renewals,
        "bureau",
        key_negotiation("replacement-identity-must-not-win"),
        "http://127.0.0.1:2".into(),
    )
    .await;

    assert!(result.is_err(), "Linux cannot unseal the active identity");
    let approval_error = service
        .approve_certificate_renewal("bureau".into(), None)
        .await
        .expect_err("approval cannot start without a verified manifest");
    assert!(approval_error.contains("lire d'abord la demande"));
    let renewals = service.renewals.lock().await;
    let retained = renewals
        .get("bureau")
        .expect("failed resume keeps the in-flight operation");
    assert_eq!(retained.settings.identity, original_settings.identity);
    assert_eq!(retained.session.request_fingerprint(), request_fingerprint);
    assert_eq!(
        retained
            .session
            .request()
            .new_ml_dsa_87_public_key
            .to_base64(),
        candidate_public_key,
        "resuming does not replace the candidate keys"
    );
    assert_eq!(retained.store.state(), &active_state_before);
    assert_eq!(
        std::fs::read(scratch.0.join("trust.json")).expect("trust bytes after refusal"),
        persisted_before,
        "a failed local resume does not persist a partial candidate"
    );
}

#[tokio::test]
async fn recovery_requires_a_negotiating_profile_before_it_can_open_or_resume() {
    let scratch = Scratch::new("recovery-no-settings");
    let service = service(&scratch);

    let error = service
        .drive_recovery("classic", None)
        .await
        .expect_err("a classic profile has no recovery identity");

    assert_eq!(error, "ce profil ne négocie pas de clé");
    assert!(service.recoveries.lock().await.is_empty());
    let resume_error = service
        .resume_certificate_recovery("00000000000000000000000000000001".into())
        .await
        .expect_err("a validly shaped identifier cannot select an absent session");
    assert!(resume_error.contains("aucune récupération ouverte"));
    assert!(service.recoveries.lock().await.is_empty());
}

#[tokio::test]
async fn renewal_begin_rejects_a_missing_identity_before_network_or_map_mutation() {
    let scratch = Scratch::new("renewal-missing-identity");
    let service = service(&scratch);
    let settings = key_negotiation("identity-not-in-protected-store");

    let result = drive_renewal_in_map(
        &service.renewals,
        "bureau",
        settings,
        "http://127.0.0.1:1".into(),
    )
    .await;

    assert!(result.is_err(), "an absent local identity cannot renew");
    assert!(service.renewals.lock().await.is_empty());
}

#[tokio::test]
async fn certificate_overview_does_not_serialize_profile_private_key_or_static_psk() {
    let scratch = Scratch::new("overview-no-secrets");
    let service = service(&scratch);
    let private_key_marker = "ORION_PRIVATE_KEY_SENTINEL";
    let psk_marker = "ORION_STATIC_PSK_SENTINEL";
    {
        let mut config = service.config.lock().await;
        let mut profile = profile("bureau", ProfileKind::HeliosKeyNegotiation);
        profile.private_key = aether::SecretString::new(private_key_marker);
        profile.preshared_key = Some(aether::SecretString::new(psk_marker));
        profile.key_negotiation = Some(key_negotiation("sealed-identity"));
        config.profiles.push(profile);
    }

    let overview = service
        .certificate_overview()
        .await
        .expect("overview is available even when Linux cannot unseal identities");
    let serialized = serde_json::to_string(&overview).expect("overview serializes");

    assert_eq!(overview.len(), 1);
    assert_eq!(overview[0].name, "bureau");
    assert!(!serialized.contains(private_key_marker));
    assert!(!serialized.contains(psk_marker));
}

#[tokio::test]
async fn automatic_renewal_skips_when_the_client_certificate_is_unavailable() {
    let scratch = Scratch::new("automatic-no-certificate");
    let service = service(&scratch);
    let prerequisite = tokio::spawn(async {});
    let task = spawn_automatic_certificate_renewal(
        prerequisite,
        Arc::clone(&service.controller),
        Arc::clone(&service.renewals),
        "bureau".into(),
        key_negotiation("sealed-identity"),
        "http://127.0.0.1:1".into(),
        Arc::new(|_| {}),
    );

    task.await.expect("automatic task exits cleanly");
    assert!(service.renewals.lock().await.is_empty());
}
