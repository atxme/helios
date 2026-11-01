//! The authorization policy, checked against the enum itself.

use super::{EngineCommand, EngineReply, ProfileDraft, SecretInput};
use crate::view::{
    AboutView, ActionOutcome, ConfigView, ImportOutcome, InvitationPreviewView,
    KeyNegotiationSupport, ProfileCertificates, ProfileView, RenewalProgress,
};
use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraCredentialBinding, AstraRenewalApproval,
    CredentialRegistry, CredentialState,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, WireGuardKey,
};
use aether::certificates::WebAuthnAssertion;
use orion_core::certificate_approval::{ApprovalManifest, ApprovalMaterial};
use orion_core::enrollment::PendingEnrollment;
use orion_core::{
    CertificateAction, CertificateActionState, CertificateInventory, ClientConfig, ClientProfile,
    ProfileIssues, SpeedTestResult,
};

/// The secret every fixture carries: no output may ever contain it.
const SECRET: &str = "SECRET-QUI-NE-DOIT-PAS-FUIR";

/// The « Moteur » column of the command partition, written out here on
/// purpose: changing the policy means changing this list too.
///
/// `import_profile_path` is absent on purpose: the UI reads the file it is
/// given and sends the engine only its text (F11 ruling), so no command of
/// the engine names a path.
const ENGINE_COMMANDS: [&str; 38] = [
    "get_state",
    "backend_kind",
    "adapter_is_up",
    "about_orion",
    "key_negotiation_support",
    "run_speed_test",
    "connect",
    "disconnect",
    "renew_psk",
    "get_config",
    "import_profile",
    "vault_posture",
    "allow_unencrypted_volume",
    "generate_private_key",
    "adopt_private_key",
    "discard_staged_key",
    "adopt_preshared_key",
    "discard_staged_psk",
    "ssh_command",
    "save_profile",
    "delete_profile",
    "select_profile",
    "validate_profile",
    "preview_enrollment_invitation",
    "begin_enrollment",
    "list_pending_enrollments",
    "export_pending_request",
    "discard_pending_enrollment",
    "certificate_inventory",
    "certificate_overview",
    "certificate_actions",
    "run_certificate_action",
    "resume_certificate_recovery",
    "certificate_approval_manifest",
    "certificate_approval_material",
    "submit_certificate_approval",
    "last_certificate_error",
    "shutdown",
];

fn approval_fixture() -> AstraRenewalApproval {
    let binding = binding_fixture();
    AstraRenewalApproval {
        format_version: 1,
        operation_id: Id16::new([3; 16]).expect("non-zero id"),
        request_fingerprint: Fingerprint::of(b"request"),
        approval_request_fingerprint: Fingerprint::of(b"signed request"),
        credential_fingerprint: Fingerprint::of(b"credential"),
        assertion_fingerprint: Fingerprint::of(b"assertion"),
        credential_binding: binding,
        webauthn_assertion: WebAuthnAssertion {
            authenticator_data: vec![1],
            client_data_json: vec![2],
            signature: vec![3],
        },
        approved_at: 1_000,
        expires_at: 1_200,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    }
}

fn binding_fixture() -> AstraCredentialBinding {
    AstraCredentialBinding {
        format_version: 1,
        credential_id: b"credential-one".to_vec(),
        credential_public_key: vec![4],
        aaguid: [0; 16],
        trust_domain_id: Id16::new([1; 16]).expect("non-zero id"),
        gateway_wg_public_key: WireGuardKey::from_bytes([5; 32]),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 900,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
}

/// A material assembled from unsigned public objects: nothing is verified
/// when it is deserialised, which is all the wire tests need.
fn material_fixture() -> ApprovalMaterial {
    let domain = Id16::new([1; 16]).expect("non-zero id");
    let gateway = WireGuardKey::from_bytes([5; 32]);
    let (_, key) = generate_ml_dsa_87_keypair().expect("a key pair");
    let request = AstraCredentialApprovalRequest {
        format_version: 1,
        operation_id: Id16::new([3; 16]).expect("non-zero id"),
        request_fingerprint: Fingerprint::of(b"request"),
        trust_domain_id: domain,
        gateway_wg_public_key: gateway,
        client_wg_public_key: WireGuardKey::from_bytes([6; 32]),
        active_generation: 1,
        requested_generation: 2,
        credential_registry_epoch: 1,
        webauthn_rp_id: "astra.example".into(),
        webauthn_origin: "https://astra.example".into(),
        allowed_credential_ids: vec![b"credential-one".to_vec()],
        required_credentials: 1,
        created_at: 1_000,
        expires_at: 1_200,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    };
    let registry = CredentialRegistry {
        trust_domain_id: domain,
        gateway_wg_public_key: gateway,
        ca_epoch: 1,
        credential_registry_epoch: 1,
        bindings: vec![binding_fixture()],
    };
    serde_json::from_value(serde_json::json!({
        "request": request,
        "registry": registry,
        "identity": {
            "trust_domain_id": domain,
            "gateway_wg_public_key": gateway,
            "server_name": "gateway.example",
            "ca_epoch": 1,
            "ca_tls_epoch": 1,
        },
        "service_key": key,
        "service_key_epoch": 1,
        "ca_pq": key,
        "rp_id": "astra.example",
        "active_generation": 1,
    }))
    .expect("a material deserialises")
}

fn secret() -> SecretInput {
    SecretInput::from(SECRET.to_string())
}

fn draft() -> ProfileDraft {
    serde_json::from_value(serde_json::json!({
        "name": "poste",
        "endpoint": "203.0.113.10:51820",
        "peer_public_key": "cHVibGlj",
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25,
    }))
    .expect("a minimal draft deserialises")
}

/// One command of each variant.
///
/// The `label` match below has no wildcard: a variant added to the enum stops
/// this module from compiling until it is labelled here and listed above.
fn every_command() -> Vec<EngineCommand> {
    vec![
        EngineCommand::GetState,
        EngineCommand::BackendKind,
        EngineCommand::AdapterIsUp,
        EngineCommand::AboutOrion,
        EngineCommand::KeyNegotiationSupport,
        EngineCommand::RunSpeedTest {
            mode: "download".into(),
        },
        EngineCommand::Connect {
            name: Some("poste".into()),
        },
        EngineCommand::Disconnect,
        EngineCommand::RenewPsk,
        EngineCommand::GetConfig,
        EngineCommand::ImportProfile {
            contents: secret(),
            file_name: "poste.helios-profile".into(),
        },
        EngineCommand::VaultPosture,
        EngineCommand::AllowUnencryptedVolume,
        EngineCommand::GeneratePrivateKey,
        EngineCommand::AdoptPrivateKey {
            private_key: secret(),
        },
        EngineCommand::DiscardStagedKey,
        EngineCommand::AdoptPresharedKey {
            preshared_key: secret(),
        },
        EngineCommand::DiscardStagedPsk,
        EngineCommand::SshCommand { name: None },
        EngineCommand::SaveProfile { draft: draft() },
        EngineCommand::DeleteProfile {
            name: "poste".into(),
        },
        EngineCommand::SelectProfile {
            name: "poste".into(),
        },
        EngineCommand::ValidateProfile { draft: draft() },
        EngineCommand::PreviewEnrollmentInvitation {
            contents: "invitation".into(),
        },
        EngineCommand::BeginEnrollment {
            invitation: "invitation".into(),
            confirmed_ca_fingerprint: "empreinte".into(),
            requested_name: "poste".into(),
        },
        EngineCommand::ListPendingEnrollments,
        EngineCommand::ExportPendingRequest {
            request_id: "0123".into(),
        },
        EngineCommand::DiscardPendingEnrollment {
            request_id: "0123".into(),
        },
        EngineCommand::CertificateInventory {
            key_negotiation: None,
        },
        EngineCommand::CertificateOverview,
        EngineCommand::CertificateActions {
            key_negotiation: None,
        },
        EngineCommand::RunCertificateAction {
            name: "poste".into(),
            action: orion_core::CertificateAction::RenewEveryProfile,
        },
        EngineCommand::ResumeCertificateRecovery {
            operation_id: "0123".into(),
        },
        EngineCommand::CertificateApprovalManifest {
            name: "poste".into(),
        },
        EngineCommand::CertificateApprovalMaterial {
            name: "poste".into(),
        },
        EngineCommand::SubmitCertificateApproval {
            name: "poste".into(),
            approval: Box::new(approval_fixture()),
        },
        EngineCommand::LastCertificateError {
            name: "poste".into(),
        },
        EngineCommand::Shutdown,
    ]
}

/// The wire name of each variant, from an exhaustive match.
fn label(command: &EngineCommand) -> &'static str {
    match command {
        EngineCommand::GetState => "get_state",
        EngineCommand::BackendKind => "backend_kind",
        EngineCommand::AdapterIsUp => "adapter_is_up",
        EngineCommand::AboutOrion => "about_orion",
        EngineCommand::KeyNegotiationSupport => "key_negotiation_support",
        EngineCommand::RunSpeedTest { .. } => "run_speed_test",
        EngineCommand::Connect { .. } => "connect",
        EngineCommand::Disconnect => "disconnect",
        EngineCommand::RenewPsk => "renew_psk",
        EngineCommand::GetConfig => "get_config",
        EngineCommand::ImportProfile { .. } => "import_profile",
        EngineCommand::VaultPosture => "vault_posture",
        EngineCommand::AllowUnencryptedVolume => "allow_unencrypted_volume",
        EngineCommand::GeneratePrivateKey => "generate_private_key",
        EngineCommand::AdoptPrivateKey { .. } => "adopt_private_key",
        EngineCommand::DiscardStagedKey => "discard_staged_key",
        EngineCommand::AdoptPresharedKey { .. } => "adopt_preshared_key",
        EngineCommand::DiscardStagedPsk => "discard_staged_psk",
        EngineCommand::SshCommand { .. } => "ssh_command",
        EngineCommand::SaveProfile { .. } => "save_profile",
        EngineCommand::DeleteProfile { .. } => "delete_profile",
        EngineCommand::SelectProfile { .. } => "select_profile",
        EngineCommand::ValidateProfile { .. } => "validate_profile",
        EngineCommand::PreviewEnrollmentInvitation { .. } => "preview_enrollment_invitation",
        EngineCommand::BeginEnrollment { .. } => "begin_enrollment",
        EngineCommand::ListPendingEnrollments => "list_pending_enrollments",
        EngineCommand::ExportPendingRequest { .. } => "export_pending_request",
        EngineCommand::DiscardPendingEnrollment { .. } => "discard_pending_enrollment",
        EngineCommand::CertificateInventory { .. } => "certificate_inventory",
        EngineCommand::CertificateOverview => "certificate_overview",
        EngineCommand::CertificateActions { .. } => "certificate_actions",
        EngineCommand::RunCertificateAction { .. } => "run_certificate_action",
        EngineCommand::ResumeCertificateRecovery { .. } => "resume_certificate_recovery",
        EngineCommand::CertificateApprovalManifest { .. } => "certificate_approval_manifest",
        EngineCommand::CertificateApprovalMaterial { .. } => "certificate_approval_material",
        EngineCommand::SubmitCertificateApproval { .. } => "submit_certificate_approval",
        EngineCommand::LastCertificateError { .. } => "last_certificate_error",
        EngineCommand::Shutdown => "shutdown",
    }
}

#[test]
fn secret_input_never_shows_in_debug() {
    let commands = [
        EngineCommand::AdoptPresharedKey {
            preshared_key: secret(),
        },
        EngineCommand::AdoptPrivateKey {
            private_key: secret(),
        },
        EngineCommand::ImportProfile {
            contents: secret(),
            file_name: "poste.helios-profile".into(),
        },
    ];
    for command in &commands {
        // The rendering is not printed on failure: it would carry the secret.
        assert!(!format!("{command:?}").contains(SECRET));
    }
    assert!(!format!("{:?}", secret()).contains(SECRET));
}

#[test]
fn a_secret_arrives_as_a_plain_json_string() {
    let command: EngineCommand = serde_json::from_value(serde_json::json!({
        "command": "adopt_preshared_key",
        "preshared_key": SECRET,
    }))
    .expect("the UI sends the secret as a string");
    let EngineCommand::AdoptPresharedKey { preshared_key } = command else {
        panic!("wrong variant");
    };
    assert_eq!(preshared_key.expose(), SECRET);
}

#[test]
fn no_engine_command_names_an_output_path() {
    for command in every_command() {
        let value = serde_json::to_value(&command).expect("a command serialises");
        let fields = value.as_object().expect("a command is a JSON object");
        for key in fields.keys() {
            let forbidden = matches!(
                key.as_str(),
                "output" | "out" | "destination" | "path" | "exe" | "executable" | "program"
            );
            assert!(
                !forbidden,
                "{} names the forbidden field {key}",
                label(&command)
            );
        }
    }
}

#[test]
fn the_command_list_matches_the_partition() {
    let commands = every_command();
    let mut produced: Vec<&str> = commands.iter().map(label).collect();
    produced.sort_unstable();
    let mut partition = ENGINE_COMMANDS.to_vec();
    partition.sort_unstable();
    assert_eq!(produced, partition);

    // The wire name is the label: what the UI sends is what the policy lists.
    for command in &commands {
        let value = serde_json::to_value(command).expect("a command serialises");
        assert_eq!(value["command"], label(command));
    }
}

/// A profile whose private key and static PSK both carry the secret.
fn secret_profile() -> ClientProfile {
    ClientProfile {
        name: "poste".into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: SECRET.into(),
        peer_public_key: "cHVibGlj".into(),
        preshared_key: Some(SECRET.into()),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    }
}

/// One reply of each variant. The fixtures that come from a profile carry the
/// secret, through the same conversions production uses.
fn every_reply() -> Vec<EngineReply> {
    let config = ClientConfig {
        profiles: vec![secret_profile()],
        selected: Some("poste".into()),
    };
    let imported = ImportOutcome {
        profile: ProfileView::from(&secret_profile()),
        identity_sealed: false,
        private_key_missing: None,
        incomplete: None,
        notices: Vec::new(),
    };
    let progress = RenewalProgress::AwaitingOperator {
        operation_id: "0123".into(),
    };
    vec![
        EngineReply::Unit,
        EngineReply::State("connected".into()),
        EngineReply::Backend("dry-run".into()),
        EngineReply::Flag(true),
        EngineReply::About(AboutView {
            version: "0.27.0".into(),
            backend: "dry-run".into(),
            profile_extension: "helios-profile".into(),
            log_path: None,
        }),
        EngineReply::KeyNegotiation(KeyNegotiationSupport {
            identity_store: true,
        }),
        EngineReply::SpeedTest(SpeedTestResult {
            latency_ms: 12.5,
            jitter_ms: 0.5,
            latency_p95_ms: 14.0,
            download_mbps: 800.0,
            upload_mbps: 400.0,
            download_variation_pct: 1.0,
            upload_variation_pct: 2.0,
            duration_ms: 9_000,
            download_bytes: 1_000,
            upload_bytes: 500,
            parallel_streams: 4,
            measurement_rounds: 3,
            mode: orion_core::SpeedTestMode::Full,
            tcp_download_mbps: None,
            tcp_upload_mbps: None,
            udp_download_mbps: None,
            udp_upload_mbps: None,
            udp_loss_pct: None,
            udp_jitter_ms: None,
            tcp_streams: 4,
            test_duration_secs: 10,
        }),
        EngineReply::Config(ConfigView::from(&config)),
        EngineReply::Imported(imported.clone()),
        EngineReply::VaultPosture(orion_core::vault::VaultPosture {
            hardware_backed: true,
            software_keystore: false,
            volume: "bitlocker".to_string(),
            volume_protected: true,
            unencrypted_volume_waived: false,
            memory_locked: true,
            memory: "locked".to_string(),
            dumps_excluded: true,
            dumps: "excluded".to_string(),
            rotation_required: Vec::new(),
            legacy_present: false,
        }),
        EngineReply::PublicKey("cHVibGlj".into()),
        EngineReply::SshCommand("ssh operateur@poste".into()),
        EngineReply::Issues(ProfileIssues::default()),
        EngineReply::InvitationPreview(InvitationPreviewView {
            server_name: "passerelle".into(),
            ca_fingerprint: "0123 4567".into(),
            expires_at_unix: 1_800_000_000,
            invitation_token: "invitation".into(),
        }),
        EngineReply::EnrollmentStarted("0123".into()),
        EngineReply::PendingEnrollments(vec![PendingEnrollment {
            invitation_id: Id16::new([1; 16]).expect("non-zero id"),
            request_id: Id16::new([2; 16]).expect("non-zero id"),
            requested_name: "poste".into(),
            server_name: "passerelle".into(),
            created_at_unix: 1_800_000_000,
            invitation_expires_at_unix: 1_800_003_600,
        }]),
        EngineReply::RequestFile("request".into()),
        EngineReply::CertificateInventory(CertificateInventory::default()),
        EngineReply::CertificateOverview(vec![ProfileCertificates {
            name: "poste".into(),
            identity: "identite".into(),
            negotiates: true,
            inventory: CertificateInventory::default(),
            actions: Vec::new(),
            last_error: None,
        }]),
        EngineReply::CertificateActions(vec![CertificateActionState {
            action: CertificateAction::RenewEveryProfile,
            label: "Renouveler".into(),
            blocked_by: None,
            message: None,
        }]),
        EngineReply::ActionOutcome(ActionOutcome::default()),
        EngineReply::ApprovalManifest(ApprovalManifest {
            operation_id: "0123".into(),
            client_wg_public_key: "cHVibGlj".into(),
            active_generation: 1,
            requested_generation: 2,
            request_fingerprint: "abcd".into(),
            expires_at: 1_800_000_000,
            eligible_credentials: 1,
        }),
        EngineReply::RenewalProgress(progress),
        EngineReply::ApprovalMaterial(Box::new(material_fixture())),
        EngineReply::LastError(Some("échec".into())),
    ]
}

/// The wire name of each reply variant, from an exhaustive match.
fn reply_label(reply: &EngineReply) -> &'static str {
    match reply {
        EngineReply::Unit => "unit",
        EngineReply::State(_) => "state",
        EngineReply::Backend(_) => "backend",
        EngineReply::Flag(_) => "flag",
        EngineReply::About(_) => "about",
        EngineReply::KeyNegotiation(_) => "key_negotiation",
        EngineReply::SpeedTest(_) => "speed_test",
        EngineReply::Config(_) => "config",
        EngineReply::Imported(_) => "imported",
        EngineReply::VaultPosture(_) => "vault_posture",
        EngineReply::PublicKey(_) => "public_key",
        EngineReply::SshCommand(_) => "ssh_command",
        EngineReply::Issues(_) => "issues",
        EngineReply::InvitationPreview(_) => "invitation_preview",
        EngineReply::EnrollmentStarted(_) => "enrollment_started",
        EngineReply::PendingEnrollments(_) => "pending_enrollments",
        EngineReply::RequestFile(_) => "request_file",
        EngineReply::CertificateInventory(_) => "certificate_inventory",
        EngineReply::CertificateOverview(_) => "certificate_overview",
        EngineReply::CertificateActions(_) => "certificate_actions",
        EngineReply::ActionOutcome(_) => "action_outcome",
        EngineReply::ApprovalManifest(_) => "approval_manifest",
        EngineReply::RenewalProgress(_) => "renewal_progress",
        EngineReply::ApprovalMaterial(_) => "approval_material",
        EngineReply::LastError(_) => "last_error",
    }
}

#[test]
fn every_reply_serializes_without_secret_material() {
    // The fixture must really carry the key, or the absence checked below
    // would prove nothing.
    let config = serde_json::to_string(&EngineReply::Config(ConfigView::from(&ClientConfig {
        profiles: vec![secret_profile()],
        selected: None,
    })))
    .expect("a reply serialises");
    assert!(config.contains("\"has_private_key\":true"));

    for reply in every_reply() {
        let json = serde_json::to_string(&reply).expect("a reply serialises");
        assert!(
            !json.contains(SECRET),
            "{} carries secret material",
            reply_label(&reply)
        );
    }
}

#[test]
fn every_reply_round_trips() {
    assert_eq!(
        serde_json::to_value(EngineReply::Unit).expect("a reply serialises"),
        serde_json::json!({"reply": "unit"})
    );
    for reply in every_reply() {
        let label = reply_label(&reply);
        let json = serde_json::to_string(&reply).expect("a reply serialises");
        let back: EngineReply = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("{label} does not deserialise: {error}"));
        assert_eq!(reply_label(&back), label);
        assert_eq!(serde_json::to_string(&back).expect("serialises"), json);
        let value = serde_json::to_value(&reply).expect("a reply serialises");
        assert_eq!(value["reply"], label);
    }
}

#[test]
fn the_approval_commands_round_trip() {
    for command in [
        EngineCommand::CertificateApprovalMaterial {
            name: "poste".into(),
        },
        EngineCommand::SubmitCertificateApproval {
            name: "poste".into(),
            approval: Box::new(approval_fixture()),
        },
    ] {
        let json = serde_json::to_string(&command).expect("a command serialises");
        let back: EngineCommand = serde_json::from_str(&json).expect("it deserialises");
        assert_eq!(label(&back), label(&command));
        assert_eq!(serde_json::to_string(&back).expect("serialises"), json);
    }
}

#[test]
fn the_retired_approval_commands_no_longer_deserialise() {
    for retired in [
        serde_json::json!({"command": "approve_certificate_renewal", "name": "poste", "pin": null}),
        serde_json::json!({"command": "certificate_approval_needs_pin", "name": "poste"}),
        serde_json::json!({"command": "companion_arguments", "name": "poste"}),
    ] {
        assert!(serde_json::from_value::<EngineCommand>(retired).is_err());
    }
}
