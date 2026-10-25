//! The authorization policy, checked against the enum itself.

use super::{EngineCommand, ProfileDraft, SecretInput};

/// The secret every fixture carries: no output may ever contain it.
const SECRET: &str = "SECRET-QUI-NE-DOIT-PAS-FUIR";

/// The « Moteur » column of the command partition, written out here on
/// purpose: changing the policy means changing this list too.
const ENGINE_COMMANDS: [&str; 39] = [
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
    "import_profile_path",
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
    "approve_certificate_renewal",
    "certificate_approval_needs_pin",
    "last_certificate_error",
    "shutdown",
];

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
        EngineCommand::ImportProfilePath {
            path: Some("C:\\profils\\poste.helios-profile".into()),
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
        EngineCommand::ApproveCertificateRenewal {
            name: "poste".into(),
            pin: Some(secret()),
        },
        EngineCommand::CertificateApprovalNeedsPin {
            name: "poste".into(),
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
        EngineCommand::ImportProfilePath { .. } => "import_profile_path",
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
        EngineCommand::ApproveCertificateRenewal { .. } => "approve_certificate_renewal",
        EngineCommand::CertificateApprovalNeedsPin { .. } => "certificate_approval_needs_pin",
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
        EngineCommand::ApproveCertificateRenewal {
            name: "poste".into(),
            pin: Some(secret()),
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
            let reads_a_profile = key == "path" && label(&command) == "import_profile_path";
            assert!(
                !forbidden || reads_a_profile,
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
