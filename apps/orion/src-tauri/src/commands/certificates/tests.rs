use super::*;
#[cfg(not(windows))]
use crate::commands::test_support::command_app;
use crate::commands::test_support::scripted_engine;
use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraCredentialBinding, CredentialRegistry, CredentialState,
    PER_REQUEST_APPROVAL_CREDENTIALS,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, WireGuardKey,
};
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::ProtectionMode;
use aether_fido::authenticator::{Authenticator, CredentialSubject};
use aether_fido::DomainIdentity;
use astra_operator::operations::fixtures::{TestKey, NOW};
use orion_core::CertificateActionBlock;

const PROFILE: &str = "workstation-a";
const OTHER: &str = "workstation-b";
const RP_ID: &str = "astra.example";
const PIN: &str = "fixture-pin";

fn settings() -> KeyNegotiationSettings {
    KeyNegotiationSettings {
        mode: ProtectionMode::MlKem,
        minimum_mode: ProtectionMode::MlKem,
        endpoint: "vpn.example:51821".into(),
        server_name: "vpn.example".into(),
        gateway_ca_der: "ZGVy".into(),
        gateway_pq_certificate: "cHFj".into(),
        identity: "protected-workstation-a".into(),
        trust: None,
    }
}

fn inventory() -> CertificateInventory {
    CertificateInventory {
        identity_sealed: true,
        faults: vec!["gateway PQ leaf is unreadable".into()],
        ..CertificateInventory::default()
    }
}

fn blocked_action() -> CertificateActionState {
    let reason = CertificateActionBlock::PreviousIdentityExpired { expired_at: 640 };
    CertificateActionState {
        action: CertificateAction::RollbackToPrevious,
        label: CertificateAction::RollbackToPrevious.label().into(),
        message: Some(reason.message()),
        blocked_by: Some(reason),
    }
}

#[cfg(not(windows))]
#[tokio::test]
async fn state_backed_certificate_commands_forward_through_the_managed_engine_client() {
    use tauri::Manager;

    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let state = app.state::<AppState>();
    let expected_settings = settings();

    let command_task = async {
        let inventory = certificate_inventory(state.clone(), Some(expected_settings.clone())).await;
        let overview = certificate_overview(state.clone()).await;
        let actions = certificate_actions(state.clone(), Some(expected_settings.clone())).await;
        let action =
            run_certificate_action(state.clone(), PROFILE.into(), CertificateAction::RenewNow)
                .await;
        let recovery = resume_certificate_recovery(state.clone(), "operation-a".into()).await;
        let manifest = certificate_approval_manifest(state.clone(), PROFILE.into()).await;
        let error = last_certificate_error(state, PROFILE.into()).await;
        (
            inventory, overview, actions, action, recovery, manifest, error,
        )
    };
    let engine_task = async {
        engine
            .reply(|command| {
                assert!(matches!(
                    command,
                    EngineCommand::CertificateInventory {
                        key_negotiation: Some(_)
                    }
                ));
                Ok(EngineReply::CertificateInventory(inventory()))
            })
            .await;
        engine
            .reply(|command| {
                assert!(matches!(command, EngineCommand::CertificateOverview));
                Ok(EngineReply::CertificateOverview(Vec::new()))
            })
            .await;
        engine
            .reply(|command| {
                assert!(matches!(
                    command,
                    EngineCommand::CertificateActions {
                        key_negotiation: Some(_)
                    }
                ));
                Ok(EngineReply::CertificateActions(vec![blocked_action()]))
            })
            .await;
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::RunCertificateAction { name, action: CertificateAction::RenewNow } if name == PROFILE));
            Ok(EngineReply::ActionOutcome(ActionOutcome::of(
                PROFILE,
                RenewalProgress::Committed { generation: 12 },
            )))
        }).await;
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::ResumeCertificateRecovery { operation_id } if operation_id == "operation-a"));
            Ok(EngineReply::ActionOutcome(ActionOutcome::of(
                PROFILE,
                RenewalProgress::Recovered {
                    generation: 12,
                    activation_at: NOW + 200,
                },
            )))
        }).await;
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::CertificateApprovalManifest { name } if name == PROFILE));
            Ok(EngineReply::ApprovalManifest(ApprovalManifest {
                operation_id: "operation-a".into(),
                client_wg_public_key: WireGuardKey::from_bytes([8; 32]).to_base64(),
                active_generation: 11,
                requested_generation: 12,
                request_fingerprint: Fingerprint::of(b"rotation request").to_hex(),
                expires_at: NOW + 150,
                eligible_credentials: 1,
            }))
        }).await;
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::LastCertificateError { name } if name == PROFILE));
            Ok(EngineReply::LastError(Some("request expired".into())))
        }).await;
    };

    let (
        (
            inventory_result,
            overview_result,
            actions_result,
            action_result,
            recovery_result,
            manifest_result,
            error_result,
        ),
        (),
    ) = tokio::join!(command_task, engine_task);
    assert_eq!(inventory_result.unwrap(), inventory());
    assert!(overview_result.unwrap().is_empty());
    assert_eq!(actions_result.unwrap(), vec![blocked_action()]);
    assert_eq!(
        action_result.unwrap().progress.get(PROFILE),
        Some(&RenewalProgress::Committed { generation: 12 })
    );
    assert_eq!(
        recovery_result.unwrap().progress.get(PROFILE),
        Some(&RenewalProgress::Recovered {
            generation: 12,
            activation_at: NOW + 200,
        })
    );
    assert_eq!(manifest_result.unwrap().eligible_credentials, 1);
    assert_eq!(error_result.unwrap().as_deref(), Some("request expired"));
}

#[tokio::test]
async fn inventory_forwarding_keeps_the_profile_pins_and_partial_faults() {
    let (client, mut engine) = scripted_engine().await;
    let expected = settings();
    let (result, ()) = tokio::join!(
        certificate_inventory_from(&client, Some(expected.clone())),
        engine.reply(|command| {
            let EngineCommand::CertificateInventory { key_negotiation } = command else {
                panic!("expected CertificateInventory");
            };
            assert_eq!(
                serde_json::to_value(key_negotiation).unwrap(),
                serde_json::to_value(&expected).unwrap(),
            );
            Ok(EngineReply::CertificateInventory(inventory()))
        })
    );
    assert_eq!(result.unwrap(), inventory());
}

#[tokio::test]
async fn actions_for_a_classic_profile_send_no_settings() {
    let (client, mut engine) = scripted_engine().await;
    let blocked = CertificateActionState {
        action: CertificateAction::RenewNow,
        label: CertificateAction::RenewNow.label().into(),
        blocked_by: Some(CertificateActionBlock::NoNegotiation),
        message: Some(CertificateActionBlock::NoNegotiation.message()),
    };
    let (result, ()) = tokio::join!(
        certificate_actions_from(&client, None),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::CertificateActions {
                    key_negotiation: None
                }
            ));
            Ok(EngineReply::CertificateActions(vec![blocked.clone()]))
        })
    );
    assert_eq!(result.unwrap(), vec![blocked]);
}

#[tokio::test]
async fn overview_preserves_profile_order_and_keeps_each_profiles_error_and_actions() {
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(
        certificate_overview_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::CertificateOverview));
            Ok(EngineReply::CertificateOverview(vec![
                ProfileCertificates {
                    name: OTHER.into(),
                    identity: String::new(),
                    negotiates: false,
                    inventory: CertificateInventory::default(),
                    actions: Vec::new(),
                    last_error: None,
                },
                ProfileCertificates {
                    name: PROFILE.into(),
                    identity: settings().identity,
                    negotiates: true,
                    inventory: inventory(),
                    actions: vec![blocked_action()],
                    last_error: Some("staged identity expired".into()),
                },
            ]))
        })
    );
    let profiles = result.unwrap();
    let [classic, negotiated] = profiles.as_slice() else {
        panic!("expected both profiles");
    };
    assert_eq!(classic.name, OTHER);
    assert!(!classic.negotiates);
    assert!(classic.last_error.is_none());
    assert_eq!(negotiated.name, PROFILE);
    assert_eq!(negotiated.identity, settings().identity);
    assert!(negotiated.negotiates);
    assert_eq!(
        negotiated.last_error.as_deref(),
        Some("staged identity expired")
    );
    assert_eq!(negotiated.inventory, inventory());
    assert_eq!(negotiated.actions, vec![blocked_action()]);
}

#[tokio::test]
async fn fleet_renewal_keeps_progress_and_refusals_attributed_to_their_profiles() {
    let (client, mut engine) = scripted_engine().await;
    let mut outcome = ActionOutcome::of(
        PROFILE,
        RenewalProgress::AwaitingOperator {
            operation_id: "operation-a".into(),
        },
    );
    outcome
        .refused
        .insert(OTHER.into(), "no protected identity".into());
    let (result, ()) = tokio::join!(
        run_certificate_action_with(
            &client,
            PROFILE.into(),
            CertificateAction::RenewEveryProfile
        ),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::RunCertificateAction {
                    name,
                    action: CertificateAction::RenewEveryProfile,
                } if name == PROFILE
            ));
            Ok(EngineReply::ActionOutcome(outcome.clone()))
        })
    );
    assert_eq!(result.unwrap(), outcome);
}

#[tokio::test]
async fn recovered_identity_keeps_the_operation_and_activation_deadline() {
    let (client, mut engine) = scripted_engine().await;
    let operation_id = "68656c696f732d7265636f7665727921";
    let outcome = ActionOutcome::of(
        PROFILE,
        RenewalProgress::Recovered {
            generation: 9,
            activation_at: 2_000,
        },
    );
    let (result, ()) = tokio::join!(
        resume_certificate_recovery_with(&client, operation_id.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::ResumeCertificateRecovery { operation_id: received }
                    if received == operation_id
            ));
            Ok(EngineReply::ActionOutcome(outcome.clone()))
        })
    );
    assert_eq!(result.unwrap(), outcome);
}

#[tokio::test]
async fn approval_manifest_returns_the_verified_peer_and_generation_for_the_named_profile() {
    let (client, mut engine) = scripted_engine().await;
    let manifest = ApprovalManifest {
        operation_id: "operation-a".into(),
        client_wg_public_key: WireGuardKey::from_bytes([8; 32]).to_base64(),
        active_generation: 11,
        requested_generation: 12,
        request_fingerprint: Fingerprint::of(b"rotation request").to_hex(),
        expires_at: NOW + 150,
        eligible_credentials: 2,
    };
    let (result, ()) = tokio::join!(
        certificate_approval_manifest_from(&client, PROFILE.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::CertificateApprovalManifest { name } if name == PROFILE
            ));
            Ok(EngineReply::ApprovalManifest(manifest.clone()))
        })
    );
    assert_eq!(result.unwrap(), manifest);
}

#[tokio::test]
async fn last_certificate_error_distinguishes_an_error_record_from_no_record() {
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(
        async {
            let first = last_certificate_error_from(&client, PROFILE.into())
                .await
                .unwrap();
            let second = last_certificate_error_from(&client, OTHER.into())
                .await
                .unwrap();
            (first, second)
        },
        async {
            engine
                .reply(|command| {
                    assert!(matches!(
                        command,
                        EngineCommand::LastCertificateError { name } if name == PROFILE
                    ));
                    Ok(EngineReply::LastError(Some("request expired".into())))
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(
                        command,
                        EngineCommand::LastCertificateError { name } if name == OTHER
                    ));
                    Ok(EngineReply::LastError(None))
                })
                .await;
        }
    );
    assert_eq!(result, (Some("request expired".into()), None));
}

#[tokio::test]
async fn engine_refusal_is_preserved_for_a_single_profile_action() {
    let (client, mut engine) = scripted_engine().await;
    let refusal = "L'identité précédente ne peut pas être réintroduite.";
    let (result, ()) = tokio::join!(
        run_certificate_action_with(
            &client,
            PROFILE.into(),
            CertificateAction::RollbackToPrevious
        ),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::RunCertificateAction {
                    name,
                    action: CertificateAction::RollbackToPrevious,
                } if name == PROFILE
            ));
            Err(refusal.into())
        })
    );
    assert_eq!(result.unwrap_err(), refusal);
}

#[tokio::test]
async fn a_reply_from_another_command_is_an_error_even_if_that_reply_is_empty() {
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(
        certificate_actions_from(&client, Some(settings())),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::CertificateActions { .. }));
            Ok(EngineReply::CertificateOverview(Vec::new()))
        })
    );
    assert_eq!(result.unwrap_err(), unexpected_engine_reply());
}

fn approval_fixture() -> (TestKey, ApprovalMaterial) {
    let key = TestKey::new(1);
    let registration = key
        .register(
            RP_ID,
            &CredentialSubject {
                user_id: vec![1],
                user_name: "operator".into(),
                display_name: "Operator".into(),
            },
            &[],
            PIN,
        )
        .expect("register fixture key");
    let (ca_private, ca_pq) = generate_ml_dsa_87_keypair().expect("CA-PQ fixture");
    let (service_private, service_key) =
        generate_ml_dsa_87_keypair().expect("Astra service fixture");
    let identity = DomainIdentity {
        trust_domain_id: Id16::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        server_name: "vpn.example".into(),
        ca_epoch: 2,
        ca_tls_epoch: 3,
    };
    let allowed_credential_ids = vec![registration.credential_id.clone()];
    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: registration.credential_id,
        credential_public_key: registration.credential_public_key,
        aaguid: registration.aaguid,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 4,
        ca_epoch: identity.ca_epoch,
        created_at: NOW - 100,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("sign binding");
    let registry = CredentialRegistry {
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        ca_epoch: identity.ca_epoch,
        credential_registry_epoch: 4,
        bindings: vec![binding],
    };
    let request = AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: Id16::new([3; 16]).expect("operation"),
        request_fingerprint: Fingerprint::of(b"rotation request"),
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        client_wg_public_key: WireGuardKey::from_bytes([8; 32]),
        active_generation: 11,
        requested_generation: 12,
        credential_registry_epoch: registry.credential_registry_epoch,
        webauthn_rp_id: RP_ID.into(),
        webauthn_origin: format!("https://{RP_ID}"),
        allowed_credential_ids,
        required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
        created_at: NOW - 10,
        expires_at: NOW + 150,
        astra_service_key_epoch: 5,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service_private)
    .expect("sign request");
    (
        key,
        ApprovalMaterial {
            active_generation: request.active_generation,
            service_key_epoch: request.astra_service_key_epoch,
            request: Box::new(request),
            registry: Box::new(registry),
            identity,
            service_key,
            ca_pq,
            rp_id: RP_ID.into(),
        },
    )
}

fn material_reply(
    command: EngineCommand,
    material: ApprovalMaterial,
) -> Result<EngineReply, String> {
    assert!(matches!(
        command,
        EngineCommand::CertificateApprovalMaterial { name } if name == PROFILE
    ));
    Ok(EngineReply::ApprovalMaterial(Box::new(material)))
}

#[tokio::test]
async fn mismatched_approval_material_reply_stops_before_the_key() {
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(
        approve_certificate_renewal_with(&client, PROFILE.into(), None, |_, _| {
            panic!("must not consult a key after the wrong engine reply")
        }),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::CertificateApprovalMaterial { name } if name == PROFILE
            ));
            Ok(EngineReply::Unit)
        })
    );
    assert_eq!(result.unwrap_err(), unexpected_engine_reply());
}

#[tokio::test]
async fn a_failed_key_gesture_does_not_submit_and_the_same_operation_can_be_retried() {
    let (client, mut engine) = scripted_engine().await;
    let (key, material) = approval_fixture();
    let operation_id = material.request.operation_id;
    let request_fingerprint = material.request.request_fingerprint;
    let approval_request_fingerprint = material.request.fingerprint();
    let expected_progress = RenewalProgress::Issuing {
        operation_id: operation_id.to_hex(),
    };

    let (result, ()) = tokio::join!(
        async {
            let decline =
                approve_certificate_renewal_with(&client, PROFILE.into(), None, |_, pin| {
                    assert!(pin.is_empty());
                    Err("operator cancelled the gesture".into())
                })
                .await;
            assert_eq!(decline.unwrap_err(), "operator cancelled the gesture");
            approve_certificate_renewal_with(
                &client,
                PROFILE.into(),
                Some(PIN.into()),
                move |material, pin| {
                    assert_eq!(pin, PIN);
                    let approval = material
                        .approve(&key, pin, NOW)
                        .map_err(|err| err.to_string())?;
                    assert_eq!(key.touches.get(), 1);
                    Ok(approval)
                },
            )
            .await
        },
        async {
            engine
                .reply(|command| material_reply(command, material.clone()))
                .await;
            // The retry must request material again; a premature submission fails here.
            engine
                .reply(|command| material_reply(command, material))
                .await;
            engine
                .reply(|command| {
                    let EngineCommand::SubmitCertificateApproval { name, approval } = command
                    else {
                        panic!("expected assertion submission after the key gesture");
                    };
                    assert_eq!(name, PROFILE);
                    let approval = approval.into_inner();
                    assert_eq!(approval.operation_id, operation_id);
                    assert_eq!(approval.request_fingerprint, request_fingerprint);
                    assert_eq!(
                        approval.approval_request_fingerprint,
                        approval_request_fingerprint
                    );
                    assert!(!approval.webauthn_assertion.signature.is_empty());
                    Ok(EngineReply::RenewalProgress(expected_progress.clone()))
                })
                .await;
        }
    );

    assert_eq!(result.unwrap(), expected_progress);
}
