use super::*;
use aether::certificates::encoding::Id16;
use orion_core::certificate_recovery::RecoveryStep;
use orion_core::{ClientProfile, ProfileKind};

fn profile_with_secrets() -> (ClientProfile, String, String) {
    let pair = aether::wg::generate_keypair().expect("WireGuard keypair");
    let private = pair.private_key.expose().to_owned();
    let public = pair.public_key;
    let profile = ClientProfile {
        name: "poste".into(),
        endpoint: "203.0.113.7:51820".into(),
        private_key: private.clone().into(),
        peer_public_key: "gateway-public".into(),
        preshared_key: Some("static-psk-secret".into()),
        profile_type: Some(ProfileKind::HeliosKeyNegotiation),
        ..ClientProfile::default()
    };
    (profile, private, public)
}

#[test]
fn profile_view_redacts_secret_values_but_preserves_presence_and_public_identity() {
    let (profile, private, public) = profile_with_secrets();
    let view = ProfileView::from(&profile);
    let encoded = serde_json::to_value(&view).expect("view serializes");

    assert_eq!(view.public_key.as_deref(), Some(public.as_str()));
    assert!(view.has_private_key);
    assert!(view.has_static_psk);
    assert_eq!(view.profile_type, "helios_key_negotiation");
    let fields = encoded.as_object().expect("view is a JSON object");
    assert!(!fields.values().any(|value| value == &private));
    assert!(!fields.values().any(|value| value == "static-psk-secret"));
    assert!(!fields.contains_key("private_key"));
    assert!(!fields.contains_key("preshared_key"));
}

#[test]
fn profile_without_local_secrets_reports_absence_without_inventing_identity() {
    let profile = ClientProfile {
        name: "invitation-incomplete".into(),
        profile_type: Some(ProfileKind::Classic),
        ..ClientProfile::default()
    };
    let view = ProfileView::from(&profile);

    assert!(!view.has_private_key);
    assert!(!view.has_static_psk);
    assert_eq!(view.public_key, None);
    assert_eq!(view.profile_type, "classic");
}

#[test]
fn config_view_keeps_selection_and_profile_order_and_starts_without_vault_error() {
    let (first, _, _) = profile_with_secrets();
    let second = ClientProfile {
        name: "secours".into(),
        ..ClientProfile::default()
    };
    let config = ClientConfig {
        profiles: vec![first, second],
        selected: Some("secours".into()),
    };

    let view = ConfigView::from(&config);
    assert_eq!(
        view.profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        ["poste", "secours"]
    );
    assert_eq!(view.selected.as_deref(), Some("secours"));
    assert_eq!(view.vault_error, None);
    assert!(view.profiles[0].has_private_key);
    assert!(!view.profiles[1].has_private_key);
}

#[test]
fn action_outcome_attributes_progress_to_the_requested_profile() {
    let outcome = ActionOutcome::of("bureau", RenewalProgress::Committed { generation: 8 });

    assert_eq!(
        outcome.progress.get("bureau"),
        Some(&RenewalProgress::Committed { generation: 8 })
    );
    assert!(outcome.refused.is_empty());
}

#[test]
fn renewal_progress_uses_stable_discriminants_and_keeps_operation_context() {
    let issuing = serde_json::to_value(RenewalProgress::Issuing {
        operation_id: "op-123".into(),
    })
    .expect("progress serializes");
    assert_eq!(issuing["step"], "issuing");
    assert_eq!(issuing["operation_id"], "op-123");

    let recovered = serde_json::to_value(RenewalProgress::Recovered {
        generation: 9,
        activation_at: 1_900_000_000,
    })
    .expect("recovery progress serializes");
    assert_eq!(recovered["step"], "recovered");
    assert_eq!(recovered["generation"], 9);
    assert_eq!(recovered["activation_at"], 1_900_000_000);
    assert!(recovered.get("operation_id").is_none());
}

#[test]
fn renewal_steps_map_to_progress_without_losing_operation_or_generation() {
    let operation_id = Id16::new([0x2a; 16]).expect("operation id");

    assert_eq!(
        RenewalProgress::of(&RenewalStep::AwaitingOperator { operation_id }),
        RenewalProgress::AwaitingOperator {
            operation_id: operation_id.to_hex()
        }
    );
    assert_eq!(
        RenewalProgress::of(&RenewalStep::Issuing { operation_id }),
        RenewalProgress::Issuing {
            operation_id: operation_id.to_hex()
        }
    );
    assert_eq!(
        RenewalProgress::of(&RenewalStep::Committed {
            generation: u64::MAX
        }),
        RenewalProgress::Committed {
            generation: u64::MAX
        }
    );
}

#[test]
fn recovery_steps_keep_the_recovery_discriminant_and_all_context() {
    let operation_id = Id16::new([0x51; 16]).expect("operation id");

    assert_eq!(
        RenewalProgress::of_recovery(&RecoveryStep::AwaitingOperator { operation_id }),
        RenewalProgress::RecoveryAwaitingOperator {
            operation_id: operation_id.to_hex()
        }
    );
    assert_eq!(
        RenewalProgress::of_recovery(&RecoveryStep::Issuing { operation_id }),
        RenewalProgress::Issuing {
            operation_id: operation_id.to_hex()
        }
    );
    assert_eq!(
        RenewalProgress::of_recovery(&RecoveryStep::Recovered {
            generation: 17,
            activation_at: u64::MAX,
        }),
        RenewalProgress::Recovered {
            generation: 17,
            activation_at: u64::MAX,
        }
    );
}

#[test]
fn action_outcome_can_report_progress_and_refusals_for_different_profiles() {
    let outcome = ActionOutcome {
        progress: [(
            "bureau".into(),
            RenewalProgress::Committed { generation: 12 },
        )]
        .into_iter()
        .collect(),
        refused: [("secours".into(), "gateway unavailable".into())]
            .into_iter()
            .collect(),
    };
    let encoded = serde_json::to_value(&outcome).expect("outcome serializes");

    assert_eq!(encoded["progress"]["bureau"]["step"], "committed");
    assert_eq!(encoded["progress"]["bureau"]["generation"], 12);
    assert_eq!(encoded["refused"]["secours"], "gateway unavailable");
    assert_eq!(
        serde_json::from_value::<ActionOutcome>(encoded).expect("outcome deserializes"),
        outcome
    );
}
