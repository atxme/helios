//! The key negotiation block of an operator document: settings, protection
//! floor, gateway pinning and trust material.

use aether::key_negotiation::ProtectionMode;
use base64::Engine as _;

use super::fixtures::{document_with, gateway_settings, CLIENT_PRIVATE};
use crate::profile_import::parse_profile_import;

/// The trust material is checked when it arrives, not at the first
/// renewal — 80 % into a leaf's life is the worst moment to discover a
/// typo an operator made months earlier.
#[test]
fn an_unusable_trust_block_is_refused_at_import() {
    let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    settings.as_object_mut().unwrap().insert(
        "trust".into(),
        serde_json::json!({
            "trust_domain_id": "pas de l'hexadécimal",
            "ca_epoch": 1,
            "ca_pq_public_key": "",
            "ca_tls_epoch": 1,
            "client_tls_ca_der": "",
            "client_generation": 4,
            "astra_authority_url": "https://astra.example",
            "webauthn_rp_id": "astra.example",
            "astra_policy_fingerprint": "1111111111111111111111111111111111111111111111111111111111111111",
            "credential_registry_epoch": 1,
            "astra_service_key_epoch": 1,
            "astra_service_public_key": "",
        }),
    );
    let error = parse_profile_import(&document_with(settings), "portable.orion")
        .unwrap_err()
        .to_string();
    assert!(error.contains("matériel de confiance"));
}

/// A genuine trust block imports, and reaches the profile intact.
#[test]
fn a_genuine_trust_block_reaches_the_profile() {
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;
    use base64::engine::general_purpose::STANDARD;

    let (_, ca_pq) = generate_ml_dsa_87_keypair().unwrap();
    let (_, astra) = generate_ml_dsa_87_keypair().unwrap();
    let ca_tls = aether::certificates::test_x509::certificate_authority("CA-TLS");

    let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    settings.as_object_mut().unwrap().insert(
        "trust".into(),
        serde_json::json!({
            "trust_domain_id": "0102030405060708090a0b0c0d0e0f10",
            "ca_epoch": 2,
            "ca_pq_public_key": ca_pq.to_base64(),
            "ca_tls_epoch": 1,
            "client_tls_ca_der": STANDARD.encode(ca_tls.as_bytes()),
            "client_generation": 4,
            "astra_authority_url": "https://astra.example",
            "webauthn_rp_id": "astra.example",
            "astra_policy_fingerprint": "1111111111111111111111111111111111111111111111111111111111111111",
            "credential_registry_epoch": 1,
            "astra_service_key_epoch": 1,
            "astra_service_public_key": astra.to_base64(),
            "active_gateway_identity_epoch": 1,
            "gateway_decision_epoch": 1,
        }),
    );
    let imported = parse_profile_import(&document_with(settings), "portable.orion")
        .expect("a genuine trust block");
    let trust = imported
        .profile
        .key_negotiation
        .and_then(|block| block.trust)
        .expect("the trust material reaches the profile");
    assert_eq!(trust.ca_epoch, 2);
    assert_eq!(trust.client_generation, 4);
    assert_eq!(trust.active_gateway_identity_epoch, 1);
    assert_eq!(trust.gateway_decision_epoch, 1);
    assert!(trust.trust_domain().is_ok());
    assert!(trust.ca_pq().is_ok());
    assert!(trust.client_tls_ca().is_ok());
}

/// The operator document is the vehicle for the negotiation settings:
/// without it, the screen would have nothing to display and the user
/// would have to retype a certificate by hand.
#[test]
fn imports_the_key_negotiation_block_of_an_operator_document() {
    let settings = gateway_settings(ProtectionMode::MlKem);
    let raw = document_with(serde_json::to_value(&settings).unwrap());

    let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
    let imported = profile.key_negotiation.expect("block expected");
    assert_eq!(imported.mode, ProtectionMode::MlKem);
    assert_eq!(imported.minimum_mode, ProtectionMode::MlKem);
    assert_eq!(imported.endpoint, "vpn.example.net:51821");
    assert!(imported.gateway_pq_fingerprint().is_some());
}

/// An absent floor is not "no floor": accepting a classic negotiation
/// tomorrow would void the mode chosen today.
#[test]
fn an_imported_block_without_a_floor_takes_its_selected_mode_as_floor() {
    let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("minimum_mode")
        .expect("the fixture carries a floor");

    let profile = parse_profile_import(&document_with(settings), "portable.json")
        .unwrap()
        .profile;
    assert_eq!(
        profile.key_negotiation.unwrap().minimum_mode,
        ProtectionMode::MlKem
    );
}

/// A document that asks for less than its own floor is contradictory:
/// import refuses it rather than silently picking a side.
#[test]
fn a_mode_below_the_declared_floor_is_refused_at_import() {
    let mut settings = gateway_settings(ProtectionMode::StaticPsk);
    settings.minimum_mode = ProtectionMode::MlKem;
    let raw = document_with(serde_json::to_value(&settings).unwrap());

    let error = parse_profile_import(&raw, "portable.json")
        .expect_err("a mode below the floor must be refused")
        .to_string();
    assert!(error.contains("plancher"), "message : {error}");
}

/// A certificate pinned to another gateway must not pass for this one:
/// it's the only check that ties the imported material to the peer key
/// the profile is about to talk to.
#[test]
fn a_certificate_pinned_to_another_gateway_is_refused() {
    let settings = gateway_settings(ProtectionMode::MlKem);
    let mut document: serde_json::Value =
        serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
    document["profile"]["peer_public_key"] = serde_json::Value::String(CLIENT_PRIVATE.to_string());

    assert!(parse_profile_import(&document.to_string(), "portable.json").is_err());
}

/// A document written before the gateway identity epochs existed is refused
/// here, where the operator can reprint the block.
///
/// Importing it would seed a store at epoch 0 against a registry that starts
/// at 1, and every trust update this profile ever sent would come back as a
/// `503` that no renewal repairs — discovered on the user's machine, months
/// later, as a refusal nobody can explain.
#[test]
fn a_trust_block_without_the_gateway_identity_epochs_is_refused_at_import() {
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;
    use base64::engine::general_purpose::STANDARD;

    let (_, ca_pq) = generate_ml_dsa_87_keypair().unwrap();
    let (_, astra) = generate_ml_dsa_87_keypair().unwrap();
    let ca_tls = aether::certificates::test_x509::certificate_authority("CA-TLS");

    let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    settings.as_object_mut().unwrap().insert(
        "trust".into(),
        serde_json::json!({
            "trust_domain_id": "0102030405060708090a0b0c0d0e0f10",
            "ca_epoch": 2,
            "ca_pq_public_key": ca_pq.to_base64(),
            "ca_tls_epoch": 1,
            "client_tls_ca_der": STANDARD.encode(ca_tls.as_bytes()),
            "client_generation": 4,
            "astra_authority_url": "https://astra.example",
            "webauthn_rp_id": "astra.example",
            "astra_policy_fingerprint": "1111111111111111111111111111111111111111111111111111111111111111",
            "credential_registry_epoch": 1,
            "astra_service_key_epoch": 1,
            "astra_service_public_key": astra.to_base64(),
        }),
    );
    let error = parse_profile_import(&document_with(settings), "portable.orion")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("matériel de confiance"),
        "the import names the trust block: {error}"
    );
}

/// `classic` is no longer a negotiation mode, so a document that still names
/// it is refused at import, with the French message of an invalid document.
#[test]
fn a_classic_negotiation_mode_is_refused_at_import() {
    let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    settings["mode"] = serde_json::json!("classic");
    let raw = document_with(settings);

    let error = parse_profile_import(&raw, "ancien.orion")
        .expect_err("a classic negotiation mode must be refused")
        .to_string();
    assert!(
        error.contains("document JSON Orion invalide"),
        "message : {error}"
    );
}
