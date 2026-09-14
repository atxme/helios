//! The negotiation identity shipped inside the document: returned apart from
//! the profile, and tied to the entry it names.

use aether::key_negotiation::ProtectionMode;

use super::fixtures::{document_with, gateway_settings, identity_bundle};
use crate::profile_import::parse_profile_import;

/// The identity travels with the profile so the user has **one** file to
/// import — but it must come back separately, because the two have
/// opposite destinies: one is persisted, the other is sealed.
#[test]
fn the_shipped_identity_is_returned_apart_from_the_profile() {
    let settings = gateway_settings(ProtectionMode::MlKem);
    let mut document: serde_json::Value =
        serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
    document["profile"]["key_negotiation_identity"] = identity_bundle(&settings.identity);

    let imported = parse_profile_import(&document.to_string(), "portable.json").unwrap();
    let identity = imported.identity.expect("identity expected");
    assert_eq!(identity.identity, settings.identity);

    // The decisive property: nothing of the secret can reach the profile,
    // hence nothing can reach `profiles.toml`.
    let persisted = toml::to_string(&imported.profile).unwrap();
    assert!(!persisted.contains("pq_private_key"), "{persisted}");
    assert!(
        !persisted.contains(&identity.pq_private_key),
        "the PQ private key must not be persistable"
    );
}

/// An identity sealed under a name the profile never looks up would be a
/// secret stored for nothing.
#[test]
fn an_identity_naming_another_entry_is_refused() {
    let settings = gateway_settings(ProtectionMode::MlKem);
    let mut document: serde_json::Value =
        serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
    document["profile"]["key_negotiation_identity"] = identity_bundle("un-autre-poste");

    let error = parse_profile_import(&document.to_string(), "portable.json")
        .expect_err("mismatched identity must be refused")
        .to_string();
    assert!(error.contains("un-autre-poste"), "message : {error}");
}
