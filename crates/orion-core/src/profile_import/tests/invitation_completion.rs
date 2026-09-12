//! Completion of a partial document: what the gap report names, and which
//! local key may complete an invitation.

use aether::key_negotiation::ProtectionMode;
use base64::Engine as _;

use super::fixtures::{
    complete_profile, document_with, gateway_settings, identity_bundle, CLIENT_PRIVATE,
    GATEWAY_PUBLIC,
};
use crate::profile_import::{complete_profile_import, parse_profile_import};
use crate::{ClientConfig, ClientProfile, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

/// A document may leave fields out; it is loaded, not refused.
///
/// The operator sends what they know. Refusing to *parse* an invitation
/// with no endpoint returned the user to a file picker with a sentence,
/// instead of to a form with one field left to fill. `validate` is what
/// decides whether a tunnel may mount — parsing only decides whether the
/// document is intelligible.
#[test]
fn a_partial_document_is_loaded_and_its_gap_named() {
    let document = serde_json::json!({
        "format": "orion-profile",
        "version": 1,
        "profile": { "name": "poste" },
    })
    .to_string();

    let imported =
        parse_profile_import(&document, "poste.orion").expect("un document partiel doit se lire");
    assert_eq!(imported.profile.name, "poste");
    // The defaults are applied rather than left empty.
    assert_eq!(imported.profile.allowed_ips, DEFAULT_ALLOWED_IPS);
    assert_eq!(
        imported.profile.persistent_keepalive,
        DEFAULT_KEEPALIVE_SECS
    );

    let completed =
        complete_profile_import(imported.profile, &ClientConfig::default(), None, Vec::new())
            .expect("l'import ne refuse pas un document incomplet");
    assert!(
        completed.private_key_missing.is_some(),
        "l'absence de clé privée doit être nommée"
    );
    assert!(
        completed.incomplete.is_some(),
        "ce qui reste à compléter doit être nommé, pas tu"
    );
}

/// A complete document reports nothing to fill in.
#[test]
fn a_complete_document_reports_no_gap() {
    let pair = aether::wg::generate_keypair().expect("keypair");
    let profile = ClientProfile {
        private_key: pair.private_key.expose().to_string(),
        ..complete_profile()
    };
    let completed = complete_profile_import(profile, &ClientConfig::default(), None, Vec::new())
        .expect("import");
    assert!(completed.private_key_missing.is_none());
    assert!(
        completed.incomplete.is_none(),
        "obtenu : {:?}",
        completed.incomplete
    );
}

/// Adding negotiation to a profile that already exists must not disturb
/// its WireGuard identity.
///
/// This is the ordinary upgrade path: a client enrolled long ago is
/// re-enrolled from its **public** key, so the document carries no
/// private key and completion takes the local one. Regenerating a key
/// here would silently break an admission the gateway already holds.
#[test]
fn enrolling_an_existing_profile_keeps_its_wireguard_identity() {
    let settings = gateway_settings(ProtectionMode::MlKem);
    let mut document: serde_json::Value =
        serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
    // Invitation form: `helios-ctl enroll --public-key <clé existante>`.
    document["profile"]["private_key"] = serde_json::Value::String(String::new());

    let imported = parse_profile_import(&document.to_string(), "portable.json").unwrap();
    assert!(imported.profile.private_key.is_empty());

    let mut config = ClientConfig::default();
    config
        .upsert(ClientProfile {
            name: "portable".into(),
            private_key: CLIENT_PRIVATE.into(),
            ..complete_profile()
        })
        .unwrap();

    let completed = complete_profile_import(imported.profile, &config, None, Vec::new())
        .unwrap()
        .profile;
    assert_eq!(completed.private_key, CLIENT_PRIVATE);
    assert!(
        completed.key_negotiation.is_some(),
        "the negotiation block must survive completion"
    );
}

/// The decisive case of an enrolled client: the operator names it
/// `poste-windows`, the machine kept it under another name, and the
/// admitted key is the same on both sides. Matching by name refused the
/// document; matching by key is what makes it importable.
#[test]
fn an_invitation_is_completed_by_the_admitted_key_whatever_the_name() {
    use base64::engine::general_purpose::STANDARD;

    let admitted = ClientProfile {
        private_key: CLIENT_PRIVATE.into(),
        ..complete_profile()
    }
    .public_key()
    .unwrap();

    let settings = gateway_settings(ProtectionMode::MlKem);
    let mut document: serde_json::Value =
        serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
    document["profile"]["private_key"] = serde_json::Value::String(String::new());
    let mut bundle = identity_bundle(&settings.identity);
    bundle["pq_certificate"] =
        serde_json::Value::String(STANDARD.encode(
            serde_json::json!({ "version": 1, "wireguard_public_key": admitted }).to_string(),
        ));
    document["profile"]["key_negotiation_identity"] = bundle;

    let imported = parse_profile_import(&document.to_string(), "portable.orion").unwrap();
    assert_eq!(imported.admitted_public_key().as_deref(), Some(&*admitted));

    let mut config = ClientConfig::default();
    config
        .upsert(ClientProfile {
            // Same client, other name: the situation the name rule refused.
            name: "poste-de-christophe".into(),
            private_key: CLIENT_PRIVATE.into(),
            ..complete_profile()
        })
        .unwrap();

    let admitted_key = imported.admitted_public_key();
    let completed = complete_profile_import(
        imported.profile,
        &config,
        admitted_key.as_deref(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(completed.private_key_missing, None);
    assert_eq!(completed.profile.private_key, CLIENT_PRIVATE);
    assert_eq!(completed.profile.name, "portable");
}

/// A same-name profile holding **another** key is not a match: it was
/// never admitted, and using it would produce a tunnel that handshakes
/// with nobody.
#[test]
fn a_local_profile_holding_another_key_does_not_complete_an_invitation() {
    let invitation = ClientProfile {
        private_key: String::new(),
        ..complete_profile()
    };
    let mut config = ClientConfig::default();
    config
        .upsert(ClientProfile {
            private_key: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into(),
            ..complete_profile()
        })
        .unwrap();

    let completed = complete_profile_import(
        invitation,
        &config,
        Some("une-autre-clé-publique"),
        Vec::new(),
    )
    .unwrap();
    let message = completed
        .private_key_missing
        .expect("an unadmitted local key must not complete the document");
    assert!(message.contains("une-autre-clé-publique"), "{message}");
    assert!(completed.profile.private_key.is_empty());
}

/// Invitation profile (ADR-004 §6): the operator admits the public key
/// the client sent, and returns everything **except** the private key,
/// which it never held. The UI takes it back from the local profile of
/// the same name.
#[test]
fn imports_an_invitation_without_a_private_key() {
    let raw = format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "address": "100.64.1.2/32"
            }}
        }}"#
    );

    let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
    assert!(
        profile.private_key.is_empty(),
        "the invitation must carry no private key"
    );
    assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
    assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
    assert!(
        profile.validate().is_err(),
        "an invitation alone must not be presented as connectable"
    );
}

#[test]
fn completes_an_invitation_with_the_local_key_of_the_same_name() {
    let invitation = ClientProfile {
        name: "portable".into(),
        endpoint: "vpn.example.net:51820".into(),
        peer_public_key: GATEWAY_PUBLIC.into(),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    };
    let config = ClientConfig {
        profiles: vec![ClientProfile {
            name: "portable".into(),
            private_key: CLIENT_PRIVATE.into(),
            ..ClientProfile::default()
        }],
        selected: None,
    };

    let completed = complete_profile_import(invitation, &config, None, Vec::new()).unwrap();
    assert_eq!(completed.private_key_missing, None);
    assert_eq!(completed.profile.private_key, CLIENT_PRIVATE);
}

#[test]
fn reports_an_invitation_without_a_matching_local_key() {
    let invitation = ClientProfile {
        name: "portable".into(),
        endpoint: "vpn.example.net:51820".into(),
        peer_public_key: GATEWAY_PUBLIC.into(),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    };

    // Reported, not raised: the draft stays visible so the user sees
    // which endpoint and which address were issued, and can paste the
    // key rather than being told to start over.
    let completed =
        complete_profile_import(invitation, &ClientConfig::default(), None, Vec::new()).unwrap();
    let message = completed
        .private_key_missing
        .expect("the absence of a key must be reported");
    assert!(message.contains("aucun profil local"), "{message}");
    assert!(completed.profile.private_key.is_empty());
    assert_eq!(completed.profile.name, "portable");
}
