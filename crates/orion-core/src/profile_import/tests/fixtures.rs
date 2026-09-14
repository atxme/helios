//! Shared constructors for the `orion-profile` v1 documents and profiles
//! the import tests are written against.

use aether::key_negotiation::ProtectionMode;
use base64::Engine as _;

use crate::profile_import::{PROFILE_IMPORT_FORMAT, PROFILE_IMPORT_VERSION};
use crate::{ClientProfile, KeyNegotiationSettings};

pub(super) const CLIENT_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
pub(super) const GATEWAY_PUBLIC: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

/// Temporary directory of the calling test.
///
/// Named after the process **and** the thread: the suite runs in
/// parallel, and two tests writing `portable.orion` in one shared
/// directory would delete each other's file.
pub(super) fn temp_directory(prefix: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "{prefix}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

pub(super) fn complete_profile() -> ClientProfile {
    ClientProfile {
        name: "poste".into(),
        endpoint: "vpn.example.net:51820".into(),
        private_key: CLIENT_PRIVATE.into(),
        peer_public_key: GATEWAY_PUBLIC.into(),
        address: Some("100.64.1.2/32".into()),
        allowed_ips: "0.0.0.0/0".into(),
        persistent_keepalive: 25,
        ..ClientProfile::default()
    }
}

/// Gateway material as the operator distributes it: public certificate,
/// public CA, and the name of the protected store entry — never the
/// client's own private key.
pub(super) fn gateway_settings(mode: ProtectionMode) -> KeyNegotiationSettings {
    use aether::key_negotiation::{
        generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
        PQ_CERTIFICATE_VERSION,
    };
    use base64::engine::general_purpose::STANDARD;

    let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [7u8; 16],
            subject: "vpn.example.net".into(),
            issuer: "vpn.example.net".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: GATEWAY_PUBLIC.into(),
            ml_dsa_87_public_key: STANDARD.encode(&public_key),
            not_before_unix: now - 60,
            not_after_unix: now + 3600,
            ml_dsa_87_signature: String::new(),
        },
        &private_key,
    )
    .unwrap();

    KeyNegotiationSettings {
        mode,
        minimum_mode: mode,
        endpoint: "vpn.example.net:51821".into(),
        server_name: "vpn.example.net".into(),
        gateway_ca_der: STANDARD.encode([0x30, 0x82, 0x01, 0x00]),
        gateway_pq_certificate: STANDARD.encode(serde_json::to_vec(&certificate).unwrap()),
        identity: "orion-portable".into(),
        trust: None,
    }
}

pub(super) fn document_with(settings: serde_json::Value) -> String {
    serde_json::json!({
        "format": PROFILE_IMPORT_FORMAT,
        "version": PROFILE_IMPORT_VERSION,
        "profile": {
            "name": "portable",
            "endpoint": "vpn.example.net:51820",
            "private_key": CLIENT_PRIVATE,
            "peer_public_key": GATEWAY_PUBLIC,
            "address": "100.64.1.2/32",
            "key_negotiation": settings,
        }
    })
    .to_string()
}

/// A document declaring its kind, with or without a negotiation block.
pub(super) fn document_of_kind(kind: &str, settings: Option<serde_json::Value>) -> String {
    let mut profile = serde_json::json!({
        "name": "portable",
        "endpoint": "vpn.example.net:51820",
        "private_key": CLIENT_PRIVATE,
        "peer_public_key": GATEWAY_PUBLIC,
        "address": "100.64.1.2/32",
        "type": kind,
    });
    if let Some(settings) = settings {
        profile
            .as_object_mut()
            .unwrap()
            .insert("key_negotiation".into(), settings);
    }
    serde_json::json!({
        "format": PROFILE_IMPORT_FORMAT,
        "version": PROFILE_IMPORT_VERSION,
        "profile": profile,
    })
    .to_string()
}

pub(super) fn identity_bundle(name: &str) -> serde_json::Value {
    use base64::engine::general_purpose::STANDARD;

    serde_json::json!({
        "identity": name,
        "certificate_chain": [STANDARD.encode([0x30, 0x82, 0x01, 0x00])],
        "private_key": STANDARD.encode([0x30, 0x81, 0x87, 0x02]),
        "pq_certificate": STANDARD.encode(br#"{"version":1}"#),
        "pq_private_key": STANDARD.encode([7u8; 64]),
    })
}
