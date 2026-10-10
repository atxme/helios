use super::*;

/// Verification of the pinned gateway leaf, which only has two legal
/// shapes. Gated like [`crate::test_domain`]: the fixture signs real
/// ML-DSA-87 objects, and a test that faked them would not exercise the
/// signature check that is the whole point here.
#[cfg(feature = "certificate-signing")]
mod pinned_gateway_certificate {
    use crate::config::{verify_pinned_gateway_certificate, TrustMaterial};
    use crate::test_domain::{domain, gateway_key, settings, Domain, NOW, SERVER_NAME};
    use aether::certificates::encoding::generate_ml_dsa_87_keypair;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    /// The shape a gateway serves once it has no trust domain: the pinned
    /// bytes are the whole trust, and there is no anchor to check them under.
    fn self_signed_gateway_leaf() -> PqCertificate {
        let (private, public) = generate_ml_dsa_87_keypair().expect("gateway key");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: SERVER_NAME.into(),
                issuer: SERVER_NAME.into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key().to_base64(),
                ml_dsa_87_public_key: B64.encode(public.as_bytes()),
                not_before_unix: NOW - 3_600,
                not_after_unix: NOW + 10 * 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &private,
        )
        .expect("self-signed gateway leaf")
    }

    fn trust_of(domain: &Domain) -> TrustMaterial {
        settings(domain)
            .trust
            .expect("the fixture carries a trust block")
    }

    /// The regression this pair of checks exists for.
    ///
    /// `heliosd init-trust-domain` replaces the gateway's self-signed leaf
    /// with one issued under `CA-PQ` (ADR-008 §13.1). Verifying that leaf
    /// against its own key — which is what `verify_self_signed` does — fails
    /// by construction, so a profile pinned to a gateway with a trust domain
    /// was refused at load and no client could be enrolled at all.
    #[test]
    fn a_ca_issued_gateway_leaf_verifies_under_the_domain_anchor() {
        let domain = domain();
        let trust = trust_of(&domain);
        verify_pinned_gateway_certificate(
            &domain.gateway_leaf,
            SERVER_NAME,
            &gateway_key().to_base64(),
            Some(&trust),
            NOW,
        )
        .expect("the anchor the profile pins is the one that issued the leaf");
    }

    /// The half that keeps the fix from being a downgrade: a CA-issued leaf
    /// carries the issuer's name, never the issuer's key, so there is nothing
    /// in it to fall back on. Without the anchor it must be refused by name.
    #[test]
    fn a_ca_issued_gateway_leaf_is_refused_without_an_anchor() {
        let domain = domain();
        let error = verify_pinned_gateway_certificate(
            &domain.gateway_leaf,
            SERVER_NAME,
            &gateway_key().to_base64(),
            None,
            NOW,
        )
        .expect_err("no anchor, no verification");
        let message = format!("{error}");
        assert!(
            message.contains("CA-PQ") && message.contains("ne porte pas"),
            "the message must name the missing anchor, not the signature: {message}"
        );
    }

    /// A second domain's anchor is not this domain's anchor.
    #[test]
    fn a_ca_issued_gateway_leaf_is_refused_under_a_foreign_anchor() {
        let this = domain();
        let other = domain();
        let mut trust = trust_of(&this);
        trust.ca_pq_public_key = other.ca_pq_public.to_base64();
        verify_pinned_gateway_certificate(
            &this.gateway_leaf,
            SERVER_NAME,
            &gateway_key().to_base64(),
            Some(&trust),
            NOW,
        )
        .expect_err("a leaf signed by another authority is not this domain's gateway");
    }

    /// Profiles issued before any trust domain existed keep working: they pin
    /// a self-signed leaf and carry no anchor, and that combination stays
    /// valid rather than becoming collateral of the fix.
    #[test]
    fn a_self_signed_gateway_leaf_still_verifies_without_a_trust_block() {
        verify_pinned_gateway_certificate(
            &self_signed_gateway_leaf(),
            SERVER_NAME,
            &gateway_key().to_base64(),
            None,
            NOW,
        )
        .expect("a gateway without a trust domain is verified by its own key");
    }
}

/// The trust block's own refusals. Gated with the fixture it needs: a
/// block that validates carries a real CA-TLS and two real ML-DSA-87 keys.
#[cfg(feature = "certificate-signing")]
mod trust_material_validation {
    use crate::test_domain::{domain, settings};

    /// A block printed before the gateway identity epochs existed decodes
    /// to zero, and zero is not a state any domain is ever in (§13.1).
    ///
    /// Refused here rather than seeded: a store at epoch 0 against a
    /// registry at 1 is behind on the trust-update comparison forever, so
    /// the gateway answers `503` to every poll and no renewal repairs it.
    /// The operator is holding the gateway when this runs; the message
    /// names the command that reprints the block.
    #[test]
    fn a_block_without_the_gateway_identity_epochs_is_refused_by_name() {
        let domain = domain();
        let material = settings(&domain).trust.expect("trust block");
        material.validate().expect("the fixture's block is usable");

        for spoil in [
            |m: &mut crate::config::TrustMaterial| m.active_gateway_identity_epoch = 0,
            |m: &mut crate::config::TrustMaterial| m.gateway_decision_epoch = 0,
        ] {
            let mut stale = material.clone();
            spoil(&mut stale);
            let error = stale
                .validate()
                .expect_err("a zero gateway epoch is not a domain state");
            let message = format!("{error}");
            assert!(
                message.contains("show-trust-enrolment"),
                "the message must name the command that repairs it: {message}"
            );
        }
    }
}

/// The failure the discriminant exists for.
///
/// A Helios profile whose negotiation block is lost — a bad edit, a
/// partial import, a conversion — used to arrive looking exactly like a
/// deliberate classic profile. Orion mounted a tunnel with no
/// pre-WireGuard authentication and reported nothing, because from its
/// side nothing was wrong. That is a silent downgrade of the protection
/// level, which is the one outcome this client may not produce.
#[test]
fn a_helios_profile_that_lost_its_block_is_refused_not_downgraded() {
    let mut profile = ClientProfile {
        name: "poste".into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: "cHJpdmF0ZQ==".into(),
        peer_public_key: "cHVibGlj".into(),
        profile_type: Some(ProfileKind::HeliosKeyNegotiation),
        ..ClientProfile::default()
    };
    profile.key_negotiation = None;

    let error = profile
        .validate()
        .expect_err("the contradiction is refused");
    assert!(
        format!("{error}").contains("sans authentification avant WireGuard"),
        "the message must name the consequence, not the field: {error}"
    );
    assert!(
        profile.negotiates(),
        "the declared kind still governs: a lost block never turns a Helios \
             profile into a classic one"
    );
}

/// The other half of the exclusivity, refused for the same reason.
#[test]
fn a_classic_profile_carrying_a_negotiation_block_is_refused() {
    let profile = ClientProfile {
        name: "poste".into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: "cHJpdmF0ZQ==".into(),
        peer_public_key: "cHVibGlj".into(),
        profile_type: Some(ProfileKind::Classic),
        key_negotiation: Some(KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: "203.0.113.10:51821".into(),
            server_name: "gw.example".into(),
            gateway_ca_der: "MIIB".into(),
            gateway_pq_certificate: "e30=".into(),
            identity: "orion-poste".into(),
            trust: None,
        }),
        ..ClientProfile::default()
    };

    assert!(profile.validate().is_err());
}

/// A profile that predates the field keeps behaving exactly as before.
#[test]
fn an_undeclared_profile_falls_back_to_the_historical_inference() {
    let classic = ClientProfile {
        profile_type: None,
        ..ClientProfile::default()
    };
    assert_eq!(classic.kind(), ProfileKind::Classic);
    assert!(!classic.negotiates());
}

#[test]
fn upsert_and_remove() {
    let mut cfg = ClientConfig::default();
    cfg.upsert(ClientProfile {
        name: "a".into(),
        ..ClientProfile::default()
    })
    .unwrap();
    cfg.upsert(ClientProfile {
        name: "b".into(),
        ..ClientProfile::default()
    })
    .unwrap();
    cfg.selected = Some("b".into());
    assert_eq!(cfg.profiles.len(), 2);

    // upsert on an existing name replaces, doesn't add.
    cfg.upsert(ClientProfile {
        name: "a".into(),
        endpoint: "203.0.113.1:51820".into(),
        ..ClientProfile::default()
    })
    .unwrap();
    assert_eq!(cfg.profiles.len(), 2);
    assert_eq!(cfg.find("a").unwrap().endpoint, "203.0.113.1:51820");

    cfg.remove("b");
    assert_eq!(cfg.profiles.len(), 1);
    assert_eq!(cfg.selected.as_deref(), Some("a")); // auto re-selection
}

fn negotiating(mode: ProtectionMode, minimum_mode: ProtectionMode) -> ClientProfile {
    ClientProfile {
        name: "poste".into(),
        key_negotiation: Some(KeyNegotiationSettings {
            mode,
            minimum_mode,
            endpoint: "vpn.example.net:51821".into(),
            server_name: "vpn.example.net".into(),
            gateway_ca_der: "MIIB".into(),
            gateway_pq_certificate: "e30=".into(),
            identity: "orion-poste".into(),
            trust: None,
        }),
        ..ClientProfile::default()
    }
}

/// Saving a profile must never reopen a weaker negotiation.
///
/// The scenario is ordinary: a screen left open before the floor was
/// raised, saved afterwards. Without the ratchet, the stale draft would
/// carry the whole client back down to `classic` — exactly the downgrade
/// the gateway refuses over the network.
#[test]
fn saving_a_profile_never_lowers_the_key_negotiation_floor() {
    let mut cfg = ClientConfig::default();
    cfg.upsert(negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem))
        .unwrap();
    cfg.upsert(negotiating(
        ProtectionMode::Classic,
        ProtectionMode::Classic,
    ))
    .unwrap();

    let saved = cfg.find("poste").unwrap().key_negotiation.as_ref().unwrap();
    assert_eq!(saved.minimum_mode, ProtectionMode::MlKem);
    // A mode left below the restored floor is raised with it: the two
    // must never contradict each other on disk.
    assert_eq!(saved.mode, ProtectionMode::MlKem);
}

/// Dropping the block is a downgrade too: the legacy path leaves the
/// first handshake unprotected.
#[test]
fn saving_a_profile_without_its_block_is_refused() {
    let mut cfg = ClientConfig::default();
    cfg.upsert(negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem))
        .unwrap();
    let error = cfg
        .upsert(ClientProfile {
            name: "poste".into(),
            profile_type: Some(ProfileKind::Classic),
            ..ClientProfile::default()
        })
        .unwrap_err();

    assert!(error.to_string().contains("type du profil"));
    assert_eq!(
        cfg.find("poste").unwrap().kind(),
        ProfileKind::HeliosKeyNegotiation
    );
}

/// A separately identified Helios profile survives the save and reload.
///
/// A classic profile cannot be converted in place: the new Helios profile
/// receives another stable identifier, represented here by another name.
///
/// Serialized in place rather than through `save`/`load`: those go through
/// `ORION_CONFIG`, a process-wide variable that parallel tests would fight
/// over. The property under test is the encoding, not the file path.
#[test]
fn a_negotiation_block_survives_save_and_reload() {
    let mut cfg = ClientConfig::default();
    // The profile as it exists before enrollment: no block at all.
    cfg.upsert(ClientProfile {
        name: "poste".into(),
        endpoint: "vpn.example.net:51820".into(),
        private_key: "cHJpdmF0ZQ==".into(),
        ..ClientProfile::default()
    })
    .unwrap();
    assert!(cfg.find("poste").unwrap().key_negotiation.is_none());

    // Re-enrolled under a distinct name, now carrying negotiation.
    let mut enrolled = negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem);
    enrolled.name = "poste-helios".into();
    cfg.upsert(enrolled).unwrap();

    let encoded = cfg.encode_legacy_fixture().unwrap();
    let reloaded: ClientConfig = toml::from_str(&encoded).unwrap();
    let settings = reloaded
        .find("poste-helios")
        .expect("profile kept")
        .key_negotiation
        .as_ref()
        .expect("the negotiation block must survive the round-trip");
    assert_eq!(settings.mode, ProtectionMode::MlKem);
    assert_eq!(settings.identity, "orion-poste");
}

/// Even a legacy `classic` floor does not permit changing profile kind.
#[test]
fn a_classic_floor_does_not_allow_reclassifying_the_profile() {
    let mut cfg = ClientConfig::default();
    cfg.upsert(negotiating(
        ProtectionMode::Classic,
        ProtectionMode::Classic,
    ))
    .unwrap();
    let error = cfg
        .upsert(ClientProfile {
            name: "poste".into(),
            profile_type: Some(ProfileKind::Classic),
            ..ClientProfile::default()
        })
        .unwrap_err();

    assert!(error.to_string().contains("type du profil"));
    assert!(cfg.find("poste").unwrap().key_negotiation.is_some());
}

#[test]
fn disk_roundtrip() {
    let dir = std::env::temp_dir().join(format!("orion-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("profiles.toml");
    std::env::set_var("ORION_CONFIG", &path);

    let mut cfg = ClientConfig::default();
    cfg.upsert(ClientProfile {
        name: "site-a".into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: "cHJpdmF0ZQ==".into(),
        peer_public_key: "cHVibGlj".into(),
        preshared_key: Some("cHNr".into()),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    })
    .unwrap();
    cfg.selected = Some("site-a".into());
    cfg.save().unwrap();

    let loaded = ClientConfig::load().unwrap();
    assert_eq!(loaded.profiles.len(), 1);
    let p = loaded.find("site-a").unwrap();
    assert_eq!(p.endpoint, "203.0.113.10:51820");
    assert_eq!(p.address.as_deref(), Some("100.64.1.2/32"));
    // WireGuard defaults must survive the round-trip.
    assert_eq!(p.allowed_ips, DEFAULT_ALLOWED_IPS);
    assert_eq!(p.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
    assert!(p.has_preshared_key());
    assert_eq!(loaded.selected.as_deref(), Some("site-a"));

    // The file carries a private key and a PSK: it must never be readable
    // by anyone else. Asserted on the SECOND write too, because that is the
    // one that used to hand the mode back to the umask (ADR-006).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "mode after the first save");
        cfg.save().unwrap();
        assert_eq!(mode(&path), 0o600, "mode after a rewrite");
    }

    std::env::remove_var("ORION_CONFIG");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The default full tunnel captures both families, spelled canonically.
///
/// `0.0.0.0/0` alone let a dual-stack machine send all of its IPv6 around the
/// tunnel, in clear. The spelling matters as much: a default the import path
/// would rewrite reads as an unsaved change on the first reload.
#[test]
fn the_default_full_tunnel_captures_both_families() {
    assert_eq!(DEFAULT_ALLOWED_IPS, "0.0.0.0/0, ::/0");
    assert_eq!(
        crate::profile_import::normalize_cidr_list(DEFAULT_ALLOWED_IPS),
        DEFAULT_ALLOWED_IPS
    );
    assert!(crate::profile_import::validate_allowed_ips(DEFAULT_ALLOWED_IPS).is_ok());
    let fresh = ClientProfile::default();
    assert_eq!(fresh.allowed_ips, DEFAULT_ALLOWED_IPS);
    assert!(!fresh.ipv6_uncaptured_full_tunnel());
}

/// A profile stored with the old IPv4-only default is read back as stored.
///
/// The serde default only fills an **absent** field. A stored `0.0.0.0/0` is
/// a value, and widening it on load would change a routing table nobody
/// edited: it is flagged instead.
#[test]
fn a_stored_ipv4_only_full_tunnel_is_not_widened_on_load() {
    let raw = r#"
        selected = "site-a"

        [[profiles]]
        name = "site-a"
        endpoint = "203.0.113.10:51820"
        allowed_ips = "0.0.0.0/0"
    "#;
    let loaded: ClientConfig = toml::from_str(raw).unwrap();
    let profile = loaded.find("site-a").unwrap();
    assert_eq!(profile.allowed_ips, "0.0.0.0/0");
    assert!(profile.ipv6_uncaptured_full_tunnel());
}

/// A profile written before `address_v6` existed reads with none, and one
/// without it serializes without the key: an absent value writes nothing.
#[test]
fn an_absent_ipv6_address_is_neither_invented_nor_written() {
    let raw = r#"
        [[profiles]]
        name = "site-a"
        address = "100.64.1.2/32"
    "#;
    let loaded: ClientConfig = toml::from_str(raw).unwrap();
    let profile = loaded.find("site-a").unwrap();
    assert_eq!(profile.address_v6, None);

    let toml = toml::to_string(&profile.legacy_fixture()).unwrap();
    assert!(!toml.contains("address_v6"), "{toml}");
    let json = serde_json::to_string(&profile.legacy_fixture()).unwrap();
    assert!(!json.contains("address_v6"), "{json}");

    let dual = ClientProfile {
        address_v6: Some("fd3c:91a2:7e04::2/128".into()),
        ..profile.duplicate()
    };
    let reread: ClientProfile =
        toml::from_str(&toml::to_string(&dual.legacy_fixture()).unwrap()).unwrap();
    assert_eq!(reread.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));
}

#[test]
fn secrets_masked_in_debug() {
    let p = ClientProfile {
        private_key: "TRES_SECRET".into(),
        preshared_key: Some("PSK_SECRET".into()),
        ..ClientProfile::default()
    };
    let dump = format!("{p:?}");
    assert!(
        !dump.contains("TRES_SECRET"),
        "the private key leaks into logs"
    );
    assert!(!dump.contains("PSK_SECRET"), "the PSK leaks into logs");
}
