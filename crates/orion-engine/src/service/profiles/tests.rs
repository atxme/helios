//! The merge of a draft onto what is stored, and the choice of the edit base:
//! what the save and the validation both rely on, checked without a vault.

use super::merge_draft;
use crate::command::ProfileDraft;
use crate::service::{StagedKey, StagedPsk};
use crate::view::ProfileView;
use orion_core::ClientProfile;

fn profile(name: &str) -> ClientProfile {
    let pair = aether::wg::generate_keypair().expect("keypair");
    let gateway = aether::wg::generate_keypair().expect("keypair");
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: pair.private_key.duplicate(),
        peer_public_key: gateway.public_key,
        preshared_key: Some("cHNrLXN0YXRpcXVlLWhvcnMtYmFuZGU=".into()),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    }
}

fn draft(name: &str) -> ProfileDraft {
    ProfileDraft {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        peer_public_key: "cHVibGlj".into(),
        address: None,
        address_v6: None,
        allowed_ips: "0.0.0.0/0".into(),
        persistent_keepalive: 25,
        heliosd_url: None,
        key_negotiation: None,
        use_staged_key: false,
        clear_preshared_key: false,
        use_staged_psk: false,
        ssh_target: None,
    }
}

#[test]
fn a_pending_import_replaces_the_stored_wireguard_identity() {
    let stored = profile("poste-windows");
    let imported = profile("poste-windows");
    assert_ne!(stored.private_key, imported.private_key);

    let base = super::profile_edit_base(Some(&imported), Some(&stored))
        .expect("an imported profile is the edit base");
    let merged = merge_draft(draft("poste-windows"), Some(base), None, None)
        .expect("the imported profile remains complete");

    assert_eq!(merged.private_key, imported.private_key);
    assert_ne!(merged.private_key, stored.private_key);
}

/// The IPv6 gap of an old full tunnel reaches the screen as the core's verdict.
///
/// And saving such a profile for an unrelated edit hands its list back
/// untouched: the screen warns, the user decides, nothing widens it on the
/// way through.
#[test]
fn the_view_flags_an_ipv4_only_full_tunnel_and_saving_keeps_it() {
    let legacy = ClientProfile {
        allowed_ips: "0.0.0.0/0".into(),
        ..profile("poste")
    };
    assert!(ProfileView::from(&legacy).ipv6_uncaptured_full_tunnel);
    assert!(!ProfileView::from(&profile("poste")).ipv6_uncaptured_full_tunnel);
    let split = ClientProfile {
        allowed_ips: "100.64.0.1/32, 10.0.0.0/8".into(),
        ..profile("poste")
    };
    assert!(!ProfileView::from(&split).ipv6_uncaptured_full_tunnel);

    let mut edit = draft("poste");
    edit.endpoint = "198.51.100.7:51820".into();
    edit.allowed_ips = ProfileView::from(&legacy).allowed_ips;
    let merged = merge_draft(edit, Some(&legacy), None, None).expect("merge");
    assert_eq!(merged.allowed_ips, "0.0.0.0/0");
    assert!(merged.ipv6_uncaptured_full_tunnel());
}

/// The IPv6 address makes the round trip through the screen: shown as `null`
/// for a profile without one, kept by a save that sends it back, and set or
/// cleared only by the draft (`ADRESSAGE-IPV6.md` §8).
#[test]
fn the_ipv6_address_round_trips_through_the_view_and_the_draft() {
    let ipv4 = profile("poste");
    let json = serde_json::to_value(ProfileView::from(&ipv4)).expect("serialise");
    assert!(json["address_v6"].is_null(), "{json}");

    let dual = ClientProfile {
        address_v6: Some("fd3c:91a2:7e04::2/128".into()),
        ..profile("poste")
    };
    let view = ProfileView::from(&dual);
    assert_eq!(view.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));

    let mut edit = draft("poste");
    edit.address_v6 = view.address_v6.clone();
    let merged = merge_draft(edit, Some(&dual), None, None).expect("merge");
    assert_eq!(merged.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));

    let cleared = merge_draft(draft("poste"), Some(&dual), None, None).expect("merge");
    assert_eq!(cleared.address_v6, None, "the user's edit clears it");
}

/// A draft that never carried the secret must not erase it on save.
///
/// This is what makes the redaction usable rather than merely safe: the
/// user edits an endpoint, the screen sends back everything it knows —
/// which excludes the key — and the stored key survives untouched.
#[test]
fn editing_a_profile_keeps_the_secrets_it_never_saw() {
    let stored = profile("poste");
    let key = stored.private_key.duplicate();
    let psk = stored
        .preshared_key
        .as_ref()
        .map(aether::SecretString::duplicate);

    let mut edit = draft("poste");
    edit.endpoint = "198.51.100.7:51820".into();
    let merged = merge_draft(edit, Some(&stored), None, None).expect("merge");

    assert_eq!(merged.private_key, key, "la clé stockée a été perdue");
    assert_eq!(merged.preshared_key, psk, "le PSK stocké a été perdu");
    assert_eq!(merged.endpoint, "198.51.100.7:51820");
}

/// Removing the block cannot rewrite an existing Helios profile as classic.
#[test]
fn editing_cannot_change_an_existing_profile_kind() {
    let mut stored = profile("poste");
    stored.profile_type = Some(orion_core::ProfileKind::HeliosKeyNegotiation);
    stored.key_negotiation = Some(orion_core::KeyNegotiationSettings {
        mode: aether::key_negotiation::ProtectionMode::MlKem,
        minimum_mode: aether::key_negotiation::ProtectionMode::MlKem,
        endpoint: "203.0.113.10:51821".into(),
        server_name: "gateway.example".into(),
        gateway_ca_der: "Q0E=".into(),
        gateway_pq_certificate: "Q0VSVA==".into(),
        identity: "poste".into(),
        trust: None,
    });

    let error = merge_draft(draft("poste"), Some(&stored), None, None).unwrap_err();
    assert!(error.contains("helios_key_negotiation"), "{error}");
}

/// The staged key is what a save adopts, and only when asked.
///
/// The pair is drawn — or parsed — by the commands, which return the
/// **public** half; the private one waits in `AppState`. `merge_draft` is the
/// step that attaches it, and it must refuse to invent one.
#[test]
fn only_a_staged_key_becomes_a_profile_key() {
    let pair = aether::wg::generate_keypair().expect("keypair");
    let staged = StagedKey {
        private_key: aether::SecretString::new(pair.private_key.expose().to_owned()),
        public_key: pair.public_key.clone(),
    };

    let mut adopting = draft("nouveau");
    adopting.use_staged_key = true;
    let created = merge_draft(adopting, None, Some(&staged), None).expect("merge");
    assert_eq!(created.private_key, staged.private_key);
    assert_eq!(
        created.public_key().as_deref(),
        Some(pair.public_key.as_str())
    );

    // Asking for a staged key that does not exist is an error, not a
    // silently invented identity the operator never admitted.
    let mut orphan = draft("nouveau");
    orphan.use_staged_key = true;
    assert!(merge_draft(orphan, None, None, None).is_err());

    // And without the intent, a stored key is left exactly as it was.
    let kept = merge_draft(draft("poste"), Some(&created), Some(&staged), None);
    assert_eq!(kept.expect("merge").private_key, created.private_key);
}

/// Touching a static PSK is explicit in both directions.
#[test]
fn a_static_psk_is_set_or_cleared_only_on_an_explicit_intent() {
    let stored = profile("poste");
    let mut clearing = draft("poste");
    clearing.clear_preshared_key = true;
    assert_eq!(
        merge_draft(clearing, Some(&stored), None, None)
            .expect("merge")
            .preshared_key,
        None
    );

    // And a merge never marks a stored PSK as negotiated: that flag belongs
    // to the ephemeral profile the backend mounts, nowhere else.
    assert!(
        !merge_draft(draft("poste"), Some(&stored), None, None)
            .expect("merge")
            .preshared_key_is_negotiated
    );

    // Adopting one: the value waited in Rust, the draft only said "keep it".
    let waiting = StagedPsk {
        value: aether::SecretString::new("bm91dmVhdS1wc2stc3RhdGlxdWUtaG9ycy1iYW5kZQ=="),
    };
    let mut adopting = draft("poste");
    adopting.use_staged_psk = true;
    assert_eq!(
        merge_draft(adopting, Some(&stored), None, Some(&waiting))
            .expect("merge")
            .preshared_key
            .as_ref()
            .map(aether::SecretString::expose),
        Some(waiting.value.expose())
    );

    // Claiming a PSK that was never staged fails rather than silently
    // leaving the previous one: the screen showed the new value as adopted.
    let mut orphan = draft("poste");
    orphan.use_staged_psk = true;
    assert!(merge_draft(orphan, Some(&stored), None, None).is_err());

    // Both intents at once — a PSK typed, then a mode chosen that forbids
    // one, in the same edit. Clearing wins, whatever the field order.
    let mut contradicted = draft("poste");
    contradicted.use_staged_psk = true;
    contradicted.clear_preshared_key = true;
    assert_eq!(
        merge_draft(contradicted, Some(&stored), None, Some(&waiting))
            .expect("merge")
            .preshared_key,
        None
    );
}
