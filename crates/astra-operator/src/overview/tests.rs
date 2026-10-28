use super::*;
use crate::handoff::{self, DomainHandoff};
use crate::store;
use crate::vault::{
    draw_salt, AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, SlotSecret,
};
use aether::certificates::encoding::{generate_ml_dsa_87_keypair, TrustDomainId};

fn enrolment(role: SlotRole, seed: u8, label: &str) -> SlotEnrolment {
    SlotEnrolment {
        role,
        label: label.into(),
        credential_id: vec![seed; 64],
        credential_public_key: vec![0xa5, seed],
        aaguid: [seed; 16],
        enrolled_at: 2_000,
    }
}

fn vault_with_two_slots() -> AuthorityVault {
    let (private_key, public_key) = generate_ml_dsa_87_keypair().expect("keypair");
    let secrets = AuthoritySecrets {
        ca_pq_private_key: aether_base64(&private_key),
        ca_pq_public_key: public_key.to_base64(),
        ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
        retained_ca_tls: None,
    };
    let mut vault = AuthorityVault::create(
        TrustDomainId::new([3; 16]).expect("domain"),
        "astra.example",
        draw_salt().expect("salt"),
        &secrets,
        enrolment(SlotRole::Primary, 1, "clé quotidienne"),
        &SlotSecret::new(vec![1; 32]),
        1_000,
    )
    .expect("create");
    vault
        .add_slot(
            &[1; 64],
            &SlotSecret::new(vec![1; 32]),
            enrolment(SlotRole::Recovery, 2, "clé de secours"),
            &SlotSecret::new(vec![2; 32]),
        )
        .expect("add slot");
    vault
}

fn aether_base64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn saved_vault() -> (tempfile::TempDir, std::path::PathBuf, AuthorityVault) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("astra").join("authority-vault.json");
    let vault = vault_with_two_slots();
    store::save(&path, &vault).expect("save vault");
    (directory, path, vault)
}

#[test]
fn a_missing_vault_reads_as_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("authority-vault.json");
    let overview = read(&path).expect("absent is a state");
    assert!(!overview.exists);
    assert!(overview.vault_fingerprint.is_none());
    assert!(overview.slots.is_empty());
    assert!(overview.domain.is_none());
    assert_eq!(overview.vault_path, path.display().to_string());
}

#[test]
fn an_unreadable_vault_is_an_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("authority-vault.json");
    std::fs::write(&path, b"not a vault").expect("write");
    assert!(read(&path).is_err());
}

#[test]
fn slots_are_listed_with_their_role_and_label() {
    let (_directory, path, vault) = saved_vault();
    let overview = read(&path).expect("read");
    assert!(overview.exists);
    assert_eq!(overview.max_slots, crate::vault::MAX_SLOTS);
    assert_eq!(
        overview.vault_fingerprint,
        Some(vault.fingerprint().expect("fingerprint").to_hex())
    );
    assert_eq!(overview.slots.len(), 2);
    assert_eq!(overview.slots[0].role, "principale");
    assert_eq!(overview.slots[0].label, "clé quotidienne");
    assert_eq!(
        overview.slots[0].slot_id,
        hex::encode(vault.slots[0].slot_id)
    );
    assert_eq!(overview.slots[0].slot_id.len(), 32);
    assert_eq!(overview.slots[1].role, "recuperation");
    assert_eq!(overview.slots[1].label, "clé de secours");
}

#[test]
fn the_domain_comes_from_the_relay_beside_the_vault() {
    let (_directory, path, vault) = saved_vault();
    let mut relay = DomainHandoff::of(&vault).expect("relay");
    relay.ca_epoch = Some(4);
    relay.ca_tls_epoch = Some(2);
    relay.ca_tls_certificate = Some("Y2VydA==".into());
    relay.server_name = Some("gw.example".into());
    relay.gateway_wg_public_key = Some("d2c=".into());
    handoff::save(&handoff::path_beside(&path), &relay).expect("save relay");

    let domain = read(&path).expect("read").domain.expect("domain");
    assert_eq!(domain.trust_domain_id, vault.trust_domain_id.to_hex());
    assert_eq!(domain.rp_id, "astra.example");
    assert_eq!(domain.ca_epoch, Some(4));
    assert_eq!(domain.ca_tls_epoch, Some(2));
    assert!(domain.ca_tls_present);
    assert_eq!(domain.server_name.as_deref(), Some("gw.example"));
    assert_eq!(domain.gateway_wg_public_key.as_deref(), Some("d2c="));
    let ungrouped = domain.ca_pq_fingerprint.replace(' ', "");
    assert_eq!(ungrouped.len(), 64);
    assert_eq!(domain.ca_pq_fingerprint, grouped_hex(&ungrouped));
}

#[test]
fn a_vault_without_relay_has_no_domain() {
    let (_directory, path, _vault) = saved_vault();
    assert!(read(&path).expect("read").domain.is_none());
}

#[test]
fn an_unreadable_relay_leaves_the_domain_out() {
    let (_directory, path, _vault) = saved_vault();
    std::fs::write(handoff::path_beside(&path), b"{").expect("write");
    let overview = read(&path).expect("read");
    assert!(overview.exists);
    assert!(overview.domain.is_none());
}

#[test]
fn the_overview_carries_no_secret() {
    let (_directory, path, vault) = saved_vault();
    let relay = DomainHandoff::of(&vault).expect("relay");
    handoff::save(&handoff::path_beside(&path), &relay).expect("save relay");

    let json = serde_json::to_string(&read(&path).expect("read")).expect("json");
    for field in [
        "wrapped",
        "wrapped_master",
        "secret",
        "salt",
        "sealed_payload",
        "credential_id",
        "credential_public_key",
        "aaguid",
        "private",
    ] {
        assert!(!json.contains(field), "{field} must not be serialized");
    }
    for slot in &vault.slots {
        assert!(!json.contains(&slot.wrapped_master));
        assert!(!json.contains(&slot.credential_id));
    }
    assert!(!json.contains(&vault.sealed_payload));
    assert!(!json.contains(&vault.salt));
    for seed in [1u8, 2] {
        assert!(
            !json.contains(&hex::encode(vec![seed; 32])),
            "slot secret bytes"
        );
    }
}

#[test]
fn a_fingerprint_is_shown_in_groups_of_four() {
    assert_eq!(grouped_hex("0123456789abcdef"), "0123 4567 89ab cdef");
}

#[test]
fn a_missing_folder_is_not_an_absent_vault() {
    let directory = tempfile::tempdir().expect("tempdir");
    let overview = read(&directory.path().join("authority-vault.json")).expect("absent");
    assert!(!overview.exists);
    assert!(overview.location_available);
    assert!(!overview.bootstrapped);

    let missing = directory.path().join("absent").join("authority-vault.json");
    let overview = read(&missing).expect("a missing folder is a state");
    assert!(!overview.exists);
    assert!(!overview.location_available);
    assert!(!overview.credentials_complete);
}
