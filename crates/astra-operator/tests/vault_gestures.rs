//! The key gestures Orion's operator ceremony runs, against simulated keys.
//!
//! Each gesture takes the vault's path and the opening the ceremony already
//! holds, so what these tests count is touches: an operator presses each key
//! once per gesture, and a gesture that quietly asked for a second assertion
//! would be a second press nobody announced.

mod support;

use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::{TrustDomainId, WireGuardKey};
use astra_operator::authenticator::Opened;
use astra_operator::gestures::{NewAuthority, NewKey};
use astra_operator::vault::{SlotRole, MAX_SLOTS};
use astra_operator::vault_gestures::{
    add_key_with, check_addition, check_creation, check_marking, check_removal, create_first_key,
    mark_key_with, prove_opens, remove_key_with, rename_key, SetupRefusal,
};
use astra_operator::{credentials, handoff, signing, store};
use support::{FakeKey, PIN, RP_ID};

const NOW: u64 = 1_800_000_000;
const AUTHORITY_URL: &str = "https://astra.helios.test/";
const SERVER_NAME: &str = "gateway.helios.test";

fn request() -> NewAuthority {
    NewAuthority {
        rp_id: RP_ID.into(),
        trust_domain_id: TrustDomainId::new([0x2A; 16]).expect("domain"),
        label: "YubiKey du bureau".into(),
        role: SlotRole::Primary,
    }
}

fn new_key(label: &str) -> NewKey {
    NewKey {
        label: label.into(),
        role: SlotRole::Recovery,
    }
}

fn vault_path(directory: &tempfile::TempDir) -> PathBuf {
    directory.path().join("authority-vault.json")
}

/// The refusal an error carries, when it carries one.
fn refusal<T>(result: anyhow::Result<T>) -> Option<SetupRefusal> {
    result
        .err()
        .and_then(|error| error.downcast_ref::<SetupRefusal>().copied())
}

fn create(path: &Path, key: &FakeKey) -> Opened {
    create_first_key(path, &request(), AUTHORITY_URL, key, PIN, NOW).expect("the domain is created")
}

fn add(path: &Path, opening: &Opened, key: &FakeKey, label: &str) -> ([u8; 16], Opened) {
    let added =
        add_key_with(path, opening, key, &new_key(label), PIN, NOW).expect("the key is added");
    (added.slot_id, added.opening)
}

/// Records the gateway on the relay, which is what lets a document be signed.
fn complete_relay(path: &Path) {
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = Some(WireGuardKey::from_bytes([0x11; 32]).to_base64());
    relay.server_name = Some(SERVER_NAME.into());
    handoff::save(&relay_path, &relay).expect("relay saved");
}

/// Emits the credential document the way a finished domain holds one.
fn emit_document(path: &Path, opening: &Opened) {
    let vault = store::load(path).expect("vault");
    let identity =
        handoff::identity_of(&handoff::load(&handoff::path_beside(path)).expect("relay"))
            .expect("identity");
    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path).expect("previous");
    let registry =
        signing::sign_credential_bindings(&vault, opening, &identity, previous.as_ref(), &[], NOW)
            .expect("document signed");
    credentials::save(&registry_path, &registry).expect("document saved");
}

fn document(path: &Path) -> credentials::CredentialRegistry {
    credentials::load(&credentials::path_beside(path))
        .expect("document readable")
        .expect("document present")
}

fn state_of(path: &Path, slot_id: &[u8; 16]) -> CredentialState {
    let vault = store::load(path).expect("vault");
    let credential_id = vault
        .slot(slot_id)
        .expect("slot")
        .credential_id()
        .expect("credential");
    document(path)
        .binding(&credential_id)
        .expect("a row for the slot")
        .state
}

/// The creation is two presses, one per key, and the trial of both keys that
/// ADR-008 §4 asks for reuses those two openings rather than a third press.
#[test]
fn creating_a_domain_takes_one_assertion_per_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    let key2 = FakeKey::new(2);

    let first = create(&path, &key1);
    let added = add_key_with(&path, &first, &key2, &new_key("YubiKey du sac"), PIN, NOW)
        .expect("the second key is added");

    assert_eq!(key1.assertions(), 1);
    assert_eq!(key2.assertions(), 1);
    let vault = store::load(&path).expect("vault");
    assert!(vault.is_bootstrapped());
    let relay = handoff::load(&handoff::path_beside(&path)).expect("relay");
    assert_eq!(
        relay.astra_authority_url.as_deref(),
        Some("https://astra.helios.test")
    );
    // No gateway on the relay yet, so no document to sign.
    assert!(credentials::load(&credentials::path_beside(&path))
        .expect("readable")
        .is_none());

    prove_opens(&path, &[&first, &added.opening]).expect("both keys open the anchors");
    assert_eq!(key1.assertions(), 1);
    assert_eq!(key2.assertions(), 1);
}

/// Trying the same key twice is not a trial of two keys.
#[test]
fn proving_needs_distinct_keys() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    let first = create(&path, &key1);

    assert!(prove_opens(&path, &[&first, &first]).is_err());
    assert!(prove_opens(&path, &[]).is_err());
}

#[test]
fn the_same_token_cannot_take_the_second_slot() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    let first = create(&path, &key1);

    assert!(add_key_with(&path, &first, &key1, &new_key("la même"), PIN, NOW).is_err());

    let vault = store::load(&path).expect("vault");
    assert_eq!(vault.slots.len(), 1);
    assert!(!vault.is_bootstrapped());
}

#[test]
fn creation_refuses_an_existing_vault_and_a_missing_folder() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    check_creation(&path).expect("an empty folder takes a vault");
    create(&path, &key1);

    assert_eq!(check_creation(&path), Err(SetupRefusal::VaultExists));
    let missing = directory.path().join("absent").join("authority-vault.json");
    assert_eq!(
        check_creation(&missing),
        Err(SetupRefusal::LocationUnavailable)
    );

    // The gesture itself refuses again, before the key is asked anything.
    let key2 = FakeKey::new(2);
    let before = std::fs::read(&path).expect("vault bytes");
    assert_eq!(
        refusal(create_first_key(
            &path,
            &request(),
            AUTHORITY_URL,
            &key2,
            PIN,
            NOW
        )),
        Some(SetupRefusal::VaultExists)
    );
    assert_eq!(
        refusal(create_first_key(
            &missing,
            &request(),
            AUTHORITY_URL,
            &key2,
            PIN,
            NOW
        )),
        Some(SetupRefusal::LocationUnavailable)
    );
    assert_eq!(key2.assertions(), 0);
    assert_eq!(std::fs::read(&path).expect("vault bytes"), before);
    assert!(!missing.exists());
}

/// An authority origin that is not `https://` is refused before the key is
/// asked anything, and nothing is written.
#[test]
fn creation_refuses_a_plain_http_origin_before_any_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);

    assert!(create_first_key(
        &path,
        &request(),
        "http://astra.helios.test",
        &key1,
        PIN,
        NOW
    )
    .is_err());
    assert_eq!(key1.assertions(), 0);
    assert!(!path.exists());
    assert!(!handoff::path_beside(&path).exists());
}

#[test]
fn adding_a_key_resigns_the_document_without_another_touch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    let key2 = FakeKey::new(2);
    let first = create(&path, &key1);
    complete_relay(&path);
    emit_document(&path, &first);
    assert_eq!(document(&path).bindings.len(), 1);

    let (slot_id, _) = add(&path, &first, &key2, "YubiKey du sac");

    assert_eq!(
        key1.assertions(),
        1,
        "the opening is reused for the document"
    );
    assert_eq!(key2.assertions(), 1);
    let vault = store::load(&path).expect("vault");
    let registry = document(&path);
    assert_eq!(registry.bindings.len(), vault.slots.len());
    assert_eq!(registry.credential_registry_epoch, 2);
    assert_eq!(state_of(&path, &slot_id), CredentialState::Active);
}

#[test]
fn a_full_vault_refuses_before_any_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    let first = create(&path, &key1);
    let keys: Vec<FakeKey> = (2..=MAX_SLOTS as u8).map(FakeKey::new).collect();
    for key in &keys {
        add(&path, &first, key, "clé");
    }
    let vault = store::load(&path).expect("vault");
    assert_eq!(vault.slots.len(), MAX_SLOTS);

    assert_eq!(check_addition(&vault), Err(SetupRefusal::VaultFull));
    let extra = FakeKey::new(0xEE);
    assert_eq!(
        refusal(add_key_with(
            &path,
            &first,
            &extra,
            &new_key("de trop"),
            PIN,
            NOW
        )),
        Some(SetupRefusal::VaultFull)
    );
    assert_eq!(extra.assertions(), 0);
}

#[test]
fn the_opening_key_cannot_remove_itself() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, opening3) = add(&path, &first, &key3, "YubiKey du coffre-fort");
    complete_relay(&path);
    emit_document(&path, &first);
    let vault_bytes = std::fs::read(&path).expect("vault bytes");
    let document_bytes = std::fs::read(credentials::path_beside(&path)).expect("document bytes");

    assert_eq!(
        refusal(remove_key_with(&path, &opening3, &slot3, NOW)),
        Some(SetupRefusal::KeyBeingRemoved)
    );

    assert_eq!(std::fs::read(&path).expect("vault bytes"), vault_bytes);
    assert_eq!(
        std::fs::read(credentials::path_beside(&path)).expect("document bytes"),
        document_bytes
    );
}

#[test]
fn removal_writes_the_document_before_the_vault() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, _) = add(&path, &first, &key3, "YubiKey perdue");
    complete_relay(&path);
    emit_document(&path, &first);
    let removed_credential = store::load(&path)
        .expect("vault")
        .slot(&slot3)
        .expect("slot")
        .credential_id()
        .expect("credential");

    remove_key_with(&path, &first, &slot3, NOW).expect("the third key goes");

    assert_eq!(
        key1.assertions(),
        1,
        "the opening is reused for the document"
    );
    let vault = store::load(&path).expect("vault");
    assert_eq!(vault.slots.len(), 2);
    let registry = document(&path);
    assert_eq!(
        registry
            .binding(&removed_credential)
            .expect("the withdrawn credential keeps a row")
            .state,
        CredentialState::Revoked
    );
    assert_eq!(registry.bindings.len(), 3);
}

#[test]
fn two_keys_are_the_floor() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    let (slot2, _) = add(&path, &first, &key2, "YubiKey du sac");
    let vault = store::load(&path).expect("vault");

    assert_eq!(
        check_removal(&vault, &slot2).err(),
        Some(SetupRefusal::MinimumKeys)
    );
    assert_eq!(
        check_removal(&vault, &[0xFF; 16]).err(),
        Some(SetupRefusal::UnknownSlot)
    );
    let vault_bytes = std::fs::read(&path).expect("vault bytes");
    assert_eq!(
        refusal(remove_key_with(&path, &first, &slot2, NOW)),
        Some(SetupRefusal::MinimumKeys)
    );
    assert_eq!(std::fs::read(&path).expect("vault bytes"), vault_bytes);
}

#[test]
fn marking_needs_the_gateway_and_moves_the_state() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    let (slot2, _) = add(&path, &first, &key2, "YubiKey du sac");
    let vault = store::load(&path).expect("vault");

    assert_eq!(
        check_marking(&path, &vault, &slot2).err(),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
    assert_eq!(
        refusal(mark_key_with(&path, &first, &slot2, true, NOW)),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
    assert!(!credentials::path_beside(&path).exists());

    complete_relay(&path);
    assert_eq!(
        check_marking(&path, &vault, &[0xFF; 16]).err(),
        Some(SetupRefusal::UnknownSlot)
    );
    check_marking(&path, &vault, &slot2).expect("the gateway is known");

    let lost_epoch = mark_key_with(&path, &first, &slot2, true, NOW).expect("marked lost");
    assert_eq!(state_of(&path, &slot2), CredentialState::Lost);
    assert_eq!(document(&path).credential_registry_epoch, lost_epoch);

    let found_epoch = mark_key_with(&path, &first, &slot2, false, NOW).expect("marked found");
    assert_eq!(state_of(&path, &slot2), CredentialState::Active);
    assert!(found_epoch > lost_epoch);
    assert_eq!(key1.assertions(), 1);
}

#[test]
fn a_blank_or_long_label_is_refused_and_nothing_moves() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    create(&path, &key1);
    let slot_id = store::load(&path).expect("vault").slots[0].slot_id;
    let vault_bytes = std::fs::read(&path).expect("vault bytes");

    assert!(rename_key(&path, &slot_id, "  ").is_err());
    assert!(rename_key(&path, &slot_id, &"x".repeat(65)).is_err());
    assert_eq!(
        refusal(rename_key(&path, &[0xFF; 16], "Bureau")),
        Some(SetupRefusal::UnknownSlot)
    );
    assert_eq!(std::fs::read(&path).expect("vault bytes"), vault_bytes);

    rename_key(&path, &slot_id, "Bureau").expect("renamed");
    let vault = store::load(&path).expect("vault");
    assert_eq!(vault.slot(&slot_id).expect("slot").label, "Bureau");
    assert_eq!(key1.assertions(), 1, "renaming asks no key");
}
