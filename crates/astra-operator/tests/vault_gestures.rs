//! The key gestures Orion's operator ceremony runs, against simulated keys.
//!
//! Each gesture takes the vault's path and the opening the ceremony already
//! holds, so what these tests count is touches: an operator presses each key
//! once per gesture, and a gesture that quietly asked for a second assertion
//! would be a second press nobody announced.

mod support;

use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::GatewayBootstrapRequest;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
use astra_operator::authenticator::Opened;
use astra_operator::gestures::{NewAuthority, NewKey};
use astra_operator::vault::{SlotRole, MAX_SLOTS};
use astra_operator::vault_gestures::{
    add_key_with, adopt_gateway, authority_origin, check_addition, check_creation, check_document,
    check_marking, check_removal, create_first_key, finalization, finalize_with, mark_key_with,
    open_for_removal, prove_opens, remove_key_with, rename_key, write_relay, RelayUpdate,
    SetupRefusal,
};
use astra_operator::{credentials, handoff, overview, signing, store};
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

/// Forgets the gateway on the relay, as a hand-edited or stale relay would.
fn clear_gateway(path: &Path) {
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = None;
    relay.server_name = None;
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

/// The document is written first: a vault save that fails after it leaves the
/// credential revoked while the old vault still holds it (fail closed), never
/// an absent slot still marked active.
///
/// The save is made to fail by putting a symbolic link where the vault is:
/// the vault still reads through it, and the private writer refuses to
/// replace a link. Unix only, where a test may create one.
#[cfg(unix)]
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

    let held = directory.path().join("held-vault.json");
    std::fs::rename(&path, &held).expect("vault moved aside");
    std::os::unix::fs::symlink(&held, &path).expect("link in the vault's place");
    let vault_bytes = std::fs::read(&held).expect("vault bytes");

    remove_key_with(&path, &first, &slot3, NOW).expect_err("the vault cannot be saved");

    assert_eq!(
        std::fs::read(&held).expect("vault bytes"),
        vault_bytes,
        "the vault is unchanged"
    );
    assert_eq!(store::load(&path).expect("vault").slots.len(), 3);
    assert_eq!(
        document(&path)
            .binding(&removed_credential)
            .expect("the withdrawn credential has a row")
            .state,
        CredentialState::Revoked,
        "the revocation was signed before the vault was written"
    );

    // Once the vault can be written, the removal completes over the document
    // it left.
    std::fs::remove_file(&path).expect("link removed");
    std::fs::rename(&held, &path).expect("vault back in place");
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

/// The key being withdrawn is left out of the opening's allow-list: it is not
/// asked for a touch the removal would refuse, and another key opens.
#[test]
fn the_removal_opening_never_asks_the_key_being_removed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    let (slot2, _) = add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, _) = add(&path, &first, &key3, "YubiKey du coffre-fort");
    let vault = store::load(&path).expect("vault");
    let asked_before = key3.assertions();

    assert!(open_for_removal(&key3, &vault, &slot3, PIN).is_err());
    assert_eq!(
        key3.assertions(),
        asked_before,
        "the removed key answered nothing"
    );

    let opened = open_for_removal(&key2, &vault, &slot3, PIN).expect("another key opens");
    let slot3_credential = vault
        .slot(&slot3)
        .expect("slot")
        .credential_id()
        .expect("credential");
    assert_ne!(opened.credential_id, slot3_credential);
    assert_eq!(
        vault
            .slot_for_credential(&opened.credential_id)
            .expect("an enrolled key")
            .slot_id,
        slot2
    );
    assert_eq!(
        refusal(open_for_removal(&key2, &vault, &[0xFF; 16], PIN)),
        Some(SetupRefusal::UnknownSlot)
    );
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

/// A key the document already revokes — a removal stopped after its
/// document — is not marked lost or active again: that would take back a
/// signed revocation.
#[test]
fn a_revoked_key_is_not_marked_again() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, _) = add(&path, &first, &key3, "YubiKey perdue");
    complete_relay(&path);
    let vault = store::load(&path).expect("vault");
    let revoked = vault
        .slot(&slot3)
        .expect("slot")
        .credential_id()
        .expect("credential");
    let identity = handoff::identity_of(&relay(&path)).expect("the relay names the gateway");
    let registry = signing::sign_credential_bindings(
        &vault,
        &first,
        &identity,
        None,
        &[(revoked, CredentialState::Revoked)],
        NOW,
    )
    .expect("document signed");
    credentials::save(&credentials::path_beside(&path), &registry).expect("document saved");
    let document_bytes = std::fs::read(credentials::path_beside(&path)).expect("document bytes");

    assert_eq!(
        check_marking(&path, &vault, &slot3).err(),
        Some(SetupRefusal::KeyRevoked)
    );
    for lost in [true, false] {
        assert_eq!(
            refusal(mark_key_with(&path, &first, &slot3, lost, NOW)),
            Some(SetupRefusal::KeyRevoked)
        );
    }
    assert_eq!(
        std::fs::read(credentials::path_beside(&path)).expect("document bytes"),
        document_bytes
    );
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

/// A document already in place cannot be left describing a table that moved:
/// with the gateway gone from the relay, the removal is refused before it
/// writes anything.
#[test]
fn removal_refuses_a_document_it_cannot_resign() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, _) = add(&path, &first, &key3, "YubiKey perdue");
    complete_relay(&path);
    emit_document(&path, &first);
    clear_gateway(&path);
    let vault_bytes = std::fs::read(&path).expect("vault bytes");
    let document_bytes = std::fs::read(credentials::path_beside(&path)).expect("document bytes");

    assert_eq!(
        refusal(remove_key_with(&path, &first, &slot3, NOW)),
        Some(SetupRefusal::GatewayIdentityMissing)
    );

    assert_eq!(std::fs::read(&path).expect("vault bytes"), vault_bytes);
    assert_eq!(
        std::fs::read(credentials::path_beside(&path)).expect("document bytes"),
        document_bytes
    );
}

/// The same rule for an addition, settled before the new key is asked to
/// register: no orphan credential on the token, no slot in the vault.
#[test]
fn addition_refuses_a_document_it_cannot_resign_before_the_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    complete_relay(&path);
    emit_document(&path, &first);
    clear_gateway(&path);
    let vault_bytes = std::fs::read(&path).expect("vault bytes");

    assert_eq!(
        refusal(add_key_with(
            &path,
            &first,
            &key2,
            &new_key("YubiKey du sac"),
            PIN,
            NOW
        )),
        Some(SetupRefusal::GatewayIdentityMissing)
    );

    assert!(
        key2.credential_ids().is_empty(),
        "the new key registered nothing"
    );
    assert_eq!(key2.assertions(), 0);
    assert_eq!(std::fs::read(&path).expect("vault bytes"), vault_bytes);
}

// --- Domain -----------------------------------------------------------------

fn relay(path: &Path) -> handoff::DomainHandoff {
    handoff::load(&handoff::path_beside(path)).expect("relay")
}

/// A gateway leaf issued under this domain's `CA-PQ`, through the bootstrap
/// gesture that issues the real one.
fn domain_leaf(
    path: &Path,
    opening: &Opened,
    server_name: &str,
    gateway: WireGuardKey,
) -> PqCertificate {
    let vault = store::load(path).expect("vault");
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let request = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: gateway,
        server_name: server_name.into(),
        ml_dsa_87_public_key: gateway_public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway_private)
    .expect("bootstrap request");
    signing::issue_gateway_bootstrap_certificate(
        &vault,
        opening,
        &MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("anchor"),
        &signing::GatewayBootstrapDecision {
            request: &request,
            leaf_validity: (NOW - 60, NOW + 86_400),
            serial: [9; 16],
        },
    )
    .expect("gateway leaf")
}

/// The same leaf, signed by a CA that is not this domain's.
fn foreign_leaf(server_name: &str, gateway: WireGuardKey) -> PqCertificate {
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("foreign CA");
    let (_, subject) = generate_ml_dsa_87_keypair().expect("subject");
    aether::key_negotiation::issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [9; 16],
            subject: server_name.into(),
            issuer: "helios-ca-pq".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway.to_base64(),
            ml_dsa_87_public_key: subject.to_base64(),
            not_before_unix: NOW - 60,
            not_after_unix: NOW + 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("foreign leaf")
}

/// A domain with its two keys and the gateway recorded on the relay.
fn domain_with_gateway(path: &Path, key1: &FakeKey, key2: &FakeKey) -> Opened {
    let first = create(path, key1);
    add(path, &first, key2, "YubiKey du sac");
    complete_relay(path);
    first
}

#[test]
fn the_relay_takes_only_valid_values() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    create(&path, &key1);
    let relay_path = handoff::path_beside(&path);
    let before = std::fs::read(&relay_path).expect("relay bytes");

    let invalid = RelayUpdate {
        server_name: Some(SERVER_NAME.into()),
        astra_authority_url: Some("http://x".into()),
        ..RelayUpdate::default()
    };
    assert!(write_relay(&path, &invalid).is_err());
    assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);
    for invalid in [
        RelayUpdate {
            gateway_wg_public_key: Some("not a key".into()),
            ..RelayUpdate::default()
        },
        RelayUpdate {
            server_name: Some("not a name!".into()),
            ..RelayUpdate::default()
        },
        RelayUpdate {
            astra_service_key_epoch: Some(0),
            ..RelayUpdate::default()
        },
        RelayUpdate {
            astra_service_public_key: Some("bm9wZQ==".into()),
            ..RelayUpdate::default()
        },
    ] {
        assert!(write_relay(&path, &invalid).is_err(), "{invalid:?}");
        assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);
    }

    let gateway = WireGuardKey::from_bytes([0x11; 32]).to_base64();
    let written = write_relay(
        &path,
        &RelayUpdate {
            gateway_wg_public_key: Some(format!("  {gateway} ")),
            server_name: Some(format!(" {SERVER_NAME}")),
            ..RelayUpdate::default()
        },
    )
    .expect("valid values are recorded");

    let read = relay(&path);
    assert_eq!(read, written);
    assert_eq!(
        read.gateway_wg_public_key.as_deref(),
        Some(gateway.as_str())
    );
    assert_eq!(read.server_name.as_deref(), Some(SERVER_NAME));
    assert_eq!(
        read.astra_authority_url.as_deref(),
        Some("https://astra.helios.test"),
        "what was recorded before is kept"
    );
}

/// The gateway's identity is filled in once: the same value again is no
/// change, another one is a gateway transition and is refused.
#[test]
fn the_relay_never_moves_to_another_gateway() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let key1 = FakeKey::new(1);
    create(&path, &key1);
    complete_relay(&path);
    let relay_path = handoff::path_beside(&path);
    let before = std::fs::read(&relay_path).expect("relay bytes");

    for moved in [
        RelayUpdate {
            gateway_wg_public_key: Some(WireGuardKey::from_bytes([0x22; 32]).to_base64()),
            ..RelayUpdate::default()
        },
        RelayUpdate {
            server_name: Some("other.helios.test".into()),
            ..RelayUpdate::default()
        },
    ] {
        let error = write_relay(&path, &moved).expect_err("another gateway is refused");
        assert!(
            error.to_string().contains("transition de gateway"),
            "{error}"
        );
        assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);
    }

    let same = write_relay(
        &path,
        &RelayUpdate {
            gateway_wg_public_key: Some(WireGuardKey::from_bytes([0x11; 32]).to_base64()),
            server_name: Some(SERVER_NAME.into()),
            astra_service_key_epoch: Some(3),
            ..RelayUpdate::default()
        },
    )
    .expect("the recorded gateway again is no change");
    assert_eq!(same.server_name.as_deref(), Some(SERVER_NAME));
    assert_eq!(same.astra_service_key_epoch, Some(3));
}

#[test]
fn adopting_takes_the_gateway_the_domain_signed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let gateway = WireGuardKey::from_bytes([0x11; 32]);
    let relay_path = handoff::path_beside(&path);
    let before = std::fs::read(&relay_path).expect("relay bytes");

    assert!(adopt_gateway(&path, &foreign_leaf(SERVER_NAME, gateway), NOW).is_err());
    assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);

    let leaf = domain_leaf(&path, &first, SERVER_NAME, gateway);
    let adopted = adopt_gateway(&path, &leaf, NOW).expect("the domain's own leaf");
    assert_eq!(relay(&path), adopted);
    assert_eq!(
        adopted.gateway_wg_public_key.as_deref(),
        Some(gateway.to_base64().as_str())
    );
    assert_eq!(adopted.server_name.as_deref(), Some(SERVER_NAME));

    let adopted_bytes = std::fs::read(&relay_path).expect("relay bytes");
    adopt_gateway(&path, &leaf, NOW).expect("the same gateway again changes nothing");
    assert_eq!(
        std::fs::read(&relay_path).expect("relay bytes"),
        adopted_bytes
    );

    let other = domain_leaf(
        &path,
        &first,
        "other.helios.test",
        WireGuardKey::from_bytes([0x22; 32]),
    );
    let error = adopt_gateway(&path, &other, NOW).expect_err("another gateway is a transition");
    assert!(
        error.to_string().contains("transition de gateway"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&relay_path).expect("relay bytes"),
        adopted_bytes
    );
}

/// A relay that lost the gateway still belongs to the gateway its document
/// is bound to: neither adoption nor a typed key moves it to another.
#[test]
fn a_document_bound_to_another_gateway_keeps_the_domain() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = domain_with_gateway(&path, &key1, &key2);
    emit_document(&path, &first);
    clear_gateway(&path);
    let relay_path = handoff::path_beside(&path);
    let before = std::fs::read(&relay_path).expect("relay bytes");
    let other = WireGuardKey::from_bytes([0x22; 32]);

    let error = adopt_gateway(&path, &domain_leaf(&path, &first, SERVER_NAME, other), NOW)
        .expect_err("the document names another gateway");
    assert!(
        error.to_string().contains("transition de gateway"),
        "{error}"
    );
    let error = write_relay(
        &path,
        &RelayUpdate {
            gateway_wg_public_key: Some(other.to_base64()),
            ..RelayUpdate::default()
        },
    )
    .expect_err("the document names another gateway");
    assert!(
        error.to_string().contains("transition de gateway"),
        "{error}"
    );
    assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);

    let bound = WireGuardKey::from_bytes([0x11; 32]);
    let written = write_relay(
        &path,
        &RelayUpdate {
            gateway_wg_public_key: Some(bound.to_base64()),
            ..RelayUpdate::default()
        },
    )
    .expect("the gateway the document is bound to");
    assert_eq!(
        written.gateway_wg_public_key.as_deref(),
        Some(bound.to_base64().as_str())
    );
}

/// The same WireGuard key under another server name is another gateway too.
#[test]
fn adopting_refuses_the_same_key_under_another_name() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = domain_with_gateway(&path, &key1, &key2);
    let relay_path = handoff::path_beside(&path);
    let before = std::fs::read(&relay_path).expect("relay bytes");

    let renamed = domain_leaf(
        &path,
        &first,
        "other.helios.test",
        WireGuardKey::from_bytes([0x11; 32]),
    );
    let error = adopt_gateway(&path, &renamed, NOW).expect_err("another server name");
    assert!(
        error.to_string().contains("transition de gateway"),
        "{error}"
    );
    assert_eq!(std::fs::read(&relay_path).expect("relay bytes"), before);
}

/// The relay records an origin: a host and its port, nothing after them.
#[test]
fn the_authority_origin_is_an_origin_and_nothing_more() {
    for (typed, recorded) in [
        ("https://astra.helios.test", "https://astra.helios.test"),
        (" https://astra.helios.test/ ", "https://astra.helios.test"),
        (
            "https://astra.helios.test:8443",
            "https://astra.helios.test:8443",
        ),
        ("https://[fd00::1]:8443/", "https://[fd00::1]:8443"),
    ] {
        assert_eq!(authority_origin(typed).expect(typed), recorded, "{typed}");
    }
    for refused in [
        "",
        "https://",
        "http://astra.helios.test",
        "astra.helios.test",
        "https:astra.helios.test",
        "https://astra.helios.test/astra",
        "https://astra.helios.test?x=1",
        "https://astra.helios.test#here",
        "https://user@astra.helios.test",
        "https://user:secret@astra.helios.test",
        "https://astra.helios.test:99999",
        "https://astra.helios.test:",
        "https://astra.helios.test:0",
        "https://astra.helios.test:08443",
        "https://[fd00::1",
        "https://astra .helios.test",
        "https://astra\\helios.test",
        "https://astra%2Ehelios.test",
        "https://Astra.helios.test",
        "https://astra.helios.test:443",
        "https://[FD00::1]:8443",
        "https://[fd00:0::1]:8443",
    ] {
        assert!(authority_origin(refused).is_err(), "{refused}");
    }
}

#[test]
fn finalizing_issues_what_is_missing_in_one_touch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = domain_with_gateway(&path, &key1, &key2);

    let plan = finalization(&path).expect("something to finalize");
    assert!(plan.issues_ca_tls);
    assert!(plan.issues_credentials);
    assert_eq!(plan.server_name, SERVER_NAME);
    assert_eq!(
        plan.gateway_wg_public_key,
        WireGuardKey::from_bytes([0x11; 32])
    );

    let finalized = finalize_with(&path, &first, NOW).expect("finalized");

    assert_eq!(
        key1.assertions(),
        1,
        "the opening already held is the one touch"
    );
    let relay = relay(&path);
    assert!(relay.ca_tls_certificate.is_some());
    assert_eq!(relay.ca_tls_epoch, Some(1));
    let registry = document(&path);
    assert_eq!(registry.bindings.len(), 2);
    assert_eq!(
        finalized.credentials_epoch,
        Some(registry.credential_registry_epoch)
    );
    let pem = finalized.ca_tls_pem.expect("CA-TLS issued");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{pem}");
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"), "{pem}");
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    assert!(pem.lines().all(|line| line.len() <= 64));
    assert_eq!(Some(body), relay.ca_tls_certificate);
}

#[test]
fn finalizing_twice_never_reissues_ca_tls() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = domain_with_gateway(&path, &key1, &key2);
    finalize_with(&path, &first, NOW).expect("first finalization");
    let certificate = relay(&path).ca_tls_certificate;
    std::fs::remove_file(credentials::path_beside(&path)).expect("document removed");

    let plan = finalization(&path).expect("the document is missing");
    assert!(!plan.issues_ca_tls);
    assert!(plan.issues_credentials);

    let second = finalize_with(&path, &first, NOW).expect("second finalization");
    assert_eq!(second.ca_tls_pem, None);
    assert!(second.credentials_epoch.is_some());
    assert_eq!(relay(&path).ca_tls_certificate, certificate);
    document(&path);

    assert_eq!(
        finalization(&path).err(),
        Some(SetupRefusal::DomainComplete)
    );
    assert_eq!(
        refusal(finalize_with(&path, &first, NOW)),
        Some(SetupRefusal::DomainComplete)
    );
    assert_eq!(relay(&path).ca_tls_certificate, certificate);
}

#[test]
fn finalization_needs_the_gateway() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let relay_bytes = std::fs::read(handoff::path_beside(&path)).expect("relay bytes");

    assert_eq!(
        finalization(&path).err(),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
    assert_eq!(
        refusal(finalize_with(&path, &first, NOW)),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
    assert_eq!(
        std::fs::read(handoff::path_beside(&path)).expect("relay bytes"),
        relay_bytes
    );
    assert!(!credentials::path_beside(&path).exists());
}

/// What a gesture would find unable to re-sign is refused before any press.
#[test]
fn a_document_the_relay_cannot_resign_is_refused_before_the_press() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    check_document(&path).expect("no document yet, nothing to re-sign");

    complete_relay(&path);
    emit_document(&path, &first);
    check_document(&path).expect("a document the relay names");

    clear_gateway(&path);
    assert_eq!(
        check_document(&path),
        Err(SetupRefusal::GatewayIdentityMissing)
    );

    complete_relay(&path);
    let registry_path = credentials::path_beside(&path);
    let mut registry = document(&path);
    registry.bindings[0].state = CredentialState::Lost;
    credentials::save(&registry_path, &registry).expect("altered document");
    assert_eq!(
        check_document(&path),
        Err(SetupRefusal::GatewayIdentityMissing)
    );
    assert_eq!(
        finalization(&path).err(),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
}

/// A key's state is shown only as a document that verifies says it: a row
/// read from an altered one would describe a decision nobody signed.
#[test]
fn the_overview_shows_states_only_from_a_verified_document() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let first = domain_with_gateway(&path, &key1, &key2);
    let view = overview::read(&path).expect("overview");
    assert!(view.bootstrapped);
    assert!(view.location_available);
    assert!(!view.credentials_complete, "no document yet");
    assert!(view.slots.iter().all(|slot| slot.state.is_none()));

    let lost = store::load(&path).expect("vault").slots[1].slot_id;
    mark_key_with(&path, &first, &lost, true, NOW).expect("marked lost");

    let view = overview::read(&path).expect("overview");
    assert!(view.credentials_complete);
    assert_eq!(view.slots[0].state.as_deref(), Some("active"));
    assert_eq!(view.slots[1].state.as_deref(), Some("lost"));

    let registry_path = credentials::path_beside(&path);
    let mut altered = document(&path);
    for binding in &mut altered.bindings {
        binding.state = CredentialState::Active;
    }
    credentials::save(&registry_path, &altered).expect("altered document");

    let view = overview::read(&path).expect("overview");
    assert!(!view.credentials_complete);
    assert!(view.slots.iter().all(|slot| slot.state.is_none()));
}
