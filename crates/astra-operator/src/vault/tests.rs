use super::tests_support::*;
use super::*;

fn secrets() -> AuthoritySecrets {
    AuthoritySecrets {
        ca_pq_private_key: "Y2EtcHEtcHJpdmF0ZQ==".into(),
        ca_pq_public_key: "Y2EtcHEtcHVibGlj".into(),
        ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
        retained_ca_tls: None,
    }
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([3; 16]).expect("domain")
}

fn credential(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

fn enrolment(role: SlotRole, seed: u8) -> SlotEnrolment {
    SlotEnrolment {
        role,
        label: format!("clé {seed}"),
        credential_id: credential(seed),
        credential_public_key: vec![0xa5, seed],
        aaguid: [seed; 16],
        enrolled_at: 2_000,
    }
}

fn material(seed: u8) -> SlotSecret {
    SlotSecret::new(vec![seed; 32])
}

fn vault() -> AuthorityVault {
    AuthorityVault::create(
        domain(),
        RP_ID,
        draw_salt().expect("salt"),
        &secrets(),
        enrolment(SlotRole::Primary, 1),
        &material(1),
        1_000,
    )
    .expect("create")
}

/// The nominal path: one credential opens the anchors.
#[test]
fn a_registered_credential_opens_the_anchors() {
    let vault = vault();
    let opened = vault.open(&credential(1), &material(1)).expect("open");
    assert_eq!(opened, secrets());
}

/// Another authenticator's output opens nothing, and the failure is the
/// AEAD's rather than a comparison this module could get wrong.
#[test]
fn another_authenticator_opens_nothing() {
    let vault = vault();
    assert!(vault.open(&credential(1), &material(9)).is_err());
}

/// A credential nobody registered is named as such, before any AEAD work.
#[test]
fn an_unregistered_credential_is_named() {
    let vault = vault();
    assert!(matches!(
        vault.open(&credential(7), &material(7)),
        Err(VaultError::UnknownCredential)
    ));
}

/// A vault with one credential is one lost object away from being a lost
/// trust domain. The bootstrap is not finalised there.
#[test]
fn one_slot_is_not_a_bootstrapped_authority() {
    let mut vault = vault();
    assert!(!vault.is_bootstrapped());

    vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("the second credential registers");
    assert!(vault.is_bootstrapped());
}

/// Any key opens the vault alone: the recovery one must genuinely recover
/// the loss of the others (1-of-N, not M-of-N). Including a third, which
/// the specification allows and an operator eventually buys.
#[test]
fn each_slot_opens_the_vault_alone() {
    let mut vault = vault();
    for seed in [2u8, 3, 4] {
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, seed),
                &material(seed),
            )
            .expect("another credential registers");
    }
    assert_eq!(vault.slots.len(), 4);

    for seed in [1u8, 2, 3, 4] {
        assert_eq!(
            vault
                .open(&credential(seed), &material(seed))
                .expect("open"),
            secrets(),
            "credential {seed} opens the vault on its own"
        );
    }
    // And a slot only opens with **its own** material.
    assert!(vault.open(&credential(4), &material(1)).is_err());
}

/// A key registered later opens a vault created before it existed: adding
/// a slot re-seals the body, and every earlier slot must survive that.
#[test]
fn adding_a_key_leaves_the_earlier_ones_working() {
    let mut vault = vault();
    vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("second slot");
    // Registered through the *second* key, which is the case an operator
    // hits after losing the first one and buying a replacement.
    vault
        .add_slot(
            &credential(2),
            &material(2),
            enrolment(SlotRole::Recovery, 3),
            &material(3),
        )
        .expect("third slot, opened by the second");

    assert_eq!(
        vault.open(&credential(1), &material(1)).expect("first"),
        secrets()
    );
    assert_eq!(
        vault.open(&credential(3), &material(3)).expect("third"),
        secrets()
    );
}

/// Adding a slot needs the master key, and the master key needs a slot.
/// Someone holding the file and a fresh YubiKey has nothing to wrap.
#[test]
fn a_stranger_cannot_append_a_slot_of_their_own() {
    let mut vault = vault();
    assert!(vault
        .add_slot(
            &credential(1),
            // The file is theirs; the authenticator is not.
            &material(42),
            enrolment(SlotRole::Primary, 3),
            &material(3),
        )
        .is_err());
    assert_eq!(vault.slots.len(), 1);
}

/// The same credential twice is one credential, not two recoveries.
#[test]
fn a_credential_is_registered_once() {
    let mut vault = vault();
    assert!(matches!(
        vault.add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 1),
            &material(1)
        ),
        Err(VaultError::SlotAlreadyPresent)
    ));
}

/// Removing a key may never leave the authority without a recovery.
#[test]
fn removing_a_slot_never_leaves_the_authority_alone() {
    let mut vault = vault();
    let second = vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("second slot");

    assert!(matches!(
        vault.remove_slot(&credential(1), &material(1), &second),
        Err(VaultError::LastRecoverySlot)
    ));

    let third = vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 3),
            &material(3),
        )
        .expect("third slot");
    vault
        .remove_slot(&credential(1), &material(1), &third)
        .expect("a third slot may go");
    assert_eq!(vault.slots.len(), 2);
}

/// The point of removal: a withdrawn row spliced back from a backup opens
/// nothing, because the payload is bound to the slot table it left.
#[test]
fn a_withdrawn_slot_spliced_back_opens_nothing() {
    let mut vault = vault();
    for seed in [2u8, 3] {
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, seed),
                &material(seed),
            )
            .expect("another credential registers");
    }
    let withdrawn = vault
        .slot_for_credential(&credential(3))
        .expect("slot")
        .clone();
    vault
        .remove_slot(&credential(1), &material(1), &withdrawn.slot_id)
        .expect("the third slot goes");
    assert!(matches!(
        vault.open(&credential(3), &material(3)),
        Err(VaultError::UnknownCredential)
    ));

    // The attacker puts the row back, byte for byte. It still yields the
    // master key — and the body no longer opens under it.
    vault.slots.push(withdrawn);
    assert!(vault.open(&credential(3), &material(3)).is_err());
    // And the keys that stayed are unaffected by the attempt only once the
    // spliced row is gone: the table is what the body is bound to.
    vault
        .slots
        .retain(|slot| slot.credential_id != encode(&credential(3)));
    assert_eq!(
        vault.open(&credential(1), &material(1)).expect("first"),
        secrets()
    );
}

/// Renaming a key is not an authority operation, and must never be one:
/// the label sits outside the digest on purpose.
#[test]
fn renaming_a_slot_does_not_lock_anyone_out() {
    let mut vault = vault();
    let slot_id = vault.slots[0].slot_id;
    vault
        .rename_slot(&slot_id, "YubiKey du bureau")
        .expect("rename");
    assert_eq!(vault.slots[0].label, "YubiKey du bureau");
    assert_eq!(
        vault.open(&credential(1), &material(1)).expect("open"),
        secrets()
    );
}

/// A slot lifted from another vault opens nothing here, even with its own
/// authenticator: the container is bound to both identifiers.
#[test]
fn a_slot_from_another_vault_does_not_open_this_one() {
    let mut mine = vault();
    let theirs = vault();
    mine.slots[0].wrapped_master = theirs.slots[0].wrapped_master.clone();
    assert!(mine.open(&credential(1), &material(1)).is_err());
}

/// One salt per vault, and two vaults never share it: the same credential
/// enrolled twice must not derive the same secret.
#[test]
fn two_vaults_do_not_share_a_salt() {
    assert_ne!(vault().salt, vault().salt);
    assert_eq!(vault().salt().expect("salt").len(), SALT_LEN);
}

/// The allow-list an assertion is asked for names every registered
/// credential: the authenticator picks the one it holds.
#[test]
fn the_allow_list_names_every_registered_credential() {
    let mut vault = vault();
    vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("second slot");
    assert_eq!(
        vault.credential_ids().expect("ids"),
        vec![credential(1), credential(2)]
    );
}

/// Reordering the file is not a change of table: an operator who sorts the
/// slots by hand must not lock the authority.
#[test]
fn reordering_the_slots_is_not_a_change_of_table() {
    let mut vault = vault();
    vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("second slot");
    let before = vault.slot_table_digest();
    vault.slots.reverse();
    assert_eq!(before, vault.slot_table_digest());
    assert_eq!(
        vault.open(&credential(1), &material(1)).expect("open"),
        secrets()
    );
}

/// The fingerprint covers the slot table, not only the body: a backup
/// whose slots changed is what an operator has to notice.
#[test]
fn the_fingerprint_moves_when_a_slot_is_added() {
    let mut vault = vault();
    let before = vault.fingerprint().expect("fingerprint");
    vault
        .add_slot(
            &credential(1),
            &material(1),
            enrolment(SlotRole::Recovery, 2),
            &material(2),
        )
        .expect("second slot");
    assert_ne!(before, vault.fingerprint().expect("fingerprint"));
}

/// A credential identifier is bounded before it is decoded: the vault is a
/// file an attacker may hand over.
#[test]
fn an_oversized_credential_identifier_is_refused() {
    let mut vault = vault();
    let mut oversized = enrolment(SlotRole::Recovery, 2);
    oversized.credential_id = vec![0; MAX_CREDENTIAL_ID_BYTES + 1];
    assert!(matches!(
        vault.add_slot(&credential(1), &material(1), oversized, &material(2)),
        Err(VaultError::CredentialIdOutOfBounds)
    ));
}

/// A blank label names nothing on an operator's screen, and a long one is
/// an allocation from a file.
#[test]
fn a_label_is_bounded() {
    let mut vault = vault();
    let mut blank = enrolment(SlotRole::Recovery, 2);
    blank.label = "   ".into();
    assert!(matches!(
        vault.add_slot(&credential(1), &material(1), blank, &material(2)),
        Err(VaultError::LabelOutOfBounds)
    ));
}
/// The clear anchor is read without a security key, by two other programs.
/// Editing it must be caught — and the only moment that can happen is when
/// the sealed copy becomes readable.
#[test]
fn an_edited_clear_anchor_is_caught_at_the_next_unlock() {
    let mut vault = vault();
    vault.ca_pq_public_key = "YXV0cmUtYW5jcmU=".into();
    assert!(matches!(
        vault.open(&credential(1), &material(1)),
        Err(VaultError::AnchorMismatch)
    ));
}

/// And the nominal case still carries it, since that is what an operator
/// hands to `astra bootstrap`.
#[test]
fn the_clear_anchor_is_the_one_the_vault_seals() {
    let vault = vault();
    assert_eq!(vault.ca_pq_public_key, secrets().ca_pq_public_key);
}
