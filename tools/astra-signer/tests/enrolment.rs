//! The authority gestures, end to end, against simulated security keys.
//!
//! What is simulated is exactly one thing: the CTAP2 boundary — see
//! [`support::FakeKey`]. Everything above it is the production code, including
//! the vault.
//!
//! So these tests do not prove a YubiKey works; nothing outside a real machine
//! can (see `docs/testing/TESTING.md`). They prove the sequence around it does:
//! that a second key registered a year after the first opens the same anchors,
//! that a third and a fourth do too, that a key which was never enrolled opens
//! nothing, and that withdrawing one leaves everyone else working.

mod support;

use aether::certificates::encoding::TrustDomainId;
use astra::vault::{AuthorityVault, SlotRole};
use astra_signer::authenticator::{Authenticator, AuthenticatorError, CredentialSubject};
use astra_signer::gestures::{
    self, add_key, create_authority, open_with_authorized_key, prove_anchors_open, remove_key,
    NewAuthority, NewKey,
};
use support::{FakeKey, PIN, RP_ID};

fn domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

fn create(key: &FakeKey) -> AuthorityVault {
    create_authority(
        key,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: domain(),
            label: "YubiKey du bureau".into(),
            role: SlotRole::Primary,
        },
        PIN,
        1_000,
    )
    .expect("create")
    .vault
}

fn enrol(vault: &mut AuthorityVault, opening: &FakeKey, new: &FakeKey, label: &str) -> [u8; 16] {
    let opened = open_with_authorized_key(opening, vault, PIN).expect("the authorized key opens");
    add_key(
        new,
        vault,
        &opened,
        &NewKey {
            label: label.into(),
            role: SlotRole::Recovery,
        },
        PIN,
        2_000,
    )
    .expect("the new key registers")
}

/// The whole point of the lot: the operator starts with one key today, adds
/// the second when it is back in hand, and a third and a fourth whenever they
/// buy them. Every one of them opens the anchors alone, afterwards.
#[test]
fn keys_enrolled_one_at_a_time_all_open_the_anchors() {
    let first = FakeKey::new(1);
    let mut vault = create(&first);
    assert!(
        !vault.is_bootstrapped(),
        "one key is not a bootstrapped authority"
    );

    let second = FakeKey::new(2);
    enrol(&mut vault, &first, &second, "YubiKey de récupération");
    assert!(vault.is_bootstrapped());

    // Bought later, and registered through whichever key is at hand — here the
    // second, which is the case after losing the first one.
    let third = FakeKey::new(3);
    enrol(&mut vault, &second, &third, "YubiKey du sac");
    let fourth = FakeKey::new(4);
    enrol(&mut vault, &third, &fourth, "YubiKey du coffre-fort");
    assert_eq!(vault.slots.len(), 4);

    for key in [&first, &second, &third, &fourth] {
        let opened = open_with_authorized_key(key, &vault, PIN).expect("opens");
        prove_anchors_open(&vault, &opened).expect("the anchors read");
    }
}

/// A key nobody enrolled opens nothing, and says so as a credential the vault
/// does not know rather than as a decryption failure.
#[test]
fn a_key_that_was_never_enrolled_opens_nothing() {
    let first = FakeKey::new(1);
    let vault = create(&first);

    let stranger = FakeKey::new(9);
    // The stranger has to mint a credential of its own to have anything at
    // all; it is still not in the vault's allow-list.
    stranger
        .register(
            RP_ID,
            &CredentialSubject {
                user_id: vec![],
                user_name: String::new(),
                display_name: String::new(),
            },
            &[],
            PIN,
        )
        .expect("mint");
    assert!(matches!(
        open_with_authorized_key(&stranger, &vault, PIN),
        Err(gestures::GestureError::Authenticator(
            AuthenticatorError::UnknownCredential
        ))
    ));
}

/// Plugging the same key twice does not buy a recovery, and the refusal comes
/// from the token — the exclusion list is what CTAP2 is given.
#[test]
fn the_same_key_does_not_take_two_slots() {
    let first = FakeKey::new(1);
    let mut vault = create(&first);
    let opened = open_with_authorized_key(&first, &vault, PIN).expect("opens");
    assert!(add_key(
        &first,
        &mut vault,
        &opened,
        &NewKey {
            label: "la même".into(),
            role: SlotRole::Recovery,
        },
        PIN,
        2_000,
    )
    .is_err());
    assert_eq!(vault.slots.len(), 1);
}

/// Withdrawing a key leaves every other one working, and the withdrawn one
/// out — which is the pair of properties `remove` exists for.
#[test]
fn withdrawing_a_key_leaves_the_others_working() {
    let first = FakeKey::new(1);
    let mut vault = create(&first);
    let second = FakeKey::new(2);
    enrol(&mut vault, &first, &second, "récupération");
    let third = FakeKey::new(3);
    let third_slot = enrol(&mut vault, &first, &third, "perdue");

    let opened = open_with_authorized_key(&first, &vault, PIN).expect("opens");
    remove_key(&mut vault, &opened, &third_slot).expect("the third slot goes");

    for key in [&first, &second] {
        let opened = open_with_authorized_key(key, &vault, PIN).expect("still opens");
        prove_anchors_open(&vault, &opened).expect("the anchors still read");
    }
    assert!(open_with_authorized_key(&third, &vault, PIN).is_err());
}

/// A wrong PIN is a refusal, not an opening: user verification is what makes a
/// key-slot more than a file the token happens to be near.
#[test]
fn a_wrong_pin_opens_nothing() {
    let first = FakeKey::new(1);
    let vault = create(&first);
    assert!(open_with_authorized_key(&first, &vault, "000000").is_err());
}

/// The vault survives the file, and a key enrolled before the round trip still
/// opens it after: nothing about a slot lives in memory.
#[test]
fn keys_still_open_the_vault_after_a_round_trip_through_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("authority-vault.json");

    let first = FakeKey::new(1);
    let vault = create(&first);
    astra_signer::store::save_new(&path, &vault).expect("save");

    let mut reloaded = astra_signer::store::load(&path).expect("load");
    let second = FakeKey::new(2);
    enrol(&mut reloaded, &first, &second, "récupération");
    astra_signer::store::save(&path, &reloaded).expect("save again");

    let finally = astra_signer::store::load(&path).expect("load again");
    for key in [&first, &second] {
        let opened = open_with_authorized_key(key, &finally, PIN).expect("opens");
        prove_anchors_open(&finally, &opened).expect("the anchors read");
    }
}

/// The gesture must fit the stack the binary gives it.
///
/// ML-DSA-87 keeps its working state on the stack and a debug build copies
/// every intermediate: key generation alone was measured between 768 KiB and
/// 1 MiB. Windows hands a main thread exactly 1 MiB, so `init` overflowed
/// there while passing everywhere else — found on the operator's machine, at
/// the one command that creates the trust domain.
///
/// This runs the whole authority creation on a thread of exactly the size the
/// binary reserves. A stack overflow aborts the process rather than failing a
/// test, so the signal is blunt — which is the right volume for « the tool no
/// longer starts on Windows ».
#[test]
fn the_authority_gesture_fits_the_stack_the_binary_reserves() {
    let done = std::thread::Builder::new()
        .stack_size(astra_signer::WORK_STACK_BYTES)
        .spawn(|| {
            let key = FakeKey::new(1);
            let vault = create(&key);
            // Opening exercises the other heavy half: the AEAD and the
            // payload, on the same stack.
            let opened = open_with_authorized_key(&key, &vault, PIN).expect("opens");
            prove_anchors_open(&vault, &opened).expect("the anchors read");
        })
        .expect("spawn")
        .join();
    assert!(
        done.is_ok(),
        "the gesture completed within the reserved stack"
    );
}
