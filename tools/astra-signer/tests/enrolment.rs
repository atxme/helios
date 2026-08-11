//! The authority gestures, end to end, against simulated security keys.
//!
//! What is simulated is exactly one thing: the CTAP2 boundary. A fake token
//! holds a per-credential secret it never releases, and answers an assertion
//! with `HMAC(secret, salt)` — which is what `hmac-secret` is. Everything
//! above that is the production code, including the vault.
//!
//! So these tests do not prove a YubiKey works; nothing outside a real machine
//! can (see `docs/testing/TESTING.md`). They prove the sequence around it does:
//! that a second key registered a year after the first opens the same anchors,
//! that a third and a fourth do too, that a key which was never enrolled opens
//! nothing, and that withdrawing one leaves everyone else working.

use std::cell::RefCell;
use std::collections::HashMap;

use aether::certificates::encoding::TrustDomainId;
use astra::vault::{AuthorityVault, SlotRole, SlotSecret};
use astra_signer::authenticator::{Authenticator, AuthenticatorError, CredentialSubject, Opened};
use astra_signer::gestures::{
    self, add_key, create_authority, open_with_authorized_key, prove_anchors_open, remove_key,
    NewAuthority, NewKey,
};

const RP_ID: &str = "astra.helios.test";
const PIN: &str = "123456";

/// One simulated security key.
///
/// `serial` stands for the physical object: two tokens with the same serial
/// are the same token, and a credential minted on one is unknown to the other.
struct FakeKey {
    serial: u8,
    /// Credentials this token minted, and the secret behind each. The secret
    /// never leaves — only a derivation of it does.
    credentials: RefCell<HashMap<Vec<u8>, [u8; 32]>>,
    minted: RefCell<u8>,
}

impl FakeKey {
    fn new(serial: u8) -> Self {
        Self {
            serial,
            credentials: RefCell::new(HashMap::new()),
            minted: RefCell::new(0),
        }
    }
}

impl Authenticator for FakeKey {
    fn register(
        &self,
        _rp_id: &str,
        _subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        pin: &str,
    ) -> Result<Vec<u8>, AuthenticatorError> {
        if pin != PIN {
            return Err(AuthenticatorError::Device("PIN invalide".into()));
        }
        // CTAP2's `excludeList`: a token that already holds one of these
        // refuses rather than minting a second.
        if exclude
            .iter()
            .any(|candidate| self.credentials.borrow().contains_key(candidate))
        {
            return Err(AuthenticatorError::Device(
                "cette clé détient déjà un credential de ce coffre".into(),
            ));
        }
        let mut minted = self.minted.borrow_mut();
        *minted += 1;
        let credential_id = vec![self.serial, *minted, 0xC0, 0xDE]
            .into_iter()
            .cycle()
            .take(64)
            .collect::<Vec<u8>>();
        let mut secret = [0u8; 32];
        secret[0] = self.serial;
        secret[1] = *minted;
        self.credentials
            .borrow_mut()
            .insert(credential_id.clone(), secret);
        Ok(credential_id)
    }

    fn derive(
        &self,
        _rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<Opened, AuthenticatorError> {
        if pin != PIN {
            return Err(AuthenticatorError::Device("PIN invalide".into()));
        }
        let held = self.credentials.borrow();
        let credential_id = credentials
            .iter()
            .find(|candidate| held.contains_key(*candidate))
            .ok_or(AuthenticatorError::UnknownCredential)?
            .clone();
        let secret = held[&credential_id];

        // `hmac-secret`, in shape if not in algorithm: a value determined by
        // the credential's secret and the salt, and by nothing else.
        let mut output = [0u8; 32];
        for index in 0..32 {
            output[index] = secret[index] ^ salt[index];
        }
        Ok(Opened {
            credential_id,
            secret: SlotSecret::new(output.to_vec()),
        })
    }
}

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
