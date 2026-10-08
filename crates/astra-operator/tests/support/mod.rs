//! One simulated security key, shared by the tests above it.
//!
//! What is simulated is exactly one thing: the CTAP2 boundary. A fake token
//! mints an Ed25519 credential it never releases, answers a derivation with
//! `HMAC(secret, salt)` — which is what `hmac-secret` is — and answers an
//! approval with a **real** WebAuthn assertion over the exact
//! `clientDataJSON` it was handed. Everything above that is the production
//! code, vault and verifier included.
//!
//! The assertion being real is what makes the approval tests worth running:
//! `aether::certificates::webauthn::verify_assertion` checks the relying party
//! hash, the flags, the origin, the challenge and the signature, and a fake
//! that returned canned bytes would prove none of it.

// A shared test module is compiled into each test binary, so what one of them
// does not name reads as dead. The other one names it.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;

use astra_operator::authenticator::{
    Approval, ApprovedOpening, Authenticator, AuthenticatorError, CredentialSubject, Opened,
    Registration,
};
use astra_operator::vault::SlotSecret;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

pub const RP_ID: &str = "astra.helios.test";
pub const ORIGIN: &str = "https://astra.helios.test";
pub const PIN: &str = "123456";

/// User presence and user verification, the two flags §2.4 requires.
const FLAGS: u8 = 0x01 | 0x04;

/// What one credential is, inside the token.
struct Credential {
    /// The `hmac-secret` seed. Never leaves; only a derivation of it does.
    secret: [u8; 32],
    /// Ed25519 seed of the credential key pair. Kept rather than the key pair
    /// itself so the credential is `Clone`-free and the token stays `!Send`
    /// like the object it stands for.
    signing_seed: [u8; 32],
}

/// One simulated security key.
///
/// `serial` stands for the physical object: two tokens with the same serial
/// are the same token, and a credential minted on one is unknown to the other.
pub struct FakeKey {
    serial: u8,
    credentials: RefCell<HashMap<Vec<u8>, Credential>>,
    minted: RefCell<u8>,
    /// Every `GetAssertion` answered, whichever method asked. The number an
    /// operator would count in touches.
    assertions: RefCell<u32>,
}

impl FakeKey {
    pub fn new(serial: u8) -> Self {
        Self {
            serial,
            credentials: RefCell::new(HashMap::new()),
            minted: RefCell::new(0),
            assertions: RefCell::new(0),
        }
    }

    /// How many `GetAssertion` ceremonies this token has answered.
    pub fn assertions(&self) -> u32 {
        *self.assertions.borrow()
    }

    /// The credential identifiers this token holds, in minting order.
    ///
    /// Only useful to a test that has to name one — the production path always
    /// learns them from the vault or from a signed binding.
    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        let mut ids: Vec<Vec<u8>> = self.credentials.borrow().keys().cloned().collect();
        ids.sort();
        ids
    }
}

fn key_pair(seed: &[u8; 32]) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(seed).expect("an Ed25519 seed is thirty-two bytes")
}

/// The COSE encoding of one Ed25519 public key: `{1: 1, 3: -8, -1: 6, -2: x}`.
fn cose_ed25519(public_key: &[u8]) -> Vec<u8> {
    let mut cose = vec![0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    cose.extend_from_slice(public_key);
    cose
}

impl Authenticator for FakeKey {
    fn register(
        &self,
        rp_id: &str,
        _subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        pin: &str,
    ) -> Result<Registration, AuthenticatorError> {
        if pin != PIN {
            return Err(AuthenticatorError::Device("PIN invalide".into()));
        }
        if rp_id != RP_ID {
            return Err(AuthenticatorError::Device("autre RP ID".into()));
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
        let mut signing_seed = [0x5A; 32];
        signing_seed[0] = self.serial;
        signing_seed[1] = *minted;
        let credential_public_key = cose_ed25519(key_pair(&signing_seed).public_key().as_ref());
        self.credentials.borrow_mut().insert(
            credential_id.clone(),
            Credential {
                secret,
                signing_seed,
            },
        );
        Ok(Registration {
            credential_id,
            credential_public_key,
            aaguid: [0u8; 16],
        })
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
        let secret = held[&credential_id].secret;
        *self.assertions.borrow_mut() += 1;

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

    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        pin: &str,
    ) -> Result<Approval, AuthenticatorError> {
        if pin != PIN {
            return Err(AuthenticatorError::Device("PIN invalide".into()));
        }
        let held = self.credentials.borrow();
        let credential_id = credentials
            .iter()
            .find(|candidate| held.contains_key(*candidate))
            .ok_or(AuthenticatorError::UnknownCredential)?
            .clone();
        *self.assertions.borrow_mut() += 1;

        // What an authenticator actually signs: `rpIdHash || flags ||
        // signCount`, then the SHA-256 of the client data appended to it.
        let mut authenticator_data =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, rp_id.as_bytes())
                .as_ref()
                .to_vec();
        authenticator_data.push(FLAGS);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());

        let mut message = authenticator_data.clone();
        message.extend_from_slice(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, client_data_json).as_ref(),
        );
        let signature = key_pair(&held[&credential_id].signing_seed)
            .sign(&message)
            .as_ref()
            .to_vec();

        Ok(Approval {
            credential_id,
            assertion: aether::certificates::webauthn::WebAuthnAssertion {
                authenticator_data,
                client_data_json: client_data_json.to_vec(),
                signature,
            },
        })
    }

    /// One ceremony, counted once: the two halves are what `approve` and
    /// `derive` would have answered, without the second touch.
    fn approve_and_derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<ApprovedOpening, AuthenticatorError> {
        let before = self.assertions();
        let approval = self.approve(rp_id, credentials, client_data_json, pin)?;
        let opened = self.derive(
            rp_id,
            std::slice::from_ref(&approval.credential_id),
            salt,
            pin,
        )?;
        *self.assertions.borrow_mut() = before + 1;
        Ok(ApprovedOpening { approval, opened })
    }
}
