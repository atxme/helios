//! The one place that talks to a security key.
//!
//! Two gestures, and no others, because the vault needs no others:
//!
//! - [`Authenticator::register`] creates a credential carrying `hmac-secret`,
//!   and returns its identifier. That identifier is public; the secret behind
//!   it never leaves the token.
//! - [`Authenticator::derive`] hands the token the vault's salt and an
//!   allow-list of registered credentials. The token answers with the one it
//!   holds and the 32 bytes `hmac-secret` produced for it. One touch resolves
//!   *which key this is* and *what it unwraps*, together.
//!
//! # What a security key does here, and what it never does
//!
//! It authenticates, and it derives. It **signs nothing this program keeps.**
//! An assertion carries a signature; we read the extension output and drop the
//! signature on the floor, because no field of the certificate lifecycle holds
//! anything but an `MlDsa87Signature` and no FIDO2 authenticator produces one.
//! The token's job is to be a secret that cannot be copied, released only on
//! presence and verification — which is exactly what unwrapping a key-slot
//! asks for (ADR-008 §4).
//!
//! # Non-discoverable credentials
//!
//! Credentials are created without the resident-key flag: a YubiKey 5 holds
//! about twenty-five discoverable credentials, and spending one per vault slot
//! would eventually cost the operator a slot they wanted for something else.
//! Non-discoverable costs nothing on the token, and the price — the client has
//! to remember the credential identifier — is already paid, since the vault
//! stores it in the very row the credential unwraps.
//!
//! # CTAP n'est pas une feature de compilation
//!
//! Tout binaire `astra-signer` porte cette pile, sans condition. Un compagnon
//! qui ne parle à aucune clé n'ouvre aucun coffre, et la spécification refuse
//! tout autre déverrouillage — ni PIN seul, ni assertion non liée au coffre,
//! ni mot de passe de secours. Le bâtir sans le matériel produirait donc un
//! programme qui se lance, affiche ses commandes, et échoue à la seule chose
//! pour laquelle il existe : indiscernable d'une panne, du point de vue de
//! l'opérateur.
//!
//! Le prix est une dépendance de compilation : `hidapi` exige `libudev` sous
//! Linux, que `scripts/setup-dev.sh` installe.
//!
//! # Limite connue : ce chemin ne s'exerce pas ici
//!
//! WSL2 n'a aucun passthrough USB, et sous Windows l'accès HID direct aux
//! périphériques FIDO est réservé aux processus élevés depuis Windows 10 1903 :
//! le compagnon s'y lance en administrateur. Les essais sont donc *target-only*,
//! comme DPAPI et le TPM — voir [`docs/testing/TESTING.md`].
//!
//! [`docs/testing/TESTING.md`]: ../../../docs/testing/TESTING.md

use astra::vault::{SlotSecret, SALT_LEN};

/// Length of the `hmac-secret` output, in bytes. Fixed by CTAP2.
pub const HMAC_SECRET_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    #[error("aucune clé de sécurité FIDO2 branchée")]
    NoDevice,
    #[error(
        "plusieurs clés de sécurité branchées : n'en laisser qu'une, sinon l'opération porterait \
         sur celle que le système a listée en premier"
    )]
    SeveralDevices,
    #[error(
        "cette clé ne prend pas en charge l'extension CTAP2 `hmac-secret` : elle ne peut pas \
         porter un key-slot d'autorité"
    )]
    NoHmacSecret,
    #[error(
        "cette clé n'a pas de PIN configuré : la vérification utilisateur est exigée, et une \
         simple présence physique ne l'est pas"
    )]
    NoPin,
    #[error("la clé branchée ne détient aucun des credentials enregistrés dans ce coffre")]
    UnknownCredential,
    #[error("la clé n'a rendu aucune sortie `hmac-secret` : l'extension a été ignorée")]
    NoHmacOutput,
    #[error("dialogue avec la clé de sécurité : {0}")]
    Device(String),
}

pub type Result<T> = std::result::Result<T, AuthenticatorError>;

/// Who the credential is created for, as WebAuthn requires it to be named.
///
/// Nothing here is secret and nothing is a key: the identifier ties the
/// credential to one trust domain, so a key registered for two authorities
/// shows two distinct entries rather than one ambiguous one.
pub struct CredentialSubject {
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub display_name: String,
}

/// What one assertion resolved.
pub struct Opened {
    /// The credential the token turned out to hold, among those offered.
    pub credential_id: Vec<u8>,
    pub secret: SlotSecret,
}

/// A security key, as this program needs it.
pub trait Authenticator {
    /// Registers a credential carrying `hmac-secret`, and returns its
    /// identifier.
    ///
    /// `exclude` names the credentials already registered in this vault, so a
    /// token that already holds one refuses rather than adding a second — an
    /// operator who plugs the same key twice has not gained a recovery.
    fn register(
        &self,
        rp_id: &str,
        subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        pin: &str,
    ) -> Result<Vec<u8>>;

    /// Resolves which of `credentials` the token holds, and derives its slot
    /// secret from `salt`.
    fn derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; SALT_LEN],
        pin: &str,
    ) -> Result<Opened>;
}

/// Opens the single connected security key.
///
/// Exactly one: a second key plugged in during an enrolment is how an operator
/// registers the credential of one token into the slot they meant for another.
pub fn connect() -> Result<Box<dyn Authenticator>> {
    Ok(Box::new(ctap::Ctap2Authenticator::connect()?))
}

mod ctap {
    use super::{AuthenticatorError, CredentialSubject, Opened, Result, HMAC_SECRET_LEN, SALT_LEN};
    use astra::vault::SlotSecret;
    use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as AssertionExt;
    use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
    use ctap_hid_fido2::fidokey::get_info::{InfoOption, InfoParam};
    use ctap_hid_fido2::fidokey::make_credential::{
        Extension as CredentialExt, MakeCredentialArgsBuilder,
    };
    use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
    use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};

    fn device(error: anyhow::Error) -> AuthenticatorError {
        AuthenticatorError::Device(format!("{error:#}"))
    }

    pub struct Ctap2Authenticator {
        key: FidoKeyHid,
    }

    impl Ctap2Authenticator {
        pub fn connect() -> Result<Self> {
            let devices = ctap_hid_fido2::get_fidokey_devices();
            match devices.len() {
                0 => return Err(AuthenticatorError::NoDevice),
                1 => {}
                _ => return Err(AuthenticatorError::SeveralDevices),
            }
            let mut cfg = LibCfg::init();
            // The touch prompt goes to stderr: stdout carries values an
            // operator pipes into `astra bootstrap`, and a prompt mixed into
            // them would travel with the key material.
            cfg.keep_alive_msg = "— toucher la clé de sécurité".to_string();
            cfg.keep_alive_msg_to_stderr = true;
            let key = FidoKeyHidFactory::create(&cfg).map_err(device)?;

            let authenticator = Self { key };
            authenticator.assert_capable()?;
            Ok(authenticator)
        }

        /// Refuses an unusable token **before** an operator is asked to touch
        /// anything, and before a vault is created around a key that cannot
        /// carry a slot.
        fn assert_capable(&self) -> Result<()> {
            if !self
                .key
                .enable_info_param(&InfoParam::ExtensionsHmacSecret)
                .map_err(device)?
            {
                return Err(AuthenticatorError::NoHmacSecret);
            }
            // `clientPin` absent means the model has no PIN at all; present and
            // false means one was never set. Both are the same refusal: user
            // verification is required, and presence alone is not it.
            if self
                .key
                .enable_info_option(&InfoOption::ClientPin)
                .map_err(device)?
                != Some(true)
            {
                return Err(AuthenticatorError::NoPin);
            }
            Ok(())
        }
    }

    impl super::Authenticator for Ctap2Authenticator {
        fn register(
            &self,
            rp_id: &str,
            subject: &CredentialSubject,
            exclude: &[Vec<u8>],
            pin: &str,
        ) -> Result<Vec<u8>> {
            let challenge = super::random_challenge()?;
            let user = PublicKeyCredentialUserEntity::new(
                Some(&subject.user_id),
                Some(&subject.user_name),
                Some(&subject.display_name),
            );
            let mut builder = MakeCredentialArgsBuilder::new(rp_id, &challenge)
                .pin(pin)
                .user_entity(&user)
                .extensions(&[CredentialExt::HmacSecret(Some(true))]);
            for credential in exclude {
                builder = builder.exclude_authenticator(credential);
            }
            let attestation = self
                .key
                .make_credential_with_args(&builder.build())
                .map_err(device)?;

            let credential_id = attestation.credential_descriptor.id;
            if credential_id.is_empty() {
                return Err(AuthenticatorError::Device(
                    "la clé n'a rendu aucun identifiant de credential".into(),
                ));
            }
            // A token that registered the credential without the extension
            // would hand back an identifier that unwraps nothing — and the
            // failure would only surface at the next unlock.
            if !attestation
                .extensions
                .iter()
                .any(|ext| matches!(ext, CredentialExt::HmacSecret(Some(true))))
            {
                return Err(AuthenticatorError::NoHmacSecret);
            }
            Ok(credential_id)
        }

        fn derive(
            &self,
            rp_id: &str,
            credentials: &[Vec<u8>],
            salt: &[u8; SALT_LEN],
            pin: &str,
        ) -> Result<Opened> {
            if credentials.is_empty() {
                return Err(AuthenticatorError::UnknownCredential);
            }
            let challenge = super::random_challenge()?;
            let mut builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
                .pin(pin)
                .extensions(&[AssertionExt::HmacSecret(Some(*salt))]);
            for credential in credentials {
                builder = builder.add_credential_id(credential);
            }
            let assertions =
                self.key
                    .get_assertion_with_args(&builder.build())
                    .map_err(|error| {
                        // CTAP2 answers `NO_CREDENTIALS` when the token holds none
                        // of the allow-list. That is the ordinary case of plugging
                        // the wrong key, and it deserves its own sentence rather
                        // than a status code.
                        let text = format!("{error:#}");
                        if text.contains("0x2E") || text.to_lowercase().contains("no_credentials") {
                            AuthenticatorError::UnknownCredential
                        } else {
                            AuthenticatorError::Device(text)
                        }
                    })?;
            let assertion = assertions
                .into_iter()
                .next()
                .ok_or(AuthenticatorError::UnknownCredential)?;

            // CTAP2 may omit the credential from the response when the
            // allow-list held exactly one entry: there is nothing to
            // disambiguate. Falling back to that single entry is not a guess.
            let credential_id = if assertion.credential_id.is_empty() {
                if credentials.len() != 1 {
                    return Err(AuthenticatorError::Device(
                        "la clé n'a pas nommé le credential utilisé alors que plusieurs étaient \
                         proposés"
                            .into(),
                    ));
                }
                credentials[0].clone()
            } else {
                assertion.credential_id.clone()
            };
            if !credentials.contains(&credential_id) {
                return Err(AuthenticatorError::UnknownCredential);
            }

            let output = assertion
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    AssertionExt::HmacSecret(Some(output)) => Some(*output),
                    _ => None,
                })
                .ok_or(AuthenticatorError::NoHmacOutput)?;
            debug_assert_eq!(output.len(), HMAC_SECRET_LEN);

            Ok(Opened {
                credential_id,
                secret: SlotSecret::new(output.to_vec()),
            })
        }
    }
}

/// A fresh client-data hash for one operation.
///
/// WebAuthn's replay defence, and it costs nothing to keep: a fixed challenge
/// would let a captured assertion be replayed against a token that is no longer
/// present.
fn random_challenge() -> Result<[u8; 32]> {
    use aws_lc_rs::rand::SecureRandom as _;
    let mut out = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| AuthenticatorError::Device("générateur aléatoire indisponible".into()))?;
    Ok(out)
}
