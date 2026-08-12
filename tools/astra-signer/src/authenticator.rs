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

/// USB vendor identifiers of common security-key makers.
///
/// **Purely diagnostic.** Nothing selects, accepts or refuses a key on this
/// list: that is the HID usage page's job, and a key from a vendor nobody
/// listed works exactly the same. It exists so that « nothing found » can
/// become « your key is right there, and here is what is blocking it », which
/// is the difference between a dead end and a fix.
const SECURITY_KEY_VENDORS: &[u16] = &[
    0x1050, // Yubico
    0x096e, // Feitian
    0x20a0, // Nitrokey
    0x0483, // SoloKeys (STMicroelectronics)
    0x1d50, // OpenMoko — Solo 1, OnlyKey
    0x2581, // Kensington / Plug-up
    0x311f, // TrustKey
    0x32a3, // Idem Key
    0x2c97, // Ledger
];

/// Length of the `hmac-secret` output, in bytes. Fixed by CTAP2.
pub const HMAC_SECRET_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    #[error("{0}")]
    NoDevice(String),
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

/// How this program reaches the security key.
///
/// Explicit, never inferred at runtime: which transport opened a vault decides
/// what protected it — an elevated process talking raw HID, or the platform
/// collecting the PIN itself — and an operator must not have to guess which
/// one they got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Transport {
    /// The operating system's own API. No elevation, and it collects the PIN
    /// itself so the PIN never enters this process. Windows only.
    #[cfg_attr(windows, default)]
    Platform,
    /// Raw CTAP2 over HID. Works everywhere; under Windows it needs an
    /// elevated process, which for a program holding `CA-PQ` in the clear is
    /// a privilege nobody should want.
    #[cfg_attr(not(windows), default)]
    Hid,
}

/// A security key, as this program needs it.
pub trait Authenticator {
    /// Whether the caller must collect the PIN and pass it in.
    ///
    /// False on the platform transport: the operating system asks for it in
    /// its own dialog, and the value never crosses into this process. A caller
    /// that prompted anyway would be asking for a secret it has no use for.
    fn needs_pin(&self) -> bool {
        true
    }

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

/// One HID device, as the system exposes it.
///
/// Public because diagnosing « nothing found » is impossible from the outside:
/// the interesting fact is whether the system shows *any* HID at all, and
/// whether the ones it shows carry the FIDO usage page.
pub struct VisibleDevice {
    pub product: String,
    pub vendor_id: u16,
    pub product_id: u16,
    /// Carries HID usage page `0xF1D0`. The only thing that makes a device a
    /// security key here — never its model.
    pub fido: bool,
    /// Its vendor makes security keys. Diagnostic only: it selects nothing,
    /// and a key from an unlisted vendor works identically. It is what turns
    /// « nothing found » into « found, and blocked ».
    pub known_vendor: bool,
    /// What the HID layer reports: usage page, usage, serial, path.
    pub detail: String,
}

/// Every HID device the system exposes, FIDO or not.
pub fn visible_devices() -> Vec<VisibleDevice> {
    let fido_paths: std::collections::HashSet<String> = ctap_hid_fido2::get_fidokey_devices()
        .iter()
        .filter_map(path_of)
        .collect();
    ctap_hid_fido2::get_hid_devices()
        .iter()
        .map(|device| VisibleDevice {
            product: device.product_string.clone(),
            vendor_id: device.vid,
            product_id: device.pid,
            fido: path_of(device).is_some_and(|path| fido_paths.contains(&path)),
            known_vendor: SECURITY_KEY_VENDORS.contains(&device.vid),
            detail: device.info.clone(),
        })
        .collect()
}

fn path_of(device: &ctap_hid_fido2::HidInfo) -> Option<String> {
    match &device.param {
        ctap_hid_fido2::HidParam::Path(path) => Some(path.clone()),
        ctap_hid_fido2::HidParam::VidPid { .. } => None,
    }
}

/// The salt the authenticator is actually handed, from the vault's salt.
///
/// WebAuthn's PRF extension does **not** pass the caller's value to
/// `hmac-secret` as-is: it hashes it first, as
/// `SHA-256("WebAuthn PRF" || 0x00 || value)`. Windows applies that conversion
/// inside `pHmacSecretSaltValues` — the header says so in as many words — and
/// offers no way to opt out.
///
/// So the raw CTAP path applies it too. Without this, the same vault salt would
/// derive two different secrets depending on the transport: a vault created on
/// Windows would refuse the very same key over raw HID, and the failure would
/// arrive as an AEAD error naming nothing at all.
///
/// It is a domain separation either way, which is why adopting the platform's
/// costs nothing: the value is public, and the secret comes from the
/// credential's own `CredRandom`.
fn prf_salt(salt: &[u8; SALT_LEN]) -> [u8; SALT_LEN] {
    use aws_lc_rs::digest;
    let mut input = Vec::with_capacity(PRF_PREFIX.len() + salt.len());
    input.extend_from_slice(PRF_PREFIX);
    input.extend_from_slice(salt);
    let digest = digest::digest(&digest::SHA256, &input);
    let mut out = [0u8; SALT_LEN];
    out.copy_from_slice(digest.as_ref());
    out
}

/// `"WebAuthn PRF"` and the separator the specification puts after it.
const PRF_PREFIX: &[u8] = b"WebAuthn PRF\x00";

/// Opens the single connected security key, over `transport`.
///
/// Exactly one: a second key plugged in during an enrolment is how an operator
/// registers the credential of one token into the slot they meant for another.
pub fn connect(transport: Transport) -> Result<Box<dyn Authenticator>> {
    match transport {
        Transport::Hid => Ok(Box::new(ctap::Ctap2Authenticator::connect()?)),
        #[cfg(windows)]
        Transport::Platform => Ok(Box::new(webauthn::WebAuthnAuthenticator::connect()?)),
        #[cfg(not(windows))]
        Transport::Platform => Err(AuthenticatorError::Device(
            "aucune API de plateforme sur ce système : seule `--transport hid` existe ici"
                .to_string(),
        )),
    }
}

#[cfg(windows)]
mod webauthn;

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

    /// Says why nothing was found, rather than that nothing was found.
    ///
    /// A FIDO device is recognised by its HID **usage page** (`0xF1D0`), never
    /// by a vendor or product identifier — so « we do not know this model » is
    /// never the answer. Reading that usage page means opening the device, and
    /// Windows refuses to open a FIDO HID to a process that is not elevated
    /// since Windows 10 1903: the key is plugged in, visible as a HID device,
    /// and filtered out because its usage page could not be read.
    ///
    /// Distinguishing « no HID at all » from « HID present, none FIDO » is
    /// therefore the whole diagnosis, and it costs one more enumeration.
    fn no_device_diagnosis() -> String {
        let all = ctap_hid_fido2::get_hid_devices();
        if all.is_empty() {
            return "aucun périphérique HID n'est visible : ni clé de sécurité, ni clavier, ni \
                    souris. C'est la pile HID du système qui ne répond pas, pas la clé"
                .to_string();
        }

        // A security-key vendor among the visible devices settles it: the
        // object is on the bus, the system sees it, and only its FIDO
        // interface is unreadable. Nothing *selects* a key by vendor — that
        // stays the usage page's job — but naming one here turns « nothing
        // found » into « found, and here is what is in the way ».
        let suspects: Vec<String> = all
            .iter()
            .filter(|device| super::SECURITY_KEY_VENDORS.contains(&device.vid))
            .map(|device| {
                format!(
                    "{} ({:04x}:{:04x})",
                    if device.product_string.trim().is_empty() {
                        "sans nom"
                    } else {
                        device.product_string.trim()
                    },
                    device.vid,
                    device.pid
                )
            })
            .collect();

        let mut diagnosis = format!(
            "aucune interface FIDO2 lisible, sur {} périphérique(s) HID visibles. Une clé FIDO2 \
             se reconnaît à son usage page HID 0xF1D0 — jamais à son modèle —, et lire cette \
             valeur exige d'ouvrir le périphérique",
            all.len()
        );
        if !suspects.is_empty() {
            diagnosis.push_str(&format!(
                ".\n\nUne clé de sécurité EST pourtant visible : {}. Elle est donc bien \
                 branchée et reconnue par le système ; c'est l'ouverture de son interface FIDO \
                 qui est refusée",
                suspects.join(", ")
            ));
        }
        if cfg!(windows) {
            diagnosis.push_str(
                ".\n\nSous Windows, ouvrir un HID FIDO est réservé aux processus élevés depuis \
                 Windows 10 1903, et une console PowerShell ordinaire ne suffit pas. Depuis \
                 celle-ci, pour en ouvrir une élevée au même endroit :\n\n    Start-Process \
                 powershell -Verb RunAs -ArgumentList '-NoExit','-Command',\"cd '$PWD'\"",
            );
        } else {
            diagnosis.push_str(
                ".\n\nSous Linux, il manque en général une règle udev donnant l'accès au \
                 périphérique à l'utilisateur courant",
            );
        }
        diagnosis
            .push_str("\n\n`astra-signer devices` liste chaque périphérique et son usage page.");
        diagnosis
    }

    pub struct Ctap2Authenticator {
        key: FidoKeyHid,
    }

    impl Ctap2Authenticator {
        pub fn connect() -> Result<Self> {
            let devices = ctap_hid_fido2::get_fidokey_devices();
            match devices.len() {
                0 => return Err(AuthenticatorError::NoDevice(no_device_diagnosis())),
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
            // The platform's conversion, applied here: see `super::prf_salt`.
            // Skipping it would make a vault created on Windows unopenable
            // over this transport, with the same key.
            let mut builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
                .pin(pin)
                .extensions(&[AssertionExt::HmacSecret(Some(super::prf_salt(salt)))]);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform hashes the PRF value before it reaches `hmac-secret`, and
    /// the raw path must do the same. If this ever becomes the identity again,
    /// a vault created on Windows stops opening over HID — with the same key,
    /// and an error naming only the AEAD.
    #[test]
    fn the_prf_salt_is_the_platform_transformation_and_not_the_salt() {
        let salt = [0x5Au8; SALT_LEN];
        let derived = prf_salt(&salt);
        assert_ne!(derived, salt, "the value is hashed, not passed through");
        assert_eq!(derived, prf_salt(&salt), "and deterministically so");
        assert_ne!(
            derived,
            prf_salt(&[0x5Bu8; SALT_LEN]),
            "a different vault salt gives a different secret"
        );
    }

    /// The prefix is the specification's, byte for byte: `"WebAuthn PRF"` then
    /// a `0x00`. A stray character here derives a secret nothing else agrees
    /// with, and only a real key would ever notice.
    #[test]
    fn the_prf_prefix_is_the_one_the_specification_names() {
        assert_eq!(PRF_PREFIX, b"WebAuthn PRF\0");
        assert_eq!(PRF_PREFIX.len(), 13);
    }
}
