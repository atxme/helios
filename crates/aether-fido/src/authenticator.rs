//! The one place that talks to a security key.
//!
//! Three gestures, and no others, because the authority needs no others:
//!
//! - [`Authenticator::register`] creates a credential carrying `hmac-secret`,
//!   and returns its identifier, its COSE public key and its AAGUID. All three
//!   are public; the secret behind them never leaves the token.
//! - [`Authenticator::derive`] hands the token the vault's salt and an
//!   allow-list of registered credentials. The token answers with the one it
//!   holds and the 32 bytes `hmac-secret` produced for it. One touch resolves
//!   *which key this is* and *what it unwraps*, together.
//! - [`Authenticator::approve`] asks for presence and user verification over
//!   one exact `clientDataJSON`, and returns the WebAuthn assertion. It takes
//!   **no salt**, so it can obtain no `hmac-secret` output and open no
//!   key-slot — spec §14.1 asks for exactly that separation, and here it is a
//!   signature rather than a convention.
//!
//! # What a security key does here, and what it never does
//!
//! It authenticates, it derives, and it authorizes. It **produces no signature
//! of this protocol.** [`Authenticator::approve`] returns an assertion
//! signature, and that signature authorizes the use of the delegated issuer —
//! it never becomes a field of the certificate lifecycle, because every one of
//! those is an `MlDsa87Signature` and no FIDO2 authenticator produces one. In
//! [`Authenticator::derive`] the assertion's signature is dropped on the floor
//! entirely; only the extension output is read. The token's job is to be a
//! secret that cannot be copied, released only on presence and verification —
//! which is exactly what unwrapping a key-slot asks for (ADR-008 §4).
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

use aether::certificates::webauthn::{WebAuthnAssertion, MAX_CREDENTIAL_PUBLIC_KEY_BYTES};

/// Length of the salt handed to `hmac-secret`, in bytes, and the material a
/// key releases for one slot.
///
/// Both are properties of the key rather than of this crate, and both are
/// therefore defined in `aether` and merely re-exported here. That is not
/// tidiness: `astra` names them to read a vault file, and it must be able to
/// do so **without** linking the CTAP2 stack — the HID pile drags `libudev`,
/// which has no business in a container where no security key is ever plugged
/// in. Everything that actually speaks to a key stays below this line.
pub use aether::certificates::webauthn::{SlotSecret, SALT_LEN};

/// Largest credential identifier accepted, in bytes.
///
/// CTAP2 credential IDs are typically 32–128 bytes; the ceiling refuses input
/// that would drive an allocation before a single field is used. One value for
/// the whole tree: the bound the lifecycle objects validate against is the
/// bound a vault file is parsed with.
pub use aether::certificates::client::MAX_CREDENTIAL_ID_BYTES;

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
        "cette clé n'a pas de PIN configuré : la vérification utilisateur est exigée, et une \
         simple présence physique ne l'est pas"
    )]
    NoPin,
    #[error("la clé branchée ne détient aucun des credentials enregistrés dans ce coffre")]
    UnknownCredential,
    #[error(
        "la clé n'a rendu aucune sortie `hmac-secret` : sans elle, aucun key-slot ne \
         s'ouvre. Soit l'authentificateur ne porte pas l'extension, soit le credential a été \
         créé sans elle — un credential enrôlé par un autre outil, ou avant que celui-ci ne \
         demande PRF"
    )]
    NoHmacOutput,
    #[error("dialogue avec la clé de sécurité : {0}")]
    Device(String),
    #[error(
        "la clé n'a pas rendu les données de credential attestées : sans sa clé publique COSE et \
         son AAGUID, aucun `AstraCredentialBinding` ne peut décrire ce key-slot ({0})"
    )]
    NoAttestedCredential(&'static str),
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

/// The public half of one freshly created credential.
///
/// All three fields go into the `AstraCredentialBinding` `CA-PQ` signs in the
/// same operation as the key-slot. A registration that returned only the
/// identifier would leave the binding unable to name the key an assertion is
/// verified under — and the gap would be found at the first approval, which is
/// the one moment there is no fallback.
pub struct Registration {
    pub credential_id: Vec<u8>,
    /// COSE public key, exactly as the authenticator attested it.
    pub credential_public_key: Vec<u8>,
    /// Authenticator model identifier. Frequently all-zero by design.
    pub aaguid: [u8; 16],
}

/// What one approval ceremony produced.
///
/// There is deliberately no field for an `hmac-secret` output: the method that
/// returns this value is handed no salt, so there is nothing to put in one.
/// An ordinary renewal therefore cannot open a key-slot even by mistake.
pub struct Approval {
    /// The credential the token turned out to hold, among those offered.
    pub credential_id: Vec<u8>,
    pub assertion: WebAuthnAssertion,
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
    ) -> Result<Registration>;

    /// Resolves which of `credentials` the token holds, and derives its slot
    /// secret from `salt`.
    fn derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; SALT_LEN],
        pin: &str,
    ) -> Result<Opened>;

    /// Asks for presence and user verification over one exact
    /// `clientDataJSON`, and returns the assertion.
    ///
    /// `client_data_json` is composed by the caller and carries the challenge
    /// of the operation being approved — the SHA-256 of a canonical request,
    /// never a value this module chooses. The bytes are returned unchanged
    /// inside the assertion so a verifier re-derives the challenge from them
    /// rather than being told what it was.
    ///
    /// No salt, and that is the point: §14.1 requires an ordinary renewal to
    /// obtain no PRF output and open no key-slot, and a method with nowhere to
    /// put one obeys that whatever its callers do.
    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        pin: &str,
    ) -> Result<Approval>;
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
/// by default inside `pHmacSecretSaltValues` — the header says so in as many
/// words. This code deliberately leaves
/// `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` disabled; enabling it would
/// ask Windows to treat the input as a raw CTAP salt and break transport
/// equivalence.
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

/// Offset of the attested credential data inside authenticator data.
///
/// `rpIdHash(32) || flags(1) || signCount(4)`, then — when the AT flag is set
/// — `aaguid(16) || credentialIdLength(2) || credentialId || COSEKey`.
const ATTESTED_CREDENTIAL_OFFSET: usize = 32 + 1 + 4;

/// The AT flag: authenticator data carries attested credential data.
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

/// The public credential material a `MakeCredential` attested.
///
/// Read from the authenticator data both transports already return, rather
/// than from whatever shape each API re-exposes it in: `webauthn.dll` publishes
/// no COSE key at all, and `ctap-hid-fido2` re-encodes it into an SPKI that has
/// lost the algorithm labels a binding must carry. The authenticator data is
/// the one representation both hand back untouched, so it is the one parsed.
pub(crate) struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}

/// Extracts the attested credential data from authenticator data.
///
/// Bounded at every step, because these bytes come from a device: the
/// credential identifier is checked against the vault's own ceiling and the
/// COSE key against WebAuthn's, before either is copied.
pub(crate) fn attested_credential(authenticator_data: &[u8]) -> Result<AttestedCredential> {
    let mut cursor = ATTESTED_CREDENTIAL_OFFSET;
    if authenticator_data.len() <= cursor {
        return Err(AuthenticatorError::NoAttestedCredential(
            "données d'authentificateur trop courtes",
        ));
    }
    if authenticator_data[32] & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
        return Err(AuthenticatorError::NoAttestedCredential(
            "drapeau AT absent",
        ));
    }

    let aaguid: [u8; 16] = authenticator_data
        .get(cursor..cursor + 16)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(AuthenticatorError::NoAttestedCredential("AAGUID tronqué"))?;
    cursor += 16;

    let length = authenticator_data
        .get(cursor..cursor + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_be_bytes)
        .ok_or(AuthenticatorError::NoAttestedCredential(
            "longueur de credential tronquée",
        ))? as usize;
    cursor += 2;
    if length == 0 || length > MAX_CREDENTIAL_ID_BYTES {
        return Err(AuthenticatorError::NoAttestedCredential(
            "identifiant de credential hors bornes",
        ));
    }
    let credential_id = authenticator_data
        .get(cursor..cursor + length)
        .ok_or(AuthenticatorError::NoAttestedCredential(
            "identifiant de credential tronqué",
        ))?
        .to_vec();
    cursor += length;

    let remainder = &authenticator_data[cursor..];
    let key_length = cose_key_length(remainder)?;
    Ok(AttestedCredential {
        aaguid,
        credential_id,
        credential_public_key: remainder[..key_length].to_vec(),
    })
}

/// Length of the COSE key opening `bytes`, so extension output that follows it
/// is left out.
///
/// A COSE key is a definite-length CBOR map of integer labels to integers and
/// byte strings, and this reads exactly that — no tags, no indefinite lengths,
/// no nested containers. Anything else is refused rather than skipped: a
/// reader that tolerated more than the shape it needs would decide where a key
/// ends by guessing, and the guess would end up inside a signed binding.
fn cose_key_length(bytes: &[u8]) -> Result<usize> {
    fn refuse() -> AuthenticatorError {
        AuthenticatorError::NoAttestedCredential("clé publique COSE illisible")
    }

    /// Reads one CBOR head, returning `(major type, argument, bytes read)`.
    fn head(bytes: &[u8], offset: usize) -> Result<(u8, u64, usize)> {
        let initial = *bytes.get(offset).ok_or_else(refuse)?;
        let major = initial >> 5;
        let extra = initial & 0x1f;
        let (argument, width) = match extra {
            value @ 0..=23 => (u64::from(value), 0usize),
            24 => (u64::from(*bytes.get(offset + 1).ok_or_else(refuse)?), 1),
            25 => (
                u64::from(u16::from_be_bytes(
                    bytes
                        .get(offset + 1..offset + 3)
                        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
                        .ok_or_else(refuse)?,
                )),
                2,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    bytes
                        .get(offset + 1..offset + 5)
                        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
                        .ok_or_else(refuse)?,
                )),
                4,
            ),
            // 64-bit arguments and the indefinite-length marker have no place
            // in a COSE key of the two shapes a FIDO2 credential registers.
            _ => return Err(refuse()),
        };
        Ok((major, argument, 1 + width))
    }

    let (major, entries, mut offset) = head(bytes, 0)?;
    if major != 5 {
        return Err(refuse());
    }
    for _ in 0..entries {
        for position in 0..2 {
            let (major, argument, width) = head(bytes, offset)?;
            offset += width;
            match major {
                // Unsigned and negative integers: the labels, the key type,
                // the algorithm and the curve.
                0 | 1 => {}
                // Byte strings: the coordinates. Never a label.
                2 if position == 1 => {
                    let length = usize::try_from(argument).map_err(|_| refuse())?;
                    offset = offset.checked_add(length).ok_or_else(refuse)?;
                    if offset > bytes.len() {
                        return Err(refuse());
                    }
                }
                _ => return Err(refuse()),
            }
        }
    }
    if offset == 0 || offset > MAX_CREDENTIAL_PUBLIC_KEY_BYTES || offset > bytes.len() {
        return Err(refuse());
    }
    Ok(offset)
}

/// The window the platform dialog belongs to.
///
/// # Why a caller has to say
///
/// Windows attaches its WebAuthn dialog to an owner window. A console program
/// has one for free, and asking the system for it was the whole of this
/// decision while the only caller was a terminal. A program launched with no
/// console — the helper Orion starts — gets a null handle from that same call,
/// and the dialog then opens **unowned**: it can appear behind the window the
/// operator is looking at, on a machine where the only instruction is «touchez
/// la clé». A prompt nobody sees is indistinguishable from a key that is not
/// answering.
///
/// So the owner is named by whoever knows: a terminal says [`Self::Console`],
/// a windowed program hands the handle of a window it owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialogOwner {
    /// The console window of this process, if it has one.
    #[default]
    Console,
    /// A top-level window this process owns.
    ///
    /// Carried as `isize` rather than a platform handle type so the choice can
    /// be made, passed and tested in code that compiles everywhere.
    Window(isize),
}

/// Opens the single connected security key, over `transport`.
///
/// Exactly one: a second key plugged in during an enrolment is how an operator
/// registers the credential of one token into the slot they meant for another.
///
/// The dialog attaches to this process's console. A program without one must
/// use [`connect_owned`] and say where its prompts belong.
pub fn connect(transport: Transport) -> Result<Box<dyn Authenticator>> {
    connect_owned(transport, DialogOwner::Console)
}

/// Opens the key and attaches any platform dialog to `owner`.
pub fn connect_owned(transport: Transport, owner: DialogOwner) -> Result<Box<dyn Authenticator>> {
    match transport {
        // Raw CTAP shows nothing: the gesture is on the token, and there is no
        // dialog for an owner to own.
        Transport::Hid => Ok(Box::new(ctap::Ctap2Authenticator::connect()?)),
        #[cfg(windows)]
        Transport::Platform => Ok(Box::new(webauthn::WebAuthnAuthenticator::connect(owner)?)),
        #[cfg(not(windows))]
        Transport::Platform => {
            let _ = owner;
            Err(AuthenticatorError::Device(
                "aucune API de plateforme sur ce système : seule `--transport hid` existe ici"
                    .to_string(),
            ))
        }
    }
}

#[cfg(windows)]
mod webauthn;

mod ctap {
    use super::SlotSecret;
    use super::{
        Approval, AuthenticatorError, CredentialSubject, Opened, Registration, Result,
        HMAC_SECRET_LEN, SALT_LEN,
    };
    use aether::certificates::webauthn::WebAuthnAssertion;
    use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as AssertionExt;
    use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
    use ctap_hid_fido2::fidokey::get_info::InfoOption;
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

        /// Refuses a token that has no PIN, before an operator is asked to
        /// touch anything.
        ///
        /// **Only** the PIN. `hmac-secret` is deliberately not gated on what
        /// `getInfo` advertises: refusing on a capability report, before
        /// attempting the operation, turns any misreading of that report into
        /// « your key cannot do this » — which is what happened to a YubiKey 5
        /// firmware 5.7.4 that does it perfectly well. The operation is the
        /// proof: [`Ctap2Authenticator::register`] checks the attestation, and
        /// `derive` fails with [`AuthenticatorError::NoHmacOutput`] if nothing
        /// comes back. Both are facts rather than claims.
        ///
        /// The PIN is different in kind: `clientPin` absent means the model has
        /// no PIN at all, present and false means one was never set. Both are
        /// the same refusal — user verification is required, and physical
        /// presence alone is not it — and the failure is otherwise reported by
        /// CTAP as a bare status code.
        fn assert_capable(&self) -> Result<()> {
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

        /// What `getInfo` advertised, to enrich a failure rather than cause one.
        fn advertised_extensions(&self) -> String {
            match self.key.get_info() {
                Ok(info) if info.extensions.is_empty() => "aucune annoncée".to_string(),
                Ok(info) => info.extensions.join(", "),
                Err(error) => format!("illisibles ({error})"),
            }
        }
    }

    impl super::Authenticator for Ctap2Authenticator {
        fn register(
            &self,
            rp_id: &str,
            subject: &CredentialSubject,
            exclude: &[Vec<u8>],
            pin: &str,
        ) -> Result<Registration> {
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
            // The COSE key and the AAGUID come out of the authenticator data
            // rather than out of `credential_publickey`: that field has already
            // been re-encoded into an SPKI, which no longer says which COSE
            // algorithm the credential registered under.
            let attested = super::attested_credential(&attestation.auth_data)?;
            if attested.credential_id != credential_id {
                return Err(AuthenticatorError::NoAttestedCredential(
                    "l'identifiant attesté diffère de celui rendu",
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
                return Err(AuthenticatorError::Device(format!(
                    "la clé a créé le credential sans activer `hmac-secret`, donc il n'ouvrira \
                     aucun key-slot. Extensions annoncées par la clé : {}",
                    self.advertised_extensions()
                )));
            }
            Ok(Registration {
                credential_id,
                credential_public_key: attested.credential_public_key,
                aaguid: attested.aaguid,
            })
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

        fn approve(
            &self,
            rp_id: &str,
            credentials: &[Vec<u8>],
            client_data_json: &[u8],
            pin: &str,
        ) -> Result<Approval> {
            if credentials.is_empty() {
                return Err(AuthenticatorError::UnknownCredential);
            }
            // CTAP2 signs a `clientDataHash`, and this crate hashes whatever it
            // is handed as the challenge. Handing it the `clientDataJSON`
            // therefore produces exactly WebAuthn's own hash — and the caller
            // keeps the pre-image, which is what a verifier re-derives the
            // challenge from.
            //
            // No `Extension::HmacSecret` here, and no salt to put in one: this
            // ceremony authorizes, it does not unwrap.
            let mut builder = GetAssertionArgsBuilder::new(rp_id, client_data_json).pin(pin);
            for credential in credentials {
                builder = builder.add_credential_id(credential);
            }
            let assertions =
                self.key
                    .get_assertion_with_args(&builder.build())
                    .map_err(|error| {
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

            // Same rule as `derive`: CTAP2 may omit the credential when the
            // allow-list held exactly one entry, and falling back to it then is
            // not a guess.
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

            Ok(Approval {
                credential_id,
                assertion: WebAuthnAssertion {
                    authenticator_data: assertion.auth_data,
                    client_data_json: client_data_json.to_vec(),
                    signature: assertion.signature,
                },
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
    let mut out = [0u8; 32];
    aether::random::fill_public(&mut out).map_err(|error| {
        AuthenticatorError::Device(format!("générateur approuvé indisponible: {error}"))
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests;
