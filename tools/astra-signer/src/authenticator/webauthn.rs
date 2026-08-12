//! The Windows transport: `webauthn.dll` rather than raw HID.
//!
//! # Why this exists at all
//!
//! Windows reserves opening a FIDO HID device to elevated processes, and has
//! done since Windows 10 1903. Talking CTAP directly therefore means running
//! `astra-signer` as Administrator — a program that holds `CA-PQ` in the clear
//! for the length of an operation, run with the widest privileges the machine
//! has. That is the exact opposite of what ADR-008 §4 asks for.
//!
//! The platform API needs no elevation: it is what browsers call, and browsers
//! are not Administrator. It also collects the PIN **itself**, in its own
//! dialog, so the PIN never enters this process — one secret fewer to hold,
//! zeroize and get wrong.
//!
//! # Same credentials, either way
//!
//! A credential is the authenticator's, not the API's. One created through
//! `webauthn.dll` is opened by the raw CTAP path and the other way round, as
//! long as the RP ID matches — which the vault pins. Switching transports
//! migrates nothing.
//!
//! # One salt for every credential offered
//!
//! `pGlobalHmacSalt` applies the same salt to the whole allow-list, which is
//! exactly the vault's model: one salt per vault, the credential's own
//! `CredRandom` making each output different. The per-credential list
//! (`pCredWithHmacSecretSaltList`) would express something the vault does not
//! have.
//!
//! # Limite connue : `hmac-secret` exige l'API version 4
//!
//! Les sels `hmac-secret` ne sont exposés qu'à partir de
//! [`WEBAUTHN_API_VERSION_4`]. Sur un Windows antérieur, [`connect`] refuse en
//! nommant la version trouvée et renvoie vers `--transport hid`, qui marche
//! partout au prix de l'élévation. Pas de repli implicite : un coffre ouvert
//! par un chemin que l'opérateur n'a pas choisi est un coffre dont il ne sait
//! plus ce qui le protège.
//!
//! # Limite connue : ce module ne se compile pas ailleurs que sous Windows
//!
//! Et il ne s'exerce que sur une vraie machine, avec une vraie clé. Ce qui est
//! au-dessus de la frontière [`super::Authenticator`] est éprouvé par
//! `tests/enrolment.rs` contre des clés simulées ; ce qui est en dessous est
//! *target-only*, comme DPAPI et le TPM.

use std::ffi::c_void;

use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{BOOL, FALSE, HWND, TRUE};
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::Console::GetConsoleWindow;

use super::{
    Authenticator, AuthenticatorError, CredentialSubject, Opened, Result, HMAC_SECRET_LEN,
};
use astra::vault::{SlotSecret, SALT_LEN};

/// Longest an operator is asked to look for their key before we give up.
const TIMEOUT_MS: u32 = 120_000;

pub struct WebAuthnAuthenticator {
    /// The window the platform dialog attaches to. A console application has
    /// one; without it the prompt would have no owner and could open behind
    /// everything.
    window: HWND,
}

impl WebAuthnAuthenticator {
    pub fn connect() -> Result<Self> {
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        if version < WEBAUTHN_API_VERSION_4 {
            return Err(AuthenticatorError::Device(format!(
                "l'API WebAuthn de ce Windows est en version {version}, or les sels \
                 `hmac-secret` exigent la version {WEBAUTHN_API_VERSION_4} : mettre Windows à \
                 jour, ou utiliser `--transport hid` dans une console administrateur"
            )));
        }
        Ok(Self {
            window: unsafe { GetConsoleWindow() },
        })
    }
}

impl Authenticator for WebAuthnAuthenticator {
    /// Windows collects it, in its own dialog. It never reaches this process.
    fn needs_pin(&self) -> bool {
        false
    }

    fn register(
        &self,
        rp_id: &str,
        subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        _pin: &str,
    ) -> Result<Vec<u8>> {
        let rp_id_w = wide(rp_id);
        let rp_name_w = wide("Helios");
        let user_name_w = wide(&subject.user_name);
        let display_name_w = wide(&subject.display_name);
        let mut user_id = subject.user_id.clone();
        let mut client_data_json = client_data(rp_id, "webauthn.create")?;

        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id_w.as_ptr(),
            pwszName: rp_name_w.as_ptr(),
            pwszIcon: std::ptr::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name_w.as_ptr(),
            pwszIcon: std::ptr::null(),
            pwszDisplayName: display_name_w.as_ptr(),
        };
        let mut algorithms = [WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        }];
        let parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: algorithms.len() as u32,
            pCredentialParameters: algorithms.as_mut_ptr(),
        };
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        // `hmac-secret` asked for at creation. Without it the credential is
        // minted without the secret, and the failure would only surface at the
        // next unlock — with a key-slot that unwraps nothing.
        let mut wants_hmac: BOOL = TRUE;
        let mut extensions = [WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: std::mem::size_of::<BOOL>() as u32,
            pvExtension: &mut wants_hmac as *mut BOOL as *mut c_void,
        }];

        // The exclusion list keeps one token from taking two slots of the same
        // vault: two slots on one object is not a recovery, though it reads as
        // one in `list`.
        let mut excluded = CredentialList::new(exclude);
        let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: std::ptr::null_mut(),
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: extensions.len() as u32,
                pExtensions: extensions.as_mut_ptr(),
            },
            // Cross-platform, or Windows offers Hello — a platform
            // authenticator bound to this machine, which is not a key an
            // operator can carry to the recovery site.
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            // Non-discoverable: a YubiKey holds about twenty-five discoverable
            // credentials, and the vault stores the identifier anyway.
            bRequireResidentKey: FALSE,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            dwFlags: 0,
            pCancellationId: std::ptr::null_mut(),
            pExcludeCredentialList: excluded.as_ptr(),
            dwEnterpriseAttestation: 0,
            dwLargeBlobSupport: 0,
            bPreferResidentKey: FALSE,
            bBrowserInPrivateMode: FALSE,
            bEnablePrf: FALSE,
            pLinkedDevice: std::ptr::null_mut(),
            cbJsonExt: 0,
            pbJsonExt: std::ptr::null_mut(),
        };

        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        let status = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                self.window,
                &rp,
                &user,
                &parameters,
                &client,
                &mut options,
                &mut attestation,
            )
        };
        if status != 0 || attestation.is_null() {
            return Err(AuthenticatorError::Device(error_name(status)));
        }

        // From here every exit must free the attestation: it is Windows'
        // allocation, and returning early would leak it.
        let credential_id = unsafe {
            let attested = &*attestation;
            let id = std::slice::from_raw_parts(
                attested.pbCredentialId,
                attested.cbCredentialId as usize,
            )
            .to_vec();
            WebAuthNFreeCredentialAttestation(attestation);
            id
        };
        if credential_id.is_empty() {
            return Err(AuthenticatorError::Device(
                "la clé n'a rendu aucun identifiant de credential".into(),
            ));
        }
        Ok(credential_id)
    }

    fn derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; SALT_LEN],
        _pin: &str,
    ) -> Result<Opened> {
        if credentials.is_empty() {
            return Err(AuthenticatorError::UnknownCredential);
        }
        let rp_id_w = wide(rp_id);
        let mut client_data_json = client_data(rp_id, "webauthn.get")?;
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut salt_bytes = *salt;
        let mut global_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: salt_bytes.len() as u32,
            pbFirst: salt_bytes.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        // One salt for the whole allow-list: the vault draws one per vault,
        // and each credential's own `CredRandom` makes the outputs differ.
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut global_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };

        let mut allowed = CredentialList::new(credentials);
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: std::ptr::null_mut(),
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: 0,
                pExtensions: std::ptr::null_mut(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: 0,
            pwszU2fAppId: std::ptr::null(),
            pbU2fAppId: std::ptr::null_mut(),
            pCancellationId: std::ptr::null_mut(),
            pAllowCredentialList: allowed.as_ptr(),
            dwCredLargeBlobOperation: 0,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: std::ptr::null_mut(),
            pHmacSecretSaltValues: &mut salt_values,
            bBrowserInPrivateMode: FALSE,
            pLinkedDevice: std::ptr::null_mut(),
            bAutoFill: FALSE,
            cbJsonExt: 0,
            pbJsonExt: std::ptr::null_mut(),
        };

        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        let status = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                self.window,
                rp_id_w.as_ptr(),
                &client,
                &options,
                &mut assertion,
            )
        };
        if status != 0 || assertion.is_null() {
            return Err(AuthenticatorError::Device(error_name(status)));
        }

        let opened = unsafe {
            let asserted = &*assertion;
            let credential_id = std::slice::from_raw_parts(
                asserted.Credential.pbId,
                asserted.Credential.cbId as usize,
            )
            .to_vec();
            // `pHmacSecret` null means Windows dropped the extension — an
            // assertion that authenticates but unwraps nothing.
            let secret = if asserted.pHmacSecret.is_null() {
                None
            } else {
                let output = &*asserted.pHmacSecret;
                if output.pbFirst.is_null() || output.cbFirst as usize != HMAC_SECRET_LEN {
                    None
                } else {
                    Some(
                        std::slice::from_raw_parts(output.pbFirst, output.cbFirst as usize)
                            .to_vec(),
                    )
                }
            };
            WebAuthNFreeAssertion(assertion);
            (credential_id, secret)
        };
        let (credential_id, secret) = opened;

        let secret = secret.ok_or(AuthenticatorError::NoHmacOutput)?;
        // The token answers with the credential it holds among those offered.
        // Comparing here keeps a caller from proceeding with one the vault
        // does not know.
        if !credentials.contains(&credential_id) {
            return Err(AuthenticatorError::UnknownCredential);
        }
        Ok(Opened {
            credential_id,
            secret: SlotSecret::new(secret),
        })
    }
}

/// Owns the `WEBAUTHN_CREDENTIAL_EX` array and the pointers into it.
///
/// The API takes a list of *pointers* to entries, so both the entries and the
/// identifiers they point at must outlive the call. Keeping them in one value
/// is what makes that visible rather than accidental.
struct CredentialList {
    /// Owned so the `pbId` pointers below stay valid for the whole call.
    /// Never read again — its job is to exist.
    #[allow(dead_code)]
    identifiers: Vec<Vec<u8>>,
    entries: Vec<WEBAUTHN_CREDENTIAL_EX>,
    pointers: Vec<*mut WEBAUTHN_CREDENTIAL_EX>,
    list: WEBAUTHN_CREDENTIAL_LIST,
    empty: bool,
}

impl CredentialList {
    fn new(identifiers: &[Vec<u8>]) -> Self {
        let mut identifiers = identifiers.to_vec();
        let entries: Vec<WEBAUTHN_CREDENTIAL_EX> = identifiers
            .iter_mut()
            .map(|id| WEBAUTHN_CREDENTIAL_EX {
                dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                // USB only: a vault key is an object one carries, not a
                // credential synchronised into somebody's cloud — which
                // ADR-008 §4 refuses outright.
                dwTransports: WEBAUTHN_CTAP_TRANSPORT_USB,
            })
            .collect();
        let mut list = Self {
            empty: entries.is_empty(),
            identifiers,
            entries,
            pointers: Vec::new(),
            list: WEBAUTHN_CREDENTIAL_LIST {
                cCredentials: 0,
                ppCredentials: std::ptr::null_mut(),
            },
        };
        list.pointers = list
            .entries
            .iter_mut()
            .map(|entry| entry as *mut WEBAUTHN_CREDENTIAL_EX)
            .collect();
        list.list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: list.pointers.len() as u32,
            ppCredentials: list.pointers.as_mut_ptr(),
        };
        list
    }

    /// Null for an empty list: a zero-length list is not the same thing as no
    /// list, and the API reads the pointer before the count.
    fn as_ptr(&mut self) -> *mut WEBAUTHN_CREDENTIAL_LIST {
        if self.empty {
            std::ptr::null_mut()
        } else {
            &mut self.list
        }
    }
}

/// The client data the platform hashes and the authenticator signs.
///
/// Its `challenge` is fresh per operation: WebAuthn's replay defence, and it
/// costs nothing to keep. The origin is derived from the RP ID because the RP
/// ID must be a registrable suffix of it — anything else is refused by the
/// platform, and rightly.
fn client_data(rp_id: &str, operation: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let challenge = super::random_challenge()?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    Ok(format!(
        r#"{{"type":"{operation}","challenge":"{challenge}","origin":"https://{rp_id}","crossOrigin":false}}"#
    )
    .into_bytes())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Windows' own name for a failure, which is more useful than its number.
fn error_name(status: HRESULT) -> String {
    let name = unsafe { WebAuthNGetErrorName(status) };
    if name.is_null() {
        return format!("WebAuthn a échoué (HRESULT {status:#010x})");
    }
    let mut length = 0usize;
    while unsafe { *name.add(length) } != 0 {
        length += 1;
    }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name, length) });
    format!("WebAuthn : {text} (HRESULT {status:#010x})")
}
