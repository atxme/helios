//! Non-exportable TPM key in the *Microsoft Platform Crypto Provider*
//! (ADR-006 §3, layer 1).
//!
//! # What this layer buys, precisely
//!
//! The private key lives **in the TPM** and never leaves it. Copying the sealed
//! files to another machine therefore makes them permanently unreadable — that
//! is the whole answer to threat T4, and the reason a software provider is
//! refused rather than accepted quietly.
//!
//! It does **not** make the installation root non-exportable. Orion asks the
//! TPM to unwrap, and the plaintext root comes back into this process. Code
//! running as the same account can observe it at that moment (T9). The TPM
//! bounds a compromise in time and space; it does not prevent one.
//!
//! # What is verified, before anything is persisted
//!
//! Provider type, non-exportability, modulus and the operation result, on the
//! freshly finalised handle — a key created and then found wanting must not
//! leave a file behind that a later run would adopt.
//!
//! The access list is where the account binding lives, and the **scope** of the
//! key ([`KeyScope`]) decides which one applies:
//!
//! * [`KeyScope::Machine`], the engine's key, is created in the machine
//!   container with a DACL that admits only Administrators and SYSTEM, set
//!   before the key is finalised. That DACL is read back and **enforced**
//!   ([`KeyAccess`]): a wider or unreadable list is refused.
//! * [`KeyScope::User`] is the per-user container of the first version. It is
//!   opened without `NCRYPT_MACHINE_KEY_FLAG`, so another account does not see
//!   it, and it is not ACL-checked. It is kept so that the migration can read a
//!   root wrapped under it.
//!
//! The owner SID, by contrast, is still only *observed*: see [`KeyOwnership`].
//!
//! OAEP-SHA-256 over RSA. The modulus is **preferred** at 3072 and **floored**
//! at 2048 — see [`MIN_RSA_BITS`] for why the hardware settled that argument.
//! Falling back is announced in the log; moving to the software provider never
//! happens, because that would keep the screen's promise while removing what
//! backs it.

use zeroize::Zeroizing;

use crate::vault::{keys::KEY_LEN, VaultError};

/// Name the key is persisted under, inside the provider's own store.
pub const KEY_NAME: &str = "Helios Orion device root v1";

/// Name of the machine key of `user_sid`, the one the engine uses.
///
/// Distinct from [`KEY_NAME`] and per user, so a machine key is never taken for
/// the per-user one and two accounts never share a slot.
pub fn machine_key_slot(user_sid: &str) -> String {
    format!("Helios Orion device root v2 {user_sid}")
}

/// Which persisted key the root is wrapped under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyScope {
    /// The per-user container, under [`KEY_NAME`].
    User,
    /// The machine container, under the name of the interactive user's SID.
    Machine(String),
}

impl KeyScope {
    /// The name the key is persisted under in this scope.
    pub fn key_name(&self) -> String {
        match self {
            Self::User => KEY_NAME.to_string(),
            Self::Machine(user_sid) => machine_key_slot(user_sid),
        }
    }

    /// The scope's name for the log. Never the SID: a log line has no use for it.
    pub fn label(&self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Machine(_) => "Machine",
        }
    }
}

/// The scope the engine uses, given the interactive user's SID when there is one.
///
/// A known SID selects that user's machine key. Without one, which happens only
/// outside the engine, the user scope is the only one available.
pub fn key_scope_for(user_sid: Option<&str>) -> KeyScope {
    match user_sid {
        Some(sid) => KeyScope::Machine(sid.to_string()),
        None => KeyScope::User,
    }
}

/// Whether the access list of the key is read and enforced for `scope`.
///
/// Every machine key is; the user-scope key never is.
pub fn access_is_checked(scope: &KeyScope) -> bool {
    matches!(scope, KeyScope::Machine(_))
}

/// What the access list of the key admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAccess {
    /// Not read. Only the user-scope key is left unchecked: its account binding
    /// is the container it is opened from.
    NotChecked,
    /// Read, and only Administrators and SYSTEM may use the key.
    AdminsOnly,
    /// Read, and a principal other than Administrators or SYSTEM may use it.
    Wider,
    /// Not readable, or not exposed by the provider. Refused: fail closed.
    Unreadable,
}

/// Modulus asked for first.
///
/// Kept as the preference, not as a requirement — see [`MIN_RSA_BITS`].
pub const PREFERRED_RSA_BITS: u32 = 3072;

/// Smallest modulus accepted. Below it, refuse.
///
/// # Pourquoi 2048 et non 3072 (amendement du 2 août 2026)
///
/// La décision initiale posait 3072 en plancher et refusait tout TPM qui ne le
/// portait pas. Le matériel a tranché autrement : le *TPM 2.0 PC Client
/// Profile* n'impose que **RSA-2048**, et 3072 y est facultatif — donc absent
/// de la quasi-totalité des puces. `NCryptSetProperty(NCRYPT_LENGTH_PROPERTY)`
/// y répond `NTE_INVALID_PARAMETER` (0x80090027), la création échoue, et Orion
/// refuse alors de conserver le moindre secret. Un plancher que le matériel
/// courant ne franchit pas ne protège rien : il supprime la fonctionnalité.
///
/// Ce que cette clé garantit est la **non-exportabilité** — un coffre copié sur
/// une autre machine y reste illisible — et cette propriété ne dépend pas du
/// module. Elle enveloppe 32 octets ; contre RSA-2048, un adversaire a des
/// chemins bien moins coûteux que la factorisation.
///
/// [`PREFERRED_RSA_BITS`] reste demandé en premier et obtenu quand le TPM le
/// porte. Le repli est **annoncé**, jamais silencieux : c'est la différence que
/// l'ADR-006 exige entre dégrader et se taire.
pub const MIN_RSA_BITS: u32 = 2048;

/// What the key's security descriptor says about its owner — **observed, not
/// enforced**.
///
/// # Why this stopped being a gate (amendement du 2 août 2026)
///
/// It was written as the fourth check of ADR-006 §3, comparing the descriptor's
/// owner SID to the process token's user SID and refusing on a mismatch. On
/// real hardware that refused every key, and the reason is that the premise was
/// wrong: on Windows the **owner** of a security descriptor is not the list of
/// principals allowed to use the object. CNG keys are routinely owned by
/// `SYSTEM` or by `Administrators` while the DACL grants the user their access
/// — exactly as a file in your own profile can be owned by Administrators and
/// still be yours to open. A mismatch therefore says nothing, and refusing on
/// it blocked a working TPM.
///
/// The binding to the account does not depend on the owner. A machine key is
/// created with a DACL that admits Administrators and SYSTEM alone, and that
/// DACL is **read back and enforced** — see [`KeyAccess`]. The owner is kept
/// for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum KeyOwnership {
    /// The descriptor's owner is the account running this process.
    CurrentUser,
    /// The descriptor names another principal — commonly `SYSTEM` or
    /// `Administrators`, which is the ordinary shape of a CNG key and says
    /// nothing about who may use it. Recorded, not refused.
    AnotherPrincipal,
    /// The provider does not expose a security descriptor at all
    /// (`NTE_NOT_SUPPORTED`).
    NotExposed,
    /// The descriptor exists but could not be read, or the process token could
    /// not be obtained.
    Unverifiable,
}

/// Checks the security properties independently of the Win32 property reader.
///
/// Keeping the decision pure lets every refusal branch run on every host,
/// while the Windows suite separately exercises the CNG calls that obtain the
/// values.
#[cfg(any(windows, test))]
fn validate_key_properties(
    hardware_backed: bool,
    export_allowed: bool,
    bits: u32,
    ownership: KeyOwnership,
    access: KeyAccess,
) -> Result<(), VaultError> {
    if !hardware_backed {
        return Err(VaultError::Tpm(
            "the provider answered but the key is not hardware-backed".into(),
        ));
    }
    if export_allowed {
        return Err(VaultError::Tpm(
            "the key is exportable — the machine binding it exists for would not hold".into(),
        ));
    }
    if bits < MIN_RSA_BITS {
        return Err(VaultError::Tpm(format!(
            "modulus of {bits} bits below the {MIN_RSA_BITS} floor — refused rather than lowered"
        )));
    }
    match access {
        KeyAccess::NotChecked | KeyAccess::AdminsOnly => {}
        KeyAccess::Wider => {
            return Err(VaultError::Tpm(
                "the machine key admits a non-administrator account — refused".into(),
            ))
        }
        KeyAccess::Unreadable => {
            return Err(VaultError::Tpm(
                "the machine key's access list cannot be read — refused".into(),
            ))
        }
    }
    // Observed, never refused — see `KeyOwnership`. The owner of a descriptor is
    // not the list of principals allowed to use the key. The message is only
    // true of the user scope, the one `NotChecked` stands for: there the
    // container is the binding. A checked machine key is bound by its DACL.
    if access == KeyAccess::NotChecked && ownership != KeyOwnership::CurrentUser {
        tracing::info!(
            ?ownership,
            "propriétaire du descripteur de la clé TPM non concluant ; la liaison au compte \
             tient au conteneur utilisateur dans lequel la clé est ouverte"
        );
    }
    Ok(())
}

#[cfg(windows)]
pub use imp::{delete_key, unwrap_root, wrap_root};

#[cfg(windows)]
mod imp {
    // Glob rather than a named list, deliberately. This module only compiles on
    // Windows, and the workstation that builds it is not the one that edits it:
    // an item added above and forgotten here fails on the target, minutes into a
    // build, with an error nobody on Linux ever sees — `PREFERRED_RSA_BITS` did
    // exactly that. The parent module is small, private and entirely dedicated
    // to this one, so the usual argument against a glob does not apply.
    use super::*;
    use crate::protected_root::{
        access_of, admits_only_admins, LocalBlock, ADMINISTRATORS, SYSTEM,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, NTE_BAD_KEYSET, NTE_NOT_SUPPORTED, NTE_NO_KEY,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG,
        NCRYPT_PAD_OAEP_FLAG, NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SILENT_FLAG,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorOwner, GetTokenInformation, TokenUser,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Owner Administrators; a protected DACL with full control for
    /// Administrators and SYSTEM and nobody else. Keys do not inherit, so no
    /// container flags are needed.
    const MACHINE_KEY_SDDL: &str = "O:BAD:P(A;;GA;;;BA)(A;;GA;;;SY)";

    /// Frees an `NCRYPT_*` handle on every exit path, including a `?`.
    struct Handle(usize);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { NCryptFreeObject(self.0 as NCRYPT_HANDLE) };
            }
        }
    }

    /// Only the key **name** needs converting: every `NCRYPT_*` and
    /// `BCRYPT_*` property constant is already a `PCWSTR` in `windows-sys`.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn fail(step: &str, status: i32) -> VaultError {
        VaultError::Tpm(format!("{step} failed with NTSTATUS {status:#010x}"))
    }

    fn open_provider() -> Result<Handle, VaultError> {
        let mut provider = 0usize;
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        if status != 0 {
            // No platform provider at all: this machine has no usable TPM, and
            // that is a refusal, not a reason to fall back.
            return Err(VaultError::NoHardwareRoot);
        }
        Ok(Handle(provider))
    }

    /// Reads a `DWORD` property, or `None` when the provider does not expose it.
    ///
    /// `NTE_NOT_SUPPORTED` means the provider has no opinion on this property —
    /// the question does not apply here, which is not the same as the answer
    /// being bad.
    fn read_u32(
        handle: usize,
        property: windows_sys::core::PCWSTR,
        what: &str,
    ) -> Result<Option<u32>, VaultError> {
        let mut value = 0u32;
        let mut written = 0u32;
        let status = unsafe {
            NCryptGetProperty(
                handle as NCRYPT_HANDLE,
                property,
                (&raw mut value).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut written,
                0,
            )
        };
        match status {
            0 => Ok(Some(value)),
            NTE_NOT_SUPPORTED => Ok(None),
            _ => Err(fail(&format!("reading {what}"), status)),
        }
    }

    /// The four checks ADR-006 §3 demands.
    ///
    /// # Which handle answers which question
    ///
    /// `NCRYPT_IMPL_TYPE_PROPERTY` is a **provider** property, not a key one.
    /// Reading it from the key handle — as this did — makes the Platform Crypto
    /// Provider answer `NTE_NOT_SUPPORTED` (0x80090029), and the whole vault
    /// refused to open on hardware that was working perfectly. Export policy
    /// and modulus, by contrast, genuinely belong to the key.
    ///
    /// # Absent is not wrong
    ///
    /// A provider that does not expose a property is telling us the question
    /// does not apply, which is not the same as answering badly. For the
    /// implementation type the fallback is sound and narrow: reaching this
    /// point means `MS_PLATFORM_CRYPTO_PROVIDER` opened, and that provider is
    /// TPM-backed by definition — there is no software mode of it to fall into.
    /// A property that *is* readable and wrong still refuses, which is the case
    /// the check exists for.
    fn verify(provider: usize, key: usize, scope: &KeyScope) -> Result<(), VaultError> {
        let implementation = read_u32(provider, NCRYPT_IMPL_TYPE_PROPERTY, "the provider type")?;
        let export = read_u32(key, NCRYPT_EXPORT_POLICY_PROPERTY, "the export policy")?;
        let bits = read_u32(key, NCRYPT_LENGTH_PROPERTY, "the modulus length")?;

        let hardware_backed = match implementation {
            Some(value) => value & NCRYPT_IMPL_HARDWARE_FLAG != 0,
            None => {
                tracing::info!(
                    "le fournisseur n'expose pas son type d'implémentation ; \
                     MS_PLATFORM_CRYPTO_PROVIDER est adossé au TPM par construction"
                );
                true
            }
        };
        let export_allowed = match export {
            Some(value) => value & NCRYPT_ALLOW_EXPORT_FLAG != 0,
            // The policy was set to "no export" before finalisation, and after
            // finalisation it is immutable. A provider that will not read it
            // back cannot have changed it either.
            None => false,
        };
        let bits = match bits {
            Some(bits) => bits,
            // Unreadable length: take the floor rather than refuse. The modulus
            // was chosen by `create_at`, and an existing key that opens at all
            // came from this same code.
            None => MIN_RSA_BITS,
        };

        let ownership = ownership_of(key);
        let access = if access_is_checked(scope) {
            access_of_key(key)
        } else {
            KeyAccess::NotChecked
        };
        // The four answers, as the provider actually gave them. Three failed
        // starts were spent guessing which one was refusing.
        tracing::info!(
            portee = scope.label(),
            materiel = hardware_backed,
            exportable = export_allowed,
            module = bits,
            ?ownership,
            acces = ?access,
            "propriétés de la clé TPM"
        );
        validate_key_properties(hardware_backed, export_allowed, bits, ownership, access)
    }

    /// SID of the account this process runs as, owned for the call's duration.
    ///
    /// The buffer is variable-length — a `SID` grows with its sub-authorities —
    /// so `GetTokenInformation` is called twice: once for the size, once for
    /// the value. The `PSID` inside points **into** the returned buffer, which
    /// is why the buffer is handed back with it rather than dropped.
    fn current_user_sid() -> Option<(Vec<u8>, PSID)> {
        struct Token(HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        let mut raw: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close;
        // `raw` is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return None;
        }
        let token = Token(raw);

        let mut needed = 0u32;
        // First call sizes the buffer; it is expected to fail with
        // ERROR_INSUFFICIENT_BUFFER, so only `needed` is trusted here.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return None;
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is exactly the size the call just asked for.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: on success the buffer starts with a `TOKEN_USER`, whose
        // `User.Sid` points inside that same buffer.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if sid.is_null() {
            return None;
        }
        Some((buffer, sid))
    }

    /// Reads the key's owner and compares it to the current account.
    ///
    /// Every failure collapses into [`KeyOwnership::Unverifiable`], which
    /// `validate_key_properties` refuses: distinguishing "no descriptor" from
    /// "unreadable token" would change the log and not the decision, and a
    /// branch that answered `CurrentUser` on a technicality would cost the
    /// whole check.
    fn ownership_of(key: usize) -> KeyOwnership {
        let mut needed = 0u32;
        // Sizing pass. The descriptor is variable-length like the SID above.
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                std::ptr::null_mut(),
                0,
                &mut needed,
                OWNER_SECURITY_INFORMATION,
            )
        };
        // The Platform Crypto Provider commonly declines this property
        // outright. That is "no such question here", not a failed answer — see
        // `KeyOwnership::NotExposed`.
        if status == NTE_NOT_SUPPORTED {
            return KeyOwnership::NotExposed;
        }
        if status != 0 || needed == 0 {
            return KeyOwnership::Unverifiable;
        }
        // Eight-byte units, for the same alignment reason as `access_of_key`.
        let mut descriptor = vec![0u64; (needed as usize).div_ceil(8)];
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
                OWNER_SECURITY_INFORMATION,
            )
        };
        if status != 0 {
            return KeyOwnership::Unverifiable;
        }

        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0i32;
        // SAFETY: `descriptor` holds a self-relative security descriptor the
        // provider just wrote; `owner` points into it on success.
        let ok = unsafe {
            GetSecurityDescriptorOwner(
                descriptor.as_ptr() as PSECURITY_DESCRIPTOR,
                &mut owner,
                &mut defaulted,
            )
        };
        if ok == 0 || owner.is_null() {
            return KeyOwnership::Unverifiable;
        }

        let Some((_token_buffer, ours)) = current_user_sid() else {
            return KeyOwnership::Unverifiable;
        };
        // SAFETY: both SIDs are valid for the duration of this scope —
        // `owner` inside `descriptor`, `ours` inside `_token_buffer`.
        if unsafe { EqualSid(owner, ours) } != 0 {
            KeyOwnership::CurrentUser
        } else {
            KeyOwnership::AnotherPrincipal
        }
    }

    /// The flag that selects the machine container, or none for the user's.
    fn container_flag(scope: &KeyScope) -> u32 {
        match scope {
            KeyScope::User => 0,
            KeyScope::Machine(_) => NCRYPT_MACHINE_KEY_FLAG,
        }
    }

    /// The key's access list, read back and judged.
    ///
    /// Every failure is [`KeyAccess::Unreadable`], including a null DACL: a list
    /// that cannot be read is not a list that admits only administrators.
    fn access_of_key(key: usize) -> KeyAccess {
        let flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut needed = 0u32;
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                std::ptr::null_mut(),
                0,
                &mut needed,
                flags,
            )
        };
        if status != 0 || needed == 0 {
            tracing::warn!(
                status = format_args!("{status:#010x}"),
                needed,
                "lecture de la taille du descripteur de la clé TPM refusée"
            );
            return KeyAccess::Unreadable;
        }
        // Eight-byte units: the entries are read through `ACE_HEADER` and the
        // SID pointers, which a byte buffer does not align.
        let mut descriptor = vec![0u64; (needed as usize).div_ceil(8)];
        let status = unsafe {
            NCryptGetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
                flags,
            )
        };
        if status != 0 {
            tracing::warn!(
                status = format_args!("{status:#010x}"),
                "lecture du descripteur de la clé TPM refusée"
            );
            return KeyAccess::Unreadable;
        }
        // SAFETY: `descriptor` holds the self-relative descriptor the provider
        // just wrote, and it outlives the call.
        match unsafe { access_of(descriptor.as_mut_ptr().cast()) } {
            Ok((owner, aces, protected)) if admits_only_admins(&owner, &aces, protected) => {
                KeyAccess::AdminsOnly
            }
            Ok((owner, aces, protected)) => {
                // Counts only: the SIDs of other accounts are not written down.
                let other_allowed = aces
                    .iter()
                    .filter(|ace| ace.allow && ace.sid != ADMINISTRATORS && ace.sid != SYSTEM)
                    .count();
                tracing::warn!(
                    owner = %owner,
                    protected,
                    entrees = aces.len(),
                    autorisations_hors_administrateurs = other_allowed,
                    "descripteur de la clé TPM : accès hors administrateurs"
                );
                KeyAccess::Wider
            }
            Err(error) => {
                tracing::warn!(?error, "descripteur de la clé TPM illisible");
                KeyAccess::Unreadable
            }
        }
    }

    /// Restricts a machine key to Administrators and SYSTEM.
    ///
    /// Called before finalisation: the access list is then part of the key
    /// from its first use, and never a window in which it is open.
    fn restrict(key: usize) -> Result<(), VaultError> {
        let sddl = wide(MACHINE_KEY_SDDL);
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut size = 0u32;
        // SAFETY: `sddl` is NUL-terminated and alive for the call; the out-pointers
        // are valid. The descriptor they return is freed by `LocalBlock` below.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        };
        let _descriptor = LocalBlock(descriptor);
        if converted == 0 {
            return Err(VaultError::Tpm(format!(
                "restricting the machine key failed: its descriptor cannot be built ({})",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: on success `descriptor` is self-relative and `size` is its
        // length, both as the call reported them.
        let status = unsafe {
            NCryptSetProperty(
                key as NCRYPT_HANDLE,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.cast::<u8>().cast_const(),
                size,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            )
        };
        if status != 0 {
            return Err(fail("restricting the machine key", status));
        }
        Ok(())
    }

    /// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`: the key file of a persisted
    /// key that was never created.
    const KEY_FILE_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

    fn open_existing(scope: &KeyScope) -> Result<Option<(Handle, Handle)>, VaultError> {
        let provider = open_provider()?;
        let mut key = 0usize;
        let name = wide(&scope.key_name());
        let status = unsafe {
            NCryptOpenKey(
                provider.0,
                &mut key,
                name.as_ptr(),
                0,
                container_flag(scope) | NCRYPT_SILENT_FLAG,
            )
        };
        // Only "no such key" means absent. Any other status (an access refusal
        // among them) is an error: reading it as absence would send `create` to
        // overwrite a key that is there, and report a lost key to the person.
        // Providers spell "no such key" three ways; all three mean absent.
        if [NTE_BAD_KEYSET, NTE_NO_KEY, KEY_FILE_NOT_FOUND].contains(&status) {
            return Ok(None);
        }
        if status != 0 {
            return Err(fail("opening the TPM key", status));
        }
        let key = Handle(key);
        verify(provider.0, key.0, scope)?;
        Ok(Some((provider, key)))
    }

    /// Creates the persisted key, at the largest modulus this TPM accepts.
    ///
    /// Tries [`PREFERRED_RSA_BITS`] then [`MIN_RSA_BITS`]. Most TPM 2.0 chips
    /// implement only the mandatory RSA-2048 and answer `NTE_INVALID_PARAMETER`
    /// to anything larger — refusing outright, as the first version did, made
    /// Orion unusable on ordinary hardware.
    ///
    /// The fallback is announced. A degradation nobody is told about is the one
    /// failure mode ADR-006 refuses everywhere else.
    fn create(scope: &KeyScope) -> Result<(Handle, Handle), VaultError> {
        let mut last = None;
        for bits in [PREFERRED_RSA_BITS, MIN_RSA_BITS] {
            match create_at(scope, bits) {
                Ok(handles) => {
                    if bits < PREFERRED_RSA_BITS {
                        tracing::warn!(
                            bits,
                            preferred = PREFERRED_RSA_BITS,
                            "TPM sans RSA-{PREFERRED_RSA_BITS} : clé d'enveloppe créée en \
                             RSA-{bits}. La liaison matérielle et la non-exportabilité sont \
                             conservées ; c'est le module qui est plus court."
                        );
                    }
                    return Ok(handles);
                }
                // Only a refusal of the *size* is worth retrying smaller. A
                // provider that is absent, or a key we do not own, would fail
                // identically at every size — retrying would just hide it
                // behind a second, less precise error.
                Err(error) if retryable_at_a_smaller_modulus(&error) => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| VaultError::Tpm("no RSA modulus accepted by this TPM".into())))
    }

    /// `true` when the failure plausibly comes from the requested modulus.
    fn retryable_at_a_smaller_modulus(error: &VaultError) -> bool {
        matches!(error, VaultError::Tpm(message) if message.contains("modulus length")
            || message.contains("finalising"))
    }

    fn create_at(scope: &KeyScope, bits: u32) -> Result<(Handle, Handle), VaultError> {
        let provider = open_provider()?;
        let mut key = 0usize;
        let name = wide(&scope.key_name());
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                name.as_ptr(),
                0,
                container_flag(scope) | NCRYPT_OVERWRITE_KEY_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("creating the TPM key", status));
        }
        let key = Handle(key);

        // Length and export policy are set **before** finalisation: after it,
        // they are immutable, which is precisely the property we want.
        let status = unsafe {
            NCryptSetProperty(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_LENGTH_PROPERTY,
                (&raw const bits).cast(),
                std::mem::size_of::<u32>() as u32,
                0,
            )
        };
        if status != 0 {
            return Err(fail("setting the modulus length", status));
        }

        let no_export = 0u32;
        let status = unsafe {
            NCryptSetProperty(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                (&raw const no_export).cast(),
                std::mem::size_of::<u32>() as u32,
                0,
            )
        };
        if status != 0 {
            return Err(fail("forbidding export", status));
        }

        if let KeyScope::Machine(_) = scope {
            restrict(key.0)?;
        }

        let status = unsafe { NCryptFinalizeKey(key.0, 0) };
        if status != 0 {
            return Err(fail("finalising the TPM key", status));
        }
        verify(provider.0, key.0, scope)?;
        Ok((provider, key))
    }

    fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        }
    }

    /// Wraps the installation root under the TPM key, creating it on first use.
    pub fn wrap_root(scope: &KeyScope, root: &[u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
        let (_provider, key) = match open_existing(scope)? {
            Some(handles) => handles,
            None => create(scope)?,
        };
        let padding = oaep();

        let mut needed = 0u32;
        let status = unsafe {
            NCryptEncrypt(
                key.0,
                root.as_ptr(),
                root.len() as u32,
                (&raw const padding).cast(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("sizing the TPM wrap", status));
        }
        let mut wrapped = vec![0u8; needed as usize];
        let mut written = 0u32;
        let status = unsafe {
            NCryptEncrypt(
                key.0,
                root.as_ptr(),
                root.len() as u32,
                (&raw const padding).cast(),
                wrapped.as_mut_ptr(),
                wrapped.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(fail("wrapping under the TPM key", status));
        }
        wrapped.truncate(written as usize);
        Ok(wrapped)
    }

    /// Unwraps the installation root. Absence of the key is fatal: there is no
    /// second envelope to fall back on, by design.
    pub fn unwrap_root(
        scope: &KeyScope,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let Some((_provider, key)) = open_existing(scope)? else {
            return Err(VaultError::TpmKeyLost);
        };
        let padding = oaep();

        let mut needed = 0u32;
        let status = unsafe {
            NCryptDecrypt(
                key.0,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                (&raw const padding).cast(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(VaultError::TpmKeyLost);
        }
        let mut plaintext = Zeroizing::new(vec![0u8; needed as usize]);
        let mut written = 0u32;
        let status = unsafe {
            NCryptDecrypt(
                key.0,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                (&raw const padding).cast(),
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(VaultError::TpmKeyLost);
        }
        if written as usize != KEY_LEN {
            return Err(VaultError::Tpm(format!(
                "unwrapped {written} bytes where {KEY_LEN} were expected"
            )));
        }
        let mut root = Zeroizing::new([0u8; KEY_LEN]);
        root.copy_from_slice(&plaintext[..KEY_LEN]);
        Ok(root)
    }

    /// Deletes the persisted key of `scope`. An absent key is success: the
    /// migration removes the per-user key once, whether or not it was ever
    /// created on this machine.
    pub fn delete_key(scope: &KeyScope) -> Result<(), VaultError> {
        let provider = open_provider()?;
        let mut key = 0usize;
        let name = wide(&scope.key_name());
        let status = unsafe {
            NCryptOpenKey(
                provider.0,
                &mut key,
                name.as_ptr(),
                0,
                container_flag(scope) | NCRYPT_SILENT_FLAG,
            )
        };
        if [NTE_BAD_KEYSET, NTE_NO_KEY, KEY_FILE_NOT_FOUND].contains(&status) {
            return Ok(());
        }
        if status != 0 {
            return Err(fail("opening the TPM key to delete it", status));
        }
        // No `Handle` guard here: NCryptDeleteKey releases the key handle
        // whatever its outcome, so freeing it again would be a double free.
        let status = unsafe { NCryptDeleteKey(key as NCRYPT_HANDLE, NCRYPT_SILENT_FLAG) };
        if status != 0 {
            return Err(fail("deleting the TPM key", status));
        }
        Ok(())
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER_USER: &str = "S-1-5-21-1-2-3-1002";

    #[test]
    fn machine_key_slots_are_per_user_sid() {
        assert_eq!(
            machine_key_slot(USER),
            "Helios Orion device root v2 S-1-5-21-1-2-3-1001"
        );
        assert_ne!(machine_key_slot(USER), machine_key_slot(OTHER_USER));
    }

    #[test]
    fn a_machine_slot_never_equals_the_user_slot() {
        let machine = KeyScope::Machine(USER.to_string());
        assert_eq!(KeyScope::User.key_name(), KEY_NAME);
        assert_eq!(machine.key_name(), machine_key_slot(USER));
        assert_ne!(machine.key_name(), KEY_NAME);
        assert_ne!(machine.key_name(), KeyScope::User.key_name());
    }

    #[test]
    fn a_machine_key_open_to_users_is_refused() {
        let ours = KeyOwnership::CurrentUser;
        let wider =
            validate_key_properties(true, false, MIN_RSA_BITS, ours, KeyAccess::Wider).unwrap_err();
        assert!(matches!(wider, VaultError::Tpm(message) if message.contains("non-administrator")));
        assert!(
            validate_key_properties(true, false, MIN_RSA_BITS, ours, KeyAccess::AdminsOnly).is_ok()
        );
    }

    #[test]
    fn an_unreadable_machine_key_acl_is_refused() {
        let ours = KeyOwnership::CurrentUser;
        let unreadable =
            validate_key_properties(true, false, MIN_RSA_BITS, ours, KeyAccess::Unreadable)
                .unwrap_err();
        assert!(
            matches!(unreadable, VaultError::Tpm(message) if message.contains("cannot be read"))
        );
    }

    #[test]
    fn a_known_user_sid_selects_the_machine_scope() {
        assert_eq!(
            key_scope_for(Some(USER)),
            KeyScope::Machine(USER.to_string())
        );
        assert_eq!(key_scope_for(None), KeyScope::User);
    }

    #[test]
    fn a_machine_key_is_always_acl_checked() {
        assert!(access_is_checked(&KeyScope::Machine(USER.to_string())));
        assert!(!access_is_checked(&KeyScope::User));
    }

    #[test]
    fn a_user_scope_key_is_not_acl_checked() {
        let ours = KeyOwnership::CurrentUser;
        assert!(
            validate_key_properties(true, false, MIN_RSA_BITS, ours, KeyAccess::NotChecked).is_ok()
        );
    }

    #[test]
    fn only_hardware_non_exportable_keys_at_the_rsa_floor_are_accepted() {
        let ours = KeyOwnership::CurrentUser;
        let check = KeyAccess::NotChecked;
        assert!(validate_key_properties(true, false, MIN_RSA_BITS, ours, check).is_ok());
        assert!(validate_key_properties(true, false, MIN_RSA_BITS + 1024, ours, check).is_ok());

        let software =
            validate_key_properties(false, false, MIN_RSA_BITS, ours, check).unwrap_err();
        assert!(
            matches!(software, VaultError::Tpm(message) if message.contains("not hardware-backed"))
        );

        let exportable =
            validate_key_properties(true, true, MIN_RSA_BITS, ours, check).unwrap_err();
        assert!(matches!(exportable, VaultError::Tpm(message) if message.contains("exportable")));

        let weak = validate_key_properties(true, false, MIN_RSA_BITS - 1, ours, check).unwrap_err();
        assert!(matches!(weak, VaultError::Tpm(message) if message.contains("below")));
    }

    /// The descriptor's owner is **recorded, never enforced**.
    ///
    /// This used to refuse on a mismatch, and refused every key on real
    /// hardware. The premise was wrong: on Windows the owner of a security
    /// descriptor is not the set of principals allowed to use the object. CNG
    /// keys are commonly owned by `SYSTEM` or `Administrators` while the DACL
    /// grants the user their access — so a mismatch carries no information,
    /// and gating on it only broke working machines.
    ///
    /// What binds the key to the account is the per-user container it is
    /// opened from, which no descriptor can contradict. The four outcomes must
    /// therefore all pass, and the type keeps them distinct only so the log can
    /// say which one was seen.
    #[test]
    fn the_descriptor_owner_is_observed_and_never_blocks() {
        let sound = |ownership| {
            validate_key_properties(true, false, MIN_RSA_BITS, ownership, KeyAccess::NotChecked)
        };

        for ownership in [
            KeyOwnership::CurrentUser,
            KeyOwnership::AnotherPrincipal,
            KeyOwnership::NotExposed,
            KeyOwnership::Unverifiable,
        ] {
            assert!(
                sound(ownership).is_ok(),
                "le propriétaire du descripteur ne doit plus bloquer le coffre : {ownership:?}"
            );
        }

        // The cases stay distinguishable: they mean different things, and the
        // day a real DACL walk lands it will need them apart.
        assert_ne!(KeyOwnership::NotExposed, KeyOwnership::Unverifiable);
        assert_ne!(KeyOwnership::CurrentUser, KeyOwnership::AnotherPrincipal);
    }

    /// The properties that *do* gate are unaffected.
    #[test]
    fn the_real_gates_still_refuse() {
        let ours = KeyOwnership::CurrentUser;
        let check = KeyAccess::NotChecked;
        assert!(validate_key_properties(false, false, MIN_RSA_BITS, ours, check).is_err());
        assert!(validate_key_properties(true, true, MIN_RSA_BITS, ours, check).is_err());
        assert!(validate_key_properties(true, false, MIN_RSA_BITS - 1, ours, check).is_err());
    }
}

#[cfg(not(windows))]
pub fn wrap_root(_scope: &KeyScope, _root: &[u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
    Err(VaultError::NoHardwareRoot)
}

#[cfg(not(windows))]
pub fn unwrap_root(
    _scope: &KeyScope,
    _wrapped: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    Err(VaultError::NoHardwareRoot)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn without_a_platform_provider_both_directions_refuse() {
        for scope in [KeyScope::User, KeyScope::Machine(String::new())] {
            assert!(matches!(
                wrap_root(&scope, &[0u8; KEY_LEN]),
                Err(VaultError::NoHardwareRoot)
            ));
            assert!(matches!(
                unwrap_root(&scope, b"wrapped"),
                Err(VaultError::NoHardwareRoot)
            ));
        }
    }
}
