//! The vault gestures of Orion's operator ceremony, by path and by opening.
//!
//! [`crate::gestures`] works on a vault in memory and asks a key for whatever
//! it needs. The ceremony works differently: it plugs one key at a time,
//! between two presses, and holds the opening each press produced. So every
//! gesture here takes the vault's **path** — it reads and writes the vault,
//! the relay and the credential document beside it — and the **opening** the
//! ceremony already holds, and asks a key for nothing more than the gesture
//! itself requires. A gesture that quietly asked for another assertion would
//! be a press nobody announced.
//!
//! The sequences are those of `astra-signer` (`init`, `enrol`, `remove`,
//! `bindings`, `rename`), without the terminal.
//!
//! # Checks, then gestures
//!
//! Each gesture has a `check_*` that refuses what is predictable before a key
//! is asked anything, as a [`SetupRefusal`] the ceremony names to the operator.
//! The gesture runs its check again (fail closed: the interface disabling a
//! button is not a guarantee), and the refusal then travels inside the
//! `anyhow::Error`, recoverable by `downcast_ref::<SetupRefusal>()`.
//!
//! Every [`Opened`] handled here is secret: none is logged, serialized nor
//! shown.

use std::path::Path;

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::MlDsa87PublicKey;
use anyhow::{bail, Result};

use crate::authenticator::{Authenticator, Opened};
use crate::gestures::{self, AddedKey, NewAuthority, NewKey};
use crate::vault::{AuthorityVault, KeySlot, MAX_SLOTS, REQUIRED_SLOTS};
use crate::{credentials, handoff, signing, store};

/// What a vault gesture refuses before any key is asked anything.
///
/// Closed, so the ceremony maps each variant to a refusal of its own and no
/// text crosses that boundary; the sentence below is for logs and the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupRefusal {
    #[error("un coffre d'autorité existe déjà à cet emplacement et n'est jamais remplacé")]
    VaultExists,
    #[error("le dossier prévu pour le coffre d'autorité n'existe pas ou n'est pas accessible")]
    LocationUnavailable,
    #[error("le coffre est plafonné à {MAX_SLOTS} clés : en retirer une avant d'en ajouter une")]
    VaultFull,
    #[error(
        "l'autorité exige au moins {REQUIRED_SLOTS} clés : en ajouter une avant d'en retirer une"
    )]
    MinimumKeys,
    #[error("aucune clé de ce coffre ne porte cet identifiant")]
    UnknownSlot,
    #[error(
        "la clé qui ouvre le coffre ne peut pas se retirer elle-même : brancher une autre clé"
    )]
    KeyBeingRemoved,
    #[error("le relais de domaine ne porte pas encore la clé WireGuard et le nom de la gateway")]
    GatewayIdentityMissing,
    #[error("le domaine est complet : il ne reste rien à finaliser")]
    DomainComplete,
}

// --- Keys -------------------------------------------------------------------

/// Whether a vault may be created at `vault_path`.
///
/// Anything already at that path is a vault that would be destroyed — the only
/// object that opens its anchors — so it is refused whatever it is. The folder
/// must already exist: the operator chose it, and creating one silently would
/// hide a mistyped choice.
pub fn check_creation(vault_path: &Path) -> std::result::Result<(), SetupRefusal> {
    match std::fs::symlink_metadata(vault_path) {
        Ok(_) => return Err(SetupRefusal::VaultExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(SetupRefusal::LocationUnavailable),
    }
    let folder = match vault_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    match std::fs::metadata(folder) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        _ => Err(SetupRefusal::LocationUnavailable),
    }
}

/// Creates the vault around fresh anchors, registers the first key, and
/// writes the relay beside it — `astra-signer init`, plus the authority
/// origin.
///
/// One assertion on `key`. Its opening is returned so the ceremony registers
/// the second key without pressing this one again.
pub fn create_first_key(
    vault_path: &Path,
    request: &NewAuthority,
    authority_url: &str,
    key: &dyn Authenticator,
    pin: &str,
    now_unix: u64,
) -> Result<Opened> {
    check_creation(vault_path)?;
    // Refused before the key is asked anything: an origin found invalid after
    // the vault exists would leave a domain whose relay names nothing.
    let authority_url = authority_origin(authority_url)?;

    let created = gestures::create_authority(key, request, pin, now_unix)?;
    // Built before the vault is written, so a relay that cannot be derived
    // leaves no one-key vault behind it.
    let mut relay = handoff::DomainHandoff::of(&created.vault)?;
    relay.astra_authority_url = Some(authority_url);
    store::save_new(vault_path, &created.vault)?;
    handoff::save(&handoff::path_beside(vault_path), &relay)?;
    Ok(created.opening)
}

/// Whether the vault has room for another key.
pub fn check_addition(vault: &AuthorityVault) -> std::result::Result<(), SetupRefusal> {
    if vault.slots.len() >= MAX_SLOTS {
        return Err(SetupRefusal::VaultFull);
    }
    Ok(())
}

/// Registers `key` with the master key `opening` released — `astra-signer
/// enrol`.
///
/// One assertion on `key`, none on the key behind `opening`: the vault is
/// saved, then the credential document is re-signed with `opening` when the
/// domain has one. The slots keep the master key and the salt, so an opening
/// obtained before the table moved still opens it after.
///
/// Whether a document follows, and whether the one in place verifies, is
/// settled before the new key is asked anything: once the vault is saved,
/// only a write or the signature itself can still fail.
pub fn add_key_with(
    vault_path: &Path,
    opening: &Opened,
    key: &dyn Authenticator,
    request: &NewKey,
    pin: &str,
    now_unix: u64,
) -> Result<AddedKey> {
    let mut vault = store::load(vault_path)?;
    check_addition(&vault)?;
    let document = pending_document(vault_path, &vault)?;
    let added = gestures::add_key_opened(key, &mut vault, opening, request, pin, now_unix)?;
    store::save(vault_path, &vault)?;
    if let Some(document) = document {
        document.resign(&vault, opening, &[], now_unix)?;
    }
    Ok(added)
}

/// Proves each opening reads the anchors, not merely a slot.
///
/// The trial ADR-008 §4 asks for before a bootstrap is final, run on the
/// openings the ceremony already holds — so it costs no press. The same key
/// presented twice is one key tried, and is refused as such.
pub fn prove_opens(vault_path: &Path, openings: &[&Opened]) -> Result<()> {
    if openings.is_empty() {
        bail!("aucune clé n'a été éprouvée");
    }
    gestures::require_distinct_credentials(openings.len(), openings)?;
    let vault = store::load(vault_path)?;
    for opening in openings {
        gestures::prove_anchors_open(&vault, opening)?;
    }
    Ok(())
}

/// Whether a key may be withdrawn, and which one it is.
pub fn check_removal<'v>(
    vault: &'v AuthorityVault,
    slot_id: &[u8; 16],
) -> std::result::Result<&'v KeySlot, SetupRefusal> {
    let slot = vault.slot(slot_id).map_err(|_| SetupRefusal::UnknownSlot)?;
    if vault.slots.len() <= REQUIRED_SLOTS {
        return Err(SetupRefusal::MinimumKeys);
    }
    Ok(slot)
}

/// Withdraws a key — `astra-signer remove`.
///
/// The key behind `opening` cannot be the one withdrawn: it would sign the
/// document that revokes itself, with nothing left to prove another key still
/// opens the vault. Nothing is written in that case, nor when the domain has
/// a document that can no longer be re-signed.
pub fn remove_key_with(
    vault_path: &Path,
    opening: &Opened,
    slot_id: &[u8; 16],
    now_unix: u64,
) -> Result<()> {
    let mut vault = store::load(vault_path)?;
    let removed = check_removal(&vault, slot_id)?.credential_id()?;
    if removed == opening.credential_id {
        return Err(SetupRefusal::KeyBeingRemoved.into());
    }
    gestures::remove_key(&mut vault, opening, slot_id)?;
    // The document first, as `astra-signer remove` does: a crash between the
    // two writes then leaves a credential revoked that the old vault still
    // holds (fail closed), never an absent slot still marked active.
    if let Some(document) = pending_document(vault_path, &vault)? {
        document.resign(&vault, opening, &[], now_unix)?;
    }
    store::save(vault_path, &vault)?;
    Ok(())
}

/// Whether a key's state may be signed, and which key it is.
///
/// The state lives in the credential document, which names the gateway: a
/// relay that cannot name it — absent, unreadable or incomplete — has no
/// document to sign.
pub fn check_marking<'v>(
    vault_path: &Path,
    vault: &'v AuthorityVault,
    slot_id: &[u8; 16],
) -> std::result::Result<&'v KeySlot, SetupRefusal> {
    let slot = vault.slot(slot_id).map_err(|_| SetupRefusal::UnknownSlot)?;
    let identity_known = handoff::DomainHandoff::beside(vault_path, vault)
        .is_ok_and(|relay| handoff::identity_of(&relay).is_ok());
    if !identity_known {
        return Err(SetupRefusal::GatewayIdentityMissing);
    }
    Ok(slot)
}

/// Signs a key as lost, or as active again — `astra-signer bindings --lost` /
/// `--active`.
///
/// Returns the epoch of the document written.
pub fn mark_key_with(
    vault_path: &Path,
    opening: &Opened,
    slot_id: &[u8; 16],
    lost: bool,
    now_unix: u64,
) -> Result<u64> {
    let vault = store::load(vault_path)?;
    let credential_id = check_marking(vault_path, &vault, slot_id)?.credential_id()?;
    let state = if lost {
        CredentialState::Lost
    } else {
        CredentialState::Active
    };
    // `check_marking` proved the identity, so a domain with no document yet
    // gets its first one here.
    let document =
        pending_document(vault_path, &vault)?.ok_or(SetupRefusal::GatewayIdentityMissing)?;
    document.resign(&vault, opening, &[(credential_id, state)], now_unix)
}

/// Renames a key. No key is asked anything: the label is outside the slot
/// digest, so the vault is not re-sealed.
pub fn rename_key(vault_path: &Path, slot_id: &[u8; 16], label: &str) -> Result<()> {
    let mut vault = store::load(vault_path)?;
    vault.slot(slot_id).map_err(|_| SetupRefusal::UnknownSlot)?;
    vault.rename_slot(slot_id, label)?;
    store::save(vault_path, &vault)
}

// --- Shared -----------------------------------------------------------------

/// The authority origin as the relay records it: `https://`, no trailing `/`.
fn authority_origin(value: &str) -> Result<String> {
    let value = value.trim();
    let origin = value.trim_end_matches('/');
    match origin.strip_prefix("https://") {
        Some(host) if !host.is_empty() => Ok(origin.to_string()),
        _ => bail!("l'origine de l'autorité doit être une URL https:// : {value}"),
    }
}

/// The credential document a gesture is about to re-sign, settled before it
/// writes anything.
///
/// Every gesture that moves the slot table, or a key's state, re-signs the
/// document in the same operation (spec §2.4): a document describing a slot
/// the vault no longer holds is a signed lie nothing downstream can catch.
struct PendingDocument {
    identity: signing::DomainIdentity,
    registry_path: std::path::PathBuf,
    previous: Option<credentials::CredentialRegistry>,
}

/// Whether the gesture re-signs a document, and what it builds on.
///
/// `None` only while the domain has no document **and** the relay does not
/// name the gateway yet — the bootstrap, where there is nothing to keep
/// current. A document already in place whose gateway the relay no longer
/// names is refused as [`SetupRefusal::GatewayIdentityMissing`] (fail closed):
/// carrying on would leave its rows describing a table that moved. The
/// document in place is verified under the vault's `CA-PQ` here, so it is not
/// found unreadable after the vault has moved.
fn pending_document(vault_path: &Path, vault: &AuthorityVault) -> Result<Option<PendingDocument>> {
    let relay = handoff::DomainHandoff::beside(vault_path, vault)?;
    let registry_path = credentials::path_beside(vault_path);
    let previous = credentials::load(&registry_path)?;
    let identity = match (handoff::identity_of(&relay), &previous) {
        (Ok(identity), _) => identity,
        (Err(_), None) => return Ok(None),
        (Err(_), Some(_)) => return Err(SetupRefusal::GatewayIdentityMissing.into()),
    };
    if let Some(previous) = &previous {
        previous.verify(
            &MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            previous.credential_registry_epoch,
        )?;
    }
    Ok(Some(PendingDocument {
        identity,
        registry_path,
        previous,
    }))
}

impl PendingDocument {
    /// Signs the document from `vault`'s slot table with the opening the
    /// gesture already holds, writes it, and returns its epoch.
    fn resign(
        self,
        vault: &AuthorityVault,
        opening: &Opened,
        overrides: &[(Vec<u8>, CredentialState)],
        now_unix: u64,
    ) -> Result<u64> {
        let registry = signing::sign_credential_bindings(
            vault,
            opening,
            &self.identity,
            self.previous.as_ref(),
            overrides,
            now_unix,
        )?;
        credentials::save(&self.registry_path, &registry)?;
        Ok(registry.credential_registry_epoch)
    }
}
