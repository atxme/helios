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
//! `bindings`, `rename`, `domain`, `issue-ca-tls`), without the terminal.
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
use aether::certificates::encoding::{
    validate_server_name, DerCertificate, MlDsa87PublicKey, WireGuardKey,
};
use aether::key_negotiation::{PqCertificate, PqCertificateRole};
use anyhow::{bail, Context, Result};

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
    #[error("le document de credentials révoque cette clé : son retrait est à terminer, pas son état à changer")]
    KeyRevoked,
    #[error("le relais de domaine ne porte pas encore la clé WireGuard et le nom de la gateway")]
    GatewayIdentityMissing,
    #[error("le domaine est complet : il ne reste rien à finaliser")]
    DomainComplete,
    #[error("le domaine nomme déjà une autre gateway ; en changer est une transition de gateway")]
    OtherGateway,
    #[error("ce fichier n'est pas une demande d'amorçage de gateway qui se vérifie")]
    BootstrapRequestInvalid,
    #[error("le document de credentials révoque cette clé : en présenter une autre")]
    SignerRevoked,
    #[error(
        "le domaine a changé depuis l'affichage de ce qui allait être signé : recommencer le geste"
    )]
    PlanChanged,
    #[error(
        "une rotation est en cours : la mener à son terme avant de changer les clés du coffre"
    )]
    RotationInFlight,
}

/// Refuses a change of key slots while a rotation journal is in flight.
///
/// The rotation applies the vault signed before it, over the one in place: a key
/// added, removed or marked in between would be undone, and a removed key would
/// regain access. By presence, as `ensure_none_in_flight` reads it, so a journal too
/// damaged to read refuses as well. Asked before any key, and again by each gesture
/// that writes, since the journal may have appeared during the touches.
pub fn ensure_no_rotation_in_flight(vault_path: &Path) -> std::result::Result<(), SetupRefusal> {
    crate::rotation_journal::ensure_none_in_flight(vault_path)
        .map_err(|_| SetupRefusal::RotationInFlight)
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
    ensure_no_rotation_in_flight(vault_path)?;
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

/// Opens the vault to withdraw `slot_id`, with any enrolled key but that one.
///
/// The allow-list leaves the withdrawn credential out, so the key being
/// removed is not asked for a PIN and a touch that [`remove_key_with`] would
/// then refuse. A key that answers for it anyway is refused as
/// [`SetupRefusal::KeyBeingRemoved`], and [`remove_key_with`] checks again.
pub fn open_for_removal(
    key: &dyn Authenticator,
    vault: &AuthorityVault,
    slot_id: &[u8; 16],
    pin: &str,
) -> Result<Opened> {
    let removed = check_removal(vault, slot_id)?.credential_id()?;
    let others: Vec<Vec<u8>> = vault
        .credential_ids()?
        .into_iter()
        .filter(|credential_id| *credential_id != removed)
        .collect();
    let opened = key.derive(&vault.rp_id, &others, &vault.salt()?, pin)?;
    if opened.credential_id == removed {
        return Err(SetupRefusal::KeyBeingRemoved.into());
    }
    vault.slot_for_credential(&opened.credential_id)?;
    Ok(opened)
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
    ensure_no_rotation_in_flight(vault_path)?;
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
/// document to sign. A key the verified document already revokes — a removal
/// interrupted after its document was written — is refused: marking it lost
/// or active would take back a revocation already signed.
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
    let revoked = verified_document(vault_path, vault)
        .zip(slot.credential_id().ok())
        .and_then(|(document, credential_id)| {
            document.binding(&credential_id).map(|row| row.state)
        })
        == Some(CredentialState::Revoked);
    if revoked {
        return Err(SetupRefusal::KeyRevoked);
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
    ensure_no_rotation_in_flight(vault_path)?;
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

// --- Domain -----------------------------------------------------------------

/// Values an operator records on the relay — `astra-signer domain`'s flags.
///
/// Each absent field leaves what the relay already records.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayUpdate {
    pub gateway_wg_public_key: Option<String>,
    pub server_name: Option<String>,
    pub astra_service_public_key: Option<String>,
    pub astra_service_key_epoch: Option<u64>,
    pub astra_authority_url: Option<String>,
}

/// Records values on the relay beside the vault — `astra-signer domain`.
///
/// The relay is read first and refreshed from the vault, so what was recorded
/// earlier stays. Every value is checked before anything is written: a key
/// that is not a key would be carried into every object signed afterwards.
///
/// The gateway's identity — its WireGuard key and its server name — is only
/// ever filled in: a relay that already records another value refuses the
/// change, because every document and leaf of the domain names that gateway,
/// and moving to another is a gateway transition, not an edit.
pub fn write_relay(vault_path: &Path, update: &RelayUpdate) -> Result<handoff::DomainHandoff> {
    let vault = store::load(vault_path)?;
    let mut relay = handoff::DomainHandoff::beside(vault_path, &vault)?;
    if let Some(value) = &update.gateway_wg_public_key {
        let key = WireGuardKey::parse(value).context("clé publique WireGuard de la gateway")?;
        if let Some(recorded) = relay.gateway_wg_public_key.as_deref() {
            if WireGuardKey::parse(recorded).ok() != Some(key) {
                return Err(GATEWAY_TRANSITION.into());
            }
        }
        // As `adopt_gateway`: a document already bound to another gateway
        // names the domain's gateway too, whatever the relay lost.
        if bound_to_another_gateway(vault_path, &key)? {
            return Err(GATEWAY_TRANSITION.into());
        }
        relay.gateway_wg_public_key = Some(value.trim().to_string());
    }
    if let Some(value) = &update.server_name {
        validate_server_name(value.trim()).context("nom de service de la gateway")?;
        if relay
            .server_name
            .as_deref()
            .is_some_and(|recorded| recorded != value.trim())
        {
            return Err(GATEWAY_TRANSITION.into());
        }
        relay.server_name = Some(value.trim().to_string());
    }
    if let Some(value) = &update.astra_service_public_key {
        MlDsa87PublicKey::parse(value.trim()).context("clé publique de service d'Astra")?;
        relay.astra_service_public_key = Some(value.trim().to_string());
    }
    if let Some(epoch) = update.astra_service_key_epoch {
        if epoch == 0 {
            bail!("l'époque de la clé de service Astra doit être non nulle");
        }
        relay.astra_service_key_epoch = Some(epoch);
    }
    if let Some(value) = &update.astra_authority_url {
        relay.astra_authority_url = Some(authority_origin(value)?);
    }
    handoff::save(&handoff::path_beside(vault_path), &relay)?;
    Ok(relay)
}

/// Moving a domain to another gateway is a gateway transition, never an edit
/// of its relay.
const GATEWAY_TRANSITION: SetupRefusal = SetupRefusal::OtherGateway;

/// Whether the credential document beside the vault, when there is one, is
/// bound to a gateway other than `gateway`.
pub(crate) fn bound_to_another_gateway(vault_path: &Path, gateway: &WireGuardKey) -> Result<bool> {
    Ok(credentials::load(&credentials::path_beside(vault_path))?
        .is_some_and(|document| document.gateway_wg_public_key != *gateway))
}

/// Records the gateway a leaf of this domain names: its server name and its
/// WireGuard key.
///
/// The leaf must verify under the domain's `CA-PQ` for exactly that identity,
/// so the relay only ever names a gateway the authority itself certified. A
/// relay that already names it is left as it is; one that names another, or a
/// document bound to another, is refused: moving a domain to another gateway
/// is a gateway transition, not an adoption.
pub fn adopt_gateway(
    vault_path: &Path,
    leaf: &PqCertificate,
    now_unix: u64,
) -> Result<handoff::DomainHandoff> {
    let vault = store::load(vault_path)?;
    let mut relay = handoff::DomainHandoff::beside(vault_path, &vault)?;
    let gateway = WireGuardKey::parse(&leaf.wireguard_public_key)
        .context("clé publique WireGuard de la feuille gateway")?;
    validate_server_name(&leaf.subject).context("nom de service de la feuille gateway")?;
    let ca_pq = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim())?;
    leaf.verify(
        ca_pq.as_bytes(),
        PqCertificateRole::Gateway,
        Some(&leaf.subject),
        &gateway.to_base64(),
        now_unix,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "la feuille de la gateway ne vérifie pas sous le CA-PQ du domaine : {error}"
        )
    })?;

    let recorded_gateway = relay
        .gateway_wg_public_key
        .as_deref()
        .map(WireGuardKey::parse)
        .transpose()?;
    let other_gateway = recorded_gateway.is_some_and(|recorded| recorded != gateway)
        || bound_to_another_gateway(vault_path, &gateway)?
        || relay
            .server_name
            .as_deref()
            .is_some_and(|recorded| recorded != leaf.subject);
    if other_gateway {
        return Err(GATEWAY_TRANSITION.into());
    }
    if recorded_gateway.is_some() && relay.server_name.is_some() {
        return Ok(relay);
    }
    relay.gateway_wg_public_key = Some(gateway.to_base64());
    relay.server_name = Some(leaf.subject.clone());
    handoff::save(&handoff::path_beside(vault_path), &relay)?;
    Ok(relay)
}

/// Lifetime of the `CA-TLS` a finalization self-signs, in days: the longest
/// [`signing::MAX_CA_TLS_LIFETIME_SECS`] allows.
pub const CA_TLS_DAYS: u64 = 3650;

pub(crate) const DAY_SECS: u64 = 86_400;

/// What finalizing the domain will issue, shown before the press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalization {
    pub server_name: String,
    pub gateway_wg_public_key: WireGuardKey,
    /// The relay carries no `CA-TLS` yet.
    pub issues_ca_tls: bool,
    /// No credential document verifies under `CA-PQ` with a row for every
    /// slot of the vault.
    pub issues_credentials: bool,
}

/// What finalizing the domain issues, or why there is nothing to.
///
/// The gateway's identity comes first: both objects name it. A document in
/// place that cannot be re-signed is refused here, as
/// [`check_document`] refuses it, rather than found so after the press —
/// and after a `CA-TLS` was already written.
pub fn finalization(vault_path: &Path) -> std::result::Result<Finalization, SetupRefusal> {
    let vault = store::load(vault_path).map_err(|_| SetupRefusal::LocationUnavailable)?;
    check_document_of(vault_path, &vault)?;
    let relay = handoff::DomainHandoff::beside(vault_path, &vault)
        .map_err(|_| SetupRefusal::GatewayIdentityMissing)?;
    let identity =
        handoff::identity_of(&relay).map_err(|_| SetupRefusal::GatewayIdentityMissing)?;
    let issues_ca_tls = relay.ca_tls_certificate.is_none();
    let issues_credentials = !verified_document(vault_path, &vault)
        .is_some_and(|document| describes_every_slot(&document, &vault));
    if !issues_ca_tls && !issues_credentials {
        return Err(SetupRefusal::DomainComplete);
    }
    Ok(Finalization {
        server_name: identity.server_name,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        issues_ca_tls,
        issues_credentials,
    })
}

/// What a finalization issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalized {
    /// The public `CA-TLS` certificate, PEM, when this finalization issued it.
    pub ca_tls_pem: Option<String>,
    /// Epoch of the credential document, when this finalization signed one.
    pub credentials_epoch: Option<u64>,
}

/// Issues what [`finalization`] found missing, with the opening the ceremony
/// already holds — `astra-signer issue-ca-tls`, then the credential document.
///
/// `CA-TLS` is never issued twice: a relay that carries one keeps it, and
/// replacing it is the §9.4 transition. The document is settled before
/// anything is written, so only a write or a signature can still fail once
/// `CA-TLS` is on the relay; a second call then issues the document alone.
pub fn finalize_with(vault_path: &Path, opening: &Opened, now_unix: u64) -> Result<Finalized> {
    let plan = finalization(vault_path)?;
    let vault = store::load(vault_path)?;
    let document = if plan.issues_credentials {
        Some(pending_document(vault_path, &vault)?.ok_or(SetupRefusal::GatewayIdentityMissing)?)
    } else {
        None
    };

    let mut ca_tls_pem = None;
    if plan.issues_ca_tls {
        let mut relay = handoff::DomainHandoff::beside(vault_path, &vault)?;
        let identity = handoff::identity_of(&relay)?;
        let not_after = CA_TLS_DAYS
            .checked_mul(DAY_SECS)
            .and_then(|lifetime| now_unix.checked_add(lifetime))
            .context("durée hors bornes")?;
        let certificate = signing::issue_ca_tls(&vault, opening, &identity, now_unix, not_after)?;
        // The epoch moves with the certificate, in the same write, as
        // `astra-signer issue-ca-tls` does: a relay naming one epoch and
        // carrying another would have every later delegation refused.
        relay.ca_tls_epoch = Some(identity.ca_tls_epoch);
        relay.ca_tls_certificate = Some(certificate.to_base64());
        handoff::save(&handoff::path_beside(vault_path), &relay)?;
        ca_tls_pem = Some(pem_of(&certificate));
    }

    let credentials_epoch = document
        .map(|document| document.resign(&vault, opening, &[], now_unix))
        .transpose()?;
    Ok(Finalized {
        ca_tls_pem,
        credentials_epoch,
    })
}

/// Whether the credential document in place could be re-signed by the next
/// gesture.
///
/// Refuses, as [`SetupRefusal::GatewayIdentityMissing`], a document whose
/// gateway the relay does not name — absent, unreadable or incomplete — and a
/// document that does not verify under the vault's `CA-PQ`. No document yet
/// is no refusal. The rule is the one every key gesture applies before it
/// writes, so the ceremony can refuse before the press.
pub fn check_document(vault_path: &Path) -> std::result::Result<(), SetupRefusal> {
    let vault = store::load(vault_path).map_err(|_| SetupRefusal::LocationUnavailable)?;
    check_document_of(vault_path, &vault)
}

fn check_document_of(
    vault_path: &Path,
    vault: &AuthorityVault,
) -> std::result::Result<(), SetupRefusal> {
    match pending_document(vault_path, vault) {
        Ok(_) => Ok(()),
        Err(error) => Err(error
            .downcast_ref::<SetupRefusal>()
            .copied()
            .unwrap_or(SetupRefusal::GatewayIdentityMissing)),
    }
}

/// The credential document beside the vault, when it verifies under the
/// vault's `CA-PQ` for the gateway the relay names.
///
/// `None` for every other case — absent, unreadable, forged, or a relay that
/// names no gateway — because a row read from a document that does not verify
/// says nothing about the key it describes.
pub(crate) fn verified_document(
    vault_path: &Path,
    vault: &AuthorityVault,
) -> Option<credentials::CredentialRegistry> {
    let relay = handoff::DomainHandoff::beside(vault_path, vault).ok()?;
    let identity = handoff::identity_of(&relay).ok()?;
    let document = credentials::load(&credentials::path_beside(vault_path)).ok()??;
    verifies_for(&document, vault, &identity).then_some(document)
}

/// Whether `document` verifies under `vault`'s `CA-PQ` for `identity`.
pub(crate) fn verifies_for(
    document: &credentials::CredentialRegistry,
    vault: &AuthorityVault,
    identity: &signing::DomainIdentity,
) -> bool {
    MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).is_ok_and(|ca_pq| {
        document
            .verify(
                &ca_pq,
                &identity.trust_domain_id,
                &identity.gateway_wg_public_key,
                identity.ca_epoch,
                document.credential_registry_epoch,
            )
            .is_ok()
    })
}

/// Whether `document` has a row for every slot of `vault`.
pub(crate) fn describes_every_slot(
    document: &credentials::CredentialRegistry,
    vault: &AuthorityVault,
) -> bool {
    vault.slots.iter().all(|slot| {
        slot.credential_id()
            .is_ok_and(|credential_id| document.binding(&credential_id).is_some())
    })
}

// --- Shared -----------------------------------------------------------------

/// The PEM form of a certificate, as `astra-signer` writes one.
fn pem_of(certificate: &DerCertificate) -> String {
    let body = certificate.to_base64();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The authority origin as the relay records it: `https://host[:port]`, no
/// trailing `/`.
///
/// An origin and nothing more: no path, query, fragment nor user information,
/// which a relay would otherwise carry into every URL built on it. Only the
/// trailing `/` an operator may type is trimmed; any other character outside
/// a host and its port is refused rather than dropped.
pub fn authority_origin(value: &str) -> Result<String> {
    let value = value.trim();
    let origin = value.trim_end_matches('/');
    let authority_chars = origin.strip_prefix("https://").is_some_and(|authority| {
        !authority.is_empty()
            && authority.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
            })
            && port_of(authority).is_none_or(|port| {
                port.parse::<u16>().is_ok_and(|port| port != 0) && !port.starts_with('0')
            })
    });
    // The parser settles what the characters alone do not: one host, a valid
    // address between brackets, nothing after it.
    let parsed = authority_chars
        && reqwest::Url::parse(origin).is_ok_and(|url| {
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.host().is_some()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                // Recorded as typed and later compared byte for byte: only the
                // spelling the parser itself gives back can ever match.
                && url.origin().ascii_serialization() == origin
        });
    if !parsed {
        bail!(
            "l'origine de l'autorité doit être https://hôte[:port], en minuscules, sans chemin \
             ni port 443 : {value}"
        );
    }
    Ok(origin.to_string())
}

/// What follows the host's `:` in `authority`, when it names a port. The `:`
/// inside a bracketed IPv6 address does not.
fn port_of(authority: &str) -> Option<&str> {
    let after_host = authority
        .rfind(']')
        .map_or(authority, |end| &authority[end + 1..]);
    after_host.rsplit_once(':').map(|(_, port)| port)
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
