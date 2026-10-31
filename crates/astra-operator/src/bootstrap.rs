//! The gateway bootstrap of Orion's operator ceremony, by path and by opening.
//!
//! `astra-signer issue-gateway-bootstrap` without the terminal: the gateway's
//! public request, two keys, and epoch 1 of its leaf under `CA-PQ`, followed
//! by whatever the domain still lacks to be finished (`CA-TLS`, the credential
//! document) — so a fresh domain is served by one gesture rather than three.
//!
//! # Plan, then gesture
//!
//! [`bootstrap_plan`] refuses what is predictable before any key is asked
//! anything, as a [`SetupRefusal`], and says what the gesture will write.
//! [`bootstrap_with`] runs the same checks again (fail closed: the interface
//! disabling a button is not a guarantee), proves both keys open the anchors,
//! and only then writes, in this order: the gateway's identity on the relay,
//! the leaf beside the vault, then the finalization. A failure after the leaf
//! leaves the leaf in place, and « Finaliser le domaine » resumes the rest.
//!
//! The request, the leaf and `CA-TLS` are public. Every [`Opened`] handled
//! here is secret: none is logged, serialized nor shown.

use std::path::{Path, PathBuf};

use aether::certificates::approval::{CredentialRegistry, CredentialState};
use aether::certificates::encoding::{MlDsa87PublicKey, WireGuardKey};
use aether::certificates::gateway::{pq_certificate_fingerprint, GatewayBootstrapRequest};
use aether::certificates::status::CampaignScope;
use anyhow::{bail, Context, Result};

use crate::authenticator::Opened;
use crate::vault::{AuthorityVault, REQUIRED_SLOTS};
use crate::vault_gestures::{
    bound_to_another_gateway, describes_every_slot, finalize_with, verifies_for, Finalized,
    SetupRefusal, DAY_SECS,
};
use crate::{credentials, gestures, handoff, signing, store};

/// Lifetime of the leaf a bootstrap issues, in days — `astra-signer`'s.
pub const BOOTSTRAP_LEAF_DAYS: u64 = 365;

/// The leaf's file, beside the vault: the name `scripts/deploy.sh` reads.
pub const BOOTSTRAP_CERTIFICATE_FILE: &str = "gateway-bootstrap-certificate.json";

/// The largest request read, the bound « Accepter une demande » applies to a
/// file the WebView reads.
pub const MAX_BOOTSTRAP_REQUEST_BYTES: usize = 256 * 1024;

/// How far before the issuance the leaf is already valid, for a gateway whose
/// clock runs slightly behind the operator's.
const LEAF_BACKDATE_SECS: u64 = 300;

/// What a bootstrap will write, shown before the first press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPlan {
    /// The gateway's request, verified.
    pub request: GatewayBootstrapRequest,
    /// The relay does not name the gateway yet: its key and server name are
    /// recorded from the request.
    pub records_identity: bool,
    /// The relay carries no `CA-TLS`: the finalization issues one.
    pub issues_ca_tls: bool,
    /// No credential document verifies with a row for every slot: the
    /// finalization signs one.
    pub issues_credentials: bool,
}

/// What a bootstrap wrote. Public, every field of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    /// The leaf, as written at [`path_beside`].
    pub leaf_json: String,
    pub leaf_fingerprint: String,
    /// What the finalization issued, when the domain still lacked something.
    pub finalized: Option<Finalized>,
}

/// Where the leaf is written: beside the vault, whatever the vault's path.
pub fn path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(BOOTSTRAP_CERTIFICATE_FILE)
}

/// What bootstrapping the gateway of `request_json` will write, or why it is
/// refused. Writes nothing and asks no key anything.
pub fn bootstrap_plan(
    vault_path: &Path,
    request_json: &str,
) -> std::result::Result<BootstrapPlan, SetupRefusal> {
    if request_json.len() > MAX_BOOTSTRAP_REQUEST_BYTES {
        return Err(SetupRefusal::BootstrapRequestInvalid);
    }
    let request: GatewayBootstrapRequest =
        serde_json::from_str(request_json).map_err(|_| SetupRefusal::BootstrapRequestInvalid)?;
    request
        .verify()
        .map_err(|_| SetupRefusal::BootstrapRequestInvalid)?;
    plan_for(vault_path, &request).map(|assessed| assessed.plan)
}

/// Issues the gateway's leaf with the two openings the ceremony holds, then
/// finishes the domain — `astra-signer issue-gateway-bootstrap`, then
/// « Finaliser le domaine ».
///
/// `first` signs the leaf and the finalization; `second` is the second
/// approval [`CampaignScope::GatewayBootstrap`] requires. No key is asked
/// anything here: both openings were obtained before.
///
/// What is written is settled again from the domain as it is now, not from
/// `plan`: only its request is taken from it.
pub fn bootstrap_with(
    vault_path: &Path,
    plan: &BootstrapPlan,
    first: &Opened,
    second: &Opened,
    now_unix: u64,
) -> Result<Bootstrapped> {
    plan.request
        .verify()
        .map_err(|_| SetupRefusal::BootstrapRequestInvalid)?;
    let Assessed {
        plan: current,
        vault,
        mut relay,
        document,
    } = plan_for(vault_path, &plan.request)?;

    // One key presented twice is one approval, whatever the scope's policy
    // says: refused here as well, so no change to that policy relaxes it.
    if first.credential_id == second.credential_id {
        bail!("le même credential a été présenté deux fois : l'amorçage en exige deux distincts");
    }
    gestures::require_scope_credentials(CampaignScope::GatewayBootstrap, &[first, second])?;
    for opening in [first, second] {
        if revoked(document.as_ref(), &opening.credential_id) {
            return Err(SetupRefusal::SignerRevoked.into());
        }
    }
    // The trial ADR-008 §4 asks for before first use: both keys open the
    // anchors, not merely a slot. Nothing is written before it passes.
    for opening in [first, second] {
        gestures::prove_anchors_open(&vault, opening)?;
    }

    // Signed before anything is written, so a signature that fails leaves
    // the domain as it was.
    let request = &plan.request;
    let not_after = BOOTSTRAP_LEAF_DAYS
        .checked_mul(DAY_SECS)
        .and_then(|lifetime| now_unix.checked_add(lifetime))
        .context("durée de validité hors bornes")?;
    let serial = aether::random::public_bytes::<16>()
        .map_err(|_| anyhow::anyhow!("aléa indisponible pour le numéro de la feuille"))?;
    let leaf = signing::issue_gateway_bootstrap_certificate(
        &vault,
        first,
        &MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?,
        &signing::GatewayBootstrapDecision {
            request,
            leaf_validity: (now_unix.saturating_sub(LEAF_BACKDATE_SECS), not_after),
            serial,
        },
    )?;
    let leaf_json = serde_json::to_string_pretty(&leaf).context("encodage de la feuille")?;
    let leaf_fingerprint = pq_certificate_fingerprint(&leaf)?.to_string();

    // Recorded, never replaced: `plan_for` refused a relay naming another
    // gateway.
    if current.records_identity {
        relay.gateway_wg_public_key = Some(request.gateway_wg_public_key.to_base64());
        relay.server_name = Some(request.server_name.clone());
        handoff::save(&handoff::path_beside(vault_path), &relay)?;
    }
    let leaf_path = path_beside(vault_path);
    aether::private_file::write_private_atomic(&leaf_path, leaf_json.as_bytes())
        .with_context(|| format!("écriture de {}", leaf_path.display()))?;

    let finalized = if current.issues_ca_tls || current.issues_credentials {
        match finalize_with(vault_path, first, now_unix) {
            Ok(finalized) => Some(finalized),
            Err(error) if error.downcast_ref() == Some(&SetupRefusal::DomainComplete) => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    Ok(Bootstrapped {
        leaf_json,
        leaf_fingerprint,
        finalized,
    })
}

/// A plan, and what it was settled from.
struct Assessed {
    plan: BootstrapPlan,
    vault: AuthorityVault,
    relay: handoff::DomainHandoff,
    /// The credential document in place, when there is one: it verifies for
    /// the request's gateway.
    document: Option<CredentialRegistry>,
}

/// The checks of [`bootstrap_plan`] after the request is read, shared with
/// [`bootstrap_with`].
///
/// The document is verified for the gateway the relay will name once the
/// request is recorded, so a relay that lost the gateway still finds the
/// document it signed — and a document bound to another gateway keeps the
/// domain, as in [`crate::vault_gestures::adopt_gateway`].
fn plan_for(
    vault_path: &Path,
    request: &GatewayBootstrapRequest,
) -> std::result::Result<Assessed, SetupRefusal> {
    let vault = store::load(vault_path).map_err(|_| SetupRefusal::LocationUnavailable)?;
    let relay = handoff::DomainHandoff::beside(vault_path, &vault)
        .map_err(|_| SetupRefusal::GatewayIdentityMissing)?;
    let mut named = relay.clone();
    named.gateway_wg_public_key = Some(request.gateway_wg_public_key.to_base64());
    named.server_name = Some(request.server_name.clone());
    let identity =
        handoff::identity_of(&named).map_err(|_| SetupRefusal::GatewayIdentityMissing)?;
    let (document, unverifiable) = match credentials::load(&credentials::path_beside(vault_path))
        .map_err(|_| SetupRefusal::GatewayIdentityMissing)?
    {
        Some(document) if verifies_for(&document, &vault, &identity) => (Some(document), false),
        Some(_) => (None, true),
        None => (None, false),
    };

    // A slot the verified document revokes cannot approve; one marked lost
    // still can, as everywhere else in the ceremony.
    let usable = vault
        .slots
        .iter()
        .filter(|slot| {
            slot.credential_id()
                .is_ok_and(|credential_id| !revoked(document.as_ref(), &credential_id))
        })
        .count();
    if usable < REQUIRED_SLOTS {
        return Err(SetupRefusal::MinimumKeys);
    }

    let other_key = relay
        .gateway_wg_public_key
        .as_deref()
        .is_some_and(|recorded| {
            WireGuardKey::parse(recorded).ok() != Some(request.gateway_wg_public_key)
        });
    let other_name = relay
        .server_name
        .as_deref()
        .is_some_and(|recorded| recorded != request.server_name);
    let bound_elsewhere = bound_to_another_gateway(vault_path, &request.gateway_wg_public_key)
        .map_err(|_| SetupRefusal::GatewayIdentityMissing)?;
    if other_key || other_name || bound_elsewhere {
        return Err(SetupRefusal::OtherGateway);
    }
    // Restoring a document that no longer verifies is the operator's call,
    // from a backup: re-signing over it would take back whatever it decided.
    if unverifiable {
        return Err(SetupRefusal::GatewayIdentityMissing);
    }

    let plan = BootstrapPlan {
        request: request.clone(),
        records_identity: relay.gateway_wg_public_key.is_none() || relay.server_name.is_none(),
        issues_ca_tls: relay.ca_tls_certificate.is_none(),
        issues_credentials: !document
            .as_ref()
            .is_some_and(|document| describes_every_slot(document, &vault)),
    };
    Ok(Assessed {
        plan,
        vault,
        relay,
        document,
    })
}

/// Whether `document` revokes `credential_id`. No document revokes nothing.
fn revoked(document: Option<&CredentialRegistry>, credential_id: &[u8]) -> bool {
    document
        .and_then(|document| document.binding(credential_id))
        .is_some_and(|row| row.state == CredentialState::Revoked)
}
