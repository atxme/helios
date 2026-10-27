//! What the operator vault and its trust domain look like, read without a key.
//!
//! Everything here is public: a slot's identifier, label and role, the vault's
//! fingerprint, and the values of the domain relay beside it. No key-slot is
//! opened, so no PIN, no security key and no secret is involved — which is what
//! lets Orion show the vault to anyone looking at the screen.

use std::path::Path;

use aether::certificates::encoding::MlDsa87PublicKey;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::handoff::{self, DomainHandoff};
use crate::store;
use crate::vault::{AuthorityVault, KeySlot, SlotRole, MAX_SLOTS};

/// The vault as the operator sees it, with nothing that opens it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultOverview {
    pub vault_path: String,
    pub exists: bool,
    pub vault_fingerprint: Option<String>,
    pub slots: Vec<SlotView>,
    pub max_slots: usize,
    pub domain: Option<DomainView>,
}

/// One registered key, described and never unwrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotView {
    /// 32 hexadecimal characters.
    pub slot_id: String,
    pub label: String,
    /// `principale` or `recuperation`.
    pub role: String,
}

/// The public half of the trust domain, as the relay beside the vault records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainView {
    pub trust_domain_id: String,
    pub rp_id: String,
    /// Fingerprint of `CA-PQ`, grouped by four as it is read aloud.
    pub ca_pq_fingerprint: String,
    pub ca_epoch: Option<u64>,
    pub ca_tls_epoch: Option<u64>,
    pub ca_tls_present: bool,
    pub server_name: Option<String>,
    pub gateway_wg_public_key: Option<String>,
}

/// Reads the vault at `vault_path` and the domain relay beside it.
///
/// An absent vault is a state, not a failure. An unreadable one is a failure:
/// showing «no vault» over a corrupt file would invite creating a second one.
/// An absent or unreadable relay only leaves the domain out.
pub fn read(vault_path: &Path) -> Result<VaultOverview> {
    let mut overview = VaultOverview {
        vault_path: vault_path.display().to_string(),
        exists: false,
        vault_fingerprint: None,
        slots: Vec::new(),
        max_slots: MAX_SLOTS,
        domain: None,
    };
    match std::fs::metadata(vault_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(overview),
        Err(error) => {
            return Err(error).with_context(|| format!("lecture de {}", vault_path.display()))
        }
    }
    let vault = store::load(vault_path)?;
    overview.exists = true;
    overview.vault_fingerprint = Some(vault.fingerprint()?.to_hex());
    overview.slots = vault.slots.iter().map(slot_view).collect();
    overview.domain = domain_view(vault_path, &vault)?;
    Ok(overview)
}

fn slot_view(slot: &KeySlot) -> SlotView {
    SlotView {
        slot_id: hex::encode(slot.slot_id),
        label: slot.label.clone(),
        role: match slot.role {
            SlotRole::Primary => "principale",
            SlotRole::Recovery => "recuperation",
        }
        .to_string(),
    }
}

/// The relay is read only when it exists: `DomainHandoff::beside` would
/// otherwise build one from the vault and present it as recorded.
fn domain_view(vault_path: &Path, vault: &AuthorityVault) -> Result<Option<DomainView>> {
    if !handoff::path_beside(vault_path).is_file() {
        return Ok(None);
    }
    let Ok(relay) = DomainHandoff::beside(vault_path, vault) else {
        return Ok(None);
    };
    let anchor = MlDsa87PublicKey::parse(&relay.ca_pq_public_key)?;
    Ok(Some(DomainView {
        trust_domain_id: relay.trust_domain_id,
        rp_id: relay.rp_id,
        ca_pq_fingerprint: grouped_hex(&anchor.authority_fingerprint().to_hex()),
        ca_epoch: relay.ca_epoch,
        ca_tls_epoch: relay.ca_tls_epoch,
        ca_tls_present: relay.ca_tls_certificate.is_some(),
        server_name: relay.server_name,
        gateway_wg_public_key: relay.gateway_wg_public_key,
    }))
}

/// A hexadecimal fingerprint in groups of four, as it is read aloud.
pub fn grouped_hex(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests;
