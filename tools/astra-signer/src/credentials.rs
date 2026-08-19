//! The credential bindings of the domain, beside the vault — spec §2.4.
//!
//! # Why the whole table is re-signed every time
//!
//! An [`AstraCredentialBinding`] says «this credential belongs to this trust
//! domain, in this state». A binding describing a key-slot the vault no longer
//! holds is a signed lie, and nothing downstream can catch it: Helios and Orion
//! check the `CA-PQ` signature, and the signature is genuine.
//!
//! So this document is never *edited*. Every change of the key-slot table
//! rebuilds it from the table: one `active` binding per slot present, one
//! `revoked` binding per credential that was withdrawn. A binding that does not
//! correspond to the current table therefore cannot be produced — not because a
//! check refuses it, but because nothing constructs it.
//!
//! # Why withdrawn credentials stay
//!
//! Removing a slot makes the vault stop opening for that token. It does not
//! tell Helios or Orion anything, and «absent from a document» is not a
//! decision they can act on: §2.4 makes `revoked` a signed state that dominates
//! permanently. A withdrawn credential therefore keeps a row, marked `revoked`,
//! carrying the public key it was registered with — which is exactly what makes
//! [`AstraCredentialBinding::supersedes`] refuse a restored backup that would
//! un-revoke it.
//!
//! # Why the epoch lives here
//!
//! `credential_registry_epoch` only ever rises, and every consumer keeps the
//! highest it has seen. It is the vault's neighbour rather than the vault's
//! content because the vault is re-sealed only when its slot table moves, while
//! a `lost` or `revoked` decision moves neither the table nor the master key.

use std::path::{Path, PathBuf};

use aether::certificates::approval::{AstraCredentialBinding, CredentialState};
use aether::certificates::encoding::{TrustDomainId, WireGuardKey};
use anyhow::{bail, Context, Result};
use base64::Engine as _;

/// Name of the credential document, beside the vault.
pub const CREDENTIALS_FILE: &str = "astra-credentials.json";

/// Largest credential document read, in bytes.
///
/// Eight slots plus the credentials they replaced, each with a COSE key and an
/// ML-DSA-87 signature of about 4.6 KiB. A megabyte is far above that and
/// refuses a file that would drive an allocation before a field is parsed.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;

/// Every signed credential decision of one trust domain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRegistry {
    pub trust_domain_id: TrustDomainId,
    /// The gateway the bindings are bound to. Fixed at the first emission and
    /// compared afterwards: a binding under another gateway is a binding for
    /// another domain's consumers, and would verify nowhere.
    pub gateway_wg_public_key: WireGuardKey,
    pub ca_epoch: u64,
    pub credential_registry_epoch: u64,
    pub bindings: Vec<AstraCredentialBinding>,
}

impl CredentialRegistry {
    /// The binding of one credential identifier, if this document holds one.
    pub fn binding(&self, credential_id: &[u8]) -> Option<&AstraCredentialBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.credential_id == credential_id)
    }

    /// The bindings a renewal approval may be answered by (spec §2.4).
    pub fn approvable(&self) -> Vec<&AstraCredentialBinding> {
        self.bindings
            .iter()
            .filter(|binding| binding.state == CredentialState::Active)
            .collect()
    }

    /// Refuses a document that does not describe the vault it sits beside.
    pub fn assert_describes(
        &self,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
    ) -> Result<()> {
        if self.trust_domain_id != *trust_domain_id {
            bail!(
                "le document de credentials décrit le domaine {} et non {}",
                self.trust_domain_id,
                trust_domain_id
            );
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            bail!(
                "le document de credentials est lié à une autre gateway : {} plutôt que {}",
                self.gateway_wg_public_key,
                gateway_wg_public_key
            );
        }
        Ok(())
    }

    /// One line per credential, for an operator to read before touching a key.
    pub fn summarize(&self) -> Vec<String> {
        self.bindings
            .iter()
            .map(|binding| {
                format!(
                    "  {} — {} — époque {}",
                    short(&binding.credential_id),
                    state_label(binding.state),
                    binding.credential_epoch
                )
            })
            .collect()
    }
}

/// The operator-facing name of a credential state.
pub fn state_label(state: CredentialState) -> &'static str {
    match state {
        CredentialState::Active => "active",
        CredentialState::Lost => "perdue",
        CredentialState::Revoked => "révoquée",
    }
}

/// The first bytes of a credential identifier, base64 — enough to tell two
/// rows apart on a terminal, and never enough to be mistaken for the whole.
pub fn short(credential_id: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(credential_id);
    encoded.chars().take(16).collect::<String>() + "…"
}

/// Where the document sits: beside the vault, whatever the vault's path.
pub fn path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CREDENTIALS_FILE)
}

/// Reads the document, or nothing when a domain has not emitted one yet.
pub fn load(path: &Path) -> Result<Option<CredentialRegistry>> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(None);
    };
    if metadata.len() > MAX_CREDENTIALS_BYTES {
        bail!(
            "{} pèse {} octets : ce n'est pas un document de credentials",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    let registry = serde_json::from_slice(&bytes)
        .with_context(|| format!("lecture du document de credentials {}", path.display()))?;
    Ok(Some(registry))
}

/// Writes the document, replacing any previous one.
///
/// Replacing rather than refusing, unlike the vault: everything here is a
/// public decision that the current vault and the previous document reproduce,
/// and a stale file is the one outcome worth avoiding.
pub fn save(path: &Path, registry: &CredentialRegistry) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes =
        serde_json::to_vec_pretty(registry).context("sérialisation du document de credentials")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(credential_id: Vec<u8>, state: CredentialState) -> AstraCredentialBinding {
        AstraCredentialBinding {
            format_version: 1,
            credential_id,
            credential_public_key: vec![0xa5, 0x01],
            aaguid: [0; 16],
            trust_domain_id: TrustDomainId::new([3; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([4; 32]),
            state,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: 10,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        }
    }

    fn registry() -> CredentialRegistry {
        CredentialRegistry {
            trust_domain_id: TrustDomainId::new([3; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([4; 32]),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: vec![
                binding(vec![1; 32], CredentialState::Active),
                binding(vec![2; 32], CredentialState::Revoked),
                binding(vec![3; 32], CredentialState::Lost),
            ],
        }
    }

    /// Only an `active` credential may answer a renewal challenge. A `lost`
    /// one is not merely unlikely to be plugged in — it must not be offered,
    /// or the allow-list would ask for a token somebody else may hold.
    #[test]
    fn only_active_credentials_are_offered_an_approval() {
        let registry = registry();
        let approvable = registry.approvable();
        assert_eq!(approvable.len(), 1);
        assert_eq!(approvable[0].credential_id, vec![1; 32]);
    }

    /// A document belongs to one domain and one gateway, and says so before
    /// anything is signed under it.
    #[test]
    fn a_document_for_another_gateway_is_refused_by_name() {
        let registry = registry();
        let domain = TrustDomainId::new([3; 16]).expect("domain");
        assert!(registry
            .assert_describes(&domain, &WireGuardKey::from_bytes([4; 32]))
            .is_ok());
        assert!(registry
            .assert_describes(&domain, &WireGuardKey::from_bytes([9; 32]))
            .is_err());
        assert!(registry
            .assert_describes(
                &TrustDomainId::new([8; 16]).expect("domain"),
                &WireGuardKey::from_bytes([4; 32])
            )
            .is_err());
    }

    /// The document survives the file byte for byte: the signatures are base64
    /// in JSON, and a lossy encoding would only be found at the next approval.
    #[test]
    fn the_document_round_trips_beside_the_vault() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault_path = directory.path().join("astra").join("authority-vault.json");
        let path = path_beside(&vault_path);
        assert_eq!(path.file_name().expect("name"), CREDENTIALS_FILE);

        let original = registry();
        save(&path, &original).expect("save");
        assert_eq!(load(&path).expect("load"), Some(original));
    }

    /// A domain that has emitted nothing yet is not an error: bindings need
    /// the gateway identity, which does not exist when the vault is created.
    #[test]
    fn a_missing_document_is_an_absence_rather_than_a_failure() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(CREDENTIALS_FILE);
        assert_eq!(load(&path).expect("load"), None);
    }
}
