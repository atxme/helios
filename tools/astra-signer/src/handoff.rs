//! The public hand-off between the operator's machine and the deployment.
//!
//! Creating a trust domain produces three values that two other programs need
//! — `astra bootstrap` in the container and `heliosd init-trust-domain` on the
//! gateway. Retyping them is where a deployment goes wrong: a truncated base64
//! anchor produces a domain nobody holds the key to, and the failure surfaces
//! much later, as a refusal naming neither.
//!
//! So `init` writes them to a file `scripts/deploy.sh` reads. Nothing in it is
//! secret: an identifier, a DNS name, and a public key. The private anchors
//! never leave the sealed vault beside it.
//!
//! # Why not read it out of the vault directly
//!
//! It could be. The file exists so a deployment needs neither the vault nor a
//! security key — it carries only what is public, and can be copied to a build
//! machine that must never see the authority itself.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use astra::vault::AuthorityVault;
use serde::{Deserialize, Serialize};

/// Name of the hand-off file, beside the vault.
pub const HANDOFF_FILE: &str = "astra-domain.json";

/// Everything public about a trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainHandoff {
    /// Trust domain identifier, 32 hex characters.
    pub trust_domain_id: String,
    /// WebAuthn RP ID. Chosen once and never changed: the key-slots are bound
    /// to it, and changing it makes every one of them unopenable.
    pub rp_id: String,
    /// Public `CA-PQ` key, base64. The anchor of the domain.
    pub ca_pq_public_key: String,
    /// Fingerprint of the vault as it stood when this was written, so an
    /// operator can tell which vault a hand-off belongs to.
    pub vault_fingerprint: String,
}

impl DomainHandoff {
    pub fn of(vault: &AuthorityVault) -> Result<Self> {
        Ok(Self {
            trust_domain_id: vault.trust_domain_id.to_hex(),
            rp_id: vault.rp_id.clone(),
            ca_pq_public_key: vault.ca_pq_public_key.clone(),
            vault_fingerprint: vault.fingerprint()?.to_hex(),
        })
    }
}

/// Where the hand-off sits: beside the vault, whatever the vault's path.
pub fn path_beside(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(HANDOFF_FILE)
}

/// Writes the hand-off, replacing any previous one.
///
/// Replacing rather than refusing: unlike the vault, this file holds nothing
/// that cannot be produced again from the vault it describes. Refusing to
/// overwrite would only leave an operator with a stale one.
pub fn save(path: &Path, handoff: &DomainHandoff) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(handoff).context("sérialisation du relais")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

pub fn load(path: &Path) -> Result<DomainHandoff> {
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("lecture du relais {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra::vault::{AuthoritySecrets, SlotEnrolment, SlotRole, SlotSecret};

    fn vault() -> AuthorityVault {
        AuthorityVault::create(
            aether::certificates::encoding::TrustDomainId::new([9; 16]).expect("domain"),
            "astra.example",
            astra::vault::draw_salt().expect("salt"),
            &AuthoritySecrets {
                ca_pq_private_key: "cHJpdmU=".into(),
                ca_pq_public_key: "cHVibGlj".into(),
                ca_tls_private_key: "dGxz".into(),
            },
            SlotEnrolment {
                role: SlotRole::Primary,
                label: "clé".into(),
                credential_id: vec![4; 64],
                enrolled_at: 10,
            },
            &SlotSecret::new(vec![4; 32]),
            10,
        )
        .expect("create")
    }

    /// The three values a deployment needs, and no fourth: the hand-off is
    /// read by machines that must never see the authority.
    #[test]
    fn the_handoff_carries_what_a_deployment_needs_and_nothing_secret() {
        let vault = vault();
        let handoff = DomainHandoff::of(&vault).expect("handoff");
        assert_eq!(handoff.trust_domain_id, vault.trust_domain_id.to_hex());
        assert_eq!(handoff.rp_id, "astra.example");
        assert_eq!(handoff.ca_pq_public_key, "cHVibGlj");

        let encoded = serde_json::to_string(&handoff).expect("json");
        assert!(!encoded.contains("cHJpdmU="), "no private anchor");
        assert!(!encoded.contains("dGxz"), "no CA-TLS key");
        assert!(!encoded.contains("wrapped"), "no key-slot material");
    }

    /// It survives the file, and lands beside the vault rather than in a place
    /// an operator has to remember.
    #[test]
    fn the_handoff_round_trips_beside_the_vault() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault_path = directory.path().join("astra").join("authority-vault.json");
        let path = path_beside(&vault_path);
        assert_eq!(path.file_name().expect("name"), HANDOFF_FILE);

        let handoff = DomainHandoff::of(&vault()).expect("handoff");
        save(&path, &handoff).expect("save");
        assert_eq!(load(&path).expect("load"), handoff);
    }

    /// Rewriting it is ordinary: it holds nothing the vault cannot reproduce,
    /// so refusing would only leave a stale file behind.
    #[test]
    fn a_handoff_is_replaced_rather_than_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(HANDOFF_FILE);
        let handoff = DomainHandoff::of(&vault()).expect("handoff");
        save(&path, &handoff).expect("save");
        save(&path, &handoff).expect("save again");
        assert_eq!(load(&path).expect("load"), handoff);
    }
}
