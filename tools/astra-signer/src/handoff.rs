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
//!
//! # Why the signing commands read it too
//!
//! Signing a delegation, approving a renewal or emitting a credential binding
//! all need values the vault does not hold: the gateway's WireGuard key, the
//! server name, the Astra service key the companion **pins**, and the two
//! authority epochs. Retyping them on every command is where an operator
//! eventually signs a delegation for the wrong gateway — an object `CA-PQ`
//! vouches for, which no later check can undo.
//!
//! So they are recorded here once, next to the anchor, and every later command
//! reads them. They are all optional because they arrive in the order a
//! deployment produces them: the vault exists before the gateway does, and the
//! Astra service key exists only after `astra bootstrap`. A command that needs
//! one and does not find it says which value is missing and which flag records
//! it, rather than proceeding on a default.

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
    /// Epoch of `CA-PQ`. Advanced by an anchor rotation, and by nothing else.
    #[serde(default)]
    pub ca_epoch: Option<u64>,
    /// Epoch of `CA-TLS`. Advanced when a new client TLS CA is self-signed.
    #[serde(default)]
    pub ca_tls_epoch: Option<u64>,
    /// The self-signed client `CA-TLS` certificate, DER base64.
    ///
    /// Public: it is what the gateway pins and what a delegated intermediate
    /// chains to. The private half stays in the sealed body.
    #[serde(default)]
    pub ca_tls_certificate: Option<String>,
    /// WireGuard public key of the gateway this domain serves, base64.
    ///
    /// Every `CA-PQ`-signed object of the lifecycle names it, so recording it
    /// once removes it from every command line.
    #[serde(default)]
    pub gateway_wg_public_key: Option<String>,
    /// Server name of the gateway. Part of the pinned issuance policy.
    #[serde(default)]
    pub server_name: Option<String>,
    /// The Astra service key this companion **pins**, base64.
    ///
    /// Printed by `astra bootstrap`. A companion that learned the service key
    /// from the request it is about to trust would authenticate nothing, so it
    /// is recorded here and compared afterwards.
    #[serde(default)]
    pub astra_service_public_key: Option<String>,
    #[serde(default)]
    pub astra_service_key_epoch: Option<u64>,
}

impl DomainHandoff {
    /// A hand-off carrying only what the vault itself knows.
    pub fn of(vault: &AuthorityVault) -> Result<Self> {
        let mut handoff = Self {
            trust_domain_id: String::new(),
            rp_id: String::new(),
            ca_pq_public_key: String::new(),
            vault_fingerprint: String::new(),
            ca_epoch: None,
            ca_tls_epoch: None,
            ca_tls_certificate: None,
            gateway_wg_public_key: None,
            server_name: None,
            astra_service_public_key: None,
            astra_service_key_epoch: None,
        };
        handoff.adopt(vault)?;
        Ok(handoff)
    }

    /// Refreshes the vault-derived half, leaving everything recorded later.
    ///
    /// Rewriting the file from the vault alone would silently drop the gateway
    /// key and the pinned service key — and the next command would then ask an
    /// operator to retype them, which is the failure this file exists to
    /// prevent.
    pub fn adopt(&mut self, vault: &AuthorityVault) -> Result<()> {
        self.trust_domain_id = vault.trust_domain_id.to_hex();
        self.rp_id = vault.rp_id.clone();
        self.ca_pq_public_key = vault.ca_pq_public_key.clone();
        self.vault_fingerprint = vault.fingerprint()?.to_hex();
        Ok(())
    }

    /// Loads the hand-off beside a vault, or builds a fresh one.
    pub fn beside(vault_path: &Path, vault: &AuthorityVault) -> Result<Self> {
        let path = path_beside(vault_path);
        match load(&path) {
            Ok(mut handoff) => {
                handoff.adopt(vault)?;
                Ok(handoff)
            }
            Err(_) => Self::of(vault),
        }
    }

    /// A value the deployment recorded, or a refusal naming the flag that
    /// records it.
    pub fn require<'a, T>(&self, value: Option<&'a T>, what: &str, flag: &str) -> Result<&'a T> {
        value.ok_or_else(|| {
            anyhow::anyhow!(
                "le relais de domaine ne porte pas {what} : le renseigner par `astra-signer \
                 domain {flag} <valeur>`"
            )
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
                credential_public_key: vec![0xa5, 0x01],
                aaguid: [0; 16],
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
