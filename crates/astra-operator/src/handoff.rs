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

use crate::vault::AuthorityVault;
use aether::certificates::encoding::{MlDsa87PublicKey, TrustDomainId, WireGuardKey};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::campaign::Campaign;
use crate::origin::CampaignRequest;
use crate::signing::DomainIdentity;

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
    /// The authority origin **the domain** declares, as `astra
    /// init-trust-domain` recorded it.
    ///
    /// Every `AstraSignerRequest` names it, and the companion compares the two
    /// rather than believing the one it was sent. On the public channel the
    /// dialled URL served as that expected value; inside the tunnel there is
    /// no dialled URL, so it has to come from something this companion already
    /// holds — which is this file. Optional because a hand-off written before
    /// the amendment of 4 September 2026 has none; a campaign carried by the
    /// tunnel then says so and names the command that records it.
    #[serde(default)]
    pub astra_authority_url: Option<String>,
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
            astra_authority_url: None,
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
        match std::fs::metadata(&path) {
            Ok(_) => {
                let mut handoff = load(&path)?;
                handoff.adopt(vault)?;
                Ok(handoff)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::of(vault),
            Err(error) => Err(error).with_context(|| format!("lecture de {}", path.display())),
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

/// The domain identity every signing gesture reads out of the relay.
///
/// Shared rather than rebuilt at each call site: an identity assembled twice
/// is an identity that can differ once, and what it names — the gateway, the
/// server name, the two epochs — is exactly what `CA-PQ` vouches for.
pub fn identity_of(handoff: &DomainHandoff) -> Result<DomainIdentity> {
    let gateway = handoff.require(
        handoff.gateway_wg_public_key.as_ref(),
        "la clé publique de la gateway",
        "--gateway-wg-public-key",
    )?;
    let server_name = handoff.require(
        handoff.server_name.as_ref(),
        "le nom de service de la gateway",
        "--server-name",
    )?;
    Ok(DomainIdentity {
        trust_domain_id: TrustDomainId::parse_hex(&handoff.trust_domain_id)?,
        gateway_wg_public_key: WireGuardKey::parse(gateway)?,
        server_name: server_name.clone(),
        ca_epoch: handoff.ca_epoch.unwrap_or(1),
        ca_tls_epoch: handoff.ca_tls_epoch.unwrap_or(1),
    })
}

/// The authority origin a signed request must name, from what is already held.
///
/// Never from the answer being verified: an `authority_url` taken out of the
/// response would let whoever served it choose the value it is checked
/// against.
pub fn expected_authority_url(handoff: &DomainHandoff, channel: &Campaign) -> Result<String> {
    match (handoff.astra_authority_url.as_deref(), channel) {
        (Some(declared), Campaign::Origin(origin)) if origin.base() != declared => bail!(
            "ce relais de domaine déclare l'origine « {declared} » et cette commande compose \
             « {} ». Rien n'a été signé : corriger l'une des deux avant de continuer.",
            origin.base()
        ),
        (Some(declared), _) => Ok(declared.to_string()),
        (None, Campaign::Origin(origin)) => Ok(origin.base().to_string()),
        (None, Campaign::Tunnel(_)) => bail!(
            "le relais de domaine ne porte pas l'origine déclarée par l'autorité : la renseigner \
             par `astra-signer domain --astra-authority-url <url>`. Dans le tunnel aucune URL \
             n'est composée, donc rien d'autre ne peut servir de valeur attendue à la demande \
             signée."
        ),
    }
}

/// Checks what the authority served, before an operator is asked for anything.
///
/// The request is signed by Astra's service key and verified under the key
/// this companion already pins; the campaign is bound to that signature; and
/// the relying party the authority announces is **compared** to the vault's,
/// never adopted.
///
/// `authority_url` is the expected value [`expected_authority_url`] resolved —
/// never one this answer supplied.
pub fn verify_campaign_request(
    handoff: &DomainHandoff,
    vault: &AuthorityVault,
    request: &CampaignRequest,
    authority_url: &str,
    now: u64,
) -> Result<()> {
    let service_key = handoff.astra_service_public_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "ce relais de domaine ne porte pas la clé de service Astra : la réémettre par \
             `astra-signer domain`, sinon rien ne vérifie ce que l'origine renvoie"
        )
    })?;
    let service_key_epoch = handoff.astra_service_key_epoch.ok_or_else(|| {
        anyhow::anyhow!("ce relais de domaine ne porte pas l'époque de la clé de service")
    })?;
    request.signer_request.verify(
        &MlDsa87PublicKey::parse(service_key)?,
        service_key_epoch,
        authority_url,
        now,
    )?;
    if request.webauthn_rp_id != vault.rp_id {
        bail!(
            "l'autorité annonce le RP ID « {} » alors que ce coffre épingle « {} ». Rien n'est \
             signé : une assertion produite sous un autre RP ID vaudrait pour un autre domaine.",
            request.webauthn_rp_id,
            vault.rp_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{AuthoritySecrets, SlotEnrolment, SlotRole, SlotSecret};

    fn vault() -> AuthorityVault {
        AuthorityVault::create(
            aether::certificates::encoding::TrustDomainId::new([9; 16]).expect("domain"),
            "astra.example",
            crate::vault::draw_salt().expect("salt"),
            &AuthoritySecrets {
                ca_pq_private_key: "cHJpdmU=".into(),
                ca_pq_public_key: "cHVibGlj".into(),
                ca_tls_private_key: "dGxz".into(),
                retained_ca_tls: None,
                retained_outgoing_ca_pq: None,
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

    #[test]
    fn a_corrupt_handoff_is_not_mistaken_for_an_absent_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault_path = directory.path().join("authority-vault.json");
        let path = path_beside(&vault_path);
        std::fs::write(&path, b"not a handoff").expect("write corrupt handoff");

        assert!(DomainHandoff::beside(&vault_path, &vault()).is_err());
        assert_eq!(
            std::fs::read(&path).expect("still present"),
            b"not a handoff"
        );
    }
}
