//! Chiffrement des secrets Orion au repos ([ADR-006](../../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §3).
//!
//! # The asymmetry this closes
//!
//! Until this module, the key-negotiation identity was sealed by DPAPI while
//! the **WireGuard private key** — the one that actually brings the tunnel up —
//! sat in plaintext TOML next to it. The key that matters most was the least
//! protected. Everything here exists to end that.
//!
//! # Layout
//!
//! * [`keys`] — the installation key hierarchy, and why it is a conjunction;
//! * [`manifest`] — the atomic security manifest and its hand-rolled encoding;
//! * this module — identifiers, object contexts and the platform seam.
//!
//! # État d'avancement
//!
//! The storage core is complete and portable. Three pieces are deliberately
//! **not** here, because they cannot be compiled or exercised from WSL2 and
//! belong to the TPM lot:
//!
//! * wrapping [`keys::DeviceRootKey`] in a non-exportable *Microsoft Platform
//!   Crypto Provider* key, then DPAPI;
//! * the BitLocker posture check that gates import, migration and auto-connect;
//! * the `nomade` passphrase prompt through a native dialog.
//!
//! [`RootKeyProvider`] is the seam they plug into. Off Windows it fails
//! explicitly rather than writing an unprotected root — the same stance
//! `identity_store` already takes, and for the same reason: a protection that
//! silently is not one is worse than a refusal.

pub mod codec;
pub mod keys;
pub mod manifest;
pub mod passphrase;
pub mod registry;
pub mod store;
pub mod windows;

pub use keys::{DeviceRootKey, KEY_LEN};
pub use manifest::{ProfileManifest, SecurityGeneration, MAX_MANIFEST_BYTES};
pub use registry::{Registry, RegistryEntry};
pub use store::{Bootstrap, MigrationReport, ProfileStore};

use helios_vault::Context;

/// Vault domain of an Orion profile manifest (ADR-006 §2).
pub const DOMAIN_PROFILE: &str = "orion.profile";
/// Vault domain of the installation registry.
pub const DOMAIN_REGISTRY: &str = "orion.registry";

/// Stable, opaque identifier of a profile.
///
/// 128 random bits drawn once and **immutable**, deliberately distinct from the
/// display name: a name is edited, reused and shown, so binding a blob to it
/// would make renaming a way to swap profiles. The identifier is what the
/// object context is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileId([u8; 16]);

impl ProfileId {
    /// Draws a new identifier.
    pub fn generate() -> Result<Self, VaultError> {
        use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

        let mut id = [0u8; 16];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| VaultError::Rng)?;
        // An all-zero identifier is what an uninitialised buffer looks like;
        // refusing it turns a silent bug into a loud one.
        if id.iter().all(|byte| *byte == 0) {
            return Err(VaultError::Rng);
        }
        Ok(Self(id))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Hexadecimal form, for logs and file names. Carries no secret.
    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Object context binding a manifest to one profile **and** to the peers it
/// speaks to.
///
/// ADR-006 §2 requires the client public key and the gateway public key
/// alongside the identifier. The identifier alone would stop Alice's blob from
/// opening as Bob's; adding the two keys also stops a blob from being replayed
/// after its peer changed — the context no longer matches what the manifest
/// says.
///
/// After opening, the caller **must** re-derive the client public key from the
/// recovered private key and compare it to this context before any network
/// access. The container authenticates the context; only that comparison proves
/// the context describes the secret actually inside.
pub fn profile_context(
    id: ProfileId,
    client_public_key: &str,
    gateway_public_key: &str,
) -> Context {
    Context::new()
        .field("profile_id", id.as_bytes())
        .field("client_public_key", client_public_key.as_bytes())
        .field("gateway_public_key", gateway_public_key.as_bytes())
}

/// Object context of the installation registry.
pub fn registry_context(install_id: &[u8]) -> Context {
    Context::new().field("install_id", install_id)
}

/// Where the installation root comes from.
///
/// Implemented by the Orion shell over the platform's hardware-backed store.
/// The trait exists so this crate stays testable without a TPM, **not** so a
/// software fallback becomes acceptable: a shipped Orion that answers here
/// without hardware is the degraded `danger_allow_software_keystore` mode, and
/// it must say so in the posture panel and in a `WARN` at every start.
///
/// `Send + Sync` because the Orion shell keeps the store in shared application
/// state across async commands: a provider that could not cross threads would
/// force the whole store behind a lock it does not need.
pub trait RootKeyProvider: Send + Sync {
    /// Unwraps the installation root, creating it on first use.
    fn root_key(&self) -> Result<DeviceRootKey, VaultError>;

    /// `true` when the root is bound to hardware.
    ///
    /// Drives the posture panel. It must never be `true` unless the provider
    /// verified the provider name, the non-exportability, the user ACL and the
    /// operation result — ADR-006 §3 refuses a TPM whose properties cannot be
    /// checked rather than assuming them.
    fn hardware_backed(&self) -> bool;
}

/// A provider that refuses, for every platform without a protected store.
///
/// Not a stub: it is the correct behaviour off Windows. Writing the root in the
/// clear would look like it worked while offering none of the protection the
/// screen promises.
pub struct UnsupportedRootKeyProvider;

impl RootKeyProvider for UnsupportedRootKeyProvider {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        Err(VaultError::NoHardwareRoot)
    }

    fn hardware_backed(&self) -> bool {
        false
    }
}

/// Seals a manifest for one profile.
pub fn seal_manifest(
    root: &DeviceRootKey,
    id: ProfileId,
    manifest: &ProfileManifest,
    client_public_key: &str,
) -> Result<Vec<u8>, VaultError> {
    let key = root.profile_root_key(id)?;
    let context = profile_context(id, client_public_key, &manifest.peer_public_key);
    let encoded = manifest.encode()?;
    helios_vault::seal(
        DOMAIN_PROFILE,
        &context,
        &helios_vault::Unlock::Key(&key),
        &encoded,
    )
    .map_err(VaultError::Container)
}

/// Opens a manifest and proves the context describes what is inside it.
///
/// The comparison is the point: the AEAD proves nobody rewrote the context, and
/// this proves the context is not describing another profile's key. Skipping it
/// would leave a blob openable under a context that lies about its content.
pub fn open_manifest(
    root: &DeviceRootKey,
    id: ProfileId,
    client_public_key: &str,
    gateway_public_key: &str,
    blob: &[u8],
) -> Result<ProfileManifest, VaultError> {
    let key = root.profile_root_key(id)?;
    let context = profile_context(id, client_public_key, gateway_public_key);
    let plaintext = helios_vault::open(
        DOMAIN_PROFILE,
        &context,
        &helios_vault::Unlock::Key(&key),
        blob,
    )
    .map_err(VaultError::Container)?;
    let manifest = ProfileManifest::decode(&plaintext)?;

    let derived = aether::wg::public_from_private(manifest.private_key.as_str())
        .map_err(|_| VaultError::ContextDisagrees)?;
    if derived != client_public_key {
        return Err(VaultError::ContextDisagrees);
    }
    if manifest.peer_public_key != gateway_public_key {
        return Err(VaultError::ContextDisagrees);
    }
    Ok(manifest)
}

/// Failure modes, kept distinct because the user acts differently on each.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error(
        "aucune racine matérielle sur ce poste : Orion refuse de conserver ses secrets sans \
         stockage protégé. Le contournement explicite est `danger_allow_software_keystore`"
    )]
    NoHardwareRoot,
    #[error("système CSPRNG indisponible")]
    Rng,
    #[error("dérivation de clé impossible")]
    Derive,
    #[error("manifeste de {0} octets au-delà de la borne")]
    ManifestTooLarge(usize),
    #[error("version de manifeste {0} non supportée")]
    UnsupportedManifest(u8),
    #[error("manifeste illisible : {0}")]
    ManifestEncoding(String),
    #[error(
        "le contexte du coffre ne décrit pas le secret qu'il contient — ce profil vient d'un \
         autre poste ou d'un autre pair"
    )]
    ContextDisagrees,
    #[error("scellement DPAPI refusé par le système : {0}")]
    Dpapi(String),
    #[error("TPM : {0}")]
    Tpm(String),
    #[error(
        "la clé TPM de ce poste n'existe plus — TPM réinitialisé, carte mère changée ou firmware \
         invalidant. DPAPI ne constitue pas une récupération : les profils doivent être ré-enrôlés"
    )]
    TpmKeyLost,
    #[error("{}", .0.detail())]
    VolumeUnprotected(windows::bitlocker::VolumeProtection),
    #[error("saisie de la passphrase annulée")]
    PassphraseCancelled,
    #[error(
        "aucune boîte de saisie protégée sur cette plateforme : le profil nomade exige que la \
         passphrase ne traverse ni le DOM, ni JavaScript, ni un message sérialisé"
    )]
    NoNativePrompt,
    #[error("{path} : {cause}")]
    Io {
        path: std::path::PathBuf,
        cause: String,
    },
    #[error(
        "génération de sécurité {offered} inférieure à {observed} déjà observée — un état \
         antérieur a été remis en place"
    )]
    GenerationWentBackwards { observed: u64, offered: u64 },
    #[error("hygiène mémoire : {0}")]
    MemoryHygiene(&'static str),
    #[error(transparent)]
    Container(helios_vault::VaultError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProfile;
    use zeroize::Zeroizing;

    /// A real Curve25519 pair, so the post-open derivation check is exercised
    /// rather than bypassed.
    fn keypair() -> (String, String) {
        let pair = aether::wg::generate_keypair().expect("keypair");
        (
            pair.private_key.expose().to_string(),
            pair.public_key.clone(),
        )
    }

    fn root() -> DeviceRootKey {
        DeviceRootKey::from_unwrapped(Zeroizing::new([5u8; KEY_LEN]))
    }

    fn manifest_for(private_key: &str, gateway_public: &str) -> ProfileManifest {
        let profile = ClientProfile {
            name: "poste".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: private_key.into(),
            peer_public_key: gateway_public.into(),
            ..ClientProfile::default()
        };
        ProfileManifest::from_profile(&profile, SecurityGeneration(1))
    }

    #[test]
    fn a_manifest_round_trips_through_the_vault() {
        let (private_key, public_key) = keypair();
        let (_, gateway_public) = keypair();
        let id = ProfileId::generate().unwrap();
        let manifest = manifest_for(&private_key, &gateway_public);

        let blob = seal_manifest(&root(), id, &manifest, &public_key).expect("seal");
        assert!(
            !blob
                .windows(private_key.len())
                .any(|w| w == private_key.as_bytes()),
            "the private key is readable in the sealed blob"
        );

        let opened = open_manifest(&root(), id, &public_key, &gateway_public, &blob).expect("open");
        assert_eq!(opened.private_key.as_str(), private_key);
        assert_eq!(opened.generation, SecurityGeneration(1));
    }

    /// The property `profile_id` exists for.
    #[test]
    fn a_blob_of_another_profile_does_not_open() {
        let (private_key, public_key) = keypair();
        let (_, gateway_public) = keypair();
        let alice = ProfileId::generate().unwrap();
        let bob = ProfileId::generate().unwrap();

        let blob = seal_manifest(
            &root(),
            alice,
            &manifest_for(&private_key, &gateway_public),
            &public_key,
        )
        .expect("seal");
        assert!(open_manifest(&root(), bob, &public_key, &gateway_public, &blob).is_err());
    }

    /// A blob is bound to its peer too: replaying one after the gateway key
    /// changed must fail rather than reconnect to the old identity.
    #[test]
    fn a_blob_is_bound_to_its_gateway() {
        let (private_key, public_key) = keypair();
        let (_, gateway_public) = keypair();
        let (_, other_gateway) = keypair();
        let id = ProfileId::generate().unwrap();

        let blob = seal_manifest(
            &root(),
            id,
            &manifest_for(&private_key, &gateway_public),
            &public_key,
        )
        .expect("seal");
        assert!(open_manifest(&root(), id, &public_key, &other_gateway, &blob).is_err());
    }

    /// Another installation's root opens nothing, which is what makes copying
    /// a profile to another machine useless.
    #[test]
    fn another_installation_root_opens_nothing() {
        let (private_key, public_key) = keypair();
        let (_, gateway_public) = keypair();
        let id = ProfileId::generate().unwrap();
        let blob = seal_manifest(
            &root(),
            id,
            &manifest_for(&private_key, &gateway_public),
            &public_key,
        )
        .expect("seal");

        let other = DeviceRootKey::from_unwrapped(Zeroizing::new([6u8; KEY_LEN]));
        assert!(open_manifest(&other, id, &public_key, &gateway_public, &blob).is_err());
    }

    /// The context must describe the secret actually inside, not merely be
    /// authentic. A blob whose context announces a key other than the one it
    /// holds is refused after decryption.
    #[test]
    fn a_context_that_lies_about_its_content_is_refused() {
        let (private_key, _) = keypair();
        let (_, other_public) = keypair();
        let (_, gateway_public) = keypair();
        let id = ProfileId::generate().unwrap();

        // Sealed while claiming someone else's public key.
        let blob = seal_manifest(
            &root(),
            id,
            &manifest_for(&private_key, &gateway_public),
            &other_public,
        )
        .expect("seal");
        assert!(matches!(
            open_manifest(&root(), id, &other_public, &gateway_public, &blob),
            Err(VaultError::ContextDisagrees)
        ));
    }

    #[test]
    fn an_identifier_is_never_all_zero() {
        for _ in 0..64 {
            let id = ProfileId::generate().unwrap();
            assert!(id.as_bytes().iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn identifiers_do_not_repeat() {
        let a = ProfileId::generate().unwrap();
        let b = ProfileId::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.to_hex().len(), 32);
    }

    /// Off Windows, the refusal is the feature.
    #[test]
    fn the_unsupported_provider_refuses_rather_than_pretending() {
        let provider = UnsupportedRootKeyProvider;
        assert!(!provider.hardware_backed());
        assert!(matches!(
            provider.root_key(),
            Err(VaultError::NoHardwareRoot)
        ));
    }
}

/// What the vault can honestly claim about itself, for the posture panel.
///
/// Aggregated in one place, and **derived from what was actually verified**
/// rather than from what the configuration asked for. Each field is a fact the
/// UI is allowed to state; a field that could not be established says so
/// instead of defaulting to the reassuring answer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPosture {
    /// The installation root is bound to a TPM key that was checked — provider,
    /// non-exportability, ACL, modulus. Never `true` on a claim alone.
    pub hardware_backed: bool,
    /// `danger_allow_software_keystore` is on. A **downgrade**, not a recovery:
    /// resistance to inter-machine copying, hardware rollback and a domain
    /// administrator holding DPAPI backup keys is withdrawn with it.
    pub software_keystore: bool,
    /// Volume-encryption posture of the disk holding the profiles.
    pub volume: &'static str,
    pub volume_protected: bool,
    /// Whether secret pages are held out of swap and hibernation.
    pub memory_locked: bool,
    pub memory: &'static str,
    /// Whether secret pages are excluded from Windows Error Reporting dumps.
    pub dumps_excluded: bool,
    pub dumps: &'static str,
    /// Profiles whose key once lived in plaintext and is presumed compromised.
    /// They stay unconnectable until a new key is admitted.
    pub rotation_required: Vec<String>,
    /// A plaintext `profiles.toml` is still present and not yet migrated.
    pub legacy_present: bool,
}

impl VaultPosture {
    /// `true` when nothing is withheld — every claim the panel can make holds.
    pub fn is_clean(&self) -> bool {
        self.hardware_backed
            && !self.software_keystore
            && self.volume_protected
            && self.memory_locked
            && self.rotation_required.is_empty()
            && !self.legacy_present
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    type PostureMutation = fn(&mut VaultPosture);

    fn clean() -> VaultPosture {
        VaultPosture {
            hardware_backed: true,
            software_keystore: false,
            volume: "",
            volume_protected: true,
            memory_locked: true,
            memory: "",
            dumps_excluded: true,
            dumps: "",
            rotation_required: Vec::new(),
            legacy_present: false,
        }
    }

    /// Every withheld guarantee must show. A posture that reported itself clean
    /// while one of them was missing would be the screen keeping a promise
    /// nothing backs — the failure ADR-006 §3 names explicitly.
    #[test]
    fn any_missing_guarantee_makes_the_posture_unclean() {
        assert!(clean().is_clean());

        let cases: [(&str, PostureMutation); 6] = [
            ("no hardware root", |p| p.hardware_backed = false),
            ("software keystore", |p| p.software_keystore = true),
            ("volume unprotected", |p| p.volume_protected = false),
            ("memory not locked", |p| p.memory_locked = false),
            ("rotation pending", |p| {
                p.rotation_required = vec!["poste".into()]
            }),
            ("legacy file", |p| p.legacy_present = true),
        ];
        for (label, break_it) in cases {
            let mut posture = clean();
            break_it(&mut posture);
            assert!(!posture.is_clean(), "{label} was reported as clean");
        }
    }

    /// The WER exclusion is defence in depth, not a guarantee the panel gates
    /// on: it covers WER reports only, never a debugger or an injection.
    #[test]
    fn the_dump_exclusion_alone_does_not_make_the_posture_unclean() {
        let mut posture = clean();
        posture.dumps_excluded = false;
        assert!(posture.is_clean());
    }
}
