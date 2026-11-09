//! The authority vault: `CA-PQ` and `CA-TLS` behind hardware key-slots.
//!
//! # Why the anchor is a software key at all
//!
//! `CA-PQ` is ML-DSA-87. No FIDO2 authenticator signs ML-DSA — a YubiKey 5
//! holds RSA, P-256/P-384 and, from firmware 5.7, Ed25519/X25519, and nothing
//! post-quantum. The anchor of a post-quantum PKI therefore **cannot** live on
//! the token, and no amount of wanting it to changes that.
//!
//! So the token does the other half of the job, which it is very good at: it
//! holds a secret that never leaves it, and releases a derivation of that
//! secret only on physical presence and user verification. That derivation
//! unwraps a key-slot; the slot yields the vault's master key; the master key
//! opens the payload. The private anchors exist in the clear only inside
//! `astra-signer`, on the operator's machine, for the length of one signature
//! (ADR-008 §4).
//!
//! # Slots, and why adding one requires opening one
//!
//! Each registered credential gets its own slot, LUKS-style: a random master
//! key, wrapped once per credential. Any single slot opens the vault — the
//! recovery key must genuinely recover the loss of the current one, so the
//! v1 policy is 1-of-N, not M-of-N (ADR-008 §4). The ADR requires *at least*
//! two; [`MAX_SLOTS`] is where more stop being registered.
//!
//! Adding a slot needs the master key, and the master key needs an existing
//! slot to be opened. That is not a check this module performs; it is the
//! shape of the data. Someone holding the encrypted vault and a fresh YubiKey
//! cannot append a slot of their own, because they would have nothing to wrap.
//!
//! # Why the payload is bound to the slot table
//!
//! Withdrawing a credential drops its row, and nothing more would leave the
//! master key untouched. An operator who kept a backup — or an attacker who
//! took one — could then splice the withdrawn row back into the current file
//! and open it: same vault identifier, same slot identifier, same master.
//! Removal would mean nothing.
//!
//! So the payload container is bound to a digest of the slot table
//! ([`AuthorityVault::slot_table_digest`]). Every change of the table re-seals
//! the payload, which needs the master key and therefore one authorized
//! credential — **one**, not all of them, since the rows themselves are
//! untouched. A spliced row still yields the master key and still opens
//! nothing.
//!
//! What this does not do is reach into copies already made: an old file opens
//! with the credential that was authorized when it was written, forever. The
//! remedy for a genuinely compromised credential is a `CA-PQ` rotation, not a
//! slot removal, and the specification says so.
//!
//! # One salt, per vault
//!
//! `hmac-secret` outputs `HMAC(CredRandom, salt)`, and `CredRandom` is drawn
//! by the authenticator per credential. Two slots of the same vault therefore
//! derive different secrets from the same salt, and a per-slot salt would add
//! nothing — while costing the ability to resolve a slot and derive its secret
//! in a single assertion. The salt is drawn per vault, so the same credential
//! registered in two vaults still yields two unrelated secrets.
//!
//! # Limite connue : le matériel n'est pas exerçable ici
//!
//! Nothing in this module talks to CTAP. A slot is opened from key material
//! the caller supplies — the `hmac-secret` output on a real machine, a fixed
//! value in a test — because WSL2 has no USB passthrough and because the
//! Windows path goes through `webauthn.dll` rather than raw HID. The boundary
//! is [`SlotSecret`], and what is above it is fully exercised; what is below
//! it is target-only, like DPAPI and the TPM.
//! See [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md).

use aether::certificates::encoding::{Fingerprint, MlDsa87PublicKey, TrustDomainId};
use aether_vault::{Context, Unlock};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Domain of the container that wraps the master key in one slot.
const SLOT_DOMAIN: &str = "helios/astra-authority-slot/v1";
/// Domain of the container that holds the private anchors.
const PAYLOAD_DOMAIN: &str = "helios/astra-authority-payload/v1";
/// Derivation label of a slot's wrapping key, from the authenticator output.
const SLOT_INFO: &[u8] = b"helios/astra-authority-slot-wrapping/v1";

/// Format version of the vault document.
pub const AUTHORITY_VAULT_VERSION: u16 = 1;

/// Length of the salt handed to `hmac-secret`, in bytes.
///
/// Re-exported from the shared contracts: CTAP2 fixes it, so the value belongs
/// where the key's own properties are stated rather than where the file is
/// written. Kept visible here because every vault reader names it. Taken from
/// `aether` and not from `aether-fido` on purpose — Astra reads this format
/// but never speaks to a key, and linking the CTAP2 stack for a constant would
/// drag `libudev` into a container that has no USB port to offer it.
pub use aether::certificates::webauthn::SALT_LEN;

/// Largest number of credentials a vault registers.
///
/// Generous next to the two the specification requires, and bounded because
/// the slot table is parsed from a file an attacker may hand over.
pub const MAX_SLOTS: usize = 8;

/// Slots below which the vault is not bootstrapped (ADR-008 §4).
///
/// Two, and the reason is stated as a rule rather than advice: a single
/// authenticator makes the loss of one object the loss of the trust domain.
/// The specification also refuses a passphrase fallback — «le PIN seul, une
/// assertion WebAuthn non liée au coffre ou un mot de passe de secours ne
/// déverrouillent pas l'autorité» — so the second slot is a second piece of
/// hardware, kept elsewhere. Beyond two, more are welcome and none is special.
pub const REQUIRED_SLOTS: usize = 2;

/// Largest credential identifier accepted, in bytes. Also from the shared
/// contracts: the bound is CTAP2's, not this file format's, and it is the same
/// one the lifecycle objects validate against.
pub use aether::certificates::client::MAX_CREDENTIAL_ID_BYTES;

/// Largest COSE credential public key accepted, in bytes.
///
/// WebAuthn's own ceiling, repeated here so a vault file is bounded before it
/// reaches the verifier that shares it.
pub const MAX_CREDENTIAL_PUBLIC_KEY_BYTES: usize = 1024;

/// Longest operator-facing slot label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("coffre d'autorité : {0}")]
    Container(#[from] aether_vault::VaultError),
    #[error("version de coffre non prise en charge : {0}")]
    UnsupportedVersion(u16),
    #[error("aucun key-slot ne porte cet identifiant")]
    UnknownSlot,
    #[error("aucun key-slot n'est enregistré pour ce credential")]
    UnknownCredential,
    #[error("ce credential possède déjà un key-slot")]
    SlotAlreadyPresent,
    #[error(
        "le coffre est plafonné à {MAX_SLOTS} key-slots : en retirer un avant d'en ajouter un"
    )]
    TooManySlots,
    #[error(
        "retirer ce key-slot ne laisserait plus de clé de récupération : l'autorité exige au \
         moins {REQUIRED_SLOTS} credentials"
    )]
    LastRecoverySlot,
    #[error("identifiant de credential hors bornes")]
    CredentialIdOutOfBounds,
    #[error("libellé de key-slot hors bornes")]
    LabelOutOfBounds,
    #[error(
        "la clé publique CA-PQ inscrite en clair sur le coffre ne correspond pas à celle qu'il \
         scelle : le fichier a été modifié"
    )]
    AnchorMismatch,
    #[error("clé publique de credential hors bornes")]
    CredentialKeyOutOfBounds,
    #[error(
        "ce key-slot a été enregistré sans la clé publique de son credential : aucun \
         `AstraCredentialBinding` ne peut le décrire. Le retirer et réenrôler la clé"
    )]
    CredentialKeyMissing,
    #[error(
        "une fenêtre de rotation CA-TLS est déjà ouverte : la mener à son terme par \
         `astra-signer promote-ca-tls` avant d'en ouvrir une seconde"
    )]
    CaTlsWindowOpen,
    #[error(
        "la clé CA-PQ sortante reste conservée jusqu'à la seconde {at} : elle ne peut être \
         détruite avant"
    )]
    OutgoingCaPqKept { at: u64 },
    #[error("contenu du coffre illisible : {0}")]
    Corrupt(String),
}

type Result<T> = std::result::Result<T, VaultError>;

/// Key material an authenticator released for one slot.
///
/// It is what a security key hands back, and this file merely derives from it.
/// Re-exported so vault readers keep naming it here — and named from `aether`,
/// so that reading a vault requires no HID stack. Astra transports this format
/// and never opens it.
pub use aether::certificates::webauthn::SlotSecret;

/// What role a slot plays for the operator. Cryptographically identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotRole {
    /// The key in daily use.
    Primary,
    /// A key kept elsewhere, whose only job is to survive the loss of another.
    Recovery,
}

impl std::fmt::Display for SlotRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Primary => "principale",
            Self::Recovery => "récupération",
        })
    }
}

/// One registered credential, and the master key wrapped for it.
///
/// Everything here is **public**: a credential identifier is a value the
/// authenticator needs handed back to it, and it says nothing about the secret
/// it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlot {
    pub slot_id: [u8; 16],
    pub role: SlotRole,
    /// Operator-facing name. Never used in a derivation nor in the slot-table
    /// digest: renaming a key must not stop it from opening the vault.
    pub label: String,
    /// CTAP2 credential identifier, base64.
    pub credential_id: String,
    /// COSE public key of the credential, base64, exactly as the authenticator
    /// attested it.
    ///
    /// Public, and kept here because the `AstraCredentialBinding` that `CA-PQ`
    /// signs must name the key an approval assertion is verified under. It is
    /// deliberately outside [`AuthorityVault::slot_table_digest`]: it is not a
    /// wrapping input, and re-sealing the body on account of it would make a
    /// value the token already published into an unlock condition.
    ///
    /// Defaulted for a vault written before bindings existed. Such a slot
    /// still opens the anchors and is still refused a binding by name —
    /// [`VaultError::CredentialKeyMissing`] — rather than described by a
    /// guessed one.
    #[serde(default)]
    pub credential_public_key: String,
    /// Authenticator model identifier. All-zero by design on many models, so
    /// it is raw bytes rather than an identifier type that refuses that value.
    #[serde(default)]
    pub aaguid: [u8; 16],
    /// When this credential was registered.
    pub enrolled_at: u64,
    /// The master key, sealed under this slot's wrapping key, base64.
    pub wrapped_master: String,
}

impl KeySlot {
    /// The decoded COSE public key of this slot's credential.
    ///
    /// Refuses by name when the slot predates bindings, rather than handing
    /// back an empty key that would be signed into a document claiming to
    /// describe a credential.
    pub fn credential_public_key(&self) -> Result<Vec<u8>> {
        if self.credential_public_key.trim().is_empty() {
            return Err(VaultError::CredentialKeyMissing);
        }
        let bytes = decode(&self.credential_public_key, "clé publique de credential")?;
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES {
            return Err(VaultError::CredentialKeyOutOfBounds);
        }
        Ok(bytes)
    }

    /// The decoded CTAP2 credential identifier of this slot.
    pub fn credential_id(&self) -> Result<Vec<u8>> {
        decode(&self.credential_id, "identifiant de credential")
    }
}

/// The private anchors of the domain. Never leaves `astra-signer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct AuthoritySecrets {
    /// ML-DSA-87 private key of `CA-PQ`, base64.
    pub ca_pq_private_key: String,
    /// The matching public key, base64.
    ///
    /// Sealed alongside the private half so the clear copy on the vault has
    /// something to be checked against. `fips204` exposes no way to derive one
    /// from the other, and a public anchor an operator hands to two other
    /// programs must not be a value anybody can edit unnoticed.
    pub ca_pq_public_key: String,
    /// PKCS#8 private key of the client `CA-TLS` **currently issuing**.
    pub ca_tls_private_key: String,
    /// The other half of an open `CA-TLS` window, sealed beside the issuing
    /// one (spec §9.2, §9.4). `None` outside a rotation.
    #[serde(default)]
    pub retained_ca_tls: Option<RetainedCaTls>,
    /// The outgoing `CA-PQ`, kept from the signature of a rotation until
    /// « Terminer ». `None` outside that window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_outgoing_ca_pq: Option<RetainedOutgoingCaPq>,
}

/// The successor `CA-TLS` key, sealed beside the one that issues.
///
/// # Why the outgoing key stays the issuing one for the whole window
///
/// A client generation carries `ca_tls_epoch`, and the gateway checks it with
/// strict equality against [`ClientTlsCaState::ca_tls_epoch`], which advances
/// at `retire_active_at` — the window's `not_after`, not its `activation_at`.
/// So an authority that started stamping the next generation at activation
/// would have every issuance of the overlap refused, for as long as the
/// overlap lasts. The overlap exists exactly so leaves under the outgoing
/// anchor keep working; the authority stays on it until the fleet has moved.
///
/// # Why it is kept, and why keeping it is not using it
///
/// §9.2 lets the old private half be destroyed **only** after the window ends
/// and the transition is durably published. Destroying it at the ceremony
/// instead would leave a domain that has announced a successor no gateway has
/// installed yet with no way back: the anchor the fleet still accepts would
/// have no key, and the one with a key nothing yet trusts.
///
/// The successor, meanwhile, certifies nothing. It is not
/// [`AuthoritySecrets::ca_tls_private_key`], which is the only key any
/// issuance path reads, and the one thing that moves it there is
/// [`AuthorityVault::advance_ca_tls`] — which the clock gates, and which
/// destroys the outgoing key in the same sealed write.
///
/// [`ClientTlsCaState::ca_tls_epoch`]: aether::certificates::state::ClientTlsCaState
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCaTls {
    /// PKCS#8 private key of the incoming anchor, base64.
    pub private_key: String,
    /// SHA-256 of the DER certificate this key belongs to, hex.
    #[zeroize(skip)]
    pub certificate_fingerprint: String,
    /// The same, for the anchor currently issuing — the one this replaces.
    #[zeroize(skip)]
    pub counterpart_fingerprint: String,
    /// The window this successor belongs to, from the transition that opened
    /// it. `activation_at` is when the *fleet* starts accepting the incoming
    /// anchor; `not_after` is when the outgoing one is retired, and the only
    /// second at which this vault moves.
    #[zeroize(skip)]
    pub activation_at: u64,
    #[zeroize(skip)]
    pub not_after: u64,
}

/// The outgoing `CA-PQ`, sealed beside the anchor that replaced it.
///
/// A revocation signed during the overlap must still verify under the anchor
/// the fleet trusts until `not_after`, so the outgoing private half is kept
/// from the signature of the rotation and destroyed only by
/// [`AuthorityVault::retire_outgoing_ca_pq`] at that second.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct RetainedOutgoingCaPq {
    /// ML-DSA-87 private key of the outgoing anchor, base64.
    pub private_key: String,
    /// The matching public key, base64.
    #[zeroize(skip)]
    pub public_key: String,
    /// The `CA-PQ` epoch this key was the anchor of.
    #[zeroize(skip)]
    pub ca_epoch: u64,
    /// The rotation window's `not_after`: the second the old anchor stops
    /// being accepted, and the only second this key may be destroyed.
    #[zeroize(skip)]
    pub not_after: u64,
}

impl RetainedOutgoingCaPq {
    fn public(&self) -> OutgoingCaPqPublic {
        OutgoingCaPqPublic {
            public_key: self.public_key.clone(),
            ca_epoch: self.ca_epoch,
            not_after: self.not_after,
        }
    }
}

/// The public half of [`RetainedOutgoingCaPq`], kept in the clear on the vault
/// beside `ca_pq_public_key`, so that a revocation can be verified under the
/// outgoing anchor without opening it. Checked against the sealed copy at every
/// unlock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingCaPqPublic {
    /// ML-DSA-87 public key of the outgoing anchor, base64.
    pub public_key: String,
    pub ca_epoch: u64,
    pub not_after: u64,
}

/// What one call to [`AuthorityVault::advance_ca_tls`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaTlsAdvance {
    /// No window is open. Nothing was written.
    Idle,
    /// A successor is sealed and the retirement second has not arrived. An
    /// operator who runs the command early is told when to come back rather
    /// than left wondering whether it worked.
    Awaiting { at: u64 },
    /// The successor is now the issuing key and the outgoing private key is
    /// gone, in one sealed write. The window is closed.
    Rotated {
        /// The anchor that now issues.
        certificate_fingerprint: String,
        /// The anchor whose private half was destroyed.
        destroyed_fingerprint: String,
    },
}

/// The vault as it travels: an encrypted body and a table of key-slots.
///
/// It may sit in Astra's state and in its backups. Astra never opens it, and
/// nothing here lets it: opening needs an authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityVault {
    pub format_version: u16,
    pub vault_id: [u8; 16],
    pub trust_domain_id: TrustDomainId,
    /// Public `CA-PQ` key, base64. **Public by definition**, kept in the clear.
    ///
    /// Two other programs need it — `astra bootstrap` and `heliosd
    /// init-trust-domain` — and needing a security key to read a public value
    /// would be absurd. It is checked against the sealed copy every time the
    /// vault is opened, so an edited file is caught at the next unlock rather
    /// than propagated into a trust domain.
    pub ca_pq_public_key: String,
    /// The outgoing `CA-PQ`'s public half, in the clear, while one is kept.
    /// Mirrors the sealed copy and is checked against it at every unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_outgoing_ca_pq_public: Option<OutgoingCaPqPublic>,
    /// WebAuthn RP ID the credentials are registered under. An assertion must
    /// name the same one it was created with, so the vault carries it rather
    /// than asking an operator to remember it.
    pub rp_id: String,
    pub created_at: u64,
    /// Salt handed to `hmac-secret`, base64. Drawn once, for the whole vault.
    pub salt: String,
    pub slots: Vec<KeySlot>,
    /// The anchors, sealed under the master key, base64.
    pub sealed_payload: String,
}

/// What an operator must present to register a new credential.
#[derive(Debug)]
pub struct SlotEnrolment {
    pub role: SlotRole,
    pub label: String,
    /// CTAP2 credential identifier of the authenticator being registered.
    pub credential_id: Vec<u8>,
    /// COSE public key the authenticator attested for this credential.
    ///
    /// Required at enrolment, unlike on [`KeySlot`], where it is defaulted for
    /// files written before bindings existed: a key registered from now on
    /// always has one, so a new slot without a binding cannot be created.
    pub credential_public_key: Vec<u8>,
    pub aaguid: [u8; 16],
    pub enrolled_at: u64,
}

impl SlotEnrolment {
    fn validate(&self) -> Result<()> {
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(VaultError::CredentialIdOutOfBounds);
        }
        if self.credential_public_key.is_empty()
            || self.credential_public_key.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES
        {
            return Err(VaultError::CredentialKeyOutOfBounds);
        }
        if self.label.trim().is_empty() || self.label.chars().count() > MAX_LABEL_CHARS {
            return Err(VaultError::LabelOutOfBounds);
        }
        Ok(())
    }
}

fn encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(value: &str, what: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| VaultError::Corrupt(format!("{what} : base64 illisible")))
}

/// Context binding a slot container to this vault and this slot.
///
/// Both identifiers, so a slot lifted from another vault — or from another
/// slot of the same vault — fails to open rather than yielding someone else's
/// master key.
fn slot_context(vault_id: &[u8; 16], slot_id: &[u8; 16]) -> Context {
    Context::new()
        .field("vault", vault_id)
        .field("slot", slot_id)
}

/// Context binding the payload to this vault, this domain and this exact slot
/// table. See the module header for what the last field buys.
fn payload_context(
    vault_id: &[u8; 16],
    trust_domain_id: &TrustDomainId,
    slots: &Fingerprint,
) -> Context {
    Context::new()
        .field("vault", vault_id)
        .field("domain", trust_domain_id.as_bytes())
        .field("slots", slots.as_bytes())
}

/// Draws vault material from the approved DRBG, with prediction resistance.
///
/// Everything this returns — master key, HVLT salts, vault and slot
/// identifiers — outlives the process that drew it, so it all takes the rule
/// the specification states for a lasting secret rather than the cheaper one
/// for a throwaway identifier.
fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    aether::random::fill_secret(&mut out).map_err(|error| {
        VaultError::Corrupt(format!("générateur approuvé indisponible: {error}"))
    })?;
    Ok(out)
}

/// Draws a vault salt.
///
/// Public because the first slot's secret is derived from it before
/// [`AuthorityVault::create`] can be called at all.
pub fn draw_salt() -> Result<[u8; SALT_LEN]> {
    random_bytes()
}

/// Wraps the master key for one credential.
fn wrap_master(
    vault_id: &[u8; 16],
    slot_id: &[u8; 16],
    secret: &SlotSecret,
    master: &[u8; aether_vault::KEY_LEN],
) -> Result<String> {
    let blob = aether_vault::seal(
        SLOT_DOMAIN,
        &slot_context(vault_id, slot_id),
        &Unlock::Derived {
            ikm: secret.expose(),
            info: SLOT_INFO,
        },
        master,
    )?;
    Ok(encode(&blob))
}

impl AuthorityVault {
    /// Creates a vault around fresh anchors, with its first key-slot.
    ///
    /// One slot, and the vault is **not** bootstrapped yet: see
    /// [`Self::is_bootstrapped`]. Creating it in that state is deliberate —
    /// registering the second authenticator needs the first one to open the
    /// vault, so there is no order in which both arrive at once.
    /// `salt` is drawn by the caller rather than here, and that is forced by
    /// the order of the gestures: the first slot's secret is the token's
    /// `hmac-secret` output **for this salt**, so it has to exist before the
    /// vault does. [`draw_salt`] is what a caller with nothing better should
    /// use.
    pub fn create(
        trust_domain_id: TrustDomainId,
        rp_id: &str,
        salt: [u8; SALT_LEN],
        secrets: &AuthoritySecrets,
        first: SlotEnrolment,
        first_secret: &SlotSecret,
        now_unix: u64,
    ) -> Result<Self> {
        first.validate()?;
        if rp_id.trim().is_empty() {
            return Err(VaultError::Corrupt("RP ID WebAuthn vide".into()));
        }
        let vault_id: [u8; 16] = random_bytes()?;
        let master: [u8; aether_vault::KEY_LEN] = random_bytes()?;
        let mut master = Zeroizing::new(master);

        let slot_id: [u8; 16] = random_bytes()?;
        let wrapped_master = wrap_master(&vault_id, &slot_id, first_secret, &master)?;
        let slots = vec![KeySlot {
            slot_id,
            role: first.role,
            label: first.label,
            credential_id: encode(&first.credential_id),
            credential_public_key: encode(&first.credential_public_key),
            aaguid: first.aaguid,
            enrolled_at: now_unix,
            wrapped_master,
        }];

        let sealed_payload = seal_payload(
            &vault_id,
            &trust_domain_id,
            &slot_table_digest(&slots),
            &master,
            secrets,
        )?;
        master.zeroize();

        Ok(Self {
            format_version: AUTHORITY_VAULT_VERSION,
            vault_id,
            trust_domain_id,
            ca_pq_public_key: secrets.ca_pq_public_key.clone(),
            retained_outgoing_ca_pq_public: secrets
                .retained_outgoing_ca_pq
                .as_ref()
                .map(RetainedOutgoingCaPq::public),
            rp_id: rp_id.to_string(),
            created_at: now_unix,
            salt: encode(&salt),
            slots,
            sealed_payload,
        })
    }

    /// Whether the authority may be used at all (ADR-008 §4).
    ///
    /// A vault with one slot is a trust domain one lost object away from being
    /// gone. The bootstrap is finalised only past this, and the check lives
    /// here so every caller asks the same question.
    pub fn is_bootstrapped(&self) -> bool {
        self.slots.len() >= REQUIRED_SLOTS
    }

    /// The salt every credential of this vault is handed.
    pub fn salt(&self) -> Result<[u8; SALT_LEN]> {
        decode(&self.salt, "sel du coffre")?
            .try_into()
            .map_err(|_| VaultError::Corrupt("sel de longueur inattendue".into()))
    }

    /// Every credential identifier registered, in slot order.
    ///
    /// This is the allow-list an assertion is asked for: the authenticator
    /// picks the one it holds, and its answer names the slot. One touch
    /// resolves both.
    pub fn credential_ids(&self) -> Result<Vec<Vec<u8>>> {
        self.slots
            .iter()
            .map(|slot| decode(&slot.credential_id, "identifiant de credential"))
            .collect()
    }

    pub fn slot(&self, slot_id: &[u8; 16]) -> Result<&KeySlot> {
        self.slots
            .iter()
            .find(|slot| slot.slot_id == *slot_id)
            .ok_or(VaultError::UnknownSlot)
    }

    /// The slot a credential identifier belongs to.
    pub fn slot_for_credential(&self, credential_id: &[u8]) -> Result<&KeySlot> {
        let encoded = encode(credential_id);
        self.slots
            .iter()
            .find(|slot| slot.credential_id == encoded)
            .ok_or(VaultError::UnknownCredential)
    }

    /// Identity of the slot table, as the payload container is bound to it.
    ///
    /// Sorted by slot identifier, so reordering the file changes nothing; over
    /// the wrapped material and the identifiers only, so renaming a key or
    /// changing its operational role never locks anybody out.
    pub fn slot_table_digest(&self) -> Fingerprint {
        slot_table_digest(&self.slots)
    }

    /// Recovers the master key from one slot.
    fn master(
        &self,
        slot_id: &[u8; 16],
        secret: &SlotSecret,
    ) -> Result<Zeroizing<[u8; aether_vault::KEY_LEN]>> {
        if self.format_version != AUTHORITY_VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(self.format_version));
        }
        let slot = self.slot(slot_id)?;
        let blob = decode(&slot.wrapped_master, "key-slot")?;
        let opened = aether_vault::open(
            SLOT_DOMAIN,
            &slot_context(&self.vault_id, slot_id),
            &Unlock::Derived {
                ikm: secret.expose(),
                info: SLOT_INFO,
            },
            &blob,
        )?;
        let master: [u8; aether_vault::KEY_LEN] = opened
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("clé maîtresse de longueur inattendue".into()))?;
        Ok(Zeroizing::new(master))
    }

    /// Opens the private anchors with the credential the authenticator used.
    ///
    /// The returned value zeroizes on drop, and callers must keep it for the
    /// length of one signature. Nothing in Astra ever calls this: the vault
    /// travels through Astra, it does not open there (ADR-008 §4).
    pub fn open(&self, credential_id: &[u8], secret: &SlotSecret) -> Result<AuthoritySecrets> {
        let slot_id = self.slot_for_credential(credential_id)?.slot_id;
        let master = self.master(&slot_id, secret)?;
        self.open_payload(&master)
    }

    fn open_payload(&self, master: &[u8; aether_vault::KEY_LEN]) -> Result<AuthoritySecrets> {
        let blob = decode(&self.sealed_payload, "corps du coffre")?;
        let payload = aether_vault::open(
            PAYLOAD_DOMAIN,
            &payload_context(
                &self.vault_id,
                &self.trust_domain_id,
                &self.slot_table_digest(),
            ),
            &Unlock::Key(master),
            &blob,
        )?;
        let secrets: AuthoritySecrets = serde_json::from_slice(&payload)
            .map_err(|error| VaultError::Corrupt(format!("corps du coffre : {error}")))?;
        // The clear anchor is what two other programs are handed. If it no
        // longer matches the sealed one, someone edited the file — and the
        // whole point of keeping it in the clear is that it is read without a
        // key, so this is the only place the substitution can be caught.
        if secrets.ca_pq_public_key != self.ca_pq_public_key {
            return Err(VaultError::AnchorMismatch);
        }
        let sealed_outgoing = secrets
            .retained_outgoing_ca_pq
            .as_ref()
            .map(RetainedOutgoingCaPq::public);
        if sealed_outgoing != self.retained_outgoing_ca_pq_public {
            return Err(VaultError::AnchorMismatch);
        }
        Ok(secrets)
    }

    /// Registers another authenticator.
    ///
    /// Takes an **opening** credential and its secret, because wrapping the
    /// master key for a new one requires the master key. That is the
    /// specification's rule — «ajouter une clé exige une clé autorisée
    /// existante et la présence de la nouvelle» — enforced by the shape of the
    /// data rather than by a condition someone can forget to write.
    ///
    /// The two touches are on two different devices, and the caller is
    /// expected to have obtained them one at a time.
    pub fn add_slot(
        &mut self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
        enrolment: SlotEnrolment,
        new_secret: &SlotSecret,
    ) -> Result<[u8; 16]> {
        enrolment.validate()?;
        if self.slots.len() >= MAX_SLOTS {
            return Err(VaultError::TooManySlots);
        }
        let credential_id = encode(&enrolment.credential_id);
        if self
            .slots
            .iter()
            .any(|slot| slot.credential_id == credential_id)
        {
            return Err(VaultError::SlotAlreadyPresent);
        }

        let opening_slot = self.slot_for_credential(opening_credential)?.slot_id;
        let master = self.master(&opening_slot, opening_secret)?;
        // The payload must open under the *current* table before the table
        // moves: an operator who cannot read the anchors is not entitled to
        // re-seal them, and this is where a corrupt file says so rather than
        // producing a second unreadable one.
        let secrets = self.open_payload(&master)?;

        let slot_id: [u8; 16] = random_bytes()?;
        let wrapped_master = wrap_master(&self.vault_id, &slot_id, new_secret, &master)?;
        let mut slots = self.slots.clone();
        slots.push(KeySlot {
            slot_id,
            role: enrolment.role,
            label: enrolment.label,
            credential_id,
            credential_public_key: encode(&enrolment.credential_public_key),
            aaguid: enrolment.aaguid,
            enrolled_at: enrolment.enrolled_at,
            wrapped_master,
        });
        self.reseal(slots, &master, &secrets)?;
        Ok(slot_id)
    }

    /// Withdraws an authenticator, never the last recovery.
    ///
    /// Also takes an opening credential: removing a key is an authority
    /// operation, and someone holding only the file must not be able to strip
    /// it down to the one credential they happen to have.
    pub fn remove_slot(
        &mut self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
        removed: &[u8; 16],
    ) -> Result<()> {
        let opening_slot = self.slot_for_credential(opening_credential)?.slot_id;
        let master = self.master(&opening_slot, opening_secret)?;
        let secrets = self.open_payload(&master)?;
        if self.slot(removed).is_err() {
            return Err(VaultError::UnknownSlot);
        }
        if self.slots.len() <= REQUIRED_SLOTS {
            return Err(VaultError::LastRecoverySlot);
        }
        let mut slots = self.slots.clone();
        slots.retain(|slot| slot.slot_id != *removed);
        self.reseal(slots, &master, &secrets)
    }

    /// Replaces the sealed anchors, under the slot table already in place.
    ///
    /// This is what a `CA-PQ` rotation lands (spec §9.1): the key-slots do not
    /// move — every credential that opened the vault before opens it after —
    /// and only the body changes. It takes an opening credential for the same
    /// reason [`Self::add_slot`] does: re-sealing needs the master key, and the
    /// master key needs a slot.
    ///
    /// The clear `ca_pq_public_key` is advanced in the **same** call, so the
    /// copy two other programs read can never describe a different anchor from
    /// the one the body holds.
    pub fn replace_anchors(
        &mut self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
        secrets: &AuthoritySecrets,
    ) -> Result<()> {
        if secrets.ca_pq_private_key.trim().is_empty()
            || secrets.ca_pq_public_key.trim().is_empty()
            || secrets.ca_tls_private_key.trim().is_empty()
        {
            return Err(VaultError::Corrupt(
                "ancres de remplacement incomplètes".into(),
            ));
        }
        let opening_slot = self.slot_for_credential(opening_credential)?.slot_id;
        let master = self.master(&opening_slot, opening_secret)?;
        // The current body must open before it is replaced: an operator who
        // cannot read the anchors is not entitled to overwrite them, and this
        // is where a corrupt file says so rather than producing a second one.
        let current = self.open_payload(&master)?;
        // A `CA-PQ` rotation must carry an open `CA-TLS` window through
        // untouched. Dropping it here would destroy a successor the domain
        // has already been told about, or an outgoing key §9.2 keeps until
        // `not_after` — on an operation that rotates neither.
        if current.retained_ca_tls != secrets.retained_ca_tls {
            return Err(VaultError::Corrupt(
                "le remplacement d'ancre ne conserve pas la fenêtre CA-TLS ouverte".into(),
            ));
        }
        // The same for the outgoing `CA-PQ`: a replacement may keep it or
        // start keeping one, never drop one before « Terminer ».
        if current.retained_outgoing_ca_pq.is_some()
            && current.retained_outgoing_ca_pq != secrets.retained_outgoing_ca_pq
        {
            return Err(VaultError::Corrupt(
                "le remplacement d'ancre ne conserve pas la clé CA-PQ sortante".into(),
            ));
        }
        let slots = self.slots.clone();
        let public_key = secrets.ca_pq_public_key.clone();
        let outgoing = secrets
            .retained_outgoing_ca_pq
            .as_ref()
            .map(RetainedOutgoingCaPq::public);
        self.reseal(slots, &master, secrets)?;
        self.ca_pq_public_key = public_key;
        self.retained_outgoing_ca_pq_public = outgoing;
        Ok(())
    }

    /// Seals the successor of a `CA-TLS` rotation beside the issuing key.
    ///
    /// The issuing key is **not** replaced. §9.4 requires the gateway to be
    /// prepared before anything is issued under the new anchor, and §4.1 puts
    /// an `activation_at` between the two: a vault that swapped at the
    /// ceremony would certify leaves the fleet does not yet accept.
    ///
    /// One window at a time. Two overlapping rotations would leave three
    /// anchors alive, of which the domain's registry names only two, and the
    /// third would be a key nothing can retire.
    pub fn stage_ca_tls_successor(
        &mut self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
        successor: RetainedCaTls,
    ) -> Result<()> {
        if successor.private_key.trim().is_empty()
            || successor.certificate_fingerprint.trim().is_empty()
        {
            return Err(VaultError::Corrupt("successeur CA-TLS incomplet".into()));
        }
        if successor.activation_at >= successor.not_after {
            return Err(VaultError::Corrupt(
                "fenêtre de rotation CA-TLS vide : activation au plus tard au retrait".into(),
            ));
        }
        let opening_slot = self.slot_for_credential(opening_credential)?.slot_id;
        let master = self.master(&opening_slot, opening_secret)?;
        let secrets = self.open_payload(&master)?;
        if secrets.retained_ca_tls.is_some() {
            return Err(VaultError::CaTlsWindowOpen);
        }
        let staged = AuthoritySecrets {
            ca_pq_private_key: secrets.ca_pq_private_key.clone(),
            ca_pq_public_key: secrets.ca_pq_public_key.clone(),
            ca_tls_private_key: secrets.ca_tls_private_key.clone(),
            retained_ca_tls: Some(successor),
            retained_outgoing_ca_pq: secrets.retained_outgoing_ca_pq.clone(),
        };
        let slots = self.slots.clone();
        self.reseal(slots, &master, &staged)
    }

    /// Closes an open `CA-TLS` window at `not_after` (spec §9.2).
    ///
    /// One sealed write does everything: the successor becomes the issuing
    /// key and the outgoing private half ceases to exist. Splitting the two
    /// would allow a restart to find a vault that had destroyed the anchor it
    /// was still issuing under, or one issuing under an anchor it had not yet
    /// stopped calling a successor.
    ///
    /// Idempotent: called before `not_after`, it writes nothing and reports
    /// which second it is waiting for.
    pub fn advance_ca_tls(
        &mut self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
        now_unix: u64,
    ) -> Result<CaTlsAdvance> {
        let opening_slot = self.slot_for_credential(opening_credential)?.slot_id;
        let master = self.master(&opening_slot, opening_secret)?;
        let secrets = self.open_payload(&master)?;
        let Some(retained) = secrets.retained_ca_tls.clone() else {
            return Ok(CaTlsAdvance::Idle);
        };
        if now_unix < retained.not_after {
            return Ok(CaTlsAdvance::Awaiting {
                at: retained.not_after,
            });
        }
        let rotated = AuthoritySecrets {
            ca_pq_private_key: secrets.ca_pq_private_key.clone(),
            ca_pq_public_key: secrets.ca_pq_public_key.clone(),
            ca_tls_private_key: retained.private_key.clone(),
            retained_ca_tls: None,
            retained_outgoing_ca_pq: secrets.retained_outgoing_ca_pq.clone(),
        };
        let slots = self.slots.clone();
        self.reseal(slots, &master, &rotated)?;
        Ok(CaTlsAdvance::Rotated {
            certificate_fingerprint: retained.certificate_fingerprint.clone(),
            destroyed_fingerprint: retained.counterpart_fingerprint.clone(),
        })
    }

    /// Destroys the outgoing `CA-PQ` at `not_after` (spec §9.1), in one sealed
    /// write. Refused before that second, naming it.
    ///
    /// Nothing to retire is not an error: the call writes nothing and returns
    /// `Ok`, so an operator who repeats « Terminer » is not told it failed.
    pub fn retire_outgoing_ca_pq(
        &mut self,
        opening: &crate::authenticator::Opened,
        now_unix: u64,
    ) -> Result<()> {
        let opening_slot = self.slot_for_credential(&opening.credential_id)?.slot_id;
        let master = self.master(&opening_slot, &opening.secret)?;
        let secrets = self.open_payload(&master)?;
        let Some(retained) = secrets.retained_outgoing_ca_pq.as_ref() else {
            return Ok(());
        };
        if now_unix < retained.not_after {
            return Err(VaultError::OutgoingCaPqKept {
                at: retained.not_after,
            });
        }
        let retired = AuthoritySecrets {
            ca_pq_private_key: secrets.ca_pq_private_key.clone(),
            ca_pq_public_key: secrets.ca_pq_public_key.clone(),
            ca_tls_private_key: secrets.ca_tls_private_key.clone(),
            retained_ca_tls: secrets.retained_ca_tls.clone(),
            retained_outgoing_ca_pq: None,
        };
        let slots = self.slots.clone();
        self.reseal(slots, &master, &retired)?;
        self.retained_outgoing_ca_pq_public = None;
        Ok(())
    }

    /// The outgoing `CA-PQ`'s public key, its epoch and its `not_after`, read
    /// without a key. `None` when no rotation is awaiting « Terminer », or when
    /// the clear copy is not a key at all — which the unlock refuses anyway.
    pub fn retained_outgoing_ca_pq_public(&self) -> Option<(MlDsa87PublicKey, u64, u64)> {
        let public = self.retained_outgoing_ca_pq_public.as_ref()?;
        let key = MlDsa87PublicKey::parse(public.public_key.trim()).ok()?;
        Some((key, public.ca_epoch, public.not_after))
    }

    /// What the vault holds beside the issuing `CA-TLS` key, if anything.
    ///
    /// Public material only: the caller learns which window is open and when
    /// it closes, never the key.
    pub fn ca_tls_window(
        &self,
        opening_credential: &[u8],
        opening_secret: &SlotSecret,
    ) -> Result<Option<(String, u64)>> {
        let secrets = self.open(opening_credential, opening_secret)?;
        Ok(secrets
            .retained_ca_tls
            .as_ref()
            .map(|retained| (retained.certificate_fingerprint.clone(), retained.not_after)))
    }

    /// Renames a slot. Never re-seals: the label is outside the digest, which
    /// is exactly so that this needs no authenticator at all.
    pub fn rename_slot(&mut self, slot_id: &[u8; 16], label: &str) -> Result<()> {
        if label.trim().is_empty() || label.chars().count() > MAX_LABEL_CHARS {
            return Err(VaultError::LabelOutOfBounds);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.slot_id == *slot_id)
            .ok_or(VaultError::UnknownSlot)?;
        slot.label = label.to_string();
        Ok(())
    }

    /// Re-seals the payload under a new slot table, then adopts both at once.
    ///
    /// Computed aside and adopted on success, so a sealing failure leaves the
    /// vault exactly as it was rather than carrying a table its body no longer
    /// matches — which is a vault nobody can open.
    fn reseal(
        &mut self,
        slots: Vec<KeySlot>,
        master: &[u8; aether_vault::KEY_LEN],
        secrets: &AuthoritySecrets,
    ) -> Result<()> {
        let sealed_payload = seal_payload(
            &self.vault_id,
            &self.trust_domain_id,
            &slot_table_digest(&slots),
            master,
            secrets,
        )?;
        self.slots = slots;
        self.sealed_payload = sealed_payload;
        Ok(())
    }

    /// Identity of this vault's exact contents, for an operator to record.
    ///
    /// Covers the body **and** the slot table: a vault whose slots were
    /// changed is a different vault, and that is precisely the change worth
    /// noticing on a backup.
    pub fn fingerprint(&self) -> Result<Fingerprint> {
        let canonical =
            serde_json::to_vec(self).map_err(|error| VaultError::Corrupt(error.to_string()))?;
        Ok(Fingerprint::of(&canonical))
    }
}

fn slot_table_digest(slots: &[KeySlot]) -> Fingerprint {
    let mut rows: Vec<(&[u8; 16], &str, &str)> = slots
        .iter()
        .map(|slot| {
            (
                &slot.slot_id,
                slot.credential_id.as_str(),
                slot.wrapped_master.as_str(),
            )
        })
        .collect();
    rows.sort_by(|left, right| left.0.cmp(right.0));

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    for (slot_id, credential_id, wrapped_master) in rows {
        buffer.extend_from_slice(slot_id);
        for field in [credential_id, wrapped_master] {
            buffer.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buffer.extend_from_slice(field.as_bytes());
        }
    }
    Fingerprint::of(&buffer)
}

fn seal_payload(
    vault_id: &[u8; 16],
    trust_domain_id: &TrustDomainId,
    slots: &Fingerprint,
    master: &[u8; aether_vault::KEY_LEN],
    secrets: &AuthoritySecrets,
) -> Result<String> {
    let payload =
        serde_json::to_vec(secrets).map_err(|error| VaultError::Corrupt(error.to_string()))?;
    let mut payload = Zeroizing::new(payload);
    let blob = aether_vault::seal(
        PAYLOAD_DOMAIN,
        &payload_context(vault_id, trust_domain_id, slots),
        &Unlock::Key(master),
        &payload,
    )?;
    payload.zeroize();
    Ok(encode(&blob))
}

/// Fixtures shared by the test modules below.
#[cfg(test)]
mod tests_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ca_tls_window_tests;
