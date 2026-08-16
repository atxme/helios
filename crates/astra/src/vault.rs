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

use aether::certificates::encoding::{Fingerprint, TrustDomainId};
use helios_vault::{Context, Unlock};
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
/// CTAP2 fixes it: the extension takes a 32-byte salt and returns a 32-byte
/// output.
pub const SALT_LEN: usize = 32;

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

/// Largest credential identifier accepted, in bytes.
///
/// CTAP2 credential IDs are typically 32–128 bytes; the ceiling refuses a
/// file that would drive an allocation.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;

/// Longest operator-facing slot label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("coffre d'autorité : {0}")]
    Container(#[from] helios_vault::VaultError),
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
    #[error("contenu du coffre illisible : {0}")]
    Corrupt(String),
}

type Result<T> = std::result::Result<T, VaultError>;

/// Key material an authenticator released for one slot.
///
/// On a real machine this is the CTAP2 `hmac-secret` output for the slot's
/// credential and the vault's salt, obtained with user presence **and** user
/// verification. The type exists so nothing above this boundary can confuse it
/// with a key: it is input to a derivation, never a wrapping key itself.
pub struct SlotSecret(Zeroizing<Vec<u8>>);

impl SlotSecret {
    pub fn new(material: Vec<u8>) -> Self {
        Self(Zeroizing::new(material))
    }
}

impl std::fmt::Debug for SlotSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotSecret(<redacted>)")
    }
}

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
    /// When this credential was registered.
    pub enrolled_at: u64,
    /// The master key, sealed under this slot's wrapping key, base64.
    pub wrapped_master: String,
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
    /// PKCS#8 private key of the client `CA-TLS`, base64.
    pub ca_tls_private_key: String,
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
    pub enrolled_at: u64,
}

impl SlotEnrolment {
    fn validate(&self) -> Result<()> {
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(VaultError::CredentialIdOutOfBounds);
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
    master: &[u8; helios_vault::KEY_LEN],
) -> Result<String> {
    let blob = helios_vault::seal(
        SLOT_DOMAIN,
        &slot_context(vault_id, slot_id),
        &Unlock::Derived {
            ikm: &secret.0,
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
        let master: [u8; helios_vault::KEY_LEN] = random_bytes()?;
        let mut master = Zeroizing::new(master);

        let slot_id: [u8; 16] = random_bytes()?;
        let wrapped_master = wrap_master(&vault_id, &slot_id, first_secret, &master)?;
        let slots = vec![KeySlot {
            slot_id,
            role: first.role,
            label: first.label,
            credential_id: encode(&first.credential_id),
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
    ) -> Result<Zeroizing<[u8; helios_vault::KEY_LEN]>> {
        if self.format_version != AUTHORITY_VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(self.format_version));
        }
        let slot = self.slot(slot_id)?;
        let blob = decode(&slot.wrapped_master, "key-slot")?;
        let opened = helios_vault::open(
            SLOT_DOMAIN,
            &slot_context(&self.vault_id, slot_id),
            &Unlock::Derived {
                ikm: &secret.0,
                info: SLOT_INFO,
            },
            &blob,
        )?;
        let master: [u8; helios_vault::KEY_LEN] = opened
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

    fn open_payload(&self, master: &[u8; helios_vault::KEY_LEN]) -> Result<AuthoritySecrets> {
        let blob = decode(&self.sealed_payload, "corps du coffre")?;
        let payload = helios_vault::open(
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
        master: &[u8; helios_vault::KEY_LEN],
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
    master: &[u8; helios_vault::KEY_LEN],
    secrets: &AuthoritySecrets,
) -> Result<String> {
    let payload =
        serde_json::to_vec(secrets).map_err(|error| VaultError::Corrupt(error.to_string()))?;
    let mut payload = Zeroizing::new(payload);
    let blob = helios_vault::seal(
        PAYLOAD_DOMAIN,
        &payload_context(vault_id, trust_domain_id, slots),
        &Unlock::Key(master),
        &payload,
    )?;
    payload.zeroize();
    Ok(encode(&blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RP_ID: &str = "astra.example";

    fn secrets() -> AuthoritySecrets {
        AuthoritySecrets {
            ca_pq_private_key: "Y2EtcHEtcHJpdmF0ZQ==".into(),
            ca_pq_public_key: "Y2EtcHEtcHVibGlj".into(),
            ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
        }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([3; 16]).expect("domain")
    }

    fn credential(seed: u8) -> Vec<u8> {
        vec![seed; 64]
    }

    fn enrolment(role: SlotRole, seed: u8) -> SlotEnrolment {
        SlotEnrolment {
            role,
            label: format!("clé {seed}"),
            credential_id: credential(seed),
            enrolled_at: 2_000,
        }
    }

    fn material(seed: u8) -> SlotSecret {
        SlotSecret::new(vec![seed; 32])
    }

    fn vault() -> AuthorityVault {
        AuthorityVault::create(
            domain(),
            RP_ID,
            draw_salt().expect("salt"),
            &secrets(),
            enrolment(SlotRole::Primary, 1),
            &material(1),
            1_000,
        )
        .expect("create")
    }

    /// The nominal path: one credential opens the anchors.
    #[test]
    fn a_registered_credential_opens_the_anchors() {
        let vault = vault();
        let opened = vault.open(&credential(1), &material(1)).expect("open");
        assert_eq!(opened, secrets());
    }

    /// Another authenticator's output opens nothing, and the failure is the
    /// AEAD's rather than a comparison this module could get wrong.
    #[test]
    fn another_authenticator_opens_nothing() {
        let vault = vault();
        assert!(vault.open(&credential(1), &material(9)).is_err());
    }

    /// A credential nobody registered is named as such, before any AEAD work.
    #[test]
    fn an_unregistered_credential_is_named() {
        let vault = vault();
        assert!(matches!(
            vault.open(&credential(7), &material(7)),
            Err(VaultError::UnknownCredential)
        ));
    }

    /// A vault with one credential is one lost object away from being a lost
    /// trust domain. The bootstrap is not finalised there.
    #[test]
    fn one_slot_is_not_a_bootstrapped_authority() {
        let mut vault = vault();
        assert!(!vault.is_bootstrapped());

        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("the second credential registers");
        assert!(vault.is_bootstrapped());
    }

    /// Any key opens the vault alone: the recovery one must genuinely recover
    /// the loss of the others (1-of-N, not M-of-N). Including a third, which
    /// the specification allows and an operator eventually buys.
    #[test]
    fn each_slot_opens_the_vault_alone() {
        let mut vault = vault();
        for seed in [2u8, 3, 4] {
            vault
                .add_slot(
                    &credential(1),
                    &material(1),
                    enrolment(SlotRole::Recovery, seed),
                    &material(seed),
                )
                .expect("another credential registers");
        }
        assert_eq!(vault.slots.len(), 4);

        for seed in [1u8, 2, 3, 4] {
            assert_eq!(
                vault
                    .open(&credential(seed), &material(seed))
                    .expect("open"),
                secrets(),
                "credential {seed} opens the vault on its own"
            );
        }
        // And a slot only opens with **its own** material.
        assert!(vault.open(&credential(4), &material(1)).is_err());
    }

    /// A key registered later opens a vault created before it existed: adding
    /// a slot re-seals the body, and every earlier slot must survive that.
    #[test]
    fn adding_a_key_leaves_the_earlier_ones_working() {
        let mut vault = vault();
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("second slot");
        // Registered through the *second* key, which is the case an operator
        // hits after losing the first one and buying a replacement.
        vault
            .add_slot(
                &credential(2),
                &material(2),
                enrolment(SlotRole::Recovery, 3),
                &material(3),
            )
            .expect("third slot, opened by the second");

        assert_eq!(
            vault.open(&credential(1), &material(1)).expect("first"),
            secrets()
        );
        assert_eq!(
            vault.open(&credential(3), &material(3)).expect("third"),
            secrets()
        );
    }

    /// Adding a slot needs the master key, and the master key needs a slot.
    /// Someone holding the file and a fresh YubiKey has nothing to wrap.
    #[test]
    fn a_stranger_cannot_append_a_slot_of_their_own() {
        let mut vault = vault();
        assert!(vault
            .add_slot(
                &credential(1),
                // The file is theirs; the authenticator is not.
                &material(42),
                enrolment(SlotRole::Primary, 3),
                &material(3),
            )
            .is_err());
        assert_eq!(vault.slots.len(), 1);
    }

    /// The same credential twice is one credential, not two recoveries.
    #[test]
    fn a_credential_is_registered_once() {
        let mut vault = vault();
        assert!(matches!(
            vault.add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 1),
                &material(1)
            ),
            Err(VaultError::SlotAlreadyPresent)
        ));
    }

    /// Removing a key may never leave the authority without a recovery.
    #[test]
    fn removing_a_slot_never_leaves_the_authority_alone() {
        let mut vault = vault();
        let second = vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("second slot");

        assert!(matches!(
            vault.remove_slot(&credential(1), &material(1), &second),
            Err(VaultError::LastRecoverySlot)
        ));

        let third = vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 3),
                &material(3),
            )
            .expect("third slot");
        vault
            .remove_slot(&credential(1), &material(1), &third)
            .expect("a third slot may go");
        assert_eq!(vault.slots.len(), 2);
    }

    /// The point of removal: a withdrawn row spliced back from a backup opens
    /// nothing, because the payload is bound to the slot table it left.
    #[test]
    fn a_withdrawn_slot_spliced_back_opens_nothing() {
        let mut vault = vault();
        for seed in [2u8, 3] {
            vault
                .add_slot(
                    &credential(1),
                    &material(1),
                    enrolment(SlotRole::Recovery, seed),
                    &material(seed),
                )
                .expect("another credential registers");
        }
        let withdrawn = vault
            .slot_for_credential(&credential(3))
            .expect("slot")
            .clone();
        vault
            .remove_slot(&credential(1), &material(1), &withdrawn.slot_id)
            .expect("the third slot goes");
        assert!(matches!(
            vault.open(&credential(3), &material(3)),
            Err(VaultError::UnknownCredential)
        ));

        // The attacker puts the row back, byte for byte. It still yields the
        // master key — and the body no longer opens under it.
        vault.slots.push(withdrawn);
        assert!(vault.open(&credential(3), &material(3)).is_err());
        // And the keys that stayed are unaffected by the attempt only once the
        // spliced row is gone: the table is what the body is bound to.
        vault
            .slots
            .retain(|slot| slot.credential_id != encode(&credential(3)));
        assert_eq!(
            vault.open(&credential(1), &material(1)).expect("first"),
            secrets()
        );
    }

    /// Renaming a key is not an authority operation, and must never be one:
    /// the label sits outside the digest on purpose.
    #[test]
    fn renaming_a_slot_does_not_lock_anyone_out() {
        let mut vault = vault();
        let slot_id = vault.slots[0].slot_id;
        vault
            .rename_slot(&slot_id, "YubiKey du bureau")
            .expect("rename");
        assert_eq!(vault.slots[0].label, "YubiKey du bureau");
        assert_eq!(
            vault.open(&credential(1), &material(1)).expect("open"),
            secrets()
        );
    }

    /// A slot lifted from another vault opens nothing here, even with its own
    /// authenticator: the container is bound to both identifiers.
    #[test]
    fn a_slot_from_another_vault_does_not_open_this_one() {
        let mut mine = vault();
        let theirs = vault();
        mine.slots[0].wrapped_master = theirs.slots[0].wrapped_master.clone();
        assert!(mine.open(&credential(1), &material(1)).is_err());
    }

    /// One salt per vault, and two vaults never share it: the same credential
    /// enrolled twice must not derive the same secret.
    #[test]
    fn two_vaults_do_not_share_a_salt() {
        assert_ne!(vault().salt, vault().salt);
        assert_eq!(vault().salt().expect("salt").len(), SALT_LEN);
    }

    /// The allow-list an assertion is asked for names every registered
    /// credential: the authenticator picks the one it holds.
    #[test]
    fn the_allow_list_names_every_registered_credential() {
        let mut vault = vault();
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("second slot");
        assert_eq!(
            vault.credential_ids().expect("ids"),
            vec![credential(1), credential(2)]
        );
    }

    /// Reordering the file is not a change of table: an operator who sorts the
    /// slots by hand must not lock the authority.
    #[test]
    fn reordering_the_slots_is_not_a_change_of_table() {
        let mut vault = vault();
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("second slot");
        let before = vault.slot_table_digest();
        vault.slots.reverse();
        assert_eq!(before, vault.slot_table_digest());
        assert_eq!(
            vault.open(&credential(1), &material(1)).expect("open"),
            secrets()
        );
    }

    /// The fingerprint covers the slot table, not only the body: a backup
    /// whose slots changed is what an operator has to notice.
    #[test]
    fn the_fingerprint_moves_when_a_slot_is_added() {
        let mut vault = vault();
        let before = vault.fingerprint().expect("fingerprint");
        vault
            .add_slot(
                &credential(1),
                &material(1),
                enrolment(SlotRole::Recovery, 2),
                &material(2),
            )
            .expect("second slot");
        assert_ne!(before, vault.fingerprint().expect("fingerprint"));
    }

    /// A credential identifier is bounded before it is decoded: the vault is a
    /// file an attacker may hand over.
    #[test]
    fn an_oversized_credential_identifier_is_refused() {
        let mut vault = vault();
        let mut oversized = enrolment(SlotRole::Recovery, 2);
        oversized.credential_id = vec![0; MAX_CREDENTIAL_ID_BYTES + 1];
        assert!(matches!(
            vault.add_slot(&credential(1), &material(1), oversized, &material(2)),
            Err(VaultError::CredentialIdOutOfBounds)
        ));
    }

    /// A blank label names nothing on an operator's screen, and a long one is
    /// an allocation from a file.
    #[test]
    fn a_label_is_bounded() {
        let mut vault = vault();
        let mut blank = enrolment(SlotRole::Recovery, 2);
        blank.label = "   ".into();
        assert!(matches!(
            vault.add_slot(&credential(1), &material(1), blank, &material(2)),
            Err(VaultError::LabelOutOfBounds)
        ));
    }
    /// The clear anchor is read without a security key, by two other programs.
    /// Editing it must be caught — and the only moment that can happen is when
    /// the sealed copy becomes readable.
    #[test]
    fn an_edited_clear_anchor_is_caught_at_the_next_unlock() {
        let mut vault = vault();
        vault.ca_pq_public_key = "YXV0cmUtYW5jcmU=".into();
        assert!(matches!(
            vault.open(&credential(1), &material(1)),
            Err(VaultError::AnchorMismatch)
        ));
    }

    /// And the nominal case still carries it, since that is what an operator
    /// hands to `astra bootstrap`.
    #[test]
    fn the_clear_anchor_is_the_one_the_vault_seals() {
        let vault = vault();
        assert_eq!(vault.ca_pq_public_key, secrets().ca_pq_public_key);
    }
}
