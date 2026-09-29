//! Conteneur unique des secrets au repos ([ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md)).
//!
//! # Why a single container
//!
//! Before this crate there was **one** encrypted container in the repository
//! (`HKS1`, in `helios-tpm`) and **none** on the Orion side. Adding a second
//! format would have guaranteed the two drift apart, and that a review of one
//! misses the defect in the other. Everything that must survive on a disk goes
//! through here — gateway, client, present and future.
//!
//! # Format
//!
//! ```text
//! HVLT │ ver:u8 │ kdf:u8 │ dom_len:u8 │ ctx_len:u16be
//!      │ domain │ object_context │ salt[16] │ nonce[12] │ ciphertext ‖ tag[16]
//!
//! AAD = "helios-vault/v1" ‖ <tout l'en-tête, de HVLT au nonce inclus>
//! ```
//!
//!
//! `domain` separates **uses**; `object_context` separates **instances of one
//! use**. Without the second, two blobs of the same kind stay interchangeable:
//! Alice's profile could be opened as Bob's under a shared root key. Contexts
//! are built through [`Context`], which length-prefixes every field so that
//! `("ab", "c")` and `("a", "bc")` never collide.
//!
//! The AAD covers **every byte** of the header. A subset would leave the salt
//! malleable: under [`Unlock::Key`] it takes no part in the derivation, so
//! nothing else would bind it — dead but rewritable, and no longer dead the day
//! a future KDF reads it.
//!
//! # What this container does and does not give
//!
//! It gives confidentiality, authenticity and **binding to a context**. It does
//! **not** give freshness: an old but authentic blob still opens. Rollback
//! resistance needs a counter that a restore cannot rewind, and that arbitration
//! is the one still blocked by ADR-002's second amendment. Callers carry a
//! `security_generation` in their own manifest and refuse to go backwards
//! in-process; nothing here claims more.
//!
//! # Bounds, before allocating
//!
//! Every length is validated against the bytes actually held before a single
//! byte is reserved, and [`open_file`] checks the file's size **before** reading
//! it — a bound applied after a `std::fs::read` is a bound that already lost.
//! [`seal`] likewise refuses to produce a blob that [`open`] would reject.
//!
//! # The nonce
//!
//! For a 96-bit random nonce, the birthday approximation `n ≈ sqrt(2 × 2^96 × p)`
//! gives roughly **12.6 billion** invocations for `p = 10⁻⁹`. The operational
//! ceiling is deliberately far lower: a single DEK must never exceed **2³²**
//! seals, and Helios re-derives the DEK on every write. A CSPRNG or derivation
//! failure is fatal — there is no fixed nonce and no counter fallback.

use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    hkdf, pbkdf2,
};
use zeroize::Zeroizing;

/// Distinguishes a vault from any other blob on disk.
const MAGIC: &[u8; 4] = b"HVLT";

/// Format version. Any other value is refused rather than guessed.
const VERSION: u8 = 1;

/// Prefix of the authenticated data. Separates this container from every other
/// use of AES-GCM in the project.
const AAD_PREFIX: &[u8] = b"helios-vault/v1";

/// Salt length. Unused by [`Unlock::Key`], always present so the layout does
/// not depend on the KDF — a variable header is how a parser grows a corner
/// case.
const SALT_LEN: usize = 16;

/// AES-256-GCM tag length.
const TAG_LEN: usize = 16;

/// Fixed part of the header: magic, version, kdf, dom_len, ctx_len.
const FIXED_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 2;

/// Key length: AES-256.
pub const KEY_LEN: usize = 32;

/// Largest vault accepted, checked **before** any allocation.
///
/// A legitimate vault holds a WireGuard key, a PSK map or an identity bundle —
/// tens of kilobytes at the very most. The bound is generous and still refuses
/// to let a forged length drive our memory.
pub const MAX_VAULT_BYTES: usize = 256 * 1024;

/// Longest domain accepted. The field is a `u8`, so this is the type's own
/// bound restated where it is enforced.
pub const MAX_DOMAIN_BYTES: usize = 255;

/// Longest object context accepted.
///
/// Well under the `u16` the field could carry: a context holds identifiers and
/// public keys, not payload. Keeping the practical bound tight is what stops a
/// context from quietly becoming a second storage area.
pub const MAX_CONTEXT_BYTES: usize = 4096;

/// PBKDF2 iteration count for [`Unlock::Passphrase`].
///
/// OWASP publishes a **lower** benchmark for PBKDF2-HMAC-SHA-512 than for
/// SHA-256. Helios keeps 600 000 anyway, and the reason is ergonomic rather
/// than numerological: the passphrase is entered once per session, so the cost
/// is paid once and buys a strictly higher price per guess. It is *not*
/// justified by the naive claim that "512 bits is automatically safer than
/// 256" — what actually decides resistance here is passphrase entropy, the
/// PRF, the output length and above all the measured cost (ADR-006 §3).
///
/// The count is deliberately **not** stored in the header: the `kdf` byte
/// encodes the *whole* parameter set, so the cost cannot be lowered under the
/// same identifier. Raising it mints a new one, which an old binary refuses
/// cleanly instead of silently deriving a different key — and which lets a
/// newer one re-wrap after a successful open.
///
/// A target-only regression checks that 600 000 stays under two seconds on the
/// minimum supported Windows hardware; WSL2 does not measure that.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Key-derivation identifiers. See [`PBKDF2_ITERATIONS`] on why parameters are
/// baked into the identifier rather than stored beside it.
mod kdf {
    /// The caller already holds the 256-bit key (TPM- or DPAPI-unwrapped).
    pub const RAW: u8 = 0;

    /// **Burned.** Briefly meant PBKDF2-HMAC-SHA-256 in an unreleased
    /// revision, and is now permanently refused.
    ///
    /// Reusing it for SHA-512 would have been *technically* safe — nothing ever
    /// persisted a passphrase vault — but it would have made an identifier mean
    /// two different algorithms across two builds. That is exactly the property
    /// the `kdf` byte exists to prevent, and a rule one bends once stops being a
    /// rule. Burning costs one integer.
    pub const BURNED_PBKDF2_HMAC_SHA256: u8 = 1;

    /// PBKDF2-HMAC-SHA-512, 600 000 iterations.
    pub const PBKDF2_HMAC_SHA512: u8 = 2;

    /// HKDF-SHA-256 from caller-supplied input keying material, using the
    /// container's own fresh salt and a caller-supplied `info` label.
    pub const HKDF_SHA256: u8 = 3;
}

/// How the 256-bit AEAD key is obtained.
///
/// **Argon2id was arbitrated away** (ADR-006 §3): PBKDF2 keeps the single
/// crypto engine and the FIPS trajectory. It is genuinely weaker against GPU
/// and ASIC cracking, and the countermeasure is a high-entropy passphrase the
/// UI must require — not a larger iteration count. The choice stays migratable
/// because the `kdf` byte is versioned.
pub enum Unlock<'a> {
    /// A key already held by the caller.
    Key(&'a [u8; KEY_LEN]),
    /// A passphrase, stretched with PBKDF2-HMAC-SHA-512.
    Passphrase(&'a str),
    /// A key derived from other key material this caller already holds.
    ///
    /// For a vault whose key must **live and die with another secret** rather
    /// than with the machine. ADR-006 §4 needs exactly that for the gateway's
    /// static-PSK table: sealing it under the general TPM secret would make it
    /// unrecoverable after a PCR change, since the escrow restores only the
    /// WireGuard identity. Deriving it from that identity instead ties the two
    /// together — the table survives a resealing if and only if the identity
    /// does.
    ///
    /// The salt is the container's own, drawn fresh at every seal, so two
    /// vaults sealed from the same `ikm` never share a key. `info` separates
    /// uses and is a caller-side constant, reproduced at open time exactly as
    /// the domain is.
    Derived {
        /// Input keying material. **Secret** — it is another secret's bytes.
        ikm: &'a [u8],
        /// Domain label of this derivation, e.g. `b"helios/static-psk-map/v1"`.
        info: &'a [u8],
    },
}

impl Unlock<'_> {
    fn id(&self) -> u8 {
        match self {
            Self::Key(_) => kdf::RAW,
            Self::Passphrase(_) => kdf::PBKDF2_HMAC_SHA512,
            Self::Derived { .. } => kdf::HKDF_SHA256,
        }
    }
}

/// Canonical, unambiguous object context.
///
/// The context answers "**which** instance of this use", and it is compared
/// byte for byte. Building it by concatenating strings would make
/// `("ab", "c")` and `("a", "bc")` the same value — and two profiles
/// interchangeable. Every field is therefore length-prefixed: a one-byte label
/// length, the label, a four-byte value length, the value.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct Context(Vec<u8>);

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a labelled field. Order is part of the value: two contexts with
    /// the same fields in a different order are different contexts.
    #[must_use]
    pub fn field(mut self, label: &str, value: &[u8]) -> Self {
        let label = label.as_bytes();
        // Labels are compile-time constants in this codebase; truncating one
        // silently would be worse than the assertion a caller gets from an
        // over-long context at seal time.
        self.0.push(label.len().min(u8::MAX as usize) as u8);
        self.0
            .extend_from_slice(&label[..label.len().min(u8::MAX as usize)]);
        self.0
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rebuilds a context from bytes **already** produced by [`Self::field`].
    ///
    /// Only for the peek-then-open flow, where the context is read from a blob
    /// and handed straight back to [`open`] so the AEAD can authenticate it.
    /// Passing arbitrary bytes here defeats the canonical encoding, which is
    /// why nothing else in the codebase should call it.
    pub fn from_encoded(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&Context> for Vec<u8> {
    fn from(context: &Context) -> Self {
        context.0.clone()
    }
}

/// Everything that can go wrong, kept distinct because the operator acts
/// differently on each.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault larger than the {MAX_VAULT_BYTES} byte bound: {0} bytes")]
    TooLarge(u64),
    #[error("truncated vault: {0}")]
    Truncated(&'static str),
    #[error("not a Helios vault (bad magic)")]
    BadMagic,
    #[error("unsupported vault version {0} — this binary writes version {VERSION}")]
    UnsupportedVersion(u8),
    #[error("unsupported key derivation {0}")]
    UnsupportedKdf(u8),
    #[error(
        "key derivation {0} was withdrawn from the format and is permanently refused — \
         this vault predates a deliberate change, it is not corrupt"
    )]
    BurnedKdf(u8),
    #[error("domain longer than {MAX_DOMAIN_BYTES} bytes")]
    DomainTooLong,
    #[error("object context longer than {MAX_CONTEXT_BYTES} bytes")]
    ContextTooLong,
    #[error("vault sealed for domain « {found} », opened as « {expected} »")]
    DomainMismatch { expected: String, found: String },
    #[error(
        "vault sealed for another object — a blob of one profile, peer or machine \
         is never openable as another"
    )]
    ContextMismatch,
    #[error(
        "vault sealed with another unlock method — a passphrase and a key are not interchangeable"
    )]
    UnlockMismatch,
    #[error(
        "vault undecryptable: wrong key or passphrase, or the content was altered. \
         Nothing is guessed here — the two cases are indistinguishable by design"
    )]
    Undecipherable,
    #[error("key derivation failed")]
    Derive,
    #[error("system CSPRNG unavailable")]
    Rng,
    #[error("reading {path}: {cause}")]
    Io { path: PathBuf, cause: String },
}

type Result<T> = std::result::Result<T, VaultError>;

/// Encrypts `plaintext` for `domain` and `context`.
///
/// Refuses to produce anything [`open`] would reject: a caller must not
/// discover at read time that what it wrote is unreadable.
pub fn seal(
    domain: &str,
    context: &Context,
    unlock: &Unlock<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let domain_bytes = domain.as_bytes();
    let context_bytes = context.as_bytes();
    if domain_bytes.len() > MAX_DOMAIN_BYTES {
        return Err(VaultError::DomainTooLong);
    }
    if context_bytes.len() > MAX_CONTEXT_BYTES {
        return Err(VaultError::ContextTooLong);
    }
    let total = header_len(domain_bytes.len(), context_bytes.len()) + plaintext.len() + TAG_LEN;
    if total > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge(total as u64));
    }
    let kdf_id = unlock.id();

    // Salt and nonce come from the approved DRBG with prediction resistance:
    // both are sealed into a file that outlives the process, and a repeated
    // nonce under one key is what breaks AES-GCM outright.
    let mut salt = [0u8; SALT_LEN];
    aether::random::fill_secret(&mut salt).map_err(|_| VaultError::Rng)?;
    let mut nonce = [0u8; NONCE_LEN];
    aether::random::fill_secret(&mut nonce).map_err(|_| VaultError::Rng)?;

    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(MAGIC);
    blob.push(VERSION);
    blob.push(kdf_id);
    blob.push(domain_bytes.len() as u8);
    blob.extend_from_slice(&(context_bytes.len() as u16).to_be_bytes());
    blob.extend_from_slice(domain_bytes);
    blob.extend_from_slice(context_bytes);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);

    let key = derive(unlock, &salt)?;
    // `Zeroizing`, like the open path: `seal_in_place_append_tag` needs an owned
    // buffer, so this copy holds the plaintext for the length of the call. A
    // plain `Vec` would leave it in a freed, unwiped allocation — the very
    // remanence ADR-006 §5 puts on the buffers, not only on the types.
    let mut in_out = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(&blob)),
        &mut *in_out,
    )
    .map_err(|_| VaultError::Undecipherable)?;

    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Decrypts a vault, checking it was sealed for `domain` **and** `context`.
///
/// The returned plaintext is [`Zeroizing`]: it is wiped when it leaves scope,
/// which is the whole reason callers must not copy it into a plain `Vec` or
/// `String`.
pub fn open(
    domain: &str,
    context: &Context,
    unlock: &Unlock<'_>,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let parsed = parse(blob)?;
    if parsed.domain != domain.as_bytes() {
        return Err(VaultError::DomainMismatch {
            expected: domain.to_string(),
            found: String::from_utf8_lossy(parsed.domain).into_owned(),
        });
    }
    // Named rather than left to the tag: "this blob belongs to another profile"
    // and "this blob is corrupt" call for entirely different actions.
    if parsed.context != context.as_bytes() {
        return Err(VaultError::ContextMismatch);
    }
    if parsed.kdf_id != unlock.id() {
        return Err(VaultError::UnlockMismatch);
    }

    let key = derive(unlock, &parsed.salt)?;
    let mut in_out = Zeroizing::new(blob[parsed.header_len..].to_vec());
    let length = key
        .open_in_place(
            Nonce::assume_unique_for_key(parsed.nonce),
            Aad::from(aad(&blob[..parsed.header_len])),
            in_out.as_mut(),
        )
        // Wrong key and tampered content are indistinguishable, and must stay
        // so: telling them apart would answer a question an attacker asked.
        .map_err(|_| VaultError::Undecipherable)?
        .len();
    // `open_in_place` returns a prefix of the very buffer handed in. Truncating
    // it keeps the plaintext in the `Zeroizing` allocation instead of copying it
    // into a second one that nothing would wipe (ADR-006 §5).
    in_out.truncate(length);
    Ok(in_out)
}

/// Reads the object context of a blob **without authenticating it**.
///
/// For the one flow where the expected context cannot be known in advance: open
/// the vault, derive the identity from the recovered secret, and compare. The
/// value returned here is attacker-controlled until [`open`] has succeeded with
/// it — never act on it before that.
pub fn peek_context(blob: &[u8]) -> Result<Vec<u8>> {
    Ok(parse(blob)?.context.to_vec())
}

/// Reads a vault file into memory, bounding the read **before** it happens.
///
/// The one entry point for getting a vault off a disk. It is public because
/// [`open_file`] cannot serve every caller: the static-PSK table has to
/// [`peek_context`] its blob before it can name the context to open it with,
/// and a caller that reached for `std::fs::read` to do so would reintroduce
/// exactly the unbounded allocation this function exists to prevent.
///
/// The size is checked on the metadata, then the read is itself capped: a file
/// that grows between the two, or a sparse file that costs nothing to create
/// and everything to read, is refused rather than allocated.
pub fn read_file_bounded(path: &Path) -> Result<Vec<u8>> {
    let io = |cause: std::io::Error| VaultError::Io {
        path: path.to_path_buf(),
        cause: cause.to_string(),
    };
    let metadata = std::fs::metadata(path).map_err(io)?;
    if metadata.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::TooLarge(metadata.len()));
    }
    let file = File::open(path).map_err(io)?;
    let mut blob = Vec::with_capacity(metadata.len().min(MAX_VAULT_BYTES as u64) as usize);
    // `take` and not a bare `read_to_end`: the metadata check above is a
    // time-of-check, this is the time-of-use.
    file.take(MAX_VAULT_BYTES as u64 + 1)
        .read_to_end(&mut blob)
        .map_err(io)?;
    if blob.len() > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge(blob.len() as u64));
    }
    Ok(blob)
}

/// Opens a vault stored at `path`, bounding the read **before** it happens.
pub fn open_file(
    path: &Path,
    domain: &str,
    context: &Context,
    unlock: &Unlock<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    open(domain, context, unlock, &read_file_bounded(path)?)
}

/// Header fields, all bounds already checked.
struct Parsed<'a> {
    kdf_id: u8,
    domain: &'a [u8],
    context: &'a [u8],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    header_len: usize,
}

fn parse(blob: &[u8]) -> Result<Parsed<'_>> {
    if blob.len() > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge(blob.len() as u64));
    }
    if blob.len() < FIXED_HEADER_LEN {
        return Err(VaultError::Truncated("header"));
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    let version = blob[4];
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let kdf_id = blob[5];
    // A withdrawn identifier is named as such: "refused because we changed our
    // mind" and "refused because the file is damaged" call for very different
    // reactions from whoever reads the log.
    if kdf_id == kdf::BURNED_PBKDF2_HMAC_SHA256 {
        return Err(VaultError::BurnedKdf(kdf_id));
    }
    if kdf_id != kdf::RAW && kdf_id != kdf::PBKDF2_HMAC_SHA512 && kdf_id != kdf::HKDF_SHA256 {
        return Err(VaultError::UnsupportedKdf(kdf_id));
    }
    let domain_len = blob[6] as usize;
    let context_len = u16::from_be_bytes([blob[7], blob[8]]) as usize;
    if context_len > MAX_CONTEXT_BYTES {
        return Err(VaultError::ContextTooLong);
    }
    let header_len = header_len(domain_len, context_len);
    // Both declared lengths are attacker-controlled: this is the check that
    // turns a lying byte into a clean error instead of a panic.
    if blob.len() < header_len + TAG_LEN {
        return Err(VaultError::Truncated("domain, context, salt, nonce or tag"));
    }

    let domain_at = FIXED_HEADER_LEN;
    let context_at = domain_at + domain_len;
    let salt_at = context_at + context_len;
    let nonce_at = salt_at + SALT_LEN;
    Ok(Parsed {
        kdf_id,
        domain: &blob[domain_at..context_at],
        context: &blob[context_at..salt_at],
        salt: blob[salt_at..nonce_at]
            .try_into()
            .map_err(|_| VaultError::Truncated("salt"))?,
        nonce: blob[nonce_at..header_len]
            .try_into()
            .map_err(|_| VaultError::Truncated("nonce"))?,
        header_len,
    })
}

fn header_len(domain_len: usize, context_len: usize) -> usize {
    FIXED_HEADER_LEN + domain_len + context_len + SALT_LEN + NONCE_LEN
}

/// Authenticated data: the prefix followed by the **whole header**.
fn aad(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + header.len());
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(header);
    aad
}

fn derive(unlock: &Unlock<'_>, salt: &[u8; SALT_LEN]) -> Result<LessSafeKey> {
    let material = derive_key_material(unlock, salt)?;
    let unbound =
        UnboundKey::new(&AES_256_GCM, material.as_ref()).map_err(|_| VaultError::Derive)?;
    Ok(LessSafeKey::new(unbound))
}

/// Split out from [`derive`] so a known-answer test can pin the PRF and the
/// iteration count, which the round-trip tests cannot: they would pass just as
/// well with any other consistent KDF.
fn derive_key_material(
    unlock: &Unlock<'_>,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let material: Zeroizing<[u8; KEY_LEN]> = match unlock {
        Unlock::Key(key) => Zeroizing::new(**key),
        Unlock::Passphrase(passphrase) => {
            let mut derived = Zeroizing::new([0u8; KEY_LEN]);
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA512,
                std::num::NonZeroU32::new(PBKDF2_ITERATIONS).ok_or(VaultError::Derive)?,
                salt,
                passphrase.as_bytes(),
                derived.as_mut(),
            );
            derived
        }
        Unlock::Derived { ikm, info } => {
            // The container's own fresh salt, so two vaults sealed from the
            // same input keying material never share a key — which is what
            // makes re-sealing under an unchanged identity safe.
            let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
            let mut derived = Zeroizing::new([0u8; KEY_LEN]);
            prk.expand(&[info], hkdf::HKDF_SHA256)
                .map_err(|_| VaultError::Derive)?
                .fill(derived.as_mut())
                .map_err(|_| VaultError::Derive)?;
            derived
        }
    };
    Ok(material)
}

#[cfg(test)]
mod tests;
