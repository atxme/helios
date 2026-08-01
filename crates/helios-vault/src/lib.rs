//! Conteneur unique des secrets au repos ([ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md)).
//!
//! # Why a single container
//!
//! Before this crate there was **one** encrypted container in the repository
//! (`HKS1`, in `helio-tpm`) and **none** on the Orion side. Adding a second
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
    rand::{SecureRandom as _, SystemRandom},
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

    let random = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    random.fill(&mut salt).map_err(|_| VaultError::Rng)?;
    let mut nonce = [0u8; NONCE_LEN];
    random.fill(&mut nonce).map_err(|_| VaultError::Rng)?;

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
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(&blob)),
        &mut in_out,
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

/// Opens a vault stored at `path`, bounding the read **before** it happens.
///
/// The size is checked on the metadata, then the read is itself capped: a file
/// that grows between the two, or a sparse file that costs nothing to create
/// and everything to read, is refused rather than allocated.
pub fn open_file(
    path: &Path,
    domain: &str,
    context: &Context,
    unlock: &Unlock<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
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
    open(domain, context, unlock, &blob)
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
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];
    const DOMAIN: &str = "orion.profile";

    fn key_unlock() -> Unlock<'static> {
        Unlock::Key(&KEY)
    }

    fn context(id: &str) -> Context {
        Context::new().field("profile_id", id.as_bytes())
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-vault-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    #[test]
    fn a_sealed_secret_comes_back_identical() {
        let secret = b"cHJpdmF0ZS1rZXktYmFzZTY0";
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), secret).expect("seal");
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "the sealed blob still contains the plaintext"
        );
        assert_eq!(
            open(DOMAIN, &ctx, &key_unlock(), &blob)
                .expect("open")
                .as_slice(),
            secret
        );
    }

    #[test]
    fn two_seals_of_the_same_secret_differ() {
        let ctx = context("alice");
        let a = seal(DOMAIN, &ctx, &key_unlock(), b"same").expect("seal a");
        let b = seal(DOMAIN, &ctx, &key_unlock(), b"same").expect("seal b");
        assert_ne!(a, b);
    }

    /// The property `object_context` exists for: under a shared root key, two
    /// blobs of the same kind must not be interchangeable.
    #[test]
    fn a_blob_of_another_object_is_refused() {
        let blob = seal(DOMAIN, &context("alice"), &key_unlock(), b"secret").expect("seal");
        assert!(matches!(
            open(DOMAIN, &context("bob"), &key_unlock(), &blob),
            Err(VaultError::ContextMismatch)
        ));
    }

    /// Length prefixing is what makes the context unambiguous: without it,
    /// `("ab","c")` and `("a","bc")` would be the same bytes.
    #[test]
    fn context_fields_cannot_be_confused_by_concatenation() {
        let a = Context::new().field("k", b"ab").field("l", b"c");
        let b = Context::new().field("k", b"a").field("l", b"bc");
        assert_ne!(a.as_bytes(), b.as_bytes());

        let blob = seal(DOMAIN, &a, &key_unlock(), b"secret").expect("seal");
        assert!(matches!(
            open(DOMAIN, &b, &key_unlock(), &blob),
            Err(VaultError::ContextMismatch)
        ));
    }

    #[test]
    fn context_field_order_matters() {
        let a = Context::new().field("x", b"1").field("y", b"2");
        let b = Context::new().field("y", b"2").field("x", b"1");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn a_context_rewritten_in_the_blob_fails_the_tag() {
        let mut blob = seal(DOMAIN, &context("aaaaa"), &key_unlock(), b"secret").expect("seal");
        let at = FIXED_HEADER_LEN + DOMAIN.len();
        let ctx = context("aaaaa");
        let replacement = context("bbbbb");
        assert_eq!(ctx.as_bytes().len(), replacement.as_bytes().len());
        blob[at..at + replacement.as_bytes().len()].copy_from_slice(replacement.as_bytes());
        assert!(matches!(
            open(DOMAIN, &replacement, &key_unlock(), &blob),
            Err(VaultError::Undecipherable)
        ));
    }

    #[test]
    fn peek_context_reads_the_declared_context() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        assert_eq!(peek_context(&blob).expect("peek"), ctx.as_bytes());
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        let other = [8u8; KEY_LEN];
        assert!(matches!(
            open(DOMAIN, &ctx, &Unlock::Key(&other), &blob),
            Err(VaultError::Undecipherable)
        ));
    }

    #[test]
    fn a_substituted_domain_is_refused() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        assert!(matches!(
            open("helios.gateway.wg-key", &ctx, &key_unlock(), &blob),
            Err(VaultError::DomainMismatch { .. })
        ));
    }

    #[test]
    fn an_unknown_version_is_refused_not_guessed() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[4] = 99;
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::UnsupportedVersion(99))
        ));
    }

    /// The withdrawn identifier must never be silently reinterpreted.
    ///
    /// This is the whole point of burning it: a vault written when `1` meant
    /// SHA-256 fails with a message saying so, instead of being handed to
    /// SHA-512 and producing an `Undecipherable` that looks like corruption.
    #[test]
    fn the_burned_kdf_is_refused_and_named() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[5] = kdf::BURNED_PBKDF2_HMAC_SHA256;
        let error = open(DOMAIN, &ctx, &key_unlock(), &blob).unwrap_err();
        assert!(
            matches!(error, VaultError::BurnedKdf(1)),
            "obtained: {error}"
        );
    }

    /// No live identifier may collide with the burned one.
    #[test]
    fn no_live_kdf_reuses_the_burned_identifier() {
        assert_ne!(kdf::RAW, kdf::BURNED_PBKDF2_HMAC_SHA256);
        assert_ne!(kdf::PBKDF2_HMAC_SHA512, kdf::BURNED_PBKDF2_HMAC_SHA256);
        assert_ne!(kdf::HKDF_SHA256, kdf::BURNED_PBKDF2_HMAC_SHA256);
        assert_eq!(
            Unlock::Passphrase("x").id(),
            kdf::PBKDF2_HMAC_SHA512,
            "the passphrase path must not write the burned identifier"
        );
    }

    #[test]
    fn an_unknown_kdf_is_refused() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[5] = 42;
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::UnsupportedKdf(42))
        ));
    }

    #[test]
    fn bad_magic_is_refused() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[0] = b'X';
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::BadMagic)
        ));
    }

    #[test]
    fn a_lying_context_length_does_not_panic() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[7] = 0xff;
        blob[8] = 0xff;
        let error = open(DOMAIN, &ctx, &key_unlock(), &blob).unwrap_err();
        assert!(
            matches!(error, VaultError::ContextTooLong | VaultError::Truncated(_)),
            "obtained: {error}"
        );
    }

    #[test]
    fn a_lying_domain_length_does_not_panic() {
        let ctx = context("alice");
        let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        blob[6] = 255;
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::Truncated(_))
        ));
    }

    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"a reasonably long secret").expect("seal");
        for cut in 0..blob.len() {
            open(DOMAIN, &ctx, &key_unlock(), &blob[..cut])
                .expect_err("a truncated vault must never open");
        }
    }

    /// Header, context, ciphertext and tag in one sweep. Would catch an AAD
    /// that stopped covering a field.
    #[test]
    fn flipping_any_byte_is_refused() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret payload").expect("seal");
        for index in 0..blob.len() {
            let mut altered = blob.clone();
            altered[index] ^= 0xff;
            assert!(
                open(DOMAIN, &ctx, &key_unlock(), &altered).is_err(),
                "byte {index} altered and the vault still opened"
            );
        }
    }

    #[test]
    fn a_vault_over_the_bound_is_refused_before_parsing() {
        let oversized = vec![0u8; MAX_VAULT_BYTES + 1];
        assert!(matches!(
            open(DOMAIN, &context("alice"), &key_unlock(), &oversized),
            Err(VaultError::TooLarge(_))
        ));
    }

    /// `seal` must not produce what `open` would reject: discovering that at
    /// read time would mean a secret written and lost.
    #[test]
    fn seal_refuses_what_open_could_not_read() {
        let plaintext = vec![0u8; MAX_VAULT_BYTES];
        assert!(matches!(
            seal(DOMAIN, &context("alice"), &key_unlock(), &plaintext),
            Err(VaultError::TooLarge(_))
        ));
    }

    #[test]
    fn a_context_over_the_bound_is_refused() {
        let ctx = Context::new().field("blob", &vec![0u8; MAX_CONTEXT_BYTES]);
        assert!(matches!(
            seal(DOMAIN, &ctx, &key_unlock(), b"secret"),
            Err(VaultError::ContextTooLong)
        ));
    }

    #[test]
    fn a_domain_over_the_bound_is_refused() {
        let domain = "d".repeat(MAX_DOMAIN_BYTES + 1);
        assert!(matches!(
            seal(&domain, &context("alice"), &key_unlock(), b"secret"),
            Err(VaultError::DomainTooLong)
        ));
    }

    #[test]
    fn an_empty_secret_round_trips() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"").expect("seal");
        assert!(open(DOMAIN, &ctx, &key_unlock(), &blob)
            .expect("open")
            .is_empty());
    }

    #[test]
    fn a_passphrase_round_trips() {
        let unlock = Unlock::Passphrase("correcte batterie agrafe cheval quinze");
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal");
        assert_eq!(
            open(DOMAIN, &ctx, &unlock, &blob).expect("open").as_slice(),
            b"secret"
        );
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &Unlock::Passphrase("bonne"), b"secret").expect("seal");
        assert!(matches!(
            open(DOMAIN, &ctx, &Unlock::Passphrase("mauvaise"), &blob),
            Err(VaultError::Undecipherable)
        ));
    }

    #[test]
    fn the_unlock_method_must_match() {
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &Unlock::Passphrase("phrase"), b"secret").expect("seal");
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::UnlockMismatch)
        ));
    }

    /// Pins the PRF **and** the iteration count.
    ///
    /// Every other passphrase test would pass unchanged if the KDF silently
    /// became SHA-256, or if the count were lowered — seal and open would
    /// simply agree with each other. This vector does not: it is
    /// `PBKDF2-HMAC-SHA-512(passphrase, salt, 600 000, 32)` computed
    /// independently. ADR-006 §3 requires the `kdf` identifier to bind the
    /// whole parameter set; this is what makes that binding real.
    #[test]
    fn the_passphrase_kdf_matches_its_reference_vector() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
        let expected =
            hex_to_bytes("4047acfe6d63e30a1f0f135f1c1c2c1d581492cdd2697405c8d7bdd1070eb0a0");
        let derived = derive_key_material(
            &Unlock::Passphrase("correcte batterie agrafe cheval quinze"),
            &salt,
        )
        .expect("derive");
        assert_eq!(
            derived.as_ref(),
            expected.as_slice(),
            "the passphrase KDF is no longer PBKDF2-HMAC-SHA-512 at {PBKDF2_ITERATIONS} iterations"
        );

        // And the SHA-256 output of the same inputs, so a swap is caught with
        // a message naming the culprit rather than a bare mismatch.
        let sha256 =
            hex_to_bytes("8773d7bfacbcb6bb09182f5328c73f1db9e866aa949aff13a02cb615397e38b6");
        assert_ne!(
            derived.as_ref(),
            sha256.as_slice(),
            "the KDF fell back to SHA-256"
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    const PSK_MAP_INFO: &[u8] = b"helios/static-psk-map/v1";

    fn derived_unlock(ikm: &[u8]) -> Unlock<'_> {
        Unlock::Derived {
            ikm,
            info: PSK_MAP_INFO,
        }
    }

    #[test]
    fn a_derived_key_round_trips() {
        let ikm = [9u8; 32];
        let ctx = context("gateway");
        let blob = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal");
        assert_eq!(
            open(DOMAIN, &ctx, &derived_unlock(&ikm), &blob)
                .expect("open")
                .as_slice(),
            b"table"
        );
    }

    /// The property ADR-006 §4 relies on: the vault lives and dies with the
    /// key material it was derived from. Another identity opens nothing.
    #[test]
    fn another_input_keying_material_opens_nothing() {
        let ctx = context("gateway");
        let blob = seal(DOMAIN, &ctx, &derived_unlock(&[9u8; 32]), b"table").expect("seal");
        assert!(matches!(
            open(DOMAIN, &ctx, &derived_unlock(&[8u8; 32]), &blob),
            Err(VaultError::Undecipherable)
        ));
    }

    /// `info` separates uses: the same material under another label is another
    /// key, so a PSK table cannot be opened as anything else.
    #[test]
    fn another_info_label_opens_nothing() {
        let ikm = [9u8; 32];
        let ctx = context("gateway");
        let blob = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal");
        let other = Unlock::Derived {
            ikm: &ikm,
            info: b"helios/autre-usage/v1",
        };
        assert!(matches!(
            open(DOMAIN, &ctx, &other, &blob),
            Err(VaultError::Undecipherable)
        ));
    }

    /// Two seals of the same material must not share a key: the container's
    /// fresh salt is what makes re-sealing safe.
    #[test]
    fn two_derived_seals_use_different_salts() {
        let ikm = [9u8; 32];
        let ctx = context("gateway");
        let a = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal a");
        let b = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal b");
        let salt_at = FIXED_HEADER_LEN + DOMAIN.len() + ctx.as_bytes().len();
        assert_ne!(
            a[salt_at..salt_at + SALT_LEN],
            b[salt_at..salt_at + SALT_LEN]
        );
    }

    #[test]
    fn a_derived_vault_is_not_openable_with_a_raw_key() {
        let ctx = context("gateway");
        let blob = seal(DOMAIN, &ctx, &derived_unlock(&[9u8; 32]), b"table").expect("seal");
        assert!(matches!(
            open(DOMAIN, &ctx, &key_unlock(), &blob),
            Err(VaultError::UnlockMismatch)
        ));
    }

    /// Pins the PRF, the salt placement and the `info` handling against an
    /// implementation written outside this crate. A round trip would agree
    /// with itself under any consistent KDF.
    #[test]
    fn the_derived_kdf_matches_its_reference_vector() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
        let derived = derive_key_material(&derived_unlock(&[9u8; 32]), &salt).expect("derive");
        assert_eq!(
            derived.as_ref(),
            hex_to_bytes("78934c37a46e3380f05143199ac623e8acc02236d6ccc24528d5a6210a8804e1")
                .as_slice(),
            "the derived KDF is no longer HKDF-SHA-256 over the container salt"
        );
    }

    #[test]
    fn two_passphrase_seals_use_different_salts() {
        let unlock = Unlock::Passphrase("phrase");
        let ctx = context("alice");
        let a = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal a");
        let b = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal b");
        let salt_at = FIXED_HEADER_LEN + DOMAIN.len() + ctx.as_bytes().len();
        assert_ne!(
            a[salt_at..salt_at + SALT_LEN],
            b[salt_at..salt_at + SALT_LEN]
        );
    }

    #[test]
    fn a_file_round_trips() {
        let dir = tmp_dir("file");
        let path = dir.join("vault.hvlt");
        let ctx = context("alice");
        let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
        std::fs::write(&path, &blob).unwrap();
        assert_eq!(
            open_file(&path, DOMAIN, &ctx, &key_unlock())
                .expect("open_file")
                .as_slice(),
            b"secret"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bound must live in the **file reader**, not only in the in-memory
    /// parser. A sparse file costs nothing to create and everything to read:
    /// checking after a `std::fs::read` is a bound that already lost.
    #[test]
    fn a_sparse_file_over_the_bound_is_refused_without_reading_it() {
        let dir = tmp_dir("sparse");
        let path = dir.join("huge.hvlt");
        let file = File::create(&path).unwrap();
        // Two gigabytes that occupy no blocks. A `read_to_end` here would try
        // to allocate all of it.
        file.set_len(2 * 1024 * 1024 * 1024).unwrap();
        drop(file);

        assert!(matches!(
            open_file(&path, DOMAIN, &context("alice"), &key_unlock()),
            Err(VaultError::TooLarge(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_reports_its_path() {
        let dir = tmp_dir("missing");
        let path = dir.join("absent.hvlt");
        assert!(matches!(
            open_file(&path, DOMAIN, &context("alice"), &key_unlock()),
            Err(VaultError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
