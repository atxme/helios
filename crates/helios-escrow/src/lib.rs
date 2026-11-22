//! WireGuard key escrow held by the operator, to survive a PCR change.
//!
//! # The problem
//!
//! A resealing generates a **new** TPM secret; the old one is unrecoverable by
//! construction. The vault encrypted with the old one becomes undecipherable,
//! and the WireGuard key is lost. Without a key, no tunnel — hence no API,
//! which lives behind the tunnel. The gateway becomes unreachable remotely.
//!
//! This does not happen on every OTA. Sealing covers PCR 0/4/7 — firmware,
//! boot chain, and Secure Boot. Replacing the `heliosd` binary touches none of
//! the three: unseal succeeds and the key survives. A new kernel/initrd,
//! bootloader, firmware update, or Secure Boot key change moves these PCRs.
//!
//! # The security boundary
//!
//! If the gateway could recover on its own after a PCR change, TPM protection
//! would be worthless: an attacker who replaces the kernel would obtain the
//! key through the same path. Recovery therefore requires an element held by
//! the operator. The gateway can seal to the operator's public key, but it
//! cannot open what it sealed because it never has the corresponding private
//! key.
//!
//! # The mechanism
//!
//! ```text
//! Under normal operation:
//! WireGuard key ──encrypted to the escrow public key──► wg-key.escrow (HESC v2)
//!                 + counter and gateway public key, in clear and authenticated
//!                        (only the operator can open it)
//!
//! After a PCR change, offline, with the operator's private key:
//! 1. prepare: open the escrow, read the counter and public key, and produce
//!    the request the publisher signs. The private key is never output.
//! 2. The publisher signs that request (`helios-publisher wg-recovery`).
//! 3. assemble: reopen the escrow, verify the signed authorization, and get
//!    the recovery frame. The gateway consumes it, reseals the key under the
//!    new TPM secret, then erases the file.
//! ```
//!
//! The two operations live in [`recovery`]. The key never passes through an
//! intermediate file between them.
//!
//! No SSH is required: the key travels with the OTA, like the reseal ticket.
//!
//! # Bounded exposure
//!
//! The recovery file contains the key **in the clear** for the duration of one
//! boot. At that moment the gateway has no pre-existing secret to decrypt it
//! with — that is precisely what the resealing destroyed. The exposure is
//! bounded rather than eliminated:
//!
//! * the file is read only if the vault is genuinely undecipherable;
//! * it is erased immediately after use;
//! * it must be delivered with the same care as the OTA bundle itself.
//!
//! The HESC blobs use an ephemeral X25519 key pair, HKDF-SHA256, and
//! AES-256-GCM. Fresh ephemeral material and a fresh nonce are generated for
//! every sealing through [`aether::random`]. HESC v2 binds its whole header
//! (counter and gateway public key) as AAD: a modified header makes the escrow
//! undecipherable. HESC v1 is only opened, for secrets with no escrow context.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf;
use zeroize::Zeroizing;

/// Length of an X25519 public or private key.
pub const KEY_LEN: usize = 32;

pub mod recovery;

const MAGIC: &[u8; 4] = b"HESC";
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const AAD_V1: &[u8] = b"helios-escrow-v1";
const AAD_V2: &[u8] = b"helios-escrow-v2";
const KDF_INFO_V1: &[u8] = b"helios-escrow-kdf-v1";
const KDF_INFO_V2: &[u8] = b"helios-escrow-kdf-v2";
/// Bytes before the ephemeral key: magic, version (v1 layout).
const HEADER_LEN_V1: usize = 4 + 1 + KEY_LEN + NONCE_LEN;
/// v2 adds, before the ephemeral key, the metadata flag, the counter (u64
/// big-endian, zero when absent) and the gateway public key.
const METADATA_LEN: usize = 1 + 8 + KEY_LEN;
const HEADER_LEN_V2: usize = 4 + 1 + METADATA_LEN + KEY_LEN + NONCE_LEN;

/// Errors returned by the escrow format and cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("invalid escrow key: {0}")]
    BadKey(String),
    #[error("invalid escrow blob: {0}")]
    Format(String),
    #[error("cannot open the escrow (wrong private key or tampered blob)")]
    Undecipherable,
    #[error("secret generation (CSPRNG) failed: {0}")]
    Rng(String),
    #[error("serialization/deserialization: escrow encryption failed")]
    Encryption,
    #[error("serialization/deserialization: escrow derivation failed")]
    Derivation,
    #[error("serialization/deserialization: invalid escrow AEAD key")]
    InvalidAeadKey,
}

/// Result type for escrow operations.
pub type Result<T> = std::result::Result<T, EscrowError>;

/// Values the gateway writes in clear in a HESC v2 header, bound by the AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowMetadata {
    /// Value of the NV counter when the escrow was written, if it was readable.
    pub counter: Option<u64>,
    /// WireGuard public key of the identity the escrow recovers.
    pub gateway_public_key: [u8; KEY_LEN],
}

/// Result of opening an escrow: the metadata is absent for HESC v1.
#[derive(Debug)]
pub struct OpenedEscrow {
    pub metadata: Option<EscrowMetadata>,
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// Encrypts `plaintext` to the operator's escrow public key, as HESC v2.
pub fn seal_to_operator(
    operator_public_key: &[u8],
    plaintext: &[u8],
    metadata: &EscrowMetadata,
) -> Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(HEADER_LEN_V2 - NONCE_LEN - KEY_LEN);
    prefix.extend_from_slice(MAGIC);
    prefix.push(VERSION_V2);
    match metadata.counter {
        Some(counter) => {
            prefix.push(1);
            prefix.extend_from_slice(&counter.to_be_bytes());
        }
        None => {
            prefix.push(0);
            prefix.extend_from_slice(&[0u8; 8]);
        }
    }
    prefix.extend_from_slice(&metadata.gateway_public_key);
    seal_frame(operator_public_key, plaintext, &prefix, KDF_INFO_V2, true)
}

/// Encrypts a secret that has no WireGuard escrow context (HESC v1).
///
/// For secrets other than the WireGuard escrow, whose authenticated context
/// travels in their own signed request.
pub fn seal_secret_to_operator(operator_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let prefix = [MAGIC.as_slice(), &[VERSION_V1]].concat();
    seal_frame(operator_public_key, plaintext, &prefix, KDF_INFO_V1, false)
}

/// Shared sealing: `prefix` is the header before the ephemeral key. The v2
/// AAD covers the whole header up to the nonce; v1 binds only its domain.
fn seal_frame(
    operator_public_key: &[u8],
    plaintext: &[u8],
    prefix: &[u8],
    kdf_info: &[u8],
    bind_header: bool,
) -> Result<Vec<u8>> {
    let recipient = x25519_dalek::PublicKey::from(to_array(operator_public_key)?);

    let mut ephemeral_bytes = Zeroizing::new([0u8; KEY_LEN]);
    aether::random::fill_secret(ephemeral_bytes.as_mut_slice()).map_err(|error| {
        EscrowError::Rng(format!("approved DRBG unavailable for escrow: {error}"))
    })?;
    let ephemeral_secret = x25519_dalek::StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let key = derive_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        recipient.as_bytes(),
        kdf_info,
    )?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aether::random::fill_secret(&mut nonce_bytes).map_err(|error| {
        EscrowError::Rng(format!("approved DRBG unavailable for nonce: {error}"))
    })?;

    let mut header = Vec::with_capacity(prefix.len() + KEY_LEN + NONCE_LEN);
    header.extend_from_slice(prefix);
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&nonce_bytes);

    let aad = if bind_header {
        [AAD_V2, header.as_slice()].concat()
    } else {
        AAD_V1.to_vec()
    };

    let mut in_out = Zeroizing::new(Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len()));
    in_out.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad.as_slice()),
        &mut *in_out,
    )
    .map_err(|_| EscrowError::Encryption)?;

    let mut blob = Vec::with_capacity(header.len() + in_out.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Opens an escrow with the operator's private key (HESC v1 or v2).
///
/// The gateway never possesses this private key. The returned plaintext is
/// zeroizing so recovered key material is cleared when the value is dropped.
pub fn open_as_operator(operator_private_key: &[u8], blob: &[u8]) -> Result<OpenedEscrow> {
    if blob.len() < 5 {
        return Err(EscrowError::Format("truncated blob".into()));
    }
    if &blob[..4] != MAGIC {
        return Err(EscrowError::Format("invalid magic".into()));
    }
    match blob[4] {
        VERSION_V1 => {
            if blob.len() < HEADER_LEN_V1 {
                return Err(EscrowError::Format("truncated blob".into()));
            }
            let plaintext = open_frame(
                operator_private_key,
                blob,
                HEADER_LEN_V1,
                KDF_INFO_V1,
                AAD_V1.to_vec(),
            )?;
            Ok(OpenedEscrow {
                metadata: None,
                plaintext,
            })
        }
        VERSION_V2 => {
            if blob.len() < HEADER_LEN_V2 {
                return Err(EscrowError::Format("truncated blob".into()));
            }
            let counter = match blob[5] {
                0 => None,
                1 => {
                    Some(u64::from_be_bytes(blob[6..14].try_into().map_err(
                        |_| EscrowError::Format("invalid counter".into()),
                    )?))
                }
                flag => return Err(EscrowError::Format(format!("invalid counter flag {flag}"))),
            };
            let mut gateway_public_key = [0u8; KEY_LEN];
            gateway_public_key.copy_from_slice(&blob[14..14 + KEY_LEN]);
            let metadata = EscrowMetadata {
                counter,
                gateway_public_key,
            };

            let aad = [AAD_V2, &blob[..HEADER_LEN_V2]].concat();
            let plaintext =
                open_frame(operator_private_key, blob, HEADER_LEN_V2, KDF_INFO_V2, aad)?;
            Ok(OpenedEscrow {
                metadata: Some(metadata),
                plaintext,
            })
        }
        version => Err(EscrowError::Format(format!(
            "unsupported version {version}"
        ))),
    }
}

/// Shared opening: the ephemeral key and nonce close the header, whatever
/// the version.
fn open_frame(
    operator_private_key: &[u8],
    blob: &[u8],
    header_len: usize,
    kdf_info: &[u8],
    aad: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = x25519_dalek::StaticSecret::from(to_array(operator_private_key)?);
    let recipient_public = x25519_dalek::PublicKey::from(&secret);

    let ephemeral_start = header_len - NONCE_LEN - KEY_LEN;
    let mut ephemeral = [0u8; KEY_LEN];
    ephemeral.copy_from_slice(&blob[ephemeral_start..ephemeral_start + KEY_LEN]);
    let ephemeral_public = x25519_dalek::PublicKey::from(ephemeral);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[header_len - NONCE_LEN..header_len]);

    let shared = secret.diffie_hellman(&ephemeral_public);
    let key = derive_key(
        shared.as_bytes(),
        &ephemeral,
        recipient_public.as_bytes(),
        kdf_info,
    )?;

    let mut in_out = Zeroizing::new(blob[header_len..].to_vec());
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_slice()),
            &mut in_out,
        )
        .map_err(|_| EscrowError::Undecipherable)?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

fn derive_key(
    shared: &[u8],
    ephemeral_public: &[u8],
    recipient_public: &[u8],
    kdf_info: &[u8],
) -> Result<LessSafeKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared);
    let info: [&[u8]; 3] = [kdf_info, ephemeral_public, recipient_public];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| EscrowError::Derivation)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    okm.fill(key_bytes.as_mut_slice())
        .map_err(|_| EscrowError::Derivation)?;

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_slice())
        .map_err(|_| EscrowError::InvalidAeadKey)?;
    Ok(LessSafeKey::new(unbound))
}

fn to_array(key: &[u8]) -> Result<[u8; KEY_LEN]> {
    key.try_into()
        .map_err(|_| EscrowError::BadKey(format!("{} bytes instead of {KEY_LEN}", key.len())))
}

/// Generates an operator escrow keypair. The private half stays off the gateway.
pub fn generate_operator_keypair() -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; KEY_LEN])> {
    let mut private = Zeroizing::new([0u8; KEY_LEN]);
    aether::random::fill_secret(private.as_mut_slice())
        .map_err(|error| EscrowError::Rng(format!("approved DRBG unavailable: {error}")))?;
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((private, *public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_round_trip() {
        let (private, public) = generate_operator_keypair().unwrap();
        let wg_key = b"cle-privee-wireguard-de-32-octet";

        let blob = seal_secret_to_operator(&public, wg_key).unwrap();
        let out = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(out.plaintext.as_slice(), wg_key);
    }

    #[test]
    /// The gateway seals but cannot reopen. A compromised gateway does not
    /// obtain the operator's private key through this mechanism.
    fn a_different_private_key_does_not_open_it() {
        let (_, public) = generate_operator_keypair().unwrap();
        let (other_private, _) = generate_operator_keypair().unwrap();

        let blob = seal_secret_to_operator(&public, b"secret").unwrap();
        assert!(matches!(
            open_as_operator(other_private.as_slice(), &blob),
            Err(EscrowError::Undecipherable)
        ));
    }

    #[test]
    fn two_sealings_of_the_same_content_differ() {
        let (_, public) = generate_operator_keypair().unwrap();
        let a = seal_secret_to_operator(&public, b"secret").unwrap();
        let b = seal_secret_to_operator(&public, b"secret").unwrap();
        assert_ne!(
            a, b,
            "ephemeral pair and nonce must be fresh on each sealing"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_secret_to_operator(&public, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    #[test]
    /// The ephemeral key enters the KDF, so the ciphertext is bound to the
    /// exact ephemeral/recipient pair.
    fn substituting_the_ephemeral_key_is_detected() {
        let (private, public) = generate_operator_keypair().unwrap();
        let mut blob = seal_secret_to_operator(&public, b"secret").unwrap();
        blob[6] ^= 0xff;
        assert!(open_as_operator(private.as_slice(), &blob).is_err());
    }

    #[test]
    fn wrong_size_keys_are_rejected() {
        assert!(seal_secret_to_operator(&[0u8; 10], b"x").is_err());
        let (_, public) = generate_operator_keypair().unwrap();
        let blob = seal_secret_to_operator(&public, b"x").unwrap();
        assert!(open_as_operator(&[0u8; 10], &blob).is_err());
    }

    #[test]
    fn legacy_error_display_texts_are_preserved() {
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable for escrow: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable for escrow: detail"
        );
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable for nonce: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable for nonce: detail"
        );
        assert_eq!(
            EscrowError::Rng("approved DRBG unavailable: detail".into()).to_string(),
            "secret generation (CSPRNG) failed: approved DRBG unavailable: detail"
        );
        assert_eq!(
            EscrowError::Encryption.to_string(),
            "serialization/deserialization: escrow encryption failed"
        );
        assert_eq!(
            EscrowError::Derivation.to_string(),
            "serialization/deserialization: escrow derivation failed"
        );
        assert_eq!(
            EscrowError::InvalidAeadKey.to_string(),
            "serialization/deserialization: invalid escrow AEAD key"
        );
    }

    #[test]
    fn invalid_formats_are_rejected() {
        let (private, _) = generate_operator_keypair().unwrap();
        assert!(open_as_operator(private.as_slice(), b"court").is_err());

        let mut bad = vec![0u8; HEADER_LEN_V1 + 16];
        bad[..4].copy_from_slice(b"NOPE");
        assert!(open_as_operator(private.as_slice(), &bad).is_err());

        let mut bad_version = vec![0u8; HEADER_LEN_V1 + 16];
        bad_version[..4].copy_from_slice(MAGIC);
        bad_version[4] = 9;
        assert!(open_as_operator(private.as_slice(), &bad_version).is_err());
    }

    #[test]
    fn hesc_v2_round_trips_with_its_metadata() {
        let (private, public) = generate_operator_keypair().unwrap();
        let metadata = EscrowMetadata {
            counter: Some(5),
            gateway_public_key: [7u8; KEY_LEN],
        };

        let blob = seal_to_operator(&public, b"cle-wireguard", &metadata).unwrap();
        assert_eq!(blob[4], 2, "new escrows are written as HESC v2");

        let opened = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"cle-wireguard");
        assert_eq!(opened.metadata, Some(metadata));
    }

    #[test]
    fn hesc_v2_round_trips_without_a_counter() {
        let (private, public) = generate_operator_keypair().unwrap();
        let metadata = EscrowMetadata {
            counter: None,
            gateway_public_key: [9u8; KEY_LEN],
        };

        let blob = seal_to_operator(&public, b"cle", &metadata).unwrap();
        let opened = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(opened.metadata, Some(metadata));
    }

    #[test]
    fn a_tampered_v2_header_is_undecipherable() {
        let (private, public) = generate_operator_keypair().unwrap();
        let metadata = EscrowMetadata {
            counter: Some(5),
            gateway_public_key: [7u8; KEY_LEN],
        };
        let blob = seal_to_operator(&public, b"secret", &metadata).unwrap();

        // Layout: magic(4) version(1) flag(1) counter(8) key(32) ephemeral nonce.
        let mut counter_changed = blob.clone();
        counter_changed[13] ^= 0x01;
        assert!(matches!(
            open_as_operator(private.as_slice(), &counter_changed),
            Err(EscrowError::Undecipherable)
        ));

        let mut key_changed = blob.clone();
        key_changed[20] ^= 0x01;
        assert!(matches!(
            open_as_operator(private.as_slice(), &key_changed),
            Err(EscrowError::Undecipherable)
        ));
    }

    #[test]
    fn a_v1_escrow_still_opens_without_metadata() {
        let (private, public) = generate_operator_keypair().unwrap();
        let blob = seal_secret_to_operator(&public, b"ancienne").unwrap();
        assert_eq!(blob[4], 1);

        let opened = open_as_operator(private.as_slice(), &blob).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"ancienne");
        assert_eq!(opened.metadata, None);
    }
}
