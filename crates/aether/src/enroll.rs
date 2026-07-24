//! Provisioning protocol: messages and derivation of the post-quantum PSK.
//!
//! This module is **shared** by both ends, like [`crate::pq`]: the gateway
//! (`helios-provisioning`) and the client (`orion-core`) must speak the same
//! format and derive **the same** PSK. Placing it on only one side would
//! force the other to depend on a crate that does not concern it.
//!
//! # Scope: provisioning, not admission
//!
//! This protocol does **not** let in an unknown client. WireGuard is built
//! on Noise_IK: the responder rejects an initiator whose static public key
//! it does not know. A client that was never declared therefore cannot
//! bring up the tunnel — and this protocol lives *inside* the tunnel.
//!
//! Enrollment splits into two:
//!
//! * **Admission** (first contact) — necessarily **out-of-band**: an
//!   operator declares the client's public key. Its VIP is derived
//!   deterministically from it (`helios-provisioning::ipam`).
//! * **Provisioning** (this module) — inside the tunnel, automated: ML-KEM
//!   exchange, PSK derivation, VIP confirmation, rotation.
//!
//! # Sequence (ADR-001)
//!
//! ```text
//! 1. Classic WireGuard tunnel established (Curve25519), Connecting state,
//!    kill-switch engaged — no user traffic.
//! 2. Control channel INSIDE the tunnel:
//!      client  -> ProvisionRequest  { ephemeral ML-KEM public key, nonce }
//!      gateway -> ProvisionResponse { ML-KEM ciphertext, nonce, VIP }
//!    Both derive the same PSK.
//! 3. PSK installed on both sides -> the next handshake succeeds -> Up.
//! ```
//!
//! It is the **client** that generates the ML-KEM key pair and the
//! **gateway** that encapsulates: the secret is thus fresh for every session
//! and its freshness is controlled by the gateway, not by a potentially
//! compromised client.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pq::SharedSecret;

/// Protocol version. A client and a gateway on different versions must
/// explicitly refuse rather than negotiate blindly.
pub const PROTOCOL_VERSION: u16 = 1;

/// KDF domain separator. Changing this value invalidates every derived PSK:
/// it is part of the cryptographic contract.
const PSK_DOMAIN: &[u8] = b"helios-provisioning-psk-v1";

/// Length of session nonces, in bytes.
pub const NONCE_LEN: usize = 16;

/// Derived WireGuard PSK, 32 bytes, wiped on drop.
pub type Psk = Zeroizing<[u8; 32]>;

/// Provisioning protocol errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    #[error("incompatible protocol version: client {client}, gateway {gateway}")]
    VersionMismatch { client: u16, gateway: u16 },
    #[error("ML-KEM public key of invalid length: {0} instead of {expected}", expected = crate::pq::PUBLIC_KEY_LEN)]
    BadKemPublicKey(usize),
    #[error("ML-KEM ciphertext of invalid length: {0} instead of {expected}", expected = crate::pq::CIPHERTEXT_LEN)]
    BadKemCiphertext(usize),
    #[error("client WireGuard public key missing or empty")]
    MissingClientKey,
    #[error("unknown peer: out-of-band admission not performed")]
    UnknownPeer,
    #[error("PSK derivation failed")]
    Kdf,
}

/// Provisioning request, emitted by the client **inside** the tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub protocol_version: u16,
    /// Client's WireGuard public key (base64) — its identity, already known
    /// to the gateway via out-of-band admission.
    pub client_wg_public_key: String,
    /// **Ephemeral** ML-KEM public key, generated for this session.
    pub kem_public_key: Vec<u8>,
    /// Client-side randomness. Contributes to the KDF salt so that neither
    /// end alone controls the derivation.
    pub client_nonce: [u8; NONCE_LEN],
}

/// Gateway response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResponse {
    pub protocol_version: u16,
    /// ML-KEM encapsulation towards the client's ephemeral public key.
    pub kem_ciphertext: Vec<u8>,
    /// Gateway-side randomness.
    pub gateway_nonce: [u8; NONCE_LEN],
    /// VIP assigned to the client, in CIDR notation (e.g. `100.64.1.2/32`).
    /// Derived from its WireGuard public key, hence stable without disk state.
    pub assigned_address: String,
    /// Gateway's WireGuard public key (base64), so the client can complete
    /// its profile without manual configuration.
    pub gateway_wg_public_key: String,
    /// PSK validity duration, in seconds. Past this delay, the client must
    /// restart a provisioning.
    pub psk_lifetime_secs: u32,
}

impl ProvisionRequest {
    /// Structural validation, before any cryptographic operation.
    pub fn validate(&self) -> Result<(), EnrollError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(EnrollError::VersionMismatch {
                client: self.protocol_version,
                gateway: PROTOCOL_VERSION,
            });
        }
        if self.client_wg_public_key.trim().is_empty() {
            return Err(EnrollError::MissingClientKey);
        }
        if self.kem_public_key.len() != crate::pq::PUBLIC_KEY_LEN {
            return Err(EnrollError::BadKemPublicKey(self.kem_public_key.len()));
        }
        Ok(())
    }
}

impl ProvisionResponse {
    pub fn validate(&self) -> Result<(), EnrollError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(EnrollError::VersionMismatch {
                client: PROTOCOL_VERSION,
                gateway: self.protocol_version,
            });
        }
        if self.kem_ciphertext.len() != crate::pq::CIPHERTEXT_LEN {
            return Err(EnrollError::BadKemCiphertext(self.kem_ciphertext.len()));
        }
        Ok(())
    }
}

/// Derives the WireGuard PSK from the ML-KEM secret.
///
/// The ML-KEM secret is already 32 uniform bytes, exactly the size of the
/// PSK slot: it could be used raw. We still go through an HKDF to **bind**
/// the PSK to its context:
///
/// * both nonces — the same secret cannot be replayed in another session,
///   and neither end alone controls the salt;
/// * both WireGuard identities — a PSK derived for a (client, gateway) pair
///   is not valid for another;
/// * a versioned domain separator — the secret cannot be diverted towards
///   another cryptographic use in the project.
///
/// The concatenation order is fixed (client then gateway): both ends
/// **must** apply it identically, otherwise the PSKs diverge and the
/// handshake fails silently.
pub fn derive_psk(
    kem_secret: &SharedSecret,
    client_nonce: &[u8; NONCE_LEN],
    gateway_nonce: &[u8; NONCE_LEN],
    client_wg_public_key: &str,
    gateway_wg_public_key: &str,
) -> Result<Psk, EnrollError> {
    use aws_lc_rs::hkdf;

    // Salt: contribution from both ends, fixed order.
    let mut salt_bytes = Vec::with_capacity(NONCE_LEN * 2);
    salt_bytes.extend_from_slice(client_nonce);
    salt_bytes.extend_from_slice(gateway_nonce);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(kem_secret.as_slice());

    // `info`: domain + identities, length-prefixed so that no ambiguous
    // concatenation can produce two identical contexts.
    let client_id = client_wg_public_key.as_bytes();
    let gateway_id = gateway_wg_public_key.as_bytes();
    let client_len = (client_id.len() as u16).to_be_bytes();
    let gateway_len = (gateway_id.len() as u16).to_be_bytes();
    let info: [&[u8]; 5] = [PSK_DOMAIN, &client_len, client_id, &gateway_len, gateway_id];

    // `HKDF_SHA256` as `KeyType` produces exactly 32 bytes.
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| EnrollError::Kdf)?;
    let mut psk = Zeroizing::new([0u8; 32]);
    okm.fill(psk.as_mut_slice()).map_err(|_| EnrollError::Kdf)?;
    Ok(psk)
}

/// Encodes a PSK in base64, the format expected by WireGuard.
pub fn psk_to_base64(psk: &Psk) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(psk.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SharedSecret {
        Zeroizing::new([byte; 32])
    }

    fn psk_for(
        s: &SharedSecret,
        cn: [u8; NONCE_LEN],
        gn: [u8; NONCE_LEN],
        ck: &str,
        gk: &str,
    ) -> Psk {
        derive_psk(s, &cn, &gn, ck, gk).unwrap()
    }

    #[test]
    fn derivation_is_deterministic_for_both_ends() {
        // The client and the gateway compute separately: they must converge.
        let a = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        assert_eq!(*a, *b);
    }

    #[test]
    fn the_psk_depends_on_each_nonce() {
        let base = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        // Changing the client's nonce is enough.
        assert_ne!(
            *base,
            *psk_for(&secret(7), [9; 16], [2; 16], "client", "gateway")
        );
        // So is the gateway's: neither controls the salt alone.
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [9; 16], "client", "gateway")
        );
    }

    #[test]
    fn the_psk_is_bound_to_both_identities() {
        let base = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [2; 16], "autre", "gateway")
        );
        assert_ne!(
            *base,
            *psk_for(&secret(7), [1; 16], [2; 16], "client", "autre")
        );
    }

    /// Without a length prefix, ("ab","c") and ("a","bc") would give the same
    /// `info` — two distinct contexts would share a PSK.
    #[test]
    fn no_collision_from_ambiguous_concatenation() {
        let a = psk_for(&secret(7), [1; 16], [2; 16], "ab", "c");
        let b = psk_for(&secret(7), [1; 16], [2; 16], "a", "bc");
        assert_ne!(*a, *b);
    }

    #[test]
    fn a_different_kem_secret_gives_a_different_psk() {
        let a = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b = psk_for(&secret(8), [1; 16], [2; 16], "client", "gateway");
        assert_ne!(*a, *b);
    }

    #[test]
    fn psk_encodes_to_44_base64_characters() {
        let psk = psk_for(&secret(7), [1; 16], [2; 16], "client", "gateway");
        let b64 = psk_to_base64(&psk);
        // 32 bytes -> 44 base64 characters, the format expected by WireGuard.
        assert_eq!(b64.len(), 44);
    }

    #[test]
    fn request_validates_versions_and_lengths() {
        let mut req = ProvisionRequest {
            protocol_version: PROTOCOL_VERSION,
            client_wg_public_key: "cGVlcg==".into(),
            kem_public_key: vec![0u8; crate::pq::PUBLIC_KEY_LEN],
            client_nonce: [0; NONCE_LEN],
        };
        assert!(req.validate().is_ok());

        req.protocol_version = 99;
        assert!(matches!(
            req.validate(),
            Err(EnrollError::VersionMismatch { .. })
        ));

        req.protocol_version = PROTOCOL_VERSION;
        req.kem_public_key = vec![0u8; 10];
        assert!(matches!(
            req.validate(),
            Err(EnrollError::BadKemPublicKey(10))
        ));

        req.kem_public_key = vec![0u8; crate::pq::PUBLIC_KEY_LEN];
        req.client_wg_public_key = "  ".into();
        assert_eq!(req.validate(), Err(EnrollError::MissingClientKey));
    }

    #[test]
    fn response_validates_the_ciphertext_length() {
        let mut resp = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: vec![0u8; crate::pq::CIPHERTEXT_LEN],
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: "Z3c=".into(),
            psk_lifetime_secs: 3600,
        };
        assert!(resp.validate().is_ok());

        resp.kem_ciphertext = vec![0u8; 5];
        assert!(matches!(
            resp.validate(),
            Err(EnrollError::BadKemCiphertext(5))
        ));
    }
}
