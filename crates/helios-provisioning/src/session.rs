//! Handling of a provisioning session, on the gateway side.
//!
//! Transport-agnostic: this logic knows nothing about TLS or sockets. It
//! consumes a [`ProvisionRequest`] and produces a [`ProvisionResponse`] plus
//! the PSK to install. The real channel (TPM-anchored TLS 1.3, *inside* the
//! tunnel) wraps it without modifying it — this separation makes the entire
//! exchange testable without a network, even on WSL2, with **real** ML-KEM crypto.
//!
//! # What this session does not do
//!
//! It does not admit an unknown client. Since WireGuard is built on
//! Noise_IK, an undeclared peer cannot bring up the tunnel, so it cannot
//! reach this code. Admission is **out of band** (see [`crate`] and
//! `aether::enroll`): here, an unknown peer is refused with
//! [`EnrollError::UnknownPeer`] rather than enrolled on the fly.

use std::net::Ipv4Addr;

use aether::enroll::{
    derive_psk, EnrollError, ProvisionRequest, ProvisionResponse, Psk, NONCE_LEN, PROTOCOL_VERSION,
};
use aether::pq::{Kem, MlKem1024Kem};

use crate::ipam::{assign_vip, PeerTable, MAX_VIP_PROBES};

/// Default PSK validity duration, in seconds (1 hour).
///
/// Bounds the exploitation window of a compromised PSK. Too short, and
/// rotations multiply — and every rotation is a moment of fragility (see
/// `rotation`).
pub const DEFAULT_PSK_LIFETIME_SECS: u32 = 3600;

/// The registry of admitted peers, on the gateway side.
///
/// Admission is out of band: this interface only *queries*. A typical
/// implementation reads the `peers` list from `network.toml`.
pub trait AdmittedPeers {
    /// Has this peer been admitted (WireGuard public key, base64)?
    fn is_admitted(&self, wg_public_key: &str) -> bool;
}

/// Result of a successful session.
#[derive(Debug)]
pub struct Provisioned {
    /// To be sent back to the client over the control channel.
    pub response: ProvisionResponse,
    /// PSK to install on the WireGuard peer, gateway side. **Secret.**
    pub psk: Psk,
    /// VIP retained for this peer.
    pub address: Ipv4Addr,
}

/// The gateway's invariant parameters for a session.
pub struct GatewayIdentity<'a> {
    /// Gateway's WireGuard public key (base64).
    pub wg_public_key: &'a str,
    /// Validity duration announced for the PSK.
    pub psk_lifetime_secs: u32,
}

/// Handles a provisioning request.
///
/// `gateway_nonce` is injected rather than drawn here: this makes the
/// function deterministic and therefore testable end to end. In production,
/// the caller draws it from the OS's CSPRNG — see [`fresh_nonce`].
pub fn handle_request<P, T>(
    request: &ProvisionRequest,
    gateway: &GatewayIdentity<'_>,
    admitted: &P,
    peers: &T,
    gateway_nonce: [u8; NONCE_LEN],
) -> Result<Provisioned, EnrollError>
where
    P: AdmittedPeers,
    T: PeerTable,
{
    // 1. Structural validation before any costly or secret operation.
    request.validate()?;

    // 2. Admission is a prerequisite, not a side effect of this session.
    if !admitted.is_admitted(&request.client_wg_public_key) {
        return Err(EnrollError::UnknownPeer);
    }

    // 3. VIP derived from the client's WireGuard public key: stable across
    //    sessions and restarts, with no state on disk.
    let pubkey_bytes = decode_wg_key(&request.client_wg_public_key)?;
    let address =
        assign_vip(peers, &pubkey_bytes, MAX_VIP_PROBES).map_err(|_| EnrollError::UnknownPeer)?;

    // 4. ML-KEM encapsulation towards the client's ephemeral key. It is the
    //    gateway that encapsulates: the secret's freshness therefore does
    //    not depend on a potentially compromised client.
    let (ciphertext, kem_secret) = MlKem1024Kem::encapsulate(&request.kem_public_key)
        .map_err(|_| EnrollError::BadKemPublicKey(request.kem_public_key.len()))?;

    // 5. PSK bound to both nonces and both identities.
    let psk = derive_psk(
        &kem_secret,
        &request.client_nonce,
        &gateway_nonce,
        &request.client_wg_public_key,
        gateway.wg_public_key,
    )?;

    Ok(Provisioned {
        response: ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce,
            assigned_address: format!("{address}/32"),
            gateway_wg_public_key: gateway.wg_public_key.to_string(),
            psk_lifetime_secs: gateway.psk_lifetime_secs,
        },
        psk,
        address,
    })
}

/// Decodes a base64 WireGuard public key into its 32 raw bytes.
///
/// These are the bytes — not the base64 string — that feed the IPAM: VIP
/// derivation must be independent of the encoding.
fn decode_wg_key(b64: &str) -> Result<Vec<u8>, EnrollError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| EnrollError::MissingClientKey)?;
    if raw.len() != 32 {
        return Err(EnrollError::MissingClientKey);
    }
    Ok(raw)
}

/// Draws a session nonce from the system's CSPRNG.
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
    let mut nonce = [0u8; NONCE_LEN];
    // `SystemRandom` can only fail if the OS has no entropy: in that case we
    // must absolutely not continue with a predictable nonce.
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("system CSPRNG unavailable — cannot provision safely");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::PROTOCOL_VERSION;
    use std::collections::HashSet;

    struct Registry(HashSet<String>);
    impl AdmittedPeers for Registry {
        fn is_admitted(&self, k: &str) -> bool {
            self.0.contains(k)
        }
    }

    struct EmptyTable;
    impl PeerTable for EmptyTable {
        fn is_taken_by_other(&self, _: Ipv4Addr, _: &[u8]) -> bool {
            false
        }
    }

    const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn registry() -> Registry {
        Registry(HashSet::from([CLIENT_KEY.to_string()]))
    }

    fn gateway() -> GatewayIdentity<'static> {
        GatewayIdentity {
            wg_public_key: GATEWAY_KEY,
            psk_lifetime_secs: DEFAULT_PSK_LIFETIME_SECS,
        }
    }

    /// Simulates the client: generates its ephemeral ML-KEM pair and its request.
    fn client_request() -> (
        <MlKem1024Kem as Kem>::SecretKey,
        [u8; NONCE_LEN],
        ProvisionRequest,
    ) {
        let (dk, ek) = MlKem1024Kem::generate().unwrap();
        let client_nonce = [42u8; NONCE_LEN];
        let req = ProvisionRequest {
            protocol_version: PROTOCOL_VERSION,
            client_wg_public_key: CLIENT_KEY.into(),
            kem_public_key: ek,
            client_nonce,
        };
        (dk, client_nonce, req)
    }

    /// The full exchange, with **real** ML-KEM crypto: both ends must
    /// derive the same PSK. This is the test that validates the protocol.
    #[test]
    fn the_full_exchange_both_ends_derive_the_same_psk() {
        let (dk, client_nonce, req) = client_request();
        let gw_nonce = [7u8; NONCE_LEN];

        // ── Gateway side ──
        let out = handle_request(&req, &gateway(), &registry(), &EmptyTable, gw_nonce).unwrap();
        out.response.validate().unwrap();

        // ── Client side: decapsulates and derives independently ──
        let kem_secret = MlKem1024Kem::decapsulate(&dk, &out.response.kem_ciphertext).unwrap();
        let client_psk = derive_psk(
            &kem_secret,
            &client_nonce,
            &out.response.gateway_nonce,
            CLIENT_KEY,
            &out.response.gateway_wg_public_key,
        )
        .unwrap();

        assert_eq!(
            *client_psk, *out.psk,
            "client and gateway must derive an identical PSK, otherwise the \
             WireGuard handshake would fail silently"
        );
    }

    #[test]
    fn the_vip_is_stable_across_two_sessions() {
        let (_, _, req1) = client_request();
        let (_, _, req2) = client_request();
        let a =
            handle_request(&req1, &gateway(), &registry(), &EmptyTable, [1; NONCE_LEN]).unwrap();
        let b =
            handle_request(&req2, &gateway(), &registry(), &EmptyTable, [2; NONCE_LEN]).unwrap();
        assert_eq!(
            a.address, b.address,
            "the VIP derives from the key, not from the session"
        );
        assert!(a.response.assigned_address.ends_with("/32"));
    }

    #[test]
    fn two_sessions_yield_different_psks() {
        let (_, _, req) = client_request();
        let a = handle_request(&req, &gateway(), &registry(), &EmptyTable, [1; NONCE_LEN]).unwrap();
        let b = handle_request(&req, &gateway(), &registry(), &EmptyTable, [2; NONCE_LEN]).unwrap();
        assert_ne!(*a.psk, *b.psk, "every session must produce a fresh PSK");
    }

    /// An unadmitted client is refused: this session performs no admission.
    #[test]
    fn unadmitted_peer_refused() {
        let (_, _, mut req) = client_request();
        req.client_wg_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into();
        let err = handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]);
        assert_eq!(err.unwrap_err(), EnrollError::UnknownPeer);
    }

    #[test]
    fn incompatible_version_refused_before_any_crypto() {
        let (_, _, mut req) = client_request();
        req.protocol_version = 99;
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]),
            Err(EnrollError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn malformed_kem_key_refused() {
        let (_, _, mut req) = client_request();
        req.kem_public_key = vec![0u8; 10];
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), &EmptyTable, [0; NONCE_LEN]),
            Err(EnrollError::BadKemPublicKey(10))
        ));
    }

    #[test]
    fn drawn_nonces_are_distinct() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
