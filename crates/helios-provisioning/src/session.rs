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
//!
//! It does not choose an address either. The IPAM runs at admission, and
//! only there; this session returns the VIPs admission persisted
//! (`ADRESSAGE-IPV6.md` §3 bis.2, rule 4). Deriving them again here is what
//! once let provisioning announce one address while the gateway routed
//! another.

use aether::enroll::{
    derive_psk, EnrollError, ProvisionRequest, ProvisionResponse, Psk, NONCE_LEN, PROTOCOL_VERSION,
};
use aether::net::{AddressError, PeerVips};
use aether::pq::{Kem, MlKem1024Kem};
use aether::NetworkConfig;

/// Default PSK validity duration, in seconds (1 hour).
///
/// Bounds the exploitation window of a compromised PSK. Too short, and
/// rotations multiply — and every rotation is a moment of fragility (see
/// `rotation`).
pub const DEFAULT_PSK_LIFETIME_SECS: u32 = 3600;

/// The registry of admitted peers, on the gateway side.
///
/// Admission is out of band: this interface only *queries*. The gateway's
/// implementation is the `peers` list of `network.toml`, through
/// [`NetworkConfig`].
pub trait AdmittedPeers {
    /// The VIPs persisted for the admitted peer holding this WireGuard public
    /// key (base64), or `None` when no admitted peer holds it.
    fn declared_vips(&self, wg_public_key: &str) -> Option<Result<PeerVips, AddressError>>;
}

impl AdmittedPeers for NetworkConfig {
    fn declared_vips(&self, wg_public_key: &str) -> Option<Result<PeerVips, AddressError>> {
        self.peers
            .iter()
            .find(|peer| peer.public_key == wg_public_key)
            .map(aether::WgPeer::vips)
    }
}

/// Result of a successful session.
#[derive(Debug)]
pub struct Provisioned {
    /// To be sent back to the client over the control channel.
    pub response: ProvisionResponse,
    /// PSK to install on the WireGuard peer, gateway side. **Secret.**
    pub psk: Psk,
    /// The VIPs persisted for this peer, as announced in `response`.
    pub vips: PeerVips,
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
pub fn handle_request<P>(
    request: &ProvisionRequest,
    gateway: &GatewayIdentity<'_>,
    admitted: &P,
    gateway_nonce: [u8; NONCE_LEN],
) -> Result<Provisioned, EnrollError>
where
    P: AdmittedPeers,
{
    // 1. Structural validation before any costly or secret operation.
    request.validate()?;

    // 2. Admission is a prerequisite, not a side effect of this session, and
    //    it is what fixed the peer's VIPs: they are read back, not derived.
    //    The gateway's `AllowedIPs` carry these very addresses, so announcing
    //    anything else would hand the client an address its traffic is
    //    dropped from.
    let vips = match admitted.declared_vips(&request.client_wg_public_key) {
        None => return Err(EnrollError::UnknownPeer),
        Some(Err(_)) => return Err(EnrollError::UndeclaredAddress),
        Some(Ok(vips)) => vips,
    };

    // 3. ML-KEM encapsulation towards the client's ephemeral key. It is the
    //    gateway that encapsulates: the secret's freshness therefore does
    //    not depend on a potentially compromised client.
    let (ciphertext, kem_secret) = MlKem1024Kem::encapsulate(&request.kem_public_key)
        .map_err(|_| EnrollError::BadKemPublicKey(request.kem_public_key.len()))?;

    // 4. PSK bound to both nonces and both identities.
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
            assigned_address: vips.address(),
            assigned_address_v6: vips.address_v6(),
            gateway_wg_public_key: gateway.wg_public_key.to_string(),
            psk_lifetime_secs: gateway.psk_lifetime_secs,
        },
        psk,
        vips,
    })
}

/// Draws a session nonce from the approved DRBG.
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    // The DRBG only fails when the platform has no entropy, its health test
    // refuses a block, or a fork has not been reseeded away. In every one of
    // those cases continuing with a predictable nonce is the worse outcome.
    aether::random::fill_public(&mut nonce)
        .expect("the approved DRBG cannot produce a session nonce");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::derive_cgnat_ip;
    use aether::enroll::PROTOCOL_VERSION;

    const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// Deliberately not the VIP the IPAM derives for `CLIENT_KEY`: what
    /// provisioning returns must come from the declaration.
    const DECLARED: &str = "100.64.1.2/32";

    fn peer(address: &str, address_v6: Option<&str>) -> aether::WgPeer {
        aether::WgPeer {
            name: "workstation".into(),
            public_key: CLIENT_KEY.into(),
            address: address.into(),
            address_v6: address_v6.map(|text| text.parse().expect("IPv6 host")),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }
    }

    /// The gateway's admission registry: `network.toml`'s peer table.
    fn registry() -> NetworkConfig {
        NetworkConfig {
            peers: vec![peer(DECLARED, None)],
            ..NetworkConfig::default()
        }
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
        let out = handle_request(&req, &gateway(), &registry(), gw_nonce).unwrap();
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

    /// §3 bis.2, rule 4: the announced address is the persisted one, even
    /// when the derivation would have chosen another — as it does after a
    /// collision resolved at admission.
    #[test]
    fn provisioning_returns_the_declared_vip_not_a_derived_one() {
        assert_ne!(
            format!("{}/32", derive_cgnat_ip(&[1u8; 32], 0)),
            DECLARED,
            "the test needs a declaration the derivation would not produce"
        );
        let (_, _, req1) = client_request();
        let (_, _, req2) = client_request();
        let a = handle_request(&req1, &gateway(), &registry(), [1; NONCE_LEN]).unwrap();
        let b = handle_request(&req2, &gateway(), &registry(), [2; NONCE_LEN]).unwrap();

        assert_eq!(a.response.assigned_address, DECLARED);
        assert_eq!(a.vips.address(), DECLARED);
        assert_eq!(a.vips, b.vips, "the VIP does not depend on the session");
        assert_eq!(
            a.response.assigned_address_v6, None,
            "a peer without an IPv6 VIP announces none"
        );
    }

    #[test]
    fn provisioning_returns_the_declared_ipv6_vip() {
        const DECLARED_V6: &str = "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517";
        let registry = NetworkConfig {
            peers: vec![peer(DECLARED, Some(DECLARED_V6))],
            ..NetworkConfig::default()
        };
        let (_, _, req) = client_request();
        let out = handle_request(&req, &gateway(), &registry, [1; NONCE_LEN]).unwrap();

        assert_eq!(out.response.assigned_address, DECLARED);
        assert_eq!(
            out.response.assigned_address_v6.as_deref(),
            Some(format!("{DECLARED_V6}/128").as_str())
        );
    }

    /// A peer admitted without a readable address is a named error, not an
    /// occasion to derive one.
    #[test]
    fn an_admitted_peer_without_a_readable_address_is_refused() {
        for unreadable in ["", "100.64.1.2", "100.64.1.0/24"] {
            let registry = NetworkConfig {
                peers: vec![peer(unreadable, None)],
                ..NetworkConfig::default()
            };
            let (_, _, req) = client_request();
            assert_eq!(
                handle_request(&req, &gateway(), &registry, [0; NONCE_LEN]).unwrap_err(),
                EnrollError::UndeclaredAddress,
                "{unreadable:?}"
            );
        }
    }

    #[test]
    fn two_sessions_yield_different_psks() {
        let (_, _, req) = client_request();
        let a = handle_request(&req, &gateway(), &registry(), [1; NONCE_LEN]).unwrap();
        let b = handle_request(&req, &gateway(), &registry(), [2; NONCE_LEN]).unwrap();
        assert_ne!(*a.psk, *b.psk, "every session must produce a fresh PSK");
    }

    /// An unadmitted client is refused: this session performs no admission.
    #[test]
    fn unadmitted_peer_refused() {
        let (_, _, mut req) = client_request();
        req.client_wg_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into();
        let err = handle_request(&req, &gateway(), &registry(), [0; NONCE_LEN]);
        assert_eq!(err.unwrap_err(), EnrollError::UnknownPeer);
    }

    #[test]
    fn incompatible_version_refused_before_any_crypto() {
        let (_, _, mut req) = client_request();
        req.protocol_version = 99;
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), [0; NONCE_LEN]),
            Err(EnrollError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn malformed_kem_key_refused() {
        let (_, _, mut req) = client_request();
        req.kem_public_key = vec![0u8; 10];
        assert!(matches!(
            handle_request(&req, &gateway(), &registry(), [0; NONCE_LEN]),
            Err(EnrollError::BadKemPublicKey(10))
        ));
    }

    #[test]
    fn drawn_nonces_are_distinct() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
