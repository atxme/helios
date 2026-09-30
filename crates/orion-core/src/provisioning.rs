//! Client-side provisioning: obtaining the post-quantum PSK from the gateway.
//!
//! # When this runs
//!
//! **Only once the classic tunnel is mounted**, like telemetry. ADR-001's
//! timeline:
//!
//! ```text
//! 1. Classic WireGuard tunnel (Curve25519) mounted -> Connecting state,
//!    kill-switch engaged, no user traffic.
//! 2. THIS MODULE: provisioning request to the gateway, INSIDE the tunnel.
//!    -> ML-KEM exchange -> PSK derived on both sides.
//! 3. PSK installed -> next handshake succeeds -> Up.
//! ```
//!
//! # Why no TLS here
//!
//! The channel lives **inside** the WireGuard tunnel, which already provides
//! confidentiality *and* mutual authentication: each end knows the other's
//! static public key (`peer_public_key` on the client side, peer table on the
//! gateway side). An additional TLS layer would add neither.
//!
//! And even if the classic tunnel were later broken by a quantum adversary,
//! that wouldn't compromise the PSK: the attacker would only see the ML-KEM
//! public key and the ciphertext — exactly what a passive observer of an
//! ML-KEM exchange conducted in the clear sees, which ML-KEM resists by
//! construction.
//!
//! # What this module doesn't do
//!
//! It doesn't enroll an unknown client. If the gateway doesn't yet know the
//! client's WireGuard public key, the classic tunnel doesn't mount and this
//! code is never reached. Admission is out of band (see
//! `helios_provisioning`).

use std::time::Duration;

use aether::enroll::{
    derive_psk, EnrollError, ProvisionRequest, ProvisionResponse, PROTOCOL_VERSION,
};
use aether::pq::{Kem, MlKem1024Kem};

use crate::config::ClientProfile;

/// Max delay of a provisioning request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of a successful provisioning.
#[derive(Debug)]
pub struct ProvisionOutcome {
    /// Post-quantum PSK, in base64, ready for the `PresharedKey` slot.
    ///
    /// A [`SecretString`](aether::SecretString), which is also what keeps the `Debug` above honest:
    /// this structure is built on every enrolment, and a derived `Debug` over
    /// a bare `String` would print the PSK into any log that formats it
    /// (ADR-006 §5).
    pub preshared_key: aether::SecretString,
    /// VIP assigned by the gateway (CIDR).
    pub address: String,
    /// Gateway's WireGuard public key, as it declares itself.
    pub gateway_public_key: String,
    /// Announced validity duration of the PSK.
    pub lifetime: Duration,
}

/// Client-side provisioning errors.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("le profil n'est pas exploitable : {0}")]
    Profile(String),
    #[error("canal de provisioning injoignable : {0}")]
    Transport(String),
    #[error("la gateway a refusé le provisioning (HTTP {status}) : {body}")]
    Rejected { status: u16, body: String },
    #[error("réponse de provisioning illisible : {0}")]
    BadResponse(String),
    #[error(transparent)]
    Protocol(#[from] EnrollError),
    #[error("échange ML-KEM impossible : {0}")]
    Kem(String),
    /// The gateway doesn't announce the public key expected by the profile.
    #[error("identité de gateway inattendue : le profil attend `{expected}`, la gateway annonce `{announced}`")]
    GatewayIdentityMismatch { expected: String, announced: String },
}

/// Builds the request and its associated ephemeral ML-KEM pair.
///
/// The pair is **ephemeral per session**: the secret doesn't survive
/// provisioning, which bounds the impact of a later client compromise.
fn build_request(
    profile: &ClientProfile,
) -> Result<(<MlKem1024Kem as Kem>::SecretKey, [u8; 16], ProvisionRequest), ProvisionError> {
    let (secret_key, kem_public_key) =
        MlKem1024Kem::generate().map_err(|e| ProvisionError::Kem(e.to_string()))?;

    let client_nonce = fresh_nonce();
    let request = ProvisionRequest {
        protocol_version: PROTOCOL_VERSION,
        client_wg_public_key: profile.wg_public_key()?,
        kem_public_key,
        client_nonce,
    };
    Ok((secret_key, client_nonce, request))
}

/// Derives the PSK from the gateway's response.
///
/// Separated from transport to be testable without a network — this is
/// where all the cryptographic logic lives.
pub fn finish(
    profile: &ClientProfile,
    secret_key: &<MlKem1024Kem as Kem>::SecretKey,
    client_nonce: &[u8; 16],
    response: &ProvisionResponse,
) -> Result<ProvisionOutcome, ProvisionError> {
    response.validate()?;

    // The gateway must be the one the profile expects. Without this check, a
    // compromised gateway could substitute itself and negotiate a PSK with
    // us — even though the WireGuard tunnel already makes this scenario
    // very unlikely.
    if response.gateway_wg_public_key != profile.peer_public_key {
        return Err(ProvisionError::GatewayIdentityMismatch {
            expected: profile.peer_public_key.clone(),
            announced: response.gateway_wg_public_key.clone(),
        });
    }

    let kem_secret = MlKem1024Kem::decapsulate(secret_key, &response.kem_ciphertext)
        .map_err(|e| ProvisionError::Kem(e.to_string()))?;

    let psk = derive_psk(
        &kem_secret,
        client_nonce,
        &response.gateway_nonce,
        &profile.wg_public_key()?,
        &response.gateway_wg_public_key,
    )?;

    Ok(ProvisionOutcome {
        preshared_key: aether::enroll::psk_to_base64(&psk).into(),
        address: response.assigned_address.clone(),
        gateway_public_key: response.gateway_wg_public_key.clone(),
        lifetime: Duration::from_secs(u64::from(response.psk_lifetime_secs)),
    })
}

/// Runs a complete provisioning against the gateway.
///
/// `gateway_url` is the internal URL, reachable **only inside the tunnel**
/// (e.g. `http://100.64.0.1:8080`).
pub async fn provision(
    profile: &ClientProfile,
    gateway_url: &str,
) -> Result<ProvisionOutcome, ProvisionError> {
    let (secret_key, client_nonce, request) = build_request(profile)?;

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // The provisioning endpoint is inside WireGuard. Never let an
        // inherited desktop proxy move the signed request off the tunnel.
        .no_proxy()
        .build()
        .map_err(|e| ProvisionError::Transport(e.to_string()))?;

    let url = format!("{}/api/provision", gateway_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| ProvisionError::Transport(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ProvisionError::Rejected {
            status: status.as_u16(),
            body,
        });
    }

    let response: ProvisionResponse = resp
        .json()
        .await
        .map_err(|e| ProvisionError::BadResponse(e.to_string()))?;

    finish(profile, &secret_key, &client_nonce, &response)
}

/// Draws a session nonce from the approved DRBG.
fn fresh_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    aether::random::fill_public(&mut nonce)
        .expect("the approved DRBG cannot produce a session nonce");
    nonce
}

impl ClientProfile {
    /// Client's WireGuard public key, derived from its private key.
    ///
    /// This is the identity the gateway knows. We recompute it rather than
    /// store it: it can never diverge from the private key actually used.
    pub fn wg_public_key(&self) -> Result<String, ProvisionError> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.private_key.trim())
            .map_err(|e| ProvisionError::Profile(format!("clé privée illisible : {e}")))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| ProvisionError::Profile("clé privée de longueur invalide".into()))?;

        // Curve25519: public key = base * private key (clamped).
        let secret = x25519_dalek::StaticSecret::from(raw);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::NONCE_LEN;

    const CLIENT_PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_PUB: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "test".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: CLIENT_PRIV.into(),
            peer_public_key: GATEWAY_PUB.into(),
            ..ClientProfile::default()
        }
    }

    #[test]
    fn the_public_key_is_derived_from_the_private_key() {
        let pk = profile().wg_public_key().unwrap();
        assert_eq!(pk.len(), 44, "Curve25519 key in base64");
        // Deterministic: two calls give the same identity.
        assert_eq!(pk, profile().wg_public_key().unwrap());
    }

    #[test]
    fn invalid_private_key_rejected() {
        let mut p = profile();
        p.private_key = "not-base64".into();
        assert!(matches!(p.wg_public_key(), Err(ProvisionError::Profile(_))));
    }

    /// The full client-side round trip, without a network: we simulate the
    /// gateway with real ML-KEM crypto and check the derived PSK is usable.
    #[test]
    fn full_provisioning_produces_a_usable_psk() {
        let profile = profile();
        let (secret_key, client_nonce, request) = build_request(&profile).unwrap();
        request.validate().unwrap();

        // ── Simulated gateway ──
        let gateway_nonce = [7u8; NONCE_LEN];
        let (ciphertext, kem_secret) = MlKem1024Kem::encapsulate(&request.kem_public_key).unwrap();
        let expected_psk = derive_psk(
            &kem_secret,
            &client_nonce,
            &gateway_nonce,
            &request.client_wg_public_key,
            GATEWAY_PUB,
        )
        .unwrap();

        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce,
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: GATEWAY_PUB.into(),
            psk_lifetime_secs: 3600,
        };

        // ── Client-side return ──
        let outcome = finish(&profile, &secret_key, &client_nonce, &response).unwrap();
        assert_eq!(
            outcome.preshared_key.expose(),
            aether::enroll::psk_to_base64(&expected_psk),
            "the client must derive exactly the PSK the gateway computed"
        );
        assert_eq!(outcome.address, "100.64.1.2/32");
        assert_eq!(outcome.lifetime, Duration::from_secs(3600));
    }

    /// `ProvisionOutcome` derives `Debug` and is built on every enrolment, so
    /// the only thing standing between the PSK and any log that formats the
    /// outcome is the field's type. The test is what fails if it goes back to
    /// being a `String` (ADR-006 §5).
    #[test]
    fn the_debug_of_an_outcome_reveals_no_preshared_key() {
        let outcome = ProvisionOutcome {
            preshared_key: "PSK-QUI-NE-DOIT-PAS-FUIR".into(),
            address: "100.64.1.2/32".into(),
            gateway_public_key: GATEWAY_PUB.into(),
            lifetime: Duration::from_secs(3600),
        };

        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains("PSK-QUI-NE-DOIT-PAS-FUIR"),
            "the Debug of an outcome must not carry the PSK: {rendered}"
        );
        assert_eq!(
            outcome.preshared_key.expose(),
            "PSK-QUI-NE-DOIT-PAS-FUIR",
            "redacting the Debug must not alter the value itself"
        );
    }

    /// A gateway that isn't the profile's must be rejected.
    #[test]
    fn unexpected_gateway_rejected() {
        let profile = profile();
        let (secret_key, client_nonce, request) = build_request(&profile).unwrap();
        let (ciphertext, _) = MlKem1024Kem::encapsulate(&request.kem_public_key).unwrap();

        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            // A different identity than the one expected by the profile.
            gateway_wg_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            psk_lifetime_secs: 3600,
        };

        assert!(matches!(
            finish(&profile, &secret_key, &client_nonce, &response),
            Err(ProvisionError::GatewayIdentityMismatch { .. })
        ));
    }

    #[test]
    fn malformed_ciphertext_rejected() {
        let profile = profile();
        let (secret_key, client_nonce, _) = build_request(&profile).unwrap();
        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: vec![0u8; 10],
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: GATEWAY_PUB.into(),
            psk_lifetime_secs: 3600,
        };
        assert!(finish(&profile, &secret_key, &client_nonce, &response).is_err());
    }

    #[test]
    fn two_sessions_use_distinct_kem_pairs() {
        let p = profile();
        let (_, n1, r1) = build_request(&p).unwrap();
        let (_, n2, r2) = build_request(&p).unwrap();
        assert_ne!(
            r1.kem_public_key, r2.kem_public_key,
            "ephemeral pair per session"
        );
        assert_ne!(n1, n2, "fresh nonce per session");
    }
}
