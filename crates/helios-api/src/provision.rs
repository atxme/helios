//! Provisioning endpoint: `POST /api/provision`.
//!
//! # Why here, and why without TLS
//!
//! ADR-001 planned a dedicated TLS 1.3 channel, TPM-anchored. At
//! implementation time, this channel turns out to be **redundant**: it would
//! live inside the WireGuard tunnel anyway, which already provides
//!
//! * **confidentiality** (ChaCha20-Poly1305), and
//! * **mutual authentication** — each end knows the other's static public key
//!   (`peer_public_key` on the Orion side, the peer table on the gateway
//!   side). A third party cannot impersonate the gateway without its
//!   Curve25519 private key.
//!
//! TLS would therefore add no property the tunnel doesn't already give.
//! Provisioning is grafted onto the existing HTTP server, which also lives
//! behind the tunnel.
//!
//! And the PSK's **post-quantum** confidentiality does not depend on the
//! channel: an adversary who later breaks the classical tunnel would only see
//! the ML-KEM public key and the ciphertext — exactly what a passive observer
//! of a plaintext ML-KEM exchange sees, which ML-KEM resists by construction.
//!
//! # What the TPM should protect
//!
//! The intent to "anchor the gateway's identity in the TPM" remains valid,
//! but it targets the wrong secret: it isn't a redundant TLS key that needs
//! sealing, it's **`wg_private_key`** — the gateway's real cryptographic
//! identity, today stored in clear in `network.toml`. Open work item.

use std::time::Duration;

use aether::enroll::{EnrollError, ProvisionRequest, ProvisionResponse};
use aether::{InstallPskRequest, SecretString};
use axum::{extract::State, http::StatusCode, Extension, Json};
use helios_provisioning::{
    handle_request, session::fresh_nonce, AdmittedPeers, GatewayIdentity, Provisioned,
    DEFAULT_PSK_LIFETIME_SECS,
};
use helios_wireguard::PeerAddressTable;
use tokio::sync::oneshot;

use crate::AppState;

/// "Admitted peers" view backed by the network config.
///
/// Admission stays **out of band**: this list is the one the operator
/// declared (`peers` in `network.toml`). Provisioning never extends it.
struct AdmittedFromConfig(Vec<String>);

impl AdmittedPeers for AdmittedFromConfig {
    fn is_admitted(&self, wg_public_key: &str) -> bool {
        self.0.iter().any(|k| k == wg_public_key)
    }
}

/// Handles a provisioning request coming from a client, **inside the tunnel**.
pub async fn provision(
    State(s): State<AppState>,
    caller: Option<Extension<crate::auth::Caller>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, String)> {
    match caller {
        Some(Extension(caller)) if caller.dev_loopback => {}
        Some(Extension(caller))
            if caller.public_key.as_deref() == Some(request.client_wg_public_key.as_str()) => {}
        Some(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                "the requested key does not belong to the calling WireGuard peer".into(),
            ));
        }
        None if s.dry_run => {}
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "missing WireGuard identity".into(),
            ));
        }
    }
    let network = s.network.read().await;

    // Without a private key, the gateway has no identity to announce: refuse
    // explicitly rather than deriving a PSK against an empty identity.
    if !network.wireguard_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway not configured: `wg_private_key` missing".to_string(),
        ));
    }

    let gateway_public_key = match gateway_public_key(&network.wg_private_key) {
        Ok(k) => k,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    };

    let admitted = AdmittedFromConfig(network.peers.iter().map(|p| p.public_key.clone()).collect());

    // The *live* peer table serves as the source of truth for VIP
    // collisions. In dry-run it is empty: the derived VIP is then kept
    // as-is, which is the expected behavior.
    let peers = PeerAddressTable::from_peers(&[]);

    let identity = GatewayIdentity {
        wg_public_key: &gateway_public_key,
        psk_lifetime_secs: DEFAULT_PSK_LIFETIME_SECS,
    };

    let provisioned =
        handle_request(&request, &identity, &admitted, &peers, fresh_nonce()).map_err(to_http)?;

    // The config is no longer needed, and the orchestrator will want to
    // write it: release the read lock before handing over control.
    drop(network);

    // The PSK is installed on the data plane BEFORE being announced to the
    // client. WireGuard has only one PSK slot per peer: a PSK installed on
    // just one side makes every subsequent handshake fail — and the control
    // channel that would allow recovery lives precisely in this tunnel.
    install_psk(&s, &request.client_wg_public_key, &provisioned).await?;

    tracing::info!(
        peer = %request.client_wg_public_key,
        vip = %provisioned.address,
        "provisioning completed — post-quantum PSK derived and installed"
    );

    Ok(Json(provisioned.response))
}

/// Wait time for the orchestrator's acknowledgement.
///
/// Generous relative to a local `sync_peers`, but bounded: a client blocked
/// indefinitely wouldn't know whether it should install the PSK or not.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Asks the orchestrator to install the PSK, and waits for its confirmation.
///
/// Any failure — saturated channel, orchestrator stopped, data plane error,
/// timeout — results in a failed request. This is deliberately fail-closed:
/// better a refused provisioning, which leaves the classical tunnel intact,
/// than an orphaned PSK that kills the tunnel.
async fn install_psk(
    s: &AppState,
    client_public_key: &str,
    provisioned: &Provisioned,
) -> Result<(), (StatusCode, String)> {
    let (reply_tx, reply_rx) = oneshot::channel();

    let request = InstallPskRequest {
        public_key: client_public_key.to_string(),
        address: format!("{}/32", provisioned.address),
        psk: Some(SecretString::new(aether::enroll::psk_to_base64(
            &provisioned.psk,
        ))),
        reply: reply_tx,
    };

    s.psk_tx.send(request).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "orchestrator unavailable: PSK not installed".to_string(),
        )
    })?;

    match tokio::time::timeout(INSTALL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("PSK installation refused: {e}"),
        )),
        Ok(Err(_)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "orchestrator stopped before acknowledging the PSK".to_string(),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            "timed out installing the PSK".to_string(),
        )),
    }
}

/// Translates a protocol error into an HTTP response.
///
/// An unadmitted peer gets `403`, not `404`: the fact "this key isn't
/// admitted" isn't a secret anyway — the caller is already inside the
/// tunnel, so already authenticated by WireGuard.
fn to_http(e: EnrollError) -> (StatusCode, String) {
    let code = match e {
        EnrollError::UnknownPeer => StatusCode::FORBIDDEN,
        EnrollError::VersionMismatch { .. } => StatusCode::CONFLICT,
        EnrollError::Kdf => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    // A refused provisioning shows up in the log: it's the only place where
    // an enrollment attempt leaves a trace, since WireGuard's refusal of an
    // unknown peer stays invisible from user space.
    tracing::warn!(status = %code, "provisioning refused: {e}");
    (code, e.to_string())
}

/// Derives the gateway's WireGuard public key from its private key.
fn gateway_public_key(private_key_b64: &str) -> Result<String, String> {
    aether::wg::public_from_private(private_key_b64)
        .map_err(|e| format!("unreadable gateway private key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::{derive_psk, ProvisionRequest, NONCE_LEN, PROTOCOL_VERSION};
    use aether::pq::{Kem, MlKem1024Kem};
    use aether::{NetworkConfig, TunnelState};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc, RwLock};

    const PRIV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const CLIENT_PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// The client's public key, as the gateway knows it through admission.
    fn client_public_key() -> String {
        use base64::Engine as _;
        let raw: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(CLIENT_PRIV)
            .unwrap()
            .try_into()
            .unwrap();
        let secret = x25519_dalek::StaticSecret::from(raw);
        base64::engine::general_purpose::STANDARD
            .encode(x25519_dalek::PublicKey::from(&secret).as_bytes())
    }

    /// `AppState` rigged for provisioning, with the PSK channel handed back
    /// to the test: it decides whether to acknowledge, so it plays the
    /// orchestrator.
    fn provisionable_state() -> (AppState, mpsc::Receiver<InstallPskRequest>) {
        let network = NetworkConfig {
            wg_private_key: PRIV.into(),
            wg_address: "100.64.0.1/10".into(),
            peers: vec![aether::WgPeer {
                name: "workstation".into(),
                public_key: client_public_key(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: None,
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
            }],
            ..NetworkConfig::default()
        };
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (psk_tx, psk_rx) = mpsc::channel(8);
        let state = AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(TunnelState::Connecting)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        (state, psk_rx)
    }

    /// Builds a real provisioning request, as Orion would.
    fn client_request() -> (
        <MlKem1024Kem as Kem>::SecretKey,
        [u8; NONCE_LEN],
        ProvisionRequest,
    ) {
        let (dk, ek) = MlKem1024Kem::generate().unwrap();
        let nonce = [42u8; NONCE_LEN];
        (
            dk,
            nonce,
            ProvisionRequest {
                protocol_version: PROTOCOL_VERSION,
                client_wg_public_key: client_public_key(),
                kem_public_key: ek,
                client_nonce: nonce,
            },
        )
    }

    /// The full round trip: the PSK announced to the client is exactly the
    /// one the gateway asked to install, and installation precedes the response.
    #[tokio::test]
    async fn the_psk_is_installed_before_being_announced_and_both_ends_agree() {
        let (state, mut psk_rx) = provisionable_state();
        let (dk, client_nonce, request) = client_request();

        // Simulated orchestrator: it acknowledges and keeps what was asked of it.
        let orchestrator = tokio::spawn(async move {
            let demand = psk_rx.recv().await.expect("a request must arrive");
            let psk = demand
                .psk
                .expect("provisioning always installs a PSK")
                .expose()
                .to_string();
            let address = demand.address.clone();
            demand.reply.send(Ok(())).unwrap();
            (psk, address)
        });

        let response = provision(State(state), None, Json(request))
            .await
            .expect("provisioning must succeed")
            .0;

        let (installed_psk, address) = orchestrator.await.unwrap();
        // The transmitted VIP is the one the IPAM derives from the public
        // key, and it is indeed the one announced to the client: the two
        // must agree.
        assert_eq!(
            address, response.assigned_address,
            "the installed VIP must be the one announced to the client"
        );

        // Client side: independent decapsulation and derivation.
        let kem_secret = MlKem1024Kem::decapsulate(&dk, &response.kem_ciphertext).unwrap();
        let client_psk = derive_psk(
            &kem_secret,
            &client_nonce,
            &response.gateway_nonce,
            &client_public_key(),
            &response.gateway_wg_public_key,
        )
        .unwrap();

        assert_eq!(
            aether::enroll::psk_to_base64(&client_psk),
            installed_psk,
            "the PSK installed on the gateway must be the one the client derives, \
             otherwise every subsequent handshake would fail"
        );
    }

    /// Fail-closed: if the gateway cannot install the PSK, it does not
    /// announce it. The client stays on the classical tunnel rather than an
    /// orphaned PSK being installed, which would kill the tunnel — and with
    /// it the recovery channel.
    #[tokio::test]
    async fn an_uninstalled_psk_is_never_announced_to_the_client() {
        let (state, mut psk_rx) = provisionable_state();
        let (_dk, _nonce, request) = client_request();

        // The orchestrator refuses the installation.
        tokio::spawn(async move {
            let demand = psk_rx.recv().await.unwrap();
            demand
                .reply
                .send(Err("data plane unavailable".into()))
                .unwrap();
        });

        let error = provision(State(state), None, Json(request))
            .await
            .expect_err("an uninstalled PSK must fail the request");

        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn the_requested_key_must_belong_to_the_calling_peer() {
        let (state, _psk_rx) = provisionable_state();
        let (_dk, _nonce, request) = client_request();
        let caller = crate::auth::Caller {
            source: "100.64.1.3".parse().unwrap(),
            name: "other-peer".into(),
            public_key: Some("another-peers-key".into()),
            admin: false,
            dev_loopback: false,
        };
        let error = provision(State(state), Some(Extension(caller)), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }

    /// Orchestrator stopped: same requirement, via a different path.
    #[tokio::test]
    async fn missing_orchestrator_fails_provisioning() {
        let (state, psk_rx) = provisionable_state();
        drop(psk_rx);
        let (_dk, _nonce, request) = client_request();

        let error = provision(State(state), None, Json(request))
            .await
            .expect_err("without an orchestrator, no PSK must be announced");

        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn the_gateways_public_key_derives_from_its_private_key() {
        let pk = gateway_public_key(PRIV).unwrap();
        assert_eq!(pk.len(), 44);
        assert_eq!(pk, gateway_public_key(PRIV).unwrap(), "stable derivation");
    }

    #[test]
    fn invalid_private_key_is_reported() {
        assert!(gateway_public_key("not-base64").is_err());
        assert!(gateway_public_key("AAAA").is_err(), "invalid length");
    }

    #[test]
    fn only_declared_peers_are_admitted() {
        let admitted = AdmittedFromConfig(vec!["key-a".into()]);
        assert!(admitted.is_admitted("key-a"));
        assert!(
            !admitted.is_admitted("key-b"),
            "provisioning must never extend admission"
        );
    }

    #[test]
    fn protocol_errors_have_the_right_http_code() {
        assert_eq!(to_http(EnrollError::UnknownPeer).0, StatusCode::FORBIDDEN);
        assert_eq!(
            to_http(EnrollError::VersionMismatch {
                client: 2,
                gateway: 1
            })
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            to_http(EnrollError::BadKemPublicKey(3)).0,
            StatusCode::BAD_REQUEST
        );
    }
}
