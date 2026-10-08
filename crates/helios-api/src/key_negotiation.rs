//! In-tunnel PSK release: `POST /api/key-negotiation/release`.
//!
//! # Why this is not on the public negotiation port
//!
//! Negotiating a key has to happen **before** WireGuard exists, which is what
//! the public QUIC port is for. An explicit disconnection is the opposite
//! situation: it happens after a successful handshake, when an encrypted and
//! mutually authenticated channel to the gateway is already up. Reopening the
//! public port to announce a teardown re-authenticated by mTLS, a challenge
//! and an ML-DSA signature a machine that had nothing left to prove — and it
//! kept a second listener's worth of attack surface alive for a courtesy
//! message (spec §7.5, ADR-005 amendment of 2026-08-08).
//!
//! # Authentication order
//!
//! [`crate::auth::require_peer`] runs first and resolves the socket's **real**
//! source address to the single `/32` VIP of an admitted peer — no proxy
//! header is ever consulted. That resolution yields the caller's WireGuard
//! key, and the handler compares the body's `client_wg_public_key` against it.
//! The body's key is therefore never a lookup key: a stolen negotiation
//! identity cannot aim a release at another peer. The PQ certificate,
//! its admitted fingerprint and the ML-DSA-87 signature are checked after
//! that, so a release engages the client's WireGuard key **and** its ML-DSA
//! key.
//!
//! # Why the statuses are so coarse
//!
//! The answer never describes the slot. Cleared, already empty, owned by
//! another transaction and holding a configured static PSK are one and the
//! same `204`: telling them apart would be an oracle on a peer's state, and
//! Orion bases no decision on the answer anyway — changing the PSK can make
//! the response untransportable on the very WireGuard session that carried
//! the request.

use aether::key_negotiation::{AuthenticatedPskRelease, KEY_NEGOTIATION_VERSION};
use async_trait::async_trait;
use axum::{body::Bytes, extract::State, http::StatusCode, Extension};

use crate::AppState;

/// Largest release body read before deserialization.
///
/// A release carries an ML-DSA-87 certificate and signature, so it is a few
/// tens of kilobytes at worst. The bound exists so that an admitted peer
/// cannot make the gateway buffer arbitrary JSON on the control plane.
pub const MAX_RELEASE_BODY_BYTES: usize = 32 * 1024;

/// Why a release was refused, in the only three shapes the API may report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskReleaseRefusal {
    /// Unusable message: wrong protocol version, malformed structure.
    Protocol,
    /// Authenticated transport, refused identity: the body names another
    /// peer or gateway, or the certificate or signature does not verify.
    Rejected,
    /// The data-plane write or an internal transition failed. The only case
    /// where the caller learns something happened on the gateway — and it is
    /// about the gateway, not about the slot.
    Internal,
}

/// The gateway side of a release, implemented by the key-negotiation service.
///
/// A trait rather than a direct call because the API process must never hold
/// a WireGuard backend: it hands the authenticated command to the state
/// machine that owns the per-peer serializer, and learns nothing else.
#[async_trait]
pub trait PskReleaseHandler: Send + Sync {
    /// `caller_wg_public_key` is the key `require_peer` resolved from the
    /// source address — the trusted one. The release's own copy of it is only
    /// ever compared against this.
    async fn release(
        &self,
        caller_wg_public_key: &str,
        release: AuthenticatedPskRelease,
    ) -> Result<(), PskReleaseRefusal>;
}

/// Handles a signed release arriving **inside the tunnel**.
pub async fn release(
    State(s): State<AppState>,
    Extension(caller): Extension<crate::auth::Caller>,
    body: Bytes,
) -> StatusCode {
    // `require_peer` also admits the `--dev` loopback identity, which has no
    // WireGuard key at all. A release names a peer's slot; without a key
    // there is no peer to name.
    let Some(caller_key) = caller.public_key.as_deref() else {
        tracing::warn!(
            source = %caller.source,
            "release refused: the caller is not tied to a WireGuard peer"
        );
        return StatusCode::UNAUTHORIZED;
    };
    if body.len() > MAX_RELEASE_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let authenticated: AuthenticatedPskRelease = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(peer = %caller_key, %error, "release refused: unreadable body");
            return StatusCode::BAD_REQUEST;
        }
    };
    if authenticated.release.protocol_version != KEY_NEGOTIATION_VERSION {
        tracing::warn!(
            peer = %caller_key,
            received = authenticated.release.protocol_version,
            "release refused: unsupported protocol version"
        );
        return StatusCode::BAD_REQUEST;
    }
    let Some(handler) = s.psk_release.as_ref() else {
        // No `key_negotiation_port`, so no negotiated slot can exist and
        // there is nothing to withdraw. Idempotent like every other no-op —
        // but worth a line, because a client sending one here is configured
        // against a service this gateway does not run.
        tracing::warn!(
            peer = %caller_key,
            "release ignored: this gateway runs no key-negotiation service"
        );
        return StatusCode::NO_CONTENT;
    };
    match handler.release(caller_key, authenticated).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(PskReleaseRefusal::Protocol) => StatusCode::BAD_REQUEST,
        Err(PskReleaseRefusal::Rejected) => StatusCode::FORBIDDEN,
        Err(PskReleaseRefusal::Internal) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PskRelease};
    use aether::{NetworkConfig, TunnelState};
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, mpsc, RwLock};

    const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// Records what the API forwarded, and answers what the test asks for.
    struct SpyHandler {
        answer: Result<(), PskReleaseRefusal>,
        seen: Mutex<Option<(String, PskRelease)>>,
    }

    #[async_trait]
    impl PskReleaseHandler for SpyHandler {
        async fn release(
            &self,
            caller_wg_public_key: &str,
            release: AuthenticatedPskRelease,
        ) -> Result<(), PskReleaseRefusal> {
            *self.seen.lock().unwrap() = Some((caller_wg_public_key.to_string(), release.release));
            self.answer
        }
    }

    fn state_with(handler: Option<Arc<SpyHandler>>) -> AppState {
        let network = NetworkConfig::default();
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (psk_tx, _psk_rx) = mpsc::channel(8);
        let state = AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(TunnelState::Up)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        match handler {
            Some(handler) => state.with_psk_release(handler),
            None => state,
        }
    }

    fn caller(public_key: Option<&str>) -> crate::auth::Caller {
        crate::auth::Caller {
            source: "100.64.1.2".parse().unwrap(),
            name: "workstation".into(),
            public_key: public_key.map(str::to_string),
            admin: false,
            dev_loopback: false,
            local: false,
        }
    }

    /// A syntactically complete release. Its signature is never reached in
    /// these tests: the API only parses and forwards, and every refusal it
    /// can produce on its own happens before any verification.
    fn body(version: u16) -> Bytes {
        let release = AuthenticatedPskRelease {
            release: PskRelease {
                protocol_version: version,
                installed_transaction_id: [9; 16],
                client_wg_public_key: CLIENT_KEY.into(),
                gateway_wg_public_key: GATEWAY_KEY.into(),
            },
            certificate: PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: "orion".into(),
                issuer: "operator".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: CLIENT_KEY.into(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            ml_dsa_87_signature: String::new(),
        };
        Bytes::from(serde_json::to_vec(&release).unwrap())
    }

    fn spy(answer: Result<(), PskReleaseRefusal>) -> Arc<SpyHandler> {
        Arc::new(SpyHandler {
            answer,
            seen: Mutex::new(None),
        })
    }

    /// The key the handler receives is the one the transport proved, not the
    /// one the body claims — and the body's copy travels alongside for the
    /// state machine to compare.
    #[tokio::test]
    async fn an_accepted_release_forwards_the_source_resolved_key() {
        let handler = spy(Ok(()));
        let status = release(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(Some(CLIENT_KEY))),
            body(aether::key_negotiation::KEY_NEGOTIATION_VERSION),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        let seen = handler.seen.lock().unwrap().clone();
        let (key, release) = seen.expect("the release must reach the state machine");
        assert_eq!(key, CLIENT_KEY);
        assert_eq!(release.installed_transaction_id, [9; 16]);
    }

    /// `--dev` admits a loopback identity with no WireGuard key at all. A
    /// release names a peer's slot; without a key there is no peer to name.
    #[tokio::test]
    async fn a_caller_without_a_wireguard_key_is_refused() {
        let handler = spy(Ok(()));
        let status = release(
            State(state_with(Some(Arc::clone(&handler)))),
            Extension(caller(None)),
            body(aether::key_negotiation::KEY_NEGOTIATION_VERSION),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            handler.seen.lock().unwrap().is_none(),
            "nothing must reach the state machine without a resolved peer"
        );
    }

    /// The three refusal classes are the only thing a peer learns, and none of
    /// them describes the slot.
    #[tokio::test]
    async fn every_refusal_class_maps_to_one_bounded_status() {
        for (refusal, expected) in [
            (PskReleaseRefusal::Protocol, StatusCode::BAD_REQUEST),
            (PskReleaseRefusal::Rejected, StatusCode::FORBIDDEN),
            (
                PskReleaseRefusal::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let status = release(
                State(state_with(Some(spy(Err(refusal))))),
                Extension(caller(Some(CLIENT_KEY))),
                body(aether::key_negotiation::KEY_NEGOTIATION_VERSION),
            )
            .await;
            assert_eq!(status, expected, "{refusal:?}");
        }
    }

    /// Unreadable body, wrong version and oversized body are all refused
    /// before the state machine is reached.
    #[tokio::test]
    async fn a_body_the_api_cannot_use_never_reaches_the_state_machine() {
        let handler = spy(Ok(()));
        let state = state_with(Some(Arc::clone(&handler)));

        assert_eq!(
            release(
                State(state.clone()),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from_static(b"{"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            release(
                State(state.clone()),
                Extension(caller(Some(CLIENT_KEY))),
                body(4),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "a v4 release must not be honoured by a v5 gateway"
        );
        assert_eq!(
            release(
                State(state),
                Extension(caller(Some(CLIENT_KEY))),
                Bytes::from(vec![b'x'; MAX_RELEASE_BODY_BYTES + 1]),
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(handler.seen.lock().unwrap().is_none());
    }

    /// A gateway with no `key_negotiation_port` holds no negotiated slot, so
    /// there is nothing to withdraw — and the answer stays the idempotent
    /// no-op every other unmatched release gets.
    #[tokio::test]
    async fn a_gateway_without_the_service_answers_the_same_no_op() {
        let status = release(
            State(state_with(None)),
            Extension(caller(Some(CLIENT_KEY))),
            body(aether::key_negotiation::KEY_NEGOTIATION_VERSION),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}
