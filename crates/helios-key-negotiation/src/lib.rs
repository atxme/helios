//! Authenticated QUIC transport for key negotiation.
//!
//! The crate owns no WireGuard backend and no certificate authority. Callers
//! provide DER identities and a transaction handler. This separation keeps
//! the public parser and TLS boundary independently testable.

mod client;
mod endpoint;
mod error;
mod framing;
mod identity;
mod rate_limit;
mod server;
mod transaction;

#[cfg(test)]
use aether::key_negotiation::{
    static_psk_commitment, AuthenticatedKeyNegotiationCommit,
    AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest,
    KeyNegotiationRequest, KeyNegotiationResponse, KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
};
#[cfg(test)]
use aether::pq::{Kem, MlKem1024Kem};
#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use quinn::Endpoint;
#[cfg(test)]
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub use client::{negotiate, request_challenge, ClientSession, PendingChallenge};
pub use endpoint::{client_endpoint, client_endpoint_on_socket, server_endpoint};
pub use error::{PublicError, TransportError};
pub use identity::{certificate_fingerprint_der, TlsIdentity};
pub use server::{
    prepare_key_material, serve, GatewayIdentity, NegotiationHandler, PreparedKeyMaterial,
    PreparedNegotiation,
};

/// ALPN prevents another QUIC application on the host from accepting these
/// credentials and messages by accident.
pub const KEY_NEGOTIATION_ALPN: &[u8] = b"helios-key-negotiation/5";
/// Confirmation is bounded independently from transport idle time.
///
/// The client confirms as soon as a WireGuard handshake succeeds with the PSK
/// it has just installed, which takes a second or two. This bound is
/// therefore not a wait anyone lives
/// through — it is how long a **failed** attempt keeps the peer's transaction
/// slot, during which every new negotiation from that client is refused as
/// busy. Three minutes of that was a client locked out for three minutes by a
/// session that had already died; forty-five seconds still leaves twenty
/// times the room a handshake needs.
pub const DEFAULT_CONFIRMATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Bounds concurrent **negotiations** on the public WAN port.
///
/// Not a tunnel ceiling. Since v5 the connection is closed right after the
/// commit, so it lives for one transaction — a few hundred milliseconds in
/// the nominal case. In v4 the same number bounded the tunnels themselves,
/// because every connected client held its connection open for the life of
/// its tunnel.
pub const MAX_ACTIVE_NEGOTIATIONS: usize = 128;

/// How long a gateway-issued challenge stays usable.
///
/// It lives in the connection's own state, so this bound only matters for a
/// client that asks for one and then dawdles. Long enough to cover an
/// ML-KEM keygen and an ML-DSA-87 signature on a slow laptop, short enough
/// that a connection cannot sit on a valid authorization.
pub const CHALLENGE_VALIDITY: std::time::Duration = std::time::Duration::from_secs(45);

/// Handshakes accepted per source address and per window, once its address is
/// validated.
///
/// Address validation stops spoofed floods; it does nothing against an
/// attacker using its own address, which can still make the gateway run TLS
/// handshakes and ML-DSA verifications. This second bound makes that cost
/// linear in the number of addresses an attacker actually holds.
pub const MAX_HANDSHAKES_PER_SOURCE: u32 = 8;

/// Negotiations one admitted identity may open per [`SOURCE_RATE_WINDOW`].
///
/// Charged after mTLS, when the peer has a name. The address budget below
/// bounds anonymous traffic; this one bounds an authenticated peer that
/// roams, whose every attempt still costs an ML-DSA-87 verification and an
/// ML-KEM encapsulation.
pub const MAX_NEGOTIATIONS_PER_IDENTITY: u32 = 8;

/// Longest a negotiation connection may live, from address validation.
///
/// Not renewable, and unrelated to the idle timeout: a peer that keeps
/// sending well-formed frames is never idle, so an idle timeout alone lets a
/// connection — and the concurrency permit it holds — live for ever. With
/// only 128 permits, a handful of such connections is the whole service.
///
/// Sized above the sum of the phases it must contain: a challenge round trip,
/// a preparation, and up to a 45-second wait for the confirming WireGuard
/// handshake.
pub const MAX_CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(90);

/// Window over which [`MAX_HANDSHAKES_PER_SOURCE`] is counted.
///
/// A legitimate client negotiates once per connection, so eight attempts a
/// minute leaves ample room for retries on a lossy link.
pub const SOURCE_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(test)]
use endpoint::{CHALLENGE_TIMEOUT, RESPONSE_TIMEOUT, TRANSACTION_IDLE_TIMEOUT};
#[cfg(test)]
use framing::{read_frame, write_frame, ClientMessage, ServerMessage};
#[cfg(test)]
use rate_limit::{rate_bucket, RateLimiter};
#[cfg(test)]
use transaction::{Deadline, RollbackGuard};

#[cfg(test)]
mod tests {
    use super::*;

    /// Horloge des tests : les requêtes doivent être fraîches pour passer la
    /// fenêtre anti-rejeu.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    use aether::key_negotiation::{
        authenticate_commit, authenticate_confirmation, authenticate_request,
        authenticate_response, generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate,
        PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_NONCE_LEN, PQ_CERTIFICATE_VERSION,
    };
    use base64::Engine as _;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TEST_SERVER_NAME: &str = "gateway.test";
    const TEST_CHALLENGE: [u8; SERVER_CHALLENGE_LEN] = [5; SERVER_CHALLENGE_LEN];
    const GATEWAY_CERT_FINGERPRINT: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// The cheapest request a v5 decoder accepts.
    ///
    /// Was a `classic` request until that mode stopped being negotiable.
    /// `static_psk` costs one HMAC to build, where `ml_kem` costs a keypair.
    fn simple_request(transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN]) -> KeyNegotiationRequest {
        let mut request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: TEST_CHALLENGE,
            transaction_id,
            mode: ProtectionMode::StaticPsk,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: TEST_SERVER_NAME.into(),
            gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
            client_nonce: [2; KEY_NEGOTIATION_NONCE_LEN],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_commitment: None,
        };
        let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        request.static_psk_commitment = Some(commitment(&psk, &request));
        request
    }

    /// Address validation proves an address is real, not that it is
    /// friendly. This bound is what keeps a validated attacker's CPU cost
    /// linear in the number of addresses it actually holds.
    #[test]
    fn a_single_source_cannot_buy_unlimited_handshakes() {
        let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
        let attacker: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let bystander: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let start = Instant::now();

        for attempt in 1..=MAX_HANDSHAKES_PER_SOURCE {
            assert!(
                limiter.admit(attacker, start),
                "attempt {attempt} is within the budget"
            );
        }
        assert!(
            !limiter.admit(attacker, start),
            "the budget must run out for this address"
        );
        // One noisy address must not deny the service to everyone else.
        assert!(limiter.admit(bystander, start));

        // The window slides: the budget comes back rather than banning.
        let later = start + SOURCE_RATE_WINDOW + Duration::from_secs(1);
        assert!(limiter.admit(attacker, later));
        assert!(
            limiter.seen.len() <= 2,
            "expired entries must be pruned rather than accumulate"
        );
    }

    /// Counting IPv6 per exact address is the same as not counting it.
    ///
    /// A subscriber is routinely handed a `/64`, which is 2^64 addresses: an
    /// attacker with one of those can spend a fresh source for every single
    /// handshake and never meet the budget. Bucketing by prefix is what makes
    /// the IPv6 limit mean anything at all.
    #[test]
    fn an_ipv6_attacker_cannot_walk_out_of_its_own_budget() {
        let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
        let start = Instant::now();

        // Every attempt from a different address inside one /64.
        for attempt in 0..=MAX_HANDSHAKES_PER_SOURCE {
            let source: std::net::IpAddr =
                format!("2001:db8:1:1::{:x}", attempt + 1).parse().unwrap();
            let admitted = limiter.admit(rate_bucket(source), start);
            if attempt == MAX_HANDSHAKES_PER_SOURCE {
                assert!(!admitted, "the whole /64 shares one budget");
            } else {
                assert!(admitted, "attempt {attempt} is within the budget");
            }
        }

        // A neighbouring /64 is a different subscriber and keeps its own.
        let neighbour: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        assert!(limiter.admit(rate_bucket(neighbour), start));
    }

    /// The concurrency permit is held for the whole connection, so a
    /// connection that never ends is a permit that never returns.
    #[test]
    fn the_absolute_lifetime_covers_every_phase_it_must_contain() {
        // A challenge round trip, then a preparation, then the longest
        // confirmation wait a client may be told to observe.
        let phases = CHALLENGE_TIMEOUT
            + RESPONSE_TIMEOUT
            + Duration::from_secs(aether::key_negotiation::MAX_CONFIRMATION_TIMEOUT_SECS as u64);
        assert!(
            MAX_CONNECTION_LIFETIME >= phases,
            "an honest negotiation must never be cut short by the ceiling meant for hostile ones"
        );
        assert!(
            MAX_CONNECTION_LIFETIME > TRANSACTION_IDLE_TIMEOUT,
            "the ceiling exists because the idle timeout cannot bound a busy connection"
        );
    }

    #[test]
    fn all_modes_prepare_exactly_one_wireguard_slot_state() {
        let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);

        let base = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: TEST_CHALLENGE,
            transaction_id: [1; 16],
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: TEST_SERVER_NAME.into(),
            gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
            client_nonce: [2; 16],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_commitment: None,
        };
        // Every other mode prepares a slot. `classic` prepares nothing,
        // because it no longer exists as a negotiation outcome: a tunnel with
        // no preshared key is a plain WireGuard profile.
        //
        // `Protocol`, not `Rejected`: this is a decoding refusal, and it says
        // nothing about the peer. That the mode is retired is public
        // knowledge, unlike a peer's floor or its admission status.
        assert!(matches!(
            prepare_key_material(
                &base,
                GATEWAY_WG_KEY,
                [3; 16],
                Some(&static_psk),
                DEFAULT_CONFIRMATION_TIMEOUT,
            ),
            Err(PublicError::Protocol)
        ));

        let mut static_request = base.clone();
        static_request.mode = ProtectionMode::StaticPsk;
        static_request.static_psk_commitment = Some(commitment(&static_psk, &static_request));
        let prepared = prepare_key_material(
            &static_request,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&static_psk),
            DEFAULT_CONFIRMATION_TIMEOUT,
        )
        .unwrap();
        assert_eq!(prepared.psk.unwrap().expose(), static_psk);

        let (_secret_key, public_key) = MlKem1024Kem::generate().unwrap();
        let mut kem_request = base;
        kem_request.mode = ProtectionMode::MlKem;
        kem_request.kem_public_key = Some(public_key);
        let prepared = prepare_key_material(
            &kem_request,
            GATEWAY_WG_KEY,
            [3; 16],
            None,
            DEFAULT_CONFIRMATION_TIMEOUT,
        )
        .unwrap();
        assert!(prepared.psk.is_some());
        assert!(prepared.response.kem_ciphertext.is_some());
    }

    /// Recomputes an engagement exactly as the gateway will.
    fn commitment(psk: &str, request: &KeyNegotiationRequest) -> String {
        static_psk_commitment(
            psk,
            &request.transaction_id,
            &request.client_nonce,
            &request.server_challenge,
            &request.client_wg_public_key,
            GATEWAY_WG_KEY,
        )
        .unwrap()
    }

    /// L'engagement prouve la possession **pour cette transaction** : celui
    /// d'un autre PSK ne passe pas, et rien dans le refus ne dit lequel des
    /// deux cas — pas de PSK configuré, ou mauvais PSK — s'est produit.
    #[test]
    fn static_mode_rejects_another_psk_commitment() {
        let configured = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let other = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let mut request = simple_request([1; 16]);
        request.mode = ProtectionMode::StaticPsk;
        request.static_psk_commitment = Some(commitment(&other, &request));
        assert!(matches!(
            prepare_key_material(
                &request,
                GATEWAY_WG_KEY,
                [3; 16],
                Some(&configured),
                DEFAULT_CONFIRMATION_TIMEOUT
            ),
            Err(PublicError::Rejected)
        ));

        // Le bon PSK, lui, passe — sinon le test ci-dessus ne prouverait rien.
        request.static_psk_commitment = Some(commitment(&configured, &request));
        assert!(prepare_key_material(
            &request,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&configured),
            DEFAULT_CONFIRMATION_TIMEOUT
        )
        .is_ok());
    }

    /// Deux transactions, le **même** PSK : deux engagements différents. C'est
    /// ce qui remplace l'empreinte stable de la v4, corrélable d'une session à
    /// l'autre par un simple observateur du port public.
    #[test]
    fn the_same_static_psk_commits_differently_each_transaction() {
        let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let first = simple_request([1; 16]);
        let mut second = simple_request([2; 16]);
        second.server_challenge = [6; SERVER_CHALLENGE_LEN];
        assert_ne!(commitment(&psk, &first), commitment(&psk, &second));
    }

    struct TestPki {
        ca_der: Vec<u8>,
        server: TlsIdentity,
        client: TlsIdentity,
        client_fingerprint: String,
        client_pq_certificate: PqCertificate,
        client_pq_private_key: Vec<u8>,
        gateway_pq_certificate: PqCertificate,
        gateway_pq_private_key: Vec<u8>,
    }

    fn pq_identity(
        subject: &str,
        role: PqCertificateRole,
        wireguard_public_key: &str,
    ) -> (PqCertificate, Vec<u8>) {
        let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [9; 16],
                subject: subject.into(),
                issuer: subject.into(),
                role,
                wireguard_public_key: wireguard_public_key.into(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            private_key.as_slice(),
        )
        .unwrap();
        (certificate, private_key.to_vec())
    }

    fn test_pki() -> TestPki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        fn leaf(
            name: &str,
            usage: ExtendedKeyUsagePurpose,
            ca: &Certificate,
            ca_key: &KeyPair,
        ) -> (Vec<u8>, Vec<u8>) {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, ca, ca_key).unwrap();
            (cert.der().to_vec(), key.serialize_der())
        }

        let ca_der = ca.der().to_vec();
        let (server_cert, server_key) = leaf(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client_cert, client_key) =
            leaf("orion", ExtendedKeyUsagePurpose::ClientAuth, &ca, &ca_key);
        let (client_pq_certificate, client_pq_private_key) =
            pq_identity("orion", PqCertificateRole::Client, CLIENT_WG_KEY);
        let (gateway_pq_certificate, gateway_pq_private_key) =
            pq_identity("localhost", PqCertificateRole::Gateway, GATEWAY_WG_KEY);
        TestPki {
            ca_der,
            server: TlsIdentity {
                certificate_chain: vec![server_cert, ca.der().to_vec()],
                private_key: server_key,
            },
            client_fingerprint: certificate_fingerprint_der(&client_cert),
            client: TlsIdentity {
                certificate_chain: vec![client_cert, ca.der().to_vec()],
                private_key: client_key,
            },
            client_pq_certificate,
            client_pq_private_key,
            gateway_pq_certificate,
            gateway_pq_private_key,
        }
    }

    /// A second client authority, independent from the one that issued the
    /// server identity in [`test_pki`].
    ///
    /// A renewed Orion leaf has exactly this shape: it chains to the domain
    /// `CA-TLS`, while the gateway leaf and the first client generation still
    /// belong to their original authorities.
    fn independent_client_identity(name: &str) -> (Vec<u8>, TlsIdentity) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec![name.into()]).unwrap();
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        (
            ca.der().to_vec(),
            TlsIdentity {
                certificate_chain: vec![leaf.der().to_vec(), ca.der().to_vec()],
                private_key: leaf_key.serialize_der(),
            },
        )
    }

    struct Handler {
        expected_fingerprint: String,
        reject_prepare: AtomicBool,
        confirmed: AtomicBool,
        rolled_back: AtomicBool,
        /// How many rollbacks actually ran to completion.
        rollbacks: std::sync::atomic::AtomicUsize,
        /// Held open by default; a test can close it to park a rollback on an
        /// `await` and then destroy the task sitting there.
        rollback_gate: tokio::sync::Semaphore,
        gateway_pq_certificate: PqCertificate,
        gateway_pq_private_key: Vec<u8>,
    }

    impl Handler {
        fn new(pki: &TestPki) -> Self {
            Self::with_rollback_permits(pki, tokio::sync::Semaphore::MAX_PERMITS)
        }

        /// A handler whose `rollback` blocks until the test lets it through.
        fn with_blocked_rollback(pki: &TestPki) -> Self {
            Self::with_rollback_permits(pki, 0)
        }

        fn with_rollback_permits(pki: &TestPki, permits: usize) -> Self {
            Self {
                expected_fingerprint: pki.client_fingerprint.clone(),
                reject_prepare: AtomicBool::new(false),
                confirmed: AtomicBool::new(false),
                rolled_back: AtomicBool::new(false),
                rollbacks: std::sync::atomic::AtomicUsize::new(0),
                rollback_gate: tokio::sync::Semaphore::new(permits),
                gateway_pq_certificate: pki.gateway_pq_certificate.clone(),
                gateway_pq_private_key: pki.gateway_pq_private_key.clone(),
            }
        }
    }

    #[async_trait]
    impl NegotiationHandler for Handler {
        fn announced_identity(&self) -> GatewayIdentity {
            GatewayIdentity {
                wg_public_key: GATEWAY_WG_KEY.into(),
                server_name: "localhost".into(),
            }
        }

        async fn prepare(
            &self,
            certificate_sha256: String,
            request: AuthenticatedKeyNegotiationRequest,
        ) -> Result<PreparedNegotiation, PublicError> {
            // A wrong TLS fingerprint is `Rejected` like every other
            // pre-installation refusal: the public boundary must not let a
            // caller tell an unknown peer from a mismatched certificate.
            if certificate_sha256 != self.expected_fingerprint {
                return Err(PublicError::Rejected);
            }
            if self.reject_prepare.load(Ordering::SeqCst) {
                return Err(PublicError::Rejected);
            }
            Ok(PreparedNegotiation {
                response: authenticate_response(
                    KeyNegotiationResponse {
                        protocol_version: KEY_NEGOTIATION_VERSION,
                        transaction_id: request.request.transaction_id,
                        server_challenge: request.request.server_challenge,
                        selected_mode: request.request.mode,
                        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
                        client_wg_public_key: request.request.client_wg_public_key.clone(),
                        gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
                        kem_ciphertext: None,
                        confirmation_timeout_secs: 2,
                        psk_lifetime_secs: match request.request.mode {
                            ProtectionMode::StaticPsk => 0,
                            _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
                        },
                    },
                    self.gateway_pq_certificate.clone(),
                    &self.gateway_pq_private_key,
                )
                .map_err(|_| PublicError::Protocol)?,
                confirmation_timeout: Duration::from_secs(2),
            })
        }

        async fn confirm(
            &self,
            confirmation: AuthenticatedKeyNegotiationConfirmation,
        ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
            self.confirmed.store(true, Ordering::SeqCst);
            authenticate_commit(
                confirmation.confirmation.server_challenge,
                confirmation.confirmation.transaction_id,
                &self.gateway_pq_private_key,
            )
            .map_err(|_| PublicError::Internal)
        }

        async fn resolve_admitted_peer(&self, certificate_sha256: &str) -> Option<String> {
            (certificate_sha256 == self.expected_fingerprint).then(|| CLIENT_WG_KEY.to_string())
        }

        async fn rollback(&self, _transaction_id: [u8; 16], _public_key: &str) {
            // The suspension point a real rollback has — it writes to the
            // data plane — and the one a cancelled task can be destroyed in.
            let _permit = self.rollback_gate.acquire().await;
            self.rolled_back.store(true, Ordering::SeqCst);
            self.rollbacks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The rollback survives the destruction of the task that owned it.
    ///
    /// This is what the absolute-lifetime timeout does to a connection still
    /// waiting for its confirmation: it drops the future, and dropping a
    /// future runs none of the exit paths. Before the guard existed that left
    /// the candidate PSK posed and the peer reserved, with nothing left able
    /// to resolve either — one unfinished connection locked an admitted peer
    /// out until the daemon restarted.
    #[tokio::test]
    async fn a_destroyed_connection_still_rolls_its_candidate_back() {
        let pki = test_pki();
        let handler = Arc::new(Handler::new(&pki));
        drop(RollbackGuard::arm(
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
            [3; 16],
            CLIENT_WG_KEY.into(),
        ));

        // `Drop` cannot await, so it spawns; yielding is what lets that run.
        tokio::task::yield_now().await;

        assert!(
            handler.rolled_back.load(Ordering::SeqCst),
            "a candidate must be undone even when nothing returns from the connection"
        );
    }

    #[tokio::test]
    async fn a_disarmed_guard_never_undoes_a_signed_commit() {
        let pki = test_pki();
        let handler = Arc::new(Handler::new(&pki));
        let mut guard = RollbackGuard::arm(
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
            [3; 16],
            CLIENT_WG_KEY.into(),
        );
        guard.disarm();
        drop(guard);

        tokio::task::yield_now().await;

        assert!(
            !handler.rolled_back.load(Ordering::SeqCst),
            "past the point of no return there is nothing to undo, and undoing it would hand a \
             client a valid commit against a gateway that had restored the previous state"
        );
    }

    /// A rollback destroyed **inside its own await** must be run again.
    ///
    /// The guard used to clear `armed` before awaiting the rollback, which
    /// reintroduced the hole it exists to close: the ceiling fires while the
    /// rollback is writing to the data plane, the task is destroyed, and
    /// `Drop` finds a guard that has already declared itself finished. The
    /// candidate stays posed and the peer stays reserved — and on the gateway
    /// side that window is real, because undoing removes the transaction
    /// record *before* it awaits the restore.
    #[tokio::test]
    async fn a_rollback_destroyed_inside_its_own_await_is_run_again() {
        let pki = test_pki();
        let handler = Arc::new(Handler::with_blocked_rollback(&pki));

        let task = tokio::spawn({
            let handler = Arc::clone(&handler) as Arc<dyn NegotiationHandler>;
            async move {
                let mut guard = RollbackGuard::arm(handler, [4; 16], CLIENT_WG_KEY.into());
                guard.roll_back().await;
            }
        });
        // Let it reach the suspension point inside `rollback`, then destroy
        // it there — which is exactly what the absolute ceiling does.
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert_eq!(
            handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the first attempt must not have completed, or this proves nothing"
        );

        handler.rollback_gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            while handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a rollback destroyed part-way through must be retried by the guard");
    }

    /// No phase may outlive the connection that carries it.
    ///
    /// The 45-second confirmation wait is the one that would: a client that
    /// dawdles before requesting leaves less than 45 seconds of budget, and
    /// the ceiling would then fire during the wait — destroying the task
    /// instead of timing the phase out. Clamping keeps the exit on an
    /// ordinary code path.
    #[test]
    fn a_phase_is_clamped_to_what_is_left_of_the_connection() {
        let nearly_over = Deadline(Instant::now() + Duration::from_secs(2));
        assert!(
            nearly_over.clamp(Duration::from_secs(45)) <= Duration::from_secs(2),
            "the confirmation wait must not outlast the connection's ceiling"
        );

        let over = Deadline(Instant::now() - Duration::from_secs(1));
        assert_eq!(
            over.clamp(Duration::from_secs(45)),
            Duration::ZERO,
            "past the ceiling every phase expires at once, rather than saturating backwards"
        );
    }

    /// The historical validator of an expired identity has no door on this
    /// transport (spec §7.5, §14.1).
    ///
    /// Recovery is an Astra decision, reached over the veth after an operator
    /// ceremony. QUIC carries three messages, its vocabulary is closed, and a
    /// recovery request is not a message it can be asked to read — so an
    /// expired leaf stays refused here for want of anything to present it to.
    #[test]
    fn the_quic_vocabulary_holds_no_recovery_message() {
        // The whole vocabulary, and the only member that needs no signed
        // material to build.
        assert!(serde_json::from_str::<ClientMessage>(
            r#"{"type":"challenge_request","protocol_version":5}"#
        )
        .is_ok());

        // A recovery request has no discriminant here.
        for smuggled in [
            r#"{"type":"expired_certificate_recovery_request"}"#,
            r#"{"type":"recovery"}"#,
            r#"{"type":"historical_certificate"}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientMessage>(smuggled).is_err(),
                "the transport accepted {smuggled}"
            );
        }

        // Nor can one ride inside a message that does exist: the frames deny
        // unknown fields, so a historical proof appended to a legal request is
        // a frame the transport never parses.
        assert!(serde_json::from_str::<ClientMessage>(
            r#"{"type":"challenge_request","protocol_version":5,"historical_certificate":"x"}"#
        )
        .is_err());
    }

    /// Monte le service et rend l'endpoint client, pour ne pas répéter huit
    /// lignes de PKI dans chaque test.
    fn bench(
        pki: &TestPki,
    ) -> (
        Arc<Handler>,
        tokio::task::JoinHandle<()>,
        Endpoint,
        SocketAddr,
    ) {
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.server,
            std::slice::from_ref(&pki.ca_der),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handler = Arc::new(Handler::new(pki));
        let task = tokio::spawn(serve(
            server,
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        ));
        let client = client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.client,
            pki.ca_der.clone(),
        )
        .unwrap();
        (handler, task, client, server_addr)
    }

    /// The mTLS boundary must accept a renewed client whose chain ends at the
    /// domain CA, even though the server certificate and first-generation
    /// clients still use the original CA.
    ///
    /// Exercising a real Quinn handshake matters here: checking that two DER
    /// blobs entered a `RootCertStore` would not prove rustls can build the
    /// second chain presented by Orion.
    #[tokio::test]
    async fn every_configured_client_ca_can_authenticate_a_connection() {
        let pki = test_pki();
        let (domain_ca, renewed_client) = independent_client_identity("renewed-orion");
        let client_cas = vec![pki.ca_der.clone(), domain_ca];
        let server =
            server_endpoint("127.0.0.1:0".parse().unwrap(), &pki.server, &client_cas).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut handler = Handler::new(&pki);
        handler.expected_fingerprint =
            certificate_fingerprint_der(&renewed_client.certificate_chain[0]);
        let handler = Arc::new(handler);
        let task = tokio::spawn(serve(
            server,
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        ));
        let client = client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &renewed_client,
            pki.ca_der.clone(),
        )
        .unwrap();

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .expect("the domain CA is one of the configured client roots");
        drop(pending);

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// An unrelated client authority remains outside the trust boundary.
    /// Adding the domain CA must be an explicit set extension, not a fallback
    /// that accepts any readable chain.
    #[tokio::test]
    async fn an_unconfigured_client_ca_is_refused_by_mtls() {
        let pki = test_pki();
        let (_untrusted_ca, untrusted_client) = independent_client_identity("untrusted-orion");
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.server,
            std::slice::from_ref(&pki.ca_der),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut handler = Handler::new(&pki);
        handler.expected_fingerprint =
            certificate_fingerprint_der(&untrusted_client.certificate_chain[0]);
        let handler = Arc::new(handler);
        let task = tokio::spawn(serve(
            server,
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        ));
        let client = client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &untrusted_client,
            pki.ca_der.clone(),
        )
        .unwrap();

        assert!(
            request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
                .await
                .is_err(),
            "a CA absent from the configured set must fail at the mTLS boundary"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// An empty trust set is a configuration error, not a server that starts
    /// successfully while refusing every legitimate client.
    #[test]
    fn an_empty_client_ca_set_is_refused() {
        let pki = test_pki();
        assert!(matches!(
            server_endpoint("127.0.0.1:0".parse().unwrap(), &pki.server, &[]),
            Err(TransportError::InvalidCertificate)
        ));
    }

    /// The nominal v5 sequence is challenge, request, response, confirmation,
    /// commit, then **closure**. The connection does not outlive the
    /// transaction, and closing it does not remove any PSK.
    #[tokio::test]
    async fn a_negotiation_ends_with_a_commit_and_a_closed_connection() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let challenge = pending.server_challenge();
        assert_ne!(
            challenge, [0u8; SERVER_CHALLENGE_LEN],
            "un challenge nul ne prouverait rien"
        );

        let mut request = simple_request([1; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = challenge;
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request.clone(),
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (response, session) = negotiate(&client, pending, &authenticated_request)
            .await
            .unwrap();
        response
            .response
            .validate_for(&request, GATEWAY_WG_KEY)
            .unwrap();

        let confirmation = authenticate_confirmation(
            challenge,
            request.transaction_id,
            &pki.client_pq_private_key,
        )
        .unwrap();
        let commit = session.confirm(confirmation).await.unwrap();
        commit
            .verify(&pki.gateway_pq_certificate.ml_dsa_87_public_key)
            .unwrap();
        assert_eq!(commit.server_challenge, challenge);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler.confirmed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // The key v5 property: the connection is over, and that says nothing
        // about the tunnel. In v4 the same closure released the slot; here it
        // must not trigger rollback, and this port can no longer remove a PSK.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !handler.rolled_back.load(Ordering::SeqCst),
            "closing the connection after commit must not undo anything"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// A terminal refusal must arrive as the public protocol error, not as a
    /// transport reset. Dropping the send stream immediately after writing
    /// this frame made Quinn discard it and Orion reported `connection lost`.
    #[tokio::test]
    async fn a_prepare_refusal_is_delivered_before_the_connection_closes() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);
        handler.reject_prepare.store(true, Ordering::SeqCst);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([9; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = pending.server_challenge();
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();

        match negotiate(&client, pending, &authenticated_request).await {
            Err(TransportError::Rejected(PublicError::Rejected)) => {}
            Err(error) => {
                panic!("the framed refusal must survive graceful connection teardown: {error}")
            }
            Ok(_) => panic!("a handler refusal must not produce a negotiated session"),
        }

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Le challenge est à usage unique : le rejouer sur une seconde connexion
    /// échoue, ce qui est exactement la propriété que la v4 n'avait pas.
    #[tokio::test]
    async fn a_challenge_cannot_be_replayed_on_another_connection() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let stolen = pending.server_challenge();
        drop(pending);

        // Nouvelle connexion, donc nouveau challenge — mais on présente
        // l'ancien, entièrement signé.
        let second = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([7; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = stolen;
        request.server_name = "localhost".into();
        let replayed = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let outcome = negotiate(&client, second, &replayed).await.err();
        assert!(
            matches!(outcome, Some(TransportError::Protocol(_))),
            "une requête portant le challenge d'une autre connexion doit être refusée : {outcome:?}"
        );
        assert!(!handler.confirmed.load(Ordering::SeqCst));

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Le client refuse une gateway qui annonce une autre identité, avant
    /// d'avoir produit la moindre signature.
    #[tokio::test]
    async fn a_gateway_announcing_another_identity_is_refused_before_signing() {
        let pki = test_pki();
        let (_handler, task, client, server_addr) = bench(&pki);

        let outcome = request_challenge(&client, server_addr, "localhost", CLIENT_WG_KEY)
            .await
            .err();
        assert!(
            matches!(outcome, Some(TransportError::Protocol(_))),
            "l'identité annoncée doit être comparée au profil : {outcome:?}"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// `release` has left this port: the legacy tag no longer decodes.
    ///
    /// Merely not sending it is insufficient. An outdated Orion and a migrated
    /// gateway must fail explicitly rather than silently. Rejection happens in
    /// the parser, before any handler, without revealing slot state.
    #[tokio::test]
    async fn the_legacy_quic_release_message_is_refused_as_a_protocol_error() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let PendingChallenge {
            connection,
            mut send,
            mut recv,
            challenge,
        } = pending;

        // The message exactly as v5 carried it before August 8, 2026.
        let legacy = serde_json::json!({
            "type": "release",
            "release": {
                "release": {
                    "protocol_version": KEY_NEGOTIATION_VERSION,
                    "server_challenge": challenge.server_challenge,
                    "installed_transaction_id": vec![4u8; KEY_NEGOTIATION_NONCE_LEN],
                    "client_wg_public_key": CLIENT_WG_KEY,
                    "gateway_wg_public_key": GATEWAY_WG_KEY,
                    "timestamp_unix": test_now(),
                },
                "certificate": pki.client_pq_certificate,
                "ml_dsa_87_signature": "",
            },
        });
        write_frame(&mut send, &legacy).await.unwrap();
        let _ = send.finish();

        // The gateway closes without acknowledging anything: `released` no
        // longer exists.
        let answer = tokio::time::timeout(
            Duration::from_secs(2),
            read_frame::<ServerMessage>(&mut recv),
        )
        .await
        .unwrap();
        assert!(
            answer.is_err(),
            "a removed tag must not produce an application response: {answer:?}"
        );
        assert!(!handler.rolled_back.load(Ordering::SeqCst));

        connection.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Une session abandonnée avant confirmation doit être défaite : c'est le
    /// rollback, qui n'existe que **avant** la signature du commit.
    #[tokio::test]
    async fn closing_an_unconfirmed_session_requests_rollback() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([4; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = pending.server_challenge();
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (_, session) = negotiate(&client, pending, &authenticated_request)
            .await
            .unwrap();
        drop(session);

        tokio::time::timeout(Duration::from_secs(5), async {
            while !handler.rolled_back.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!handler.confirmed.load(Ordering::SeqCst));
        client.close(0u32.into(), b"test complete");
        task.abort();
    }
}
