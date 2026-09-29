use super::*;
use aether::certificates::client::{ClientCertificateGeneration, GatewayCertificateStageReceipt};
use aether::certificates::encoding::Fingerprint;
use axum::body::Body;
use axum::http::Request;
use std::sync::Mutex;
use tower::ServiceExt as _;

/// The two relayed surfaces address two prefixes, and never each other.
///
/// This is where "an operator route reaches no peer's renewal operation"
/// is actually decided (spec §8.5.2): the same 128-bit identifier under
/// the operator prefix reaches the campaign store, and under the rotation
/// prefix the renewal one. A single builder with a prefix argument would
/// be one wrong argument away from crossing them.
#[test]
fn a_campaign_path_and_a_renewal_path_never_name_the_same_route() {
    let id = Id16::new([7; 16]).expect("identifier");
    let campaign = operator_path("operations", &id.to_string());
    let renewal = operation_path("operations", &id);

    assert!(campaign.starts_with(ASTRA_OPERATOR_PREFIX));
    assert!(renewal.starts_with(ASTRA_INTERNAL_PREFIX));
    assert_ne!(campaign, renewal);
    assert!(!campaign.starts_with(ASTRA_INTERNAL_PREFIX));
    assert!(!renewal.starts_with(ASTRA_OPERATOR_PREFIX));
    assert!(!ASTRA_OPERATOR_PREFIX.starts_with(ASTRA_TRUST_UPDATE_PREFIX));
}

/// A path segment a caller chose cannot escape its segment.
///
/// The identifiers are hexadecimal today, so nothing in them needs
/// escaping — which is exactly how the next change of encoding introduces
/// a traversal. The encoder is what makes that impossible rather than
/// improbable.
#[test]
fn an_operator_path_segment_cannot_escape_its_segment() {
    let path = operator_path("vaults", "../../internal/v1/client-rotation/request");
    assert!(
        path.starts_with(ASTRA_OPERATOR_PREFIX),
        "the prefix is not something a caller can leave"
    );
    let segment = path
        .strip_prefix(&format!("{ASTRA_OPERATOR_PREFIX}vaults/"))
        .expect("the collection is the gateway's, not the caller's");
    assert!(
        !segment.contains('/'),
        "an encoded segment holds no separator, so it stays one segment: {segment}"
    );
    assert!(!path.contains("client-rotation/request"));
}

/// The private result envelope has a fixed and explicitly reserved cost.
///
/// The canonical result may consume the whole public 64 KiB allowance.
/// Only a typed WireGuard key (or the smaller development marker) is added
/// on the private hop, so the extra 256-byte allowance must cover every
/// identity variant and the surrounding JSON field names.
#[test]
fn every_operator_identity_fits_the_reserved_relay_overhead() {
    for operator in [
        OperatorIdentity::WireGuard {
            public_key: WireGuardKey::from_bytes([7; 32]),
        },
        OperatorIdentity::DevLoopback,
    ] {
        let envelope = serde_json::json!({
            "operator": operator,
            "result": null,
        });
        let encoded = serde_json::to_vec(&envelope).expect("operator envelope");
        let overhead = encoded.len() - b"null".len();
        assert!(
            overhead <= MAX_OPERATOR_RELAY_BODY_BYTES - MAX_OPERATOR_REQUEST_BYTES,
            "operator envelope uses {overhead} bytes"
        );
    }
}

/// A disposable transport identity, built exactly as the two `init`
/// commands build theirs.
struct Disposable {
    identity: ChannelIdentity,
    certificate: DerCertificate,
}

fn disposable(name: &str, role: PinnedRole) -> Disposable {
    let (certificate_der, private_key_der) = self_signed(name, role, 30);
    Disposable {
        certificate: DerCertificate::new(certificate_der.clone()).expect("der"),
        identity: ChannelIdentity {
            certificate_der,
            private_key_der,
        },
    }
}

fn self_signed(name: &str, role: PinnedRole, days: i64) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![match role {
        PinnedRole::Client => ExtendedKeyUsagePurpose::ClientAuth,
        PinnedRole::Server => ExtendedKeyUsagePurpose::ServerAuth,
    }];
    let now = time::OffsetDateTime::now_utc();
    if days >= 0 {
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(days);
    } else {
        // Entirely in the past: a pin that has run out of window.
        params.not_before = now + time::Duration::days(days * 2);
        params.not_after = now + time::Duration::days(days);
    }
    let key_pair = KeyPair::generate().expect("keygen");
    let certificate = params.self_signed(&key_pair).expect("self-signed");
    (certificate.der().to_vec(), key_pair.serialize_der())
}

struct SpyHandler {
    seen: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl AstraStageHandler for SpyHandler {
    async fn stage_from_astra(
        &self,
        _authorization: Box<ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("stage");
        Err(TrustUpdateRefusal::Rejected)
    }
}

#[async_trait]
impl AstraChannelHandler for SpyHandler {
    async fn revoke(
        &self,
        _revocation: Box<EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("revoke");
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn gateway_transition_published(
        &self,
        _published: GatewayTransitionPublished,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen
            .lock()
            .unwrap()
            .push("gateway_transition_published");
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn distribute(
        &self,
        _distribution: Box<TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("distribute");
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn commit_recovery(
        &self,
        _relayed: Box<RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("commit_recovery");
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn peer_state(
        &self,
        _identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("peer_state");
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn gateway_identity(&self) -> Result<GatewayIdentityView, TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("gateway_identity");
        Err(TrustUpdateRefusal::Rejected)
    }
}

fn spy() -> Arc<SpyHandler> {
    Arc::new(SpyHandler {
        seen: Mutex::new(Vec::new()),
    })
}

async fn status_of(handler: Arc<SpyHandler>, method: &str, uri: &str) -> StatusCode {
    router(handler)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The listener serves the lifecycle and nothing else. Everything the
/// gateway exposes elsewhere — administration, WebSocket, console — is
/// refused by the router, not by convention.
#[tokio::test]
async fn only_the_certificate_routes_exist() {
    for (method, uri) in [
        ("GET", "/api/status"),
        ("POST", "/api/peers"),
        ("POST", "/api/peers/revoke"),
        ("POST", "/api/network"),
        ("GET", "/api/network"),
        ("POST", "/api/tunnel/start"),
        ("POST", "/api/key-negotiation/release"),
        ("POST", "/api/key-negotiation/trust-update"),
        ("GET", "/ws"),
        ("GET", "/"),
        ("POST", "/internal/v1/campaigns/apply"),
        ("GET", "/internal/v1/certificates"),
        ("GET", "/internal/v1/certificates/state"),
    ] {
        let handler = spy();
        assert_eq!(
            status_of(Arc::clone(&handler), method, uri).await,
            StatusCode::NOT_FOUND,
            "{method} {uri} was served by the private listener"
        );
        assert!(
            handler.seen.lock().unwrap().is_empty(),
            "{method} {uri} reached a handler"
        );
    }
}

/// The three live routes reach their handler, and a body the API cannot
/// read never does.
#[tokio::test]
async fn the_live_routes_reach_their_handler() {
    for path in [STAGE_PATH, REVOKE_PATH] {
        let handler = spy();
        assert_eq!(
            status_of(Arc::clone(&handler), "POST", path).await,
            StatusCode::BAD_REQUEST,
            "an empty object is not a lifecycle object"
        );
        assert!(
            handler.seen.lock().unwrap().is_empty(),
            "{path} handed an unreadable body to the registry"
        );
    }

    let handler = spy();
    let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment("AAAA"));
    assert_eq!(
        status_of(Arc::clone(&handler), "GET", &uri).await,
        StatusCode::BAD_REQUEST,
        "a malformed key never reaches the registry"
    );
    assert!(handler.seen.lock().unwrap().is_empty());

    let handler = spy();
    let key = WireGuardKey::from_bytes([7; 32]).to_base64();
    let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment(&key));
    assert_eq!(
        status_of(Arc::clone(&handler), "GET", &uri).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(handler.seen.lock().unwrap().as_slice(), ["peer_state"]);
}

/// A commit on this link carries a whole relayed document, and a body that
/// is not one never reaches the registry: an empty POST is a protocol
/// error, not an ordinary commit that happened to arrive here.
#[tokio::test]
async fn a_commit_without_its_authorization_never_reaches_the_registry() {
    let handler = spy();
    assert_eq!(
        status_of(Arc::clone(&handler), "POST", STAGE_COMMIT_PATH).await,
        StatusCode::BAD_REQUEST
    );
    assert!(
        handler.seen.lock().unwrap().is_empty(),
        "the handler decides which stagings are recoveries; it must not be asked about \
             something that is not even a commit"
    );
}

#[test]
fn every_refusal_maps_to_one_bounded_status() {
    for (refusal, expected) in [
        (InternalRefusal::Protocol, StatusCode::BAD_REQUEST),
        (InternalRefusal::Rejected, StatusCode::FORBIDDEN),
        (
            InternalRefusal::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (InternalRefusal::Internal, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        assert_eq!(refusal.status(), expected, "{refusal:?}");
    }
}

/// Both configurations state the same bounds. A bound only one side
/// declares bounds only that side.
#[test]
fn both_ends_refuse_tls12_resumption_and_early_data() {
    let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
    let astra = disposable("astra.internal", PinnedRole::Client);

    let server = server_config(&gateway.identity, &astra.certificate).expect("server");
    assert_eq!(server.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
    assert_eq!(
        server.send_tls13_tickets, 0,
        "a ticket is what enables psk_ke"
    );
    assert_eq!(server.max_early_data_size, 0, "0-RTT is replayable");
    assert!(
        server
            .crypto_provider()
            .cipher_suites
            .iter()
            .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
        "the server kept a TLS 1.2 suite"
    );

    let client = client_config(&astra.identity, &gateway.certificate).expect("client");
    assert_eq!(client.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
    assert!(!client.enable_early_data, "0-RTT is replayable");
    assert!(
        client
            .crypto_provider()
            .cipher_suites
            .iter()
            .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
        "the client kept a TLS 1.2 suite"
    );
}

/// Runs one complete handshake between two in-memory connections.
///
/// No socket: what is under test is the key schedule the two
/// configurations agree on, and a listener would only add a port to it.
fn handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Vec<u8> {
    for _ in 0..16 {
        let mut to_server = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut to_server).expect("client writes");
        }
        if !to_server.is_empty() {
            server
                .read_tls(&mut to_server.as_slice())
                .expect("server reads");
            server.process_new_packets().expect("server processes");
        }

        let mut to_client = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut to_client).expect("server writes");
        }
        if !to_client.is_empty() {
            client
                .read_tls(&mut to_client.as_slice())
                .expect("client reads");
            client.process_new_packets().expect("client processes");
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            let exported = client
                .export_keying_material(vec![0u8; 32], b"helios veth session probe", None)
                .expect("exporter");
            assert_eq!(
                exported,
                server
                    .export_keying_material(vec![0u8; 32], b"helios veth session probe", None)
                    .expect("exporter"),
                "the two ends must agree on the session they just derived"
            );
            return exported;
        }
    }
    panic!("the handshake never completed");
}

/// Every reconnection derives its own session keys (spec §14.1).
///
/// It follows from the bounds the configurations declare — no ticket, no
/// resumption, no 0-RTT — but it is the property the specification names,
/// and the one an operator cares about: a captured veth session gives
/// nothing about the next one.
#[test]
fn each_veth_reconnection_derives_its_own_session_keys() {
    let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
    let astra = disposable("astra.internal", PinnedRole::Client);
    let server_config =
        Arc::new(server_config(&gateway.identity, &astra.certificate).expect("server"));
    let client_config =
        Arc::new(client_config(&astra.identity, &gateway.certificate).expect("client"));
    let name = rustls::pki_types::ServerName::try_from(INTERNAL_SERVER_NAME).expect("name");

    let mut keys = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let mut client = rustls::ClientConnection::new(Arc::clone(&client_config), name.clone())
            .expect("client connection");
        let mut server =
            rustls::ServerConnection::new(Arc::clone(&server_config)).expect("connection");
        keys.insert(handshake(&mut client, &mut server));
    }

    assert_eq!(
        keys.len(),
        3,
        "two reconnections landed on the same session keys"
    );
}

/// A pin has to be usable for the role it is pinned in, and it has to be
/// alive. Both are checked when the configuration is built, so a bad
/// install fails at startup rather than on the first rotation.
#[test]
fn a_pin_is_refused_when_it_is_the_wrong_role_or_expired() {
    let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
    let astra = disposable("astra.internal", PinnedRole::Client);

    // A `serverAuth` certificate pinned as the dialling identity can never
    // authenticate a client, and vice versa.
    assert!(
        matches!(
            server_config(&gateway.identity, &gateway.certificate),
            Err(ChannelError::Pin(_))
        ),
        "a serverAuth certificate was accepted as the pinned client"
    );
    assert!(
        matches!(
            client_config(&astra.identity, &astra.certificate),
            Err(ChannelError::Pin(_))
        ),
        "a clientAuth certificate was accepted as the pinned server"
    );

    // Well formed, right role, out of its window: refused at the handshake
    // rather than trusted for ever.
    let (stale_der, _) = self_signed("stale.internal", PinnedRole::Server, -1);
    let stale = DerCertificate::new(stale_der).expect("der");
    let verifier = PinnedPeer::new(&stale, PinnedRole::Server, provider()).expect("pin");
    let refusal = verifier.accept(
        &CertificateDer::from(stale.as_bytes().to_vec()),
        &[],
        UnixTime::now(),
    );
    assert!(
        matches!(
            refusal,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired
            ))
        ),
        "an expired pin was accepted: {refusal:?}"
    );
}

/// The pin is the identity. Another certificate — even a well-formed one
/// with the same name and the right usage — is refused, and so is a chain
/// that tries to be verified through an issuer.
#[test]
fn an_unpinned_identity_is_refused() {
    let astra = disposable("astra.internal", PinnedRole::Client);
    let impostor = disposable("astra.internal", PinnedRole::Client);
    let verifier =
        PinnedPeer::new(&astra.certificate, PinnedRole::Client, provider()).expect("pin");

    assert!(
        verifier
            .accept(
                &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
                &[],
                UnixTime::now()
            )
            .is_ok(),
        "the pinned identity must be accepted"
    );

    let refusal = verifier.accept(
        &CertificateDer::from(impostor.certificate.as_bytes().to_vec()),
        &[],
        UnixTime::now(),
    );
    assert!(
        matches!(
            refusal,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            ))
        ),
        "a second certificate with the same name was accepted: {refusal:?}"
    );

    let refusal = verifier.accept(
        &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
        &[CertificateDer::from(
            impostor.certificate.as_bytes().to_vec(),
        )],
        UnixTime::now(),
    );
    assert!(
        matches!(
            refusal,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ),
        "a chain was accepted on a link that has no issuer: {refusal:?}"
    );
}

/// The TLS 1.2 refusal exists in the verifier as well as in the version
/// list: the second one still stands if a future edit widens the first.
#[test]
fn a_tls12_signature_is_refused_by_the_verifier() {
    assert!(matches!(
        PinnedPeer::refuse_tls12(),
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
    ));
}

/// A WireGuard key is base64: unescaped, `/` splits it into path segments
/// and the route silently stops matching.
#[test]
fn a_base64_identity_survives_the_path() {
    let key = WireGuardKey::from_bytes([255; 32]).to_base64();
    assert!(key.contains('/') || key.contains('+') || key.contains('='));
    let encoded = percent_encode_segment(&key);
    assert!(!encoded.contains('/'));
    assert!(!encoded.contains('+'));
    assert!(!encoded.contains('='));
}

/// The view carries the bounded state and nothing else — no key, no PSK.
#[test]
fn the_state_view_serializes_no_secret() {
    let view = PeerCertificateStateView {
        name: "workstation".into(),
        state: ClientCertificateState::new(ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            not_before: 0,
            not_after: 1_000_000,
        }),
        active_pq_certificate: aether::key_negotiation::PqCertificate {
            version: 2,
            serial: [7; 16],
            subject: "workstation".into(),
            issuer: "operator".into(),
            role: aether::key_negotiation::PqCertificateRole::Client,
            wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
            ml_dsa_87_public_key: "cHVibGlj".into(),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: "c2lnbmF0dXJl".into(),
        },
        admission_pq_ca: None,
    };
    let encoded = serde_json::to_string(&view)
        .expect("encode")
        .to_ascii_lowercase();
    for forbidden in ["private", "preshared", "psk", "secret", "sealed"] {
        assert!(
            !encoded.contains(forbidden),
            "the state view mentions « {forbidden} »: {encoded}"
        );
    }
}
