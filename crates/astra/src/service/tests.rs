use super::*;

#[test]
fn an_ipv6_budget_counts_prefixes_not_addresses() {
    let mut budget = SourceBudget::default();
    let first: IpAddr = "2001:db8::1".parse().unwrap();
    let second: IpAddr = "2001:db8::dead:beef".parse().unwrap();
    // Same /64: the two addresses share one budget.
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(first, 1_000));
    }
    assert!(
        !budget.charge(second, 1_000),
        "a second address in the same /64 must not reset the budget"
    );

    // A different /64 has its own.
    let elsewhere: IpAddr = "2001:db9::1".parse().unwrap();
    assert!(budget.charge(elsewhere, 1_000));
}

/// A dual-stack `[::]` listener hands IPv4 clients over as `::ffff:a.b.c.d`.
/// Each must keep its own IPv4 budget rather than share `::/64`.
#[test]
fn an_ipv4_mapped_source_is_charged_as_its_ipv4_address() {
    let mut budget = SourceBudget::default();
    let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    let plain: IpAddr = "203.0.113.7".parse().unwrap();
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(mapped, 1_000));
    }
    assert!(
        !budget.charge(plain, 1_000),
        "the mapped and plain forms are one source and share one budget"
    );
    let neighbour: IpAddr = "::ffff:203.0.113.8".parse().unwrap();
    assert!(
        budget.charge(neighbour, 1_000),
        "two IPv4 clients must never share a budget through their mapped form"
    );
}

/// An unbounded map turns a rate limit into a memory-exhaustion
/// primitive: every fresh source would cost an entry, and an attacker has
/// as many as they like.
#[test]
fn the_source_map_is_bounded_and_refuses_rather_than_growing() {
    let mut budget = SourceBudget::default();
    let mut accepted = 0usize;
    for index in 0..(MAX_TRACKED_SOURCES + 64) {
        let source: IpAddr = format!("2001:db8:{:x}:{:x}::1", index / 65_536, index % 65_536)
            .parse()
            .unwrap();
        if budget.charge(source, 1_000) {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, MAX_TRACKED_SOURCES,
        "past the ceiling a new source is refused, not admitted for free"
    );

    // The next window frees the whole table again.
    let fresh: IpAddr = "203.0.113.9".parse().unwrap();
    assert!(budget.charge(fresh, 1_000 + BUDGET_WINDOW_SECS));
}

/// One admitted peer must not be able to spend the authority's signature
/// budget from a thousand addresses.
#[test]
fn an_admitted_peer_has_its_own_budget() {
    let mut budget = SourceBudget::default();
    let peer = WireGuardKey::from_bytes([4; 32]);
    for _ in 0..PEER_BUDGET {
        assert!(budget.charge_peer(&peer, 1_000));
    }
    assert!(!budget.charge_peer(&peer, 1_000));
    assert!(budget.charge_peer(&WireGuardKey::from_bytes([5; 32]), 1_000));
    assert!(budget.charge_peer(&peer, 1_000 + BUDGET_WINDOW_SECS));
}

#[test]
fn a_budget_refills_at_the_next_window() {
    let mut budget = SourceBudget::default();
    let source: IpAddr = "203.0.113.7".parse().unwrap();
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(source, 1_000));
    }
    assert!(!budget.charge(source, 1_000));
    assert!(budget.charge(source, 1_000 + BUDGET_WINDOW_SECS));
}

/// Two distinct IPv4 sources never share a budget.
#[test]
fn two_ipv4_sources_have_two_budgets() {
    let mut budget = SourceBudget::default();
    let first: IpAddr = "198.51.100.1".parse().unwrap();
    let second: IpAddr = "198.51.100.2".parse().unwrap();
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(first, 1_000));
    }
    assert!(!budget.charge(first, 1_000));
    assert!(budget.charge(second, 1_000));
}

/// The refusal classes are the only thing a caller learns, and none of
/// them describes a certificate.
#[test]
fn every_refusal_maps_to_one_bounded_status() {
    for (error, expected) in [
        (ServiceError::Protocol, StatusCode::BAD_REQUEST),
        (ServiceError::Refused, StatusCode::FORBIDDEN),
        (ServiceError::Throttled, StatusCode::TOO_MANY_REQUESTS),
        (ServiceError::HeldBack, StatusCode::CONFLICT),
        (
            ServiceError::OperatorCredentialUnavailable,
            StatusCode::NOT_IMPLEMENTED,
        ),
        (ServiceError::Internal, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        assert_eq!(error.into_response().status(), expected, "{error:?}");
    }
}

/// A capability token travels in one header, and nowhere else (§8.2).
///
/// A token in a path would be in every proxy log and every browser history
/// on the way. Accepting one from anywhere else is how it ends up there.
#[test]
fn a_bearer_is_read_from_the_authorization_header_alone() {
    let mut headers = HeaderMap::new();
    assert!(bearer(&headers).is_err(), "no header, no token");

    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer abc123".parse().expect("header"),
    );
    assert_eq!(bearer(&headers).expect("token"), "abc123");

    // Neither an empty credential nor another scheme is one.
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer ".parse().expect("header"),
    );
    assert!(bearer(&headers).is_err());
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Basic abc123".parse().expect("header"),
    );
    assert!(bearer(&headers).is_err());
}

/// The length ceiling is applied before parsing, so a caller cannot make
/// this process do work proportional to a string it chose.
#[test]
fn an_oversized_path_identifier_is_refused_before_it_is_parsed() {
    let long = "a".repeat(MAX_PATH_IDENTIFIER_BYTES + 1);
    assert!(matches!(path_id(&long), Err(ServiceError::Protocol)));

    // Inside the ceiling, a malformed identifier is a refusal and not a
    // protocol complaint: before a valid proof the endpoint says nothing
    // about what exists.
    assert!(matches!(path_id("not-hex"), Err(ServiceError::Refused)));
    assert!(path_id(&"ab".repeat(16)).is_ok());
}

#[cfg(test)]
mod http_routes {
    use super::*;
    use aether::certificates::{
        approval::{AstraIssuancePolicy, AstraPolicyPin},
        encoding::{generate_ml_dsa_87_keypair, TrustDomainId, WireGuardKey},
    };
    use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    struct Fixture {
        address: SocketAddr,
        _task: ServerTask,
        _directory: tempfile::TempDir,
        _service: Arc<AstraService>,
        ca_private_key: Zeroizing<Vec<u8>>,
    }

    struct ServerTask(tokio::task::JoinHandle<()>);

    impl Drop for ServerTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn fixture() -> Fixture {
        fixture_with_encrypted_vault(None).await
    }

    async fn fixture_with_encrypted_vault(encrypted_vault: Option<Vec<u8>>) -> Fixture {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let domain = TrustDomainId::new([1; 16]).expect("domain");
        let gateway = WireGuardKey::from_bytes([2; 32]);
        let (ca_private_key, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (service_private, service_public) =
            generate_ml_dsa_87_keypair().expect("service keypair");
        let policy = AstraIssuancePolicy::standard(domain, gateway, "astra.example".into())
            .fingerprint()
            .expect("policy fingerprint");
        let registry = AstraRegistry::new(
            directory.path().join("astra.json"),
            crate::registry::AstraState {
                trust_domain_id: domain,
                gateway_wg_public_key: gateway,
                server_name: "astra.example".into(),
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: AstraPolicyPin::new(policy).expect("policy pin"),
                credential_registry_epoch: 1,
                ca_epoch: 1,
                ca_public_key: ca_public,
                ca_rotation: None,
                ca_tls_epoch: 1,
                ca_tls_fingerprint: None,
                ca_tls_rotation: None,
                astra_service_key_epoch: 1,
                astra_service_public_key: service_public.clone(),
                issuer: None,
                transitions: Vec::new(),
                promoted_credentials: None,
                peers: BTreeMap::new(),
                status_epochs: BTreeMap::new(),
                audit: crate::audit::AuditChain::default(),
            },
        );
        let state_dir = directory.path().to_path_buf();
        let service = Arc::new(AstraService {
            registry: tokio::sync::Mutex::new(registry),
            issuer: RwLock::new(None),
            challenges: tokio::sync::Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
            budgets: tokio::sync::Mutex::new(SourceBudget::default()),
            service_private_key: service_private,
            service_public_key: service_public,
            operations: tokio::sync::Mutex::new(crate::operations::OperationStore::new()),
            capabilities: tokio::sync::Mutex::new(CapabilityTokens::new().expect("capability key")),
            approval_credentials: RwLock::new(Arc::new(crate::service::ApprovalCredentials {
                ids: Vec::new(),
                epoch: 1,
                registry: Some(Box::new(
                    aether::certificates::approval::CredentialRegistry {
                        trust_domain_id: domain,
                        gateway_wg_public_key: gateway,
                        ca_epoch: 1,
                        credential_registry_epoch: 1,
                        bindings: Vec::new(),
                    },
                )),
            })),
            signing: tokio::sync::Mutex::new(crate::signing::SigningOperationStore::new()),
            recoveries: tokio::sync::Mutex::new(crate::recovery::RecoveryStore::new()),
            reconciliation: tokio::sync::Mutex::new(()),
            encrypted_vault: RwLock::new(encrypted_vault.map(Arc::new)),
            state_dir,
            gateway: None,
            volume_writes: crate::door::VolumeWrites::new(),
        });
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let app = router(service.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Fixture {
            address,
            _task: ServerTask(task),
            _directory: directory,
            _service: service,
            ca_private_key,
        }
    }

    async fn request(
        fixture: &Fixture,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (u16, String, Vec<u8>) {
        let response = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut stream = TcpStream::connect(fixture.address).await.expect("connect");
            let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
            for (name, value) in headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await.expect("write headers");
            stream.write_all(body).await.expect("write body");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.expect("read response");
            response
        })
        .await
        .expect("HTTP request timed out");
        let separator = response
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("HTTP headers");
        let head = String::from_utf8_lossy(&response[..separator]);
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("status")
            .parse()
            .expect("numeric status");
        let content_type = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-type: ")
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        (status, content_type, response[separator + 4..].to_vec())
    }

    #[tokio::test]
    async fn public_route_methods_and_unimplemented_campaign_are_explicit() {
        let fixture = fixture().await;
        assert_eq!(
            request(&fixture, "POST", "/v1/status/challenge", &[], b"")
                .await
                .0,
            200
        );
        assert_eq!(
            request(&fixture, "GET", "/v1/status/challenge", &[], b"")
                .await
                .0,
            405
        );
        let (status, content_type, body) =
            request(&fixture, "POST", "/v1/campaigns", &[], b"{}").await;
        assert_eq!(status, 501);
        assert!(content_type.starts_with("application/json"));
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).expect("coarse error")["error"], "this operation needs the operator approval protocol, whose routes and signing commands are not implemented");
        assert_eq!(
            request(&fixture, "POST", "/v1/unknown", &[], b"").await.0,
            404
        );
        assert_eq!(
            request(&fixture, "GET", "/v1/campaigns", &[], b"").await.0,
            405
        );
    }

    #[tokio::test]
    async fn public_body_limit_and_malformed_json_are_enforced_before_handlers() {
        let fixture = fixture().await;
        let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            request(
                &fixture,
                "POST",
                "/v1/status/query",
                &[("content-type", "application/json")],
                &oversized
            )
            .await
            .0,
            413
        );
        assert_eq!(
            request(
                &fixture,
                "POST",
                "/v1/status/query",
                &[("content-type", "application/json")],
                b"{"
            )
            .await
            .0,
            400
        );
    }

    #[tokio::test]
    async fn real_connect_info_source_budget_returns_too_many_requests() {
        let mut observed_stable_window = false;
        for _attempt in 0..3 {
            let fixture = fixture().await;
            let window_at_start = now_unix() / BUDGET_WINDOW_SECS;
            for _ in 0..SOURCE_BUDGET {
                assert_eq!(
                    request(&fixture, "POST", "/v1/status/challenge", &[], b"")
                        .await
                        .0,
                    200
                );
            }
            let window_at_end = now_unix() / BUDGET_WINDOW_SECS;
            if window_at_start != window_at_end {
                continue;
            }

            let window_before_over_budget = now_unix() / BUDGET_WINDOW_SECS;
            if window_before_over_budget != window_at_start {
                continue;
            }
            let over_budget_status = request(&fixture, "POST", "/v1/status/challenge", &[], b"")
                .await
                .0;
            let window_after_over_budget = now_unix() / BUDGET_WINDOW_SECS;
            if window_after_over_budget != window_at_start {
                continue;
            }
            assert_eq!(over_budget_status, 429);
            observed_stable_window = true;
            break;
        }
        assert!(
            observed_stable_window,
            "three attempts crossed a source-budget window before a stable HTTP assertion"
        );
    }

    #[tokio::test]
    async fn status_query_consumes_challenge_and_keeps_bad_proof_and_unknown_peer_coarse() {
        use aether::certificates::{
            client::ClientCertificateGeneration,
            encoding::{MlDsa87Signature, WireGuardKey},
        };
        use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let fixture = fixture().await;
        let certificate_expires_at = now_unix() + 10 * 365 * 24 * 60 * 60;
        let client = WireGuardKey::from_bytes([0x37; 32]);
        let (_, subject_public_key) = generate_ml_dsa_87_keypair().expect("client keypair");
        let certificate = aether::key_negotiation::issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [0x52; 16],
                subject: "workstation".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: client.to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public_key.as_bytes()),
                not_before_unix: 0,
                not_after_unix: certificate_expires_at,
                ml_dsa_87_signature: String::new(),
            },
            &fixture.ca_private_key,
        )
        .expect("signed client certificate");
        let certificate_fingerprint =
            aether::certificates::gateway::pq_certificate_fingerprint(&certificate)
                .expect("certificate fingerprint");
        fixture
            ._service
            .registry
            .lock()
            .await
            .admit(
                crate::registry::PeerRecord {
                    name: "workstation".into(),
                    client_wg_public_key: client,
                    active: ClientCertificateGeneration {
                        generation: 4,
                        ca_tls_epoch: 1,
                        tls_ca_certificate_fingerprint: Fingerprint::of(b"TLS CA"),
                        tls_certificate_fingerprint: Fingerprint::of(b"active TLS"),
                        pq_certificate_fingerprint: certificate_fingerprint,
                        not_before: 0,
                        not_after: certificate_expires_at,
                    },
                    active_pq_certificate: certificate.clone(),
                    pending: None,
                    revoked: false,
                    revocation_epoch: 0,
                    admission_pq_ca: None,
                },
                1,
            )
            .expect("transcribe peer");

        let challenge_body = request(&fixture, "POST", "/v1/status/challenge", &[], b"").await;
        assert_eq!(challenge_body.0, 200);
        let challenge: ChallengeResponse =
            serde_json::from_slice(&challenge_body.2).expect("challenge response");
        let query = |client_wg_public_key| StatusQuery {
            astra_challenge: challenge.astra_challenge,
            request_id: Id16::new([0x63; 16]).expect("request ID"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            client_wg_public_key,
            certificate_fingerprint,
            certificate: certificate.clone(),
            signature: MlDsa87Signature::placeholder(),
        };
        let bad_proof_body = serde_json::to_vec(&query(client)).expect("query JSON");
        let bad_proof = request(
            &fixture,
            "POST",
            "/v1/status/query",
            &[("content-type", "application/json")],
            &bad_proof_body,
        )
        .await;
        assert_eq!(bad_proof.0, 403);
        assert!(
            !fixture
                ._service
                .challenges
                .lock()
                .await
                .consume(&challenge.astra_challenge, now_unix()),
            "a bad proof must still spend its single-use challenge before verification"
        );
        let replay = request(
            &fixture,
            "POST",
            "/v1/status/query",
            &[("content-type", "application/json")],
            &bad_proof_body,
        )
        .await;
        assert_eq!(bad_proof.0, replay.0);
        assert_eq!(bad_proof.2, replay.2);

        let other_challenge: ChallengeResponse = serde_json::from_slice(
            &request(&fixture, "POST", "/v1/status/challenge", &[], b"")
                .await
                .2,
        )
        .expect("second challenge");
        let unknown_query = StatusQuery {
            astra_challenge: other_challenge.astra_challenge,
            ..query(WireGuardKey::from_bytes([0x38; 32]))
        };
        let unknown_body = serde_json::to_vec(&unknown_query).expect("query JSON");
        let unknown = request(
            &fixture,
            "POST",
            "/v1/status/query",
            &[("content-type", "application/json")],
            &unknown_body,
        )
        .await;
        assert_eq!(unknown.0, bad_proof.0);
        assert_eq!(unknown.2, bad_proof.2);
    }

    #[tokio::test]
    async fn private_companion_routes_do_not_disclose_unknown_or_ordinary_operations() {
        let fixture = fixture().await;
        let ordinary_id = Id16::new([0x42; 16]).expect("operation ID");
        let client = WireGuardKey::from_bytes([0x24; 32]);
        let (_, new_public_key) = generate_ml_dsa_87_keypair().expect("client keypair");
        let rotation_request = Box::new(
            aether::certificates::client::ClientCertificateRotationRequest {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
                request_id: Id16::new([0x31; 16]).expect("request ID"),
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                server_name: "astra.example".into(),
                client_wg_public_key: client,
                active_generation: 4,
                requested_generation: 5,
                active_tls_certificate_fingerprint: Fingerprint::of(b"active TLS"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"active PQ"),
                tls_csr: aether::certificates::encoding::DerCertificate::new(vec![7; 64])
                    .expect("CSR"),
                new_ml_dsa_87_public_key: new_public_key,
                created_at: 1_000,
                expires_at: 5_000,
                active_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(
                ),
                new_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            },
        );
        let mut approval_request = aether::certificates::approval::AstraCredentialApprovalRequest {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            operation_id: ordinary_id,
            request_fingerprint: rotation_request.fingerprint(),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            client_wg_public_key: client,
            active_generation: 4,
            requested_generation: 5,
            credential_registry_epoch: 1,
            webauthn_rp_id: "astra.example".into(),
            webauthn_origin: "https://astra.example".into(),
            allowed_credential_ids: vec![vec![1]],
            required_credentials: 1,
            created_at: 1_000,
            expires_at: 1_300,
            astra_service_key_epoch: 1,
            astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        };
        approval_request.request_fingerprint = rotation_request.fingerprint();
        let ordinary = crate::operations::Operation::awaiting_operator(
            ordinary_id,
            client,
            rotation_request,
            Box::new(approval_request),
            1_000,
        );
        fixture
            ._service
            .operations
            .lock()
            .await
            .open(ordinary, 1_001)
            .expect("ordinary renewal operation");
        let unknown = request(
            &fixture,
            "GET",
            "/v1/operations/00000000000000000000000000000001",
            &[],
            b"",
        )
        .await;
        let malformed = request(&fixture, "GET", "/v1/operations/not-hex", &[], b"").await;
        let ordinary = request(
            &fixture,
            "GET",
            &format!("/v1/operations/{ordinary_id}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(unknown.0, 403);
        assert_eq!(unknown.0, malformed.0);
        assert_eq!(unknown.0, ordinary.0);
        assert_eq!(unknown.1, malformed.1);
        assert_eq!(unknown.2, ordinary.2);
        let body = String::from_utf8(unknown.2).expect("error body");
        assert!(!body.contains("operation"));
        assert_eq!(
            request(
                &fixture,
                "POST",
                "/v1/operations/00000000000000000000000000000001",
                &[],
                b"{}"
            )
            .await
            .0,
            405
        );
        let vault_path =
            "/v1/vaults/0101010101010101010101010101010101010101010101010101010101010101";
        assert_eq!(request(&fixture, "GET", vault_path, &[], b"").await.0, 400);
        assert_eq!(
            request(
                &fixture,
                "GET",
                vault_path,
                &[("authorization", "Bearer invalid")],
                b""
            )
            .await
            .0,
            403
        );
        let signer_path = "/v1/signer-requests/00000000000000000000000000000001";
        assert_eq!(request(&fixture, "GET", signer_path, &[], b"").await.0, 400);
        assert_eq!(
            request(
                &fixture,
                "GET",
                signer_path,
                &[("authorization", "Bearer invalid")],
                b""
            )
            .await
            .0,
            403
        );
        assert_eq!(
            request(
                &fixture,
                "POST",
                "/v1/signer-results/00000000000000000000000000000001",
                &[("content-type", "application/json")],
                b"{"
            )
            .await
            .0,
            400
        );
    }

    #[tokio::test]
    async fn a_valid_scope_bound_capability_reads_the_operator_request() {
        use aether::certificates::{
            capability::{CapabilityGrant, CapabilityScope},
            status::{
                AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget,
                CertificateKind,
            },
            CERTIFICATE_FORMAT_VERSION,
        };

        let fixture = fixture().await;
        let now = now_unix();
        let operation_id = Id16::new([0x61; 16]).expect("operation ID");
        let campaign = Box::new(AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([0x62; 16]).expect("campaign ID"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "astra.example".into(),
            created_at: now,
            expires_at: now + 3_000,
            scope: CampaignScope::FleetLeafs,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientPq,
                identity_key: WireGuardKey::from_bytes([3; 32]),
                epoch: 1,
                generation: 4,
                active_tls_certificate_fingerprint: Fingerprint::of(b"TLS"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"PQ"),
            }],
            reason: "rotation".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: CampaignScope::FleetLeafs.required_credentials(),
        });
        let vault_fingerprint = Fingerprint::of(b"encrypted vault");
        let signer_request = Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id,
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: vault_fingerprint,
            required_credentials: campaign.required_credentials,
            created_at: now,
            expires_at: now + 3_000,
            astra_service_key_epoch: 1,
            astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        });
        let operation =
            crate::signing::SigningOperation::new(campaign.clone(), signer_request, now)
                .expect("operator operation");
        fixture
            ._service
            .signing
            .lock()
            .await
            .open(operation, now)
            .expect("store operation");
        let grant = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            operation_id,
            campaign.fingerprint(),
            None,
            now,
            now + 120,
        )
        .expect("scope grant");
        let token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&grant, now + 3_000)
            .expect("bearer token");
        let authorization = format!("Bearer {token}");
        let headers = [("authorization", authorization.as_str())];
        let response = request(
            &fixture,
            "GET",
            &format!("/v1/signer-requests/{operation_id}"),
            &headers,
            b"",
        )
        .await;
        assert_eq!(response.0, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.2).expect("response JSON");
        assert_eq!(
            body["signer_request"]["operation_id"],
            operation_id.to_string()
        );
        assert_eq!(
            body["campaign"]["campaign_id"],
            campaign.campaign_id.to_string()
        );
        assert!(!String::from_utf8_lossy(&response.2).contains(&token));

        let wrong_scope_grant = CapabilityGrant::new(
            CapabilityScope::SignerResultSubmit,
            operation_id,
            campaign.fingerprint(),
            None,
            now,
            now + 120,
        )
        .expect("wrong-scope grant");
        let wrong_scope_token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&wrong_scope_grant, now + 3_000)
            .expect("wrong-scope bearer");

        let other_operation_id = Id16::new([0x64; 16]).expect("other operation ID");
        let wrong_operation_grant = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            other_operation_id,
            campaign.fingerprint(),
            None,
            now,
            now + 120,
        )
        .expect("wrong-operation grant");
        let wrong_operation_token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&wrong_operation_grant, now + 3_000)
            .expect("wrong-operation bearer");

        let expired_grant = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            operation_id,
            campaign.fingerprint(),
            None,
            now.saturating_sub(120),
            now.saturating_sub(1),
        )
        .expect("expired grant");
        let expired_token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&expired_grant, now + 3_000)
            .expect("expired bearer");

        let missing_bearer = request(
            &fixture,
            "GET",
            &format!("/v1/signer-requests/{operation_id}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(missing_bearer.0, 400);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&missing_bearer.2)
                .expect("coarse protocol error")["error"],
            "malformed request"
        );
        for rejected_token in [wrong_scope_token, wrong_operation_token, expired_token] {
            let authorization = format!("Bearer {rejected_token}");
            let rejected = request(
                &fixture,
                "GET",
                &format!("/v1/signer-requests/{operation_id}"),
                &[("authorization", authorization.as_str())],
                b"",
            )
            .await;
            assert_eq!(rejected.0, 403);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&rejected.2)
                    .expect("coarse capability refusal")["error"],
                "refused"
            );
        }
    }

    #[tokio::test]
    async fn recovery_route_is_public_without_bearer_and_unknown_id_is_coarse() {
        let fixture = fixture().await;
        let known_shape = request(
            &fixture,
            "GET",
            "/v1/client-rotation/recovery/00000000000000000000000000000001",
            &[],
            b"",
        )
        .await;
        let malformed = request(
            &fixture,
            "GET",
            "/v1/client-rotation/recovery/not-hex",
            &[],
            b"",
        )
        .await;
        assert_eq!(known_shape.0, 403);
        assert_eq!(known_shape.0, malformed.0);
        assert_eq!(known_shape.2, malformed.2);
        assert_eq!(
            request(&fixture, "GET", "/v1/client-rotation/recovery", &[], b"")
                .await
                .0,
            405
        );
        assert_eq!(
            request(
                &fixture,
                "GET",
                "/v1/client-rotation/recovery/00000000000000000000000000000001/commit",
                &[],
                b""
            )
            .await
            .0,
            405
        );
    }

    #[tokio::test]
    async fn challenge_store_saturation_returns_429_without_evicting_live_challenges() {
        let fixture = fixture().await;
        let now = now_unix();
        let preserved = [0x91; 32];
        {
            let mut challenges = fixture._service.challenges.lock().await;
            assert!(challenges.issue(preserved, now));
            for index in 1..MAX_LIVE_CHALLENGES {
                let mut challenge = [0; 32];
                challenge[..8].copy_from_slice(&(index as u64).to_be_bytes());
                assert!(challenges.issue(challenge, now));
            }
        }

        let response = request(&fixture, "POST", "/v1/status/challenge", &[], b"").await;

        assert_eq!(response.0, 429);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.2).expect("error JSON")["error"],
            "too many requests from this source"
        );
        assert!(
            fixture
                ._service
                .challenges
                .lock()
                .await
                .consume(&preserved, now_unix()),
            "saturation must refuse the new challenge without evicting an issued one"
        );
    }

    async fn vault_read_capability(fixture: &Fixture, vault: &[u8]) -> (Fingerprint, String) {
        use aether::certificates::{
            capability::{CapabilityGrant, CapabilityScope},
            status::{
                AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget,
                CertificateKind,
            },
            CERTIFICATE_FORMAT_VERSION,
        };

        let now = now_unix();
        let operation_id = Id16::new([0x73; 16]).expect("operation ID");
        let domain = TrustDomainId::new([1; 16]).expect("domain");
        let gateway = WireGuardKey::from_bytes([2; 32]);
        let vault_fingerprint = Fingerprint::of(vault);
        let campaign = Box::new(AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([0x74; 16]).expect("campaign ID"),
            trust_domain_id: domain,
            gateway_wg_public_key: gateway,
            server_name: "astra.example".into(),
            created_at: now,
            expires_at: now + 3_000,
            scope: CampaignScope::TrustAuthorities,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::CaPq,
                identity_key: gateway,
                epoch: 1,
                generation: 1,
                active_tls_certificate_fingerprint: Fingerprint::of(b"active TLS CA"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"active PQ CA"),
            }],
            reason: "scheduled anchor rotation".into(),
            requested_by: "test operator".into(),
            policy_fingerprint: AstraIssuancePolicy::standard(
                domain,
                gateway,
                "astra.example".into(),
            )
            .fingerprint()
            .expect("policy fingerprint"),
            required_credentials: CampaignScope::TrustAuthorities.required_credentials(),
        });
        let signer_request = Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id,
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: vault_fingerprint,
            required_credentials: campaign.required_credentials,
            created_at: now,
            expires_at: now + 3_000,
            astra_service_key_epoch: 1,
            astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        });
        let operation =
            crate::signing::SigningOperation::new(campaign.clone(), signer_request, now)
                .expect("valid authority campaign");
        fixture
            ._service
            .signing
            .lock()
            .await
            .open(operation, now)
            .expect("store operator campaign");

        let grant = CapabilityGrant::new(
            CapabilityScope::EncryptedVaultRead,
            operation_id,
            campaign.fingerprint(),
            Some(vault_fingerprint),
            now,
            now + 120,
        )
        .expect("vault-read capability");
        let token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&grant, now + 3_000)
            .expect("issue vault-read capability");
        (vault_fingerprint, token)
    }

    #[tokio::test]
    async fn encrypted_vault_route_requires_its_scope_and_exact_operation_fingerprint() {
        use aether::certificates::capability::{CapabilityGrant, CapabilityScope};

        let vault = b"encrypted HVLT fixture";
        let fixture = fixture_with_encrypted_vault(Some(vault.to_vec())).await;
        let (fingerprint, token) = vault_read_capability(&fixture, vault).await;
        let authorization = format!("Bearer {token}");
        let response = request(
            &fixture,
            "GET",
            &format!("/v1/vaults/{fingerprint}"),
            &[("authorization", authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(response.0, 200);
        assert!(response.1.starts_with("application/octet-stream"));
        assert_eq!(response.2, vault);

        let operation_id = Id16::new([0x73; 16]).expect("operation ID");
        let campaign_fingerprint = fixture
            ._service
            .signing
            .lock()
            .await
            .get(&operation_id, now_unix())
            .expect("stored campaign")
            .manifest_fingerprint();
        let wrong_scope = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            operation_id,
            campaign_fingerprint,
            None,
            now_unix(),
            now_unix() + 120,
        )
        .expect("request-read capability");
        let wrong_scope_token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&wrong_scope, now_unix() + 3_000)
            .expect("issue request-read capability");
        let wrong_scope_authorization = format!("Bearer {wrong_scope_token}");
        let wrong_scope_response = request(
            &fixture,
            "GET",
            &format!("/v1/vaults/{fingerprint}"),
            &[("authorization", wrong_scope_authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(wrong_scope_response.0, 403);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wrong_scope_response.2)
                .expect("coarse capability error")["error"],
            "refused"
        );

        let other_fingerprint = Fingerprint::of(b"another encrypted vault");
        let mismatched_path = request(
            &fixture,
            "GET",
            &format!("/v1/vaults/{other_fingerprint}"),
            &[("authorization", authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(mismatched_path.0, 403);
        assert_eq!(mismatched_path.2, wrong_scope_response.2);
    }

    #[tokio::test]
    async fn encrypted_vault_route_reports_volume_size_and_fingerprint_mismatches_as_internal() {
        let vault = b"encrypted HVLT fixture";
        let oversized_vault = vec![0x55; MAX_RESPONSE_BYTES + 1];
        let fixture = fixture_with_encrypted_vault(Some(oversized_vault)).await;
        let (fingerprint, token) = vault_read_capability(&fixture, vault).await;
        let authorization = format!("Bearer {token}");

        let oversized = request(
            &fixture,
            "GET",
            &format!("/v1/vaults/{fingerprint}"),
            &[("authorization", authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(oversized.0, 500);
        assert!(!String::from_utf8_lossy(&oversized.2).contains("vault"));

        let mismatched_fixture =
            fixture_with_encrypted_vault(Some(b"different encrypted vault".to_vec())).await;
        let (mismatched_fingerprint, mismatched_token) =
            vault_read_capability(&mismatched_fixture, vault).await;
        assert_eq!(mismatched_fingerprint, fingerprint);
        let mismatched_authorization = format!("Bearer {mismatched_token}");
        let mismatched_volume = request(
            &mismatched_fixture,
            "GET",
            &format!("/v1/vaults/{fingerprint}"),
            &[("authorization", mismatched_authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(mismatched_volume.0, 500);
        assert_eq!(mismatched_volume.2, oversized.2);
    }

    async fn simultaneous_vault_operation(
        fixture: &Fixture,
        vault_fingerprint: Fingerprint,
        operation_bytes: [u8; 16],
        campaign_bytes: [u8; 16],
        scope: aether::certificates::status::CampaignScope,
        certificate_kind: aether::certificates::status::CertificateKind,
        identity_key: WireGuardKey,
    ) -> (Id16, String, String) {
        use aether::certificates::{
            capability::{CapabilityGrant, CapabilityScope},
            status::{AstraRotationCampaign, AstraSignerRequest, CampaignTarget},
            CERTIFICATE_FORMAT_VERSION,
        };

        let now = now_unix();
        let operation_id = Id16::new(operation_bytes).expect("operation ID");
        let domain = TrustDomainId::new([1; 16]).expect("domain");
        let gateway = WireGuardKey::from_bytes([2; 32]);
        let campaign = Box::new(AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new(campaign_bytes).expect("campaign ID"),
            trust_domain_id: domain,
            gateway_wg_public_key: gateway,
            server_name: "astra.example".into(),
            created_at: now,
            expires_at: now + 3_000,
            scope,
            targets: vec![CampaignTarget {
                certificate_kind,
                identity_key,
                epoch: 1,
                generation: 1,
                active_tls_certificate_fingerprint: Fingerprint::of(b"active TLS"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"active PQ"),
            }],
            reason: "test operation".into(),
            requested_by: "test operator".into(),
            policy_fingerprint: AstraIssuancePolicy::standard(
                domain,
                gateway,
                "astra.example".into(),
            )
            .fingerprint()
            .expect("policy fingerprint"),
            required_credentials: scope.required_credentials(),
        });
        let signer_request = Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id,
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: vault_fingerprint,
            required_credentials: campaign.required_credentials,
            created_at: now,
            expires_at: now + 3_000,
            astra_service_key_epoch: 1,
            astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        });
        let operation =
            crate::signing::SigningOperation::new(campaign.clone(), signer_request, now)
                .expect("valid vault campaign");
        fixture
            ._service
            .signing
            .lock()
            .await
            .open(operation, now)
            .expect("store simultaneous operation");

        let capabilities = fixture._service.capabilities.lock().await;
        let request_grant = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            operation_id,
            campaign.fingerprint(),
            None,
            now,
            now + 120,
        )
        .expect("signer-request capability");
        let request_token = capabilities
            .issue(&request_grant, now + 3_000)
            .expect("issue signer-request capability");
        let vault_grant = CapabilityGrant::new(
            CapabilityScope::EncryptedVaultRead,
            operation_id,
            campaign.fingerprint(),
            Some(vault_fingerprint),
            now,
            now + 120,
        )
        .expect("vault-read capability");
        let vault_token = capabilities
            .issue(&vault_grant, now + 3_000)
            .expect("issue vault-read capability");
        (operation_id, request_token, vault_token)
    }

    #[tokio::test]
    async fn simultaneous_authority_and_revocation_operations_share_only_the_named_vault() {
        use aether::certificates::{
            capability::{CapabilityGrant, CapabilityScope},
            status::{CampaignScope, CertificateKind},
        };

        let vault = b"shared encrypted HVLT fixture";
        let fixture = fixture_with_encrypted_vault(Some(vault.to_vec())).await;
        let fingerprint = Fingerprint::of(vault);
        let (authority_id, authority_request_token, authority_vault_token) =
            simultaneous_vault_operation(
                &fixture,
                fingerprint,
                [0x81; 16],
                [0x82; 16],
                CampaignScope::TrustAuthorities,
                CertificateKind::CaPq,
                WireGuardKey::from_bytes([2; 32]),
            )
            .await;
        let (revocation_id, revocation_request_token, revocation_vault_token) =
            simultaneous_vault_operation(
                &fixture,
                fingerprint,
                [0x83; 16],
                [0x84; 16],
                CampaignScope::EmergencyRevocation,
                CertificateKind::ClientPq,
                WireGuardKey::from_bytes([0x39; 32]),
            )
            .await;

        let authority_request = format!("Bearer {authority_request_token}");
        let authority_read = request(
            &fixture,
            "GET",
            &format!("/v1/signer-requests/{authority_id}"),
            &[("authorization", authority_request.as_str())],
            b"",
        )
        .await;
        assert_eq!(authority_read.0, 200);
        let authority_request_body: serde_json::Value =
            serde_json::from_slice(&authority_read.2).expect("authority request JSON");
        assert_eq!(
            authority_request_body["signer_request"]["operation_id"],
            authority_id.to_string()
        );

        let revocation_request = format!("Bearer {revocation_request_token}");
        let revocation_read = request(
            &fixture,
            "GET",
            &format!("/v1/signer-requests/{revocation_id}"),
            &[("authorization", revocation_request.as_str())],
            b"",
        )
        .await;
        assert_eq!(revocation_read.0, 200);
        let revocation_request_body: serde_json::Value =
            serde_json::from_slice(&revocation_read.2).expect("revocation request JSON");
        assert_eq!(
            revocation_request_body["signer_request"]["operation_id"],
            revocation_id.to_string()
        );

        for (path_id, wrong_token) in [
            (authority_id, revocation_request.as_str()),
            (revocation_id, authority_request.as_str()),
        ] {
            let wrong_operation = request(
                &fixture,
                "GET",
                &format!("/v1/signer-requests/{path_id}"),
                &[("authorization", wrong_token)],
                b"",
            )
            .await;
            assert_eq!(wrong_operation.0, 403);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&wrong_operation.2)
                    .expect("coarse capability error")["error"],
                "refused"
            );
        }

        for token in [&authority_vault_token, &revocation_vault_token] {
            let authorization = format!("Bearer {token}");
            let response = request(
                &fixture,
                "GET",
                &format!("/v1/vaults/{fingerprint}"),
                &[("authorization", authorization.as_str())],
                b"",
            )
            .await;
            assert_eq!(response.0, 200);
            assert_eq!(response.2, vault);
        }

        let unknown_operation = Id16::new([0x85; 16]).expect("unknown operation ID");
        let now = now_unix();
        let unknown_grant = CapabilityGrant::new(
            CapabilityScope::EncryptedVaultRead,
            unknown_operation,
            Fingerprint::of(b"unregistered campaign"),
            Some(fingerprint),
            now,
            now + 120,
        )
        .expect("unregistered-operation capability");
        let unknown_token = fixture
            ._service
            .capabilities
            .lock()
            .await
            .issue(&unknown_grant, now + 300)
            .expect("issue unregistered-operation capability");
        let unknown_authorization = format!("Bearer {unknown_token}");
        let unknown_vault_read = request(
            &fixture,
            "GET",
            &format!("/v1/vaults/{fingerprint}"),
            &[("authorization", unknown_authorization.as_str())],
            b"",
        )
        .await;
        assert_eq!(unknown_vault_read.0, 403);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&unknown_vault_read.2)
                .expect("coarse capability error")["error"],
            "refused"
        );
    }
}
