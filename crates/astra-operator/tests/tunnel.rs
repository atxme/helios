//! The in-tunnel transport of §8.1.2, against a stub gateway.
//!
//! A stub and not a mock: the point is to exercise the HTTP that will actually
//! run, including the bearer headers, the paths and the answers a real gateway
//! returns. What the stub does not have is a security key, which is exactly
//! why every test here is about the transport and none is about the gesture.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use aether::certificates::approval::{AstraCredentialApprovalRequest, CredentialRegistry};
use aether::certificates::authority::{CaTransition, ClientTlsCaTransition};
use aether::certificates::encoding::{
    DerCertificate, Fingerprint, Id16, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
    OperatorAuthorityStatus, OperatorGatewayPublish, OperatorGatewayPublished, OperatorOpenAction,
    OperatorOpenRequest, OperatorOpened, OperatorVaultCopied, OperatorVaultCopy,
};
use aether::certificates::window::TransitionWindow;
use astra_operator::rotation_journal::RotationKind;
use astra_operator::tunnel::{Tunnel, TunnelRefusal, VaultCopySent};

const RP_ID: &str = "astra.helios.test";

fn operation() -> Id16 {
    Id16::new([4; 16]).expect("id")
}

fn approval_request(operation_id: Id16) -> AstraCredentialApprovalRequest {
    AstraCredentialApprovalRequest {
        format_version: 1,
        operation_id,
        request_fingerprint: Fingerprint::of(b"rotation request"),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        active_generation: 4,
        requested_generation: 5,
        credential_registry_epoch: 1,
        webauthn_rp_id: RP_ID.into(),
        webauthn_origin: format!("https://{RP_ID}"),
        allowed_credential_ids: vec![vec![7; 32]],
        required_credentials: 1,
        created_at: 1_700_000_000,
        expires_at: 1_700_000_300,
        astra_service_key_epoch: 1,
        // Never verified here: `approve_renewal` is what checks it, and this
        // module is the wire.
        astra_signature: MlDsa87Signature::placeholder(),
    }
}

fn view(
    operation_id: Id16,
    request: &AstraCredentialApprovalRequest,
) -> ClientRenewalOperationView {
    ClientRenewalOperationView {
        operation_id,
        state: ClientRenewalOperationState::AwaitingOperator,
        client_wg_public_key: request.client_wg_public_key,
        request_fingerprint: request.request_fingerprint,
        operation_manifest_fingerprint: request.fingerprint(),
        created_at: request.created_at,
        expires_at: request.expires_at,
        signer_request_token: Some("read-token".into()),
        signer_result_token: Some("result-token".into()),
        grant: None,
    }
}

/// What the gateway serves the companion, with the allow-list's own document.
///
/// The registry is never verified in these tests — `approve_renewal` is what
/// checks it under `CA-PQ`, and this module is the wire.
fn signer_request(
    operation_id: Id16,
    request: &AstraCredentialApprovalRequest,
) -> ClientRenewalSignerRequest {
    ClientRenewalSignerRequest {
        operation_id,
        approval_request: Box::new(request.clone()),
        credential_registry: Box::new(CredentialRegistry {
            trust_domain_id: request.trust_domain_id,
            gateway_wg_public_key: request.gateway_wg_public_key,
            ca_epoch: 1,
            credential_registry_epoch: request.credential_registry_epoch,
            bindings: Vec::new(),
        }),
        authority_url: "https://astra.helios.test".into(),
        webauthn_rp_id: RP_ID.into(),
    }
}

/// One request the stub saw: enough to assert on the route and the header.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// A gateway that answers a fixed script, and reports what it was asked.
///
/// The answers are given as `(status, json)` in the order the companion is
/// expected to make them. A test that ends with unused answers has not
/// exercised the path it thought it did.
struct Stub {
    base: String,
    seen: mpsc::Receiver<Seen>,
}

impl Stub {
    fn serving(answers: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let (sender, seen) = mpsc::channel();
        thread::spawn(move || {
            for (index, (status, body)) in answers.into_iter().enumerate() {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                match serve(stream, status, &body) {
                    Ok(request) => {
                        if sender.send(request).is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = index;
                        return;
                    }
                }
            }
        });
        Self { base, seen }
    }

    fn next(&self) -> Seen {
        self.seen
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the companion made a request")
    }
}

fn serve(mut stream: TcpStream, status: u16, body: &str) -> std::io::Result<Seen> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut authorization = None;
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("authorization:") {
            authorization = Some(value.trim().to_string());
        }
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload)?;
    }

    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(Seen {
        method,
        path,
        authorization,
        body: payload,
    })
}

/// The whole point: two reads, and the capability token on the second one.
///
/// The operation route is authenticated by the peer's VIP, so it carries no
/// bearer; the companion route is, so it must.
#[test]
fn the_companion_reads_the_operation_then_the_request_it_is_bound_to() {
    let operation_id = operation();
    let request = approval_request(operation_id);
    let signer = signer_request(operation_id, &request);
    let stub = Stub::serving(vec![
        (
            200,
            serde_json::to_string(&view(operation_id, &request)).unwrap(),
        ),
        (200, serde_json::to_string(&signer).unwrap()),
    ]);

    let fetched = Tunnel::new(&stub.base)
        .expect("tunnel")
        .fetch(&operation_id)
        .expect("the request this operation is waiting on");

    let first = stub.next();
    assert_eq!(first.method, "GET");
    assert_eq!(
        first.path,
        format!(
            "/api/key-negotiation/certificate-renewal/operations/{}",
            operation_id.to_hex()
        )
    );
    assert!(
        first.authorization.is_none(),
        "the operation route is authenticated by the VIP, not by a token"
    );

    let second = stub.next();
    assert_eq!(
        second.path,
        format!(
            "/api/key-negotiation/certificate-renewal/signer-requests/{}",
            operation_id.to_hex()
        )
    );
    assert_eq!(second.authorization.as_deref(), Some("bearer read-token"));

    assert_eq!(fetched.result_token, "result-token");
    assert_eq!(fetched.webauthn_rp_id, RP_ID);
    assert_eq!(fetched.approval_request.operation_id, operation_id);
}

/// The token is minted for one manifest. A request that is not the object the
/// operation is bound to is refused before an operator is shown anything.
#[test]
fn a_request_that_is_not_the_bound_manifest_is_refused() {
    let operation_id = operation();
    let request = approval_request(operation_id);
    let mut bound = view(operation_id, &request);
    bound.operation_manifest_fingerprint = Fingerprint::of(b"another manifest");
    let signer = signer_request(operation_id, &request);
    let stub = Stub::serving(vec![
        (200, serde_json::to_string(&bound).unwrap()),
        (200, serde_json::to_string(&signer).unwrap()),
    ]);

    let refusal = Tunnel::new(&stub.base)
        .expect("tunnel")
        .fetch(&operation_id)
        .expect_err("a manifest the token was not issued for");
    assert!(
        refusal.to_string().contains("manifeste"),
        "expected the manifest binding to be named, got: {refusal}"
    );
}

/// An operation that is past the operator, or that failed, is not something to
/// touch a key for — and each says a different thing to do next.
#[test]
fn an_operation_that_no_longer_awaits_an_operator_is_refused() {
    for (state, expected) in [
        (ClientRenewalOperationState::PendingCommit, "déjà approuvée"),
        (ClientRenewalOperationState::Failed, "échoué"),
    ] {
        let operation_id = operation();
        let request = approval_request(operation_id);
        let mut answer = view(operation_id, &request);
        answer.state = state;
        let stub = Stub::serving(vec![(200, serde_json::to_string(&answer).unwrap())]);

        let refusal = Tunnel::new(&stub.base)
            .expect("tunnel")
            .fetch(&operation_id)
            .expect_err("nothing to sign");
        assert!(
            refusal.to_string().contains(expected),
            "expected {expected:?}, got: {refusal}"
        );
    }
}

/// An expired window mints no token. Refusing here rather than at the deposit
/// is what keeps an operator from touching their key for nothing.
#[test]
fn an_operation_without_a_token_is_refused_before_the_key_is_touched() {
    let operation_id = operation();
    let request = approval_request(operation_id);
    let mut answer = view(operation_id, &request);
    answer.signer_result_token = None;
    let stub = Stub::serving(vec![(200, serde_json::to_string(&answer).unwrap())]);

    let refusal = Tunnel::new(&stub.base)
        .expect("tunnel")
        .fetch(&operation_id)
        .expect_err("no slot to post into");
    assert!(
        refusal.to_string().contains("cinq minutes"),
        "expected the capability window to be named, got: {refusal}"
    );
}

/// The assertion goes to the submission route, under the **result** token, and
/// the answer is where the operation landed.
#[test]
fn the_assertion_is_posted_under_the_result_token() {
    let operation_id = operation();
    let request = approval_request(operation_id);
    let mut landed = view(operation_id, &request);
    landed.state = ClientRenewalOperationState::PendingCommit;
    let stub = Stub::serving(vec![(200, serde_json::to_string(&landed).unwrap())]);

    let approval = sample_approval(operation_id);
    let state = Tunnel::new(&stub.base)
        .expect("tunnel")
        .submit(&operation_id, "result-token", &approval)
        .expect("posted");
    assert_eq!(state, ClientRenewalOperationState::PendingCommit);

    let seen = stub.next();
    assert_eq!(seen.method, "POST");
    assert_eq!(
        seen.path,
        format!(
            "/api/key-negotiation/certificate-renewal/signer-results/{}",
            operation_id.to_hex()
        )
    );
    assert_eq!(seen.authorization.as_deref(), Some("bearer result-token"));
    let sent: serde_json::Value = serde_json::from_slice(&seen.body).expect("json body");
    assert_eq!(
        sent["operation_id"].as_str(),
        Some(operation_id.to_hex().as_str()),
        "the body is the approval itself, not an envelope the gateway would have to unwrap"
    );
}

/// A refused token and an absent authority send the operator to two different
/// places, so they are the two the transport names.
#[test]
fn the_two_refusals_worth_telling_apart_are_named() {
    for (status, expected) in [(403u16, "cinq minutes"), (503, "Astra")] {
        let operation_id = operation();
        let stub = Stub::serving(vec![(status, "{}".into())]);
        let refusal = Tunnel::new(&stub.base)
            .expect("tunnel")
            .fetch(&operation_id)
            .expect_err("refused");
        assert!(
            refusal.to_string().contains(expected)
                || refusal
                    .source()
                    .is_some_and(|source| source.to_string().contains(expected)),
            "status {status} should name {expected:?}, got: {refusal:#}"
        );
    }
}

/// An address without a scheme is refused where it is typed, not at the first
/// call: the operator is at a prompt, and the error must point at the argument.
#[test]
fn an_address_without_a_scheme_is_refused() {
    assert!(Tunnel::new("100.64.0.1:8080").is_err());
    assert!(Tunnel::new("http://100.64.0.1:8080").is_ok());
}

/// Campaign responses use the public operator ceiling, not the larger bound
/// retained by the ordinary renewal transport.
#[test]
fn operator_campaign_answers_stop_at_128_kib() {
    let operation_id = operation();

    let within = format!("{{}}{}", " ".repeat(96 * 1024));
    let stub = Stub::serving(vec![(200, within)]);
    let refusal = Tunnel::new(&stub.base)
        .expect("tunnel")
        .fetch_campaign(&operation_id)
        .expect_err("an incomplete operation view");
    assert!(
        refusal.to_string().contains("lecture de l'opération")
            && !format!("{refusal:#}").contains("au-delà de la borne"),
        "a response below 128 KiB must reach decoding: {refusal:#}"
    );

    let oversized = " ".repeat(128 * 1024 + 1);
    let stub = Stub::serving(vec![(200, oversized)]);
    let refusal = Tunnel::new(&stub.base)
        .expect("tunnel")
        .fetch_campaign(&operation_id)
        .expect_err("an oversized campaign answer");
    assert!(
        format!("{refusal:#}").contains("au-delà de la borne"),
        "an answer above 128 KiB was not rejected at the transport boundary: {refusal:#}"
    );
}

/// An approval shaped like a real one. Nothing here verifies — the gesture
/// does that, on the operator's machine, with a key in hand. What the wire
/// carries is these bytes, and that is what the test asserts on.
fn sample_approval(operation_id: Id16) -> aether::certificates::approval::AstraRenewalApproval {
    use aether::certificates::approval::{
        AstraCredentialBinding, AstraRenewalApproval, CredentialState,
    };
    use aether::certificates::webauthn::WebAuthnAssertion;

    let assertion = WebAuthnAssertion {
        authenticator_data: vec![0; 37],
        client_data_json: b"{}".to_vec(),
        signature: vec![1; 64],
    };
    let binding = AstraCredentialBinding {
        format_version: 1,
        credential_id: vec![7; 32],
        credential_public_key: vec![8; 64],
        aaguid: [0; 16],
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 1_700_000_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    };
    AstraRenewalApproval {
        format_version: 1,
        operation_id,
        request_fingerprint: Fingerprint::of(b"rotation request"),
        approval_request_fingerprint: Fingerprint::of(b"approval request"),
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: assertion.fingerprint(),
        credential_binding: binding,
        webauthn_assertion: assertion,
        approved_at: 1_700_000_010,
        expires_at: 1_700_000_300,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    }
}

// ---------------------------------------------------------------------------
// The administrator routes a rotation travels on (lot 5b).
// ---------------------------------------------------------------------------

fn fingerprint_hex(seed: &[u8]) -> String {
    Fingerprint::of(seed).to_hex()
}

fn refusal_status(error: &anyhow::Error) -> Option<u16> {
    error
        .downcast_ref::<TunnelRefusal>()
        .map(|refusal| refusal.status)
}

/// A rotation's opening, as the gateway's route takes it.
#[test]
fn a_campaign_opens_on_the_operator_route() {
    let opened = OperatorOpened {
        operation_id: operation(),
        campaign_id: Id16::new([5; 16]).expect("id"),
        campaign_fingerprint: Fingerprint::of(b"campagne"),
        scope: aether::certificates::status::CampaignScope::TrustAuthorities,
        target_count: 1,
        required_credentials: 2,
        expires_at: 1_700_000_300,
        revocation_expiries: None,
        delegation_request: None,
        gateway_certificate: None,
    };
    let stub = Stub::serving(vec![(200, serde_json::to_string(&opened).expect("json"))]);
    let request = OperatorOpenRequest {
        action: OperatorOpenAction::TrustAuthorities,
        reason: "remplacement".into(),
        requested_by: "opératrice".into(),
        window_secs: 300,
    };
    let answer = Tunnel::new(&stub.base)
        .expect("tunnel")
        .open_campaign(&request)
        .expect("opened");
    assert_eq!(answer, opened);

    let seen = stub.next();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/api/certificates/operator/campaigns");
    assert_eq!(seen.authorization, None);
    let sent: OperatorOpenRequest = serde_json::from_slice(&seen.body).expect("body");
    assert_eq!(sent, request);
}

#[test]
fn the_authority_status_is_read_on_the_operator_route() {
    let status = OperatorAuthorityStatus {
        ca_epoch: 1,
        ca_fingerprint: Fingerprint::of(b"ca"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: None,
        next_ca_tls_fingerprint: Some(Fingerprint::of(b"suivante")),
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
        revoked_peers: Vec::new(),
        served_credentials: None,
    };
    let stub = Stub::serving(vec![(200, serde_json::to_string(&status).expect("json"))]);
    let answer = Tunnel::new(&stub.base)
        .expect("tunnel")
        .authority_status()
        .expect("status");
    assert_eq!(answer, status);
    let seen = stub.next();
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/api/certificates/operator/status");
}

/// A vault above the 64 KiB relay bound travels whole: it has a route bound of
/// its own, and this side must not assume the smaller one.
#[test]
fn a_vault_copy_above_the_relay_bound_is_sent_whole() {
    let copied = OperatorVaultCopied {
        fingerprint: Fingerprint::of(b"coffre"),
        credential_registry_epoch: None,
    };
    let stub = Stub::serving(vec![(200, serde_json::to_string(&copied).expect("json"))]);
    let copy = OperatorVaultCopy {
        vault_base64: "A".repeat(100 * 1024),
        credentials: None,
    };
    let answer = Tunnel::new(&stub.base)
        .expect("tunnel")
        .send_vault_copy(&copy)
        .expect("sent");
    assert_eq!(answer, VaultCopySent::Copied(copied));

    let seen = stub.next();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/api/certificates/operator/vault-copy");
    let sent: OperatorVaultCopy = serde_json::from_slice(&seen.body).expect("body");
    assert_eq!(sent.vault_base64.len(), 100 * 1024);
}

/// The publication goes to its own route, with the epoch it names, and the
/// answer says whether the gateway confirmed the relay.
#[test]
fn a_gateway_publication_posts_its_epoch_to_its_route() {
    let published = OperatorGatewayPublished {
        epoch: 7,
        relayed: true,
    };
    let stub = Stub::serving(vec![(
        200,
        serde_json::to_string(&published).expect("json"),
    )]);
    let answer = Tunnel::new(&stub.base)
        .expect("tunnel")
        .publish_gateway_transition(7)
        .expect("published");
    assert_eq!(answer, published);

    let seen = stub.next();
    assert_eq!(seen.method, "POST");
    assert_eq!(
        seen.path,
        "/api/certificates/operator/gateway-identity/publish"
    );
    let sent: OperatorGatewayPublish = serde_json::from_slice(&seen.body).expect("body");
    assert_eq!(sent, OperatorGatewayPublish { epoch: 7 });
}

/// Held back by a live operation is a result, and not a failure: the rotation
/// goes on, and the same copy passes once that operation is over.
#[test]
fn a_vault_copy_held_back_is_its_own_result() {
    let stub = Stub::serving(vec![(409, "{}".into())]);
    let copy = OperatorVaultCopy {
        vault_base64: "e30=".into(),
        credentials: None,
    };
    let answer = Tunnel::new(&stub.base)
        .expect("tunnel")
        .send_vault_copy(&copy)
        .expect("not a failure");
    assert_eq!(answer, VaultCopySent::HeldBack);
}

/// A copy refused for what it is will not pass later: it stays a failure, and
/// says so apart from a body over the bound.
#[test]
fn a_vault_copy_refused_for_good_stays_a_failure() {
    for status in [403u16, 413, 503] {
        let stub = Stub::serving(vec![(status, "{}".into())]);
        let copy = OperatorVaultCopy {
            vault_base64: "e30=".into(),
            credentials: None,
        };
        let refusal = Tunnel::new(&stub.base)
            .expect("tunnel")
            .send_vault_copy(&copy)
            .expect_err("refused");
        assert_eq!(refusal_status(&refusal), Some(status), "{refusal:#}");
    }
}

#[test]
fn the_two_transitions_install_on_their_own_routes() {
    let tls = client_tls_transition();
    let stub = Stub::serving(vec![(200, r#"{"already_present":true}"#.into())]);
    Tunnel::new(&stub.base)
        .expect("tunnel")
        .install_client_tls_ca_transition(&tls)
        .expect("installed");
    let seen = stub.next();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/api/certificates/client-tls-ca-transition");
    let sent: ClientTlsCaTransition = serde_json::from_slice(&seen.body).expect("body");
    assert_eq!(sent, tls);

    let pq = ca_transition();
    let stub = Stub::serving(vec![(200, r#"{"already_present":false}"#.into())]);
    Tunnel::new(&stub.base)
        .expect("tunnel")
        .install_ca_transition(&pq)
        .expect("installed");
    let seen = stub.next();
    assert_eq!(seen.path, "/api/certificates/ca-transition");
    let sent: CaTransition = serde_json::from_slice(&seen.body).expect("body");
    assert_eq!(sent, pq);
}

/// The gateway names why it refused an installation, for the operator's sake
/// (`GatewayActionRefusal`), and past the deadline that sentence is the answer.
#[test]
fn a_refused_installation_carries_the_gateways_sentence() {
    let stub = Stub::serving(vec![(
        409,
        r#"{"message":"TLS CA rotation activates in the past"}"#.into(),
    )]);
    let refusal = Tunnel::new(&stub.base)
        .expect("tunnel")
        .install_client_tls_ca_transition(&client_tls_transition())
        .expect_err("refused");
    assert_eq!(refusal_status(&refusal), Some(409));
    assert!(
        format!("{refusal:#}").contains("activates in the past"),
        "{refusal:#}"
    );
}

/// The domain view has many fields this side does not read, and will gain more.
#[test]
fn the_gateway_anchor_is_the_next_or_else_the_current() {
    let anchor = |kind, answer: serde_json::Value| {
        let stub = Stub::serving(vec![(200, answer.to_string())]);
        let read = Tunnel::new(&stub.base)
            .expect("tunnel")
            .gateway_next_anchor(kind)
            .expect("read");
        let seen = stub.next();
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/api/certificates");
        read
    };
    let current = fingerprint_hex(b"courante");
    let next = fingerprint_hex(b"suivante");

    assert_eq!(
        anchor(
            RotationKind::CaPq,
            serde_json::json!({
                "ca_pq_fingerprint": current,
                "next_ca_fingerprint": next,
                "client_tls_ca_fingerprint": fingerprint_hex(b"autre famille"),
                "unknown_to_this_build": [1, 2, 3],
            })
        ),
        Some(Fingerprint::of(b"suivante"))
    );
    assert_eq!(
        anchor(
            RotationKind::CaPq,
            serde_json::json!({ "ca_pq_fingerprint": current, "next_ca_fingerprint": null })
        ),
        Some(Fingerprint::of(b"courante"))
    );
    assert_eq!(
        anchor(
            RotationKind::CaTls,
            serde_json::json!({
                "ca_pq_fingerprint": fingerprint_hex(b"autre famille"),
                "client_tls_ca_fingerprint": current,
                "next_client_tls_ca_fingerprint": next,
            })
        ),
        Some(Fingerprint::of(b"suivante"))
    );
    assert_eq!(
        anchor(
            RotationKind::CaTls,
            serde_json::json!({
                "ca_pq_fingerprint": fingerprint_hex(b"autre famille"),
                "client_tls_ca_fingerprint": current,
            })
        ),
        Some(Fingerprint::of(b"courante"))
    );
    // A gateway older than these two fields names no such anchor.
    assert_eq!(
        anchor(
            RotationKind::CaTls,
            serde_json::json!({ "ca_pq_fingerprint": current })
        ),
        None
    );
}

/// A domain with many peers is a larger answer than any operator object.
#[test]
fn the_domain_read_has_a_bound_of_its_own() {
    let padded = serde_json::json!({
        "ca_pq_fingerprint": fingerprint_hex(b"courante"),
        "peers": "x".repeat(512 * 1024),
    });
    let stub = Stub::serving(vec![(200, padded.to_string())]);
    assert_eq!(
        Tunnel::new(&stub.base)
            .expect("tunnel")
            .gateway_next_anchor(RotationKind::CaPq)
            .expect("read"),
        Some(Fingerprint::of(b"courante"))
    );
}

/// A resume tells a refusal from a silence by this type: the first decides the
/// journal's fate, the second only postpones it.
#[test]
fn a_refused_deposit_can_be_told_from_a_lost_connection() {
    let stub = Stub::serving(vec![(403, "{}".into())]);
    let result = aether::certificates::status::AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(aether::certificates::status::CampaignApproval {
            campaign_id: Id16::new([5; 16]).expect("id"),
            campaign_fingerprint: Fingerprint::of(b"campagne"),
            required_credentials: 2,
            approved_at: 1,
            approvals: Vec::new(),
        }),
        objects: Vec::new(),
        credential_registry: None,
        issuer_authorization: None,
    };
    let tunnel = Tunnel::new(&stub.base).expect("tunnel");
    let refused = tunnel
        .submit_campaign(&operation(), "jeton", &result)
        .expect_err("refused");
    assert_eq!(refusal_status(&refused), Some(403));

    // Nobody listens on the address any more.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", listener.local_addr().expect("addr"))
    };
    let lost = Tunnel::new(&closed)
        .expect("tunnel")
        .submit_campaign(&operation(), "jeton", &result)
        .expect_err("no gateway");
    assert_eq!(refusal_status(&lost), None, "{lost:#}");
}

fn client_tls_transition() -> ClientTlsCaTransition {
    ClientTlsCaTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        current_ca_tls_epoch: 1,
        next_ca_tls_epoch: 2,
        active_client_tls_ca_fingerprint: Fingerprint::of(b"sortante"),
        next_client_tls_ca_certificate: DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
            .expect("certificate"),
        window: TransitionWindow {
            not_before: 10,
            activation_at: 20,
            not_after: 30,
        },
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
}

fn ca_transition() -> CaTransition {
    let (_, public) = aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keys");
    CaTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        current_ca_epoch: 1,
        next_ca_epoch: 2,
        current_ca_fingerprint: Fingerprint::of(b"sortante"),
        next_ca_fingerprint: public.authority_fingerprint(),
        next_ca_public_key: public,
        window: TransitionWindow {
            not_before: 10,
            activation_at: 20,
            not_after: 30,
        },
        current_ca_signature: MlDsa87Signature::placeholder(),
        next_ca_signature: MlDsa87Signature::placeholder(),
    }
}
