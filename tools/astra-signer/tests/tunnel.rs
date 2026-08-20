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
use aether::certificates::encoding::{
    Fingerprint, Id16, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
};
use astra_signer::tunnel::Tunnel;

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
