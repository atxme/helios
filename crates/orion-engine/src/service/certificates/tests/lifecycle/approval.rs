use super::*;

use aether::certificates::{
    approval::{
        AstraCredentialApprovalRequest, AstraCredentialBinding, CredentialRegistry,
        CredentialState, PER_REQUEST_APPROVAL_CREDENTIALS,
    },
    encoding::{generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature},
    transport::{
        ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
    },
    CERTIFICATE_FORMAT_VERSION,
};
use orion_core::certificate_renewal::RenewalSession;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;

const PROFILE: &str = "workstation";
const READ_TOKEN: &str = "fixture-read-capability";

async fn exchange(listener: &TcpListener, response: &impl serde::Serialize) -> (String, Vec<u8>) {
    let (mut stream, _) = listener.accept().await.expect("gateway request");
    let mut reader = BufReader::new(&mut stream);
    let mut header = String::new();
    loop {
        let length = reader.read_line(&mut header).await.expect("header line");
        assert_ne!(length, 0, "request ended before its headers");
        if header.ends_with("\r\n\r\n") {
            break;
        }
    }
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| {
            value.trim().parse().expect("content length")
        });
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.expect("request body");
    let response = serde_json::to_vec(response).expect("response body");
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        )
        .await
        .expect("response headers");
    stream.write_all(&response).await.expect("response payload");
    (header, body)
}

fn signer_request(
    state: &orion_core::certificates::TrustState,
    session: &RenewalSession,
    operation_id: Id16,
    now: u64,
    ca_private: &[u8],
    service_private: &[u8],
) -> ClientRenewalSignerRequest {
    let credential_id = b"test-operator-credential".to_vec();
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[3; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[5; 32]);

    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id: credential_id.clone(),
        credential_public_key: key,
        aaguid: [0; 16],
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway.gateway_wg_public_key,
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: state.astra.credential_registry_epoch,
        ca_epoch: state.gateway.ca_epoch,
        created_at: now,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("sign binding with fixture CA");
    let request = AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id,
        request_fingerprint: session.request_fingerprint(),
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway.gateway_wg_public_key,
        client_wg_public_key: state.client_wg_public_key,
        active_generation: session.request().active_generation,
        requested_generation: session.request().requested_generation,
        credential_registry_epoch: state.astra.credential_registry_epoch,
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
        webauthn_origin: state.astra.authority_url.clone(),
        allowed_credential_ids: vec![credential_id],
        required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
        created_at: now,
        expires_at: now + 240,
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(service_private)
    .expect("sign request with fixture Astra service key");

    ClientRenewalSignerRequest {
        operation_id,
        approval_request: Box::new(request),
        credential_registry: Box::new(CredentialRegistry {
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            ca_epoch: state.gateway.ca_epoch,
            credential_registry_epoch: state.astra.credential_registry_epoch,
            bindings: vec![binding],
        }),
        authority_url: state.astra.authority_url.clone(),
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
    }
}

async fn approval_round_trip(label: &str, refuse_signature: bool) {
    let scratch = Scratch::new(label);
    let service = service(&scratch);
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("fixture CA");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("Astra key");
    let path = scratch.0.join("trust.json");
    let mut state = prepared_renewal_store(path.clone()).state().clone();
    state.gateway.current_ca_public_key = ca_public;
    state.astra.active_astra_service_public_key = service_public;
    let store = orion_core::certificates::TrustStore::new(path.clone(), state);
    store.save().expect("fixture trust state");
    let before = std::fs::read(&path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let now = now_unix() - 1;
    let mut session = RenewalSession::prepare(&store, "CN=fixture Orion", &url, now).unwrap();
    let (active_key, _) = generate_ml_dsa_87_keypair().unwrap();
    session
        .sign(&orion_core::certificate_renewal::ActiveIdentity {
            pq_private_key: active_key,
            tls_private_key_der: zeroize::Zeroizing::new(Vec::new()),
        })
        .unwrap();

    let operation_id = Id16::new([42; 16]).unwrap();
    let expected_fingerprint = session.request_fingerprint();
    let view = ClientRenewalOperationView {
        operation_id,
        state: ClientRenewalOperationState::PendingGrant,
        client_wg_public_key: store.state().client_wg_public_key,
        request_fingerprint: expected_fingerprint,
        operation_manifest_fingerprint: Fingerprint::of(b"fixture operation"),
        created_at: now,
        expires_at: now + 240,
        signer_request_token: Some(READ_TOKEN.into()),
        signer_result_token: Some("fixture-submit-capability".into()),
        grant: None,
    };
    let mut reply = signer_request(
        store.state(),
        &session,
        operation_id,
        now,
        &ca_private,
        &service_private,
    );
    if refuse_signature {
        reply.approval_request.astra_signature = MlDsa87Signature::placeholder();
    }
    let approval_fingerprint = reply.approval_request.fingerprint();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (header, body) = exchange(&listener, &view).await;
            assert!(header.starts_with("POST /api/key-negotiation/certificate-renewal/request "));
            let sent: aether::certificates::client::ClientCertificateRotationRequest =
                serde_json::from_slice(&body).expect("rotation request");
            assert_eq!(sent.fingerprint(), expected_fingerprint);
            let (header, body) = exchange(&listener, &reply).await;
            assert!(header.starts_with(&format!(
                "GET /api/key-negotiation/certificate-renewal/signer-requests/{} ",
                operation_id.to_hex(),
            )));
            assert!(header
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {READ_TOKEN}\r\n")));
            assert!(body.is_empty());
        })
        .await
        .expect("two requests within the test deadline");
    });

    session
        .open()
        .await
        .expect("gateway supplies the open operation");
    service.renewals.lock().await.insert(
        PROFILE.into(),
        InFlightRenewal {
            session,
            store,
            settings: key_negotiation("fixture"),
            approval: None,
        },
    );
    let manifest = service.certificate_approval_manifest(PROFILE.into()).await;
    server.await.expect("gateway request assertions");

    if refuse_signature {
        assert!(manifest.is_err(), "unverifiable manifest must be refused");
        assert_eq!(
            service
                .certificate_approval_material(PROFILE.into())
                .await
                .err()
                .as_deref(),
            Some(READ_THE_REQUEST_FIRST),
        );
    } else {
        let manifest = manifest.expect("verified manifest");
        assert_eq!(manifest.operation_id, operation_id.to_hex());
        assert_eq!(manifest.request_fingerprint, expected_fingerprint.to_hex());
        assert_eq!(
            manifest.requested_generation,
            manifest.active_generation + 1
        );
        assert_eq!(manifest.eligible_credentials, 1);
        for _ in 0..2 {
            let material = service
                .certificate_approval_material(PROFILE.into())
                .await
                .expect("verified material remains available until deposit");
            assert_eq!(material.request.fingerprint(), approval_fingerprint);
            assert_eq!(material.rp_id, "astra.example");
        }
    }
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "approval reads do not persist trust"
    );
}

#[tokio::test]
async fn signed_approval_manifest_keeps_verified_material_available_for_the_ui() {
    approval_round_trip("verified-approval-manifest", false).await;
}

#[tokio::test]
async fn invalid_approval_signature_keeps_the_ui_material_unavailable() {
    approval_round_trip("invalid-approval-signature", true).await;
}

#[tokio::test]
async fn approval_reads_require_an_open_renewal_for_the_selected_profile() {
    let scratch = Scratch::new("approval-no-renewal");
    let service = service(&scratch);

    for error in [
        service
            .certificate_approval_manifest(PROFILE.into())
            .await
            .err(),
        service
            .certificate_approval_material(PROFILE.into())
            .await
            .err(),
    ] {
        assert_eq!(error.as_deref(), Some(NO_OPEN_RENEWAL));
    }
    assert!(service.renewals.lock().await.is_empty());
}

#[tokio::test]
async fn recovery_resume_refuses_bad_or_unknown_operation_ids_without_recording_an_error() {
    let scratch = Scratch::new("recovery-no-operation");
    let service = service(&scratch);

    for (operation, expected) in [
        ("not-hex".into(), "identifiant de récupération illisible"),
        (
            Id16::new([13; 16]).unwrap().to_hex(),
            "aucune récupération ouverte dans Orion ne correspond à cette opération",
        ),
    ] {
        let error = service
            .resume_certificate_recovery(operation)
            .await
            .unwrap_err();
        assert_eq!(error, expected);
    }
    assert!(service.recoveries.lock().await.is_empty());
    assert!(service.last_certificate_error.lock().await.is_empty());
}
