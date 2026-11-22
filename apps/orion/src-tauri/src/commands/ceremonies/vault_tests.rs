use super::*;
use crate::commands::test_support::answer_gateway;
use crate::operator::{rotations::VaultCopyOutcome, GatewayTarget};
use aether::certificates::{
    encoding::{Fingerprint, WireGuardKey},
    transport::{OperatorVaultCopied, OperatorVaultCopy},
};
use astra_operator::operations::fixtures::{domain, gateway_key};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpListener;

fn target(listener: &TcpListener, key: WireGuardKey) -> GatewayTarget {
    GatewayTarget {
        address: format!("http://{}", listener.local_addr().unwrap()),
        peer_key: key.to_base64(),
        own_key: None,
    }
}

fn authority_status(credential_epoch: Option<u64>) -> String {
    json!({
        "ca_epoch": 1,
        "ca_fingerprint": "fixture-ca",
        "ca_tls_epoch": 1,
        "revoked_peers": [],
        "credential_registry_epoch": credential_epoch,
    })
    .to_string()
}

#[tokio::test]
async fn vault_overview_reads_only_public_metadata_without_touching_keys() {
    let domain = domain();
    let before = std::fs::read(&domain.path).unwrap();
    let overview = operator_overview_from(domain.path.clone())
        .await
        .expect("vault overview");

    assert!(overview.exists);
    assert!(overview.bootstrapped);
    assert!(overview.credentials_complete);
    assert_eq!(overview.slots.len(), 3);
    assert_eq!(overview.slots[0].label, "Clé 1");
    assert_eq!(overview.slots[0].state.as_deref(), Some("active"));
    assert_eq!(
        overview.domain.unwrap().gateway_wg_public_key.as_deref(),
        Some(gateway_key().to_base64().as_str())
    );
    assert_eq!(domain.touches(), 0);
    assert!(
        std::fs::read(&domain.path).unwrap() == before,
        "overview changed the vault"
    );
}

#[tokio::test]
async fn vault_overview_distinguishes_absence_from_corruption() {
    let domain = domain();
    let absent = domain.path.with_file_name("absent.vault");
    let overview = operator_overview_from(absent.clone())
        .await
        .expect("missing vault is a state");
    assert!(!overview.exists);
    assert!(overview.slots.is_empty());
    assert!(!absent.exists());

    let corrupt = domain.path.with_file_name("corrupt.vault");
    std::fs::write(&corrupt, b"unreadable file").unwrap();
    assert!(operator_overview_from(corrupt.clone()).await.is_err());
    assert_eq!(std::fs::read(&corrupt).unwrap(), b"unreadable file");
}

#[tokio::test]
async fn vault_copy_retries_without_the_document_when_the_gateway_holds_it_back() {
    let domain = domain();
    let before = std::fs::read(&domain.path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target(&listener, gateway_key());
    let expected = astra_operator::operations::rotation::vault_copy(&domain.path).unwrap();
    let expected_document = domain.registry();
    let fingerprint = Fingerprint::of(&STANDARD.decode(&expected.vault_base64).unwrap());
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let status = authority_status(None);
            let request = answer_gateway(
                &listener,
                "GET /api/certificates/operator/status ",
                "200 OK",
                &status,
            )
            .await;
            assert!(request.is_empty());
            let first: OperatorVaultCopy = serde_json::from_slice(
                &answer_gateway(
                    &listener,
                    "POST /api/certificates/operator/vault-copy ",
                    "409 Conflict",
                    "{}",
                )
                .await,
            )
            .unwrap();
            assert!(!first.replace_newer);
            assert_eq!(first.credentials.as_deref(), Some(&expected_document));
            assert!(
                first.vault_base64 == expected.vault_base64,
                "first copy differs from the vault"
            );

            let receipt = serde_json::to_string(&OperatorVaultCopied {
                fingerprint,
                credential_registry_epoch: None,
            })
            .unwrap();
            let second: OperatorVaultCopy = serde_json::from_slice(
                &answer_gateway(
                    &listener,
                    "POST /api/certificates/operator/vault-copy ",
                    "200 OK",
                    &receipt,
                )
                .await,
            )
            .unwrap();
            assert!(!second.replace_newer);
            assert!(second.credentials.is_none());
            assert!(
                second.vault_base64 == expected.vault_base64,
                "retry changed the sealed vault"
            );
        })
        .await
        .expect("three gateway calls");
    });

    let outcome = send_vault_copy_to(domain.path.clone(), target, false)
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(
        outcome,
        VaultCopyOutcome::Copied {
            fingerprint: fingerprint.to_hex(),
            credential_registry_epoch: None,
            document_waits: true,
        }
    );
    assert_eq!(domain.touches(), 0);
    assert!(
        std::fs::read(&domain.path).unwrap() == before,
        "sending a copy changed the vault"
    );
}

#[tokio::test]
async fn forced_vault_copy_submits_the_replace_flag_and_keeps_a_stale_outcome() {
    let domain = domain();
    let epoch = domain.registry().credential_registry_epoch;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target(&listener, gateway_key());
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            answer_gateway(
                &listener,
                "GET /api/certificates/operator/status ",
                "200 OK",
                &authority_status(Some(epoch)),
            )
            .await;
            let body = answer_gateway(
                &listener,
                "POST /api/certificates/operator/vault-copy ",
                "412 Precondition Failed",
                "{}",
            )
            .await;
            let request: OperatorVaultCopy = serde_json::from_slice(&body).unwrap();
            assert!(request.replace_newer);
            assert!(
                request.credentials.is_none(),
                "the gateway already has this document"
            );
        })
        .await
        .expect("authority status and forced request");
    });

    assert_eq!(
        send_vault_copy_to(domain.path.clone(), target, true).await,
        Ok(VaultCopyOutcome::Stale),
    );
    server.await.unwrap();
    assert_eq!(domain.touches(), 0);
}

#[tokio::test]
async fn vault_copy_checks_domain_and_in_flight_rotation_before_contacting_gateway() {
    let domain = domain();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wrong = target(&listener, WireGuardKey::from_bytes([0x22; 32]));
    let error = send_vault_copy_to(domain.path.clone(), wrong, false)
        .await
        .unwrap_err();
    assert!(error.contains("nomme le relais du domaine"), "{error}");

    let journal = astra_operator::rotation_journal::path_beside(&domain.path);
    std::fs::write(&journal, b"pending rotation marker").unwrap();
    let target = target(&listener, gateway_key());
    let error = send_vault_copy_to(domain.path.clone(), target, true)
        .await
        .unwrap_err();
    assert_eq!(error, "Rotation en cours. La mener à son terme d’abord.");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(domain.touches(), 0);
    assert_eq!(std::fs::read(journal).unwrap(), b"pending rotation marker");
}

#[tokio::test]
async fn vault_copy_stops_when_the_gateway_refuses_the_authority_status() {
    let domain = domain();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target(&listener, gateway_key());
    let server = tokio::spawn(async move {
        let request = tokio::time::timeout(
            Duration::from_secs(5),
            answer_gateway(
                &listener,
                "GET /api/certificates/operator/status ",
                "403 Forbidden",
                "{}",
            ),
        )
        .await
        .expect("authority status request");
        assert!(request.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "a vault copy must not follow a refused status read"
        );
    });

    let result = send_vault_copy_to(domain.path.clone(), target, false).await;

    server.await.expect("gateway server");
    assert_eq!(
        result,
        Err("ce poste n'est pas administrateur de la gateway".into())
    );
    assert_eq!(domain.touches(), 0);
}

#[cfg(not(windows))]
#[path = "vault_command_tests.rs"]
mod commands;
