//! The vault copy and the credential document an administrator sends through
//! the tunnel (spec §5.9).

use aether::certificates::approval::{AstraCredentialBinding, CredentialRegistry, CredentialState};
use astra_channel::{
    OperatorVaultCopied, OperatorVaultCopy, RelayedOperatorVaultCopy,
    MAX_OPERATOR_VAULT_COPY_BODY_BYTES, MAX_OPERATOR_VAULT_COPY_BYTES, OPERATOR_VAULT_COPY_ROUTE,
};
use base64::Engine as _;

use super::tunnel::{listen, post_to};
use super::*;
use crate::service::{CREDENTIALS_FILE, PREVIOUS_VAULT_FILE, VAULT_FILE};

const DOMAIN: [u8; 16] = [1; 16];

/// What a vault looks like from outside: a version and a domain it names, and
/// a body Astra cannot read.
fn vault_of(domain: [u8; 16], marker: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format_version": 1,
        "trust_domain_id": TrustDomainId::new(domain).expect("domain"),
        "body": marker,
    }))
    .expect("vault")
}

fn cose_key() -> Vec<u8> {
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[1; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[2; 32]);
    key
}

/// A credential document signed under the fixture's `CA-PQ`.
fn credentials_at(ca_private: &[u8], registry_epoch: u64) -> Box<CredentialRegistry> {
    let binding = AstraCredentialBinding {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id: vec![7; 16],
        credential_public_key: cose_key(),
        aaguid: [0; 16],
        trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: registry_epoch,
        ca_epoch: 1,
        created_at: 500,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("sign");
    Box::new(CredentialRegistry {
        trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        ca_epoch: 1,
        credential_registry_epoch: registry_epoch,
        bindings: vec![binding],
    })
}

fn send(vault: Vec<u8>, credentials: Option<Box<CredentialRegistry>>) -> DoorRequest {
    DoorRequest::VaultCopy {
        vault: vault.into(),
        credentials,
    }
}

async fn tunnel_send(
    service: &AstraService,
    vault: Vec<u8>,
    credentials: Option<Box<CredentialRegistry>>,
) -> Result<DoorOutcome, DoorRefusal> {
    service.door(tunnel(), send(vault, credentials), NOW).await
}

fn on_disk(service: &AstraService, name: &str) -> Option<Vec<u8>> {
    std::fs::read(service.state_dir.join(name)).ok()
}

#[tokio::test]
async fn vault_copy_is_available_to_the_door_at_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    *service.encrypted_vault.write().expect("vault lock") = None;
    let before = service
        .door(
            tunnel(),
            DoorRequest::TrustAuthorities { text: text() },
            NOW,
        )
        .await;
    assert!(matches!(before, Err(DoorRefusal::NoVault)));

    let vault = vault_of(DOMAIN, "first");
    let outcome = tunnel_send(&service, vault.clone(), None)
        .await
        .expect("the copy is taken");
    assert_eq!(
        outcome,
        DoorOutcome::VaultCopied {
            fingerprint: Fingerprint::of(&vault),
            credential_registry_epoch: None,
        }
    );
    assert_eq!(on_disk(&service, VAULT_FILE), Some(vault.clone()));
    assert_eq!(service.encrypted_vault().as_deref(), Some(&vault));
    // The same service, no restart.
    let after = service
        .door(
            tunnel(),
            DoorRequest::TrustAuthorities { text: text() },
            NOW,
        )
        .await;
    assert!(after.is_ok(), "{after:?}");
}

#[tokio::test]
async fn vault_copy_keeps_the_previous_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let held = service.encrypted_vault().expect("fixture vault");

    let first = vault_of(DOMAIN, "first");
    tunnel_send(&service, first.clone(), None)
        .await
        .expect("first");
    assert_eq!(on_disk(&service, PREVIOUS_VAULT_FILE), Some(held.to_vec()));

    let second = vault_of(DOMAIN, "second");
    tunnel_send(&service, second.clone(), None)
        .await
        .expect("second");
    assert_eq!(on_disk(&service, PREVIOUS_VAULT_FILE), Some(first));
    assert_eq!(on_disk(&service, VAULT_FILE), Some(second));
}

#[tokio::test]
async fn vault_copy_refuses_another_domain_and_garbage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let held = service.encrypted_vault().expect("fixture vault");
    let oversized = vec![b' '; MAX_OPERATOR_VAULT_COPY_BYTES + 1];
    let cases = [
        vault_of([2; 16], "elsewhere"),
        b"not json at all".to_vec(),
        br#"{"format_version":1}"#.to_vec(),
        Vec::new(),
        oversized,
    ];
    for vault in cases {
        let refusal = tunnel_send(&service, vault, None).await;
        assert!(
            matches!(refusal, Err(DoorRefusal::VaultCopyRefused)),
            "{refusal:?}"
        );
    }
    assert_eq!(on_disk(&service, VAULT_FILE), None);
    assert_eq!(on_disk(&service, PREVIOUS_VAULT_FILE), None);
    assert_eq!(service.encrypted_vault().as_deref(), Some(&*held));
}

#[tokio::test]
async fn credentials_travel_with_the_vault_and_are_served_at_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (service, ca_private) = build_service_with_ca(dir.path(), None, None);
    let vault = vault_of(DOMAIN, "with credentials");

    let outcome = tunnel_send(
        &service,
        vault.clone(),
        Some(credentials_at(&ca_private, 2)),
    )
    .await
    .expect("both are taken");
    assert_eq!(
        outcome,
        DoorOutcome::VaultCopied {
            fingerprint: Fingerprint::of(&vault),
            credential_registry_epoch: Some(2),
        }
    );
    assert_eq!(service.approval_credentials().epoch, 2);
    assert_eq!(service.approval_credentials().ids, vec![vec![7; 16]]);
    let written: CredentialRegistry =
        serde_json::from_slice(&on_disk(&service, CREDENTIALS_FILE).expect("file")).expect("json");
    assert_eq!(written.credential_registry_epoch, 2);
}

#[tokio::test]
async fn an_older_credentials_document_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (service, ca_private) = build_service_with_ca(dir.path(), None, None);
    *service.approval_credentials.write().expect("lock") = Arc::new(
        crate::service::ApprovalCredentials::from_document(credentials_at(&ca_private, 3)),
    );
    let held = service.encrypted_vault().expect("fixture vault");

    let refusal = tunnel_send(
        &service,
        vault_of(DOMAIN, "rollback"),
        Some(credentials_at(&ca_private, 2)),
    )
    .await;
    assert!(
        matches!(refusal, Err(DoorRefusal::CredentialsRollback)),
        "{refusal:?}"
    );
    assert_eq!(
        on_disk(&service, VAULT_FILE),
        None,
        "the vault is not written"
    );
    assert_eq!(on_disk(&service, CREDENTIALS_FILE), None);
    assert_eq!(service.encrypted_vault().as_deref(), Some(&*held));
    assert_eq!(service.approval_credentials().epoch, 3);
}

#[tokio::test]
async fn a_credentials_document_not_signed_under_the_anchor_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let (other_private, _) = generate_ml_dsa_87_keypair().expect("another CA-PQ");

    let refusal = tunnel_send(
        &service,
        vault_of(DOMAIN, "forged"),
        Some(credentials_at(&other_private, 2)),
    )
    .await;
    assert!(
        matches!(refusal, Err(DoorRefusal::VaultCopyRefused)),
        "{refusal:?}"
    );
    assert_eq!(on_disk(&service, VAULT_FILE), None);
    assert_eq!(on_disk(&service, CREDENTIALS_FILE), None);
}

#[tokio::test]
async fn credentials_are_refused_while_a_ca_pq_rotation_is_in_flight() {
    use crate::registry::CaPqRotation;

    let dir = tempfile::tempdir().expect("temp dir");
    let (service, ca_private) = build_service_with_ca(dir.path(), None, None);
    let (_, next) = generate_ml_dsa_87_keypair().expect("next CA-PQ");
    rewrite_registry(&service, |state| {
        state.ca_rotation = Some(CaPqRotation {
            next_ca_epoch: 2,
            next_ca_public_key: next,
            activation_at: NOW,
            retire_active_at: NOW + 10,
        });
    })
    .await;

    let refusal = tunnel_send(
        &service,
        vault_of(DOMAIN, "during rotation"),
        Some(credentials_at(&ca_private, 2)),
    )
    .await;
    assert!(
        matches!(refusal, Err(DoorRefusal::CredentialsDuringRotation)),
        "{refusal:?}"
    );
    assert_eq!(on_disk(&service, VAULT_FILE), None);
    assert_eq!(on_disk(&service, CREDENTIALS_FILE), None);

    // The vault alone is what the end of a rotation sends.
    let vault = vault_of(DOMAIN, "alone");
    tunnel_send(&service, vault.clone(), None)
        .await
        .expect("the vault alone passes");
    assert_eq!(on_disk(&service, VAULT_FILE), Some(vault));
}

#[tokio::test]
async fn console_cannot_send_a_vault_copy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let refusal = service
        .door(console(), send(vault_of(DOMAIN, "console"), None), NOW)
        .await;
    assert!(matches!(refusal, Err(DoorRefusal::NotAllowedHere)));
    assert_eq!(on_disk(&service, VAULT_FILE), None);
}

#[tokio::test]
async fn a_failed_write_is_an_internal_refusal_and_serves_the_old_copy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let held = service.encrypted_vault().expect("fixture vault");
    // A directory where the vault file goes: the atomic write cannot land.
    std::fs::create_dir(service.state_dir.join(VAULT_FILE)).expect("obstacle");

    let refusal = tunnel_send(&service, vault_of(DOMAIN, "blocked"), None).await;
    assert!(
        matches!(refusal, Err(DoorRefusal::NotRecorded)),
        "{refusal:?}"
    );
    assert_eq!(service.encrypted_vault().as_deref(), Some(&*held));
}

#[test]
fn the_vault_never_reaches_a_log_through_debug() {
    let request = send(b"SECRET-VAULT-BYTES".to_vec(), None);
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(!rendered.contains("83, 69"), "{rendered}");
    assert_eq!(request.action(), "vault_copy");
}

fn relayed_copy(vault: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&RelayedOperatorVaultCopy {
        operator: OperatorIdentity::WireGuard {
            public_key: tunnel_key(),
        },
        copy: OperatorVaultCopy {
            vault_base64: base64::engine::general_purpose::STANDARD.encode(vault),
            credentials: None,
        },
    })
    .expect("relayed copy")
}

#[tokio::test]
async fn the_private_route_adopts_a_copy_and_refuses_the_rest_coarsely() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let vault = vault_of(DOMAIN, "over the route");
    let (status, body) = post_to(&listener, OPERATOR_VAULT_COPY_ROUTE, &relayed_copy(&vault)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let copied: OperatorVaultCopied = serde_json::from_slice(&body).expect("the answer");
    assert_eq!(copied.fingerprint, Fingerprint::of(&vault));
    assert_eq!(copied.credential_registry_epoch, None);
    assert_eq!(on_disk(&service, VAULT_FILE), Some(vault));

    let (status, _) = post_to(
        &listener,
        OPERATOR_VAULT_COPY_ROUTE,
        &relayed_copy(&vault_of([2; 16], "elsewhere")),
    )
    .await;
    assert_eq!(status, 403, "a refusal is its class");

    let unreadable = serde_json::to_vec(&serde_json::json!({
        "operator": OperatorIdentity::DevLoopback,
        "copy": { "vault_base64": "!!!not base64!!!" },
    }))
    .expect("body");
    let (status, _) = post_to(&listener, OPERATOR_VAULT_COPY_ROUTE, &unreadable).await;
    assert_eq!(status, 400);

    let oversized = vec![b' '; MAX_OPERATOR_VAULT_COPY_BODY_BYTES + 1024];
    let (status, _) = post_to(&listener, OPERATOR_VAULT_COPY_ROUTE, &oversized).await;
    assert_eq!(status, 413);
}
