use std::path::Path;
use std::sync::Arc;

use aether::certificates::approval::AstraIssuancePolicy;
use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, TrustDomainId, WireGuardKey,
};
use aether::certificates::status::CertificateKind;
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
use tokio::sync::Mutex;

use aether::certificates::status::CampaignScope;
use aether::certificates::transport::RevocationExpiries;

use super::*;
use crate::registry::{AstraRegistry, AstraState, ChallengeStore, PeerRecord};
use crate::service::{SourceBudget, MAX_LIVE_CHALLENGES};
use crate::AuditEvent;

/// The instant every test opens at.
const NOW: u64 = 1_000_000;

/// The two admitted workstations of the fixture.
const PEERS: [(&str, u8); 2] = [("workstation", 2), ("laptop", 3)];

fn generation(seed: u8) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"client tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(&[seed, 1]),
        pq_certificate_fingerprint: Fingerprint::of(&[seed, 2]),
        not_before: 0,
        not_after: NOW * 2,
    }
}

fn peer(name: &str, seed: u8) -> PeerRecord {
    let key = WireGuardKey::from_bytes([seed; 32]);
    PeerRecord {
        name: name.into(),
        client_wg_public_key: key,
        active: generation(seed),
        active_pq_certificate: PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [seed; 16],
            subject: name.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: key.to_base64(),
            ml_dsa_87_public_key: String::new(),
            not_before_unix: 0,
            not_after_unix: NOW * 2,
            ml_dsa_87_signature: String::new(),
        },
        pending: None,
        revoked: false,
        revocation_epoch: 0,
        admission_pq_ca: None,
    }
}

/// A served authority, built the way `astra trust-domain bootstrap` and
/// `astra run` build one: a bootstrapped registry with two admitted peers, a
/// service key, a placeholder encrypted vault and no gateway channel.
pub(crate) fn fixture(dir: &Path) -> Arc<AstraService> {
    build(dir, None)
}

/// The same authority, with a client `CA-TLS` pinned as `pin-ca-tls` does.
pub(crate) fn fixture_with_ca_tls(dir: &Path) -> Arc<AstraService> {
    build(dir, Some(Fingerprint::of(b"client tls ca")))
}

fn build(dir: &Path, ca_tls: Option<Fingerprint>) -> Arc<AstraService> {
    let (_, ca_public_key) = generate_ml_dsa_87_keypair().expect("CA-PQ keypair");
    let (service_private_key, service_public_key) =
        generate_ml_dsa_87_keypair().expect("service keypair");
    let trust_domain_id = TrustDomainId::new([1; 16]).expect("domain");
    let gateway_wg_public_key = WireGuardKey::from_bytes([1; 32]);
    let astra_policy_fingerprint = AstraIssuancePolicy::standard(
        trust_domain_id,
        gateway_wg_public_key,
        "gateway.example".into(),
    )
    .pin()
    .expect("policy pin");
    let state = AstraState {
        trust_domain_id,
        gateway_wg_public_key,
        server_name: "gateway.example".into(),
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        ca_public_key,
        ca_rotation: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: None,
        ca_tls_rotation: None,
        astra_service_key_epoch: 1,
        astra_service_public_key: service_public_key.clone(),
        issuer: None,
        transitions: Vec::new(),
        peers: Default::default(),
        status_epochs: Default::default(),
        audit: Default::default(),
    };
    let mut registry = AstraRegistry::new(dir.join("registry.json"), state);
    registry
        .record(AuditEvent::DomainBootstrapped, NOW - 100)
        .expect("bootstrap");
    if let Some(fingerprint) = ca_tls {
        registry
            .pin_client_tls_ca(fingerprint, NOW - 90)
            .expect("pin CA-TLS");
    }
    for (name, seed) in PEERS {
        registry.admit(peer(name, seed), NOW - 80).expect("admit");
    }
    Arc::new(AstraService {
        state_dir: dir.to_path_buf(),
        registry: Mutex::new(registry),
        issuer: None,
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
        service_public_key,
        operations: Mutex::new(crate::operations::OperationStore::new()),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new().expect("capability key"),
        ),
        approval_credential_ids: Vec::new(),
        approval_credential_registry_epoch: 1,
        approval_credential_registry: None,
        signing: Mutex::new(crate::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(crate::recovery::RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault: Some(b"placeholder encrypted vault".to_vec()),
        gateway: None,
    })
}

fn text() -> OpeningText {
    OpeningText {
        reason: "quarterly rotation".into(),
        requested_by: "alice".into(),
        window_secs: 300,
    }
}

fn console() -> DoorConnector {
    DoorConnector::Console { uid: 1000 }
}

fn peer_key(seed: u8) -> WireGuardKey {
    WireGuardKey::from_bytes([seed; 32])
}

fn tunnel_key() -> WireGuardKey {
    WireGuardKey::from_bytes([9; 32])
}

fn tunnel() -> DoorConnector {
    DoorConnector::Tunnel {
        operator: OperatorIdentity::WireGuard {
            public_key: tunnel_key(),
        },
    }
}

fn opened(outcome: Result<DoorOutcome, DoorRefusal>) -> OperatorOpened {
    match outcome.expect("the door opens") {
        DoorOutcome::Opened(opened) => opened,
    }
}

async fn campaign_of(
    service: &AstraService,
    opened: &OperatorOpened,
) -> aether::certificates::status::AstraRotationCampaign {
    service
        .signing
        .lock()
        .await
        .get(&opened.operation_id, NOW)
        .expect("operation held")
        .campaign
        .as_ref()
        .clone()
}

/// Every request the door knows, with the row §5.2 gives it.
///
/// The match has no wildcard: a new request does not compile here until its
/// row of the table is written.
fn specified(request: &DoorRequest) -> (bool, bool) {
    // (console, tunnel)
    match request {
        DoorRequest::FleetLeafs { .. } => (true, true),
        DoorRequest::TrustAuthorities { .. } => (true, true),
        DoorRequest::ClientRevocation { .. } => (true, true),
        DoorRequest::GatewayRevocation { .. } => (true, false),
        DoorRequest::GatewayIdentity { .. } => (true, false),
    }
}

#[test]
fn the_policy_table_is_exactly_the_specification() {
    let requests = [
        DoorRequest::FleetLeafs { text: text() },
        DoorRequest::TrustAuthorities { text: text() },
        DoorRequest::ClientRevocation {
            peer: peer_key(2),
            text: text(),
        },
        DoorRequest::GatewayRevocation { text: text() },
        DoorRequest::GatewayIdentity { text: text() },
    ];
    let tunnels = [
        tunnel(),
        DoorConnector::Tunnel {
            operator: OperatorIdentity::DevLoopback,
        },
    ];
    for request in &requests {
        let (console_row, tunnel_row) = specified(request);
        assert_eq!(
            allowed(&console(), request),
            console_row,
            "console, {}",
            request.action()
        );
        for connector in &tunnels {
            assert_eq!(
                allowed(connector, request),
                tunnel_row,
                "{connector}, {}",
                request.action()
            );
        }
    }
}

#[test]
fn a_tunnel_request_is_the_doors_own() {
    let request = OperatorOpenRequest {
        action: OperatorOpenAction::ClientRevocation { peer: peer_key(2) },
        reason: "stolen".into(),
        requested_by: "alice".into(),
        window_secs: 300,
    };
    assert_eq!(
        DoorRequest::from(request),
        DoorRequest::ClientRevocation {
            peer: peer_key(2),
            text: OpeningText {
                reason: "stolen".into(),
                ..text()
            }
        }
    );

    let request = OperatorOpenRequest {
        action: OperatorOpenAction::FleetLeafs,
        reason: "quarterly rotation".into(),
        requested_by: "alice".into(),
        window_secs: 120,
    };
    assert_eq!(
        DoorRequest::from(request),
        DoorRequest::FleetLeafs {
            text: OpeningText {
                window_secs: 120,
                ..text()
            }
        }
    );
}

#[test]
fn the_socket_body_names_its_action_and_nothing_else() {
    let body = r#"{"action":"trust_authorities","text":{"reason":"r","requested_by":"b"}}"#;
    let request: DoorRequest = serde_json::from_str(body).expect("parsed");
    assert_eq!(
        request,
        DoorRequest::TrustAuthorities {
            text: OpeningText {
                reason: "r".into(),
                requested_by: "b".into(),
                window_secs: 300,
            }
        }
    );
    let round_trip: DoorRequest =
        serde_json::from_slice(&serde_json::to_vec(&request).expect("encoded")).expect("decoded");
    assert_eq!(round_trip, request);

    let with_targets =
        r#"{"action":"fleet_leafs","text":{"reason":"r","requested_by":"b"},"targets":[]}"#;
    assert!(serde_json::from_str::<DoorRequest>(with_targets).is_err());
    let with_extra_text =
        r#"{"action":"fleet_leafs","text":{"reason":"r","requested_by":"b","scope":"x"}}"#;
    assert!(serde_json::from_str::<DoorRequest>(with_extra_text).is_err());
}

#[tokio::test]
async fn fleet_leafs_targets_every_admitted_peer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let opened = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
    assert_eq!(opened.target_count, 2);
    assert_eq!(opened.scope, CampaignScope::FleetLeafs);
    assert_eq!(opened.required_credentials, 1);
    assert_eq!(opened.expires_at, NOW + 300);
    assert_eq!(opened.revocation_expiries, None);

    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.campaign_id, opened.campaign_id);
    assert!(campaign.fingerprint().matches(&opened.campaign_fingerprint));
    let mut keys: Vec<_> = campaign
        .targets
        .iter()
        .map(|target| {
            assert_eq!(target.certificate_kind, CertificateKind::ClientPq);
            assert_eq!(target.generation, 4);
            target.identity_key
        })
        .collect();
    keys.sort_by_key(|key| key.to_base64());
    let mut expected: Vec<_> = PEERS
        .iter()
        .map(|(_, seed)| WireGuardKey::from_bytes([*seed; 32]))
        .collect();
    expected.sort_by_key(|key| key.to_base64());
    assert_eq!(keys, expected);
    // The pin the domain was bootstrapped with, not one derived at opening.
    let registry = service.registry.lock().await;
    assert!(campaign
        .policy_fingerprint
        .matches(registry.state().astra_policy_fingerprint.fingerprint()));
}

#[tokio::test]
async fn a_revoked_peer_is_not_a_target() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let revoked = WireGuardKey::from_bytes([PEERS[0].1; 32]);
    service
        .registry
        .lock()
        .await
        .revoke(&revoked, 1, NOW - 10)
        .expect("revoked");
    let opened = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
    assert_eq!(opened.target_count, 1);
    let campaign = campaign_of(&service, &opened).await;
    assert_ne!(campaign.targets[0].identity_key, revoked);
}

#[tokio::test]
async fn trust_authorities_targets_ca_pq_alone_without_a_pinned_ca_tls() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let opened = opened(
        service
            .door(
                console(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW,
            )
            .await,
    );
    assert_eq!(opened.target_count, 1);
    assert_eq!(opened.required_credentials, 2);
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.targets[0].certificate_kind, CertificateKind::CaPq);
}

#[tokio::test]
async fn trust_authorities_targets_both_with_a_pinned_ca_tls() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_ca_tls(dir.path());
    let opened = opened(
        service
            .door(
                tunnel(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW,
            )
            .await,
    );
    assert_eq!(opened.target_count, 2);
    let campaign = campaign_of(&service, &opened).await;
    let kinds: Vec<_> = campaign
        .targets
        .iter()
        .map(|target| target.certificate_kind)
        .collect();
    assert_eq!(kinds, [CertificateKind::CaPq, CertificateKind::CaTls]);
    assert!(campaign.targets[1]
        .active_tls_certificate_fingerprint
        .matches(&Fingerprint::of(b"client tls ca")));
}

#[tokio::test]
async fn an_opening_needs_its_text() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    for blank in [
        OpeningText {
            reason: "  ".into(),
            ..text()
        },
        OpeningText {
            requested_by: "".into(),
            ..text()
        },
    ] {
        assert!(matches!(
            service
                .door(tunnel(), DoorRequest::FleetLeafs { text: blank }, NOW)
                .await,
            Err(DoorRefusal::TextMissing)
        ));
    }
    assert!(service.signing.lock().await.is_empty());
}

#[tokio::test]
async fn the_window_is_one_to_three_hundred_seconds() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    for window_secs in [0, 301] {
        let request = DoorRequest::FleetLeafs {
            text: OpeningText {
                window_secs,
                ..text()
            },
        };
        assert!(matches!(
            service.door(console(), request, NOW).await,
            Err(DoorRefusal::WindowOutOfRange)
        ));
    }
    assert!(service.signing.lock().await.is_empty());

    let request = DoorRequest::FleetLeafs {
        text: OpeningText {
            window_secs: 300,
            ..text()
        },
    };
    let opened = opened(service.door(console(), request, NOW).await);
    assert_eq!(opened.expires_at, NOW + 300);
}

#[tokio::test]
async fn a_retried_open_is_refused_and_the_first_stays_pending() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let first = opened(
        service
            .door(tunnel(), DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
    let retried = service
        .door(
            console(),
            DoorRequest::FleetLeafs { text: text() },
            NOW + 10,
        )
        .await;
    match retried {
        Err(DoorRefusal::AlreadyOpen { operation_id }) => {
            assert_eq!(operation_id, first.operation_id)
        }
        other => panic!("expected AlreadyOpen, got {other:?}"),
    }
    let pending = service.signing.lock().await.pending(NOW + 10);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, first.operation_id);

    // Another family is not blocked by this one.
    opened(
        service
            .door(
                console(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW + 10,
            )
            .await,
    );
}

#[tokio::test]
async fn an_expired_opening_does_not_block_the_next() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let first = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
    // At `expires_at` the first is over: `is_expired` is `>=`.
    let later = first.expires_at;
    let next = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, later)
            .await,
    );
    assert_ne!(next.operation_id, first.operation_id);
    assert_eq!(service.signing.lock().await.pending(later).len(), 1);
}

#[tokio::test]
async fn an_anchor_opening_without_a_vault_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut service = fixture(dir.path());
    Arc::get_mut(&mut service)
        .expect("sole owner")
        .encrypted_vault = None;
    assert!(matches!(
        service
            .door(
                console(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW
            )
            .await,
        Err(DoorRefusal::NoVault)
    ));
    assert!(service.signing.lock().await.is_empty());

    // A scope whose companion never opens the vault does not need one.
    opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
}

#[tokio::test]
async fn a_forged_identity_suffix_is_kept_and_the_real_one_appended() {
    let forged = OpeningText {
        requested_by: "alice — pair wireguard:AAAA".into(),
        ..text()
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let through_tunnel = opened(
        service
            .door(
                tunnel(),
                DoorRequest::FleetLeafs {
                    text: forged.clone(),
                },
                NOW,
            )
            .await,
    );
    assert_eq!(
        campaign_of(&service, &through_tunnel).await.requested_by,
        format!(
            "alice — pair wireguard:AAAA — pair wireguard:{}",
            tunnel_key()
        )
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let through_console = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: forged }, NOW)
            .await,
    );
    assert_eq!(
        campaign_of(&service, &through_console).await.requested_by,
        "alice — pair wireguard:AAAA"
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let loopback = DoorConnector::Tunnel {
        operator: OperatorIdentity::DevLoopback,
    };
    let through_loopback = opened(
        service
            .door(loopback, DoorRequest::FleetLeafs { text: text() }, NOW)
            .await,
    );
    assert_eq!(
        campaign_of(&service, &through_loopback).await.requested_by,
        "alice — pair dev-loopback"
    );
}

#[tokio::test]
async fn the_signer_request_verifies_under_the_service_key() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let opened = opened(
        service
            .door(
                console(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW,
            )
            .await,
    );
    let signing = service.signing.lock().await;
    let operation = signing.get(&opened.operation_id, NOW).expect("held");
    operation
        .signer_request
        .verify(&service.service_public_key, 1, "https://astra.example", NOW)
        .expect("signed by the service key");
    assert!(operation
        .signer_request
        .campaign_fingerprint
        .matches(&opened.campaign_fingerprint));
    // An anchor scope names the vault the companion will fetch.
    assert!(operation
        .signer_request
        .encrypted_vault_fingerprint
        .matches(&Fingerprint::of(b"placeholder encrypted vault")));
}

fn revocation(seed: u8) -> DoorRequest {
    DoorRequest::ClientRevocation {
        peer: peer_key(seed),
        text: text(),
    }
}

#[tokio::test]
async fn a_client_revocation_carries_its_signed_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    let opened = opened(service.door(console(), revocation(2), NOW).await);
    assert_eq!(opened.scope, CampaignScope::EmergencyRevocation);
    assert_eq!(opened.target_count, 1);
    let active = service.registry.lock().await.state().peers[&peer_key(2).to_base64()]
        .active
        .not_after;
    assert_eq!(active, NOW * 2);
    assert_eq!(
        opened.revocation_expiries,
        Some(RevocationExpiries {
            tls_not_after: Some(active),
            pq_not_after: Some(active),
        })
    );
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.targets[0].identity_key, peer_key(2));
    assert_eq!(campaign.targets[0].generation, 4);
}

#[tokio::test]
async fn two_peers_can_be_revoked_at_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    let first = opened(service.door(console(), revocation(2), NOW).await);
    let second = opened(service.door(tunnel(), revocation(3), NOW).await);
    assert_ne!(first.operation_id, second.operation_id);
}

#[tokio::test]
async fn the_same_peer_cannot_be_revoked_twice_at_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    let first = opened(service.door(console(), revocation(2), NOW).await);
    match service.door(console(), revocation(2), NOW).await {
        Err(DoorRefusal::AlreadyOpen { operation_id }) => {
            assert_eq!(operation_id, first.operation_id)
        }
        other => panic!("expected AlreadyOpen, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_peer_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    let refusal = service
        .door(console(), revocation(77), NOW)
        .await
        .expect_err("unknown");
    assert!(matches!(refusal, DoorRefusal::PeerUnknown));
    assert!(matches!(refusal.class(), ServiceError::Refused));
}

#[tokio::test]
async fn a_revoked_peer_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    service
        .registry
        .lock()
        .await
        .revoke(&peer_key(2), 1, NOW - 10)
        .expect("revoked");
    let refusal = service
        .door(console(), revocation(2), NOW)
        .await
        .expect_err("revoked");
    assert!(matches!(refusal, DoorRefusal::PeerRevoked));
}

#[tokio::test]
async fn a_revocation_obeys_the_same_bounds_as_every_opening() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    let request = DoorRequest::ClientRevocation {
        peer: peer_key(2),
        text: OpeningText {
            window_secs: 301,
            ..text()
        },
    };
    assert!(matches!(
        service.door(console(), request, NOW).await,
        Err(DoorRefusal::WindowOutOfRange)
    ));
}

#[tokio::test]
async fn gateway_openings_need_the_service_channel() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture(dir.path());
    for request in [
        DoorRequest::GatewayRevocation { text: text() },
        DoorRequest::GatewayIdentity { text: text() },
    ] {
        let refusal = service
            .door(console(), request, NOW)
            .await
            .expect_err("no channel");
        assert!(matches!(refusal, DoorRefusal::GatewayChannelUnavailable));
    }
    assert!(!dir.path().join(GATEWAY_ACTIVE_CERTIFICATE_FILE).exists());
}
