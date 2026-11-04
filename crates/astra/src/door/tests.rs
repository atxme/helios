use std::path::Path;
use std::sync::{Arc, RwLock};

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

mod tunnel;

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
    Arc::new(build_service(dir, ca_tls, None))
}

fn build_service(
    dir: &Path,
    ca_tls: Option<Fingerprint>,
    gateway: Option<crate::gateway::GatewayChannel>,
) -> AstraService {
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
        promoted_credentials: None,
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
    AstraService {
        state_dir: dir.to_path_buf(),
        registry: Mutex::new(registry),
        issuer: RwLock::new(None),
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
        service_public_key,
        operations: Mutex::new(crate::operations::OperationStore::new()),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new().expect("capability key"),
        ),
        approval_credentials: RwLock::new(Arc::new(crate::service::ApprovalCredentials {
            ids: Vec::new(),
            epoch: 1,
            registry: None,
        })),
        signing: Mutex::new(crate::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(crate::recovery::RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault: RwLock::new(Some(Arc::new(b"placeholder encrypted vault".to_vec()))),
        gateway,
        volume_writes: VolumeWrites::new(),
    }
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
        DoorOutcome::Opened(opening) => opening.opened,
        other => panic!("expected a campaign, got {other:?}"),
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
        DoorRequest::ChainOpen { .. } => (true, false),
        DoorRequest::ChainNext {} => (true, false),
        DoorRequest::ChainAbandon {} => (true, false),
        DoorRequest::IssuerDelegation { .. } => (true, false),
        DoorRequest::IssuerRequest {} => (true, false),
        DoorRequest::PinCaTls { .. } => (true, false),
        DoorRequest::IssuerInstall { .. } => (true, false),
        DoorRequest::GatewayIdentityPublish { .. } => (true, false),
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
        DoorRequest::ChainOpen { text: text() },
        DoorRequest::ChainNext {},
        DoorRequest::ChainAbandon {},
        DoorRequest::IssuerDelegation { text: text() },
        DoorRequest::IssuerRequest {},
        DoorRequest::PinCaTls {
            fingerprint: Fingerprint::of(b"client tls ca"),
        },
        DoorRequest::IssuerInstall {
            authorization: Box::new(delegation(&delegated_material(), 1)),
        },
        DoorRequest::GatewayIdentityPublish { epoch: 5 },
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
async fn an_opening_text_is_bounded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    for long in [
        OpeningText {
            reason: "a".repeat(MAX_REASON_CHARS + 1),
            ..text()
        },
        OpeningText {
            requested_by: "a".repeat(MAX_REQUESTED_BY_CHARS + 1),
            ..text()
        },
    ] {
        for connector in [console(), tunnel()] {
            let refused = service
                .door(
                    connector,
                    DoorRequest::FleetLeafs { text: long.clone() },
                    NOW,
                )
                .await;
            assert!(
                matches!(refused, Err(DoorRefusal::TextTooLong)),
                "{refused:?}"
            );
        }
    }
    assert!(service.signing.lock().await.is_empty());
}

/// What would garble the operator's screen, or hide the identity the tunnel
/// appends: a line break, a control character, a bidirectional override, an
/// invisible mark.
#[tokio::test]
async fn an_opening_text_refuses_what_the_operator_would_not_read() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    for hidden in [
        "rotation\n— pair wireguard:AAAA",
        "rotation\r",
        "rotation\u{7}",
        "rotation\u{85}",
        "alice\u{202E}AAAA:draugeriw riap —",
        "alice\u{2066}",
        "ali\u{200B}ce",
        "ali\u{200D}ce",
        "alice\u{FEFF}",
        "alice\u{AD}",
        "rotation\u{2028}— pair wireguard:AAAA",
        "alice\u{E0041}",
    ] {
        for (reason, requested_by) in [(hidden, "alice"), ("quarterly rotation", hidden)] {
            for connector in [console(), tunnel()] {
                let request = DoorRequest::FleetLeafs {
                    text: OpeningText {
                        reason: reason.into(),
                        requested_by: requested_by.into(),
                        ..text()
                    },
                };
                let refused = service.door(connector, request, NOW).await;
                assert!(
                    matches!(refused, Err(DoorRefusal::TextUnprintable)),
                    "{hidden:?}: {refused:?}"
                );
            }
        }
    }
    assert!(service.signing.lock().await.is_empty());
}

/// Ordinary French, accents, typographic quotes and dashes included, opens at
/// the very bound: the bound counts characters, not bytes.
#[tokio::test]
async fn an_opening_text_in_ordinary_french_opens_at_the_bound() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let sentence = "Rotation trimestrielle : clés « été » renouvelées — après l'incident n° 3. ";
    let reason: String = sentence.chars().cycle().take(MAX_REASON_CHARS).collect();
    let requested_by: String = "Élodie Gaëlle Œuvray-Brûlé "
        .chars()
        .cycle()
        .take(MAX_REQUESTED_BY_CHARS)
        .collect();
    assert!(reason.len() > MAX_REASON_CHARS, "multi-byte characters");
    let opened = opened(
        service
            .door(
                console(),
                DoorRequest::FleetLeafs {
                    text: OpeningText {
                        reason: reason.clone(),
                        requested_by: requested_by.clone(),
                        ..text()
                    },
                },
                NOW,
            )
            .await,
    );
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.reason, reason.trim());
    assert_eq!(campaign.requested_by, requested_by.trim());
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
        .encrypted_vault = RwLock::new(None);
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
    assert_eq!(
        campaign.targets[0].epoch,
        service.registry.lock().await.state().peers[&peer_key(2).to_base64()].revocation_epoch
    );
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

/// What the fake gateway serves, and what the door must read back.
const GATEWAY_TLS_NOT_AFTER: u64 = 100_000;
const GATEWAY_LEAF_NOT_AFTER: u64 = 1_000_000;
const GATEWAY_GENERATION: u64 = 3;
const GATEWAY_DECISION_EPOCH: u64 = 7;

fn served_leaf() -> PqCertificate {
    use base64::Engine as _;
    let (ca_private, _) = aether::key_negotiation::generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) =
        aether::key_negotiation::generate_ml_dsa_87_keypair().expect("keygen");
    aether::key_negotiation::issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [0x31; 16],
            subject: "gateway".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([1; 32]).to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(&subject_public),
            not_before_unix: 0,
            not_after_unix: GATEWAY_LEAF_NOT_AFTER,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("signed leaf")
}

/// A gateway that answers the identity read and refuses everything else.
struct FakeGateway;

#[async_trait::async_trait]
impl astra_channel::AstraStageHandler for FakeGateway {
    async fn stage_from_astra(
        &self,
        _: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<
        Box<aether::certificates::client::GatewayCertificateStageReceipt>,
        aether::certificates::transport::TrustUpdateRefusal,
    > {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }
}

#[async_trait::async_trait]
impl astra_channel::AstraChannelHandler for FakeGateway {
    async fn revoke(
        &self,
        _: Box<aether::certificates::revocation::EmergencyCertificateRevocation>,
    ) -> Result<(), aether::certificates::transport::TrustUpdateRefusal> {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }

    async fn distribute(
        &self,
        _: Box<astra_channel::TrustDistribution>,
    ) -> Result<(), aether::certificates::transport::TrustUpdateRefusal> {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }

    async fn commit_recovery(
        &self,
        _: Box<astra_channel::RelayedStageCommit>,
    ) -> Result<(), aether::certificates::transport::TrustUpdateRefusal> {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }

    async fn gateway_transition_published(
        &self,
        _: astra_channel::GatewayTransitionPublished,
    ) -> Result<(), aether::certificates::transport::TrustUpdateRefusal> {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }

    async fn gateway_identity(
        &self,
    ) -> Result<
        astra_channel::GatewayIdentityView,
        aether::certificates::transport::TrustUpdateRefusal,
    > {
        let pq_certificate = served_leaf();
        Ok(astra_channel::GatewayIdentityView {
            pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
                &pq_certificate,
            )
            .expect("fingerprint"),
            pq_certificate,
            tls_certificate_fingerprint: Fingerprint::of(b"gateway tls in service"),
            tls_certificate_not_after: GATEWAY_TLS_NOT_AFTER,
            active_gateway_identity_epoch: GATEWAY_GENERATION,
            gateway_decision_epoch: GATEWAY_DECISION_EPOCH,
        })
    }

    async fn peer_state(
        &self,
        _: &WireGuardKey,
    ) -> Result<
        astra_channel::PeerCertificateStateView,
        aether::certificates::transport::TrustUpdateRefusal,
    > {
        Err(aether::certificates::transport::TrustUpdateRefusal::Rejected)
    }
}

/// Astra's transport identity, written in `dir`, and a gateway server
/// identity for the channel to pin: the two halves every loopback gateway
/// below is built from.
fn channel_identities(
    dir: &Path,
) -> (
    aether::certificates::encoding::DerCertificate,
    astra_channel::ChannelIdentity,
    aether::certificates::encoding::DerCertificate,
) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    let astra_certificate = crate::gateway::initialize(dir, false).expect("astra identity");
    let mut params = CertificateParams::new(vec![astra_channel::INTERNAL_SERVER_NAME.to_string()])
        .expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    let key_pair = KeyPair::generate().expect("keygen");
    let certificate = params.self_signed(&key_pair).expect("self-signed");
    let der = certificate.der().to_vec();
    let identity = astra_channel::ChannelIdentity {
        certificate_der: der.clone(),
        private_key_der: key_pair.serialize_der(),
    };
    let gateway_certificate =
        aether::certificates::encoding::DerCertificate::new(der).expect("der");
    (astra_certificate, identity, gateway_certificate)
}

/// The fixture, with its gateway channel dialing a fake gateway on loopback.
async fn fixture_with_gateway(dir: &Path) -> Arc<AstraService> {
    let (astra_certificate, identity, gateway_certificate) = channel_identities(dir);
    let config = astra_channel::server_config(&identity, &astra_certificate).expect("server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let router = astra_channel::router(Arc::new(FakeGateway));
    tokio::spawn(async move {
        let _ = astra_channel::serve(address, config, router, astra_channel::INTERNAL_PREFIX).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let channel = crate::gateway::GatewayChannel::open(dir, address, &gateway_certificate)
        .expect("channel opens");
    Arc::new(build_service(dir, None, Some(channel)))
}

#[tokio::test]
async fn a_gateway_revocation_reads_both_expiries_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture_with_gateway(dir.path()).await;
    let request = DoorRequest::GatewayRevocation { text: text() };
    let opened = opened(service.door(console(), request, NOW).await);
    assert_eq!(opened.scope, CampaignScope::EmergencyRevocation);
    assert_eq!(
        opened.revocation_expiries,
        Some(RevocationExpiries {
            tls_not_after: Some(GATEWAY_TLS_NOT_AFTER),
            pq_not_after: Some(GATEWAY_LEAF_NOT_AFTER),
        })
    );
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(
        campaign.targets[0].certificate_kind,
        CertificateKind::GatewayPq
    );
    assert_eq!(campaign.targets[0].epoch, GATEWAY_DECISION_EPOCH);
    assert_eq!(campaign.targets[0].generation, GATEWAY_GENERATION);
}

#[tokio::test]
async fn a_gateway_identity_opening_freezes_the_leaf_and_exports_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = fixture_with_gateway(dir.path()).await;
    let request = DoorRequest::GatewayIdentity { text: text() };
    let opened = opened(service.door(console(), request, NOW).await);
    assert_eq!(opened.scope, CampaignScope::GatewayIdentity);
    assert_eq!(opened.revocation_expiries, None);
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.targets[0].epoch, GATEWAY_DECISION_EPOCH);
    assert_eq!(campaign.targets[0].generation, GATEWAY_GENERATION);
    let exported = std::fs::read(dir.path().join(GATEWAY_ACTIVE_CERTIFICATE_FILE))
        .expect("the leaf in service is exported");
    let leaf: PqCertificate = serde_json::from_slice(&exported).expect("a PQ certificate");
    assert_eq!(leaf.not_after_unix, GATEWAY_LEAF_NOT_AFTER);
}

fn plan_path(dir: &Path) -> std::path::PathBuf {
    dir.join(crate::chain::CHAIN_PLAN_FILE)
}

fn read_plan(dir: &Path) -> crate::chain::ChainPlan {
    serde_json::from_slice(&std::fs::read(plan_path(dir)).expect("plan present"))
        .expect("plan decodes")
}

fn chain_step(
    outcome: Result<DoorOutcome, DoorRefusal>,
) -> (Option<OperatorOpened>, Option<String>, usize) {
    match outcome.expect("the door answers") {
        DoorOutcome::ChainStep {
            opened,
            delegation_request,
            remaining,
            ..
        } => (
            opened.map(|opening| opening.opened),
            delegation_request,
            remaining,
        ),
        other => panic!("expected a chain step, got {other:?}"),
    }
}

#[tokio::test]
async fn a_tunnel_cannot_reach_a_console_action() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let refusal = service
        .door(tunnel(), DoorRequest::ChainOpen { text: text() }, NOW)
        .await
        .expect_err("the tunnel is refused");
    assert!(matches!(refusal, DoorRefusal::NotAllowedHere));
    assert!(service.signing.lock().await.pending(NOW).is_empty());
    assert!(!plan_path(dir.path()).exists());
}

#[tokio::test]
async fn the_chain_opens_its_first_step_and_records_the_plan() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let (opened, request, remaining) = chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    let opened = opened.expect("the first step opens a campaign");
    assert_eq!(opened.scope, CampaignScope::IssuerDelegation);
    assert_eq!(remaining, 4);
    let request: crate::issuer::IssuerDelegationRequest =
        serde_json::from_str(&request.expect("the issuer step returns its request"))
            .expect("the request is JSON");
    assert_eq!(request.issuer_epoch, 1);

    let plan = read_plan(dir.path());
    assert_eq!(plan.current, 0);
    assert_eq!(plan.steps[0].operation_id, Some(opened.operation_id));
    assert_eq!(plan.reason, "quarterly rotation");
    assert!(crate::issuer::pq_key_path(dir.path(), 1).exists());
    assert!(crate::issuer::tls_key_path(dir.path(), 1).exists());
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.targets.len(), 1);
    assert_eq!(
        campaign.targets[0].certificate_kind,
        CertificateKind::AstraIssuer
    );

    let again = service
        .door(console(), DoorRequest::ChainOpen { text: text() }, NOW + 1)
        .await;
    assert!(matches!(
        again,
        Err(DoorRefusal::ChainAlreadyOpen { remaining: 4 })
    ));
}

#[tokio::test]
async fn a_chain_step_and_a_fleet_campaign_block_each_other() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let (step, ..) = chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    let step = step.expect("opened");
    // The first step is of the issuer family: an isolated delegation is its
    // twin, and is refused while the step waits.
    let refused = service
        .door(
            console(),
            DoorRequest::IssuerDelegation { text: text() },
            NOW + 1,
        )
        .await;
    match refused {
        Err(DoorRefusal::AlreadyOpen { operation_id }) => {
            assert_eq!(operation_id, step.operation_id)
        }
        other => panic!("expected AlreadyOpen, got {other:?}"),
    }
    // A bare request would overwrite the keys the waiting step pins.
    assert!(matches!(
        service
            .door(console(), DoorRequest::IssuerRequest {}, NOW + 1)
            .await,
        Err(DoorRefusal::AlreadyOpen { .. })
    ));

    // The last step is of the fleet family: an isolated campaign blocks it,
    // and the plan does not move when the step is refused.
    let mut plan = read_plan(dir.path());
    plan.current = 2;
    plan.steps[2].operation_id = None;
    std::fs::write(
        plan_path(dir.path()),
        serde_json::to_vec(&plan).expect("encodes"),
    )
    .expect("plan rewritten");
    let fleet = opened(
        service
            .door(console(), DoorRequest::FleetLeafs { text: text() }, NOW + 2)
            .await,
    );
    match service
        .door(console(), DoorRequest::ChainNext {}, NOW + 3)
        .await
    {
        Err(DoorRefusal::AlreadyOpen { operation_id }) => {
            assert_eq!(operation_id, fleet.operation_id)
        }
        other => panic!("expected AlreadyOpen, got {other:?}"),
    }
    assert_eq!(read_plan(dir.path()).current, 2);
}

#[tokio::test]
async fn chain_next_refuses_a_step_that_has_not_landed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    assert!(matches!(
        service
            .door(console(), DoorRequest::ChainNext {}, NOW)
            .await,
        Err(DoorRefusal::NoChain)
    ));
    chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    let refused = service
        .door(console(), DoorRequest::ChainNext {}, NOW + 1)
        .await;
    assert!(
        matches!(refused, Err(DoorRefusal::ChainStepIncomplete(_))),
        "{refused:?}"
    );
    assert_eq!(read_plan(dir.path()).current, 0);
}

#[tokio::test]
async fn chain_next_opens_the_following_step_once_the_previous_has_landed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_ca_tls(dir.path());
    chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    // The issuer effect cannot be produced without a companion; stand in for
    // it by naming an effect the registry already shows.
    let mut plan = read_plan(dir.path());
    plan.steps[0].effect = crate::chain::ChainEffect::SpentByPeers;
    std::fs::write(
        plan_path(dir.path()),
        serde_json::to_vec(&plan).expect("encodes"),
    )
    .expect("plan rewritten");

    let (opened, request, remaining) = chain_step(
        service
            .door(console(), DoorRequest::ChainNext {}, NOW + 1)
            .await,
    );
    let opened = opened.expect("the second step opens");
    assert_eq!(opened.scope, CampaignScope::TrustAuthorities);
    assert_eq!(request, None);
    assert_eq!(remaining, 3);
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.targets.len(), 1);
    assert_eq!(campaign.targets[0].certificate_kind, CertificateKind::CaTls);
    assert_eq!(read_plan(dir.path()).current, 1);
}

#[tokio::test]
async fn a_chain_can_be_abandoned_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    assert!(matches!(
        service
            .door(console(), DoorRequest::ChainAbandon {}, NOW)
            .await,
        Err(DoorRefusal::NoChain)
    ));
    chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    assert!(matches!(
        service
            .door(console(), DoorRequest::ChainAbandon {}, NOW + 1)
            .await,
        Ok(DoorOutcome::ChainAbandoned { .. })
    ));
    assert!(!plan_path(dir.path()).exists());
}

#[tokio::test]
async fn an_issuer_request_writes_its_keys_and_returns_the_public_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let outcome = service
        .door(console(), DoorRequest::IssuerRequest {}, NOW)
        .await
        .expect("the request is drawn");
    let DoorOutcome::IssuerRequested { request, .. } = outcome else {
        panic!("expected an issuer request");
    };
    let request: crate::issuer::IssuerDelegationRequest =
        serde_json::from_str(&request).expect("the request is JSON");
    assert_eq!(request.issuer_epoch, 1);
    assert_eq!(
        request.trust_domain_id,
        TrustDomainId::new([1; 16]).expect("domain").to_hex()
    );
    assert!(crate::issuer::pq_key_path(dir.path(), 1).exists());
    assert!(crate::issuer::tls_key_path(dir.path(), 1).exists());
}

#[tokio::test]
async fn an_issuer_request_without_text_opens_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let outcome = service
        .door(console(), DoorRequest::IssuerRequest {}, NOW)
        .await
        .expect("the request is drawn");
    assert!(matches!(
        outcome,
        DoorOutcome::IssuerRequested { opened: None, .. }
    ));
    assert!(service.signing.lock().await.pending(NOW).is_empty());
}

#[tokio::test]
async fn an_issuer_delegation_pins_the_material_it_returns() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let outcome = service
        .door(
            console(),
            DoorRequest::IssuerDelegation { text: text() },
            NOW,
        )
        .await
        .expect("the delegation opens");
    let DoorOutcome::IssuerRequested {
        request,
        opened: Some(Opening { opened, .. }),
    } = outcome
    else {
        panic!("expected a request and a campaign");
    };
    let request: crate::issuer::IssuerDelegationRequest =
        serde_json::from_str(&request).expect("the request is JSON");
    let campaign = campaign_of(&service, &opened).await;
    assert_eq!(campaign.scope, CampaignScope::IssuerDelegation);
    assert_eq!(campaign.targets[0].epoch, request.issuer_epoch);
    let public_key =
        aether::certificates::encoding::MlDsa87PublicKey::parse(&request.pq_issuer_public_key)
            .expect("public key");
    assert_eq!(
        campaign.targets[0].active_pq_certificate_fingerprint,
        Fingerprint::of(public_key.as_bytes())
    );
}

#[tokio::test]
async fn a_refused_delegation_leaves_the_keys_it_would_have_replaced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    service
        .door(
            console(),
            DoorRequest::IssuerDelegation { text: text() },
            NOW,
        )
        .await
        .expect("the delegation opens");
    let before = std::fs::read(crate::issuer::pq_key_path(dir.path(), 1)).expect("key");
    let mut empty = text();
    empty.reason.clear();
    for request in [
        DoorRequest::IssuerDelegation { text: empty },
        DoorRequest::IssuerDelegation { text: text() },
        DoorRequest::IssuerRequest {},
    ] {
        service
            .door(console(), request, NOW + 1)
            .await
            .expect_err("refused");
    }
    assert_eq!(
        std::fs::read(crate::issuer::pq_key_path(dir.path(), 1)).expect("key"),
        before
    );
}

#[test]
fn the_requests_without_text_are_a_bare_action_on_the_socket() {
    for (body, expected) in [
        (r#"{"action":"chain_next"}"#, DoorRequest::ChainNext {}),
        (
            r#"{"action":"chain_abandon"}"#,
            DoorRequest::ChainAbandon {},
        ),
        (
            r#"{"action":"issuer_request"}"#,
            DoorRequest::IssuerRequest {},
        ),
    ] {
        assert_eq!(
            serde_json::from_str::<DoorRequest>(body).expect("decodes"),
            expected
        );
    }
    assert!(serde_json::from_str::<DoorRequest>(
        r#"{"action":"issuer_request","out":"/etc/passwd"}"#
    )
    .is_err());
}

/// What `CA-PQ` signs for a delegation, and the private halves it names.
struct Delegated {
    ca_private: zeroize::Zeroizing<Vec<u8>>,
    ca_public: aether::certificates::encoding::MlDsa87PublicKey,
    issuer_private: zeroize::Zeroizing<Vec<u8>>,
    issuer_public: aether::certificates::encoding::MlDsa87PublicKey,
    intermediate: aether::certificates::encoding::DerCertificate,
    intermediate_key: Vec<u8>,
}

fn delegated_material() -> Delegated {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("CA-PQ keypair");
    let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "astra delegated issuer 1");
    // The chain is read against the clock, and these tests drive a synthetic
    // one near the Unix epoch.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let key = KeyPair::generate().expect("intermediate key");
    let certificate = params.self_signed(&key).expect("intermediate");
    Delegated {
        ca_private,
        ca_public,
        issuer_private,
        issuer_public,
        intermediate: aether::certificates::encoding::DerCertificate::new(
            certificate.der().to_vec(),
        )
        .expect("der"),
        intermediate_key: key.serialize_der(),
    }
}

/// A delegation of `epoch`, signed under `delegated.ca_private` for the
/// fixture's domain and policy.
fn delegation(
    delegated: &Delegated,
    epoch: u64,
) -> aether::certificates::authority::AstraIssuerAuthorization {
    let trust_domain_id = TrustDomainId::new([1; 16]).expect("domain");
    let gateway_wg_public_key = WireGuardKey::from_bytes([1; 32]);
    aether::certificates::authority::AstraIssuerAuthorization {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id,
        ca_epoch: 1,
        ca_tls_epoch: 1,
        gateway_wg_public_key,
        server_name: "gateway.example".into(),
        issuer_epoch: epoch,
        pq_issuer_public_key: delegated.issuer_public.clone(),
        tls_intermediate_certificate: delegated.intermediate.clone(),
        allowed_usage: aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
        maximum_leaf_lifetime_secs: 200_000,
        policy_fingerprint: AstraIssuancePolicy::standard(
            trust_domain_id,
            gateway_wg_public_key,
            "gateway.example".into(),
        )
        .fingerprint()
        .expect("policy"),
        not_before: 0,
        not_after: NOW * 2,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&delegated.ca_private)
    .expect("signed delegation")
}

/// Rewrites the service's registry in memory and on disk, as if it had been
/// bootstrapped that way.
async fn rewrite_registry(service: &AstraService, change: impl FnOnce(&mut AstraState)) {
    let mut registry = service.registry.lock().await;
    let mut state = registry.state().clone();
    change(&mut state);
    *registry = AstraRegistry::new(service.state_dir.join("registry.json"), state);
    registry.save().expect("registry saved");
}

/// A domain under `delegated`'s `CA-PQ`, holding the private keys of its
/// epoch-1 delegation where an issuer request leaves them.
async fn ready_to_install(service: &AstraService) -> Delegated {
    let delegated = delegated_material();
    let ca_public = delegated.ca_public.clone();
    rewrite_registry(service, |state| state.ca_public_key = ca_public).await;
    std::fs::write(
        crate::issuer::pq_key_path(&service.state_dir, 1),
        delegated.issuer_private.as_slice(),
    )
    .expect("pq key");
    std::fs::write(
        crate::issuer::tls_key_path(&service.state_dir, 1),
        &delegated.intermediate_key,
    )
    .expect("tls key");
    delegated
}

/// Points the service's registry at a file no save can write, keeping the
/// state it holds.
async fn make_registry_unwritable(service: &AstraService) {
    let mut registry = service.registry.lock().await;
    let state = registry.state().clone();
    *registry = AstraRegistry::new(
        service.state_dir.join("absent").join("registry.json"),
        state,
    );
}

async fn memory_of(service: &AstraService) -> AstraState {
    service.registry.lock().await.state().clone()
}

fn registry_on_disk(dir: &Path) -> AstraRegistry {
    AstraRegistry::load(&dir.join("registry.json"), None).expect("registry on disk")
}

#[test]
fn the_lock_is_exclusive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let held = VolumeLock::try_acquire(dir.path())
        .expect("lockable")
        .expect("the first taker holds it");
    assert!(dir.path().join(VOLUME_LOCK_FILE).exists());
    assert!(VolumeLock::try_acquire(dir.path())
        .expect("lockable")
        .is_none());
    drop(held);
    assert!(VolumeLock::try_acquire(dir.path())
        .expect("lockable")
        .is_some());
}

#[tokio::test]
async fn a_pinned_ca_tls_is_a_target_without_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let fingerprint = Fingerprint::of(b"client tls ca");
    let outcome = service
        .door(console(), DoorRequest::PinCaTls { fingerprint }, NOW)
        .await
        .expect("pinned");
    let DoorOutcome::Pinned {
        audit_head,
        changed: true,
    } = outcome
    else {
        panic!("expected a pin, got {outcome:?}");
    };
    assert_eq!(audit_head, service.registry.lock().await.audit_head());
    let on_disk = registry_on_disk(dir.path());
    assert_eq!(on_disk.state().ca_tls_fingerprint, Some(fingerprint));
    assert_eq!(on_disk.audit_head(), audit_head);

    // The same service, never reloaded.
    let request = DoorRequest::TrustAuthorities { text: text() };
    let opened = opened(service.door(console(), request, NOW).await);
    assert_eq!(opened.target_count, 2);
    let campaign = campaign_of(&service, &opened).await;
    assert!(campaign
        .targets
        .iter()
        .any(|target| target.certificate_kind == CertificateKind::CaTls));
}

#[tokio::test]
async fn a_pinned_anchor_is_never_replaced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_ca_tls(dir.path());
    let held = Fingerprint::of(b"client tls ca");
    let before = service.registry.lock().await.audit_head();

    // The anchor already held: nothing changes, and it is not a refusal.
    let outcome = service
        .door(console(), DoorRequest::PinCaTls { fingerprint: held }, NOW)
        .await
        .expect("idempotent");
    assert_eq!(
        outcome,
        DoorOutcome::Pinned {
            audit_head: before,
            changed: false
        }
    );

    let refusal = service
        .door(
            console(),
            DoorRequest::PinCaTls {
                fingerprint: Fingerprint::of(b"another client tls ca"),
            },
            NOW,
        )
        .await
        .expect_err("a pinned anchor is not replaced");
    assert!(matches!(refusal, DoorRefusal::ClientTlsAnchorAlreadyPinned));
    let registry = service.registry.lock().await;
    assert_eq!(registry.state().ca_tls_fingerprint, Some(held));
    assert_eq!(registry.audit_head(), before);
    assert_eq!(registry_on_disk(dir.path()).audit_head(), before);
}

#[tokio::test]
async fn an_installed_delegation_is_recorded_in_memory_and_on_disk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let delegated = ready_to_install(&service).await;

    let outcome = service
        .door(
            console(),
            DoorRequest::IssuerInstall {
                authorization: Box::new(delegation(&delegated, 1)),
            },
            NOW,
        )
        .await
        .expect("installed");
    let DoorOutcome::IssuerInstalled {
        issuer_epoch,
        not_after,
        audit_head,
    } = outcome
    else {
        panic!("expected an installed delegation, got {outcome:?}");
    };
    assert_eq!((issuer_epoch, not_after), (1, NOW * 2));
    {
        let registry = service.registry.lock().await;
        assert_eq!(
            registry
                .state()
                .issuer
                .as_ref()
                .map(|issuer| issuer.issuer_epoch),
            Some(1)
        );
        assert_eq!(registry.audit_head(), audit_head);
    }
    let on_disk = registry_on_disk(dir.path());
    assert_eq!(
        on_disk
            .state()
            .issuer
            .as_ref()
            .map(|issuer| issuer.issuer_epoch),
        Some(1)
    );
    assert_eq!(on_disk.audit_head(), audit_head);

    // The next request draws the epoch after it, without a restart.
    let DoorOutcome::IssuerRequested { request, .. } = service
        .door(console(), DoorRequest::IssuerRequest {}, NOW)
        .await
        .expect("the next request")
    else {
        panic!("expected an issuer request");
    };
    let request: crate::issuer::IssuerDelegationRequest =
        serde_json::from_str(&request).expect("the request is JSON");
    assert_eq!(request.issuer_epoch, 2);
}

#[tokio::test]
async fn a_console_install_is_adopted_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let delegated = ready_to_install(&service).await;
    assert!(service.issuer().is_none());

    service
        .door(
            console(),
            DoorRequest::IssuerInstall {
                authorization: Box::new(delegation(&delegated, 1)),
            },
            NOW,
        )
        .await
        .expect("installed");
    assert_eq!(
        service
            .issuer()
            .expect("adopted")
            .authorization
            .issuer_epoch,
        1
    );
}

#[tokio::test]
async fn a_delegation_under_another_anchor_is_refused_and_records_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let delegated = delegated_material();
    let before = service.registry.lock().await.audit_head();
    let refusal = service
        .door(
            console(),
            DoorRequest::IssuerInstall {
                authorization: Box::new(delegation(&delegated, 1)),
            },
            NOW,
        )
        .await
        .expect_err("not signed by this domain's CA-PQ");
    assert!(matches!(refusal, DoorRefusal::DelegationRefused(_)));
    assert!(service.registry.lock().await.state().issuer.is_none());
    assert_eq!(registry_on_disk(dir.path()).audit_head(), before);
}

#[test]
fn an_issuer_campaign_for_a_passed_epoch_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = build_service(dir.path(), None, None);
    let mut registry = service.registry.into_inner();
    super::issuer::still_next_epoch(registry.state(), 1).expect("epoch 1 follows none");

    // A delegation of epoch 1 lands between the draw and the opening.
    let delegated = delegated_material();
    let mut state = registry.state().clone();
    state.issuer = Some(aether::certificates::state::AstraIssuerState {
        issuer_epoch: 1,
        authorization: delegation(&delegated, 1),
        state: aether::certificates::state::IssuerLifecycle::Active,
    });
    registry = AstraRegistry::new(dir.path().join("registry.json"), state);
    assert!(matches!(
        super::issuer::still_next_epoch(registry.state(), 1),
        Err(DoorRefusal::IssuerEpochMoved { epoch: 1 })
    ));
    super::issuer::still_next_epoch(registry.state(), 2).expect("epoch 2 follows 1");
}

/// The gateway transition of `epoch`, stored as an approved campaign leaves
/// it: accepted, not yet published.
fn stored_gateway_transition(epoch: u64) -> crate::registry::StoredTransition {
    use aether::certificates::gateway::GatewayIdentityTransition;
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("CA-PQ keypair");
    let transition = GatewayIdentityTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls in service"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq in service"),
        next_gateway_certificate: Some(served_leaf()),
        window: aether::certificates::window::TransitionWindow::new(NOW, NOW + 100, NOW + 200)
            .expect("window"),
        reason: aether::certificates::authority::RotationReason::Scheduled,
        ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("signed transition");
    crate::registry::StoredTransition {
        campaign_id: aether::certificates::encoding::Id16::new([5; 16]).expect("id"),
        accepted_at: NOW - 10,
        published: false,
        object: aether::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(
            Box::new(transition),
        ),
        credential_registry: None,
    }
}

fn published_on_disk(dir: &Path) -> bool {
    registry_on_disk(dir)
        .state()
        .transitions
        .iter()
        .any(|stored| stored.published)
}

#[tokio::test]
async fn a_publication_is_marked_before_the_relay() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A gateway that refuses every publication: the relay fails.
    let service = fixture_with_gateway(dir.path()).await;
    let stored = stored_gateway_transition(5);
    let aether::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(transition) =
        &stored.object
    else {
        panic!("a gateway transition");
    };
    let marked = DoorOutcome::Published {
        epoch: 5,
        transition_fingerprint: transition.fingerprint().expect("fingerprint"),
        activation_at: transition.window.activation_at,
        confirmed: false,
    };
    rewrite_registry(&service, |state| state.transitions.push(stored.clone())).await;

    let request = DoorRequest::GatewayIdentityPublish { epoch: 5 };
    let outcome = service
        .door(console(), request.clone(), NOW)
        .await
        .expect("marked although the relay failed");
    assert_eq!(outcome, marked);
    assert!(published_on_disk(dir.path()));
    let head = registry_on_disk(dir.path()).audit_head();

    // Replayable: the same request relays again and marks nothing twice.
    let outcome = service
        .door(console(), request, NOW + 1)
        .await
        .expect("replayed");
    assert_eq!(outcome, marked);
    assert_eq!(registry_on_disk(dir.path()).audit_head(), head);
}

#[tokio::test]
async fn a_publication_without_the_service_channel_marks_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    rewrite_registry(&service, |state| {
        state.transitions.push(stored_gateway_transition(5))
    })
    .await;
    let refusal = service
        .door(
            console(),
            DoorRequest::GatewayIdentityPublish { epoch: 5 },
            NOW,
        )
        .await
        .expect_err("nowhere to relay");
    assert!(matches!(
        refusal,
        DoorRefusal::PublicationChannelUnavailable
    ));
    assert!(!published_on_disk(dir.path()));
}

#[tokio::test]
async fn a_publication_names_a_stored_transition() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_gateway(dir.path()).await;
    let refusal = service
        .door(
            console(),
            DoorRequest::GatewayIdentityPublish { epoch: 5 },
            NOW,
        )
        .await
        .expect_err("nothing stored at this epoch");
    assert!(matches!(
        refusal,
        DoorRefusal::NoGatewayTransition { epoch: 5 }
    ));
}

/// The bound a test gives the door's gateway calls, in place of
/// [`GATEWAY_CALL_BOUND`]: short, so the test does not wait twenty seconds.
const MUTE_GATEWAY_BOUND: std::time::Duration = std::time::Duration::from_millis(200);

/// How long a test waits before it calls a wedged door wedged.
const WEDGE_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

/// The fixture, with its gateway channel dialing a gateway that accepts every
/// connection and never answers: no handshake, no byte, no close.
async fn fixture_with_mute_gateway(dir: &Path) -> Arc<AstraService> {
    let (_, _, gateway_certificate) = channel_identities(dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((connection, _)) = listener.accept().await {
            held.push(connection);
        }
    });
    let channel = crate::gateway::GatewayChannel::open(dir, address, &gateway_certificate)
        .expect("channel opens");
    Arc::new(build_service(dir, None, Some(channel)))
}

/// `chain next` holds the volume gate across its live read of the gateway
/// identity. A gateway that never answers must not hold it with it: the read
/// gives up at the bound, the step is refused by its name, and a command
/// waiting on the gate proceeds.
#[tokio::test]
async fn a_mute_gateway_releases_the_volume_gate_at_the_bound() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_mute_gateway(dir.path()).await;
    chain_step(
        service
            .door(console(), DoorRequest::ChainOpen { text: text() }, NOW)
            .await,
    );
    // The second step stands as never deposited: `next` passes it and opens
    // the gateway's, which is read live.
    let mut plan = read_plan(dir.path());
    plan.current = 1;
    plan.steps[1].operation_id = None;
    std::fs::write(
        plan_path(dir.path()),
        serde_json::to_vec(&plan).expect("encodes"),
    )
    .expect("plan rewritten");

    let wedged = {
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            service
                .door_within(
                    console(),
                    DoorRequest::ChainNext {},
                    NOW + 1,
                    MUTE_GATEWAY_BOUND,
                )
                .await
        })
    };
    // On this single-threaded runtime the spawned step runs up to its first
    // wait — the gateway — with the gate taken.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let abandoned = tokio::time::timeout(
        WEDGE_GUARD,
        service.door(console(), DoorRequest::ChainAbandon {}, NOW + 2),
    )
    .await
    .expect("the gate is released once the gateway read gives up");
    assert!(
        matches!(abandoned, Ok(DoorOutcome::ChainAbandoned { .. })),
        "{abandoned:?}"
    );
    let refused = tokio::time::timeout(WEDGE_GUARD, wedged)
        .await
        .expect("the step ends at the bound")
        .expect("joined");
    assert!(
        matches!(refused, Err(DoorRefusal::GatewayChannelUnavailable)),
        "the step held the gate first, and was refused by the gateway's silence: {refused:?}"
    );
}

/// A publication the gateway never answers is recorded and unconfirmed at the
/// bound: the mark is already persisted, and the operator asks again.
#[tokio::test]
async fn a_publication_to_a_mute_gateway_is_unconfirmed_at_the_bound() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_mute_gateway(dir.path()).await;
    rewrite_registry(&service, |state| {
        state.transitions.push(stored_gateway_transition(5))
    })
    .await;
    let outcome = tokio::time::timeout(
        WEDGE_GUARD,
        service.door_within(
            console(),
            DoorRequest::GatewayIdentityPublish { epoch: 5 },
            NOW,
            MUTE_GATEWAY_BOUND,
        ),
    )
    .await
    .expect("the relay ends at the bound")
    .expect("marked although the gateway said nothing");
    assert!(
        matches!(
            outcome,
            DoorOutcome::Published {
                epoch: 5,
                confirmed: false,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(published_on_disk(dir.path()));
}

#[test]
fn the_writes_are_bodies_of_the_socket() {
    let fingerprint = Fingerprint::of(b"client tls ca");
    let body = format!(r#"{{"action":"pin_ca_tls","fingerprint":"{fingerprint}"}}"#);
    assert_eq!(
        serde_json::from_str::<DoorRequest>(&body).expect("decodes"),
        DoorRequest::PinCaTls { fingerprint }
    );
    assert_eq!(
        serde_json::from_str::<DoorRequest>(r#"{"action":"gateway_identity_publish","epoch":5}"#)
            .expect("decodes"),
        DoorRequest::GatewayIdentityPublish { epoch: 5 }
    );
    let delegated = delegated_material();
    let install = DoorRequest::IssuerInstall {
        authorization: Box::new(delegation(&delegated, 1)),
    };
    let round_trip: DoorRequest =
        serde_json::from_slice(&serde_json::to_vec(&install).expect("encoded")).expect("decoded");
    assert_eq!(round_trip, install);
    assert!(serde_json::from_str::<DoorRequest>(
        r#"{"action":"gateway_identity_publish","epoch":5,"gateway_channel":"127.0.0.1:1"}"#
    )
    .is_err());
}

#[tokio::test]
async fn a_pin_whose_save_fails_leaves_memory_as_it_was() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    make_registry_unwritable(&service).await;
    let before = memory_of(&service).await;
    let refusal = service
        .door(
            console(),
            DoorRequest::PinCaTls {
                fingerprint: Fingerprint::of(b"client tls ca"),
            },
            NOW,
        )
        .await
        .expect_err("the save fails");
    assert!(matches!(refusal, DoorRefusal::NotRecorded));
    assert_eq!(memory_of(&service).await, before);

    // The next opening sees the domain the file describes: one target.
    let request = DoorRequest::TrustAuthorities { text: text() };
    assert_eq!(
        opened(service.door(console(), request, NOW).await).target_count,
        1
    );
}

#[tokio::test]
async fn an_install_whose_save_fails_leaves_memory_as_it_was() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let delegated = ready_to_install(&service).await;
    make_registry_unwritable(&service).await;
    let before = memory_of(&service).await;
    let refusal = service
        .door(
            console(),
            DoorRequest::IssuerInstall {
                authorization: Box::new(delegation(&delegated, 1)),
            },
            NOW,
        )
        .await
        .expect_err("the save fails");
    assert!(matches!(refusal, DoorRefusal::NotRecorded));
    assert_eq!(memory_of(&service).await, before);
    assert!(before.issuer.is_none());
}

#[tokio::test]
async fn a_publication_whose_save_fails_is_not_relayed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_gateway(dir.path()).await;
    rewrite_registry(&service, |state| {
        state.transitions.push(stored_gateway_transition(5))
    })
    .await;
    make_registry_unwritable(&service).await;
    let before = memory_of(&service).await;
    let request = DoorRequest::GatewayIdentityPublish { epoch: 5 };

    // Refused before the relay, which only ever follows a saved mark; and
    // memory still says unpublished, so a replay marks again rather than
    // relaying a mark the file does not hold.
    for at in [NOW, NOW + 1] {
        let refusal = service
            .door(console(), request.clone(), at)
            .await
            .expect_err("the save fails");
        assert!(matches!(refusal, DoorRefusal::NotPublished));
        assert_eq!(memory_of(&service).await, before);
    }
    assert!(!published_on_disk(dir.path()));
}

#[tokio::test]
async fn a_replayed_publication_is_saved_before_it_is_relayed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_gateway(dir.path()).await;
    rewrite_registry(&service, |state| {
        let mut stored = stored_gateway_transition(5);
        stored.published = true;
        state.transitions.push(stored)
    })
    .await;
    make_registry_unwritable(&service).await;

    // Already marked in memory: the replay still has to land the mark on
    // disk, and refuses rather than relaying when it cannot.
    let refusal = service
        .door(
            console(),
            DoorRequest::GatewayIdentityPublish { epoch: 5 },
            NOW,
        )
        .await
        .expect_err("the save fails");
    assert!(matches!(refusal, DoorRefusal::NotPublished));
}
