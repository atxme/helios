use super::*;
use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87Signature, WireGuardKey};
use aether::key_negotiation::{
    EnrollmentInvitation, ProtectionMode, ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use astra_operator::enrollment::{InvitationRecord, InvitationState};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "orion-invitation-registry-tests-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create scratch directory: {error}"),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn issue(registry: &astra_operator::enrollment::InvitationRegistry, seed: u8, expiry: u64) -> Id16 {
    let invitation = record(seed, InvitationState::Issued, expiry).invitation;
    let id = invitation.invitation_id;
    registry
        .issue(&invitation, Zeroizing::new([seed; 32]))
        .expect("record the issued invitation");
    id
}

/// A fresh WireGuard public key; the seed only keeps call sites apart.
fn key(_seed: u8) -> WireGuardKey {
    let pair = aether::wg::generate_keypair().expect("keys");
    WireGuardKey::parse(&pair.public_key).expect("key")
}

fn record(seed: u8, state: InvitationState, not_after: u64) -> InvitationRecord {
    InvitationRecord {
        invitation: EnrollmentInvitation {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: Id16::new([seed; 16]).expect("id"),
            gateway_wg_public_key: key(1),
            gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
            server_name: "gateway.example".into(),
            operator_ca_public_key: aether::certificates::encoding::generate_ml_dsa_87_keypair()
                .expect("ca key")
                .1,
            wireguard_proof_public_key: key(2),
            not_before_unix: NOW - 100,
            not_after_unix: not_after,
            minimum_mode: ProtectionMode::MlKem,
            allow_readmission: false,
            operator_signature: MlDsa87Signature::placeholder(),
        },
        state,
    }
}

fn consumed(device: &WireGuardKey) -> InvitationState {
    InvitationState::Consumed {
        request_id: Id16::new([9; 16]).expect("id"),
        request_fingerprint: Fingerprint::from_bytes([5; 32]),
        client_wg_public_key: *device,
        consumed_at_unix: NOW - 50,
        issued: None,
    }
}

/// The four states read as the mockup words them, and only an issued
/// invitation can be revoked.
#[test]
fn each_state_has_its_french_label() {
    let device = key(7);
    let views = view_all(
        vec![
            record(1, InvitationState::Issued, NOW + 3600),
            record(2, consumed(&device), NOW + 3600),
            record(3, InvitationState::Revoked { at_unix: NOW }, NOW + 3600),
            record(4, InvitationState::Expired { at_unix: NOW }, NOW - 1),
        ],
        &|_| Ok(None),
        None,
    );
    let labels: Vec<&str> = views.iter().map(|view| view.state.as_str()).collect();
    assert_eq!(labels, ["émise", "consommée", "révoquée", "expirée"]);
    assert!(views.iter().all(|view| !view.resumable));
    assert!(views.iter().all(|view| view.peer_admitted.is_none()));
}

/// `peer_admitted` is read from the gateway when one answers, and `None`
/// otherwise; `resumable` is the presence of the kept acceptance.
#[test]
fn a_kept_acceptance_is_resumable_and_the_gateway_tells_if_the_peer_is_admitted() {
    let device = key(7);
    let kept = |_: &InvitationRecord| Ok(Some("laptop".to_string()));
    let admitted = vec![device.to_base64()];

    let with_gateway = view_all(
        vec![record(2, consumed(&device), NOW + 3600)],
        &kept,
        Some(&admitted),
    );
    assert_eq!(with_gateway[0].peer_admitted, Some(true));
    assert!(with_gateway[0].resumable);
    assert_eq!(with_gateway[0].requested_name.as_deref(), Some("laptop"));

    let other = vec![key(8).to_base64()];
    let not_admitted = view_all(
        vec![record(2, consumed(&device), NOW + 3600)],
        &kept,
        Some(&other),
    );
    assert_eq!(not_admitted[0].peer_admitted, Some(false));

    let no_gateway = view_all(vec![record(2, consumed(&device), NOW + 3600)], &kept, None);
    assert_eq!(no_gateway[0].peer_admitted, None);
    assert!(no_gateway[0].resumable);
}

/// A CLI acceptance (consumed, nothing kept) and an unreadable kept file are
/// never offered for resumption.
#[test]
fn a_cli_acceptance_or_an_unreadable_one_is_not_resumable() {
    let device = key(7);
    let cli = view_all(
        vec![record(2, consumed(&device), NOW + 3600)],
        &|_| Ok(None),
        None,
    );
    assert!(!cli[0].resumable);
    let broken = view_all(
        vec![record(2, consumed(&device), NOW + 3600)],
        &|_| Err("illisible".to_string()),
        None,
    );
    assert!(!broken[0].resumable);
}

#[test]
fn a_consumed_peer_is_matched_after_trimming_gateway_key_values() {
    let device = key(7);
    let admitted = vec![format!("  {}\n", device.to_base64())];
    let views = view_all(
        vec![record(2, consumed(&device), NOW + 3600)],
        &|_| Ok(None),
        Some(&admitted),
    );

    assert_eq!(views[0].peer_admitted, Some(true));
    assert_eq!(views[0].requested_name, None);
    assert!(!views[0].resumable);
}

#[test]
fn listing_marks_only_lapsed_issued_records_expired_and_keeps_live_records_issued() {
    let scratch = Scratch::new();
    let registry = astra_operator::enrollment::InvitationRegistry::at(scratch.0.clone());
    let live = issue(&registry, 11, NOW + 3600);
    let expired = issue(&registry, 12, NOW - 1);

    let views = list(&registry, NOW, None).expect("list and expire lapsed invitations");

    assert_eq!(views.len(), 2);
    let by_id: std::collections::HashMap<_, _> = views
        .iter()
        .map(|view| (view.invitation_id.as_str(), view.state.as_str()))
        .collect();
    assert_eq!(by_id.get(live.to_hex().as_str()), Some(&"émise"));
    assert_eq!(by_id.get(expired.to_hex().as_str()), Some(&"expirée"));
    assert!(views.iter().all(|view| !view.resumable));
    assert_eq!(
        registry.load(&live).expect("live record").state,
        InvitationState::Issued
    );
    assert!(matches!(
        registry.load(&expired).expect("expired record").state,
        InvitationState::Expired { at_unix: NOW }
    ));
}

#[test]
fn listing_reports_a_corrupt_registry_record_instead_of_skipping_it() {
    let scratch = Scratch::new();
    let registry = astra_operator::enrollment::InvitationRegistry::at(scratch.0.clone());
    let id = Id16::new([21; 16]).expect("id");
    std::fs::write(
        registry.directory().join(format!("{}.json", id.to_hex())),
        b"broken",
    )
    .expect("write corrupt record");

    let error = list(&registry, NOW, None).expect_err("a corrupt record is not omitted");

    assert!(error.contains("lisible") || error.contains("JSON"));
}

#[test]
fn revoke_changes_an_issued_record_and_a_second_revoke_is_refused() {
    let scratch = Scratch::new();
    let registry = astra_operator::enrollment::InvitationRegistry::at(scratch.0.clone());
    let id = issue(&registry, 22, NOW + 3600);

    revoke(&registry, &id, NOW).expect("revoke issued invitation");

    assert!(matches!(
        registry.load(&id).expect("revoked record").state,
        InvitationState::Revoked { at_unix: NOW }
    ));
    let error =
        revoke(&registry, &id, NOW + 1).expect_err("revoked record cannot be revoked twice");
    assert!(error.contains("révoquée"));
}

#[test]
fn revoking_an_expired_invitation_expires_it_then_refuses_the_revoke() {
    let scratch = Scratch::new();
    let registry = astra_operator::enrollment::InvitationRegistry::at(scratch.0.clone());
    let id = issue(&registry, 23, NOW - 1);

    let error = revoke(&registry, &id, NOW).expect_err("expired invitation is not revocable");

    assert!(error.contains("expirée"));
    assert!(matches!(
        registry.load(&id).expect("purged record").state,
        InvitationState::Expired { at_unix: NOW }
    ));
}
