use super::test_support::*;
use super::*;

fn registry() -> (tempfile::TempDir, InvitationRegistry) {
    let directory = tempfile::tempdir().expect("tempdir");
    let registry = InvitationRegistry::at(directory.path().join("enrollment-invitations"));
    (directory, registry)
}

fn issued(
    registry: &InvitationRegistry,
    ca: &Ca,
    id: u8,
    readmission: bool,
) -> EnrollmentInvitation {
    let (invitation, proof) = invitation(ca, id, readmission);
    registry.issue(&invitation, proof).expect("issued");
    invitation
}

#[test]
fn an_issued_invitation_is_consumed_once() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let client = request(&invitation, "laptop-alice");

    let consumed = registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .expect("first consumption");
    assert_eq!(consumed.invitation, invitation);

    assert!(registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .is_err());
    match registry
        .load(&invitation.invitation_id)
        .expect("record")
        .state
    {
        InvitationState::Consumed {
            request_fingerprint,
            client_wg_public_key,
            ..
        } => {
            assert_eq!(request_fingerprint, client.request.fingerprint());
            assert_eq!(client_wg_public_key, client.request.client_wg_public_key);
        }
        other => panic!("unexpected state {other:?}"),
    }
}

#[test]
fn a_second_request_on_a_consumed_invitation_is_refused() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let first = request(&invitation, "laptop-alice");
    registry
        .consume(&invitation.invitation_id, &first.request, NOW)
        .expect("first");
    let second = request(&invitation, "laptop-bob");
    assert!(registry
        .consume(&invitation.invitation_id, &second.request, NOW)
        .is_err());
}

#[test]
fn consumption_destroys_the_ephemeral_key_on_disk() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (invitation, proof) = invitation(&ca, 1, false);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, *proof);
    registry.issue(&invitation, proof).expect("issued");
    let path = registry.path_of(&invitation.invitation_id);
    assert!(std::fs::read_to_string(&path)
        .expect("file")
        .contains(&encoded));

    let client = request(&invitation, "laptop-alice");
    registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .expect("consumed");
    assert!(!std::fs::read_to_string(&path)
        .expect("file")
        .contains(&encoded));
}

#[test]
fn a_bad_proof_leaves_the_invitation_issued() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    // Proved against another invitation's ephemeral key.
    let (other, _) = self::invitation(&ca, 2, false);
    let mut client = request(&other, "laptop-alice");
    client.request.invitation_id = invitation.invitation_id;
    assert!(registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .is_err());
    assert!(matches!(
        registry
            .load(&invitation.invitation_id)
            .expect("record")
            .state,
        InvitationState::Issued
    ));
}

#[test]
fn an_expired_invitation_is_purged_by_list_and_cannot_be_consumed() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let later = invitation.not_after_unix + 1;
    let listed = registry.list(later).expect("list");
    assert!(matches!(listed[0].state, InvitationState::Expired { .. }));
    let raw = std::fs::read_to_string(registry.path_of(&invitation.invitation_id)).expect("file");
    assert!(!raw.contains("proof_private_key"));

    let client = request(&invitation, "laptop-alice");
    assert!(registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .is_err());
}

#[test]
fn a_late_consumption_marks_the_invitation_expired() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let client = request(&invitation, "laptop-alice");
    assert!(registry
        .consume(
            &invitation.invitation_id,
            &client.request,
            invitation.not_after_unix + 1
        )
        .is_err());
    assert!(matches!(
        registry
            .load(&invitation.invitation_id)
            .expect("record")
            .state,
        InvitationState::Expired { .. }
    ));
}

#[test]
fn a_revoked_invitation_cannot_be_consumed() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    registry
        .revoke(&invitation.invitation_id, NOW)
        .expect("revoked");
    let client = request(&invitation, "laptop-alice");
    assert!(registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .is_err());
    assert!(matches!(
        registry
            .load(&invitation.invitation_id)
            .expect("record")
            .state,
        InvitationState::Revoked { .. }
    ));
}

#[test]
fn a_key_already_enrolled_needs_allow_readmission() {
    let (_dir, registry) = registry();
    let ca = ca();
    let first = issued(&registry, &ca, 1, false);
    let client = request(&first, "laptop-alice");
    registry
        .consume(&first.invitation_id, &client.request, NOW)
        .expect("first enrollment");
    assert!(registry
        .readmits(&client.request.client_wg_public_key)
        .expect("lookup"));

    let reused = || WgKeys {
        private: client.wg.private.clone(),
        public: client.wg.public,
    };
    let plain = issued(&registry, &ca, 2, false);
    let again = request_with(&plain, "laptop-alice", reused());
    assert!(registry
        .consume(&plain.invitation_id, &again.request, NOW)
        .is_err());
    assert!(matches!(
        registry.load(&plain.invitation_id).expect("record").state,
        InvitationState::Issued
    ));

    let readmission = issued(&registry, &ca, 3, true);
    let again = request_with(&readmission, "laptop-alice", reused());
    registry
        .consume(&readmission.invitation_id, &again.request, NOW)
        .expect("readmission allowed");
}

#[test]
fn an_invitation_id_is_issued_once() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (invitation, proof) = invitation(&ca, 1, false);
    registry.issue(&invitation, proof.clone()).expect("issued");
    assert!(registry.issue(&invitation, proof).is_err());
}

#[cfg(unix)]
#[test]
fn registry_files_are_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(registry.directory()), 0o700);
    assert_eq!(mode(&registry.path_of(&invitation.invitation_id)), 0o600);
}

/// `list` used to expire a lapsed invitation without the consumption lock. A
/// `consume` that read it `issued` just before, and wrote it `consumed` in
/// between, then had its state overwritten: the readmission policy forgot the
/// key and `sign_document` refused a document whose leaves were issued.
#[test]
fn list_never_rewrites_an_invitation_another_command_holds() {
    let (_dir, registry) = registry();
    let ca = ca();
    let invitation = issued(&registry, &ca, 1, false);
    let held = ConsumptionLock::take(&registry, &invitation.invitation_id).expect("lock");

    let listed = registry.list(invitation.not_after_unix + 1).expect("list");
    assert!(matches!(listed[0].state, InvitationState::Issued));
    let raw = std::fs::read_to_string(registry.path_of(&invitation.invitation_id)).expect("file");
    assert!(raw.contains("proof_private_key"), "left to its holder");

    drop(held);
    let listed = registry.list(invitation.not_after_unix + 1).expect("list");
    assert!(matches!(listed[0].state, InvitationState::Expired { .. }));
}

/// §15.2 destroys the proof key at expiry. No process watches the registry
/// between two commands, so every command that opens it purges what lapsed.
#[test]
fn every_registry_command_purges_lapsed_invitations() {
    let (_dir, registry) = registry();
    let ca = ca();
    let lapsed = issued(&registry, &ca, 1, false);
    let other = issued(&registry, &ca, 2, false);
    let later = lapsed.not_after_unix + 1;

    assert!(registry.revoke(&other.invitation_id, later).is_err());
    assert!(matches!(
        registry.load(&lapsed.invitation_id).expect("record").state,
        InvitationState::Expired { .. }
    ));
    let raw = std::fs::read_to_string(registry.path_of(&lapsed.invitation_id)).expect("file");
    assert!(!raw.contains("proof_private_key"));
}

fn leaves(
    seed: u8,
) -> (
    aether::certificates::encoding::DerCertificate,
    aether::key_negotiation::PqCertificate,
) {
    let tls = aether::certificates::encoding::DerCertificate::new(vec![seed; 64]).expect("der");
    let pq = aether::key_negotiation::PqCertificate {
        version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
        serial: [seed; aether::key_negotiation::KEY_NEGOTIATION_NONCE_LEN],
        subject: "laptop-alice".into(),
        issuer: "helios-ca-pq".into(),
        role: aether::key_negotiation::PqCertificateRole::Client,
        wireguard_public_key: STANDARD.encode([seed; 32]),
        ml_dsa_87_public_key: STANDARD.encode(
            vec![seed; aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN],
        ),
        not_before_unix: NOW,
        not_after_unix: NOW + 100,
        ml_dsa_87_signature: STANDARD
            .encode(vec![seed; aether::key_negotiation::ML_DSA_87_SIGNATURE_LEN]),
    };
    (tls, pq)
}

fn fingerprints_of(
    tls: &aether::certificates::encoding::DerCertificate,
    pq: &aether::key_negotiation::PqCertificate,
) -> IssuedLeafFingerprints {
    IssuedLeafFingerprints {
        tls_certificate: tls.fingerprint(),
        pq_certificate: aether::certificates::gateway::pq_certificate_fingerprint(pq)
            .expect("pq fingerprint"),
    }
}

/// A consumed invitation whose leaves are recorded; returns what to store.
fn accepted_invitation(
    registry: &InvitationRegistry,
    ca: &Ca,
    id: u8,
) -> (Id16, AcceptedEnrollment) {
    let invitation = issued(registry, ca, id, false);
    let client = request(&invitation, "laptop-alice");
    registry
        .consume(&invitation.invitation_id, &client.request, NOW)
        .expect("consumed");
    let (tls, pq) = leaves(id);
    registry
        .record_issued(&invitation.invitation_id, fingerprints_of(&tls, &pq))
        .expect("recorded");
    (
        invitation.invitation_id,
        AcceptedEnrollment {
            request: client.request,
            tls_certificate: tls,
            pq_certificate: pq,
        },
    )
}

#[test]
fn accepted_leaves_round_trip() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (id, accepted) = accepted_invitation(&registry, &ca, 1);
    registry.store_accepted(&id, &accepted).expect("stored");
    assert_eq!(registry.accepted(&id).expect("read"), Some(accepted));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = registry
            .directory()
            .join(format!("{}.accepted.json", id.to_hex()));
        let mode = std::fs::metadata(path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn accepted_leaves_must_match_the_recorded_fingerprints() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (id, accepted) = accepted_invitation(&registry, &ca, 1);
    let (other_tls, _) = leaves(9);
    let mismatched = AcceptedEnrollment {
        tls_certificate: other_tls,
        ..accepted.clone()
    };
    assert!(registry.store_accepted(&id, &mismatched).is_err());
    assert_eq!(registry.accepted(&id).expect("absent"), None);

    registry.store_accepted(&id, &accepted).expect("stored");
    let path = registry
        .directory()
        .join(format!("{}.accepted.json", id.to_hex()));
    let mut tampered = serde_json::to_value(&accepted).expect("json");
    tampered["tls_certificate"] = serde_json::to_value(leaves(9).0).expect("json");
    std::fs::write(&path, serde_json::to_vec(&tampered).expect("bytes")).expect("write");
    assert!(registry.accepted(&id).is_err());
}

#[test]
fn an_issued_invitation_cannot_store_leaves() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (id, accepted) = accepted_invitation(&registry, &ca, 1);
    let invitation = issued(&registry, &ca, 2, false);
    assert!(registry
        .store_accepted(&invitation.invitation_id, &accepted)
        .is_err());
    assert!(registry
        .accepted(&invitation.invitation_id)
        .expect("none")
        .is_none());

    // A stray file beside an invitation that is not consumed is never offered.
    let stray = registry.directory().join(format!(
        "{}.accepted.json",
        invitation.invitation_id.to_hex()
    ));
    std::fs::write(&stray, serde_json::to_vec(&accepted).expect("bytes")).expect("write");
    assert!(registry.accepted(&invitation.invitation_id).is_err());
    let _ = id;
}

#[test]
fn listing_ignores_accepted_files() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (id, accepted) = accepted_invitation(&registry, &ca, 1);
    registry.store_accepted(&id, &accepted).expect("stored");
    let listed = registry.list(NOW).expect("list");
    assert_eq!(listed.len(), 1);
}

#[test]
fn an_invitation_accepted_by_the_cli_lists_without_resume() {
    let (_dir, registry) = registry();
    let ca = ca();
    let (id, _) = accepted_invitation(&registry, &ca, 1);
    let listed = registry.list(NOW).expect("list");
    assert!(matches!(
        listed[0].state,
        InvitationState::Consumed {
            issued: Some(_),
            ..
        }
    ));
    assert_eq!(registry.accepted(&id).expect("none"), None);
}
