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
