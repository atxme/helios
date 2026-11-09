//! The local identity promotion and rollback windows are bounded by the
//! signed grant, even when a client comes back late or has been revoked.

use crate::certificate_renewal::{
    prepare_identity_for_connection, promote_local_identity_if_due, promotion::rollback_window,
    RenewalError,
};
use crate::certificates::TrustState;
use crate::identity_store::ProtectedIdentityStore;
use crate::test_domain::{domain, settings, store, NOW};

fn state_with_overlap() -> TrustState {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut state = store(directory.path(), &domain).state().clone();
    let mut incoming = state.certificates.active.clone();
    incoming.generation += 1;
    state.certificates.next = Some(incoming);
    state.certificates.activation_at = Some(NOW + 3_600);
    state.certificates.retire_active_at = Some(NOW + 7_200);
    state
}

#[test]
fn rollback_requires_a_complete_next_generation_and_window() {
    let mut state = state_with_overlap();
    state.certificates.next = None;
    assert!(matches!(
        rollback_window(&state, NOW + 4_000),
        Err(RenewalError::RollbackUnavailable)
    ));

    let mut state = state_with_overlap();
    state.certificates.activation_at = None;
    assert!(matches!(
        rollback_window(&state, NOW + 4_000),
        Err(RenewalError::RollbackUnavailable)
    ));

    let mut state = state_with_overlap();
    state.certificates.retire_active_at = None;
    assert!(matches!(
        rollback_window(&state, NOW + 4_000),
        Err(RenewalError::RollbackUnavailable)
    ));
}

#[test]
fn rollback_is_available_at_activation_but_ends_at_retirement() {
    let state = state_with_overlap();
    let outgoing_generation = state.certificates.active.generation;
    let incoming_generation = state
        .certificates
        .next
        .as_ref()
        .expect("incoming generation")
        .generation;
    let activation_at = state.certificates.activation_at.expect("activation");
    let retire_at = state.certificates.retire_active_at.expect("retirement");

    let (outgoing, incoming, available_until) =
        rollback_window(&state, activation_at).expect("activation starts overlap");
    assert_eq!(outgoing.generation, outgoing_generation);
    assert_eq!(incoming.generation, incoming_generation);
    assert_eq!(available_until, retire_at);
    assert!(rollback_window(&state, retire_at - 1).is_ok());
    assert!(matches!(
        rollback_window(&state, activation_at - 1),
        Err(RenewalError::RollbackUnavailable)
    ));
    assert!(matches!(
        rollback_window(&state, retire_at),
        Err(RenewalError::RollbackUnavailable)
    ));

    let mut revoked = state;
    revoked.certificates.revoked = true;
    assert!(matches!(
        rollback_window(&revoked, activation_at),
        Err(RenewalError::RollbackUnavailable)
    ));
}

#[test]
fn pre_wireguard_connection_promotion_is_a_noop_without_trust_material() {
    let directory = tempfile::tempdir().expect("identity dir");
    let identities = ProtectedIdentityStore::at(directory.path().to_path_buf());
    let domain = domain();
    let mut profile = settings(&domain);
    profile.trust = None;

    assert!(!promote_local_identity_if_due(&profile, &identities, NOW)
        .expect("unmanaged profile needs no protected identity"));
    assert!(!prepare_identity_for_connection(&profile, &identities, NOW)
        .expect("unmanaged profile proceeds without promotion"));
}

#[test]
fn trusted_connection_promotion_refuses_an_empty_identity_name_before_io() {
    let directory = tempfile::tempdir().expect("identity dir");
    let identities = ProtectedIdentityStore::at(directory.path().to_path_buf());
    let domain = domain();
    let mut profile = settings(&domain);
    profile.identity = "  ".into();

    assert!(matches!(
        promote_local_identity_if_due(&profile, &identities, NOW),
        Err(RenewalError::Identity(message)) if message == "ce profil ne nomme aucune identité protégée"
    ));
    assert!(matches!(
        prepare_identity_for_connection(&profile, &identities, NOW),
        Err(RenewalError::Identity(message)) if message == "ce profil ne nomme aucune identité protégée"
    ));
}
