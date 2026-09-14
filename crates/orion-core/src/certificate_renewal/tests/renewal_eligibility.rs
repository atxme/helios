//! When a renewal may run at all: the guard that holds a committed candidate
//! until it activates, the continuity an expired active leaf can no longer
//! prove, and the overlap a service rollback reads.

use aether::certificates::encoding::Fingerprint;

use crate::certificate_renewal::exchange::assert_active_can_prove_continuity;
use crate::certificate_renewal::promotion::rollback_window;
use crate::certificate_renewal::{committed_and_waiting, horodatage, open_or_seed, RenewalError};
use crate::test_domain::*;

/// The contradiction this guard exists to remove.
///
/// A renewal committed at 18:26 was followed ten seconds later by two
/// fresh requests, refused by the authority — which was right: the peer
/// already held the generation it was asking for. The refusal then
/// overwrote the success on the operator's screen, so a rotation that had
/// worked read as one that had failed.
#[test]
fn a_committed_candidate_stops_a_second_renewal_until_it_activates() {
    fn generation(number: u64) -> aether::certificates::client::ClientCertificateGeneration {
        aether::certificates::client::ClientCertificateGeneration {
            generation: number,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            not_before: 0,
            not_after: 10_000,
        }
    }

    let mut certificates = aether::certificates::state::ClientCertificateState::new(generation(1));
    // Nothing committed: a renewal is the operator's to ask for.
    assert_eq!(committed_and_waiting(&certificates, 1_000), None);

    certificates.next = Some(generation(2));
    certificates.activation_at = Some(2_000);
    assert_eq!(
        committed_and_waiting(&certificates, 1_000),
        Some((2, 2_000))
    );

    // Once the instant passes, `promote_due` takes it and asking again is
    // legitimate. The guard must not outlive the wait it describes.
    assert_eq!(committed_and_waiting(&certificates, 2_000), None);

    certificates.active.not_after = 900;
    let (generation, activation_at) =
        committed_and_waiting(&certificates, 1_000).expect("recovery still waits");
    let refusal = RenewalError::ActivationPending {
        generation,
        activation_at: horodatage(activation_at),
    };
    assert!(refusal.to_string().contains("réessayer la connexion"));
}

/// An expired leaf cannot sign the continuity proof a rotation needs, so
/// the refusal names the recovery rather than letting the authority refuse
/// without saying which side is wrong.
#[test]
fn an_expired_active_leaf_cannot_prove_continuity() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    let expired_at = NOW + 20 * 86_400;
    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    assert!(matches!(
        assert_active_can_prove_continuity(store.state(), expired_at),
        Err(RenewalError::ActiveExpired { .. })
    ));
    assert!(
        assert_active_can_prove_continuity(store.state(), NOW).is_ok(),
        "a leaf still inside its validity proves continuity"
    );
}

#[test]
fn service_rollback_reads_the_overlap_without_lowering_any_counter() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut state = store(directory.path(), &domain).state().clone();
    let mut incoming = state.certificates.active.clone();
    incoming.generation += 1;
    incoming.tls_certificate_fingerprint = Fingerprint::of(b"incoming TLS");
    incoming.pq_certificate_fingerprint = Fingerprint::of(b"incoming PQ");
    state.certificates.next = Some(incoming.clone());
    state.certificates.activation_at = Some(NOW + 100);
    state.certificates.retire_active_at = Some(NOW + 200);
    state.certificates.revocation_epoch = 7;
    let before = state.clone();

    let (outgoing, selected_incoming, retire_at) =
        rollback_window(&state, NOW + 150).expect("inside overlap");
    assert_eq!(outgoing.generation, 4);
    assert_eq!(selected_incoming, incoming);
    assert_eq!(retire_at, NOW + 200);
    assert_eq!(
        state, before,
        "service selection must not mutate trust state"
    );
    assert_eq!(state.certificates.revocation_epoch, 7);
    assert!(rollback_window(&state, NOW + 99).is_err());
    assert!(rollback_window(&state, NOW + 200).is_err());
}
