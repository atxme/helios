use super::*;
use aether::certificates::authority::RotationReason;
use aether::certificates::client::ClientCertificateGeneration;

fn generation(not_before: u64, not_after: u64) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(b"tls"),
        pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        not_before,
        not_after,
    }
}

/// The three constraints of §7.2 and §4.1 hold together, and the leaf
/// strictly outlives the window it carries.
#[test]
fn a_planned_window_satisfies_every_bound_it_is_read_against() {
    let active = generation(0, 100 * 24 * 3_600);
    let now = 85 * 24 * 3_600;
    let plan = plan_window(
        &active,
        now + 24 * 3_600,
        DEFAULT_CLIENT_LEAF_LIFETIME_SECS,
        now,
    )
    .expect("plan");

    assert_eq!(plan.window.not_before, now);
    assert_eq!(plan.window.activation_at, now + STAGE_LEASE_SECS);
    assert_eq!(plan.stage_expires_at, plan.window.activation_at);
    assert!(plan.stage_expires_at <= now + MAX_STAGE_LEASE_SECS);
    assert!(plan.window.overlap_secs() <= MAX_OVERLAP_SECS);
    plan.window.validate().expect("window");
    assert!(
        plan.leaf_not_after > plan.window.not_after,
        "a leaf that expires inside its own overlap is refused by the gateway"
    );
    assert!(plan.leaf_not_before <= plan.window.activation_at);
}

/// A request that expires sooner than the default lease shortens the
/// lease, never the other way round.
#[test]
fn a_short_request_shortens_the_stage_lease() {
    let active = generation(0, 100 * 24 * 3_600);
    let now = 85 * 24 * 3_600;
    let plan =
        plan_window(&active, now + 300, DEFAULT_CLIENT_LEAF_LIFETIME_SECS, now).expect("plan");
    assert_eq!(plan.stage_expires_at, now + 300);
    assert_eq!(plan.window.activation_at, now + 300);
}

/// A delegation whose ceiling is shorter than the overlap the candidate
/// carries is refused here, not at the gateway.
#[test]
fn a_delegation_too_short_for_its_own_overlap_is_refused() {
    let active = generation(0, 100 * 24 * 3_600);
    let now = 85 * 24 * 3_600;
    assert!(
        plan_window(&active, now + 24 * 3_600, STAGE_LEASE_SECS, now).is_err(),
        "a ceiling under the window was accepted"
    );
}

/// An active leaf about to expire gets only the overlap it can honestly
/// provide; the window never extends its validity on paper.
#[test]
fn an_almost_expired_leaf_still_gets_an_overlap() {
    let active = generation(0, 1_000);
    let plan = plan_window(&active, 100_000, DEFAULT_CLIENT_LEAF_LIFETIME_SECS, 990).expect("plan");
    plan.window.validate().expect("window");
    assert_eq!(plan.window.activation_at, 999);
    assert_eq!(plan.window.not_after, active.not_after);
    assert_eq!(plan.window.overlap_secs(), 1);
}

/// Only `scheduled` reaches the delegated issuer from this path.
#[test]
fn the_relayed_path_only_ever_delegates_a_scheduled_renewal() {
    assert!(RotationReason::Scheduled.is_delegable());
    assert_eq!(RELAYED_ISSUER_KIND, IssuerKind::Astra);
}
