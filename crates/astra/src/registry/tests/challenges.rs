use super::*;

/// A challenge is spent once, and only inside its window.
#[test]
fn a_challenge_is_single_use_and_short_lived() {
    let mut store = ChallengeStore::with_capacity(4);
    assert!(store.issue([7; 32], 1_000));
    assert!(store.consume(&[7; 32], 1_030));
    assert!(!store.consume(&[7; 32], 1_030), "already spent");

    assert!(store.issue([8; 32], 1_000));
    assert!(
        !store.consume(&[8; 32], 1_000 + CHALLENGE_LIFETIME_SECS),
        "expired"
    );
}

/// Refusing beats evicting: a flood must not invalidate the challenges of
/// clients that are mid-request.
#[test]
fn a_full_challenge_store_refuses_rather_than_evicting() {
    let mut store = ChallengeStore::with_capacity(2);
    assert!(store.issue([1; 32], 1_000));
    assert!(store.issue([2; 32], 1_000));
    assert!(!store.issue([3; 32], 1_000));
    assert!(store.consume(&[1; 32], 1_010), "the earlier one survived");
}
