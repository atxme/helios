use std::time::{Duration, Instant};

use crate::{
    endpoint::{CHALLENGE_TIMEOUT, RESPONSE_TIMEOUT, TRANSACTION_IDLE_TIMEOUT},
    rate_limit::{rate_bucket, RateLimiter},
    transaction::Deadline,
    MAX_CONNECTION_LIFETIME, MAX_HANDSHAKES_PER_SOURCE, SOURCE_RATE_WINDOW,
};

/// Address validation proves an address is real, not that it is
/// friendly. This bound is what keeps a validated attacker's CPU cost
/// linear in the number of addresses it actually holds.
#[test]
fn a_single_source_cannot_buy_unlimited_handshakes() {
    let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
    let attacker: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let bystander: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    let start = Instant::now();

    for attempt in 1..=MAX_HANDSHAKES_PER_SOURCE {
        assert!(
            limiter.admit(attacker, start),
            "attempt {attempt} is within the budget"
        );
    }
    assert!(
        !limiter.admit(attacker, start),
        "the budget must run out for this address"
    );
    // One noisy address must not deny the service to everyone else.
    assert!(limiter.admit(bystander, start));

    // The window slides: the budget comes back rather than banning.
    let later = start + SOURCE_RATE_WINDOW + Duration::from_secs(1);
    assert!(limiter.admit(attacker, later));
    assert!(
        limiter.seen.len() <= 2,
        "expired entries must be pruned rather than accumulate"
    );
}

/// Counting IPv6 per exact address is the same as not counting it.
///
/// A subscriber is routinely handed a `/64`, which is 2^64 addresses: an
/// attacker with one of those can spend a fresh source for every single
/// handshake and never meet the budget. Bucketing by prefix is what makes
/// the IPv6 limit mean anything at all.
#[test]
fn an_ipv6_attacker_cannot_walk_out_of_its_own_budget() {
    let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
    let start = Instant::now();

    // Every attempt from a different address inside one /64.
    for attempt in 0..=MAX_HANDSHAKES_PER_SOURCE {
        let source: std::net::IpAddr = format!("2001:db8:1:1::{:x}", attempt + 1).parse().unwrap();
        let admitted = limiter.admit(rate_bucket(source), start);
        if attempt == MAX_HANDSHAKES_PER_SOURCE {
            assert!(!admitted, "the whole /64 shares one budget");
        } else {
            assert!(admitted, "attempt {attempt} is within the budget");
        }
    }

    // A neighbouring /64 is a different subscriber and keeps its own.
    let neighbour: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
    assert!(limiter.admit(rate_bucket(neighbour), start));
}

/// A dual-stack `[::]` socket hands IPv4 clients over as `::ffff:a.b.c.d`.
///
/// Read as IPv6, all of them sit in `::/64`: one IPv4 attacker would then
/// spend the budget of every other IPv4 client at once.
#[test]
fn an_ipv4_mapped_source_is_counted_as_its_ipv4_address() {
    let mapped: std::net::IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    let plain: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    assert_eq!(rate_bucket(mapped), rate_bucket(plain));

    let other: std::net::IpAddr = "::ffff:198.51.100.1".parse().unwrap();
    assert_ne!(
        rate_bucket(mapped),
        rate_bucket(other),
        "two IPv4 clients must never share a budget through their mapped form"
    );

    // Canonicalization leaves native IPv6 on its /64.
    let native: std::net::IpAddr = "2001:db8:1:1::7".parse().unwrap();
    let expected: std::net::IpAddr = "2001:db8:1:1::".parse().unwrap();
    assert_eq!(rate_bucket(native), expected);
}

#[test]
fn a_mapped_attacker_does_not_exhaust_other_ipv4_clients() {
    let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
    let attacker: std::net::IpAddr = "::ffff:203.0.113.9".parse().unwrap();
    let bystander: std::net::IpAddr = "::ffff:203.0.113.10".parse().unwrap();
    let start = Instant::now();

    for _ in 0..MAX_HANDSHAKES_PER_SOURCE {
        assert!(limiter.admit(rate_bucket(attacker), start));
    }
    assert!(!limiter.admit(rate_bucket(attacker), start));
    assert!(
        limiter.admit(rate_bucket(bystander), start),
        "a second IPv4 client keeps its own budget on a dual-stack socket"
    );
}

/// The concurrency permit is held for the whole connection, so a
/// connection that never ends is a permit that never returns.
#[test]
fn the_absolute_lifetime_covers_every_phase_it_must_contain() {
    // A challenge round trip, then a preparation, then the longest
    // confirmation wait a client may be told to observe.
    let phases = CHALLENGE_TIMEOUT
        + RESPONSE_TIMEOUT
        + Duration::from_secs(aether::key_negotiation::MAX_CONFIRMATION_TIMEOUT_SECS as u64);
    assert!(
        MAX_CONNECTION_LIFETIME >= phases,
        "an honest negotiation must never be cut short by the ceiling meant for hostile ones"
    );
    assert!(
        MAX_CONNECTION_LIFETIME > TRANSACTION_IDLE_TIMEOUT,
        "the ceiling exists because the idle timeout cannot bound a busy connection"
    );
}
#[test]
fn a_phase_is_clamped_to_what_is_left_of_the_connection() {
    let nearly_over = Deadline(Instant::now() + Duration::from_secs(2));
    assert!(
        nearly_over.clamp(Duration::from_secs(45)) <= Duration::from_secs(2),
        "the confirmation wait must not outlast the connection's ceiling"
    );

    let over = Deadline(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        over.clamp(Duration::from_secs(45)),
        Duration::ZERO,
        "past the ceiling every phase expires at once, rather than saturating backwards"
    );
}
