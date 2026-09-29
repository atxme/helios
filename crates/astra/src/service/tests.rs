use super::*;

#[test]
fn an_ipv6_budget_counts_prefixes_not_addresses() {
    let mut budget = SourceBudget::default();
    let first: IpAddr = "2001:db8::1".parse().unwrap();
    let second: IpAddr = "2001:db8::dead:beef".parse().unwrap();
    // Same /64: the two addresses share one budget.
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(first, 1_000));
    }
    assert!(
        !budget.charge(second, 1_000),
        "a second address in the same /64 must not reset the budget"
    );

    // A different /64 has its own.
    let elsewhere: IpAddr = "2001:db9::1".parse().unwrap();
    assert!(budget.charge(elsewhere, 1_000));
}

/// An unbounded map turns a rate limit into a memory-exhaustion
/// primitive: every fresh source would cost an entry, and an attacker has
/// as many as they like.
#[test]
fn the_source_map_is_bounded_and_refuses_rather_than_growing() {
    let mut budget = SourceBudget::default();
    let mut accepted = 0usize;
    for index in 0..(MAX_TRACKED_SOURCES + 64) {
        let source: IpAddr = format!("2001:db8:{:x}:{:x}::1", index / 65_536, index % 65_536)
            .parse()
            .unwrap();
        if budget.charge(source, 1_000) {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, MAX_TRACKED_SOURCES,
        "past the ceiling a new source is refused, not admitted for free"
    );

    // The next window frees the whole table again.
    let fresh: IpAddr = "203.0.113.9".parse().unwrap();
    assert!(budget.charge(fresh, 1_000 + BUDGET_WINDOW_SECS));
}

/// One admitted peer must not be able to spend the authority's signature
/// budget from a thousand addresses.
#[test]
fn an_admitted_peer_has_its_own_budget() {
    let mut budget = SourceBudget::default();
    let peer = WireGuardKey::from_bytes([4; 32]);
    for _ in 0..PEER_BUDGET {
        assert!(budget.charge_peer(&peer, 1_000));
    }
    assert!(!budget.charge_peer(&peer, 1_000));
    assert!(budget.charge_peer(&WireGuardKey::from_bytes([5; 32]), 1_000));
    assert!(budget.charge_peer(&peer, 1_000 + BUDGET_WINDOW_SECS));
}

#[test]
fn a_budget_refills_at_the_next_window() {
    let mut budget = SourceBudget::default();
    let source: IpAddr = "203.0.113.7".parse().unwrap();
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(source, 1_000));
    }
    assert!(!budget.charge(source, 1_000));
    assert!(budget.charge(source, 1_000 + BUDGET_WINDOW_SECS));
}

/// Two distinct IPv4 sources never share a budget.
#[test]
fn two_ipv4_sources_have_two_budgets() {
    let mut budget = SourceBudget::default();
    let first: IpAddr = "198.51.100.1".parse().unwrap();
    let second: IpAddr = "198.51.100.2".parse().unwrap();
    for _ in 0..SOURCE_BUDGET {
        assert!(budget.charge(first, 1_000));
    }
    assert!(!budget.charge(first, 1_000));
    assert!(budget.charge(second, 1_000));
}

/// The refusal classes are the only thing a caller learns, and none of
/// them describes a certificate.
#[test]
fn every_refusal_maps_to_one_bounded_status() {
    for (error, expected) in [
        (ServiceError::Protocol, StatusCode::BAD_REQUEST),
        (ServiceError::Refused, StatusCode::FORBIDDEN),
        (ServiceError::Throttled, StatusCode::TOO_MANY_REQUESTS),
        (
            ServiceError::OperatorCredentialUnavailable,
            StatusCode::NOT_IMPLEMENTED,
        ),
        (ServiceError::Internal, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        assert_eq!(error.into_response().status(), expected, "{error:?}");
    }
}

/// A capability token travels in one header, and nowhere else (§8.2).
///
/// A token in a path would be in every proxy log and every browser history
/// on the way. Accepting one from anywhere else is how it ends up there.
#[test]
fn a_bearer_is_read_from_the_authorization_header_alone() {
    let mut headers = HeaderMap::new();
    assert!(bearer(&headers).is_err(), "no header, no token");

    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer abc123".parse().expect("header"),
    );
    assert_eq!(bearer(&headers).expect("token"), "abc123");

    // Neither an empty credential nor another scheme is one.
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer ".parse().expect("header"),
    );
    assert!(bearer(&headers).is_err());
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Basic abc123".parse().expect("header"),
    );
    assert!(bearer(&headers).is_err());
}

/// The length ceiling is applied before parsing, so a caller cannot make
/// this process do work proportional to a string it chose.
#[test]
fn an_oversized_path_identifier_is_refused_before_it_is_parsed() {
    let long = "a".repeat(MAX_PATH_IDENTIFIER_BYTES + 1);
    assert!(matches!(path_id(&long), Err(ServiceError::Protocol)));

    // Inside the ceiling, a malformed identifier is a refusal and not a
    // protocol complaint: before a valid proof the endpoint says nothing
    // about what exists.
    assert!(matches!(path_id("not-hex"), Err(ServiceError::Refused)));
    assert!(path_id(&"ab".repeat(16)).is_ok());
}
