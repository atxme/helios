use super::*;

const USER: &str = "S-1-5-21-1-2-3-1001";
const OTHER: &str = "S-1-5-21-1-2-3-1002";

#[test]
fn an_elevated_token_is_never_impersonated() {
    assert!(!may_impersonate(USER, USER, true));
}

#[test]
fn another_accounts_token_is_never_impersonated() {
    assert!(!may_impersonate(OTHER, USER, false));
}

#[test]
fn the_users_limited_token_is_impersonated() {
    assert!(may_impersonate(USER, USER, false));
}
