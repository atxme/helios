use super::held_chain_from;
use aether::certificates::{
    encoding::{Fingerprint, Id16},
    status::CampaignScope,
    transport::OperatorOpened,
};
use std::sync::Mutex;

fn public_chain_step() -> OperatorOpened {
    OperatorOpened {
        operation_id: Id16::new([0x31; 16]).expect("valid operation id"),
        campaign_id: Id16::new([0x32; 16]).expect("valid campaign id"),
        campaign_fingerprint: Fingerprint::of(b"public campaign"),
        scope: CampaignScope::IssuerDelegation,
        target_count: 2,
        required_credentials: 2,
        expires_at: 1_900_000_000,
        revocation_expiries: None,
        delegation_request: Some("public delegation request".into()),
        gateway_certificate: None,
    }
}

#[test]
fn held_chain_read_is_a_public_snapshot_and_does_not_change_held_state() {
    let held = Mutex::new(None);
    assert_eq!(held_chain_from(&held), None);
    *held.lock().expect("chain lock") = Some(public_chain_step());
    let snapshot = held_chain_from(&held).expect("held campaign");
    assert_eq!(snapshot, public_chain_step());

    // The WebView receives a value copy; it cannot mutate the chain's held step.
    let mut page_copy = snapshot;
    page_copy.target_count = 99;
    let original = held_chain_from(&held).expect("held campaign remains");
    assert_eq!(original, public_chain_step());
    assert_ne!(page_copy, original);

    let encoded = serde_json::to_value(held_chain_from(&held)).expect("public snapshot JSON");
    let serialized = encoded.to_string();
    assert!(serialized.contains("public delegation request"));
    assert!(!serialized.contains("token"));
    assert!(!serialized.contains("secret"));
}

#[cfg(not(windows))]
#[path = "chain_command_tests.rs"]
mod commands;
