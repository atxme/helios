use std::sync::atomic::AtomicBool;

use super::should_report_engine_loss;

/// The loss is reported to the person once, however many watches see it.
#[test]
fn an_engine_loss_is_reported_once() {
    let already_reported = AtomicBool::new(false);
    assert!(should_report_engine_loss(false, &already_reported));
    assert!(!should_report_engine_loss(false, &already_reported));
}

/// Quitting ends the engine on purpose: its exit is not a failure to report,
/// and it does not use up the one report either.
#[test]
fn a_loss_while_quitting_is_not_reported() {
    let already_reported = AtomicBool::new(false);
    assert!(!should_report_engine_loss(true, &already_reported));
    assert!(should_report_engine_loss(false, &already_reported));
}
