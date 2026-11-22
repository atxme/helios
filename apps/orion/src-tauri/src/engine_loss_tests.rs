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

#[test]
fn two_concurrent_watchers_only_report_the_engine_loss_once() {
    let already_reported = AtomicBool::new(false);
    let go = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        let report = || {
            go.wait();
            should_report_engine_loss(false, &already_reported)
        };
        let ipc = threads.spawn(report);
        let process = threads.spawn(report);
        assert_ne!(ipc.join().unwrap(), process.join().unwrap());
    });
}
