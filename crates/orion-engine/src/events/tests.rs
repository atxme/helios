use super::*;

use aether::TunnelState;

/// Fills the queue with log lines, which are not critical.
fn fill(sink: &EventSink) {
    for _ in 0..EVENT_QUEUE {
        sink(ClientEvent::log("info", "line"));
    }
}

/// Counts what the receiver holds, without waiting.
fn drained(receiver: &mut mpsc::Receiver<ClientEvent>) -> usize {
    let mut count = 0;
    while receiver.try_recv().is_ok() {
        count += 1;
    }
    count
}

#[test]
fn telemetry_and_logs_are_dropped_when_full() {
    let (queue, mut receiver) = EventQueue::new();
    let sink = queue.sink();
    fill(&sink);

    sink(ClientEvent::Telemetry {
        iface: "wg0".into(),
        rx_bps: 1,
        tx_bps: 2,
        rx_pps: 3,
        tx_pps: 4,
    });
    sink(ClientEvent::log("info", "one line too many"));

    assert!(!queue.overflowed());
    assert_eq!(drained(&mut receiver), EVENT_QUEUE);
}

#[test]
fn a_critical_event_that_finds_no_room_raises_the_flag() {
    let (queue, mut receiver) = EventQueue::new();
    let sink = queue.sink();
    fill(&sink);

    sink(ClientEvent::state(TunnelState::Up));

    assert!(queue.overflowed());
    // The critical event was not placed: the queue still holds only the logs.
    assert_eq!(drained(&mut receiver), EVENT_QUEUE);
}
