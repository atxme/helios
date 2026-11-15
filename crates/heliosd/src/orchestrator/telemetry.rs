//! The telemetry loop.

use super::*;

pub(super) fn spawn_telemetry_loop(iface: String, event_tx: broadcast::Sender<HeliosEvent>) {
    tokio::spawn(async move {
        let mut prev: Option<(u64, u64, u64, u64)> = None;
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await else {
                continue;
            };
            let Some(cur) = parse_proc_net_dev(&content, &iface) else {
                continue;
            };
            if let Some(event) = telemetry_event(&iface, prev, cur) {
                let _ = event_tx.send(event);
            }
            prev = Some(cur);
        }
    });
}

fn telemetry_event(
    iface: &str,
    previous: Option<(u64, u64, u64, u64)>,
    current: (u64, u64, u64, u64),
) -> Option<HeliosEvent> {
    let previous = previous?;
    Some(HeliosEvent::Telemetry {
        iface: iface.to_owned(),
        rx_bps: current.0.saturating_sub(previous.0) * 8,
        tx_bps: current.1.saturating_sub(previous.1) * 8,
        rx_pps: current.2.saturating_sub(previous.2),
        tx_pps: current.3.saturating_sub(previous.3),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_does_not_report_a_rate() {
        assert!(telemetry_event("eth0", None, (100, 200, 3, 4)).is_none());
    }

    #[test]
    fn telemetry_reports_byte_deltas_as_bits_per_second_and_packet_deltas() {
        assert!(matches!(
            telemetry_event("eth0", Some((100, 200, 3, 4)), (110, 220, 8, 10)),
            Some(HeliosEvent::Telemetry {
                iface,
                rx_bps: 80,
                tx_bps: 160,
                rx_pps: 5,
                tx_pps: 6,
            }) if iface == "eth0"
        ));
    }

    #[test]
    fn counter_resets_saturate_instead_of_wrapping_rates() {
        assert!(matches!(
            telemetry_event("eth0", Some((100, 200, 3, 4)), (50, 100, 1, 2)),
            Some(HeliosEvent::Telemetry {
                rx_bps: 0,
                tx_bps: 0,
                rx_pps: 0,
                tx_pps: 0,
                ..
            })
        ));
    }
}
