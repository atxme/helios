//! Runs Orion's raw speedtest from a shell and prints its result as JSON.
//!
//! Development tooling for `scripts/netns-bench.sh --throughput`, which sets
//! this measurement against `iperf3` through a kernel WireGuard tunnel. Not a
//! shipped tool: on a workstation, Orion is the only client binary.
//!
//! ```sh
//! raw_speedtest [tcp|udp|full] [seconds]
//! ```

use orion_core::speedtest::{run_with_progress, SpeedTestMode};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = SpeedTestMode::parse(args.next().as_deref().unwrap_or("tcp"))?;
    let duration_secs = match args.next() {
        Some(value) => value.parse()?,
        None => aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_with_progress(
        mode,
        duration_secs,
        None,
        Arc::new(|_| {}),
    ))?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
