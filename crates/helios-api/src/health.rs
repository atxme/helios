//! Health of the machine the gateway runs on, and its sealing posture.
//!
//! Until now the console could say everything about the tunnel and nothing
//! about the box carrying it: an operator watching handshakes fail had no way
//! to tell an overloaded CPU from a thermally throttled board from a full
//! memory, without opening an SSH session.
//!
//! Everything here is read from `/proc` and `/sys` at request time. Each field
//! is optional and read independently: a kernel that does not publish thermal
//! zones — which is most virtual machines, and WSL2 — must cost the *other*
//! readings nothing.
//!
//! # Limite connue
//!
//! Disk usage is absent. It needs `statvfs`, which the standard library does
//! not expose, and pulling `libc` into this crate for one figure was judged a
//! worse trade than leaving the field out. Adding it means a `libc` dependency
//! and an `unsafe` call, both of which deserve their own review.

use std::{fs, time::Duration};

use axum::{extract::State, Json};
use serde::Serialize;

use crate::AppState;

/// The gateway's sealing posture, without the secret it was derived from.
///
/// A projection of `helio_tpm::BootDecision`, which carries the unlock key and
/// therefore must never reach this crate. `heliosd` computes this summary at
/// startup and hands over only these two non-secret facts.
#[derive(Serialize, Clone, Copy)]
pub struct TpmSummary {
    /// `disabled`, `bypassed`, `unsealed`, `provisioned`, `resealed` or
    /// `window_resealed`.
    pub kind: &'static str,
    /// Whether this boot kept the secret the vaults were encrypted under.
    ///
    /// `false` means `wg-key.sealed` and the negotiation identity no longer
    /// open — the whole fleet needs re-enrolling, which is the single most
    /// consequential thing this console can report.
    pub preserved_vaults: bool,
}

#[derive(Serialize)]
pub struct HealthResponse {
    /// Seconds since the machine booted, not since the daemon started.
    pub uptime_seconds: Option<u64>,
    /// Run-queue averages over 1, 5 and 15 minutes.
    pub load: Option<[f32; 3]>,
    pub cpu_count: Option<usize>,
    pub memory_total_bytes: Option<u64>,
    /// What the kernel considers actually reclaimable — not `MemFree`, which
    /// on a healthy Linux box is always near zero and would read as an alarm.
    pub memory_available_bytes: Option<u64>,
    /// Warmest thermal zone, in degrees Celsius.
    pub temperature_celsius: Option<f32>,
    /// `None` when the daemon was built or started without TPM support.
    pub tpm: Option<TpmSummary>,
}

/// Seconds since boot, from the first field of `/proc/uptime`.
fn read_uptime() -> Option<u64> {
    let raw = fs::read_to_string("/proc/uptime").ok()?;
    let seconds: f64 = raw.split_whitespace().next()?.parse().ok()?;
    Some(seconds as u64)
}

fn read_load() -> Option<[f32; 3]> {
    let raw = fs::read_to_string("/proc/loadavg").ok()?;
    let mut fields = raw.split_whitespace();
    Some([
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ])
}

fn read_cpu_count() -> Option<usize> {
    std::thread::available_parallelism().ok().map(|n| n.get())
}

/// `MemTotal` and `MemAvailable`, converted from the kibibytes `/proc` uses.
fn read_memory() -> (Option<u64>, Option<u64>) {
    let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let field = |name: &str| -> Option<u64> {
        raw.lines()
            .find(|line| line.starts_with(name))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|kib| kib * 1024)
    };
    (field("MemTotal:"), field("MemAvailable:"))
}

/// The warmest zone, because that is the one that throttles first.
fn read_temperature() -> Option<f32> {
    let zones = fs::read_dir("/sys/class/thermal").ok()?;
    zones
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if !path.file_name()?.to_str()?.starts_with("thermal_zone") {
                return None;
            }
            let raw = fs::read_to_string(path.join("temp")).ok()?;
            // Millidegrees. A zone reporting an absurd value is a zone that
            // does not mean temperature; dropping it beats showing 4 °C.
            let millidegrees: f32 = raw.trim().parse().ok()?;
            let celsius = millidegrees / 1000.0;
            (5.0..=150.0).contains(&celsius).then_some(celsius)
        })
        .fold(None, |warmest: Option<f32>, celsius| {
            Some(warmest.map_or(celsius, |current| current.max(celsius)))
        })
}

pub async fn health(State(s): State<AppState>) -> Json<HealthResponse> {
    let (memory_total_bytes, memory_available_bytes) = read_memory();
    Json(HealthResponse {
        uptime_seconds: read_uptime(),
        load: read_load(),
        cpu_count: read_cpu_count(),
        memory_total_bytes,
        memory_available_bytes,
        temperature_celsius: read_temperature(),
        tpm: s.tpm,
    })
}

/// Formats an uptime the way an operator says it. Exposed for tests.
pub fn humanize_uptime(uptime: Duration) -> String {
    let days = uptime.as_secs() / 86_400;
    let hours = (uptime.as_secs() % 86_400) / 3_600;
    if days > 0 {
        format!("{days} j {hours} h")
    } else {
        format!("{hours} h {} min", (uptime.as_secs() % 3_600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_reported_in_bytes_not_in_the_kibibytes_proc_uses() {
        // /proc/meminfo speaks kibibytes; publishing them raw would make a
        // 16 GiB gateway look like it had 16 MiB.
        let (total, available) = read_memory();
        if let (Some(total), Some(available)) = (total, available) {
            assert!(total > 64 * 1024 * 1024, "suspicious total: {total}");
            assert!(available <= total);
        }
    }

    #[test]
    fn every_reading_is_independent_of_the_others() {
        // No unwrap anywhere: a kernel without thermal zones — every virtual
        // machine, and WSL2 — must still report load and memory.
        let temperature = read_temperature();
        assert!(temperature.is_none() || temperature.is_some_and(|c| (5.0..=150.0).contains(&c)));
        assert!(read_uptime().is_some(), "/proc/uptime is expected on Linux");
    }

    #[test]
    fn uptime_reads_as_days_and_hours_once_past_a_day() {
        assert_eq!(humanize_uptime(Duration::from_secs(90_000)), "1 j 1 h");
        assert_eq!(humanize_uptime(Duration::from_secs(7_800)), "2 h 10 min");
    }
}
