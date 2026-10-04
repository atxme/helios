//! Read-only inspection commands: what the gateway already serves, laid out
//! for the operator. None of them changes any state.

use aether::certificates::window::ValidityPhase;
use anyhow::{Context, Result};
use helios_update::UpdateStatus;
use reqwest::Client;
use serde::Deserialize;

use crate::{api, transport::Api};

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

// ─── Views ────────────────────────────────────────────────────────────────────
//
// Partial on purpose: unknown fields are ignored, so a newer gateway that adds
// one does not break an older terminal.

/// `GET /api/health`.
#[derive(Debug, Deserialize)]
pub struct HealthView {
    pub uptime_seconds: Option<u64>,
    pub load: Option<[f32; 3]>,
    pub cpu_count: Option<usize>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub temperature_celsius: Option<f32>,
    pub tpm: Option<TpmView>,
}

#[derive(Debug, Deserialize)]
pub struct TpmView {
    pub kind: String,
    pub preserved_vaults: bool,
}

/// `GET /api/firewall/rules`.
#[derive(Debug, Deserialize)]
pub struct FirewallView {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

/// `GET /api/trust`.
#[derive(Debug, Deserialize)]
pub struct TrustView {
    pub required_algs: Vec<String>,
    pub publisher_keys: Vec<PublisherKeyView>,
    pub development_keys: bool,
    pub reseal_domain: String,
    pub reseal_format_version: u32,
}

#[derive(Debug, Deserialize)]
pub struct PublisherKeyView {
    pub key_epoch: u32,
    pub fingerprint: String,
}

/// `GET /api/certificates`.
#[derive(Debug, Deserialize)]
pub struct DomainView {
    pub trust_domain_id: String,
    pub server_name: String,
    pub now_unix: u64,
    pub ca_epoch: u64,
    pub ca_pq_fingerprint: String,
    pub ca_transition_pending: bool,
    pub gateway_identity_epoch: u64,
    pub gateway_tls_fingerprint: String,
    pub gateway_pq_fingerprint: String,
    pub gateway_transition_pending: bool,
    pub astra_authority_url: String,
    pub issuer: Option<IssuerView>,
    pub peers: Vec<PeerCertView>,
}

#[derive(Debug, Deserialize)]
pub struct IssuerView {
    pub issuer_epoch: u64,
    pub not_after: u64,
    pub usable: bool,
}

#[derive(Debug, Deserialize)]
pub struct PeerCertView {
    pub name: String,
    pub generation: u64,
    pub not_after: u64,
    pub phase: ValidityPhase,
    pub revoked: bool,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

pub async fn health(client: &Client, base: &str) -> Result<()> {
    let view: HealthView = api::get(client, base, "/api/health").await?;
    print!("{}", render_health(&view));
    Ok(())
}

pub async fn firewall(client: &Client, base: &str) -> Result<()> {
    let view: FirewallView = api::get(client, base, "/api/firewall/rules").await?;
    print!("{}", render_firewall(&view));
    Ok(())
}

pub async fn certificates(client: &Client, base: &str) -> Result<()> {
    let view: DomainView = api::get_optional(client, base, "/api/certificates")
        .await?
        .context("this gateway has no trust domain — run `heliosd init-trust-domain`")?;
    print!("{}", render_certificates(&view));
    Ok(())
}

pub async fn trust(client: &Client, base: &str) -> Result<()> {
    let view: TrustView = api::get(client, base, "/api/trust").await?;
    print!("{}", render_trust(&view));
    Ok(())
}

pub async fn release(client: &Client, base: &str) -> Result<()> {
    let view: UpdateStatus = api::get(client, base, "/api/update").await?;
    print!("{}", render_release(&view));
    Ok(())
}

pub async fn negotiation(client: &Client, base: &str) -> Result<()> {
    let view = api::key_negotiation(client, base)
        .await?
        .context("this gateway serves no key-negotiation material")?;
    println!();
    println!("  {BOLD}Key negotiation{RESET}");
    println!();
    row(
        "Port",
        &view
            .port
            .map_or_else(|| "closed".to_owned(), |port| format!("UDP {port}")),
    );
    row("Server name", &clean(&view.server_name));
    row("WireGuard key", &clean(&view.wireguard_public_key));
    row("PQ cert SHA-256", &clean(&view.pq_certificate_sha256));
    println!();
    Ok(())
}

/// The daemon's journal, read locally: it never transits the API.
pub async fn logs(lines: usize, follow: bool) -> Result<()> {
    let status = tokio::process::Command::new("journalctl")
        .args(journal_args(lines, follow))
        // Ctrl-C abandons the command future; the reader must not outlive it.
        .kill_on_drop(true)
        .status()
        .await
        .context("running journalctl — is this the gateway?")?;
    // SIGINT ends `--follow`; that is the normal way out, not a failure.
    if !status.success() && !(follow && status.code().is_none()) {
        anyhow::bail!("journalctl exited with {status}");
    }
    Ok(())
}

fn journal_args(lines: usize, follow: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "--namespace=helios",
        "-u",
        "heliosd",
        "-n",
        &lines.to_string(),
        "--no-pager",
        "-o",
        "short-iso",
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect();
    if follow {
        args.push("--follow".to_owned());
    }
    args
}

pub async fn doctor(target: &Api) -> Result<()> {
    let (client, base) = (&target.client, target.base.as_str());
    let message = |error: anyhow::Error| format!("{error:#}");
    let inputs = DoctorInputs {
        transport: target.label(),
        status: crate::api_status(client, base)
            .await
            .map(|status| {
                let (online, total) = status.online_peers();
                StatusFacts {
                    state: status.state,
                    dry_run: status.dry_run,
                    online,
                    total,
                }
            })
            .map_err(message),
        health: api::get(client, base, "/api/health").await.map_err(message),
        firewall: api::get(client, base, "/api/firewall/rules")
            .await
            .map_err(message),
        domain: api::get_optional(client, base, "/api/certificates")
            .await
            .map_err(message),
        release: api::get(client, base, "/api/update").await.map_err(message),
    };
    let checks = diagnose(&inputs);
    print!("{}", render_doctor(&checks));
    let failed = checks
        .iter()
        .filter(|check| check.level == Level::Fail)
        .count();
    anyhow::ensure!(failed == 0, "{failed} check(s) failed");
    Ok(())
}

// ─── Doctor ───────────────────────────────────────────────────────────────────

pub struct StatusFacts {
    pub state: String,
    pub dry_run: bool,
    pub online: usize,
    pub total: usize,
}

/// Everything the doctor reads, fetched once; an error is kept as text so a
/// failed read becomes a failed check instead of aborting the others.
pub struct DoctorInputs {
    pub transport: String,
    pub status: Result<StatusFacts, String>,
    pub health: Result<HealthView, String>,
    pub firewall: Result<FirewallView, String>,
    pub domain: Result<Option<DomainView>, String>,
    pub release: Result<UpdateStatus, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug)]
pub struct Check {
    pub level: Level,
    pub label: &'static str,
    pub detail: String,
}

fn check(level: Level, label: &'static str, detail: impl Into<String>) -> Check {
    Check {
        level,
        label,
        detail: detail.into(),
    }
}

pub fn diagnose(inputs: &DoctorInputs) -> Vec<Check> {
    use Level::{Fail, Ok, Warn};
    let mut checks = Vec::new();
    match &inputs.status {
        Err(error) => checks.push(check(Fail, "API", error.clone())),
        Result::Ok(status) => {
            checks.push(check(
                Ok,
                "API",
                format!("reachable ({})", clean(&inputs.transport)),
            ));
            let peers = format!("{}/{} peers online", status.online, status.total);
            checks.push(match status.state.as_str() {
                "up" => check(Ok, "Tunnel", format!("up · {peers}")),
                "connecting" => check(Warn, "Tunnel", format!("waiting for clients · {peers}")),
                other => check(Fail, "Tunnel", format!("{} · {peers}", clean(other))),
            });
            checks.push(if status.dry_run {
                check(
                    Warn,
                    "Mode",
                    "simulation (dry-run): nothing reaches the kernel",
                )
            } else {
                check(Ok, "Mode", "real")
            });
        }
    }
    match &inputs.health {
        Err(error) => checks.push(check(Fail, "Health", error.clone())),
        Result::Ok(health) => {
            checks.push(match &health.tpm {
                None => check(Warn, "TPM", "boot integrity not validated"),
                Some(tpm) if !tpm.preserved_vaults => check(
                    Fail,
                    "TPM",
                    format!(
                        "{}: the sealed vaults were not preserved this boot",
                        clean(&tpm.kind)
                    ),
                ),
                Some(tpm) if matches!(tpm.kind.as_str(), "disabled" | "bypassed") => {
                    check(Warn, "TPM", clean(&tpm.kind))
                }
                Some(tpm) => check(Ok, "TPM", clean(&tpm.kind)),
            });
            if let (Some(total), Some(available)) =
                (health.memory_total_bytes, health.memory_available_bytes)
            {
                let percent = percent(available, total);
                let detail = format!("{} available ({percent} %)", bytes(available));
                checks.push(check(
                    if percent < 10 { Warn } else { Ok },
                    "Memory",
                    detail,
                ));
            }
            if let Some(celsius) = health.temperature_celsius {
                let level = if celsius >= 85.0 { Warn } else { Ok };
                checks.push(check(level, "Temperature", format!("{celsius:.1} °C")));
            }
        }
    }
    checks.push(match &inputs.firewall {
        Err(error) => check(Fail, "Firewall", error.clone()),
        Result::Ok(firewall) if firewall.default_verdict == "drop" => {
            check(Ok, "Firewall", "default drop")
        }
        Result::Ok(firewall) => check(
            Fail,
            "Firewall",
            format!(
                "default {} — expected drop",
                clean(&firewall.default_verdict)
            ),
        ),
    });
    checks.push(match &inputs.domain {
        Err(error) => check(Fail, "Certificates", error.clone()),
        Result::Ok(None) => check(Warn, "Certificates", "no trust domain on this gateway"),
        Result::Ok(Some(domain)) => {
            let attention = domain
                .peers
                .iter()
                .filter(|peer| {
                    !peer.revoked
                        && matches!(
                            peer.phase,
                            ValidityPhase::Warning
                                | ValidityPhase::Critical
                                | ValidityPhase::Expired
                        )
                })
                .count();
            if domain.issuer.as_ref().is_some_and(|issuer| !issuer.usable) {
                check(Fail, "Certificates", "the issuer is not usable")
            } else if attention > 0 {
                check(
                    Warn,
                    "Certificates",
                    format!("{attention} client certificate(s) near or past expiry"),
                )
            } else {
                check(
                    Ok,
                    "Certificates",
                    format!(
                        "{} client certificate(s) in good standing",
                        domain.peers.len()
                    ),
                )
            }
        }
    });
    checks.push(match &inputs.release {
        Err(error) => check(Fail, "Release", error.clone()),
        Result::Ok(release) => {
            let active = release.active_version.as_deref().unwrap_or("unknown");
            match release.activation_pending {
                Some(sequence) => check(
                    Warn,
                    "Release",
                    format!(
                        "{} · activation of sequence {sequence} pending",
                        clean(active)
                    ),
                ),
                None => check(Ok, "Release", format!("{} active", clean(active))),
            }
        }
    });
    checks
}

pub fn render_doctor(checks: &[Check]) -> String {
    let mut out = format!("\n  {BOLD}Doctor{RESET}\n\n");
    for check in checks {
        let mark = match check.level {
            Level::Ok => format!("{GREEN}✓{RESET}"),
            Level::Warn => format!("{YELLOW}!{RESET}"),
            Level::Fail => format!("{RED}✗{RESET}"),
        };
        out.push_str(&format!(
            "  {mark} {:<13} {}\n",
            check.label,
            clean(&check.detail)
        ));
    }
    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warned = checks.iter().filter(|c| c.level == Level::Warn).count();
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let summary = match (failed, warned) {
        (0, 0) => format!("{GREEN}all checks passed{RESET}"),
        (0, w) => format!("{YELLOW}{}{RESET}", plural(w, "warning")),
        (f, w) => format!("{RED}{f} failed, {}{RESET}", plural(w, "warning")),
    };
    out.push_str(&format!("\n  {summary}\n\n"));
    out
}

// ─── Rendering ────────────────────────────────────────────────────────────────

fn row(label: &str, value: &str) {
    println!("  {DIM}{label:<13}{RESET} {value}");
}

fn line(label: &str, value: &str) -> String {
    format!("  {DIM}{label:<13}{RESET} {value}\n")
}

pub fn render_health(view: &HealthView) -> String {
    let unknown = || "unknown".to_owned();
    let mut out = format!("\n  {BOLD}Health{RESET}\n\n");
    out.push_str(&line(
        "Uptime",
        &view.uptime_seconds.map_or_else(unknown, duration),
    ));
    out.push_str(&line(
        "Load",
        &view.load.map_or_else(unknown, |[one, five, fifteen]| {
            let cpus = view
                .cpu_count
                .map(|count| format!(" ({count} CPU)"))
                .unwrap_or_default();
            format!("{one:.2} {five:.2} {fifteen:.2}{cpus}")
        }),
    ));
    out.push_str(&line(
        "Memory",
        &match (view.memory_available_bytes, view.memory_total_bytes) {
            (Some(available), Some(total)) => format!(
                "{} available of {} ({} %)",
                bytes(available),
                bytes(total),
                percent(available, total)
            ),
            _ => unknown(),
        },
    ));
    out.push_str(&line(
        "Temperature",
        &view
            .temperature_celsius
            .map_or_else(unknown, |celsius| format!("{celsius:.1} °C")),
    ));
    out.push_str(&line(
        "TPM",
        &view.tpm.as_ref().map_or_else(
            || "not validated".to_owned(),
            |tpm| {
                format!(
                    "{} · {}",
                    clean(&tpm.kind),
                    if tpm.preserved_vaults {
                        "vaults preserved"
                    } else {
                        "vaults NOT preserved"
                    }
                )
            },
        ),
    ));
    out.push('\n');
    out
}

pub fn render_firewall(view: &FirewallView) -> String {
    let mode = if view.dry_run { " · dry-run" } else { "" };
    let mut out = format!(
        "\n  {BOLD}Firewall{RESET}  {DIM}default {}{mode}{RESET}\n\n",
        clean(&view.default_verdict)
    );
    for rule in view.rules.lines() {
        out.push_str(&format!("  {}\n", clean(rule)));
    }
    out.push('\n');
    out
}

pub fn render_certificates(view: &DomainView) -> String {
    let pending = |flag: bool| {
        if flag {
            format!(" · {YELLOW}transition pending{RESET}")
        } else {
            String::new()
        }
    };
    let mut out = format!("\n  {BOLD}Certificates{RESET}\n\n");
    out.push_str(&line(
        "Trust domain",
        &format!(
            "{} · {}",
            clean(&view.trust_domain_id),
            clean(&view.server_name)
        ),
    ));
    out.push_str(&line(
        "CA",
        &format!(
            "epoch {} · {}{}",
            view.ca_epoch,
            short(&view.ca_pq_fingerprint),
            pending(view.ca_transition_pending)
        ),
    ));
    out.push_str(&line(
        "Gateway",
        &format!(
            "identity epoch {} · TLS {} · PQ {}{}",
            view.gateway_identity_epoch,
            short(&view.gateway_tls_fingerprint),
            short(&view.gateway_pq_fingerprint),
            pending(view.gateway_transition_pending)
        ),
    ));
    if let Some(issuer) = &view.issuer {
        out.push_str(&line(
            "Issuer",
            &format!(
                "epoch {} · {} · expires {}",
                issuer.issuer_epoch,
                if issuer.usable {
                    "usable"
                } else {
                    "NOT usable"
                },
                relative(issuer.not_after, view.now_unix)
            ),
        ));
    }
    out.push_str(&line("Authority", &clean(&view.astra_authority_url)));
    out.push_str(&format!(
        "\n  {BOLD}Clients ({}){RESET}\n",
        view.peers.len()
    ));
    for peer in &view.peers {
        let (mark, state) = if peer.revoked {
            (format!("{RED}✗{RESET}"), "revoked".to_owned())
        } else {
            let (color, label) = match peer.phase {
                ValidityPhase::NotYetValid => (DIM, "not yet valid"),
                ValidityPhase::Valid => (GREEN, "valid"),
                ValidityPhase::RenewalDue => (YELLOW, "renewal due"),
                ValidityPhase::Warning => (YELLOW, "warning"),
                ValidityPhase::Critical => (RED, "critical"),
                ValidityPhase::Expired => (RED, "expired"),
            };
            (
                format!("{color}●{RESET}"),
                format!(
                    "{label} · expires {}",
                    relative(peer.not_after, view.now_unix)
                ),
            )
        };
        out.push_str(&format!(
            "    {mark} {:<20} {DIM}gen {}{RESET} · {state}\n",
            clean(&peer.name),
            peer.generation
        ));
    }
    out.push('\n');
    out
}

pub fn render_trust(view: &TrustView) -> String {
    let mut out = format!("\n  {BOLD}Update trust{RESET}\n\n");
    let algs: Vec<String> = view.required_algs.iter().map(|alg| clean(alg)).collect();
    out.push_str(&line("Required", &algs.join(" + ")));
    for key in &view.publisher_keys {
        out.push_str(&line(
            &format!("Epoch {}", key.key_epoch),
            &clean(&key.fingerprint),
        ));
    }
    if view.development_keys {
        out.push_str(&line(
            "Warning",
            &format!("{YELLOW}development publisher keys are trusted{RESET}"),
        ));
    }
    out.push_str(&line(
        "Reseal",
        &format!(
            "{} · format {}",
            clean(&view.reseal_domain),
            view.reseal_format_version
        ),
    ));
    out.push('\n');
    out
}

pub fn render_release(view: &UpdateStatus) -> String {
    let mut out = format!("\n  {BOLD}Release{RESET}\n\n");
    out.push_str(&line(
        "Active",
        &clean(view.active_version.as_deref().unwrap_or("unknown")),
    ));
    out.push_str(&line(
        "Channel",
        &format!("{} · {}", clean(&view.channel), clean(&view.target)),
    ));
    out.push_str(&line(
        "Confirmed",
        &format!("sequence {}", view.highest_confirmed_sequence),
    ));
    if view.staged.is_empty() {
        out.push_str(&line("Staged", "none"));
    }
    for staged in &view.staged {
        out.push_str(&line(
            "Staged",
            &format!(
                "{} · sequence {} · {}",
                clean(&staged.version),
                staged.release_sequence,
                short(&staged.sha256)
            ),
        ));
    }
    if let Some(sequence) = view.activation_pending {
        out.push_str(&line(
            "Pending",
            &format!("{YELLOW}activation of sequence {sequence}{RESET}"),
        ));
    }
    out.push('\n');
    out
}

// ─── Formatting ───────────────────────────────────────────────────────────────

/// Gateway-supplied text is data, never terminal control sequences.
fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

fn short(fingerprint: &str) -> String {
    let fingerprint = clean(fingerprint);
    match fingerprint.char_indices().nth(16) {
        Some((end, _)) => format!("{}…", &fingerprint[..end]),
        None => fingerprint,
    }
}

fn percent(part: u64, total: u64) -> u64 {
    part.saturating_mul(100).checked_div(total).unwrap_or(0)
}

fn bytes(value: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if value < 1024 {
        return format!("{value} B");
    }
    let mut amount = value as f64 / 1024.0;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    format!("{amount:.1} {}", UNITS[unit])
}

fn duration(seconds: u64) -> String {
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3_600,
        seconds % 3_600 / 60,
    );
    if days > 0 {
        format!("{days} d {hours:02} h")
    } else if hours > 0 {
        format!("{hours} h {minutes:02} min")
    } else if minutes > 0 {
        format!("{minutes} min {:02} s", seconds % 60)
    } else {
        format!("{seconds} s")
    }
}

/// On the gateway's clock (`now`), never the operator's.
fn relative(at: u64, now: u64) -> String {
    if at >= now {
        format!("in {}", duration(at - now))
    } else {
        format!("{} ago", duration(now - at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn health() -> HealthView {
        HealthView {
            uptime_seconds: Some(3 * 86_400 + 4 * 3_600 + 120),
            load: Some([0.12, 0.08, 0.05]),
            cpu_count: Some(4),
            memory_total_bytes: Some(8 * 1024 * 1024 * 1024),
            memory_available_bytes: Some(2 * 1024 * 1024 * 1024),
            temperature_celsius: Some(48.0),
            tpm: Some(TpmView {
                kind: "unsealed".into(),
                preserved_vaults: true,
            }),
        }
    }

    fn domain(peers: Vec<PeerCertView>) -> DomainView {
        DomainView {
            trust_domain_id: "helios-home".into(),
            server_name: "gw.helios".into(),
            now_unix: 1_000_000,
            ca_epoch: 2,
            ca_pq_fingerprint: "ab".repeat(32),
            ca_transition_pending: false,
            gateway_identity_epoch: 5,
            gateway_tls_fingerprint: "cd".repeat(32),
            gateway_pq_fingerprint: "ef".repeat(32),
            gateway_transition_pending: true,
            astra_authority_url: "https://astra.example".into(),
            issuer: Some(IssuerView {
                issuer_epoch: 1,
                not_after: 1_000_000 + 20 * 86_400,
                usable: true,
            }),
            peers,
        }
    }

    fn peer(name: &str, phase: ValidityPhase, days: i64, revoked: bool) -> PeerCertView {
        PeerCertView {
            name: name.into(),
            generation: 3,
            not_after: (1_000_000 + days * 86_400) as u64,
            phase,
            revoked,
        }
    }

    fn release() -> UpdateStatus {
        UpdateStatus {
            highest_confirmed_sequence: 1_790_960_566,
            active_version: Some("1.13.0".into()),
            staged: Vec::new(),
            activation_pending: None,
            channel: "production".into(),
            target: "x86_64-unknown-linux-gnu".into(),
        }
    }

    fn healthy() -> DoctorInputs {
        DoctorInputs {
            transport: "local".into(),
            status: Ok(StatusFacts {
                state: "up".into(),
                dry_run: false,
                online: 2,
                total: 17,
            }),
            health: Ok(health()),
            firewall: Ok(FirewallView {
                rules: "table inet helios {}".into(),
                default_verdict: "drop".into(),
                dry_run: false,
            }),
            domain: Ok(Some(domain(vec![peer(
                "laptop",
                ValidityPhase::Valid,
                40,
                false,
            )]))),
            release: Ok(release()),
        }
    }

    #[test]
    fn sizes_durations_and_instants_read_like_a_person_wrote_them() {
        assert_eq!(bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
        assert_eq!(bytes(512 * 1024), "512.0 KiB");
        assert_eq!(bytes(12), "12 B");
        assert_eq!(duration(3 * 86_400 + 4 * 3_600 + 120), "3 d 04 h");
        assert_eq!(duration(3_720), "1 h 02 min");
        assert_eq!(duration(42), "42 s");
        assert_eq!(relative(1_000_000 + 5 * 86_400, 1_000_000), "in 5 d 00 h");
        assert_eq!(relative(1_000_000 - 3_600, 1_000_000), "1 h 00 min ago");
    }

    #[test]
    fn health_shows_every_reading_and_says_when_one_is_missing() {
        let text = strip(&render_health(&health()));
        assert!(text.contains("3 d 04 h"), "{text}");
        assert!(text.contains("0.12 0.08 0.05 (4 CPU)"), "{text}");
        assert!(
            text.contains("2.0 GiB available of 8.0 GiB (25 %)"),
            "{text}"
        );
        assert!(text.contains("48.0 °C"), "{text}");
        assert!(text.contains("unsealed · vaults preserved"), "{text}");
        let empty = HealthView {
            uptime_seconds: None,
            load: None,
            cpu_count: None,
            memory_total_bytes: None,
            memory_available_bytes: None,
            temperature_celsius: None,
            tpm: None,
        };
        let text = strip(&render_health(&empty));
        assert!(text.contains("TPM           not validated"), "{text}");
        assert!(text.matches("unknown").count() >= 4, "{text}");
    }

    #[test]
    fn certificates_flag_renewals_revocations_and_drop_terminal_controls() {
        let view = domain(vec![
            peer("laptop", ValidityPhase::Valid, 40, false),
            peer("phone\x1b[2J", ValidityPhase::RenewalDue, 5, false),
            peer("old", ValidityPhase::Expired, -3, true),
        ]);
        let raw = render_certificates(&view);
        assert!(!raw.contains("\x1b[2J"));
        let text = strip(&raw);
        assert!(text.contains("helios-home · gw.helios"), "{text}");
        assert!(text.contains("identity epoch 5"), "{text}");
        assert!(text.contains("transition pending"), "{text}");
        assert!(text.contains("usable · expires in 20 d 00 h"), "{text}");
        assert!(text.contains("Clients (3)"), "{text}");
        assert!(text.contains("phone[2J"), "{text}");
        assert!(text.contains("renewal due · expires in 5 d 00 h"), "{text}");
        assert!(text.contains("revoked"), "{text}");
    }

    #[test]
    fn a_healthy_gateway_passes_every_check() {
        let checks = diagnose(&healthy());
        assert!(
            checks.iter().all(|check| check.level == Level::Ok),
            "{checks:?}"
        );
        assert!(strip(&render_doctor(&checks)).contains("all checks passed"));
    }

    #[test]
    fn the_doctor_warns_on_soft_problems_and_fails_on_hard_ones() {
        let mut inputs = healthy();
        inputs.status = Ok(StatusFacts {
            state: "connecting".into(),
            dry_run: false,
            online: 0,
            total: 17,
        });
        inputs.health.as_mut().unwrap().tpm = Some(TpmView {
            kind: "unsealed".into(),
            preserved_vaults: false,
        });
        inputs.firewall.as_mut().unwrap().default_verdict = "accept".into();
        inputs.domain = Ok(Some(domain(vec![peer(
            "phone",
            ValidityPhase::Critical,
            1,
            false,
        )])));
        inputs.release = Err("403 Forbidden".into());
        let checks = diagnose(&inputs);
        let level = |label: &str| {
            checks
                .iter()
                .find(|check| check.label == label)
                .unwrap_or_else(|| panic!("no {label} check in {checks:?}"))
                .level
        };
        assert_eq!(level("Tunnel"), Level::Warn);
        assert_eq!(level("TPM"), Level::Fail);
        assert_eq!(level("Firewall"), Level::Fail);
        assert_eq!(level("Certificates"), Level::Warn);
        assert_eq!(level("Release"), Level::Fail);
        let text = strip(&render_doctor(&checks));
        assert!(text.contains("3 failed, 2 warnings"), "{text}");
        assert!(
            text.contains("waiting for clients · 0/17 peers online"),
            "{text}"
        );
    }

    #[test]
    fn an_unreachable_api_is_one_failure_not_a_cascade_of_guesses() {
        let mut inputs = healthy();
        inputs.status = Err("connection refused".into());
        let checks = diagnose(&inputs);
        let api = checks.iter().find(|check| check.label == "API").unwrap();
        assert_eq!(api.level, Level::Fail);
        assert!(api.detail.contains("connection refused"));
        assert!(checks.iter().all(|check| check.label != "Tunnel"));
    }

    #[test]
    fn journal_arguments_never_reach_a_shell() {
        assert_eq!(
            journal_args(50, false),
            [
                "--namespace=helios",
                "-u",
                "heliosd",
                "-n",
                "50",
                "--no-pager",
                "-o",
                "short-iso"
            ]
        );
        assert!(journal_args(10, true).contains(&"--follow".to_owned()));
    }
}
