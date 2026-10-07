//! Read-only commands: what the gateway serves, laid out for the operator.
//! None of them changes any state. Rendering is separate from fetching so
//! each layout is tested on recorded gateway data.

use aether::{certificates::window::ValidityPhase, key_negotiation::ProtectionMode};
use anyhow::{Context, Result};
use helios_update::UpdateStatus;
use reqwest::Client;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;

use crate::{
    api::{self, NetworkConfigView},
    transport::Api,
    ui::{self, bytes, clean, duration, percent, relative, short, Cell, Level, Tone, Ui},
    Status,
};

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
    #[serde(default)]
    pub wg_public_key: String,
    pub generation: u64,
    pub not_after: u64,
    pub phase: ValidityPhase,
    pub revoked: bool,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

pub async fn status(client: &Client, base: &str) -> Result<()> {
    let status = crate::api_status(client, base).await?;
    print!("{}", render_status(&Ui::detect(), &status));
    Ok(())
}

pub async fn peers(client: &Client, base: &str) -> Result<()> {
    let status = crate::api_status(client, base).await?;
    print!("{}", render_peers(&Ui::detect(), &status));
    Ok(())
}

pub async fn network(client: &Client, base: &str) -> Result<()> {
    let view = api::network(client, base).await?;
    print!("{}", render_network(&Ui::detect(), &view));
    Ok(())
}

pub async fn health(client: &Client, base: &str) -> Result<()> {
    let view: HealthView = api::get(client, base, "/api/health").await?;
    print!("{}", render_health(&Ui::detect(), &view));
    Ok(())
}

pub async fn firewall(client: &Client, base: &str, raw: bool) -> Result<()> {
    let view: FirewallView = api::get(client, base, "/api/firewall/rules").await?;
    if raw {
        // Exactly what nftables holds, for copying or diffing.
        print!("{}", clean_lines(&view.rules));
        return Ok(());
    }
    print!("{}", render_firewall(&Ui::detect(), &view));
    Ok(())
}

pub async fn certificates(client: &Client, base: &str) -> Result<()> {
    let view: DomainView = api::get_optional(client, base, "/api/certificates")
        .await?
        .context("this gateway has no trust domain — run `heliosd init-trust-domain`")?;
    print!("{}", render_certificates(&Ui::detect(), &view));
    Ok(())
}

pub async fn trust(client: &Client, base: &str) -> Result<()> {
    let view: TrustView = api::get(client, base, "/api/trust").await?;
    print!("{}", render_trust(&Ui::detect(), &view));
    Ok(())
}

pub async fn release(client: &Client, base: &str) -> Result<()> {
    let view: UpdateStatus = api::get(client, base, "/api/update").await?;
    print!("{}", render_release(&Ui::detect(), &view));
    Ok(())
}

pub async fn negotiation(client: &Client, base: &str) -> Result<()> {
    let view = api::key_negotiation(client, base)
        .await?
        .context("this gateway serves no key-negotiation material")?;
    let ui = Ui::detect();
    let mut out = ui.title(
        "Key negotiation",
        "public material pinned by Orion profiles",
    );
    out.push_str(
        &ui.field(
            "Port",
            &view
                .port
                .map_or_else(|| "closed".to_owned(), |port| format!("UDP {port}")),
        ),
    );
    out.push_str(&ui.field("Server name", &view.server_name));
    out.push_str(&ui.field("Gateway key", &view.wireguard_public_key));
    out.push_str(&ui.field("PQ cert", &format!("sha256 {}", view.pq_certificate_sha256)));
    out.push('\n');
    print!("{out}");
    Ok(())
}

/// The daemon's journal, read locally: it never transits the API.
pub async fn logs(lines: usize, follow: bool, verbose: bool) -> Result<()> {
    let ui = Ui::detect();
    let mut child = tokio::process::Command::new("journalctl")
        .args(journal_args(lines, follow))
        .stdout(std::process::Stdio::piped())
        // Ctrl-C abandons the command future; the reader must not outlive it.
        .kill_on_drop(true)
        .spawn()
        .context("running journalctl — is this the gateway?")?;
    let stdout = child.stdout.take().context("journalctl stdout")?;
    let mut reader = tokio::io::BufReader::new(stdout).lines();
    println!();
    while let Some(line) = reader.next_line().await.context("reading journalctl")? {
        print!("{}", render_log_line(&ui, &line, verbose));
    }
    let status = child.wait().await.context("waiting for journalctl")?;
    println!();
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
    print!("{}", render_doctor(&Ui::detect(), &checks));
    let failed = checks
        .iter()
        .filter(|check| check.level == Level::Fail)
        .count();
    anyhow::ensure!(failed == 0, "{failed} check(s) failed");
    Ok(())
}

// ─── Status, peers, network ───────────────────────────────────────────────────

fn mode_label(mode: &str) -> &str {
    match mode {
        "ml_kem" => "ML-KEM",
        "static_psk" => "static PSK",
        "classic" => "classic",
        _ => "unknown",
    }
}

fn host(address: &str) -> &str {
    address.strip_suffix("/32").unwrap_or(address)
}

fn list_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        empty.to_owned()
    } else {
        items
            .iter()
            .map(|item| clean(item))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn handshake_cell(age: Option<u64>, stale: Option<u64>) -> Cell {
    match age {
        None => Cell::new("never", Tone::Dim),
        Some(age) if stale.is_none_or(|stale| age <= stale) => {
            Cell::new(format!("{} ago", duration(age)), Tone::Good)
        }
        Some(age) => Cell::new(format!("{} ago", duration(age)), Tone::Dim),
    }
}

fn traffic(rx: u64, tx: u64) -> String {
    if rx == 0 && tx == 0 {
        "–".to_owned()
    } else {
        format!("↓ {}  ↑ {}", bytes(rx), bytes(tx))
    }
}

pub fn render_status(ui: &Ui, status: &Status) -> String {
    let (online, total) = status.online_peers();
    let mode = if status.dry_run {
        ui.paint("dry-run", Tone::Warn)
    } else {
        "real".to_owned()
    };
    let mut out = format!(
        "\n  {} {}  {}\n\n",
        ui.paint("●", ui::state_tone(&status.state)),
        ui.paint(&ui::state_label(&status.state), Tone::Bold),
        ui.paint(
            &format!(
                "{online} of {total} peers online · heliosd v{} · ",
                clean(&status.version)
            ),
            Tone::Dim
        ) + &mode
    );
    out.push_str(&ui.field("Uplinks", &list_or(&status.wan_ifaces, "none")));
    let mut tunnel = vec![clean(&status.wg_iface)];
    tunnel.push(
        status
            .wg_listen_port
            .map_or_else(|| "port closed".to_owned(), |port| format!("UDP {port}")),
    );
    if let Some(port) = status.key_negotiation_port {
        tunnel.push(format!("negotiation UDP {port}"));
    }
    out.push_str(&ui.field("Tunnel", &tunnel.join(" · ")));
    out.push_str(&ui.field("LAN", &list_or(&status.lan_ifaces, "none")));
    let mut ssh = Vec::new();
    if !status.allow_ssh_from.is_empty() {
        ssh.push(format!("from {}", list_or(&status.allow_ssh_from, "")));
    }
    if !status.admin_ifaces.is_empty() {
        ssh.push(format!(
            "out-of-band via {}",
            list_or(&status.admin_ifaces, "")
        ));
    }
    out.push_str(&ui.field(
        "SSH",
        &if ssh.is_empty() {
            "tunnel only".to_owned()
        } else {
            ssh.join(" · ")
        },
    ));
    if !status.wg_peers.is_empty() {
        out.push_str(&ui.field("Site-to-site", &list_or(&status.wg_peers, "")));
    }
    if !status.split_tunnel_cidrs.is_empty() {
        out.push_str(&ui.field("Split tunnel", &list_or(&status.split_tunnel_cidrs, "")));
    }
    if let Some(mss) = status.mss_clamp {
        out.push_str(&ui.field("MSS clamp", &mss.to_string()));
    }
    if let Some(gateway) = &status.captive_portal_gateway {
        out.push_str(&ui.field_toned("Captive portal", gateway, Tone::Warn));
    }
    let stale = status.handshake_stale_after_seconds;
    let live: Vec<Vec<Cell>> = status
        .peers
        .iter()
        .filter(|peer| {
            peer.last_handshake_age_seconds
                .is_some_and(|age| stale.is_none_or(|stale| age <= stale))
        })
        .map(|peer| {
            vec![
                Cell::new(&peer.name, Tone::Bold),
                Cell::plain(host(&peer.address)),
                handshake_cell(peer.last_handshake_age_seconds, stale),
                Cell::plain(traffic(peer.rx_bytes, peer.tx_bytes)),
                if peer.post_quantum {
                    Cell::new("ML-KEM", Tone::Good)
                } else {
                    Cell::new("–", Tone::Dim)
                },
                Cell::new(peer.endpoint.as_deref().unwrap_or("–"), Tone::Dim),
            ]
        })
        .collect();
    if live.is_empty() {
        out.push('\n');
        out.push_str(&ui.note(&format!(
            "No peer online — /peer list shows the {total} admitted peers."
        )));
    } else {
        out.push('\n');
        out.push_str(&ui.section("Online", ""));
        out.push_str(&ui.table(
            2,
            &["NAME", "ADDRESS", "HANDSHAKE", "TRAFFIC", "PSK", "ENDPOINT"],
            &live,
        ));
    }
    out.push('\n');
    out
}

pub fn render_peers(ui: &Ui, status: &Status) -> String {
    if status.peers.is_empty() {
        return format!(
            "{}{}\n",
            ui.title("Peers", "none admitted"),
            ui.note("Admit one with /peer add.")
        );
    }
    let (online, total) = status.online_peers();
    let admins = status.peers.iter().filter(|peer| peer.admin).count();
    let modes: Vec<&str> = status
        .peers
        .iter()
        .map(|peer| peer.minimum_key_negotiation_mode.as_str())
        .collect();
    let uniform = modes.windows(2).all(|pair| pair[0] == pair[1]);
    let mut out = ui.title(
        "Peers",
        &format!("{total} admitted · {admins} admin · {online} online"),
    );
    let stale = status.handshake_stale_after_seconds;
    let mut headers = vec!["NAME", "ADDRESS", "ROLE", "HANDSHAKE", "TRAFFIC"];
    if !uniform {
        headers.push("MIN MODE");
    }
    headers.push("KEY");
    let rows: Vec<Vec<Cell>> = status
        .peers
        .iter()
        .map(|peer| {
            let mut row = vec![
                Cell::new(&peer.name, Tone::Bold),
                Cell::plain(host(&peer.address)),
                if peer.admin {
                    Cell::new("admin", Tone::Warn)
                } else {
                    Cell::new("–", Tone::Dim)
                },
                handshake_cell(peer.last_handshake_age_seconds, stale),
                Cell::new(traffic(peer.rx_bytes, peer.tx_bytes), Tone::Dim),
            ];
            if !uniform {
                row.push(Cell::plain(mode_label(&peer.minimum_key_negotiation_mode)));
            }
            row.push(Cell::new(short(&peer.public_key, 8), Tone::Dim));
            row
        })
        .collect();
    out.push_str(&ui.table(2, &headers, &rows));
    if uniform {
        out.push('\n');
        out.push_str(&ui.note(&format!(
            "Every peer requires {} key negotiation.",
            mode_label(modes[0])
        )));
    }
    out.push('\n');
    out
}

pub fn render_network(ui: &Ui, view: &NetworkConfigView) -> String {
    let mut out = ui.title("Network", "configuration held by heliosd (no secret)");
    out.push_str(&ui.field("Uplinks", &list_or(&view.wan_ifaces, "none")));
    out.push_str(&ui.field("LAN", &list_or(&view.lan_ifaces, "none")));
    out.push_str(&ui.field(
        "Tunnel",
        &format!(
            "{} · {} · UDP {}",
            clean(&view.wg_iface),
            clean(&view.wg_address),
            view.wg_listen_port
        ),
    ));
    out.push_str(
        &ui.field(
            "Negotiation",
            &view
                .key_negotiation_port
                .map_or_else(|| "disabled".to_owned(), |port| format!("UDP {port}")),
        ),
    );
    let key = view
        .wg_public_key
        .as_deref()
        .map_or_else(|| "unknown".to_owned(), clean);
    if view.wg_private_key_configured {
        out.push_str(&ui.field(
            "Gateway key",
            &format!("{key} · private key present, never shown"),
        ));
    } else {
        out.push_str(&ui.field_toned("Gateway key", "private key missing", Tone::Bad));
    }
    out.push_str(&match &view.admin_iface {
        Some(iface) => ui.field("Admin API", &format!("through {} only", clean(iface))),
        None => ui.field_toned(
            "Admin API",
            "no tunnel interface: unreachable remotely",
            Tone::Warn,
        ),
    });
    out.push_str(&ui.field(
        "Out-of-band",
        &if view.admin_ifaces.is_empty() {
            "none".to_owned()
        } else {
            format!("SSH via {}", list_or(&view.admin_ifaces, ""))
        },
    ));
    out.push_str(&ui.field("SSH from", &list_or(&view.allow_ssh_from, "nowhere")));
    let pinned = view
        .peers
        .iter()
        .filter(|peer| {
            peer.key_negotiation_certificate_sha256.is_some()
                && peer.key_negotiation_pq_certificate_sha256.is_some()
        })
        .count();
    let admins = view.peers.iter().filter(|peer| peer.admin).count();
    let static_psk = view
        .peers
        .iter()
        .filter(|peer| peer.preshared_key_configured)
        .count();
    let classic = view
        .peers
        .iter()
        .filter(|peer| peer.minimum_key_negotiation_mode == ProtectionMode::Classic)
        .count();
    let mut peers = vec![
        format!("{} admitted", view.peers.len()),
        format!("{admins} admin"),
        format!("{pinned} with pinned negotiation certificates"),
    ];
    if static_psk > 0 {
        peers.push(format!("{static_psk} with a static PSK"));
    }
    out.push_str(&ui.field("Peers", &format!("{} — /peer list", peers.join(" · "))));
    if classic > 0 {
        // Retired mode (spec §19): worth seeing from the configuration view.
        out.push_str(&ui.field_toned(
            "",
            &format!("{classic} peer(s) still accept classic WireGuard without a PSK"),
            Tone::Warn,
        ));
    }
    out.push('\n');
    out
}

// ─── Health, firewall, certificates, trust, release ──────────────────────────

pub fn render_health(ui: &Ui, view: &HealthView) -> String {
    let unknown = || "unknown".to_owned();
    let mut out = ui.title("Health", "");
    out.push_str(&ui.field(
        "Uptime",
        &view.uptime_seconds.map_or_else(unknown, duration),
    ));
    out.push_str(&ui.field(
        "Load",
        &view.load.map_or_else(unknown, |[one, five, fifteen]| {
            let cpus = view
                .cpu_count
                .map(|count| format!(" on {count} CPU"))
                .unwrap_or_default();
            format!("{one:.2} {five:.2} {fifteen:.2}{cpus}")
        }),
    ));
    let memory = match (view.memory_available_bytes, view.memory_total_bytes) {
        (Some(available), Some(total)) => {
            let share = percent(available, total);
            let tone = if share < 10 { Tone::Warn } else { Tone::Plain };
            (
                format!("{} free of {} ({share} %)", bytes(available), bytes(total)),
                tone,
            )
        }
        _ => (unknown(), Tone::Dim),
    };
    out.push_str(&ui.field_toned("Memory", &memory.0, memory.1));
    out.push_str(&match view.temperature_celsius {
        Some(celsius) => ui.field_toned(
            "Temperature",
            &format!("{celsius:.1} °C"),
            if celsius >= 85.0 {
                Tone::Warn
            } else {
                Tone::Plain
            },
        ),
        None => ui.field_toned("Temperature", "unknown", Tone::Dim),
    });
    out.push_str(&match &view.tpm {
        None => ui.field_toned("TPM", "not validated", Tone::Warn),
        Some(tpm) if !tpm.preserved_vaults => ui.field_toned(
            "TPM",
            &format!("{} · sealed vaults NOT preserved", tpm.kind),
            Tone::Bad,
        ),
        Some(tpm) => ui.field("TPM", &format!("{} · sealed vaults preserved", tpm.kind)),
    });
    out.push('\n');
    out
}

/// One parsed nftables rule: verdict, match and the ruleset's own comment.
struct Rule {
    verdict: String,
    matcher: String,
    comment: String,
}

struct Chain {
    name: String,
    policy: String,
    rules: Vec<Rule>,
}

const VERDICTS: &[&str] = &[
    "accept",
    "drop",
    "reject",
    "return",
    "masquerade",
    "snat",
    "dnat",
    "redirect",
];

/// Reads the ruleset text heliosd renders. Lines it does not recognise are
/// kept as rules without a verdict rather than dropped.
fn parse_ruleset(text: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = Vec::new();
    for raw in text.lines() {
        let line = clean(raw);
        let line = line.trim();
        if line.is_empty() || line == "}" || line.starts_with("table ") {
            continue;
        }
        if let Some(name) = line.strip_prefix("chain ") {
            chains.push(Chain {
                name: name.trim_end_matches('{').trim().to_owned(),
                policy: String::new(),
                rules: Vec::new(),
            });
            continue;
        }
        let Some(chain) = chains.last_mut() else {
            continue;
        };
        if line.starts_with("type ") {
            if let Some(policy) = line.split("policy ").nth(1) {
                chain.policy = policy.trim_end_matches(';').trim().to_owned();
            }
            continue;
        }
        let (rule, comment) = match line.split_once("  # ") {
            Some((rule, comment)) => (rule.trim(), comment.trim()),
            None => (line, ""),
        };
        let mut words: Vec<&str> = rule.split_whitespace().collect();
        let verdict = match words.last() {
            Some(last) if VERDICTS.contains(last) => words.pop().unwrap_or_default(),
            _ => "",
        };
        words.retain(|word| *word != "counter");
        chain.rules.push(Rule {
            verdict: verdict.to_owned(),
            matcher: words.join(" "),
            comment: comment.to_owned(),
        });
    }
    chains
}

pub fn render_firewall(ui: &Ui, view: &FirewallView) -> String {
    let chains = parse_ruleset(&view.rules);
    let counts: Vec<String> = chains
        .iter()
        .map(|chain| format!("{} {}", chain.name, chain.rules.len()))
        .collect();
    let mode = if view.dry_run { " · dry-run" } else { "" };
    let mut out = ui.title(
        "Firewall",
        &format!(
            "default {}{mode} · rules: {}",
            clean(&view.default_verdict),
            counts.join(", ")
        ),
    );
    for (index, chain) in chains.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&ui.section(
            &chain.name,
            &if chain.policy.is_empty() {
                String::new()
            } else {
                format!("policy {}", chain.policy)
            },
        ));
        // One rule per line, its reason underneath; consecutive rules that
        // share a reason (one per uplink) show it once, after the last.
        for (position, rule) in chain.rules.iter().enumerate() {
            let tone = match rule.verdict.as_str() {
                "accept" | "masquerade" | "snat" | "dnat" | "redirect" => Tone::Good,
                "drop" | "reject" => Tone::Bad,
                _ => Tone::Dim,
            };
            out.push_str(&format!(
                "    {} {}\n",
                ui.paint(&format!("{:<6}", rule.verdict), tone),
                ui.fit(&rule.matcher, 11)
            ));
            let next = chain.rules.get(position + 1);
            if !rule.comment.is_empty() && next.is_none_or(|next| next.comment != rule.comment) {
                out.push_str(&format!(
                    "           {}\n",
                    ui.paint(&ui.fit(&rule.comment, 11), Tone::Dim)
                ));
            }
        }
    }
    out.push('\n');
    out.push_str(&ui.note("/firewall --raw prints the exact nftables ruleset."));
    out.push('\n');
    out
}

fn certificate_rank(peer: &PeerCertView) -> u8 {
    if peer.revoked {
        return 6;
    }
    match peer.phase {
        ValidityPhase::Expired => 0,
        ValidityPhase::Critical => 1,
        ValidityPhase::Warning => 2,
        ValidityPhase::RenewalDue => 3,
        ValidityPhase::Valid => 4,
        ValidityPhase::NotYetValid => 5,
    }
}

pub fn render_certificates(ui: &Ui, view: &DomainView) -> String {
    let now = view.now_unix;
    let pending = |flag: bool| if flag { " · transition pending" } else { "" };
    let mut out = ui.title(
        "Certificates",
        &format!(
            "trust domain {} · {}",
            short(&view.trust_domain_id, 12),
            clean(&view.server_name)
        ),
    );
    if let Some(issuer) = &view.issuer {
        if issuer.usable {
            out.push_str(&ui.field(
                "Issuer",
                &format!(
                    "epoch {} · expires {}",
                    issuer.issuer_epoch,
                    relative(issuer.not_after, now)
                ),
            ));
        } else {
            let why = if issuer.not_after <= now {
                format!("expired {}", relative(issuer.not_after, now))
            } else {
                "not usable".to_owned()
            };
            out.push_str(&ui.field_toned(
                "Issuer",
                &format!("epoch {} {why} — clients cannot renew", issuer.issuer_epoch),
                Tone::Bad,
            ));
        }
    }
    out.push_str(&ui.field(
        "CA",
        &format!(
            "epoch {} · {}{}",
            view.ca_epoch,
            short(&view.ca_pq_fingerprint, 16),
            pending(view.ca_transition_pending)
        ),
    ));
    out.push_str(&ui.field(
        "Gateway",
        &format!(
            "identity epoch {} · TLS {} · PQ {}{}",
            view.gateway_identity_epoch,
            short(&view.gateway_tls_fingerprint, 12),
            short(&view.gateway_pq_fingerprint, 12),
            pending(view.gateway_transition_pending)
        ),
    ));
    out.push_str(&ui.field("Authority", &view.astra_authority_url));

    let mut peers: Vec<&PeerCertView> = view.peers.iter().collect();
    peers.sort_by_key(|peer| (certificate_rank(peer), peer.not_after));
    let count = |ranks: &[u8]| {
        peers
            .iter()
            .filter(|peer| ranks.contains(&certificate_rank(peer)))
            .count()
    };
    let mut summary = vec![
        format!("{} total", peers.len()),
        format!("{} valid", count(&[3, 4, 5])),
    ];
    for (n, label) in [
        (count(&[1, 2]), "expiring"),
        (count(&[0]), "expired"),
        (count(&[6]), "revoked"),
    ] {
        if n > 0 {
            summary.push(format!("{n} {label}"));
        }
    }
    out.push('\n');
    out.push_str(&ui.section("Clients", &summary.join(" · ")));
    let rows: Vec<Vec<Cell>> = peers
        .iter()
        .map(|peer| {
            let left = relative(peer.not_after, now);
            let (mark, state) = if peer.revoked {
                (Cell::new("✗", Tone::Dim), Cell::new("revoked", Tone::Dim))
            } else {
                match peer.phase {
                    ValidityPhase::Expired => (
                        Cell::new("✗", Tone::Bad),
                        Cell::new(format!("expired {left}"), Tone::Bad),
                    ),
                    ValidityPhase::Critical | ValidityPhase::Warning => (
                        Cell::new("!", Tone::Bad),
                        Cell::new(format!("expires {left}"), Tone::Bad),
                    ),
                    ValidityPhase::RenewalDue => (
                        Cell::new("!", Tone::Warn),
                        Cell::new(format!("renewal due · expires {left}"), Tone::Warn),
                    ),
                    ValidityPhase::Valid => (
                        Cell::new("●", Tone::Good),
                        Cell::plain(format!("valid · expires {left}")),
                    ),
                    ValidityPhase::NotYetValid => (
                        Cell::new("○", Tone::Dim),
                        Cell::new("not yet valid", Tone::Dim),
                    ),
                }
            };
            vec![
                mark,
                Cell::new(&peer.name, Tone::Bold),
                Cell::new(format!("gen {}", peer.generation), Tone::Dim),
                Cell::new(short(&peer.wg_public_key, 8), Tone::Dim),
                state,
            ]
        })
        .collect();
    out.push_str(&ui.table(4, &["", "NAME", "GEN", "KEY", "STATE"], &rows));
    out.push('\n');
    out
}

pub fn render_trust(ui: &Ui, view: &TrustView) -> String {
    let mut out = ui.title("Update trust", "what an application release must carry");
    let algs: Vec<String> = view.required_algs.iter().map(|alg| clean(alg)).collect();
    out.push_str(&ui.field(
        "Signatures",
        &format!("{} (all required)", algs.join(" + ")),
    ));
    for key in &view.publisher_keys {
        out.push_str(&ui.field(
            "Publisher",
            &format!("epoch {} · {}", key.key_epoch, clean(&key.fingerprint)),
        ));
    }
    if view.development_keys {
        out.push_str(&ui.field_toned(
            "Warning",
            "development publisher keys are trusted",
            Tone::Bad,
        ));
    }
    out.push_str(&ui.field(
        "TPM reseal",
        &format!(
            "{} · format {}",
            clean(&view.reseal_domain),
            view.reseal_format_version
        ),
    ));
    out.push('\n');
    out
}

pub fn render_release(ui: &Ui, view: &UpdateStatus) -> String {
    let active = view.active_version.as_deref().unwrap_or("unknown");
    let mut out = ui.title(
        "Release",
        &format!(
            "heliosd {} · {} · {}",
            clean(active),
            clean(&view.channel),
            clean(&view.target)
        ),
    );
    out.push_str(&ui.field(
        "Confirmed",
        &format!("sequence {}", view.highest_confirmed_sequence),
    ));
    match view.activation_pending {
        Some(sequence) => out.push_str(&ui.field_toned(
            "Activation",
            &format!("sequence {sequence} pending"),
            Tone::Warn,
        )),
        None => out.push_str(&ui.field("Activation", "none pending")),
    }
    if view.staged.is_empty() {
        out.push_str(&ui.field("Staged", "none"));
    } else {
        out.push('\n');
        out.push_str(&ui.section("Staged", ""));
        let rows: Vec<Vec<Cell>> = view
            .staged
            .iter()
            .map(|staged| {
                // Anti-rollback: nothing at or below the confirmed sequence
                // can be activated again.
                let state = if staged.release_sequence > view.highest_confirmed_sequence {
                    Cell::new("ready to activate", Tone::Good)
                } else {
                    Cell::new("superseded — cannot be activated", Tone::Dim)
                };
                vec![
                    Cell::new(&staged.version, Tone::Bold),
                    Cell::plain(staged.release_sequence.to_string()),
                    Cell::new(short(&staged.sha256, 12), Tone::Dim),
                    state,
                ]
            })
            .collect();
        out.push_str(&ui.table(4, &["VERSION", "SEQUENCE", "SHA-256", "STATE"], &rows));
    }
    out.push('\n');
    out
}

// ─── Logs ─────────────────────────────────────────────────────────────────────

/// `journalctl -o short-iso` prefixes host and process to a tracing line
/// that already carries its own UTC timestamp. Keep the local time, the
/// level and the message; the module path only when asked.
pub fn render_log_line(ui: &Ui, line: &str, verbose: bool) -> String {
    let line = clean(line);
    let parsed = (|| {
        let (local, rest) = line.split_once(' ')?;
        let (_, message) = rest.split_once("]: ")?;
        let time = local.get(11..19)?;
        let date = local.get(5..10)?;
        let mut words = message.split_whitespace().peekable();
        if words
            .peek()
            .is_some_and(|word| word.ends_with('Z') && word.contains('T'))
        {
            words.next();
        }
        let level = match words.peek().copied() {
            Some(level @ ("TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR")) => {
                words.next();
                level
            }
            _ => "",
        };
        let target = match words.peek().copied() {
            // tracing puts the module path right after the level.
            Some(target)
                if !level.is_empty()
                    && target.len() > 1
                    && target.ends_with(':')
                    && target
                        .trim_end_matches(':')
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') =>
            {
                words.next();
                target.trim_end_matches(':')
            }
            _ => "",
        };
        let text: Vec<&str> = words.collect();
        Some((date, time, level, target, text.join(" ")))
    })();
    let Some((date, time, level, target, text)) = parsed else {
        return format!("  {}\n", ui.paint(&line, Tone::Dim));
    };
    let tone = match level {
        "ERROR" => Tone::Bad,
        "WARN" => Tone::Warn,
        "INFO" => Tone::Plain,
        _ => Tone::Dim,
    };
    let prefix = format!(
        "  {} {}  {}  ",
        ui.paint(date, Tone::Dim),
        time,
        ui.paint(&format!("{level:<5}"), tone)
    );
    let indent = 2 + 5 + 1 + 8 + 2 + 5 + 2;
    let text = if verbose && !target.is_empty() {
        format!("{} {text}", ui.paint(target, Tone::Dim))
    } else {
        text
    };
    let width = ui
        .width
        .map_or(usize::MAX, |width| width.saturating_sub(indent + 1).max(20));
    let mut lines = wrap(&text, width).into_iter();
    let mut out = format!("{prefix}{}\n", lines.next().unwrap_or_default());
    for rest in lines {
        out.push_str(&format!("{}{rest}\n", " ".repeat(indent)));
    }
    out
}

/// Breaks on spaces; a word longer than the width is split.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let current = lines.last().map_or(0, |line| line.chars().count());
        let length = word.chars().count();
        if current > 0 && current + 1 + length <= width {
            if let Some(line) = lines.last_mut() {
                line.push(' ');
                line.push_str(word);
            }
            continue;
        }
        if current > 0 {
            lines.push(String::new());
        }
        let mut chars: Vec<char> = word.chars().collect();
        while chars.len() > width {
            let rest = chars.split_off(width);
            if let Some(line) = lines.last_mut() {
                line.extend(chars);
            }
            lines.push(String::new());
            chars = rest;
        }
        if let Some(line) = lines.last_mut() {
            line.extend(chars);
        }
    }
    lines
}

fn clean_lines(text: &str) -> String {
    text.lines()
        .map(|line| format!("{}\n", clean(line)))
        .collect()
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
                other => check(
                    Fail,
                    "Tunnel",
                    format!("{} · {peers}", ui::state_label(other)),
                ),
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
                Some(tpm) => check(
                    Ok,
                    "TPM",
                    format!("{} · sealed vaults preserved", clean(&tpm.kind)),
                ),
            });
            if let (Some(total), Some(available)) =
                (health.memory_total_bytes, health.memory_available_bytes)
            {
                let share = percent(available, total);
                let detail = format!("{} free ({share} %)", bytes(available));
                checks.push(check(if share < 10 { Warn } else { Ok }, "Memory", detail));
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
        Result::Ok(Some(domain)) => certificates_check(domain),
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
                None => check(Ok, "Release", format!("heliosd {} active", clean(active))),
            }
        }
    });
    checks
}

fn certificates_check(domain: &DomainView) -> Check {
    if let Some(issuer) = domain.issuer.as_ref().filter(|issuer| !issuer.usable) {
        let why = if issuer.not_after <= domain.now_unix {
            format!("expired {}", relative(issuer.not_after, domain.now_unix))
        } else {
            "not usable".to_owned()
        };
        return check(
            Level::Fail,
            "Certificates",
            format!("issuer {why} — clients cannot renew"),
        );
    }
    let attention: Vec<String> = domain
        .peers
        .iter()
        .filter(|peer| {
            !peer.revoked
                && matches!(
                    peer.phase,
                    ValidityPhase::Warning | ValidityPhase::Critical | ValidityPhase::Expired
                )
        })
        .map(|peer| clean(&peer.name))
        .collect();
    if attention.is_empty() {
        check(
            Level::Ok,
            "Certificates",
            format!(
                "{} client certificate(s) in good standing",
                domain.peers.len()
            ),
        )
    } else {
        check(
            Level::Warn,
            "Certificates",
            format!(
                "{} client(s) expired or expiring: {}",
                attention.len(),
                attention.join(", ")
            ),
        )
    }
}

pub fn render_doctor(ui: &Ui, checks: &[Check]) -> String {
    let mut out = ui.title("Doctor", "one pass over the gateway");
    for check in checks {
        let tone = match check.level {
            Level::Ok => Tone::Plain,
            Level::Warn => Tone::Warn,
            Level::Fail => Tone::Bad,
        };
        let detail = ui.fit(&clean(&check.detail), 2 + 2 + 13 + 1);
        out.push_str(&format!(
            "  {} {} {}\n",
            ui.mark(check.level),
            ui.paint(&format!("{:<13}", check.label), Tone::Dim),
            ui.paint(&detail, tone)
        ));
    }
    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warned = checks.iter().filter(|c| c.level == Level::Warn).count();
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let summary = match (failed, warned) {
        (0, 0) => ui.paint("all checks passed", Tone::Good),
        (0, w) => ui.paint(&plural(w, "warning"), Tone::Warn),
        (f, w) => ui.paint(&format!("{f} failed, {}", plural(w, "warning")), Tone::Bad),
    };
    out.push_str(&format!("\n  {summary}\n\n"));
    out
}

#[cfg(test)]
mod tests;
