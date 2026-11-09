//! End-to-end campaigns for post-quantum provisioning.
//!
//! # One tool for both dry-run and target
//!
//! The scenarios are written **against the API**, not against an
//! implementation: the same binary runs against a `heliosd --dev` on WSL2 and
//! against a real gateway. Only the [`Category::PlanDeDonnees`] category
//! requires the target, because it reads the kernel's WireGuard state —
//! something no simulation can prove (see `docs/testing/TESTING.md`).
//!
//! # The campaign is a client, it does not simulate one
//!
//! The network scenarios go through [`orion_core::provision`], the code the
//! client actually embeds. Reimplementing the protocol here would validate
//! that reimplementation, not Orion. This is also what makes the campaign a
//! test **of the client** as much as **of the daemon**: a regression in
//! `orion-core` makes it fail.
//!
//! # The scenarios do not modify the configuration
//!
//! No scenario declares a peer or touches `network.toml`. Admission stays
//! out of band: this is an architectural invariant, not a gap in the tool. A
//! campaign whose keys are not admitted **fails** instead of self-admitting,
//! which would amount to testing a complacent gateway.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aether::enroll::{ProvisionResponse, PROTOCOL_VERSION};
use aether::pq::{Kem, MlKem1024Kem};
use anyhow::{Context, Result};
use base64::Engine as _;
use orion_core::provisioning::{finish, ProvisionError};
use orion_core::ClientProfile;
use reqwest::Client;

use crate::{fail, ok};

/// Scenario families, by what they require from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Category {
    /// Client logic only: no daemon required. Runs everywhere.
    Client,
    /// Client ↔ daemon over HTTP. Dry-run or target, either way.
    Protocole,
    /// Reads the WireGuard data plane. **Target only.**
    PlanDeDonnees,
    /// Pre-WireGuard key negotiation: crypto primitives, the enrolled
    /// profile, then the real service. **Windows workstation**, where the
    /// protected identity store lives.
    NegociationDeCle,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Category::Client => "client",
            Category::Protocole => "protocol",
            Category::PlanDeDonnees => "data plane",
            Category::NegociationDeCle => "key negotiation",
        }
    }
}

/// Parameters of a campaign.
pub struct Options {
    /// Client WireGuard private key (base64). Its peer must be **admitted**
    /// on the gateway, otherwise the network scenarios fail — rightly so.
    pub client_key: Option<String>,
    /// Gateway WireGuard public key (base64), as the profile expects it.
    /// Used to verify the gateway really is the one announced.
    pub gateway_key: Option<String>,
    /// WireGuard interface to inspect (`helios0`). Enables the
    /// [`Category::PlanDeDonnees`] category.
    pub wg_iface: Option<String>,
    /// Runs only one category.
    pub only: Option<Category>,
    /// Number of passes. Beyond 1, this is an endurance campaign: it reveals
    /// state leaks that a single run does not show (drifting VIP, a PSK that
    /// freezes, a peer table that grows).
    pub repeat: u32,
    /// Orion profile to negotiate with, by name, as this workstation holds it.
    ///
    /// Required by [`Category::NegociationDeCle`] beyond its crypto scenarios:
    /// the negotiation needs a pinned certificate and an identity sealed in
    /// the machine's protected store. Absent, the category runs its offline
    /// half and says why it stopped there.
    pub profile: Option<String>,
    /// Runs the scenarios that have to wait — the liveness link holds one
    /// tunnel silent for forty seconds.
    pub soak: bool,
}

/// Outcome of a scenario. `Skip` is not a failure: a scenario out of the
/// environment's reach must **say so**, not stay silent or lie.
#[derive(Debug)]
pub enum Outcome {
    Pass(String),
    Skip(String),
    Fail(String),
}

impl Outcome {
    pub fn pass(detail: impl Into<String>) -> Self {
        Outcome::Pass(detail.into())
    }
    pub fn skip(reason: impl Into<String>) -> Self {
        Outcome::Skip(reason.into())
    }
    pub fn fail(reason: impl Into<String>) -> Self {
        Outcome::Fail(reason.into())
    }
    /// Translates a boolean condition into an outcome, with the failure message.
    pub fn check(condition: bool, detail: impl Into<String>, failure: impl Into<String>) -> Self {
        if condition {
            Outcome::pass(detail)
        } else {
            Outcome::fail(failure)
        }
    }
}

/// Generates a WireGuard key pair.
///
/// **Standard output carries only two `KEY=value` lines**, to be consumable
/// by `eval` without fragile parsing; all the formatting goes to standard
/// error. Mixing the two would make a script depend on the punctuation of
/// help text — which breaks at the first reformatting.
pub fn generate_keys() {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut raw = [0u8; 32];
    aether::random::fill_secret(&mut raw).expect("the approved DRBG cannot produce a private key");
    let secret = x25519_dalek::StaticSecret::from(raw);
    let public = x25519_dalek::PublicKey::from(&secret);
    let (private, public) = (
        engine.encode(secret.to_bytes()),
        engine.encode(public.as_bytes()),
    );

    println!("WG_PRIVATE_KEY={private}");
    println!("WG_PUBLIC_KEY={public}");

    eprintln!("\n\x1b[1mWireGuard key pair\x1b[0m");
    eprintln!("───────────────────────");
    eprintln!("  Declare the peer on the gateway (network.toml), then rerun");
    eprintln!("  the campaign with --client-key:\n");
    eprintln!("    [[peers]]");
    eprintln!("    name = \"campaign\"");
    eprintln!("    public_key = \"{public}\"");
    eprintln!("    address = \"100.64.1.2/32\"\n");
}

/// WireGuard public key derived from a base64 private key.
fn public_from_private(private_b64: &str) -> Result<String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let raw: [u8; 32] = engine
        .decode(private_b64.trim())
        .context("unreadable private key (expected base64)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key has invalid length (32 bytes expected)"))?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    Ok(engine.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// Disposable profile for purely local scenarios.
///
/// These scenarios exercise the client's validation logic — rejecting a
/// spoofed gateway, a malformed ciphertext, an unknown version. No real peer
/// is involved, so requiring admitted keys would make no sense: the category
/// must run everywhere, including in regression, with no gateway or prior
/// configuration.
fn ephemeral_profile() -> ClientProfile {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut client = [0u8; 32];
    let mut gateway = [0u8; 32];
    aether::random::fill_secret(&mut client)
        .expect("the approved DRBG cannot produce a private key");
    aether::random::fill_secret(&mut gateway)
        .expect("the approved DRBG cannot produce a private key");
    let gateway_public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(gateway));

    ClientProfile {
        name: "local-campaign".into(),
        endpoint: "127.0.0.1:51820".into(),
        private_key: engine.encode(client).into(),
        peer_public_key: engine.encode(gateway_public.as_bytes()),
        ..ClientProfile::default()
    }
}

/// Campaign client profile, built from the options.
fn profile(opts: &Options, url: &str) -> Result<ClientProfile> {
    let client_key = opts
        .client_key
        .as_deref()
        .context("--client-key required for network scenarios")?;
    let gateway_key = opts
        .gateway_key
        .as_deref()
        .context("--gateway-key required to verify the gateway's identity")?;
    Ok(ClientProfile {
        name: "campaign".into(),
        // The UDP endpoint is unused here: the campaign talks to the API
        // inside the tunnel, it does not bring up the tunnel itself.
        endpoint: "127.0.0.1:51820".into(),
        private_key: client_key.into(),
        peer_public_key: gateway_key.to_string(),
        heliosd_url: Some(url.to_string()),
        ..ClientProfile::default()
    })
}

// ─── Scenarios: client logic, no daemon ───────────────────────────────────────

/// Builds a plausible gateway response, signed by no particular identity —
/// it is up to the client to judge.
fn response_for(kem_public: &[u8], gateway_key: &str) -> ProvisionResponse {
    let (ciphertext, _) = MlKem1024Kem::encapsulate(kem_public).expect("ML-KEM encapsulation");
    ProvisionResponse {
        protocol_version: PROTOCOL_VERSION,
        kem_ciphertext: ciphertext,
        gateway_nonce: [7u8; 16],
        assigned_address: "100.64.1.2/32".into(),
        assigned_address_v6: None,
        gateway_wg_public_key: gateway_key.into(),
        psk_lifetime_secs: 3600,
    }
}

/// A gateway that is not the one from the profile must be rejected, even if
/// its cryptography is perfectly valid. Without this check, a compromised
/// gateway would negotiate a PSK with the client.
fn scenario_gateway_identity(profile: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem1024Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("ML-KEM generation failed: {e}")),
    };
    let impostor = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let response = response_for(&pk, impostor);

    match finish(profile, &sk, &[42u8; 16], &response) {
        Err(ProvisionError::GatewayIdentityMismatch { .. }) => {
            Outcome::pass("spoofed gateway rejected")
        }
        Err(e) => Outcome::fail(format!("rejected, but for the wrong reason: {e}")),
        Ok(_) => Outcome::fail(
            "INVARIANT VIOLATED: the client negotiated a PSK with a gateway \
             whose identity does not match its profile",
        ),
    }
}

/// A malformed ciphertext must never produce a PSK.
fn scenario_malformed_ciphertext(profile: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem1024Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("ML-KEM generation failed: {e}")),
    };
    let mut response = response_for(&pk, &profile.peer_public_key);
    response.kem_ciphertext = vec![0u8; 10];

    Outcome::check(
        finish(profile, &sk, &[42u8; 16], &response).is_err(),
        "truncated ciphertext rejected",
        "a 10-byte ciphertext produced a PSK",
    )
}

/// An unknown protocol version must be rejected before any crypto.
fn scenario_protocol_version(profile: &ClientProfile) -> Outcome {
    let (sk, pk) = match MlKem1024Kem::generate() {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("ML-KEM generation failed: {e}")),
    };
    let mut response = response_for(&pk, &profile.peer_public_key);
    response.protocol_version = PROTOCOL_VERSION.wrapping_add(1);

    Outcome::check(
        finish(profile, &sk, &[42u8; 16], &response).is_err(),
        "incompatible version rejected",
        "an unknown protocol version was accepted",
    )
}

// ─── Scenarios: client ↔ daemon ───────────────────────────────────────────────

/// The nominal path: an admitted peer obtains a usable PSK.
async fn scenario_provisioning_nominal(profile: &ClientProfile, url: &str) -> Outcome {
    match orion_core::provision(profile, url).await {
        Err(e) => Outcome::fail(format!("{e}")),
        Ok(outcome) => {
            let engine = base64::engine::general_purpose::STANDARD;
            let size = engine
                .decode(outcome.preshared_key.expose())
                .map(|k| k.len());
            match size {
                Ok(32) if outcome.lifetime > Duration::ZERO => Outcome::pass(format!(
                    "PSK 32 B, VIP {}, lifetime {} s",
                    outcome.address,
                    outcome.lifetime.as_secs()
                )),
                Ok(n) => Outcome::fail(format!(
                    "PSK of {n} bytes: the WireGuard slot requires exactly 32"
                )),
                Err(e) => Outcome::fail(format!("PSK not decodable as base64: {e}")),
            }
        }
    }
}

/// Every session must produce a fresh PSK: this bounds the exploitation
/// window of a compromised PSK, and is thus the whole point of provisioning
/// versus a static PSK.
async fn scenario_fresh_psk(profile: &ClientProfile, url: &str) -> Outcome {
    let a = match orion_core::provision(profile, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("first session: {e}")),
    };
    let b = match orion_core::provision(profile, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("second session: {e}")),
    };

    Outcome::check(
        a.preshared_key != b.preshared_key,
        "two sessions, two distinct PSKs",
        "identical PSK across sessions: rotation adds nothing and a \
         compromised PSK stays compromised",
    )
}

/// The VIP derives from the public key, not from the session: it must be
/// stable across provisioning runs, with no state on disk on the gateway
/// side.
async fn scenario_stable_vip(profile: &ClientProfile, url: &str) -> Outcome {
    let a = match orion_core::provision(profile, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("first session: {e}")),
    };
    let b = match orion_core::provision(profile, url).await {
        Ok(v) => v,
        Err(e) => return Outcome::fail(format!("second session: {e}")),
    };

    Outcome::check(
        a.address == b.address,
        format!("VIP {} stable", a.address),
        format!(
            "unstable VIP: {} then {} — derivation cannot depend on the \
             session",
            a.address, b.address
        ),
    )
}

/// A never-declared peer must be rejected: provisioning admits no one.
async fn scenario_unadmitted_peer(profile: &ClientProfile, url: &str) -> Outcome {
    // A fresh key, so absent from `network.toml` by construction.
    let mut raw = [0u8; 32];
    if aether::random::fill_secret(&mut raw).is_err() {
        return Outcome::fail("the approved DRBG produced no key");
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let intruder = ClientProfile {
        private_key: engine.encode(raw).into(),
        ..profile.duplicate()
    };

    match orion_core::provision(&intruder, url).await {
        Err(ProvisionError::Rejected { status: 403, .. }) => {
            Outcome::pass("unknown peer rejected (403)")
        }
        Err(ProvisionError::Rejected { status, .. }) => {
            Outcome::fail(format!("rejected with {status} instead of 403"))
        }
        Err(e) => Outcome::fail(format!("rejected, but for the wrong reason: {e}")),
        Ok(_) => Outcome::fail(
            "INVARIANT VIOLATED: the gateway provisioned a key that was \
             never declared — out-of-band admission no longer holds",
        ),
    }
}

/// Field names that must never be serialized by a read.
///
/// The comparison is **exact**, not a substring match: the API legitimately
/// exposes `preshared_key_configured` and `wg_private_key_configured`,
/// booleans that say a secret exists without disclosing it. Confusing them
/// would make the tool fail against a correct API.
const SECRET_FIELDS: [&str; 3] = ["preshared_key", "wg_private_key", "private_key"];

/// Recursively looks for a serialized secret field.
fn secret_field(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                if SECRET_FIELDS.contains(&key.as_str()) {
                    return Some(key.clone());
                }
                if let Some(found) = secret_field(v) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(secret_field),
        _ => None,
    }
}

/// API reads must never leak a secret.
async fn scenario_no_secrets_in_api(client: &Client, base: &str) -> Outcome {
    let body: serde_json::Value = match client.get(format!("{base}/api/network")).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return Outcome::fail(format!("unreadable JSON response: {e}")),
        },
        Err(e) => return Outcome::fail(format!("call failed: {e}")),
    };

    match secret_field(&body) {
        Some(field) => Outcome::fail(format!(
            "GET /api/network serializes the `{field}` field — no read should \
             expose a secret"
        )),
        None => Outcome::pass("no secret field in GET /api/network"),
    }
}

/// Mutations require JSON: an untyped body must be rejected.
async fn scenario_mutation_without_json(client: &Client, base: &str) -> Outcome {
    let response = client
        .post(format!("{base}/api/tunnel/start"))
        .header("content-type", "text/plain")
        .body("connect")
        .send()
        .await;

    match response {
        Err(e) => Outcome::fail(format!("call failed: {e}")),
        Ok(r) => Outcome::check(
            r.status() == 415,
            "non-JSON body rejected (415)",
            format!("mutation accepted with {} without JSON", r.status()),
        ),
    }
}

// ─── Scenarios: data plane (target) ───────────────────────────────────────────

/// Reads `wg show <iface> dump` and returns the peer lines.
///
/// Format: the first line describes the interface, the following ones the
/// peers — `public key, PSK, endpoint, allowed-ips, latest handshake, rx,
/// tx, keepalive`.
fn wg_dump(iface: &str) -> Result<Vec<Vec<String>>> {
    let output = std::process::Command::new("wg")
        .args(["show", iface, "dump"])
        .output()
        .context("`wg` not found — tool available on the target only")?;
    if !output.status.success() {
        anyhow::bail!(
            "`wg show {iface} dump` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1) // interface line
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect())
}

/// The PSK must be **actually** installed in the kernel's WireGuard slot.
///
/// This is the only proof that matters: everything else can succeed while
/// the data plane received nothing. No simulation can establish it.
fn scenario_psk_on_interface(iface: &str, peer: &str) -> Outcome {
    let peers = match wg_dump(iface) {
        Ok(p) => p,
        Err(e) => return Outcome::fail(format!("{e}")),
    };
    let Some(line) = peers
        .iter()
        .find(|c| c.first().map(String::as_str) == Some(peer))
    else {
        return Outcome::fail(format!(
            "peer {peer} is absent from {iface}: provisioning did not install it"
        ));
    };
    let psk = line.get(1).map(String::as_str).unwrap_or("(none)");

    Outcome::check(
        psk != "(none)" && !psk.is_empty(),
        "PresharedKey slot populated in the kernel",
        "empty PresharedKey slot: the tunnel relies on Curve25519 alone, so \
         it remains vulnerable to \"harvest now, decrypt later\"",
    )
}

/// A recent handshake proves the installed PSK did not break the session —
/// the exact risk of a one-sided PSK.
fn scenario_recent_handshake(iface: &str, peer: &str) -> Outcome {
    let peers = match wg_dump(iface) {
        Ok(p) => p,
        Err(e) => return Outcome::fail(format!("{e}")),
    };
    let Some(line) = peers
        .iter()
        .find(|c| c.first().map(String::as_str) == Some(peer))
    else {
        return Outcome::fail(format!("peer {peer} absent from {iface}"));
    };
    let timestamp: u64 = line.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
    if timestamp == 0 {
        return Outcome::fail(
            "no handshake since the PSK was installed — the signature of a \
             PSK present on only one side",
        );
    }
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(timestamp))
        .unwrap_or(u64::MAX);

    Outcome::check(
        age < 180,
        format!("last handshake {age} s ago"),
        format!("last handshake {age} s ago (> REJECT_AFTER_TIME): the session is dead"),
    )
}

// ─── Execution ────────────────────────────────────────────────────────────────

/// Logs an outcome and reports whether it counts as a failure.
fn report(name: &str, outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Pass(d) => {
            println!("  {} {name:<38} \x1b[2m{d}\x1b[0m", ok());
            false
        }
        Outcome::Skip(r) => {
            println!("  \x1b[90m—\x1b[0m {name:<38} \x1b[90m{r}\x1b[0m");
            false
        }
        Outcome::Fail(r) => {
            println!("  {} {name:<38} \x1b[31m{r}\x1b[0m", fail());
            true
        }
    }
}

fn header(category: Category) {
    println!("\n\x1b[1m{}\x1b[0m", category.label());
    println!("{}", "─".repeat(category.label().chars().count()));
}

/// Runs the campaign. Returns an error if at least one scenario failed.
pub async fn run(client: &Client, base: &str, opts: Options) -> Result<()> {
    let plays = |c: Category| opts.only.is_none_or(|only| only == c);
    let mut failures = 0usize;
    let mut played = 0usize;

    println!("\n\x1b[1mPost-quantum provisioning campaign\x1b[0m");
    println!("  target  {base}");
    println!("  passes  {}", opts.repeat);

    for pass in 1..=opts.repeat {
        if opts.repeat > 1 {
            println!("\n\x1b[1m╌╌ pass {pass}/{} ╌╌\x1b[0m", opts.repeat);
        }

        // The profile is only required by the network categories: a
        // `--only client` campaign must run without any key.
        let profile = profile(&opts, base);

        if plays(Category::Client) {
            header(Category::Client);
            // These scenarios involve no real peer: absent supplied keys, an
            // ephemeral profile is enough and makes the category runnable
            // everywhere.
            let p = match &profile {
                Ok(p) => p.duplicate(),
                Err(_) => ephemeral_profile(),
            };
            for (name, outcome) in [
                ("gateway identity verified", scenario_gateway_identity(&p)),
                (
                    "malformed ciphertext rejected",
                    scenario_malformed_ciphertext(&p),
                ),
                ("protocol version verified", scenario_protocol_version(&p)),
            ] {
                played += 1;
                failures += usize::from(report(name, &outcome));
            }
        }

        if plays(Category::Protocole) {
            header(Category::Protocole);
            match &profile {
                Err(e) => {
                    report("network scenarios", &Outcome::skip(format!("{e}")));
                }
                Ok(p) => {
                    let outcomes = vec![
                        (
                            "nominal provisioning",
                            scenario_provisioning_nominal(p, base).await,
                        ),
                        ("fresh PSK per session", scenario_fresh_psk(p, base).await),
                        (
                            "stable VIP across sessions",
                            scenario_stable_vip(p, base).await,
                        ),
                        (
                            "unadmitted peer rejected",
                            scenario_unadmitted_peer(p, base).await,
                        ),
                        (
                            "no secrets in the API",
                            scenario_no_secrets_in_api(client, base).await,
                        ),
                        (
                            "mutation without JSON rejected",
                            scenario_mutation_without_json(client, base).await,
                        ),
                    ];
                    for (name, outcome) in outcomes {
                        played += 1;
                        failures += usize::from(report(name, &outcome));
                    }
                }
            }
        }

        if plays(Category::PlanDeDonnees) {
            header(Category::PlanDeDonnees);
            match (&opts.wg_iface, &profile) {
                (None, _) => {
                    report(
                        "data plane",
                        &Outcome::skip("--wg-iface absent (target only)"),
                    );
                }
                (Some(_), Err(e)) => {
                    report("data plane", &Outcome::skip(format!("{e}")));
                }
                (Some(iface), Ok(p)) => {
                    let peer = match public_from_private(p.private_key.expose()) {
                        Ok(k) => k,
                        Err(e) => anyhow::bail!("{e}"),
                    };
                    for (name, outcome) in [
                        (
                            "PSK installed in the kernel",
                            scenario_psk_on_interface(iface, &peer),
                        ),
                        (
                            "live handshake with PSK",
                            scenario_recent_handshake(iface, &peer),
                        ),
                    ] {
                        played += 1;
                        failures += usize::from(report(name, &outcome));
                    }
                }
            }
        }

        if plays(Category::NegociationDeCle) {
            header(Category::NegociationDeCle);
            // The crypto half depends on nothing: it runs on the build
            // machine as well as on the enrolled workstation.
            for (name, outcome) in crate::campaign_key_nego::crypto_scenarios() {
                played += 1;
                failures += usize::from(report(name, &outcome));
            }

            match opts.profile.as_deref() {
                None => {
                    report(
                        "enrolled profile",
                        &Outcome::skip("--profile <nom> required to reach the gateway"),
                    );
                }
                Some(name) => match crate::campaign_key_nego::load_enrolled(name) {
                    Err(error) => {
                        report("enrolled profile", &Outcome::fail(format!("{error:#}")));
                        failures += 1;
                        played += 1;
                    }
                    Ok(enrolled) => {
                        for (name, outcome) in
                            crate::campaign_key_nego::profile_scenarios(&enrolled).await
                        {
                            played += 1;
                            failures += usize::from(report(name, &outcome));
                        }
                        // Announced before, not after: the operator must be
                        // able to stop here rather than discover afterwards
                        // that a connected Orion lost its tunnel.
                        println!(
                            "  \x1b[90m…\x1b[0m négociations réelles — le PSK du pair est \
                             renégocié puis relâché"
                        );
                        for (name, outcome) in
                            crate::campaign_key_nego::gateway_scenarios(&enrolled, opts.soak).await
                        {
                            played += 1;
                            failures += usize::from(report(name, &outcome));
                        }
                    }
                },
            }
        }
    }

    println!();
    if failures == 0 {
        println!("  {} campaign passed — {played} scenario(s)\n", ok());
        Ok(())
    } else {
        println!(
            "  {} {failures} failure(s) out of {played} scenario(s)\n",
            fail()
        );
        anyhow::bail!("campaign failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::ProvisionRequest;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[derive(Default)]
    struct LoopbackFaults {
        wrong_admission_status: bool,
        leak_private_key: bool,
        accept_plain_text_mutation: bool,
        unstable_vip: bool,
    }

    struct ObservedRequest {
        method: String,
        target: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    async fn read_request(stream: &mut TcpStream) -> ObservedRequest {
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
            let mut chunk = [0; 2048];
            let read = stream.read(&mut chunk).await.expect("read HTTP request");
            assert_ne!(read, 0, "request has complete headers");
            bytes.extend_from_slice(&chunk[..read]);
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).expect("HTTP headers");
        let mut request_line = headers
            .lines()
            .next()
            .expect("request line")
            .split_whitespace();
        let method = request_line.next().expect("HTTP method").to_owned();
        let target = request_line.next().expect("request target").to_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .unwrap_or_default();
        let body_end = header_end + content_length;
        while bytes.len() < body_end {
            let mut chunk = [0; 2048];
            let read = stream.read(&mut chunk).await.expect("read HTTP body");
            assert_ne!(read, 0, "request body is complete");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let content_type = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_owned())
        });
        ObservedRequest {
            method,
            target,
            content_type,
            body: bytes[header_end..body_end].to_vec(),
        }
    }

    async fn respond_json<T: serde::Serialize>(
        stream: &mut TcpStream,
        status: u16,
        reason: &str,
        value: &T,
    ) {
        let body = serde_json::to_vec(value).expect("response JSON");
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        stream
            .write_all(&response)
            .await
            .expect("write HTTP response");
    }

    async fn loopback_gateway(
        admitted_key: String,
        gateway_key: String,
        faults: LoopbackFaults,
    ) -> (String, tokio::task::JoinHandle<Vec<ObservedRequest>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let server = tokio::spawn(async move {
            let mut observed = Vec::new();
            let mut accepted_sessions = 0u8;
            // A protocol-only run performs five admitted provisions, then one
            // unknown-peer provision, one safe API read, and one bad-content
            // type mutation.
            for _ in 0..8 {
                let (mut stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                        .await
                        .expect("campaign request arrived before timeout")
                        .expect("client connection");
                let request = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    read_request(&mut stream),
                )
                .await
                .expect("HTTP request completed before timeout");
                match (request.method.as_str(), request.target.as_str()) {
                    ("POST", "/api/provision") => {
                        let provision: ProvisionRequest =
                            serde_json::from_slice(&request.body).expect("provision JSON");
                        provision.validate().expect("well-formed provision request");
                        assert!(
                            secret_field(&serde_json::from_slice(&request.body).expect("JSON"))
                                .is_none(),
                            "provision request contains no private secret field"
                        );
                        if provision.client_wg_public_key != admitted_key {
                            let status = if faults.wrong_admission_status {
                                401
                            } else {
                                403
                            };
                            let reason = if status == 403 {
                                "Forbidden"
                            } else {
                                "Unauthorized"
                            };
                            respond_json(&mut stream, status, reason, &serde_json::json!({})).await;
                        } else {
                            let mut response =
                                response_for(&provision.kem_public_key, &gateway_key);
                            response.gateway_nonce = [accepted_sessions.wrapping_add(1); 16];
                            if faults.unstable_vip && accepted_sessions == 4 {
                                response.assigned_address = "100.64.1.3/32".into();
                            }
                            accepted_sessions += 1;
                            respond_json(&mut stream, 200, "OK", &response).await;
                        }
                    }
                    ("GET", "/api/network") => {
                        let value = if faults.leak_private_key {
                            serde_json::json!({"peers": [{"private_key": "fixture-only"}]})
                        } else {
                            serde_json::json!({
                                "wg_private_key_configured": true,
                                "peers": [{"preshared_key_configured": true}]
                            })
                        };
                        respond_json(&mut stream, 200, "OK", &value).await;
                    }
                    ("POST", "/api/tunnel/start") => {
                        assert_eq!(request.content_type.as_deref(), Some("text/plain"));
                        assert_eq!(request.body, b"connect");
                        let (status, reason) = if faults.accept_plain_text_mutation {
                            (200, "OK")
                        } else {
                            (415, "Unsupported Media Type")
                        };
                        respond_json(&mut stream, status, reason, &serde_json::json!({})).await;
                    }
                    route => panic!("unexpected campaign request: {route:?}"),
                }
                observed.push(request);
            }
            observed
        });
        (base, server)
    }

    fn protocol_options(client_key: String, gateway_key: String) -> Options {
        Options {
            client_key: Some(client_key),
            gateway_key: Some(gateway_key),
            wg_iface: None,
            only: Some(Category::Protocole),
            repeat: 1,
            profile: None,
            soak: false,
        }
    }

    fn assert_protocol_requests(requests: &[ObservedRequest], admitted_key: &str) {
        assert_eq!(requests.len(), 8);
        for request in &requests[..5] {
            assert_eq!(request.method, "POST");
            assert_eq!(request.target, "/api/provision");
            let provision: ProvisionRequest =
                serde_json::from_slice(&request.body).expect("provision JSON");
            assert_eq!(provision.client_wg_public_key, admitted_key);
            assert_eq!(provision.protocol_version, PROTOCOL_VERSION);
            assert!(secret_field(&serde_json::from_slice(&request.body).expect("JSON")).is_none());
        }
        let unknown: ProvisionRequest =
            serde_json::from_slice(&requests[5].body).expect("unknown-peer provision JSON");
        assert_eq!(requests[5].method, "POST");
        assert_eq!(requests[5].target, "/api/provision");
        assert_ne!(unknown.client_wg_public_key, admitted_key);
        assert!(secret_field(&serde_json::from_slice(&requests[5].body).expect("JSON")).is_none());
        assert_eq!(requests[6].method, "GET");
        assert_eq!(requests[6].target, "/api/network");
        assert_eq!(requests[7].method, "POST");
        assert_eq!(requests[7].target, "/api/tunnel/start");
        assert_eq!(requests[7].content_type.as_deref(), Some("text/plain"));
        assert_eq!(requests[7].body, b"connect");
    }

    #[tokio::test]
    async fn client_only_campaign_runs_without_profile_or_gateway() {
        let client = Client::builder().no_proxy().build().expect("HTTP client");
        let options = Options {
            client_key: None,
            gateway_key: None,
            wg_iface: None,
            only: Some(Category::Client),
            repeat: 1,
            profile: None,
            soak: false,
        };

        run(&client, "http://127.0.0.1:1", options)
            .await
            .expect("offline client scenarios pass without profile keys");
    }

    #[tokio::test]
    async fn protocol_campaign_runs_against_a_loopback_gateway() {
        const PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let admitted_key = public_from_private(PRIVATE).expect("valid client key");
        let gateway_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let (base, server) = loopback_gateway(
            admitted_key.clone(),
            gateway_key.clone(),
            LoopbackFaults::default(),
        )
        .await;
        let client = Client::builder().no_proxy().build().expect("HTTP client");

        run(
            &client,
            &base,
            protocol_options(PRIVATE.into(), gateway_key),
        )
        .await
        .expect("all protocol scenarios pass");

        let requests = server.await.expect("fake gateway task");
        assert_protocol_requests(&requests, &admitted_key);
    }

    #[tokio::test]
    async fn protocol_campaign_reports_gateway_policy_and_api_leaks_as_failures() {
        const PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let admitted_key = public_from_private(PRIVATE).expect("valid client key");
        let gateway_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let (base, server) = loopback_gateway(
            admitted_key.clone(),
            gateway_key.clone(),
            LoopbackFaults {
                wrong_admission_status: true,
                leak_private_key: true,
                accept_plain_text_mutation: true,
                unstable_vip: true,
            },
        )
        .await;
        let client = Client::builder().no_proxy().build().expect("HTTP client");

        assert!(
            run(
                &client,
                &base,
                protocol_options(PRIVATE.into(), gateway_key)
            )
            .await
            .is_err(),
            "wrong admission status, leaked secret, unstable VIP and accepted text mutation fail"
        );

        let requests = server.await.expect("fake gateway task");
        assert_protocol_requests(&requests, &admitted_key);
    }

    #[test]
    fn the_public_key_derives_from_the_private_key_and_is_stable() {
        const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let a = public_from_private(PRIV).unwrap();
        assert_eq!(a.len(), 44, "base64 Curve25519 key");
        assert_eq!(a, public_from_private(PRIV).unwrap(), "stable derivation");
    }

    #[test]
    fn invalid_private_key_is_reported() {
        assert!(public_from_private("not-base64").is_err());
        assert!(public_from_private("AAAA").is_err(), "invalid length");
    }

    /// An incomplete profile must block the network scenarios **before** any
    /// call: a misconfigured campaign must say so, not fail on a timeout.
    #[test]
    fn profile_requires_both_keys() {
        let with_nothing = Options {
            client_key: None,
            gateway_key: None,
            wg_iface: None,
            only: None,
            repeat: 1,
            profile: None,
            soak: false,
        };
        assert!(profile(&with_nothing, "http://x").is_err());

        let without_gateway = Options {
            client_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into()),
            ..with_nothing
        };
        assert!(profile(&without_gateway, "http://x").is_err());
    }

    /// The client scenarios must run without a network: they are the common
    /// base for both dry-run and target.
    #[test]
    fn client_scenarios_detect_a_spoofed_gateway() {
        let profile = ClientProfile {
            name: "t".into(),
            endpoint: "127.0.0.1:51820".into(),
            private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            peer_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            ..ClientProfile::default()
        };
        assert!(matches!(
            scenario_gateway_identity(&profile),
            Outcome::Pass(_)
        ));
        assert!(matches!(
            scenario_malformed_ciphertext(&profile),
            Outcome::Pass(_)
        ));
        assert!(matches!(
            scenario_protocol_version(&profile),
            Outcome::Pass(_)
        ));
    }

    /// The secret detector must distinguish a serialized secret from a mere
    /// presence indicator. Confusing them would make the campaign fail
    /// against a perfectly correct API — exactly what happened to the first
    /// version of this scenario.
    #[test]
    fn presence_indicator_is_not_a_leak() {
        let correct = serde_json::json!({
            "wg_private_key_configured": true,
            "peers": [{ "name": "laptop", "preshared_key_configured": true }]
        });
        assert_eq!(secret_field(&correct), None, "false positive on a boolean");

        let root_leak = serde_json::json!({ "wg_private_key": "AAAA" });
        assert_eq!(secret_field(&root_leak).as_deref(), Some("wg_private_key"));

        // The leak can be nested in an array: the traversal must descend,
        // not just look at the root.
        let nested_leak = serde_json::json!({
            "peers": [{ "name": "laptop", "preshared_key": "secret" }]
        });
        assert_eq!(secret_field(&nested_leak).as_deref(), Some("preshared_key"));
    }

    #[test]
    fn outcome_check_translates_the_condition() {
        assert!(matches!(Outcome::check(true, "d", "e"), Outcome::Pass(_)));
        assert!(matches!(Outcome::check(false, "d", "e"), Outcome::Fail(_)));
    }

    #[test]
    fn private_key_is_detected_at_the_root_and_deep_inside_arrays_and_objects() {
        let at_root = serde_json::json!({"private_key": "secret"});
        assert_eq!(secret_field(&at_root).as_deref(), Some("private_key"));

        // Non-secret array entries before the target ensure the traversal keeps
        // searching; alternating arrays and objects exercises both recursive arms.
        let deeply_nested = serde_json::json!({
            "profiles": [
                {"name": "first", "private_key_configured": true},
                {"items": [{"label": "second"}, {"credentials": {"private_key": "secret"}}]}
            ]
        });
        assert_eq!(secret_field(&deeply_nested).as_deref(), Some("private_key"));
    }

    #[test]
    fn all_secret_presence_indicators_remain_non_leaking() {
        let indicators_only = serde_json::json!({
            "wg_private_key_configured": true,
            "preshared_key_configured": true,
            "private_key_configured": true,
            "nested": [
                {"private_key_configured": false},
                {"preshared_key_configured": true}
            ]
        });
        assert_eq!(secret_field(&indicators_only), None);
    }
}
