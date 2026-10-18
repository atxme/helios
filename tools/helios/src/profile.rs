//! Client profile emission, in the format read by Orion's import.
//!
//! The `orion-profile` v1 document had a consumer
//! (`orion_core::profile_import`) and no producer: the profile had to be
//! hand-copied. This is where the loop closes.
//!
//! # Two modes, and why the default is the right one (ADR-004 §6)
//!
//! * **Invitation** — the operator starts from the **public** key the client
//!   sent them. It admits it and returns everything except the private key,
//!   which the operator never held. Orion completes it from the local
//!   profile of the same name.
//! * **Assisted** (`--with-private-key`) — the operator generates the pair
//!   and hands over a complete profile. This is the only path where a client
//!   private key exists outside the client workstation. It is kept because a
//!   fleet where the user can do nothing themselves really exists, and
//!   forbidding it would just make people redo the same thing by hand, worse.
//!
//! Both modes admit the peer: a profile emitted for a key the gateway does
//! not know would bring up no tunnel, and the user would have no way to
//! understand why.

use std::path::{Path, PathBuf};

use aether::key_negotiation::ProtectionMode;
use anyhow::{bail, Context, Result};
use orion_core::profile_import::TunnelCapture;
use orion_core::ProfileKind;
use reqwest::Client;
use serde::Serialize;

use crate::{
    api::{self, NetworkPeerView},
    ui::{self, Tone, Ui},
};

/// Document identifier and version, as required by `orion-core`.
const FORMAT: &str = "orion-profile";
const VERSION: u16 = 1;

pub struct EmitOptions {
    /// Profile name, also used as the peer name on the gateway.
    pub name: String,
    /// Gateway's public UDP endpoint (`IP:port` or `FQDN:port`).
    pub endpoint: String,
    /// Client public key, received out of band. Invitation mode.
    pub public_key: Option<String>,
    /// Generate the pair on the operator side. Assisted mode.
    pub with_private_key: bool,
    /// Admit the peer as a control-plane administrator.
    pub admin: bool,
    /// Split tunnel to ship with the profile. Absent = full tunnel.
    pub allowed_ips: Option<String>,
    /// SSH destination to ship with the profile. Absent = no terminal button.
    pub ssh_target: Option<String>,
    /// Output file. Absent: standard output.
    pub output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Document<'a> {
    format: &'a str,
    version: u16,
    profile: TaggedProfile<'a>,
}

/// The profile, plus the §19 discriminant [`render`] derives for it.
///
/// Kept out of [`Profile`] on purpose: the kind is not something a caller
/// chooses beside the negotiation block, it is what the presence of that block
/// *means*. Deriving it at the single point that renders a document makes the
/// two impossible to contradict — which is the failure the field exists to
/// stop, and it would be a poor joke to reintroduce it in the emitter.
#[derive(Serialize)]
struct TaggedProfile<'a> {
    #[serde(rename = "type")]
    profile_type: ProfileKind,
    #[serde(flatten)]
    inner: PublicProfile<'a>,
}

/// The `private_key` field is omitted in invitation mode: `orion-core` treats
/// it as absent, not empty, and completes it from the local profile.
pub struct Profile<'a> {
    pub name: &'a str,
    pub endpoint: &'a str,
    pub private_key: Option<&'a str>,
    pub peer_public_key: &'a str,
    pub address: &'a str,
    /// IPv6 VIP, `…/128`, written **only** when the peer has one
    /// (`ADRESSAGE-IPV6.md` §7.2).
    ///
    /// The document is `deny_unknown_fields`: an Orion older than the field
    /// refuses any profile carrying the key, even empty or `null`. Omitting it
    /// for a peer without IPv6 is what keeps the profile of a gateway without
    /// IPv6 readable by every Orion.
    pub address_v6: Option<&'a str>,
    /// Traffic the client routes into the tunnel — one or more CIDR prefixes,
    /// comma-separated.
    ///
    /// Omitted rather than defaulted, because the two are not the same thing:
    /// an absent field lets `orion-core` apply its default full tunnel,
    /// `0.0.0.0/0, ::/0`, which stays the right answer when the operator has
    /// said nothing. Only
    /// a split tunnel needs stating, and it is stated **here** so a fleet gets
    /// it from the document rather than from each user retyping prefixes into
    /// the Advanced panel.
    pub allowed_ips: Option<&'a str>,
    /// SSH destination inside the tunnel, `user@host`. Omitted = no terminal.
    pub ssh_target: Option<&'a str>,
    pub heliosd_url: Option<String>,
    /// Public negotiation settings. Absent when the gateway serves none:
    /// the profile then falls back to the legacy path, whose first handshake
    /// is unprotected.
    pub key_negotiation: Option<KeyNegotiation>,
    /// Client identity. **Secret** — only `enroll` fills it in, and the file
    /// it produces is born at 0600.
    pub key_negotiation_identity: Option<orion_core::ClientIdentityBundle>,
}

/// The serializable half of an emitted profile contains public fields only.
#[derive(Serialize)]
struct PublicProfile<'a> {
    name: &'a str,
    endpoint: &'a str,
    peer_public_key: &'a str,
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_v6: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_ips: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    heliosd_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation: Option<&'a KeyNegotiation>,
}

/// Public negotiation block, as `orion-core` reads it back.
#[derive(Serialize)]
pub struct KeyNegotiation {
    pub mode: ProtectionMode,
    /// Written explicitly even though `orion-core` would default it to
    /// `mode`: a floor that is visible in the document is one an operator can
    /// audit without knowing the defaulting rule.
    pub minimum_mode: ProtectionMode,
    pub endpoint: String,
    pub server_name: String,
    pub gateway_ca_der: String,
    pub gateway_pq_certificate: String,
    pub identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<orion_core::TrustMaterial>,
}

/// Renders the document, and checks it against the consumer before writing.
///
/// The round-trip through `orion_core::parse_profile_import` is the point:
/// this tool and Orion must agree on the format, and the only way to be sure
/// is to have the actual consumer accept the actual bytes. A document that
/// Orion would refuse must never reach a user's machine.
pub fn render(profile: Profile<'_>) -> Result<zeroize::Zeroizing<String>> {
    let profile_type = if profile.key_negotiation.is_some() {
        ProfileKind::HeliosKeyNegotiation
    } else {
        ProfileKind::Classic
    };
    let public = serde_json::to_vec(&Document {
        format: FORMAT,
        version: VERSION,
        profile: TaggedProfile {
            profile_type,
            inner: PublicProfile {
                name: profile.name,
                endpoint: profile.endpoint,
                peer_public_key: profile.peer_public_key,
                address: profile.address,
                address_v6: profile.address_v6,
                allowed_ips: profile.allowed_ips,
                ssh_target: profile.ssh_target,
                heliosd_url: profile.heliosd_url.as_deref(),
                key_negotiation: profile.key_negotiation.as_ref(),
            },
        },
    })
    .context("serializing the public profile fields")?;
    let mut encoded =
        aether::secret::json::SecretJson::new(orion_core::profile_import::MAX_PROFILE_IMPORT_BYTES);
    // The serializer above emits an envelope ending in the two object braces.
    encoded.append(&public[..public.len() - 2])?;
    if let Some(private_key) = profile.private_key {
        encoded.append(b",\"private_key\":")?;
        encoded.secret_str(private_key)?;
    }
    if let Some(identity) = &profile.key_negotiation_identity {
        encoded.append(b",\"key_negotiation_identity\":")?;
        encoded.append(&identity.encode()?)?;
    }
    encoded.append(b"}}")?;
    let json = encoded.finish_string()?;
    orion_core::parse_profile_import(&json, "profile.json")
        .context("the emitted profile is not readable by Orion — this is a tooling bug")?;
    Ok(json)
}

/// Reads a document exactly as Orion will.
///
/// The same code as the client's import, so the verdict holds: if this
/// command accepts it, Orion accepts it. Nothing secret is printed — only
/// what it takes to locate a failure.
pub fn check(path: &Path) -> Result<()> {
    let imported = orion_core::read_profile_import_path(path)
        .with_context(|| format!("reading {}", path.display()))?;
    print!("{}", render_check(&Ui::detect(), path, &imported));
    Ok(())
}

fn render_check(ui: &Ui, path: &Path, imported: &orion_core::ProfileImport) -> String {
    let profile = &imported.profile;
    let mut out = ui.done(&format!("Readable by Orion  {}", path.display()));
    out.push('\n');
    out.push_str(&ui.field("Profile", &profile.name));
    out.push_str(&ui.field("Endpoint", &profile.endpoint));
    out.push_str(&match profile.address.as_deref() {
        Some(address) => ui.field("Address", address),
        None => ui.field_toned("Address", "not set", Tone::Dim),
    });
    // Only when present: a document without it is an IPv4-only profile.
    if let Some(address_v6) = profile.address_v6.as_deref() {
        out.push_str(&ui.field(
            "IPv6 address",
            &format!("{address_v6} · older Orion releases refuse this profile"),
        ));
    }
    // Said whether or not the document stated it: what matters is what the
    // client will route, and an absent field means the full tunnel.
    let capture = capture_label(&profile.allowed_ips);
    out.push_str(&ui.field_toned(
        "Routes",
        &format!("{} · {capture}", profile.allowed_ips),
        if matches!(
            orion_core::profile_import::tunnel_capture(&profile.allowed_ips),
            TunnelCapture::Full
        ) {
            Tone::Plain
        } else {
            Tone::Warn
        },
    ));
    out.push_str(&match profile.heliosd_url.as_deref() {
        Some(url) => ui.field("Tunnel API", url),
        None => ui.field_toned(
            "Tunnel API",
            "missing — the profile connects but cannot renew",
            Tone::Warn,
        ),
    });
    // What the import does with an absent private key is the question most
    // asked of this command: the admitted key names the local profile it
    // completes, to compare with what Orion shows as "Your public key".
    out.push_str(&match (
        profile.private_key.is_empty(),
        imported.admitted_public_key(),
    ) {
        (false, _) => ui.field("Private key", "included"),
        (true, Some(admitted)) => ui.field(
            "Private key",
            &format!("absent — Orion takes it from the local profile holding key {admitted}"),
        ),
        (true, None) => ui.field(
            "Private key",
            "absent — Orion takes it from the local profile of the same name",
        ),
    });
    match &profile.key_negotiation {
        Some(settings) => {
            out.push_str(&ui.field(
                "Negotiation",
                &format!(
                    "{} (minimum {}) · {} · server {}",
                    ui::protection_mode(settings.mode),
                    ui::protection_mode(settings.minimum_mode),
                    settings.endpoint,
                    settings.server_name
                ),
            ));
            out.push_str(&match settings.gateway_pq_fingerprint() {
                Some(fingerprint) => ui.field("PQ pin", &format!("sha256 {fingerprint}")),
                None => ui.field_toned("PQ pin", "unreadable", Tone::Bad),
            });
            out.push_str(&ui.field("Identity", &settings.identity));
        }
        None => out.push_str(&ui.field_toned("Negotiation", "none (legacy path)", Tone::Warn)),
    }
    out.push_str(&if imported.identity.is_some() {
        ui.field_toned(
            "Bundled id",
            "yes — sealed on import; destroy the file afterwards",
            Tone::Warn,
        )
    } else {
        ui.field("Bundled id", "no")
    });
    out
}

/// What a document's `AllowedIPs` leaves outside the tunnel, in words.
///
/// Classified by `orion-core`, the same rule the Orion screen warns with: a
/// document that captures `0.0.0.0/0` alone was a full tunnel before `::/0`
/// joined the default, and calling it one still would tell the operator that
/// a client leaking all of its IPv6 is protected.
fn capture_label(allowed_ips: &str) -> &'static str {
    match orion_core::profile_import::tunnel_capture(allowed_ips) {
        TunnelCapture::Full => "full tunnel",
        TunnelCapture::Ipv4Only => "IPv4-only full tunnel: IPv6 traffic leaves unencrypted",
        TunnelCapture::Partial => "split tunnel: everything else leaves unencrypted",
    }
}

pub async fn emit(client: &Client, base: &str, options: EmitOptions) -> Result<()> {
    let public_key = resolve_public_key(&options)?;
    refuse_admission_options(&options)?;

    let view = api::network(client, base).await?;
    let gateway_public_key = view
        .wg_public_key
        .clone()
        .filter(|k| !k.is_empty())
        .context(
            "the gateway does not have a WireGuard identity yet — run `heliosd init-identity` \
         on the gateway, with console access",
        )?;

    let address = reuse_admission(&view.peers, &options.name, &public_key)?;
    eprintln!("  \x1b[2mpeer admitted with this key — profile emitted for its address\x1b[0m");
    let address_v6 = admitted_address_v6(&view, &options.name, &public_key, &address)?;

    let json = render(Profile {
        name: &options.name,
        endpoint: &options.endpoint,
        private_key: None,
        peer_public_key: &gateway_public_key,
        address: &address,
        address_v6: address_v6.as_deref(),
        allowed_ips: options.allowed_ips.as_deref(),
        ssh_target: options.ssh_target.as_deref(),
        heliosd_url: heliosd_url(&view.wg_address),
        // `emit` never ships an identity: it is the path that keeps the
        // document free of secrets. Wiring the negotiation from here would
        // therefore hand out a profile whose connection fails for lack of a
        // certificate — `enroll` is the command that does both at once.
        key_negotiation: None,
        key_negotiation_identity: None,
    })?;

    match &options.output {
        Some(path) => {
            // An invitation carries no secret; it still never silently
            // replaces an existing file.
            crate::files::write_new(path, json.as_bytes(), false)?;
            report(path, &options, &public_key);
        }
        None => println!("{}", json.as_str()),
    }
    Ok(())
}

/// The client's public key, the only mode left.
///
/// `emit` admits nobody: admission requires the client's TLS and PQ
/// key-negotiation certificates (floor `ml_kem`), which this command neither
/// issues nor carries. The assisted mode generated a pair the gateway had
/// never seen, so it could only ever be refused there; it is refused here,
/// before any call, with the command that issues keys, certificates,
/// admission and profile at once.
fn resolve_public_key(options: &EmitOptions) -> Result<String> {
    if options.with_private_key {
        bail!(
            "--with-private-key is refused: it generated a pair the gateway had never admitted, \
             and admission now requires the client's key-negotiation certificates. To enroll \
             a new client, `helios enroll` issues its keys, certificates, admission and \
             profile at once"
        );
    }
    let Some(public_key) = &options.public_key else {
        bail!(
            "provide --public-key <public key of an admitted client>: `profile emit` re-emits \
             the invitation of a peer the gateway already holds. To enroll a new client, use \
             `helios enroll`"
        );
    };
    let public_key = public_key.trim().to_string();
    aether::wg::validate_key(&public_key).context("invalid client public key")?;
    Ok(public_key)
}

/// Refuses the options that only meant something when `emit` admitted the
/// peer: silently ignored, they would hand out a profile that is not the one
/// asked for.
fn refuse_admission_options(options: &EmitOptions) -> Result<()> {
    if options.admin {
        bail!(
            "--admin is refused: `profile emit` admits nobody, and the role is chosen at \
             admission — `helios peer add --admin` with the client's key-negotiation \
             certificates, or `helios enroll --admin`"
        );
    }
    Ok(())
}

/// The persisted address of the peer named `name`, which must hold
/// `public_key`.
///
/// Re-emitting a lost invitation is the need this command still serves:
/// without it, the peer would have to be revoked and re-admitted — cutting
/// off the user to rebuild the file they misplaced.
fn reuse_admission(peers: &[NetworkPeerView], name: &str, public_key: &str) -> Result<String> {
    let Some(existing) = peers.iter().find(|peer| peer.name.trim() == name.trim()) else {
        bail!(
            "no peer named \"{name}\" is admitted, and `profile emit` admits nobody: \
             admission requires the client's key-negotiation certificates. Admit it with \
             `helios peer add --name {name} --public-key <key> \
             --key-negotiation-certificate-sha256 <sha256> \
             --key-negotiation-pq-certificate-sha256 <sha256>`, then re-run this command; \
             or enroll it in one go with `helios enroll`"
        );
    };
    if existing.public_key.trim() != public_key {
        bail!(
            "a peer named \"{}\" is already admitted with a different public key. \
             Revoke it first (`helios peer revoke --name {}`) if the old key is \
             indeed lost: the client holding it will drop at its next handshake.",
            existing.name,
            existing.name
        );
    }
    Ok(existing.address.clone())
}

/// The IPv6 VIP the gateway persisted for the peer just admitted, if any.
///
/// Read from `GET /api/network`, the view of `network.toml`, because the
/// admission answer carries the IPv4 VIP only. The peer is matched by name
/// **and** key, and its IPv4 VIP must be the one admission returned: a view
/// that disagrees is a gateway that changed in between, and emitting a
/// profile from it would mix two records. A blank value is no value — the key
/// is never written empty.
pub(crate) fn admitted_address_v6(
    view: &api::NetworkConfigView,
    name: &str,
    public_key: &str,
    address: &str,
) -> Result<Option<String>> {
    let peer = view
        .peers
        .iter()
        .find(|peer| peer.name.trim() == name.trim() && peer.public_key.trim() == public_key)
        .with_context(|| {
            format!(
                "peer \"{name}\" was admitted but is absent from the gateway's network view — \
                 re-run the command"
            )
        })?;
    if peer.address != address {
        bail!(
            "the gateway's network view gives peer \"{name}\" the address {}, while admission \
             returned {address} — re-run the command",
            peer.address
        );
    }
    Ok(peer
        .address_v6
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

/// API URL as seen from the tunnel, derived from the gateway address.
///
/// Serves enriched telemetry and the client's post-quantum provisioning.
/// Absent if the address is unreadable: a profile without this URL still
/// works, it only loses the enrichment.
pub fn heliosd_url(wg_address: &str) -> Option<String> {
    let host = wg_address.split('/').next()?.trim();
    host.parse::<std::net::Ipv4Addr>().ok()?;
    Some(format!("http://{host}:{}", aether::API_PORT))
}

fn report(path: &Path, options: &EmitOptions, public_key: &str) {
    println!(
        "{} profile \"{}\" written to {}",
        crate::ok(),
        options.name,
        path.display()
    );
    println!();
    println!("  \x1b[2mNo private key in this file: Orion completes it from the local\x1b[0m");
    println!("  \x1b[2mprofile of the same name, the one that holds the key.\x1b[0m");
    println!();
    println!("  \x1b[2mAdmitted public key: {public_key}\x1b[0m");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> EmitOptions {
        EmitOptions {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            public_key: None,
            with_private_key: false,
            admin: false,
            allowed_ips: None,
            ssh_target: None,
            output: None,
        }
    }

    #[test]
    fn check_reads_in_english_and_flags_what_needs_attention() {
        let pair = aether::wg::generate_keypair().unwrap();
        let json = render(Profile {
            name: "laptop",
            endpoint: "vpn.example.net:51820",
            private_key: None,
            peer_public_key: &pair.public_key,
            address: "100.64.1.9/32",
            address_v6: None,
            allowed_ips: Some("10.0.0.0/8"),
            ssh_target: None,
            heliosd_url: None,
            key_negotiation: None,
            key_negotiation_identity: None,
        })
        .unwrap();
        let imported = orion_core::parse_profile_import(&json, "laptop.orion").unwrap();
        let text = render_check(&Ui::plain(None), Path::new("laptop.orion"), &imported);
        assert!(
            text.starts_with("  ✓ Readable by Orion  laptop.orion\n"),
            "{text}"
        );
        for expected in [
            "  Profile       laptop\n",
            "  Address       100.64.1.9/32\n",
            "  Routes        10.0.0.0/8 · split tunnel: everything else leaves unencrypted\n",
            "  Tunnel API    missing — the profile connects but cannot renew\n",
            "  Negotiation   none (legacy path)\n",
            "  Bundled id    no\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        for french in ["lisible", "clé", "absente", "trafic"] {
            assert!(!text.contains(french), "{text}");
        }
    }

    #[test]
    fn invitation_mode_produces_no_private_key() {
        let pair = aether::wg::generate_keypair().unwrap();
        let public_key = resolve_public_key(&EmitOptions {
            public_key: Some(pair.public_key.clone()),
            ..options()
        })
        .expect("invitation mode");
        assert_eq!(public_key, pair.public_key);
    }

    /// The assisted mode generated a pair the gateway had never seen, so it
    /// had to admit it — without negotiation certificates, which the `ml_kem`
    /// admission floor refuses every time. It is refused here, before any
    /// call, and the message names the command that does both at once.
    #[test]
    fn assisted_mode_is_refused_and_points_to_enroll() {
        let error = resolve_public_key(&EmitOptions {
            with_private_key: true,
            ..options()
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("helios enroll"), "message: {error}");
        assert!(error.contains("certificates"), "message: {error}");
    }

    fn admitted(name: &str, public_key: &str) -> NetworkPeerView {
        NetworkPeerView {
            name: name.into(),
            public_key: public_key.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            preshared_key_configured: false,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::MlKem,
            admin: false,
        }
    }

    /// `emit` admits nobody: a key the gateway does not know is refused, and
    /// the message names the two ways a client is admitted.
    #[test]
    fn an_unadmitted_key_is_refused_with_the_admission_commands() {
        let key = aether::wg::generate_keypair().unwrap().public_key;
        let error = reuse_admission(&[], "portable", &key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("helios peer add"), "message: {error}");
        assert!(
            error.contains("--key-negotiation-pq-certificate-sha256"),
            "message: {error}"
        );
        assert!(error.contains("helios enroll"), "message: {error}");
    }

    #[test]
    fn an_admitted_key_reuses_its_persisted_address() {
        let key = aether::wg::generate_keypair().unwrap().public_key;
        assert_eq!(
            reuse_admission(&[admitted("portable", &key)], "portable", &key).unwrap(),
            "100.64.1.2/32"
        );
    }

    #[test]
    fn a_name_admitted_with_another_key_is_refused() {
        let admitted_key = aether::wg::generate_keypair().unwrap().public_key;
        let other_key = aether::wg::generate_keypair().unwrap().public_key;
        let error = reuse_admission(
            &[admitted("portable", &admitted_key)],
            "portable",
            &other_key,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("different public key"), "message: {error}");
    }

    /// `--admin` chose the role of the peer `emit` admitted. Now that it
    /// admits nobody, ignoring the flag would hand out a profile whose role
    /// is not the one asked for: it is refused, pointing to the admission.
    #[test]
    fn the_admin_role_is_refused_since_emit_admits_nobody() {
        let error = refuse_admission_options(&EmitOptions {
            admin: true,
            public_key: Some(aether::wg::generate_keypair().unwrap().public_key),
            ..options()
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("--admin"), "message: {error}");
        assert!(error.contains("helios peer add"), "message: {error}");
    }

    /// The two modes are exclusive: combining them would mean admitting one
    /// key and delivering another, hence a profile that never comes up.
    #[test]
    fn the_two_modes_cannot_be_combined() {
        assert!(resolve_public_key(&EmitOptions {
            public_key: Some(aether::wg::generate_keypair().unwrap().public_key),
            with_private_key: true,
            ..options()
        })
        .is_err());
    }

    #[test]
    fn without_a_public_key_the_tool_refuses_and_points_to_enroll() {
        let error = resolve_public_key(&options()).unwrap_err().to_string();
        assert!(error.contains("--public-key"), "message: {error}");
        assert!(error.contains("helios enroll"), "message: {error}");
        assert!(!error.contains("--with-private-key"), "message: {error}");
    }

    #[test]
    fn an_invalid_public_key_is_rejected_before_any_call() {
        assert!(resolve_public_key(&EmitOptions {
            public_key: Some("not-a-key".into()),
            ..options()
        })
        .is_err());
    }

    #[test]
    fn the_api_url_is_derived_from_the_gateway_address() {
        assert_eq!(
            heliosd_url("100.64.0.1/10").as_deref(),
            Some("http://100.64.0.1:8080")
        );
        assert_eq!(heliosd_url("not-an-address").as_deref(), None);
    }

    /// The emitted document must be readable back by Orion's import: that is
    /// the only criterion that matters, and checking it here avoids a manual
    /// round trip.
    #[test]
    fn the_emitted_document_is_read_back_by_orion_import() {
        let client_key = aether::wg::generate_keypair().unwrap();
        let gateway_key = aether::wg::generate_keypair().unwrap();

        for private_key in [None, Some(client_key.private_key.expose())] {
            // `render` itself replays the document through Orion's import:
            // reaching this point already proves the two agree on the format.
            let json = render(Profile {
                name: "portable",
                endpoint: "vpn.example.net:51820",
                private_key,
                peer_public_key: &gateway_key.public_key,
                address: "100.64.1.2/32",
                address_v6: None,
                allowed_ips: None,
                ssh_target: None,
                heliosd_url: heliosd_url("100.64.0.1/10"),
                key_negotiation: None,
                key_negotiation_identity: None,
            })
            .expect("document read back by Orion");
            let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();

            assert_eq!(imported.profile.name, "portable");
            assert_eq!(imported.profile.peer_public_key, gateway_key.public_key);
            assert_eq!(imported.profile.address.as_deref(), Some("100.64.1.2/32"));
            assert_eq!(
                imported.profile.private_key.is_empty(),
                private_key.is_none()
            );
            assert!(imported.identity.is_none(), "emit ships no secret");
            assert_eq!(
                imported.profile.profile_type,
                Some(ProfileKind::Classic),
                "a document with no negotiation block says so, rather than \
                 leaving the reader to infer it"
            );
            let document: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(
                document["profile"]["type"], "classic",
                "the field is spelled `type`, as the specification writes it"
            );
        }
    }

    /// The full `enroll` document — profile, negotiation block and identity —
    /// must be read back by Orion in one go.
    ///
    /// This is the contract that actually matters: the tooling and the client
    /// are two binaries that never meet, and a disagreement on this document
    /// would only surface on a user's machine, as a profile that imports and
    /// never connects.
    #[test]
    fn the_enrollment_document_is_read_back_whole() {
        use aether::key_negotiation::{
            generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
            PQ_CERTIFICATE_VERSION,
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let client_key = aether::wg::generate_keypair().unwrap();
        let gateway_key = aether::wg::generate_keypair().unwrap();
        let (gateway_pq_private, gateway_pq_public) = generate_ml_dsa_87_keypair().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let gateway_certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3u8; 16],
                subject: "vpn.example.net".into(),
                issuer: "vpn.example.net".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key.public_key.clone(),
                ml_dsa_87_public_key: STANDARD.encode(&gateway_pq_public),
                not_before_unix: now - 60,
                not_after_unix: now + 3600,
                ml_dsa_87_signature: String::new(),
            },
            &gateway_pq_private,
        )
        .unwrap();

        let json = render(Profile {
            name: "portable",
            endpoint: "vpn.example.net:51820",
            private_key: Some(client_key.private_key.expose()),
            peer_public_key: &gateway_key.public_key,
            address: "100.64.1.2/32",
            address_v6: None,
            allowed_ips: Some("100.64.0.0/10, 192.168.1.0/24"),
            ssh_target: Some("christophe@100.64.0.1"),
            heliosd_url: heliosd_url("100.64.0.1/10"),
            key_negotiation: Some(KeyNegotiation {
                mode: ProtectionMode::MlKem,
                minimum_mode: ProtectionMode::MlKem,
                endpoint: "vpn.example.net:51821".into(),
                server_name: "vpn.example.net".into(),
                gateway_ca_der: STANDARD.encode([0x30, 0x82, 0x01, 0x00]),
                gateway_pq_certificate: STANDARD
                    .encode(serde_json::to_vec(&gateway_certificate).unwrap()),
                identity: "orion-portable".into(),
                trust: None,
            }),
            key_negotiation_identity: Some(orion_core::ClientIdentityBundle {
                identity: "orion-portable".into(),
                certificate_chain: vec![STANDARD.encode([0x30, 0x82, 0x02, 0x00])],
                private_key: STANDARD.encode([0x30, 0x81, 0x87, 0x02]).into(),
                pq_certificate: STANDARD.encode(br#"{"version":1}"#),
                pq_private_key: STANDARD.encode([9u8; 64]).into(),
            }),
        })
        .expect("enrollment document read back by Orion");

        let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();
        let settings = imported.profile.key_negotiation.expect("negotiation block");
        assert_eq!(settings.mode, ProtectionMode::MlKem);
        assert_eq!(settings.minimum_mode, ProtectionMode::MlKem);
        assert_eq!(settings.identity, "orion-portable");
        // The pinned certificate must verify against the gateway key the
        // profile talks to — that check is the whole reason it is shipped.
        assert!(settings.gateway_pq_fingerprint().is_some());
        assert_eq!(
            imported.identity.expect("identity shipped").identity,
            "orion-portable"
        );
        // A split tunnel stated by the operator reaches the client through the
        // document. Without this field it did not: every user had to retype
        // the prefixes into the Advanced panel, and a fleet ended up with as
        // many routing tables as it had people.
        assert_eq!(
            imported.profile.allowed_ips,
            "100.64.0.0/10, 192.168.1.0/24"
        );
    }

    /// Saying nothing is not saying `0.0.0.0/0, ::/0` — but it must behave that
    /// way.
    ///
    /// The field is omitted rather than written out, so an operator reading a
    /// document sees only what was decided. `orion-core` supplies the full
    /// tunnel, which is the safe default: it is that capture, in both
    /// families, with the adapter lifecycle, that makes WireGuard drop packets
    /// rather than leak them.
    #[test]
    fn an_omitted_split_tunnel_becomes_the_full_tunnel_on_the_client() {
        let client_key = aether::wg::generate_keypair().unwrap();
        let gateway_key = aether::wg::generate_keypair().unwrap();

        let json = render(Profile {
            name: "portable",
            endpoint: "vpn.example.net:51820",
            private_key: Some(client_key.private_key.expose()),
            peer_public_key: &gateway_key.public_key,
            address: "100.64.1.2/32",
            address_v6: None,
            allowed_ips: None,
            ssh_target: None,
            heliosd_url: None,
            key_negotiation: None,
            key_negotiation_identity: None,
        })
        .expect("document read back by Orion");

        assert!(!json.contains("allowed_ips"), "{}", json.as_str());
        let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();
        assert_eq!(imported.profile.allowed_ips, "0.0.0.0/0, ::/0");
        assert_eq!(capture_label(&imported.profile.allowed_ips), "full tunnel");
    }

    fn document(address_v6: Option<&str>) -> zeroize::Zeroizing<String> {
        let client_key = aether::wg::generate_keypair().unwrap();
        let gateway_key = aether::wg::generate_keypair().unwrap();
        render(Profile {
            name: "portable",
            endpoint: "vpn.example.net:51820",
            private_key: Some(client_key.private_key.expose()),
            peer_public_key: &gateway_key.public_key,
            address: "100.64.1.2/32",
            address_v6,
            allowed_ips: None,
            ssh_target: None,
            heliosd_url: heliosd_url("100.64.0.1/10"),
            key_negotiation: None,
            key_negotiation_identity: None,
        })
        .expect("document read back by Orion")
    }

    /// A peer without IPv6 gets a document without the key — not an empty
    /// one, not a `null`: an Orion older than the field refuses either, and
    /// the profile of a gateway without IPv6 must stay readable by all
    /// (`ADRESSAGE-IPV6.md` §7.2, §8).
    #[test]
    fn a_peer_without_ipv6_gets_no_address_v6_key() {
        let json = document(None);
        assert!(!json.contains("address_v6"), "{}", json.as_str());
        let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();
        assert_eq!(imported.profile.address_v6, None);
    }

    #[test]
    fn a_peer_with_ipv6_gets_both_addresses() {
        let json = document(Some("fd3c:91a2:7e04::2/128"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["profile"]["address_v6"], "fd3c:91a2:7e04::2/128");
        let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();
        assert_eq!(imported.profile.address.as_deref(), Some("100.64.1.2/32"));
        assert_eq!(
            imported.profile.address_v6.as_deref(),
            Some("fd3c:91a2:7e04::2/128")
        );
    }

    fn view(peers: serde_json::Value) -> api::NetworkConfigView {
        serde_json::from_value(serde_json::json!({
            "wan_ifaces": ["eth0"],
            "lan_ifaces": [],
            "allow_ssh_from": [],
            "admin_iface": "helios0",
            "wg_iface": "helios0",
            "wg_private_key_configured": true,
            "wg_public_key": "gateway-public",
            "wg_address": "100.64.0.1/10",
            "wg_listen_port": 51820,
            "key_negotiation_port": 51821,
            "peers": peers,
        }))
        .unwrap()
    }

    fn peer(address_v6: serde_json::Value) -> serde_json::Value {
        let mut peer = serde_json::json!({
            "name": "portable",
            "public_key": "client-public",
            "address": "100.64.1.2/32",
            "preshared_key_configured": false,
            "key_negotiation_certificate_sha256": null,
            "key_negotiation_pq_certificate_sha256": null,
            "minimum_key_negotiation_mode": "ml_kem",
            "admin": false
        });
        if !address_v6.is_null() {
            peer["address_v6"] = address_v6;
        }
        peer
    }

    #[test]
    fn the_ipv6_vip_is_read_from_the_record_of_the_admitted_peer() {
        let read =
            |peers| admitted_address_v6(&view(peers), "portable", "client-public", "100.64.1.2/32");
        assert_eq!(
            read(serde_json::json!([peer("fd3c:91a2:7e04::2/128".into())])).unwrap(),
            Some("fd3c:91a2:7e04::2/128".into())
        );
        // A gateway without IPv6, or older than the field, and an explicit
        // `null`: no address, so no key.
        assert_eq!(
            read(serde_json::json!([peer(serde_json::Value::Null)])).unwrap(),
            None
        );
        let mut explicit_null = peer(serde_json::Value::Null);
        explicit_null["address_v6"] = serde_json::Value::Null;
        assert_eq!(read(serde_json::json!([explicit_null])).unwrap(), None);
        // Never written empty.
        assert_eq!(read(serde_json::json!([peer("  ".into())])).unwrap(), None);
    }

    #[test]
    fn a_view_that_disagrees_with_the_admission_is_refused() {
        let mut moved = peer("fd3c:91a2:7e04::2/128".into());
        moved["address"] = "100.64.1.9/32".into();
        let error = admitted_address_v6(
            &view(serde_json::json!([moved])),
            "portable",
            "client-public",
            "100.64.1.2/32",
        )
        .unwrap_err();
        assert!(error.to_string().contains("100.64.1.9/32"), "{error}");

        let mut other_key = peer(serde_json::Value::Null);
        other_key["public_key"] = "someone-else".into();
        assert!(admitted_address_v6(
            &view(serde_json::json!([other_key])),
            "portable",
            "client-public",
            "100.64.1.2/32"
        )
        .is_err());
    }

    /// The old full tunnel is not called a full tunnel any more.
    ///
    /// `0.0.0.0/0` alone leaves IPv6 outside: labelled "full tunnel", a
    /// client leaking all of its IPv6 would read as protected to the operator
    /// checking its document. A narrowed list keeps its own label.
    #[test]
    fn the_capture_label_names_an_ipv4_only_full_tunnel() {
        assert_eq!(
            capture_label("0.0.0.0/0"),
            "IPv4-only full tunnel: IPv6 traffic leaves unencrypted"
        );
        assert_eq!(capture_label("0.0.0.0/0, ::/0"), "full tunnel");
        // Order is not a decision: the same two prefixes are the same tunnel.
        assert_eq!(capture_label("::/0, 0.0.0.0/0"), "full tunnel");
        assert_eq!(
            capture_label("100.64.0.0/10, 192.168.1.0/24"),
            "split tunnel: everything else leaves unencrypted"
        );
        assert_eq!(
            capture_label("::/0"),
            "split tunnel: everything else leaves unencrypted"
        );
    }
}
