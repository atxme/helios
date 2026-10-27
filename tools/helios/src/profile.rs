//! Client profile emission, in the format read by Orion's import.
//!
//! The `orion-profile` v1 document had a consumer
//! (`orion_core::profile_import`) and no producer: the profile had to be
//! hand-copied. This is where the loop closes.
//!
//! # An invitation, for an admitted peer only (ADR-004 §6)
//!
//! The operator starts from the **public** key the client sent them, and the
//! command returns everything except the private key, which the operator
//! never held. Orion completes it from the local profile of the same name.
//!
//! `emit` admits nobody. Admission requires the client's TLS and PQ
//! key-negotiation certificates (floor `ml_kem`), which this command neither
//! issues nor carries: a new Helios client is enrolled from an
//! `astra-signer enroll invite` invitation (NEGOCIATION-DE-CLE-V5 §15), whose
//! signed document `helios enroll document` drafts. A profile emitted for a
//! key the gateway does not know would bring up no tunnel, so such a key is
//! refused. The assisted mode, where the operator generated the pair, is
//! gone: the pair it generated could never be admitted.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use orion_core::enrollment_draft::{tagged, Profile, TaggedProfile};
use orion_core::profile_import::TunnelCapture;
#[cfg(test)]
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
    /// Public key of the admitted client, received out of band.
    pub public_key: Option<String>,
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

/// Renders a classic v1 document, and checks it against the consumer before
/// writing.
///
/// The round-trip through `orion_core::parse_profile_import` is the point:
/// this tool and Orion must agree on the format, and the only way to be sure
/// is to have the actual consumer accept the actual bytes. A document that
/// Orion would refuse must never reach a user's machine.
///
/// A Helios profile is refused here: it travels as a v5 document signed under
/// `CA-PQ` (NEGOCIATION-DE-CLE-V5 §15.3), never as an unsigned v1 one.
pub fn render(profile: Profile<'_>) -> Result<zeroize::Zeroizing<String>> {
    if profile.key_negotiation.is_some() {
        bail!(
            "a Helios profile travels as a signed v5 document: `helios enroll document`, then \
             `astra-signer enroll sign-document`"
        );
    }
    let public = serde_json::to_vec(&Document {
        format: FORMAT,
        version: VERSION,
        profile: tagged(&profile),
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
    // asked of this command.
    out.push_str(
        &match (profile.private_key.is_empty(), &imported.enrollment) {
            (false, _) => ui.field("Private key", "included"),
            (true, Some(_)) => ui.field(
                "Private key",
                "absent — Orion takes it from the enrollment request pending on the client",
            ),
            (true, None) => ui.field(
                "Private key",
                "absent — Orion takes it from the local profile of the same name",
            ),
        },
    );
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
    out.push_str(&match &imported.enrollment {
        Some(document) => ui.field(
            "Signed",
            &format!(
                "v5 · request {} · CA-PQ {} · {}",
                document.request_id,
                document.operator_ca_fingerprint,
                if document.operator_signature.is_some() {
                    "verified by Orion against the CA the client pinned"
                } else {
                    "draft, not signed yet"
                }
            ),
        ),
        None => ui.field("Signed", "no — classic v1 document"),
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
        // A Helios profile is a signed v5 document, which `enroll document`
        // drafts and `astra-signer` signs.
        key_negotiation: None,
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

/// The admitted client's public key, validated before any call.
fn resolve_public_key(options: &EmitOptions) -> Result<String> {
    let Some(public_key) = &options.public_key else {
        bail!(
            "provide --public-key <public key of an admitted client>: `profile emit` re-emits \
             the invitation of a peer the gateway already holds. To enroll a new client, start \
             from `astra-signer enroll invite`"
        );
    };
    let public_key = public_key.trim().to_string();
    aether::wg::validate_key(&public_key).context("invalid client public key")?;
    Ok(public_key)
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
             or enroll it from `astra-signer enroll invite`"
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
            "  Signed        no — classic v1 document\n",
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

    fn admitted(name: &str, public_key: &str) -> NetworkPeerView {
        NetworkPeerView {
            name: name.into(),
            public_key: public_key.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            preshared_key_configured: false,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: Some(aether::key_negotiation::ProtectionMode::MlKem),
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
        assert!(
            error.contains("astra-signer enroll invite"),
            "message: {error}"
        );
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

    #[test]
    fn without_a_public_key_the_tool_refuses_and_points_to_enroll() {
        let error = resolve_public_key(&options()).unwrap_err().to_string();
        assert!(error.contains("--public-key"), "message: {error}");
        assert!(
            error.contains("astra-signer enroll invite"),
            "message: {error}"
        );
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
            assert!(imported.enrollment.is_none(), "emit ships no secret");
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
