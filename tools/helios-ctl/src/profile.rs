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

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Serialize;

use crate::api;

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
    /// Output file. Absent: standard output.
    pub output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Document<'a> {
    format: &'a str,
    version: u16,
    profile: Profile<'a>,
}

/// The `private_key` field is omitted in invitation mode: `orion-core` treats
/// it as absent, not empty, and completes it from the local profile.
#[derive(Serialize)]
struct Profile<'a> {
    name: &'a str,
    endpoint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<&'a str>,
    peer_public_key: &'a str,
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    heliosd_url: Option<String>,
}

pub async fn emit(client: &Client, base: &str, options: EmitOptions) -> Result<()> {
    let (public_key, private_key) = resolve_keys(&options)?;

    let view = api::network(client, base).await?;
    let gateway_public_key = view
        .wg_public_key
        .clone()
        .filter(|k| !k.is_empty())
        .context(
            "the gateway does not have a WireGuard identity yet — run `heliosd init-identity` \
         on the gateway, with console access",
        )?;

    let address = admit_or_reuse(client, base, &options, &public_key).await?;

    let document = Document {
        format: FORMAT,
        version: VERSION,
        profile: Profile {
            name: &options.name,
            endpoint: &options.endpoint,
            private_key: private_key.as_deref(),
            peer_public_key: &gateway_public_key,
            address: &address,
            heliosd_url: heliosd_url(&view.wg_address),
        },
    };
    let json = serde_json::to_string_pretty(&document).context("serializing the profile")?;

    match &options.output {
        Some(path) => {
            // A complete profile carries a private key: it is born at 0600,
            // and never silently replaces an existing file.
            crate::files::write_new(path, json.as_bytes(), private_key.is_some())?;
            report(path, &options, &public_key);
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Picks the mode and returns `(public key, optional private key)`.
fn resolve_keys(options: &EmitOptions) -> Result<(String, Option<String>)> {
    match (&options.public_key, options.with_private_key) {
        (Some(_), true) => bail!(
            "--public-key and --with-private-key are mutually exclusive: either the client \
             already holds its key and supplies its public half, or the operator generates \
             the pair"
        ),
        (Some(public_key), false) => {
            let public_key = public_key.trim().to_string();
            aether::wg::validate_key(&public_key).context("invalid client public key")?;
            Ok((public_key, None))
        }
        (None, true) => {
            let pair = aether::wg::generate_keypair()
                .map_err(|e| anyhow::anyhow!("generating the client key pair: {e}"))?;
            Ok((pair.public_key, Some(pair.private_key.expose().to_string())))
        }
        (None, false) => bail!(
            "provide --public-key <client public key> (recommended: the client's secret never \
             travels), or --with-private-key so the operator generates the pair"
        ),
    }
}

/// Admits the peer, or reuses its admission if it already matches.
///
/// Re-emitting a lost profile is a common need. Without this fallback, the
/// peer would have to be revoked to be re-admitted — cutting off the user to
/// rebuild the file they misplaced.
async fn admit_or_reuse(
    client: &Client,
    base: &str,
    options: &EmitOptions,
    public_key: &str,
) -> Result<String> {
    match crate::peer::admit(client, base, &options.name, public_key, options.admin, None).await {
        Ok(peer) => Ok(peer.address),
        Err(error) => {
            let view = api::network(client, base).await?;
            let existing = view
                .peers
                .iter()
                .find(|peer| peer.name.trim() == options.name.trim())
                .ok_or(error)?;
            if existing.public_key.trim() != public_key {
                bail!(
                    "a peer named \"{}\" is already admitted with a different public key. \
                     Revoke it first (`helios-ctl peer revoke --name {}`) if the old key is \
                     indeed lost: the client holding it will drop at its next handshake.",
                    existing.name,
                    existing.name
                );
            }
            eprintln!(
                "  \x1b[2mpeer already admitted with the same key — profile re-emitted for its address\x1b[0m"
            );
            Ok(existing.address.clone())
        }
    }
}

/// API URL as seen from the tunnel, derived from the gateway address.
///
/// Serves enriched telemetry and the client's post-quantum provisioning.
/// Absent if the address is unreadable: a profile without this URL still
/// works, it only loses the enrichment.
fn heliosd_url(wg_address: &str) -> Option<String> {
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
    if options.with_private_key {
        println!(
            "  \x1b[33mThis file contains the client's private key.\x1b[0m Hand it over through a"
        );
        println!("  controlled channel, then erase it from the operator workstation.");
    } else {
        println!("  \x1b[2mNo private key in this file: Orion completes it from the local\x1b[0m");
        println!("  \x1b[2mprofile of the same name, the one that holds the key.\x1b[0m");
    }
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
            output: None,
        }
    }

    #[test]
    fn invitation_mode_produces_no_private_key() {
        let pair = aether::wg::generate_keypair().unwrap();
        let (public_key, private_key) = resolve_keys(&EmitOptions {
            public_key: Some(pair.public_key.clone()),
            ..options()
        })
        .expect("invitation mode");
        assert_eq!(public_key, pair.public_key);
        assert!(
            private_key.is_none(),
            "the client's secret must not be manufactured by the operator"
        );
    }

    #[test]
    fn assisted_mode_produces_a_consistent_pair() {
        let (public_key, private_key) = resolve_keys(&EmitOptions {
            with_private_key: true,
            ..options()
        })
        .expect("assisted mode");
        let private_key = private_key.expect("generated private key");
        assert_eq!(
            aether::wg::public_from_private(&private_key).unwrap(),
            public_key
        );
    }

    /// The two modes are exclusive: combining them would mean admitting one
    /// key and delivering another, hence a profile that never comes up.
    #[test]
    fn the_two_modes_cannot_be_combined() {
        assert!(resolve_keys(&EmitOptions {
            public_key: Some(aether::wg::generate_keypair().unwrap().public_key),
            with_private_key: true,
            ..options()
        })
        .is_err());
    }

    #[test]
    fn without_an_explicit_mode_the_tool_refuses_rather_than_choosing() {
        let error = resolve_keys(&options()).unwrap_err().to_string();
        assert!(error.contains("--public-key"), "message: {error}");
        assert!(error.contains("--with-private-key"), "message: {error}");
    }

    #[test]
    fn an_invalid_public_key_is_rejected_before_any_call() {
        assert!(resolve_keys(&EmitOptions {
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
            let document = Document {
                format: FORMAT,
                version: VERSION,
                profile: Profile {
                    name: "portable",
                    endpoint: "vpn.example.net:51820",
                    private_key,
                    peer_public_key: &gateway_key.public_key,
                    address: "100.64.1.2/32",
                    heliosd_url: heliosd_url("100.64.0.1/10"),
                },
            };
            let json = serde_json::to_string(&document).unwrap();
            let profile = orion_core::parse_profile_import(&json, "portable.json")
                .expect("document read back by Orion");

            assert_eq!(profile.name, "portable");
            assert_eq!(profile.peer_public_key, gateway_key.public_key);
            assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
            assert_eq!(profile.private_key.is_empty(), private_key.is_none());
        }
    }
}
