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
    profile: Profile<'a>,
}

/// The `private_key` field is omitted in invitation mode: `orion-core` treats
/// it as absent, not empty, and completes it from the local profile.
#[derive(Serialize)]
pub struct Profile<'a> {
    pub name: &'a str,
    pub endpoint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<&'a str>,
    pub peer_public_key: &'a str,
    pub address: &'a str,
    /// Traffic the client routes into the tunnel — one or more CIDR prefixes,
    /// comma-separated.
    ///
    /// Omitted rather than defaulted, because the two are not the same thing:
    /// an absent field lets `orion-core` apply `0.0.0.0/0`, the full tunnel,
    /// which stays the right answer when the operator has said nothing. Only
    /// a split tunnel needs stating, and it is stated **here** so a fleet gets
    /// it from the document rather than from each user retyping prefixes into
    /// the Advanced panel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<&'a str>,
    /// SSH destination inside the tunnel, `user@host`. Omitted = no terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heliosd_url: Option<String>,
    /// Public negotiation settings. Absent when the gateway serves none:
    /// the profile then falls back to the legacy path, whose first handshake
    /// is unprotected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_negotiation: Option<KeyNegotiation>,
    /// Client identity. **Secret** — only `enroll` fills it in, and the file
    /// it produces is born at 0600.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_negotiation_identity: Option<orion_core::ClientIdentityBundle>,
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
pub fn render(profile: Profile<'_>) -> Result<String> {
    let json = serde_json::to_string_pretty(&Document {
        format: FORMAT,
        version: VERSION,
        profile,
    })
    .context("serializing the profile")?;

    orion_core::parse_profile_import(&json, "profile.json")
        .context("the emitted profile is not readable by Orion — this is a tooling bug")?;
    Ok(json)
}

/// Relit un document exactement comme Orion le fera.
///
/// Le même code que l'import client, donc un verdict qui vaut : si cette
/// commande accepte, Orion accepte. Rien n'est affiché du contenu secret —
/// seulement ce qu'il faut pour situer un échec.
pub fn check(path: &Path) -> Result<()> {
    let imported = orion_core::read_profile_import_path(path)
        .with_context(|| format!("relecture de {}", path.display()))?;
    let profile = &imported.profile;

    println!("{} document lisible par Orion", crate::ok());
    println!();
    println!("  profil          : {}", profile.name);
    println!("  endpoint        : {}", profile.endpoint);
    println!(
        "  adresse         : {}",
        profile.address.as_deref().unwrap_or("—")
    );
    // Said whether or not the document stated it: what matters to the reader
    // is what the client will route, and an absent field means the full
    // tunnel — a fact no one should have to know the defaulting rule to learn.
    println!(
        "  trafic capté    : {}{}",
        profile.allowed_ips,
        if profile.allowed_ips == orion_core::DEFAULT_ALLOWED_IPS {
            "  (tunnel complet)"
        } else {
            "  (tunnel fractionné — le reste sort en clair)"
        }
    );
    println!(
        "  API dans tunnel : {}",
        profile
            .heliosd_url
            .as_deref()
            .unwrap_or("— absente : le profil se connecte, mais ne peut pas renouveler")
    );
    // Ce que l'import fera de la clé privée absente est la question qu'on
    // pose le plus souvent à cette commande : la clé admise est ce qui
    // désigne le profil local à compléter, et l'afficher permet de la
    // comparer à ce qu'Orion montre dans « Votre clé publique ».
    match (
        profile.private_key.is_empty(),
        imported.admitted_public_key(),
    ) {
        (false, _) => println!("  clé privée      : présente"),
        (true, Some(admitted)) => println!(
            "  clé privée      : absente — Orion reprendra celle du profil local\n                    portant la clé admise {admitted}"
        ),
        (true, None) => println!(
            "  clé privée      : absente — Orion reprendra celle du profil local de même nom"
        ),
    }

    match &profile.key_negotiation {
        Some(settings) => {
            println!("  négociation     : {:?}", settings.mode);
            println!("  plancher        : {:?}", settings.minimum_mode);
            println!("  endpoint négo   : {}", settings.endpoint);
            println!("  serveur épinglé : {}", settings.server_name);
            println!(
                "  empreinte PQ    : {}",
                settings
                    .gateway_pq_fingerprint()
                    .unwrap_or_else(|| "illisible".into())
            );
            println!("  identité        : {}", settings.identity);
        }
        None => println!("  négociation     : aucune (chemin hérité)"),
    }
    println!(
        "  identité jointe : {}",
        if imported.identity.is_some() {
            "oui — scellée à l'import, détruire le fichier ensuite"
        } else {
            "non"
        }
    );
    Ok(())
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

    let json = render(Profile {
        name: &options.name,
        endpoint: &options.endpoint,
        private_key: private_key.as_deref(),
        peer_public_key: &gateway_public_key,
        address: &address,
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
            allowed_ips: None,
            ssh_target: None,
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
            // `render` itself replays the document through Orion's import:
            // reaching this point already proves the two agree on the format.
            let json = render(Profile {
                name: "portable",
                endpoint: "vpn.example.net:51820",
                private_key,
                peer_public_key: &gateway_key.public_key,
                address: "100.64.1.2/32",
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
                private_key: STANDARD.encode([0x30, 0x81, 0x87, 0x02]),
                pq_certificate: STANDARD.encode(br#"{"version":1}"#),
                pq_private_key: STANDARD.encode([9u8; 64]),
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

    /// Saying nothing is not saying `0.0.0.0/0` — but it must behave that way.
    ///
    /// The field is omitted rather than written out, so an operator reading a
    /// document sees only what was decided. `orion-core` supplies the full
    /// tunnel, which is the safe default: it is that prefix, with the adapter
    /// lifecycle, that makes WireGuard drop packets rather than leak them.
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
            allowed_ips: None,
            ssh_target: None,
            heliosd_url: None,
            key_negotiation: None,
            key_negotiation_identity: None,
        })
        .expect("document read back by Orion");

        assert!(!json.contains("allowed_ips"), "{json}");
        let imported = orion_core::parse_profile_import(&json, "portable.json").unwrap();
        assert_eq!(
            imported.profile.allowed_ips,
            orion_core::DEFAULT_ALLOWED_IPS
        );
    }
}
