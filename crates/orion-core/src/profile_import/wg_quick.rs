//! The single-peer `wg-quick` format, and what Orion does with the
//! properties it does not apply.

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::{ClientProfile, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

use super::field_rules::split_interface_address;
use super::ProfileKind;

#[derive(Clone, Copy, PartialEq, Eq)]
enum WgSection {
    Interface,
    Peer,
}

/// A wg-quick file, read into a profile plus what was dropped along the way.
pub(super) struct WgQuickImport {
    pub(super) profile: ClientProfile,
    pub(super) notices: Vec<String>,
}

/// wg-quick properties Orion reads and applies.
const WG_APPLIED_INTERFACE: &[&str] = &["privatekey", "address"];
const WG_APPLIED_PEER: &[&str] = &[
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
];

/// Properties Orion understands, does not apply, and **says so**.
///
/// Refusing the file over these was the wrong trade: they appear in almost
/// every configuration a provider hands out, and a client that cannot open a
/// normal WireGuard file is not a WireGuard client. Dropping them silently is
/// the other wrong trade — a `DNS` line that vanishes takes name resolution
/// with it, and the user sees a tunnel that works and a browser that does not.
///
/// So each one is imported as a notice naming the consequence.
fn wg_unapplied_notice(field: &str, value: &str) -> Option<String> {
    let value = value.trim();
    Some(match field {
        // Orion does not tunnel DNS at all — the same documented limit the
        // gateway's ruleset carries. Naming it here is the only chance the
        // user has to learn it before the queries leave in the clear.
        "dns" => format!(
            "DNS = {value} : Orion n'applique pas de serveur DNS et ne tunnelise pas les \
             requêtes de résolution ; elles sortiront hors du tunnel."
        ),
        "mtu" => format!(
            "MTU = {value} : Orion laisse l'adaptateur choisir son MTU. Un chemin qui exigeait \
             cette valeur peut fragmenter."
        ),
        "table" => {
            format!("Table = {value} : Orion pose ses routes lui-même, à partir du trafic capté.")
        }
        "listenport" => {
            format!("ListenPort = {value} : Orion laisse le système attribuer le port source.")
        }
        "fwmark" => format!("FwMark = {value} : Orion ne marque pas ses paquets."),
        _ => return None,
    })
}

/// Properties Orion refuses, because they run something.
///
/// A `PostUp` is a shell command the configuration depends on — a firewall
/// rule, a route, a resolver swap. Orion will not execute it, and importing
/// the file **without** it would produce a tunnel the author never described.
/// This is the one class where refusing is right: the alternative is a profile
/// that looks identical and behaves differently.
fn wg_executable_field(field: &str) -> bool {
    matches!(
        field,
        "preup" | "postup" | "predown" | "postdown" | "saveconfig"
    )
}

pub(super) fn parse_wg_quick(contents: &str, file_name: &str) -> Result<WgQuickImport> {
    let mut section = None;
    let mut interface = HashMap::new();
    let mut peer = HashMap::new();
    let mut interface_count = 0_u8;
    let mut peer_count = 0_u8;

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    interface_count += 1;
                    if interface_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : une seule section [Interface] est autorisée"
                        );
                    }
                    Some(WgSection::Interface)
                }
                "peer" => {
                    peer_count += 1;
                    if peer_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : Orion accepte un seul pair par profil"
                        );
                    }
                    Some(WgSection::Peer)
                }
                other => anyhow::bail!("ligne {line_number} : section [{other}] inconnue"),
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            anyhow::bail!("ligne {line_number} : propriété WireGuard mal formée");
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim().to_string();
        let fields = match section {
            Some(WgSection::Interface) => &mut interface,
            Some(WgSection::Peer) => &mut peer,
            None => {
                anyhow::bail!("ligne {line_number} : propriété placée avant [Interface] ou [Peer]")
            }
        };
        if fields.insert(key.clone(), value).is_some() {
            anyhow::bail!("ligne {line_number} : propriété {key} déclarée plusieurs fois");
        }
    }

    if peer_count == 0 {
        anyhow::bail!("section [Peer] absente du fichier WireGuard");
    }
    if interface_count == 0 {
        anyhow::bail!("section [Interface] absente du fichier WireGuard");
    }
    let mut notices = Vec::new();
    classify_wg_fields(
        &interface,
        WG_APPLIED_INTERFACE,
        "[Interface]",
        &mut notices,
    )?;
    classify_wg_fields(&peer, WG_APPLIED_PEER, "[Peer]", &mut notices)?;

    let keepalive = match peer.get("persistentkeepalive") {
        Some(raw) => raw
            .parse::<u16>()
            .context("PersistentKeepalive doit être un entier entre 0 et 65535")?,
        None => DEFAULT_KEEPALIVE_SECS,
    };

    // `Address = 100.64.1.2/32, fd…/128` is one address per family: each
    // lands in its own field, and anything that would leave a choice to make
    // is refused by name rather than resolved.
    let (address, address_v6) = match interface.get("address") {
        Some(value) => split_interface_address(value)?,
        None => (None, None),
    };

    let profile = ClientProfile {
        name: profile_name_from_file(file_name),
        endpoint: required_field(&peer, "endpoint", "Endpoint")?,
        private_key: required_field(&interface, "privatekey", "PrivateKey")?.into(),
        peer_public_key: required_field(&peer, "publickey", "PublicKey")?,
        preshared_key: peer.get("presharedkey").map(|key| key.as_str().into()),
        address,
        address_v6,
        allowed_ips: peer
            .get("allowedips")
            .cloned()
            .unwrap_or_else(|| DEFAULT_ALLOWED_IPS.to_string()),
        persistent_keepalive: keepalive,
        heliosd_url: None,
        // A wg-quick file **is** the classic shape: it has no way to express a
        // Helios negotiation, so the discriminant is a fact here, not a guess.
        profile_type: Some(ProfileKind::Classic),
        ssh_target: None,
        key_negotiation: None,
        preshared_key_is_negotiated: false,
    };
    Ok(WgQuickImport { profile, notices })
}

/// Sorts a section's properties into applied, reported and refused.
///
/// The three classes are the whole point. An allowlist alone refused ordinary
/// files; no list at all would drop, without a word, lines the tunnel's
/// behaviour depends on.
fn classify_wg_fields(
    fields: &HashMap<String, String>,
    applied: &[&str],
    section: &str,
    notices: &mut Vec<String>,
) -> Result<()> {
    // Sorted, so two imports of one file report the same thing in the same
    // order: a notice list that shuffled between runs reads as new problems.
    let mut names: Vec<&String> = fields.keys().collect();
    names.sort();
    for field in names {
        if applied.contains(&field.as_str()) {
            continue;
        }
        if wg_executable_field(field) {
            anyhow::bail!(
                "propriété {field} de {section} : Orion n'exécute aucune commande d'un fichier \
                 importé, et l'importer sans elle produirait un tunnel différent de celui que ce \
                 fichier décrit. La retirer du fichier, en connaissance de cause, permet l'import."
            );
        }
        match wg_unapplied_notice(field, &fields[field]) {
            Some(notice) => notices.push(notice),
            // A property nobody here knows about could mean anything, and
            // guessing which half of the trade it falls on is how a silent
            // behaviour change gets shipped.
            None => anyhow::bail!(
                "propriété {field} de {section} inconnue d'Orion ; la retirer modifierait \
                 peut-être le comportement du profil"
            ),
        }
    }
    Ok(())
}

fn required_field(
    fields: &HashMap<String, String>,
    normalized_name: &str,
    display_name: &str,
) -> Result<String> {
    fields
        .get(normalized_name)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .with_context(|| format!("propriété {display_name} requise"))
}

fn profile_name_from_file(file_name: &str) -> String {
    let basename = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .trim();
    let stem = basename.rsplit_once('.').map_or(basename, |(stem, _)| stem);
    if stem.trim().is_empty() {
        "profil-importé".to_string()
    } else {
        stem.trim().to_string()
    }
}
